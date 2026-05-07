//! At-rest encryption for the agent's long-lived signing key (`agent.id`).
//!
//! Without this layer, anyone with read access to the agent's working
//! directory could lift the raw 32-byte Ed25519 signing key off disk and
//! immediately impersonate the agent — defeating the registry's TOFU bind
//! and the gRPC call-signing checks. With it, an attacker also needs the
//! KEK material derived from `AGENTLANG_MASTER_KEY`.
//!
//! When `AGENTLANG_MASTER_KEY` is set, the on-disk file is wrapped:
//!   `MAGIC (6 bytes) || nonce (12 bytes) || AES-256-GCM(plaintext, KEK)`.
//! The KEK is `SHA-256(env_key || b"\x00identity-kek-v1")`, domain-separated
//! from the session AEAD key (which derives from the same env var but
//! without the suffix) so a leak of one cannot be used in place of the
//! other.
//!
//! When the env var is unset, the file falls back to legacy plaintext (the
//! pre-fix behavior) and a one-line warning is printed once. Existing
//! plaintext files are auto-migrated to the encrypted format on the next
//! load that happens with the env var present.
use anyhow::{Result, anyhow};
use rand::RngCore;
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    digest,
};
use std::sync::atomic::{AtomicBool, Ordering};

const MAGIC: &[u8; 6] = b"AGLE1\0";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ENV_VAR: &str = "AGENTLANG_MASTER_KEY";
const STRICT_ENV_VAR: &str = "AGENTLANG_REQUIRE_ENCRYPTED_KEYS";

/// Strict mode: when set to a truthy value, the runtime refuses to read or
/// write any key material in plaintext. Used by production deployments to
/// guarantee `AGENTLANG_MASTER_KEY` is configured and no fallback codepath
/// silently leaves identity bytes on disk.
pub fn strict_mode() -> bool {
    matches!(
        std::env::var(STRICT_ENV_VAR).ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes")
    )
}

/// Returns 32-byte KEK derived from `AGENTLANG_MASTER_KEY` if set.
/// Domain-separated from the session key derivation.
pub fn identity_kek_from_env() -> Option<[u8; 32]> {
    let env_key = std::env::var(ENV_VAR).ok()?;
    let mut input = Vec::with_capacity(env_key.len() + 16);
    input.extend_from_slice(env_key.as_bytes());
    input.extend_from_slice(b"\x00identity-kek-v1");
    let h = digest::digest(&digest::SHA256, &input);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_ref());
    Some(out)
}

fn wrap(plaintext: &[u8], kek: &[u8; 32]) -> Result<Vec<u8>> {
    let unbound = UnboundKey::new(&AES_256_GCM, kek)
        .map_err(|_| anyhow!("Failed to construct identity KEK"))?;
    let key = LessSafeKey::new(unbound);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut buf = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| anyhow!("Failed to seal identity at rest"))?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + buf.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(out)
}

fn unwrap(ciphertext: &[u8], kek: &[u8; 32]) -> Result<Vec<u8>> {
    if ciphertext.len() < MAGIC.len() + NONCE_LEN + TAG_LEN
        || &ciphertext[..MAGIC.len()] != MAGIC
    {
        return Err(anyhow!("identity file is not in encrypted format"));
    }
    let nonce_bytes: [u8; NONCE_LEN] = ciphertext[MAGIC.len()..MAGIC.len() + NONCE_LEN]
        .try_into()
        .unwrap();
    let mut buf = ciphertext[MAGIC.len() + NONCE_LEN..].to_vec();

    let unbound = UnboundKey::new(&AES_256_GCM, kek)
        .map_err(|_| anyhow!("Failed to construct identity KEK"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let plaintext_len = buf.len() - TAG_LEN;
    key.open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| anyhow!("Identity decryption failed (wrong AGENTLANG_MASTER_KEY?)"))?;
    buf.truncate(plaintext_len);
    Ok(buf)
}

static WARNED_ONCE: AtomicBool = AtomicBool::new(false);

fn warn_unencrypted() {
    if !WARNED_ONCE.swap(true, Ordering::Relaxed) {
        eprintln!(
            "[agentlang] WARNING: identity key is stored in plaintext. \
             Set {} to enable at-rest encryption.",
            ENV_VAR
        );
    }
}

/// Read the identity signing key from `path`. Auto-detects the on-disk
/// format. Returns `Ok(None)` if the file does not exist (caller will
/// generate a new identity), or `Ok(Some(bytes))` with the decoded 32-byte
/// signing key. Errors only on real corruption / wrong KEK / IO problems.
pub fn read_identity(path: &str) -> Result<Option<[u8; 32]>> {
    let raw = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow!("Failed to read identity file '{}': {}", path, e)),
    };

    let kek = identity_kek_from_env();

    // Encrypted format
    if raw.len() >= MAGIC.len() && &raw[..MAGIC.len()] == MAGIC {
        let kek = kek.ok_or_else(|| {
            anyhow!(
                "Identity file '{}' is encrypted but {} is not set",
                path,
                ENV_VAR
            )
        })?;
        let plain = unwrap(&raw, &kek)?;
        if plain.len() != 32 {
            return Err(anyhow!("Decrypted identity has unexpected length"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&plain);
        return Ok(Some(out));
    }

    // Legacy plaintext format
    if raw.len() == 32 {
        if strict_mode() && kek.is_none() {
            return Err(anyhow!(
                "Identity file '{}' is plaintext and {} is unset, but {} is enabled",
                path,
                ENV_VAR,
                STRICT_ENV_VAR
            ));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        // If a KEK is available, re-write encrypted so the next load is
        // protected. Failure to migrate is non-fatal: the bytes loaded are
        // still valid for this run.
        if let Some(kek) = kek
            && let Ok(blob) = wrap(&out, &kek)
        {
            let _ = std::fs::write(path, blob);
        } else {
            warn_unencrypted();
        }
        return Ok(Some(out));
    }

    Err(anyhow!(
        "Identity file '{}' has unexpected length {} (expected 32 bytes plaintext or AGLE1 envelope)",
        path,
        raw.len()
    ))
}

/// Write a freshly generated 32-byte signing key. Encrypts when KEK is
/// available, otherwise writes plaintext (with a one-shot warning). Refuses
/// to write plaintext when strict mode is on.
pub fn write_identity(path: &str, bytes: &[u8; 32]) -> Result<()> {
    if let Some(kek) = identity_kek_from_env() {
        let blob = wrap(bytes, &kek)?;
        std::fs::write(path, blob)
            .map_err(|e| anyhow!("Failed to write encrypted identity '{}': {}", path, e))?;
    } else {
        if strict_mode() {
            return Err(anyhow!(
                "Refusing to write plaintext identity to '{}': {} is set but {} is unset",
                path,
                STRICT_ENV_VAR,
                ENV_VAR
            ));
        }
        warn_unencrypted();
        std::fs::write(path, bytes)
            .map_err(|e| anyhow!("Failed to write identity '{}': {}", path, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    fn set_master_key(val: Option<&str>) {
        unsafe {
            match val {
                Some(v) => std::env::set_var(ENV_VAR, v),
                None => std::env::remove_var(ENV_VAR),
            }
        }
    }

    fn set_strict(on: bool) {
        unsafe {
            if on {
                std::env::set_var(STRICT_ENV_VAR, "1");
            } else {
                std::env::remove_var(STRICT_ENV_VAR);
            }
        }
    }

    #[test]
    #[serial]
    fn round_trip_with_master_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agent.id");
        let path_str = path.to_str().unwrap();
        set_master_key(Some("hunter2"));

        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        write_identity(path_str, &bytes).unwrap();

        // The file on disk must NOT be raw 32 bytes — that would mean
        // we silently regressed to plaintext.
        let raw = std::fs::read(path_str).unwrap();
        assert_ne!(raw.len(), 32, "encrypted file must not be 32 bytes");
        assert!(raw.starts_with(MAGIC), "file must start with magic header");

        let recovered = read_identity(path_str).unwrap().unwrap();
        assert_eq!(recovered, bytes);
        set_master_key(None);
    }

    #[test]
    #[serial]
    fn read_fails_with_wrong_master_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agent.id");
        let path_str = path.to_str().unwrap();

        set_master_key(Some("correct"));
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        write_identity(path_str, &bytes).unwrap();

        set_master_key(Some("wrong"));
        let res = read_identity(path_str);
        set_master_key(None);
        assert!(res.is_err(), "must fail with wrong master key");
    }

    #[test]
    #[serial]
    fn legacy_plaintext_migrates_when_master_key_set() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agent.id");
        let path_str = path.to_str().unwrap();

        // Pre-populate as raw plaintext (legacy on-disk format).
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        std::fs::write(&path, bytes).unwrap();

        set_master_key(Some("rotate"));
        let recovered = read_identity(path_str).unwrap().unwrap();
        assert_eq!(recovered, bytes, "legacy bytes must read back unchanged");

        let raw = std::fs::read(&path).unwrap();
        assert!(raw.starts_with(MAGIC), "legacy file should be re-encrypted on read");
        set_master_key(None);
    }

    #[test]
    #[serial]
    fn read_encrypted_file_without_master_key_errors() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agent.id");
        let path_str = path.to_str().unwrap();

        set_master_key(Some("set-once"));
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        write_identity(path_str, &bytes).unwrap();

        set_master_key(None);
        let res = read_identity(path_str);
        assert!(
            res.is_err(),
            "encrypted file must not be readable without master key"
        );
    }

    #[test]
    #[serial]
    fn missing_file_returns_none() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("does_not_exist");
        set_master_key(None);
        assert!(read_identity(path.to_str().unwrap()).unwrap().is_none());
    }

    #[test]
    #[serial]
    fn strict_mode_refuses_plaintext_write() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agent.id");
        set_master_key(None);
        set_strict(true);

        let bytes = [9u8; 32];
        let res = write_identity(path.to_str().unwrap(), &bytes);
        set_strict(false);

        assert!(res.is_err(), "strict mode must refuse plaintext writes");
        assert!(
            !path.exists(),
            "no file should be created when strict mode rejects the write"
        );
    }

    #[test]
    #[serial]
    fn strict_mode_refuses_plaintext_read() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agent.id");

        // Pre-seed legacy plaintext file.
        let bytes = [7u8; 32];
        std::fs::write(&path, bytes).unwrap();

        set_master_key(None);
        set_strict(true);
        let res = read_identity(path.to_str().unwrap());
        set_strict(false);

        assert!(
            res.is_err(),
            "strict mode must refuse to read a plaintext identity file"
        );
    }

    #[test]
    #[serial]
    fn strict_mode_with_master_key_round_trips() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agent.id");
        let path_str = path.to_str().unwrap();

        set_master_key(Some("strict-pass"));
        set_strict(true);
        let bytes = [3u8; 32];
        write_identity(path_str, &bytes).unwrap();
        let recovered = read_identity(path_str).unwrap().unwrap();
        set_strict(false);
        set_master_key(None);

        assert_eq!(recovered, bytes);
    }
}
