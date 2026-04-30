# SHA-256 Inside the AIR

**Status:** Planning
**Owner:** TBD
**Estimated effort:** 3–5 engineer-weeks
**Sequencing:** Second of three. **Soft-depends on `01-per-statement-airs.md`** for the lookup-argument tooling — if `01` slips, this doc's "fast path" (direct in-circuit SHA-256) ships independently with a known proving-time cost. Tackle before `03-zkvm-migration.md`.

## Context

`ExecutionDigestAir` (shipped 2026-04) commits state via a Schwartz-Zippel polynomial digest: `digest_{i+1} = digest_i * M + s_i` where `M` is a Fiat-Shamir-derived multiplier in the f128 base field. That gives strong soundness against state-byte tampering (~2^-108 for traces ≤ 2^20) but the soundness depends on the prover's inability to grind the multiplier — which we get by deriving `M = SHA256(claim || domain-separator)`.

This is fine for the threat model where the **claim is fixed before state is chosen**. It weakens if the prover can choose both the claim *and* the state to find a collision: a sufficiently motivated adversary with control over the claim string has more grinding freedom than the polynomial-digest analysis assumes.

Replacing the polynomial digest with **SHA-256 inside the AIR** removes this concern. Collision-finding cost becomes the generic 2^128 birthday bound regardless of how much choice the prover has over inputs. The trade-off is trace size — SHA-256 is expensive to arithmetize.

## What we're proving (before vs. after)

| Today (polynomial digest) | After this work |
|---|---|
| `state_digest` = polynomial eval of state bytes under Fiat-Shamir multiplier | `state_digest` = SHA-256 of state bytes |
| Soundness depends on multiplier unguessability (~2^-32 if claim attacker-controlled) | Soundness is generic 2^128 birthday |
| Trace: ~`max(N+1, 8)` rows for `N` state bytes | Trace: ~`64 * ceil((N+9)/64) + (N+1)` rows |
| Prover work: linear in N, ~milliseconds for typical N | Prover work: ~60–80× larger, ~hundred-millisecond range |
| Public input: `state_digest: u128` (full base-field element) | Public input: `state_digest_sha: [u8; 32]` |

## Non-goals

- **Replacing the audit-chain hash.** `AuditChain::append` (`src/runtime/audit.rs:60`) already uses SHA-256 outside the proof. This doc is about the digest *inside* the AIR.
- **Proving the SHA-256 implementation itself.** We rely on a well-reviewed reference implementation. Auditing the in-circuit SHA-256 is the implementer's responsibility, not part of this work.
- **Hiding state contents from the verifier.** The verifier learns the SHA-256 output. Privacy-preserving commitments (Pedersen, KZG) are a separate design question.
- **Replacing the polynomial digest in tests of historical proofs.** A migration window keeps the polynomial digest verifiable for old proofs (see Rollout).

## Detailed design

### Trace shape

SHA-256 processes 512-bit message blocks. For `N` state bytes:
- Pad to a multiple of 512 bits with the standard `0x80` + length suffix → ceil((N+9)/64) blocks.
- Each block requires 64 rounds; in-circuit each round is 1 row of ~70 columns (a, b, c, d, e, f, g, h working state + message schedule W[0..15] window + intermediate temporaries).
- One block ⇒ 64 rows. Two blocks ⇒ 128 rows. Plus a constant amount of glue.

Total trace rows for `N`-byte state:
```
trace_len = next_power_of_two( 64 * ceil((N+9)/64) + glue_rows )
```

For a typical 200-byte state (sample size of `build_state_bytes` output): 4 blocks × 64 = 256 rows + glue ≈ 320, padded to 512. Compared to today's ≈32 rows, that's ~16× larger. Proving time scales roughly linearly in trace size, so expect ~10× slower proving.

### Public-input changes

`PublicInputs` (`src/crypto.rs:66`) stays mostly the same; `state_digest` widens:
```rust
pub struct PublicInputs {
    pub claim_hash: BaseElement,
    pub multiplier: BaseElement,            // KEEP for back-compat verifier path
    pub state_digest: [BaseElement; 4],     // 256-bit, four field elements (4×64 bits packed)
}
```

`StarkProof` (`src/crypto.rs:278`):
```rust
pub struct StarkProof {
    pub proof: Vec<u8>,
    pub state_digest: [u8; 32],   // was: u128
    pub claim_hash: u64,
    pub num_state_bytes: u64,
    pub trace_length: u64,
    pub multiplier: u64,           // KEEP for old-proof verifier path during migration
    pub digest_scheme: u8,         // new: 0 = polynomial (legacy), 1 = sha256
}
```

`digest_state_bytes` (`src/crypto.rs:435`) gets a sibling `digest_state_bytes_sha(state_bytes: &[u8]) -> [u8; 32]` that uses the standard `sha2` crate — for verifier-side independent verification.

### Reference implementation choice

Two production-quality candidates as of April 2026:

1. **winterfell `examples/rescue` adjacent / community SHA-256 AIR.** Native winterfell, 0 dependencies outside the workspace, ~70-column trace layout, MIT-licensed. Lower fidelity (no precompile-style optimizations) but most direct integration with the existing `ExecutionDigestAir`.
2. **Port from SP1's `precompile-sha256`.** Higher-quality arithmetization (lookup-table-backed), but SP1 uses a different field (`BabyBear`) and a different prover stack. Porting back to f128 is non-trivial.

**Recommendation:** start with the winterfell-native AIR. Ship Phase 1 with it. If proving time is unacceptable, replace it with a lookup-table SHA-256 in Phase 3 — but that depends on the lookup tooling from `01-per-statement-airs.md` Phase 3, which is why this doc soft-depends on `01`.

### Glue constraint

The new SHA-256 sub-trace consumes the same byte stream that `ExecutionDigestAir` consumes today. We need a constraint linking them:

- The SHA-256 input message bytes (32 bytes per "row" of the message-schedule expansion) must equal the `byte_input` column of the existing `ExecutionDigestAir` trace, byte-for-byte.
- Concretely: a copy constraint (or equality permutation argument) from column `byte_input` in `ExecutionDigestAir` to the SHA-256 trace's input window. winterfell aux-segments support this via random linear combinations.

For Phase 1, we can simplify by **replacing** the polynomial digest with SHA-256 entirely — no two-segment trace, just one SHA-256 trace whose input is `state_bytes`. The polynomial digest stays in the codebase but moves to `digest_state_bytes_polynomial` for old proofs.

### Integration touchpoints

- `src/crypto.rs:66` — `PublicInputs`: `state_digest` widens.
- `src/crypto.rs:91` — `ExecutionDigestAir`: replaced by `Sha256DigestAir` (or extended with a feature flag).
- `src/crypto.rs:278` — `StarkProof`: adds `digest_scheme` discriminator, widens `state_digest`.
- `src/crypto.rs:361` — `generate_proof`: dispatches on `digest_scheme`.
- `src/crypto.rs:400` — `verify_proof`: dispatches on `digest_scheme` for back-compat.
- `src/crypto.rs:435` — `digest_state_bytes`: split into `_polynomial` (legacy) and `_sha` (new).
- `src/runtime/eval.rs:34` — `build_state_bytes`: unchanged.
- `Cargo.toml`: add the SHA-256 AIR crate (winterfell or community port).

## Alternatives considered

- **Keep polynomial digest, harden the multiplier derivation.** Already done as much as possible (Fiat-Shamir from claim hash). Beyond that, only a real cryptographic hash closes the residual gap.
- **Pedersen / Poseidon hash inside AIR.** Faster than SHA-256 in-circuit (~10× fewer rows for Poseidon). Rejected because verifier-side independent re-hashing requires a Poseidon implementation; SHA-256 is universally available. We'd revisit if Poseidon becomes a project standard for other reasons.
- **Hash outside the AIR, attest via signature.** Defeats the point: a signed external hash is a separate trust assumption, not a proof.
- **Two-tier digest: polynomial inside AIR, SHA-256 wrapper outside.** Almost-good: the SHA-256 wrapper would commit to the polynomial digest, gaining birthday-bound soundness on the wrapper but still depending on Schwartz-Zippel for the inside. Rejected because it doubles complexity for a smaller security improvement than full SHA-256-inside.

## Phased delivery

### Phase 1 — Standalone SHA-256 AIR (week 1)

- Drop in the chosen SHA-256 AIR as `src/crypto/sha256_air.rs`.
- Round-trip test: 64-byte input, prove `output == SHA-256(input)`, verify.
- No integration with `ExecutionDigestAir` yet.
- Risk: low.

### Phase 2 — Replace polynomial digest with SHA-256 (weeks 2–3)

- New `Sha256DigestAir` extends `ExecutionDigestAir`'s public-API contract.
- `StarkProof` gains `digest_scheme`. Old proofs (with `digest_scheme = 0`) still verify via the legacy code path; new proofs use scheme 1.
- `Statement::Prove` uses scheme 1 by default.
- Update `Statement::Reveal` and the `runtime::tests::test_eval_*` family to assert against the new digest output.
- Benchmark: prove + verify for a representative 200-byte state. Compare vs. polynomial-digest baseline. Acceptance: ≤10× slower proving, equal verifying.
- Risk: medium — the existing test suite expects 128-bit digests; widening to 256 touches multiple files.

### Phase 3 — Lookup-based SHA-256 (weeks 4–5, OPTIONAL)

**Only if `01-per-statement-airs.md` Phase 3 has shipped lookup tooling.**

- Replace round-by-round in-circuit SHA-256 with a precomputed-round-table lookup AIR.
- Trace size drops ~4–5×; proving time drops correspondingly.
- Risk: medium-high; requires the lookup machinery to be production-quality.

If `01` slips: stop after Phase 2. The direct in-circuit SHA-256 is a complete, shippable improvement. The 10× slowdown is acceptable for the security gain.

## Risk register

1. **Proving-time blowup unacceptable to operators.** Real risk. 10× slower proving may move `Prove` from "fast enough to use freely" to "bench it before each call."
   *Mitigation:* Phase 2 has a benchmark gate. If breached, fall back to keeping polynomial digest as default and offering SHA-256 only via opt-in env var until Phase 3 lookup tooling lands.
2. **SHA-256 AIR audit burden.** A bug in the in-circuit SHA-256 implementation breaks soundness silently.
   *Mitigation:* use a well-reviewed reference; cross-check 1000+ random inputs against the `sha2` crate as part of CI.
3. **Migration of historical proofs.** Existing proofs with the polynomial digest must remain verifiable.
   *Mitigation:* `digest_scheme` discriminator + full legacy-verify path retained. Test that old proofs still verify after the migration.

## Rollout plan

- Phase 1 lands behind a build-time feature flag `sha256_in_air`.
- Phase 2 ships with `digest_scheme` flag in proofs but **default behavior remains polynomial digest** for one minor version. Operators can opt in via `AGENTLANG_DIGEST_SCHEME=sha256` env var.
- After 6 weeks of opt-in usage with no soundness or performance regressions, default flips to SHA-256.
- Polynomial digest path retained for 2 minor versions for old-proof verification, then verifier-only (no new-proof generation).

## Verification plan

- **Unit tests** in `src/crypto::tests`:
  - Round-trip: prove & verify for empty, 1-byte, 100-byte, 10KB states.
  - Tamper-detection: flip a byte in the proof's `state_digest`, expect verify failure.
  - Cross-check: `digest_state_bytes_sha(s)` matches `sha2::Sha256::digest(s)` for 1000 random `s`.
  - Legacy compat: an old polynomial-digest proof still verifies after the migration.
- **Benchmark suite** in `benches/sha256_air.rs` (new): proving and verifying time for state sizes 1, 64, 256, 1024, 8192 bytes. Posted in the PR.
- **End-to-end:** `Statement::Prove { ... }` integration tests in `src/runtime/mod.rs` extended to assert proof carries `digest_scheme = 1` and verification succeeds.
- **CI:** new test job runs the cross-check against `sha2` on 10K random inputs.

## Open questions

1. Padded byte-length encoding: SHA-256 standard requires the bit-length appended; do we expose the raw bit length or the post-pad block count to the verifier? (Tooling-affecting — the latter simplifies the verifier.)
2. Multi-hash protocol: should `state_digest` always be SHA-256, or should we let `Statement::Prove` pick a hash family per call? (Default-yes simplifies; per-call gives flexibility for future Poseidon.)
3. Verifier-side independent recomputation: do we ship a stable canonical-form serializer alongside `digest_state_bytes_sha` so external verifiers don't depend on AgentLang's internal `Debug` format? (Probably yes — Phase 2 deliverable.)
4. CI benchmark gate threshold: what's the ceiling on proving time before we block the rollout? Suggest 30 s for a 1 KB state on the reference machine; needs review.
