# AgentLang Security Audit & Feature Gap Analysis
**Original audit:** April 2026
**Last updated:** 2026-04-28 — Section 2 rewritten to match implementation; gaps 2.2/2.3/2.5 reclassified as **IMPLEMENTED**, 2.4 as **PARTIALLY ADDRESSED**, 2.1 reclassified as **MOSTLY ADDRESSED** after Fibonacci STARK was replaced with `ExecutionDigestAir`. Companion roadmap for the residual ZKP gaps lives in `ZKP_ROADMAP.md`.

> **Note on file paths.** The original audit predates the split of
> `src/runtime.rs` into the `src/runtime/` module. References below have
> been updated to point at the current files.

## 1. Security Vulnerabilities

### 1.1 Critical: Registry Hijacking (Identity Theft) — **REMEDIATED**
- **Location:** `src/lib.rs` (`MyRegistryService::register_agent`)
- **Finding:** The registry accepts `RegisterRequest` without verifying the `signature`.
- **Impact:** Any entity can register as any `agent_id` (e.g., "PrimaryOrchestrator"), redirecting all traffic and CALL requests to a malicious endpoint.
- **Resolution:** Ed25519 signature verification on registration is now enforced (the agent signs `agent_id:endpoint` with the public key it presents). In addition, **trust-on-first-use binding** rejects re-registration of an existing `agent_id` with a different public key — closing the residual hole where an attacker with their own valid keypair could still claim a well-known ID.

### 1.2 High: Plaintext Secret Storage — **PARTIALLY REMEDIATED**
- **Location:** `src/runtime/context.rs` (`Context::new`)
- **Finding:** Identity keys (`agent.id`) and session encryption keys (`agent.key`) are stored as raw bytes on the filesystem.
- **Impact:** Local compromise leads to total loss of agent identity and access to all "long_term" encrypted memory.
- **Resolution (identity key):** When `AGENTLANG_MASTER_KEY` is set, `agent.id` is wrapped with AES-256-GCM under a domain-separated KEK derived from that env var. Existing plaintext files auto-migrate on first read. When the env var is unset the file is still plaintext (with a one-shot stderr warning) — production deployments should set the env var.
- **Resolution (strict mode):** A new `AGENTLANG_REQUIRE_ENCRYPTED_KEYS=1` env var refuses to read or write any key material in plaintext: `secret::write_identity` errors when no KEK is available, `secret::read_identity` errors on legacy plaintext files, and `Context::new` panics if no master key is set. This gives operators a forcing function for production deployments — once strict mode is on, no fallback codepath can silently leave key bytes on disk.
- **Outstanding:** Without strict mode, `agent.key` is still raw bytes on disk in the no-env-var path. Without an OS keychain (macOS Security framework, Linux Secret Service, Windows DPAPI), there's no portable place to store a wrapping key for the env-var-unset path. Strict mode + `AGENTLANG_MASTER_KEY` is the recommended posture today; OS keychain integration is the long-term fix.

### 1.3 High: Unbounded WASM Execution (DoS) — **REMEDIATED**
- **Location:** `src/runtime/eval.rs` (`Statement::UseWasm`)
- **Finding:** WASM modules are executed using a default `Store` and `Linker` with no resource limits.
- **Impact:** A malicious or buggy WASM tool can consume 100% CPU or all available RAM, crashing the agent runtime.
- **Resolution:** `wasm_config.consume_fuel(true)` is set on the engine and each WASM invocation calls `store.set_fuel(1_000_000)`, bounding per-call CPU work.

### 1.4 Medium: Unencrypted Inter-Agent Communication — **REMEDIATED**
- **Location:** `src/lib.rs`, `src/runtime/eval.rs`, `src/runtime/context.rs`, `src/main.rs`
- **Finding:** gRPC connections to the Registry and between Agents use `http` instead of `https`.
- **Impact:** Sensitive data (though `AS sensitive` fields are redacted/checked) and orchestrator commands are visible to network observers.
- **Resolution:** TLS is now opt-in via `src/tls.rs`. Setting `AGENTLANG_TLS_CERT` + `AGENTLANG_TLS_KEY` enables TLS on `start_registry` / `start_agent`. Clients route through `tls::connect_registry` / `tls::connect_agent`, which use TLS for `https://` URLs (with bundled webpki roots, optionally augmented by `AGENTLANG_TLS_CA`) and stay plaintext for `http://`. Plaintext remains the default so local development and existing tests aren't disrupted.

### 1.5 Medium: Contract/Permission Bypass — **REMEDIATED**
- **Location:** `src/runtime/context.rs` (`check_contracts`)
- **Finding:** The runtime checks if a contract has expired but ignores the `capabilities` vector.
- **Impact:** An agent can call any tool regardless of whether its contract permits it.
- **Resolution:** `check_contracts(required_capability)` walks each contract's `capabilities`, honors `CanUse(*)`/`CanUse(cap)` for grant and `CannotUse(...)` for explicit denial, and returns "permission denied" when no active contract grants the capability.

### 1.6 Low: Volatile Audit Trail — **REMEDIATED**
- **Location:** `src/runtime/audit.rs` (`AuditChain`)
- **Finding:** The hash-chain is stored in a `Vec` in memory and never flushed to disk.
- **Impact:** Audit logs are lost on restart, breaking the "immutable trail" guarantee.
- **Resolution:** `AuditChain::new(path)` rehydrates from the JSON file on startup and `append(...)` rewrites it on every entry — entries persist across restarts.

---

## 2. Feature Gaps (Specification Deviations)

### 2.1 Zero Knowledge Proofs (ZKP) — **MOSTLY ADDRESSED**
- **Status:** State-binding STARK in place; execution-trace and per-statement binding still future work (see `ZKP_ROADMAP.md`).
- **Resolution:** `src/crypto.rs` now hosts an `ExecutionDigestAir` that binds the proof to a Schwartz-Zippel-style polynomial digest of the post-execution state. The trace enforces the recurrence `digest_{i+1} = digest_i * M + s_i` over the bytes produced by `build_state_bytes` (`src/runtime/eval.rs:34`). The AIR's public inputs are `(claim_hash, multiplier, state_digest)` where `claim_hash = SHA-256(claim)` and `multiplier` is a Fiat-Shamir-derived constant — also bound to the claim, so the prover cannot grind it after the fact. The AIR is degree-1 in trace columns and uses the f128 base field; soundness against state-byte tampering is `≤ N/|F| ≈ 2^-108` for `N ≤ 2^20`. The full 128-bit `state_digest` is exposed in `StarkProof` so external comparison preserves that margin (we previously truncated to u64, which broke OOD frame consistency).
- **Outstanding:**
  - The trace encodes the bytes of *post-execution state*, not statement-level evaluation steps. Two different statement sequences that produce the same final state are indistinguishable to a verifier — execution path is not bound, only the result.
  - State serialization is `key:Debug(value)|` text. Strings, lists, and objects are formatted via `Debug`, so the bound is on textual representation rather than a canonical structural form.
  - No per-statement-type AIRs (REMEMBER/RECALL/IF/GOAL each as their own constraint encoding), no zkVM migration, no SHA-256-inside-AIR digest. These are tracked in `ZKP_ROADMAP.md` as multi-week-to-multi-month follow-on work.

### 2.2 Shared Memory — **IMPLEMENTED**
- **Status:** Functional.
- **Resolution:** `MemoryScope::Shared` reads/writes through registry RPCs (`get_shared_state` / `put_shared_state`) — see `src/runtime/context.rs:230` (read) and `src/runtime/context.rs:341` (write). Values are JSON-encoded `AnnotatedValue`s and round-trip through any of the configured registries.
- **Outstanding:** No replication or conflict resolution between peer registries; the first-found-wins read strategy is racy under concurrent writes. Acceptable for single-registry deployments.

### 2.3 RPC Argument Injection — **IMPLEMENTED**
- **Status:** Functional.
- **Resolution:** `MyAgentService::call_goal` (`src/lib.rs:252`) parses each `CallRequest.args` entry into a typed `Value` (`Number` / `Boolean` / `Text`) and inserts it into the isolated context's `working_variables` before evaluating the goal body. The caller (`src/runtime/eval.rs:1229`) serializes call-site arguments into the same map.
- **Outstanding:** Args are stringly-typed over the wire (`map<string, string>`); structured values like lists or nested objects must be passed as JSON text and parsed by the callee. Tighter typing would require evolving `proto/agent.proto`.

### 2.4 Limited WASM Interoperability — **MOSTLY ADDRESSED**
- **Status:** All AgentLang value variants can be passed; structured types use a JSON-via-pointer convention.
- **Current support:**
  - Numerics: `I32`, `I64`, `F32`, `F64` (`src/runtime/eval.rs`).
  - Booleans coerce to `I32`.
  - **Text:** allocated via the module's `alloc` export and written **NUL-terminated** into linear memory; the function receives the pointer as `I32`. (Pre-fix, the runtime allocated `len` bytes and skipped the trailing NUL — callees that scanned for termination read past the payload into uninitialized heap.)
  - **Lists & Objects:** serialized to JSON, then passed under the same NUL-terminated-string convention. Callees parse the payload with their JSON library of choice. End-to-end coverage in `runtime::tests::test_wasm_list_marshaling_via_json` and `test_wasm_object_marshaling_via_json`.
- **Outstanding:** No wit-bindgen / Component-Model bindings — every WASM tool must implement `alloc(size: i32) -> i32` and a `memory` export. Multi-return-value support is limited to the first slot. Floats narrower than `F64` lose precision through the `as f64` cast on return.

### 2.5 Federated Registry — **IMPLEMENTED**
- **Status:** Functional with caveats.
- **Resolution:** `MyRegistryService` carries a `peer_registries: Vec<String>` field (`src/lib.rs:36`); `lookup_agent` recursively delegates to peers with a TTL bound (`src/lib.rs:128`). Multiple registries can be configured per agent via `Context::registries`. The default `http://[::1]:50050` is just a starting value, not a hard assumption.
- **Outstanding:** No discovery, gossip, or signed peering — peers must be configured statically. The registry-to-registry protocol is plaintext gRPC unless the operator configures TLS via `AGENTLANG_TLS_*`.
