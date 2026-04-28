# AgentLang Security Audit & Feature Gap Analysis
**Original audit:** April 2026
**Last updated:** April 2026 — multiple findings remediated; see status notes below.

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
- **Outstanding:** `agent.key` (session AEAD key for long-term memory) is still raw bytes on disk in the no-env-var path; with the env var set, it derives directly from the env var rather than being persisted, which is already safe. Adopting OS keychain integration would close the gap fully.

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

### 2.1 Mocked Zero Knowledge Proofs (ZKP)
- **Status:** Stubbed.
- **Deviation:** `PROVE` statements execute logic but generate a Fibonacci STARK proof instead of proving the actual execution trace or state transitions.
- **Impact:** The "Trusted by Design" promise is currently non-functional for privacy-preserving claims.

### 2.2 Unimplemented Shared Memory
- **Status:** Missing.
- **Deviation:** `MemoryScope::Shared` returns `Err("Scope not implemented")`.
- **Impact:** Agents cannot collaborate via a shared state layer as defined in §7.2.

### 2.3 RPC Argument Injection
- **Status:** Broken.
- **Deviation:** `CALL` sends arguments over the wire, but the receiving agent (`MyAgentService::call_goal`) executes the goal in a fresh context without injecting those arguments into `working_variables`.
- **Impact:** Cross-agent cooperation is limited to parameter-less goals.

### 2.4 Limited WASM Interoperability
- **Status:** Minimal.
- **Deviation:** The runtime only supports `I32` arguments and return values.
- **Impact:** Complex data structures (strings, lists, objects) cannot be passed to WASM tools.

### 2.5 Hardcoded Federated Registry
- **Status:** Centralized.
- **Deviation:** The runtime assumes a single local registry at `[::1]:50050`.
- **Impact:** Federation (§12) is not implemented.
