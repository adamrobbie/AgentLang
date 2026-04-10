# AgentLang Security Audit & Feature Gap Analysis
**Date:** April 2026  
**Status:** High Priority Remediation Required

## 1. Security Vulnerabilities

### 1.1 Critical: Registry Hijacking (Identity Theft)
- **Location:** `src/main.rs` (`register_agent`)
- **Finding:** The registry accepts `RegisterRequest` without verifying the `signature`. 
- **Impact:** Any entity can register as any `agent_id` (e.g., "PrimaryOrchestrator"), redirecting all traffic and CALL requests to a malicious endpoint.
- **Recommendation:** Implement Ed25519 signature verification on registration. The agent must sign its ID and endpoint using the public key it provides.

### 1.2 High: Plaintext Secret Storage
- **Location:** `src/runtime.rs` (`Context::new`)
- **Finding:** Identity keys (`agent.id`) and session encryption keys (`agent.key`) are stored as raw bytes on the filesystem.
- **Impact:** Local compromise leads to total loss of agent identity and access to all "long_term" encrypted memory.
- **Recommendation:** Use a secure enclave or at least OS-level secret management (e.g., Keychain, SecretService) or prompt for a master password to derive an encryption key.

### 1.3 High: Unbounded WASM Execution (DoS)
- **Location:** `src/runtime.rs` (`Statement::UseWasm`)
- **Finding:** WASM modules are executed using a default `Store` and `Linker` with no resource limits.
- **Impact:** A malicious or buggy WASM tool can consume 100% CPU or all available RAM, crashing the agent runtime.
- **Recommendation:** Implement `wasmtime` fuel consumption (CPU limits) and memory limits (pooling allocator).

### 1.4 Medium: Unencrypted Inter-Agent Communication
- **Location:** `src/main.rs`, `src/runtime.rs`
- **Finding:** gRPC connections to the Registry and between Agents use `http` instead of `https`.
- **Impact:** Sensitive data (though `AS sensitive` fields are redacted/checked) and orchestrator commands are visible to network observers.
- **Recommendation:** Enable TLS for all Tonic services and clients.

### 1.5 Medium: Contract/Permission Bypass
- **Location:** `src/runtime.rs` (`check_contracts`)
- **Finding:** The runtime checks if a contract has expired but ignores the `capabilities` vector.
- **Impact:** An agent can call any tool regardless of whether its contract permits it.
- **Recommendation:** Update `check_contracts` to accept the required capability and verify it against the `active_contracts`.

### 1.6 Low: Volatile Audit Trail
- **Location:** `src/runtime.rs` (`AuditChain`)
- **Finding:** The hash-chain is stored in a `Vec` in memory and never flushed to disk.
- **Impact:** Audit logs are lost on restart, breaking the "immutable trail" guarantee.
- **Recommendation:** Persist the `AuditChain` to a local append-only file or database.

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
