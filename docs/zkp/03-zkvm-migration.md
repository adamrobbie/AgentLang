# zkVM Migration (RISC0 / SP1 / Jolt)

**Status:** Planning
**Owner:** TBD
**Estimated effort:** 8–16 engineer-weeks (12-week mid-point, +4-week buffer for witness-protocol unknowns)
**Sequencing:** Third and last of three. **Best after `01-per-statement-airs.md`** — that work formalizes statement semantics at constraint level, which transfers directly into the in-zkVM interpreter contract. SHA-256-in-AIR (`02`) is independent.

## Context

Hand-written AIRs (today's `ExecutionDigestAir`, plus the per-statement extension in `01`) prove specific properties of AgentLang execution: byte-level state binding now, statement-level semantics after `01`. They're fast to prove (sub-second for typical traces) but require constraint engineering for every new feature.

A zkVM flips that trade-off: compile the AgentLang interpreter to RISC-V, run it inside a generic zkVM (RISC0, SP1, Jolt), and the zkVM produces a proof of "this RISC-V binary executed faithfully against these inputs and produced these outputs." Constraint engineering disappears. Proof time rises 10–100×.

This document plans a **hybrid deployment** where AIRs handle the hot path and zkVM handles the cold path — the proofs that need full execution-trace ZK. It is **not** a plan to replace AIRs.

## What we're proving (before vs. after)

| Today + after `01` (AIR-based) | After this work (hybrid) |
|---|---|
| Specific statement-level properties: state digest, memory commitment, capability check, etc. | Full execution: "the AgentLang interpreter, given this Prove block and this witness, produces this state and audit log." |
| Proving: hand-written constraints per feature | Proving: compile interpreter, done |
| Proof time: sub-second to seconds | Proof time: tens of seconds to minutes |
| Proof size: 50–200 KB | 200 KB – 2 MB pre-recursion; ~10 KB after Groth16 wrap |
| New language features: each adds constraints | New language features: free, as long as they fit the deterministic-interpreter mold |
| Network/filesystem/WASM: out-of-AIR via witness | Network/filesystem/WASM: same — pre-recorded as witness |

## Non-goals

- **Replace AIRs.** AIR proofs stay, both for hot-path performance and for use cases where constraint-level granularity is desirable (privacy of unrevealed memory, fine-grained reveal semantics).
- **Prove WASM tool execution.** WASM tool calls are pre-recorded `(input, output, fuel)` tuples supplied as witness. The in-zkVM interpreter trusts the recorded result. zkVM-inside-WASM-inside-zkVM is out of scope.
- **Prove network calls succeeded honestly.** RPC results are witness-supplied. The proof binds the envelope and the result the agent observed; it does not bind to what the remote actually computed.
- **Eliminate Tokio from the production interpreter.** The witness-driven core is a *separate* execution mode used only inside the zkVM. The Tokio-driven runtime stays for live agent operation.
- **One-and-done verification.** Proofs from this path are larger; recursive proof composition (e.g. wrapping in Groth16 for on-chain verification) is a follow-on, not part of this work.

## Detailed design

### zkVM matrix

Three credible options as of April 2026:

| | RISC0 | SP1 | Jolt |
|---|---|---|---|
| Field | BabyBear (extension) | BabyBear | BN254-friendly |
| Maturity | 1.x production, mature SDK | 4.x, fast-evolving | Newer; lookup-arg-heavy |
| Proof time (1M cycles) | ~30 s | ~10 s | ~5–8 s |
| Proof size pre-wrap | ~250 KB | ~200 KB | ~150 KB |
| Recursive wrap | Yes (Groth16 conversion) | Yes (Groth16 conversion) | Native folding |
| Rust toolchain | Bespoke `cargo risczero` | Standard `cargo prove` | Standard `cargo prove` |
| Precompiles for hashes | Yes (SHA-256, K256, BN254) | Yes (extensive) | Yes |
| Memory model | 32-bit, 256 MB cap | 32-bit, larger cap | 32-bit |
| License | Apache-2.0 | MIT | Apache-2.0 |

**Decision deferred to Phase 1.** This doc commits to a benchmark: take a representative AgentLang program (a Goal containing two REMEMBERs, one RECALL, one IF, one CALL with witness-supplied result) and measure proof time, proof size, memory use on each zkVM. Pick after data lands. Rough expectation: SP1 wins on proving-time-per-cycle today, but RISC0's tooling is more stable; Jolt is most exciting but has the smallest production footprint.

### Interpreter restriction

The current interpreter (`src/runtime/eval.rs:188`) is `async`, Tokio-driven, and has `.await` points for network, filesystem, sleep, and WASM. Inside the zkVM, none of those are available — the in-zkVM interpreter must be **fully synchronous, deterministic, and witness-driven**.

Every non-deterministic input becomes a witness entry. Listing of `.await` points and how each is handled:

| Site | Today | Inside zkVM |
|---|---|---|
| `eval.rs:242` (Wait sleep) | `tokio::time::sleep` | Logical clock advance, no real wait |
| `eval.rs:816` (Remember TTL) | TTL-aware sleep | Witness records TTL outcome |
| `eval.rs:697–750` (Delegate RPC) | gRPC via `tokio::spawn` | Witness records `(callee_id, goal, args, result, success)` tuple |
| `eval.rs:1221–1310` (Call RPC) | gRPC via `tokio::spawn` | Same as Delegate |
| `context.rs:243–268` (shared memory lookup) | Registry RPC | Witness pre-records the lookup result |
| `context.rs:237, 350, 352` (long-term memory FS I/O via `JsonFileBackend`) | `std::fs` | Witness pre-loads the entire long-term memory state used by this Prove |
| `eval.rs:1055–1168` (WASM invocation) | `wasmtime::Instance::call` | Witness records `(module_hash, input_hash, output, fuel_consumed)` |
| Any RNG | Various | Witness supplies the RNG seed; interpreter uses a deterministic PRNG |

The shape this takes in code:

```rust
// New: src/runtime/witness.rs
pub struct ProveWitness {
    pub rpc_results: Vec<RpcResult>,         // ordered by call site
    pub shared_memory_reads: Vec<SharedRead>,
    pub long_term_memory: Vec<MemoryEntry>,  // full snapshot
    pub wasm_calls: Vec<WasmCall>,
    pub clock: LogicalClock,
    pub rng_seed: [u8; 32],
}

// New: src/runtime/eval_sync.rs
pub fn eval_sync(stmt: &Statement, ctx: &mut SyncContext, witness: &mut ProveWitness) -> Result<()>;
```

`eval_sync` mirrors the structure of `eval` (`src/runtime/eval.rs:188`) but with each `.await` replaced by a witness consumption: `let result = witness.next_rpc_result()?;`. Statement order in the witness must match execution order — a sequence number guards against reordering attacks.

### Witness protocol

The witness is the trust seam. It must be:

1. **Deterministic in shape.** Given a Prove block, the witness's structure is determined by the Prove body; only the *contents* are free.
2. **Bound to the proof.** A canonical hash of the witness is a public input to the zkVM proof. Tampering breaks verification.
3. **Reproducible from the live runtime.** When the live (Tokio) runtime executes a Prove block, it records every `.await` outcome into a `WitnessRecorder` so the same execution can be replayed inside the zkVM.

The flow:

```
Live runtime:                               zkVM proving:
  ┌────────────────┐                          ┌────────────────────┐
  │ eval (async)   │ ──records──>             │ ProveWitness       │
  │                │                          │ (canonical bytes)  │
  └───────┬────────┘                          └─────────┬──────────┘
          │                                             │
          ▼                                             ▼
   working state                              ┌────────────────────┐
   change set Δ                               │ eval_sync inside   │
          │                                   │ guest binary       │
          │                                   └─────────┬──────────┘
          │                                             │
          ▼                                             ▼
                                              ┌────────────────────┐
                                              │ zkVM proof:        │
                                              │  pub_inputs =      │
                                              │   (Δ_hash,         │
                                              │    witness_hash,   │
                                              │    audit_root)     │
                                              └────────────────────┘
```

The verifier checks: `Δ` matches the agent's pre/post Prove state; `witness_hash` is what the proof was generated against; `audit_root` matches the audit log.

### Public outputs from the zkVM

The guest binary writes to its public-output buffer:
- 32 bytes: SHA-256 of working-state bytes pre-Prove.
- 32 bytes: SHA-256 of working-state bytes post-Prove.
- 32 bytes: audit-chain root post-Prove.
- 32 bytes: claim hash (Fiat-Shamir, same as today).
- 8 bytes: number of statements executed.

The zkVM receipt commits to all of these.

### Receipt verification

`verify_proof` (`src/crypto.rs:400`) becomes a thin shim that dispatches on `digest_scheme`:
- Schemes 0/1 (polynomial, SHA-256 in AIR) → existing winterfell verifier.
- Scheme 2 (zkVM) → `risc0_zkvm::Receipt::verify(&program_id)` or SP1 equivalent.

`StarkProof.proof: Vec<u8>` carries the receipt bytes. Receipt `program_id` is pinned at build time (a hash of the guest binary) — the verifier rejects receipts from any other binary.

### Hybrid mode selection

`Statement::Prove` (`src/runtime/eval.rs:1010`) gains a mode field:

```rust
Statement::Prove {
    statements: Vec<Statement>,
    claim: String,
    proof_name: String,
    mode: ProveMode,  // new
}

pub enum ProveMode {
    Auto,            // pick based on body
    Air,             // force AIR
    ZkVm,            // force zkVM
}
```

`Auto` heuristic: zkVM if the body contains any `Call`, `Delegate`, or `UseWasm` (heavyweight, witness-based) **or** more than N statements; AIR otherwise. Threshold tunable per deployment.

Default: `Auto`. Operators tune via env var `AGENTLANG_PROVE_DEFAULT_MODE`.

### Integration touchpoints

- `src/crypto.rs:278` — `StarkProof` gains `digest_scheme = 2` for zkVM proofs.
- `src/crypto.rs:361` — `generate_proof` dispatches on mode.
- `src/crypto.rs:400` — `verify_proof` dispatches on scheme.
- `src/runtime/eval.rs:188` — `eval`'s Prove arm dispatches on `ProveMode`.
- `src/runtime/eval.rs:1010` — `Statement::Prove` arm grows witness recording.
- `src/runtime/witness.rs` (new) — `ProveWitness` struct, `WitnessRecorder` type.
- `src/runtime/eval_sync.rs` (new) — synchronous interpreter mirroring `eval`.
- `crates/agentlang-guest/` (new) — RISC-V guest binary crate, depends on `eval_sync` and the chosen zkVM SDK.
- `Cargo.toml` workspace — adds the guest crate; conditional on the `zkvm` feature.
- `proto/agent.proto` — `CallResponse` adds an optional `result_bytes_for_witness` field (Phase 4) so live calls can be faithfully recorded.

## Alternatives considered

- **Replace AIRs entirely with zkVM.** Rejected. Proof time is 10–100× slower; for high-throughput proving (every REMEMBER produces a proof), AIRs win. Hybrid is the right shape.
- **Build our own custom zkVM tuned for AgentLang.** Multi-year effort for marginal benefit over RISC0/SP1/Jolt. Hard pass.
- **Compile AgentLang to a fixed AIR (no zkVM, no per-statement).** Considered in `01`'s Alternatives. Worst of both worlds.
- **Wait for zkVM proof times to drop further.** Tempting given the trajectory (proof time has fallen ~5× year-over-year for the last 3 years). But the engineering work to be ready when it lands is the same; better to build now and benefit immediately as proof time falls.
- **Use a single zkVM (RISC0) without benchmarking.** Rejected — the gap between best and worst on AgentLang's specific workload could be 3–5×, and one engineer-week of benchmarking saves quarters of regret.

## Phased delivery

Each phase has a working artifact at the end. Buffer is 4 weeks beyond the nominal 12 weeks for witness-protocol unknowns (especially around shared memory and federated registry).

### Phase 1 — zkVM toolchain bench + pick (weeks 1–2)

- Write a representative AgentLang program in a benchmark repo (separate crate so it doesn't bloat AgentLang itself initially).
- Manually port to a guest binary for each of RISC0, SP1, Jolt.
- Measure proof time, proof size, memory, ergonomic friction.
- Pick. Commit decision in a memo at `docs/zkp/03b-zkvm-pick.md` (separate doc so the decision is reviewable independently).
- Risk: low. If proof times all exceed acceptability, escalate to roadmap re-planning.

### Phase 2 — Sync, witness-driven interpreter (weeks 3–4)

- Refactor `eval` to extract the statement-evaluation logic from the async transport layer.
- Implement `eval_sync` with witness consumption at every former `.await`.
- Wire `WitnessRecorder` into the live `eval` so each execution produces a witness as a side effect.
- Test: live execution of `Prove { Set; If; Set }` produces a witness; `eval_sync(stmt, witness)` reproduces the exact same final state.
- Risk: high. This is the bulk of the engineering work. Async-vs-sync semantics around shared memory and registry need careful design.

### Phase 3 — Guest binary + receipt verification wiring (weeks 5–6)

- New crate `crates/agentlang-guest/` builds to RISC-V using the chosen zkVM's SDK.
- Host program: takes `(prove_statements, witness, claim)`, runs guest, gets receipt, packs into `StarkProof` with `digest_scheme = 2`.
- `verify_proof` dispatches; receipt verification works end-to-end.
- Test: an end-to-end Prove → Reveal cycle through zkVM mode passes.
- Risk: medium. Toolchain integration is fiddly but well-trodden.

### Phase 4 — WASM as witness-supplied results (weeks 7–8)

- Live runtime records `(module_hash, input, output, fuel)` per WASM call.
- Guest's `eval_sync` consumes the witness instead of executing WASM.
- Test: a Prove block containing UseWasm round-trips through zkVM mode.
- Risk: medium. WASM tool calls today are stateful in subtle ways (memory persistence across calls within a single Prove); we need to record full state, not just I/O.

### Phase 5 — Audit log + contracts integration (weeks 9–10)

- `audit_root` becomes a public output of the zkVM proof.
- Capability checks (`check_contracts` at `context.rs:272`) execute inside guest against a witnessed contract list, with the contract-list-hash as a public input.
- Test: a Call without permission produces no verifying proof.
- Risk: low.

### Phase 6 — Hybrid auto-select + production rollout (weeks 11–12)

- `ProveMode::Auto` heuristic.
- Env var configuration.
- Documentation: when each mode is appropriate.
- Risk: low.

### Buffer (weeks 13–16)

Reserved for unknowns surfaced during Phases 2–4. Most likely consumers:
- Witness protocol for federated-registry lookups (multiple peers, race conditions).
- Shared-memory consistency model in zkVM mode (currently first-found-wins; needs deterministic ordering).
- Recursive proof composition for cross-agent Prove chains (likely deferred to a later doc).

## Risk register

1. **Witness protocol underspecifies non-determinism.** Async semantics in the live runtime allow racy outcomes; capturing that into a deterministic witness is the deepest design risk.
   *Mitigation:* prototype the witness format in Phase 2 against `Parallel`, `Wait`, and federated-registry lookups specifically. Budget 1 week of buffer for surfacing issues.
2. **Proof time too slow for any path.** If even simple Prove blocks take >60s in the chosen zkVM, the cold-path proposition is broken.
   *Mitigation:* Phase 1 has a hard go/no-go gate. If breached, raise to roadmap re-planning — possibly stop after `01` and `02`.
3. **WASM-as-witness threat-model misread.** Reviewers may interpret "verifying proof" as "WASM tool ran correctly." It does not.
   *Mitigation:* `verify_proof` rustdoc, `Reveal` output, and the `StarkProof::digest_scheme` discriminator all document this prominently. Separate threat-model doc published with Phase 4.

## Rollout plan

- Phase 1–5 land behind a feature flag `zkvm_prove`. Default off; opt in by building with `--features zkvm_prove`.
- Phase 6 ships the auto-select heuristic but **defaults to `ProveMode::Air` system-wide**. Operators opt in to `Auto` via `AGENTLANG_PROVE_DEFAULT_MODE=auto`.
- After 8 weeks of production opt-in usage with no soundness issues and acceptable performance:
  - Default flips to `Auto`.
  - `Air` and `ZkVm` remain explicit overrides indefinitely.
- The feature flag is removed two minor versions after default flip.

## Verification plan

- **Differential testing:** for every test in `src/runtime/mod.rs::tests` that exercises `Statement::Prove`, run the test in both `Air` and `ZkVm` mode and assert identical outcomes (state, proof verification status, audit-root output).
- **Witness fuzzing:** randomly mutate one byte of a witness; assert that either (a) the live recorder rejects it on canonicalization, or (b) the zkVM proof fails to verify. Never accept silently.
- **Property tests:** for 1000 random AgentLang programs, prove in zkVM mode, verify, then re-execute live and compare states. They must match.
- **Benchmark suite** in `benches/zkvm_proving.rs` (new): proving and verifying time for representative programs at sizes 1, 10, 100, 1000 statements. Posted in PR; CI-checked against ceiling thresholds.
- **End-to-end integration:** a `tests/prove_zkvm_e2e.rs` exercises Prove → Reveal across a process boundary (proof generated in one binary, verified in another). Replicates the production flow.
- **Migration tests:** existing AIR proofs (schemes 0 and 1) must still verify after the zkVM scheme lands. Cross-version compatibility test in CI.

## Open questions

1. **zkVM choice.** Defer to Phase 1 benchmark. No defensible answer absent data on AgentLang's actual workload.
2. **Recursive composition.** Cross-agent Prove chains (agent A's Prove references a Prove from agent B) require recursive proof composition. Likely a follow-on doc; should we sketch the API surface here? (Inclined to no — recursion is a separate trust model decision.)
3. **Witness-recorder durability.** If the live runtime crashes mid-Prove, what happens to a partial witness? Either: (a) discard; (b) persist and resume. Decision for Phase 2.
4. **Federated-registry witness.** A registry lookup that hits 3 peers and gets 3 different responses — what does the witness encode? Probably the first response, but the protocol must be explicit. Phase 2 deliverable.
5. **zkVM precompiles for SHA-256.** The chosen zkVM likely has an in-VM SHA-256 precompile. Use it for the `audit_root` computation? Probably yes, since the live `AuditChain::append` uses SHA-256 (`src/runtime/audit.rs:60`) — matching that inside zkVM is essentially free with a precompile.
6. **Memory budget.** RISC-V zkVMs cap at 256 MB guest memory. AgentLang's long-term memory backend is unbounded. Phase 5 must document a per-Prove memory budget and the truncation policy when exceeded.
