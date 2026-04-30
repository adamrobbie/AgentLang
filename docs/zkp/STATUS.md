# AgentLang ZKP — Implementation Status

**Last updated:** 2026-04-30
**Branch:** `security-hardening-1` (5 commits ahead of `main` as of push)

This is a snapshot of where the per-statement-AIR roadmap actually stands
in the code. Plan-of-record lives in
[`docs/zkp/01-per-statement-airs.md`](01-per-statement-airs.md); this doc
is the running ledger of what shipped, what's open, and where the
implementation diverged from the plan.

## Roadmap items (from `ZKP_ROADMAP.md`)

| # | Item | Status |
|---|------|--------|
| 1 | Per-statement-type AIRs | **Phases 1+2 shipped.** Phase 3 next. |
| 2 | SHA-256 inside AIR | Not started. Soft-depends on #1 Phase 3 lookup tooling. |
| 3 | zkVM migration | Not started. Sequenced after #1, #2. |

## Item #1: Per-statement-type AIRs

The deep-dive plan splits this into 5 phases. Status per phase:

### Phase 1 — Execution log infrastructure ✅

`src/runtime/exec_log.rs` defines `ExecutionLog`, `LogEntry`, `Operands`,
and `Opcode` (11 stable discriminants). Every recording statement arm in
`src/runtime/eval.rs` calls `ctx.record_log(...)`. Coverage:

- ✅ `Set` (eval.rs:382), `Goal` enter (253), `Goal` exit (355), `If` (406)
- ✅ `Remember` (874), `Recall` (963/976), `Forget` (993)
- ✅ `Call` (1350), `Delegate` (743), `UseWasm` (1262)

Recorded but **not yet AIR-constrained:** Remember/Recall/Forget,
Call/Delegate/UseWasm. These appear in the log and bind into the digest
via `log.canonical_bytes()` (Slice 1+2), but Phase 3+ adds the structural
constraints.

### Phase 2 — Control-flow constraints ✅

`ControlFlowAir` in `src/crypto.rs` enforces, per row:

| # | Constraint | Degree |
|---|------------|--------|
| 1 | opcode ∈ {11 valid discriminants} | 11 |
| 2 | `branch_taken ∈ {0, 1}` | 2 |
| 3 | `goal_status ∈ {0, 1, 2, 3}` | 4 |
| 4 | `claim_hash` carry | 1 |
| 5 | depth recurrence (GoalEnter +1 / GoalExit -1) | 10 |
| 6 | `branch_taken * (opcode - IF) = 0` | 2 |

Boundary assertions: claim at row 0, depth=0 at row 0 and last row.
Wired into `Statement::Prove` (eval.rs:1142) and verified in
`Statement::Reveal` (crypto.rs `verify_proof`). Empty logs skip CF
emission — the all-Nop trace is degenerate for winterfell; documented
inline.

**Key implementation deviations from the deep-dive's Phase 2 sketch:**

- **Selector strategy.** Plan called for "selector columns per opcode +
  selector-mutual-exclusion" constraints. We chose **Lagrange indicator
  polynomials** over the opcode column instead (`opcode_indicator` in
  crypto.rs). Soundness: zero witness gap (deterministic from opcode).
  Cost: higher constraint degree (10 instead of 2). Reconsider if degree
  becomes an FFT-cost problem in Phase 3+.
- **Anti-pad design.** Power-of-two padding to a multiplicative subgroup
  of size N can collapse witness columns into degree-N/2 polynomials when
  the column happens to be even-symmetric (f(g^k) = f(g^(k+N/2))). The
  current 5-row anti-pad (Nop, IF, GoalEnter, IF, GoalExit with
  `goal_status=3`) is tuned to break this for every shipping test trace.
  Documented inline at `ControlFlowProver::build_trace`.
- **`StarkProof.control_flow` is `Option`-shaped, not feature-flagged.**
  Plan called for a build-time `per_statement_air` feature; we ended up
  with runtime opt-in via "log present ⇒ CF proof present." Simpler,
  serialization-stable across versions, and lets dogfooding be per-call
  rather than per-build. Revisit before flipping the default.

Slice ledger (commits on `security-hardening-1`):

- `9dbd2af` — ExecutionLog + 7 statement types wired (Phase 1)
- `1a923f7` — Call/Delegate/UseWasm wired (Phase 1 finish)
- `a6d90c2` — Log bound into Prove digest (Slices 1+2)
- `756bbc4` — `LogTrace` builder (Slice 3)
- `6037933` — `ControlFlowAir` + constraints 1–4 (Slice 4)
- `bc25b34` — Wired into `Statement::Prove` (Slice 5)
- `4e92970` — GOAL_ENTER/EXIT pairing (Slice 6)
- `0319f47` — IF branch-selector binding (Slice 7)
- `77354db` — End-to-end nested round-trip test (Slice 8)

### Phase 3 — Memory commitment + REMEMBER/RECALL lookup ⏳

**Not started. Highest schedule risk in the roadmap.**

Required work, per the deep-dive's §"Memory" and Phase 3 plan:

1. **Memory commitment scheme.** `src/runtime/context.rs:45–48` (the
   four-scope storage: Working/Session/LongTerm/Persistent) needs a
   `commit_root() -> [u8; 32]` and `prove_membership(path) -> MerkleProof`
   surface. Default candidate: sparse Merkle over (scope, path_hash) →
   value_hash; alternatives in §"Open questions" item 2.
2. **Lookup-argument tooling.** **2-day prototype** comparing winterfell
   auxiliary segments vs. a Plonky3 port. This is the gating decision
   for Phase 3+. The deep dive's risk register flags this as the highest
   schedule risk; the Phase 2 work didn't move the needle on it.
3. **AIR constraints.** Per-row constraint families:
   - `REMEMBER`: lookup proves `(scope, path_hash) ∉ commit_root_curr`
     (or `∈` with prior value), `commit_root_next` matches the updated
     tree.
   - `RECALL`: lookup proves `(scope, path_hash) ∈ commit_root_curr`
     with the witnessed `value_hash`.
   - `FORGET`: lookup proves prior membership, `commit_root_next` reflects
     deletion.
4. **Public-input changes.** `StarkProof` grows
   `memory_root_pre`/`memory_root_post: [u8; 32]`. Verifier checks the
   prover's claimed roots match the runtime's actual roots at Prove
   start/end.
5. **Tests.** REMEMBER then RECALL round-trips (positive); tampering
   with a value mid-Prove fails verification (negative).

**Open questions to resolve before implementation:**

- Winterfell aux-segments vs Plonky3 port (deep dive Q1) — needs the
  prototype.
- Memory commitment scheme choice — sparse Merkle by default, but
  long-term backend may prefer something else.
- How to expose `memory_root_*` to the verifier without leaking memory
  contents. Probably: just publish the roots, never the leaves.

### Phase 4 — CALL / DELEGATE / WASM envelope binding ⏳

**Not started. Soft-depends on Phase 3 lookup tooling** (capability lookups
share machinery with memory lookups).

Per the deep-dive's Phase 4 plan:

1. **Capability commitment.** Active contracts at
   `src/runtime/context.rs:272` (`check_contracts`) need a Merkle root
   over `(agent_id, capability) → contract_metadata`. Built at
   contract-issuance time, exposed via `capability_root()`.
2. **AIR constraints.**
   - `CALL`: capability-root membership for `(callee_hash, goal_hash)`;
     `args_hash` binding to the recorded RPC envelope.
   - `DELEGATE`: same as CALL plus fire-and-forget acknowledgement that
     the RPC outcome lives outside the proof.
   - `USEWASM`: WASM module hash + (input, output, fuel) tuple binding.
     Note: the proof binds to the module hash but **not** its execution.
     This is documented as a soundness escape hatch in the deep dive's
     non-goals.
3. **Public-input changes.** `StarkProof` grows `capability_root: [u8;32]`.
4. **Proto change.** `proto/agent.proto` `CallRequest`/`CallResponse` may
   grow a `result_commitment` field so callers can bind RPC outputs.
5. **Tests.** CALL with disallowed capability fails to produce a verifying
   proof; verifying proof with tampered args is rejected.

### Phase 5 — Misc statements + fuzz harness + soundness review ⏳

**Not started.** Per the deep-dive plan:

1. Desugar `Parallel`, `ForEach`, `Repeat`, `Wait` into Goal-bounded
   segments with control selectors. Out-of-scope statements
   (`UseTool`, `Tool`, `Agent`, `Contract`, `Emit`, `On`, `Await`)
   stay non-goal for v1.
2. **Property-based fuzz harness** (`tests/per_statement_fuzz.rs`,
   new): 10K random AgentLang programs, run interpreter, prove, verify;
   assert proof verifies iff interpreter succeeded.
3. **External soundness review** of the constraint catalog before
   declaring v1 done. Budget ~2 weeks of auditor time outside the
   8-week engineering plan.
4. **Benchmark gate.** Proving time for a representative 20-statement
   Goal must stay under 30 s on the reference machine. If exceeded, the
   Phase 3 lookup choice gets revisited.

## Cross-cutting items still open

These belong to no single phase and are tracked here so they don't fall
through the cracks:

- **Audit-chain root carry.** The constraint catalog in §"Constraint
  catalog" line 93 calls for `audit_root_next = SHA256(audit_root_curr ||
  event_bytes)`. Today `AuditChain` is recorded but not bound by AIR;
  the audit_root field exists on `GoalEnter`/`GoalExit` operands but is
  not constrained across rows. Needs the SHA-256-in-AIR work (item #2)
  or a separate Schwartz-Zippel chain — decided when item #2 is staged.
- **Proof versioning.** A `proof_version: u8` field in `StarkProof` plus
  a verifier dispatch table is open question Q5 in the deep dive; needs
  to ship before any constraint-catalog change that breaks older proofs.
  Likely lands with Phase 4.
- **Empty-log degeneracy.** `ControlFlowAir` cannot prove an all-Nop
  trace (winterfell rejects the zero quotient polynomial). Today the
  runtime sidesteps this by emitting CF only when `log.entries() != []`.
  When Phase 3 wires REMEMBER/RECALL into `Prove`, every non-trivial
  Prove body necessarily emits at least one entry, so this becomes
  unreachable. Documented inline in `crypto.rs` tests.

## Item #2: SHA-256 inside AIR

Not started. See [`docs/zkp/02-sha256-in-air.md`](02-sha256-in-air.md)
for the full plan. Soft-depends on #1 Phase 3 lookup tooling for the
optimal lookup-based variant; ships independently with the direct
in-circuit variant if Phase 3 slips.

## Item #3: zkVM migration

Not started. See [`docs/zkp/03-zkvm-migration.md`](03-zkvm-migration.md)
for the full plan. Sequenced after #1 and #2.
