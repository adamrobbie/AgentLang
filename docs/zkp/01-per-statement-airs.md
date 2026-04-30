# Per-Statement-Type AIRs

**Status:** Planning
**Owner:** TBD
**Estimated effort:** 6–10 engineer-weeks (12-week ceiling if Plonky3 port required)
**Sequencing:** First of three follow-on items in `ZKP_ROADMAP.md`. Tackle before `02-sha256-in-air.md` (lookup tooling shared) and `03-zkvm-migration.md` (forces semantic formalization that pays off either way).

## Context

`ExecutionDigestAir` (shipped 2026-04) binds a STARK proof to the *byte representation* of post-execution working state. That's a real guarantee against state-byte tampering, but it's silent on **how** the state got there: a malicious or buggy interpreter that bypassed `Statement` semantics still produces a verifying proof so long as the final byte sequence matches.

This document plans the work to close that gap: encode each `Statement` variant's semantics as its own constraint family inside the AIR, so a verifying proof testifies "the AgentLang interpreter executed faithfully" rather than just "some byte sequence matches the digest."

## What we're proving (before vs. after)

| Today (`ExecutionDigestAir`) | After this work |
|---|---|
| Final state bytes match `state_digest` | Final state bytes match, **and** every state mutation traces back to a permitted statement opcode |
| Claim binding via Fiat-Shamir multiplier | Same, plus per-segment opcode binding |
| Interpreter compliance: trusted | Interpreter compliance: enforced by constraints |
| Memory writes: unbounded by AIR | Memory writes: lookup-argument-checked against committed memory root |
| Audit-chain link to proof: none | Audit-chain root is a public input; segment transitions enforce hash chain |

## Non-goals

- **Full execution-trace ZK across all of AgentLang** — that's `03-zkvm-migration.md`. This doc keeps writing constraints by hand for known-shape statement bodies.
- **Proving WASM tool semantics** — we bind the `(input, output, fuel)` tuple of a WASM call but treat the tool itself as an opaque oracle. Proving WASM execution would require a zkVM-inside-AIR, which is out of scope.
- **Proving network results** — `Call` and `Delegate` results are witness-supplied. The constraint family proves the *envelope* is well-formed and capability-checked, not that the remote agent answered correctly.
- **Privacy of memory contents** — readers of the proof learn the memory commitment root and any values explicitly revealed via `RECALL`. Privacy of unrevealed memory is preserved, but "zero knowledge" beyond commitment is not promised.

## Detailed design

### Trace shape

A multi-segment trace where each row is tagged by an opcode column. Conceptually:

```
row | opcode  | operand_a | operand_b | ... | mem_root | audit_root | selector_REM | selector_IF | ...
----+---------+-----------+-----------+-----+----------+------------+--------------+-------------+-----
 0  | ENTER   |   ...     |   ...     | ... |  R_0     |  A_0       |     0        |     0       | ...
 1  | REM     |  path_h   |  val_h    | ... |  R_1     |  A_1       |     1        |     0       | ...
 2  | IF      |  cond_h   |   ...     | ... |  R_1     |  A_2       |     0        |     1       | ...
...
```

Selectors are 0/1 columns; constraints for each opcode are multiplied by the corresponding selector so they only fire on rows of that kind. This is winterfell-idiomatic — see `winterfell/examples/lamport`'s selector pattern.

### Public-input changes

Today's `PublicInputs` (`src/crypto.rs:66`):
```rust
pub struct PublicInputs {
    pub claim_hash: BaseElement,
    pub multiplier: BaseElement,
    pub state_digest: BaseElement,
}
```

Becomes:
```rust
pub struct PublicInputs {
    pub claim_hash: BaseElement,
    pub multiplier: BaseElement,
    pub state_digest: BaseElement,        // unchanged: final working state
    pub memory_root_initial: [BaseElement; 4],   // 256-bit Merkle root of long-term memory
    pub memory_root_final:   [BaseElement; 4],
    pub audit_root_initial:  [BaseElement; 4],
    pub audit_root_final:    [BaseElement; 4],
    pub contract_root:       [BaseElement; 4],   // active contracts at proof time
}
```

`StarkProof` (`src/crypto.rs:278`) widens to carry the four roots. The verifier compares `memory_root_initial` against the agent's actual pre-Prove memory root and `memory_root_final` against the post-Prove root — that's how the proof is bound to **this** agent's memory, not a fabricated one.

### Constraint catalog

One section per statement variant. Cite the current dispatch arm; the constraint family replaces the trust assumption that arm currently makes.

#### `Statement::Set` — `src/runtime/eval.rs:345`

Writes a working variable. Trace contribution:
- One row, opcode `SET`, operands `(name_hash, value_hash)`.
- Constraint: `state_digest_next = state_digest_curr * M + chunk(name||value)` — i.e. extends the existing digest recurrence over the SET event's bytes.
- No memory or audit interaction.

Smallest variant; ships in Phase 2.

#### `Statement::Remember` — `src/runtime/eval.rs:794`

Writes long-term or shared memory.
- One row, opcode `REM`, operands `(scope, path_hash, value_hash, ttl)`.
- **Memory lookup:** the new `(path, value)` pair is inserted into the memory commitment. Constraint: `memory_root_next = update(memory_root_curr, path_hash, value_hash)` where `update` is a Merkle-update gadget. Implementation choice: out-of-AIR Merkle proof witness, in-AIR verifier (~2log₂(N) rows per update).
- **Audit chain:** `audit_root_next = SHA256(audit_root_curr || event_bytes)` where `event_bytes` includes opcode + operands. (For Phase 2 we use the polynomial digest carry from `02-sha256-in-air.md` if landed, else a separate Schwartz-Zippel chain.)
- TTL: encoded as a row field; expiry handled by a separate cleanup statement (out of scope for this doc).

#### `Statement::Recall` — `src/runtime/eval.rs:848`

Reads long-term or shared memory.
- One row, opcode `RCL`, operands `(scope, path_hash, value_hash)`.
- **Memory lookup:** Merkle-membership constraint that `(path_hash, value_hash)` is present under `memory_root_curr`. No root mutation.
- Working-state side effect: the recalled value enters working state, which extends `state_digest`. Same constraint as SET.

#### `Statement::Forget` — `src/runtime/eval.rs:903`

- Opcode `FGT`. Memory removal as Merkle update with empty leaf. Otherwise mirrors REM.

#### `Statement::If` — `src/runtime/eval.rs:351`

Branching.
- Header row: opcode `IF`, operand `cond_hash`. The cond expression's evaluation contributes a sub-trace that ends in a boolean cell.
- A **branch-selector witness column** records which branch was taken (0/1).
- Constraint family: `cond_eval == branch_selector` AND only the rows belonging to the taken branch fire their selectors. Skipped-branch rows are no-ops (opcode `NOP`, all selectors zero).
- Cleanly nests with REM/RCL inside branches.

#### `Statement::Goal` — `src/runtime/eval.rs:190`

The structural unit. A Goal body is a contiguous segment of the trace.
- Enter row: opcode `GOAL_ENTER`, operands `(name_hash, audit_root_at_entry)`.
- Exit row: opcode `GOAL_EXIT`, operands `(name_hash, status, audit_root_at_exit)`.
- Constraint: opcode names match across enter/exit; `audit_root_at_exit == hash_chain(audit_root_at_entry, all events in segment)`.
- Status field encodes success/failure/timeout (binds to `classify_goal_failure` at `src/runtime/goal.rs`).

#### `Statement::Call` — `src/runtime/eval.rs:1170`

Inter-agent RPC.
- Row, opcode `CALL`, operands `(callee_hash, goal_hash, args_hash, result_hash)`.
- **Capability lookup:** the row enforces a Merkle-membership check that `goal_hash` is present in the active `contract_root` with `CanUse` permission. This replaces the runtime check at `src/runtime/eval.rs:1178` with a constraint.
- Result is a witness — the proof binds `result_hash` to whatever value `store_call_result` (`src/runtime/call.rs`) put into context.
- The `args_hash` is bound via working-state digest carry, so tampering with the args after-the-fact breaks the proof.

#### `Statement::Delegate` — `src/runtime/eval.rs:667`

Same shape as Call but with selector `DEL`. Distinct opcode so verifiers can distinguish synchronous calls from fire-and-forget delegations.

#### `Statement::UseWasm` — `src/runtime/eval.rs:1055`

WASM tool invocation.
- Row, opcode `WASM`, operands `(module_hash, function_hash, input_hash, output_hash, fuel_consumed)`.
- **Capability check:** Merkle-membership that `module_hash` is granted under the active contract.
- Result/fuel are witnesses; the AIR binds the tuple but does not execute WASM. (Threat model: a malicious agent could lie about output, but the proof still attests "the agent claimed this tool returned this for this input" — which is the same trust posture as the runtime today.)

#### `Statement::Prove` — `src/runtime/eval.rs:1010`

The outer envelope. After this work lands:
- A `Prove` block produces a single proof whose trace contains one segment per inner statement.
- The current per-statement digest carry is replaced by the per-statement constraint families above.
- `build_state_bytes` (`src/runtime/eval.rs:34`) is retained but moves down the stack — it now feeds the *initial state* into the trace, not the final.

#### `Statement::Reveal` — `src/runtime/eval.rs:1029`

No AIR contribution. Verifier-side. After this work, `Reveal` additionally returns the new public roots so callers can compare against agent state.

#### Other variants

- `Parallel`, `ForEach`, `Repeat`, `Wait` — desugared into Goal-bounded segments with control selectors. Phase 5.
- `UseTool`, `Tool`, `Agent`, `Contract`, `Emit`, `On`, `Await` — Phase 5+ or non-goal for v1. Doc each as out-of-scope until follow-on.

### Integration touchpoints

Files that change in this work:

- `src/crypto.rs` — `PublicInputs`, `StarkProof`, `ExecutionDigestAir` extended into a multi-segment AIR; new `ExecutionLog` type.
- `src/runtime/eval.rs:188` (the `eval` dispatch) — each arm gains a "log to ExecutionLog" call when running inside a `Prove` block.
- `src/runtime/eval.rs:34` (`build_state_bytes`) — repurposed; new helper `build_execution_log` produces the trace input.
- `src/runtime/context.rs:45–48` — memory backends gain a `commit_root() -> [u8; 32]` method.
- `src/runtime/audit.rs:60` (`AuditChain::append`) — already SHA-256-based; expose `current_root()` for the AIR public input.
- `src/runtime/context.rs:272` (`check_contracts`) — runtime check stays; AIR-side constraint duplicates it for in-proof binding.
- `proto/agent.proto` — RPC `CallRequest`/`CallResponse` may grow a `result_commitment` field (Phase 4).

### Lookup-argument choice

The single biggest open implementation question. Two paths:

1. **Stay on winterfell** and use auxiliary segments + a custom LogUp-style lookup. Winterfell 0.13 supports auxiliary trace segments but the lookup ergonomics are sparse; we'd write the arithmetization ourselves.
2. **Port to Plonky3** which has mature lookup tables (Lasso/Jolt-derived). Cost: rewrite the entire AIR; benefit: faster proving, proven lookup machinery.

Decision deferred to Phase 3 (week 4); a 2-day prototype on each compares wall-clock proving for a 10-statement Goal.

## Alternatives considered

- **One global state-transition AIR (no per-statement selectors).** Rejected: a single set of constraints expressive enough for every statement variant becomes degree-explosion problem; the selector pattern is the standard solution.
- **Polynomial commitments instead of Merkle for memory.** Rejected for v1: KZG/IPA add a trusted setup or a slower opening cost; Merkle works in the f128 base field with no setup.
- **Skip per-statement work, jump to zkVM.** Rejected: zkVM proving is 10–100× slower than hand-rolled AIRs. We need the AIR path for hot-path proofs (REMEMBER, simple Goals); the per-statement work is the foundation. zkVM is the "cold path" complement, not a replacement (see `03-zkvm-migration.md`).
- **In-circuit semantic interpreter (compile AgentLang to a fixed AIR).** Rejected: midway between per-statement AIRs and a zkVM, with the worst of both — fixed-circuit means no flexibility, and writing a single AIR for the full language is more work than per-statement.

## Phased delivery

Each phase ends with a green test suite and a shippable checkpoint.

### Phase 1 — Execution log infrastructure (week 1)

- Add `ExecutionLog` type in `src/runtime/exec_log.rs` (new file): append-only log of `(opcode, operands)` tuples.
- Modify `Statement::Prove` body evaluation (`src/runtime/eval.rs:1010`) to allocate an `ExecutionLog` and pass it through to inner statements via a new field on `Context`.
- Each statement arm in `eval` gains a `log.record(...)` call. No AIR change yet — the log is unused.
- Tests: `Prove { Set { ... } }` produces a log with one `SET` entry.
- Risk: low.

### Phase 2 — IF + GOAL selectors and control-flow constraints (weeks 2–3)

- Multi-segment trace shape: opcode column, selector columns for `GOAL_ENTER/EXIT`, `IF`, `NOP`.
- Constraints: opcode-validity, selector-mutual-exclusion, GOAL enter/exit pairing, IF branch-selector witness.
- `state_digest` recurrence stays; opcodes contribute to it.
- New test: `Prove { Goal { If { Set; Else: Set; } } }` round-trips through prover/verifier.
- Risk: medium — winterfell auxiliary segments may need touching.

### Phase 3 — Memory commitment + REMEMBER/RECALL lookup (weeks 4–5)

- Memory backend gains `commit_root() -> [u8; 32]` and `prove_membership(path) -> MerkleProof`.
- AIR constraint: REM/RCL/FGT each enforce Merkle update or membership against `memory_root_*` public inputs.
- **Decision point:** prototype winterfell-aux vs Plonky3-port for 2 days; pick.
- New tests: REMEMBER then RECALL round-trips; tampering with a value between mid breaks verification.
- Risk: high — the lookup-argument choice dominates.

### Phase 4 — CALL / DELEGATE / WASM envelope binding (week 6)

- AIR constraints for `CALL`, `DEL`, `WASM` opcodes: capability-Merkle-membership, args/result/output binding.
- Contract root construction in `src/runtime/context.rs`.
- Tests: a CALL with disallowed capability fails to produce a verifying proof; a verifying proof with tampered args is rejected.
- Risk: medium.

### Phase 5 — Misc statements + fuzz harness + soundness review (weeks 7–8)

- Add Parallel, ForEach, Repeat, Wait as desugared Goal segments.
- Property-based fuzzing: random AgentLang programs, run interpreter, prove, verify; assert proof verifies iff interpreter succeeded.
- External soundness review of the constraint catalog before declaring v1 done.
- Risk: low.

## Risk register

1. **Lookup-argument tooling (Phase 3).** Highest schedule risk.
   *Mitigation:* 2-day winterfell-vs-Plonky3 prototype before committing; budget +2 weeks if Plonky3 port is chosen.
2. **AIR degree explosion from selectors.** Each opcode-gated constraint multiplies in a selector, raising effective degree.
   *Mitigation:* keep base constraints degree-1; group selectors via `TransitionConstraintDegree::with_cycles` to amortize. Profile after Phase 2.
3. **WASM-as-witness threat-model communication.** Reviewers may misread "verifying proof" as "WASM tool ran correctly." It doesn't.
   *Mitigation:* the doc's Non-goals section is verbatim in `verify_proof` rustdoc; threat model published alongside v1.

## Rollout plan

- Phase 1–4 land behind a build-time feature flag `per_statement_air`. Default off.
- Phase 5 enables an env var `AGENTLANG_PROVE_MODE=per-statement` to opt in at runtime; default remains `digest-only` (today's behavior).
- After 4 weeks of dogfooding (internal usage at scale, no soundness regressions), default flips to `per-statement` and `digest-only` becomes the legacy fallback.
- Legacy flag retained for one minor version, then removed.

## Verification plan

- **Unit tests** in `src/crypto.rs::tests`: each constraint family has positive (round-trip) and negative (tampered field rejected) tests.
- **Property fuzzing** in a new `tests/per_statement_fuzz.rs`: 10K random Prove programs, assert verify ⇔ interpreter-succeeded.
- **End-to-end** in `src/runtime/mod.rs` (mirror of existing `test_eval_prove_statement` / `test_eval_reveal_statement`): one test per statement variant, plus nested combinations.
- **Soundness review:** external auditor pass on the constraint catalog before flipping the default. Budget: ~2 weeks of auditor time outside the 8-week engineering plan.
- **Benchmark gate:** proving time for a representative 20-statement Goal must stay under 30 s on the reference machine. If exceeded, the lookup-argument choice (Phase 3) is revisited before Phase 5 ships.

## Open questions

1. Winterfell aux-segments vs Plonky3 port — needs the 2-day prototype. (Phase 3.)
2. Memory commitment scheme (sparse Merkle vs binary Merkle vs verkle) — depends on backend. Sparse Merkle is the default, but the long-term backend may have a preferred scheme.
3. Should `audit_root` be exposed in `Reveal` results? Trade-off between observability and information leak about non-Prove activity.
4. Granularity of `Statement::Parallel` segments — one segment per branch, or interleaved? Decision deferred to Phase 5 with prototype data.
5. Per-statement constraint catalog versioning: how do we evolve constraints without breaking verification of older proofs? Likely via a `proof_version: u8` field in `StarkProof` and verifier dispatch table. Spec'd in Phase 4.
