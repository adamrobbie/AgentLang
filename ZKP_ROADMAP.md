# AgentLang ZKP Roadmap

**Status:** Companion document to `SECURITY_AUDIT.md` §2.1.
**Last updated:** 2026-04-28
**Owner:** TBD

## Where we are today

`src/crypto.rs` ships an `ExecutionDigestAir` that binds proofs to a
Schwartz-Zippel polynomial digest of post-execution state bytes. This is a
real-but-narrow ZK guarantee:

- **What it binds:** the byte representation of the working-variable map at
  the moment `Statement::Prove` finishes. Tampering with any state byte
  invalidates the proof.
- **What it does NOT bind:** the execution path that produced that state, the
  individual statements that ran, the types/structure of values (we serialize
  via `Debug`), or anything outside the working-variable map (long-term
  memory, audit log, contracts).
- **External soundness:** ~2^-108 for traces ≤ 2^20 bytes against state-byte
  tampering. The 128-bit state digest is exposed verbatim in `StarkProof`, so
  external state comparison preserves that margin.
- **Practical limits:** the trace must be non-degenerate (winterfell rejects
  constant trace polynomials), so `build_state_bytes` always emits a magic
  prefix.

The three items below were explicitly carved out of the in-session work as
"multi-week to multi-month" each. They are listed in **recommended
sequencing order** — start at the top, since each step makes the next
cheaper.

---

## 1. Per-statement-type AIRs

### What

Today's AIR encodes one constraint family: a polynomial-digest recurrence
over a flat byte array. To prove that *specific statement semantics* held
during execution — e.g. "this REMEMBER actually wrote `x=42` to long-term
memory", "this IF branch was taken because `balance > 100` was true",
"this GOAL completed without contract violation" — we need constraint
encodings keyed off statement type.

The natural shape: a multi-segment trace where segment headers tag a
statement kind (REMEMBER, RECALL, IF, GOAL, CALL, USE-WASM, …) and
segment-internal constraints enforce the semantics of that kind:

| Statement | Constraint sketch |
|---|---|
| REMEMBER | `next_memory[k].value = current.value` AND `next_memory[k].provenance == hash(current_audit_event)` |
| RECALL | `current.value == prior_memory[k].value` (lookup argument or Merkle proof against memory commitment) |
| IF cond THEN ... ELSE ... | one segment for taken branch; cond evaluation must hold |
| GOAL ... | enter/exit segment with audit-chain root commitment delta |
| CALL agent.goal(args) | contract-permission check + RPC envelope binding |

### Why it matters

Currently a malicious or buggy interpreter that mutates state without going
through the spec-defined semantics still produces a verifying proof, as long
as the *final state bytes* match. Per-statement AIRs would close that gap —
the proof becomes a guarantee that AgentLang's execution rules were
followed, not just that some byte sequence ended up in `state_digest`.

### Design sketch

1. Define a `StatementOp` enum that maps each AST `Statement` variant to a
   small fixed-width encoding (opcode + operand columns). The trace becomes
   a sequence of rows, each row tagged with one opcode.
2. Introduce **selector columns** per opcode. For each statement type, write
   a constraint set guarded by the corresponding selector — winterfell's
   `evaluate_transition` can multiply by selectors to gate which constraints
   apply on which rows. Constraint degrees grow by `+1` per selector, so the
   AIR's overall degree budget needs review.
3. **Lookup arguments** for memory / contract / registry state. Long-term
   memory is too big to put in trace columns, so we'd commit to it via
   Merkle root in `PublicInputs` and use a lookup argument (e.g. LogUp,
   RAP-style) to prove RECALL pulls the right value. Plonky3's lookup
   tables and winterfell's auxiliary segments are both candidate primitives.
4. Wire `Statement::Prove` to record an *execution log* (the sequence of
   opcodes + operands that ran inside its body) and feed that log into the
   AIR builder.

### Effort estimate

**6–10 engineer-weeks** for a full first cut covering REMEMBER/RECALL/IF/
GOAL/CALL. Breakdown:

- Week 1: opcode encoding + execution log scaffolding in interpreter.
- Week 2–3: AIR with selectors + transition constraints for control flow
  (IF/GOAL).
- Week 4–5: memory lookup argument (largest unknown — needs prototyping).
- Week 6: CALL/USE-WASM segment binding to RPC envelopes.
- Week 7–8: end-to-end fuzz harness + soundness review.
- Buffer 2 weeks for integration with audit-chain commitment.

The lookup-argument step has the most schedule risk; it may push to 12
weeks if winterfell's auxiliary-segment API turns out to be too restrictive
and we end up porting to Plonky3.

### Recommended sequencing

Tackle this **before** zkVM migration. Building per-statement AIRs first
forces us to formalize what AgentLang's semantics actually are at the
constraint level — that work pays off whether we eventually keep AIRs or
migrate to a zkVM.

---

## 2. SHA-256-inside-AIR

### What

Replace the Schwartz-Zippel polynomial digest with a SHA-256 commitment
computed *inside* the AIR. The `state_digest` public input becomes
`SHA-256(state_bytes)` evaluated by an in-circuit SHA-256 implementation.

### Why it matters

The current digest is a polynomial evaluation in f128. Soundness against
*tampering with state bytes* is excellent (Schwartz-Zippel, ~2^-108) but
soundness against *finding two distinct byte sequences with the same
digest* depends on the multiplier being unguessable to the prover. Today
we derive the multiplier from `claim_hash` via Fiat-Shamir, but a prover
who can choose the *claim* before fixing the state has degrees of freedom
to grind for collisions that a cryptographic hash forecloses.

A SHA-256 commitment removes this concern: collision-finding cost is the
generic 2^128 birthday bound regardless of how much choice the prover has
over inputs.

### Design sketch

1. Drop in an existing SHA-256 AIR — there are reference implementations
   in winterfell (`examples/`) and SP1's `precompile-sha256`. Roughly 64
   round-function rows per 512-bit block, ~70 trace columns.
2. Add a sub-trace segment to the existing AIR that consumes
   `state_bytes` chunked into 512-bit blocks and outputs the 256-bit hash.
   Constrain the final output equal to the public `state_digest` input.
3. Replace the polynomial recurrence in `ExecutionDigestAir` with a glue
   constraint: "the input to the SHA-256 segment is the same byte sequence
   the verifier committed to via `num_state_bytes`."
4. `state_digest` widens from `u128` to `[u8; 32]` (or two `u128`s).

### Effort estimate

**3–5 engineer-weeks**. SHA-256 AIRs are well-documented; the work is
mostly integration and trace-layout decisions. The hard part is sizing —
SHA-256 inside an AIR roughly multiplies trace size by 60–80×, so for a
1KB state today (32-row trace) we'd jump to a 2K–3K-row trace. Proof time
grows linearly in trace size; verification stays cheap.

If the trace explosion is a problem, the alternative is **lookup-based
SHA-256** (precomputed table of round outputs) — cheaper but requires the
auxiliary-segment / lookup machinery from item #1, which is why this
should sequence after per-statement AIRs.

### Recommended sequencing

After per-statement AIRs (item #1). The lookup-argument tooling we build
for memory commitments in #1 is the same tooling we'd want for a
table-driven SHA-256.

---

## 3. zkVM migration (RISC0 / SP1 / Jolt)

### What

Compile the AgentLang interpreter (or a subset of it) to a RISC-V binary,
run it inside a zkVM (RISC0, SP1, or Jolt), and let the zkVM produce the
proof. The AIR-design effort effectively disappears — the zkVM has a
fixed AIR for RISC-V semantics, and we get "the program ran correctly"
for free as long as our interpreter is well-defined.

### Why it matters

This is the only path that gives us **execution-trace ZK** without writing
constraints by hand. Per-statement AIRs (item #1) prove AgentLang
semantics one statement type at a time; a zkVM proves *the entire
interpreter* — including statement evaluation, memory bookkeeping,
WASM tool invocation guards, contract checks. It's a categorical
upgrade.

### Tradeoffs

| Dimension | AIR-based (today + #1 + #2) | zkVM (RISC0/SP1) |
|---|---|---|
| Engineering cost | High — every statement type is a hand-written constraint | Low — compile interpreter, done |
| Proof time | Fast (10K-row traces prove in seconds) | Slow (millions of cycles → minutes) |
| Proof size | Small (~50–200 KB) | Larger (~200 KB – 2 MB pre-recursion) |
| Verification cost | Cheap (~ms in Rust) | Cheap if recursive; raw RISC0 receipts ~ms also |
| Privacy granularity | Fine — we choose what's public | Coarse — public outputs only |
| Maturity (April 2026) | Mature (winterfell/Plonky3) | RISC0 1.x and SP1 4.x both production-ready |

### Design sketch

1. **Restrict the interpreter** to a deterministic, no-async subset for
   in-zkVM execution. Tokio futures, gRPC, filesystem I/O all become
   pre-recorded "witness" inputs that the in-zkVM interpreter consumes
   instead of generating. (RPC results, registry lookups, WASM invocation
   results: all witness-supplied.)
2. **Build the host program**: a Rust binary that takes (program,
   pre-recorded witness, claim) and runs the interpreter to completion,
   asserting the claim holds. RISC0's `risc0-zkvm-platform` or SP1's
   `sp1-sdk` provide the build harness.
3. **Bridge audit log → public outputs**: the zkVM-produced receipt
   commits to whatever the host program writes to its public-output
   buffer. We'd write the audit-chain root + final state digest there.
4. **Replace `crypto::generate_proof`** with a host-side call that
   invokes the zkVM, leaving `Statement::Prove`'s API surface unchanged.

### Effort estimate

**8–16 engineer-weeks**, dominated by the interpreter-restriction work
and the witness-supply protocol. Specifically:

- 1 week: zkVM toolchain choice (RISC0 vs SP1 vs Jolt) — benchmark proof
  time and ergonomic fit on a representative AgentLang program.
- 2–3 weeks: refactor interpreter into a sync, witness-driven core.
- 2 weeks: host program + receipt verification wiring.
- 2–3 weeks: WASM tool invocations as witness-supplied results (this
  bridges to deterministic execution; non-trivial).
- 2 weeks: integration with audit log / contracts.
- 4 weeks buffer: the witness protocol for shared memory / federated
  registry will surface design issues we can't predict.

### Recommended sequencing

**Last.** Doing #1 and #2 first gives us a robust, fast, AIR-based proof
system that's deployable today. zkVM migration is a categorical upgrade
but not strictly necessary — and proof times are 10–100× slower than
hand-rolled AIRs, so for the high-throughput case (e.g. proving millions
of agent interactions), we may keep AIRs even after a zkVM is available
for the heavy-lift cases.

The realistic deployment shape is **hybrid**: AIRs for hot-path proofs
(REMEMBER, simple GOALs), zkVM for proofs that need full execution
binding (e.g. contract-violation disputes, regulator-facing audits).

---

## Sequencing summary

```
[ NOW: ExecutionDigestAir, state-byte binding only ]
              │
              ▼
    [ #1: per-statement AIRs ]   ← 6–10 weeks; hardest, highest ROI
              │
              ▼
    [ #2: SHA-256 inside AIR ]   ← 3–5 weeks; rides on #1's tooling
              │
              ▼
    [ #3: zkVM migration ]       ← 8–16 weeks; categorical upgrade
```

Each step is independently shippable. Stop at any point and the system
still has a real ZK story, just with the limits documented in
`SECURITY_AUDIT.md` §2.1.
