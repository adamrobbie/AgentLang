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

**Key implementation deviations from the deep-dive's Phase 2 sketch.**
Each closes off an option the plan assumed was open, so each carries a
forward constraint into Phase 3+:

- **Selector strategy: Lagrange indicators (degree 10) instead of
  selector columns (degree 2).** `opcode_indicator` in `crypto.rs`
  derives a degree-10 Lagrange polynomial over the 11-element opcode
  alphabet. Soundness: no witness gap. Cost: every opcode-gated
  constraint inherits degree 10.
  *Phase 3 constraint, now closed:* with `blowup_factor=16` (max
  constraint degree 16), the lookup argument has only 6 degrees of
  headroom before we have to double the blowup. The 2-day winterfell-
  vs-Plonky3 prototype landed 2026-05-05 (see Phase 3 §"Lookup-
  argument tooling" for results) and confirmed both candidate variants
  land at transition degree 2 — comfortably within the 6-degree budget
  with 4 degrees of slack. We're staying on `blowup_factor=16`.
- **`StarkProof.control_flow: Option<ControlFlowProof>` runtime opt-in
  instead of build-time `per_statement_air` feature flag.** Simpler,
  serialization-stable, and lets dogfooding happen per-call.
  *Phase 3 constraint, now mitigated:* `proof_version: u8` + verifier
  dispatch (open question Q5) was originally scheduled for Phase 4 but
  landed early so Phase 3 can ship a v2 shape without forcing every
  prior proof through a hard incompatibility. `CURRENT_PROOF_VERSION = 1`
  today; Phase 3 will add a v2 entry covering `memory_root_pre/post`.
- **5-row anti-pad to break subgroup even-symmetry.** Power-of-two
  padding to a multiplicative subgroup of size N can collapse a witness
  column to a degree-N/2 polynomial when the column happens to be
  even-symmetric (f(g^k) = f(g^(k+N/2))). The current anti-pad (Nop,
  IF, GoalEnter, IF, GoalExit with `goal_status=3`) is hand-tuned to
  break this for every shipping test trace, on the *current* witness
  columns.
  *Phase 3 constraint:* every new column added by Phase 3 (memory_root,
  path_hash, etc.) needs the same audit. If a Prove body emits no
  REMEMBER/RECALL, those columns are all-zero on real rows and the
  anti-pad won't drive variation. Implementer choice: extend the
  anti-pad (couples it to every column ever added) or split into
  per-statement-family AIRs (multi-AIR aggregation cost). Soundness
  review (Phase 5) must verify the chosen anti-pad doesn't open a
  forgery vector.

### Phase 3 — Memory commitment + REMEMBER/RECALL lookup ⏳

**Sub-phases 3a + 3b + 3c-runtime + 3c-AIR + 3d + 3e-aux-shape
shipped.** 3e-boundary, 3e-rootcarry, 3e-lookup-trace, 3e-lookup-table,
and 3f–3h still ahead — the remaining 3e sub-pieces (the actual lookup
argument) stay the highest schedule risk in the roadmap.
Implementation plan drafted 2026-05-06 in
[`phase3-implementation-plan.md`](phase3-implementation-plan.md) — that
doc walks the work in 8 sub-phases (3a–3h) against concrete file:line
anchors and includes the lookup-degree audit, the anti-pad extension
argument, and the v2 wire-format dispatch.

**Sub-phase 3a — memory commitment scheme ✅** (2026-05-06)

`src/runtime/memory_commit.rs` implements a sparse Merkle tree at
depth 256 over `Address = SHA-256(scope_byte || path_hash)`, with
SHA-256 internal nodes (matches `exec_log::hash`, no Blake3 dual-stack)
and a OnceLock-cached default-subtree root vector. Public surface:
`MemoryCommit { new, insert, remove, get, root, prove }`,
`InclusionProof::{verify, compute_root}`, plus
`RememberWitness`/`ForgetWitness` builders that the AIR-side lookup
prover (3e) will consume directly. 13 unit tests cover empty root,
inclusion roundtrip, non-membership, scope separation, REMEMBER /
FORGET roundtrip, tampered-witness rejection, and a 32-leaf
inclusion-at-depth-256 case. The full library suite stays green
(380 tests).

**Sub-phase 3b — v2 wire shape + envelope-integrity check ✅** (2026-05-06)

`StarkProof` grows `memory_root_pre`/`memory_root_post: [u8; 32]`
fields (`#[serde(default)]` for v1 backcompat); `CURRENT_PROOF_VERSION`
bumps to `2`. The verify dispatch grows a `2 => verify_proof_v2` arm
that currently mirrors v1 — the AIR doesn't bind the memory roots
yet, that lands in 3e. A new `StoredProof { proof, memory_root_pre,
memory_root_post }` wrapper carries the runtime-observed roots
alongside the StarkProof. `Statement::Prove` writes the same root
values into both the envelope and the wrapper (the empty-SMT root
returned by `memory_commit::empty_root()` for both pre and post,
until 3c wires a Context-level commit). `Statement::Reveal` asserts
the envelope's claimed roots match the wrapper's recorded roots
before invoking `verify_proof`.

What this gives us today is a stable wire shape and a guard against
post-Prove envelope tampering — not yet a binding between prover
claims and witness state, since both fields are written from the same
source. The actual "prover claim ↔ trace witness" attestation is C8
(lookup running product) inside the AIR, scheduled for 3e; 3b clears
the path so 3e doesn't need a second version bump. Test coverage: v1
dispatch still alive (forged-v1 envelope still verifies through the
v1 arm), v1 on-disk envelope still deserialises cleanly, fresh proofs
carry v2 + the empty-tree root (regression-asserted distinct from
`[0u8; 32]`), tampering with either pre or post root inside the
envelope causes Reveal to reject with a readable error.

**Sub-phase 3c-runtime — `from_context` + real pre/post roots ✅** (2026-05-06)

`MemoryCommit::from_context(&Context)` enumerates `working_variables`,
`session_variables`, and `long_term_backend.load(...)` into the SMT.
`Statement::Prove` now reads pre/post roots from this constructor
instead of `memory_commit::empty_root()`, so the envelope claims real
state. Shared scope is intentionally excluded (3a option a — RPC-
routed, outside the SMT); the AIR-side gating in 3e will mirror this.

Per option (Y, 2026-05-06), `Statement::Set` joins
REMEMBER/RECALL/FORGET in the memory selector. SET writes to
`working_variables` like `REMEMBER { scope: Working }`, so
`from_context` already attests SET-written values; the trace-side
selector in C7 (lands in 3d) counts 4 memory opcodes, not 3.
`Operands::Set { name_hash, value_hash }` carries no scope field
(`exec_log.rs:279-285`), so the trace builder will fill
`CFA_SCOPE_COL` with the constant `Working = 0` for SET rows.

Test coverage: 3 new `memory_commit` unit tests
(`from_context_empty_returns_empty_root`,
`from_context_reflects_set_and_remember_in_working`,
`from_context_excludes_shared_scope`) plus the renamed
`prove_emits_v2_envelope_with_set_induced_post_root` which now asserts
`pre == empty_root` and `post != empty_root` (was: both equal). Library
suite: 385 passing.

This is still not the in-AIR binding — the `mroot` column is not yet
emitted by the trace, and C8 doesn't exist. A malicious prover could
still hand-craft the StarkProof envelope with arbitrary `memory_root_*`
values; what stops that today is the runtime-side equality check in
`Statement::Reveal` (3b) plus the fact that the runtime computes those
values itself. The 3e lookup-running-product is what makes the claim
checkable from the proof bytes alone.

**Sub-phase 3c-AIR — memory-row witness columns ✅** (2026-05-06)

`ControlFlowAir`'s main segment grows from 5 to 9 columns. The four
new columns (`CFA_SCOPE_COL=5`, `CFA_PATH_COL=6`, `CFA_VALUE_COL=7`,
`CFA_MROOT_COL=8`) are populated for `Set`/`Remember`/`Recall`/
`Forget` rows by `LogTrace::from`; every other row keeps zeros.
Encoding choices that the table-side prover (3d/3e) must mirror:

- `scope` uses the 0-based `mem_scope_byte` (Working=0, Session=1,
  LongTerm=2, Shared=3) — aligned with `memory_commit::scope_byte`,
  *not* the 1-based `exec_log::scope_byte` used for canonical-bytes
  digest binding. The two namespaces stay deliberately distinct.
- `path` and `value` are the first 16 bytes of the source `Hash32`
  folded big-endian via `exec_log::fold_to_u128`. Lossy by ~64 bits
  vs. the source SHA-256; the 3e lookup argument's α/β randomization
  recovers the soundness margin.
- `Operands::Set` carries no scope field (`exec_log.rs:279-285`); the
  `From` impl injects `scope=0` (Working) per option (Y).
- `Operands::Forget` writes `value=0`, matching `EMPTY_LEAF` folding
  to 0 — without this, a FORGET row's `(scope,path,value)` lookup
  factor would miss the table side in 3e.

`mroot` stays zero throughout 3c-AIR. Sub-phase 3d wires
`MemoryCommit`'s running root through the prover into this column;
3e adds the auxiliary segment, the gated lookup running product (C8),
and the boundary assertions that bind `mroot[0] = memory_root_pre`
and `mroot[last] = memory_root_post`.

No constraint changes in 3c-AIR — the existing 6 transition
constraints (Phase 2) and 3 boundary assertions are untouched, so the
degree budget (max 11, blowup 16) is unchanged. Anti-pad memory
columns stay at zero; an extension that drives the future memory
selector off zero on at least one anti-pad row lands in sub-phase 3f
once the selector exists.

Test coverage: 7 new `exec_log::tests` covering `fold_to_u128`,
SET-row population, REMEMBER scope mapping across all four scopes,
RECALL parity with REMEMBER, FORGET zero-value invariant, and the
non-memory-row "all zeros" defence-in-depth check. Existing `Default`
test extended to assert all four new fields default to zero. Full
library suite: 392 passing (up from 385 after 3c-runtime).

**Sub-phase 3d — running mroot column populated by replay ✅** (2026-05-06)

`LogTrace::from_log_and_commit(log, starting_commit)` replays the log
against `starting_commit`, advancing the running SMT root for each
memory mutation and recording the *entering* root onto each row's
`CFA_MROOT_COL`. Boundary semantics (used by 3e):
- `rows[0].mroot == fold_to_u128(starting_commit.root())`. With
  `starting_commit = MemoryCommit::from_context(&ctx)` at Prove start,
  this is the folded `memory_root_pre`.
- After replay finishes, the running commit's root equals
  `memory_root_post`. Padding rows (which the 3e prover will need to
  carry the post-root) extend that value out to the trace end.
- Non-memory rows, RECALL rows, and any Shared-scope row pass the
  running root through unchanged — `apply_remember`/`apply_forget`
  return None for Shared and the replay only advances on a successful
  mutation.

`crypto::generate_control_flow_proof_with_commit(log, starting_commit,
claim)` is the new prover entry point; the original
`generate_control_flow_proof(log, claim)` stays as a witness-only
shim (mroot=0) for hand-built fuzz/test traces. `Statement::Prove` now
captures `commit_pre` once via `from_context`, derives `memory_root_pre`
from it, then moves the same commit into the proof generator — so the
trace's `mroot[0]` and the envelope's `memory_root_pre` come from the
same source by construction.

Witness only: no AIR constraint reads from the column yet. A tampering
prover can still build a trace whose `mroot` cells don't match the
running SMT — what stops that today remains the runtime equality
check in `Statement::Reveal` (3b) plus the fact that the runtime
itself supplies `commit_pre`. Sub-phase 3e adds the boundary
assertions binding `mroot[0]`/`mroot[last]` to the envelope and the
gated lookup running product (C8) that ties memory rows to the
table-side SMT mutations.

Refactor note: `LogTrace::From<&ExecutionLog>` and
`from_log_and_commit` now share `entry_witnesses` and
`entry_depth_delta` helpers — the row-level extraction logic
(opcode/branch/status/scope/path/value, depth delta) lives in one
place so the two constructors only differ in their `mroot` policy.

Test coverage: 7 new `exec_log::tests` for the replay
(empty-log/empty-commit, single-SET pre-root, two-SET advance,
RECALL no-advance, Shared no-advance, non-memory carry, From-default
mroot=0 regression). Library suite: 399 passing (up from 392 after
3c-AIR).

**Sub-phase 3e-aux-shape — multi-segment trace plumbing ✅** (2026-05-07)

`ControlFlowAir` switches from a single-segment `TraceTable<BaseElement>`
to a multi-segment trace: 9 main columns (unchanged) plus 1 auxiliary Z
column. The aux segment is committed *after* the main segment, so any
verifier randomness it consumes is post-commit — the soundness property
3e-lookup-trace will rely on. The entire lookup-running-product
machinery from `prototypes/lookup-bench/` is now applicable to this
AIR; what was missing was the trace-shape plumbing, and that's what
this sub-phase delivers.

Concrete shape:
- New `ControlFlowTrace { info: TraceInfo, main: ColMatrix<BaseElement> }`
  carries a multi-segment `TraceInfo` (`new_multi_segment(9, 1, 1, len,
  vec![])` — 9 main, 1 aux, 1 aux-randomness, no periodic columns).
  `TraceTable::new` always builds aux-width-0 info, which is mismatched
  with the AIR's aux-width-1 declaration; the custom impl is the
  minimal fix on the winterfell 0.13 trait surface.
- `ControlFlowAir::new` calls `AirContext::new_multi_segment` with main
  degrees `[11, 2, 4, 1, 10, 2]` (Phase 2, unchanged), aux degrees
  `[1]`, 3 main assertions, 1 aux assertion.
- `evaluate_aux_transition`: `result[0] = z_next - z_curr` (degree 1).
  Trivial. With `Z[0] = 1` boundary it pins Z to the constant 1.
- `get_aux_assertions`: `Assertion::single(0, 0, E::ONE)`.
- `ControlFlowProver::Trace = ControlFlowTrace`; `build_trace`
  assembles columns via `CFA_*_COL` indices into a `Vec<Vec<BaseElement>>`
  rather than the old closure-based `TraceTable::fill`. `build_aux_trace`
  returns `ColMatrix::new(vec![vec![E::ONE; n]])`.

Witness only — Z carries no information yet. 3e-rootcarry replaces
the aux transition with the gated mroot-carry recurrence
`(1 - is_mem(opcode)) * (mroot_next - mroot_curr) = 0` (degree 11);
3e-lookup-trace replaces it again with the running-product recurrence
gated on `is_mem` (degree 12 under the blowup-16 ceiling). Both fit
because the aux segment shape stays "one column, one transition" —
only the constraint body changes.

A subtle layout-invariant check landed alongside: `build_trace`
populates `main_columns[CFA_*_COL] = column` rather than relying on
the `vec![]` literal's positional ordering. If a future edit were to
drift the constants from the assembly, that would now panic at trace
construction (`vec![Vec::new(); CFA_NUM_COLS]` indexing) rather than
silently misroute a column to the wrong constraint.

Anti-pad rows still leave the new aux Z column at 1 (built unconditionally
in `build_aux_trace`); the row-level anti-pad extension that drives the
memory selector off zero on at least one row stays scheduled for 3f
once the selector exists.

Test coverage: no new tests — the existing 9 `crypto::tests`
control-flow proofs (round-trip, balanced goal, branch-IF binding,
opcode/branch/status/depth rejection, claim-tamper) all exercise the
multi-segment proving + verification path. Library suite: 399 passing
(unchanged from 3d — the trace-shape evolution carries no behavioral
delta yet).

Required work, per the deep-dive's §"Memory" and Phase 3 plan:

1. **Memory commitment scheme.** `src/runtime/context.rs:45–48` (the
   four-scope storage: Working/Session/LongTerm/Persistent) needs a
   `commit_root() -> [u8; 32]` and `prove_membership(path) -> MerkleProof`
   surface. Default candidate: sparse Merkle over (scope, path_hash) →
   value_hash; alternatives in §"Open questions" item 2.
2. **Lookup-argument tooling. ✅ Decision made 2026-05-05: winterfell
   auxiliary segments.** The 2-day prototype lives in
   [`prototypes/lookup-bench/`](../../prototypes/lookup-bench/).
   Headline:
   - All three variants (winterfell main-segment probe, winterfell
     aux-segment soundness-correct, Plonky3 single-AIR running product)
     land at transition degree 2, fitting the blowup-16 ceiling with 4
     degrees of slack after the Phase 2 selector. The degree-budget
     concern is closed.
   - The soundness-correct winterfell aux-segment variant landed in
     the same prototype iteration. Numbers at N=1024: 18.4 ms prove,
     44 KB proof, 421 µs verify. Cost over the main-segment probe is
     ~40 % prove, ~24 % proof size, ~19 % verify — the price of
     putting Z behind a verifier-supplied challenge. Acceptable.
   - vs Plonky3 at N=1024: aux-segment is ~15 % slower to prove but
     ~3.4× smaller proof and ~5.8× faster verify. For the expected
     "many verifications per proof" runtime profile, the verify-time
     advantage dominates.
   - Plonky3's LogUp gadget (`p3-lookup`) requires a custom multi-AIR
     prover that doesn't ship in `p3-uni-stark` — adds 1–2 engineer-
     weeks of plumbing on top of the Phase 3 work itself.
   - Implementer note: stock `TraceTable` always reports single-segment
     `TraceInfo`; a custom `Trace` impl (~30 LOC, see `LookupAuxTrace`
     in `prototypes/lookup-bench/src/winterfell_aux_lookup.rs`) is
     required to declare aux columns. Phase 3 lifts that wrapper
     verbatim.
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

- ~~Winterfell aux-segments vs Plonky3 port (deep dive Q1) — needs the
  prototype.~~ **Closed 2026-05-05** in favour of winterfell aux
  segments; see prototype results above.
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
- **Proof versioning. ✅** `StarkProof.proof_version: u8` + dispatch in
  `verify_proof` shipped ahead of Phase 3 (open question Q5 closed).
  `CURRENT_PROOF_VERSION = 1` today. Adding a Phase 3 shape is now a
  matter of bumping the constant and adding a `2 => verify_proof_v2(...)`
  arm; pre-v1 (unversioned) blobs hit the catch-all and are rejected
  with a readable error.
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
