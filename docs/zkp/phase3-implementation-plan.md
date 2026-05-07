# Phase 3 Implementation Plan — Memory Commitment + REMEMBER/RECALL/FORGET Lookup

**Status:** Drafted 2026-05-06
**Owner:** TBD
**Estimated effort:** 2.5–4 engineer-weeks (Phase 2 took 3; this is a touch larger).
**Sequencing:** First non-prereq Phase 3 work. Builds on the soundness-correct
aux-segment prototype at
[`prototypes/lookup-bench/src/winterfell_aux_lookup.rs`](../../prototypes/lookup-bench/src/winterfell_aux_lookup.rs).
The prototype's `LookupAuxAir`, `LookupAuxTrace`, and `LookupAuxProver`
are the templates for what lands here; the plan below is what makes
that template real against the runtime, statements, and proof shape
that already exist.

This is a per-implementer document. The roadmap-level summary lives in
[`STATUS.md`](STATUS.md) Phase 3; the deep-dive design context is in
[`01-per-statement-airs.md`](01-per-statement-airs.md). Read those
first if anything below is unclear.

## Context

Phase 2 (`security-hardening-1`, shipped 2026-04-30) attests **control
flow** — opcode validity, branch booleanity, goal-pair balance, claim
binding, depth recurrence — but treats **memory** as an opaque side
effect. A malicious or buggy interpreter that records a `RECALL` log
entry without actually consulting any committed state still produces a
verifying Phase 2 proof, because there is no constraint connecting the
log row's `path_hash` / `value_hash` to a real memory layout.

Phase 3 closes that gap by:

1. Committing the agent's long-term memory to a Merkle root.
2. Adding constraints that, on every `REMEMBER` / `RECALL` / `FORGET`
   row of the execution log, the row's `(scope, path_hash, value_hash)`
   is consistent with the committed root before/after that row.
3. Publishing `memory_root_pre` and `memory_root_post` as proof public
   inputs so the verifier can bind them to the agent's actual memory
   roots at the proof's start/end.

After this work lands, `Statement::Reveal` on a Phase 3 proof tells the
verifier: not just "the interpreter recorded these opcodes," but "the
recorded memory operations are consistent with this initial memory and
produced this final memory."

## What we're proving — before vs after

| Today (Phase 2) | After Phase 3 |
|---|---|
| Opcode set, branch booleanity, goal balance, claim binding, depth recurrence | All of those, **plus** memory-operation consistency |
| `Operands::Remember{path_hash, value_hash}` only bound by being in the log digest | `REMEMBER` rows additionally proven to update `memory_root` correctly |
| `RECALL` semantics: trust the prover wrote a real value into the log | `RECALL` rows proven against `memory_root_pre` (or post-write subtree if a same-Prove `REMEMBER` preceded) |
| Memory contents: no commitment | Memory contents committed; verifier checks roots match agent's actual roots |
| `StarkProof` v1 | `StarkProof` v2 (carries `memory_root_pre`/`memory_root_post`; v1 still verifies via dispatch) |

## Non-goals

- **Privacy of memory contents.** The Merkle root + selectively
  revealed leaves is the privacy guarantee. Unrevealed leaves stay
  hidden; this is *commitment*, not *zero-knowledge of memory*.
- **Cross-proof memory continuity.** Phase 3 binds `memory_root_pre` to
  the agent's actual root *at proof start*, but two consecutive Prove
  blocks are not yet linked end-to-end via a chain. That's a Phase 4/5
  concern.
- **Shared (registry) memory.** `MemoryScope::Shared` writes go through
  RPC (`src/runtime/eval.rs:868-872, 934-937`) and are out of scope for
  this phase — they need the capability lookup that Phase 4 ships.
  REMEMBER/RECALL/FORGET with `scope: Shared` continue to be
  log-recorded, but **do not enter the SMT**: 3a's
  `MemoryCommit::apply_remember`/`apply_forget` return `None` and skip
  the mutation entirely. The AIR (3e) consequently gates *both* C8
  (lookup) and C11 (root carry) on `scope ∈ {0,1,2}`, so a Shared row
  has no in-AIR memory binding — the runtime SMT is unchanged across
  it, and that fact is the integrity property. Phase 4's capability
  lookup is what eventually attests Shared writes; until then a Shared
  REMEMBER produces a verifying proof that does not claim anything
  about shared state, which is the honest answer.
- **WASM, CALL, DELEGATE memory effects.** Tools and remote calls can
  write to `Working` memory via interpreter side effects, but proving
  those writes is Phase 4 territory.

> **Note (option Y, decided 2026-05-06).** `Statement::Set` is *not* a
> non-goal — it joins REMEMBER/RECALL/FORGET in the memory selector.
> SET writes to `working_variables` exactly like
> `REMEMBER { scope: Working }`; treating it as anything else creates a
> divergence between the runtime SMT (which sees SET-written values via
> `from_context`) and the AIR's `mroot` column (which would skip SET
> rows). C7 therefore counts 4 memory opcodes, not 3. SET's scope is a
> compile-time constant (`Working = 0`); the trace builder fills
> `CFA_SCOPE_COL` from the constant rather than from an `Operands::Set`
> field, since `Operands::Set { name_hash, value_hash }` carries no
> scope (`exec_log.rs:279-285`).

## Detailed design

### 1. Memory commitment scheme

**Choice: sparse Merkle tree (SMT), addressed by
`SHA256(scope_byte || path_hash) → value_hash`, depth 256, SHA-256
nodes.** Locked-in by sub-phase 3a (`src/runtime/memory_commit.rs`).

Rationale:
- The `Hash32` already used in `Operands::Remember{path_hash}`
  (`src/runtime/exec_log.rs`) is `ring::digest::SHA256` of the path
  string — see `exec_log::hash`. The SMT reuses the same hash so
  `Operands::Remember.path_hash` flows into `address_of(scope, path)`
  with no recanonicalisation step.
- Sparse so that empty-memory roots and incremental updates are cheap.
  The default-subtree trick (precomputed empty subtree roots per
  depth, cached in `empty_subtree_roots()`) keeps an update O(256)
  Merkle hashes regardless of memory size.
- SHA-256 inside the AIR is *not* required at this phase — Phase 3
  binds memory operations via lookup, not by re-executing Merkle hashes
  inside the circuit. SHA-256-in-AIR is item #2 in the roadmap; if it
  lands, it natively matches what 3a chose. (The earlier draft of this
  plan called for Blake3 nodes; the 3a implementer chose SHA-256 to
  avoid a dual-hash dependency with `exec_log::hash`.)

**Address encoding.** `address_of(scope, path_hash) =
SHA256(scope_byte || path_hash)` where `scope_byte ∈ {0=Working,
1=Session, 2=LongTerm, 3=Shared}`. Folding the scope byte into the
*address* (rather than the leaf) means same `path_hash` across scopes
maps to distinct 256-bit addresses with collision resistance ≈ 2^128 —
sufficient to rule out scope-confusion attacks without carrying scope
as a separate column on every leaf.

**Leaf encoding.** A leaf is the raw `value_hash: Hash32` carried in
the log row (`Operands::Remember.value_hash`). The earlier draft of
this plan re-hashed `(scope, value_postcard)` into the leaf to escape
the log's `format!("{:?}", val.value)` debug-encoding — but since the
*address* now folds scope in, the leaf only needs to bind `value_hash`
to itself, and the log's existing hash can be reused. The
debug-encoding canonicalisation issue (open question 1) is now
exclusively about hardening `Operands::*.value_hash` against
representation drift, independent of the SMT's leaf shape. Empty slot
→ all-zero leaf hash (`EMPTY_LEAF`).

**Surface (shipped in 3a).** Module `src/runtime/memory_commit.rs`:

```rust
pub fn empty_root() -> Hash32;          // helper — empty *tree* root
pub fn address_of(scope: MemoryScope, path_hash: &Hash32) -> Address;

pub struct MemoryCommit { leaves: BTreeMap<Address, Hash32> }

impl MemoryCommit {
    pub fn new() -> Self;
    pub fn root(&self) -> Hash32;
    pub fn prove(&self, addr: Address) -> InclusionProof;
    // Returns None for MemoryScope::Shared — shared writes are RPC-routed
    // and intentionally live outside the SMT (see §"Non-goals").
    pub fn apply_remember(&mut self, scope: MemoryScope, path: &Hash32, value: Hash32)
        -> Option<RememberWitness>;
    pub fn apply_forget(&mut self, scope: MemoryScope, path: &Hash32)
        -> Option<ForgetWitness>;
}
```

Not yet shipped (deferred to 3c): `MemoryCommit::from_context(ctx) ->
Self`. Today every Prove block constructs an empty `MemoryCommit::new()`;
3c will replace that with a constructor that enumerates the
Working/Session/LongTerm scopes from `Context`. Until then the SMT only
sees writes that happen *inside* the Prove block.

Per option (Y), `from_context` enumerates `working_variables` (which
holds both REMEMBER-into-Working *and* SET-written values — they share
the same map at `context.rs:46`). The constructor doesn't distinguish
how a value got there; the AIR's selector C7 covers both opcodes
independently.

Touchpoints in the existing tree:

- `src/runtime/context.rs:45-58` — `Context` adds
  `pub memory_commit: Arc<Mutex<MemoryCommit>>`. Initialised in
  `Context::new`; eagerly rebuilt from `working_variables`,
  `session_variables`, `long_term_backend.load(...)` on first use.
- `src/runtime/memory.rs:121` `MemoryBackend` — no change. The commit
  reads through the existing trait.
- The commit is **rebuilt per Prove block**, not maintained
  incrementally across the whole runtime. Reason: scope ownership
  semantics for Working/Session memory mean the commit's "current"
  state is naturally per-Prove-execution. An incremental cache is a
  later optimisation.

### 2. Trace shape — extending `ControlFlowAir`

`ControlFlowAir` (`src/crypto.rs:577-675`) keeps its existing 5 main
columns:

```
[CFA_OPCODE_COL, CFA_BRANCH_COL, CFA_STATUS_COL, CFA_CLAIM_COL, CFA_DEPTH_COL]
```

We **add** to the main segment:

| New column | Purpose | Source |
|---|---|---|
| `CFA_SCOPE_COL` | scope ∈ {0=Working, 1=Session, 2=LongTerm, 3=Shared, 4=N/A} | `Operands::Remember/Recall/Forget.scope`; `Set` rows use the constant `0=Working` |
| `CFA_PATH_COL` | path_hash folded to BaseElement | `Operands::Set.name_hash` (SET) / `Operands::Remember/Recall/Forget.path_hash` |
| `CFA_VALUE_COL` | value_hash folded to BaseElement | `Operands::Set.value_hash` (SET) / `Operands::Remember/Recall.value_hash`; FORGET rows use `EMPTY_LEAF` |
| `CFA_MROOT_COL` | running memory root (folded to BaseElement) | derived from `MemoryCommit::root()` after each row |

**Folding.** A `Hash32` is 256 bits; `BaseElement` (winterfell's
`f128`) is 128 bits. Use the same `fold_to_u64` style already in
`crypto.rs:328-332` but two-element: `(hi64, lo64)` pair stored across
two columns, or single-column `fold_to_u128`. **Recommendation:** start
with `fold_to_u128` (lossy but cheap; 64 bits of collision resistance
on hash binding). The lookup argument's α/β randomization buys back the
soundness margin — `α·path + β·value` collision-finds at the field
level, not the hash level. Document explicitly in `crypto.rs` as the
collision-resistance budget for Phase 3 (calls for SHA-256-in-AIR /
field upgrade in the future).

We **add** an aux segment:

| Aux column | Purpose |
|---|---|
| `CFA_AUX_Z_COL` | running product Z over memory-touching rows |

Aux randomness: 2 elements `(α, β)` drawn from the public coin after
main commitment, exactly as the prototype's `LookupAuxAir`.

### 3. Constraint catalog (delta from Phase 2)

Phase 2's six transition constraints (`crypto.rs:631-669`) all stay.
Phase 3 adds:

**C7 — Memory-row indicator selector.** Define
`is_mem(opcode) = I_SET(opcode) + I_REM(opcode) + I_RECALL(opcode) + I_FORGET(opcode)`,
where each `I_*` is the Lagrange indicator over the 11-opcode alphabet
(same construction as `opcode_indicator` at `crypto.rs:692`). Degree 10.

SET joins the selector per option (Y) — it is a Working-scope memory
write whose effect on the SMT (visible through `from_context`) must
agree with what the lookup running product attests.

**C8 — Lookup running product (aux segment, gated).** On every
memory row, the running product advances by the `(scope, path, value)`
factor; on every non-memory row, Z carries unchanged.

```text
result[7] = is_mem(opcode_curr) * (
    Z_next * trace_factor − Z_curr * table_factor
) + (1 − is_mem(opcode_curr)) * (
    Z_next − Z_curr
)
```

where `trace_factor = scope + α·path + α²·value + β` and `table_factor`
is supplied by a per-row periodic column built from the memory commit's
witnessed (key, value) pairs in row order. **Degree:** `10 (selector)
× 2 (running-product transition) = 20`. Combined with the running-
product-only branch (degree 2) the max is 20. **This breaks the
blowup-16 ceiling.** See §"Anti-pad and degree-budget audit" for the
fix.

**C9 — Boundary: Z[0] = 1.** Aux assertion at row 0 (matches
prototype's `get_aux_assertions`).

**C10 — Boundary: memory_root carry.** Main-segment assertions:
`CFA_MROOT_COL[0] = memory_root_pre`,
`CFA_MROOT_COL[last_real_row] = memory_root_post`. The "last real row"
must be derivable from the trace shape; either reserve a sentinel
opcode for the closing row or use the existing 5-row anti-pad's last
real row index. Recommend the latter (no new sentinel needed).

**C11 — Memory-root carry transition.** On memory rows, the root
*can* change; on non-memory rows it must not:

```text
result[10] = (1 − is_mem(opcode_curr)) * (mroot_next − mroot_curr)
```

Degree 10 × 1 = 10. Fits. The *correct* transition on memory rows
isn't constrained by C11 alone — that's what the lookup running
product attests to: the lookup table the table_factor reads from is
keyed by (scope, path, value, mroot_pre, mroot_post), and the table
itself is the prover's witness Merkle path. C11 just rules out
modifying the root on a non-memory row.

### 4. Degree-budget audit and the gating-degree fix

The prototype measured the ungated lookup transition at degree 2. With
the Phase 2 Lagrange selector (degree 10), the gated form is
`10 + 2 = 12`, fitting blowup-16 with 4 degrees of slack.

**But C8 above is degree 20.** The reason: I wrote it as
`selector × Δ_active + (1−selector) × Δ_inactive`, which multiplies
both branches by the selector factor. The correct form is to *only*
multiply the active branch — the inactive branch (`Z_next - Z_curr`) is
already degree 1 unconstrained, and the selector-gating is what makes
the *combined* constraint vanish on non-memory rows.

Restated:

```text
result[7]_v2 = Z_next * inactive_or_table − Z_curr * inactive_or_factor
```

where
```text
inactive_or_table  = is_mem * table_factor + (1 − is_mem) * 1
inactive_or_factor = is_mem * trace_factor + (1 − is_mem) * 1
```

`is_mem` is degree 10; `table_factor` and `trace_factor` are degree 1
each. So `inactive_or_*` is degree 11. The full transition is
`Z * deg11 − Z * deg11 = deg 12`. **Slack: 4 degrees on blowup-16.
Matches the prototype's measurement. Phase 3 viable.**

This is the load-bearing trick from the prototype README's degree
budget — write it out fully here so the implementer doesn't accidentally
re-derive a degree-20 form. The same pattern applies if Phase 3+
adds more conditional sub-constraints.

### 5. Anti-pad audit (forward constraint #3 from prereqs)

The 5-row anti-pad in `crypto.rs::ControlFlowProver::build_trace`
(`crypto.rs:692-`) was designed to break subgroup even-symmetry on
the *current* witness columns. Adding `CFA_SCOPE_COL`, `CFA_PATH_COL`,
`CFA_VALUE_COL`, `CFA_MROOT_COL`, and the aux `Z` column means the
anti-pad must drive variation on each of those new columns *or* a Prove
body with zero memory operations would leave them all-zero on the real
rows, collapsing to the same degeneracy that motivated the anti-pad.

**Required anti-pad extension** (drop into `build_trace`'s anti-pad
constructor):

- Append a `REMEMBER` anti-row with synthetic `(scope=Working,
  path=ANTIPAD_PATH, value=ANTIPAD_VALUE)` and a `mroot` value taken
  from the Merkle path of an empty subtree. Choose `ANTIPAD_PATH` /
  `ANTIPAD_VALUE` to be field elements that are not in the legitimate
  memory commit (e.g. `path = BaseElement::new(0xDEAD)`). The lookup
  running product Z must update on this row, and the anti-row's lookup
  factor must be in the periodic table (so soundness is preserved).
  This means the prover *also* has to commit the anti-row's
  `(scope, path, value)` into the memory commitment witness table. The
  cost is one extra Merkle witness per Prove block.
- Append a matching `FORGET` anti-row to undo the REMEMBER. Z[final]
  then closes back to its pre-anti-pad value. Without this, the aux
  boundary assertion changes per-trace and the verifier can't predict
  the closing Z (which would force a public-input bump and is an
  ergonomic regression — keep Z[final] = product_of_real_factors).
- The existing 5-row anti-pad becomes 7 rows (Nop, IF, GoalEnter, IF,
  GoalExit, REMEMBER, FORGET). The IF/Goal anti-rows still drive the
  Phase 2 columns; the new REMEMBER/FORGET anti-rows drive the Phase 3
  columns. Document in a comment block at the construction site.

**Soundness verification (Phase 5 audit item):** confirm that no
malicious prover can match the anti-row's `(scope, path, value, mroot)`
pattern with a non-anti-pad row. The path-element collision space is
~95 bits after folding to BaseElement, which is well above the
~80-bit security target. The implementer should add a unit test that
attempts to forge such a collision and expects failure.

### 6. Public-input changes — `StarkProof` v2

`CURRENT_PROOF_VERSION` (`crypto.rs:289`) bumps from `1` to `2`. The
v1 verifier (`verify_proof_v1` at `:457`) stays as-is — v1 proofs
generated before Phase 3 must continue to verify. Add `verify_proof_v2`
behind a `2 => verify_proof_v2(...)` arm in `verify_proof`'s match
(`:447`).

`StarkProof` (`:292`) gains:

```rust
#[serde(default)]
pub memory_root_pre: [u8; 32],
#[serde(default)]
pub memory_root_post: [u8; 32],
```

`#[serde(default)]` ensures v1 blobs still deserialize (those fields
default to all-zero). The v2 path then enforces non-default values; v1
path ignores them.

**No changes to `ControlFlowProof`** (`crypto.rs:882`) — the new
columns and aux segment are *fields of the Phase 2 control-flow trace*,
not a sibling proof. Keep one envelope.

The verifier (in `Statement::Reveal`, `eval.rs:1156`) compares the
proof's `memory_root_pre` against
`MemoryCommit::from_context(ctx).root()` *as recorded at the matching
Prove site*. Because Reveal can run after arbitrary intervening
statements, we need to record the pre/post roots at Prove time and
keep them alongside the proof in `Context::proofs`. New struct:

```rust
pub struct StoredProof {
    pub proof: StarkProof,
    pub memory_root_pre: Hash32,
    pub memory_root_post: Hash32,
}
```

Replaces `Context::proofs: HashMap<String, StarkProof>` at
`context.rs:57`. Reveal's verification then asserts
`stored.memory_root_pre == proof.memory_root_pre` and
`stored.memory_root_post == proof.memory_root_post`. Without this
binding, the prover-side roots would be unconstrained against runtime
truth.

### 7. Integration touchpoints (file:line punch list)

The implementer should be able to walk these in order:

1. **`src/runtime/memory_commit.rs` (new)** — `MemoryCommit`,
   `InclusionProof`, witness-builder helpers.
2. **`src/runtime/context.rs:45-58`** — add `memory_commit:
   Arc<Mutex<MemoryCommit>>` field to `Context`; init in
   `Context::new`; rebuild on Prove entry.
3. **`src/runtime/context.rs:57`** — `proofs` becomes `HashMap<String,
   StoredProof>`.
4. **`src/runtime/eval.rs:1105-1154`** — `Statement::Prove`:
   - Capture `memory_root_pre` before the inner statements run.
   - After the inner loop, capture `memory_root_post`.
   - Pass both into `crypto::generate_proof` (signature gains
     `(memory_root_pre, memory_root_post)`).
   - Store the `StoredProof` in `ctx.proofs`.
5. **`src/runtime/eval.rs:381, 861, 923, 992`** — `Statement::Set`,
   `::Remember`, `::Recall`, `::Forget`: after the existing
   `record_log(...)` call, additionally call
   `ctx.memory_commit.lock().apply_*(...)` so the running commit
   reflects each operation. SET reuses `apply_remember` with
   `scope=Working` (option Y). The witness `Operands::*` already
   carries the right hashes — no log change required for the
   v1-incompatible value-hash canonicalization unless we choose to do
   it (see §"Open questions").
6. **`src/crypto.rs:577-675`** — `ControlFlowAir`:
   - Add 4 new main-segment columns + 1 aux column to the `TraceInfo`.
   - Switch from `AirContext::new` (single-segment) to
     `AirContext::new_multi_segment`.
   - Add C7, C8 (gated lookup), C11 (root carry) to
     `evaluate_transition` / new `evaluate_aux_transition`.
   - Add C9 (Z[0]=1) to `get_aux_assertions`.
   - Add C10 (mroot pre/post) to `get_assertions`.
7. **`src/crypto.rs:677-`** — `ControlFlowProver`:
   - `build_trace` populates the 4 new main columns from the log
     entries' operands.
   - Implement `build_aux_trace` exactly like the prototype
     (`prototypes/lookup-bench/src/winterfell_aux_lookup.rs`'s
     `LookupAuxProver::build_aux_trace`), using the witness Merkle
     paths to drive the table side of the running product.
   - Replace the stock `TraceTable` with a custom `Trace` impl
     analogous to `LookupAuxTrace` in the prototype. Required because
     `TraceTable` always reports single-segment `TraceInfo` — see the
     prototype's documentation for the failure mode.
8. **`src/crypto.rs:289`** — bump `CURRENT_PROOF_VERSION` to 2.
9. **`src/crypto.rs:292-326`** — add `memory_root_pre`,
   `memory_root_post` to `StarkProof`.
10. **`src/crypto.rs:446-455`** — add `2 => verify_proof_v2(...)` arm;
    write `verify_proof_v2` (mostly mirrors v1 but threads the new
    public inputs).
11. **`src/runtime/eval.rs:1156`** — `Statement::Reveal`: assert
    `stored.memory_root_pre == proof.memory_root_pre` and
    `stored.memory_root_post == proof.memory_root_post`.

### 8. Test plan (lands alongside the implementation)

Three layers:

**Unit tests in `src/runtime/memory_commit.rs`:**
- Empty commit's root matches the all-zero default-subtree precompute.
- `apply_remember` then `prove_inclusion` round-trips for the same key.
- `apply_forget` returns a witness that verifies against pre/post
  roots.

**Property tests in `tests/phase3_memory.rs` (new):**
- Random sequence of REMEMBER/RECALL/FORGET operations: prove +
  verify always succeeds.
- For 10K random Prove blocks, verify Phase 3 proof iff a reference
  in-process simulator agrees on the post-root.

**Negative tests in `tests/phase3_tampering.rs` (new):**
- Tamper with a `value_hash` in the log mid-Prove → prove succeeds
  (the prover doesn't refuse), verify fails (the lookup running product
  closes to ≠ 1).
- Tamper with `memory_root_post` in the published proof → verify
  fails on the Reveal-side root match.
- Submit a v1 proof to the v2 verifier-dispatch → returns the v1 path
  unchanged (regression guard for proof_version dispatch).

**End-to-end in `tests/per_statement_e2e.rs` (extend):**
- Prove block with REMEMBER + same-block RECALL → both verify.
- Prove block whose `Statement::Reveal` runs after intervening
  `Statement::Forget` of an unrelated key → still verifies (pre/post
  roots are *the Prove-time* roots, not Reveal-time).

## Phased delivery (within Phase 3)

| Sub-phase | Scope | Days |
|---|---|---|
| 3a | `MemoryCommit` module + unit tests ✅ | 2 |
| 3b | `StoredProof` + `proof_version=2` wire shape + dispatch ✅ | 1 |
| 3c-runtime | `MemoryCommit::from_context` + Prove pre/post roots reflect real Context state (no AIR change) | 1 |
| 3c | Trace shape extension (4 new main columns + aux Z) — no constraints yet | 2 |
| 3d | C7 selector + C11 root-carry + C9/C10 boundaries — Phase 2 still passes | 2 |
| 3e | Aux segment + C8 gated lookup running product | 3 |
| 3f | Anti-pad extension + symmetry audit unit test | 1 |
| 3g | Negative tampering tests + property fuzz | 2 |
| 3h | Reveal-side root binding + end-to-end | 1 |

Each sub-phase ends in a green `cargo test` run. Sub-phases 3a–3d
land *without* changing proof semantics — they widen the trace and
plumb wire format, but the Z column is constant 1. Sub-phase 3e is
where the lookup soundness comes online; 3g is where we *prove* it
came online by failing forged proofs.

## Alternatives considered

**A. Per-statement-family AIRs (one AIR per opcode kind).** Rejected
for Phase 3. The forward-looking note in
`memory/zkp_phase3_constraints.md` lists this as an alternative to
extending the anti-pad. It would need a multi-AIR aggregation
infrastructure (Plonky3's strength, winterfell's not). 1–2 weeks of
plumbing on top of the Phase 3 work itself, with the same final
soundness guarantee. Defer to Phase 6+ if the unified AIR's anti-pad
audit becomes a recurring toil.

**B. Schwartz-Zippel hash-chain (no Merkle commitment).** Treat
memory as a running hash `H_next = SHA(H_curr || op_bytes)`. Cheap to
constrain (degree-1 hash recurrence in-AIR is just XOR/AND, which
SHA-256-in-AIR will eventually give us), but RECALL would have to
re-execute the hash chain to prove a value was ever written, which is
O(n) per RECALL instead of O(log n). Rejected on access-pattern
asymmetry alone.

**C. Dense Merkle (vs sparse).** Empty-memory programs would still
pay the full tree cost. Rejected; sparse with default-subtree
precompute is strictly better.

**D. LogUp instead of running-product.** The 2026-05-05 prototype
showed LogUp on Plonky3 needs a custom multi-AIR prover (1–2 weeks
plumbing) and at single-AIR scale the running product wins on every
metric. Rejected; revisit if the 8-week Phase 5 benchmark gate fails.

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| **Lookup degree blows past 12 once gating is right.** Sub-phase 3e is the first time we land C8 in production code; the prototype is single-purpose. | Low (same algebraic shape). | Sub-phase 3e ends with `cargo run --release --bin winterfell_aux_lookup`-style measurement against the production AIR. If degree > 12, escalate to selector-column refactor or blowup-32. |
| **Anti-pad symmetry audit fails (post-Phase 3 columns collapse on empty-Prove)** — same failure pattern that motivated the Slice 7 fix in Phase 2. | Medium. | Sub-phase 3f is *gated* on a unit test that synthesises the all-zero-memory empty-Prove case and asserts the trace polynomial doesn't collapse. Test must pass before merging. |
| **Sparse Merkle implementation gets the default-subtree precompute wrong** (off-by-one between leaf depth and root depth is the classic bug). | Medium. | Sub-phase 3a's unit tests include a known-answer test against an independent SMT reference (e.g. `sparse-merkle-tree` crate's vectors) before any AIR work begins. |
| **Memory-root-binding doesn't match runtime truth** at Prove time because of intervening tokio task lifetimes (the REMEMBER `expires` background task at `eval.rs:885-919` mutates memory). | Low (the background task fires *after* the Prove block returns). | Document as a known soundness boundary; add a regression test that schedules a same-Prove-block `expires` and verifies the post-root reflects the value present *at Prove return*, not after the timer fires. |
| **`fold_to_u128` collision-resistance is below threshold** for high-stakes proofs. | Acknowledged. | Document the 64-bit collision-finding cost in `crypto.rs` and gate the upgrade on item #2 (SHA-256-in-AIR) landing — at which point we move to a 256-bit field commitment naturally. |

## Rollout plan

Phase 3 ships behind the existing `proof_version` dispatch — there is
no runtime feature flag. The transition is:

1. **Pre-merge:** all v1 proofs in any persisted store still verify
   under v2's `verify_proof_v1` arm. Add a regression test that loads a
   committed-to-disk v1 proof fixture and asserts the new verifier
   accepts it.
2. **Merge:** new Prove blocks emit v2 proofs (with the new
   memory_root_pre/post fields). Existing reveal flows for v1 proofs
   continue to use the v1 path.
3. **N weeks of dogfooding:** every internal AgentLang invocation
   produces v2 proofs and verifies them. Monitor for proving-time
   regressions vs the Phase 2 baseline (target: <30s for a 20-statement
   Goal, per the Phase 5 benchmark gate).
4. **Default-on:** v1 path remains compiled in but emits a deprecation
   log; eventual removal sequenced behind a v3 introduction.

No env vars, no config flags. The proof_version field is the rollout
mechanism, and it already exists.

## Verification plan

How we know Phase 3 actually works:

1. **All Phase 2 tests still green.** `cargo test --workspace` continues
   to pass; the Phase 2 trace (no memory operations) produces a v2 proof
   whose memory_root_pre == memory_root_post == empty-subtree-root.
2. **Phase 3 unit tests** (per §"Test plan").
3. **Phase 3 negative tests:** tamper-a-value-hash, tamper-a-root,
   and submit-malformed-version all fail loudly.
4. **Property fuzz** at 10K random Prove blocks (degenerate cases,
   max-Remember count up to runtime memory limits, mixed scopes). One
   property: "verify iff in-process simulator agrees."
5. **Benchmark gate.** A representative 20-statement Goal proves in
   <30s on the reference machine. If exceeded, either the lookup
   shape is wrong or the SMT depth needs trimming. Re-open the Phase 3
   §"Lookup-argument tooling" decision.
6. **External soundness review** as part of Phase 5. Phase 3 contributes
   the constraint catalog (§"Constraint catalog (delta from Phase 2)"),
   the anti-pad symmetry argument (§"Anti-pad audit"), and the
   lookup-degree budget (§"Degree-budget audit"). All three are
   audit-targets.

## Open questions

1. **Canonicalize `value_hash` in the log to postcard?** Today
   (`eval.rs:386, 879, 968, 981`) it's `SHA-256(format!("{:?}", val.value))`,
   which is debug-format-dependent. Affects all four memory opcodes
   (SET joined per option Y) plus `from_context`'s leaf-encoding.
   Phase 3 wants the same hashing to bind into the Merkle leaf, where
   stability matters. **Recommend:** take the one-time incompatibility
   now, in the v2 envelope. v1 proofs are unaffected (their value_hash
   is opaque to the v1 verifier); v2 proofs use the new canonicalization.
   Marks v1↔v2 as semantically distinct, which is honest.
2. **One folded `mroot` column or two `(hi64, lo64)` columns?** Single
   column is simpler; two columns gives full 128-bit collision
   resistance against Phase-3-only attacks. **Recommend:** single
   column for sub-phase 3c; revisit if the soundness review flags it.
3. ~~**`Shared` scope: warn or silently no-op?**~~ **Closed
   2026-05-06.** Decision: silent no-op at the SMT level. 3a's
   `apply_remember`/`apply_forget` return `None` for `MemoryScope::Shared`
   so the SMT stays unchanged across Shared rows; the AIR (3e) gates
   both C8 and C11 on `scope ∈ {0,1,2}`. A `verify_proof_v2`-side
   warning was considered and rejected as ergonomically weak — the
   honest signal is that v2 proofs simply don't attest to Shared
   writes, full stop, and Phase 4's capability lookup is the
   attestation that does. Updating §"Non-goals" Shared paragraph to
   match.
4. **Are `expires`-driven background removals (`eval.rs:885-919`) in
   scope?** Per the risk register, currently no — the post-root reflects
   *Prove return* state. If a future test surfaces an audit-chain
   inconsistency between log timeline and memory timeline, revisit.
