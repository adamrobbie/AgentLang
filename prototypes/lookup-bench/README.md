# Lookup-argument Tooling Prototype

A 2-day spike to decide between **winterfell auxiliary segments** and a
**Plonky3 port** for the lookup machinery Phase 3 of the per-statement-AIR
roadmap needs (memory commitment + REMEMBER/RECALL lookup).

This is research, not production code. It lives outside the main crate so
it can pull in heavy ZK deps (Plonky3) without affecting build times for
the rest of AgentLang. Findings get written up in §"Results" below and
folded back into [`docs/zkp/STATUS.md`](../../docs/zkp/STATUS.md) when
the prototype concludes.

## Why this matters

Phase 2 chose Lagrange opcode indicators (max degree 10) over selector
columns (max degree 2). With `blowup_factor = 16`, the constraint-degree
ceiling is 16 — which leaves only **6 degrees of headroom** for any
opcode-gated Phase 3 lookup constraint before we have to bump the blowup
to 32 (doubling FFT cost).

So this prototype isn't just an API-ergonomics probe (the original
framing). The gating measurement is the **lookup-argument's own
constraint degree** when the gate is folded with our existing degree-10
selector. If a candidate's lookup adds degree ≥ 7 on top of the selector,
that variant is non-viable on the current blowup. The user's project
memory at `memory/zkp_phase3_constraints.md` calls this out explicitly.

## Toy problem

Both implementations attest the same statement, so measurements are
comparable.

> Given a witness trace `T` with two columns `key`, `value` of length
> `N`, and a public lookup table `M` with `N` entries, prove that the
> trace's `(key, value)` rows are a permutation of `M`'s rows — i.e.
> every "memory read" on the trace was of a real "memory write" in `M`.

This is the simplest non-trivial shape that mirrors what Phase 3 needs
for `RECALL`: each recalled `(scope, path_hash, value_hash)` row must
appear in the memory commitment's leaves.

We sweep `N ∈ {64, 256, 1024, 4096}`. The minimum is 64 because
winterfell's DEEP composer asserts `trace_poly.degree() == N − 1`, and
power-of-two-friendly trace shapes only stabilise at moderate sizes
(very small traces like `N = 8` hit the assertion's edge). The 1024-row
case is the one that maps to a typical Phase 3 Prove body.

For the prototype both columns are `BaseElement` field elements; the
"hash" framing is dropped to keep the trace honest. A real Phase 3 AIR
would use a Merkle proof rather than a flat lookup, but the underlying
machinery (auxiliary segment + Z-column or its equivalent) is the same.

## What we're measuring

| Metric | Why |
|---|---|
| **Max constraint degree** | The gate. ≥ 7 on top of selector kills the variant on blowup 16. Reported as the AIR's declared transition degree, plus a manual cross-check against the actual transition polynomial shape. |
| Prove time, 64-row trace | Sanity. Should be sub-10ms on either side. |
| Prove time, 1024-row trace | Real. This is the regime where the FFT cost shows up. |
| Proof size | Operator concern; cheap to measure. |
| Verify time | Should be roughly constant per AIR; useful sanity. |
| Lines of AIR code | Rough proxy for ergonomics. Subjective; counts the AIR struct + its `evaluate_transition` + lookup setup, excluding boilerplate. |

Measurements are taken with `cargo run --release` and `std::time::Instant`
(no criterion — overkill for this spike). Each variant runs the prove
loop 5 times and reports min / median / max.

## Variants

### A. Winterfell main-segment running-product (degree probe)

Pattern: declare an extra main-trace column `Z` with running product
`Z[i+1] · trace_factor[i] = Z[i] · table_factor[i]`, where
`trace_factor[i] = T.key[i] + α · T.value[i] + β` and the table factor
is read from a length-`N` periodic column. `Z[0] = 1`, and
multiset equality is implied if the trace and table are permutations.

**Important caveat on soundness.** The shipped variant derives `α`, `β`
from the public table rather than from main-trace commitment randomness,
so a malicious prover *could* grind a satisfying trace. This is fine for
this iteration's purpose — we are measuring the constraint degree of
the running-product transition, which is the same regardless of where
the challenges come from. The soundness-correct version (auxiliary
trace segment + verifier-supplied randomness) is the next iteration and
will not change the headline degree number.

Implemented in [`src/winterfell_lookup.rs`](src/winterfell_lookup.rs).

### B. Plonky3 running-product (single-AIR via `p3-uni-stark`)

The original framing here was "Plonky3 LogUp gadget", but landing the
prototype surfaced a structural issue: as of `p3-lookup = 0.5.2`,
LogUp ships as a constraint-evaluation **gadget** that hooks into
`PermutationAirBuilder`, not a drop-in prover. The single-AIR prover
(`p3-uni-stark`) doesn't expose permutation challenges, and the
multi-AIR provers that do (SP1, Valida, etc.) each maintain their own
custom-built infrastructure rather than shipping a reusable one.

So the prototype implements the **same running-product trick** as
variant A, but in `p3-air` against `p3-uni-stark`. This gives a true
apples-to-apples comparison of the two AIR DSLs and the two FRI
backends. The headline number we *don't* get is "what does Plonky3
LogUp cost end-to-end" — that's a 1–2 week engineering item on its
own (custom multi-AIR prover plumbing) and is captured in the
§Decision below.

Implemented in [`src/plonky3_lookup.rs`](src/plonky3_lookup.rs).

## Running

```sh
cargo run --release --bin winterfell_lookup
cargo run --release --bin plonky3_lookup
```

Each prints a measurement table to stdout. Numbers go in §"Results" by
hand — auto-generating them is out of scope for a spike.

## Results

Captured 2026-05-05 on the user's reference machine (Apple silicon,
release build, median of 5 prove runs).

| Variant | Transition degree | Prove (N=64) | Prove (N=1024) | Prove (N=4096) | Proof size (N=1024) | Verify (N=1024) | LOC (file) |
|---|---|---|---|---|---|---|---|
| Winterfell running product (main segment, `f128`) | **2** | 0.88 ms | 13.16 ms | 57.93 ms | 35,955 B | 354 µs | 370 |
| Winterfell running product (aux segment, soundness-correct) | **2** | 0.99 ms | 18.38 ms | 84.51 ms | 44,569 B | 421 µs | 425 |
| Plonky3 running product (`p3-uni-stark`, BabyBear) | **2** | 1.44 ms | 15.95 ms | 65.82 ms | 150,306 B | 2.43 ms | 337 |

**Headline degree-budget verdict.** Both variants land at transition
degree 2. With the Phase 2 Lagrange opcode selector contributing
degree 10, the gated lookup transition is degree **12** in either
system — fitting the blowup-16 ceiling with **4 degrees of slack**.
The aux-segment / soundness-correct versions of either variant carry
the same algebraic shape and would land at the same degree. **Verdict:
viable on the current `blowup_factor = 16` setting in both systems;
no FFT-cost doubling required.**

**Performance verdict.** Both winterfell variants beat Plonky3 on
proof size and verify time at every size we ran. The main-segment
probe also wins on prove time; the soundness-correct aux-segment
variant is within ~15 % of Plonky3's prove time but keeps the proof-
size and verify-time advantages mostly intact:

- **Main-segment probe vs Plonky3** (running-product baseline,
  not soundness-correct, kept for comparability with the API ergonomics
  question): prove 10–20 % faster, proof ~4× smaller, verify ~7×
  faster.
- **Aux-segment variant vs Plonky3** (soundness-correct, the actual
  Phase 3 reference): prove ~15 % slower at N=1024 / ~28 % slower at
  N=4096, proof ~3.4× smaller (44 KB vs 150 KB), verify ~5.8× faster
  (421 µs vs 2.43 ms).
- **Aux-segment cost over main-segment** (the price of soundness):
  prove ~40 % slower, proof ~24 % larger, verify ~19 % slower. This
  is the cost of committing the Z column in a separate trace segment
  with its own LDE / Merkle commitment. Acceptable.

The proof-size gap is the surprise. Plausible cause: Plonky3's
`MerkleTreeMmcs` packs `[F::Packing; 8]`-leaves with a Poseidon2
compression, whose witness commitments are larger per query than
winterfell's Blake3-leaved Merkle paths over `f128`. The 32-query
config dominates the proof body in both systems, but the per-query
overhead is much higher on Plonky3 at this trace size. The gap
narrows as a fraction of the proof at larger N (38 % at N=4096).

LOC counts are full source files (`wc -l`) including ~80 lines of
header documentation each — comparable but not strictly "AIR DSL
size." The pure-AIR portions are similar in both: ~30 lines for the
constraint definition, ~50 lines for boilerplate (winterfell's `Air`
trait + `Prover` trait, vs. Plonky3's `BaseAir` + `Air<AB>` +
`StarkConfig` builder).

## Decision

**Stay on winterfell for Phase 3 lookup tooling.**

Three independent reasons, any one of which would be sufficient:

1. **Performance favours winterfell on the metrics that matter most
   for verifier-side workloads.** The soundness-correct aux-segment
   variant trails Plonky3 on prove time by ~15 % at N=1024 / ~28 % at
   N=4096, but holds a ~3.4× lead on proof size and a ~5.8× lead on
   verify time (see §Results). For agents that re-verify proofs much
   more often than they create them — the expected runtime profile —
   the verify-time and proof-size deltas dominate.
2. **Lookup-argument tooling on winterfell is first-class today.**
   Auxiliary trace segments + verifier-supplied randomness are part
   of the 0.13.x trait set; the soundness-correct variant of this
   prototype landed 2026-05-05 alongside the degree probe and Plonky3
   port (`src/winterfell_aux_lookup.rs`). Caveat for implementers:
   the stock `TraceTable` always reports a single-segment `TraceInfo`,
   so a custom `Trace` impl (~30 LOC, see `LookupAuxTrace` in the
   prototype) is required to declare aux columns. Phase 3 lifts that
   wrapper verbatim.
3. **Plonky3 LogUp is a custom-prover effort.** `p3-lookup` ships
   the LogUp gadget but not a prover that wires it through. Building
   one (extending `p3-uni-stark` with permutation-segment support,
   or porting SP1's stack) is a 1–2 engineer-week item, on top of the
   Phase 3 work itself. We'd be paying that cost to reach feature
   parity with what winterfell aux-segments already give us.

What would change this decision: a 3× prove-time gap in the *other*
direction once both sides are running their soundness-correct
production lookups. That's not impossible — LogUp's multiplicities
trick can amortise multi-table lookups in ways the Schwartz-Zippel
running product can't — but the gap would have to be very large to
overcome the proof-size and verify-time deficits seen here.

**Caveats explicitly worth re-checking when Phase 3 lands:**

- Plonky3 proof-size at larger N. The 38 % gap at N=4096 is closing;
  if a real Phase 3 Prove body runs >8 K rows, that may flip.
- Plonky3 prove-time on multi-AIR aggregations. The single-AIR
  comparison ignores Plonky3's strength at composing many small AIRs
  (which is where SP1 and Valida win). If REMEMBER/RECALL ends up
  splitting into per-statement-family AIRs (per `MEMORY.md` Phase 3
  constraint #3), this comparison stops being load-bearing.

This decision goes back into [`docs/zkp/STATUS.md`](../../docs/zkp/STATUS.md)
Phase 3 §"Lookup-argument tooling" and unblocks Phase 3
implementation.
