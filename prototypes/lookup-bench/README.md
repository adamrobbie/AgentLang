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

### B. Plonky3 lookup gadget

Plonky3 ships first-class LogUp lookup support via `p3-uni-stark` +
`p3-lookup`. The trace setup is the same, but the lookup itself is a
gadget call rather than hand-rolled column accounting.

Implemented in `src/plonky3_lookup.rs` *(stub for next session)*.

## Running

```sh
cargo run --release --bin winterfell_lookup
cargo run --release --bin plonky3_lookup    # next session
```

Each prints a measurement table to stdout. Numbers go in §"Results" by
hand — auto-generating them is out of scope for a spike.

## Results

Captured 2026-05-01 on the user's reference machine (Apple silicon,
release build, median of 5 prove runs).

| Variant | Transition degree | Prove (N=64) | Prove (N=1024) | Prove (N=4096) | Proof size (N=1024) | Verify (N=1024) | LOC |
|---|---|---|---|---|---|---|---|
| Winterfell running product (main segment) | **2** | 0.88 ms | 13.16 ms | 57.93 ms | 35,955 B | 354 µs | ~100 |
| Plonky3 LogUp | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |

**Headline degree-budget verdict for winterfell.** With a base
running-product transition of degree 2 and the Phase 2 Lagrange opcode
selector contributing degree 10, the gated lookup transition lands at
degree **12** — which fits inside the blowup-16 ceiling (max constraint
degree 16) with **4 degrees of slack**. The aux-segment variant carries
the same algebraic shape, so the soundness-correct version is expected
to land at the same degree. **Verdict: viable on the current
`blowup_factor = 16` setting; no FFT-cost doubling required.**

LOC count is the AIR struct + `evaluate_transition` + periodic-column
setup, excluding the prover boilerplate winterfell forces every AIR to
re-implement (the `Prover` trait impl with its associated-type tax adds
another ~70 lines that aren't really "AIR code").

## Decision

_Final decision deferred until the Plonky3 LogUp variant lands._ The
winterfell measurement is decisive on its own terms — degree 12 with
4 slack is fine — so the only reason to switch to Plonky3 would be a
materially better proof time, proof size, or developer ergonomics
profile, not a degree-budget escape hatch.

Provisional lean as of 2026-05-01: **stay on winterfell** unless Plonky3
turns out to be at least 3× faster on the 1024-row case or qualitatively
simpler to wire into the existing `ControlFlowAir` infrastructure.

Either decision goes back into [`docs/zkp/STATUS.md`](../../docs/zkp/STATUS.md)
and unblocks Phase 3 implementation.
