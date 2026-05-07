# AgentLang ZKP Roadmap

**Status:** Companion document to `SECURITY_AUDIT.md` §2.1.
**Last updated:** 2026-04-30
**Owner:** TBD

This is the **index** to AgentLang's ZKP roadmap. Each follow-on item has
its own deep-dive document under `docs/zkp/` — that's where the detail
lives. This page is intended as a one-page orientation for new readers.

For implementation status (what's shipped, what's next, deviations from
the deep-dive plans), see [`docs/zkp/STATUS.md`](docs/zkp/STATUS.md).

## Where we are today

`src/crypto.rs` ships an `ExecutionDigestAir` that binds proofs to a
Schwartz-Zippel polynomial digest of post-execution state bytes:

- **What it binds:** the byte representation of the working-variable map
  at the moment `Statement::Prove` finishes. Tampering with any state
  byte invalidates the proof.
- **What it does NOT bind:** the execution path that produced that state,
  the individual statements that ran, the structure of values (we
  serialize via `Debug`), or anything outside the working-variable map
  (long-term memory, audit log, contracts).
- **Soundness:** ~2^-108 against state-byte tampering for traces ≤ 2^20.
  The full 128-bit digest is exposed in `StarkProof`, preserving that
  margin externally.

The three follow-on items below close those gaps in increasing order of
ambition. Each is independently shippable — stop after any of them and
the system still has a real ZK story, just with the limits documented
in `SECURITY_AUDIT.md` §2.1.

---

## 1. Per-statement-type AIRs

**Deep dive:** [`docs/zkp/01-per-statement-airs.md`](docs/zkp/01-per-statement-airs.md)
**Effort:** 6–10 engineer-weeks
**Sequencing:** First.

Encode each `Statement` variant's semantics as its own constraint family
inside a multi-segment AIR (selector columns per opcode, lookup arguments
for memory and contracts, audit-chain root binding). After this, a
verifying proof testifies "the AgentLang interpreter executed faithfully"
rather than just "some byte sequence matches the digest."

The work also formalizes AgentLang semantics at the constraint level —
that formalization pays off whether we eventually keep AIRs or migrate
to a zkVM.

---

## 2. SHA-256 inside the AIR

**Deep dive:** [`docs/zkp/02-sha256-in-air.md`](docs/zkp/02-sha256-in-air.md)
**Effort:** 3–5 engineer-weeks
**Sequencing:** Second. Soft-depends on #1's lookup-argument tooling for
the optimal trace shape; ships independently with the in-circuit fast
path if #1 slips.

Replace the polynomial digest with a SHA-256 commitment computed inside
the AIR. Soundness on `state_digest` collision-finding rises to the
generic 2^128 birthday bound, independent of the prover's freedom to
choose claim or state. Trade-off: ~10× slower proving from the larger
trace.

---

## 3. zkVM migration (RISC0 / SP1 / Jolt)

**Deep dive:** [`docs/zkp/03-zkvm-migration.md`](docs/zkp/03-zkvm-migration.md)
**Effort:** 8–16 engineer-weeks (12-week mid-point + 4-week buffer)
**Sequencing:** Last.

Compile the AgentLang interpreter to RISC-V, run inside a generic zkVM,
get full execution-trace ZK without hand-written constraints. **Does not
replace AIRs** — the design is hybrid: AIRs for hot-path proofs
(sub-second), zkVM for cold-path proofs that need execution binding
(seconds to minutes). `Statement::Prove` grows a mode field with auto-
selection.

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

Each deep-dive doc has its own phased delivery, risk register, rollout
plan, alternatives considered, non-goals, verification plan, and open
questions. Read those before starting on any of the items.
