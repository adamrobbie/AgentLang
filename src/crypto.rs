//! Execution-digest STARK.
//!
//! The previous implementation generated a Fibonacci STARK whose trace had
//! no relationship to AgentLang execution — the proof would verify
//! identically for any state, breaking the "Trusted by Design" promise.
//!
//! This module replaces it with an `ExecutionDigestAir`: the trace is a
//! Schwartz-Zippel-style polynomial digest evaluated over the bytes of the
//! post-execution state. Concretely, for state bytes `s_0 .. s_{N-1}`
//! and a public multiplier `M`, the trace enforces the recurrence
//!
//!   digest_0 = 0
//!   digest_{i+1} = digest_i * M + s_i
//!
//! so the final digest equals the polynomial
//!
//!   s_0 * M^{N-1} + s_1 * M^{N-2} + ... + s_{N-1}.
//!
//! The public inputs `(claim_hash, multiplier, state_digest, num_state_bytes)`
//! and the AIR transition together imply the prover knew a byte sequence of
//! the declared length whose polynomial digest matches `state_digest`. The
//! multiplier is derived deterministically from `claim_hash` (Fiat-Shamir
//! flavor), so the prover cannot grind the multiplier to fit any chosen
//! digest after the fact.
//!
//! Soundness: collision probability for two distinct byte sequences hashing
//! to the same digest under a uniformly chosen multiplier is at most
//! `N / |F|` where `|F| ≈ 2^128` (Schwartz-Zippel). For practical traces
//! (N ≤ 2^20), that's `≤ 2^-108`. The proof exposes the full 128-bit
//! `state_digest` field element, so external comparison preserves that
//! soundness margin. Future work: layer a SHA-256 commitment outside the
//! AIR for cryptographic-grade binding (Schwartz-Zippel still depends on
//! the multiplier being unguessable to the prover, which Fiat-Shamir-from-
//! claim only addresses if the claim itself is fixed before state choice).
//!
//! Limitations vs. true execution-trace ZK:
//!   - The trace encodes the *bytes of post-execution state*, not the
//!     statement evaluation steps themselves. Two different statement
//!     sequences that produce the same final state are indistinguishable
//!     to a verifier — execution path is not bound, only the result.
//!   - The state serialization (`build_state_bytes` in `runtime/eval.rs`)
//!     is a sorted `key:value` text format. Strings, lists, and objects
//!     are formatted via `Debug`, so the bound is on the textual
//!     representation, not a canonical structural form.
//!
//! These remain in §2.1 of `SECURITY_AUDIT.md` as outstanding work.

use ring::digest;
use serde::{Deserialize, Serialize};
use winter_crypto::{DefaultRandomCoin, MerkleTree, hashers::Blake3_256};
use winterfell::{
    AcceptableOptions, Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame,
    FieldExtension, PartitionOptions, Proof, ProofOptions, Prover, StarkDomain, Trace, TraceInfo,
    TracePolyTable, TraceTable, math::FieldElement, math::StarkField, math::ToElements,
    math::fields::f128::BaseElement, matrix::ColMatrix,
};

const MIN_TRACE_LENGTH: usize = 8;

// ------------------------------------------------------------------------------------------------
// PUBLIC INPUTS
// ------------------------------------------------------------------------------------------------

pub struct PublicInputs {
    pub claim_hash: BaseElement,
    pub multiplier: BaseElement,
    pub state_digest: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.claim_hash, self.multiplier, self.state_digest]
    }
}

// ------------------------------------------------------------------------------------------------
// EXECUTION-DIGEST AIR
// ------------------------------------------------------------------------------------------------

/// Trace columns:
/// - col 0: `digest`     — running polynomial digest, starts at 0, ends at `state_digest`.
/// - col 1: `byte_input` — the state byte consumed at this step (free witness).
/// - col 2: `claim_hash` — the public claim hash, carried unchanged.
///
/// The multiplier is *not* a trace column — it's bound through public inputs
/// and embedded as a constant in `evaluate_transition`. Doing it that way
/// keeps both transition constraints degree-1 in trace columns, which both
/// matches winterfell's degree-tracking and makes the AIR cheaper.
pub struct ExecutionDigestAir {
    context: AirContext<BaseElement>,
    pub_inputs: PublicInputs,
}

impl Air for ExecutionDigestAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Two transition constraints, each degree 1 in trace columns:
        //   1) digest_next - (digest_curr * MULT_const + byte_input_curr) = 0
        //   2) claim_hash_next - claim_hash_curr = 0
        let degrees = vec![
            winterfell::TransitionConstraintDegree::new(1),
            winterfell::TransitionConstraintDegree::new(1),
        ];
        let num_assertions = 3;
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        Self {
            context,
            pub_inputs,
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            // digest starts at 0
            Assertion::single(0, 0, BaseElement::ZERO),
            // claim_hash at step 0 must match public input
            Assertion::single(2, 0, self.pub_inputs.claim_hash),
            // digest at the last step must match the public state_digest
            Assertion::single(0, last_step, self.pub_inputs.state_digest),
        ]
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();
        let multiplier = E::from(self.pub_inputs.multiplier);
        // digest_next = digest_curr * MULT + byte_input_curr  (degree 1 in trace)
        result[0] = next[0] - (current[0] * multiplier + current[1]);
        // claim_hash carried over
        result[1] = next[2] - current[2];
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ------------------------------------------------------------------------------------------------
// PROVER
// ------------------------------------------------------------------------------------------------

pub struct ExecutionProver {
    options: ProofOptions,
    state_bytes: Vec<u8>,
    claim_hash: BaseElement,
    multiplier: BaseElement,
}

impl ExecutionProver {
    pub fn new(
        options: ProofOptions,
        state_bytes: Vec<u8>,
        claim_hash: BaseElement,
        multiplier: BaseElement,
    ) -> Self {
        Self {
            options,
            state_bytes,
            claim_hash,
            multiplier,
        }
    }

    pub fn build_trace(&self) -> TraceTable<BaseElement> {
        let trace_len = padded_trace_length(self.state_bytes.len());
        let mut trace = TraceTable::new(3, trace_len);

        let claim_hash = self.claim_hash;
        let multiplier = self.multiplier;
        let bytes = self.state_bytes.clone();

        // Pad with zeros up to trace_len. Padding bytes still advance the
        // digest (digest := digest * M + 0 = digest * M), so the verifier
        // must know `num_state_bytes` to interpret which prefix of the
        // implicit input is "real". That's exposed in `StarkProof`.
        let mut padded = bytes;
        padded.resize(trace_len, 0);

        trace.fill(
            |state| {
                state[0] = BaseElement::ZERO;
                state[1] = BaseElement::new(padded[0] as u128);
                state[2] = claim_hash;
            },
            |step, state| {
                let new_digest = state[0] * multiplier + state[1];
                state[0] = new_digest;
                let next_byte_idx = step + 1;
                state[1] = if next_byte_idx < padded.len() {
                    BaseElement::new(padded[next_byte_idx] as u128)
                } else {
                    BaseElement::ZERO
                };
                state[2] = claim_hash;
            },
        );
        trace
    }
}

impl Prover for ExecutionProver {
    type BaseField = BaseElement;
    type Air = ExecutionDigestAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            claim_hash: self.claim_hash,
            multiplier: self.multiplier,
            state_digest: trace.get(0, last_step),
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }
}

// ------------------------------------------------------------------------------------------------
// PUBLIC API
// ------------------------------------------------------------------------------------------------

/// Wire-format version of `StarkProof`. Bumped whenever the constraint
/// catalog or the set of public inputs changes in a way that would make
/// an older verifier accept a proof it should reject (or vice versa).
///
/// Verification dispatches on this field, so older proofs keep verifying
/// after we evolve the AIR — the dispatch entry for the older version
/// stays alive until we drop support for it explicitly. Unknown versions
/// are rejected outright (no "best effort" fallback).
///
/// History:
/// - `1` — first explicitly versioned shape. `state_digest` polynomial
///   binding + optional `control_flow` segment (Phase 2 control-flow AIR).
/// - `2` — adds `memory_root_pre`/`memory_root_post`. Phase 3b: the fields
///   are present in the wire shape but the AIR does not yet bind them
///   (that lands in 3e). Phase 3b consumers see them as runtime-side
///   metadata that the [`StoredProof`] wrapper cross-checks against
///   what the runtime actually observed, closing the envelope-integrity
///   loop ahead of in-AIR enforcement.
pub const CURRENT_PROOF_VERSION: u8 = 2;

#[derive(Serialize, Deserialize, Clone)]
pub struct StarkProof {
    /// Wire-format version. See [`CURRENT_PROOF_VERSION`] for the version
    /// log. `#[serde(default)]` lets unversioned blobs deserialize as
    /// version `0`, which the verifier dispatch then rejects with a clear
    /// error rather than silently treating them as the current shape.
    #[serde(default)]
    pub proof_version: u8,
    /// The serialized winterfell proof bytes.
    pub proof: Vec<u8>,
    /// Full polynomial digest of post-execution state, as a 128-bit field
    /// element. Matches the AIR's public `state_digest` input exactly —
    /// the verifier reconstructs `pub_inputs` with this value, so any
    /// truncation here would desynchronize boundary constraints.
    pub state_digest: u128,
    /// SHA-256(claim) folded to u64; matches the AIR's `claim_hash` input.
    pub claim_hash: u64,
    /// Number of meaningful state bytes consumed by the trace (excluding
    /// trailing zero padding). Two states with the same content but
    /// different trace padding would produce different digests, so the
    /// verifier needs this length to interpret the trace.
    pub num_state_bytes: u64,
    /// Power-of-two trace length used by the prover. The verifier needs
    /// this to reconstruct the AIR with matching `TraceInfo`.
    pub trace_length: u64,
    /// Fiat-Shamir-derived multiplier (folded to u64) used in the digest
    /// recurrence. Deterministically derived from `claim_hash`, exposed
    /// for ergonomic verification.
    pub multiplier: u64,
    /// Phase 2 control-flow proof — present iff the execution log
    /// recorded at least one statement. Empty `Prove` blocks produce
    /// digest-only envelopes (no control flow to attest to). When
    /// present, `verify_proof` verifies it alongside the digest layer.
    #[serde(default)]
    pub control_flow: Option<ControlFlowProof>,
    /// Memory commitment root captured by the prover *before* executing
    /// the `Prove` body. Phase 3b carries this in the envelope only;
    /// Phase 3e will enforce it as a public input the AIR's first row
    /// pins. `generate_proof` defaults this to `[0u8; 32]`; the runtime
    /// (`Statement::Prove`) overrides it with the empty-SMT root or the
    /// actual pre-state root once Phase 3c lands the Context-level
    /// commitment.
    #[serde(default)]
    pub memory_root_pre: [u8; 32],
    /// Memory commitment root captured by the prover *after* executing
    /// the `Prove` body. Same status as `memory_root_pre` in 3b.
    #[serde(default)]
    pub memory_root_post: [u8; 32],
}

/// Runtime-side proof envelope. Wraps a [`StarkProof`] with the memory
/// roots the runtime *actually observed* at Prove start/end.
///
/// `Statement::Reveal` cross-checks the prover-claimed roots inside the
/// `StarkProof` against these runtime-observed roots before invoking
/// `verify_proof`. That binding closes the loop a malicious prover could
/// otherwise exploit by claiming arbitrary `memory_root_pre`/`post`
/// values inside the proof envelope. Phase 3b ships the binding ahead
/// of in-AIR enforcement (3e) so the wire shape and dispatch path stay
/// stable when the AIR-side constraints turn on.
#[derive(Clone)]
pub struct StoredProof {
    pub proof: StarkProof,
    pub memory_root_pre: [u8; 32],
    pub memory_root_post: [u8; 32],
}

fn fold_to_u64(bytes: &[u8]) -> u64 {
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[..8]);
    u64::from_be_bytes(arr)
}

fn hash_claim(claim: &str) -> BaseElement {
    let h = digest::digest(&digest::SHA256, claim.as_bytes());
    BaseElement::new(fold_to_u64(h.as_ref()) as u128)
}

/// Derives a multiplier from the claim hash via a domain-separated SHA-256.
/// This makes the AIR's polynomial digest unguessable in advance — the
/// prover cannot pick a multiplier that happens to make any chosen byte
/// sequence digest to a target value, because the multiplier is bound to
/// the claim string before the trace is constructed.
fn derive_multiplier(claim: &str) -> BaseElement {
    let mut input = Vec::with_capacity(claim.len() + 32);
    input.extend_from_slice(claim.as_bytes());
    input.extend_from_slice(b"\x00agentlang-stark-multiplier-v1");
    let h = digest::digest(&digest::SHA256, &input);
    // Force a non-zero, non-one multiplier so the digest recurrence isn't
    // degenerate. Adding 2 keeps it well within field range.
    let val = fold_to_u64(h.as_ref()).saturating_add(2);
    BaseElement::new(val as u128)
}

/// A trace of length `L` has `L - 1` transitions, so it consumes at most
/// `L - 1` bytes. We size the trace to guarantee `L >= num_bytes + 1` and
/// is a power of two ≥ `MIN_TRACE_LENGTH`.
fn padded_trace_length(num_bytes: usize) -> usize {
    let needed = num_bytes.saturating_add(1).max(MIN_TRACE_LENGTH);
    if needed.is_power_of_two() {
        needed
    } else {
        needed.next_power_of_two()
    }
}

fn proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

// ControlFlowAir's opcode-validity constraint is degree 11 (product of 11
// linear factors over `VALID_OPCODES`). Winterfell requires
// blowup_factor >= next_power_of_two(max_constraint_degree), which is 16
// for degree 11. Keep the rest of the proof options aligned with the
// shared digest options for consistency.
fn control_flow_proof_options() -> ProofOptions {
    ProofOptions::new(
        32,
        16,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

/// Generates a proof binding `state_bytes` to `claim`. The post-execution
/// state must already be serialized to bytes by the caller (sorted, canonical
/// form recommended). The proof's public inputs commit to:
/// - the SHA-256 of `claim` (so the proof can only be re-used for this claim),
/// - a polynomial digest of `state_bytes` (so tampering with any byte breaks
///   verification),
/// - `state_bytes.len()` (so trace padding is unambiguous).
pub fn generate_proof(state_bytes: &[u8], claim: &str) -> anyhow::Result<StarkProof> {
    let claim_hash = hash_claim(claim);
    let multiplier = derive_multiplier(claim);

    let prover = ExecutionProver::new(
        proof_options(),
        state_bytes.to_vec(),
        claim_hash,
        multiplier,
    );
    let trace = prover.build_trace();
    let trace_length = trace.length();
    let pub_inputs = prover.get_pub_inputs(&trace);

    let proof = prover
        .prove(trace)
        .map_err(|e| anyhow::anyhow!("STARK proving failed: {}", e))?;

    Ok(StarkProof {
        proof_version: CURRENT_PROOF_VERSION,
        proof: proof.to_bytes(),
        state_digest: pub_inputs.state_digest.as_int(),
        claim_hash: claim_hash.as_int() as u64,
        num_state_bytes: state_bytes.len() as u64,
        trace_length: trace_length as u64,
        multiplier: multiplier.as_int() as u64,
        control_flow: None,
        // Phase 3b: defaults; the runtime overrides these in
        // `Statement::Prove` with the empty-SMT root (3b/3c) or the
        // actual pre/post memory roots once 3c wires Context state.
        memory_root_pre: [0u8; 32],
        memory_root_post: [0u8; 32],
    })
}

/// Verifies a proof against a claim. Checks:
/// 1. `claim_hash` matches `SHA-256(claim)` — proof is bound to this claim.
/// 2. `multiplier` matches the deterministic derivation from claim — the
///    prover did not grind a custom multiplier.
/// 3. The STARK proof verifies under the AIR with the declared public
///    inputs — the `state_digest` field is a faithful polynomial digest
///    of *some* byte sequence of length `num_state_bytes`.
///
/// To bind to a *specific* state, the caller should also compare
/// `proof.state_digest` against an independently-computed digest of the
/// expected state (see `digest_state_bytes`).
pub fn verify_proof(proof_data: &StarkProof, claim: &str) -> anyhow::Result<()> {
    match proof_data.proof_version {
        1 => verify_proof_v1(proof_data, claim),
        2 => verify_proof_v2(proof_data, claim),
        v => Err(anyhow::anyhow!(
            "Unsupported proof version {} (this verifier supports {})",
            v,
            CURRENT_PROOF_VERSION
        )),
    }
}

/// Phase 3b: v2 currently mirrors v1 — the `memory_root_pre`/`post`
/// envelope fields are present on the wire but the AIR does not yet
/// enforce them. The Phase 3 binding lives runtime-side via
/// [`StoredProof`]: `Statement::Reveal` asserts the prover-claimed
/// roots match what the runtime observed before calling this verifier.
/// Phase 3e replaces this body with an AIR-level memory_root boundary
/// check; the v1 dispatch arm stays alive so older proofs keep
/// verifying after that change.
fn verify_proof_v2(proof_data: &StarkProof, claim: &str) -> anyhow::Result<()> {
    verify_proof_v1(proof_data, claim)
}

fn verify_proof_v1(proof_data: &StarkProof, claim: &str) -> anyhow::Result<()> {
    let expected_claim_hash = hash_claim(claim);
    if proof_data.claim_hash != expected_claim_hash.as_int() as u64 {
        return Err(anyhow::anyhow!("Proof was not generated for this claim"));
    }

    let expected_multiplier = derive_multiplier(claim);
    if proof_data.multiplier != expected_multiplier.as_int() as u64 {
        return Err(anyhow::anyhow!(
            "Proof multiplier does not match the deterministic derivation from claim"
        ));
    }

    let proof = Proof::from_bytes(&proof_data.proof)
        .map_err(|e| anyhow::anyhow!("Failed to parse STARK proof: {}", e))?;

    let pub_inputs = PublicInputs {
        claim_hash: expected_claim_hash,
        multiplier: expected_multiplier,
        state_digest: BaseElement::new(proof_data.state_digest),
    };
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);

    winterfell::verify::<
        ExecutionDigestAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    .map_err(|e| anyhow::anyhow!("STARK verification failed: {}", e))?;

    // Phase 2: if a control-flow proof was attached, it must verify too.
    // Absence is permitted (empty `Prove` body has no log to attest to);
    // presence is mandatory to verify.
    //
    // 3e-boundary: the v1-shape envelope carries `memory_root_pre`/
    // `memory_root_post` (defaulted to `[0u8; 32]` for pre-3b proofs
    // via `#[serde(default)]`). The control-flow proof's AIR pins
    // `mroot[0]`/`mroot[last]` to those values; v1-shape proofs whose
    // envelope roots are zero match traces whose `mroot` column is all
    // zero (the legacy `generate_control_flow_proof` path used by
    // hand-built tests). Real-Prove envelopes (3c-runtime+) carry
    // non-zero roots and the AIR binds the trace's running mroot to
    // them. Forwarding the envelope bytes here is what closes the
    // verifier-side half of the binding: the same bytes that
    // `Statement::Reveal` cross-checks against `StoredProof` are
    // also what the AIR checks against the trace.
    if let Some(cf) = &proof_data.control_flow {
        verify_control_flow_proof(
            cf,
            claim,
            proof_data.memory_root_pre,
            proof_data.memory_root_post,
        )
        .map_err(|e| anyhow::anyhow!("Control-flow verification failed: {}", e))?;
    }

    Ok(())
}

/// Computes the polynomial digest of `state_bytes` under the multiplier
/// derived from `claim`. Useful for verifiers who want to independently
/// confirm a proof's `state_digest` matches a state they hold.
pub fn digest_state_bytes(state_bytes: &[u8], claim: &str) -> u128 {
    let multiplier = derive_multiplier(claim);
    let trace_len = padded_trace_length(state_bytes.len());
    let mut padded = state_bytes.to_vec();
    // Trace has trace_len rows but only trace_len - 1 transitions, so it
    // consumes only the first trace_len - 1 bytes. Mirror that here.
    padded.resize(trace_len, 0);
    let consumed = trace_len - 1;

    let mut digest = BaseElement::ZERO;
    for byte in &padded[..consumed] {
        digest = digest * multiplier + BaseElement::new(*byte as u128);
    }
    digest.as_int()
}

// ------------------------------------------------------------------------------------------------
// CONTROL-FLOW AIR (Phase 2 Slice 4)
// ------------------------------------------------------------------------------------------------
//
// A separate AIR over a `LogTrace`. One row per LogEntry (padded to a
// power of two with Nop). Constrains opcode validity, branch_taken bool,
// goal_status range, and claim_hash carry. Not yet bound to the digest
// AIR's input — Phase 3 (sha256-in-air) will close that gap.

use crate::runtime::exec_log::{ExecutionLog, LogTrace, LogTraceRow, fold_to_u128};
use crate::runtime::memory_commit::MemoryCommit;

/// Stable opcode bytes the AIR accepts. Must mirror `Opcode` discriminants
/// in `runtime::exec_log`. Pinned by `opcode_byte_values_are_stable`.
const VALID_OPCODES: &[u128] = &[
    0x00, 0x01, 0x02, 0x10, 0x11, 0x20, 0x21, 0x22, 0x30, 0x31, 0x40,
];

const CFA_OPCODE_COL: usize = 0;
const CFA_BRANCH_COL: usize = 1;
const CFA_STATUS_COL: usize = 2;
const CFA_CLAIM_COL: usize = 3;
const CFA_DEPTH_COL: usize = 4;
// ---- Phase 3c-AIR memory-row witness columns ----------------------------
// Witness only — no transition constraint references these columns yet.
// Sub-phase 3d wires the running SMT root through the prover so
// `CFA_MROOT_COL` carries real values; sub-phase 3e adds the auxiliary
// segment Z column and the gated `(scope, path, value, mroot)` lookup
// against the table-side memory commitment. Adding the witness columns
// now keeps the trace-shape evolution decoupled from constraint work,
// so the existing Phase 2 constraint suite stays green across this
// landing and 3d/3e can ship as targeted constraint deltas.
const CFA_SCOPE_COL: usize = 5;
const CFA_PATH_COL: usize = 6;
const CFA_VALUE_COL: usize = 7;
const CFA_MROOT_COL: usize = 8;
const CFA_NUM_COLS: usize = 9;
const CFA_MIN_TRACE_LEN: usize = 8;

const OPCODE_GOAL_ENTER: u128 = 0x01;
const OPCODE_GOAL_EXIT: u128 = 0x02;
const OPCODE_IF: u128 = 0x11;

// ---- Phase 3e-aux-shape: multi-segment trace plumbing -------------------
//
// The Phase 3 lookup/root-carry constraints all live on an *auxiliary*
// trace segment whose contents are committed after the main trace, so
// the prover can't grind their values to satisfy the lookup product.
// Until the lookup actually lands, the aux segment carries a single
// trivial column `Z = 1` constrained by `Z_next - Z_curr = 0` (degree 1)
// with boundary `Z[0] = 1`. This pins the column to a constant — useless
// on its own, but it gets the multi-segment plumbing in place so
// 3e-rootcarry / 3e-lookup-trace can ship as constraint-only edits.
//
// `TraceTable<BaseElement>`'s constructor always builds a single-segment
// `TraceInfo`, which `AirContext::new_multi_segment` rejects. We have to
// thread our own multi-segment `TraceInfo` through, which means a custom
// `Trace` impl over `ColMatrix`. The shape (main_width=9, aux_width=1,
// num_aux_rand=1, no periodic columns) is what 3e-rootcarry will keep
// and 3e-lookup-trace will extend (likely to num_aux_rand=2 for α/β).

/// Width of the auxiliary segment. One trivial Z column today; stays at
/// 1 through 3e-rootcarry and 3e-lookup-trace (the running product fits
/// in the same column — only the recurrence changes).
const CFA_AUX_WIDTH: usize = 1;
/// Aux randomness count requested from the public coin. We don't read
/// it in the trivial-Z carry, but winterfell still needs a non-zero
/// allocation when an aux segment is present, and 3e-lookup-trace will
/// bump this to 2 (α and β over the memory tuple).
const CFA_AUX_RAND_COUNT: usize = 1;

/// Custom `Trace` impl carrying a multi-segment `TraceInfo`. Mirrors
/// the `LookupAuxTrace` pattern from `prototypes/lookup-bench` —
/// committed-once `ColMatrix` of main columns plus a `TraceInfo` that
/// reports the aux-segment width to winterfell. The aux Z column is
/// built at prove time inside `ControlFlowProver::build_aux_trace`.
#[derive(Clone)]
pub struct ControlFlowTrace {
    info: TraceInfo,
    main: ColMatrix<BaseElement>,
}

impl Trace for ControlFlowTrace {
    type BaseField = BaseElement;

    fn info(&self) -> &TraceInfo {
        &self.info
    }

    fn main_segment(&self) -> &ColMatrix<Self::BaseField> {
        &self.main
    }

    fn read_main_frame(&self, row_idx: usize, frame: &mut EvaluationFrame<Self::BaseField>) {
        let next_row_idx = (row_idx + 1) % self.info.length();
        self.main.read_row_into(row_idx, frame.current_mut());
        self.main.read_row_into(next_row_idx, frame.next_mut());
    }
}

/// Lagrange indicator polynomial that is 1 at `target` and 0 at every
/// other valid opcode. Degree 10 over the 11-element opcode alphabet.
/// Combined with the opcode-validity constraint, this lets the AIR drive
/// the depth recurrence directly from the opcode column without an
/// extra witness column.
fn opcode_indicator<E: FieldElement<BaseField = BaseElement>>(opcode: E, target: u128) -> E {
    let mut num = E::ONE;
    let mut denom = BaseElement::ONE;
    let target_bf = BaseElement::new(target);
    for &v in VALID_OPCODES {
        if v == target {
            continue;
        }
        let v_bf = BaseElement::new(v);
        num *= opcode - E::from(v_bf);
        denom *= target_bf - v_bf;
    }
    num * E::from(denom.inv())
}

pub struct ControlFlowPublicInputs {
    pub claim_hash: BaseElement,
    /// Folded `memory_root_pre` (first 16 bytes of `Hash32` big-endian).
    /// 3e-boundary asserts `mroot[0]` equals this. The folding is lossy
    /// vs. the source SHA-256 by ~64 bits; 3e-lookup-trace's α/β
    /// randomization is what recovers the soundness margin against a
    /// prover crafting two distinct memory states whose folded roots
    /// collide.
    pub memory_root_pre: BaseElement,
    /// Folded `memory_root_post`. 3e-boundary asserts `mroot[last]`
    /// equals this. Combined with `memory_root_pre` and 3e-rootcarry's
    /// gated carry constraint, this binds the running mroot column
    /// end-to-end to the prover's claimed pre/post envelope.
    pub memory_root_post: BaseElement,
}

impl ToElements<BaseElement> for ControlFlowPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.claim_hash, self.memory_root_pre, self.memory_root_post]
    }
}

pub struct ControlFlowAir {
    context: AirContext<BaseElement>,
    pub_inputs: ControlFlowPublicInputs,
}

impl Air for ControlFlowAir {
    type BaseField = BaseElement;
    type PublicInputs = ControlFlowPublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Main constraint degrees:
        //   opcode validity:  product of 11 linear factors → degree 11
        //   branch_taken bool: x*(x-1)                     → degree 2
        //   goal_status range: x*(x-1)*(x-2)*(x-3)         → degree 4
        //   claim_hash carry: next - current               → degree 1
        //   depth recurrence: degree-10 indicator polys    → degree 10
        //   branch-IF binding: branch_taken*(opcode-IF)    → degree 2
        let main_degrees = vec![
            winterfell::TransitionConstraintDegree::new(11),
            winterfell::TransitionConstraintDegree::new(2),
            winterfell::TransitionConstraintDegree::new(4),
            winterfell::TransitionConstraintDegree::new(1),
            winterfell::TransitionConstraintDegree::new(10),
            winterfell::TransitionConstraintDegree::new(2),
        ];
        // Aux constraint degree: trivial Z carry (next - curr = 0). 3e-
        // rootcarry replaces this with `(1 - is_mem(opcode)) * (mroot_next
        // - mroot_curr)` (degree 11); 3e-lookup-trace replaces it again
        // with the gated running-product recurrence (degree 12 under the
        // blowup-16 ceiling). Both fit because the aux constraint shape
        // stays "one column, one transition" — only its degree changes.
        let aux_degrees = vec![winterfell::TransitionConstraintDegree::new(1)];
        // Five main boundary assertions:
        //   - claim_hash at row 0 binds the trace to the claim
        //   - depth at row 0 = 0 (clean stack on entry)
        //   - depth at last row = 0 (every Enter matched by an Exit)
        //   - mroot at row 0 = memory_root_pre (3e-boundary)
        //   - mroot at last row = memory_root_post (3e-boundary)
        // One aux boundary assertion:
        //   - Z[0] = 1 (running product initialised). Combined with the
        //     transition above, pins Z to the constant 1 today.
        let context = AirContext::new_multi_segment(trace_info, main_degrees, aux_degrees, 5, 1, options);
        Self {
            context,
            pub_inputs,
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last = self.context.trace_info().length() - 1;
        vec![
            Assertion::single(CFA_CLAIM_COL, 0, self.pub_inputs.claim_hash),
            Assertion::single(CFA_DEPTH_COL, 0, BaseElement::ZERO),
            Assertion::single(CFA_DEPTH_COL, last, BaseElement::ZERO),
            // 3e-boundary: pin the running-mroot column to the public
            // pre/post roots. With 3e-rootcarry's gated carry constraint
            // (deferred), the interior cells are forced to lie on the
            // line connecting these two boundaries via memory rows only.
            // Until 3e-rootcarry lands, only the endpoints are bound —
            // a tampering prover could still scribble inside the column,
            // but no row reads from it yet so that's not exploitable.
            Assertion::single(CFA_MROOT_COL, 0, self.pub_inputs.memory_root_pre),
            Assertion::single(CFA_MROOT_COL, last, self.pub_inputs.memory_root_post),
        ]
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let next = frame.next();

        // 1) opcode validity: ∏ (opcode - v) = 0 over the valid set.
        let mut opcode_poly = E::ONE;
        for &v in VALID_OPCODES {
            opcode_poly *= cur[CFA_OPCODE_COL] - E::from(BaseElement::new(v));
        }
        result[0] = opcode_poly;

        // 2) branch_taken ∈ {0, 1}
        let bt = cur[CFA_BRANCH_COL];
        result[1] = bt * (bt - E::ONE);

        // 3) goal_status ∈ {0, 1, 2, 3}
        let gs = cur[CFA_STATUS_COL];
        result[2] = gs
            * (gs - E::ONE)
            * (gs - E::from(BaseElement::new(2)))
            * (gs - E::from(BaseElement::new(3)));

        // 4) claim_hash carries unchanged
        result[3] = next[CFA_CLAIM_COL] - cur[CFA_CLAIM_COL];

        // 5) Goal-pair recurrence: next_depth = cur_depth + I_enter - I_exit.
        //    I_enter is 1 iff cur_opcode = GoalEnter, 0 otherwise; symmetric
        //    for I_exit. Combined with depth=0 boundary assertions at row 0
        //    and the last padded row, this enforces every GoalEnter has a
        //    matching GoalExit. (Negative-depth detection — i.e., "Exit
        //    before Enter" with later compensating Enter — is deferred to
        //    a future range-proof; the global-balance check still catches
        //    most malformed traces.)
        let opcode = cur[CFA_OPCODE_COL];
        let i_enter = opcode_indicator(opcode, OPCODE_GOAL_ENTER);
        let i_exit = opcode_indicator(opcode, OPCODE_GOAL_EXIT);
        result[4] = next[CFA_DEPTH_COL] - cur[CFA_DEPTH_COL] - i_enter + i_exit;

        // 6) Branch-IF binding: branch_taken=1 only on IF rows. Combined
        //    with constraint 2 (branch_taken ∈ {0,1}), this rules out a
        //    prover claiming `branch_taken=1` on (e.g.) a Set or Remember
        //    row to forge a witness-driven branch decision elsewhere.
        result[5] = bt * (opcode - E::from(BaseElement::new(OPCODE_IF)));
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        _main_frame: &EvaluationFrame<F>,
        aux_frame: &EvaluationFrame<E>,
        _periodic_values: &[F],
        _aux_rand_elements: &AuxRandElements<E>,
        result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + winterfell::math::ExtensionOf<F>,
    {
        // 3e-aux-shape: trivial Z carry. With Z[0]=1 boundary this pins Z
        // to the constant 1 — no soundness work yet. 3e-rootcarry swaps
        // this for the gated mroot-carry constraint; 3e-lookup-trace
        // swaps it again for the running-product recurrence. The aux-
        // segment plumbing it lands here is identical for all three.
        let z_curr = aux_frame.current()[0];
        let z_next = aux_frame.next()[0];
        result[0] = z_next - z_curr;
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        vec![Assertion::single(0, 0, E::ONE)]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

pub struct ControlFlowProver {
    options: ProofOptions,
    rows: Vec<LogTraceRow>,
    claim_hash: BaseElement,
    memory_root_pre: BaseElement,
    memory_root_post: BaseElement,
}

impl ControlFlowProver {
    fn new(
        options: ProofOptions,
        rows: Vec<LogTraceRow>,
        claim_hash: BaseElement,
        memory_root_pre: BaseElement,
        memory_root_post: BaseElement,
    ) -> Self {
        Self {
            options,
            rows,
            claim_hash,
            memory_root_pre,
            memory_root_post,
        }
    }

    fn build_trace(&self) -> ControlFlowTrace {
        // The trace gets five appended "anti-padding" rows after the
        // real ones, then default Nop rows out to a power-of-two length.
        //
        // Anti-pad layout (in order):
        //   row R    : Nop, branch=0, status=0
        //   row R+1  : IF, branch=1, status=0
        //              — drives branch_taken=1 variation at depth d.
        //   row R+2  : GoalEnter, branch=0, status=0
        //              — depth column rises by 1 here.
        //   row R+3  : IF, branch=1, status=0
        //              — drives a SECOND branch_taken=1 at depth d+1.
        //                The two IFs sit at different positions whose
        //                offsets keep the branch column from collapsing
        //                to an even-symmetric polynomial on the
        //                multiplicative subgroup (f(g^k) = f(g^(k+N/2)))
        //                for the small-real-row traces where padding to
        //                a power of two would otherwise pair the real
        //                If's br=1 with the anti-pad IF's br=1 at
        //                exactly the N/2 offset.
        //   row R+4  : GoalExit, branch=0, status=3 (Timeout)
        //              — drives goal_status≠0 variation and brings depth
        //                back to its pre-anti-pad value. We use status=3
        //                rather than 1 so the gs column escapes
        //                even-symmetry on the multiplicative subgroup
        //                (i.e. f(g^k) ≠ f(g^(k+N/2))) for short balanced
        //                traces where the only real GoalExit also carries
        //                status=1 — otherwise the gs column polynomial
        //                collapses to degree (N/2 − 1) and winterfell's
        //                degree-4 gs-range constraint quotient comes up
        //                short of the expected bound.
        //
        // Both IFs are valid under Slice 7's binding constraint
        // `branch_taken * (opcode - IF) = 0`. After the anti-pad
        // sequence, depth lands back at `d_after_real`. Default-padding
        // rows carry `depth = d_after_real`, satisfying the recurrence
        // (Nop is depth-neutral) *and* exposing balance failures: the
        // depth-at-last-row boundary assertion checks for 0, so any
        // d_after_real ≠ 0 (i.e., real rows had unmatched
        // GoalEnter/Exit) triggers verifier rejection.

        let real_rows = self.rows.clone();

        // Compute depth-after-last-real-row from the row witnesses.
        // The depth field on each real row is the depth BEFORE that
        // row's opcode is processed, so we apply the last row's delta
        // to derive what the next slot would carry.
        let d_after_real: i64 = if let Some(last) = real_rows.last() {
            let d = last.depth as i64;
            match last.opcode {
                0x01 => d + 1, // GoalEnter
                0x02 => d - 1, // GoalExit
                _ => d,
            }
        } else {
            0
        };
        let d_after_real_u32 = d_after_real.max(0) as u32;
        let d_after_real_plus_one_u32 = (d_after_real + 1).max(0) as u32;

        let mut rows = real_rows;
        // Anti-pad rows leave the Phase 3c-AIR memory operand columns
        // (scope/path/value) at zero — they're non-memory opcodes
        // (Nop/IF/GoalEnter/GoalExit). Memory-column anti-pad that
        // drives the future selector off zero on at least one row is
        // sub-phase 3f's job.
        //
        // 3e-boundary: the `mroot` cell on every anti-pad and padding
        // row carries `memory_root_post` (folded). The trace's last
        // real row's mroot is the SMT root entering that row (3d's
        // before-row semantics); after its effect lands, the running
        // root is `memory_root_post`. Anti-pad and padding rows are
        // non-memory ops, so the running root stays at
        // `memory_root_post` through the trace tail. Setting these
        // cells explicitly makes the `mroot[last]` boundary assertion
        // succeed by construction; 3e-rootcarry will additionally
        // enforce it row-by-row through the gated carry constraint.
        let pad_mroot = self.memory_root_post.as_int();
        rows.push(LogTraceRow {
            opcode: 0x00, // Nop
            branch_taken: 0,
            goal_status: 0,
            depth: d_after_real_u32,
            mroot: pad_mroot,
            ..LogTraceRow::default()
        });
        rows.push(LogTraceRow {
            opcode: 0x11, // IF #1 — branch_taken=1 at depth d (pre-GoalEnter)
            branch_taken: 1,
            goal_status: 0,
            depth: d_after_real_u32,
            mroot: pad_mroot,
            ..LogTraceRow::default()
        });
        rows.push(LogTraceRow {
            opcode: 0x01, // GoalEnter
            branch_taken: 0,
            goal_status: 0,
            depth: d_after_real_u32,
            mroot: pad_mroot,
            ..LogTraceRow::default()
        });
        rows.push(LogTraceRow {
            opcode: 0x11, // IF #2 — branch_taken=1 at depth d+1 (post-GoalEnter)
            branch_taken: 1,
            goal_status: 0,
            depth: d_after_real_plus_one_u32,
            mroot: pad_mroot,
            ..LogTraceRow::default()
        });
        rows.push(LogTraceRow {
            opcode: 0x02, // GoalExit
            branch_taken: 0,
            goal_status: 3, // Timeout — chosen to break gs column even-symmetry
            depth: d_after_real_plus_one_u32,
            mroot: pad_mroot,
            ..LogTraceRow::default()
        });

        let needed = rows.len().saturating_add(1).max(CFA_MIN_TRACE_LEN);
        let trace_len = if needed.is_power_of_two() {
            needed
        } else {
            needed.next_power_of_two()
        };

        let claim_hash = self.claim_hash;
        let pad_depth = BaseElement::new(d_after_real_u32 as u128);
        // Nop-padding rows past the anti-pad sequence carry the same
        // post-execution mroot as the anti-pad rows themselves, so the
        // `mroot[last]` boundary against `memory_root_post` is
        // satisfied by construction. See the anti-pad block above for
        // the full rationale.
        let pad_mroot_be = self.memory_root_post;

        // Build columns directly. We can't reuse `TraceTable::fill`
        // anymore because the multi-segment `TraceInfo` it builds
        // internally has aux_width=0, and `ControlFlowAir`'s context
        // declares aux_width=1 — mismatched info shapes between trace
        // and AIR cause the prover to panic at composition time.
        let mut opcode_col = Vec::with_capacity(trace_len);
        let mut branch_col = Vec::with_capacity(trace_len);
        let mut status_col = Vec::with_capacity(trace_len);
        let mut claim_col = Vec::with_capacity(trace_len);
        let mut depth_col = Vec::with_capacity(trace_len);
        let mut scope_col = Vec::with_capacity(trace_len);
        let mut path_col = Vec::with_capacity(trace_len);
        let mut value_col = Vec::with_capacity(trace_len);
        let mut mroot_col = Vec::with_capacity(trace_len);

        for step in 0..trace_len {
            let row_opt = rows.get(step).copied();
            let row = row_opt.unwrap_or_default();
            opcode_col.push(BaseElement::new(row.opcode as u128));
            branch_col.push(BaseElement::new(row.branch_taken as u128));
            status_col.push(BaseElement::new(row.goal_status as u128));
            claim_col.push(claim_hash);
            // Default-padding rows carry depth = d_after_real so the
            // depth recurrence holds across the Nop tail. Real and
            // anti-pad rows already encode their own depth.
            depth_col.push(if row_opt.is_some() {
                BaseElement::new(row.depth as u128)
            } else {
                pad_depth
            });
            // Phase 3c-AIR memory-row witness columns. Witness only —
            // no transition constraint reads from these in 3c/3d, so
            // the existing main degree budget is unchanged. SET/REMEMBER/
            // RECALL/FORGET rows carry the operand-derived values
            // populated by `LogTrace::from*`; every other opcode (and
            // every padding row) keeps zeros.
            scope_col.push(BaseElement::new(row.scope as u128));
            path_col.push(BaseElement::new(row.path));
            value_col.push(BaseElement::new(row.value));
            // Real and anti-pad rows already carry their authentic mroot
            // (3d before-row replay for real rows, `pad_mroot` set in
            // each anti-pad literal for the trailing five). Past the
            // anti-pad block, `unwrap_or_default()` would zero this
            // cell — override with `pad_mroot_be` so the boundary at
            // `mroot[last]` holds.
            mroot_col.push(if row_opt.is_some() {
                BaseElement::new(row.mroot)
            } else {
                pad_mroot_be
            });
        }

        // Assemble columns by their named index so the layout invariant
        // (`CFA_*_COL` constants vs. ColMatrix column order) is enforced
        // at construction, not just trusted in commentary. 3e-rootcarry's
        // `evaluate_aux_transition` reads `cur[CFA_MROOT_COL]` etc. — if
        // this assembly ever drifts from the constants, the AIR would
        // silently constrain the wrong column, which is exactly the
        // class of bug worth catching at the source.
        let mut main_columns: Vec<Vec<BaseElement>> = vec![Vec::new(); CFA_NUM_COLS];
        main_columns[CFA_OPCODE_COL] = opcode_col;
        main_columns[CFA_BRANCH_COL] = branch_col;
        main_columns[CFA_STATUS_COL] = status_col;
        main_columns[CFA_CLAIM_COL] = claim_col;
        main_columns[CFA_DEPTH_COL] = depth_col;
        main_columns[CFA_SCOPE_COL] = scope_col;
        main_columns[CFA_PATH_COL] = path_col;
        main_columns[CFA_VALUE_COL] = value_col;
        main_columns[CFA_MROOT_COL] = mroot_col;
        let main = ColMatrix::new(main_columns);
        let info = TraceInfo::new_multi_segment(
            CFA_NUM_COLS,
            CFA_AUX_WIDTH,
            CFA_AUX_RAND_COUNT,
            trace_len,
            vec![],
        );
        ControlFlowTrace { info, main }
    }
}

impl Prover for ControlFlowProver {
    type BaseField = BaseElement;
    type Air = ControlFlowAir;
    type Trace = ControlFlowTrace;
    type HashFn = Blake3_256<Self::BaseField>;
    type VC = MerkleTree<Self::HashFn>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultTraceLde<E, Self::HashFn, Self::VC>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;
    type ConstraintCommitment<E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintCommitment<E, Self::HashFn, Self::VC>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> ControlFlowPublicInputs {
        ControlFlowPublicInputs {
            claim_hash: self.claim_hash,
            memory_root_pre: self.memory_root_pre,
            memory_root_post: self.memory_root_post,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
        partition_option: PartitionOptions,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain, partition_option)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, coefficients)
    }

    fn build_constraint_commitment<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        composition_poly_trace: CompositionPolyTrace<E>,
        num_constraint_composition_columns: usize,
        domain: &StarkDomain<Self::BaseField>,
        partition_options: PartitionOptions,
    ) -> (Self::ConstraintCommitment<E>, CompositionPoly<E>) {
        DefaultConstraintCommitment::new(
            composition_poly_trace,
            num_constraint_composition_columns,
            domain,
            partition_options,
        )
    }

    /// 3e-aux-shape: trivial Z column. Always 1, doesn't reference
    /// `aux_rand_elements`. 3e-rootcarry replaces the body with the
    /// gated mroot-carry recurrence; 3e-lookup-trace replaces it again
    /// with the running-product recurrence keyed on α/β. The signature
    /// (and the multi-segment trace plumbing it relies on) stays the
    /// same across all three.
    fn build_aux_trace<E>(
        &self,
        main_trace: &Self::Trace,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> ColMatrix<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let n = main_trace.info().length();
        ColMatrix::new(vec![vec![E::ONE; n]])
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ControlFlowProof {
    pub proof: Vec<u8>,
    pub claim_hash: u64,
    pub trace_length: u64,
}

/// Builds a ControlFlowProof binding the given log's control-flow witnesses
/// to the claim. Same claim-hash derivation as the digest AIR so a single
/// claim string keys both proofs.
///
/// `mroot` column stays zero — this entry point is for callers that have
/// no starting `MemoryCommit` to thread (hand-built fuzz/test traces and
/// the v2 envelope path that doesn't yet attest mroot in-AIR). The
/// production `Statement::Prove` path goes through
/// [`generate_control_flow_proof_with_commit`] which populates `mroot`
/// from a real running commit.
///
/// 3e-boundary public inputs: `memory_root_pre`/`memory_root_post` are
/// both `BaseElement::ZERO`, matching the all-zero `mroot` column. The
/// 3e boundary assertions are still in force — they just bind to zero
/// here instead of a real folded SMT root.
pub fn generate_control_flow_proof(
    log: &ExecutionLog,
    claim: &str,
) -> anyhow::Result<ControlFlowProof> {
    let trace = LogTrace::from(log);
    generate_control_flow_proof_from_rows(
        trace.rows,
        claim,
        BaseElement::ZERO,
        BaseElement::ZERO,
    )
}

/// Sub-phase 3d/3e: builds a ControlFlowProof whose `CFA_MROOT_COL` carries
/// the running SMT root from `starting_commit` advanced by each memory
/// operation in `log`. `starting_commit` should be `MemoryCommit::from_context`
/// taken at Prove start so `rows[0].mroot` matches `memory_root_pre`.
///
/// `memory_root_post` is the runtime-computed post-execution SMT root
/// (i.e., `MemoryCommit::from_context(&ctx).root()` after the body
/// finishes). The trace's anti-pad and padding rows carry this exact
/// value in their `mroot` cell, and the 3e-boundary assertion at
/// `mroot[last]` pins it to the AIR's public input. The runtime-side
/// 3b envelope check (`Statement::Reveal`) cross-asserts the same
/// value against the prover's claimed `StarkProof.memory_root_post`,
/// closing the loop until 3e-rootcarry adds in-AIR row-by-row carry.
///
/// In 3e-boundary, only the column endpoints are constrained — interior
/// cells aren't yet read by any transition. 3e-rootcarry adds the
/// gated row-carry constraint; 3e-lookup-trace then attests memory
/// rows against the table-side SMT mutations.
pub fn generate_control_flow_proof_with_commit(
    log: &ExecutionLog,
    starting_commit: MemoryCommit,
    memory_root_post: [u8; 32],
    claim: &str,
) -> anyhow::Result<ControlFlowProof> {
    let memory_root_pre_be =
        BaseElement::new(fold_to_u128(&starting_commit.root()));
    let memory_root_post_be = BaseElement::new(fold_to_u128(&memory_root_post));
    let trace = LogTrace::from_log_and_commit(log, starting_commit);
    generate_control_flow_proof_from_rows(
        trace.rows,
        claim,
        memory_root_pre_be,
        memory_root_post_be,
    )
}

/// Test/internal helper: prove over a hand-built row list. Used to construct
/// invalid traces for negative tests; production callers should go through
/// `generate_control_flow_proof_with_commit`, which derives rows from a
/// real log + commit.
///
/// `memory_root_pre`/`memory_root_post` are the folded pre/post roots
/// the AIR's 3e-boundary assertions will bind `mroot[0]`/`mroot[last]`
/// to. Hand-built test traces with `mroot=0` everywhere should pass
/// `BaseElement::ZERO` for both.
pub fn generate_control_flow_proof_from_rows(
    rows: Vec<LogTraceRow>,
    claim: &str,
    memory_root_pre: BaseElement,
    memory_root_post: BaseElement,
) -> anyhow::Result<ControlFlowProof> {
    let claim_hash = hash_claim(claim);
    let prover = ControlFlowProver::new(
        control_flow_proof_options(),
        rows,
        claim_hash,
        memory_root_pre,
        memory_root_post,
    );
    let trace = prover.build_trace();
    let trace_length = trace.length();

    let proof = prover
        .prove(trace)
        .map_err(|e| anyhow::anyhow!("ControlFlowAir proving failed: {}", e))?;

    Ok(ControlFlowProof {
        proof: proof.to_bytes(),
        claim_hash: claim_hash.as_int() as u64,
        trace_length: trace_length as u64,
    })
}

/// Verifies a ControlFlow proof against the claim string and the
/// pre/post memory roots the prover committed to.
///
/// `memory_root_pre`/`memory_root_post` should be the same byte arrays
/// the prover used (i.e., `StarkProof.memory_root_pre`/`memory_root_post`).
/// The verifier folds them to `BaseElement` exactly the way the prover
/// did so the public-input vector matches the prover's `get_pub_inputs`
/// output and the 3e-boundary assertions evaluate consistently.
pub fn verify_control_flow_proof(
    proof_data: &ControlFlowProof,
    claim: &str,
    memory_root_pre: [u8; 32],
    memory_root_post: [u8; 32],
) -> anyhow::Result<()> {
    let expected_claim_hash = hash_claim(claim);
    if proof_data.claim_hash != expected_claim_hash.as_int() as u64 {
        return Err(anyhow::anyhow!(
            "ControlFlow proof was not generated for this claim"
        ));
    }

    let proof = Proof::from_bytes(&proof_data.proof)
        .map_err(|e| anyhow::anyhow!("Failed to parse ControlFlow proof: {}", e))?;

    let pub_inputs = ControlFlowPublicInputs {
        claim_hash: expected_claim_hash,
        memory_root_pre: BaseElement::new(fold_to_u128(&memory_root_pre)),
        memory_root_post: BaseElement::new(fold_to_u128(&memory_root_post)),
    };
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);

    winterfell::verify::<
        ControlFlowAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    .map_err(|e| anyhow::anyhow!("ControlFlowAir verification failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state() -> Vec<u8> {
        b"x:Number(1.0)|y:Text(\"hi\")".to_vec()
    }

    #[test]
    fn proof_round_trips_for_matching_claim() {
        let proof = generate_proof(&sample_state(), "balance_above_100").unwrap();
        verify_proof(&proof, "balance_above_100").unwrap();
    }

    #[test]
    fn fresh_proof_carries_current_version() {
        let proof = generate_proof(&sample_state(), "claim").unwrap();
        assert_eq!(proof.proof_version, CURRENT_PROOF_VERSION);
    }

    #[test]
    fn verify_rejects_unversioned_proof() {
        // Simulates a blob deserialized from an older shape with no
        // `proof_version` field — `#[serde(default)]` lands it at 0.
        let mut proof = generate_proof(&sample_state(), "claim").unwrap();
        proof.proof_version = 0;
        let err = verify_proof(&proof, "claim").unwrap_err();
        assert!(
            err.to_string().contains("Unsupported proof version 0"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_rejects_future_version() {
        let mut proof = generate_proof(&sample_state(), "claim").unwrap();
        proof.proof_version = 99;
        let err = verify_proof(&proof, "claim").unwrap_err();
        assert!(
            err.to_string().contains("Unsupported proof version 99"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unversioned_proof_round_trips_through_serde() {
        // The on-disk shape may legitimately omit the field for old proofs;
        // serde must accept that and the verifier must then reject on
        // version dispatch — this catches the case where a future field
        // rename accidentally drops `#[serde(default)]`.
        let json = r#"{
            "proof": [],
            "state_digest": 0,
            "claim_hash": 0,
            "num_state_bytes": 0,
            "trace_length": 0,
            "multiplier": 0,
            "control_flow": null
        }"#;
        let parsed: StarkProof = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.proof_version, 0);
    }

    #[test]
    fn v1_proof_envelope_round_trips_through_serde() {
        // A v1-shaped on-disk blob (pre-3b) lacks the new memory_root_*
        // fields. `#[serde(default)]` must populate them with [0u8; 32]
        // so legacy proofs still deserialize cleanly.
        let json = r#"{
            "proof_version": 1,
            "proof": [],
            "state_digest": 0,
            "claim_hash": 0,
            "num_state_bytes": 0,
            "trace_length": 0,
            "multiplier": 0,
            "control_flow": null
        }"#;
        let parsed: StarkProof = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.proof_version, 1);
        assert_eq!(parsed.memory_root_pre, [0u8; 32]);
        assert_eq!(parsed.memory_root_post, [0u8; 32]);
    }

    #[test]
    fn v1_dispatch_arm_still_verifies_legacy_proofs() {
        // Forge a v1 envelope by downgrading a fresh v2 proof. The v1
        // verifier must accept it (it doesn't look at memory roots) —
        // this guards the "old proofs keep verifying after AIR evolves"
        // contract documented at `CURRENT_PROOF_VERSION`.
        let mut proof = generate_proof(&sample_state(), "claim").unwrap();
        proof.proof_version = 1;
        verify_proof(&proof, "claim").expect("v1 dispatch arm must remain alive");
    }

    #[test]
    fn verify_fails_for_different_claim() {
        let proof = generate_proof(&sample_state(), "balance_above_100").unwrap();
        let err = verify_proof(&proof, "is_admin").unwrap_err();
        assert!(
            err.to_string().contains("not generated for this claim"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_fails_when_state_digest_tampered() {
        let mut proof = generate_proof(&sample_state(), "claim").unwrap();
        proof.state_digest = proof.state_digest.wrapping_add(1);
        let err = verify_proof(&proof, "claim").unwrap_err();
        assert!(
            err.to_string().contains("STARK verification failed"),
            "tampered state_digest must break STARK verification, got: {err}"
        );
    }

    #[test]
    fn verify_fails_when_proof_bytes_tampered() {
        let mut proof = generate_proof(&sample_state(), "claim").unwrap();
        if let Some(byte) = proof.proof.get_mut(100) {
            *byte ^= 0xFF;
        }
        assert!(verify_proof(&proof, "claim").is_err());
    }

    #[test]
    fn verify_fails_when_multiplier_tampered() {
        let mut proof = generate_proof(&sample_state(), "claim").unwrap();
        proof.multiplier = proof.multiplier.wrapping_add(1);
        let err = verify_proof(&proof, "claim").unwrap_err();
        assert!(
            err.to_string().contains("multiplier does not match"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn different_state_produces_different_digest() {
        let p1 = generate_proof(b"x:1", "claim").unwrap();
        let p2 = generate_proof(b"x:2", "claim").unwrap();
        assert_ne!(
            p1.state_digest, p2.state_digest,
            "differing state must produce differing digest"
        );
    }

    #[test]
    fn same_state_and_claim_produces_same_digest() {
        let p1 = generate_proof(b"x:1", "claim").unwrap();
        let p2 = generate_proof(b"x:1", "claim").unwrap();
        assert_eq!(p1.state_digest, p2.state_digest);
        assert_eq!(p1.multiplier, p2.multiplier);
    }

    #[test]
    fn digest_helper_matches_proof_digest() {
        let state = sample_state();
        let proof = generate_proof(&state, "claim").unwrap();
        let helper_digest = digest_state_bytes(&state, "claim");
        assert_eq!(proof.state_digest, helper_digest);
    }

    #[test]
    fn small_state_pads_to_min_trace() {
        // States smaller than MIN_TRACE_LENGTH still pad up to it.
        // We avoid the all-zero case here — winterfell's prover rejects
        // traces whose polynomials are constant 0 (composer assertion at
        // poly_size - 2 == degree fails when actual degree is 0). In
        // practice `Statement::Prove` always binds non-empty state via
        // `build_state_bytes`, so this is an internal-only invariant
        // documented for future callers, not a runtime concern.
        let proof = generate_proof(b"x", "claim").unwrap();
        verify_proof(&proof, "claim").unwrap();
        assert_eq!(proof.trace_length, MIN_TRACE_LENGTH as u64);
        assert_eq!(proof.num_state_bytes, 1);
    }

    // ----------------------------------------------------------------------
    // Phase 2 Slice 4 — ControlFlowAir
    // ----------------------------------------------------------------------
    //
    // Standalone winterfell AIR over a `LogTrace`. Constrains:
    //   1. opcode column ⊆ {Nop, GoalEnter, GoalExit, Set, If, Remember,
    //      Recall, Forget, Call, Delegate, UseWasm}
    //   2. branch_taken ∈ {0, 1}
    //   3. goal_status ∈ {0, 1, 2, 3}
    //   4. claim_hash carried unchanged across rows (binds trace to claim)
    //
    // Not yet linked to the digest AIR; binding lands in Phase 3.

    use crate::ast::MemoryScope;
    use crate::runtime::exec_log::{ExecutionLog, LogEntry, LogTraceRow, Operands};

    fn nonempty_log() -> ExecutionLog {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::GoalEnter {
                name_hash: [1; 32],
                audit_root: [2; 32],
            },
        });
        log.record(LogEntry {
            operands: Operands::Set {
                name_hash: [3; 32],
                value_hash: [4; 32],
            },
        });
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: [5; 32],
                branch_taken: true,
            },
        });
        log.record(LogEntry {
            operands: Operands::Remember {
                scope: MemoryScope::LongTerm,
                path_hash: [6; 32],
                value_hash: [7; 32],
                ttl: Some(60),
            },
        });
        log.record(LogEntry {
            operands: Operands::GoalExit {
                name_hash: [1; 32],
                status: crate::runtime::exec_log::GoalStatus::Success,
                audit_root: [8; 32],
            },
        });
        log
    }

    #[test]
    fn control_flow_proof_round_trips() {
        let log = nonempty_log();
        let proof = generate_control_flow_proof(&log, "control-flow").unwrap();
        // generate_control_flow_proof uses zero pre/post — the legacy
        // mroot=0 path. Verifier folds the same zero bytes for the
        // 3e-boundary check.
        verify_control_flow_proof(&proof, "control-flow", [0u8; 32], [0u8; 32]).unwrap();
    }

    // NOTE: An empty log produces an all-Nop trace whose constraint
    // polynomials evaluate to the zero polynomial — winterfell's prover
    // rejects this as a degenerate witness ("transition constraint degrees
    // didn't match"). In practice `Statement::Prove` never invokes this AIR
    // on an empty log: the call site emits at least a Goal/segment marker
    // first. Once Slice 5 wires this AIR into Prove, the empty-log path
    // becomes unreachable and the test is redundant. Documented here
    // instead of asserted.

    #[test]
    fn control_flow_proof_fails_for_wrong_claim() {
        let log = nonempty_log();
        let proof = generate_control_flow_proof(&log, "claim-A").unwrap();
        let err = verify_control_flow_proof(&proof, "claim-B", [0u8; 32], [0u8; 32]).unwrap_err();
        assert!(
            err.to_string().contains("not generated for this claim"),
            "unexpected error: {err}"
        );
    }

    /// Bad witness gets rejected. Three valid rejection paths:
    ///   1. prove() returns Err
    ///   2. prove() panics (winterfell debug-assert: constraint != 0)
    ///   3. prove() succeeds but verify() returns Err (release builds)
    /// Any of these counts as "the system rejected the bad witness".
    fn assert_bad_rows_rejected(rows: Vec<LogTraceRow>, claim: &str) {
        // Hand-built test traces have mroot=0 throughout — pass
        // BaseElement::ZERO for the 3e-boundary public inputs so the
        // legitimate boundary at `mroot[0]`/`mroot[last]` succeeds.
        // The test still exercises whichever other constraint the bad
        // row violates (opcode set, branch bool, status range, etc.).
        // Suppress winterfell's panic stderr output for cleaner test logs.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            generate_control_flow_proof_from_rows(
                rows,
                claim,
                BaseElement::ZERO,
                BaseElement::ZERO,
            )
        }));
        std::panic::set_hook(prev_hook);

        match result {
            Err(_) => {} // panic during prove — rejected
            Ok(Err(_)) => {} // prove returned Err — rejected
            Ok(Ok(proof)) => assert!(
                verify_control_flow_proof(&proof, claim, [0u8; 32], [0u8; 32]).is_err(),
                "bad witness produced a verifying proof"
            ),
        }
    }

    #[test]
    fn control_flow_proof_rejects_invalid_opcode() {
        // 0x99 is not in the valid opcode set.
        assert_bad_rows_rejected(
            vec![LogTraceRow {
                opcode: 0x99,
                branch_taken: 0,
                goal_status: 0,
                depth: 0,
                ..LogTraceRow::default()
            }],
            "claim",
        );
    }

    #[test]
    fn control_flow_proof_rejects_invalid_branch_taken() {
        // branch_taken = 2 violates the bool constraint.
        assert_bad_rows_rejected(
            vec![LogTraceRow {
                opcode: 0x11, // If
                branch_taken: 2,
                goal_status: 0,
                depth: 0,
                ..LogTraceRow::default()
            }],
            "claim",
        );
    }

    #[test]
    fn control_flow_proof_rejects_invalid_goal_status() {
        // goal_status = 5 falls outside {0, 1, 2, 3}.
        // depth = 1 because anti-pad GoalExit at row R+2 carries depth 1
        // and we want this single-row trace's depth column to vary; but
        // the goal_status range constraint is what fails, not depth.
        assert_bad_rows_rejected(
            vec![LogTraceRow {
                opcode: 0x02, // GoalExit
                branch_taken: 0,
                goal_status: 5,
                depth: 1,
                ..LogTraceRow::default()
            }],
            "claim",
        );
    }

    #[test]
    fn control_flow_proof_rejects_tampered_claim_hash_field() {
        let log = nonempty_log();
        let mut proof = generate_control_flow_proof(&log, "claim").unwrap();
        proof.claim_hash = proof.claim_hash.wrapping_add(1);
        assert!(verify_control_flow_proof(&proof, "claim", [0u8; 32], [0u8; 32]).is_err());
    }

    // ----------------------------------------------------------------------
    // Phase 2 Slice 6 — GOAL_ENTER/EXIT pairing
    // ----------------------------------------------------------------------

    fn balanced_goal_log() -> ExecutionLog {
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::GoalEnter {
                name_hash: [9; 32],
                audit_root: [0; 32],
            },
        });
        log.record(LogEntry {
            operands: Operands::Set {
                name_hash: [1; 32],
                value_hash: [2; 32],
            },
        });
        log.record(LogEntry {
            operands: Operands::GoalExit {
                name_hash: [9; 32],
                status: crate::runtime::exec_log::GoalStatus::Success,
                audit_root: [3; 32],
            },
        });
        log
    }

    #[test]
    fn control_flow_proof_accepts_balanced_goal() {
        let log = balanced_goal_log();
        let proof = generate_control_flow_proof(&log, "balanced").unwrap();
        verify_control_flow_proof(&proof, "balanced", [0u8; 32], [0u8; 32]).unwrap();
    }

    #[test]
    fn control_flow_proof_rejects_unmatched_goal_enter() {
        // GoalEnter with no matching GoalExit → final depth ≠ 0.
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::GoalEnter {
                name_hash: [9; 32],
                audit_root: [0; 32],
            },
        });
        log.record(LogEntry {
            operands: Operands::Set {
                name_hash: [1; 32],
                value_hash: [2; 32],
            },
        });
        let trace = LogTrace::from(&log);
        assert_bad_rows_rejected(trace.rows, "claim");
    }

    #[test]
    fn control_flow_proof_rejects_branch_taken_on_non_if_opcode() {
        // Slice 7: branch_taken=1 is only meaningful for IF rows.
        // A prover claiming branch_taken=1 on (e.g.) a Set row must
        // be rejected — the AIR's binding constraint
        //     branch_taken * (opcode - IF) = 0
        // makes this impossible to verify.
        assert_bad_rows_rejected(
            vec![LogTraceRow {
                opcode: 0x10, // Set, not IF
                branch_taken: 1,
                goal_status: 0,
                depth: 0,
                ..LogTraceRow::default()
            }],
            "claim",
        );
    }

    #[test]
    fn control_flow_proof_accepts_if_with_branch_taken_one() {
        // Slice 7: legitimate IF(true) row passes.
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::If {
                cond_hash: [9; 32],
                branch_taken: true,
            },
        });
        let proof = generate_control_flow_proof(&log, "if-true").unwrap();
        verify_control_flow_proof(&proof, "if-true", [0u8; 32], [0u8; 32]).unwrap();
    }

    // ----------------------------------------------------------------------
    // Phase 3e-boundary — mroot[0]/mroot[last] boundary assertions
    // ----------------------------------------------------------------------

    #[test]
    fn cf_3e_boundary_round_trips_with_nonzero_pre_post() {
        // Real-shape exercise: starting commit non-empty, log mutates
        // the SMT, post root differs from pre. Both 3e-boundary
        // assertions must accept this end-to-end.
        let mut starting = MemoryCommit::new();
        starting.apply_remember(MemoryScope::LongTerm, &[1u8; 32], [9u8; 32]);
        let pre_root = starting.root();

        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::Remember {
                scope: MemoryScope::Working,
                path_hash: [2u8; 32],
                value_hash: [3u8; 32],
                ttl: None,
            },
        });
        // Compute the post root by applying the same mutation to a
        // clone of `starting`. The replay inside the prover will
        // produce the identical final root; passing it as
        // `memory_root_post` matches the trace's anti-pad/padding tail.
        let mut post_commit = starting.clone();
        post_commit.apply_remember(MemoryScope::Working, &[2u8; 32], [3u8; 32]);
        let post_root = post_commit.root();

        let proof = generate_control_flow_proof_with_commit(
            &log, starting, post_root, "boundary-roundtrip",
        )
        .unwrap();
        verify_control_flow_proof(&proof, "boundary-roundtrip", pre_root, post_root)
            .expect("3e-boundary must accept consistent pre/post");
    }

    #[test]
    fn cf_3e_boundary_rejects_tampered_memory_root_pre() {
        // The verifier reconstructs `memory_root_pre` from the bytes
        // it's given. Tampering with those bytes shifts the AIR's
        // boundary value, the trace's `mroot[0]` no longer matches,
        // and verification rejects.
        let log = nonempty_log();
        let proof = generate_control_flow_proof(&log, "tamper-pre").unwrap();
        // Generated with empty starting commit (mroot=0 path) → AIR
        // pub_inputs.memory_root_pre = ZERO. Pass non-zero bytes here
        // to force a mismatch.
        let mut tampered_pre = [0u8; 32];
        tampered_pre[0] = 0xFF;
        assert!(
            verify_control_flow_proof(&proof, "tamper-pre", tampered_pre, [0u8; 32]).is_err(),
            "verifier must reject when claimed memory_root_pre disagrees with trace"
        );
    }

    #[test]
    fn cf_3e_boundary_rejects_tampered_memory_root_post() {
        let log = nonempty_log();
        let proof = generate_control_flow_proof(&log, "tamper-post").unwrap();
        // Tamper a byte in the first 16 of the post-root: `fold_to_u128`
        // takes the first 16 bytes BE, so changes to bytes [16..32] are
        // not visible to the AIR's folded boundary check (that's the
        // ~64-bit lossiness 3e-lookup-trace's α/β randomization will
        // recover; here, we deliberately tamper the visible half).
        let mut tampered_post = [0u8; 32];
        tampered_post[0] = 0xFF;
        assert!(
            verify_control_flow_proof(&proof, "tamper-post", [0u8; 32], tampered_post).is_err(),
            "verifier must reject when claimed memory_root_post disagrees with trace"
        );
    }

    #[test]
    fn cf_3e_boundary_fold_lossiness_documented() {
        // Companion to the tamper test above: changes in bytes [16..32]
        // of either pre or post root are NOT detected at 3e-boundary.
        // This is the 64-bit fold lossiness, deliberate at this stage.
        // 3e-lookup-trace closes the gap by mixing α/β over the full
        // 32 bytes via a Schwartz-Zippel-style randomization.
        //
        // This test exists to flag the gap explicitly so a future
        // edit that changes the fold (e.g., to all 32 bytes via
        // multi-element packing) updates this test instead of
        // silently shifting the security claim.
        let log = nonempty_log();
        let proof = generate_control_flow_proof(&log, "fold-lossy").unwrap();
        let mut hidden_change = [0u8; 32];
        hidden_change[31] = 0xFF;
        verify_control_flow_proof(&proof, "fold-lossy", [0u8; 32], hidden_change)
            .expect("byte 31 of post lives outside the folded prefix — 3e-boundary alone can't catch this");
    }

    #[test]
    fn control_flow_proof_rejects_extra_goal_exit() {
        // GoalExit with no matching GoalEnter → final depth ≠ 0
        // (depth would have to go negative through the trace, but
        // boundary at last row catches the cumulative imbalance).
        let mut log = ExecutionLog::new();
        log.record(LogEntry {
            operands: Operands::Set {
                name_hash: [1; 32],
                value_hash: [2; 32],
            },
        });
        log.record(LogEntry {
            operands: Operands::GoalExit {
                name_hash: [9; 32],
                status: crate::runtime::exec_log::GoalStatus::Success,
                audit_root: [3; 32],
            },
        });
        let trace = LogTrace::from(&log);
        assert_bad_rows_rejected(trace.rows, "claim");
    }
}
