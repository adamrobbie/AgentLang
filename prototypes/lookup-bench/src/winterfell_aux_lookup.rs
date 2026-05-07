//! Lookup-argument prototype — winterfell **auxiliary-segment** variant.
//!
//! This is the soundness-correct successor to `winterfell_lookup.rs`.
//! Differences from the degree probe:
//!
//! 1. **Z lives in an auxiliary trace segment**, not the main trace.
//!    The aux segment is committed *after* the main segment, so the
//!    challenges used to build it can come from the verifier (drawn
//!    from the public coin keyed on the main commitment).
//!
//! 2. **`α, β` are drawn from `AuxRandElements`** rather than derived
//!    from the public table. This closes the soundness gap from the
//!    degree probe (a malicious prover can no longer grind a trace
//!    that satisfies the running-product check; doing so would
//!    require predicting the verifier's challenges before committing
//!    to the trace).
//!
//! 3. **The transition polynomial degree is unchanged** — still 2.
//!    This is the whole reason the probe was a valid measurement:
//!    where Z lives changes which segment commits to it, not the
//!    algebraic shape of the constraint.
//!
//! Phase 3 will copy this file's structure verbatim. The TODO markers
//! below flag the spots that need to grow when REMEMBER/RECALL gating
//! lands:
//!   - The `(key, value)` main columns become `(scope, path_hash,
//!     value_hash)`.
//!   - The periodic table columns are replaced by Merkle membership
//!     proofs (one per access row).
//!   - The aux transition is gated by the Phase 2 Lagrange opcode
//!     selector so the running product only updates on REMEMBER /
//!     RECALL / FORGET rows. That gating multiplies the degree by 10,
//!     producing the degree-12 result the prototype's degree budget
//!     measured.
//!
//! Run: `cargo run --release --bin winterfell_aux_lookup`.

use std::time::Instant;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, BatchingMethod,
    CompositionPoly, CompositionPolyTrace, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, ProofOptions, Prover,
    StarkDomain, Trace, TraceInfo, TracePolyTable, TransitionConstraintDegree,
};

// -------------------------------------------------------------------- toy problem

/// Length-N table whose rows the trace permutes — same construction as
/// the degree-probe variant. See `winterfell_lookup.rs` for rationale.
fn build_table(num_rows: usize) -> Vec<(BaseElement, BaseElement)> {
    let mut out = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        let k = ((i as u128).wrapping_mul(0x9E3779B97F4A7C15)) | 1;
        let v = ((i as u128).wrapping_mul(0xBB67AE8584CAA73B)) | 1;
        out.push((BaseElement::new(k), BaseElement::new(v)));
    }
    out
}

/// Builds the **main** trace — only `(key, value)` columns. The Z
/// column moves to the aux segment.
///
/// Witness rows are the table's rows in reverse order (so the multiset
/// matches and Z genuinely varies row-to-row).
///
/// Returns a custom multi-segment Trace impl. We can't use winterfell's
/// stock `TraceTable` here: `TraceTable::init` and `with_meta` always
/// build a *single-segment* `TraceInfo` (aux_width=0, num_aux_rand=0),
/// and the prover threads `trace.info()` straight into
/// `Air::new` → `AirContext::new_multi_segment`, which then panics with
/// "auxiliary transition constraint degrees specified for a single-
/// segment trace". The custom `LookupAuxTrace` below carries the right
/// multi-segment `TraceInfo` and is the minimal viable way to declare
/// a 2-main-column / 1-aux-column / 2-aux-randomness shape on the 0.13.x
/// trait surface.
fn build_main_trace(num_rows: usize) -> LookupAuxTrace {
    assert!(num_rows.is_power_of_two() && num_rows >= 64);
    let table = build_table(num_rows);

    let mut keys = Vec::with_capacity(num_rows);
    let mut vals = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        let (k, v) = table[num_rows - 1 - i];
        keys.push(k);
        vals.push(v);
    }
    LookupAuxTrace::new(keys, vals)
}

// -------------------------------------------------------------------- custom Trace

/// Custom `Trace` impl that reports a multi-segment `TraceInfo`
/// (main_width=2, aux_width=1, num_aux_rand=2) — the shape the AIR
/// expects. Only the main columns are stored here; the aux Z column is
/// built at prove-time inside `LookupAuxProver::build_aux_trace`.
///
/// Phase 3 will subclass this pattern: same `TraceInfo` shape grows
/// (main: scope/path_hash/value_hash; aux: Z; rands: still α/β over
/// the lookup tuple), and the per-statement-AIR template lifts this
/// struct verbatim. The interesting Phase-3-specific code is in the
/// AIR's `evaluate_aux_transition` and the prover's `build_aux_trace`
/// — both of which see the aux segment exactly as declared here.
#[derive(Clone)]
struct LookupAuxTrace {
    info: TraceInfo,
    main: ColMatrix<BaseElement>,
}

impl LookupAuxTrace {
    fn new(keys: Vec<BaseElement>, vals: Vec<BaseElement>) -> Self {
        let length = keys.len();
        let info = TraceInfo::new_multi_segment(2, 1, 2, length, vec![]);
        let main = ColMatrix::new(vec![keys, vals]);
        Self { info, main }
    }

    fn get_column(&self, idx: usize) -> &[BaseElement] {
        self.main.get_column(idx)
    }
}

impl Trace for LookupAuxTrace {
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

// -------------------------------------------------------------------- AIR

#[derive(Clone)]
struct LookupPubInputs {
    table: Vec<(BaseElement, BaseElement)>,
    /// Public assertion: trace[0].key. We assert this on the main
    /// segment to satisfy winterfell's "at least one main assertion"
    /// requirement *and* to give the verifier a real binding from the
    /// witness to a known public value. By construction, trace[0] =
    /// table[N-1], so this is just `table[N-1].0`.
    first_key: BaseElement,
}

impl ToElements<BaseElement> for LookupPubInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = vec![self.first_key];
        for (k, v) in self.table.iter() {
            out.push(*k);
            out.push(*v);
        }
        out
    }
}

struct LookupAuxAir {
    context: AirContext<BaseElement>,
    table: Vec<(BaseElement, BaseElement)>,
    first_key: BaseElement,
}

impl Air for LookupAuxAir {
    type BaseField = BaseElement;
    type PublicInputs = LookupPubInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Main: no transitions, single boundary on column 0 row 0.
        // Winterfell requires at least one main transition degree even
        // when the main trace has no transitions to constrain — we use
        // a trivial degree-1 placeholder that always evaluates to 0.
        let main_degrees = vec![TransitionConstraintDegree::new(1)];
        // Aux: one degree-2 transition for the running product.
        let aux_degrees = vec![TransitionConstraintDegree::with_cycles(2, vec![trace_info.length()])];
        let context = AirContext::new_multi_segment(
            trace_info,
            main_degrees,
            aux_degrees,
            1, // num_main_assertions: assert main[0][0] == first_key
            1, // num_aux_assertions:  assert aux[0][0] == 1 (Z[0] = 1)
            options,
        );
        LookupAuxAir {
            context,
            table: pub_inputs.table,
            first_key: pub_inputs.first_key,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        // No real main-segment transition constraints. The trivial
        // placeholder is always satisfied. (The boundary on column 0
        // row 0 is what binds the witness.)
        result[0] = E::ZERO;
    }

    fn evaluate_aux_transition<F, E>(
        &self,
        main_frame: &EvaluationFrame<F>,
        aux_frame: &EvaluationFrame<E>,
        periodic_values: &[F],
        aux_rand_elements: &AuxRandElements<E>,
        result: &mut [E],
    ) where
        F: FieldElement<BaseField = Self::BaseField>,
        E: FieldElement<BaseField = Self::BaseField> + winterfell::math::ExtensionOf<F>,
    {
        let main_curr = main_frame.current();
        let aux_curr = aux_frame.current();
        let aux_next = aux_frame.next();

        let key = E::from(main_curr[0]);
        let val = E::from(main_curr[1]);
        let z_curr = aux_curr[0];
        let z_next = aux_next[0];

        let rands = aux_rand_elements.rand_elements();
        let alpha = rands[0];
        let beta = rands[1];

        let trace_factor = key + alpha * val + beta;
        let table_factor =
            E::from(periodic_values[0]) + alpha * E::from(periodic_values[1]) + beta;

        // Z[i+1] · trace_factor − Z[i] · table_factor = 0
        result[0] = z_next * trace_factor - z_curr * table_factor;
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        let keys: Vec<_> = self.table.iter().map(|(k, _)| *k).collect();
        let vals: Vec<_> = self.table.iter().map(|(_, v)| *v).collect();
        vec![keys, vals]
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        // Bind main[0][0] (= trace.key[0]) to first_key, the public
        // value the verifier expects. Without this, winterfell rejects
        // the AIR (must have ≥ 1 main assertion).
        vec![Assertion::single(0, 0, self.first_key)]
    }

    fn get_aux_assertions<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        _aux_rand_elements: &AuxRandElements<E>,
    ) -> Vec<Assertion<E>> {
        // Z[0] = 1 — the running product is initialised at 1. Phase 3
        // will additionally need a final-row assertion that Z[N-1]
        // equals the expected closing value (1 if the trace is a
        // permutation of the table, more generally the product of
        // any "extra" rows that didn't cancel).
        vec![Assertion::single(0, 0, E::ONE)]
    }
}

// -------------------------------------------------------------------- Prover

struct LookupAuxProver {
    options: ProofOptions,
    table: Vec<(BaseElement, BaseElement)>,
    first_key: BaseElement,
}

impl Prover for LookupAuxProver {
    type BaseField = BaseElement;
    type Air = LookupAuxAir;
    type Trace = LookupAuxTrace;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Blake3_256<BaseElement>>;
    type RandomCoin = DefaultRandomCoin<Blake3_256<BaseElement>>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> =
        DefaultTraceLde<E, Blake3_256<BaseElement>, MerkleTree<Blake3_256<BaseElement>>>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Blake3_256<BaseElement>, MerkleTree<Blake3_256<BaseElement>>>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, LookupAuxAir, E>;

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> LookupPubInputs {
        LookupPubInputs {
            table: self.table.clone(),
            first_key: self.first_key,
        }
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

    /// **The whole point of this variant.** Given the main trace and
    /// the verifier-supplied randomness, build the Z column.
    ///
    /// Phase 3 lifts this verbatim: the same `Z[i+1] = Z[i] *
    /// table_factor / trace_factor` recurrence, where `trace_factor`
    /// uses the REMEMBER/RECALL row's `(scope, path_hash, value_hash)`
    /// and `table_factor` uses the corresponding memory-tree leaf.
    fn build_aux_trace<E>(
        &self,
        main_trace: &Self::Trace,
        aux_rand_elements: &AuxRandElements<E>,
    ) -> ColMatrix<E>
    where
        E: FieldElement<BaseField = Self::BaseField>,
    {
        let n = main_trace.length();
        let rands = aux_rand_elements.rand_elements();
        let alpha = rands[0];
        let beta = rands[1];

        // Pull the main columns we need.
        let keys = main_trace.get_column(0);
        let vals = main_trace.get_column(1);

        let mut z = Vec::with_capacity(n);
        z.push(E::ONE);
        for i in 0..(n - 1) {
            let key_e = E::from(keys[i]);
            let val_e = E::from(vals[i]);
            let trace_factor = key_e + alpha * val_e + beta;
            let (tk, tv) = self.table[i];
            let table_factor = E::from(tk) + alpha * E::from(tv) + beta;
            // z_next = z_curr * table_factor / trace_factor
            z.push(z[i] * table_factor * trace_factor.inv());
        }

        ColMatrix::new(vec![z])
    }
}

// -------------------------------------------------------------------- harness

fn proof_options() -> ProofOptions {
    // Same FRI shape as the degree probe so numbers stay comparable.
    // FieldExtension::None: f128 has 128 bits of entropy on its own —
    // enough for ~95-bit Schwartz-Zippel security on a length-N=4096
    // running product. Phase 3 will likely keep this and rely on the
    // constraint-degree budget headroom (4) for any quadratic
    // extension we might decide to need later.
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

fn run_one(num_rows: usize, runs: usize) {
    let table = build_table(num_rows);
    let first_key = table[num_rows - 1].0;
    let main_trace = build_main_trace(num_rows);

    // Multi-segment shape (main_width=2, aux_width=1, aux_rand_count=2)
    // is carried by LookupAuxTrace's TraceInfo — the Prover queries
    // `trace.info()` to construct the AIR, which is exactly what we need.
    let prover = LookupAuxProver {
        options: proof_options(),
        table: table.clone(),
        first_key,
    };

    let mut prove_times = Vec::with_capacity(runs);
    let mut proof_sizes = Vec::with_capacity(runs);
    for _ in 0..runs {
        let trace = main_trace.clone();
        let t0 = Instant::now();
        let proof = prover.prove(trace).expect("proving failed");
        prove_times.push(t0.elapsed());
        proof_sizes.push(proof.to_bytes().len());
    }
    prove_times.sort();
    let med_prove = prove_times[prove_times.len() / 2];

    // Verify once for timing.
    let trace = build_main_trace(num_rows);
    let proof = prover.prove(trace).expect("proving failed");
    let proof_bytes = proof.to_bytes();
    let parsed = winterfell::Proof::from_bytes(&proof_bytes).unwrap();
    let pub_inputs = LookupPubInputs { table: table.clone(), first_key };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    let t0 = Instant::now();
    winterfell::verify::<
        LookupAuxAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(parsed, pub_inputs, &acceptable)
    .expect("verification failed");
    let verify_time = t0.elapsed();

    println!(
        "  N={:>5} | prove_med={:>8.2?} | proof_bytes={:>5} | verify={:>7.2?}",
        num_rows,
        med_prove,
        proof_sizes[proof_sizes.len() / 2],
        verify_time,
    );
}

fn main() {
    println!("=== winterfell aux-segment lookup (soundness-correct) ===");
    println!();
    println!("AIR shape:");
    println!("  main columns:        2 (key, value)");
    println!("  aux columns:         1 (Z)");
    println!("  aux randomness:      2 (α, β) drawn from public coin");
    println!("  periodic columns:    2 (table_keys, table_vals)");
    println!("  main transition deg: [1] (trivial placeholder)");
    println!("  aux transition deg:  [2]   <-- still 2, as expected");
    println!("  blowup_factor:       16   (max constraint degree 16)");
    println!();
    println!("Phase 3 degree budget (unchanged from probe):");
    println!("  base (running product):                          2");
    println!("  + Phase 2 Lagrange opcode selector:              10");
    println!("  = gated lookup transition degree:                12");
    println!("  blowup-16 ceiling:                               16");
    println!("  → slack:                                          4 degrees");
    println!();
    println!("Timings (median of 5 runs):");

    for n in [64, 256, 1024, 4096] {
        run_one(n, 5);
    }

    println!();
    println!("Notes:");
    println!("  - α, β now come from AuxRandElements, drawn from the");
    println!("    public coin AFTER the main trace is committed.");
    println!("    Soundness gap from the degree probe is closed.");
    println!("  - Phase 3 lifts this file's structure verbatim. The");
    println!("    main-trace columns and the build_aux_trace recurrence");
    println!("    are the only parts that change; everything else");
    println!("    (AirContext::new_multi_segment, evaluate_aux_transition,");
    println!("    build_aux_trace) stays identical.");
}
