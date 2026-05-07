//! Lookup-argument degree probe — winterfell main-segment variant.
//!
//! **What this measures:** the constraint degree of a randomized-sum
//! lookup argument when expressed in winterfell. This is the gating
//! number for Phase 3 — with `blowup_factor = 16` (max degree 16) and
//! a degree-10 opcode selector already burned, the lookup itself must
//! stay ≤ 6 to avoid bumping the blowup.
//!
//! **What this does NOT measure:** soundness of a real lookup argument.
//! A correct lookup uses verifier-supplied randomness drawn from the
//! main-trace commitment (winterfell's auxiliary segment machinery).
//! Here the random challenges `α`, `β` are deterministically derived
//! from the public table, which would let a malicious prover grind a
//! trace that satisfies the running-product check without containing
//! valid memory accesses. That's fine for *this* probe because the
//! transition polynomial has the same shape either way; the auxiliary
//! segment just changes which segment the `Z` column lives in, not its
//! algebraic degree.
//!
//! **Output:** a measurement table to stdout. Numbers go in the
//! README's §Results section by hand.
//!
//! Run: `cargo run --release --bin winterfell_lookup`.

use std::time::Instant;
use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin, MerkleTree},
    math::{fields::f128::BaseElement, FieldElement, StarkField, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, BatchingMethod, ConstraintCompositionCoefficients,
    DefaultConstraintCommitment, DefaultConstraintEvaluator, DefaultTraceLde,
    EvaluationFrame, FieldExtension, PartitionOptions, ProofOptions, Prover,
    StarkDomain, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
    AuxRandElements, CompositionPoly, CompositionPolyTrace,
};

// -------------------------------------------------------------------- toy problem

/// Build a length-N table whose rows are the trace's rows in a fixed
/// permuted order. Multiset equality between trace and table is what the
/// running-product check verifies. Using N table rows (instead of 4
/// repeated periodically) keeps the table column non-periodic, which is
/// necessary because winterfell's DEEP composer asserts the trace
/// polynomials have degree exactly `trace_length - 1`. Periodic data
/// (period p) collapses to degree `N - N/p`, failing that assertion.
fn build_table(num_rows: usize) -> Vec<(BaseElement, BaseElement)> {
    // Use a Weyl-style sequence so each row has unique (k, v) values.
    // This stands in for the per-row leaves of a Phase 3 memory tree,
    // where each access has a distinct (scope, path_hash, value_hash).
    let mut out = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        let k = ((i as u128).wrapping_mul(0x9E3779B97F4A7C15)) | 1;
        let v = ((i as u128).wrapping_mul(0xBB67AE8584CAA73B)) | 1;
        out.push((BaseElement::new(k), BaseElement::new(v)));
    }
    out
}

/// Build a witness trace whose `(key, value)` rows are a permutation of
/// `table`. Z is the running product such that Z[0] = 1.
fn build_valid_trace(num_rows: usize) -> TraceTable<BaseElement> {
    assert!(num_rows.is_power_of_two() && num_rows >= 64);
    let table = build_table(num_rows);
    let (alpha, beta) = derive_challenges(&table);

    // Trace rows = table rows in reverse order. This guarantees each row
    // has trace_factor[i] != table_factor[i] (almost always), so Z
    // genuinely varies, and the multiset still matches.
    let mut keys = Vec::with_capacity(num_rows);
    let mut vals = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        let (k, v) = table[num_rows - 1 - i];
        keys.push(k);
        vals.push(v);
    }

    let mut z = Vec::with_capacity(num_rows);
    z.push(BaseElement::ONE);
    for i in 0..(num_rows - 1) {
        let trace_factor = keys[i] + alpha * vals[i] + beta;
        let (tk, tv) = table[i];
        let table_factor = tk + alpha * tv + beta;
        z.push(z[i] * table_factor * trace_factor.inv());
    }

    TraceTable::init(vec![keys, vals, z])
}

/// Domain-separated derivation of `(α, β)` from the public table.
/// **Not soundness-correct** — see file header. We only care about the
/// degree of the resulting transition polynomial, which is the same
/// regardless of where the randomness comes from.
fn derive_challenges(table: &[(BaseElement, BaseElement)]) -> (BaseElement, BaseElement) {
    let mut a: u128 = 0x9E3779B97F4A7C15;
    let mut b: u128 = 0xBB67AE8584CAA73B;
    for (k, v) in table {
        a = a.wrapping_mul(0x100000001B3).wrapping_add(k.as_int());
        b = b.wrapping_mul(0x100000001B3).wrapping_add(v.as_int());
    }
    (BaseElement::new(a), BaseElement::new(b))
}

// -------------------------------------------------------------------- AIR

#[derive(Clone)]
struct LookupPubInputs {
    alpha: BaseElement,
    beta: BaseElement,
    table: Vec<(BaseElement, BaseElement)>,
}

impl ToElements<BaseElement> for LookupPubInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut out = vec![self.alpha, self.beta];
        for (k, v) in self.table.iter() {
            out.push(*k);
            out.push(*v);
        }
        out
    }
}

struct LookupAir {
    context: AirContext<BaseElement>,
    alpha: BaseElement,
    beta: BaseElement,
    table: Vec<(BaseElement, BaseElement)>,
}

impl Air for LookupAir {
    type BaseField = BaseElement;
    type PublicInputs = LookupPubInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // Transition: Z[i+1] · trace_factor[i] − Z[i] · table_factor[i] = 0
        //   trace_factor = key + α·value + β        (degree 1 in main cols)
        //   table_factor = pcol[0] + α·pcol[1] + β  (degree 1 in periodic
        //                                            cols, period = N)
        // Z (degree 1 in main) × either factor → degree 2 total.
        // Period-N periodic columns behave like regular trace columns
        // for degree-accounting purposes.
        let n = trace_info.length();
        let degrees = vec![TransitionConstraintDegree::with_cycles(2, vec![n])];
        // For this probe we only assert Z[0] = 1 (the running-product
        // initial value). Asserting Z[N-1] would require N to align with
        // the table's permutation cycle so the multiset cancels exactly
        // at the last row — straightforward to arrange but orthogonal to
        // the degree question we're measuring here.
        let num_assertions = 1;
        LookupAir {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            alpha: pub_inputs.alpha,
            beta: pub_inputs.beta,
            table: pub_inputs.table,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let curr = frame.current();
        let next = frame.next();
        let key = curr[0];
        let val = curr[1];
        let z_curr = curr[2];
        let z_next = next[2];

        let alpha = E::from(self.alpha);
        let beta = E::from(self.beta);

        let trace_factor = key + alpha * val + beta;

        // The table factor is taken from a periodic column so it cycles
        // through the four table rows.
        let table_factor = periodic_values[0] + alpha * periodic_values[1] + beta;

        // z_next * trace_factor − z_curr * table_factor = 0
        result[0] = z_next * trace_factor - z_curr * table_factor;
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<Self::BaseField>> {
        // Two length-N periodic columns: table keys and table vals.
        // Length-N means the column doesn't actually cycle within the
        // trace — it's effectively a static column the prover doesn't
        // commit to but the verifier reads from public inputs.
        let keys: Vec<_> = self.table.iter().map(|(k, _)| *k).collect();
        let vals: Vec<_> = self.table.iter().map(|(_, v)| *v).collect();
        vec![keys, vals]
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![Assertion::single(2, 0, BaseElement::ONE)]
    }
}

// -------------------------------------------------------------------- Prover

struct LookupProver {
    options: ProofOptions,
    alpha: BaseElement,
    beta: BaseElement,
    table: Vec<(BaseElement, BaseElement)>,
}

impl Prover for LookupProver {
    type BaseField = BaseElement;
    type Air = LookupAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type VC = MerkleTree<Blake3_256<BaseElement>>;
    type RandomCoin = DefaultRandomCoin<Blake3_256<BaseElement>>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Blake3_256<BaseElement>, MerkleTree<Blake3_256<BaseElement>>>;
    type ConstraintCommitment<E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintCommitment<E, Blake3_256<BaseElement>, MerkleTree<Blake3_256<BaseElement>>>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, LookupAir, E>;

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> LookupPubInputs {
        LookupPubInputs {
            alpha: self.alpha,
            beta: self.beta,
            table: self.table.clone(),
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
}

// -------------------------------------------------------------------- bench harness

fn proof_options() -> ProofOptions {
    // Matches `src/crypto.rs::cf_proof_options()` exactly so the
    // measured prove time is comparable to Phase 2's CF proof.
    ProofOptions::new(
        32,                              // num_queries
        16,                              // blowup_factor — main crate's value
        0,                               // grinding_factor
        FieldExtension::None,
        8,                               // FRI folding
        31,                              // FRI remainder max degree
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    )
}

fn run_one(num_rows: usize, runs: usize) {
    let table = build_table(num_rows);
    let (alpha, beta) = derive_challenges(&table);
    let trace = build_valid_trace(num_rows);
    let prover = LookupProver {
        options: proof_options(),
        alpha,
        beta,
        table: table.clone(),
    };

    let mut prove_times = Vec::with_capacity(runs);
    let mut proof_sizes = Vec::with_capacity(runs);
    for _ in 0..runs {
        let trace = trace.clone();
        let t0 = Instant::now();
        let proof = prover.prove(trace).expect("proving failed");
        prove_times.push(t0.elapsed());
        proof_sizes.push(proof.to_bytes().len());
    }
    prove_times.sort();
    let med_prove = prove_times[prove_times.len() / 2];

    // Verify once for timing.
    let trace = build_valid_trace(num_rows);
    let proof = prover.prove(trace).expect("proving failed");
    let proof_bytes = proof.to_bytes();
    let parsed = winterfell::Proof::from_bytes(&proof_bytes).unwrap();
    let pub_inputs = LookupPubInputs { alpha, beta, table: table.clone() };
    let acceptable = winterfell::AcceptableOptions::MinConjecturedSecurity(95);
    let t0 = Instant::now();
    winterfell::verify::<
        LookupAir,
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
    println!("=== winterfell lookup-argument degree probe ===");
    println!();
    println!("AIR shape:");
    println!("  main columns:        3 (key, value, Z)");
    println!("  periodic columns:    2 (table_keys, table_vals; period=N)");
    println!("  transition degrees:  [2]   <-- the headline number");
    println!("  blowup_factor:       16   (max constraint degree 16)");
    println!();
    println!("Phase 3 degree budget:");
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
    println!("  - Challenges derived from public table, NOT verifier randomness.");
    println!("    Use auxiliary segment for soundness-correct version (next");
    println!("    iteration). The transition polynomial degree is the same");
    println!("    regardless — what changes is which segment Z lives in.");
    println!("  - Table is materialized as two length-N periodic columns. In");
    println!("    Phase 3, the table is the memory commitment leaves; the");
    println!("    AIR doesn't have to materialize them column-wise — a Merkle");
    println!("    membership proof per row is the production shape.");
}
