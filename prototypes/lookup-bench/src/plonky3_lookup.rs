//! Lookup-argument degree probe — Plonky3 variant.
//!
//! **Why this is not a LogUp port.** Plonky3's `p3-lookup` ships LogUp
//! as a constraint-evaluation gadget that hooks into `PermutationAirBuilder`,
//! not as a drop-in prover. Wiring it end-to-end requires a custom
//! multi-AIR prover that handles the permutation segment and extension-
//! field running sums (SP1, Valida, etc. each maintain their own).
//! `p3-uni-stark::prove` — the only released single-AIR prover — does
//! not support that flow in 0.5.2.
//!
//! **What we actually measure.** The same running-product running-sum
//! that the winterfell variant uses, written in `p3-air` against
//! `p3-uni-stark`. This gives an apples-to-apples comparison of:
//!   - prove time on the same algebraic shape (degree-2 transition),
//!   - proof size,
//!   - verify time,
//!   - end-to-end ergonomics of the two AIR DSLs.
//!
//! The number we *don't* get from this prototype is "what does Plonky3
//! LogUp cost when you build a real prover for it?". That's a 1–2 week
//! engineering item on its own and is captured as a follow-on in the
//! README §Decision section.
//!
//! Other deliberate matches with `winterfell_lookup.rs`:
//!   - same toy problem (length-N (key, value) trace = permutation of
//!     length-N table),
//!   - challenges `α, β` derived deterministically from the public
//!     table (degree probe, not soundness-correct — see winterfell
//!     header for the rationale),
//!   - `blowup_factor = 16` (Plonky3: `log_blowup = 4`),
//!   - `num_queries = 32`.
//!
//! Run: `cargo run --release --bin plonky3_lookup`.

use std::time::Instant;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField32};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;

// -------------------------------------------------------------------- field setup

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMmcs =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

// -------------------------------------------------------------------- toy problem

/// Length-N table whose rows the trace permutes. Same construction as
/// the winterfell variant: a Weyl sequence so each row is unique.
/// BabyBear is a 31-bit prime field, so `(k, v)` are `u32 mod p`. We
/// mask to 31 bits to keep them well below the field modulus.
fn build_table(num_rows: usize) -> Vec<(Val, Val)> {
    let mut out = Vec::with_capacity(num_rows);
    for i in 0..num_rows {
        let k = ((i as u64).wrapping_mul(0x9E3779B97F4A7C15) >> 33) as u32;
        let v = ((i as u64).wrapping_mul(0xBB67AE8584CAA73B) >> 33) as u32;
        // BabyBear modulus is ~2^31 - 2^27 + 1 — masking to 30 bits
        // keeps us safely under it.
        out.push((Val::from_u32(k & ((1 << 30) - 1)), Val::from_u32(v & ((1 << 30) - 1))));
    }
    out
}

/// Same domain-separated derivation as winterfell — see that variant's
/// `derive_challenges` for the rationale. Output lifted into the
/// extension field so the running product can absorb random folds.
fn derive_challenges(table: &[(Val, Val)]) -> (Challenge, Challenge) {
    let mut a: u64 = 0x9E3779B97F4A7C15;
    let mut b: u64 = 0xBB67AE8584CAA73B;
    for (k, v) in table {
        a = a
            .wrapping_mul(0x100000001B3)
            .wrapping_add(k.as_canonical_u32() as u64);
        b = b
            .wrapping_mul(0x100000001B3)
            .wrapping_add(v.as_canonical_u32() as u64);
    }
    (
        Challenge::from(Val::from_u32((a as u32) & ((1 << 30) - 1))),
        Challenge::from(Val::from_u32((b as u32) & ((1 << 30) - 1))),
    )
}

/// Build the trace.
///
/// Columns: `[trace_key, trace_val, table_key, table_val, z]`.
///
/// `(table_key, table_val)` are pinned columns whose values are the
/// public table. They live in the main trace because `p3-uni-stark`
/// has no periodic-column concept. `(trace_key, trace_val)` are the
/// witness — set to a permutation of the table rows.
///
/// `z` is the running product: `z[0] = 1`, and at every transition
/// `z[i+1] · trace_factor[i] = z[i] · table_factor[i]`.
fn build_trace(num_rows: usize) -> (RowMajorMatrix<Val>, Challenge, Challenge) {
    assert!(num_rows.is_power_of_two() && num_rows >= 64);
    let table = build_table(num_rows);
    let (alpha, beta) = derive_challenges(&table);

    // Witness rows = table rows in reverse order. Same as winterfell
    // variant: guarantees row-by-row Z variation while keeping the
    // multiset matched.
    let mut flat: Vec<Val> = Vec::with_capacity(num_rows * NUM_COLS);

    // For computing Z over the extension field. Plonky3's running
    // product needs to be expressed in the base field, but the
    // running product itself is naturally in the extension because
    // α, β are extension-field values. To keep Z in the base field
    // (so it can live in the main trace), we use the *base-field
    // image* of the challenges: α₀, β₀ ∈ Val. This loses some
    // soundness (the degree probe doesn't need it) but lets the
    // single-AIR prover handle the column directly.
    let alpha0: Val = base_part(alpha);
    let beta0: Val = base_part(beta);

    let mut z = Val::ONE;
    for i in 0..num_rows {
        let t_idx = num_rows - 1 - i;
        let trace_key = table[t_idx].0;
        let trace_val = table[t_idx].1;
        let table_key = table[i].0;
        let table_val = table[i].1;

        flat.push(trace_key);
        flat.push(trace_val);
        flat.push(table_key);
        flat.push(table_val);
        flat.push(z);

        // Update z for the next row. Using base-field α, β.
        let trace_factor = trace_key + alpha0 * trace_val + beta0;
        let table_factor = table_key + alpha0 * table_val + beta0;
        // z_next = z_curr * table_factor / trace_factor
        z = z * table_factor * trace_factor.try_inverse().expect("zero trace_factor");
    }

    (RowMajorMatrix::new(flat, NUM_COLS), alpha, beta)
}

/// Project an extension-field element down to its base-field "first
/// coordinate". For the degree probe this is sufficient.
fn base_part(c: Challenge) -> Val {
    // The extension is BinomialExtensionField<Val, 4>. Its as_base_slice
    // returns [a0, a1, a2, a3]; we take a0.
    let coords: &[Val] = c.as_basis_coefficients_slice();
    coords[0]
}

// -------------------------------------------------------------------- AIR

const NUM_COLS: usize = 5;
const COL_TRACE_KEY: usize = 0;
const COL_TRACE_VAL: usize = 1;
const COL_TABLE_KEY: usize = 2;
const COL_TABLE_VAL: usize = 3;
const COL_Z: usize = 4;

struct LookupAir {
    /// Base-field projection of α (used in transition).
    alpha: Val,
    /// Base-field projection of β.
    beta: Val,
}

impl<F> BaseAir<F> for LookupAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // z_next * trace_factor − z_curr * table_factor = 0
        //   trace_factor = key + α·val + β    (degree 1)
        //   z_next       = (degree 1)
        // → product is degree 2.
        Some(2)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for LookupAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        let alpha = AB::Expr::from(self.alpha);
        let beta = AB::Expr::from(self.beta);

        let trace_key: AB::Expr = local[COL_TRACE_KEY].into();
        let trace_val: AB::Expr = local[COL_TRACE_VAL].into();
        let table_key: AB::Expr = local[COL_TABLE_KEY].into();
        let table_val: AB::Expr = local[COL_TABLE_VAL].into();
        let z_curr: AB::Expr = local[COL_Z].into();
        let z_next: AB::Expr = next[COL_Z].into();

        let trace_factor = trace_key + alpha.clone() * trace_val + beta.clone();
        let table_factor = table_key + alpha * table_val + beta;

        // Boundary: Z[0] = 1.
        builder
            .when_first_row()
            .assert_eq(local[COL_Z], AB::Expr::ONE);

        // Transition: Z[i+1] · trace_factor[i] = Z[i] · table_factor[i].
        builder
            .when_transition()
            .assert_eq(z_next * trace_factor, z_curr * table_factor);
    }
}

// -------------------------------------------------------------------- config

fn make_config() -> MyConfig {
    let mut rng = SmallRng::seed_from_u64(0xA61E14A4);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    // Match winterfell's blowup_factor=16, num_queries=32 as closely as
    // the two systems' parameter spaces allow. log_blowup = 4 ↔ 16×.
    // Plonky3 doesn't expose grinding_factor/folding the same way; we
    // use FRI defaults that target ~100-bit security.
    let fri_params = FriParameters {
        log_blowup: 4,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 32,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

// -------------------------------------------------------------------- bench harness

fn run_one(num_rows: usize, runs: usize) {
    let (trace, alpha, beta) = build_trace(num_rows);
    let air = LookupAir {
        alpha: base_part(alpha),
        beta: base_part(beta),
    };
    let pis: Vec<Val> = vec![];

    let mut prove_times = Vec::with_capacity(runs);
    let mut proof_sizes = Vec::with_capacity(runs);
    for _ in 0..runs {
        let trace = trace.clone();
        let config = make_config();
        let t0 = Instant::now();
        let proof = prove(&config, &air, trace, &pis);
        prove_times.push(t0.elapsed());
        let bytes = postcard::to_allocvec(&proof).expect("serialize proof");
        proof_sizes.push(bytes.len());
    }
    prove_times.sort();
    let med_prove = prove_times[prove_times.len() / 2];

    // Verify once for timing.
    let config = make_config();
    let proof = prove(&config, &air, trace.clone(), &pis);
    let config = make_config();
    let t0 = Instant::now();
    verify(&config, &air, &proof, &pis).expect("verification failed");
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
    println!("=== plonky3 (p3-uni-stark) running-product probe ===");
    println!();
    println!("AIR shape:");
    println!("  main columns:        5 (trace_key, trace_val, table_key, table_val, Z)");
    println!("  preprocessed cols:   0");
    println!("  declared max degree: 2   <-- the headline number");
    println!("  log_blowup:          4   (blowup factor 16)");
    println!("  num_queries:         32");
    println!("  field:               BabyBear (31-bit) + 4-extension challenges");
    println!();
    println!("Phase 3 degree budget (same as winterfell):");
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
    println!("  - This is the same running-product trick as the winterfell");
    println!("    variant, NOT a LogUp port. p3-uni-stark 0.5.2 doesn't");
    println!("    expose permutation challenges; LogUp via p3-lookup needs");
    println!("    a custom multi-AIR prover (~1-2 weeks of plumbing).");
    println!("  - Challenges projected to base field for the degree probe.");
    println!("    A real lookup uses extension-field challenges drawn from");
    println!("    the verifier — same algebraic degree.");
    println!("  - Table embedded as 2 main-trace columns (no periodic-");
    println!("    columns concept in p3-uni-stark). In production, the");
    println!("    verifier would check those columns commit to the public");
    println!("    table via a separate hash binding.");
}
