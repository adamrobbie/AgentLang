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

// ------------------------------------------------------------------------------------------------
// FIBONACCI AIR
// ------------------------------------------------------------------------------------------------

pub struct PublicInputs {
    pub col0_last: BaseElement,
    pub col1_last: BaseElement,
    pub claim_hash: BaseElement,
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.col0_last, self.col1_last, self.claim_hash]
    }
}

pub struct FibAir {
    context: AirContext<BaseElement>,
    pub_inputs: PublicInputs,
}

impl Air for FibAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![
            winterfell::TransitionConstraintDegree::new(1),
            winterfell::TransitionConstraintDegree::new(1),
        ];
        let num_assertions = 4;
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        Self {
            context,
            pub_inputs,
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, BaseElement::ONE),
            Assertion::single(1, 0, BaseElement::ONE),
            Assertion::single(0, last_step, self.pub_inputs.col0_last),
            Assertion::single(1, last_step, self.pub_inputs.col1_last),
            // The claim_hash is a public input that we assert is correct.
            // In a more complex AIR, this would be tied to the trace.
            // For this prototype, we just verify it matches the public input.
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
        result[0] = next[0] - current[1];
        result[1] = next[1] - (current[0] + current[1]);
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ------------------------------------------------------------------------------------------------
// FIBONACCI PROVER
// ------------------------------------------------------------------------------------------------

pub struct FibProver {
    options: ProofOptions,
    claim_hash: BaseElement,
}

impl FibProver {
    pub fn new(options: ProofOptions, claim_hash: BaseElement) -> Self {
        Self { options, claim_hash }
    }

    pub fn build_trace(&self, n: usize) -> TraceTable<BaseElement> {
        let mut trace = TraceTable::new(2, n);
        trace.fill(
            |state| {
                state[0] = BaseElement::ONE;
                state[1] = BaseElement::ONE;
            },
            |_, state| {
                let next = state[0] + state[1];
                state[0] = state[1];
                state[1] = next;
            },
        );
        trace
    }
}

impl Prover for FibProver {
    type BaseField = BaseElement;
    type Air = FibAir;
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
            col0_last: trace.get(0, last_step),
            col1_last: trace.get(1, last_step),
            claim_hash: self.claim_hash,
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

#[derive(Serialize, Deserialize, Clone)]
pub struct StarkProof {
    pub proof: Vec<u8>,
    pub col0_last: u64,
    pub col1_last: u64,
    pub claim_hash: u64,
    pub num_steps: usize,
}

fn hash_claim(claim: &str) -> BaseElement {
    let mut h: u128 = 0;
    for b in claim.as_bytes() {
        h = h.wrapping_add(*b as u128).wrapping_mul(31);
    }
    BaseElement::new(h)
}

pub fn generate_proof(n: usize, claim: &str) -> anyhow::Result<StarkProof> {
    let options = ProofOptions::new(
        32,
        8,
        0,
        FieldExtension::None,
        8,
        31,
        BatchingMethod::Linear,
        BatchingMethod::Linear,
    );

    let claim_hash = hash_claim(claim);
    let prover = FibProver::new(options, claim_hash);
    let trace = prover.build_trace(n);
    let pub_inputs = prover.get_pub_inputs(&trace);

    let proof = prover
        .prove(trace)
        .map_err(|e| anyhow::anyhow!("STARK proving failed: {}", e))?;

    Ok(StarkProof {
        proof: proof.to_bytes(),
        col0_last: pub_inputs.col0_last.as_int() as u64,
        col1_last: pub_inputs.col1_last.as_int() as u64,
        claim_hash: pub_inputs.claim_hash.as_int() as u64,
        num_steps: n,
    })
}

pub fn verify_proof(proof_data: &StarkProof, claim: &str) -> anyhow::Result<()> {
    let expected_claim_hash = hash_claim(claim);
    if proof_data.claim_hash != expected_claim_hash.as_int() as u64 {
        return Err(anyhow::anyhow!("Proof was not generated for this claim"));
    }

    let proof = Proof::from_bytes(&proof_data.proof)
        .map_err(|e| anyhow::anyhow!("Failed to parse STARK proof: {}", e))?;

    let pub_inputs = PublicInputs {
        col0_last: BaseElement::new(proof_data.col0_last as u128),
        col1_last: BaseElement::new(proof_data.col1_last as u128),
        claim_hash: expected_claim_hash,
    };
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);

    winterfell::verify::<
        FibAir,
        Blake3_256<BaseElement>,
        DefaultRandomCoin<Blake3_256<BaseElement>>,
        MerkleTree<Blake3_256<BaseElement>>,
    >(proof, pub_inputs, &min_opts)
    .map_err(|e| anyhow::anyhow!("STARK verification failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_proof_success() {
        let proof_data = generate_proof(64, "my_claim").unwrap();
        assert!(verify_proof(&proof_data, "my_claim").is_ok());
    }

    #[test]
    fn test_verify_proof_invalid_inputs() {
        let mut proof_data = generate_proof(64, "my_claim").unwrap();
        // Tamper with public inputs
        proof_data.col0_last += 1;
        assert!(verify_proof(&proof_data, "my_claim").is_err());
    }

    #[test]
    fn test_verify_proof_invalid_claim() {
        let proof_data = generate_proof(64, "correct_claim").unwrap();
        assert!(verify_proof(&proof_data, "wrong_claim").is_err());
    }

    #[test]
    fn test_verify_proof_invalid_proof() {
        let mut proof_data = generate_proof(64, "my_claim").unwrap();
        // Tamper with proof bytes
        if let Some(byte) = proof_data.proof.get_mut(100) {
            *byte ^= 0xFF;
        }
        assert!(verify_proof(&proof_data, "my_claim").is_err());
    }
}
