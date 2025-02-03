use crate::poseidon2::{
    F,
    chip::merkle_tree::{air::MerkleTreeAir, column::NUM_MERKLE_TREE_COLS},
    hash_sig::{LOG_LIFETIME, PARAM_FE_LEN, TH_HASH_FE_LEN},
};
use core::any::type_name;
use generation::{generate_trace_rows, trace_height};
use openvm_stark_backend::{
    Chip, ChipUsageGetter,
    config::{Domain, StarkGenericConfig},
    p3_commit::PolynomialSpace,
    p3_field::FieldAlgebra,
    prover::types::{AirProofInput, AirProofRawInput},
    rap::AnyRap,
};
use std::sync::Arc;

mod air;
mod column;
mod generation;

pub struct MerkleTreeChip {
    extra_capacity_bits: usize,
    epoch: u32,
    inputs: Vec<(
        [F; PARAM_FE_LEN],
        [F; TH_HASH_FE_LEN],
        [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
    )>,
}

impl MerkleTreeChip {
    pub fn new(
        extra_capacity_bits: usize,
        epoch: u32,
        inputs: Vec<(
            [F; PARAM_FE_LEN],
            [F; TH_HASH_FE_LEN],
            [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
        )>,
    ) -> Self {
        Self {
            extra_capacity_bits,
            epoch,
            inputs,
        }
    }
}

impl ChipUsageGetter for MerkleTreeChip {
    fn air_name(&self) -> String {
        type_name::<MerkleTreeAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(&self.inputs)
    }

    fn trace_width(&self) -> usize {
        NUM_MERKLE_TREE_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for MerkleTreeChip
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    fn air(&self) -> Arc<dyn AnyRap<SC>> {
        Arc::new(MerkleTreeAir)
    }

    fn generate_air_proof_input(self) -> AirProofInput<SC> {
        AirProofInput {
            cached_mains_pdata: Vec::new(),
            raw: AirProofRawInput {
                cached_mains: Vec::new(),
                common_main: Some(generate_trace_rows(
                    self.extra_capacity_bits,
                    self.epoch,
                    self.inputs,
                )),
                public_values: vec![F::from_canonical_u32(self.epoch)],
            },
        }
    }
}
