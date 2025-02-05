use crate::poseidon2::{
    F,
    chip::merkle_tree::{air::MerkleTreeAir, column::NUM_MERKLE_TREE_COLS},
    concat_array,
    hash_sig::{
        LOG_LIFETIME, PARAM_FE_LEN, TH_HASH_FE_LEN, encode_tweak_merkle_tree, poseidon2_compress,
    },
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
use std::{array::from_fn, sync::Arc};

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

    pub fn poseidon2_t24_compress(&self) -> impl Iterator<Item = [F; 22]> {
        self.inputs
            .iter()
            .flat_map(move |(parameter, leaf, siblings)| {
                let mut node = *leaf;
                siblings.iter().enumerate().map(move |(level, sibling)| {
                    let input = concat_array![
                        *parameter,
                        encode_tweak_merkle_tree(level as u32 + 1, self.epoch >> (level + 1)),
                        if (self.epoch >> level) & 1 == 0 {
                            [node, *sibling].into_iter().flatten()
                        } else {
                            [*sibling, node].into_iter().flatten()
                        }
                    ];
                    node = poseidon2_compress::<24, 21, TH_HASH_FE_LEN>(input);
                    from_fn(|i| input.get(i).copied().unwrap_or_default())
                })
            })
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
