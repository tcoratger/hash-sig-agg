use crate::poseidon2::{
    F,
    chip::chain::{air::ChainAir, column::NUM_CHAIN_COLS},
    concat_array,
    hash_sig::{
        NUM_CHUNKS, PARAM_FE_LEN, SPONGE_INPUT_SIZE, TH_HASH_FE_LEN, chain,
        encode_tweak_merkle_tree,
    },
};
use core::any::type_name;
use generation::generate_trace_rows;
use openvm_stark_backend::{
    Chip, ChipUsageGetter,
    config::{Domain, StarkGenericConfig},
    p3_commit::PolynomialSpace,
    prover::types::{AirProofInput, AirProofRawInput},
    rap::AnyRap,
};
use std::sync::Arc;

mod air;
mod column;
mod generation;

mod poseidon2 {
    pub const WIDTH: usize = 16;
    pub const PARTIAL_ROUNDS: usize = 13;
}

pub struct ChainChip {
    extra_capacity_bits: usize,
    air: Arc<ChainAir>,
    epoch: u32,
    inputs: Vec<(
        [F; PARAM_FE_LEN],
        [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
        [u16; NUM_CHUNKS],
    )>,
}

impl ChainChip {
    pub fn new(
        extra_capacity_bits: usize,
        epoch: u32,
        inputs: impl IntoIterator<
            Item = (
                [F; PARAM_FE_LEN],
                [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
                [u16; NUM_CHUNKS],
            ),
        >,
    ) -> Self {
        Self {
            extra_capacity_bits,
            epoch,
            air: Default::default(),
            inputs: inputs.into_iter().collect(),
        }
    }

    pub fn poseidon2_t24_sponge_inputs(&self) -> Vec<[F; SPONGE_INPUT_SIZE]> {
        self.inputs
            .iter()
            .map(move |(parameter, one_time_sig, x)| {
                let leaves = (0..NUM_CHUNKS)
                    .flat_map(|i| chain(self.epoch, *parameter, i as _, x[i], one_time_sig[i]));
                concat_array![*parameter, encode_tweak_merkle_tree(0, self.epoch), leaves]
            })
            .collect()
    }
}

impl ChipUsageGetter for ChainChip {
    fn air_name(&self) -> String {
        type_name::<ChainAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        todo!()
    }

    fn trace_width(&self) -> usize {
        NUM_CHAIN_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for ChainChip
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    fn air(&self) -> Arc<dyn AnyRap<SC>> {
        self.air.clone()
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
                public_values: Vec::new(),
            },
        }
    }
}
