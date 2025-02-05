use crate::poseidon2::{
    F,
    chip::chain::{air::ChainAir, column::NUM_CHAIN_COLS},
    hash_sig::{NUM_CHUNKS, PublicKey, TH_HASH_FE_LEN},
};
use core::any::type_name;
use generation::{generate_trace_rows, trace_height};
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
        PublicKey,
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
                PublicKey,
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
}

impl ChipUsageGetter for ChainChip {
    fn air_name(&self) -> String {
        type_name::<ChainAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(&self.inputs)
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
