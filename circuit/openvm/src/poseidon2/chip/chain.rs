use crate::poseidon2::{
    F,
    chip::chain::{air::ChainAir, column::NUM_CHAIN_COLS},
    hash_sig::{NUM_CHUNKS, VerificationTrace, encode_tweak_merkle_tree},
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

pub const GROUP_SIZE: usize = 13;
pub const NUM_GROUPS: usize = NUM_CHUNKS.div_ceil(GROUP_SIZE);

mod air;
mod column;
mod generation;

mod poseidon2 {
    pub const WIDTH: usize = 16;
    pub const PARTIAL_ROUNDS: usize = 13;
}

pub struct ChainChip<'a> {
    air: Arc<ChainAir>,
    extra_capacity_bits: usize,
    epoch: u32,
    traces: &'a [VerificationTrace],
}

impl<'a> ChainChip<'a> {
    pub fn new(extra_capacity_bits: usize, epoch: u32, traces: &'a [VerificationTrace]) -> Self {
        Self {
            air: Default::default(),
            extra_capacity_bits,
            epoch,
            traces,
        }
    }
}

impl ChipUsageGetter for ChainChip<'_> {
    fn air_name(&self) -> String {
        type_name::<ChainAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn trace_width(&self) -> usize {
        NUM_CHAIN_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for ChainChip<'_>
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
                    self.traces,
                )),
                public_values: encode_tweak_merkle_tree(0, self.epoch).to_vec(),
            },
        }
    }
}
