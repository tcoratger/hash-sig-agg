use crate::poseidon2::{
    F,
    chip::decomposition::{
        air::DecompositionAir, column::NUM_DECOMPOSITION_COLS, generation::trace_height,
    },
    hash_sig::VerificationTrace,
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

pub struct DecompositionChip<'a> {
    extra_capacity_bits: usize,
    epoch: u32,
    traces: &'a [VerificationTrace],
}

impl<'a> DecompositionChip<'a> {
    pub fn new(extra_capacity_bits: usize, epoch: u32, traces: &'a [VerificationTrace]) -> Self {
        Self {
            extra_capacity_bits,
            epoch,
            traces,
        }
    }
}

impl ChipUsageGetter for DecompositionChip<'_> {
    fn air_name(&self) -> String {
        type_name::<DecompositionAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(self.traces)
    }

    fn trace_width(&self) -> usize {
        NUM_DECOMPOSITION_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for DecompositionChip<'_>
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    fn air(&self) -> Arc<dyn AnyRap<SC>> {
        Arc::new(DecompositionAir)
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
                public_values: Vec::new(),
            },
        }
    }
}
