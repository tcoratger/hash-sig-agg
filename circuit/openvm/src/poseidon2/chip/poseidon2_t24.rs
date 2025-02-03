use crate::poseidon2::{
    F,
    chip::poseidon2_t24::{
        air::Poseidon2T24Air, column::NUM_POSEIDON2_T24_COLS, generation::generate_trace_rows,
    },
    hash_sig::SPONGE_INPUT_SIZE,
};
use core::any::type_name;
use generation::trace_height;
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

const WIDTH: usize = 24;
const PARTIAL_ROUNDS: usize = 21;

pub struct Poseidon2T24Chip {
    extra_capacity_bits: usize,
    air: Arc<Poseidon2T24Air>,
    compress_inputs: Vec<[F; 22]>,
    sponge_inputs: Vec<[F; SPONGE_INPUT_SIZE]>,
}

impl Poseidon2T24Chip {
    pub fn new(
        extra_capacity_bits: usize,
        compress_inputs: impl IntoIterator<Item = [F; 22]>,
        sponge_inputs: impl IntoIterator<Item = [F; SPONGE_INPUT_SIZE]>,
    ) -> Self {
        Self {
            extra_capacity_bits,
            air: Default::default(),
            compress_inputs: compress_inputs.into_iter().collect(),
            sponge_inputs: sponge_inputs.into_iter().collect(),
        }
    }
}

impl ChipUsageGetter for Poseidon2T24Chip {
    fn air_name(&self) -> String {
        type_name::<Poseidon2T24Air>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(&self.compress_inputs, &self.sponge_inputs)
    }

    fn trace_width(&self) -> usize {
        NUM_POSEIDON2_T24_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for Poseidon2T24Chip
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
                    self.compress_inputs,
                    self.sponge_inputs,
                )),
                public_values: Vec::new(),
            },
        }
    }
}
