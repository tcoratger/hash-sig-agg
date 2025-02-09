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
    p3_field::PrimeField32,
    prover::types::{AirProofInput, AirProofRawInput},
    rap::AnyRap,
};
use std::sync::Arc;

pub const LIMB_BITS: usize = 13;
pub const LIMB_MASK: u32 = (1 << LIMB_BITS) - 1;
pub const NUM_LIMBS: usize =
    (F::ORDER_U32.next_power_of_two().ilog2() as usize).div_ceil(LIMB_BITS);
pub const NUM_MSG_HASH_LIMBS: usize =
    (5 * F::ORDER_U32.next_power_of_two().ilog2() as usize).div_ceil(LIMB_BITS);
pub const F_MS_LIMB: u32 = {
    assert!(F::ORDER_U32 & LIMB_MASK == 1);
    assert!((F::ORDER_U32 >> LIMB_BITS) & LIMB_MASK == 0);
    F::ORDER_U32 >> (2 * LIMB_BITS)
};
pub const F_MS_LIMB_BITS: usize = F_MS_LIMB.next_power_of_two().ilog2() as usize;

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
