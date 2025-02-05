use crate::poseidon2::{
    F,
    chip::poseidon2_t24::{
        air::Poseidon2T24Air, column::NUM_POSEIDON2_T24_COLS, generation::generate_trace_rows,
    },
    hash_sig::{
        LOG_LIFETIME, MSG_LEN, PublicKey, SPONGE_INPUT_SIZE, TH_HASH_FE_LEN, encode_msg,
        encode_tweak_msg,
    },
};
use core::{any::type_name, iter};
use generation::trace_height;
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

const WIDTH: usize = 24;
const PARTIAL_ROUNDS: usize = 21;

pub struct Poseidon2T24Chip {
    extra_capacity_bits: usize,
    epoch: u32,
    msg: [u8; MSG_LEN],
    air: Arc<Poseidon2T24Air>,
    msg_hash_input: Vec<[F; 22]>,
    merkle_inputs: Vec<(
        PublicKey,
        [F; SPONGE_INPUT_SIZE],
        [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
    )>,
}

impl Poseidon2T24Chip {
    pub fn new(
        extra_capacity_bits: usize,
        epoch: u32,
        msg: [u8; MSG_LEN],
        msg_hash_input: impl IntoIterator<Item = [F; 22]>,
        merkle_inputs: impl IntoIterator<
            Item = (
                PublicKey,
                [F; SPONGE_INPUT_SIZE],
                [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
            ),
        >,
    ) -> Self {
        Self {
            extra_capacity_bits,
            epoch,
            msg,
            air: Default::default(),
            msg_hash_input: msg_hash_input.into_iter().collect(),
            merkle_inputs: merkle_inputs.into_iter().collect(),
        }
    }
}

impl ChipUsageGetter for Poseidon2T24Chip {
    fn air_name(&self) -> String {
        type_name::<Poseidon2T24Air>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(&self.msg_hash_input, &self.merkle_inputs)
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
                    self.epoch,
                    self.msg_hash_input,
                    self.merkle_inputs,
                )),
                public_values: iter::empty()
                    .chain([F::from_canonical_u32(self.epoch)])
                    .chain(encode_tweak_msg(self.epoch))
                    .chain(encode_msg(self.msg))
                    .collect(),
            },
        }
    }
}
