use crate::poseidon2::{
    F,
    chip::main::{air::MainAir, column::NUM_MAIN_COLS},
    concat_array,
    hash_sig::{
        LOG_LIFETIME, MSG_FE_LEN, MSG_HASH_FE_LEN, MSG_LEN, NUM_CHUNKS, PARAM_FE_LEN, PublicKey,
        SPONGE_INPUT_SIZE, Signature, TH_HASH_FE_LEN, TWEAK_FE_LEN, encode_msg, encode_tweak_msg,
        msg_hash_to_chunks, poseidon2_compress, poseidon2_sponge,
    },
};
use core::{
    any::type_name,
    iter::{self, zip},
};
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

pub struct MainChip {
    extra_capacity_bits: usize,
    encoded_tweak_msg: [F; TWEAK_FE_LEN],
    encoded_msg: [F; MSG_FE_LEN],
    pairs: Vec<(PublicKey, Signature)>,
}

impl MainChip {
    pub fn new(
        extra_capacity_bits: usize,
        epoch: u32,
        msg: [u8; MSG_LEN],
        pairs: Vec<(PublicKey, Signature)>,
    ) -> Self {
        let encoded_tweak_msg = encode_tweak_msg(epoch);
        let encoded_msg = encode_msg(msg);
        Self {
            extra_capacity_bits,
            encoded_tweak_msg,
            encoded_msg,
            pairs,
        }
    }

    pub fn poseidon2_t24_compress(&self) -> impl Iterator<Item = [F; 22]> {
        self.pairs.iter().map(move |(pk, sig)| {
            concat_array![
                sig.rho,
                self.encoded_tweak_msg,
                self.encoded_msg,
                pk.parameter,
            ]
        })
    }

    pub fn chain_inputs(
        &self,
    ) -> impl Iterator<
        Item = (
            [F; PARAM_FE_LEN],
            [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
            [u16; NUM_CHUNKS],
        ),
    > {
        self.pairs.iter().map(move |(pk, sig)| {
            let msg_hash = poseidon2_compress::<24, 22, MSG_HASH_FE_LEN>(concat_array![
                sig.rho,
                self.encoded_tweak_msg,
                self.encoded_msg,
                pk.parameter,
            ]);
            (pk.parameter, sig.one_time_sig, msg_hash_to_chunks(msg_hash))
        })
    }

    pub fn merkle_tree_inputs(
        &self,
        poseidon2_t24_sponge_inputs: &[[F; SPONGE_INPUT_SIZE]],
    ) -> Vec<(
        [F; PARAM_FE_LEN],
        [F; TH_HASH_FE_LEN],
        [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
    )> {
        zip(&self.pairs, poseidon2_t24_sponge_inputs)
            .map(move |((pk, sig), poseidon2_t24_sponge_input)| {
                (
                    pk.parameter,
                    poseidon2_sponge(*poseidon2_t24_sponge_input),
                    sig.merkle_siblings,
                )
            })
            .collect()
    }
}

impl ChipUsageGetter for MainChip {
    fn air_name(&self) -> String {
        type_name::<MainAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        self.pairs.len()
    }

    fn trace_width(&self) -> usize {
        NUM_MAIN_COLS
    }
}

impl<SC: StarkGenericConfig> Chip<SC> for MainChip
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    fn air(&self) -> Arc<dyn AnyRap<SC>> {
        Arc::new(MainAir)
    }

    fn generate_air_proof_input(self) -> AirProofInput<SC> {
        AirProofInput {
            cached_mains_pdata: Vec::new(),
            raw: AirProofRawInput {
                cached_mains: Vec::new(),
                common_main: Some(generate_trace_rows(
                    self.extra_capacity_bits,
                    self.encoded_tweak_msg,
                    self.encoded_msg,
                    &self.pairs,
                )),
                public_values: iter::empty()
                    .chain(self.encoded_tweak_msg)
                    .chain(self.encoded_msg)
                    .collect(),
            },
        }
    }
}
