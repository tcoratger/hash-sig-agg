use crate::poseidon2::{
    F,
    chip::main::{air::MainAir, column::NUM_MAIN_COLS},
    concat_array,
    hash_sig::{
        CHUNK_SIZE, LOG_LIFETIME, MSG_FE_LEN, MSG_HASH_FE_LEN, MSG_LEN, NUM_CHUNKS, PublicKey,
        SPONGE_INPUT_SIZE, Signature, TH_HASH_FE_LEN, TWEAK_FE_LEN, chain, encode_msg,
        encode_tweak_chain, encode_tweak_merkle_tree, encode_tweak_msg, msg_hash_to_chunks,
        poseidon2_compress,
    },
};
use core::{any::type_name, iter};
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

pub struct MainChip {
    extra_capacity_bits: usize,
    epoch: u32,
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
            epoch,
            encoded_tweak_msg,
            encoded_msg,
            pairs,
        }
    }

    pub fn msg_hash_input(&self) -> impl Iterator<Item = [F; 22]> {
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
            PublicKey,
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
            (*pk, sig.one_time_sig, msg_hash_to_chunks(msg_hash))
        })
    }

    pub fn merkle_inputs(
        &self,
    ) -> Vec<(
        PublicKey,
        [F; SPONGE_INPUT_SIZE],
        [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
    )> {
        self.pairs
            .iter()
            .map(move |(pk, sig)| {
                let msg_hash = poseidon2_compress::<24, 22, MSG_HASH_FE_LEN>(concat_array![
                    sig.rho,
                    self.encoded_tweak_msg,
                    self.encoded_msg,
                    pk.parameter,
                ]);
                let x = msg_hash_to_chunks(msg_hash);
                let leaves = (0..NUM_CHUNKS).flat_map(|i| {
                    chain(self.epoch, pk.parameter, i as _, x[i], sig.one_time_sig[i])
                });
                (
                    *pk,
                    concat_array![
                        pk.parameter,
                        encode_tweak_merkle_tree(0, self.epoch),
                        leaves
                    ],
                    sig.merkle_siblings,
                )
            })
            .collect()
    }

    pub fn decomposition_inputs(&self) -> (Vec<[F; 5]>, Vec<[F; 2]>) {
        (
            self.pairs
                .iter()
                .map(move |(pk, sig)| {
                    poseidon2_compress::<24, 22, MSG_HASH_FE_LEN>(concat_array![
                        sig.rho,
                        self.encoded_tweak_msg,
                        self.encoded_msg,
                        pk.parameter,
                    ])
                })
                .collect(),
            iter::empty()
                .chain((0..NUM_CHUNKS as u16).flat_map(|i| {
                    (1..1 << CHUNK_SIZE).map(move |step| encode_tweak_chain(self.epoch, i, step))
                }))
                .chain(
                    (0..=LOG_LIFETIME)
                        .map(|level| encode_tweak_merkle_tree(level as _, self.epoch >> level)),
                )
                .collect(),
        )
    }
}

impl ChipUsageGetter for MainChip {
    fn air_name(&self) -> String {
        type_name::<MainAir>().to_string()
    }

    fn current_trace_height(&self) -> usize {
        trace_height(&self.pairs)
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
                    self.pairs,
                )),
                public_values: Vec::new(),
            },
        }
    }
}
