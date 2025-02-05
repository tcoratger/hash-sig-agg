use crate::poseidon2::{
    F,
    chip::main::MainChip,
    hash_sig::{MSG_LEN, PublicKey, Signature},
};
use chain::ChainChip;
use core::iter;
use merkle_tree::MerkleTreeChip;
use openvm_stark_backend::{
    AirRef, Chip,
    config::{Domain, StarkGenericConfig},
    p3_commit::PolynomialSpace,
    prover::types::AirProofInput,
};
use poseidon2_t24::Poseidon2T24Chip;

pub mod chain;
pub mod main;
pub mod merkle_tree;
pub mod poseidon2_t24;

pub const BUS_POSEIDON2_T24_COMPRESS: usize = 0;
pub const BUS_POSEIDON2_T24_SPONGE: usize = 1;
pub const BUS_CHAIN: usize = 2;
pub const BUS_MERKLE_TREE: usize = 3;

pub fn generate_air_proof_inputs<SC: StarkGenericConfig>(
    extra_capacity_bits: usize,
    epoch: u32,
    msg: [u8; MSG_LEN],
    pairs: Vec<(PublicKey, Signature)>,
) -> (Vec<AirRef<SC>>, Vec<AirProofInput<SC>>)
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    let main = MainChip::new(extra_capacity_bits, epoch, msg, pairs);
    let chain = ChainChip::new(extra_capacity_bits, epoch, main.chain_inputs());
    let poseidon2_t24_sponge_inputs = chain.poseidon2_t24_sponge_inputs();
    let merkle_tree = MerkleTreeChip::new(
        extra_capacity_bits,
        epoch,
        main.merkle_tree_inputs(&poseidon2_t24_sponge_inputs),
    );
    let poseidon2_t24 = Poseidon2T24Chip::new(
        extra_capacity_bits,
        iter::empty()
            .chain(main.poseidon2_t24_compress())
            .chain(merkle_tree.poseidon2_t24_compress()),
        poseidon2_t24_sponge_inputs,
    );
    (
        vec![
            main.air(),
            chain.air(),
            merkle_tree.air(),
            poseidon2_t24.air(),
        ],
        vec![
            main.generate_air_proof_input(),
            chain.generate_air_proof_input(),
            merkle_tree.generate_air_proof_input(),
            poseidon2_t24.generate_air_proof_input(),
        ],
    )
}

#[cfg(test)]
mod test {
    use crate::{
        poseidon2::{F, chip::generate_air_proof_inputs, hash_sig::test::testdata},
        test::run,
    };
    use openvm_stark_backend::p3_field::extension::BinomialExtensionField;

    type E = BinomialExtensionField<F, 4>;

    #[test]
    fn chip() {
        for log_sigs in 0..3 {
            let (epoch, msg, pairs) = testdata(log_sigs);
            let (airs, inputs) = generate_air_proof_inputs(1, epoch, msg, pairs);
            run::<F, E>(airs, inputs).unwrap();
        }
    }
}
