use crate::poseidon2::{
    F,
    chip::main::MainChip,
    hash_sig::{MSG_LEN, PublicKey, Signature, VerificationTrace, encode_msg},
};
use chain::ChainChip;
use decomposition::DecompositionChip;
use merkle_tree::MerkleTreeChip;
use openvm_stark_backend::{
    AirRef, Chip,
    config::{Domain, StarkGenericConfig},
    p3_commit::PolynomialSpace,
    p3_maybe_rayon::prelude::*,
    prover::types::AirProofInput,
};
use range_check::RangeCheckChip;

pub mod chain;
pub mod decomposition;
pub mod main;
pub mod merkle_tree;
pub mod range_check;

#[repr(u8)]
pub enum Bus {
    Parameter,
    MsgHash,
    Chain,
    MerkleLeaf,
    Decomposition,
    RangeCheck,
}

pub fn generate_air_proof_inputs<SC: StarkGenericConfig>(
    extra_capacity_bits: usize,
    epoch: u32,
    msg: [u8; MSG_LEN],
    inputs: Vec<(PublicKey, Signature)>,
) -> (Vec<AirRef<SC>>, Vec<AirProofInput<SC>>)
where
    Domain<SC>: PolynomialSpace<Val = F>,
{
    let encoded_msg = encode_msg(msg);
    let traces = inputs
        .into_par_iter()
        .map(|(pk, sig)| VerificationTrace::generate(epoch, encoded_msg, pk, sig))
        .collect::<Vec<_>>();
    let main = MainChip::new(extra_capacity_bits, &traces);
    let chain = ChainChip::new(extra_capacity_bits, &traces);
    let merkle_tree = MerkleTreeChip::new(extra_capacity_bits, epoch, encoded_msg, &traces);
    let decomposition = DecompositionChip::new(extra_capacity_bits, &traces);
    let ((main_api, chain_api), (merkle_tree_api, (decomposition_api, range_check_mult))) = join(
        || {
            join(
                || main.generate_air_proof_input(),
                || chain.clone().generate_air_proof_input(),
            )
        },
        || {
            join(
                || merkle_tree.clone().generate_air_proof_input(),
                || decomposition.generate_air_proof_input_and_range_check_mult(),
            )
        },
    );
    let range_check_chip = RangeCheckChip::new(extra_capacity_bits, range_check_mult);
    (
        vec![
            main.air(),
            chain.air(),
            merkle_tree.air(),
            decomposition.air(),
            range_check_chip.air(),
        ],
        vec![
            main_api,
            chain_api,
            merkle_tree_api,
            decomposition_api,
            range_check_chip.generate_air_proof_input(),
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
        for log_sigs in 0..10 {
            let (epoch, msg, pairs) = testdata(log_sigs);
            let (airs, inputs) = generate_air_proof_inputs(1, epoch, msg, pairs);
            run::<F, E>(airs, inputs).unwrap();
        }
    }
}
