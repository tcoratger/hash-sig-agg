#![no_main]

use hash_sig::{verify, VerifierInput};
use sp1_zkvm::io::{commit_slice, read_vec};

mod hash_sig;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = read_vec();
    let output = VerifierInput::from_bytes(&input)
        .chunks(8)
        .map(|verifier_inputs| {
            let outputs = verifier_inputs.iter().map(verify);
            outputs.rfold(0, |acc, bit| (acc << 1) ^ bit as u8)
        })
        .collect::<Vec<_>>();
    commit_slice(&output);
}
