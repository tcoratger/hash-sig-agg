#![no_main]

use hash_sig::{from_bytes, verify};
use sp1_zkvm::io::{commit_slice, read_vec};

mod hash_sig;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input = read_vec();
    let (epoch, msg, pairs) = from_bytes(&input);
    let output = pairs
        .chunks(8)
        .map(|pairs| {
            let outputs = pairs.iter().map(|(pk, sig)| verify(epoch, msg, *pk, *sig));
            outputs.rfold(0, |acc, bit| (acc << 1) ^ bit as u8)
        })
        .collect::<Vec<_>>();
    commit_slice(&output);
}
