extern crate alloc;

use hash_sig::{verify, VerifierInput};
use openvm::io::{read_vec, reveal};

mod hash_sig;

openvm::entry!(main);

fn main() {
    let input = read_vec();
    VerifierInput::from_bytes(&input)
        .chunks(32)
        .enumerate()
        .for_each(|(idx, verifier_inputs)| {
            let outputs = verifier_inputs.iter().map(verify);
            reveal(outputs.rfold(0, |acc, bit| (acc << 1) ^ bit as u32), idx);
        });
}
