extern crate alloc;

use hash_sig::{from_bytes, verify};
use openvm::io::{read_vec, reveal};

mod hash_sig;

openvm::entry!(main);

fn main() {
    let input = read_vec();
    let (epoch, msg, pairs) = from_bytes(&input);
    pairs.chunks(32).enumerate().for_each(|(idx, pairs)| {
        let outputs = pairs.iter().map(|(pk, sig)| verify(epoch, msg, *pk, *sig));
        reveal(outputs.rfold(0, |acc, bit| (acc << 1) ^ bit as u32), idx);
    });
}
