//! Verification of [`hash-sig`] keccak instantiation [`SIGTargetSumLifetime20W2NoOff`].
//!
//! [`hash-sig`]: https://github.com/b-wagn/hash-sig
//! [`SIGTargetSumLifetime20W2NoOff`]: https://github.com/b-wagn/hash-sig/blob/ade9f14333123477b4060a6f22da4cf4433a103b/src/signature/generalized_xmss/instantiations_sha.rs#L254-L255

use core::{
    array::from_fn,
    iter::{empty, zip},
};
use sha3::{Digest, Sha3_256};

const LOG_LIFETIME: usize = 20;
const MSG_LEN: usize = 64;
const PARAM_LEN: usize = 18;
const RHO_LEN: usize = 23;
const MSG_HASH_LEN: usize = 18;
const TH_HASH_LEN: usize = 26;
const CHUNK_SIZE: usize = 2;
const NUM_CHUNKS: usize = 8 * MSG_HASH_LEN / CHUNK_SIZE;
const TARGET_SUM: u32 = 108;

pub struct VerifierInput {
    param: [u8; PARAM_LEN],
    merkle_root: [u8; TH_HASH_LEN],
    epoch: u32,
    message: [u8; MSG_LEN],
    rho: [u8; RHO_LEN],
    chain_witness: [[u8; TH_HASH_LEN]; NUM_CHUNKS],
    merkle_path: [[u8; TH_HASH_LEN]; LOG_LIFETIME],
}

impl VerifierInput {
    pub const SIZE: usize = {
        PARAM_LEN
            + TH_HASH_LEN
            + size_of::<u32>()
            + MSG_LEN
            + RHO_LEN
            + TH_HASH_LEN * NUM_CHUNKS
            + TH_HASH_LEN * LOG_LIFETIME
    };

    pub fn from_bytes(bytes: &[u8]) -> Vec<Self> {
        assert_eq!(bytes.len() % Self::SIZE, 0);
        bytes
            .chunks_exact(Self::SIZE)
            .map(|bytes| {
                let mut bytes = bytes.iter().copied();
                Self {
                    param: from_fn(|_| bytes.next().unwrap()),
                    merkle_root: from_fn(|_| bytes.next().unwrap()),
                    epoch: u32::from_le_bytes(from_fn(|_| bytes.next().unwrap())),
                    message: from_fn(|_| bytes.next().unwrap()),
                    rho: from_fn(|_| bytes.next().unwrap()),
                    chain_witness: from_fn(|_| from_fn(|_| bytes.next().unwrap())),
                    merkle_path: from_fn(|_| from_fn(|_| bytes.next().unwrap())),
                }
            })
            .collect()
    }
}

pub fn verify(verifier_input: &VerifierInput) -> bool {
    let chunks: [u8; NUM_CHUNKS] = {
        let msg_hash = truncated_sha3::<MSG_HASH_LEN>(
            empty()
                .chain(verifier_input.rho)
                .chain(verifier_input.param)
                .chain([0x02])
                .chain(verifier_input.epoch.to_le_bytes())
                .chain(verifier_input.message),
        );
        let msg_hash_chunks = bytes_to_chunks::<MSG_HASH_LEN, NUM_CHUNKS>(&msg_hash);
        if msg_hash_chunks
            .iter()
            .map(|chunk| *chunk as u32)
            .sum::<u32>()
            != TARGET_SUM
        {
            return false;
        }
        msg_hash_chunks
    };

    let leaves: [[u8; TH_HASH_LEN]; NUM_CHUNKS] = from_fn(|chain_idx| {
        chain(
            &verifier_input.param,
            verifier_input.epoch,
            chain_idx as _,
            chunks[chain_idx] as _,
            verifier_input.chain_witness[chain_idx],
        )
    });

    merkle_root(
        &verifier_input.param,
        verifier_input.epoch,
        &leaves,
        &verifier_input.merkle_path,
    ) == verifier_input.merkle_root
}

fn bytes_to_chunks<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u8; M] {
    const MASK: u8 = ((1 << CHUNK_SIZE) - 1) as u8;
    from_fn(|i| (bytes[(i * CHUNK_SIZE) / 8] >> ((i * CHUNK_SIZE) % 8)) & MASK)
}

fn chain(
    parameter: &[u8; PARAM_LEN],
    epoch: u32,
    chain_idx: u32,
    offset: u32,
    witness: [u8; TH_HASH_LEN],
) -> [u8; TH_HASH_LEN] {
    (offset..(1 << CHUNK_SIZE) - 1).fold(witness, |chain, step| {
        truncated_sha3::<TH_HASH_LEN>(
            empty()
                .chain(*parameter)
                .chain([0x01])
                .chain(epoch.to_be_bytes())
                .chain(chain_idx.to_be_bytes())
                .chain((step + 1).to_be_bytes())
                .chain(chain),
        )
    })
}

fn merkle_root(
    parameter: &[u8; PARAM_LEN],
    epoch: u32,
    leaves: &[[u8; TH_HASH_LEN]; NUM_CHUNKS],
    siblings: &[[u8; TH_HASH_LEN]; LOG_LIFETIME],
) -> [u8; TH_HASH_LEN] {
    zip(1u8.., siblings).fold(
        truncated_sha3::<TH_HASH_LEN>(
            empty()
                .chain(*parameter)
                .chain([0x00])
                .chain(0u8.to_be_bytes())
                .chain(epoch.to_be_bytes())
                .chain(leaves.iter().flatten().copied()),
        ),
        |node, (level, sibling)| {
            truncated_sha3::<TH_HASH_LEN>(
                empty()
                    .chain(*parameter)
                    .chain([0x00])
                    .chain(level.to_be_bytes())
                    .chain((epoch >> level).to_be_bytes())
                    .chain(
                        (if (epoch >> (level - 1)) & 1 == 0 {
                            [node, *sibling]
                        } else {
                            [*sibling, node]
                        })
                        .into_iter()
                        .flatten(),
                    ),
            )
        },
    )
}

fn truncated_sha3<const N: usize>(inputs: impl Iterator<Item = u8>) -> [u8; N] {
    let output = Sha3_256::digest(inputs.collect::<Vec<_>>());
    from_fn(|i| output[i])
}
