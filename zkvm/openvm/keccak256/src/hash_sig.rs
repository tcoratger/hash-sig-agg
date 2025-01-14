//! Verification of [`hash-sig`] keccak instantiation [`SIGTargetSumLifetime20W2NoOff`].
//!
//! Note that the original implementation uses sha3, but openvm only supports
//! keccak256, so we patch [`hash-sig`] to use keccak256 instead of sha3
//! to generate test data.
//! This shouldn't affect the performance since the only difference of sha3 and
//! keccak is the value of padding.
//!
//! [`hash-sig`]: https://github.com/b-wagn/hash-sig
//! [`SIGTargetSumLifetime20W2NoOff`]: https://github.com/b-wagn/hash-sig/blob/5268d83/src/signature/generalized_xmss/instantiations_sha.rs#L413C18-L414

use core::{array::from_fn, iter::zip};
use openvm_keccak256_guest::keccak256;

macro_rules! chain {
    [$first:expr $(, $rest:expr)* $(,)?] => { $first.into_iter()$(.chain($rest))* };
}

const LOG_LIFETIME: usize = 20;
const MSG_LEN: usize = 32;
const PARAM_LEN: usize = 18;
const RHO_LEN: usize = 23;
const MSG_HASH_LEN: usize = 18;
const TH_HASH_LEN: usize = 26;
const CHUNK_SIZE: usize = 2;
const NUM_CHUNKS: usize = (8 * MSG_HASH_LEN).div_ceil(CHUNK_SIZE);
const TARGET_SUM: u16 = 108;

const TH_SEP_MSG: u8 = 0x02;
const TH_SEP_TREE: u8 = 0x01;
const TH_SEP_CHAIN: u8 = 0x00;

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

pub fn verify(vi: &VerifierInput) -> bool {
    let chunks: [u16; NUM_CHUNKS] = {
        let msg_hash = truncated_keccak256::<MSG_HASH_LEN>(chain![
            vi.rho,
            vi.param,
            [TH_SEP_MSG],
            vi.epoch.to_le_bytes(),
            vi.message,
        ]);
        let msg_hash_chunks = hash_to_chunks::<MSG_HASH_LEN, NUM_CHUNKS>(&msg_hash);
        if msg_hash_chunks.iter().copied().sum::<u16>() != TARGET_SUM {
            return false;
        }
        msg_hash_chunks
    };

    let leaves: [[u8; TH_HASH_LEN]; NUM_CHUNKS] = from_fn(|chain_idx| {
        chain(
            &vi.param,
            vi.epoch,
            chain_idx as _,
            chunks[chain_idx],
            vi.chain_witness[chain_idx],
        )
    });

    merkle_root(&vi.param, vi.epoch, &leaves, &vi.merkle_path) == vi.merkle_root
}

fn hash_to_chunks<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u16; M] {
    const MASK: u8 = ((1 << CHUNK_SIZE) - 1) as u8;
    from_fn(|i| ((bytes[(i * CHUNK_SIZE) / 8] >> ((i * CHUNK_SIZE) % 8)) & MASK) as _)
}

fn chain(
    parameter: &[u8; PARAM_LEN],
    epoch: u32,
    chain_idx: u16,
    offset: u16,
    witness: [u8; TH_HASH_LEN],
) -> [u8; TH_HASH_LEN] {
    (offset..(1 << CHUNK_SIZE) - 1).fold(witness, |chain, step| {
        truncated_keccak256::<TH_HASH_LEN>(chain![
            *parameter,
            [TH_SEP_CHAIN],
            epoch.to_be_bytes(),
            chain_idx.to_be_bytes(),
            (step + 1).to_be_bytes(),
            chain,
        ])
    })
}

fn merkle_root(
    parameter: &[u8; PARAM_LEN],
    epoch: u32,
    leaves: &[[u8; TH_HASH_LEN]; NUM_CHUNKS],
    siblings: &[[u8; TH_HASH_LEN]; LOG_LIFETIME],
) -> [u8; TH_HASH_LEN] {
    zip(1u8.., siblings).fold(
        truncated_keccak256::<TH_HASH_LEN>(chain![
            *parameter,
            [TH_SEP_TREE],
            [0],
            epoch.to_be_bytes(),
            leaves.iter().flatten().copied(),
        ]),
        |node, (level, sibling)| {
            truncated_keccak256::<TH_HASH_LEN>(chain![
                *parameter,
                [TH_SEP_TREE],
                [level],
                (epoch >> level).to_be_bytes(),
                (if (epoch >> (level - 1)) & 1 == 0 {
                    [node, *sibling]
                } else {
                    [*sibling, node]
                })
                .into_iter()
                .flatten(),
            ])
        },
    )
}

fn truncated_keccak256<const N: usize>(inputs: impl Iterator<Item = u8>) -> [u8; N] {
    let output = keccak256(&inputs.collect::<Vec<_>>());
    from_fn(|i| output[i])
}
