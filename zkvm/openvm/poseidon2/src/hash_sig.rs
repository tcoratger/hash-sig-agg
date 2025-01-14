//! Verification of [`hash-sig`] poseidon2 instantiation [`SIGTargetSumLifetime20W2NoOff`].
//!
//! [`hash-sig`]: https://github.com/b-wagn/hash-sig
//! [`SIGTargetSumLifetime20W2NoOff`]: https://github.com/b-wagn/hash-sig/blob/5268d83/src/signature/generalized_xmss/instantiations_poseidon.rs#L678-L679

use core::{
    array::from_fn,
    iter::{repeat, zip},
    marker::PhantomData,
};
use num_bigint::BigUint;
use zkhash::{
    ark_ff::{BigInt, Fp, PrimeField},
    fields::babybear::FpBabyBear,
    poseidon2::{
        poseidon2::Poseidon2,
        poseidon2_instance_babybear::{POSEIDON2_BABYBEAR_16_PARAMS, POSEIDON2_BABYBEAR_24_PARAMS},
    },
};

macro_rules! chain {
    [$first:expr $(, $rest:expr)* $(,)?] => { $first.into_iter()$(.chain($rest))* };
}

type F = FpBabyBear;

const LOG_LIFETIME: usize = 20;
const MSG_LEN: usize = 32;
const MSG_FE_LEN: usize = (8 * MSG_LEN).div_ceil(31);
const PARAM_FE_LEN: usize = 5;
const RHO_FE_LEN: usize = 6;
const MSG_HASH_FE_LEN: usize = 5;
const TH_HASH_FE_LEN: usize = 7;
const TWEAK_FE_LEN: usize = 2;
const CHUNK_SIZE: usize = 2;
const NUM_CHUNKS: usize = (31 * MSG_HASH_FE_LEN).div_ceil(CHUNK_SIZE);
const TARGET_SUM: u16 = 117;

const TH_SEP_MSG: u8 = 0x02;
const TH_SEP_TREE: u8 = 0x01;
const TH_SEP_CHAIN: u8 = 0x00;

const CAPACITY: usize = 9;
const CAPACITY_VALUES: [F; CAPACITY] = [
    f_from_mont(582337159),
    f_from_mont(363129362),
    f_from_mont(1799731460),
    f_from_mont(863690413),
    f_from_mont(321077449),
    f_from_mont(2012187288),
    f_from_mont(403604058),
    f_from_mont(362470513),
    f_from_mont(249749907),
];

#[derive(Debug, PartialEq, Eq)]
pub struct VerifierInput {
    param: [F; PARAM_FE_LEN],
    merkle_root: [F; TH_HASH_FE_LEN],
    epoch: u32,
    message: [u8; MSG_LEN],
    rho: [F; RHO_FE_LEN],
    chain_witness: [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
    merkle_path: [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
}

impl VerifierInput {
    pub const SIZE: usize = {
        4 * PARAM_FE_LEN
            + 4 * TH_HASH_FE_LEN
            + size_of::<u32>()
            + MSG_LEN
            + 4 * RHO_FE_LEN
            + 4 * TH_HASH_FE_LEN * NUM_CHUNKS
            + 4 * TH_HASH_FE_LEN * LOG_LIFETIME
    };

    pub fn from_bytes(bytes: &[u8]) -> Vec<Self> {
        assert_eq!(bytes.len() % Self::SIZE, 0);
        bytes
            .chunks(Self::SIZE)
            .map(|bytes| {
                let bytes = &mut bytes.iter().copied();
                let verifier_input = Self {
                    param: fs_from_bytes(bytes),
                    merkle_root: fs_from_bytes(bytes),
                    epoch: u32::from_le_bytes(from_fn(|_| bytes.next().unwrap())),
                    message: from_fn(|_| bytes.next().unwrap()),
                    rho: fs_from_bytes(bytes),
                    chain_witness: from_fn(|_| fs_from_bytes(bytes)),
                    merkle_path: from_fn(|_| fs_from_bytes(bytes)),
                };
                assert!(bytes.next().is_none());
                verifier_input
            })
            .collect()
    }
}

pub fn verify(vi: &VerifierInput) -> bool {
    let chunks: [u16; NUM_CHUNKS] = {
        let msg_hash = poseidon2_compress::<24, MSG_HASH_FE_LEN>(chain![
            vi.rho,
            decompose::<TWEAK_FE_LEN>(shl(vi.epoch, 8) + TH_SEP_MSG),
            decompose::<MSG_FE_LEN>(BigUint::from_bytes_le(&vi.message)),
            vi.param,
        ]);
        let msg_hash_chunks = hash_to_chunks::<MSG_HASH_FE_LEN, NUM_CHUNKS>(&msg_hash);
        if msg_hash_chunks.iter().copied().sum::<u16>() != TARGET_SUM {
            return false;
        }
        msg_hash_chunks
    };

    let leaves: [[F; TH_HASH_FE_LEN]; NUM_CHUNKS] = from_fn(|chain_idx| {
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

fn hash_to_chunks<const N: usize, const M: usize>(hash: &[F; N]) -> [u16; M] {
    let big = hash.iter().fold(BigUint::ZERO, |acc, item| {
        acc * BigUint::from(F::MODULUS) + BigUint::from(*item)
    });
    let bytes = chain![big.to_bytes_le(), repeat(0)]
        .take(M * 8 / CHUNK_SIZE)
        .collect::<Vec<_>>();
    const MASK: u8 = ((1 << CHUNK_SIZE) - 1) as u8;
    from_fn(|i| (bytes[(i * CHUNK_SIZE) / 8] >> ((i * CHUNK_SIZE) % 8) & MASK) as _)
}

fn chain(
    parameter: &[F; PARAM_FE_LEN],
    epoch: u32,
    chain_idx: u16,
    offset: u16,
    witness: [F; TH_HASH_FE_LEN],
) -> [F; TH_HASH_FE_LEN] {
    (offset..(1 << CHUNK_SIZE) - 1).fold(witness, |chain, step| {
        poseidon2_compress::<16, TH_HASH_FE_LEN>(chain![
            *parameter,
            decompose::<TWEAK_FE_LEN>(
                shl(epoch, 40) + shl(chain_idx, 24) + shl(step + 1, 8) + TH_SEP_CHAIN
            ),
            chain
        ])
    })
}

fn merkle_root(
    parameter: &[F; PARAM_FE_LEN],
    epoch: u32,
    leaves: &[[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
    siblings: &[[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
) -> [F; TH_HASH_FE_LEN] {
    zip(1u32.., siblings).fold(
        poseidon2_sponge(
            CAPACITY_VALUES,
            chain![
                *parameter,
                decompose::<TWEAK_FE_LEN>(shl(0u32, 40) + shl(epoch, 8) + TH_SEP_TREE),
                leaves.iter().flatten().copied(),
            ],
        ),
        |node, (level, sibling)| {
            poseidon2_compress::<24, TH_HASH_FE_LEN>(chain![
                *parameter,
                decompose::<TWEAK_FE_LEN>(shl(level, 40) + shl(epoch >> level, 8) + TH_SEP_TREE),
                (if (epoch >> (level - 1)) & 1 == 0 {
                    [node, *sibling]
                } else {
                    [*sibling, node]
                })
                .into_iter()
                .flatten()
            ])
        },
    )
}

fn poseidon2_sponge(
    capacity: [F; CAPACITY],
    inputs: impl IntoIterator<Item = F>,
) -> [F; TH_HASH_FE_LEN] {
    const RATE: usize = 24 - CAPACITY;
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let mut state = from_fn(|i| i.checked_sub(RATE).map(|i| capacity[i]).unwrap_or_default());
    inputs.chunks(RATE).for_each(|block| {
        zip(&mut state, block).for_each(|(state, block)| *state += block);
        state = poseidon2_permutation::<24>(state);
    });
    from_fn(|i| state[i])
}

fn poseidon2_compress<const T: usize, const N: usize>(
    inputs: impl IntoIterator<Item = F>,
) -> [F; N] {
    let inputs = inputs.into_iter().collect::<Vec<_>>();
    let padded = from_fn(|i| inputs.get(i).copied().unwrap_or_default());
    let outputs = poseidon2_permutation::<T>(padded);
    from_fn(|i| inputs[i] + outputs[i])
}

// TODO: Use extension when ready
fn poseidon2_permutation<const T: usize>(state: [F; T]) -> [F; T] {
    let poseidon2 = match T {
        16 => Poseidon2::new(&POSEIDON2_BABYBEAR_16_PARAMS),
        24 => Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS),
        _ => unreachable!(),
    };
    let permuted = poseidon2.permutation(&state);
    from_fn(|i| permuted[i])
}

const fn f_from_mont(v: u32) -> F {
    Fp(BigInt::new([v as u64]), PhantomData)
}

fn fs_from_bytes<const N: usize>(bytes: &mut impl Iterator<Item = u8>) -> [F; N] {
    let f_from_u32 = |v| F::from_bigint(BigInt([v as _])).unwrap();
    from_fn(|_| f_from_u32(u32::from_le_bytes(from_fn(|_| bytes.next().unwrap()))))
}

fn shl(v: impl Into<BigUint>, shift: usize) -> BigUint {
    v.into() << shift
}

fn decompose<const N: usize>(big: impl Into<BigUint>) -> [F; N] {
    let mut big = big.into();
    from_fn(|_| {
        let rem = &big % &BigUint::from(F::MODULUS);
        big /= BigUint::from(F::MODULUS);
        F::from(rem)
    })
}
