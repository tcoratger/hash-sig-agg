//! Verification of [`hash-sig`] poseidon2 instantiation [`SIGTargetSumLifetime20W2NoOff`].
//!
//! [`hash-sig`]: https://github.com/b-wagn/hash-sig
//! [`SIGTargetSumLifetime20W2NoOff`]: https://github.com/b-wagn/hash-sig/blob/5268d83/src/signature/generalized_xmss/instantiations_poseidon.rs#L678-L679

use core::{array::from_fn, iter::zip, marker::PhantomData};
use num_bigint::BigUint;
use zkhash::{
    ark_ff::{BigInt, Fp, PrimeField},
    fields::babybear::FpBabyBear,
    poseidon2::{
        poseidon2::Poseidon2,
        poseidon2_instance_babybear::{POSEIDON2_BABYBEAR_16_PARAMS, POSEIDON2_BABYBEAR_24_PARAMS},
    },
};

macro_rules! concat {
    [$first:expr $(, $rest:expr)* $(,)?] => { $first.into_iter()$(.chain($rest))*.collect::<Vec<_>>().try_into().unwrap() };
}

type F = FpBabyBear;
const MODULUS: u32 = F::MODULUS.0[0] as u32;

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

#[derive(Clone, Copy)]
pub struct PublicKey {
    parameter: [F; PARAM_FE_LEN],
    merkle_root: [F; TH_HASH_FE_LEN],
}

impl PublicKey {
    const SIZE: usize = 4 * (PARAM_FE_LEN + TH_HASH_FE_LEN);

    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::SIZE);
        let bytes = &mut bytes.iter().copied();
        Self {
            parameter: fs_from_bytes(bytes),
            merkle_root: fs_from_bytes(bytes),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Signature {
    rho: [F; RHO_FE_LEN],
    one_time_sig: [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
    merkle_siblings: [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
}

impl Signature {
    const SIZE: usize =
        4 * (RHO_FE_LEN + TH_HASH_FE_LEN * NUM_CHUNKS + TH_HASH_FE_LEN * LOG_LIFETIME);

    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::SIZE);
        let bytes = &mut bytes.iter().copied();
        Self {
            rho: fs_from_bytes(bytes),
            one_time_sig: from_fn(|_| fs_from_bytes(bytes)),
            merkle_siblings: from_fn(|_| fs_from_bytes(bytes)),
        }
    }
}

pub fn from_bytes(bytes: &[u8]) -> (u32, [u8; MSG_LEN], Vec<(PublicKey, Signature)>) {
    let mut bytes = bytes.iter();
    let epoch = u32::from_le_bytes(from_fn(|_| *bytes.next().unwrap()));
    let msg = from_fn(|_| *bytes.next().unwrap());
    let pairs = bytes
        .as_slice()
        .chunks(PublicKey::SIZE + Signature::SIZE)
        .map(|bytes| {
            (
                PublicKey::from_bytes(&bytes[..PublicKey::SIZE]),
                Signature::from_bytes(&bytes[PublicKey::SIZE..]),
            )
        })
        .collect();
    (epoch, msg, pairs)
}

pub fn verify(epoch: u32, msg: [u8; MSG_LEN], pk: PublicKey, sig: Signature) -> bool {
    let x: [u16; NUM_CHUNKS] = {
        let msg_hash = poseidon2_compress::<24, 22, MSG_HASH_FE_LEN>(concat![
            sig.rho,
            decompose::<TWEAK_FE_LEN>(shl(epoch, 8) + TH_SEP_MSG),
            decompose::<MSG_FE_LEN>(BigUint::from_bytes_le(&msg)),
            pk.parameter,
        ]);
        msg_hash_to_chunks(msg_hash)
    };

    if x.iter().copied().sum::<u16>() != TARGET_SUM {
        return false;
    }

    let one_time_pk: [[F; TH_HASH_FE_LEN]; NUM_CHUNKS] =
        from_fn(|i| chain(epoch, pk.parameter, i as _, x[i], sig.one_time_sig[i]));

    merkle_root(epoch, pk.parameter, one_time_pk, sig.merkle_siblings) == pk.merkle_root
}

fn msg_hash_to_chunks(hash: [F; MSG_HASH_FE_LEN]) -> [u16; NUM_CHUNKS] {
    const MASK: u8 = ((1 << CHUNK_SIZE) - 1) as u8;
    let bytes = hash
        .into_iter()
        .fold(BigUint::ZERO, |acc, v| acc * MODULUS + v.into_bigint().0[0])
        .to_bytes_le();
    from_fn(|i| {
        bytes
            .get((i * CHUNK_SIZE) / 8)
            .map(|byte| ((byte >> ((i * CHUNK_SIZE) % 8)) & MASK))
            .unwrap_or(0) as u16
    })
}

fn chain(
    epoch: u32,
    parameter: [F; PARAM_FE_LEN],
    i: u16,
    x_i: u16,
    one_time_sig_i: [F; TH_HASH_FE_LEN],
) -> [F; TH_HASH_FE_LEN] {
    (x_i..(1 << CHUNK_SIZE) - 1).fold(one_time_sig_i, |value, step| {
        poseidon2_compress::<16, 14, TH_HASH_FE_LEN>(concat![
            parameter,
            decompose::<TWEAK_FE_LEN>(
                shl(epoch, 40) + shl(i, 24) + shl(step + 1, 8) + TH_SEP_CHAIN
            ),
            value
        ])
    })
}

fn merkle_root(
    epoch: u32,
    parameter: [F; PARAM_FE_LEN],
    one_time_pk: [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
    siblings: [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
) -> [F; TH_HASH_FE_LEN] {
    zip(1u32.., siblings).fold(
        poseidon2_sponge::<553>(
            CAPACITY_VALUES,
            concat![
                parameter,
                decompose::<TWEAK_FE_LEN>(shl(0u32, 40) + shl(epoch, 8) + TH_SEP_TREE),
                one_time_pk.into_iter().flatten(),
            ],
        ),
        |node, (level, sibling)| {
            poseidon2_compress::<24, 21, TH_HASH_FE_LEN>(concat![
                parameter,
                decompose::<TWEAK_FE_LEN>(shl(level, 40) + shl(epoch >> level, 8) + TH_SEP_TREE),
                (if (epoch >> (level - 1)) & 1 == 0 {
                    [node, sibling]
                } else {
                    [sibling, node]
                })
                .into_iter()
                .flatten()
            ])
        },
    )
}

fn poseidon2_sponge<const I: usize>(capacity: [F; CAPACITY], input: [F; I]) -> [F; TH_HASH_FE_LEN] {
    const RATE: usize = 24 - CAPACITY;
    let mut state = from_fn(|i| i.checked_sub(RATE).map(|i| capacity[i]).unwrap_or_default());
    input.chunks(RATE).for_each(|block| {
        zip(&mut state, block).for_each(|(state, block)| *state += block);
        state = poseidon2_permutation::<24>(state);
    });
    from_fn(|i| state[i])
}

fn poseidon2_compress<const T: usize, const I: usize, const O: usize>(input: [F; I]) -> [F; O] {
    const { assert!(I >= O && I <= T) };
    let padded = from_fn(|i| input.get(i).copied().unwrap_or_default());
    let output = poseidon2_permutation::<T>(padded);
    from_fn(|i| input[i] + output[i])
}

// TODO: Use extension if it's available.
fn poseidon2_permutation<const T: usize>(state: [F; T]) -> [F; T] {
    let poseidon2 = match T {
        16 => Poseidon2::new(&POSEIDON2_BABYBEAR_16_PARAMS),
        24 => Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS),
        _ => unreachable!(),
    };
    poseidon2.permutation(&state).try_into().unwrap()
}

const fn f_from_mont(v: u32) -> F {
    assert!(v < MODULUS);
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
