use crate::poseidon2::{F, concat_array};
use core::{array::from_fn, iter::zip, mem::transmute};
use num_bigint::BigUint;
use openvm_stark_backend::p3_field::{FieldAlgebra, PrimeField32};
use p3_poseidon2_util::horizon::baby_bear::{poseidon2_t16_horizon, poseidon2_t24_horizon};
use p3_symmetric::Permutation;

pub const MODULUS: u32 = F::ORDER_U32;

pub const LOG_LIFETIME: usize = 20;
pub const MSG_LEN: usize = 32;
pub const MSG_FE_LEN: usize = (8 * MSG_LEN).div_ceil(31);
pub const PARAM_FE_LEN: usize = 5;
pub const RHO_FE_LEN: usize = 6;
pub const MSG_HASH_FE_LEN: usize = 5;
pub const TH_HASH_FE_LEN: usize = 7;
pub const TWEAK_FE_LEN: usize = 2;
pub const CHUNK_SIZE: usize = 2;
pub const NUM_CHUNKS: usize = (31 * MSG_HASH_FE_LEN).div_ceil(CHUNK_SIZE);
pub const TARGET_SUM: u16 = 117;

pub const SPONGE_CAPACITY: usize = 9;
pub const SPONGE_CAPACITY_VALUES: [F; SPONGE_CAPACITY] = [
    F::new(1812885503),
    F::new(1176861807),
    F::new(135926247),
    F::new(1170849646),
    F::new(1751547645),
    F::new(646603316),
    F::new(1547513893),
    F::new(423708400),
    F::new(961239569),
];
pub const SPONGE_RATE: usize = 24 - SPONGE_CAPACITY;
pub const SPONGE_INPUT_SIZE: usize = PARAM_FE_LEN + TWEAK_FE_LEN + NUM_CHUNKS * TH_HASH_FE_LEN;
pub const SPONGE_PERM: usize = SPONGE_INPUT_SIZE.div_ceil(SPONGE_RATE);

#[derive(Clone, Copy, Debug, Default)]
pub struct PublicKey {
    pub parameter: [F; PARAM_FE_LEN],
    pub merkle_root: [F; TH_HASH_FE_LEN],
}

impl PublicKey {
    const SIZE: usize = 4 * (PARAM_FE_LEN + TH_HASH_FE_LEN);

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::SIZE);
        let bytes = &mut bytes.iter().copied();
        Self {
            parameter: fs_from_bytes(bytes),
            merkle_root: fs_from_bytes(bytes),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub rho: [F; RHO_FE_LEN],
    pub one_time_sig: [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
    pub merkle_siblings: [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
}

impl Signature {
    const SIZE: usize =
        4 * (RHO_FE_LEN + TH_HASH_FE_LEN * NUM_CHUNKS + TH_HASH_FE_LEN * LOG_LIFETIME);

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::SIZE);
        let bytes = &mut bytes.iter().copied();
        Self {
            rho: fs_from_bytes(bytes),
            one_time_sig: from_fn(|_| fs_from_bytes(bytes)),
            merkle_siblings: from_fn(|_| fs_from_bytes(bytes)),
        }
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            rho: Default::default(),
            one_time_sig: from_fn(|_| Default::default()),
            merkle_siblings: from_fn(|_| Default::default()),
        }
    }
}

pub struct VerificationTrace {
    pub pk: PublicKey,
    pub sig: Signature,
    pub msg_hash: [F; MSG_HASH_FE_LEN],
    pub x: [u16; NUM_CHUNKS],
    pub one_time_pk: [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
}

impl VerificationTrace {
    pub fn generate(
        epoch: u32,
        encoded_msg: [F; MSG_FE_LEN],
        pk: PublicKey,
        sig: Signature,
    ) -> Self {
        let msg_hash = poseidon2_compress::<24, 22, MSG_HASH_FE_LEN>(concat_array![
            sig.rho,
            encode_tweak_msg(epoch),
            encoded_msg,
            pk.parameter
        ]);
        let x = msg_hash_to_chunks(msg_hash);
        let one_time_pk =
            from_fn(|i| chain(epoch, pk.parameter, i as _, x[i], sig.one_time_sig[i]));
        Self {
            pk,
            sig,
            msg_hash,
            x,
            one_time_pk,
        }
    }

    pub fn msg_hash_preimage(&self, epoch: u32, encoded_msg: [F; MSG_FE_LEN]) -> [F; 24] {
        concat_array![
            self.sig.rho,
            encode_tweak_msg(epoch),
            encoded_msg,
            self.pk.parameter,
        ]
    }

    pub fn merkle_tree_leaf(&self, epoch: u32) -> [F; SPONGE_INPUT_SIZE] {
        concat_array![
            self.pk.parameter,
            encode_tweak_merkle_tree(0, epoch),
            self.one_time_pk.into_iter().flatten()
        ]
    }
}

impl Default for VerificationTrace {
    fn default() -> Self {
        Self {
            pk: Default::default(),
            sig: Default::default(),
            msg_hash: Default::default(),
            x: from_fn(|i| if i >= NUM_CHUNKS / 2 { 1 } else { 2 }),
            one_time_pk: from_fn(|_| Default::default()),
        }
    }
}

pub fn encode_msg(msg: [u8; MSG_LEN]) -> [F; MSG_FE_LEN] {
    decompose(BigUint::from_bytes_le(&msg))
}

pub fn encode_tweak_chain(epoch: u32, i: u16, k: u16) -> [F; TWEAK_FE_LEN] {
    const SEP: u64 = 0x00;
    decompose(((epoch as u64) << 40) | ((i as u64) << 24) | ((k as u64) << 8) | SEP)
}

pub fn encode_tweak_merkle_tree(l: u32, i: u32) -> [F; TWEAK_FE_LEN] {
    const SEP: u64 = 0x01;
    decompose(((l as u64) << 40) | ((i as u64) << 8) | SEP)
}

pub fn encode_tweak_msg(epoch: u32) -> [F; TWEAK_FE_LEN] {
    const SEP: u32 = 0x02;
    [F::from_canonical_u32(epoch << 8 | SEP), F::ZERO] // `decompose(((epoch as u64) << 8) | SEP)`.
}

pub fn msg_hash_to_chunks(hash: [F; MSG_HASH_FE_LEN]) -> [u16; NUM_CHUNKS] {
    const MASK: u8 = ((1 << CHUNK_SIZE) - 1) as u8;
    let bytes = hash
        .into_iter()
        .fold(BigUint::ZERO, |acc, v| acc * MODULUS + v.as_canonical_u32())
        .to_bytes_le();
    from_fn(|i| {
        bytes
            .get((i * CHUNK_SIZE) / 8)
            .map(|byte| ((byte >> ((i * CHUNK_SIZE) % 8)) & MASK))
            .unwrap_or(0) as u16
    })
}

pub fn chain(
    epoch: u32,
    parameter: [F; PARAM_FE_LEN],
    i: u16,
    x_i: u16,
    one_time_sig_i: [F; TH_HASH_FE_LEN],
) -> [F; TH_HASH_FE_LEN] {
    (x_i + 1..(1 << CHUNK_SIZE)).fold(one_time_sig_i, |value, step| {
        poseidon2_compress::<16, 14, TH_HASH_FE_LEN>(concat_array![
            parameter,
            encode_tweak_chain(epoch, i, step),
            value
        ])
    })
}

fn decompose<const N: usize>(big: impl Into<BigUint>) -> [F; N] {
    let mut big = big.into();
    from_fn(|_| {
        let rem = &big % &BigUint::from(F::ORDER_U32);
        big /= BigUint::from(F::ORDER_U32);
        F::from_canonical_u64(rem.iter_u64_digits().next().unwrap_or_default())
    })
}

fn fs_from_bytes<const N: usize>(bytes: &mut impl Iterator<Item = u8>) -> [F; N] {
    from_fn(|_| u32::from_le_bytes(from_fn(|_| bytes.next().unwrap()))).map(F::new)
}

pub fn poseidon2_sponge<const I: usize>(input: [F; I]) -> [F; TH_HASH_FE_LEN] {
    let mut state = from_fn(|i| {
        i.checked_sub(SPONGE_RATE)
            .map(|i| SPONGE_CAPACITY_VALUES[i])
            .unwrap_or_default()
    });
    input.chunks(SPONGE_RATE).for_each(|block| {
        zip(&mut state, block).for_each(|(state, block)| *state += *block);
        state = poseidon2_permutation::<24>(state);
    });
    from_fn(|i| state[i])
}

pub fn poseidon2_compress<const T: usize, const I: usize, const O: usize>(input: [F; I]) -> [F; O] {
    const { assert!(I >= O && I <= T) };
    let padded = from_fn(|i| input.get(i).copied().unwrap_or_default());
    let output = poseidon2_permutation::<T>(padded);
    from_fn(|i| input[i] + output[i])
}

fn poseidon2_permutation<const T: usize>(mut state: [F; T]) -> [F; T] {
    match T {
        16 => poseidon2_t16_horizon()
            .permute_mut(unsafe { transmute::<&mut [F; T], &mut [F; 16]>(&mut state) }),
        24 => poseidon2_t24_horizon()
            .permute_mut(unsafe { transmute::<&mut [F; T], &mut [F; 24]>(&mut state) }),
        _ => unreachable!(),
    };
    state
}

#[cfg(test)]
pub mod test {
    use crate::poseidon2::hash_sig::{MSG_LEN, PublicKey, Signature};
    use core::array::from_fn;
    use std::{fs, path::PathBuf};

    pub fn testdata(log_size: usize) -> (u32, [u8; MSG_LEN], Vec<(PublicKey, Signature)>) {
        let path = PathBuf::from_iter([
            env!("CARGO_MANIFEST_DIR"),
            "..",
            "..",
            "testdata",
            "poseidon2",
            (1 << log_size).to_string().as_str(),
        ]);
        let mut bytes = fs::read(path).unwrap().into_iter();
        let epoch = u32::from_le_bytes(from_fn(|_| bytes.next().unwrap()));
        let msg = from_fn(|_| bytes.next().unwrap());
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
}
