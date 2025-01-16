//! Verification of [`hash-sig`] keccak instantiation [`SIGTargetSumLifetime20W2NoOff`].
//!
//! [`hash-sig`]: https://github.com/b-wagn/hash-sig
//! [`SIGTargetSumLifetime20W2NoOff`]: https://github.com/b-wagn/hash-sig/blob/5268d83/src/signature/generalized_xmss/instantiations_sha.rs#L413C18-L414

use core::{array::from_fn, iter::zip};
use sha3::{Digest, Sha3_256};
const LOG_LIFETIME: usize = 20;
const MSG_LEN: usize = 32;
const PARAM_LEN: usize = 18;
const RHO_LEN: usize = 23;
const MSG_HASH_LEN: usize = 18;
const TH_HASH_LEN: usize = 26;
const CHUNK_SIZE: usize = 2;
const NUM_CHUNKS: usize = (8 * MSG_HASH_LEN).div_ceil(CHUNK_SIZE);
const TARGET_SUM: u16 = 108;

#[derive(Clone, Copy)]
pub struct PublicKey {
    parameter: [u8; PARAM_LEN],
    merkle_root: [u8; TH_HASH_LEN],
}

impl PublicKey {
    pub const SIZE: usize = PARAM_LEN + TH_HASH_LEN;

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::SIZE);
        let mut bytes = bytes.iter().copied();
        Self {
            parameter: from_fn(|_| bytes.next().unwrap()),
            merkle_root: from_fn(|_| bytes.next().unwrap()),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Signature {
    rho: [u8; RHO_LEN],
    one_time_sig: [[u8; TH_HASH_LEN]; NUM_CHUNKS],
    merkle_siblings: [[u8; TH_HASH_LEN]; LOG_LIFETIME],
}

impl Signature {
    pub const SIZE: usize = RHO_LEN + TH_HASH_LEN * NUM_CHUNKS + TH_HASH_LEN * LOG_LIFETIME;

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), Self::SIZE);
        let mut bytes = bytes.iter().copied();
        Self {
            rho: from_fn(|_| bytes.next().unwrap()),
            one_time_sig: from_fn(|_| from_fn(|_| bytes.next().unwrap())),
            merkle_siblings: from_fn(|_| from_fn(|_| bytes.next().unwrap())),
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
        let msg_hash = truncated_sha3::<78, MSG_HASH_LEN>(concat![
            sig.rho,
            pk.parameter,
            encode_tweak_msg(epoch),
            msg,
        ]);
        msg_hash_to_chunks(msg_hash)
    };

    if x.iter().copied().sum::<u16>() != TARGET_SUM {
        return false;
    }

    let one_time_pk: [[u8; TH_HASH_LEN]; NUM_CHUNKS] =
        from_fn(|i| chain(epoch, pk.parameter, i as _, x[i], sig.one_time_sig[i]));

    merkle_root(epoch, pk.parameter, one_time_pk, sig.merkle_siblings) == pk.merkle_root
}

fn chain(
    epoch: u32,
    parameter: [u8; PARAM_LEN],
    i: u16,
    x_i: u16,
    one_time_sig_i: [u8; TH_HASH_LEN],
) -> [u8; TH_HASH_LEN] {
    (x_i..(1 << CHUNK_SIZE) - 1).fold(one_time_sig_i, |value, step| {
        truncated_sha3::<53, TH_HASH_LEN>(concat![
            parameter,
            encode_tweak_chain(epoch, i, step + 1),
            value,
        ])
    })
}

fn merkle_root(
    epoch: u32,
    parameter: [u8; PARAM_LEN],
    one_time_pk: [[u8; TH_HASH_LEN]; NUM_CHUNKS],
    siblings: [[u8; TH_HASH_LEN]; LOG_LIFETIME],
) -> [u8; TH_HASH_LEN] {
    zip(1u8.., siblings).fold(
        truncated_sha3::<1896, TH_HASH_LEN>(concat![
            parameter,
            encode_tweak_merkle_tree(0, epoch),
            one_time_pk.into_iter().flatten(),
        ]),
        |node, (level, sibling)| {
            truncated_sha3::<76, TH_HASH_LEN>(concat![
                parameter,
                encode_tweak_merkle_tree(level, epoch >> level),
                (if (epoch >> (level - 1)) & 1 == 0 {
                    [node, sibling]
                } else {
                    [sibling, node]
                })
                .into_iter()
                .flatten(),
            ])
        },
    )
}

fn encode_tweak_chain(epoch: u32, i: u16, k: u16) -> [u8; 9] {
    const SEP: u8 = 0x00;
    concat![[SEP], epoch.to_be_bytes(), i.to_be_bytes(), k.to_be_bytes()]
}

fn encode_tweak_merkle_tree(l: u8, i: u32) -> [u8; 6] {
    const SEP: u8 = 0x01;
    concat![[SEP, l], i.to_be_bytes()]
}

fn encode_tweak_msg(epoch: u32) -> [u8; 5] {
    const SEP: u8 = 0x02;
    concat![[SEP], epoch.to_le_bytes()]
}

fn msg_hash_to_chunks(bytes: [u8; MSG_HASH_LEN]) -> [u16; NUM_CHUNKS] {
    const MASK: u8 = ((1 << CHUNK_SIZE) - 1) as u8;
    from_fn(|i| ((bytes[(i * CHUNK_SIZE) / 8] >> ((i * CHUNK_SIZE) % 8)) & MASK) as _)
}

fn truncated_sha3<const I: usize, const O: usize>(input: [u8; I]) -> [u8; O] {
    let output = Sha3_256::digest(input);
    from_fn(|i| output[i])
}

macro_rules! concat {
    [$first:expr $(, $rest:expr)* $(,)?] => {
        $first.into_iter()$(.chain($rest))*.collect::<Vec<_>>().try_into().unwrap()
    };
}

use concat;
