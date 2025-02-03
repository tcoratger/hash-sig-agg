use openvm_stark_sdk::p3_baby_bear::BabyBear;
use p3_poseidon2_util::horizon;

pub mod chip;
pub mod hash_sig;

pub type F = BabyBear;

pub const SBOX_REGISTERS: usize = 1;

pub use horizon::baby_bear::{
    GenericPoseidon2LinearLayersHorizon, Poseidon2Horizon,
    constant::{HALF_FULL_ROUNDS, RC16, RC24, SBOX_DEGREE},
};

macro_rules! concat_array {
    [$first:expr $(, $rest:expr)* $(,)?] => {{
        let mut iter = $first.into_iter()$(.chain($rest))*;
        ::core::array::from_fn(|_| iter.next().unwrap_or_default())
    }};
}

use concat_array;
