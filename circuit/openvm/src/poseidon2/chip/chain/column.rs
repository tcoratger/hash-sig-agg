use crate::{
    gadget::{is_equal::IsEqualCols, is_zero::IsZeroCols},
    poseidon2::{
        HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::chain::poseidon2::{PARTIAL_ROUNDS, WIDTH},
        hash_sig::{CHUNK_SIZE, PARAM_FE_LEN, TH_HASH_FE_LEN, TWEAK_FE_LEN},
    },
};
use core::{
    array::from_fn,
    borrow::{Borrow, BorrowMut},
};
use openvm_stark_backend::p3_air::AirBuilder;
use p3_poseidon2_air::Poseidon2Cols;

pub const NUM_CHAIN_COLS: usize = size_of::<ChainCols<u8>>();

#[repr(C)]
pub struct ChainCols<T> {
    pub perm:
        Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    pub encoded_tweak_chain: [T; TWEAK_FE_LEN],
    /// Indicator for whether `group[idx]` is active.
    pub group_ind: [T; 6],
    /// Concatenation of `[x_{i}, x_{i+1}, ..., x_{i+12}]` in little-endian.
    pub group_acc: [T; 6],
    /// Cycling through `0..13` and `i = 13 * group_idx + group_step`.
    pub group_step: T,
    /// Chain step in little-endian bits.
    pub chain_step_bits: [T; CHUNK_SIZE],
    /// Whether `group_step == 0`.
    pub is_group_first_step: IsZeroCols<T>,
    /// Whether `group_step == 12`.
    pub is_group_last_step: IsEqualCols<T>,
    /// Equals to `is_group_last_step * is_last_chain_step`.
    pub is_group_last_row: T,
    /// Equals to `is_group_last_step * group_ind[5]`.
    pub is_sig_last_row: T,
    pub mult: T,
}

impl<T: Copy> ChainCols<T> {
    pub fn chain_step<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        const { assert!(CHUNK_SIZE == 2) }
        self.chain_step_bits[0].into()
            + self.chain_step_bits[1].into()
            + self.chain_step_bits[1].into()
    }

    /// Returns bool indicating `chain_step == (1 << CHUNKS_SIZE) - 2`
    pub fn is_last_chain_step<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        const { assert!(CHUNK_SIZE == 2) }
        self.chain_step_bits[1].into()
    }

    pub fn parameter(&self) -> &[T] {
        &self.perm.inputs[..PARAM_FE_LEN]
    }

    pub fn chain_input<AB: AirBuilder>(&self) -> [AB::Expr; TH_HASH_FE_LEN]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| self.perm.inputs[PARAM_FE_LEN + TWEAK_FE_LEN + i].into())
    }

    pub fn chain_output<AB: AirBuilder>(&self) -> [AB::Expr; TH_HASH_FE_LEN]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| {
            self.perm.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i].into()
                + self.perm.inputs[i].into()
        })
    }
}

impl<T> Borrow<ChainCols<T>> for [T] {
    fn borrow(&self) -> &ChainCols<T> {
        debug_assert_eq!(self.len(), NUM_CHAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ChainCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<ChainCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut ChainCols<T> {
        debug_assert_eq!(self.len(), NUM_CHAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<ChainCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
