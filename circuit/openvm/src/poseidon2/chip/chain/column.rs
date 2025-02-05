use crate::{
    gadget::{is_equal::IsEqualCols, is_zero::IsZeroCols},
    poseidon2::{
        HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::chain::poseidon2::{PARTIAL_ROUNDS, WIDTH},
        hash_sig::{
            CHUNK_SIZE, NUM_CHUNKS, PARAM_FE_LEN, SPONGE_RATE, TH_HASH_FE_LEN, TWEAK_FE_LEN,
        },
    },
};
use core::{
    array::from_fn,
    borrow::{Borrow, BorrowMut},
};
use openvm_stark_backend::{p3_air::AirBuilder, p3_field::FieldAlgebra};
use p3_poseidon2_air::Poseidon2Cols;

pub const NUM_CHAIN_COLS: usize = size_of::<ChainCols<u8>>();

pub const GROUP_SIZE: usize = 13;
pub const NUM_GROUPS: usize = NUM_CHUNKS.div_ceil(GROUP_SIZE);

#[repr(C)]
pub struct ChainCols<T> {
    pub perm:
        Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    /// Indicator for whether `group[idx]` is active.
    pub group_ind: [T; NUM_GROUPS],
    /// Concatenation of `[x_{i}, x_{i+1}, ..., x_{i+12}]` in little-endian.
    pub group_acc: [T; NUM_GROUPS],
    /// Cycling through `0..13` and `i = 13 * group_idx + group_step`.
    pub group_step: T,
    /// Chain step in little-endian bits.
    pub chain_step_bits: [T; CHUNK_SIZE],
    /// Whether `group_step == 0`.
    pub is_first_group_step: IsZeroCols<T>,
    /// Whether `group_step == 12`.
    pub is_last_group_step: IsEqualCols<T>,
    /// Equals to `is_last_gruop_step * is_last_chain_step`.
    pub is_last_group_row: T,
    /// Equals to `is_last_gruop_step * group_ind[5]`.
    pub is_last_sig_row: T,
    /// Merkle tree root.
    pub merkle_root: [T; TH_HASH_FE_LEN],
    /// Leaf block step.
    pub leaf_block_step: T,
    /// Leaf block and overflowing.
    pub leaf_block_and_buf: [T; SPONGE_RATE + TH_HASH_FE_LEN - 1],
    /// Leaf block pointer indicators.
    pub leaf_block_ptr_ind: [T; SPONGE_RATE],
    /// Whether this sig is active or not.
    pub is_active: T,
}

impl<T: Copy> ChainCols<T> {
    pub fn chain_step<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        const { assert!(CHUNK_SIZE == 2) }
        self.chain_step_bits[0].into() + self.chain_step_bits[1].into().double()
    }

    /// Returns bool indicating `chain_step >= (1 << CHUNKS_SIZE) - 2`
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

    pub fn encoded_tweak_chain(&self) -> &[T] {
        &self.perm.inputs[PARAM_FE_LEN..][..TWEAK_FE_LEN]
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
