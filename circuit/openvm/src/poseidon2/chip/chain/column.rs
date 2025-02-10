use crate::{
    gadget::{is_equal::IsEqualCols, is_zero::IsZeroCols, select},
    poseidon2::{
        HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::chain::{
            GROUP_SIZE, LAST_GROUP_SIZE, NUM_GROUPS,
            poseidon2::{PARTIAL_ROUNDS, WIDTH},
        },
        hash_sig::{CHUNK_SIZE, PARAM_FE_LEN, TH_HASH_FE_LEN, TWEAK_FE_LEN},
    },
};
use core::{
    array::from_fn,
    borrow::{Borrow, BorrowMut},
    iter::zip,
};
use openvm_stark_backend::{p3_air::AirBuilder, p3_field::FieldAlgebra};
use p3_poseidon2_util::air::{Poseidon2Cols, outputs};

pub const NUM_CHAIN_COLS: usize = size_of::<ChainCols<u8>>();

#[repr(C)]
pub struct ChainCols<T> {
    pub perm:
        Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    /// One-hot array indicating whether `group[idx]` is active.
    pub group_ind: [T; NUM_GROUPS],
    /// Accumulator of `((((x_{i} << CHUNK_SIZE) + x_{i+1}) << CHUNK_SIZE) + ...) + x_{i + GROUP_SIZE - 1}`
    pub group_acc: [T; NUM_GROUPS],
    /// Equals to `group_step << (CHUNK_SIZE)`.
    pub group_acc_scalar: T,
    /// Equals to `group_acc_scalar * chain_step`.
    pub group_acc_item: T,
    /// Cycling through `0..LAST_GROUP_SIZE` when `group_ind[NUM_GROUPS - 1]`,
    /// otherwise `0..GROUP_SIZE`.
    pub group_step: T,
    /// Chain step in little-endian bits, in range `0..(1 << CHUNK_SIZE)`.
    pub chain_step_bits: [T; CHUNK_SIZE],
    /// Sum of `x_i`.
    pub sum: T,
    /// Whether `group_step == 0`.
    pub is_first_group_step: IsZeroCols<T>,
    /// Whether `group_step == LAST_GROUP_SIZE - 1` when `group_ind[NUM_GROUPS - 1]`,
    /// otherwise `group_step == GROUP_SIZE - 1`.
    pub is_last_group_step: IsEqualCols<T>,
    /// Equals to `is_last_gruop_step * is_last_chain_step`.
    pub is_last_group_row: T,
    /// Equals to `is_last_group_row * group_ind[NUM_GROUPS - 1]`.
    pub is_last_sig_row: T,
    /// Merkle tree root.
    pub merkle_root: [T; TH_HASH_FE_LEN],
    /// Whether this sig is active or not.
    pub is_active: T,
}

impl<T: Copy> ChainCols<T> {
    pub fn group_size<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        if GROUP_SIZE == LAST_GROUP_SIZE {
            AB::Expr::from_canonical_usize(GROUP_SIZE)
        } else {
            select(
                self.group_ind[NUM_GROUPS - 1].into(),
                AB::Expr::from_canonical_usize(GROUP_SIZE),
                AB::Expr::from_canonical_usize(LAST_GROUP_SIZE),
            )
        }
    }

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

    pub fn leaf_chunk_idx<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        zip((0..).step_by(GROUP_SIZE), self.group_ind)
            .map(|(scalar, ind)| AB::Expr::from_canonical_usize(scalar) * ind.into())
            .sum::<AB::Expr>()
            + self.group_step.into()
            + AB::Expr::ONE
    }

    pub fn chain_input<AB: AirBuilder>(&self) -> [AB::Expr; TH_HASH_FE_LEN]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| self.perm.inputs[PARAM_FE_LEN + TWEAK_FE_LEN + i].into())
    }

    pub fn compression_output<AB: AirBuilder>(&self) -> [AB::Expr; TH_HASH_FE_LEN]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| self.perm.inputs[i].into() + outputs(&self.perm)[i].into())
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
