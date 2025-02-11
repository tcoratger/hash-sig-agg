use crate::{
    gadget::{is_equal::IsEqualCols, is_zero::IsZeroCols, lower_rows_filter::LowerRowsFilterCols},
    poseidon2::{
        HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::chain::{
            MAX_CHAIN_STEP_DIFF_BITS,
            poseidon2::{PARTIAL_ROUNDS, WIDTH},
        },
        hash_sig::{CHUNK_SIZE, PARAM_FE_LEN, TH_HASH_FE_LEN, TWEAK_FE_LEN},
    },
};
use core::{
    array::from_fn,
    borrow::{Borrow, BorrowMut},
};
use openvm_stark_backend::{p3_air::AirBuilder, p3_field::FieldAlgebra};
use p3_poseidon2_util::air::{Poseidon2Cols, outputs};

pub const NUM_CHAIN_COLS: usize = size_of::<ChainCols<u8>>();

#[repr(C)]
pub struct ChainCols<T> {
    pub perm:
        Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    /// Whether this sig is active or not.
    pub is_active: LowerRowsFilterCols<T>,
    /// Signature index.
    pub sig_idx: T,
    /// Signature step.
    pub sig_step: T,
    /// Whether `sig_step == TARGET_SUM - 1`
    pub is_last_sig_row: IsEqualCols<T>,
    /// Chain index.
    pub chain_idx: T,
    /// Whether `chain_idx == 0`.
    pub chain_idx_is_zero: IsZeroCols<T>,
    /// Chain index diff range check.
    pub chain_idx_diff_bits: [T; MAX_CHAIN_STEP_DIFF_BITS],
    /// Chain index diff inverse.
    pub chain_idx_diff_inv: T,
    /// Chain step in little-endian bits, in range `0..(1 << CHUNK_SIZE)`.
    pub chain_step_bits: [T; CHUNK_SIZE],
    /// Chain step in little-endian bits, in range `0..(1 << CHUNK_SIZE)`.
    pub is_receiving_chain: T,
    /// Sum of `x_i`.
    pub sum: T,
}

impl<T: Copy> ChainCols<T> {
    pub fn is_sig_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        (*self.is_active).into() - self.is_last_sig_row.output.into()
    }

    pub fn chain_idx_diff<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.chain_idx_diff_bits
            .iter()
            .rfold(AB::Expr::ZERO, |acc, bit| acc.double() + (*bit).into())
    }

    pub fn chain_step<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        const { assert!(CHUNK_SIZE == 2) }
        self.chain_step_bits[0].into() + self.chain_step_bits[1].into().double()
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

    pub fn encoded_tweak_chain(&self) -> &[T] {
        &self.perm.inputs[PARAM_FE_LEN..][..TWEAK_FE_LEN]
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
