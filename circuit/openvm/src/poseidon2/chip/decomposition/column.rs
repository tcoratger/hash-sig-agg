use crate::{
    gadget::is_zero::IsZeroCols,
    poseidon2::{
        chip::decomposition::{F_MS_LIMB_BITS, NUM_LIMBS, NUM_MSG_HASH_LIMBS},
        hash_sig::MSG_HASH_FE_LEN,
    },
};
use core::borrow::{Borrow, BorrowMut};
use openvm_stark_backend::{p3_air::AirBuilder, p3_field::FieldAlgebra};

pub const NUM_DECOMPOSITION_COLS: usize = size_of::<DecompositionCols<u8>>();

#[repr(C)]
pub struct DecompositionCols<T> {
    /// One-hot vector indicating current step.
    pub ind: [T; MSG_HASH_FE_LEN],
    /// Scalars in little-endian order.
    pub values: [T; MSG_HASH_FE_LEN],
    /// Least significant limbs of `value[step]`.
    pub value_ls_limbs: [T; NUM_LIMBS - 1],
    /// Most significant limb bits of `value[step]`.
    pub value_ms_limb_bits: [T; F_MS_LIMB_BITS],
    /// Whether `value_ls_limbs[0] == 0`.
    pub value_limb_0_is_zero: IsZeroCols<T>,
    /// Whether `value_ls_limbs[1] == 0`.
    pub value_limb_1_is_zero: IsZeroCols<T>,
    /// Equals to `[value_ms_limb_bits[4] & value_ms_limb_bits[3] & value_ms_limb_bits[2], value_ms_limb_bits[1] & !value_ms_limb_bits[0]]`.
    pub value_ms_limb_auxs: [T; 2],
    /// Limbs of accumulation value.
    pub acc_limbs: [T; NUM_MSG_HASH_LIMBS],
    pub carries: [T; NUM_MSG_HASH_LIMBS - 1],
}

impl<T: Copy> DecompositionCols<T> {
    pub fn value_ms_limb<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.value_ms_limb_bits
            .iter()
            .rfold(AB::Expr::ZERO, |acc, bit| acc.double() + (*bit).into())
    }
}

impl<T> Borrow<DecompositionCols<T>> for [T] {
    fn borrow(&self) -> &DecompositionCols<T> {
        debug_assert_eq!(self.len(), NUM_DECOMPOSITION_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<DecompositionCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<DecompositionCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut DecompositionCols<T> {
        debug_assert_eq!(self.len(), NUM_DECOMPOSITION_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<DecompositionCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
