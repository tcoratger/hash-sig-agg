use crate::poseidon2::chip::decomposition::{F_MS_LIMB_BITS, NUM_LIMBS, NUM_MSG_HASH_LIMBS};
use core::borrow::{Borrow, BorrowMut};

pub const NUM_DECOMPOSITION_COLS: usize = size_of::<DecompositionCols<u8>>();

#[repr(C)]
pub struct DecompositionCols<T> {
    pub ind: [T; 5],
    pub values: [T; 5],
    pub value_ls_limbs: [T; NUM_LIMBS - 1],
    pub value_ms_limb_bits: [T; F_MS_LIMB_BITS],
    pub value_ms_limb_auxs: [T; 2],
    pub acc_limbs: [T; NUM_MSG_HASH_LIMBS],
    pub carries: [T; NUM_MSG_HASH_LIMBS - 1],
    pub mult: T,
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
