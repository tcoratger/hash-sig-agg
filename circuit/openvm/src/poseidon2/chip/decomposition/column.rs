use core::borrow::{Borrow, BorrowMut};

pub const NUM_DECOMPOSITION_COLS: usize = size_of::<DecompositionCols<u8>>();

#[repr(C)]
pub struct DecompositionCols<T> {
    values: [T; 5],
    value_bytes: [T; 4],
    ind: [T; 5],
    acc_bytes: [T; 20],
    acc_carries: [T; 20],
    mult: T,
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
