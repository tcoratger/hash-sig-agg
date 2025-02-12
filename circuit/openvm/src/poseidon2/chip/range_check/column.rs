use core::borrow::{Borrow, BorrowMut};

pub const NUM_RANGE_CHECK_COLS: usize = size_of::<RangeCheckCols<u8>>();

#[repr(C)]
pub struct RangeCheckCols<T> {
    pub value: T,
    pub mult: T,
}

impl<T> Borrow<RangeCheckCols<T>> for [T] {
    fn borrow(&self) -> &RangeCheckCols<T> {
        debug_assert_eq!(self.len(), NUM_RANGE_CHECK_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<RangeCheckCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<RangeCheckCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut RangeCheckCols<T> {
        debug_assert_eq!(self.len(), NUM_RANGE_CHECK_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<RangeCheckCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
