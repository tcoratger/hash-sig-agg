use crate::poseidon2::{
    chip::decomposition::NUM_MSG_HASH_LIMBS,
    hash_sig::{MSG_HASH_FE_LEN, PARAM_FE_LEN, TH_HASH_FE_LEN},
};
use core::borrow::{Borrow, BorrowMut};

pub const NUM_MAIN_COLS: usize = size_of::<MainCols<u8>>();

#[repr(C)]
pub struct MainCols<F> {
    pub is_active: F,
    pub parameter: [F; PARAM_FE_LEN],
    pub merkle_root: [F; TH_HASH_FE_LEN],
    pub msg_hash: [F; MSG_HASH_FE_LEN],
    pub msg_hash_limbs: [F; NUM_MSG_HASH_LIMBS],
}

impl<F> Borrow<MainCols<F>> for [F] {
    fn borrow(&self) -> &MainCols<F> {
        debug_assert_eq!(self.len(), NUM_MAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MainCols<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<F> BorrowMut<MainCols<F>> for [F] {
    fn borrow_mut(&mut self) -> &mut MainCols<F> {
        debug_assert_eq!(self.len(), NUM_MAIN_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<MainCols<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
