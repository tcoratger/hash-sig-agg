use crate::{
    gadget::is_equal::IsEqualCols,
    poseidon2::hash_sig::{PARAM_FE_LEN, TH_HASH_FE_LEN, TWEAK_FE_LEN},
};
use core::borrow::{Borrow, BorrowMut};

pub const NUM_MERKLE_TREE_COLS: usize = size_of::<MerkleTreeCols<u8>>();

#[repr(C)]
pub struct MerkleTreeCols<T> {
    pub parameter: [T; PARAM_FE_LEN],
    pub encoded_tweak: [T; TWEAK_FE_LEN],
    pub level: T,
    pub is_last_level: IsEqualCols<T>,
    pub epoch_dec: T,
    pub is_right: T,
    pub leaf: [T; TH_HASH_FE_LEN],
    pub left: [T; TH_HASH_FE_LEN],
    pub right: [T; TH_HASH_FE_LEN],
    pub output: [T; TH_HASH_FE_LEN],
    pub is_active: T,
}

impl<T> Borrow<MerkleTreeCols<T>> for [T] {
    fn borrow(&self) -> &MerkleTreeCols<T> {
        debug_assert_eq!(self.len(), NUM_MERKLE_TREE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<MerkleTreeCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<MerkleTreeCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut MerkleTreeCols<T> {
        debug_assert_eq!(self.len(), NUM_MERKLE_TREE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<MerkleTreeCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
