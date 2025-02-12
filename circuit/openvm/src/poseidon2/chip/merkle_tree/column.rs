use crate::{
    gadget::{is_equal::IsEqualCols, not},
    poseidon2::{
        HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::merkle_tree::{PARTIAL_ROUNDS, WIDTH},
        hash_sig::{
            MSG_FE_LEN, MSG_HASH_FE_LEN, PARAM_FE_LEN, RHO_FE_LEN, SPONGE_RATE, TH_HASH_FE_LEN,
            TWEAK_FE_LEN,
        },
    },
};
use core::{
    array::from_fn,
    borrow::{Borrow, BorrowMut},
};
use openvm_stark_backend::p3_air::AirBuilder;
use p3_poseidon2_util::air::{Poseidon2Cols, outputs};

pub const NUM_MERKLE_TREE_COLS: usize = size_of::<MerkleTreeCols<u8>>();

#[repr(C)]
pub struct MerkleTreeCols<T> {
    pub perm:
        Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    pub sig_idx: T,
    pub is_msg: T,
    pub is_merkle_leaf: T,
    pub is_merkle_leaf_transition: T,
    pub is_merkle_path: T,
    pub is_merkle_path_transition: T,
    pub is_recevie_merkle_tree: [T; 3],
    pub root: [T; TH_HASH_FE_LEN],
    pub sponge_step: T,
    pub is_last_sponge_step: IsEqualCols<T>,
    pub sponge_block: [T; SPONGE_RATE],
    pub leaf_chunk_start_ind: [T; SPONGE_RATE],
    pub leaf_chunk_idx: T,
    pub level: T,
    pub is_last_level: IsEqualCols<T>,
    pub epoch_dec: T,
    pub is_right: T,
}

impl<T: Copy> MerkleTreeCols<T> {
    pub fn is_sig_transition<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        self.is_msg.into() + self.is_merkle_leaf.into() + self.is_merkle_path_transition.into()
    }

    pub fn is_padding<AB: AirBuilder>(&self) -> AB::Expr
    where
        T: Into<AB::Expr>,
    {
        not(self.is_msg.into() + self.is_merkle_leaf.into() + self.is_merkle_path.into())
    }

    pub fn msg_hash_parameter(&self) -> [T; PARAM_FE_LEN] {
        from_fn(|i| self.perm.inputs[RHO_FE_LEN + TWEAK_FE_LEN + MSG_FE_LEN + i])
    }

    pub fn encoded_tweak_msg(&self) -> [T; PARAM_FE_LEN] {
        from_fn(|i| self.perm.inputs[RHO_FE_LEN + i])
    }

    pub fn encoded_msg(&self) -> [T; PARAM_FE_LEN] {
        from_fn(|i| self.perm.inputs[RHO_FE_LEN + TWEAK_FE_LEN + i])
    }

    pub fn merkle_leaf_parameter(&self) -> [T; PARAM_FE_LEN] {
        from_fn(|i| self.sponge_block[i])
    }

    pub fn encoded_tweak_merkle_leaf(&self) -> [T; TWEAK_FE_LEN] {
        from_fn(|i| self.sponge_block[PARAM_FE_LEN + i])
    }

    pub fn msg_hash<AB: AirBuilder>(&self) -> [AB::Expr; MSG_HASH_FE_LEN]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| outputs(&self.perm)[i].into() + self.perm.inputs[i].into())
    }

    pub fn compress_output<AB: AirBuilder>(&self) -> [AB::Expr; TH_HASH_FE_LEN]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| outputs(&self.perm)[i].into() + self.perm.inputs[i].into())
    }

    pub fn sponge_output(&self) -> [T; 24] {
        *outputs(&self.perm)
    }

    pub fn path_left(&self) -> [T; TH_HASH_FE_LEN] {
        from_fn(|i| self.perm.inputs[PARAM_FE_LEN + TWEAK_FE_LEN + i])
    }

    pub fn path_right(&self) -> [T; TH_HASH_FE_LEN] {
        from_fn(|i| self.perm.inputs[PARAM_FE_LEN + TWEAK_FE_LEN + TH_HASH_FE_LEN + i])
    }
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
