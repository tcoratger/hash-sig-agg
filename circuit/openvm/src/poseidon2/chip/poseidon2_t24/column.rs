use crate::{
    gadget::is_equal::IsEqualCols,
    poseidon2::{
        HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::poseidon2_t24::{PARTIAL_ROUNDS, WIDTH},
        hash_sig::{SPONGE_RATE, TH_HASH_FE_LEN},
    },
};
use core::{
    array::from_fn,
    borrow::{Borrow, BorrowMut},
};
use openvm_stark_backend::p3_air::AirBuilder;
use p3_poseidon2_air::Poseidon2Cols;

pub const NUM_POSEIDON2_T24_COLS: usize = size_of::<Poseidon2T24Cols<u8>>();

#[repr(C)]
pub struct Poseidon2T24Cols<T> {
    pub perm:
        Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    pub sponge_block_step: T,
    pub is_last_sponge_step: IsEqualCols<T>,
    pub sponge_block: [T; SPONGE_RATE],
    pub sponge_output: [T; TH_HASH_FE_LEN],
    pub is_compress: T,
    pub mult: T,
}

impl<T: Copy> Poseidon2T24Cols<T> {
    pub fn compress_output<AB: AirBuilder>(&self) -> [AB::Expr; TH_HASH_FE_LEN]
    where
        T: Into<AB::Expr>,
    {
        from_fn(|i| {
            self.perm.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i].into()
                + self.perm.inputs[i].into()
        })
    }
}

impl<T> Borrow<Poseidon2T24Cols<T>> for [T] {
    fn borrow(&self) -> &Poseidon2T24Cols<T> {
        debug_assert_eq!(self.len(), NUM_POSEIDON2_T24_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Poseidon2T24Cols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<Poseidon2T24Cols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Poseidon2T24Cols<T> {
        debug_assert_eq!(self.len(), NUM_POSEIDON2_T24_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Poseidon2T24Cols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
