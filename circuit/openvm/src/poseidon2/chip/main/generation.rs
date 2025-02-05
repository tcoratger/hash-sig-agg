use crate::poseidon2::{
    F,
    chip::main::column::{MainCols, NUM_MAIN_COLS},
    concat_array,
    hash_sig::{
        MSG_FE_LEN, MSG_HASH_FE_LEN, PublicKey, Signature, TH_HASH_FE_LEN, TWEAK_FE_LEN,
        msg_hash_to_chunks, poseidon2_compress,
    },
};
use core::array::from_fn;
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};

pub fn trace_height(pairs: &[(PublicKey, Signature)]) -> usize {
    pairs.len().next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    encoded_tweak_msg: [F; TWEAK_FE_LEN],
    encoded_msg: [F; MSG_FE_LEN],
    pairs: Vec<(PublicKey, Signature)>,
) -> RowMajorMatrix<F> {
    let height = trace_height(&pairs);
    let size = height * NUM_MAIN_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_MAIN_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<MainCols<_>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    rows.par_iter_mut().enumerate().for_each(|(idx, row)| {
        if let Some((pk, sig)) = pairs.get(idx) {
            row.is_active = F::ONE;
            row.parameter = pk.parameter;
            row.merkle_root = pk.merkle_root;
            row.rho = sig.rho;
            let hash = poseidon2_compress::<24, 22, TH_HASH_FE_LEN>(concat_array![
                sig.rho,
                encoded_tweak_msg,
                encoded_msg,
                pk.parameter,
            ]);
            row.msg_hash = from_fn(|i| hash[i]);
            row.msg_hash_aux = from_fn(|i| hash[MSG_HASH_FE_LEN + i]);
            row.x = msg_hash_to_chunks(row.msg_hash).map(F::from_canonical_u16);
        }
    });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_MAIN_COLS)
}
