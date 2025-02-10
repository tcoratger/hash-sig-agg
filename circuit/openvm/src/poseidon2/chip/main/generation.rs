use crate::{
    poseidon2::{
        F,
        chip::{
            decomposition::LIMB_BITS,
            main::column::{MainCols, NUM_MAIN_COLS},
        },
        hash_sig::VerificationTrace,
    },
    util::{MaybeUninitField, MaybeUninitFieldSlice},
};
use core::mem::MaybeUninit;
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
    traces.len().next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    traces: &[VerificationTrace],
) -> RowMajorMatrix<F> {
    let height = trace_height(traces);
    let size = height * NUM_MAIN_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_MAIN_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<MainCols<MaybeUninit<_>>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    rows.par_iter_mut().enumerate().for_each(|(idx, row)| {
        if let Some(trace) = traces.get(idx) {
            row.is_active.write(F::ONE);
            row.parameter.fill_from_slice(&trace.pk.parameter);
            row.merkle_root.fill_from_slice(&trace.pk.merkle_root);
            row.msg_hash.fill_from_slice(&trace.msg_hash);
            row.msg_hash_limbs
                .fill_from_iter(trace.msg_hash_limbs(LIMB_BITS).map(F::from_canonical_u32));
        } else {
            row.is_active.write_zero();
            row.parameter.fill_zero();
            row.merkle_root.fill_zero();
            row.msg_hash.fill_zero();
            row.msg_hash_limbs.fill_zero();
        }
    });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_MAIN_COLS)
}
