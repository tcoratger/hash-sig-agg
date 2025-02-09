use crate::poseidon2::{
    F,
    chip::{
        decomposition::LIMB_BITS,
        main::column::{MainCols, NUM_MAIN_COLS},
    },
    hash_sig::VerificationTrace,
};
use core::{iter::zip, mem::MaybeUninit};
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
            zip(&mut row.parameter, trace.pk.parameter).for_each(|(cell, value)| {
                cell.write(value);
            });
            zip(&mut row.merkle_root, trace.pk.merkle_root).for_each(|(cell, value)| {
                cell.write(value);
            });
            zip(&mut row.msg_hash, trace.msg_hash).for_each(|(cell, value)| {
                cell.write(value);
            });
            zip(&mut row.msg_hash_limbs, trace.msg_hash_limbs(LIMB_BITS)).for_each(
                |(cell, value)| {
                    cell.write(F::from_canonical_u32(value));
                },
            );
        } else {
            row.is_active.write(F::ZERO);
            row.parameter.iter_mut().for_each(|cell| {
                cell.write(F::ZERO);
            });
            row.merkle_root.iter_mut().for_each(|cell| {
                cell.write(F::ZERO);
            });
            row.msg_hash.iter_mut().for_each(|cell| {
                cell.write(F::ZERO);
            });
            row.msg_hash_limbs.iter_mut().for_each(|cell| {
                cell.write(F::ZERO);
            });
        }
    });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_MAIN_COLS)
}
