use crate::{
    poseidon2::{
        F,
        chip::decomposition::{
            F_MS_LIMB, F_MS_LIMB_BITS, LIMB_BITS, LIMB_MASK, NUM_LIMBS, NUM_MSG_HASH_LIMBS,
            column::{DecompositionCols, NUM_DECOMPOSITION_COLS},
        },
        hash_sig::{MSG_HASH_FE_LEN, VerificationTrace},
    },
    util::MaybeUninitFieldSlice,
};
use core::{array::from_fn, iter::repeat_with, mem::MaybeUninit};
use openvm_stark_backend::{
    p3_field::{FieldAlgebra, PrimeField32},
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};
use std::sync::atomic::{AtomicU32, Ordering};

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
    (MSG_HASH_FE_LEN * traces.len()).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    traces: &[VerificationTrace],
) -> (RowMajorMatrix<F>, Vec<u32>) {
    let height = trace_height(traces);
    let size = height * NUM_DECOMPOSITION_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_DECOMPOSITION_COLS);

    let (prefix, rows, suffix) = unsafe {
        trace
            .values
            .align_to_mut::<DecompositionCols<MaybeUninit<_>>>()
    };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let (msg_hash_rows, padding_rows) = rows.split_at_mut(MSG_HASH_FE_LEN * traces.len());
    let mult = repeat_with(|| AtomicU32::new(0))
        .take(1 << LIMB_BITS)
        .collect::<Vec<_>>();

    join(
        || {
            msg_hash_rows
                .par_chunks_mut(MSG_HASH_FE_LEN)
                .zip(traces.par_iter().map(|trace| trace.msg_hash))
                .for_each(|(rows, mut msg_hash)| {
                    msg_hash.reverse(); // TODO: Remove when #9 is resolved.
                    let mut acc_limbs = Default::default();
                    rows.iter_mut().enumerate().for_each(|(step, row)| {
                        generate_trace_row(row, &mut acc_limbs, msg_hash, step, &mult);
                    });
                })
        },
        || {
            padding_rows.iter_mut().for_each(|row| {
                row.ind.fill_zero();
                row.values.fill_zero();
                row.value_ls_limbs.fill_zero();
                row.value_ms_limb_bits.fill_zero();
                row.value_limb_0_is_zero.populate(F::ZERO);
                row.value_limb_1_is_zero.populate(F::ZERO);
                row.value_ms_limb_auxs.fill_zero();
                row.acc_limbs.fill_zero();
                row.carries.fill_zero();
            })
        },
    );

    unsafe { vec.set_len(size) };

    (
        RowMajorMatrix::new(vec, NUM_DECOMPOSITION_COLS),
        mult.into_par_iter()
            .map(|value| value.load(Ordering::Relaxed))
            .collect(),
    )
}

pub fn generate_trace_row(
    row: &mut DecompositionCols<MaybeUninit<F>>,
    acc_limbs: &mut [u32; NUM_MSG_HASH_LIMBS],
    values: [F; MSG_HASH_FE_LEN],
    step: usize,
    mult: &[AtomicU32],
) {
    let value = values[MSG_HASH_FE_LEN - 1 - step].as_canonical_u32();
    let value_limbs: [_; NUM_LIMBS] = from_fn(|i| (value >> (i * LIMB_BITS)) & LIMB_MASK);
    let value_ms_limb_bits: [_; F_MS_LIMB_BITS] =
        from_fn(|i| (value_limbs[NUM_LIMBS - 1] >> i) & 1 == 1);
    let value_ms_limb_auxs = {
        let aux0 = value_ms_limb_bits[4] & value_ms_limb_bits[3] & value_ms_limb_bits[2];
        let aux1 = aux0 & value_ms_limb_bits[1] & !value_ms_limb_bits[0];
        [aux0, aux1]
    };
    let mut carries = [0; NUM_MSG_HASH_LIMBS - 1];
    *acc_limbs = from_fn(|i| {
        let sum = if i == 0 {
            acc_limbs[i] + value_limbs[i]
        } else if i < NUM_LIMBS - 1 {
            acc_limbs[i] + value_limbs[i] + carries[i - 1]
        } else if i < NUM_LIMBS {
            acc_limbs[i - (NUM_LIMBS - 1)] * F_MS_LIMB
                + acc_limbs[i]
                + value_limbs[i]
                + carries[i - 1]
        } else {
            acc_limbs[i - (NUM_LIMBS - 1)] * F_MS_LIMB + acc_limbs[i] + carries[i - 1]
        };
        if i < NUM_MSG_HASH_LIMBS - 1 {
            carries[i] = sum >> LIMB_BITS;
        }
        sum & LIMB_MASK
    });
    value_limbs
        .into_iter()
        .take(NUM_LIMBS - 1)
        .chain(*acc_limbs)
        .chain(carries)
        .for_each(|value| {
            mult[value as usize].fetch_add(1, Ordering::Relaxed);
        });
    let value_ls_limbs: [_; NUM_LIMBS - 1] = from_fn(|i| F::from_canonical_u32(value_limbs[i]));
    row.ind.fill_from_iter(
        (0..MSG_HASH_FE_LEN).map(|j| F::from_bool(MSG_HASH_FE_LEN - 1 - step == j)),
    );
    row.values.fill_from_slice(&values);
    row.value_ls_limbs.fill_from_slice(&value_ls_limbs);
    row.value_ms_limb_bits
        .fill_from_iter(value_ms_limb_bits.map(F::from_bool));
    row.value_limb_0_is_zero.populate(value_ls_limbs[0]);
    row.value_limb_1_is_zero.populate(value_ls_limbs[1]);
    row.value_ms_limb_auxs
        .fill_from_iter(value_ms_limb_auxs.map(F::from_bool));
    row.acc_limbs
        .fill_from_iter(acc_limbs.map(F::from_canonical_u32));
    row.carries
        .fill_from_iter(carries.map(F::from_canonical_u32));
}
