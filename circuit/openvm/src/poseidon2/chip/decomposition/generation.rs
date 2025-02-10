use crate::poseidon2::{
    F,
    chip::decomposition::{
        F_MS_LIMB, F_MS_LIMB_BITS, LIMB_BITS, LIMB_MASK, NUM_LIMBS, NUM_MSG_HASH_LIMBS,
        column::{DecompositionCols, NUM_DECOMPOSITION_COLS},
    },
    hash_sig::{MSG_HASH_FE_LEN, VerificationTrace},
};
use core::{array::from_fn, iter::zip, mem::MaybeUninit};
use openvm_stark_backend::{
    p3_field::{FieldAlgebra, PrimeField32},
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
    (5 * traces.len()).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    traces: &[VerificationTrace],
) -> RowMajorMatrix<F> {
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

    let (msg_hash_rows, padding_rows) = rows.split_at_mut(5 * traces.len());

    join(
        || {
            msg_hash_rows
                .par_chunks_mut(5)
                .zip(traces.par_iter().map(|trace| trace.msg_hash))
                .for_each(|(rows, mut msg_hash)| {
                    msg_hash.reverse();
                    let mut acc_limbs = Default::default();
                    rows.iter_mut().enumerate().for_each(|(step, row)| {
                        generate_trace_row(row, &mut acc_limbs, msg_hash, step, 1)
                    });
                })
        },
        || {
            padding_rows.iter_mut().for_each(|row| {
                row.ind.iter_mut().for_each(|cell| {
                    cell.write(F::ZERO);
                });
                row.values.iter_mut().for_each(|cell| {
                    cell.write(F::ZERO);
                });
                row.value_ms_limb_bits.iter_mut().for_each(|cell| {
                    cell.write(F::ZERO);
                });
                row.value_ms_limb_auxs.iter_mut().for_each(|cell| {
                    cell.write(F::ZERO);
                });
                row.value_ls_limbs.iter_mut().for_each(|cell| {
                    cell.write(F::ZERO);
                });
                row.acc_limbs.iter_mut().for_each(|cell| {
                    cell.write(F::ZERO);
                });
                row.carries.iter_mut().for_each(|cell| {
                    cell.write(F::ZERO);
                });
                row.mult.write(F::ZERO);
            })
        },
    );

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_DECOMPOSITION_COLS)
}

pub fn generate_trace_row(
    row: &mut DecompositionCols<MaybeUninit<F>>,
    acc_limbs: &mut [u32; NUM_MSG_HASH_LIMBS],
    values: [F; MSG_HASH_FE_LEN],
    step: usize,
    mult: usize,
) {
    let value = values[MSG_HASH_FE_LEN - 1 - step].as_canonical_u32();
    let value_limbs: [_; NUM_LIMBS] = from_fn(|i| (value >> (i * LIMB_BITS)) & LIMB_MASK);
    let value_ms_limb_bits: [_; F_MS_LIMB_BITS] =
        from_fn(|i| (value_limbs[NUM_LIMBS - 1] >> i) & 1 == 1);
    let value_ms_limb_auxs = {
        let aux0 = value_ms_limb_bits[0] & value_ms_limb_bits[1] & value_ms_limb_bits[1];
        let aux1 = aux0 & value_ms_limb_bits[3] & !value_ms_limb_bits[4];
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
    row.ind.iter_mut().enumerate().for_each(|(j, cell)| {
        cell.write(F::from_bool(MSG_HASH_FE_LEN - 1 - step == j));
    });
    zip(&mut row.values, values).for_each(|(cell, value)| {
        cell.write(value);
    });
    row.value_ms_limb_bits
        .iter_mut()
        .zip(value_ms_limb_bits)
        .for_each(|(cell, value)| {
            cell.write(F::from_bool(value));
        });
    row.value_ms_limb_auxs
        .iter_mut()
        .zip(value_ms_limb_auxs)
        .for_each(|(cell, value)| {
            cell.write(F::from_bool(value));
        });
    row.value_ls_limbs
        .iter_mut()
        .zip(value_limbs)
        .for_each(|(cell, value)| {
            cell.write(F::from_canonical_u32(value));
        });
    row.acc_limbs
        .iter_mut()
        .zip(acc_limbs)
        .for_each(|(cell, value)| {
            cell.write(F::from_canonical_u32(*value));
        });
    row.carries
        .iter_mut()
        .zip(carries)
        .for_each(|(cell, value)| {
            cell.write(F::from_canonical_u32(value));
        });
    row.mult.write(if step == MSG_HASH_FE_LEN - 1 {
        F::from_canonical_usize(mult)
    } else {
        F::ZERO
    });
}
