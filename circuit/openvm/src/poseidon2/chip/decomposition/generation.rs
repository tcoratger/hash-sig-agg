use crate::poseidon2::{
    F,
    chip::decomposition::column::{DecompositionCols, NUM_DECOMPOSITION_COLS},
    hash_sig::{
        CHUNK_SIZE, LOG_LIFETIME, MODULUS, NUM_CHUNKS, VerificationTrace, encode_tweak_chain,
        encode_tweak_merkle_tree,
    },
};
use core::{
    iter::{repeat, zip},
    mem::MaybeUninit,
};
use num_bigint::BigUint;
use openvm_stark_backend::{
    p3_field::{FieldAlgebra, PrimeField32},
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
    (5 * traces.len() + 2 * (NUM_CHUNKS * ((1 << CHUNK_SIZE) - 1) + LOG_LIFETIME))
        .next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    epoch: u32,
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

    let tweak_merkle_path = (0..LOG_LIFETIME as _)
        .into_par_iter()
        .map(|l| encode_tweak_merkle_tree(l + 1, epoch >> (l + 1)));
    let tweak_chain = (0..NUM_CHUNKS as _)
        .flat_map(|i| {
            (1..(1 << CHUNK_SIZE))
                .map(move |k| (encode_tweak_chain(epoch, i, k), AtomicUsize::new(0)))
        })
        .collect::<Vec<_>>();
    traces.par_iter().for_each(|trace| {
        trace.x.par_iter().enumerate().for_each(|(i, x_i)| {
            (x_i + 1..1 << CHUNK_SIZE).for_each(|k| {
                tweak_chain[i * ((1 << CHUNK_SIZE) - 1) + k as usize - 1]
                    .1
                    .fetch_add(1, Ordering::Relaxed);
            });
        })
    });

    let (msg_hash_rows, rest) = rows.split_at_mut(5 * traces.len());
    let (tweak_chain_rows, rest) = rest.split_at_mut(2 * (NUM_CHUNKS * ((1 << CHUNK_SIZE) - 1)));
    let (tweak_merkle_path_rows, padding_rows) = rest.split_at_mut(2 * LOG_LIFETIME);

    join(
        || {
            join(
                || {
                    msg_hash_rows
                        .par_chunks_mut(5)
                        .zip(traces.par_iter().map(|trace| trace.msg_hash))
                        .for_each(|(rows, msg_hash)| {
                            let mut acc = BigUint::ZERO;
                            rows.iter_mut().enumerate().for_each(|(i, row)| {
                                generate_trace_row(row, &mut acc, msg_hash, i, 1)
                            });
                        })
                },
                || {
                    join(
                        || {
                            tweak_merkle_path_rows
                                .par_chunks_mut(2)
                                .zip(tweak_merkle_path)
                                .for_each(|(rows, tweak)| {
                                    let mut acc = BigUint::ZERO;
                                    rows.iter_mut().enumerate().for_each(|(i, row)| {
                                        generate_trace_row(
                                            row, &mut acc, tweak, i, /* traces.len() */ 0,
                                        )
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
                                row.value_bytes.iter_mut().for_each(|cell| {
                                    cell.write(F::ZERO);
                                });
                                row.acc_bytes.iter_mut().for_each(|cell| {
                                    cell.write(F::ZERO);
                                });
                                row.mult.write(F::ZERO);
                            })
                        },
                    )
                },
            )
        },
        || {
            tweak_chain_rows
                .par_chunks_mut(2)
                .zip(tweak_chain)
                .for_each(|(rows, (tweak, mult))| {
                    let _mult = mult.load(Ordering::Relaxed);
                    let mut acc = BigUint::ZERO;
                    rows.iter_mut().enumerate().for_each(|(i, row)| {
                        generate_trace_row(row, &mut acc, tweak, i, /* mult */ 0)
                    });
                })
        },
    );

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_DECOMPOSITION_COLS)
}

pub fn generate_trace_row<const N: usize>(
    row: &mut DecompositionCols<MaybeUninit<F>>,
    acc: &mut BigUint,
    values: [F; N],
    i: usize,
    mult: usize,
) {
    *acc *= MODULUS;
    *acc += values[i].as_canonical_u32();
    row.ind.iter_mut().enumerate().for_each(|(j, cell)| {
        cell.write(F::from_bool(5 - N + i == j));
    });
    zip(&mut row.values, values).for_each(|(cell, value)| {
        cell.write(value);
    });
    zip(
        &mut row.value_bytes,
        values[i].as_canonical_u32().to_le_bytes(),
    )
    .for_each(|(cell, value)| {
        cell.write(F::from_canonical_u8(value));
    });
    zip(
        &mut row.acc_bytes,
        acc.to_bytes_le().into_iter().chain(repeat(0)),
    )
    .for_each(|(cell, value)| {
        cell.write(F::from_canonical_u8(value));
    });
    row.mult.write(if i == N - 1 {
        F::from_canonical_usize(mult)
    } else {
        F::ZERO
    });
}
