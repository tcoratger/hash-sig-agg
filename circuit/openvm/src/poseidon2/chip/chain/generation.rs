use crate::{
    poseidon2::{
        F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC16, SBOX_DEGREE,
        SBOX_REGISTERS,
        chip::chain::{
            MAX_CHAIN_STEP_DIFF_BITS,
            column::{ChainCols, NUM_CHAIN_COLS},
            poseidon2::{PARTIAL_ROUNDS, WIDTH},
        },
        concat_array,
        hash_sig::{CHUNK_SIZE, NUM_CHUNKS, TARGET_SUM, VerificationTrace, encode_tweak_chain},
    },
    util::{MaybeUninitField, MaybeUninitFieldSlice},
};
use core::{array::from_fn, iter::zip, mem::MaybeUninit};
use openvm_stark_backend::{
    p3_field::{Field, FieldAlgebra},
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};
use p3_poseidon2_util::air::{generate_trace_rows_for_perm, outputs};

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
    (traces.len() * TARGET_SUM as usize).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    epoch: u32,
    traces: &[VerificationTrace],
) -> RowMajorMatrix<F> {
    let height = trace_height(traces);
    let size = height * NUM_CHAIN_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_CHAIN_COLS);

    let (prefix, rows, suffix) =
        unsafe { trace.values.align_to_mut::<ChainCols<MaybeUninit<F>>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let (rows, padding_rows) = rows.split_at_mut(traces.len() * TARGET_SUM as usize);

    rows.par_chunks_mut(TARGET_SUM as usize)
        .zip(traces)
        .enumerate()
        .for_each(|(sig_idx, (rows, trace))| {
            let mut rows = rows.iter_mut();
            let mut sig_step = 0..;
            let mut sum = 0;
            let mut next_i = trace
                .x
                .iter()
                .enumerate()
                .filter(|(_, x_i)| **x_i != (1 << CHUNK_SIZE) - 1)
                .map(|(i, _)| i as u16)
                .skip(1)
                .chain([NUM_CHUNKS as u16]);
            zip(0.., zip(trace.sig.one_time_sig, trace.x)).for_each(
                |(i, (one_time_sig_i, x_i))| {
                    sum += x_i;
                    let i_diff = (x_i != (1 << CHUNK_SIZE) - 1)
                        .then(|| next_i.next().unwrap() - i)
                        .unwrap_or_default();
                    zip(x_i..(1 << CHUNK_SIZE) - 1, rows.by_ref()).fold(
                        one_time_sig_i,
                        |value, (chain_step, row)| {
                            let sig_step = sig_step.next().unwrap();
                            row.is_active.populate(true);
                            row.sig_idx.write_usize(sig_idx);
                            row.sig_step.write_u16(sig_step);
                            row.is_last_sig_row.populate(
                                F::from_canonical_u16(sig_step),
                                F::from_canonical_u16(TARGET_SUM - 1),
                            );
                            row.chain_idx.write_u16(i);
                            row.chain_idx_is_zero.populate(F::from_canonical_u16(i));
                            row.chain_idx_diff_bits.fill_from_iter(
                                (0..MAX_CHAIN_STEP_DIFF_BITS)
                                    .map(|idx| F::from_bool((i_diff >> idx) & 1 == 1)),
                            );
                            row.chain_idx_diff_inv.write_f(match i_diff {
                                1 => F::ONE,
                                2 => F::ONE.halve(),
                                _ => F::from_canonical_u16(i_diff).inverse(),
                            });
                            row.chain_step_bits.fill_from_iter(
                                (0..CHUNK_SIZE)
                                    .map(|idx| F::from_bool((chain_step >> idx) & 1 == 1)),
                            );
                            row.is_receiving_chain.write_bool(chain_step == x_i);
                            row.sum.write_u16(sum);
                            let encoded_tweak = encode_tweak_chain(epoch, i, chain_step + 1);
                            let input = concat_array![trace.pk.parameter, encoded_tweak, value];
                            generate_trace_rows_for_perm::<
                                F,
                                GenericPoseidon2LinearLayersHorizon<WIDTH>,
                                WIDTH,
                                SBOX_DEGREE,
                                SBOX_REGISTERS,
                                HALF_FULL_ROUNDS,
                                PARTIAL_ROUNDS,
                            >(&mut row.perm, input, &RC16);
                            unsafe { from_fn(|i| input[i] + outputs(&row.perm)[i].assume_init()) }
                        },
                    );
                },
            );
            assert!(rows.next().is_none());
        });

    padding_rows
        .par_iter_mut()
        .for_each(generate_trace_row_padding);

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_CHAIN_COLS)
}

#[inline]
pub fn generate_trace_row_padding(row: &mut ChainCols<MaybeUninit<F>>) {
    row.is_active.populate(false);
    row.sig_idx.write_zero();
    row.sig_step.write_zero();
    row.is_last_sig_row
        .populate(F::ZERO, F::from_canonical_u16(TARGET_SUM - 1));
    row.chain_idx.write_zero();
    row.chain_idx_is_zero.populate(F::ZERO);
    row.chain_idx_diff_bits.fill_zero();
    row.chain_idx_diff_inv.write_zero();
    row.chain_step_bits.fill_zero();
    row.is_receiving_chain.write_zero();
    row.sum.write_zero();
    generate_trace_rows_for_perm::<
        F,
        GenericPoseidon2LinearLayersHorizon<WIDTH>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(&mut row.perm, Default::default(), &RC16);
}
