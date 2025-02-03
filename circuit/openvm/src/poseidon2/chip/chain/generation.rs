use crate::poseidon2::{
    F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC16, SBOX_DEGREE, SBOX_REGISTERS,
    chip::chain::{
        column::{ChainCols, NUM_CHAIN_COLS},
        poseidon2::{PARTIAL_ROUNDS, WIDTH},
    },
    concat_array,
    hash_sig::{
        CHUNK_SIZE, NUM_CHUNKS, PARAM_FE_LEN, TARGET_SUM, TH_HASH_FE_LEN, encode_tweak_chain,
    },
};
use core::{array::from_fn, iter::zip};
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::{iter::repeat, prelude::*},
};
use p3_poseidon2_util::air::generate_trace_rows_for_perm;

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    epoch: u32,
    inputs: Vec<(
        [F; PARAM_FE_LEN],
        [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
        [u16; NUM_CHUNKS],
    )>,
) -> RowMajorMatrix<F> {
    let input_extra_rows = inputs
        .iter()
        .map(|input| {
            input
                .2
                .iter()
                .filter(|x_i| **x_i == (1 << CHUNK_SIZE) - 1)
                .count()
        })
        .collect::<Vec<_>>();
    let height = (inputs.len() * TARGET_SUM as usize + input_extra_rows.iter().sum::<usize>())
        .next_power_of_two();
    let size = height * NUM_CHAIN_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_CHAIN_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<ChainCols<_>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let mut iter = rows.iter_mut();
    let mut chunks = input_extra_rows
        .iter()
        .map(|extra_rows| {
            iter.by_ref()
                .take(TARGET_SUM as usize + extra_rows)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    chunks.extend(
        iter.as_mut_slice()
            .chunks_mut(TARGET_SUM as usize)
            .map(|rows| rows.iter_mut().collect()),
    );

    let dummys = repeat((
        Default::default(),
        from_fn(|_| Default::default()),
        from_fn(|i| if i >= NUM_CHUNKS / 2 { 1 } else { 2 }),
    ))
    .take(chunks.len() - inputs.len());
    chunks
        .into_par_iter()
        .zip(inputs.into_par_iter().chain(dummys))
        .for_each(|(mut rows, (parameter, one_time_sig, x))| {
            let mut rows = rows.iter_mut();
            let mut group_acc = [0u32; 6];
            zip(0.., zip(one_time_sig, x)).for_each(|(i, (one_time_sig_i, x_i))| {
                let group_idx = i / 13;
                let group_step = i % 13;
                group_acc[group_idx as usize] =
                    (group_acc[group_idx as usize] << CHUNK_SIZE) + x_i as u32;
                zip(
                    x_i..(1 << CHUNK_SIZE) - (x_i != (1 << CHUNK_SIZE) - 1) as u16,
                    rows.by_ref(),
                )
                .fold(one_time_sig_i, |value, (chain_step, row)| {
                    let encoded_tweak_chain = encode_tweak_chain(epoch, i, chain_step + 1);
                    let input = concat_array![parameter, encoded_tweak_chain, value];
                    generate_trace_rows_for_perm::<
                        F,
                        GenericPoseidon2LinearLayersHorizon<WIDTH>,
                        WIDTH,
                        SBOX_DEGREE,
                        SBOX_REGISTERS,
                        HALF_FULL_ROUNDS,
                        PARTIAL_ROUNDS,
                    >(&mut row.perm, input, &RC16);
                    row.group_ind
                        .iter_mut()
                        .enumerate()
                        .for_each(|(idx, cell)| {
                            cell.write(F::from_bool(idx == group_idx as usize));
                        });
                    zip(&mut row.group_acc, group_acc).for_each(|(cell, value)| {
                        cell.write(F::from_canonical_u32(value));
                    });
                    row.group_step.write(F::from_canonical_u16(group_step));
                    row.is_group_first_step
                        .populate(F::from_canonical_u16(group_step));
                    row.is_group_last_step
                        .populate(F::from_canonical_u16(group_step), F::from_canonical_u8(12));
                    row.chain_step_bits
                        .iter_mut()
                        .enumerate()
                        .for_each(|(idx, cell)| {
                            cell.write(F::from_bool((chain_step >> idx) & 1 == 1));
                        });
                    row.is_group_last_row
                        .write(F::from_bool((chain_step >> 1) & 1 == 1 && group_step == 12));
                    row.is_sig_last_row.write(F::from_bool(
                        (chain_step >> 1) & 1 == 1 && group_step == 12 && group_idx == 5,
                    ));
                    row.mult.write(F::from_bool(
                        i == 77
                            && (chain_step >> 1) & 1 == 1
                            && group_step == 12
                            && parameter != [F::ZERO; PARAM_FE_LEN],
                    ));
                    zip(&mut row.encoded_tweak_chain, encoded_tweak_chain).for_each(
                        |(cell, value)| {
                            cell.write(value);
                        },
                    );
                    from_fn(|i| unsafe {
                        input[i]
                            + row.perm.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i]
                                .assume_init()
                    })
                });
            });
            assert!(rows.next().is_none());
        });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_CHAIN_COLS)
}
