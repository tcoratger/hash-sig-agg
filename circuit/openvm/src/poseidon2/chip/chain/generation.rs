use crate::poseidon2::{
    F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC16, SBOX_DEGREE, SBOX_REGISTERS,
    chip::chain::{
        GROUP_SIZE, NUM_GROUPS,
        column::{ChainCols, NUM_CHAIN_COLS},
        poseidon2::{PARTIAL_ROUNDS, WIDTH},
    },
    concat_array,
    hash_sig::{
        CHUNK_SIZE, PARAM_FE_LEN, SPONGE_RATE, TARGET_SUM, TH_HASH_FE_LEN, TWEAK_FE_LEN,
        VerificationTrace, encode_tweak_chain, encode_tweak_merkle_tree,
    },
};
use core::{array::from_fn, iter::zip};
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::{iter::repeat, prelude::*},
};
use p3_poseidon2_util::air::generate_trace_rows_for_perm;

fn input_rows(traces: &[VerificationTrace]) -> impl Iterator<Item = usize> {
    traces.iter().map(|trace| {
        TARGET_SUM as usize
            + trace
                .x
                .iter()
                .filter(|x_i| **x_i == (1 << CHUNK_SIZE) - 1)
                .count()
    })
}

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
    input_rows(traces).sum::<usize>().next_power_of_two()
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

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<ChainCols<_>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let mut iter = rows.iter_mut();
    let mut chunks = input_rows(traces)
        .map(|n| iter.by_ref().take(n).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    chunks.extend(
        iter.as_mut_slice()
            .chunks_mut(TARGET_SUM as usize)
            .map(|rows| rows.iter_mut().collect()),
    );

    let dummy = Default::default();
    let dummys = repeat(&dummy).take(chunks.len() - traces.len());
    chunks
        .into_par_iter()
        .zip(traces.into_par_iter().chain(dummys))
        .for_each(|(mut rows, trace)| {
            let mut rows = rows.iter_mut();
            let mut group_acc = [0u32; NUM_GROUPS];
            let mut leaf_block_step = 0;
            let mut leaf_block_and_buf: [F; SPONGE_RATE + TH_HASH_FE_LEN - 1] =
                concat_array![trace.pk.parameter, encode_tweak_merkle_tree(0, epoch)];
            let mut leaf_block_ptr = PARAM_FE_LEN + TWEAK_FE_LEN;
            zip(0.., zip(trace.sig.one_time_sig, trace.x)).for_each(
                |(i, (one_time_sig_i, x_i))| {
                    let group_idx = i as usize / GROUP_SIZE;
                    let group_step = i as usize % GROUP_SIZE;
                    let is_last_group_step = group_step == GROUP_SIZE - 1;
                    group_acc[group_idx] = (group_acc[group_idx] << CHUNK_SIZE) + x_i as u32;
                    zip(
                        x_i..(1 << CHUNK_SIZE) - (x_i != (1 << CHUNK_SIZE) - 1) as u16,
                        rows.by_ref(),
                    )
                    .fold(one_time_sig_i, |value, (chain_step, row)| {
                        let encoded_tweak = encode_tweak_chain(epoch, i, chain_step + 1);
                        let input = concat_array![trace.pk.parameter, encoded_tweak, value];
                        let is_last_chain_step = (chain_step >> 1) & 1 == 1;
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
                                cell.write(F::from_bool(idx == group_idx));
                            });
                        zip(&mut row.group_acc, group_acc).for_each(|(cell, value)| {
                            cell.write(F::from_canonical_u32(value));
                        });
                        row.group_step.write(F::from_canonical_usize(group_step));
                        row.is_first_group_step
                            .populate(F::from_canonical_usize(group_step));
                        row.is_last_group_step.populate(
                            F::from_canonical_usize(group_step),
                            F::from_canonical_usize(GROUP_SIZE - 1),
                        );
                        row.chain_step_bits
                            .iter_mut()
                            .enumerate()
                            .for_each(|(idx, cell)| {
                                cell.write(F::from_bool((chain_step >> idx) & 1 == 1));
                            });
                        row.is_last_group_row
                            .write(F::from_bool(is_last_chain_step && is_last_group_step));
                        row.is_last_sig_row.write(F::from_bool(
                            is_last_chain_step && is_last_group_step && group_idx == NUM_GROUPS - 1,
                        ));
                        zip(&mut row.merkle_root, trace.pk.merkle_root).for_each(
                            |(cell, value)| {
                                cell.write(value);
                            },
                        );
                        let output = if chain_step == (1 << CHUNK_SIZE) - 1 {
                            value
                        } else {
                            from_fn(|i| unsafe {
                                input[i]
                                    + row.perm.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i]
                                        .assume_init()
                            })
                        };
                        if is_last_chain_step {
                            leaf_block_and_buf[leaf_block_ptr..leaf_block_ptr + TH_HASH_FE_LEN]
                                .copy_from_slice(&output);
                            leaf_block_ptr = (leaf_block_ptr + TH_HASH_FE_LEN) % SPONGE_RATE;
                        }
                        if is_last_chain_step && leaf_block_ptr < TH_HASH_FE_LEN {
                            leaf_block_step += 1;
                            leaf_block_and_buf
                                .copy_within(SPONGE_RATE..SPONGE_RATE + leaf_block_ptr, 0);
                            leaf_block_and_buf[leaf_block_ptr..]
                                .iter_mut()
                                .for_each(|v| *v = F::ZERO);
                        }
                        row.is_active.write(F::from_bool(
                            trace.pk.merkle_root != [F::ZERO; TH_HASH_FE_LEN],
                        ));
                        output
                    });
                },
            );
            assert!(rows.next().is_none());
        });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_CHAIN_COLS)
}
