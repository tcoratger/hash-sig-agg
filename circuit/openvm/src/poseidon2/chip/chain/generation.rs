use crate::{
    poseidon2::{
        F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC16, SBOX_DEGREE,
        SBOX_REGISTERS,
        chip::chain::{
            GROUP_SIZE, LAST_GROUP_SIZE, NUM_GROUPS,
            column::{ChainCols, NUM_CHAIN_COLS},
            poseidon2::{PARTIAL_ROUNDS, WIDTH},
        },
        concat_array,
        hash_sig::{
            CHUNK_SIZE, NUM_CHUNKS, TARGET_SUM, TH_HASH_FE_LEN, VerificationTrace,
            encode_tweak_chain,
        },
    },
    util::{MaybeUninitField, MaybeUninitFieldSlice},
};
use core::{array::from_fn, iter::zip};
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::{iter::repeat, prelude::*},
};
use p3_poseidon2_util::air::{generate_trace_rows_for_perm, outputs};

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
            let mut sum = 0;
            let mut group_acc = [0u32; NUM_GROUPS];
            zip(0.., zip(trace.sig.one_time_sig, trace.x)).for_each(
                |(i, (one_time_sig_i, x_i))| {
                    sum += x_i;
                    let is_mid_of_chain = x_i != (1 << CHUNK_SIZE) - 1;
                    let group_idx = i as usize / GROUP_SIZE;
                    let group_step = i as usize % GROUP_SIZE;
                    let is_last_group = group_idx == NUM_GROUPS - 1;
                    let is_last_group_step =
                        group_step == GROUP_SIZE - 1 || i as usize == NUM_CHUNKS - 1;
                    group_acc[group_idx] += (x_i as u32) << (group_step * CHUNK_SIZE);
                    zip(
                        x_i..(1 << CHUNK_SIZE) - is_mid_of_chain as u16,
                        rows.by_ref(),
                    )
                    .fold(one_time_sig_i, |value, (chain_step, row)| {
                        let encoded_tweak = encode_tweak_chain(epoch, i, chain_step + 1);
                        let is_last_chain_step = (chain_step >> 1) & 1 == 1;
                        row.group_ind.fill_from_iter(
                            (0..NUM_GROUPS).map(|idx| F::from_bool(idx == group_idx)),
                        );
                        row.group_acc
                            .fill_from_iter(group_acc.map(F::from_canonical_u32));
                        row.group_acc_scalar
                            .write_u32(1 << (group_step * CHUNK_SIZE));
                        row.group_acc_item
                            .write_u32((chain_step as u32) << (group_step * CHUNK_SIZE));
                        row.group_step.write_usize(group_step);
                        row.chain_step_bits.fill_from_iter(
                            (0..CHUNK_SIZE).map(|idx| F::from_bool((chain_step >> idx) & 1 == 1)),
                        );
                        row.sum.write_u16(sum);
                        row.is_first_group_step
                            .populate(F::from_canonical_usize(group_step));
                        row.is_last_group_step.populate(
                            F::from_canonical_usize(group_step),
                            F::from_canonical_usize(if is_last_group {
                                LAST_GROUP_SIZE - 1
                            } else {
                                GROUP_SIZE - 1
                            }),
                        );
                        row.is_last_group_row
                            .write_bool(is_last_chain_step && is_last_group_step);
                        row.is_last_sig_row
                            .write_bool(is_last_chain_step && is_last_group_step && is_last_group);
                        row.merkle_root.fill_from_slice(&trace.pk.merkle_root);
                        row.is_active
                            .write_bool(trace.pk.merkle_root != [F::ZERO; TH_HASH_FE_LEN]);
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
                    });
                },
            );
            assert!(rows.next().is_none());
        });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_CHAIN_COLS)
}
