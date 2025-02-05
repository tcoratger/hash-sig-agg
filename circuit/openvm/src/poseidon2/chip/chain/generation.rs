use crate::poseidon2::{
    F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC16, SBOX_DEGREE, SBOX_REGISTERS,
    chip::chain::{
        column::{ChainCols, NUM_CHAIN_COLS},
        poseidon2::{PARTIAL_ROUNDS, WIDTH},
    },
    concat_array,
    hash_sig::{
        CHUNK_SIZE, NUM_CHUNKS, PARAM_FE_LEN, PublicKey, SPONGE_INPUT_SIZE, SPONGE_RATE,
        TARGET_SUM, TH_HASH_FE_LEN, TWEAK_FE_LEN, chain, encode_tweak_chain,
        encode_tweak_merkle_tree, poseidon2_sponge,
    },
};
use core::{array::from_fn, iter::zip};
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::{iter::repeat, prelude::*},
};
use p3_poseidon2_util::air::generate_trace_rows_for_perm;

fn input_rows(
    inputs: &[(
        PublicKey,
        [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
        [u16; NUM_CHUNKS],
    )],
) -> impl Iterator<Item = usize> {
    inputs.iter().map(|input| {
        TARGET_SUM as usize
            + input
                .2
                .iter()
                .filter(|x_i| **x_i == (1 << CHUNK_SIZE) - 1)
                .count()
    })
}

pub fn trace_height(
    inputs: &[(
        PublicKey,
        [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
        [u16; NUM_CHUNKS],
    )],
) -> usize {
    input_rows(inputs).sum::<usize>().next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    epoch: u32,
    inputs: Vec<(
        PublicKey,
        [[F; TH_HASH_FE_LEN]; NUM_CHUNKS],
        [u16; NUM_CHUNKS],
    )>,
) -> RowMajorMatrix<F> {
    let height = trace_height(&inputs);
    let size = height * NUM_CHAIN_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_CHAIN_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<ChainCols<_>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let mut iter = rows.iter_mut();
    let mut chunks = input_rows(&inputs)
        .map(|n| iter.by_ref().take(n).collect::<Vec<_>>())
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
        .for_each(|(mut rows, (pk, one_time_sig, x))| {
            let leaf = poseidon2_sponge::<SPONGE_INPUT_SIZE>({
                let leaves = (0..NUM_CHUNKS)
                    .flat_map(|i| chain(epoch, pk.parameter, i as _, x[i], one_time_sig[i]));
                concat_array![pk.parameter, encode_tweak_merkle_tree(0, epoch), leaves]
            });
            let mut rows = rows.iter_mut();
            let mut group_acc = [0u32; 6];
            let mut sponge_block_step = 0;
            let mut sponge_block_and_buf: [F; SPONGE_RATE + TH_HASH_FE_LEN - 1] =
                concat_array![pk.parameter, encode_tweak_merkle_tree(0, epoch)];
            let mut sponge_block_ptr = PARAM_FE_LEN + TWEAK_FE_LEN;
            zip(0.., zip(one_time_sig, x)).for_each(|(i, (one_time_sig_i, x_i))| {
                let group_idx = i / 13;
                let group_step = i % 13;
                let is_last_group_step = group_step == 12;
                group_acc[group_idx as usize] =
                    (group_acc[group_idx as usize] << CHUNK_SIZE) + x_i as u32;
                zip(
                    x_i..(1 << CHUNK_SIZE) - (x_i != (1 << CHUNK_SIZE) - 1) as u16,
                    rows.by_ref(),
                )
                .fold(one_time_sig_i, |value, (chain_step, row)| {
                    let encoded_tweak = encode_tweak_chain(epoch, i, chain_step + 1);
                    let input = concat_array![pk.parameter, encoded_tweak, value];
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
                        .write(F::from_bool(is_last_chain_step && is_last_group_step));
                    row.is_sig_last_row.write(F::from_bool(
                        is_last_chain_step && is_last_group_step && group_idx == 5,
                    ));
                    row.is_active
                        .write(F::from_bool(pk.merkle_root != [F::ZERO; TH_HASH_FE_LEN]));
                    zip(&mut row.merkle_root, pk.merkle_root).for_each(|(cell, value)| {
                        cell.write(value);
                    });
                    zip(&mut row.leaf, leaf).for_each(|(cell, value)| {
                        cell.write(value);
                    });
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
                        sponge_block_and_buf[sponge_block_ptr..sponge_block_ptr + TH_HASH_FE_LEN]
                            .copy_from_slice(&output);
                        sponge_block_ptr = (sponge_block_ptr + TH_HASH_FE_LEN) % SPONGE_RATE;
                    }
                    row.sponge_block_step
                        .write(F::from_canonical_usize(sponge_block_step));
                    zip(&mut row.sponge_block_and_buf, sponge_block_and_buf).for_each(
                        |(cell, value)| {
                            cell.write(value);
                        },
                    );
                    row.sponge_block_ptr_ind
                        .iter_mut()
                        .enumerate()
                        .for_each(|(idx, cell)| {
                            cell.write(F::from_bool(idx == sponge_block_ptr));
                        });
                    if is_last_chain_step && sponge_block_ptr < TH_HASH_FE_LEN {
                        sponge_block_step += 1;
                        sponge_block_and_buf
                            .copy_within(SPONGE_RATE..SPONGE_RATE + sponge_block_ptr, 0);
                        sponge_block_and_buf[sponge_block_ptr..]
                            .iter_mut()
                            .for_each(|v| *v = F::ZERO);
                    }
                    output
                });
            });
            assert!(rows.next().is_none());
        });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_CHAIN_COLS)
}
