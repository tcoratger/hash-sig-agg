use crate::{
    poseidon2::{
        F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC24, SBOX_DEGREE,
        SBOX_REGISTERS,
        chip::poseidon2_t24::{
            PARTIAL_ROUNDS, WIDTH,
            column::{NUM_POSEIDON2_T24_COLS, Poseidon2T24Cols},
        },
        concat_array,
        hash_sig::{
            CHUNK_SIZE, LOG_LIFETIME, MSG_FE_LEN, SPONGE_CAPACITY_VALUES, SPONGE_PERM, SPONGE_RATE,
            TH_HASH_FE_LEN, VerificationTrace, encode_tweak_merkle_tree,
        },
    },
    util::{MaybeUninitField, MaybeUninitFieldSlice},
};
use core::{
    array::from_fn,
    iter::{self, zip},
};
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};
use p3_poseidon2_util::air::{generate_trace_rows_for_perm, outputs};
use std::mem::MaybeUninit;

const MERKLE_ROWS: usize = SPONGE_PERM + LOG_LIFETIME;

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
    (traces.len() * (MERKLE_ROWS + 1)).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    epoch: u32,
    encoded_msg: [F; MSG_FE_LEN],
    traces: &[VerificationTrace],
) -> RowMajorMatrix<F> {
    let height = trace_height(traces);
    let size = height * NUM_POSEIDON2_T24_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_POSEIDON2_T24_COLS);

    let (prefix, rows, suffix) = unsafe {
        trace
            .values
            .align_to_mut::<Poseidon2T24Cols<MaybeUninit<F>>>()
    };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let (merkle_rows, msg_hash_rows) = rows.split_at_mut(traces.len() * MERKLE_ROWS);

    join(
        || {
            merkle_rows
                .par_chunks_mut(MERKLE_ROWS)
                .zip(traces)
                .enumerate()
                .for_each(|(sig_idx, (rows, trace))| {
                    let input = from_fn(|i| {
                        i.checked_sub(SPONGE_RATE)
                            .map(|i| SPONGE_CAPACITY_VALUES[i])
                            .unwrap_or_default()
                    });
                    let mut is_receive_merkle_tree = iter::empty()
                        .chain([true])
                        .chain(trace.x.iter().map(|x_i| *x_i != (1 << CHUNK_SIZE) - 1))
                        .chain([false]);
                    let (leaf_rows, path_rows) = rows.split_at_mut(SPONGE_PERM);
                    let output = leaf_rows
                        .iter_mut()
                        .zip(trace.merkle_tree_leaf(epoch).chunks(SPONGE_RATE))
                        .enumerate()
                        .fold(input, |mut input, (sponge_step, (row, sponge_block))| {
                            zip(&mut input, sponge_block)
                                .for_each(|(input, block)| *input += *block);
                            row.sig_idx.write_usize(sig_idx);
                            row.is_msg.write_zero();
                            row.is_merkle_leaf.write_one();
                            row.is_merkle_leaf_transition
                                .write_bool(sponge_step != SPONGE_PERM - 1);
                            if (sponge_step * SPONGE_RATE) % TH_HASH_FE_LEN == 0 {
                                row.is_recevie_merkle_tree.fill_from_iter(
                                    is_receive_merkle_tree.by_ref().take(3).map(F::from_bool),
                                );
                            } else {
                                row.is_recevie_merkle_tree[0].write_zero();
                                row.is_recevie_merkle_tree[1..].fill_from_iter(
                                    is_receive_merkle_tree.by_ref().take(2).map(F::from_bool),
                                );
                            }
                            row.is_merkle_path.write_zero();
                            row.is_merkle_path_transition.write_zero();
                            row.root.fill_from_slice(&trace.pk.merkle_root);
                            row.sponge_step.write_usize(sponge_step);
                            row.is_last_sponge_step.populate(
                                F::from_canonical_usize(sponge_step),
                                F::from_canonical_usize(SPONGE_PERM - 1),
                            );
                            row.sponge_block[..sponge_block.len()].fill_from_slice(sponge_block);
                            row.sponge_block[sponge_block.len()..].fill_zero();
                            row.leaf_chunk_start_ind
                                .fill_from_iter((0..SPONGE_RATE).map(|idx| {
                                    F::from_bool(
                                        (sponge_step * SPONGE_RATE + idx) % TH_HASH_FE_LEN == 0,
                                    )
                                }));
                            row.leaf_chunk_idx
                                .write_usize((sponge_step * SPONGE_RATE).div_ceil(TH_HASH_FE_LEN));
                            row.level.write_zero();
                            row.is_last_level
                                .populate(F::ZERO, F::from_canonical_usize(LOG_LIFETIME - 1));
                            row.epoch_dec.write_zero();
                            row.is_right.write_zero();
                            generate_trace_rows_for_perm::<
                                F,
                                GenericPoseidon2LinearLayersHorizon<WIDTH>,
                                WIDTH,
                                SBOX_DEGREE,
                                SBOX_REGISTERS,
                                HALF_FULL_ROUNDS,
                                PARTIAL_ROUNDS,
                            >(&mut row.perm, input, &RC24);
                            unsafe { from_fn(|i| outputs(&row.perm)[i].assume_init()) }
                        });
                    let mut epoch_dec = epoch;
                    zip(path_rows, trace.sig.merkle_siblings).enumerate().fold(
                        from_fn(|i| output[i]),
                        |node, (level, (row, sibling))| {
                            let is_right = epoch_dec & 1 == 1;
                            row.sig_idx.write_usize(sig_idx);
                            row.is_msg.write_zero();
                            row.is_merkle_leaf.write_zero();
                            row.is_merkle_leaf_transition.write_zero();
                            row.is_merkle_path.write_one();
                            row.is_merkle_path_transition
                                .write_bool(level != LOG_LIFETIME - 1);
                            row.is_recevie_merkle_tree.fill_zero();
                            row.root.fill_from_slice(&trace.pk.merkle_root);
                            row.sponge_step.write_zero();
                            row.is_last_sponge_step
                                .populate(F::ZERO, F::from_canonical_usize(SPONGE_PERM - 1));
                            row.sponge_block.fill_zero();
                            row.leaf_chunk_start_ind.fill_zero();
                            row.leaf_chunk_idx.write_zero();
                            row.level.write_usize(level);
                            row.is_last_level.populate(
                                F::from_canonical_usize(level),
                                F::from_canonical_usize(LOG_LIFETIME - 1),
                            );
                            row.epoch_dec.write_u32(epoch_dec);
                            row.is_right.write_bool(is_right);
                            let mut left_right = [node, sibling];
                            if is_right {
                                left_right.swap(0, 1);
                            }
                            let input = concat_array![
                                trace.pk.parameter,
                                encode_tweak_merkle_tree(level as u32 + 1, epoch_dec >> 1),
                                if is_right {
                                    [sibling, node].into_iter().flatten()
                                } else {
                                    [node, sibling].into_iter().flatten()
                                }
                            ];
                            generate_trace_rows_for_perm::<
                                F,
                                GenericPoseidon2LinearLayersHorizon<WIDTH>,
                                WIDTH,
                                SBOX_DEGREE,
                                SBOX_REGISTERS,
                                HALF_FULL_ROUNDS,
                                PARTIAL_ROUNDS,
                            >(&mut row.perm, input, &RC24);
                            epoch_dec >>= 1;
                            unsafe { from_fn(|i| input[i] + outputs(&row.perm)[i].assume_init()) }
                        },
                    );
                })
        },
        || {
            msg_hash_rows
                .par_iter_mut()
                .enumerate()
                .for_each(|(sig_idx, row)| {
                    row.sig_idx.write_usize(
                        (sig_idx < traces.len())
                            .then_some(sig_idx)
                            .unwrap_or_default(),
                    );
                    row.is_msg.write_bool(traces.get(sig_idx).is_some());
                    row.is_merkle_leaf.write_zero();
                    row.is_merkle_leaf_transition.write_zero();
                    row.is_merkle_path.write_zero();
                    row.is_merkle_path_transition.write_zero();
                    row.is_recevie_merkle_tree.fill_zero();
                    row.root.fill_zero();
                    row.sponge_step.write_zero();
                    row.is_last_sponge_step
                        .populate(F::ZERO, F::from_canonical_usize(SPONGE_PERM - 1));
                    row.sponge_block.fill_zero();
                    row.leaf_chunk_start_ind.fill_zero();
                    row.leaf_chunk_idx.write_zero();
                    row.level.write_zero();
                    row.is_last_level
                        .populate(F::ZERO, F::from_canonical_usize(LOG_LIFETIME - 1));
                    row.epoch_dec.write_zero();
                    row.is_right.write_zero();
                    let input = traces
                        .get(sig_idx)
                        .map(|trace| trace.msg_hash_preimage(epoch, encoded_msg))
                        .unwrap_or_default();
                    generate_trace_rows_for_perm::<
                        F,
                        GenericPoseidon2LinearLayersHorizon<WIDTH>,
                        WIDTH,
                        SBOX_DEGREE,
                        SBOX_REGISTERS,
                        HALF_FULL_ROUNDS,
                        PARTIAL_ROUNDS,
                    >(&mut row.perm, input, &RC24);
                })
        },
    );

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_POSEIDON2_T24_COLS)
}
