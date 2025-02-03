use crate::poseidon2::{
    F,
    chip::merkle_tree::column::{MerkleTreeCols, NUM_MERKLE_TREE_COLS},
    concat_array,
    hash_sig::{
        LOG_LIFETIME, PARAM_FE_LEN, TH_HASH_FE_LEN, encode_tweak_merkle_tree, poseidon2_compress,
    },
};
use core::{iter::zip, mem::MaybeUninit};
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
};
use rayon::{
    iter::{IndexedParallelIterator, ParallelIterator},
    slice::ParallelSliceMut,
};

pub fn trace_height(
    inputs: &[(
        [F; PARAM_FE_LEN],
        [F; TH_HASH_FE_LEN],
        [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
    )],
) -> usize {
    (inputs.len() * LOG_LIFETIME).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    epoch: u32,
    inputs: Vec<(
        [F; PARAM_FE_LEN],
        [F; TH_HASH_FE_LEN],
        [[F; TH_HASH_FE_LEN]; LOG_LIFETIME],
    )>,
) -> RowMajorMatrix<F> {
    let height = trace_height(&inputs);
    let size = height * NUM_MERKLE_TREE_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_MERKLE_TREE_COLS);

    let (prefix, rows, suffix) = unsafe {
        trace
            .values
            .align_to_mut::<MerkleTreeCols<MaybeUninit<F>>>()
    };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    rows.par_chunks_mut(LOG_LIFETIME)
        .enumerate()
        .for_each(|(idx, rows)| {
            if let Some((parameter, leaf, siblings)) = inputs.get(idx) {
                let mut epoch_dec = epoch;
                zip(rows, siblings)
                    .enumerate()
                    .fold(*leaf, |node, (level, (row, sibling))| {
                        let mut input = [node, *sibling];
                        let is_right = epoch_dec & 1 == 1;
                        if is_right {
                            input.swap(0, 1);
                        }
                        let output = poseidon2_compress::<24, 21, TH_HASH_FE_LEN>(concat_array![
                            *parameter,
                            encode_tweak_merkle_tree(level as u32 + 1, epoch_dec >> 1),
                            input[0],
                            input[1]
                        ]);
                        row.level.write(F::from_canonical_usize(level));
                        row.is_last_level.populate(
                            F::from_canonical_usize(level),
                            F::from_canonical_usize(LOG_LIFETIME - 1),
                        );
                        row.epoch_dec.write(F::from_canonical_u32(epoch_dec));
                        row.is_right.write(F::from_bool(is_right));
                        zip(
                            [
                                &mut row.leaf,
                                &mut row.left,
                                &mut row.right,
                                &mut row.output,
                            ],
                            [*leaf, input[0], input[1], output],
                        )
                        .for_each(|(cells, values)| {
                            zip(cells, values).for_each(|(cell, value)| {
                                cell.write(value);
                            });
                        });
                        row.is_active.write(F::ONE);
                        epoch_dec >>= 1;
                        output
                    });
            } else {
                let mut epoch_dec = epoch;
                rows.iter_mut().enumerate().for_each(|(level, row)| {
                    let is_right = epoch_dec & 1 == 1;
                    row.level.write(F::from_canonical_usize(level));
                    row.is_last_level.populate(
                        F::from_canonical_usize(level),
                        F::from_canonical_usize(LOG_LIFETIME - 1),
                    );
                    row.epoch_dec.write(F::from_canonical_u32(epoch_dec));
                    row.is_right.write(F::from_bool(is_right));
                    [
                        &mut row.leaf,
                        &mut row.left,
                        &mut row.right,
                        &mut row.output,
                    ]
                    .iter_mut()
                    .for_each(|cells| {
                        cells.iter_mut().for_each(|cell| {
                            cell.write(F::ZERO);
                        });
                    });
                    row.is_active.write(F::ZERO);
                    epoch_dec >>= 1;
                });
            }
        });

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_MERKLE_TREE_COLS)
}
