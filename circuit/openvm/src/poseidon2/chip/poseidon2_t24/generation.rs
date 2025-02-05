use crate::poseidon2::{
    F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC24, SBOX_DEGREE, SBOX_REGISTERS,
    chip::poseidon2_t24::{
        PARTIAL_ROUNDS, WIDTH,
        column::{NUM_POSEIDON2_T24_COLS, Poseidon2T24Cols},
    },
    hash_sig::{
        SPONGE_CAPACITY_VALUES, SPONGE_INPUT_SIZE, SPONGE_PERM, SPONGE_RATE, poseidon2_sponge,
    },
};
use core::{
    array::from_fn,
    iter::{repeat, zip},
};
use openvm_stark_backend::{
    p3_field::FieldAlgebra,
    p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut},
    p3_maybe_rayon::prelude::*,
};
use p3_poseidon2_util::air::generate_trace_rows_for_perm;

pub fn trace_height(
    compress_inputs: &[[F; 22]],
    sponge_inputs: &[[F; SPONGE_INPUT_SIZE]],
) -> usize {
    (compress_inputs.len() + sponge_inputs.len() * SPONGE_PERM).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    compress_inputs: Vec<[F; 22]>,
    sponge_inputs: Vec<[F; SPONGE_INPUT_SIZE]>,
) -> RowMajorMatrix<F> {
    let height = trace_height(&compress_inputs, &sponge_inputs);
    let size = height * NUM_POSEIDON2_T24_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    let trace = &mut vec.spare_capacity_mut()[..size];
    let trace = RowMajorMatrixViewMut::new(trace, NUM_POSEIDON2_T24_COLS);

    let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<Poseidon2T24Cols<_>>() };
    assert!(prefix.is_empty(), "Alignment should match");
    assert!(suffix.is_empty(), "Alignment should match");
    assert_eq!(rows.len(), height);

    let (compress_rows, sponge_rows) =
        rows.split_at_mut(height - sponge_inputs.len() * SPONGE_PERM);
    rayon::join(
        || {
            compress_rows
                .par_iter_mut()
                .enumerate()
                .for_each(|(idx, row)| {
                    let input = compress_inputs
                        .get(idx)
                        .map(|compress_input| {
                            from_fn(|i| compress_input.get(i).copied().unwrap_or_default())
                        })
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
                    row.is_compress.write(F::ONE);
                    row.mult
                        .write(F::from_bool(compress_inputs.get(idx).is_some()));
                })
        },
        || {
            sponge_rows
                .par_chunks_mut(SPONGE_PERM)
                .zip(sponge_inputs)
                .for_each(|(rows, sponge_input)| {
                    let sponge_output = poseidon2_sponge(sponge_input);
                    let mut input = from_fn(|i| {
                        i.checked_sub(SPONGE_RATE)
                            .map(|i| SPONGE_CAPACITY_VALUES[i])
                            .unwrap_or_default()
                    });
                    rows.iter_mut()
                        .zip(sponge_input.chunks(SPONGE_RATE))
                        .enumerate()
                        .for_each(|(sponge_block_step, (row, sponge_block))| {
                            row.sponge_block_step
                                .write(F::from_canonical_usize(sponge_block_step));
                            row.is_last_sponge_step.populate(
                                F::from_canonical_usize(sponge_block_step),
                                F::from_canonical_usize(SPONGE_PERM - 1),
                            );
                            zip(
                                &mut input,
                                zip(
                                    &mut row.sponge_block,
                                    sponge_block.iter().chain(repeat(&F::ZERO)),
                                ),
                            )
                            .for_each(|(state, (cell, value))| {
                                cell.write(*value);
                                *state += *value;
                            });
                            zip(&mut row.sponge_output, sponge_output).for_each(|(cell, value)| {
                                cell.write(value);
                            });
                            generate_trace_rows_for_perm::<
                                F,
                                GenericPoseidon2LinearLayersHorizon<WIDTH>,
                                WIDTH,
                                SBOX_DEGREE,
                                SBOX_REGISTERS,
                                HALF_FULL_ROUNDS,
                                PARTIAL_ROUNDS,
                            >(&mut row.perm, input, &RC24);
                            row.is_compress.write(F::ZERO);
                            row.mult.write(F::ONE);
                            input = from_fn(|i| unsafe {
                                row.perm.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i]
                                    .assume_init()
                            })
                        });
                })
        },
    );

    unsafe { vec.set_len(size) };

    RowMajorMatrix::new(vec, NUM_POSEIDON2_T24_COLS)
}
