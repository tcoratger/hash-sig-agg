use crate::poseidon2::{
    F,
    chip::decomposition::column::NUM_DECOMPOSITION_COLS,
    hash_sig::{CHUNK_SIZE, LOG_LIFETIME, NUM_CHUNKS, VerificationTrace},
};
use openvm_stark_backend::{p3_field::FieldAlgebra, p3_matrix::dense::RowMajorMatrix};

pub fn trace_height(traces: &[VerificationTrace]) -> usize {
    (5 * traces.len() + 2 * (NUM_CHUNKS * ((1 << CHUNK_SIZE) - 1) + LOG_LIFETIME + 1))
        .next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    _epoch: u32,
    traces: &[VerificationTrace],
) -> RowMajorMatrix<F> {
    let height = trace_height(traces);
    let size = height * NUM_DECOMPOSITION_COLS;
    let mut vec = Vec::with_capacity(size << extra_capacity_bits);
    // let trace = &mut vec.spare_capacity_mut()[..size];
    // let trace = RowMajorMatrixViewMut::new(trace, NUM_DECOMPOSITION_COLS);

    // let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<DecompositionCols<_>>() };
    // assert!(prefix.is_empty(), "Alignment should match");
    // assert!(suffix.is_empty(), "Alignment should match");
    // assert_eq!(rows.len(), height);

    // unsafe { vec.set_len(size) };
    vec.resize(size, F::ZERO);

    RowMajorMatrix::new(vec, NUM_DECOMPOSITION_COLS)
}
