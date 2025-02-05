use crate::poseidon2::{F, chip::decomposition::column::NUM_DECOMPOSITION_COLS};
use openvm_stark_backend::{p3_field::FieldAlgebra, p3_matrix::dense::RowMajorMatrix};

pub fn trace_height(msg_hash_inputs: &[[F; 5]], tweak_inputs: &[[F; 2]]) -> usize {
    (5 * msg_hash_inputs.len() + 2 * tweak_inputs.len()).next_power_of_two()
}

pub fn generate_trace_rows(
    extra_capacity_bits: usize,
    msg_hash_inputs: Vec<[F; 5]>,
    tweak_inputs: Vec<[F; 2]>,
) -> RowMajorMatrix<F> {
    let height = trace_height(&msg_hash_inputs, &tweak_inputs);
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
