use crate::poseidon2::{
    F,
    chip::{
        BUS_DECOMPOSITION,
        decomposition::column::{DecompositionCols, NUM_DECOMPOSITION_COLS},
    },
};
use core::{borrow::Borrow, iter};
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilderWithPublicValues, BaseAir},
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};

#[derive(Clone, Copy)]
pub struct DecompositionAir;

impl BaseAir<F> for DecompositionAir {
    fn width(&self) -> usize {
        NUM_DECOMPOSITION_COLS
    }
}

impl PartitionedBaseAir<F> for DecompositionAir {}

impl BaseAirWithPublicValues<F> for DecompositionAir {}

impl<AB> Air<AB> for DecompositionAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        // let next = main.row_slice(1);
        let local: &DecompositionCols<AB::Var> = (*local).borrow();
        // let next: &DecompositionCols<AB::Var> = (*next).borrow();

        builder.push_receive(
            BUS_DECOMPOSITION,
            iter::empty().chain(local.values).chain(local.acc_bytes),
            local.mult,
        );
    }
}
