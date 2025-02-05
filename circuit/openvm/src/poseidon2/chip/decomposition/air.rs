use crate::poseidon2::{F, chip::decomposition::column::NUM_DECOMPOSITION_COLS};
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilderWithPublicValues, BaseAir},
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
    fn eval(&self, _builder: &mut AB) {}
}
