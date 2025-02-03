use crate::poseidon2::{
    F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC24, SBOX_DEGREE, SBOX_REGISTERS,
    chip::{
        BUS_POSEIDON2_T24_COMPRESS,
        poseidon2_t24::{
            PARTIAL_ROUNDS, WIDTH,
            column::{NUM_POSEIDON2_T24_COLS, Poseidon2T24Cols},
        },
    },
};
use core::{
    borrow::Borrow,
    iter::{self},
};
use openvm_stark_backend::{
    air_builders::sub::SubAirBuilder,
    interaction::InteractionBuilder,
    p3_air::{Air, BaseAir},
    p3_field::FieldAlgebra,
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_poseidon2_air::{Poseidon2Air, num_cols};

pub struct Poseidon2T24Air(
    Poseidon2Air<
        F,
        GenericPoseidon2LinearLayersHorizon<WIDTH>,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
);

impl Default for Poseidon2T24Air {
    fn default() -> Self {
        Self(Poseidon2Air::new(RC24.into()))
    }
}

impl BaseAir<F> for Poseidon2T24Air {
    fn width(&self) -> usize {
        NUM_POSEIDON2_T24_COLS
    }
}

impl PartitionedBaseAir<F> for Poseidon2T24Air {}

impl BaseAirWithPublicValues<F> for Poseidon2T24Air {}

impl<AB> Air<AB> for Poseidon2T24Air
where
    AB: InteractionBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        self.0.eval(&mut SubAirBuilder::<
            _,
            Poseidon2Air<
                F,
                GenericPoseidon2LinearLayersHorizon<WIDTH>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
            _,
        >::new(
            builder,
            0..num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(),
        ));

        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2T24Cols<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_compress);
        let _is_sponge = AB::Expr::ONE - local.is_compress.into();

        builder.push_receive(
            BUS_POSEIDON2_T24_COMPRESS,
            iter::empty()
                .chain(local.perm.inputs.map(Into::into))
                .chain(local.compress_output::<AB>()),
            local.mult * local.is_compress.into(),
        );
    }
}
