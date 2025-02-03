use crate::poseidon2::{
    F,
    chip::{
        BUS_CHAIN, BUS_POSEIDON2_T24_COMPRESS,
        main::column::{MainCols, NUM_MAIN_COLS},
    },
    hash_sig::{CHUNK_SIZE, MSG_FE_LEN, TARGET_SUM, TWEAK_FE_LEN},
};
use core::{
    array::from_fn,
    borrow::Borrow,
    iter::{self, Sum, repeat},
};
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilderWithPublicValues, BaseAir},
    p3_field::FieldAlgebra,
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};

#[derive(Clone, Copy)]
pub struct MainAir;

impl BaseAir<F> for MainAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }
}

impl PartitionedBaseAir<F> for MainAir {}

impl BaseAirWithPublicValues<F> for MainAir {
    fn num_public_values(&self) -> usize {
        TWEAK_FE_LEN + MSG_FE_LEN
    }
}

impl<AB> Air<AB> for MainAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let encoded_tweak: [_; 2] = from_fn(|i| builder.public_values()[i]);
        let encoded_msg: [_; 9] = from_fn(|i| builder.public_values()[2 + i]);
        let local = main.row_slice(0);
        let local: &MainCols<AB::Var> = (*local).borrow();

        // TODO:
        // 1. Decompose `msg_hash` to `x`.
        // 2. Make sure all `x_i` in `x` are in range `0..1 << CHUNK_SIZE`.

        builder.assert_eq(
            F::from_canonical_u16(TARGET_SUM),
            AB::Expr::sum(local.x.iter().copied().map(Into::into)),
        );

        builder.push_send(
            BUS_POSEIDON2_T24_COMPRESS,
            iter::empty()
                .chain(
                    iter::empty()
                        .chain(local.rho.map(Into::into))
                        .chain(encoded_tweak.map(Into::into))
                        .chain(encoded_msg.map(Into::into))
                        .chain(local.parameter.map(Into::into))
                        .chain(repeat(AB::Expr::ZERO))
                        .take(24),
                )
                .chain(
                    iter::empty()
                        .chain(local.msg_hash.map(Into::into))
                        .chain(local.msg_hash_aux.map(Into::into)),
                ),
            local.is_active,
        );
        builder.push_send(
            BUS_CHAIN,
            iter::empty()
                .chain(local.parameter.map(Into::into))
                .chain(local.x.chunks(13).map(|x| {
                    x.iter()
                        .copied()
                        .map(Into::into)
                        .reduce(|acc, x_i| {
                            acc * AB::Expr::from_canonical_u32(1 << CHUNK_SIZE) + x_i
                        })
                        .unwrap()
                })),
            local.is_active,
        );
    }
}
