use crate::poseidon2::{
    F,
    chip::{
        BUS_CHAIN, BUS_DECOMPOSITION, BUS_MSG_HASH,
        chain::GROUP_SIZE,
        main::column::{MainCols, NUM_MAIN_COLS},
    },
    hash_sig::{CHUNK_SIZE, TARGET_SUM},
};
use core::{
    borrow::Borrow,
    iter::{self, Sum},
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

impl BaseAirWithPublicValues<F> for MainAir {}

impl<AB> Air<AB> for MainAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        // TODO:
        // 1. Decompose `msg_hash` to `x`.
        // 2. Make sure all `x_i` in `x` are in range `0..1 << CHUNK_SIZE`.

        let main = builder.main();

        let local = main.row_slice(0);
        let local: &MainCols<AB::Var> = (*local).borrow();

        builder.assert_eq(
            F::from_canonical_u16(TARGET_SUM),
            AB::Expr::sum(local.x.iter().copied().map(Into::into)),
        );

        builder.push_send(
            BUS_MSG_HASH,
            iter::empty().chain(local.parameter).chain(local.msg_hash),
            local.is_active,
        );
        builder.push_send(
            BUS_CHAIN,
            iter::empty()
                .chain(local.parameter.map(Into::into))
                .chain(local.merkle_root.map(Into::into))
                .chain(local.x.chunks(GROUP_SIZE).map(|x| {
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
        builder.push_send(
            BUS_DECOMPOSITION,
            iter::empty().chain(local.msg_hash.map(Into::into)).chain(
                local.x.chunks(8 / CHUNK_SIZE).map(|chunk| {
                    chunk.iter().rfold(AB::Expr::ZERO, |acc, x_i| {
                        acc * AB::Expr::from_canonical_u32(1 << CHUNK_SIZE) + (*x_i).into()
                    })
                }),
            ),
            local.is_active,
        );
    }
}
