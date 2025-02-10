use crate::poseidon2::{
    F,
    chip::{
        BUS_CHAIN, BUS_DECOMPOSITION, BUS_MSG_HASH,
        chain::GROUP_BITS,
        decomposition::LIMB_BITS,
        main::column::{MainCols, NUM_MAIN_COLS},
    },
};
use core::{borrow::Borrow, iter};
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
        let main = builder.main();

        let local = main.row_slice(0);
        let local: &MainCols<AB::Var> = (*local).borrow();

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
                .chain(
                    local
                        .msg_hash_limbs
                        .chunks(GROUP_BITS / LIMB_BITS)
                        .map(|x| {
                            x.iter().rfold(AB::Expr::ZERO, |acc, x_i| {
                                acc * AB::Expr::from_canonical_u32(1 << LIMB_BITS) + (*x_i).into()
                            })
                        }),
                ),
            local.is_active,
        );
        builder.push_send(
            BUS_DECOMPOSITION,
            iter::empty()
                .chain(local.msg_hash.into_iter().rev())
                .chain(local.msg_hash_limbs),
            local.is_active,
        );
    }
}
