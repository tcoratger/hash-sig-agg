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

        // Interaction
        send_msg_hash(builder, local);
        send_chain(builder, local);
        send_decomposition(builder, local);
    }
}

#[inline]
fn send_msg_hash<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        BUS_MSG_HASH,
        iter::empty().chain(cols.parameter).chain(cols.msg_hash),
        cols.is_active,
    );
}

#[inline]
fn send_chain<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        BUS_CHAIN,
        iter::empty()
            .chain(cols.parameter.map(Into::into))
            .chain(cols.merkle_root.map(Into::into))
            .chain(cols.msg_hash_limbs.chunks(GROUP_BITS / LIMB_BITS).map(|x| {
                x.iter().rfold(AB::Expr::ZERO, |acc, x_i| {
                    acc * AB::Expr::from_canonical_u32(1 << LIMB_BITS) + (*x_i).into()
                })
            })),
        cols.is_active,
    );
}

#[inline]
fn send_decomposition<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        BUS_DECOMPOSITION,
        iter::empty()
            .chain(cols.msg_hash.into_iter().rev())
            .chain(cols.msg_hash_limbs),
        cols.is_active,
    );
}
