use crate::poseidon2::{
    F,
    chip::{
        BUS_DECOMPOSITION, BUS_MERKLE_TREE, BUS_MSG_HASH,
        main::column::{MainCols, NUM_MAIN_COLS},
    },
    hash_sig::TWEAK_FE_LEN,
};
use core::{array::from_fn, borrow::Borrow, iter};
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir},
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
        TWEAK_FE_LEN
    }
}

impl<AB> Air<AB> for MainAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let encoded_tweak_merkle_leaf: [_; TWEAK_FE_LEN] =
            from_fn(|i| builder.public_values()[i].into());

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &MainCols<AB::Var> = (*local).borrow();
        let next: &MainCols<AB::Var> = (*next).borrow();

        // When every rows
        eval_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(*local.is_active);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_transition(&mut builder, local, next);
        }

        // Interaction
        send_msg_hash(builder, local);
        send_merkle_tree(builder, encoded_tweak_merkle_leaf, local);
        send_decomposition(builder, local);
    }
}

#[inline]
fn eval_every_row<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    cols.is_active.eval_every_row(builder);
}

#[inline]
fn eval_transition<AB>(builder: &mut AB, local: &MainCols<AB::Var>, next: &MainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    local.is_active.eval_transition(builder, &next.is_active);
}

// TODO: Send parameter to chain to make sure they all use same parameter

// TODO: Send also merkle root
#[inline]
fn send_msg_hash<AB>(builder: &mut AB, cols: &MainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_send(
        BUS_MSG_HASH,
        iter::empty().chain(cols.parameter).chain(cols.msg_hash),
        *cols.is_active,
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
            .chain([cols.sig_idx])
            .chain(cols.msg_hash.into_iter().rev()),
        *cols.is_active,
    );
}

// TODO: Remove this
#[inline]
fn send_merkle_tree<AB>(
    builder: &mut AB,
    encoded_tweak_merkle_leaf: [AB::Expr; 2],
    cols: &MainCols<AB::Var>,
) where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    builder.push_send(
        BUS_MERKLE_TREE,
        iter::empty()
            .chain([cols.sig_idx.into(), AB::Expr::ZERO])
            .chain(cols.parameter.iter().copied().map(Into::into))
            .chain(encoded_tweak_merkle_leaf.map(Into::into)),
        *cols.is_active,
    );
}
