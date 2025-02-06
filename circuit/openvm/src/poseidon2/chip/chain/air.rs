use crate::{
    gadget::{not, select},
    poseidon2::{
        F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::{
            BUS_CHAIN, BUS_MERKLE_TREE,
            chain::{
                GROUP_SIZE,
                column::{ChainCols, NUM_CHAIN_COLS},
                poseidon2::{PARTIAL_ROUNDS, WIDTH},
            },
        },
        hash_sig::{CHUNK_SIZE, TWEAK_FE_LEN},
    },
};
use core::{
    array::from_fn,
    borrow::Borrow,
    iter::{self, Sum, zip},
};
use openvm_stark_backend::{
    air_builders::sub::SubAirBuilder,
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir},
    p3_field::FieldAlgebra,
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};
use p3_poseidon2_air::{Poseidon2Air, num_cols};
use p3_poseidon2_util::horizon::baby_bear::constant::RC16;

pub struct ChainAir(
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

impl Default for ChainAir {
    fn default() -> Self {
        Self(Poseidon2Air::new(RC16.into()))
    }
}

impl BaseAir<F> for ChainAir {
    fn width(&self) -> usize {
        NUM_CHAIN_COLS
    }
}

impl PartitionedBaseAir<F> for ChainAir {}

impl BaseAirWithPublicValues<F> for ChainAir {
    fn num_public_values(&self) -> usize {
        TWEAK_FE_LEN
    }
}

impl<AB> Air<AB> for ChainAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
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

        // TODO:
        // 1. Make sure `encoded_tweak_chain` is correct.
        // 2. Make sure `leaf_block_step`, `leaf_block_and_buf` and `leaf_block_ptr_ind` is correct.

        let main = builder.main();

        let encoded_tweak_merkle_tree: [_; TWEAK_FE_LEN] =
            from_fn(|i| builder.public_values()[i].into());

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &ChainCols<AB::Var> = (*local).borrow();
        let next: &ChainCols<AB::Var> = (*next).borrow();

        // When every rows
        eval_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(local.is_active);
            eval_sig_first_row(&mut builder, local)
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_sig_transition(&mut builder, local, next);
            eval_sig_first_row(&mut builder.when(local.is_last_sig_row), next);
        }

        // Interaction
        receive_chain(builder, local);
        send_merkle_tree(builder, encoded_tweak_merkle_tree, local);
    }
}

fn eval_every_row<AB>(builder: &mut AB, cols: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    cols.group_ind.map(|bit| builder.assert_bool(bit));
    builder.assert_one(AB::Expr::sum(cols.group_ind.into_iter().map(Into::into)));
    cols.chain_step_bits.map(|bit| builder.assert_bool(bit));
    cols.is_first_group_step.eval(builder, cols.group_step);
    cols.is_last_group_step
        .eval(builder, cols.group_step, F::from_canonical_u32(12));
    builder.assert_eq(
        cols.is_last_group_row,
        cols.is_last_chain_step::<AB>() * cols.is_last_group_step.output.into(),
    );
    builder.assert_eq(
        cols.is_last_sig_row,
        cols.is_last_group_row * cols.group_ind[5],
    );
    builder.assert_bool(cols.is_active);
}

fn eval_sig_first_row<AB>(builder: &mut AB, cols: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    builder.assert_one(cols.group_ind[0]);
    builder.assert_eq(cols.group_acc[0], cols.chain_step::<AB>());
    builder.assert_zero(cols.group_step);
}

fn eval_sig_transition<AB>(builder: &mut AB, local: &ChainCols<AB::Var>, next: &ChainCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    let is_last_chain_step = local.is_last_chain_step::<AB>();
    let is_last_group_step = local.is_last_group_step.output.into();
    (0..6).for_each(|i| {
        builder.assert_eq(
            next.group_ind[i],
            select(
                local.is_last_group_row.into(),
                local.group_ind[i].into(),
                local.group_ind[i.checked_sub(1).unwrap_or(5)].into(),
            ),
        )
    });
    builder.assert_eq(
        next.group_step,
        select(
            is_last_chain_step.clone(),
            local.group_step.into(),
            (local.group_step.into() + AB::Expr::ONE)
                - is_last_group_step.clone() * AB::Expr::from_canonical_usize(GROUP_SIZE),
        ),
    );
    builder.when(not(is_last_chain_step.clone())).assert_eq(
        next.chain_step::<AB>(),
        local.chain_step::<AB>() + AB::Expr::ONE,
    );
    (0..6).for_each(|i| {
        builder
            .when(local.group_ind[i] * next.group_ind[i.checked_sub(1).unwrap_or(5)])
            .assert_eq(
                next.group_acc[i.checked_sub(1).unwrap_or(5)],
                next.chain_step::<AB>(),
            );
        builder
            .when(
                local.group_ind[i] * (is_last_chain_step.clone() - local.is_last_group_row.into()),
            )
            .assert_eq(
                next.group_acc[i],
                local.group_acc[i].into() * AB::Expr::from_canonical_u32(1 << CHUNK_SIZE)
                    + next.chain_step::<AB>(),
            );
        builder
            .when(local.group_ind[i] * not(is_last_chain_step.clone()))
            .assert_eq(next.group_acc[i], local.group_acc[i]);
    });

    // When `not(is_last_sig_row)`.
    {
        let mut builder = builder.when(not(local.is_last_sig_row.into()));

        zip(local.parameter(), next.parameter()).for_each(|(a, b)| builder.assert_eq(*a, *b));
        zip(local.merkle_root, next.merkle_root).for_each(|(a, b)| builder.assert_eq(a, b));
        builder.assert_eq(local.is_active, next.is_active)
    }

    // When `not(is_last_chain_step)`.
    {
        let mut builder = builder.when(not(is_last_chain_step.clone()));

        zip(local.compression_output::<AB>(), next.chain_input::<AB>())
            .for_each(|(a, b)| builder.assert_eq(a, b));
    }
}

fn receive_chain<AB>(builder: &mut AB, local: &ChainCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    builder.push_receive(
        BUS_CHAIN,
        iter::empty()
            .chain(local.parameter().iter().copied())
            .chain(local.merkle_root)
            .chain(local.group_acc),
        local.is_active.into() * local.is_last_sig_row.into(),
    );
}

fn send_merkle_tree<AB>(
    builder: &mut AB,
    encoded_tweak_merkle_tree: [AB::Expr; TWEAK_FE_LEN],
    local: &ChainCols<AB::Var>,
) where
    AB: InteractionBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    builder.push_send(
        BUS_MERKLE_TREE,
        iter::empty()
            .chain(local.merkle_root.map(Into::into))
            .chain([local.leaf_chunk_idx::<AB>()])
            .chain(
                zip(local.compression_output::<AB>(), local.chain_input::<AB>())
                    .map(|(a, b)| select(local.chain_step_bits[0].into(), a, b)),
            ),
        local.is_active * local.is_last_chain_step::<AB>(),
    );
    builder.push_send(
        BUS_MERKLE_TREE,
        iter::empty()
            .chain(local.merkle_root.map(Into::into))
            .chain([AB::Expr::ZERO])
            .chain(local.parameter().iter().copied().map(Into::into))
            .chain(encoded_tweak_merkle_tree.map(Into::into)),
        local.is_active * local.is_last_sig_row.into(),
    );
}
