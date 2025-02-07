use crate::{
    gadget::not,
    poseidon2::{
        F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, RC24, SBOX_DEGREE,
        SBOX_REGISTERS,
        chip::{
            BUS_MERKLE_TREE, BUS_MSG_HASH,
            poseidon2_t24::{
                PARTIAL_ROUNDS, WIDTH,
                column::{NUM_POSEIDON2_T24_COLS, Poseidon2T24Cols},
            },
        },
        hash_sig::{
            LOG_LIFETIME, MSG_FE_LEN, PARAM_FE_LEN, RHO_FE_LEN, SPONGE_CAPACITY_VALUES,
            SPONGE_PERM, SPONGE_RATE, TH_HASH_FE_LEN, TWEAK_FE_LEN,
        },
    },
};
use core::{
    array::from_fn,
    borrow::Borrow,
    iter::{self, zip},
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

impl BaseAirWithPublicValues<F> for Poseidon2T24Air {
    fn num_public_values(&self) -> usize {
        1 + TWEAK_FE_LEN + MSG_FE_LEN
    }
}

impl<AB> Air<AB> for Poseidon2T24Air
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
        // 1. Make sure `encoded_tweak_merkle_tree` (`perm.inputs[PARAM_FE_LEN..][..TWEAK_FE_LEN]`) of leaf and path is correct.

        let main = builder.main();

        let epoch = builder.public_values()[0].into();
        let encoded_tweak_msg: [_; TWEAK_FE_LEN] =
            from_fn(|i| builder.public_values()[1 + i].into());
        let encoded_msg: [_; MSG_FE_LEN] =
            from_fn(|i| builder.public_values()[1 + TWEAK_FE_LEN + i].into());

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &Poseidon2T24Cols<AB::Var> = (*local).borrow();
        let next: &Poseidon2T24Cols<AB::Var> = (*next).borrow();

        // When every row
        eval_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(local.is_merkle_leaf);
            eval_merkle_leaf_first_row(&mut builder.when(local.is_merkle_leaf), local)
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_merkle_transition(&mut builder, local, next);
            eval_merkle_leaf_transition(&mut builder, local, next);
            eval_merkle_leaf_last_row(&mut builder, epoch, local, next);
            eval_merkle_path_transition(&mut builder, local, next);
            eval_merkle_path_last_row(&mut builder, local, next);
            eval_msg_transition(&mut builder, encoded_tweak_msg, encoded_msg, local, next);
            eval_padding_transition(&mut builder, local, next);
        }

        // Interaction
        receive_msg_hash(builder, local);
        receive_merkle_tree(builder, local, next);
    }
}

fn eval_every_row<AB>(builder: &mut AB, cols: &Poseidon2T24Cols<AB::Var>)
where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    builder.assert_bool(cols.is_msg);
    builder.assert_bool(cols.is_merkle_leaf);
    builder.assert_eq(
        cols.is_merkle_leaf_transition,
        cols.is_merkle_leaf * not(cols.is_last_sponge_step.output.into()),
    );
    builder.assert_bool(cols.is_merkle_path);
    builder.assert_eq(
        cols.is_merkle_path_transition,
        cols.is_merkle_path * not(cols.is_last_level.output.into()),
    );
    builder
        .assert_bool(cols.is_msg.into() + cols.is_merkle_leaf.into() + cols.is_merkle_path.into());
    cols.is_last_sponge_step.eval(
        builder,
        cols.sponge_step,
        AB::Expr::from_canonical_usize(SPONGE_PERM - 1),
    );
    cols.is_last_level.eval(
        builder,
        cols.level,
        AB::Expr::from_canonical_usize(LOG_LIFETIME - 1),
    );
    builder.assert_bool(cols.is_right);
}

fn eval_merkle_transition<AB>(
    builder: &mut AB,
    local: &Poseidon2T24Cols<AB::Var>,
    next: &Poseidon2T24Cols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    let mut builder = builder.when(local.is_merkle_transition::<AB>());

    zip(local.root, next.root).for_each(|(a, b)| builder.assert_eq(a, b));
}

fn eval_merkle_leaf_first_row<AB>(builder: &mut AB, cols: &Poseidon2T24Cols<AB::Var>)
where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    builder.assert_zero(cols.sponge_step);
    builder.assert_zero(cols.leaf_chunk_idx);
    (0..SPONGE_RATE)
        .step_by(TH_HASH_FE_LEN)
        .for_each(|i| builder.assert_one(cols.leaf_chunk_start_ind[i]));
    zip(&cols.perm.inputs[..SPONGE_RATE], cols.sponge_block)
        .for_each(|(a, b)| builder.assert_eq(*a, b));
    zip(&cols.perm.inputs[SPONGE_RATE..], SPONGE_CAPACITY_VALUES)
        .for_each(|(a, b)| builder.assert_eq(*a, b));
}

fn eval_merkle_leaf_transition<AB>(
    builder: &mut AB,
    local: &Poseidon2T24Cols<AB::Var>,
    next: &Poseidon2T24Cols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    let mut builder = builder.when(local.is_merkle_leaf_transition);

    builder.assert_one(next.is_merkle_leaf);
    builder.assert_eq(next.sponge_step, local.sponge_step + AB::Expr::ONE);
    builder.when(local.leaf_chunk_start_ind[0]).assert_eq(
        AB::Expr::TWO,
        next.leaf_chunk_start_ind
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>(),
    );
    builder.when(local.leaf_chunk_start_ind[1]).assert_eq(
        AB::Expr::ONE + AB::Expr::TWO,
        next.leaf_chunk_start_ind
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>(),
    );
    (1..TH_HASH_FE_LEN + 1).for_each(|i| {
        (i - 1..TH_HASH_FE_LEN)
            .step_by(TH_HASH_FE_LEN)
            .for_each(|j| {
                builder
                    .when(local.leaf_chunk_start_ind[i])
                    .assert_one(next.leaf_chunk_start_ind[j])
            })
    });
    zip(next.perm.inputs, local.sponge_output())
        .enumerate()
        .for_each(|(idx, (input, output))| {
            if let Some(block) = next.sponge_block.get(idx).copied() {
                builder.assert_eq(input, output + block.into())
            } else {
                builder.assert_eq(input, output)
            }
        })
}

fn eval_merkle_leaf_last_row<AB>(
    builder: &mut AB,
    epoch: AB::Expr,
    local: &Poseidon2T24Cols<AB::Var>,
    next: &Poseidon2T24Cols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    let mut builder =
        builder.when(local.is_merkle_leaf.into() - local.is_merkle_leaf_transition.into());

    builder.assert_one(next.is_merkle_path);
    builder.assert_zero(next.level);
    builder.assert_eq(next.epoch_dec, epoch);
    zip(next.path_right(), local.sponge_output())
        .for_each(|(a, b)| builder.when(next.is_right).assert_eq(a, b));
    zip(next.path_left(), local.sponge_output())
        .for_each(|(a, b)| builder.when(not(next.is_right.into())).assert_eq(a, b));
}

fn eval_merkle_path_transition<AB>(
    builder: &mut AB,
    local: &Poseidon2T24Cols<AB::Var>,
    next: &Poseidon2T24Cols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    let mut builder = builder.when(local.is_merkle_path_transition);

    builder.assert_one(next.is_merkle_path);
    builder.assert_eq(next.level, local.level + AB::Expr::ONE);
    builder.assert_eq(
        next.epoch_dec.into().double() + local.is_right.into(),
        local.epoch_dec,
    );
    zip(next.path_right(), local.compress_output::<AB>())
        .for_each(|(a, b)| builder.when(next.is_right).assert_eq(a, b));
    zip(next.path_left(), local.compress_output::<AB>())
        .for_each(|(a, b)| builder.when(not(next.is_right.into())).assert_eq(a, b));
}

fn eval_merkle_path_last_row<AB>(
    builder: &mut AB,
    local: &Poseidon2T24Cols<AB::Var>,
    next: &Poseidon2T24Cols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    let mut builder =
        builder.when(local.is_merkle_path.into() - local.is_merkle_path_transition.into());

    builder.assert_one(next.is_merkle_leaf.into() + next.is_msg.into());
    zip(local.root, local.compress_output::<AB>()).for_each(|(a, b)| builder.assert_eq(a, b));
    eval_merkle_leaf_first_row(&mut builder.when(next.is_merkle_leaf), next);
}

fn eval_msg_transition<AB>(
    builder: &mut AB,
    encoded_tweak_msg: [AB::Expr; TWEAK_FE_LEN],
    encoded_msg: [AB::Expr; MSG_FE_LEN],
    local: &Poseidon2T24Cols<AB::Var>,
    next: &Poseidon2T24Cols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    let mut builder = builder.when(local.is_msg);

    builder.assert_zero(next.is_merkle_leaf.into() + next.is_merkle_path.into());
    zip(
        &local.perm.inputs[RHO_FE_LEN..][..TWEAK_FE_LEN],
        encoded_tweak_msg,
    )
    .for_each(|(a, b)| builder.assert_eq(*a, b));
    zip(
        &local.perm.inputs[RHO_FE_LEN + TWEAK_FE_LEN..][..MSG_FE_LEN],
        encoded_msg,
    )
    .for_each(|(a, b)| builder.assert_eq(*a, b));
}

fn eval_padding_transition<AB>(
    builder: &mut AB,
    local: &Poseidon2T24Cols<AB::Var>,
    next: &Poseidon2T24Cols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    let mut builder = builder.when(local.is_padding::<AB>());

    builder.assert_one(next.is_padding::<AB>());
}

fn receive_msg_hash<AB>(builder: &mut AB, local: &Poseidon2T24Cols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    builder.push_receive(
        BUS_MSG_HASH,
        iter::empty()
            .chain(
                local.perm.inputs[RHO_FE_LEN + TWEAK_FE_LEN + MSG_FE_LEN..][..PARAM_FE_LEN]
                    .iter()
                    .copied()
                    .map(Into::into),
            )
            .chain(local.msg_hash::<AB>()),
        local.is_msg,
    );
}

fn receive_merkle_tree<AB>(
    builder: &mut AB,
    local: &Poseidon2T24Cols<AB::Var>,
    next: &Poseidon2T24Cols<AB::Var>,
) where
    AB: InteractionBuilder<F = F>,
    AB::Expr: FieldAlgebra<F = F>,
{
    builder.push_receive(
        BUS_MERKLE_TREE,
        iter::empty()
            .chain(local.root.map(Into::into))
            .chain([local.leaf_chunk_idx.into()])
            .chain(
                local.sponge_block[..TH_HASH_FE_LEN]
                    .iter()
                    .copied()
                    .map(Into::into),
            ),
        local.is_merkle_leaf * local.leaf_chunk_start_ind[0].into(),
    );
    builder.push_receive(
        BUS_MERKLE_TREE,
        iter::empty()
            .chain(local.root.map(Into::into))
            .chain([local.leaf_chunk_idx.into() + local.leaf_chunk_start_ind[0].into()])
            .chain((0..TH_HASH_FE_LEN).map(|i| {
                (1..)
                    .take(TH_HASH_FE_LEN)
                    .map(|j| local.leaf_chunk_start_ind[j] * local.sponge_block[j + i])
                    .sum()
            })),
        local.is_merkle_leaf,
    );
    builder.push_receive(
        BUS_MERKLE_TREE,
        iter::empty()
            .chain(local.root.map(Into::into))
            .chain([local.leaf_chunk_idx.into()
                + local.leaf_chunk_start_ind[0].into()
                + AB::Expr::ONE])
            .chain((0..TH_HASH_FE_LEN).map(|i| {
                (1 + TH_HASH_FE_LEN..)
                    .take(TH_HASH_FE_LEN)
                    .map(|j| {
                        local.leaf_chunk_start_ind[j]
                            * (if j + i < SPONGE_RATE {
                                local.sponge_block[j + i]
                            } else {
                                next.sponge_block[j + i - SPONGE_RATE]
                            })
                    })
                    .sum()
            })),
        local.is_merkle_leaf * not(local.is_last_sponge_step.output.into()),
    );
}
