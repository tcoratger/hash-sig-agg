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
            SPONGE_PERM, SPONGE_RATE, TWEAK_FE_LEN,
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
        // 1. Make sure `encoded_tweak_merkle_tree` is correct.

        let main = builder.main();

        let epoch = builder.public_values()[0];
        let encoded_tweak_msg: [_; TWEAK_FE_LEN] = from_fn(|i| builder.public_values()[1 + i]);
        let encoded_msg: [_; MSG_FE_LEN] =
            from_fn(|i| builder.public_values()[1 + TWEAK_FE_LEN + i]);

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &Poseidon2T24Cols<AB::Var> = (*local).borrow();
        let next: &Poseidon2T24Cols<AB::Var> = (*next).borrow();

        // When every row

        builder.assert_bool(local.is_msg);
        builder.assert_bool(local.is_merkle_leaf);
        builder.assert_eq(
            local.is_merkle_leaf_transition,
            local.is_merkle_leaf * not(local.is_last_leaf_block_step.output.into()),
        );
        builder.assert_bool(local.is_merkle_path);
        builder.assert_eq(
            local.is_merkle_path_transition,
            local.is_merkle_path * not(local.is_last_level.output.into()),
        );
        builder.assert_bool(
            local.is_msg.into() + local.is_merkle_leaf.into() + local.is_merkle_path.into(),
        );
        local.is_last_leaf_block_step.eval(
            builder,
            local.leaf_block_step,
            AB::Expr::from_canonical_usize(SPONGE_PERM - 1),
        );
        local.is_last_level.eval(
            builder,
            local.level,
            AB::Expr::from_canonical_usize(LOG_LIFETIME - 1),
        );
        builder.assert_bool(local.is_right);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(local.is_merkle_leaf);
            zip(&local.perm.inputs[..SPONGE_RATE], local.leaf_block)
                .for_each(|(a, b)| builder.assert_eq(*a, b));
            zip(&local.perm.inputs[SPONGE_RATE..], SPONGE_CAPACITY_VALUES)
                .for_each(|(a, b)| builder.assert_eq(*a, b));
        }

        // When transition and (is_merkle_leaf or is_merkle_path) and not(is_last_level)
        {
            let mut builder = builder.when(
                builder.is_transition()
                    * (local.is_merkle_leaf.into() + local.is_merkle_path_transition.into()),
            );

            zip(local.root, next.root).for_each(|(a, b)| builder.assert_eq(a, b));
        }

        // When transition and is_merkle_leaf
        {
            let mut builder = builder.when(builder.is_transition());

            // When is_merkle_leaf_transition
            {
                let mut builder = builder.when(local.is_merkle_leaf_transition);

                builder.assert_one(next.is_merkle_leaf);
                builder.assert_eq(next.leaf_block_step, local.leaf_block_step + AB::Expr::ONE);
                zip(next.perm.inputs, local.sponge_output())
                    .enumerate()
                    .for_each(|(idx, (input, output))| {
                        if let Some(block) = next.leaf_block.get(idx).copied() {
                            builder.assert_eq(input, output + block.into())
                        } else {
                            builder.assert_eq(input, output)
                        }
                    })
            }

            // When is_merkle_leaf and is_last_leaf_block_step
            {
                let mut builder = builder
                    .when(local.is_merkle_leaf.into() - local.is_merkle_leaf_transition.into());

                builder.assert_one(next.is_merkle_path);
                builder.assert_zero(next.level);
                builder.assert_eq(next.epoch_dec, epoch);
            }
        }

        // When transition and is_merkle_path
        {
            let mut builder = builder.when(builder.is_transition());

            // When is_merkle_path_transition
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

            // When is_merkle_path and is_last_level
            {
                let mut builder = builder
                    .when(local.is_merkle_path.into() - local.is_merkle_path_transition.into());

                zip(local.root, local.compress_output::<AB>())
                    .for_each(|(a, b)| builder.assert_eq(a, b));

                // When next.is_merkle_leaf
                {
                    let mut builder = builder.when(next.is_merkle_leaf);

                    builder.assert_zero(next.leaf_block_step);
                    zip(&next.perm.inputs[..SPONGE_RATE], next.leaf_block)
                        .for_each(|(a, b)| builder.assert_eq(*a, b));
                    zip(&next.perm.inputs[SPONGE_RATE..], SPONGE_CAPACITY_VALUES)
                        .for_each(|(a, b)| builder.assert_eq(*a, b));
                }
            }
        }

        // When transition and is_msg
        {
            let mut builder = builder.when(builder.is_transition() * local.is_msg.into());

            builder.assert_zero(local.is_merkle_leaf.into() + local.is_merkle_path.into());
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

        // When transition and not(is_msg + is_merkle_leaf + is_merkle_path)
        {
            let mut builder = builder.when(
                builder.is_transition()
                    * not(local.is_msg.into()
                        + local.is_merkle_leaf.into()
                        + local.is_merkle_path.into()),
            );

            builder.assert_zero(
                local.is_msg.into() + local.is_merkle_leaf.into() + local.is_merkle_path.into(),
            );
        }

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
        builder.push_receive(
            BUS_MERKLE_TREE,
            iter::empty()
                .chain(local.root)
                .chain([local.leaf_block_step])
                .chain(local.leaf_block),
            local.is_merkle_leaf,
        );
    }
}
