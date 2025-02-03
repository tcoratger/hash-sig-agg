use crate::{
    gadget::not,
    poseidon2::{
        F,
        chip::merkle_tree::column::{MerkleTreeCols, NUM_MERKLE_TREE_COLS},
        hash_sig::LOG_LIFETIME,
    },
};
use core::{borrow::Borrow, iter::zip};
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir},
    p3_field::FieldAlgebra,
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};

#[derive(Clone, Copy)]
pub struct MerkleTreeAir;

impl BaseAir<F> for MerkleTreeAir {
    fn width(&self) -> usize {
        NUM_MERKLE_TREE_COLS
    }
}

impl PartitionedBaseAir<F> for MerkleTreeAir {}

impl BaseAirWithPublicValues<F> for MerkleTreeAir {
    fn num_public_values(&self) -> usize {
        1
    }
}

impl<AB> Air<AB> for MerkleTreeAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let epoch = builder.public_values()[0];

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &MerkleTreeCols<AB::Var> = (*local).borrow();
        let next: &MerkleTreeCols<AB::Var> = (*next).borrow();

        // When every rows
        builder.assert_bool(local.is_right);
        builder.assert_bool(local.is_active);
        local.is_last_level.eval(
            builder,
            local.level,
            AB::Expr::from_canonical_usize(LOG_LIFETIME - 1),
        );
        builder
            .when(local.is_last_level.output.into())
            .assert_eq(local.epoch_dec, local.is_right);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_zero(local.level);
            builder.assert_eq(local.epoch_dec, epoch);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            // When not(is_last_level)
            {
                let mut builder = builder.when(not(local.is_last_level.output.into()));

                builder.assert_eq(next.level, local.level + AB::Expr::ONE);
                builder.assert_eq(
                    next.epoch_dec.into().double() + local.is_right,
                    local.epoch_dec,
                );
                zip(next.right, local.output)
                    .for_each(|(a, b)| builder.when(next.is_right).assert_eq(a, b));
                zip(next.left, local.output)
                    .for_each(|(a, b)| builder.when(not(next.is_right.into())).assert_eq(a, b));
                builder.assert_eq(next.is_active, local.is_active);
            }

            // When is_last_level
            {
                let mut builder = builder.when(local.is_last_level.output.into());

                builder.assert_zero(next.level);
                builder.assert_eq(next.epoch_dec, epoch);
            }
        }

        // Interaction

        // TODO: Send to `BUS_POSEIDON2_T24_COMPRESS` when `is_active`.
    }
}
