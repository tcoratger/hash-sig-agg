use crate::{
    gadget::{not, select},
    poseidon2::{
        F, GenericPoseidon2LinearLayersHorizon, HALF_FULL_ROUNDS, SBOX_DEGREE, SBOX_REGISTERS,
        chip::{
            BUS_CHAIN,
            chain::{
                column::{ChainCols, NUM_CHAIN_COLS},
                poseidon2::{PARTIAL_ROUNDS, WIDTH},
            },
        },
        hash_sig::CHUNK_SIZE,
    },
};
use core::{
    borrow::Borrow,
    iter::{self, Sum, zip},
};
use openvm_stark_backend::{
    air_builders::sub::SubAirBuilder,
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilder, BaseAir},
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

impl BaseAirWithPublicValues<F> for ChainAir {}

impl<AB> Air<AB> for ChainAir
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
        let next = main.row_slice(1);
        let local: &ChainCols<AB::Var> = (*local).borrow();
        let next: &ChainCols<AB::Var> = (*next).borrow();

        // TODO:
        // 1. Make sure `encoded_tweak_chain` is correct.
        // 2. Schedule poseidon2 sponge invocation and send to poseidon2 sponge bus.
        // 3. Send to merkle tree opening bus.

        // When every rows

        local.group_ind.map(|bit| builder.assert_bool(bit));
        builder.assert_one(AB::Expr::sum(local.group_ind.into_iter().map(Into::into)));
        local.chain_step_bits.map(|bit| builder.assert_bool(bit));
        local.is_group_first_step.eval(builder, local.group_step);
        local
            .is_group_last_step
            .eval(builder, local.group_step, F::from_canonical_u32(12));
        builder.assert_eq(
            local.is_group_last_row,
            local.is_last_chain_step::<AB>() * local.is_group_last_step.output.into(),
        );
        builder.assert_eq(
            local.is_sig_last_row,
            local.is_group_last_row * local.group_ind[5],
        );
        builder
            .when(not(local.is_sig_last_row.into()))
            .assert_zero(local.mult);
        builder.assert_bool(local.mult);

        // When first row
        {
            let mut builder = builder.when_first_row();
            builder.assert_one(local.group_ind[0]);
            builder.assert_zero(local.group_step);
            builder
                .when_first_row()
                .assert_eq(local.group_acc[0], local.chain_step::<AB>());
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            let is_last_chain_step = local.is_last_chain_step::<AB>();
            let is_group_last_step = local.is_group_last_step.output.into();
            (0..6).for_each(|i| {
                builder.assert_eq(
                    next.group_ind[i],
                    select(
                        local.is_group_last_row.into(),
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
                        - is_group_last_step.clone() * AB::Expr::from_canonical_u32(13),
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
                        local.group_ind[i]
                            * (local.is_last_chain_step::<AB>() - local.is_group_last_row.into()),
                    )
                    .assert_eq(
                        next.group_acc[i],
                        local.group_acc[i].into() * AB::Expr::from_canonical_u32(1 << CHUNK_SIZE)
                            + next.chain_step::<AB>(),
                    );
                builder
                    .when(local.group_ind[i] * not(local.is_last_chain_step::<AB>()))
                    .assert_eq(next.group_acc[i], local.group_acc[i]);
            });

            // When `not(is_last_group * is_group_last_step * is_last_chain_step)`.
            {
                let mut builder = builder.when(not(local.is_sig_last_row.into()));

                zip(local.parameter(), next.parameter())
                    .for_each(|(a, b)| builder.assert_eq(*a, *b));
            }

            // When `not(is_last_chain_step)`.
            {
                let mut builder = builder.when(not(local.is_last_chain_step::<AB>()));
                zip(local.chain_output::<AB>(), next.chain_input::<AB>())
                    .for_each(|(a, b)| builder.assert_eq(a, b));
            }
        }

        // Interaction

        builder.push_receive(
            BUS_CHAIN,
            iter::empty()
                .chain(local.parameter().iter().copied())
                .chain(local.group_acc),
            local.mult.into(),
        );
    }
}
