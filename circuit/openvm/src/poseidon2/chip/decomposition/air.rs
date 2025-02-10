use crate::{
    gadget::not,
    poseidon2::{
        F,
        chip::{
            BUS_DECOMPOSITION, BUS_LIMB_RANGE_CHECK,
            decomposition::{
                F_MS_LIMB, LIMB_BITS, NUM_LIMBS, NUM_MSG_HASH_LIMBS,
                column::{DecompositionCols, NUM_DECOMPOSITION_COLS},
            },
        },
        hash_sig::MSG_HASH_FE_LEN,
    },
};
use core::{
    borrow::Borrow,
    iter::{self, zip},
};
use openvm_stark_backend::{
    interaction::InteractionBuilder,
    p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir},
    p3_field::FieldAlgebra,
    p3_matrix::Matrix,
    rap::{BaseAirWithPublicValues, PartitionedBaseAir},
};

#[derive(Clone, Copy)]
pub struct DecompositionAir;

impl BaseAir<F> for DecompositionAir {
    fn width(&self) -> usize {
        NUM_DECOMPOSITION_COLS
    }
}

impl PartitionedBaseAir<F> for DecompositionAir {}

impl BaseAirWithPublicValues<F> for DecompositionAir {}

impl<AB> Air<AB> for DecompositionAir
where
    AB: InteractionBuilder<F = F> + AirBuilderWithPublicValues,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let local: &DecompositionCols<AB::Var> = (*local).borrow();
        let next: &DecompositionCols<AB::Var> = (*next).borrow();

        // When every row
        eval_every_row(builder, local);

        // When first row
        {
            let mut builder = builder.when_first_row();

            builder.assert_one(local.ind[MSG_HASH_FE_LEN - 1]);
            eval_acc_first_row(&mut builder, local);
        }

        // When transition
        {
            let mut builder = builder.when_transition();

            eval_acc_transition(&mut builder, local, next);
            eval_acc_last_row(&mut builder, local, next);
        }

        // Interaction
        send_limb_range_check(builder, local);
        receive_decomposition(builder, local);
    }
}

#[inline]
fn eval_every_row<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    cols.ind.iter().for_each(|cell| builder.assert_bool(*cell));
    builder.assert_bool(cols.ind.iter().copied().map(Into::into).sum::<AB::Expr>());
    cols.value_ms_limb_bits
        .iter()
        .for_each(|cell| builder.assert_bool(*cell));
    builder.assert_eq(
        cols.value_ms_limb_auxs[0],
        cols.value_ms_limb_bits[4] * cols.value_ms_limb_bits[3] * cols.value_ms_limb_bits[2],
    );
    builder.assert_eq(
        cols.value_ms_limb_auxs[1],
        cols.value_ms_limb_auxs[0]
            * cols.value_ms_limb_bits[1]
            * not(cols.value_ms_limb_bits[0].into()),
    );
    cols.value_limb_0_is_zero
        .eval(builder, cols.value_ls_limbs[0]);
    cols.value_limb_1_is_zero
        .eval(builder, cols.value_ls_limbs[1]);
    (0..MSG_HASH_FE_LEN).for_each(|idx| {
        builder.when(cols.ind[idx]).assert_eq(
            cols.values[idx],
            cols.value_ls_limbs
                .iter()
                .copied()
                .map(Into::into)
                .chain([cols.value_ms_limb::<AB>()])
                .enumerate()
                .map(|(idx, limb)| limb * F::from_canonical_u32(1 << (idx * LIMB_BITS)))
                .sum::<AB::Expr>(),
        );
    });
    const { assert!(F_MS_LIMB == 0b11110) };
    // MSL != 31
    builder.assert_zero(
        cols.value_ms_limb_auxs[0].into()
            * cols.value_ms_limb_bits[1].into()
            * cols.value_ms_limb_bits[0].into(),
    );
    // When MSL == 31, second most significant limb should be 0.
    builder
        .when(cols.value_ms_limb_auxs[1].into())
        .assert_one(cols.value_limb_1_is_zero.output);
    // When MSL == 31 and second most significant limb == 0, LSL should be 0.
    builder
        .when(cols.value_ms_limb_auxs[1].into() * cols.value_limb_1_is_zero.output.into())
        .assert_one(cols.value_limb_0_is_zero.output);
}

#[inline]
fn eval_acc_first_row<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: AirBuilder<F = F>,
{
    zip(
        cols.acc_limbs,
        cols.value_ls_limbs
            .iter()
            .copied()
            .map(Into::into)
            .chain([cols.value_ms_limb::<AB>()]),
    )
    .for_each(|(a, b)| builder.assert_eq(a, b))
}

#[inline]
fn eval_acc_transition<AB>(
    builder: &mut AB,
    local: &DecompositionCols<AB::Var>,
    next: &DecompositionCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(not(local.ind[0].into()));

    (1..MSG_HASH_FE_LEN).for_each(|idx| builder.assert_eq(next.ind[idx - 1], local.ind[idx]));
    builder.when(local.ind[0]).assert_zero(
        next.ind[..MSG_HASH_FE_LEN - 1]
            .iter()
            .copied()
            .map(Into::into)
            .sum::<AB::Expr>(),
    );

    let f_ms_limb = F::from_canonical_u32(F_MS_LIMB);
    let base = F::from_canonical_u32(1 << LIMB_BITS);
    (0..NUM_MSG_HASH_LIMBS).for_each(|i| {
        if i == 0 {
            builder.assert_eq(
                next.carries[0] * base + next.acc_limbs[0],
                local.acc_limbs[0] + next.value_ls_limbs[0],
            );
        } else if i < NUM_LIMBS - 1 {
            builder.assert_eq(
                next.carries[i] * base + next.acc_limbs[i],
                local.acc_limbs[i] + next.value_ls_limbs[i] + next.carries[i - 1],
            );
        } else if i < NUM_LIMBS {
            builder.assert_eq(
                next.carries[i] * base + next.acc_limbs[i],
                local.acc_limbs[i - (NUM_LIMBS - 1)].into() * f_ms_limb
                    + local.acc_limbs[i]
                    + next.value_ms_limb::<AB>()
                    + next.carries[i - 1],
            );
        } else if i < NUM_MSG_HASH_LIMBS - 1 {
            builder.assert_eq(
                next.carries[i] * base + next.acc_limbs[i],
                local.acc_limbs[i - (NUM_LIMBS - 1)].into() * f_ms_limb
                    + local.acc_limbs[i]
                    + next.carries[i - 1],
            );
        } else {
            builder.assert_eq(
                next.acc_limbs[i],
                local.acc_limbs[i - (NUM_LIMBS - 1)].into() * f_ms_limb
                    + local.acc_limbs[i]
                    + next.carries[i - 1],
            );
        }
    });
}

#[inline]
fn eval_acc_last_row<AB>(
    builder: &mut AB,
    local: &DecompositionCols<AB::Var>,
    next: &DecompositionCols<AB::Var>,
) where
    AB: AirBuilder<F = F>,
{
    let mut builder = builder.when(local.ind[0]);

    eval_acc_first_row(&mut builder.when(next.ind[MSG_HASH_FE_LEN - 1]), next);
}

#[inline]
fn send_limb_range_check<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    for limb in cols
        .value_ls_limbs
        .iter()
        .chain(&cols.acc_limbs)
        .chain(&cols.carries)
    {
        builder.push_send(
            BUS_LIMB_RANGE_CHECK,
            [*limb],
            cols.ind.iter().copied().map(Into::into).sum::<AB::Expr>(),
        );
    }
}

#[inline]
fn receive_decomposition<AB>(builder: &mut AB, cols: &DecompositionCols<AB::Var>)
where
    AB: InteractionBuilder<F = F>,
{
    builder.push_receive(
        BUS_DECOMPOSITION,
        iter::empty().chain(cols.values).chain(cols.acc_limbs),
        cols.ind[0],
    );
}
