use crate::horizon::baby_bear::constant::*;
use core::{iter::zip, ops::Mul};
use p3_baby_bear::BabyBear;
use p3_field::{Field, FieldAlgebra};
use p3_poseidon2::{
    add_rc_and_sbox_generic, external_initial_permute_state, external_terminal_permute_state,
    mds_light_permutation, ExternalLayer, ExternalLayerConstants, ExternalLayerConstructor,
    GenericPoseidon2LinearLayers, HLMDSMat4, InternalLayer, InternalLayerConstructor, Poseidon2,
};
use std::sync::LazyLock;

pub mod constant;

pub type Poseidon2Horizon<const WIDTH: usize> = Poseidon2<
    <BabyBear as Field>::Packing,
    Poseidon2ExternalLayerHorizon<WIDTH>,
    Poseidon2InternalLayerHorizon<WIDTH>,
    WIDTH,
    SBOX_DEGREE,
>;

pub fn poseidon2_t16_horizon() -> &'static Poseidon2Horizon<16> {
    static INSTANCE: LazyLock<Poseidon2Horizon<16>> = LazyLock::new(|| {
        Poseidon2::new(
            ExternalLayerConstants::new(
                RC16.beginning_full_round_constants.to_vec(),
                RC16.ending_full_round_constants.to_vec(),
            ),
            RC16.partial_round_constants.to_vec(),
        )
    });
    &*INSTANCE
}

pub fn poseidon2_t24_horizon() -> &'static Poseidon2Horizon<24> {
    static INSTANCE: LazyLock<Poseidon2Horizon<24>> = LazyLock::new(|| {
        Poseidon2::new(
            ExternalLayerConstants::new(
                RC24.beginning_full_round_constants.to_vec(),
                RC24.ending_full_round_constants.to_vec(),
            ),
            RC24.partial_round_constants.to_vec(),
        )
    });
    &*INSTANCE
}

#[derive(Clone, Debug)]
pub struct Poseidon2ExternalLayerHorizon<const WIDTH: usize>(
    Vec<[BabyBear; WIDTH]>,
    Vec<[BabyBear; WIDTH]>,
);

impl<FA: FieldAlgebra<F = BabyBear>, const WIDTH: usize> ExternalLayerConstructor<FA, WIDTH>
    for Poseidon2ExternalLayerHorizon<WIDTH>
{
    fn new_from_constants(external_constants: ExternalLayerConstants<FA::F, WIDTH>) -> Self {
        let initial = external_constants.get_initial_constants().clone();
        let terminal = external_constants.get_terminal_constants().clone();
        Self(initial, terminal)
    }
}

impl<const WIDTH: usize> ExternalLayer<BabyBear, WIDTH, SBOX_DEGREE>
    for Poseidon2ExternalLayerHorizon<WIDTH>
{
    fn permute_state_initial(&self, state: &mut [BabyBear; WIDTH]) {
        external_initial_permute_state(
            state,
            &self.0,
            add_rc_and_sbox_generic::<_, SBOX_DEGREE>,
            &HLMDSMat4,
        );
    }

    fn permute_state_terminal(&self, state: &mut [BabyBear; WIDTH]) {
        external_terminal_permute_state(
            state,
            &self.1,
            add_rc_and_sbox_generic::<_, SBOX_DEGREE>,
            &HLMDSMat4,
        );
    }
}

#[derive(Clone, Debug)]
pub struct Poseidon2InternalLayerHorizon<const WIDTH: usize>(Vec<BabyBear>);

impl<FA: FieldAlgebra<F = BabyBear>, const WIDTH: usize> InternalLayerConstructor<FA>
    for Poseidon2InternalLayerHorizon<WIDTH>
{
    fn new_from_constants(internal_constants: Vec<FA::F>) -> Self {
        Self(internal_constants)
    }
}

impl<const WIDTH: usize> InternalLayer<BabyBear, WIDTH, SBOX_DEGREE>
    for Poseidon2InternalLayerHorizon<WIDTH>
{
    fn permute_state(&self, state: &mut [BabyBear; WIDTH]) {
        self.0.iter().for_each(|rc| {
            state[0] += *rc;
            state[0] = state[0].exp_const_u64::<SBOX_DEGREE>();
            let sum = state.iter().cloned().sum::<BabyBear>();
            zip(&mut *state, mat_diag_m_1::<WIDTH>())
                .for_each(|(state, mat_diag_m_1)| *state = *state * *mat_diag_m_1 + sum);
        })
    }
}

#[derive(Clone, Debug)]
pub struct GenericPoseidon2LinearLayersHorizon<const WIDTH: usize>;

impl<FA, const WIDTH: usize> GenericPoseidon2LinearLayers<FA, WIDTH>
    for GenericPoseidon2LinearLayersHorizon<WIDTH>
where
    FA: FieldAlgebra<F = BabyBear> + Mul<BabyBear, Output = FA>,
{
    fn internal_linear_layer(state: &mut [FA; WIDTH]) {
        let sum = state.iter().cloned().sum::<FA>();
        zip(&mut *state, mat_diag_m_1::<WIDTH>())
            .for_each(|(state, mat_diag_m_1)| *state = state.clone() * *mat_diag_m_1 + sum.clone());
    }

    fn external_linear_layer(state: &mut [FA; WIDTH]) {
        mds_light_permutation(state, &HLMDSMat4)
    }
}

#[cfg(test)]
mod test {
    use crate::horizon::baby_bear::{
        poseidon2_t16_horizon, poseidon2_t24_horizon, Poseidon2Horizon,
    };
    use core::array::from_fn;
    use p3_field::FieldAlgebra;
    use p3_symmetric::Permutation;
    use rand::{rngs::StdRng, SeedableRng};
    use zkhash::{
        ark_ff::{PrimeField, UniformRand},
        fields::babybear::FpBabyBear,
        poseidon2::{
            poseidon2::Poseidon2,
            poseidon2_instance_babybear::{
                POSEIDON2_BABYBEAR_16_PARAMS, POSEIDON2_BABYBEAR_24_PARAMS,
            },
        },
    };

    #[test]
    fn consistency() {
        fn check<const WIDTH: usize>(poseidon2: Poseidon2Horizon<WIDTH>) {
            let mut rng = StdRng::from_entropy();
            let reference = Poseidon2::new(match WIDTH {
                16 => &*POSEIDON2_BABYBEAR_16_PARAMS,
                24 => &*POSEIDON2_BABYBEAR_24_PARAMS,
                _ => unreachable!(),
            });
            for _ in 0..100 {
                let pre: [FpBabyBear; WIDTH] = from_fn(|_| FpBabyBear::rand(&mut rng));
                let post: [FpBabyBear; WIDTH] = reference.permutation(&pre).try_into().unwrap();
                let mut state = pre.map(horizon_to_p3);
                poseidon2.permute_mut(&mut state);
                assert_eq!(state, post.map(horizon_to_p3))
            }
        }

        check(poseidon2_t16_horizon());
        check(poseidon2_t24_horizon());
    }

    fn horizon_to_p3<F: FieldAlgebra>(value: FpBabyBear) -> F {
        F::from_canonical_u64(value.into_bigint().0[0])
    }
}
