use hash_sig_agg_circuit_openvm::poseidon2::chip::generate_air_proof_inputs;
use hash_sig_agg_circuit_openvm::poseidon2::hash_sig::test::mock_vi;
use hash_sig_agg_circuit_openvm::poseidon2::E;
use hash_sig_agg_circuit_openvm::poseidon2::F;
use hash_sig_agg_circuit_openvm::test::run;

fn main() {
    for log_sigs in 0..3 {
        let vi = mock_vi(1 << log_sigs);
        let (airs, inputs) = generate_air_proof_inputs(1, vi);

        run::<F, E>(airs, inputs).unwrap();
    }
}
