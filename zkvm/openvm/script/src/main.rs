use clap::Parser;
use openvm_build::{build_guest_package, get_package, guest_methods, GuestOptions};
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn,
};
use openvm_stark_sdk::{config::FriParameters, p3_baby_bear::BabyBear};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE, FromElf};
use std::{fs, path::PathBuf, sync::Arc};

#[derive(Parser)]
struct Args {
    #[clap(long)]
    input: String,
    #[clap(long)]
    debug: bool,
}

fn main() {
    let args = Args::parse();

    let program = if args.input.contains("keccak256") {
        "keccak256"
    } else if args.input.contains("poseidon2") {
        "poseidon2"
    } else {
        unreachable!()
    };
    let (exe, config) = build_program(program);
    let pk = {
        let app_config = AppConfig::new(FriParameters::standard_fast(), config.clone());
        Arc::new(Sdk.app_keygen(app_config).unwrap())
    };

    let stdin = StdIn::from_bytes(&fs::read(args.input).unwrap());

    if args.debug {
        let output = Sdk
            .execute(exe.clone(), config.clone(), stdin.clone())
            .unwrap();
        println!("{:?}", output);
    }

    let committed_exe = Sdk.commit_app_exe(pk.app_fri_params(), exe).unwrap();
    let proof = Sdk
        .generate_app_proof(pk.clone(), committed_exe, stdin)
        .unwrap();
    Sdk.verify_app_proof(&pk.get_app_vk(), &proof).unwrap();
}

fn build_program(program: &str) -> (VmExe<BabyBear>, SdkVmConfig) {
    let elf = {
        let workspace_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
        let target_dir = PathBuf::from_iter([workspace_dir, "target", "openvm", program]);
        let pkg = get_package(PathBuf::from_iter([workspace_dir, program]));
        let guest_opts = GuestOptions::default()
            .with_target_dir(&target_dir)
            .with_profile("release".to_string());
        build_guest_package(&pkg, &guest_opts, None, &None).unwrap();
        let elf_path = guest_methods(&pkg, &target_dir, &guest_opts.features, &guest_opts.profile)
            .pop()
            .unwrap();
        let data = fs::read(elf_path).unwrap();
        Elf::decode(&data, MEM_SIZE as u32).unwrap()
    };
    let config = match program {
        "keccak256" => SdkVmConfig::builder()
            .system(Default::default())
            .rv32i(Default::default())
            .rv32m(Default::default())
            .io(Default::default())
            .keccak(Default::default())
            .build(),
        "poseidon2" => SdkVmConfig::builder()
            .system(Default::default())
            .rv32i(Default::default())
            .rv32m(Default::default())
            .io(Default::default())
            .build(),
        _ => unreachable!(),
    };
    (VmExe::from_elf(elf, config.transpiler()).unwrap(), config)
}
