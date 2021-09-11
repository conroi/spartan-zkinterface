mod lib;
use lib::*;

use flate2::{GzBuilder, Compression, read::GzDecoder};
use libspartan::{ComputationCommitment, SNARK, NIZK};
use merlin::Transcript;
use std::env;
use std::format;
use std::fs::File;
use std::io::{Read, Write};
use std::string::String;

enum ReturnValue {
    NIZKProof = 1,
    SNARKProof,
    Args,
    Mode,
}

#[derive(PartialEq, Eq)]
enum RunMode {
    Prove,
    Verify,
    Commit,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(!args.is_empty());
    let nizk: bool;
    let usage = format!(
        "
        {0} prove --nizk <ckt> <inp> <wit>
        {0} verify --nizk <ckt> <inp> <pf>
        {0} prove --snark <ckt> <inp> <wit> <decomm>
        {0} verify --snark <ckt> <inp> <pf> <comm>
        {0} commit --snark <ckt> <inp>
        ",
        args.get(0).unwrap()
    );

    let (mode, expect_len) = match args.get(1) {
        Some(m) if m.as_str() == "prove" => (RunMode::Prove, 6),
        Some(m) if m.as_str() == "verify" => (RunMode::Verify, 6),
        Some(m) if m.as_str() == "commit" => (RunMode::Commit, 5),
        _ => (RunMode::Prove, usize::MAX)
    };

    if args.len() < expect_len {
        eprintln!("ERROR: Invalid mode or incorrect #args for mode.\n{}", usage);
        std::process::exit(ReturnValue::Args as i32);
    }

    // NIZK mode?
    match args.get(2).unwrap().as_str() {
        "--nizk" => nizk = true,
        "--snark" => nizk = false,
        _ => {
            eprintln!("ERROR: second arg must be either --snark or --nizk.\n{}", usage);
            std::process::exit(ReturnValue::Mode as i32);
        }
    }

    if nizk && mode == RunMode::Commit {
        eprintln!("ERROR: cannot commit in NIZK mode.\n{}", usage);
        std::process::exit(ReturnValue::Args as i32);
    }

    if !nizk && mode != RunMode::Commit && args.len() < 7 {
        eprintln!("ERROR: SNARK prover/verifier need decomm/comm.\n{}", usage);
        std::process::exit(ReturnValue::Args as i32);
    }

    let bufh = {
        let inputsfn = args.get(4).unwrap();
        let mut fh = File::open(inputsfn).unwrap();
        let mut bufh = Vec::new();
        fh.read_to_end(&mut bufh).unwrap();
        bufh
    };

    let bufcs = {
        let circuitfn = args.get(3).unwrap();
        let mut fcs = File::open(circuitfn).unwrap();
        let mut bufcs = Vec::new();
        fcs.read_to_end(&mut bufcs).unwrap();
        bufcs
    };

    if mode == RunMode::Prove {
        let bufwp = {
            let wpfn = args.get(5).unwrap();
            let mut fw = File::open(wpfn).unwrap();
            let mut bufw = Vec::new();
            fw.read_to_end(&mut bufw).unwrap();
            bufw
        };

        let reader = R1csReader::new(&bufh, &bufcs, Some(&bufwp));
        let r1cs = R1cs::from(reader);

        // We will encode the above constraints into three matrices, where
        // the coefficients in the matrix are in little-endian byte order
        let mut aa: Vec<(usize, usize, [u8; 32])> = Vec::new();
        let mut bb: Vec<(usize, usize, [u8; 32])> = Vec::new();
        let mut cc: Vec<(usize, usize, [u8; 32])> = Vec::new();

        let inst = r1cs.instance(&mut aa, &mut bb, &mut cc);
        let assignment_inputs = r1cs.inputs_assignment();
        let assignment_vars = r1cs.vars_assignment();

        // Check if instance is satisfiable
        let res = inst.is_sat(&assignment_vars, &assignment_inputs);
        match res {
            Ok(res) =>
                if !res {
                    std::panic!("Constraints are not satisfied by inputs");
                }
            Err(e) => std::panic!("{:?}", e)
        }

        let (pf_ser, name) = if nizk {
            let gens = r1cs.nizk_public_params();

            // produce a proof of satisfiability
            let mut prover_transcript = Transcript::new(b"NIZK");
            let proof = NIZK::prove(
                &inst,
                assignment_vars,
                &assignment_inputs,
                &gens,
                &mut prover_transcript,
                );
            (bincode::serialize(&proof).unwrap(), "nizk_proof")
        } else {
            let gens = r1cs.snark_public_params();
            let (comm, decomm) = SNARK::encode(&inst, &gens);

            // produce a proof of satisfiability
            let mut prover_transcript = Transcript::new(b"SNARK");
            let proof = SNARK::prove(
                &inst,
                &decomm,
                assignment_vars,
                &assignment_inputs,
                &gens,
                &mut prover_transcript,
                );
            (bincode::serialize(&(proof, comm)).unwrap(), "snark_proof")
        };

        // write gzipped serialized data to file
        let pf_fh = File::create(format!("{}.gz", name)).unwrap();
        let mut pf_w = GzBuilder::new()
                .comment("ZKUnbound Proof Serialization")
                .write(pf_fh, Compression::best());
        pf_w.write_all(&pf_ser[..]).unwrap();
        pf_w.finish().unwrap();
    } else if mode == RunMode::Verify {
        let buf = {
            let wpfn = args.get(5).unwrap();
            let fw = File::open(wpfn).unwrap();
            let mut pf_r = GzDecoder::new(&fw);
            let mut buf = Vec::new();
            pf_r.read_to_end(&mut buf).unwrap();
            buf
        };

        let reader = R1csReader::new(&bufh, &bufcs, None);
        let r1cs = R1cs::from(reader);
        let assignment_inputs = r1cs.inputs_assignment();
        if nizk {
            let proof: NIZK = bincode::deserialize(&buf[..]).unwrap();
            let mut aa: Vec<(usize, usize, [u8; 32])> = Vec::new();
            let mut bb: Vec<(usize, usize, [u8; 32])> = Vec::new();
            let mut cc: Vec<(usize, usize, [u8; 32])> = Vec::new();
            let inst = r1cs.instance(&mut aa, &mut bb, &mut cc);
            let gens = r1cs.nizk_public_params();

            let mut verifier_transcript = Transcript::new(b"NIZK");
            if proof.verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens).is_err() {
                std::process::exit(ReturnValue::NIZKProof as i32);
            }
        } else {
            let (proof, comm): (SNARK, ComputationCommitment) = bincode::deserialize(&buf[..]).unwrap();
            let gens = r1cs.snark_public_params();
            let mut verifier_transcript = Transcript::new(b"SNARK");
            if proof.verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens).is_err() {
                std::process::exit(ReturnValue::SNARKProof as i32);
            }
        }
    } else {
        unimplemented!();
    }
}
