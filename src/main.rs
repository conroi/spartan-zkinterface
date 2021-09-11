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
    InvalidNIZKProof = 1,
    InvalidSNARKProof,
    InvalidArgs,
    InvalidMode,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(!args.is_empty());
    let nizk: bool;
    let prove: bool;
    let usage = format!(
        "{} [prove | verify] [--nizk|--snark] <circuit.zkif> <inputs.zkif> <witness.zkif>",
        args.get(0).unwrap()
    );

    // NIZK mode?
    match (args.get(2), args.len() < 6) {
        (Some(v), false) if v.as_str() == "--nizk" => nizk = true,
        (Some(v), false) if v.as_str() == "--snark" => nizk = false,
        _ => {
            eprintln!("{}", usage);
            std::process::exit(ReturnValue::InvalidArgs as i32);
        }
    }

    // prove or verify?
    match args.get(1).unwrap().as_str() {
        "prove" => prove = true,
        "verify" => prove = false,
        _ => {
            eprintln!("{}", usage);
            std::process::exit(ReturnValue::InvalidMode as i32);
        }
    }

    let circuitfn = args.get(3).unwrap();
    let inputsfn = args.get(4).unwrap();
    let wpfn = args.get(5).unwrap();

    let mut fh = File::open(inputsfn).unwrap();
    let mut bufh = Vec::new();
    fh.read_to_end(&mut bufh).unwrap();
    let mut fcs = File::open(circuitfn).unwrap();
    let mut bufcs = Vec::new();
    fcs.read_to_end(&mut bufcs).unwrap();
    let mut fw = File::open(wpfn).unwrap();
    let mut bufw = Vec::new();
    fw.read_to_end(&mut bufw).unwrap();

    if prove {
        let reader = R1csReader::new(&mut bufh, &mut bufcs, Some(&mut bufw));
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

            let mut verifier_transcript = Transcript::new(b"NIZK");
            assert!(proof.verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens).is_ok());

            (bincode::serialize(&proof).unwrap(), "nizk_proof")
        } else {
            let gens = r1cs.snark_public_params();
            // create a commitment to the R1CS instance
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

            let mut verifier_transcript = Transcript::new(b"SNARK");
            assert!(proof.verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens).is_ok());

            (bincode::serialize(&(comm, proof)).unwrap(), "snark_proof")
        };

        // write gzipped serialized data to file
        let pf_fh = File::create(format!("{}.gz", name)).unwrap();
        let mut pf_w = GzBuilder::new()
                .comment("ZKUnbound Proof Serialization")
                .write(pf_fh, Compression::best());
        pf_w.write_all(&pf_ser[..]).unwrap();
        pf_w.finish().unwrap();
    } else {
        let mut pf_r = GzDecoder::new(&bufw[..]);
        let mut buf = Vec::new();
        pf_r.read_to_end(&mut buf).unwrap();

        if nizk {
            let proof: NIZK = bincode::deserialize(&buf[..]).unwrap();
            let reader = R1csReader::new(&mut bufh, &mut bufcs, None);
            let r1cs = R1cs::from(reader);
            let mut aa: Vec<(usize, usize, [u8; 32])> = Vec::new();
            let mut bb: Vec<(usize, usize, [u8; 32])> = Vec::new();
            let mut cc: Vec<(usize, usize, [u8; 32])> = Vec::new();
            let inst = r1cs.instance(&mut aa, &mut bb, &mut cc);
            let assignment_inputs = r1cs.inputs_assignment();
            let gens = r1cs.nizk_public_params();

            let mut verifier_transcript = Transcript::new(b"NIZK");
            if !proof.verify(&inst, &assignment_inputs, &mut verifier_transcript, &gens).is_ok() {
                std::process::exit(ReturnValue::InvalidNIZKProof as i32);
            }
        } else {
            let (comm, proof): (ComputationCommitment, SNARK) = bincode::deserialize(&buf[..]).unwrap();
            let reader = R1csReader::new(&mut bufh, &mut bufcs, None);
            let r1cs = R1cs::from(reader);
            let assignment_inputs = r1cs.inputs_assignment();
            let gens = r1cs.snark_public_params();
            let mut verifier_transcript = Transcript::new(b"SNARK");
            if !proof.verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens).is_ok() {
                std::process::exit(ReturnValue::InvalidSNARKProof as i32);
            }
        }
    }
}
