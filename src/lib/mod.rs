pub extern crate flatbuffers;

#[allow(warnings)]
pub mod zkinterface_generated;
use libspartan::{InputsAssignment, Instance, SNARKGens, VarsAssignment, NIZKGens};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use zkinterface_generated::zkinterface as fb;

#[derive(Debug)]
pub struct FlatError {
    details: String,
}

impl FlatError {
    fn new(msg: &str) -> FlatError {
        FlatError {
            details: msg.to_string(),
        }
    }
}

impl std::fmt::Display for FlatError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl std::error::Error for FlatError {
    fn description(&self) -> &str {
        &self.details
    }
}

//pub type Result<T> = std::result::Result<T, FlatError>;

impl From<std::io::Error> for FlatError {
    fn from(error: std::io::Error) -> Self {
        let msg = format!("{}", error);
        FlatError::new(&msg)
    }
}

#[derive(Debug)]
pub struct Variable {
    id: u64,
    value: [u8; 32],
}

#[derive(Debug)]
pub struct QEQ {
    a: Vec<Variable>,
    b: Vec<Variable>,
    c: Vec<Variable>,
}

#[derive(Debug)]
pub struct R1cs {
    inputs: Vec<Variable>,
    witness: Vec<Variable>,
    field_max: [u8; 32],
    constraints: Vec<QEQ>,
    non_zero_entries: usize,
    num_wit_vars: usize,
}

#[derive(Debug)]
pub struct R1csReader<'a> {
    header: fb::CircuitHeader<'a>,
    cs: fb::ConstraintSystem<'a>,
    witness: Option<fb::Witness<'a>>,
}

impl R1cs {
    pub fn inputs_assignment(&self) -> InputsAssignment {
        let mut inputs = Vec::with_capacity(self.inputs.len());
        for Variable { id: _, value } in &self.inputs {
            inputs.push(value.clone());
        }
        InputsAssignment::new(&inputs).unwrap()
    }

    pub fn vars_assignment(&self) -> VarsAssignment {
        let mut vars: Vec<[u8; 32]> = Vec::with_capacity(self.num_wit_vars);
        vars.resize_with(self.num_wit_vars, Default::default);
        for var in &self.witness {
            vars[var.id as usize].clone_from_slice(&var.value[..]);
        }
        VarsAssignment::new(&vars).unwrap()
    }

    pub fn instance(
        &self,
        aa: &mut Vec<(usize, usize, [u8; 32])>,
        bb: &mut Vec<(usize, usize, [u8; 32])>,
        cc: &mut Vec<(usize, usize, [u8; 32])>,
    ) -> Instance {
        for (i, QEQ { a, b, c }) in self.constraints.iter().enumerate() {
            for Variable { id, value } in a {
                aa.push((i, *id as usize, value.clone()));
            }
            for Variable { id, value } in b {
                bb.push((i, *id as usize, value.clone()));
            }
            for Variable { id, value } in c {
                cc.push((i, *id as usize, value.clone()));
            }
        }
        Instance::new(
            self.constraints.len(),
            self.num_wit_vars,
            self.inputs.len(),
            &aa,
            &bb,
            &cc,
        )
        .unwrap()
    }

    pub fn snark_public_params(&self) -> SNARKGens {
        SNARKGens::new(
            self.constraints.len(),
            self.num_wit_vars,
            self.inputs.len(),
            self.non_zero_entries,
        )
    }

    pub fn nizk_public_params(&self) -> NIZKGens {
        NIZKGens::new(
            self.constraints.len(),
            self.num_wit_vars,
            self.inputs.len()
        )
    }
}

impl<'a> R1csReader<'a> {
    pub fn new(
        circuit_header_buffer: &'a mut Vec<u8>,
        constraints_buffer: &'a mut Vec<u8>,
        witness_buffer: Option<&'a mut Vec<u8>>,
    ) -> Self {
        // Read circuit header, includes inputs
        let header = fb::get_root_as_root(circuit_header_buffer)
            .message_as_circuit_header()
            .ok_or(FlatError::new(
                "Input file is not a flatbuffer Circuit Header",
            ))
            .unwrap();

        // Read constraint system
        let cs = fb::get_root_as_root(constraints_buffer)
            .message_as_constraint_system()
            .ok_or(FlatError::new(
                "Input file is not a flatbuffer Constraint System",
            ))
            .unwrap();

        // Read witnesses
        let witness = witness_buffer.map(|witness_buffer| {
            fb::get_root_as_root(witness_buffer)
                .message_as_witness()
                .ok_or(FlatError::new("Input file is not a flatbuffer Witness"))
                .unwrap()
                .clone()
        });

        R1csReader {
            header,
            cs,
            witness,
        }
    }
}

// Helper to make [(k,v)] into Rust [(k',v')]
fn get_variables<'a>(fbvs: fb::Variables<'a>, discard: bool) -> Vec<Variable> {
    let var_ids = fbvs.variable_ids().unwrap();
    let values = fbvs.values().unwrap();
    let num_vars = var_ids.len();
    let mut vs = Vec::with_capacity(num_vars);
    if num_vars == 0 {
        return vs;
    }

    let ba_len = values.len() / num_vars;
    for i in 0..num_vars {
        let mut val = [0; 32];
        val[..ba_len].clone_from_slice(&values[i * ba_len..(i + 1) * ba_len]);
        if !discard || val.iter().any(|x| *x != 0) {
            let v = Variable {
                id: var_ids.get(i),
                value: val,
            };
            vs.push(v);
        }
    }
    vs
}

fn remap(vars: &mut Vec<Variable>, id_map: &mut HashMap<u64, u64>, n_inputs: usize) {
    for var in vars.iter_mut() {
        let new_id = match id_map.get(&var.id) {
            Some(&new_id) => new_id,
            None => {
                let new_id = if n_inputs == 0 {
                    // inputs are numbered from usize::MAX backwards
                    u64::MAX - id_map.len() as u64
                } else {
                    // witnesses are numbered from 0 forwards
                    (id_map.len() - n_inputs) as u64
                };
                id_map.insert(var.id, new_id);
                new_id
            }
        };
        var.id = new_id;
    }
}

fn remap_inputs(vars: &mut Vec<Variable>, num_inputs: u64, num_wit_vars: u64) {
    for var in vars.iter_mut() {
        if var.id > u64::MAX - num_inputs {
            let new_var_offset = u64::MAX - var.id;
            var.id = num_wit_vars + new_var_offset;
        }
    }
}

impl<'a> From<R1csReader<'a>> for R1cs {
    fn from(reader: R1csReader<'a>) -> R1cs {
        if reader.cs.constraints().unwrap().len() == 0 {
            panic!("No constraints given!");
        }

        // build variable mapping from constraint and input vectors
        let mut id_map = HashMap::<u64, u64>::new();
        id_map.insert(0, u64::MAX); // '0' is always the constant 1

        // first, remap the inputs, giving them temporary numbers
        let mut inputs = get_variables(reader.header.instance_variables().unwrap(), false);
        remap(&mut inputs, &mut id_map, 0);
        let input_keys = id_map.keys().cloned().collect::<HashSet<u64>>(); // including 0
        let num_inputs = input_keys.len();

        // now take a pass over the constraints, remapping all ids
        let reader_constraints = reader.cs.constraints().unwrap();
        let mut constraints = Vec::with_capacity(reader_constraints.len());
        let mut num_non_zero_a = 0;
        let mut num_non_zero_b = 0;
        let mut num_non_zero_c = 0;
        for ctr in reader_constraints {
            // get coeffs, discarding zero coeffs
            let mut a = get_variables(ctr.linear_combination_a().unwrap(), true);
            let mut b = get_variables(ctr.linear_combination_b().unwrap(), true);
            let mut c = get_variables(ctr.linear_combination_c().unwrap(), true);
            remap(&mut a, &mut id_map, num_inputs);
            remap(&mut b, &mut id_map, num_inputs);
            remap(&mut c, &mut id_map, num_inputs);
            num_non_zero_a += a.len();
            num_non_zero_b += b.len();
            num_non_zero_c += c.len();
            constraints.push(QEQ { a, b, c });
        }
        let non_zero_entries = max(num_non_zero_a, max(num_non_zero_b, num_non_zero_c));
        let num_wit_vars = id_map.len() - num_inputs;

        // remove temporary input mappings from id_map
        input_keys.iter().for_each(|x| { id_map.remove(x); });
        assert_eq!(id_map.len(), num_wit_vars);

        // remap input variables from temporary to final numbering
        remap_inputs(&mut inputs, num_inputs as u64, num_wit_vars as u64);
        for ctr in constraints.iter_mut() {
            remap_inputs(&mut ctr.a, num_inputs as u64, num_wit_vars as u64);
            remap_inputs(&mut ctr.b, num_inputs as u64, num_wit_vars as u64);
            remap_inputs(&mut ctr.c, num_inputs as u64, num_wit_vars as u64);
        }

        // finally, remap witness variables if any were supplied
        let witness = match reader.witness {
            None => Vec::new(),
            Some(witness) => {
                let mut ws = get_variables(witness.assigned_variables().unwrap(), false);
                ws.retain(|w| {
                    let is_input = input_keys.contains(&w.id);
                    let is_fresh = !id_map.contains_key(&w.id);
                    // get rid of variables that are inputs or don't appear in the constraints
                    !(is_input || is_fresh)
                });
                remap(&mut ws, &mut id_map, num_inputs);
                assert_eq!(ws.len(), num_wit_vars);
                ws
            }
        };

        let mut field_max = [0u8; 32];
        field_max.clone_from_slice(reader.header.field_maximum().unwrap());

        R1cs {
            inputs,
            witness,
            field_max,
            constraints,
            non_zero_entries,
            num_wit_vars,
        }
    }
}

// TESTS
#[cfg(test)]
fn run_e2e(circuit: &str, header: &str, witness: &str) {
    use libspartan::SNARK;
    use merlin::Transcript;
    use std::fs::File;
    use std::io::Read;

    // Read files into buffers
    let mut fh = File::open(header).unwrap();
    let mut bufh = Vec::new();
    fh.read_to_end(&mut bufh).unwrap();
    let mut fcs = File::open(circuit).unwrap();
    let mut bufcs = Vec::new();
    fcs.read_to_end(&mut bufcs).unwrap();
    let mut fw = File::open(witness).unwrap();
    let mut bufw = Vec::new();
    fw.read_to_end(&mut bufw).unwrap();

    // Initialize R1csReader
    let reader = R1csReader::new(&mut bufh, &mut bufcs, &mut bufw);
    let r1cs = R1cs::from(reader);

    // We will encode the above constraints into three matrices, where
    // the coefficients in the matrix are in the little-endian byte order
    let mut A: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut B: Vec<(usize, usize, [u8; 32])> = Vec::new();
    let mut C: Vec<(usize, usize, [u8; 32])> = Vec::new();

    let inst = r1cs.instance(&mut A, &mut B, &mut C);
    let assignment_inputs = r1cs.inputs_assignment();
    let assignment_vars = r1cs.vars_assignment();

    // Check if instance is satisfiable
    let res = inst.is_sat(&assignment_vars, &assignment_inputs);
    assert!(res.unwrap(), "should be satisfied");

    // Crypto proof public params
    let gens = r1cs.snark_public_params();

    // create a commitment to the R1CS instance
    let (comm, decomm) = SNARK::encode(&inst, &gens);

    // produce a proof of satisfiability
    let mut prover_transcript = Transcript::new(b"snark_example");
    let proof = SNARK::prove(
        &inst,
        &decomm,
        assignment_vars,
        &assignment_inputs,
        &gens,
        &mut prover_transcript,
    );

    // verify the proof of satisfiability
    let mut verifier_transcript = Transcript::new(b"snark_example");
    assert!(proof
        .verify(&comm, &assignment_inputs, &mut verifier_transcript, &gens)
        .is_ok());
    println!("proof verification successful!");
}

#[test]
fn test_e2e_foo() {
    run_e2e("test/foo.zkif", "test/foo.inp.zkif", "test/foo.wit.zkif");
}


#[test]
fn test_e2e_add() {
    run_e2e("test/add.zkif", "test/add.inp.zkif", "test/add.wit.zkif");
}

#[test]
fn test_e2e_inv() {
    run_e2e("test/inv.zkif", "test/inv.inp.zkif", "test/inv.wit.zkif");
}
