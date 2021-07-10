spartan-pq-zkinterface
---------------------

This is a fork of the zkinterface adapter written for Spartan by Lef.
This fork is meant for Spartan PQ. It requires nightly because Spartan PQ
requires nightly.

# Limitation
This version cannot serialize the proof to a file (unlike the original adapter)
because Spartan PQ uses a polycommit that does not implement the trait Serialize
for a bunch of stuff... So that will need to be fixed if one wants to get
the proof into a file or over the network.

# Compile
Make sure you have Spartan (PQ padded branch) and Ligero polycommit.

Build using rust nightly. It's been tested with `rustc 1.54.0-nightly (f64503eb5 2021-05-23)`
and it is known not to work with the latest version of Rust because
of a dependency that no longer compiles (not our fault!).

```
RUSTFLAGS="-C target_cpu=native"
cargo build --release
```

# Usage

```
// This runs the prover only.
./target/release/spzk prove --nizk test/bls12-381scalar/add.zkif 
test/bls12-381scalar/add.inp.zkif test/bls12-381scalar/add.wit.zkif


// This runs the prover AND the verifier (which consumes and checks the proof)
./target/release/spzk verify --nizk test/bls12-381scalar/add.zkif 
test/bls12-381scalar/add.inp.zkif test/bls12-381scalar/add.wit.zkif
```

There are a few other R1CS examples in the folder `test/bls12-381scalar`.
Note that it is important to select R1CS examples that use the exact
prime that Spartan PQ is configured to use.
