# Z9 performance experiments

This directory contains reproducible, benchmark-only harnesses. It does not
change HealthClaimCore or HealthClaimHardened circuit code or semantics.

Run all Z9 experiments from the repository root:

```sh
GOMAXPROCS=16 ./zkp/z9bench/run.sh
```

The script captures the raw output in
`zkp/z9bench/results/z9-benchmark-output.txt`, including OS/kernel, CPU/RAM,
toolchain and module versions, commit, and working-tree state. It uses explicit
temporary Go caches under `/tmp`. Core, Hardened, and legacy full-circuit
benchmarks use 10 independent Go benchmark runs with 10 timed operations per
run. The isolated parameterized component benchmarks use 5 independent runs
with 5 operations each. Setup, compilation, and the one warm-up proof are
outside timed proof-generation and verification loops. Separate compile and
Groth16 setup benchmarks report those costs independently, with 3 one-operation
repeats.

`scaling_test.go` measures isolated circuits only: a Poseidon2 Merkle path
with Boolean selectors (depth 4/8/16), and a Poseidon2 policy commitment,
diagnosis membership, and lab interval (set size 4/8/16/32). These variants
report their own constraints, variables, proof sizes, proving and verification
latency, bytes, and allocations. They omit other Z7 gadgets and must not be
reported as full HealthClaimHardened scaling results. Fixed public-input
verification cost and 164-byte Groth16 proof size are expected to remain
nearly flat in these variants.

`pipeline_test.go` times native record/policy/context construction, authority
signing, Merkle root/nullifier construction, and witness encoding. Its full
pipeline benchmark measures that local witness construction followed by
Groth16 proof generation and verification; it excludes compile/setup. It uses
the deterministic synthetic fixture and a fixed in-memory key. No network,
Gateway, Fabric, Docker, IPFS, or federated-learning work is included.

The legacy benchmark measures the two existing interval predicates only:
AgeRange proves `MinAge <= Age <= MaxAge`, and DiagnosisCategory proves
`CategoryMin <= DiagnosisCode <= CategoryMax`. Those are not equivalent to
Core/Hardened claims.

E6 is an aggregate comparison of existing Z6 and Z7 complete circuits. It
does not isolate the cost of each context field independently. E7 uses the
Merkle and policy component experiments for those measurable components;
signature-only isolated cost is not measured because an artificial partial
signature circuit would not represent its composition within the claim
relation.
