# Z9 performance evaluation results

## Decision and environment

**Decision: PASS WITH OBSERVATIONS.** Reproducible local measurements were
completed for the legacy interval circuits, Z6 Core, Z7 Hardened, isolated
Merkle/policy components, and the local witness/prove/verify pipeline. Component
variants are explicitly not full Z7 circuits; isolated signature overhead is
not claimed.

Measured 2026-10-04 on Ubuntu 24.04.5, Linux kernel 6.17.0-1032-oem,
linux/amd64; AMD Ryzen 7 PRO 8840HS, 8 cores / 16 threads, 27 GiB RAM;
GOMAXPROCS=16. Core and Hardened used Go 1.25.8, gnark 0.16.3,
gnark-crypto 0.21.0. Legacy used the installed Go 1.22.2, gnark 0.9.1, and
gnark-crypto v0.12.2-0.20231013160410-1f65e75b6dfb. Modules used their pinned
go.mod versions. Go caches were set to dedicated `/tmp/healthclaim-z9-*`
directories.

The benchmarked source checkout base commit was
`ee4df56b09ea7f0abbe66f31a8e6e429ec401a0f` (Z8 commit); the Z9 harness and
legacy benchmark test were uncommitted working-tree additions at benchmark
time and are preserved in the separate Z9 commit. The raw run log records the
base commit and exact dirty state: [`results/z9-benchmark-output.txt`](results/z9-benchmark-output.txt).

## Methodology

Core, Hardened, and each legacy interval benchmark used `-count=10`,
`-benchtime=10x`, `-benchmem`; these are 10 independent benchmark-process
samples, each averaging 10 timed operations. Component variants used five
independent samples with five timed operations. Compile and Groth16 setup were
timed separately over three one-operation samples. Circuit compilation,
Groth16 setup, witness generation, and a warm-up proof/verification were
outside the timed prove/verify loops. Witness construction and a complete
local witness -> prove -> verify loop were measured separately with 10 samples
of 10 operations each.

Means, medians, sample standard deviations, and nearest-rank P95 are computed
across independent Go benchmark samples. With 10 samples, P95 is the maximum
sample; with 5 samples, it is likewise the maximum. Values are local to this
host and are not paper results. No CPU-frequency, temperature, GC trace, or
system-wide scheduler instrumentation was collected.

## E1: legacy baseline

The legacy module proves two numeric interval predicates, not an authority-
signed healthcare claim. AgeRange proves `MinAge <= Age <= MaxAge`;
DiagnosisCategory proves `CategoryMin <= DiagnosisCode <= CategoryMax`.
Each compiled to 3,754 constraints, 2 public inputs, 1 private input, and a
164-byte Groth16 proof. They are not equivalent to Core or Hardened.

| Circuit / operation | Mean | Median | SD | P95 | B/op | allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| AgeRange prove | 8.781 ms | 8.645 ms | 0.509 ms | 10.077 ms | 1,840,438 | 1,638.5 |
| AgeRange verify | 0.678 ms | 0.671 ms | 0.047 ms | 0.767 ms | 29,000 | 156.4 |
| DiagnosisCategory prove | 8.638 ms | 8.580 ms | 0.198 ms | 9.131 ms | 1,839,602 | 1,634.1 |
| DiagnosisCategory verify | 0.687 ms | 0.686 ms | 0.048 ms | 0.790 ms | 28,816 | 156.0 |

## E2/E3: Core and Hardened complete circuits

Core compiled to 19,657 constraints, 6 public variables, 31 private variables;
Hardened compiled to 22,021 constraints, 13 public variables, 31 private
variables. Both serialized to 164 bytes. Core proof size was measured by the
separate metadata/proof round-trip test. In both existing production benchmark
modules, setup and witness construction are excluded from prove/verify timing.

| Circuit / operation | Mean | Median | SD | P95 | B/op | allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| Core prove | 65.811 ms | 65.108 ms | 2.632 ms | 72.338 ms | 21,151,356 | 2,602.8 |
| Core verify | 0.708 ms | 0.717 ms | 0.037 ms | 0.752 ms | 30,496 | 165.1 |
| Hardened prove | 73.575 ms | 73.494 ms | 1.008 ms | 75.972 ms | 21,689,935 | 2,605.2 |
| Hardened verify | 0.693 ms | 0.698 ms | 0.030 ms | 0.726 ms | 32,024 | 180.3 |

| Metric | Core | Hardened | Absolute difference | Relative change vs Core |
|---|---:|---:|---:|---:|
| Constraints | 19,657 | 22,021 | +2,364 | +12.02% |
| Public variables | 6 | 13 | +7 | +116.67% |
| Private variables | 31 | 31 | 0 | 0% |
| Proof generation mean | 65.811 ms | 73.575 ms | +7.764 ms | +11.80% |
| Verification mean | 0.708 ms | 0.693 ms | -0.015 ms | -2.12% |
| Proof size | 164 bytes | 164 bytes | 0 bytes | 0% |
| Generation bytes/op | 21,151,356 | 21,689,935 | +538,579 | +2.55% |
| Generation allocs/op | 2,602.8 | 2,605.2 | +2.4 | +0.09% |
| Verification bytes/op | 30,496 | 32,024 | +1,528 | +5.01% |
| Verification allocs/op | 165.1 | 180.3 | +15.2 | +9.21% |

Core's P95 proving sample is higher than its median, showing a measurable
outlier; Hardened proof generation was more tightly grouped in this run.
Verification medians are close. The apparent negative mean verification
difference is within sub-millisecond run variability and should not be
interpreted as a Hardened speed improvement.

## Separate compilation and setup costs

| Circuit stage | Mean | Median | SD | P95 | B/op | allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| Core compile | 70.153 ms | 69.792 ms | 1.155 ms | 71.445 ms | 103,924,957 | 549,827 |
| Hardened compile | 73.421 ms | 72.545 ms | 2.701 ms | 76.451 ms | 109,236,883 | 595,870 |
| Core Groth16 setup | 650.110 ms | 648.977 ms | 13.030 ms | 663.669 ms | 35,111,813 | 580 |
| Hardened Groth16 setup | 735.778 ms | 725.138 ms | 27.449 ms | 766.954 ms | 37,380,752 | 523 |

Setup/compile samples are only three one-operation runs; their P95 is the
maximum and is descriptive rather than a high-confidence tail estimate.

## E4: Merkle-depth scaling (isolated component circuits)

These variants measure only Poseidon2 path hashing, Boolean selectors, and
root equality. They omit record hashing, EdDSA, nullifier, policy, and context
gadgets. Each has 1 public variable; private variables are `1 + 2*depth`.

| Depth | Constraints | Private vars | Prove mean / median / SD / P95 | Verify mean / median / SD / P95 | Prove B/op / allocs | Verify B/op / allocs | Proof |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 1,501 | 9 | 11.865 / 11.880 / 0.076 / 11.932 ms | 0.643 / 0.652 / 0.045 / 0.682 ms | 1,006,020 / 1,947 | 29,697 / 155 | 164 B |
| 8 | 3,001 | 17 | 21.438 / 21.024 / 1.000 / 23.186 ms | 0.658 / 0.622 / 0.066 / 0.758 ms | 1,792,361 / 2,357 | 29,464 / 155 | 164 B |
| 16 | 6,001 | 33 | 33.790 / 32.655 / 2.725 / 38.410 ms | 0.674 / 0.684 / 0.028 / 0.697 ms | 3,202,291 / 2,419 | 29,464 / 155 | 164 B |

Constraint growth is almost exactly linear in depth (about 1,500 added
constraints per four levels). Proving time rises with depth; verification
remains roughly flat because the public-input count and proof system are fixed.

## E5: policy-size scaling (isolated component circuits)

These variants measure policy Poseidon2 commitment, diagnosis membership, and
the lab min/max check. They omit 64-bit range decomposition, coverage ceiling,
claim amount, record signature/path, and context binding. Each has one public
input and `size + 5` private variables.

| Entries | Constraints | Private vars | Prove mean / median / SD / P95 | Verify mean / median / SD / P95 | Prove B/op / allocs | Verify B/op / allocs | Proof |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 2,776 | 9 | 14.887 / 14.695 / 0.487 / 15.753 ms | 0.650 / 0.637 / 0.040 / 0.719 ms | 1,651,733 / 2,453 | 29,464 / 155 | 164 B |
| 8 | 3,528 | 13 | 17.895 / 17.780 / 0.341 / 18.463 ms | 0.630 / 0.634 / 0.028 / 0.664 ms | 1,843,557 / 2,487 | 29,464 / 155 | 164 B |
| 16 | 5,032 | 21 | 27.342 / 25.212 / 5.235 / 36.676 ms | 0.697 / 0.701 / 0.061 / 0.786 ms | 2,884,728 / 2,636 | 29,464 / 155 | 164 B |
| 32 | 8,040 | 37 | 35.262 / 34.736 / 1.532 / 37.743 ms | 0.707 / 0.720 / 0.034 / 0.744 ms | 3,603,213 / 2,806 | 29,786 / 156 | 164 B |

Constraint and proving cost rise with the fixed-size diagnosis set. Verification
is near-constant because the one public input remains unchanged. The 16-entry
proving run has a high outlier (36.676 ms P95 versus 25.212 ms median); system
profiling did not identify whether scheduling, garbage collection, or cache
effects caused it.

## E6/E7: context and witness complexity

The complete Z6-to-Z7 comparison is the aggregate impact of the additional
context/version relation and public interface: +2,364 constraints, +7 public
inputs, +7.764 ms mean proving latency, approximately unchanged mean
verification latency, unchanged 31 private variables, and unchanged 164-byte
proof size. It does not causally isolate each of the seven context fields.

Merkle and policy component trends are measured in E4/E5. Signed-record
verification, context hashing, and their pairwise interactions are present in
both complete circuits, but signature-only cost was **NOT EXECUTED**: an
artificial isolated signature circuit would not represent its composition
with the record and claim relation. No independent claim is made about the
standalone signature cost.

## E8/E9: repeatability and local end-to-end pipeline

| Operation | Mean | Median | SD | P95 | B/op | allocs/op |
|---|---:|---:|---:|---:|---:|---:|
| Native witness/record construction | 0.339 ms | 0.335 ms | 0.038 ms | 0.405 ms | 18,402 | 524 |
| Full local witness -> prove -> verify | 76.320 ms | 76.001 ms | 1.380 ms | 79.179 ms | 21,740,249 | 3,312 |

The pipeline uses a fixed synthetic record, signing key, Merkle path, policy,
and context. It includes native record/policy/context construction, signing,
witness encoding, proof generation, and verification. Circuit compilation and
Groth16 setup are excluded. No Gateway, Fabric, network, Docker, IPFS, or
federated-learning latency is included.

## Limits and reproducibility

The main full-circuit averages use ten process samples; component experiments
use five, and setup/compile use three. These counts support local comparison,
not population-level tail claims. The P95 is a nearest-rank statistic and
therefore equals the maximum observed value at these sample sizes. Bytes/op
and allocation counts are Go benchmark measurements; no peak resident memory
or GC trace was collected. The Go runtime reported 16 benchmark workers from
`GOMAXPROCS=16`.

To reproduce, run `GOMAXPROCS=16 ./zkp/z9bench/run.sh` from repository root.
The script records raw output, working-tree status, module versions, and
explicit cache paths. The z9bench module uses local `replace` directives for
the repository's Core and Hardened modules, so `go mod verify` reports no
ziphash for those local replacements; the underlying Core and Hardened modules
were independently downloaded/verified and use their committed go.sum files.

## Z9 decision

**PASS WITH OBSERVATIONS.** The required full-circuit and local pipeline
measurements were completed, alongside isolated, clearly scoped Merkle and
policy variants. The measurements are reproducible on the recorded toolchain
and hardware. Main observations are measurable proving/setup overhead from
Hardened context binding, linear parameterized constraint/proving growth, and
small-sample outliers in the Core and 16-entry policy proving runs. This
evaluation does not establish production performance, distributed latency,
or an isolated signature cost.
