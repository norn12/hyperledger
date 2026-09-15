# 02 Diagnosis Membership

## Goal
Model: **the patient's diagnosis belongs to the insurer's approved diagnosis set**.

## Naive implementation
The example keeps a vector of covered diagnoses and directly searches it.

It also constructs a small Merkle root to demonstrate how a set can be represented by one root.

## Important
The demo hash uses C++ `std::hash` only to keep the example dependency-free. It is **not cryptographic** and must not be used for a real Merkle tree or ZKP.

## ZKP interpretation
Private witness:
- diagnosis
- Merkle authentication path
- path direction information

Public input:
- approved diagnosis-set root

The real circuit would recompute the root from the hidden diagnosis and hidden path and constrain it to equal the public root.

## Why membership?
Diagnosis codes are naturally a set-membership problem, not simply a numeric range problem.
