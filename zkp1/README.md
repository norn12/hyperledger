# ZKP Experiment 1 — Naive C++ Circuit Models

This folder is a completely separate educational experiment from `zkp/`.

The goal is to understand the eight planned insurance ZKP statements **before** implementing them with a real proving system such as gnark/Groth16.

## Important limitation

These programs are **not zero-knowledge proofs**. They are naive C++ models of the statements that a future ZKP circuit would enforce. They directly inspect the secret input and return `true` or `false`.

They deliberately use only the C++ standard library so the logic is easy to read and experiment with.

## The eight experiments

1. `01_policy_validity` — combine several policy rules into one claim-validity decision.
2. `02_diagnosis_membership` — demonstrate Merkle-set membership for a hidden diagnosis.
3. `03_treatment_membership` — demonstrate Merkle-set membership for a covered treatment/procedure.
4. `04_claim_amount` — prove a numeric amount satisfies minimum/maximum policy limits.
5. `05_waiting_period` — prove that a required waiting period has elapsed.
6. `06_medical_history` — prove a simple property over a private medical-history set.
7. `07_age_range` — prove that a secret age lies inside a policy range.
8. `08_patient_claim_binding` — bind patient, policy, claim, and nonce into one context value.

## Suggested learning order

Start with:

```text
07_age_range
        ↓
04_claim_amount
        ↓
05_waiting_period
        ↓
02_diagnosis_membership
        ↓
03_treatment_membership
        ↓
06_medical_history
        ↓
08_patient_claim_binding
        ↓
01_policy_validity
```

## Build

From this directory:

```bash
cmake -S . -B build
cmake --build build
```

Run an experiment, for example:

```bash
./build/age_range
./build/diagnosis_membership
```

On some systems the executables may be under `build/Debug/` or another configuration-specific directory.

## How to read each experiment

Each subdirectory contains:

- `main.cpp` — fully commented naive implementation.
- `README.md` — explanation of the statement, inputs, algorithm, example, and what a future real ZKP circuit would change.

The files intentionally keep the terminology close to the planned `zkp/README.md`, while remaining independent from the production project code.
