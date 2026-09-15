# 03 Treatment Membership

## Goal
Model: **the patient's treatment/procedure belongs to the policy's covered treatment set**.

## Naive implementation
The example directly searches a vector of covered procedures and separately constructs a demonstration Merkle root.

## ZKP interpretation
Private witness:
- treatment code/value
- Merkle path
- path directions

Public input:
- covered-treatment Merkle root

A real circuit would prove that the hidden treatment reconstructs the published root.

## Limitation
The demo is educational only. The placeholder hash is not cryptographically secure.
