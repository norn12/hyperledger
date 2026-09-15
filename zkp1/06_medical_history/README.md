# 06 Medical History

## Goal
Model a narrow policy property over medical history instead of placing an entire EHR into a circuit.

## Example
The policy excludes a condition such as `heart_failure`. The private history is represented as a set, and the naive program checks that the excluded condition is absent.

## ZKP interpretation
A production circuit would operate on an authenticated commitment or suitable membership/non-membership structure. The proof should establish only the required property, not expose the complete medical history.

## Important research issue
Non-membership proofs and authenticated medical records require careful cryptographic design. This example is intentionally simple and is not a production solution.
