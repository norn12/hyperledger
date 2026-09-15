# 01 Policy Validity

## Goal
Model the statement: **all required rules of an insurance policy are satisfied by the claim**.

## Naive inputs
- `Policy`: minimum/maximum age, maximum claim amount, waiting period.
- `Claim`: age, claim amount, elapsed days.

## Logic
```text
age >= minAge
age <= maxAge
claimAmount <= maxClaimAmount
daysSincePolicyStart >= waitingDays
```
All must be true.

## ZKP interpretation
The claim fields would become private witness values. Policy identifiers and authenticated policy commitments would be public inputs. A real circuit would prove existence of private values satisfying the policy constraints.

## Limitation
This C++ program directly sees the claim and returns a boolean. It is not a ZKP and does not provide privacy.
