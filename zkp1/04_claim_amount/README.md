# 04 Claim Amount

## Goal
Model: **the private claim amount satisfies the policy's allowed financial range**.

## Naive statement
```text
minimumAllowed <= claimAmount <= maximumAllowed
```

## ZKP interpretation
Private witness: exact claim amount.

Public inputs: policy financial bounds (or an authenticated policy commitment that fixes them).

The future ZKP would prove the inequality without exposing the witness value through the proof.

## Extension ideas
The same pattern can later model deductibles, annual limits, co-pay relations, and reimbursement formulas.

## Limitation
This program directly reads the amount, so it is not zero-knowledge.
