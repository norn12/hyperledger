# 07 Age Range

## Goal
Model: **the patient's private age is within the insurer's allowed range**.

## Naive statement
```text
minAge <= age <= maxAge
```

## Inputs
- Private: age.
- Policy-controlled: minimum and maximum age.

## ZKP interpretation
The real circuit would encode the inequalities as constraints. The policy bounds must be authenticated by the insurer rather than freely selected by the prover.

## Why this matters
This experiment is intentionally similar to the current repository circuit so the conceptual difference between a naive check and a policy-bound ZKP can be studied.
