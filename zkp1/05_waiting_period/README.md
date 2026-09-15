# 05 Waiting Period

## Goal
Model: **the required waiting period has elapsed before treatment/claim eligibility**.

## Naive statement
```text
treatmentDate - policyStartDate >= waitingDays
```

## Implementation
The example parses two ISO dates and computes the elapsed day count.

## ZKP interpretation
A real circuit should use a circuit-friendly date representation, usually numeric day counters or another fixed representation, rather than ordinary C++ date parsing. Relevant dates can be private while the required waiting-period rule is public/authenticated.

## Limitation
The standard-library date calculation is only a conceptual model and is not a ZKP circuit.
