# 08 Patient Claim Binding

## Goal
Model: **a proof must belong to the intended patient, policy, claim, and fresh context**.

## Naive statement
Create a deterministic context value from:
```text
patient commitment + policy ID + claim ID + nonce
```

Changing any field should change the resulting binding.

## ZKP interpretation
The future circuit would constrain the proof to the intended public context. A fresh nonce can help prevent replay of a proof in another authorization request.

## Limitation
The example uses `std::hash`, which is not cryptographically secure. A production system requires a cryptographic hash/commitment construction suitable for the selected proving system.
