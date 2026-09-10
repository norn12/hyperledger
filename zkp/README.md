# ZeroTrustBlock — New ZKP Implementation

This document describes the planned redesign of the ZeroTrustBlock zero-knowledge proof layer. The implementation will remain focused on the existing **patient ↔ insurer** healthcare insurance workflow.

The goal is to build **real insurance verification circuits**, not demonstration-only examples. Circuit semantics, public/private inputs, commitments, security properties, and tests will be finalized before implementation.

---

## Planned ZKP Circuits

### 1. `PolicyValidityCircuit`

**Purpose:** Prove that a patient's private claim information satisfies the rules of a specific insurer policy.

**Description:** The insurer defines the policy and its public policy identifier/commitment. The patient uses private claim and medical attributes as the witness and proves that the required policy conditions are satisfied without revealing the underlying sensitive values.

---

### 2. `DiagnosisMembershipCircuit`

**Purpose:** Prove that the patient's diagnosis belongs to the set of diagnoses covered or permitted by the insurer's policy.

**Description:** The exact diagnosis remains private. The insurer provides a commitment or Merkle root representing the approved diagnosis set, and the proof demonstrates membership without revealing the diagnosis code.

---

### 3. `TreatmentMembershipCircuit`

**Purpose:** Prove that the treatment or medical procedure associated with a claim is covered by the policy.

**Description:** The treatment/procedure code remains private while the proof demonstrates membership in the policy's approved treatment set.

---

### 4. `ClaimAmountCircuit`

**Purpose:** Prove that a submitted claim amount satisfies the financial constraints of the insurance policy.

**Description:** The exact claim amount remains private while the proof establishes a policy-defined inequality or range, such as `claimAmount <= policyLimit`.

---

### 5. `WaitingPeriodCircuit`

**Purpose:** Prove that the required policy waiting period has been satisfied before a treatment or claim becomes eligible.

**Description:** Relevant dates remain private while the circuit proves the required relationship between policy activation and treatment/claim dates.

---

### 6. `MedicalHistoryCircuit`

**Purpose:** Prove that relevant medical-history conditions satisfy the policy requirements without exposing the patient's complete medical history.

**Description:** Medical history will be represented using commitments or authenticated structures so the circuit can prove a required condition, exclusion, or membership property without revealing the complete record.

---

### 7. `AgeRangeCircuit`

**Purpose:** Prove that the patient's age satisfies the eligibility range defined by the insurer's policy.

**Description:** The exact age remains private while the proof establishes the policy-bound lower and upper age constraints. The policy limits must be controlled by the insurer rather than freely selected by the prover.

---

### 8. `PatientClaimBinding`

**Purpose:** Bind a proof to the intended patient, policy, and claim so that a valid proof cannot simply be reused in another authorization context.

**Description:** The proof will bind private patient knowledge to public commitments or identifiers such as `patientCommitment`, `policyID`/policy commitment, `claimID`, and an appropriate freshness value or nonce.

---

## Planned Composition

The final implementation is intended to combine the appropriate primitives into a policy-bound insurance claim proof:

```text
Patient private data
        ↓
ZKP Prover
        ↓
Policy validity
+ Diagnosis membership
+ Treatment membership
+ Claim amount
+ Waiting period
+ Medical-history condition
+ Age condition
+ Patient/claim binding
        ↓
Proof π
        ↓
Insurer verifies against policy/claim public inputs
        ↓
VALID / INVALID
        ↓
Hyperledger Fabric records the authorization/audit result
```

The exact composition will be finalized after each individual circuit is specified and tested.

---

## Design Principles

- Keep sensitive healthcare and claim values private.
- Use **membership proofs** for diagnosis and treatment rather than treating diagnosis codes as arbitrary numeric ranges.
- Use **range/inequality proofs** where the underlying value is naturally numeric, such as age and claim amount.
- Bind proofs to the insurer's policy rather than allowing the prover to choose policy constraints.
- Use commitments/authenticated data structures instead of placing an entire EHR inside a circuit.
- Prevent proof replay and context swapping through patient, policy, claim, and freshness binding.
- Keep the current **Groth16 + BN254 + gnark** direction unless later evaluation shows a justified need to change the proving system.
- Test both valid and invalid real-world insurance claim scenarios.

---

## Reference Papers and Implementations

### Zheng, You & Hu (2022)
**A novel insurance claim blockchain scheme based on zero-knowledge proof technology**

Primary direct reference for the patient/insurer medical-insurance claim scenario, privacy-preserving insurance transactions, blockchain, and non-interactive zero-knowledge proofs.

### Sanober & Anwar (2026)
**Zero-Knowledge Proof Enabled Blockchain Smart Contracts for Efficient Health Insurance System**

Recent direct reference for health-insurance processing using ZK-SNARKs and smart contracts. Its implementation uses Polygon rather than Hyperledger Fabric, so it is a comparison/design reference rather than a direct architecture match.

### Bakare et al. (2025)
**Enhancing Privacy and Security in Blockchain-based Health Insurance Management System using Zero-Knowledge Proof**

Reference for privacy-preserving treatment, appointment, and billing verification in health insurance. The work describes a conceptual framework rather than a full production implementation.

### Harpocrates
**Privacy-Preserving and Immutable Audit Log for Sensitive Data Operations**

Reference for combining zero-knowledge proofs with Hyperledger Fabric while maintaining privacy and publicly verifiable validity of sensitive operations.

### PrivChain
**Provenance and Privacy Preservation in Blockchain-enabled Supply Chains**

Useful reference for zero-knowledge range proofs, commitments, and off-chain proof generation with blockchain verification. Although it is not healthcare-specific, its proof construction ideas are relevant to numeric claim constraints.

### ZKlaim

Implementation reference for privacy-preserving medical insurance claims. Relevant components include policy validity, amount-range checking, doctor attestation, deductible accumulation, category non-membership, and circuit composition.

---

## Implementation Status

**Current status: Design / specification phase.**

No new circuit implementation is being introduced by this document. The next step is to formally specify the first circuit's:

1. Public inputs
2. Private witness inputs
3. Exact statement being proved
4. Constraint logic
5. Commitment/set representation
6. Security assumptions
7. Positive and negative test cases

Implementation should begin only after these details are agreed upon.
