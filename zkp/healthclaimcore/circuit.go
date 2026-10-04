// Package healthclaimcore implements the isolated HealthClaimCore Groth16 circuit.
package healthclaimcore

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	cryptote "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	stdedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// MerkleDepth and DiagnosisSetSize are fixed circuit parameters in Core v1.
const (
	MerkleDepth      = 8
	DiagnosisSetSize = 4
	RangeBits        = 64
)

// HealthClaimCore proves a valid authority-issued record is registered and
// satisfies the committed policy. The public fields are deliberately limited
// to the registry/policy roots, claim amount, authority key, and nullifier.
type HealthClaimCore struct {
	RegistryRoot     frontend.Variable `gnark:",public"`
	PolicyCommitment frontend.Variable `gnark:",public"`
	ClaimAmount      frontend.Variable `gnark:",public"`
	AuthorityKeyX    frontend.Variable `gnark:",public"`
	AuthorityKeyY    frontend.Variable `gnark:",public"`
	Nullifier        frontend.Variable `gnark:",public"`

	Diagnosis        frontend.Variable
	LabValue         frontend.Variable
	PolicyID         frontend.Variable
	CoverageCeiling  frontend.Variable
	PatientSecret    frontend.Variable
	LabMin           frontend.Variable
	LabMax           frontend.Variable
	PolicyMaxClaim   frontend.Variable
	CoveredDiagnosis [DiagnosisSetSize]frontend.Variable
	Signature        eddsa.Signature
	MerkleSiblings   [MerkleDepth]frontend.Variable
	MerkleDirections [MerkleDepth]frontend.Variable
}

func poseidonHash(api frontend.API, values ...frontend.Variable) (frontend.Variable, error) {
	h, err := poseidon2.New(api)
	if err != nil {
		return nil, err
	}
	h.Write(values...)
	return h.Sum(), nil
}

func (c *HealthClaimCore) Define(api frontend.API) error {
	// The fixed-width policy and claim values prevent field-wraparound attacks.
	api.ToBinary(c.Diagnosis, 64)
	api.ToBinary(c.LabValue, RangeBits)
	api.ToBinary(c.PolicyID, 64)
	api.ToBinary(c.CoverageCeiling, RangeBits)
	api.ToBinary(c.ClaimAmount, RangeBits)
	api.ToBinary(c.LabMin, RangeBits)
	api.ToBinary(c.LabMax, RangeBits)
	api.ToBinary(c.PolicyMaxClaim, RangeBits)
	for _, diagnosis := range c.CoveredDiagnosis {
		api.ToBinary(diagnosis, 64)
	}

	keyCommitment, err := poseidonHash(api, domainSecret, c.PatientSecret)
	if err != nil {
		return err
	}
	leaf, err := poseidonHash(api, domainRecord, c.Diagnosis, c.LabValue, c.PolicyID, c.CoverageCeiling, keyCommitment)
	if err != nil {
		return err
	}
	policyValues := []frontend.Variable{domainPolicy, c.PolicyID, c.LabMin, c.LabMax, c.PolicyMaxClaim}
	policyValues = append(policyValues, c.CoveredDiagnosis[:]...)
	policyCommitment, err := poseidonHash(api, policyValues...)
	if err != nil {
		return err
	}
	api.AssertIsEqual(policyCommitment, c.PolicyCommitment)

	// EdDSA over the committed leaf using MiMC as the signature challenge hash.
	curve, err := stdedwards.NewEdCurve(api, cryptote.BN254)
	if err != nil {
		return fmt.Errorf("edwards curve: %w", err)
	}
	hSig, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("signature hash: %w", err)
	}
	issuerKey := eddsa.PublicKey{A: stdedwards.Point{X: c.AuthorityKeyX, Y: c.AuthorityKeyY}}
	if err := eddsa.Verify(curve, c.Signature, leaf, issuerKey, &hSig); err != nil {
		return fmt.Errorf("authority signature: %w", err)
	}

	// Merkle selectors are explicitly Boolean. A selector chooses left/right
	// ordering at each level; it also encodes the record index used by nullifier.
	index := frontend.Variable(0)
	current := leaf
	for level := 0; level < MerkleDepth; level++ {
		direction := c.MerkleDirections[level]
		api.AssertIsBoolean(direction)
		index = api.Add(index, api.Mul(direction, 1<<level))
		left := api.Select(direction, c.MerkleSiblings[level], current)
		right := api.Select(direction, current, c.MerkleSiblings[level])
		current, err = poseidonHash(api, domainMerkle, left, right)
		if err != nil {
			return err
		}
	}
	api.AssertIsEqual(current, c.RegistryRoot)

	// Diagnosis membership in the policy-committed fixed-size set.
	selectors := make([]frontend.Variable, DiagnosisSetSize)
	for i := range selectors {
		selectors[i] = api.IsZero(api.Sub(c.Diagnosis, c.CoveredDiagnosis[i]))
		api.AssertIsBoolean(selectors[i])
	}
	api.AssertIsEqual(api.Add(api.Add(selectors[0], selectors[1]), api.Add(selectors[2], selectors[3])), 1)

	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.LabMin, c.LabValue), 1)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.LabValue, c.LabMax), 1)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.CoverageCeiling, c.PolicyMaxClaim), 1)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, c.ClaimAmount, c.CoverageCeiling), 1)

	secretCommitment, err := poseidonHash(api, domainNullifier, c.PatientSecret, index)
	if err != nil {
		return err
	}
	api.AssertIsEqual(secretCommitment, c.Nullifier)
	return nil
}

// Field returns the scalar field used by the circuit.
func Field() *big.Int { return ecc.BN254.ScalarField() }
