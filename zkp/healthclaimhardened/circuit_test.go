package healthclaimhardened

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cryptoed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	circuitedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test"
)

func bi(v int64) *big.Int { return big.NewInt(v) }

func deterministicAuthorityKey(t testing.TB) *cryptoed.PrivateKey {
	t.Helper()
	key, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func valueBigInt(v frontend.Variable) *big.Int {
	switch value := v.(type) {
	case *big.Int:
		return new(big.Int).Set(value)
	case big.Int:
		return new(big.Int).Set(&value)
	case int:
		return big.NewInt(int64(value))
	case int64:
		return big.NewInt(value)
	case uint64:
		return new(big.Int).SetUint64(value)
	default:
		panic(fmt.Sprintf("unexpected test witness value %T", v))
	}
}

func updateContextCommitment(t testing.TB, w *HealthClaimHardened) {
	t.Helper()
	ctx, err := ContextDigest(w.Challenge.(*big.Int), w.RecipientID.(*big.Int), w.DeploymentID.(*big.Int), w.PolicyVersion.(*big.Int), w.RootVersion.(*big.Int), w.PolicyCommitment.(*big.Int), w.RegistryRoot.(*big.Int), w.AuthorityKeyX.(*big.Int), w.AuthorityKeyY.(*big.Int), w.Nullifier.(*big.Int), w.ClaimAmount.(*big.Int))
	if err != nil {
		t.Fatal(err)
	}
	w.ContextCommitment = ctx
}

func fixture(t testing.TB) (*HealthClaimHardened, error) {
	t.Helper()
	key := deterministicAuthorityKey(t)
	diagnoses := [DiagnosisSetSize]*big.Int{bi(41), bi(9), bi(77), bi(103)}
	secret, diagnosis, lab, policyID, coverage := bi(999), bi(41), bi(6), bi(12), bi(1000)
	leaf := RecordLeaf(diagnosis, lab, policyID, coverage, SecretCommitment(secret))
	sigBytes, err := SignLeaf(key, leaf)
	if err != nil {
		return nil, err
	}
	var sig eddsa.Signature
	sig.Assign(twistededwards.BN254, sigBytes)
	var path MerklePath
	for i := 0; i < MerkleDepth; i++ {
		path.Siblings[i] = bi(int64(500 + i))
		path.Directions[i] = bi(int64((9 >> i) & 1))
	}
	index := IndexFromDirections(path)
	root := RootFromPath(leaf, path)
	policyCommitment := PolicyDigest(policyID, bi(3), bi(8), bi(1200), diagnoses)
	var pubX, pubY big.Int
	key.PublicKey.A.X.BigInt(&pubX)
	key.PublicKey.A.Y.BigInt(&pubY)
	challenge, recipient, deployment, policyVersion, rootVersion := bi(777), bi(12), bi(9), bi(3), bi(5)
	claimAmount, nullifier := bi(900), RecordNullifier(secret, index)
	context, err := ContextDigest(challenge, recipient, deployment, policyVersion, rootVersion, policyCommitment, root, &pubX, &pubY, nullifier, claimAmount)
	if err != nil {
		return nil, err
	}
	w := &HealthClaimHardened{
		RegistryRoot: root, RootVersion: rootVersion, PolicyCommitment: policyCommitment,
		PolicyVersion: policyVersion, ClaimAmount: claimAmount, AuthorityKeyX: &pubX,
		AuthorityKeyY: &pubY, Nullifier: nullifier, ProtocolDomain: ProtocolDomainID,
		Challenge: challenge, RecipientID: recipient, DeploymentID: deployment,
		ContextCommitment: context,
		Diagnosis:         diagnosis, LabValue: lab, PolicyID: policyID, CoverageCeiling: coverage,
		PatientSecret: secret, LabMin: bi(3), LabMax: bi(8), PolicyMaxClaim: bi(1200),
		CoveredDiagnosis: [DiagnosisSetSize]frontend.Variable{diagnoses[0], diagnoses[1], diagnoses[2], diagnoses[3]}, Signature: sig,
	}
	for i := 0; i < MerkleDepth; i++ {
		w.MerkleSiblings[i], w.MerkleDirections[i] = path.Siblings[i], path.Directions[i]
	}
	return w, nil
}

// resealWitness creates a fresh internally consistent synthetic statement for
// boundary tests. It never changes the production circuit or its relation.
func resealWitness(t testing.TB, w *HealthClaimHardened, key *cryptoed.PrivateKey) {
	t.Helper()
	diagnoses := [DiagnosisSetSize]*big.Int{}
	for i := range diagnoses {
		diagnoses[i] = valueBigInt(w.CoveredDiagnosis[i])
	}
	policyID, labMin, labMax := valueBigInt(w.PolicyID), valueBigInt(w.LabMin), valueBigInt(w.LabMax)
	policyMax, diagnosis := valueBigInt(w.PolicyMaxClaim), valueBigInt(w.Diagnosis)
	labValue, ceiling, secret := valueBigInt(w.LabValue), valueBigInt(w.CoverageCeiling), valueBigInt(w.PatientSecret)
	policyCommitment := PolicyDigest(policyID, labMin, labMax, policyMax, diagnoses)
	leaf := RecordLeaf(diagnosis, labValue, policyID, ceiling, SecretCommitment(secret))
	sigBytes, err := SignLeaf(key, leaf)
	if err != nil {
		t.Fatal(err)
	}
	var sig eddsa.Signature
	sig.Assign(twistededwards.BN254, sigBytes)
	var path MerklePath
	for i := 0; i < MerkleDepth; i++ {
		path.Siblings[i] = valueBigInt(w.MerkleSiblings[i])
		path.Directions[i] = valueBigInt(w.MerkleDirections[i])
	}
	var keyX, keyY big.Int
	key.PublicKey.A.X.BigInt(&keyX)
	key.PublicKey.A.Y.BigInt(&keyY)
	w.AuthorityKeyX, w.AuthorityKeyY = &keyX, &keyY
	w.PolicyCommitment = policyCommitment
	w.RegistryRoot = RootFromPath(leaf, path)
	w.Nullifier = RecordNullifier(secret, IndexFromDirections(path))
	w.Signature = sig
	w.ProtocolDomain = ProtocolDomainID
	updateContextCommitment(t, w)
}

func TestHardenedRelationAndCoreAdversarialWitnesses(t *testing.T) {
	assignment, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	circuit := &HealthClaimHardened{}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("valid hardened claim rejected: %v", err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("HealthClaimHardened: constraints=%d public_variables=%d secret_variables=%d", ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1, ccs.GetNbSecretVariables())
	t.Logf("vector root=%v root_version=%v policy=%v policy_version=%v claim=%v key=(%v,%v) nullifier=%v domain=%v challenge=%v recipient=%v deployment=%v context=%v", assignment.RegistryRoot, assignment.RootVersion, assignment.PolicyCommitment, assignment.PolicyVersion, assignment.ClaimAmount, assignment.AuthorityKeyX, assignment.AuthorityKeyY, assignment.Nullifier, assignment.ProtocolDomain, assignment.Challenge, assignment.RecipientID, assignment.DeploymentID, assignment.ContextCommitment)

	mutations := map[string]func(*HealthClaimHardened){
		"diagnosis not covered":                   func(w *HealthClaimHardened) { w.Diagnosis = 42 },
		"lab below minimum":                       func(w *HealthClaimHardened) { w.LabValue = 2 },
		"lab above maximum":                       func(w *HealthClaimHardened) { w.LabValue = 9 },
		"lab exceeds 64 bits":                     func(w *HealthClaimHardened) { w.LabValue = new(big.Int).Lsh(big.NewInt(1), 64) },
		"claim above coverage ceiling":            func(w *HealthClaimHardened) { w.ClaimAmount = 1001 },
		"claim exceeds 64 bits":                   func(w *HealthClaimHardened) { w.ClaimAmount = new(big.Int).Lsh(big.NewInt(1), 64) },
		"coverage ceiling exceeds policy maximum": func(w *HealthClaimHardened) { w.CoverageCeiling = 1201 },
		"coverage ceiling exceeds 64 bits":        func(w *HealthClaimHardened) { w.CoverageCeiling = new(big.Int).Lsh(big.NewInt(1), 64) },
		"invalid authority signature":             func(w *HealthClaimHardened) { w.Signature.S = bi(0) },
		"wrong authority public key":              func(w *HealthClaimHardened) { w.AuthorityKeyX = bi(123) },
		"wrong Merkle root":                       func(w *HealthClaimHardened) { w.RegistryRoot = bi(123456) },
		"wrong registry root path":                func(w *HealthClaimHardened) { w.MerkleSiblings[0] = bi(9000) },
		"non-Boolean Merkle direction":            func(w *HealthClaimHardened) { w.MerkleDirections[0] = bi(2) },
		"wrong nullifier":                         func(w *HealthClaimHardened) { w.Nullifier = bi(987654) },
		"wrong policy commitment":                 func(w *HealthClaimHardened) { w.PolicyCommitment = bi(123) },
		"wrong challenge":                         func(w *HealthClaimHardened) { w.Challenge = bi(778) },
		"wrong recipient":                         func(w *HealthClaimHardened) { w.RecipientID = bi(13) },
		"wrong domain":                            func(w *HealthClaimHardened) { w.ProtocolDomain = bi(999) },
		"wrong deployment context":                func(w *HealthClaimHardened) { w.DeploymentID = bi(10) },
		"wrong root version":                      func(w *HealthClaimHardened) { w.RootVersion = bi(6) },
		"wrong policy version":                    func(w *HealthClaimHardened) { w.PolicyVersion = bi(4) },
		"root version exceeds 64 bits":            func(w *HealthClaimHardened) { w.RootVersion = new(big.Int).Lsh(big.NewInt(1), 64) },
		"policy version exceeds 64 bits":          func(w *HealthClaimHardened) { w.PolicyVersion = new(big.Int).Lsh(big.NewInt(1), 64) },
		"wrong context digest":                    func(w *HealthClaimHardened) { w.ContextCommitment = bi(654321) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			w := *assignment
			mutate(&w)
			if err := test.IsSolved(circuit, &w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("mutated witness unexpectedly solved")
			}
		})
	}
}

func TestPrivateWitnessMutationMatrix(t *testing.T) {
	assignment, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*HealthClaimHardened){
		"diagnosis":           func(w *HealthClaimHardened) { w.Diagnosis = bi(42) },
		"lab value":           func(w *HealthClaimHardened) { w.LabValue = bi(7) },
		"policy ID":           func(w *HealthClaimHardened) { w.PolicyID = bi(13) },
		"coverage ceiling":    func(w *HealthClaimHardened) { w.CoverageCeiling = bi(999) },
		"patient secret":      func(w *HealthClaimHardened) { w.PatientSecret = bi(998) },
		"lab minimum":         func(w *HealthClaimHardened) { w.LabMin = bi(4) },
		"lab maximum":         func(w *HealthClaimHardened) { w.LabMax = bi(7) },
		"policy max claim":    func(w *HealthClaimHardened) { w.PolicyMaxClaim = bi(1199) },
		"covered diagnosis 0": func(w *HealthClaimHardened) { w.CoveredDiagnosis[0] = bi(40) },
		"covered diagnosis 1": func(w *HealthClaimHardened) { w.CoveredDiagnosis[1] = bi(10) },
		"covered diagnosis 2": func(w *HealthClaimHardened) { w.CoveredDiagnosis[2] = bi(78) },
		"covered diagnosis 3": func(w *HealthClaimHardened) { w.CoveredDiagnosis[3] = bi(104) },
		"signature R.X":       func(w *HealthClaimHardened) { w.Signature.R.X = bi(123) },
		"signature R.Y":       func(w *HealthClaimHardened) { w.Signature.R.Y = bi(124) },
		"signature S":         func(w *HealthClaimHardened) { w.Signature.S = bi(0) },
	}
	for i := 0; i < MerkleDepth; i++ {
		level := i
		mutations[fmt.Sprintf("Merkle sibling %d", level)] = func(w *HealthClaimHardened) { w.MerkleSiblings[level] = bi(int64(9000 + level)) }
		mutations[fmt.Sprintf("Merkle direction / derived index %d", level)] = func(w *HealthClaimHardened) {
			if valueBigInt(w.MerkleDirections[level]).Sign() == 0 {
				w.MerkleDirections[level] = bi(1)
			} else {
				w.MerkleDirections[level] = bi(0)
			}
		}
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			w := *assignment
			mutate(&w)
			if err := test.IsSolved(&HealthClaimHardened{}, &w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("private witness mutation preserved the public statement")
			}
		})
	}
}

func TestRecordNullifierStableAcrossRequestContext(t *testing.T) {
	first, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	second := *first
	second.Challenge = bi(778)
	second.RecipientID = bi(13)
	updateContextCommitment(t, &second)
	if valueBigInt(first.Nullifier).Cmp(valueBigInt(second.Nullifier)) != 0 {
		t.Fatal("same record produced different nullifiers for a new request")
	}
	if valueBigInt(first.ContextCommitment).Cmp(valueBigInt(second.ContextCommitment)) == 0 {
		t.Fatal("changed request context preserved the context commitment")
	}
	for _, assignment := range []*HealthClaimHardened{first, &second} {
		if err := test.IsSolved(&HealthClaimHardened{}, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("valid record/request witness rejected: %v", err)
		}
	}
}

func TestValidNumericAndPolicyBoundaries(t *testing.T) {
	key := deterministicAuthorityKey(t)
	base, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	valid := func(name string, mutate func(*HealthClaimHardened)) {
		t.Run(name, func(t *testing.T) {
			w := *base
			mutate(&w)
			resealWitness(t, &w, key)
			if err := test.IsSolved(&HealthClaimHardened{}, &w, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("valid boundary rejected: %v", err)
			}
		})
	}
	valid("lab equals minimum", func(w *HealthClaimHardened) { w.LabValue = bi(3) })
	valid("lab equals maximum", func(w *HealthClaimHardened) { w.LabValue = bi(8) })
	valid("claim equals coverage ceiling", func(w *HealthClaimHardened) { w.ClaimAmount = bi(1000) })
	valid("coverage equals policy maximum", func(w *HealthClaimHardened) { w.CoverageCeiling, w.PolicyMaxClaim = bi(1000), bi(1000) })
	for i := 0; i < DiagnosisSetSize; i++ {
		index := i
		valid(fmt.Sprintf("diagnosis matches covered entry %d", index), func(w *HealthClaimHardened) { w.Diagnosis = valueBigInt(w.CoveredDiagnosis[index]) })
	}
	valid("smallest valid 64-bit values including zero", func(w *HealthClaimHardened) {
		w.Diagnosis, w.LabValue, w.PolicyID, w.CoverageCeiling = bi(0), bi(0), bi(0), bi(0)
		w.PatientSecret, w.LabMin, w.LabMax, w.PolicyMaxClaim, w.ClaimAmount = bi(0), bi(0), bi(0), bi(0), bi(0)
		w.PolicyVersion, w.RootVersion = bi(0), bi(0)
		w.CoveredDiagnosis = [DiagnosisSetSize]frontend.Variable{bi(0), bi(1), bi(2), bi(3)}
	})
	valid("largest valid 64-bit values", func(w *HealthClaimHardened) {
		max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
		w.Diagnosis, w.LabValue, w.PolicyID, w.CoverageCeiling = max, max, max, max
		w.PatientSecret, w.LabMin, w.LabMax, w.PolicyMaxClaim, w.ClaimAmount = max, max, max, max, max
		w.PolicyVersion, w.RootVersion = new(big.Int).Set(max), new(big.Int).Set(max)
		w.CoveredDiagnosis = [DiagnosisSetSize]frontend.Variable{new(big.Int).Set(max), bi(0), bi(1), bi(2)}
	})
}

func TestNegativeAndOverflowRangeInputsRejected(t *testing.T) {
	base, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*HealthClaimHardened){
		"negative diagnosis":                func(w *HealthClaimHardened) { w.Diagnosis = bi(-1) },
		"negative lab value":                func(w *HealthClaimHardened) { w.LabValue = bi(-1) },
		"negative policy ID":                func(w *HealthClaimHardened) { w.PolicyID = bi(-1) },
		"negative coverage ceiling":         func(w *HealthClaimHardened) { w.CoverageCeiling = bi(-1) },
		"negative claim":                    func(w *HealthClaimHardened) { w.ClaimAmount = bi(-1) },
		"negative lab minimum":              func(w *HealthClaimHardened) { w.LabMin = bi(-1) },
		"negative lab maximum":              func(w *HealthClaimHardened) { w.LabMax = bi(-1) },
		"negative policy maximum":           func(w *HealthClaimHardened) { w.PolicyMaxClaim = bi(-1) },
		"negative covered diagnosis":        func(w *HealthClaimHardened) { w.CoveredDiagnosis[0] = bi(-1) },
		"negative root version":             func(w *HealthClaimHardened) { w.RootVersion = bi(-1) },
		"negative policy version":           func(w *HealthClaimHardened) { w.PolicyVersion = bi(-1) },
		"diagnosis exceeds 64 bits":         func(w *HealthClaimHardened) { w.Diagnosis = new(big.Int).Lsh(big.NewInt(1), 64) },
		"policy ID exceeds 64 bits":         func(w *HealthClaimHardened) { w.PolicyID = new(big.Int).Lsh(big.NewInt(1), 64) },
		"lab minimum exceeds 64 bits":       func(w *HealthClaimHardened) { w.LabMin = new(big.Int).Lsh(big.NewInt(1), 64) },
		"lab maximum exceeds 64 bits":       func(w *HealthClaimHardened) { w.LabMax = new(big.Int).Lsh(big.NewInt(1), 64) },
		"policy maximum exceeds 64 bits":    func(w *HealthClaimHardened) { w.PolicyMaxClaim = new(big.Int).Lsh(big.NewInt(1), 64) },
		"covered diagnosis exceeds 64 bits": func(w *HealthClaimHardened) { w.CoveredDiagnosis[0] = new(big.Int).Lsh(big.NewInt(1), 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			w := *base
			mutate(&w)
			if err := test.IsSolved(&HealthClaimHardened{}, &w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("invalid range witness solved")
			}
		})
	}
}

func TestGroth16ProofBindsEveryPublicInput(t *testing.T) {
	assignment, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &HealthClaimHardened{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	// Groth16 verification is stateless; accepting the same proof again here
	// demonstrates that replay rejection needs external UsedNullifiers state.
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatalf("same valid proof unexpectedly failed its second verification: %v", err)
	}
	var proofBytes bytes.Buffer
	if _, err := proof.WriteTo(&proofBytes); err != nil {
		t.Fatal(err)
	}
	t.Logf("serialized Groth16 proof bytes=%d", proofBytes.Len())
	mutations := map[string]func(*HealthClaimHardened){
		"registry root": func(w *HealthClaimHardened) { w.RegistryRoot = bi(1) }, "root version": func(w *HealthClaimHardened) { w.RootVersion = bi(2) },
		"policy commitment": func(w *HealthClaimHardened) { w.PolicyCommitment = bi(3) }, "policy version": func(w *HealthClaimHardened) { w.PolicyVersion = bi(4) },
		"claim amount": func(w *HealthClaimHardened) { w.ClaimAmount = bi(5) }, "authority key x": func(w *HealthClaimHardened) { w.AuthorityKeyX = bi(6) },
		"authority key y": func(w *HealthClaimHardened) { w.AuthorityKeyY = bi(7) }, "nullifier": func(w *HealthClaimHardened) { w.Nullifier = bi(8) },
		"protocol domain": func(w *HealthClaimHardened) { w.ProtocolDomain = bi(9) }, "challenge": func(w *HealthClaimHardened) { w.Challenge = bi(10) },
		"recipient": func(w *HealthClaimHardened) { w.RecipientID = bi(11) }, "deployment": func(w *HealthClaimHardened) { w.DeploymentID = bi(12) },
		"context commitment": func(w *HealthClaimHardened) { w.ContextCommitment = bi(13) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := *assignment
			mutate(&changed)
			w, e := frontend.NewWitness(&changed, ecc.BN254.ScalarField())
			if e != nil {
				t.Fatal(e)
			}
			pub, e := w.Public()
			if e != nil {
				t.Fatal(e)
			}
			if e = groth16.Verify(proof, vk, pub); e == nil {
				t.Fatal("tampered public input verified")
			}
		})
	}
}

func TestSelfSelectedAuthorityKeyRequiresVerifierAnchor(t *testing.T) {
	assignment, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x99}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	leaf := RecordLeaf(bi(41), bi(6), bi(12), bi(1000), SecretCommitment(bi(999)))
	signed, err := SignLeaf(attacker, leaf)
	if err != nil {
		t.Fatal(err)
	}
	var sig eddsa.Signature
	sig.Assign(twistededwards.BN254, signed)
	var x, y big.Int
	attacker.PublicKey.A.X.BigInt(&x)
	attacker.PublicKey.A.Y.BigInt(&y)
	assignment.AuthorityKeyX, assignment.AuthorityKeyY, assignment.Signature = &x, &y, sig
	ctx, err := ContextDigest(assignment.Challenge.(*big.Int), assignment.RecipientID.(*big.Int), assignment.DeploymentID.(*big.Int), assignment.PolicyVersion.(*big.Int), assignment.RootVersion.(*big.Int), assignment.PolicyCommitment.(*big.Int), assignment.RegistryRoot.(*big.Int), &x, &y, assignment.Nullifier.(*big.Int), assignment.ClaimAmount.(*big.Int))
	if err != nil {
		t.Fatal(err)
	}
	assignment.ContextCommitment = ctx
	if err := test.IsSolved(&HealthClaimHardened{}, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("expected self-selected key to satisfy circuit, demonstrating external trust-anchor responsibility: %v", err)
	}
}

// Cofactor clearing in the EdDSA verifier makes curve membership insufficient
// to establish that a supplied authority key is an authorized prime-order key.
// This test intentionally demonstrates that the circuit accepts proofs under
// identity and order-2 keys; a trusted registry must reject both.
func TestIdentityAndTorsionAuthorityKeysAreVerifierRejected(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &HealthClaimHardened{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	params, err := circuitedwards.GetCurveParams(twistededwards.BN254)
	if err != nil {
		t.Fatal(err)
	}
	minusOne := new(big.Int).Sub(Field(), big.NewInt(1))
	for _, tc := range []struct {
		name string
		x, y *big.Int
	}{
		{name: "identity", x: bi(0), y: bi(1)},
		{name: "order-2 torsion point", x: bi(0), y: minusOne},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := fixture(t)
			if err != nil {
				t.Fatal(err)
			}
			w.AuthorityKeyX, w.AuthorityKeyY = tc.x, tc.y
			w.Signature = eddsa.Signature{
				R: circuitedwards.Point{X: params.Base[0], Y: params.Base[1]},
				S: bi(1),
			}
			updateContextCommitment(t, w)
			full, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			proof, err := groth16.Prove(ccs, pk, full)
			if err != nil {
				t.Fatalf("expected the relation to accept this forged low-order key witness, proving the registry check is essential: %v", err)
			}
			pub, err := full.Public()
			if err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(proof, vk, pub); err != nil {
				t.Fatalf("expected proof to verify under the supplied low-order key: %v", err)
			}
		})
	}
}

func TestContextDigestCanonicalValidation(t *testing.T) {
	valid := []*big.Int{bi(777), bi(12), bi(9), bi(3), bi(5), bi(100), bi(200), bi(300), bi(400), bi(500), bi(600)}
	if _, err := ContextDigest(valid[0], valid[1], valid[2], valid[3], valid[4], valid[5], valid[6], valid[7], valid[8], valid[9], valid[10]); err != nil {
		t.Fatal(err)
	}
	if _, err := ContextDigest(bi(-1), valid[1], valid[2], valid[3], valid[4], valid[5], valid[6], valid[7], valid[8], valid[9], valid[10]); err == nil {
		t.Fatal("accepted negative/noncanonical scalar")
	}
	if _, err := ContextDigest(valid[0], valid[1], valid[2], new(big.Int).Lsh(big.NewInt(1), 64), valid[4], valid[5], valid[6], valid[7], valid[8], valid[9], valid[10]); err == nil {
		t.Fatal("accepted oversized policy version")
	}
	if _, err := ContextDigest(fr.Modulus(), valid[1], valid[2], valid[3], valid[4], valid[5], valid[6], valid[7], valid[8], valid[9], valid[10]); err == nil {
		t.Fatal("accepted non-canonical challenge field element")
	}
}

func TestDeterministicHardenedV1Vectors(t *testing.T) {
	var vectors struct {
		Public map[string]string `json:"public"`
	}
	data, err := os.ReadFile("testdata/hardened-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	w, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	actual := map[string]string{
		"registry_root": fmt.Sprint(w.RegistryRoot), "root_version": fmt.Sprint(w.RootVersion),
		"policy_commitment": fmt.Sprint(w.PolicyCommitment), "policy_version": fmt.Sprint(w.PolicyVersion),
		"claim_amount": fmt.Sprint(w.ClaimAmount), "authority_key_x": fmt.Sprint(w.AuthorityKeyX),
		"authority_key_y": fmt.Sprint(w.AuthorityKeyY), "nullifier": fmt.Sprint(w.Nullifier),
		"protocol_domain": fmt.Sprint(w.ProtocolDomain), "challenge": fmt.Sprint(w.Challenge),
		"recipient_id": fmt.Sprint(w.RecipientID), "deployment_id": fmt.Sprint(w.DeploymentID),
		"context_commitment": fmt.Sprint(w.ContextCommitment),
	}
	for key, expected := range vectors.Public {
		if actual[key] != expected {
			t.Errorf("%s vector drift: got %s want %s", key, actual[key], expected)
		}
	}
}

func benchmarkInputs(b *testing.B) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, groth16.Proof, witness.Witness, witness.Witness) {
	b.Helper()
	assignment, err := fixture(b)
	if err != nil {
		b.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &HealthClaimHardened{})
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	pub, err := full.Public()
	if err != nil {
		b.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, full)
	if err != nil {
		b.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		b.Fatal(err)
	}
	var serialized bytes.Buffer
	if _, err := proof.WriteTo(&serialized); err != nil {
		b.Fatal(err)
	}
	return ccs, pk, vk, proof, full, pub
}
func BenchmarkProofGeneration(b *testing.B) {
	ccs, pk, _, proof, full, _ := benchmarkInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := groth16.Prove(ccs, pk, full); err != nil {
			b.Fatal(err)
		}
	}
	reportBenchmarkMetrics(b, ccs, proof)
}
func BenchmarkProofVerification(b *testing.B) {
	_, _, vk, proof, _, pub := benchmarkInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := groth16.Verify(proof, vk, pub); err != nil {
			b.Fatal(err)
		}
	}
	reportBenchmarkMetrics(b, nil, proof)
}

func reportBenchmarkMetrics(b *testing.B, ccs constraint.ConstraintSystem, proof groth16.Proof) {
	if ccs != nil {
		b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	}
	var serialized bytes.Buffer
	if _, err := proof.WriteTo(&serialized); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(serialized.Len()), "proof_bytes")
}

func TestPublicInputCount(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &HealthClaimHardened{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ccs.GetNbPublicVariables() - 1; got != 13 {
		t.Fatalf("public input count=%d want 13 (%s)", got, fmt.Sprint(got))
	}
}
