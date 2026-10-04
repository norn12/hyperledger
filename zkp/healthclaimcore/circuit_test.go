package healthclaimcore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	cryptoed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test"
)

func bi(v int64) *big.Int { return big.NewInt(v) }

func fixture(t testing.TB) (*HealthClaimCore, error) {
	t.Helper()
	key, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		return nil, err
	}
	diagnoses := [DiagnosisSetSize]*big.Int{bi(41), bi(9), bi(77), bi(103)}
	secret, diagnosis, lab, policyID, coverage := bi(999), bi(41), bi(6), bi(12), bi(1000)
	keyCommitment := SecretCommitment(secret)
	leaf := RecordLeaf(diagnosis, lab, policyID, coverage, keyCommitment)
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
	path.Index = IndexFromDirections(path)
	root := RootFromPath(leaf, path)
	policyCommitment := PolicyDigest(policyID, bi(3), bi(8), bi(1200), diagnoses)
	var pubX, pubY big.Int
	key.PublicKey.A.X.BigInt(&pubX)
	key.PublicKey.A.Y.BigInt(&pubY)
	assignment := &HealthClaimCore{
		RegistryRoot: root, PolicyCommitment: policyCommitment, ClaimAmount: bi(900),
		AuthorityKeyX: &pubX, AuthorityKeyY: &pubY,
		Nullifier: RecordNullifier(secret, path.Index),
		Diagnosis: diagnosis, LabValue: lab, PolicyID: policyID, CoverageCeiling: coverage,
		PatientSecret: secret, LabMin: bi(3), LabMax: bi(8), PolicyMaxClaim: bi(1200), CoveredDiagnosis: [DiagnosisSetSize]frontend.Variable{diagnoses[0], diagnoses[1], diagnoses[2], diagnoses[3]},
		Signature: sig,
	}
	for i := 0; i < MerkleDepth; i++ {
		assignment.MerkleSiblings[i] = path.Siblings[i]
		assignment.MerkleDirections[i] = path.Directions[i]
	}
	return assignment, nil
}

func TestCoreRelationAndAdversarialWitnesses(t *testing.T) {
	circuit := &HealthClaimCore{}
	assignment, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("valid claim rejected: %v", err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("HealthClaimCore: constraints=%d public_variables=%d secret_variables=%d", ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1, ccs.GetNbSecretVariables())
	t.Logf("vector registry_root=%v policy_commitment=%v nullifier=%v authority_key=(%v,%v)", assignment.RegistryRoot, assignment.PolicyCommitment, assignment.Nullifier, assignment.AuthorityKeyX, assignment.AuthorityKeyY)
	t.Logf("vector private diagnosis=%v lab=%v policy_id=%v ceiling=%v secret=%v claim=%v", assignment.Diagnosis, assignment.LabValue, assignment.PolicyID, assignment.CoverageCeiling, assignment.PatientSecret, assignment.ClaimAmount)

	mutations := map[string]func(*HealthClaimCore){
		"diagnosis excluded":            func(w *HealthClaimCore) { w.Diagnosis = 42 },
		"lab below bound":               func(w *HealthClaimCore) { w.LabValue = 2 },
		"lab above bound":               func(w *HealthClaimCore) { w.LabValue = 9 },
		"lab exceeds 64 bits":           func(w *HealthClaimCore) { w.LabValue = new(big.Int).Lsh(big.NewInt(1), 64) },
		"claim above ceiling":           func(w *HealthClaimCore) { w.ClaimAmount = 1001 },
		"claim exceeds 64 bits":         func(w *HealthClaimCore) { w.ClaimAmount = new(big.Int).Lsh(big.NewInt(1), 64) },
		"ceiling exceeds 64 bits":       func(w *HealthClaimCore) { w.CoverageCeiling = new(big.Int).Lsh(big.NewInt(1), 64) },
		"record ceiling exceeds policy": func(w *HealthClaimCore) { w.CoverageCeiling = 1201 },
		"invalid signature":             func(w *HealthClaimCore) { w.Signature.S = bi(0) },
		"wrong root":                    func(w *HealthClaimCore) { w.RegistryRoot = bi(123456) },
		"non-boolean direction":         func(w *HealthClaimCore) { w.MerkleDirections[0] = bi(2) },
		"wrong nullifier":               func(w *HealthClaimCore) { w.Nullifier = bi(987654) },
		"wrong policy commitment":       func(w *HealthClaimCore) { w.PolicyCommitment = bi(123) },
		"wrong authority key":           func(w *HealthClaimCore) { w.AuthorityKeyX = bi(123) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			w := *assignment
			mutate(&w)
			if err := test.IsSolved(circuit, &w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("invalid witness solved")
			}
		})
	}
}

func TestDeterministicCoreV1Vectors(t *testing.T) {
	var vectors struct {
		Public map[string]string `json:"public"`
	}
	data, err := os.ReadFile("testdata/core-v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	assignment, err := fixture(t)
	if err != nil {
		t.Fatal(err)
	}
	actual := map[string]string{
		"registry_root":     fmt.Sprint(assignment.RegistryRoot),
		"policy_commitment": fmt.Sprint(assignment.PolicyCommitment),
		"claim_amount":      fmt.Sprint(assignment.ClaimAmount),
		"authority_key_x":   fmt.Sprint(assignment.AuthorityKeyX),
		"authority_key_y":   fmt.Sprint(assignment.AuthorityKeyY),
		"nullifier":         fmt.Sprint(assignment.Nullifier),
	}
	for key, expected := range vectors.Public {
		if actual[key] != expected {
			t.Errorf("%s vector drift: got %s want %s", key, actual[key], expected)
		}
	}
}

func benchmarkProofInputs(b *testing.B) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, groth16.Proof, witness.Witness, witness.Witness) {
	b.Helper()
	assignment, err := fixture(b)
	if err != nil {
		b.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &HealthClaimCore{})
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		b.Fatal(err)
	}
	initialProof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		b.Fatal(err)
	}
	if err := groth16.Verify(initialProof, vk, publicWitness); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	return ccs, pk, vk, initialProof, witness, publicWitness
}

func BenchmarkProofGeneration(b *testing.B) {
	ccs, pk, _, _, witness, _ := benchmarkProofInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := groth16.Prove(ccs, pk, witness); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProofVerification(b *testing.B) {
	_, _, vk, proof, _, publicWitness := benchmarkProofInputs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := groth16.Verify(proof, vk, publicWitness); err != nil {
			b.Fatal(err)
		}
	}
}
