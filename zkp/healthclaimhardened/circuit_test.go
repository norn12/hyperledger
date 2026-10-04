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
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test"
)

func bi(v int64) *big.Int { return big.NewInt(v) }

func fixture(t testing.TB) (*HealthClaimHardened, error) {
	t.Helper()
	key, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		return nil, err
	}
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
