package z9bench

import (
	"bytes"
	"math/big"
	"testing"

	hard "zerotrust/healthclaimhardened"

	"github.com/consensys/gnark-crypto/ecc"
	cryptoed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
)

func buildHardenedWitness(b *testing.B, key *cryptoed.PrivateKey) witness.Witness {
	b.Helper()
	bi := func(v int64) *big.Int { return big.NewInt(v) }
	diagnoses := [hard.DiagnosisSetSize]*big.Int{bi(41), bi(9), bi(77), bi(103)}
	secret, diagnosis, lab, policyID, coverage := bi(999), bi(41), bi(6), bi(12), bi(1000)
	leaf := hard.RecordLeaf(diagnosis, lab, policyID, coverage, hard.SecretCommitment(secret))
	sigBytes, err := hard.SignLeaf(key, leaf)
	if err != nil {
		b.Fatal(err)
	}
	var sig eddsa.Signature
	sig.Assign(twistededwards.BN254, sigBytes)
	var path hard.MerklePath
	for i := 0; i < hard.MerkleDepth; i++ {
		path.Siblings[i] = bi(int64(500 + i))
		path.Directions[i] = bi(int64((9 >> i) & 1))
	}
	root := hard.RootFromPath(leaf, path)
	policy := hard.PolicyDigest(policyID, bi(3), bi(8), bi(1200), diagnoses)
	var keyX, keyY big.Int
	key.PublicKey.A.X.BigInt(&keyX)
	key.PublicKey.A.Y.BigInt(&keyY)
	claim, nullifier := bi(900), hard.RecordNullifier(secret, hard.IndexFromDirections(path))
	challenge, recipient, deployment, policyVersion, rootVersion := bi(777), bi(12), bi(9), bi(3), bi(5)
	context, err := hard.ContextDigest(challenge, recipient, deployment, policyVersion, rootVersion, policy, root, &keyX, &keyY, nullifier, claim)
	if err != nil {
		b.Fatal(err)
	}
	w := &hard.HealthClaimHardened{RegistryRoot: root, RootVersion: rootVersion, PolicyCommitment: policy, PolicyVersion: policyVersion, ClaimAmount: claim, AuthorityKeyX: &keyX, AuthorityKeyY: &keyY, Nullifier: nullifier, ProtocolDomain: hard.ProtocolDomainID, Challenge: challenge, RecipientID: recipient, DeploymentID: deployment, ContextCommitment: context, Diagnosis: diagnosis, LabValue: lab, PolicyID: policyID, CoverageCeiling: coverage, PatientSecret: secret, LabMin: bi(3), LabMax: bi(8), PolicyMaxClaim: bi(1200), CoveredDiagnosis: [hard.DiagnosisSetSize]frontend.Variable{diagnoses[0], diagnoses[1], diagnoses[2], diagnoses[3]}, Signature: sig}
	for i := 0; i < hard.MerkleDepth; i++ {
		w.MerkleSiblings[i], w.MerkleDirections[i] = path.Siblings[i], path.Directions[i]
	}
	witness, err := frontend.NewWitness(w, eccField())
	if err != nil {
		b.Fatal(err)
	}
	return witness
}

func eccField() *big.Int { return ecc.BN254.ScalarField() }

func BenchmarkWitnessConstruction(b *testing.B) {
	key, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildHardenedWitness(b, key)
	}
}

func BenchmarkFullPipeline(b *testing.B) {
	key, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		b.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &hard.HealthClaimHardened{})
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	initial := buildHardenedWitness(b, key)
	initialPublic, err := initial.Public()
	if err != nil {
		b.Fatal(err)
	}
	initialProof, err := groth16.Prove(ccs, pk, initial)
	if err != nil {
		b.Fatal(err)
	}
	if err := groth16.Verify(initialProof, vk, initialPublic); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := buildHardenedWitness(b, key)
		pub, err := w.Public()
		if err != nil {
			b.Fatal(err)
		}
		proof, err := groth16.Prove(ccs, pk, w)
		if err != nil {
			b.Fatal(err)
		}
		if err := groth16.Verify(proof, vk, pub); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	var buf bytes.Buffer
	if _, err := initialProof.WriteTo(&buf); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(buf.Len()), "proof_bytes")
}
