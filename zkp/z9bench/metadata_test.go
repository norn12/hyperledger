package z9bench

import (
	"bytes"
	"math/big"
	"testing"

	core "zerotrust/healthclaimcore"
	hard "zerotrust/healthclaimhardened"

	"github.com/consensys/gnark-crypto/ecc"
	cryptoed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdeddsa "github.com/consensys/gnark/std/signature/eddsa"
)

func TestCoreBenchmarkMetadata(t *testing.T) {
	bi := func(v int64) *big.Int { return big.NewInt(v) }
	key, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	diagnoses := [core.DiagnosisSetSize]*big.Int{bi(41), bi(9), bi(77), bi(103)}
	secret, diagnosis, lab, policyID, coverage := bi(999), bi(41), bi(6), bi(12), bi(1000)
	leaf := core.RecordLeaf(diagnosis, lab, policyID, coverage, core.SecretCommitment(secret))
	sigBytes, err := core.SignLeaf(key, leaf)
	if err != nil {
		t.Fatal(err)
	}
	var sig stdeddsa.Signature
	sig.Assign(twistededwards.BN254, sigBytes)
	var path hard.MerklePath
	for i := 0; i < core.MerkleDepth; i++ {
		path.Siblings[i] = bi(int64(500 + i))
		path.Directions[i] = bi(int64((9 >> i) & 1))
	}
	root := hard.RootFromPath(leaf, path)
	policy := core.PolicyDigest(policyID, bi(3), bi(8), bi(1200), diagnoses)
	var keyX, keyY big.Int
	key.PublicKey.A.X.BigInt(&keyX)
	key.PublicKey.A.Y.BigInt(&keyY)
	var index uint64
	for i, d := range path.Directions {
		if d.Uint64() == 1 {
			index |= 1 << i
		}
	}
	assignment := &core.HealthClaimCore{RegistryRoot: root, PolicyCommitment: policy, ClaimAmount: bi(900), AuthorityKeyX: &keyX, AuthorityKeyY: &keyY, Nullifier: core.RecordNullifier(secret, index), Diagnosis: diagnosis, LabValue: lab, PolicyID: policyID, CoverageCeiling: coverage, PatientSecret: secret, LabMin: bi(3), LabMax: bi(8), PolicyMaxClaim: bi(1200), CoveredDiagnosis: [core.DiagnosisSetSize]frontend.Variable{diagnoses[0], diagnoses[1], diagnoses[2], diagnoses[3]}, Signature: sig}
	for i := 0; i < core.MerkleDepth; i++ {
		assignment.MerkleSiblings[i], assignment.MerkleDirections[i] = path.Siblings[i], path.Directions[i]
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.HealthClaimCore{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, w)
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := proof.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	t.Logf("Core constraints=%d public=%d private=%d proof_bytes=%d", ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1, ccs.GetNbSecretVariables(), out.Len())
}

func TestHardenedBenchmarkMetadata(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &hard.HealthClaimHardened{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Hardened constraints=%d public=%d private=%d", ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1, ccs.GetNbSecretVariables())
}

func BenchmarkCircuitCompile(b *testing.B) {
	b.Run("core", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.HealthClaimCore{}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("hardened", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &hard.HealthClaimHardened{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkGroth16Setup(b *testing.B) {
	for _, tc := range []struct {
		name    string
		circuit frontend.Circuit
	}{{"core", &core.HealthClaimCore{}}, {"hardened", &hard.HealthClaimHardened{}}} {
		b.Run(tc.name, func(b *testing.B) {
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, tc.circuit)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := groth16.Setup(ccs); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
		})
	}
}
