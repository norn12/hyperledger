package zkp

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// These benchmarks measure only the legacy interval circuits: AgeRange proves
// MinAge <= Age <= MaxAge; DiagnosisCategory proves CategoryMin <= code <=
// CategoryMax. They do not prove signed records, commitments, or membership.
func prepareLegacyAge(b *testing.B) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, groth16.Proof, witness.Witness, witness.Witness) {
	b.Helper()
	circuit := &AgeRangeCircuit{}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	assignment := &AgeRangeCircuit{Age: 25, MinAge: 18, MaxAge: 120}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
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
	return ccs, pk, vk, proof, w, pub
}

func prepareLegacyDiagnosis(b *testing.B) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, groth16.Proof, witness.Witness, witness.Witness) {
	b.Helper()
	circuit := &DiagnosisCategoryCircuit{}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		b.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	assignment := &DiagnosisCategoryCircuit{DiagnosisCode: 105, CategoryMin: 100, CategoryMax: 200}
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		b.Fatal(err)
	}
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
	return ccs, pk, vk, proof, w, pub
}

func reportLegacy(b *testing.B, ccs constraint.ConstraintSystem, proof groth16.Proof) {
	b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
	b.ReportMetric(float64(ccs.GetNbPublicVariables()-1), "public_vars")
	b.ReportMetric(float64(ccs.GetNbSecretVariables()), "private_vars")
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(buf.Len()), "proof_bytes")
}

func BenchmarkLegacyAgeRangeGeneration(b *testing.B) {
	ccs, pk, _, proof, w, _ := prepareLegacyAge(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := groth16.Prove(ccs, pk, w); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	reportLegacy(b, ccs, proof)
}
func BenchmarkLegacyAgeRangeVerification(b *testing.B) {
	ccs, _, vk, proof, _, pub := prepareLegacyAge(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := groth16.Verify(proof, vk, pub); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	reportLegacy(b, ccs, proof)
}

func BenchmarkLegacyDiagnosisGeneration(b *testing.B) {
	ccs, pk, _, proof, w, _ := prepareLegacyDiagnosis(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := groth16.Prove(ccs, pk, w); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	reportLegacy(b, ccs, proof)
}
func BenchmarkLegacyDiagnosisVerification(b *testing.B) {
	ccs, _, vk, proof, _, pub := prepareLegacyDiagnosis(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := groth16.Verify(proof, vk, pub); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	reportLegacy(b, ccs, proof)
}
