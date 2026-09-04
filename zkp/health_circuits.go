package zkp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ============================================================
// Circuit Definitions
// Each circuit proves a health claim without revealing raw data
// ============================================================

// AgeRangeCircuit proves patient age is within [minAge, maxAge]
// without revealing the actual age value
type AgeRangeCircuit struct {
	// Private inputs (known only to prover)
	Age frontend.Variable `gnark:",secret"`

	// Public inputs (known to verifier)
	MinAge frontend.Variable `gnark:",public"`
	MaxAge frontend.Variable `gnark:",public"`
}

func (c *AgeRangeCircuit) Define(api frontend.API) error {
	// Prove: MinAge <= Age <= MaxAge
	api.AssertIsLessOrEqual(c.MinAge, c.Age)
	api.AssertIsLessOrEqual(c.Age, c.MaxAge)
	return nil
}

// DiagnosisCategoryCircuit proves a diagnosis code belongs to
// a permitted category without revealing the exact code
type DiagnosisCategoryCircuit struct {
	// Private input
	DiagnosisCode frontend.Variable `gnark:",secret"`

	// Public inputs
	CategoryMin frontend.Variable `gnark:",public"`
	CategoryMax frontend.Variable `gnark:",public"`
}

func (c *DiagnosisCategoryCircuit) Define(api frontend.API) error {
	// Prove: CategoryMin <= DiagnosisCode <= CategoryMax
	api.AssertIsLessOrEqual(c.CategoryMin, c.DiagnosisCode)
	api.AssertIsLessOrEqual(c.DiagnosisCode, c.CategoryMax)
	return nil
}

// ============================================================
// Proof structures for serialization
// ============================================================

type ProofResult struct {
	ProofBytes     []byte  `json:"proofBytes"`
	ProofHash      string  `json:"proofHash"`
	ProofSizeBytes int     `json:"proofSizeBytes"`
	GenTimeMs      float64 `json:"genTimeMs"`
	VerifyTimeMs   float64 `json:"verifyTimeMs"`
	CircuitType    string  `json:"circuitType"`
	IsValid        bool    `json:"isValid"`
}

// ============================================================
// ZKPService - handles proof generation and verification
// ============================================================

type ZKPService struct {
	// Cached proving/verifying keys per circuit type
	ageRangeProvingKey   groth16.ProvingKey
	ageRangeVerifyingKey groth16.VerifyingKey
	ageRangeR1CS         constraint.ConstraintSystem

	diagProvingKey   groth16.ProvingKey
	diagVerifyingKey groth16.VerifyingKey
	diagR1CS         constraint.ConstraintSystem
}

// Setup - compiles circuits and generates proving/verifying keys
// Call once at startup; keys can be saved to disk for reuse
func (s *ZKPService) Setup() error {
	if s.ageRangeR1CS != nil && s.diagR1CS != nil {
		return nil // Proving and verifying keys already compiled & cached
	}

	fmt.Println("[ZKP] Compiling AgeRange circuit...")
	ageCircuit := &AgeRangeCircuit{}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, ageCircuit)
	if err != nil {
		return fmt.Errorf("failed to compile AgeRange circuit: %v", err)
	}
	s.ageRangeR1CS = ccs

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("failed to setup AgeRange keys: %v", err)
	}
	s.ageRangeProvingKey = pk
	s.ageRangeVerifyingKey = vk
	fmt.Println("[ZKP] AgeRange circuit ready")

	fmt.Println("[ZKP] Compiling DiagnosisCategory circuit...")
	diagCircuit := &DiagnosisCategoryCircuit{}
	diagCcs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, diagCircuit)
	if err != nil {
		return fmt.Errorf("failed to compile DiagnosisCategory circuit: %v", err)
	}
	s.diagR1CS = diagCcs

	dpk, dvk, err := groth16.Setup(diagCcs)
	if err != nil {
		return fmt.Errorf("failed to setup DiagnosisCategory keys: %v", err)
	}
	s.diagProvingKey = dpk
	s.diagVerifyingKey = dvk
	fmt.Println("[ZKP] DiagnosisCategory circuit ready")

	return nil
}

// ProveAgeRange - generate a ZK proof that age is in [minAge, maxAge]
// Measures and returns generation time for benchmarking
func (s *ZKPService) ProveAgeRange(age, minAge, maxAge int) (*ProofResult, error) {
	witness, err := frontend.NewWitness(&AgeRangeCircuit{
		Age:    age,
		MinAge: minAge,
		MaxAge: maxAge,
	}, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %v", err)
	}

	// Measure proof generation time
	genStart := time.Now()
	proof, err := groth16.Prove(s.ageRangeR1CS, s.ageRangeProvingKey, witness)
	genTimeMs := float64(time.Since(genStart).Nanoseconds()) / 1e6
	if err != nil {
		return nil, fmt.Errorf("proof generation failed: %v", err)
	}

	// Serialize proof to bytes
	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %v", err)
	}

	// Hash the proof for on-chain storage
	hash := sha256.Sum256(proofBytes)
	proofHash := hex.EncodeToString(hash[:])

	// Verify immediately and measure verification time
	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to extract public witness: %v", err)
	}

	verifyStart := time.Now()
	err = groth16.Verify(proof, s.ageRangeVerifyingKey, publicWitness)
	verifyTimeMs := float64(time.Since(verifyStart).Nanoseconds()) / 1e6
	isValid := err == nil

	return &ProofResult{
		ProofBytes:     proofBytes,
		ProofHash:      proofHash,
		ProofSizeBytes: len(proofBytes),
		GenTimeMs:      genTimeMs,
		VerifyTimeMs:   verifyTimeMs,
		CircuitType:    "age_range",
		IsValid:        isValid,
	}, nil
}

// ProveDiagnosisCategory - generate ZK proof that diagnosis code
// falls within a permitted category range
func (s *ZKPService) ProveDiagnosisCategory(diagCode, categoryMin, categoryMax int) (*ProofResult, error) {
	witness, err := frontend.NewWitness(&DiagnosisCategoryCircuit{
		DiagnosisCode: diagCode,
		CategoryMin:   categoryMin,
		CategoryMax:   categoryMax,
	}, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %v", err)
	}

	genStart := time.Now()
	proof, err := groth16.Prove(s.diagR1CS, s.diagProvingKey, witness)
	genTimeMs := float64(time.Since(genStart).Nanoseconds()) / 1e6
	if err != nil {
		return nil, fmt.Errorf("proof generation failed: %v", err)
	}

	proofBytes, err := json.Marshal(proof)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize proof: %v", err)
	}

	hash := sha256.Sum256(proofBytes)
	proofHash := hex.EncodeToString(hash[:])

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to extract public witness: %v", err)
	}

	verifyStart := time.Now()
	err = groth16.Verify(proof, s.diagVerifyingKey, publicWitness)
	verifyTimeMs := float64(time.Since(verifyStart).Nanoseconds()) / 1e6
	isValid := err == nil

	return &ProofResult{
		ProofBytes:     proofBytes,
		ProofHash:      proofHash,
		ProofSizeBytes: len(proofBytes),
		GenTimeMs:      genTimeMs,
		VerifyTimeMs:   verifyTimeMs,
		CircuitType:    "diagnosis_category",
		IsValid:        isValid,
	}, nil
}
