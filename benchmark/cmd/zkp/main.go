package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	"zerotrust/zkp"
)

type RunResult struct {
	Samples             int     `json:"samples"`
	ValidProofs         int     `json:"validProofs"`
	FailedProofs        int     `json:"failedProofs"`
	AvgGenerationMs     float64 `json:"avgGenerationMs"`
	P50GenerationMs     float64 `json:"p50GenerationMs"`
	P95GenerationMs     float64 `json:"p95GenerationMs"`
	P99GenerationMs     float64 `json:"p99GenerationMs"`
	AvgVerificationMs   float64 `json:"avgVerificationMs"`
	P50VerificationMs   float64 `json:"p50VerificationMs"`
	P95VerificationMs   float64 `json:"p95VerificationMs"`
	P99VerificationMs   float64 `json:"p99VerificationMs"`
	AvgProofSizeBytes   float64 `json:"avgProofSizeBytes"`
	TotalElapsedSeconds float64 `json:"totalElapsedSeconds"`
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	v := append([]float64(nil), values...)
	sort.Float64s(v)
	idx := int((p / 100) * float64(len(v)-1))
	return v[idx]
}

func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var total float64
	for _, v := range values {
		total += v
	}
	return total / float64(len(values))
}

func main() {
	samples := 100
	if len(os.Args) > 1 {
		if _, err := fmt.Sscanf(os.Args[1], "%d", &samples); err != nil || samples < 1 {
			log.Fatalf("invalid sample count: %q", os.Args[1])
		}
	}

	service := &zkp.ZKPService{}
	setupStart := time.Now()
	if err := service.Setup(); err != nil {
		log.Fatalf("ZKP setup failed: %v", err)
	}
	setupMs := time.Since(setupStart).Seconds() * 1000

	// Warm up the proving/verification path once so compilation/setup is not
	// mixed into the cryptographic timing samples.
	if _, err := service.ProveAgeRange(25, 18, 120); err != nil {
		log.Fatalf("ZKP warmup failed: %v", err)
	}

	generation := make([]float64, 0, samples)
	verification := make([]float64, 0, samples)
	proofSizes := make([]float64, 0, samples)
	valid := 0
	failed := 0

	start := time.Now()
	for i := 0; i < samples; i++ {
		age := 25 + (i % 45)
		result, err := service.ProveAgeRange(age, 18, 120)
		if err != nil {
			failed++
			continue
		}
		generation = append(generation, float64(result.GenTimeMs))
		verification = append(verification, float64(result.VerifyTimeMs))
		proofSizes = append(proofSizes, float64(result.ProofSizeBytes))
		if result.IsValid {
			valid++
		} else {
			failed++
		}
	}
	elapsed := time.Since(start)

	result := RunResult{
		Samples:             samples,
		ValidProofs:         valid,
		FailedProofs:        failed,
		AvgGenerationMs:     average(generation),
		P50GenerationMs:     percentile(generation, 50),
		P95GenerationMs:     percentile(generation, 95),
		P99GenerationMs:     percentile(generation, 99),
		AvgVerificationMs:   average(verification),
		P50VerificationMs:   percentile(verification, 50),
		P95VerificationMs:   percentile(verification, 95),
		P99VerificationMs:   percentile(verification, 99),
		AvgProofSizeBytes:   average(proofSizes),
		TotalElapsedSeconds: elapsed.Seconds(),
	}

	output := map[string]interface{}{
		"experiment": "A - Groth16 cryptographic cost",
		"circuit":    "AgeRangeCircuit",
		"curve":      "BN254",
		"setupMs":    setupMs,
		"result":     result,
	}

	encoded, _ := json.MarshalIndent(output, "", "  ")
	if err := os.WriteFile("zkp-results.json", encoded, 0644); err != nil {
		log.Printf("warning: could not write zkp-results.json: %v", err)
	}

	fmt.Println("=== Experiment A: Groth16 Cryptographic Cost ===")
	fmt.Printf("Setup:              %.2f ms\n", setupMs)
	fmt.Printf("Samples:             %d\n", samples)
	fmt.Printf("Valid proofs:        %d\n", valid)
	fmt.Printf("Failed proofs:       %d\n", failed)
	fmt.Printf("Generation avg:      %.2f ms\n", result.AvgGenerationMs)
	fmt.Printf("Generation p95:      %.2f ms\n", result.P95GenerationMs)
	fmt.Printf("Verification avg:    %.2f ms\n", result.AvgVerificationMs)
	fmt.Printf("Verification p95:    %.2f ms\n", result.P95VerificationMs)
	fmt.Printf("Proof size avg:      %.0f bytes\n", result.AvgProofSizeBytes)
	fmt.Printf("Benchmark elapsed:   %.2fs\n", result.TotalElapsedSeconds)
	fmt.Println("Results written to:  zkp-results.json")
}
