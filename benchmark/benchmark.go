package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// BenchmarkConfig controls the load test parameters
type BenchmarkConfig struct {
	// Load test parameters (mirrors paper's 10–100K tx range)
	MinConcurrentTx int
	MaxConcurrentTx int
	StepSize        int
	TrialsPerStep   int
	DurationSec     int

	// Output
	CSVOutputPath  string
	JSONOutputPath string
}

// BenchmarkResult holds results for one load level
type BenchmarkResult struct {
	ConcurrentTx    int     `json:"concurrentTx"`
	ThroughputTPS   float64 `json:"throughputTPS"`
	AvgLatencyMs    float64 `json:"avgLatencyMs"`
	P50LatencyMs    float64 `json:"p50LatencyMs"`
	P95LatencyMs    float64 `json:"p95LatencyMs"`
	P99LatencyMs    float64 `json:"p99LatencyMs"`
	AvgZKPGenMs     float64 `json:"avgZKPGenMs"`
	AvgZKPVerifyMs  float64 `json:"avgZKPVerifyMs"`
	AvgProofBytes   float64 `json:"avgProofBytes"`
	SuccessRate     float64 `json:"successRate"`
	ErrorCount      int     `json:"errorCount"`
	TrialDurationMs int64   `json:"trialDurationMs"`
}

// TxResult holds result of a single simulated transaction
type TxResult struct {
	LatencyMs      int64
	ZKPGenMs       int64
	ZKPVerifyMs    int64
	ProofSizeBytes int
	Success        bool
}

// BenchmarkRunner orchestrates the full benchmark suite
type BenchmarkRunner struct {
	cfg     BenchmarkConfig
	results []BenchmarkResult
}

func NewBenchmarkRunner(cfg BenchmarkConfig) *BenchmarkRunner {
	return &BenchmarkRunner{cfg: cfg}
}

// RunFullBenchmark - executes all load levels and collects metrics
// Replicates Algorithm 1 from the ZeroTrustBlock paper
func (b *BenchmarkRunner) RunFullBenchmark(
	txFunc func(id int) TxResult, // injectable tx function — swap in real Fabric calls
) {
	fmt.Println("=== ZeroTrustBlock Benchmark Suite ===")
	fmt.Printf("Load range: %d → %d tx (step %d), %d trials each\n",
		b.cfg.MinConcurrentTx, b.cfg.MaxConcurrentTx, b.cfg.StepSize, b.cfg.TrialsPerStep)
	fmt.Println()

	for load := b.cfg.MinConcurrentTx; load <= b.cfg.MaxConcurrentTx; load += b.cfg.StepSize {
		result := b.runLoadLevel(load, txFunc)
		b.results = append(b.results, result)

		fmt.Printf("Load: %4d tx | TPS: %8.1f | AvgLat: %5.0fms | P99: %5.0fms | ZKPGen: %4.0fms | ZKPVerify: %4.0fms | ProofSize: %5.0fB | Success: %.1f%%\n",
			result.ConcurrentTx,
			result.ThroughputTPS,
			result.AvgLatencyMs,
			result.P99LatencyMs,
			result.AvgZKPGenMs,
			result.AvgZKPVerifyMs,
			result.AvgProofBytes,
			result.SuccessRate,
		)
	}

	b.printSummary()
}

// runLoadLevel runs all trials for a single concurrency level
func (b *BenchmarkRunner) runLoadLevel(load int, txFunc func(id int) TxResult) BenchmarkResult {
	var allLatencies []int64
	var totalZKPGen, totalZKPVerify int64
	var totalProofSize int
	var successCount, errorCount int

	trialStart := time.Now()

	for trial := 0; trial < b.cfg.TrialsPerStep; trial++ {
		var wg sync.WaitGroup
		results := make([]TxResult, load)

		for i := 0; i < load; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = txFunc(idx)
			}(i)
		}
		wg.Wait()
		fmt.Printf(".") // Trial progress

		for _, r := range results {
			allLatencies = append(allLatencies, r.LatencyMs)
			totalZKPGen += r.ZKPGenMs
			totalZKPVerify += r.ZKPVerifyMs
			totalProofSize += r.ProofSizeBytes
			if r.Success {
				successCount++
			} else {
				errorCount++
			}
		}
	}

	trialDurationMs := time.Since(trialStart).Milliseconds()
	totalTx := load * b.cfg.TrialsPerStep

	// Sort latencies for percentiles
	sortedLatencies := sortedCopy(allLatencies)

	var sumLatency int64
	for _, l := range allLatencies {
		sumLatency += l
	}

	throughput := float64(totalTx) / (float64(trialDurationMs) / 1000.0)

	return BenchmarkResult{
		ConcurrentTx:    load,
		ThroughputTPS:   throughput,
		AvgLatencyMs:    float64(sumLatency) / float64(len(allLatencies)),
		P50LatencyMs:    percentile(sortedLatencies, 50),
		P95LatencyMs:    percentile(sortedLatencies, 95),
		P99LatencyMs:    percentile(sortedLatencies, 99),
		AvgZKPGenMs:     float64(totalZKPGen) / float64(totalTx),
		AvgZKPVerifyMs:  float64(totalZKPVerify) / float64(totalTx),
		AvgProofBytes:   float64(totalProofSize) / float64(totalTx),
		SuccessRate:     float64(successCount) / float64(totalTx) * 100,
		ErrorCount:      errorCount,
		TrialDurationMs: trialDurationMs,
	}
}

func (b *BenchmarkRunner) printSummary() {
	fmt.Println()
	fmt.Println("=== Benchmark Summary ===")
	fmt.Println()

	// Check against targets from ZKP metrics document
	if len(b.results) > 0 {
		last := b.results[len(b.results)-1]
		fmt.Printf("Peak TPS:              %.1f  (paper target: 14,200)\n", last.ThroughputTPS)
		fmt.Printf("Peak Avg Latency:      %.0fms (paper target: <480ms)\n", last.AvgLatencyMs)
		fmt.Printf("Avg ZKP Gen Time:      %.0fms (doc target: <200ms)\n", last.AvgZKPGenMs)
		fmt.Printf("Avg ZKP Verify Time:   %.0fms (doc target: <100ms)\n", last.AvgZKPVerifyMs)
		fmt.Printf("Avg Proof Size:        %.0fB  (doc target: <2048B)\n", last.AvgProofBytes)
	}
}

// SaveCSV - saves results to CSV for analysis/plotting
func (b *BenchmarkRunner) SaveCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	w.Write([]string{
		"concurrent_tx", "throughput_tps", "avg_latency_ms",
		"p50_latency_ms", "p95_latency_ms", "p99_latency_ms",
		"avg_zkp_gen_ms", "avg_zkp_verify_ms", "avg_proof_bytes",
		"success_rate", "error_count",
	})

	for _, r := range b.results {
		w.Write([]string{
			fmt.Sprintf("%d", r.ConcurrentTx),
			fmt.Sprintf("%.2f", r.ThroughputTPS),
			fmt.Sprintf("%.2f", r.AvgLatencyMs),
			fmt.Sprintf("%.2f", r.P50LatencyMs),
			fmt.Sprintf("%.2f", r.P95LatencyMs),
			fmt.Sprintf("%.2f", r.P99LatencyMs),
			fmt.Sprintf("%.2f", r.AvgZKPGenMs),
			fmt.Sprintf("%.2f", r.AvgZKPVerifyMs),
			fmt.Sprintf("%.2f", r.AvgProofBytes),
			fmt.Sprintf("%.2f", r.SuccessRate),
			fmt.Sprintf("%d", r.ErrorCount),
		})
	}

	fmt.Printf("[Benchmark] Results saved to %s\n", path)
	return nil
}

// SaveJSON - saves results to JSON
func (b *BenchmarkRunner) SaveJSON(path string) error {
	data, err := json.MarshalIndent(b.results, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(path, data, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("[Benchmark] Results saved to %s\n", path)
	return nil
}

// ============================================================
// Simulation mode — used for local dev before Fabric is running
// Injects realistic latency distributions based on paper's numbers
// ============================================================
func SimulatedTxFunc(load int) func(id int) TxResult {
	return func(id int) TxResult {
		// Simulate optimized latency to reach 1500 TPS target
		baseLatency := int64(800 + (load / 10)) 

		// Simulate ZKP timings (targets from metrics document)
		zkpGenMs := int64(80 + (id % 40))    // ~80–120ms generation
		zkpVerifyMs := int64(40 + (id % 30)) // ~40–70ms verification
		proofSize := 1200 + (id % 800)        // ~1.2–2KB proof size

		// Simulate occasional failures for realism
		success := (id % 20) != 0

		time.Sleep(time.Duration(baseLatency) * time.Millisecond)

		return TxResult{
			LatencyMs:      baseLatency,
			ZKPGenMs:       zkpGenMs,
			ZKPVerifyMs:    zkpVerifyMs,
			ProofSizeBytes: proofSize,
			Success:        success,
		}
	}
}

func main() {
	cfg := BenchmarkConfig{
		MinConcurrentTx: 100,
		MaxConcurrentTx: 1500,
		StepSize:        350,
		TrialsPerStep:   5,
		CSVOutputPath:   "benchmark_results.csv",
		JSONOutputPath:  "benchmark_results.json",
	}

	runner := NewBenchmarkRunner(cfg)

	// Use simulated tx function for local dev
	// Replace SimulatedTxFunc with real Fabric gateway calls when network is running
	fmt.Println("[Benchmark] Running in SIMULATION mode")
	fmt.Println("[Benchmark] Replace SimulatedTxFunc with real Fabric calls when network is up")
	fmt.Println()

	runner.RunFullBenchmark(SimulatedTxFunc(cfg.MaxConcurrentTx))

	runner.SaveCSV(cfg.CSVOutputPath)
	runner.SaveJSON(cfg.JSONOutputPath)
}

// ============================================================
// Utility functions
// ============================================================

func sortedCopy(s []int64) []int64 {
	cp := make([]int64, len(s))
	copy(cp, s)
	// Simple insertion sort (fine for benchmark sizes)
	for i := 1; i < len(cp); i++ {
		key := cp[i]
		j := i - 1
		for j >= 0 && cp[j] > key {
			cp[j+1] = cp[j]
			j--
		}
		cp[j+1] = key
	}
	return cp
}

func percentile(sorted []int64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(p)/100.0*float64(len(sorted)-1))
	return float64(sorted[idx])
}
