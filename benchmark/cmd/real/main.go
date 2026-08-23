package main

import (
	"fmt"
	"log"
	"math/rand"
	"zerotrust/gateway"
	"github.com/google/uuid"
	"sync"
	"time"
)

type BenchmarkConfig struct {
	ConcurrentTx  int
	TotalTx       int
	WalletPath    string
	CCPPath       string
	ChannelName   string
	ChaincodeName string
}

func main() {
	cfg := BenchmarkConfig{
		ConcurrentTx:  500, // Peak Saturation
		TotalTx:       5000,
		WalletPath:    "../gateway/wallet",
		CCPPath:       "../gateway/connection-profile.yaml",
		ChannelName:   "healthchannel",
		ChaincodeName: "health",
	}

	gwCfg := gateway.GatewayConfig{
		ConnectionProfilePath: cfg.CCPPath,
		WalletPath:            cfg.WalletPath,
		OrgMSP:                "HospitalMSP",
		ChannelName:           cfg.ChannelName,
		HealthChaincode:       cfg.ChaincodeName,
		UserIdentity:          "appAdmin",
	}

	gw, err := gateway.NewGateway(gwCfg)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	fmt.Printf("=== Starting Real Network Benchmark ===\n")
	fmt.Printf("Concurrent: %d | Total: %d\n\n", cfg.ConcurrentTx, cfg.TotalTx)

	start := time.Now()
	var wg sync.WaitGroup
	results := make(chan int64, cfg.TotalTx)
	errors := make(chan error, cfg.TotalTx)

	sem := make(chan bool, cfg.ConcurrentTx)

	for i := 0; i < cfg.TotalTx; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sem <- true
			defer func() { <-sem }()

			patientID := fmt.Sprintf("BENCH_PATIENT_%d", id)
			data := map[string]interface{}{
				"id":   id,
				"uuid": uuid.New().String(),
				"val":  rand.Intn(1000),
			}

			// Measure a WriteHealthRecord
			_, metrics, err := gw.WriteHealthRecord(patientID, data, "ipfs://bench", "BENCHMARK", "ZKP_HASH_TEST")
			if err != nil {
				errors <- err
				return
			}
			results <- metrics.LatencyMs
		}(i)
	}

	wg.Wait()
	close(results)
	close(errors)

	duration := time.Since(start)
	
	var totalLatency int64
	count := 0
	for l := range results {
		totalLatency += l
		count++
	}

	errorCount := len(errors)
	if errorCount > 0 {
		fmt.Printf("First Error:      %v\n", <-errors)
	}
	
	fmt.Println("\n=== Benchmark Completed ===")
	fmt.Printf("Total Successful: %d\n", count)
	fmt.Printf("Total Errors:     %d\n", errorCount)
	fmt.Printf("Total Duration:   %.2fs\n", duration.Seconds())
	if count > 0 {
		fmt.Printf("Avg Latency:      %dms\n", totalLatency/int64(count))
		fmt.Printf("Throughput:       %.2f TPS\n", float64(count)/duration.Seconds())
	}
}
