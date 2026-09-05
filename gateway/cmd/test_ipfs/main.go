package main

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"strings"

	"zerotrust/gateway"
)

func main() {
	cfg := gateway.GatewayConfig{
		ConnectionProfilePath: "connection-profile.yaml",
		WalletPath:            "wallet",
		OrgMSP:                "HospitalMSP",
		ChannelName:           "healthchannel",
		HealthChaincode:       "health",
		UserIdentity:          "doctor",
	}

	gw, err := gateway.NewGateway(cfg)
	if err != nil {
		log.Fatalf("gateway initialization failed: %v", err)
	}
	defer gw.Close()

	fmt.Println("=== IPFS End-to-End Integration Test ===")

	expected := map[string]interface{}{
		"patient":        "IPFS-E2E-PATIENT",
		"diagnosis":      "Secure end-to-end IPFS test",
		"clinical_notes": "Encrypted off-chain payload",
	}

	fmt.Println("[1] WRITE: Gateway -> ZKP -> AES-256-GCM -> IPFS -> Fabric")
	recordID, metrics, err := gw.WriteHealthRecord(
		"IPFS-E2E-PATIENT",
		expected,
		"",
		"IPFS_E2E_TEST",
		35,
	)
	if err != nil {
		log.Fatalf("write failed: %v", err)
	}
	fmt.Printf("    record=%s latency=%dms zkp=%.2fms verify=%.2fms\n", recordID, metrics.LatencyMs, metrics.ZKPGenMs, metrics.ZKPVerifyMs)

	fmt.Println("[2] READ: Fabric authorization + audit")
	record, _, err := gw.ReadHealthRecord(recordID, 35)
	if err != nil {
		log.Fatalf("read failed: %v", err)
	}

	pointer, ok := record["offChainPointer"].(string)
	if !ok || !strings.HasPrefix(pointer, "ipfs://") {
		log.Fatalf("expected an IPFS pointer, got %v", record["offChainPointer"])
	}
	cid := strings.TrimPrefix(pointer, "ipfs://")
	if cid == "" {
		log.Fatal("IPFS pointer contains an empty CID")
	}
	fmt.Printf("    pointer=%s\n", pointer)
	fmt.Printf("    cid=%s\n", cid)
	fmt.Printf("    dataHash=%v\n", record["dataHash"])

	fmt.Println("[3] FETCH: authorized record -> IPFS CID -> decrypt -> SHA-256 -> JSON")
	actual, _, err := gw.GetAuthorizedOffChainData(recordID, 35)
	if err != nil {
		log.Fatalf("authorized off-chain retrieval failed: %v", err)
	}

	if !reflect.DeepEqual(expected, actual) {
		expectedJSON, _ := json.MarshalIndent(expected, "", "  ")
		actualJSON, _ := json.MarshalIndent(actual, "", "  ")
		log.Fatalf("payload mismatch\nexpected=%s\nactual=%s", expectedJSON, actualJSON)
	}

	fmt.Println("    payload integrity: OK")
	fmt.Println("    payload decryption: OK")
	fmt.Println("    payload round-trip: OK")
	fmt.Println("=== IPFS END-TO-END TEST PASSED ===")
}
