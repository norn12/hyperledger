package main

import (
	"fmt"
	"log"
	"zerotrust/gateway"
)

func main() {
	cfg := gateway.GatewayConfig{
		ConnectionProfilePath: "connection-profile.yaml",
		WalletPath:            "wallet",
		OrgMSP:                "HospitalMSP",
		ChannelName:           "healthchannel",
		HealthChaincode:       "health",
		UserIdentity:          "appAdmin",
	}

	gw, err := gateway.NewGateway(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
	}
	defer gw.Close()

	fmt.Println("✓ Successfully connected to ZeroTrustBlock Gateway!")

	// Test: Write a clinical record with real ZKP proof generation
	data := map[string]interface{}{
		"patient":        "Jane Doe",
		"doctor":         "Dr. Smith",
		"clinical_notes": "Allergies: Penicillin",
	}

	fmt.Println("Submitting clinical record to blockchain...")
	patientAge := 35
	recordID, metrics, err := gw.WriteHealthRecord("PATIENT_XYZ", data, "ipfs://CID_123", "DIAGNOSIS", patientAge)
	if err != nil {
		log.Fatalf("Write record failed: %v", err)
	}
	fmt.Printf("✓ Transaction success! Latency: %dms | ZKP Gen: %dms | ZKP Verify: %dms\n",
		metrics.LatencyMs, metrics.ZKPGenMs, metrics.ZKPVerifyMs)

	// Test: Read record back with ZKP proof verification
	fmt.Println("Retrieving record through Zero-Trust access control...")
	record, _, err := gw.ReadHealthRecord(recordID, patientAge)
	if err != nil {
		log.Fatalf("Read record failed: %v", err)
	}

	fmt.Printf("✓ Record found! Data Hash: %s\n", record["dataHash"])
	fmt.Println("\n=== GATEWAY TEST PASSED ===")
}
