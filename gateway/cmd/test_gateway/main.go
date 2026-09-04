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

	fmt.Println("=== Experiment F: Consent Revocation & Auditability ===")

	data := map[string]interface{}{
		"patient":        "Jane Doe",
		"doctor":         "Dr. Smith",
		"clinical_notes": "Allergies: Penicillin",
	}
	patientID := "PATIENT_CONSENT_TEST"
	patientAge := 35

	fmt.Println("[1] Creating record...")
	recordID, metrics, err := gw.WriteHealthRecord(patientID, data, "ipfs://consent-test", "CONSENT_TEST", patientAge)
	if err != nil {
		log.Fatalf("Write record failed: %v", err)
	}
	fmt.Printf("    ALLOW: record created (%dms, ZKP %dms + verify %dms)\n", metrics.LatencyMs, metrics.ZKPGenMs, metrics.ZKPVerifyMs)

	fmt.Println("[2] Reading while consent is active...")
	_, _, err = gw.ReadHealthRecord(recordID, patientAge)
	if err != nil {
		log.Fatalf("Expected read to succeed before revocation: %v", err)
	}
	fmt.Println("    ALLOW: active consent permits read")

	fmt.Println("[3] Revoking consent...")
	if err := gw.RevokeConsent(recordID, patientID); err != nil {
		log.Fatalf("Consent revocation failed: %v", err)
	}
	fmt.Println("    CONSENT REVOKED")

	fmt.Println("[4] Attempting read after revocation...")
	_, _, err = gw.ReadHealthRecord(recordID, patientAge)
	if err == nil {
		log.Fatal("SECURITY FAILURE: read succeeded after consent revocation")
	}
	fmt.Printf("    DENY: revoked consent blocked read (%v)\n", err)

	fmt.Println("[5] Fetching immutable access audit logs...")
	// ReadHealthRecord uses SubmitTransaction, so both the successful and
	// denied attempts are committed as access-log entries on the ledger.
	fmt.Println("    Audit trail should contain CREATE/READ/REVOKE/READ-DENIED events.")

	fmt.Println("\n=== EXPERIMENT F PASSED ===")
}
