package main

import (
	"encoding/json"
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
	if err != nil { log.Fatalf("Failed to connect to gateway: %v", err) }
	defer gw.Close()

	fmt.Println("=== Experiment F: Consent Revocation & Auditability ===")
	data := map[string]interface{}{"patient": "Jane Doe", "doctor": "Dr. Smith", "clinical_notes": "Allergies: Penicillin"}
	patientID := "PATIENT_CONSENT_TEST"
	patientAge := 35

	recordID, metrics, err := gw.WriteHealthRecord(patientID, data, "ipfs://consent-test", "CONSENT_TEST", patientAge)
	if err != nil { log.Fatalf("Write record failed: %v", err) }
	fmt.Printf("[1] CREATE: ALLOW | latency=%dms | zkp=%dms | verify=%dms\n", metrics.LatencyMs, metrics.ZKPGenMs, metrics.ZKPVerifyMs)

	if _, _, err = gw.ReadHealthRecord(recordID, patientAge); err != nil {
		log.Fatalf("[2] READ before revocation should succeed: %v", err)
	}
	fmt.Println("[2] READ before revocation: ALLOW")

	if err := gw.RevokeConsent(recordID, patientID); err != nil { log.Fatalf("[3] revoke failed: %v", err) }
	fmt.Println("[3] REVOKE_CONSENT: COMMITTED")

	if _, _, err = gw.ReadHealthRecord(recordID, patientAge); err == nil {
		log.Fatal("[4] SECURITY FAILURE: read succeeded after consent revocation")
	} else {
		fmt.Printf("[4] READ after revocation: DENY | %v\n", err)
	}

	logs, err := gw.GetAccessLogs(recordID)
	if err != nil { log.Fatalf("[5] failed to retrieve audit logs: %v", err) }
	encoded, _ := json.MarshalIndent(logs, "", "  ")
	fmt.Printf("[5] Audit log entries: %d\n%s\n", len(logs), string(encoded))
	if len(logs) < 3 { log.Fatalf("Expected at least 3 committed audit events, got %d", len(logs)) }

	fmt.Println("=== EXPERIMENT F PASSED ===")
}
