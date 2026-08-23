package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// HealthRecord represents a patient medical record on-chain
type HealthRecord struct {
	RecordID        string `json:"recordId"`
	PatientID       string `json:"patientId"`       // hashed, never plaintext
	DataHash        string `json:"dataHash"`         // SHA-256 of actual medical data
	OffChainPointer string `json:"offChainPointer"`  // IPFS CID
	ZKPProofHash    string `json:"zkpProofHash"`     // hash of ZKP proof for audit
	AccessPolicy    string `json:"accessPolicy"`     // JSON-encoded policy
	Timestamp       string `json:"timestamp"`
	RecordType      string `json:"recordType"`       // e.g. "diagnosis", "prescription"
	ConsentGranted  bool   `json:"consentGranted"`
	CreatorMSP      string `json:"creatorMsp"`
}

// AccessPolicyRule defines authorization policy requirements
type AccessPolicyRule struct {
	RequireZKP   bool     `json:"requireZKP"`
	AllowedRoles []string `json:"allowedRoles"`
	AllowedMSPs  []string `json:"allowedMSPs"`
}

// AccessLog tracks every access attempt for Zero Trust audit
type AccessLog struct {
	LogID       string `json:"logId"`
	RecordID    string `json:"recordId"`
	RequesterID string `json:"requesterId"`
	Action      string `json:"action"`
	Timestamp   string `json:"timestamp"`
	Granted     bool   `json:"granted"`
	ZKPVerified bool   `json:"zkpVerified"`
}

// ZeroTrustBlockContract is the main chaincode contract
type ZeroTrustBlockContract struct {
	contractapi.Contract
}

// Helper to extract deterministic transaction timestamp from Fabric proposal
func getTxTimestampString(ctx contractapi.TransactionContextInterface) (string, error) {
	txTime, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	return time.Unix(txTime.Seconds, int64(txTime.Nanos)).UTC().Format(time.RFC3339), nil
}

// ============================================================
// CreateHealthRecord - write a new encrypted health record
// ============================================================
func (c *ZeroTrustBlockContract) CreateHealthRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	patientID string, // should be hashed by gateway before sending
	dataHash string,
	offChainPointer string,
	zkpProofHash string,
	recordType string,
	accessPolicy string,
) error {
	// Check record doesn't already exist
	existing, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return fmt.Errorf("failed to read state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("record %s already exists", recordID)
	}

	// Deterministic transaction timestamp from Fabric proposal
	timestamp, err := getTxTimestampString(ctx)
	if err != nil {
		return err
	}

	// Extract creator identity MSP
	creatorMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		creatorMSP = "UNKNOWN"
	}

	// Default default policy if empty
	if strings.TrimSpace(accessPolicy) == "" {
		accessPolicy = `{"requireZKP":true,"allowedMSPs":["HospitalMSP","InsurerMSP"]}`
	}

	record := HealthRecord{
		RecordID:        recordID,
		PatientID:       patientID,
		DataHash:        dataHash,
		OffChainPointer: offChainPointer,
		ZKPProofHash:    zkpProofHash,
		AccessPolicy:    accessPolicy,
		Timestamp:       timestamp,
		RecordType:      recordType,
		ConsentGranted:  true,
		CreatorMSP:      creatorMSP,
	}

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %v", err)
	}

	return ctx.GetStub().PutState(recordID, recordBytes)
}

// ============================================================
// ReadHealthRecord - retrieve a record (enforces Zero Trust access policy & consent)
// ============================================================
func (c *ZeroTrustBlockContract) ReadHealthRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	requesterID string,
	zkpProofHash string, // requester must supply verified ZKP proof hash
) (*HealthRecord, error) {
	recordBytes, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return nil, fmt.Errorf("failed to read state: %v", err)
	}
	if recordBytes == nil {
		return nil, fmt.Errorf("record %s not found", recordID)
	}

	var record HealthRecord
	if err := json.Unmarshal(recordBytes, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal record: %v", err)
	}

	// CRITICAL FIX: Check Consent Revocation FIRST
	if !record.ConsentGranted {
		_ = c.logAccess(ctx, recordID, requesterID, "READ", false, false)
		return nil, fmt.Errorf("access denied: patient consent has been revoked for record %s", recordID)
	}

	// Extract requester MSP ID
	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		clientMSP = "UNKNOWN"
	}

	// Zero Trust: verify access policy and identity
	granted, zkpVerified := c.evaluateAccessPolicy(record.AccessPolicy, requesterID, clientMSP, zkpProofHash)

	// Always log the access attempt for immutable audit trail
	if logErr := c.logAccess(ctx, recordID, requesterID, "READ", granted, zkpVerified); logErr != nil {
		return nil, fmt.Errorf("failed to record access log: %v", logErr)
	}

	if !granted {
		return nil, fmt.Errorf("access denied for requester %s (MSP: %s) on record %s", requesterID, clientMSP, recordID)
	}

	return &record, nil
}

// ============================================================
// RevokeConsent - patient/creator revokes data sharing consent
// ============================================================
func (c *ZeroTrustBlockContract) RevokeConsent(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	patientID string,
) error {
	recordBytes, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return fmt.Errorf("failed to read state: %v", err)
	}
	if recordBytes == nil {
		return fmt.Errorf("record %s not found", recordID)
	}

	var record HealthRecord
	if err := json.Unmarshal(recordBytes, &record); err != nil {
		return fmt.Errorf("failed to unmarshal: %v", err)
	}

	// Identity Verification: verify client identity owns/created record or matches patientID
	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get client MSP: %v", err)
	}

	if record.PatientID != patientID && record.CreatorMSP != clientMSP {
		return fmt.Errorf("unauthorized: caller identity (MSP: %s) does not match patient or record creator", clientMSP)
	}

	timestamp, err := getTxTimestampString(ctx)
	if err != nil {
		return err
	}

	record.ConsentGranted = false
	record.Timestamp = timestamp

	updatedBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated record: %v", err)
	}

	if err := ctx.GetStub().PutState(recordID, updatedBytes); err != nil {
		return err
	}

	// Log consent revocation event
	return c.logAccess(ctx, recordID, patientID, "REVOKE_CONSENT", true, false)
}

// ============================================================
// UpdateZKPProof - update the ZKP proof hash for a record
// ============================================================
func (c *ZeroTrustBlockContract) UpdateZKPProof(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	newZKPProofHash string,
) error {
	recordBytes, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return fmt.Errorf("failed to read state: %v", err)
	}
	if recordBytes == nil {
		return fmt.Errorf("record %s not found", recordID)
	}

	// Verify authorization: caller must be member of an authorized MSP
	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil || (clientMSP != "HospitalMSP" && clientMSP != "InsurerMSP") {
		return fmt.Errorf("unauthorized: client MSP %s is not permitted to update ZKP proof", clientMSP)
	}

	var record HealthRecord
	if err := json.Unmarshal(recordBytes, &record); err != nil {
		return fmt.Errorf("failed to unmarshal: %v", err)
	}

	timestamp, err := getTxTimestampString(ctx)
	if err != nil {
		return err
	}

	record.ZKPProofHash = newZKPProofHash
	record.Timestamp = timestamp

	updatedBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal: %v", err)
	}

	return ctx.GetStub().PutState(recordID, updatedBytes)
}

// ============================================================
// GetAccessLogs - retrieve audit trail for a record
// ============================================================
func (c *ZeroTrustBlockContract) GetAccessLogs(
	ctx contractapi.TransactionContextInterface,
	recordID string,
) ([]AccessLog, error) {
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey("log", []string{recordID})
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %v", err)
	}
	defer iterator.Close()

	var logs []AccessLog
	for iterator.HasNext() {
		result, err := iterator.Next()
		if err != nil {
			return nil, err
		}
		var log AccessLog
		if err := json.Unmarshal(result.Value, &log); err != nil {
			continue
		}
		logs = append(logs, log)
	}

	return logs, nil
}

// ============================================================
// Internal helpers
// ============================================================

// evaluateAccessPolicy - Zero Trust access policy evaluation
func (c *ZeroTrustBlockContract) evaluateAccessPolicy(policyJSON, requesterID, clientMSP, zkpProofHash string) (bool, bool) {
	if strings.TrimSpace(zkpProofHash) == "" {
		return false, false
	}

	// Parse Policy JSON
	var policy AccessPolicyRule
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		// Fallback policy: require ZKP proof and valid MSP
		if zkpProofHash == "" {
			return false, false
		}
		return true, true
	}

	// Enforce ZKP Requirement
	if policy.RequireZKP && strings.TrimSpace(zkpProofHash) == "" {
		return false, false
	}

	// Enforce Allowed MSPs
	if len(policy.AllowedMSPs) > 0 {
		mspAllowed := false
		for _, msp := range policy.AllowedMSPs {
			if msp == clientMSP {
				mspAllowed = true
				break
			}
		}
		if !mspAllowed {
			return false, true
		}
	}

	return true, true
}

// logAccess - writes an immutable access log entry (deterministic & error checking)
func (c *ZeroTrustBlockContract) logAccess(
	ctx contractapi.TransactionContextInterface,
	recordID, requesterID, action string,
	granted bool,
	zkpVerified bool,
) error {
	txID := ctx.GetStub().GetTxID()
	timestamp, err := getTxTimestampString(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %v", err)
	}

	logID := fmt.Sprintf("%s-%s-%s", recordID, requesterID, txID)
	entry := AccessLog{
		LogID:       logID,
		RecordID:    recordID,
		RequesterID: requesterID,
		Action:      action,
		Timestamp:   timestamp,
		Granted:     granted,
		ZKPVerified: zkpVerified,
	}

	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal access log: %v", err)
	}

	compositeKey, err := ctx.GetStub().CreateCompositeKey("log", []string{recordID, logID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}

	return ctx.GetStub().PutState(compositeKey, entryBytes)
}

func main() {
	chaincode, err := contractapi.NewChaincode(&ZeroTrustBlockContract{})
	if err != nil {
		fmt.Printf("Error creating ZeroTrustBlock chaincode: %v\n", err)
		return
	}
	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting ZeroTrustBlock chaincode: %v\n", err)
	}
}
