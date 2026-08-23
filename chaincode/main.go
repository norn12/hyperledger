package main

import (
	"encoding/json"
	"fmt"
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
}

// AccessLog tracks every access attempt for Zero Trust audit
type AccessLog struct {
	LogID      string `json:"logId"`
	RecordID   string `json:"recordId"`
	RequesterID string `json:"requesterId"`
	Action     string `json:"action"`
	Timestamp  string `json:"timestamp"`
	Granted    bool   `json:"granted"`
	ZKPVerified bool  `json:"zkpVerified"`
}

// ZeroTrustBlockContract is the main chaincode contract
type ZeroTrustBlockContract struct {
	contractapi.Contract
}

// ============================================================
// CreateHealthRecord - write a new encrypted health record
// ============================================================
func (c *ZeroTrustBlockContract) CreateHealthRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	patientID string,     // should be hashed by gateway before sending
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

	record := HealthRecord{
		RecordID:        recordID,
		PatientID:       patientID,
		DataHash:        dataHash,
		OffChainPointer: offChainPointer,
		ZKPProofHash:    zkpProofHash,
		AccessPolicy:    accessPolicy,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		RecordType:      recordType,
		ConsentGranted:  true,
	}

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %v", err)
	}

	return ctx.GetStub().PutState(recordID, recordBytes)
}

// ============================================================
// ReadHealthRecord - retrieve a record (enforces access policy)
// ============================================================
func (c *ZeroTrustBlockContract) ReadHealthRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	requesterID string,
	zkpProofHash string, // requester must supply ZKP proof
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

	// Zero Trust: verify access is permitted
	granted := c.evaluateAccessPolicy(record.AccessPolicy, requesterID, zkpProofHash)

	// Always log the access attempt regardless of outcome
	c.logAccess(ctx, recordID, requesterID, "READ", granted, zkpProofHash != "")

	if !granted {
		return nil, fmt.Errorf("access denied for requester %s on record %s", requesterID, recordID)
	}

	return &record, nil
}

// ============================================================
// RevokeConsent - patient revokes data sharing consent
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

	// Only the patient can revoke their own consent
	if record.PatientID != patientID {
		return fmt.Errorf("only the patient can revoke consent")
	}

	record.ConsentGranted = false
	record.Timestamp = time.Now().UTC().Format(time.RFC3339)

	updatedBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated record: %v", err)
	}

	return ctx.GetStub().PutState(recordID, updatedBytes)
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

	var record HealthRecord
	if err := json.Unmarshal(recordBytes, &record); err != nil {
		return fmt.Errorf("failed to unmarshal: %v", err)
	}

	record.ZKPProofHash = newZKPProofHash
	record.Timestamp = time.Now().UTC().Format(time.RFC3339)

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
	// Use composite key to fetch all logs for this record
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

// evaluateAccessPolicy - simplified Zero Trust policy check
// In production this would parse the accessPolicy JSON and enforce roles
func (c *ZeroTrustBlockContract) evaluateAccessPolicy(policy, requesterID, zkpProofHash string) bool {
	// Minimal check: requester must supply a ZKP proof hash
	// Full implementation would parse policy JSON and check roles/consent
	if zkpProofHash == "" {
		return false
	}
	// TODO: extend with role-based and consent-based checks from policy JSON
	return true
}

// logAccess - writes an immutable access log entry
func (c *ZeroTrustBlockContract) logAccess(
	ctx contractapi.TransactionContextInterface,
	recordID, requesterID, action string,
	granted bool,
	zkpVerified bool,
) {
	logID := fmt.Sprintf("%s-%s-%d", recordID, requesterID, time.Now().UnixNano())
	entry := AccessLog{
		LogID:       logID,
		RecordID:    recordID,
		RequesterID: requesterID,
		Action:      action,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Granted:     granted,
		ZKPVerified: zkpVerified,
	}

	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return
	}

	compositeKey, err := ctx.GetStub().CreateCompositeKey("log", []string{recordID, logID})
	if err != nil {
		return
	}

	ctx.GetStub().PutState(compositeKey, entryBytes)
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
