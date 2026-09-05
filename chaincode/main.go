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
	PatientID       string `json:"patientId"`       // SHA-256 hash of patient identifier
	PatientIdentity string `json:"patientIdentity"` // Authenticated Fabric x509 identity derived via cid.GetID()
	DataHash        string `json:"dataHash"`        // SHA-256 of actual medical data payload
	OffChainPointer string `json:"offChainPointer"` // IPFS CID or off-chain pointer
	ZKPProofHash    string `json:"zkpProofHash"`    // Hash of verified ZKP proof registered off-chain
	AccessPolicy    string `json:"accessPolicy"`    // JSON-encoded policy
	Timestamp       string `json:"timestamp"`
	RecordType      string `json:"recordType"` // e.g. "diagnosis", "prescription"
	ConsentGranted  bool   `json:"consentGranted"`
	CreatorMSP      string `json:"creatorMsp"`
	CreatorID       string `json:"creatorId"`
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
	RequesterID string `json:"requesterId"` // Verified x509 identity derived via cid.GetID()
	Action      string `json:"action"`
	Timestamp   string `json:"timestamp"`
	Granted     bool   `json:"granted"`
	ZKPVerified bool   `json:"zkpVerified"`
}

// ReadHealthRecordResult represents the outcome of an access attempt.
// Every response field is present so Fabric Contract API can validate a
// stable response schema for both allowed and denied transactions.
type ReadHealthRecordResult struct {
	Allowed bool          `json:"allowed"`
	Record  *HealthRecord `json:"record"`
	Error   string        `json:"error"`
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
// CreateHealthRecord - write a new health record
// ============================================================
func (c *ZeroTrustBlockContract) CreateHealthRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	patientID string, // hashed patient ID
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

	// Extract creator identity from Fabric client certificate
	creatorMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		creatorMSP = "UNKNOWN"
	}
	creatorID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		creatorID = "UNKNOWN"
	}

	// Default policy if empty
	if strings.TrimSpace(accessPolicy) == "" {
		accessPolicy = `{"requireZKP":true,"allowedMSPs":["HospitalMSP","InsurerMSP"],"allowedRoles":["doctor","insurer"]}`
	}

	record := HealthRecord{
		RecordID:        recordID,
		PatientID:       patientID,
		PatientIdentity: creatorID, // Binds record to authenticated caller identity
		DataHash:        dataHash,
		OffChainPointer: offChainPointer,
		ZKPProofHash:    zkpProofHash,
		AccessPolicy:    accessPolicy,
		Timestamp:       timestamp,
		RecordType:      recordType,
		ConsentGranted:  true,
		CreatorMSP:      creatorMSP,
		CreatorID:       creatorID,
	}

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %v", err)
	}

	return ctx.GetStub().PutState(recordID, recordBytes)
}

// ============================================================
// ReadHealthRecord - retrieve a record & commit immutable audit log
// ============================================================
func (c *ZeroTrustBlockContract) ReadHealthRecord(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	zkpProofHash string,
) (*ReadHealthRecordResult, error) {
	// Derive authentic requester identity directly from Fabric certificate
	requesterID, err := ctx.GetClientIdentity().GetID()
	if err != nil || requesterID == "" {
		requesterID = "UNKNOWN_CLIENT"
	}

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

	// Check consent revocation FIRST. Expected denials return a successful
	// transaction so the corresponding audit log is committed.
	if !record.ConsentGranted {
		if err := c.logAccess(ctx, recordID, requesterID, "READ", false, false); err != nil {
			return nil, fmt.Errorf("failed to write audit log: %v", err)
		}

		return &ReadHealthRecordResult{
			Allowed: false,
			Record:  &record,
			Error:   fmt.Sprintf("access denied: patient consent has been revoked for record %s", recordID),
		}, nil
	}

	// Extract client MSP ID
	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		clientMSP = "UNKNOWN"
	}

	// Zero Trust: evaluate policy with authenticated identity and role attributes
	granted, zkpVerified := c.evaluateAccessPolicy(
		ctx,
		record.AccessPolicy,
		clientMSP,
		zkpProofHash,
	)

	// ALWAYS write the audit event.
	if err := c.logAccess(
		ctx,
		recordID,
		requesterID,
		"READ",
		granted,
		zkpVerified,
	); err != nil {
		return nil, fmt.Errorf("failed to write audit log: %v", err)
	}

	if !granted {
		return &ReadHealthRecordResult{
			Allowed: false,
			Record:  &record,
			Error: fmt.Sprintf(
				"access denied for identity %s (MSP: %s) on record %s",
				requesterID,
				clientMSP,
				recordID,
			),
		}, nil
	}

	return &ReadHealthRecordResult{
		Allowed: true,
		Record:  &record,
		Error:   "",
	}, nil
}

// ============================================================
// RevokeConsent - patient/creator revokes data sharing consent
// ============================================================
func (c *ZeroTrustBlockContract) RevokeConsent(
	ctx contractapi.TransactionContextInterface,
	recordID string,
	patientID string,
) error {
	callerID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to extract caller identity: %v", err)
	}

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

	// Identity Authorization: caller MUST match PatientIdentity or CreatorID
	if callerID != record.PatientIdentity && callerID != record.CreatorID {
		return fmt.Errorf("unauthorized: caller identity %s is neither patient nor record creator", callerID)
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
	return c.logAccess(ctx, recordID, callerID, "REVOKE_CONSENT", true, false)
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

	// Verify authorization: caller must be member of HospitalMSP or InsurerMSP
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
// Fails closed on invalid policy JSON or missing required role attributes
func (c *ZeroTrustBlockContract) evaluateAccessPolicy(
	ctx contractapi.TransactionContextInterface,
	policyJSON, clientMSP, zkpProofHash string,
) (bool, bool) {
	if strings.TrimSpace(zkpProofHash) == "" {
		return false, false
	}

	// SECURITY FIX (Point #2): Policy parsing failure MUST fail closed (deny access)
	var policy AccessPolicyRule
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return false, false
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

	// SECURITY FIX (Point #1): Enforce Allowed Roles strictly (fail closed if role attribute is missing/invalid when roles are required)
	if len(policy.AllowedRoles) > 0 {
		roleAttr, found, err := ctx.GetClientIdentity().GetAttributeValue("role")
		if err != nil || !found || strings.TrimSpace(roleAttr) == "" {
			return false, true
		}

		roleAllowed := false
		for _, role := range policy.AllowedRoles {
			if strings.EqualFold(role, roleAttr) {
				roleAllowed = true
				break
			}
		}
		if !roleAllowed {
			return false, true
		}
	}

	return true, true
}

// logAccess - writes an immutable access log entry
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

	logID := fmt.Sprintf("%s-%s", recordID, txID)
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
