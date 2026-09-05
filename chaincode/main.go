package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type HealthRecord struct {
	RecordID        string `json:"recordId"`
	PatientID       string `json:"patientId"`
	PatientIdentity string `json:"patientIdentity"`
	DataHash        string `json:"dataHash"`
	OffChainPointer string `json:"offChainPointer"`
	ZKPProofHash    string `json:"zkpProofHash"`
	AccessPolicy    string `json:"accessPolicy"`
	Timestamp       string `json:"timestamp"`
	RecordType      string `json:"recordType"`
	ConsentGranted  bool   `json:"consentGranted"`
	CreatorMSP      string `json:"creatorMsp"`
	CreatorID       string `json:"creatorId"`
}

type AccessPolicyRule struct {
	RequireZKP   bool     `json:"requireZKP"`
	AllowedRoles []string `json:"allowedRoles"`
	AllowedMSPs  []string `json:"allowedMSPs"`
}

type AccessLog struct {
	LogID       string `json:"logId"`
	RecordID    string `json:"recordId"`
	RequesterID string `json:"requesterId"`
	Action      string `json:"action"`
	Timestamp   string `json:"timestamp"`
	Granted     bool   `json:"granted"`
	ZKPVerified bool   `json:"zkpVerified"`
}

type ReadHealthRecordResult struct {
	Allowed bool          `json:"allowed"`
	Record  *HealthRecord `json:"record"`
	Error   string        `json:"error"`
}

type ZeroTrustBlockContract struct {
	contractapi.Contract
}

func getTxTimestampString(ctx contractapi.TransactionContextInterface) (string, error) {
	txTime, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", fmt.Errorf("failed to get transaction timestamp: %v", err)
	}
	return time.Unix(txTime.Seconds, int64(txTime.Nanos)).UTC().Format(time.RFC3339), nil
}

func (c *ZeroTrustBlockContract) CreateHealthRecord(ctx contractapi.TransactionContextInterface, recordID string, patientID string, dataHash string, offChainPointer string, zkpProofHash string, recordType string, accessPolicy string) error {
	existing, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return fmt.Errorf("failed to read state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("record %s already exists", recordID)
	}

	timestamp, err := getTxTimestampString(ctx)
	if err != nil {
		return err
	}

	creatorMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		creatorMSP = "UNKNOWN"
	}
	creatorID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		creatorID = "UNKNOWN"
	}

	if strings.TrimSpace(accessPolicy) == "" {
		accessPolicy = `{"requireZKP":true,"allowedMSPs":["HospitalMSP","InsurerMSP"],"allowedRoles":["doctor","insurer"]}`
	}

	record := HealthRecord{
		RecordID:        recordID,
		PatientID:       patientID,
		PatientIdentity: creatorID,
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

func (c *ZeroTrustBlockContract) ReadHealthRecord(ctx contractapi.TransactionContextInterface, recordID string, zkpProofHash string) (*ReadHealthRecordResult, error) {
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

	if !record.ConsentGranted {
		if err := c.logAccess(ctx, recordID, requesterID, "READ", false, false); err != nil {
			return nil, fmt.Errorf("failed to write audit log: %v", err)
		}
		return &ReadHealthRecordResult{Allowed: false, Record: &record, Error: fmt.Sprintf("access denied: patient consent has been revoked for record %s", recordID)}, nil
	}

	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		clientMSP = "UNKNOWN"
	}

	granted, zkpVerified := c.evaluateAccessPolicy(ctx, record.AccessPolicy, clientMSP, zkpProofHash)
	if err := c.logAccess(ctx, recordID, requesterID, "READ", granted, zkpVerified); err != nil {
		return nil, fmt.Errorf("failed to write audit log: %v", err)
	}

	if !granted {
		return &ReadHealthRecordResult{
			Allowed: false,
			Record:  &record,
			Error:   fmt.Sprintf("access denied for identity %s (MSP: %s) on record %s", requesterID, clientMSP, recordID),
		}, nil
	}

	return &ReadHealthRecordResult{Allowed: true, Record: &record, Error: ""}, nil
}

func (c *ZeroTrustBlockContract) RevokeConsent(ctx contractapi.TransactionContextInterface, recordID string, patientID string) error {
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

	if callerID != record.PatientIdentity && callerID != record.CreatorID {
		return fmt.Errorf("unauthorized: caller identity %s is neither patient nor record creator", callerID)
	}
	if strings.TrimSpace(patientID) != "" && patientID != record.PatientID {
		return fmt.Errorf("patient ID does not match the record")
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
	return c.logAccess(ctx, recordID, callerID, "REVOKE_CONSENT", true, false)
}

func (c *ZeroTrustBlockContract) UpdateZKPProof(ctx contractapi.TransactionContextInterface, recordID string, newZKPProofHash string) error {
	recordBytes, err := ctx.GetStub().GetState(recordID)
	if err != nil {
		return fmt.Errorf("failed to read state: %v", err)
	}
	if recordBytes == nil {
		return fmt.Errorf("record %s not found", recordID)
	}

	clientMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil || (clientMSP != "HospitalMSP" && clientMSP != "InsurerMSP") {
		return fmt.Errorf("unauthorized: client MSP %s is not permitted to update ZKP proof", clientMSP)
	}

	if strings.TrimSpace(newZKPProofHash) == "" {
		return fmt.Errorf("new ZKP proof hash cannot be empty")
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

func (c *ZeroTrustBlockContract) GetAccessLogs(ctx contractapi.TransactionContextInterface, recordID string) ([]AccessLog, error) {
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

func (c *ZeroTrustBlockContract) evaluateAccessPolicy(ctx contractapi.TransactionContextInterface, policyJSON, clientMSP, zkpProofHash string) (bool, bool) {
	var policy AccessPolicyRule
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return false, false
	}

	if policy.RequireZKP && strings.TrimSpace(zkpProofHash) == "" {
		return false, false
	}

	if len(policy.AllowedMSPs) > 0 {
		mspAllowed := false
		for _, msp := range policy.AllowedMSPs {
			if msp == clientMSP {
				mspAllowed = true
				break
			}
		}
		if !mspAllowed {
			return false, false
		}
	}

	if len(policy.AllowedRoles) > 0 {
		roleAttr, found, err := ctx.GetClientIdentity().GetAttributeValue("role")
		if err != nil || !found || strings.TrimSpace(roleAttr) == "" {
			return false, false
		}
		roleAllowed := false
		for _, role := range policy.AllowedRoles {
			if strings.EqualFold(role, roleAttr) {
				roleAllowed = true
				break
			}
		}
		if !roleAllowed {
			return false, false
		}
	}

	return true, true
}

func (c *ZeroTrustBlockContract) logAccess(ctx contractapi.TransactionContextInterface, recordID, requesterID, action string, granted bool, zkpVerified bool) error {
	txID := ctx.GetStub().GetTxID()
	timestamp, err := getTxTimestampString(ctx)
	if err != nil {
		return fmt.Errorf("failed to get tx timestamp: %v", err)
	}
	logID := fmt.Sprintf("%s-%s", recordID, txID)
	entry := AccessLog{LogID: logID, RecordID: recordID, RequesterID: requesterID, Action: action, Timestamp: timestamp, Granted: granted, ZKPVerified: zkpVerified}
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
