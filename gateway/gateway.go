package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"zerotrust/zkp"
)

type GatewayConfig struct {
	ConnectionProfilePath string
	WalletPath            string
	OrgMSP                string
	ChannelName           string
	HealthChaincode       string
	UserIdentity          string
}

type TransactionMetrics struct {
	TxID           string  `json:"txId"`
	Operation      string  `json:"operation"`
	StartTime      int64   `json:"startTimeUnixMs"`
	EndTime        int64   `json:"endTimeUnixMs"`
	LatencyMs      int64   `json:"latencyMs"`
	ZKPGenMs       float64 `json:"zkpGenMs"`
	ZKPVerifyMs    float64 `json:"zkpVerifyMs"`
	ProofSizeBytes int     `json:"proofSizeBytes"`
	Success        bool    `json:"success"`
	ErrorMessage   string  `json:"errorMessage,omitempty"`
}

type ZeroTrustGateway struct {
	cfg        GatewayConfig
	gw         *gateway.Gateway
	network    *gateway.Network
	zkpService *zkp.ZKPService
	ipfs       *IPFSClient
	mu         sync.Mutex
	metrics    []TransactionMetrics
}

func NewGateway(cfg GatewayConfig) (*ZeroTrustGateway, error) {
	wallet, err := gateway.NewFileSystemWallet(cfg.WalletPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet: %v", err)
	}
	if !wallet.Exists(cfg.UserIdentity) {
		return nil, fmt.Errorf("identity %s not found in wallet — run enrollUser first", cfg.UserIdentity)
	}
	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(cfg.ConnectionProfilePath)),
		gateway.WithIdentity(wallet, cfg.UserIdentity),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to gateway: %v", err)
	}
	network, err := gw.GetNetwork(cfg.ChannelName)
	if err != nil {
		gw.Close()
		return nil, fmt.Errorf("failed to get network %s: %v", cfg.ChannelName, err)
	}
	zkpSvc := &zkp.ZKPService{}
	if err := zkpSvc.Setup(); err != nil {
		gw.Close()
		return nil, fmt.Errorf("failed to initialize ZKP circuit engine: %v", err)
	}
	ipfs, err := NewIPFSClientFromEnv()
	if err != nil {
		gw.Close()
		return nil, fmt.Errorf("failed to initialize IPFS client: %v", err)
	}
	if ipfs != nil {
		fmt.Printf("[Gateway] Encrypted IPFS storage active at %s\n", ipfs.APIURL)
	}
	fmt.Println("[Gateway] ZKP Engine active with gnark BN254 Groth16 circuits")
	return &ZeroTrustGateway{cfg: cfg, gw: gw, network: network, zkpService: zkpSvc, ipfs: ipfs, metrics: make([]TransactionMetrics, 0)}, nil
}

func (g *ZeroTrustGateway) WriteHealthRecord(patientID string, rawData map[string]interface{}, offChainPointer string, recordType string, patientAge int) (string, *TransactionMetrics, error) {
	m := &TransactionMetrics{TxID: fmt.Sprintf("tx-%d", time.Now().UnixNano()), Operation: "WriteHealthRecord", StartTime: time.Now().UnixMilli()}
	if g.zkpService == nil {
		return "", nil, fmt.Errorf("ZKP circuit engine is uninitialized")
	}
	proofResult, err := g.zkpService.ProveAgeRange(patientAge, 18, 120)
	if err != nil {
		return "", nil, fmt.Errorf("ZKP proof generation failed: %w", err)
	}
	if !proofResult.IsValid {
		return "", nil, fmt.Errorf("ZKP proof verification failed: invalid zk-SNARK witness/proof")
	}
	m.ZKPGenMs, m.ZKPVerifyMs, m.ProofSizeBytes = proofResult.GenTimeMs, proofResult.VerifyTimeMs, proofResult.ProofSizeBytes
	zkpProofHash := proofResult.ProofHash
	hashedPatientID := hashString(patientID)
	dataBytes, err := json.Marshal(rawData)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal data: %v", err)
	}
	dataHash := hashBytes(dataBytes)
	recordID := fmt.Sprintf("rec-%s-%d", hashedPatientID[:8], time.Now().UnixNano())

	// If IPFS is enabled, the raw JSON is encrypted before leaving the Gateway.
	// Fabric stores the CID and the plaintext data hash; the medical payload itself
	// is never uploaded in plaintext.
	if g.ipfs != nil {
		cid, err := g.ipfs.AddEncryptedJSON(dataBytes, recordID+".json")
		if err != nil {
			return "", nil, fmt.Errorf("IPFS upload failed: %w", err)
		}
		offChainPointer = "ipfs://" + cid
	}

	accessPolicy := `{"requireZKP": true, "allowedMSPs": ["HospitalMSP", "InsurerMSP"], "allowedRoles": ["doctor", "insurer"]}`
	contract := g.network.GetContract(g.cfg.HealthChaincode)
	_, err = contract.SubmitTransaction("CreateHealthRecord", recordID, hashedPatientID, dataHash, offChainPointer, zkpProofHash, recordType, accessPolicy)
	m.EndTime = time.Now().UnixMilli()
	m.LatencyMs = m.EndTime - m.StartTime
	g.mu.Lock()
	if err != nil {
		m.Success = false
		m.ErrorMessage = err.Error()
		g.metrics = append(g.metrics, *m)
		g.mu.Unlock()
		return "", m, fmt.Errorf("chaincode invoke failed: %v", err)
	}
	m.Success = true
	g.metrics = append(g.metrics, *m)
	g.mu.Unlock()
	return recordID, m, nil
}

func (g *ZeroTrustGateway) ReadHealthRecord(recordID string, patientAge int) (map[string]interface{}, *TransactionMetrics, error) {
	m := &TransactionMetrics{TxID: fmt.Sprintf("tx-%d", time.Now().UnixNano()), Operation: "ReadHealthRecord", StartTime: time.Now().UnixMilli()}
	if g.zkpService == nil {
		return nil, nil, fmt.Errorf("ZKP circuit engine is uninitialized")
	}
	proofResult, err := g.zkpService.ProveAgeRange(patientAge, 18, 120)
	if err != nil {
		return nil, nil, fmt.Errorf("ZKP proof generation failed: %w", err)
	}
	if !proofResult.IsValid {
		return nil, nil, fmt.Errorf("ZKP proof verification failed: invalid zk-SNARK witness/proof")
	}
	m.ZKPGenMs, m.ZKPVerifyMs, m.ProofSizeBytes = proofResult.GenTimeMs, proofResult.VerifyTimeMs, proofResult.ProofSizeBytes
	result, err := g.network.GetContract(g.cfg.HealthChaincode).SubmitTransaction("ReadHealthRecord", recordID, proofResult.ProofHash)
	m.EndTime = time.Now().UnixMilli()
	m.LatencyMs = m.EndTime - m.StartTime
	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		m.Success = false
		m.ErrorMessage = err.Error()
		g.metrics = append(g.metrics, *m)
		return nil, m, fmt.Errorf("read failed: %v", err)
	}
	var readResult struct {
		Allowed bool                   `json:"allowed"`
		Record  map[string]interface{} `json:"record,omitempty"`
		Error   string                 `json:"error,omitempty"`
	}
	if err := json.Unmarshal(result, &readResult); err != nil {
		m.Success = false
		m.ErrorMessage = fmt.Sprintf("failed to parse result: %v", err)
		g.metrics = append(g.metrics, *m)
		return nil, m, fmt.Errorf("failed to parse result: %v", err)
	}
	// The Fabric transaction committed successfully, including the audit log.
	// An authorization denial is an application-level denial, not a Fabric failure.
	if !readResult.Allowed {
		m.Success = false
		m.ErrorMessage = readResult.Error
		g.metrics = append(g.metrics, *m)
		return nil, m, fmt.Errorf("%s", readResult.Error)
	}
	m.Success = true
	g.metrics = append(g.metrics, *m)
	return readResult.Record, m, nil
}

// GetOffChainData retrieves and decrypts the IPFS payload for an authorized record.
// Authorization must be performed by ReadHealthRecord before calling this method.
// The returned payload is checked against the on-chain data hash to detect corruption.
func (g *ZeroTrustGateway) GetOffChainData(record map[string]interface{}) (map[string]interface{}, error) {
	if g.ipfs == nil {
		return nil, fmt.Errorf("IPFS storage is disabled")
	}
	pointer, _ := record["offChainPointer"].(string)
	if pointer == "" || !strings.HasPrefix(pointer, "ipfs://") {
		return nil, fmt.Errorf("record does not contain an IPFS pointer")
	}
	data, err := g.ipfs.CatEncrypted(pointer)
	if err != nil {
		return nil, err
	}
	if expected, ok := record["dataHash"].(string); ok && expected != "" && hashBytes(data) != expected {
		return nil, fmt.Errorf("IPFS payload hash does not match ledger dataHash")
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("failed to parse decrypted IPFS payload: %w", err)
	}
	return decoded, nil
}

func (g *ZeroTrustGateway) RevokeConsent(recordID string, patientID string) error {
	_, err := g.network.GetContract(g.cfg.HealthChaincode).SubmitTransaction("RevokeConsent", recordID, hashString(patientID))
	return err
}

// GetAccessLogs retrieves the immutable audit entries committed by ReadHealthRecord and RevokeConsent.
func (g *ZeroTrustGateway) GetAccessLogs(recordID string) ([]map[string]interface{}, error) {
	result, err := g.network.GetContract(g.cfg.HealthChaincode).EvaluateTransaction("GetAccessLogs", recordID)
	if err != nil {
		return nil, fmt.Errorf("failed to query access logs: %v", err)
	}
	var logs []map[string]interface{}
	if err := json.Unmarshal(result, &logs); err != nil {
		return nil, fmt.Errorf("failed to parse access logs: %v", err)
	}
	return logs, nil
}

func (g *ZeroTrustGateway) GetBenchmarkSummary() map[string]interface{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.metrics) == 0 {
		return map[string]interface{}{"error": "no metrics collected yet"}
	}
	var totalLatency int64
	var totalZKPGen, totalZKPVerify float64
	var totalProofSize, successCount int
	for _, m := range g.metrics {
		totalLatency += m.LatencyMs
		totalZKPGen += m.ZKPGenMs
		totalZKPVerify += m.ZKPVerifyMs
		totalProofSize += m.ProofSizeBytes
		if m.Success { successCount++ }
	}
	count := float64(len(g.metrics))
	return map[string]interface{}{"totalTransactions": int64(count), "successRate": fmt.Sprintf("%.1f%%", float64(successCount)/count*100), "avgLatencyMs": totalLatency / int64(count), "avgZKPGenMs": totalZKPGen / count, "avgZKPVerifyMs": totalZKPVerify / count, "avgProofSizeBytes": totalProofSize / int(count)}
}

func (g *ZeroTrustGateway) Close() {
	if g.gw != nil { g.gw.Close() }
}

func hashString(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func hashBytes(b []byte) string  { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
