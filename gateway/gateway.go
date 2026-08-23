package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

// GatewayConfig holds connection settings for the Fabric network
type GatewayConfig struct {
	ConnectionProfilePath string
	WalletPath            string
	OrgMSP                string
	ChannelName           string
	HealthChaincode       string
	ZKPChaincode          string
	UserIdentity          string
}

// TransactionMetrics records timing for each transaction — used in benchmarking
type TransactionMetrics struct {
	TxID          string  `json:"txId"`
	Operation     string  `json:"operation"`
	StartTime     int64   `json:"startTimeUnixMs"`
	EndTime       int64   `json:"endTimeUnixMs"`
	LatencyMs     int64   `json:"latencyMs"`
	ZKPGenMs      int64   `json:"zkpGenMs"`
	ZKPVerifyMs   int64   `json:"zkpVerifyMs"`
	ProofSizeBytes int    `json:"proofSizeBytes"`
	Success       bool    `json:"success"`
	ErrorMessage  string  `json:"errorMessage,omitempty"`
}

// ZeroTrustGateway is the main gateway connecting clients to Fabric
type ZeroTrustGateway struct {
	cfg     GatewayConfig
	gw      *gateway.Gateway
	network *gateway.Network
	metrics []TransactionMetrics
}

// NewGateway initializes the Fabric SDK gateway
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
		return nil, fmt.Errorf("failed to get network %s: %v", cfg.ChannelName, err)
	}

	return &ZeroTrustGateway{
		cfg:     cfg,
		gw:      gw,
		network: network,
		metrics: make([]TransactionMetrics, 0),
	}, nil
}

// ============================================================
// WriteHealthRecord - encrypt, hash, and submit to Fabric
// This mirrors the paper's: Encrypt → Send to Gateway → Add to Ledger flow
// ============================================================
func (g *ZeroTrustGateway) WriteHealthRecord(
	patientID string,
	rawData map[string]interface{},
	offChainPointer string,
	recordType string,
	zkpProofHash string,
) (string, *TransactionMetrics, error) {
	m := &TransactionMetrics{
		TxID:      fmt.Sprintf("tx-%d", time.Now().UnixNano()),
		Operation: "WriteHealthRecord",
		StartTime: time.Now().UnixMilli(),
	}

	// Hash patient ID for privacy (never store plaintext)
	hashedPatientID := hashString(patientID)

	// Hash the raw data payload for on-chain integrity proof
	dataBytes, err := json.Marshal(rawData)
	if err != nil {
		m, err = g.recordFailure(m, fmt.Sprintf("failed to marshal data: %v", err))
		return "", m, err
	}
	dataHash := hashBytes(dataBytes)

	// Generate a record ID
	recordID := fmt.Sprintf("rec-%s-%d", hashedPatientID[:8], time.Now().UnixNano())

	// Default access policy: requires ZKP proof to read
	accessPolicy := `{"requireZKP": true, "allowedRoles": ["doctor", "insurer"]}`

	// Submit to Fabric chaincode
	contract := g.network.GetContract(g.cfg.HealthChaincode)
	_, err = contract.SubmitTransaction(
		"CreateHealthRecord",
		recordID,
		hashedPatientID,
		dataHash,
		offChainPointer,
		zkpProofHash,
		recordType,
		accessPolicy,
	)

	m.EndTime = time.Now().UnixMilli()
	m.LatencyMs = m.EndTime - m.StartTime

	if err != nil {
		m, err = g.recordFailure(m, fmt.Sprintf("chaincode invoke failed: %v", err))
		return "", m, err
	}

	m.Success = true
	g.metrics = append(g.metrics, *m)
	fmt.Printf("[Gateway] WriteHealthRecord: recordID=%s latency=%dms\n", recordID, m.LatencyMs)
	return recordID, m, nil
}

// ============================================================
// ReadHealthRecord - submit ZKP proof and request record
// ============================================================
func (g *ZeroTrustGateway) ReadHealthRecord(
	recordID string,
	requesterID string,
	zkpProofHash string,
) (map[string]interface{}, *TransactionMetrics, error) {
	m := &TransactionMetrics{
		TxID:      fmt.Sprintf("tx-%d", time.Now().UnixNano()),
		Operation: "ReadHealthRecord",
		StartTime: time.Now().UnixMilli(),
	}

	contract := g.network.GetContract(g.cfg.HealthChaincode)
	result, err := contract.EvaluateTransaction(
		"ReadHealthRecord",
		recordID,
		requesterID,
		zkpProofHash,
	)

	m.EndTime = time.Now().UnixMilli()
	m.LatencyMs = m.EndTime - m.StartTime

	if err != nil {
		g.recordFailure(m, fmt.Sprintf("read failed: %v", err))
		return nil, m, err
	}

	var record map[string]interface{}
	if err := json.Unmarshal(result, &record); err != nil {
		return nil, m, fmt.Errorf("failed to parse result: %v", err)
	}

	m.Success = true
	g.metrics = append(g.metrics, *m)
	return record, m, nil
}

// ============================================================
// RegisterZKPProof - register proof metadata on-chain
// ============================================================
func (g *ZeroTrustGateway) RegisterZKPProof(
	proofID string,
	circuitType string,
	proofHash string,
	proofSizeBytes int,
	verifyTimeMs int64,
	genTimeMs int64,
	isValid bool,
	patientID string,
) error {
	contract := g.network.GetContract(g.cfg.ZKPChaincode)
	_, err := contract.SubmitTransaction(
		"RegisterProof",
		proofID,
		circuitType,
		proofHash,
		fmt.Sprintf("%d", proofSizeBytes),
		fmt.Sprintf("%d", verifyTimeMs),
		fmt.Sprintf("%d", genTimeMs),
		fmt.Sprintf("%v", isValid),
		hashString(patientID),
	)
	return err
}

// ============================================================
// GetBenchmarkSummary - returns aggregated metrics for analysis
// Targets from the ZKP metrics document:
//   - Verification < 100ms
//   - Proof size < 2KB
//   - Generation < 200ms
// ============================================================
func (g *ZeroTrustGateway) GetBenchmarkSummary() map[string]interface{} {
	if len(g.metrics) == 0 {
		return map[string]interface{}{"error": "no metrics collected yet"}
	}

	var totalLatency, totalZKPGen, totalZKPVerify int64
	var totalProofSize int
	var successCount int

	for _, m := range g.metrics {
		totalLatency += m.LatencyMs
		totalZKPGen += m.ZKPGenMs
		totalZKPVerify += m.ZKPVerifyMs
		totalProofSize += m.ProofSizeBytes
		if m.Success {
			successCount++
		}
	}

	count := int64(len(g.metrics))
	return map[string]interface{}{
		"totalTransactions":    count,
		"successRate":          fmt.Sprintf("%.1f%%", float64(successCount)/float64(count)*100),
		"avgLatencyMs":         totalLatency / count,
		"avgZKPGenMs":          totalZKPGen / count,
		"avgZKPVerifyMs":       totalZKPVerify / count,
		"avgProofSizeBytes":    totalProofSize / int(count),
		// Benchmark targets from document
		"targetVerifyMs":       100,
		"targetGenMs":          200,
		"targetProofSizeBytes": 2048,
	}
}

func (g *ZeroTrustGateway) Close() {
	if g.gw != nil {
		g.gw.Close()
	}
}

// ============================================================
// Helpers
// ============================================================

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (g *ZeroTrustGateway) recordFailure(m *TransactionMetrics, msg string) (*TransactionMetrics, error) {
	m.Success = false
	m.ErrorMessage = msg
	m.EndTime = time.Now().UnixMilli()
	m.LatencyMs = m.EndTime - m.StartTime
	g.metrics = append(g.metrics, *m)
	return m, fmt.Errorf(msg)
}
