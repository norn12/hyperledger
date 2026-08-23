package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"zerotrust/zkp"
)

// GatewayConfig holds connection settings for the Fabric network
type GatewayConfig struct {
	ConnectionProfilePath string
	WalletPath            string
	OrgMSP                string
	ChannelName           string
	HealthChaincode       string
	UserIdentity          string
}

// TransactionMetrics records timing for each transaction — used in benchmarking
type TransactionMetrics struct {
	TxID           string `json:"txId"`
	Operation      string `json:"operation"`
	StartTime      int64  `json:"startTimeUnixMs"`
	EndTime        int64  `json:"endTimeUnixMs"`
	LatencyMs      int64  `json:"latencyMs"`
	ZKPGenMs       int64  `json:"zkpGenMs"`
	ZKPVerifyMs    int64  `json:"zkpVerifyMs"`
	ProofSizeBytes int    `json:"proofSizeBytes"`
	Success        bool   `json:"success"`
	ErrorMessage   string `json:"errorMessage,omitempty"`
}

// ZeroTrustGateway is the main gateway connecting clients to Fabric
type ZeroTrustGateway struct {
	cfg        GatewayConfig
	gw         *gateway.Gateway
	network    *gateway.Network
	zkpService *zkp.ZKPService
	metrics    []TransactionMetrics
}

// NewGateway initializes the Fabric SDK gateway and ZKP circuit engine
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

	// Initialize gnark ZKP Circuits & Proving/Verifying Keys
	zkpSvc := &zkp.ZKPService{}
	if err := zkpSvc.Setup(); err != nil {
		return nil, fmt.Errorf("failed to initialize ZKP circuit engine: %v", err)
	}
	fmt.Println("[Gateway] ZKP Engine active with gnark BN254 Groth16 circuits")

	return &ZeroTrustGateway{
		cfg:        cfg,
		gw:         gw,
		network:    network,
		zkpService: zkpSvc,
		metrics:    make([]TransactionMetrics, 0),
	}, nil
}

// ============================================================
// WriteHealthRecord - generate ZKP proof, hash data, and submit to Fabric
// Pipeline: Client Data -> ZKP Proof -> Cryptographic Verify -> Fabric Transaction
// ============================================================
func (g *ZeroTrustGateway) WriteHealthRecord(
	patientID string,
	rawData map[string]interface{},
	offChainPointer string,
	recordType string,
	patientAge int, // Used for ZKP Age Range Proof
) (string, *TransactionMetrics, error) {
	m := &TransactionMetrics{
		TxID:      fmt.Sprintf("tx-%d", time.Now().UnixNano()),
		Operation: "WriteHealthRecord",
		StartTime: time.Now().UnixMilli(),
	}

	// Step 1: Generate & Cryptographically Verify Real Zero-Knowledge Proof (gnark Groth16)
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

	m.ZKPGenMs = proofResult.GenTimeMs
	m.ZKPVerifyMs = proofResult.VerifyTimeMs
	m.ProofSizeBytes = proofResult.ProofSizeBytes
	zkpProofHash := proofResult.ProofHash

	fmt.Printf("[Gateway ZKP] Groth16 proof generated & verified in %dms (size: %dB, hash: %s)\n",
		m.ZKPGenMs+m.ZKPVerifyMs, m.ProofSizeBytes, zkpProofHash[:12])

	// Step 2: Hash patient ID for privacy (never store plaintext)
	hashedPatientID := hashString(patientID)

	// Step 3: Hash raw data payload for on-chain integrity verification
	dataBytes, err := json.Marshal(rawData)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal data: %v", err)
	}
	dataHash := hashBytes(dataBytes)

	// Step 4: Generate unique record ID
	recordID := fmt.Sprintf("rec-%s-%d", hashedPatientID[:8], time.Now().UnixNano())

	// Step 5: Enforce Zero Trust Access Policy JSON
	accessPolicy := `{"requireZKP": true, "allowedMSPs": ["HospitalMSP", "InsurerMSP"], "allowedRoles": ["doctor", "insurer"]}`

	// Step 6: Submit to Fabric chaincode
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
		m.Success = false
		m.ErrorMessage = err.Error()
		g.metrics = append(g.metrics, *m)
		return "", m, fmt.Errorf("chaincode invoke failed: %v", err)
	}

	m.Success = true
	g.metrics = append(g.metrics, *m)
	fmt.Printf("[Gateway] WriteHealthRecord: recordID=%s latency=%dms\n", recordID, m.LatencyMs)
	return recordID, m, nil
}

// ============================================================
// ReadHealthRecord - submit ZKP proof hash and retrieve record
// ============================================================
func (g *ZeroTrustGateway) ReadHealthRecord(
	recordID string,
	patientAge int,
) (map[string]interface{}, *TransactionMetrics, error) {
	m := &TransactionMetrics{
		TxID:      fmt.Sprintf("tx-%d", time.Now().UnixNano()),
		Operation: "ReadHealthRecord",
		StartTime: time.Now().UnixMilli(),
	}

	// Step 1: Generate & Cryptographically Verify ZKP Proof for reader request
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

	m.ZKPGenMs = proofResult.GenTimeMs
	m.ZKPVerifyMs = proofResult.VerifyTimeMs
	m.ProofSizeBytes = proofResult.ProofSizeBytes
	zkpProofHash := proofResult.ProofHash

	contract := g.network.GetContract(g.cfg.HealthChaincode)
	// Execute via SubmitTransaction to guarantee on-chain commitment of immutable access audit logs
	result, err := contract.SubmitTransaction(
		"ReadHealthRecord",
		recordID,
		zkpProofHash,
	)

	m.EndTime = time.Now().UnixMilli()
	m.LatencyMs = m.EndTime - m.StartTime

	if err != nil {
		m.Success = false
		m.ErrorMessage = err.Error()
		g.metrics = append(g.metrics, *m)
		return nil, m, fmt.Errorf("read failed: %v", err)
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
// RevokeConsent - revoke consent for a health record
// ============================================================
func (g *ZeroTrustGateway) RevokeConsent(recordID string, patientID string) error {
	contract := g.network.GetContract(g.cfg.HealthChaincode)
	_, err := contract.SubmitTransaction(
		"RevokeConsent",
		recordID,
		hashString(patientID),
	)
	return err
}

// ============================================================
// GetBenchmarkSummary - aggregated metrics
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
