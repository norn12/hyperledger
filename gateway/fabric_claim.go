package gateway

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	peer "github.com/hyperledger/fabric-protos-go/peer"
	fabricgw "github.com/hyperledger/fabric-sdk-go/pkg/gateway"
)

var fabricClaimIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type FabricClaimSubmission struct {
	CircuitID       string          `json:"circuitId"`
	CircuitVersion  string          `json:"circuitVersion"`
	ClaimID         string          `json:"claimId"`
	AuthorityID     string          `json:"authorityId"`
	Proof           []byte          `json:"proof"`
	ProofHash       string          `json:"proofHash"`
	PublicStatement PublicStatement `json:"publicStatement"`
}
type FabricClaimSubmitResult struct {
	TransactionID             string `json:"transactionId"`
	BlockNumber               uint64 `json:"blockNumber"`
	ClaimID                   string `json:"claimId"`
	Status                    string `json:"status"`
	VerificationNanoseconds   int64  `json:"verificationNanoseconds"`
	SerializationNanoseconds  int64  `json:"serializationNanoseconds"`
	SubmitCommitNanoseconds   int64  `json:"submitCommitNanoseconds"`
	TotalNanoseconds          int64  `json:"totalNanoseconds"`
	SerializedSubmissionBytes int    `json:"serializedSubmissionBytes"`
}
type fabricClaimTransport interface {
	SubmitClaim(string) ([]byte, string, uint64, error)
}
type sdkFabricClaimTransport struct{ contract *fabricgw.Contract }

func (t sdkFabricClaimTransport) SubmitClaim(raw string) ([]byte, string, uint64, error) {
	txn, err := t.contract.CreateTransaction("SubmitHealthClaimProof")
	if err != nil {
		return nil, "", 0, err
	}
	events := txn.RegisterCommitEvent()
	result, err := txn.Submit(raw)
	if err != nil {
		return nil, "", 0, fmt.Errorf("Fabric rejected claim submission: %w", err)
	}
	select {
	case event, ok := <-events:
		if !ok || event == nil {
			return nil, "", 0, fmt.Errorf("Fabric commit event was closed")
		}
		if event.TxValidationCode != peer.TxValidationCode_VALID {
			return nil, event.TxID, event.BlockNumber, fmt.Errorf("Fabric transaction invalid: %s", event.TxValidationCode.String())
		}
		return result, event.TxID, event.BlockNumber, nil
	case <-time.After(30 * time.Second):
		return nil, "", 0, fmt.Errorf("timed out waiting for Fabric commit status")
	}
}

// SubmitHealthClaimProof verifies the envelope and request against the supplied
// Z10 verifier (including configured public anchors) before any Fabric call.
// The Fabric client identity must carry InsurerMSP role=zkpVerifier.
func (g *ZeroTrustGateway) SubmitHealthClaimProof(verifier *HealthClaimGateway, request ClaimRequest, envelope ProofEnvelope, claimID, authorityID string) (FabricClaimSubmitResult, error) {
	if g == nil || g.network == nil {
		return FabricClaimSubmitResult{}, fmt.Errorf("Fabric network is unavailable")
	}
	return submitVerifiedHealthClaimProof(verifier, request, envelope, claimID, authorityID, sdkFabricClaimTransport{g.network.GetContract(g.cfg.HealthChaincode)})
}

// IssueFabricClaimChallenge creates a local verifier challenge and anchors the
// same value and request bindings in Fabric before it is used in a proof.
func (g *ZeroTrustGateway) IssueFabricClaimChallenge(verifier *HealthClaimGateway, recipient, deployment, rootVersion, policyVersion string) (string, error) {
	if g == nil || g.network == nil {
		return "", fmt.Errorf("Fabric network is unavailable")
	}
	if verifier == nil {
		return "", fmt.Errorf("health claim verifier is unavailable")
	}
	if verifier.ids == nil {
		return "", fmt.Errorf("identifier registry is unavailable")
	}
	recipientID, ok := verifier.ids.Recipient(recipient)
	if !ok {
		return "", fmt.Errorf("recipient is not registered")
	}
	deploymentID, ok := verifier.ids.Deployment(deployment)
	if !ok {
		return "", fmt.Errorf("deployment is not registered")
	}
	challenge, err := verifier.IssueChallenge(recipient, deployment)
	if err != nil {
		return "", err
	}
	contract := g.network.GetContract(g.cfg.HealthChaincode)
	if _, err = contract.SubmitTransaction("IssueHealthClaimChallenge", challenge, recipientID.String(), deploymentID.String(), rootVersion, policyVersion); err != nil {
		return "", fmt.Errorf("failed to anchor challenge in Fabric: %w", err)
	}
	return challenge, nil
}
func submitVerifiedHealthClaimProof(verifier *HealthClaimGateway, request ClaimRequest, envelope ProofEnvelope, claimID, authorityID string, transport fabricClaimTransport) (FabricClaimSubmitResult, error) {
	totalStart := time.Now()
	if verifier == nil || transport == nil {
		return FabricClaimSubmitResult{}, fmt.Errorf("verification or Fabric transport is unavailable")
	}
	if !fabricClaimIDPattern.MatchString(claimID) || !fabricClaimIDPattern.MatchString(authorityID) {
		return FabricClaimSubmitResult{}, fmt.Errorf("invalid claim or authority identifier")
	}
	verifyStart := time.Now()
	if _, err := verifier.VerifyHealthClaimProof(request, envelope); err != nil {
		return FabricClaimSubmitResult{}, fmt.Errorf("CRYPTOGRAPHIC/TRUST VERIFICATION REJECTED: %w", err)
	}
	verifyDuration := time.Since(verifyStart)
	serializeStart := time.Now()
	submission := FabricClaimSubmission{CircuitID: envelope.CircuitID, CircuitVersion: envelope.CircuitVersion, ClaimID: claimID, AuthorityID: authorityID, Proof: envelope.Proof, ProofHash: envelope.ProofHash, PublicStatement: envelope.PublicStatement}
	raw, err := json.Marshal(submission)
	if err != nil {
		return FabricClaimSubmitResult{}, fmt.Errorf("failed to serialize public claim envelope")
	}
	serializeDuration := time.Since(serializeStart)
	submitStart := time.Now()
	response, txID, block, err := transport.SubmitClaim(string(raw))
	submitDuration := time.Since(submitStart)
	metrics := FabricClaimSubmitResult{TransactionID: txID, BlockNumber: block, ClaimID: claimID, VerificationNanoseconds: verifyDuration.Nanoseconds(), SerializationNanoseconds: serializeDuration.Nanoseconds(), SubmitCommitNanoseconds: submitDuration.Nanoseconds(), TotalNanoseconds: time.Since(totalStart).Nanoseconds(), SerializedSubmissionBytes: len(raw)}
	if err != nil {
		metrics.Status = "REJECTED"
		return metrics, err
	}
	var accepted struct {
		ClaimID string `json:"claimId"`
		Status  string `json:"status"`
	}
	if err = json.Unmarshal(response, &accepted); err != nil {
		return metrics, fmt.Errorf("Fabric accepted transaction but returned malformed claim metadata")
	}
	metrics.ClaimID = accepted.ClaimID
	metrics.Status = accepted.Status
	metrics.TotalNanoseconds = time.Since(totalStart).Nanoseconds()
	return metrics, nil
}
