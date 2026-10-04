package gateway

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	hc "zerotrust/healthclaimhardened"
)

// ClaimRequest contains untrusted public request metadata. Field elements are
// canonical non-negative decimal strings to avoid JSON number precision loss.
type ClaimRequest struct {
	AuthorityID   string `json:"authorityId"`
	RootVersion   string `json:"rootVersion"`
	PolicyVersion string `json:"policyVersion"`
	ClaimAmount   string `json:"claimAmount"`
	Challenge     string `json:"challenge"`
	Recipient     string `json:"recipient"`
	Deployment    string `json:"deployment"`
}

// HealthClaimWitness is prover-side data and intentionally has no JSON form.
// Callers should source it from an authorized private-record provider.
type HealthClaimWitness struct {
	Diagnosis, LabValue, PolicyID, CoverageCeiling, PatientSecret *big.Int    `json:"-"`
	LabMin, LabMax, PolicyMaxClaim                                *big.Int    `json:"-"`
	CoveredDiagnosis                                              [4]*big.Int `json:"-"`
	Signature                                                     []byte      `json:"-"`
	MerkleSiblings                                                [8]*big.Int `json:"-"`
	MerkleDirections                                              [8]*big.Int `json:"-"`
}

type PublicStatement struct {
	RegistryRoot      string `json:"registryRoot"`
	RootVersion       string `json:"rootVersion"`
	PolicyCommitment  string `json:"policyCommitment"`
	PolicyVersion     string `json:"policyVersion"`
	ClaimAmount       string `json:"claimAmount"`
	AuthorityKeyX     string `json:"authorityKeyX"`
	AuthorityKeyY     string `json:"authorityKeyY"`
	Nullifier         string `json:"nullifier"`
	ProtocolDomain    string `json:"protocolDomain"`
	Challenge         string `json:"challenge"`
	RecipientID       string `json:"recipientId"`
	DeploymentID      string `json:"deploymentId"`
	ContextCommitment string `json:"contextCommitment"`
}

type ProofEnvelope struct {
	CircuitID       string          `json:"circuitId"`
	CircuitVersion  string          `json:"circuitVersion"`
	Proof           []byte          `json:"proof"`
	PublicStatement PublicStatement `json:"publicStatement"`
	ProofHash       string          `json:"proofHash"`
}

type VerificationResult struct {
	Valid               bool          `json:"valid"`
	VerifiedAt          time.Time     `json:"verifiedAt"`
	Nullifier           string        `json:"nullifier"`
	ErrorCode           string        `json:"errorCode,omitempty"`
	WitnessConstruction time.Duration `json:"witnessConstructionNs"`
	ProofGeneration     time.Duration `json:"proofGenerationNs"`
	LocalVerification   time.Duration `json:"localVerificationNs"`
	TotalProcessing     time.Duration `json:"totalProcessingNs"`
}

type ClaimError struct {
	Code string
	Err  error
}

func (e *ClaimError) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}
func (e *ClaimError) Unwrap() error { return e.Err }
func claimErr(code, message string) error {
	return &ClaimError{Code: code, Err: fmt.Errorf("%s", message)}
}

// MarshalJSON deliberately rejects witness serialization, even if a caller
// accidentally uses json.Marshal directly on a witness.
func (HealthClaimWitness) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("private witness serialization is forbidden")
}

func fieldString(v *big.Int) string {
	if v == nil {
		return ""
	}
	return v.String()
}
func decodeField(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("required field is empty")
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 || v.String() != s {
		return nil, fmt.Errorf("field must be canonical non-negative decimal")
	}
	if err := hc.ValidateCanonical(v); err != nil {
		return nil, err
	}
	return v, nil
}

var _ json.Marshaler = HealthClaimWitness{}
