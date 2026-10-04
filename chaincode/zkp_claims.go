package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	claimCircuitID           = "HealthClaimHardened"
	claimCircuitVersion      = "Z7-v1"
	claimProtocolDomain      = "202610041"
	claimProofBytes          = 164
	challengeLifetimeSeconds = 300
	zkClaimNamespace         = "healthclaim"
	zkAuthorityNamespace     = "zkpauthority"
	zkRootNamespace          = "zkproot"
	zkPolicyNamespace        = "zkppolicy"
	zkChallengeNamespace     = "zkpchallenge"
	zkNullifierNamespace     = "zkpnullifier"
	zkAuditNamespace         = "zkpaudit"
)

var claimIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var bn254ScalarModulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
var bn254EdwardsD, _ = new(big.Int).SetString("12181644023421730124874158521699555681764249180949974110617291017600649128846", 10)
var bn254EdwardsSubgroupOrder, _ = new(big.Int).SetString("2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

type edwardsExtendedPoint struct{ x, y, z, t *big.Int }

func edwardsMod(v *big.Int) *big.Int { return new(big.Int).Mod(v, bn254ScalarModulus) }
func edwardsAdd(p, q edwardsExtendedPoint) edwardsExtendedPoint {
	a := edwardsMod(new(big.Int).Mul(edwardsMod(new(big.Int).Sub(p.y, p.x)), edwardsMod(new(big.Int).Sub(q.y, q.x))))
	b := edwardsMod(new(big.Int).Mul(edwardsMod(new(big.Int).Add(p.y, p.x)), edwardsMod(new(big.Int).Add(q.y, q.x))))
	c := edwardsMod(new(big.Int).Mul(big.NewInt(2), edwardsMod(new(big.Int).Mul(bn254EdwardsD, edwardsMod(new(big.Int).Mul(p.t, q.t))))))
	d := edwardsMod(new(big.Int).Mul(big.NewInt(2), edwardsMod(new(big.Int).Mul(p.z, q.z))))
	e := edwardsMod(new(big.Int).Sub(b, a))
	f := edwardsMod(new(big.Int).Sub(d, c))
	g := edwardsMod(new(big.Int).Add(d, c))
	h := edwardsMod(new(big.Int).Add(b, a))
	return edwardsExtendedPoint{
		edwardsMod(new(big.Int).Mul(e, f)), edwardsMod(new(big.Int).Mul(g, h)),
		edwardsMod(new(big.Int).Mul(f, g)), edwardsMod(new(big.Int).Mul(e, h)),
	}
}

// validAuthorityEdwardsPoint mirrors the Gateway's BN254 twisted-Edwards
// trust-anchor checks: canonical coordinates, on-curve, non-identity, and
// membership in the prime-order subgroup. Extended coordinates avoid inversions.
func validAuthorityEdwardsPoint(xText, yText string) bool {
	if !canonicalField(xText) || !canonicalField(yText) {
		return false
	}
	x, _ := new(big.Int).SetString(xText, 10)
	y, _ := new(big.Int).SetString(yText, 10)
	x2 := edwardsMod(new(big.Int).Mul(x, x))
	y2 := edwardsMod(new(big.Int).Mul(y, y))
	lhs := edwardsMod(new(big.Int).Add(new(big.Int).Neg(x2), y2))
	rhs := edwardsMod(new(big.Int).Add(big.NewInt(1), edwardsMod(new(big.Int).Mul(bn254EdwardsD, edwardsMod(new(big.Int).Mul(x2, y2))))))
	if lhs.Cmp(rhs) != 0 || (x.Sign() == 0 && y.Cmp(big.NewInt(1)) == 0) {
		return false
	}
	p := edwardsExtendedPoint{x, y, big.NewInt(1), edwardsMod(new(big.Int).Mul(x, y))}
	acc := edwardsExtendedPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
	for i := 0; i < bn254EdwardsSubgroupOrder.BitLen(); i++ {
		if bn254EdwardsSubgroupOrder.Bit(i) == 1 {
			acc = edwardsAdd(acc, p)
		}
		p = edwardsAdd(p, p)
	}
	return acc.x.Sign() == 0 && edwardsMod(new(big.Int).Sub(acc.y, acc.z)).Sign() == 0
}

// PublicClaimStatement mirrors HealthClaimHardened public inputs. These values
// are public; chaincode never accepts or stores a private witness.
type PublicClaimStatement struct {
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

type FabricClaimSubmission struct {
	CircuitID       string               `json:"circuitId"`
	CircuitVersion  string               `json:"circuitVersion"`
	ClaimID         string               `json:"claimId"`
	AuthorityID     string               `json:"authorityId"`
	Proof           []byte               `json:"proof"`
	ProofHash       string               `json:"proofHash"`
	PublicStatement PublicClaimStatement `json:"publicStatement"`
}

type ClaimAuthority struct {
	AuthorityID string `json:"authorityId"`
	KeyX        string `json:"keyX"`
	KeyY        string `json:"keyY"`
	Active      bool   `json:"active"`
	UpdatedAt   string `json:"updatedAt"`
}
type AcceptedClaimRoot struct {
	DeploymentID string `json:"deploymentId"`
	Version      string `json:"version"`
	Root         string `json:"root"`
	Active       bool   `json:"active"`
	UpdatedAt    string `json:"updatedAt"`
}
type AcceptedClaimPolicy struct {
	DeploymentID string `json:"deploymentId"`
	Version      string `json:"version"`
	Commitment   string `json:"commitment"`
	Active       bool   `json:"active"`
	UpdatedAt    string `json:"updatedAt"`
}
type ClaimChallenge struct {
	Challenge     string `json:"challenge"`
	RecipientID   string `json:"recipientId"`
	DeploymentID  string `json:"deploymentId"`
	RootVersion   string `json:"rootVersion"`
	PolicyVersion string `json:"policyVersion"`
	IssuerMSP     string `json:"issuerMsp"`
	IssuerID      string `json:"issuerId"`
	IssuedAt      string `json:"issuedAt"`
	ExpiresAt     int64  `json:"expiresAtUnix"`
	Status        string `json:"status"`
	ConsumedBy    string `json:"consumedBy,omitempty"`
}
type HealthClaimProofRecord struct {
	ClaimID           string               `json:"claimId"`
	CircuitID         string               `json:"circuitId"`
	CircuitVersion    string               `json:"circuitVersion"`
	Proof             []byte               `json:"proof"`
	ProofHash         string               `json:"proofHash"`
	PublicStatement   PublicClaimStatement `json:"publicStatement"`
	AuthorityID       string               `json:"authorityId"`
	SubmitterMSP      string               `json:"submitterMsp"`
	SubmitterID       string               `json:"submitterId"`
	Status            string               `json:"status"`
	VerificationTrust string               `json:"verificationTrust"`
	CreatedAt         string               `json:"createdAt"`
	TransactionID     string               `json:"transactionId"`
}
type HealthClaimAudit struct {
	ClaimID       string `json:"claimId"`
	AuthorityID   string `json:"authorityId"`
	SubmitterMSP  string `json:"submitterMsp"`
	SubmitterID   string `json:"submitterId"`
	Nullifier     string `json:"nullifier"`
	Challenge     string `json:"challenge"`
	RecipientID   string `json:"recipientId"`
	DeploymentID  string `json:"deploymentId"`
	RootVersion   string `json:"rootVersion"`
	PolicyVersion string `json:"policyVersion"`
	Status        string `json:"status"`
	Timestamp     string `json:"timestamp"`
	TransactionID string `json:"transactionId"`
}
type HealthClaimNullifierStatus struct {
	Nullifier string `json:"nullifier"`
	Used      bool   `json:"used"`
	ClaimID   string `json:"claimId,omitempty"`
}

func canonicalField(s string) bool {
	if s == "" {
		return false
	}
	v, ok := new(big.Int).SetString(s, 10)
	return ok && v.Sign() >= 0 && v.String() == s && v.Cmp(bn254ScalarModulus) < 0
}
func canonicalVersion(s string) bool {
	if !canonicalField(s) {
		return false
	}
	n, _ := new(big.Int).SetString(s, 10)
	return n.BitLen() <= 64
}
func validClaimID(s string) bool { return claimIDPattern.MatchString(s) }
func stateKey(ctx contractapi.TransactionContextInterface, namespace string, attrs ...string) (string, error) {
	return ctx.GetStub().CreateCompositeKey(namespace, attrs)
}
func putJSON(ctx contractapi.TransactionContextInterface, key string, value interface{}) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	return ctx.GetStub().PutState(key, b)
}
func getJSON(ctx contractapi.TransactionContextInterface, key string, dst interface{}) error {
	b, e := ctx.GetStub().GetState(key)
	if e != nil {
		return e
	}
	if b == nil {
		return fmt.Errorf("ledger state not found")
	}
	return json.Unmarshal(b, dst)
}

func requireFabricIdentity(ctx contractapi.TransactionContextInterface, allowedMSP, role string) (string, string, error) {
	if ctx == nil || ctx.GetClientIdentity() == nil {
		return "", "", fmt.Errorf("client identity unavailable")
	}
	msp, e := ctx.GetClientIdentity().GetMSPID()
	if e != nil || msp != allowedMSP {
		return "", "", fmt.Errorf("unauthorized MSP")
	}
	got, found, e := ctx.GetClientIdentity().GetAttributeValue("role")
	if e != nil || !found || got != role {
		return "", "", fmt.Errorf("unauthorized role")
	}
	id, e := ctx.GetClientIdentity().GetID()
	if e != nil || strings.TrimSpace(id) == "" {
		return "", "", fmt.Errorf("client identity unavailable")
	}
	return msp, id, nil
}
func requireRegistryAdmin(ctx contractapi.TransactionContextInterface) (string, string, error) {
	return requireFabricIdentity(ctx, "HospitalMSP", "admin")
}
func requireFabricRoleAny(ctx contractapi.TransactionContextInterface, msp string, roles ...string) (string, string, error) {
	if ctx == nil || ctx.GetClientIdentity() == nil {
		return "", "", fmt.Errorf("client identity unavailable")
	}
	got, e := ctx.GetClientIdentity().GetMSPID()
	if e != nil || got != msp {
		return "", "", fmt.Errorf("unauthorized MSP")
	}
	role, found, e := ctx.GetClientIdentity().GetAttributeValue("role")
	if e != nil || !found {
		return "", "", fmt.Errorf("unauthorized role")
	}
	allowed := false
	for _, r := range roles {
		if role == r {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", "", fmt.Errorf("unauthorized role")
	}
	id, e := ctx.GetClientIdentity().GetID()
	if e != nil || strings.TrimSpace(id) == "" {
		return "", "", fmt.Errorf("client identity unavailable")
	}
	return got, id, nil
}

// RegisterTrustedAuthority is controlled prototype state. The HospitalMSP
// admin controls enrollment; chaincode stores the public key reference only.
func (c *ZeroTrustBlockContract) RegisterTrustedAuthority(ctx contractapi.TransactionContextInterface, authorityID, keyX, keyY string) error {
	_, _, e := requireRegistryAdmin(ctx)
	if e != nil {
		return e
	}
	if !validClaimID(authorityID) || !canonicalField(keyX) || !canonicalField(keyY) {
		return fmt.Errorf("invalid authority record")
	}
	if !validAuthorityEdwardsPoint(keyX, keyY) {
		return fmt.Errorf("authority key must be a non-identity subgroup point")
	}
	stamp, e := getTxTimestampString(ctx)
	if e != nil {
		return e
	}
	key, e := stateKey(ctx, zkAuthorityNamespace, authorityID)
	if e != nil {
		return e
	}
	return putJSON(ctx, key, ClaimAuthority{authorityID, keyX, keyY, true, stamp})
}
func (c *ZeroTrustBlockContract) RevokeTrustedAuthority(ctx contractapi.TransactionContextInterface, authorityID string) error {
	if _, _, e := requireRegistryAdmin(ctx); e != nil {
		return e
	}
	if !validClaimID(authorityID) {
		return fmt.Errorf("invalid authority identifier")
	}
	key, e := stateKey(ctx, zkAuthorityNamespace, authorityID)
	if e != nil {
		return e
	}
	var item ClaimAuthority
	if e = getJSON(ctx, key, &item); e != nil {
		return e
	}
	stamp, e := getTxTimestampString(ctx)
	if e != nil {
		return e
	}
	item.Active = false
	item.UpdatedAt = stamp
	return putJSON(ctx, key, item)
}
func (c *ZeroTrustBlockContract) SetAcceptedClaimRoot(ctx contractapi.TransactionContextInterface, deploymentID, version, root string) error {
	_, _, e := requireRegistryAdmin(ctx)
	if e != nil {
		return e
	}
	if !canonicalField(deploymentID) || !canonicalVersion(version) || !canonicalField(root) {
		return fmt.Errorf("invalid root registry entry")
	}
	stamp, e := getTxTimestampString(ctx)
	if e != nil {
		return e
	}
	key, e := stateKey(ctx, zkRootNamespace, deploymentID, version)
	if e != nil {
		return e
	}
	return putJSON(ctx, key, AcceptedClaimRoot{deploymentID, version, root, true, stamp})
}
func (c *ZeroTrustBlockContract) RevokeAcceptedClaimRoot(ctx contractapi.TransactionContextInterface, deploymentID, version string) error {
	if _, _, e := requireRegistryAdmin(ctx); e != nil {
		return e
	}
	key, e := stateKey(ctx, zkRootNamespace, deploymentID, version)
	if e != nil {
		return e
	}
	var item AcceptedClaimRoot
	if e = getJSON(ctx, key, &item); e != nil {
		return e
	}
	stamp, e := getTxTimestampString(ctx)
	if e != nil {
		return e
	}
	item.Active = false
	item.UpdatedAt = stamp
	return putJSON(ctx, key, item)
}
func (c *ZeroTrustBlockContract) SetAcceptedClaimPolicy(ctx contractapi.TransactionContextInterface, deploymentID, version, commitment string) error {
	_, _, e := requireRegistryAdmin(ctx)
	if e != nil {
		return e
	}
	if !canonicalField(deploymentID) || !canonicalVersion(version) || !canonicalField(commitment) {
		return fmt.Errorf("invalid policy registry entry")
	}
	stamp, e := getTxTimestampString(ctx)
	if e != nil {
		return e
	}
	key, e := stateKey(ctx, zkPolicyNamespace, deploymentID, version)
	if e != nil {
		return e
	}
	return putJSON(ctx, key, AcceptedClaimPolicy{deploymentID, version, commitment, true, stamp})
}
func (c *ZeroTrustBlockContract) RevokeAcceptedClaimPolicy(ctx contractapi.TransactionContextInterface, deploymentID, version string) error {
	if _, _, e := requireRegistryAdmin(ctx); e != nil {
		return e
	}
	key, e := stateKey(ctx, zkPolicyNamespace, deploymentID, version)
	if e != nil {
		return e
	}
	var item AcceptedClaimPolicy
	if e = getJSON(ctx, key, &item); e != nil {
		return e
	}
	stamp, e := getTxTimestampString(ctx)
	if e != nil {
		return e
	}
	item.Active = false
	item.UpdatedAt = stamp
	return putJSON(ctx, key, item)
}

// IssueHealthClaimChallenge records a Gateway-supplied unpredictable scalar.
// Chaincode does not generate randomness because Fabric endorsers must be deterministic.
func (c *ZeroTrustBlockContract) IssueHealthClaimChallenge(ctx contractapi.TransactionContextInterface, challenge, recipientID, deploymentID, rootVersion, policyVersion string) error {
	msp, id, e := requireFabricRoleAny(ctx, "InsurerMSP", "insurer", "zkpVerifier")
	if e != nil {
		return e
	}
	if !canonicalField(challenge) || !canonicalField(recipientID) || !canonicalField(deploymentID) || !canonicalVersion(rootVersion) || !canonicalVersion(policyVersion) {
		return fmt.Errorf("invalid challenge request")
	}
	key, e := stateKey(ctx, zkChallengeNamespace, challenge)
	if e != nil {
		return e
	}
	existing, e := ctx.GetStub().GetState(key)
	if e != nil {
		return e
	}
	if existing != nil {
		return fmt.Errorf("challenge already exists")
	}
	stamp, e := getTxTimestampString(ctx)
	if e != nil {
		return e
	}
	ts, e := ctx.GetStub().GetTxTimestamp()
	if e != nil {
		return e
	}
	entry := ClaimChallenge{challenge, recipientID, deploymentID, rootVersion, policyVersion, msp, id, stamp, ts.Seconds + challengeLifetimeSeconds, "ISSUED", ""}
	return putJSON(ctx, key, entry)
}

func validateClaimStatement(s PublicClaimStatement) error {
	fields := []string{s.RegistryRoot, s.PolicyCommitment, s.ClaimAmount, s.AuthorityKeyX, s.AuthorityKeyY, s.Nullifier, s.ProtocolDomain, s.Challenge, s.RecipientID, s.DeploymentID, s.ContextCommitment}
	for _, v := range fields {
		if !canonicalField(v) {
			return fmt.Errorf("public statement has non-canonical field")
		}
	}
	if !canonicalVersion(s.RootVersion) || !canonicalVersion(s.PolicyVersion) {
		return fmt.Errorf("invalid public statement version")
	}
	amount, _ := new(big.Int).SetString(s.ClaimAmount, 10)
	if amount.BitLen() > 64 {
		return fmt.Errorf("claim amount exceeds circuit range")
	}
	if s.ProtocolDomain != claimProtocolDomain {
		return fmt.Errorf("unsupported protocol domain")
	}
	return nil
}

// SubmitHealthClaimProof stores a proof after a trusted Gateway verifier identity
// submits it. Chaincode checks public state bindings, request lifecycle, proof
// encoding/hash and replay state. It does NOT execute Groth16 verification.
func (c *ZeroTrustBlockContract) SubmitHealthClaimProof(ctx contractapi.TransactionContextInterface, submissionJSON string) (*HealthClaimProofRecord, error) {
	submitterMSP, submitterID, e := requireFabricIdentity(ctx, "InsurerMSP", "zkpVerifier")
	if e != nil {
		return nil, e
	}
	var sub FabricClaimSubmission
	if e = json.Unmarshal([]byte(submissionJSON), &sub); e != nil {
		return nil, fmt.Errorf("malformed claim submission")
	}
	if !validClaimID(sub.ClaimID) || !validClaimID(sub.AuthorityID) {
		return nil, fmt.Errorf("invalid claim or authority identifier")
	}
	if sub.CircuitID != claimCircuitID || sub.CircuitVersion != claimCircuitVersion {
		return nil, fmt.Errorf("unsupported circuit")
	}
	if err := validateClaimStatement(sub.PublicStatement); err != nil {
		return nil, err
	}
	if len(sub.Proof) != claimProofBytes {
		return nil, fmt.Errorf("invalid serialized proof size")
	}
	digest := sha256.Sum256(sub.Proof)
	if sub.ProofHash != hex.EncodeToString(digest[:]) {
		return nil, fmt.Errorf("proof hash mismatch")
	}
	claimKey, e := stateKey(ctx, zkClaimNamespace, sub.ClaimID)
	if e != nil {
		return nil, e
	}
	existing, e := ctx.GetStub().GetState(claimKey)
	if e != nil {
		return nil, e
	}
	if existing != nil {
		return nil, fmt.Errorf("claim already exists")
	}
	s := sub.PublicStatement
	authorityKey, e := stateKey(ctx, zkAuthorityNamespace, sub.AuthorityID)
	if e != nil {
		return nil, e
	}
	var authority ClaimAuthority
	if e = getJSON(ctx, authorityKey, &authority); e != nil || !authority.Active {
		return nil, fmt.Errorf("authority is not trusted")
	}
	if authority.KeyX != s.AuthorityKeyX || authority.KeyY != s.AuthorityKeyY {
		return nil, fmt.Errorf("authority key does not match trusted registry")
	}
	rootKey, e := stateKey(ctx, zkRootNamespace, s.DeploymentID, s.RootVersion)
	if e != nil {
		return nil, e
	}
	var root AcceptedClaimRoot
	if e = getJSON(ctx, rootKey, &root); e != nil || !root.Active || root.Root != s.RegistryRoot {
		return nil, fmt.Errorf("root/version is not accepted")
	}
	policyKey, e := stateKey(ctx, zkPolicyNamespace, s.DeploymentID, s.PolicyVersion)
	if e != nil {
		return nil, e
	}
	var policy AcceptedClaimPolicy
	if e = getJSON(ctx, policyKey, &policy); e != nil || !policy.Active || policy.Commitment != s.PolicyCommitment {
		return nil, fmt.Errorf("policy/version is not accepted")
	}
	challengeKey, e := stateKey(ctx, zkChallengeNamespace, s.Challenge)
	if e != nil {
		return nil, e
	}
	var challenge ClaimChallenge
	if e = getJSON(ctx, challengeKey, &challenge); e != nil || challenge.Status != "ISSUED" {
		return nil, fmt.Errorf("challenge is missing or already consumed")
	}
	ts, e := ctx.GetStub().GetTxTimestamp()
	if e != nil {
		return nil, e
	}
	if ts.Seconds >= challenge.ExpiresAt {
		return nil, fmt.Errorf("challenge expired")
	}
	if challenge.RecipientID != s.RecipientID || challenge.DeploymentID != s.DeploymentID || challenge.RootVersion != s.RootVersion || challenge.PolicyVersion != s.PolicyVersion {
		return nil, fmt.Errorf("statement does not match issued challenge")
	}
	nullifierKey, e := stateKey(ctx, zkNullifierNamespace, s.Nullifier)
	if e != nil {
		return nil, e
	}
	used, e := ctx.GetStub().GetState(nullifierKey)
	if e != nil {
		return nil, e
	}
	if used != nil {
		return nil, fmt.Errorf("nullifier already used")
	}
	stamp, e := getTxTimestampString(ctx)
	if e != nil {
		return nil, e
	}
	txID := ctx.GetStub().GetTxID()
	record := HealthClaimProofRecord{sub.ClaimID, sub.CircuitID, sub.CircuitVersion, sub.Proof, sub.ProofHash, s, sub.AuthorityID, submitterMSP, submitterID, "ACCEPTED", "GATEWAY_VERIFIER_IDENTITY", stamp, txID}
	if e = putJSON(ctx, claimKey, record); e != nil {
		return nil, e
	}
	if e = ctx.GetStub().PutState(nullifierKey, []byte(sub.ClaimID)); e != nil {
		return nil, e
	}
	challenge.Status = "CONSUMED"
	challenge.ConsumedBy = sub.ClaimID
	if e = putJSON(ctx, challengeKey, challenge); e != nil {
		return nil, e
	}
	auditKey, e := stateKey(ctx, zkAuditNamespace, sub.ClaimID)
	if e != nil {
		return nil, e
	}
	audit := HealthClaimAudit{sub.ClaimID, sub.AuthorityID, submitterMSP, submitterID, s.Nullifier, s.Challenge, s.RecipientID, s.DeploymentID, s.RootVersion, s.PolicyVersion, "ACCEPTED", stamp, txID}
	if e = putJSON(ctx, auditKey, audit); e != nil {
		return nil, e
	}
	return &record, nil
}

func (c *ZeroTrustBlockContract) GetHealthClaimProof(ctx contractapi.TransactionContextInterface, claimID string) (*HealthClaimProofRecord, error) {
	if !validClaimID(claimID) {
		return nil, fmt.Errorf("invalid claim ID")
	}
	if e := requireClaimReader(ctx); e != nil {
		return nil, e
	}
	key, e := stateKey(ctx, zkClaimNamespace, claimID)
	if e != nil {
		return nil, e
	}
	var record HealthClaimProofRecord
	if e = getJSON(ctx, key, &record); e != nil {
		return nil, e
	}
	return &record, nil
}
func (c *ZeroTrustBlockContract) GetHealthClaimAudit(ctx contractapi.TransactionContextInterface, claimID string) (*HealthClaimAudit, error) {
	if !validClaimID(claimID) {
		return nil, fmt.Errorf("invalid claim ID")
	}
	if e := requireClaimReader(ctx); e != nil {
		return nil, e
	}
	key, e := stateKey(ctx, zkAuditNamespace, claimID)
	if e != nil {
		return nil, e
	}
	var audit HealthClaimAudit
	if e = getJSON(ctx, key, &audit); e != nil {
		return nil, e
	}
	return &audit, nil
}

// GetHealthClaimChallenge exposes lifecycle state to authorized channel users
// for end-to-end verification and operational audit.
func (c *ZeroTrustBlockContract) GetHealthClaimChallenge(ctx contractapi.TransactionContextInterface, challengeValue string) (*ClaimChallenge, error) {
	if !canonicalField(challengeValue) {
		return nil, fmt.Errorf("invalid challenge")
	}
	if e := requireClaimReader(ctx); e != nil {
		return nil, e
	}
	key, e := stateKey(ctx, zkChallengeNamespace, challengeValue)
	if e != nil {
		return nil, e
	}
	var challenge ClaimChallenge
	if e = getJSON(ctx, key, &challenge); e != nil {
		return nil, e
	}
	return &challenge, nil
}

// GetHealthClaimNullifier reports whether a record-bound nullifier has been
// consumed and, if so, the accepted claim that consumed it.
func (c *ZeroTrustBlockContract) GetHealthClaimNullifier(ctx contractapi.TransactionContextInterface, nullifier string) (*HealthClaimNullifierStatus, error) {
	if !canonicalField(nullifier) {
		return nil, fmt.Errorf("invalid nullifier")
	}
	if e := requireClaimReader(ctx); e != nil {
		return nil, e
	}
	key, e := stateKey(ctx, zkNullifierNamespace, nullifier)
	if e != nil {
		return nil, e
	}
	claimID, e := ctx.GetStub().GetState(key)
	if e != nil {
		return nil, e
	}
	status := &HealthClaimNullifierStatus{Nullifier: nullifier, Used: claimID != nil}
	if claimID != nil {
		status.ClaimID = string(claimID)
	}
	return status, nil
}
func requireClaimReader(ctx contractapi.TransactionContextInterface) error {
	if ctx == nil || ctx.GetClientIdentity() == nil {
		return fmt.Errorf("client identity unavailable")
	}
	msp, e := ctx.GetClientIdentity().GetMSPID()
	if e != nil {
		return fmt.Errorf("client identity unavailable")
	}
	if msp != "HospitalMSP" && msp != "InsurerMSP" {
		return fmt.Errorf("unauthorized MSP")
	}
	role, found, e := ctx.GetClientIdentity().GetAttributeValue("role")
	if e != nil || !found {
		return fmt.Errorf("unauthorized role")
	}
	if role != "admin" && role != "insurer" && role != "doctor" && role != "zkpVerifier" {
		return fmt.Errorf("unauthorized role")
	}
	return nil
}
func validateClaimDeadline(challenge ClaimChallenge, txTime time.Time) bool {
	return txTime.Unix() <= challenge.ExpiresAt
}
