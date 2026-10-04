package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	hc "zerotrust/healthclaimhardened"

	"github.com/consensys/gnark-crypto/ecc"
	bnedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	cryptoed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type TrustedAuthorityRegistry interface {
	Authority(string) (*big.Int, *big.Int, bool)
}
type TrustedRootRegistry interface {
	Root(deployment string, version *big.Int) (*big.Int, bool)
}
type TrustedPolicyRegistry interface {
	Policy(deployment string, version *big.Int) (commitment *big.Int, ok bool)
}
type IdentifierRegistry interface {
	Recipient(string) (*big.Int, bool)
	Deployment(string) (*big.Int, bool)
}
type ChallengeStore interface {
	Issue(recipient, deployment *big.Int, lifetime time.Duration) (*big.Int, error)
	Validate(challenge, recipient, deployment *big.Int) error
	Consume(challenge *big.Int) error
}
type UsedNullifiers interface {
	IsNullifierUsed(*big.Int) bool
	MarkNullifierUsed(*big.Int) error
}
type hardenedProofEngine interface {
	Prove(*hc.HealthClaimHardened) ([]byte, error)
	Verify([]byte, PublicStatement) error
}

// MemoryRegistries is a prototype trust anchor store. Registration is explicit;
// production authority/root/policy state must come from authenticated state.
type MemoryRegistries struct {
	mu          sync.RWMutex
	authorities map[string][2]*big.Int
	roots       map[string]*big.Int
	policies    map[string]*big.Int
	recipients  map[string]*big.Int
	deployments map[string]*big.Int
}

func NewMemoryRegistries() *MemoryRegistries {
	return &MemoryRegistries{authorities: map[string][2]*big.Int{}, roots: map[string]*big.Int{}, policies: map[string]*big.Int{}, recipients: map[string]*big.Int{}, deployments: map[string]*big.Int{}}
}
func regKey(deployment string, v *big.Int) string { return deployment + ":" + v.String() }
func (r *MemoryRegistries) RegisterAuthority(id string, x, y *big.Int) error {
	if id == "" || hc.ValidateCanonical(x) != nil || hc.ValidateCanonical(y) != nil {
		return fmt.Errorf("authority key coordinates are invalid")
	}
	var point bnedwards.PointAffine
	point.X.SetBigInt(x)
	point.Y.SetBigInt(y)
	if !point.IsOnCurve() || !point.IsInSubGroup() || point.IsZero() {
		return fmt.Errorf("authority key is not a non-identity subgroup point")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorities[id] = [2]*big.Int{new(big.Int).Set(x), new(big.Int).Set(y)}
	return nil
}
func (r *MemoryRegistries) RegisterRoot(deployment string, v, root *big.Int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.roots[regKey(deployment, v)] = new(big.Int).Set(root)
}
func (r *MemoryRegistries) RegisterPolicy(deployment string, v, commitment *big.Int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[regKey(deployment, v)] = new(big.Int).Set(commitment)
}
func (r *MemoryRegistries) RegisterRecipient(id string, v *big.Int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recipients[id] = new(big.Int).Set(v)
}
func (r *MemoryRegistries) RegisterDeployment(id string, v *big.Int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deployments[id] = new(big.Int).Set(v)
}
func (r *MemoryRegistries) Authority(id string) (*big.Int, *big.Int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.authorities[id]
	if !ok {
		return nil, nil, false
	}
	return new(big.Int).Set(v[0]), new(big.Int).Set(v[1]), true
}
func (r *MemoryRegistries) Root(d string, v *big.Int) (*big.Int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	x, ok := r.roots[regKey(d, v)]
	if !ok {
		return nil, false
	}
	return new(big.Int).Set(x), true
}
func (r *MemoryRegistries) Policy(d string, v *big.Int) (*big.Int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	x, ok := r.policies[regKey(d, v)]
	if !ok {
		return nil, false
	}
	return new(big.Int).Set(x), true
}
func (r *MemoryRegistries) Recipient(id string) (*big.Int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	x, ok := r.recipients[id]
	if !ok {
		return nil, false
	}
	return new(big.Int).Set(x), true
}
func (r *MemoryRegistries) Deployment(id string) (*big.Int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	x, ok := r.deployments[id]
	if !ok {
		return nil, false
	}
	return new(big.Int).Set(x), true
}

type challengeEntry struct {
	recipient, deployment *big.Int
	expires               time.Time
	consumed              bool
}
type MemoryChallengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
}

func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{entries: map[string]challengeEntry{}}
}
func (s *MemoryChallengeStore) Issue(r, d *big.Int, life time.Duration) (*big.Int, error) {
	if life <= 0 {
		return nil, fmt.Errorf("challenge lifetime must be positive")
	}
	var v *big.Int
	var e error
	for v == nil || v.Sign() == 0 {
		v, e = rand.Int(rand.Reader, hc.Field())
		if e != nil {
			return nil, e
		}
	}
	s.mu.Lock()
	s.entries[v.String()] = challengeEntry{new(big.Int).Set(r), new(big.Int).Set(d), time.Now().Add(life), false}
	s.mu.Unlock()
	return v, nil
}
func (s *MemoryChallengeStore) Validate(c, r, d *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[c.String()]
	if !ok || e.consumed || time.Now().After(e.expires) || e.recipient.Cmp(r) != 0 || e.deployment.Cmp(d) != 0 {
		return fmt.Errorf("challenge invalid, expired, consumed, or context-mismatched")
	}
	return nil
}
func (s *MemoryChallengeStore) Consume(c *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[c.String()]
	if !ok || e.consumed || time.Now().After(e.expires) {
		return fmt.Errorf("challenge unavailable")
	}
	e.consumed = true
	s.entries[c.String()] = e
	return nil
}

type MemoryUsedNullifiers struct {
	mu   sync.Mutex
	used map[string]bool
}

func NewMemoryUsedNullifiers() *MemoryUsedNullifiers {
	return &MemoryUsedNullifiers{used: map[string]bool{}}
}
func (s *MemoryUsedNullifiers) IsNullifierUsed(n *big.Int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used[n.String()]
}
func (s *MemoryUsedNullifiers) MarkNullifierUsed(n *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used[n.String()] {
		return fmt.Errorf("nullifier already used")
	}
	s.used[n.String()] = true
	return nil
}

type GnarkHardenedEngine struct {
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
}

func NewGnarkHardenedEngine() (*GnarkHardenedEngine, error) {
	c, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &hc.HealthClaimHardened{})
	if e != nil {
		return nil, e
	}
	pk, vk, e := groth16.Setup(c)
	if e != nil {
		return nil, e
	}
	return &GnarkHardenedEngine{c, pk, vk}, nil
}
func (e *GnarkHardenedEngine) Prove(a *hc.HealthClaimHardened) ([]byte, error) {
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField())
	if err != nil {
		return nil, err
	}
	p, err := groth16.Prove(e.ccs, e.pk, w)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	_, err = p.WriteTo(&b)
	return b.Bytes(), err
}
func (e *GnarkHardenedEngine) Verify(raw []byte, s PublicStatement) error {
	p := groth16.NewProof(ecc.BN254)
	if _, err := p.ReadFrom(bytes.NewReader(raw)); err != nil {
		return err
	}
	a, err := statementAssignment(s)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(a, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(p, e.vk, w)
}

type HealthClaimGateway struct {
	authorities       TrustedAuthorityRegistry
	roots             TrustedRootRegistry
	policies          TrustedPolicyRegistry
	ids               IdentifierRegistry
	challenges        ChallengeStore
	nullifiers        UsedNullifiers
	engine            hardenedProofEngine
	ChallengeLifetime time.Duration
}

// HealthClaimProtocolIdentifier is the stable application-level name mapped
// to the numeric protocol-domain constant frozen in Z7.
const HealthClaimProtocolIdentifier = "zerotrustblock.healthclaim.v1"

// ProtocolFieldValue maps the canonical symbolic identifier to the Z7 circuit
// field. Callers cannot supply arbitrary protocol-domain integers.
func ProtocolFieldValue(identifier string) (*big.Int, error) {
	if identifier != HealthClaimProtocolIdentifier {
		return nil, fmt.Errorf("unsupported health-claim protocol identifier")
	}
	return big.NewInt(hc.ProtocolDomainID), nil
}

func NewHealthClaimGateway(a TrustedAuthorityRegistry, r TrustedRootRegistry, p TrustedPolicyRegistry, i IdentifierRegistry, c ChallengeStore, n UsedNullifiers, e hardenedProofEngine) *HealthClaimGateway {
	return &HealthClaimGateway{a, r, p, i, c, n, e, 5 * time.Minute}
}
func (g *HealthClaimGateway) IssueChallenge(recipient, deployment string) (string, error) {
	if g == nil || g.ids == nil || g.challenges == nil {
		return "", claimErr("INTERNAL_ERROR", "challenge dependencies are incomplete")
	}
	rid, ok := g.ids.Recipient(recipient)
	if !ok {
		return "", claimErr("TRUST_REGISTRY_ERROR", "recipient is not registered")
	}
	did, ok := g.ids.Deployment(deployment)
	if !ok {
		return "", claimErr("TRUST_REGISTRY_ERROR", "deployment is not registered")
	}
	v, e := g.challenges.Issue(rid, did, g.ChallengeLifetime)
	if e != nil {
		return "", claimErr("INTERNAL_ERROR", "challenge creation failed")
	}
	return v.String(), nil
}
func (g *HealthClaimGateway) GenerateHealthClaimProof(req ClaimRequest, w *HealthClaimWitness) (ProofEnvelope, VerificationResult, error) {
	processingStart := time.Now()
	var empty ProofEnvelope
	if g == nil {
		return empty, VerificationResult{}, claimErr("INTERNAL_ERROR", "gateway is unavailable")
	}
	if w == nil {
		return empty, VerificationResult{}, claimErr("INPUT_ERROR", "private witness is required")
	}
	if g.engine == nil || g.authorities == nil || g.roots == nil || g.policies == nil || g.ids == nil || g.challenges == nil || g.nullifiers == nil {
		return empty, VerificationResult{}, claimErr("INTERNAL_ERROR", "gateway dependencies are incomplete")
	}
	rootV, err := decodeField(req.RootVersion)
	if err != nil {
		return empty, VerificationResult{}, claimErr("INPUT_ERROR", "invalid root version")
	}
	policyV, err := decodeField(req.PolicyVersion)
	if err != nil {
		return empty, VerificationResult{}, claimErr("INPUT_ERROR", "invalid policy version")
	}
	claim, err := decodeField(req.ClaimAmount)
	if err != nil {
		return empty, VerificationResult{}, claimErr("INPUT_ERROR", "invalid claim amount")
	}
	challenge, err := decodeField(req.Challenge)
	if err != nil {
		return empty, VerificationResult{}, claimErr("INPUT_ERROR", "invalid challenge")
	}
	recipient, ok := g.ids.Recipient(req.Recipient)
	if !ok {
		return empty, VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "recipient is not registered")
	}
	deployment, ok := g.ids.Deployment(req.Deployment)
	if !ok {
		return empty, VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "deployment is not registered")
	}
	if err = g.challenges.Validate(challenge, recipient, deployment); err != nil {
		return empty, VerificationResult{}, claimErr("REPLAY_ERROR", "challenge invalid")
	}
	root, ok := g.roots.Root(req.Deployment, rootV)
	if !ok {
		return empty, VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "root/version is not trusted")
	}
	policy, ok := g.policies.Policy(req.Deployment, policyV)
	if !ok {
		return empty, VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "policy/version is not trusted")
	}
	kx, ky, ok := g.authorities.Authority(req.AuthorityID)
	if !ok {
		return empty, VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "authority is not registered")
	}
	if err = validatePrivate(w); err != nil {
		return empty, VerificationResult{}, claimErr("INPUT_ERROR", "private witness is incomplete or malformed")
	}
	if g.nullifiers.IsNullifierUsed(hc.RecordNullifier(w.PatientSecret, hc.IndexFromDirections(pathFrom(w)))) {
		return empty, VerificationResult{}, claimErr("REPLAY_ERROR", "nullifier already used")
	}
	path := pathFrom(w)
	leaf := hc.RecordLeaf(w.Diagnosis, w.LabValue, w.PolicyID, w.CoverageCeiling, hc.SecretCommitment(w.PatientSecret))
	derivedRoot := hc.RootFromPath(leaf, path)
	if derivedRoot.Cmp(root) != 0 {
		return empty, VerificationResult{}, claimErr("CRYPTOGRAPHIC_ERROR", "Merkle witness does not match trusted root")
	}
	if hc.PolicyDigest(w.PolicyID, w.LabMin, w.LabMax, w.PolicyMaxClaim, w.CoveredDiagnosis).Cmp(policy) != 0 {
		return empty, VerificationResult{}, claimErr("CRYPTOGRAPHIC_ERROR", "private policy witness does not match trusted policy commitment")
	}
	var sig eddsa.Signature
	sig.Assign(twistededwards.BN254, w.Signature)
	nul := hc.RecordNullifier(w.PatientSecret, hc.IndexFromDirections(path))
	domain, err := ProtocolFieldValue(HealthClaimProtocolIdentifier)
	if err != nil {
		return empty, VerificationResult{}, claimErr("INPUT_ERROR", "protocol identifier is not supported")
	}
	ctx, err := hc.ContextDigest(challenge, recipient, deployment, policyV, rootV, policy, root, kx, ky, nul, claim)
	if err != nil {
		return empty, VerificationResult{}, claimErr("INPUT_ERROR", "context fields are invalid")
	}
	var covered [4]frontend.Variable
	for i := range covered {
		covered[i] = w.CoveredDiagnosis[i]
	}
	witnessStart := time.Now()
	a := &hc.HealthClaimHardened{RegistryRoot: root, RootVersion: rootV, PolicyCommitment: policy, PolicyVersion: policyV, ClaimAmount: claim, AuthorityKeyX: kx, AuthorityKeyY: ky, Nullifier: nul, ProtocolDomain: domain, Challenge: challenge, RecipientID: recipient, DeploymentID: deployment, ContextCommitment: ctx, Diagnosis: w.Diagnosis, LabValue: w.LabValue, PolicyID: w.PolicyID, CoverageCeiling: w.CoverageCeiling, PatientSecret: w.PatientSecret, LabMin: w.LabMin, LabMax: w.LabMax, PolicyMaxClaim: w.PolicyMaxClaim, CoveredDiagnosis: covered, Signature: sig}
	for x := range path.Siblings {
		a.MerkleSiblings[x] = path.Siblings[x]
		a.MerkleDirections[x] = path.Directions[x]
	}
	witnessDuration := time.Since(witnessStart)
	proveStart := time.Now()
	proof, err := g.engine.Prove(a)
	if err != nil {
		return empty, VerificationResult{}, claimErr("CRYPTOGRAPHIC_ERROR", "proof generation failed")
	}
	proveDuration := time.Since(proveStart)
	statement := statementFrom(a)
	verifyStart := time.Now()
	if err = g.engine.Verify(proof, statement); err != nil {
		return empty, VerificationResult{}, claimErr("CRYPTOGRAPHIC_ERROR", "locally generated proof failed verification")
	}
	verifyDuration := time.Since(verifyStart)
	if err = g.challenges.Consume(challenge); err != nil {
		return empty, VerificationResult{}, claimErr("REPLAY_ERROR", "challenge could not be consumed")
	}
	if err = g.nullifiers.MarkNullifierUsed(nul); err != nil {
		return empty, VerificationResult{}, claimErr("REPLAY_ERROR", "nullifier already used")
	}
	hash := sha256.Sum256(proof)
	envelope := ProofEnvelope{"HealthClaimHardened", "Z7-v1", proof, statement, hex.EncodeToString(hash[:])}
	return envelope, VerificationResult{Valid: true, VerifiedAt: time.Now().UTC(), Nullifier: nul.String(), WitnessConstruction: witnessDuration, ProofGeneration: proveDuration, LocalVerification: verifyDuration, TotalProcessing: time.Since(processingStart)}, nil
}

// VerifyHealthClaimProof validates the public request bindings and registered
// anchors, then verifies the Groth16 proof. Challenge freshness/consumption and
// durable nullifier acceptance remain stateful responsibilities of the caller.
func (g *HealthClaimGateway) VerifyHealthClaimProof(req ClaimRequest, env ProofEnvelope) (VerificationResult, error) {
	if g == nil || g.engine == nil || g.ids == nil || g.roots == nil || g.policies == nil || g.authorities == nil {
		return VerificationResult{}, claimErr("INTERNAL_ERROR", "gateway verification dependencies are incomplete")
	}
	if env.CircuitID != "HealthClaimHardened" || env.CircuitVersion != "Z7-v1" {
		return VerificationResult{}, claimErr("INPUT_ERROR", "unsupported circuit identifier or version")
	}
	s := env.PublicStatement
	rootV, err := decodeField(req.RootVersion)
	if err != nil {
		return VerificationResult{}, claimErr("INPUT_ERROR", "invalid root version")
	}
	policyV, err := decodeField(req.PolicyVersion)
	if err != nil {
		return VerificationResult{}, claimErr("INPUT_ERROR", "invalid policy version")
	}
	claim, err := decodeField(req.ClaimAmount)
	if err != nil {
		return VerificationResult{}, claimErr("INPUT_ERROR", "invalid claim amount")
	}
	challenge, err := decodeField(req.Challenge)
	if err != nil {
		return VerificationResult{}, claimErr("INPUT_ERROR", "invalid challenge")
	}
	recipient, ok := g.ids.Recipient(req.Recipient)
	if !ok {
		return VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "recipient is not registered")
	}
	deployment, ok := g.ids.Deployment(req.Deployment)
	if !ok {
		return VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "deployment is not registered")
	}
	root, ok := g.roots.Root(req.Deployment, rootV)
	if !ok {
		return VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "root/version is not trusted")
	}
	policy, ok := g.policies.Policy(req.Deployment, policyV)
	if !ok {
		return VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "policy/version is not trusted")
	}
	kx, ky, ok := g.authorities.Authority(req.AuthorityID)
	if !ok {
		return VerificationResult{}, claimErr("TRUST_REGISTRY_ERROR", "authority is not registered")
	}
	claimed, err := statementAssignment(s)
	if err != nil {
		return VerificationResult{}, claimErr("INPUT_ERROR", "malformed public statement")
	}
	domain, err := ProtocolFieldValue(HealthClaimProtocolIdentifier)
	if err != nil {
		return VerificationResult{}, claimErr("INPUT_ERROR", "protocol identifier is not supported")
	}
	if claimed.RegistryRoot.(*big.Int).Cmp(root) != 0 || claimed.RootVersion.(*big.Int).Cmp(rootV) != 0 || claimed.PolicyCommitment.(*big.Int).Cmp(policy) != 0 || claimed.PolicyVersion.(*big.Int).Cmp(policyV) != 0 || claimed.ClaimAmount.(*big.Int).Cmp(claim) != 0 || claimed.AuthorityKeyX.(*big.Int).Cmp(kx) != 0 || claimed.AuthorityKeyY.(*big.Int).Cmp(ky) != 0 || claimed.ProtocolDomain.(*big.Int).Cmp(domain) != 0 || claimed.Challenge.(*big.Int).Cmp(challenge) != 0 || claimed.RecipientID.(*big.Int).Cmp(recipient) != 0 || claimed.DeploymentID.(*big.Int).Cmp(deployment) != 0 {
		return VerificationResult{Valid: false, ErrorCode: "TRUST_REGISTRY_ERROR"}, claimErr("TRUST_REGISTRY_ERROR", "statement does not match request or trusted anchors")
	}
	nul, err := decodeField(s.Nullifier)
	if err != nil {
		return VerificationResult{}, claimErr("INPUT_ERROR", "invalid nullifier")
	}
	context, err := hc.ContextDigest(challenge, recipient, deployment, policyV, rootV, policy, root, kx, ky, nul, claim)
	if err != nil || context.Cmp(claimed.ContextCommitment.(*big.Int)) != 0 {
		return VerificationResult{Valid: false, ErrorCode: "CRYPTOGRAPHIC_ERROR"}, claimErr("CRYPTOGRAPHIC_ERROR", "context commitment mismatch")
	}
	if err := g.engine.Verify(env.Proof, env.PublicStatement); err != nil {
		return VerificationResult{Valid: false, ErrorCode: "CRYPTOGRAPHIC_ERROR"}, claimErr("CRYPTOGRAPHIC_ERROR", "proof verification failed")
	}
	hash := sha256.Sum256(env.Proof)
	if env.ProofHash != hex.EncodeToString(hash[:]) {
		return VerificationResult{Valid: false, ErrorCode: "INPUT_ERROR"}, claimErr("INPUT_ERROR", "proof hash does not match serialized proof")
	}
	return VerificationResult{Valid: true, VerifiedAt: time.Now().UTC(), Nullifier: env.PublicStatement.Nullifier}, nil
}

func pathFrom(w *HealthClaimWitness) hc.MerklePath {
	var p hc.MerklePath
	p.Siblings = w.MerkleSiblings
	p.Directions = w.MerkleDirections
	return p
}
func validatePrivate(w *HealthClaimWitness) error {
	vals := []*big.Int{w.Diagnosis, w.LabValue, w.PolicyID, w.CoverageCeiling, w.PatientSecret, w.LabMin, w.LabMax, w.PolicyMaxClaim}
	for _, v := range vals {
		if err := hc.ValidateCanonical(v); err != nil {
			return err
		}
	}
	for _, v := range w.CoveredDiagnosis {
		if err := hc.ValidateCanonical(v); err != nil {
			return err
		}
	}
	for _, v := range w.MerkleSiblings {
		if err := hc.ValidateCanonical(v); err != nil {
			return err
		}
	}
	for _, v := range w.MerkleDirections {
		if v == nil || (v.Cmp(big.NewInt(0)) != 0 && v.Cmp(big.NewInt(1)) != 0) {
			return fmt.Errorf("invalid Merkle direction")
		}
	}
	if len(w.Signature) != 64 {
		return fmt.Errorf("authority signature encoding has invalid length")
	}
	var decoded cryptoed.Signature
	if _, err := decoded.SetBytes(w.Signature); err != nil {
		return fmt.Errorf("authority signature encoding is malformed")
	}
	return nil
}
func statementFrom(a *hc.HealthClaimHardened) PublicStatement {
	return PublicStatement{fieldString(a.RegistryRoot.(*big.Int)), fieldString(a.RootVersion.(*big.Int)), fieldString(a.PolicyCommitment.(*big.Int)), fieldString(a.PolicyVersion.(*big.Int)), fieldString(a.ClaimAmount.(*big.Int)), fieldString(a.AuthorityKeyX.(*big.Int)), fieldString(a.AuthorityKeyY.(*big.Int)), fieldString(a.Nullifier.(*big.Int)), fieldString(a.ProtocolDomain.(*big.Int)), fieldString(a.Challenge.(*big.Int)), fieldString(a.RecipientID.(*big.Int)), fieldString(a.DeploymentID.(*big.Int)), fieldString(a.ContextCommitment.(*big.Int))}
}
func statementAssignment(s PublicStatement) (*hc.HealthClaimHardened, error) {
	ss := []string{s.RegistryRoot, s.RootVersion, s.PolicyCommitment, s.PolicyVersion, s.ClaimAmount, s.AuthorityKeyX, s.AuthorityKeyY, s.Nullifier, s.ProtocolDomain, s.Challenge, s.RecipientID, s.DeploymentID, s.ContextCommitment}
	v := make([]*big.Int, len(ss))
	for i, x := range ss {
		n, e := decodeField(x)
		if e != nil {
			return nil, e
		}
		v[i] = n
	}
	return &hc.HealthClaimHardened{RegistryRoot: v[0], RootVersion: v[1], PolicyCommitment: v[2], PolicyVersion: v[3], ClaimAmount: v[4], AuthorityKeyX: v[5], AuthorityKeyY: v[6], Nullifier: v[7], ProtocolDomain: v[8], Challenge: v[9], RecipientID: v[10], DeploymentID: v[11], ContextCommitment: v[12]}, nil
}

var _ = cryptoed.PrivateKey{}
