package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
)

// The test stub embeds the full Fabric interface and implements the exact state
// methods exercised here. These tests exercise contract logic; they are not
// represented as a live Fabric network integration run.
type claimTestStub struct {
	shim.ChaincodeStubInterface
	state  map[string][]byte
	txID   string
	txTime *timestamp.Timestamp
}

func newClaimTestStub() *claimTestStub {
	return &claimTestStub{state: map[string][]byte{}, txID: "tx-z11", txTime: &timestamp.Timestamp{Seconds: 1_800_000_000}}
}
func (s *claimTestStub) GetState(k string) ([]byte, error) {
	v := s.state[k]
	return append([]byte(nil), v...), nil
}
func (s *claimTestStub) PutState(k string, v []byte) error {
	s.state[k] = append([]byte(nil), v...)
	return nil
}
func (s *claimTestStub) DelState(k string) error                       { delete(s.state, k); return nil }
func (s *claimTestStub) GetTxID() string                               { return s.txID }
func (s *claimTestStub) GetTxTimestamp() (*timestamp.Timestamp, error) { return s.txTime, nil }
func (s *claimTestStub) CreateCompositeKey(object string, attrs []string) (string, error) {
	return "\x00" + object + "\x00" + strings.Join(attrs, "\x00") + "\x00", nil
}
func (s *claimTestStub) GetStateByPartialCompositeKey(object string, attrs []string) (shim.StateQueryIteratorInterface, error) {
	prefix, _ := s.CreateCompositeKey(object, attrs)
	keys := make([]string, 0)
	for k := range s.state {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	items := make([]*queryresult.KV, 0, len(keys))
	for _, k := range keys {
		items = append(items, &queryresult.KV{Key: k, Value: s.state[k]})
	}
	return &claimTestIterator{items: items}, nil
}

type claimTestIterator struct {
	items []*queryresult.KV
	index int
}

func (i *claimTestIterator) HasNext() bool { return i.index < len(i.items) }
func (i *claimTestIterator) Next() (*queryresult.KV, error) {
	if !i.HasNext() {
		return nil, fmt.Errorf("iterator exhausted")
	}
	v := i.items[i.index]
	i.index++
	return v, nil
}
func (i *claimTestIterator) Close() error { return nil }

type claimTestIdentity struct {
	msp, id string
	attrs   map[string]string
}

func (i claimTestIdentity) GetID() (string, error)    { return i.id, nil }
func (i claimTestIdentity) GetMSPID() (string, error) { return i.msp, nil }
func (i claimTestIdentity) GetAttributeValue(k string) (string, bool, error) {
	v, ok := i.attrs[k]
	return v, ok, nil
}
func (i claimTestIdentity) AssertAttributeValue(k, v string) error {
	if i.attrs[k] != v {
		return fmt.Errorf("attribute mismatch")
	}
	return nil
}
func (i claimTestIdentity) GetX509Certificate() (*x509.Certificate, error) { return nil, nil }

type claimTestContext struct {
	contractapi.TransactionContext
	stub     shim.ChaincodeStubInterface
	identity cid.ClientIdentity
}

func (c *claimTestContext) GetStub() shim.ChaincodeStubInterface  { return c.stub }
func (c *claimTestContext) GetClientIdentity() cid.ClientIdentity { return c.identity }
func newClaimContext(stub *claimTestStub, msp, id, role string) *claimTestContext {
	return &claimTestContext{stub: stub, identity: claimTestIdentity{msp: msp, id: id, attrs: map[string]string{"role": role}}}
}

type claimTestFixture struct {
	contract   *ZeroTrustBlockContract
	stub       *claimTestStub
	submission FabricClaimSubmission
}

const (
	testAuthorityX = "9671717474070082183213120605117400219616337014328744928644933853176787189663"
	testAuthorityY = "16950150798460657717958625567821834550301663161624707787222815936182638968203"
)

func preparedClaim(t *testing.T) claimTestFixture {
	t.Helper()
	c := &ZeroTrustBlockContract{}
	s := newClaimTestStub()
	hospital := newClaimContext(s, "HospitalMSP", "hospital-admin", "admin")
	insurer := newClaimContext(s, "InsurerMSP", "insurer-user", "insurer")
	verifier := newClaimContext(s, "InsurerMSP", "zkp-verifier", "zkpVerifier")
	for _, err := range []error{c.RegisterTrustedAuthority(hospital, "hospital-key", testAuthorityX, testAuthorityY), c.SetAcceptedClaimRoot(hospital, "9", "5", "111"), c.SetAcceptedClaimPolicy(hospital, "9", "3", "222"), c.IssueHealthClaimChallenge(insurer, "777", "12", "9", "5", "3")} {
		if err != nil {
			t.Fatal(err)
		}
	}
	proof := make([]byte, claimProofBytes)
	for i := range proof {
		proof[i] = byte(i)
	}
	hash := sha256.Sum256(proof)
	sub := FabricClaimSubmission{CircuitID: claimCircuitID, CircuitVersion: claimCircuitVersion, ClaimID: "claim-001", AuthorityID: "hospital-key", Proof: proof, ProofHash: hex.EncodeToString(hash[:]), PublicStatement: PublicClaimStatement{RegistryRoot: "111", RootVersion: "5", PolicyCommitment: "222", PolicyVersion: "3", ClaimAmount: "900", AuthorityKeyX: testAuthorityX, AuthorityKeyY: testAuthorityY, Nullifier: "333", ProtocolDomain: claimProtocolDomain, Challenge: "777", RecipientID: "12", DeploymentID: "9", ContextCommitment: "444"}}
	_ = verifier
	return claimTestFixture{c, s, sub}
}
func runClaim(t *testing.T, f claimTestFixture, sub FabricClaimSubmission) (*HealthClaimProofRecord, error) {
	t.Helper()
	b, e := json.Marshal(sub)
	if e != nil {
		t.Fatal(e)
	}
	return f.contract.SubmitHealthClaimProof(newClaimContext(f.stub, "InsurerMSP", "zkp-verifier", "zkpVerifier"), string(b))
}
func issueNext(t *testing.T, f claimTestFixture, challenge string) {
	t.Helper()
	err := f.contract.IssueHealthClaimChallenge(newClaimContext(f.stub, "InsurerMSP", "insurer-user", "insurer"), challenge, "12", "9", "5", "3")
	if err != nil {
		t.Fatal(err)
	}
}

func TestSubmitHealthClaimProofStoresPublicClaimAndAuditOnly(t *testing.T) {
	f := preparedClaim(t)
	record, err := runClaim(t, f, f.submission)
	if err != nil {
		t.Fatal(err)
	}
	if record.Status != "ACCEPTED" || record.VerificationTrust != "GATEWAY_VERIFIER_IDENTITY" {
		t.Fatalf("unexpected accepted metadata: %+v", record)
	}
	if record.SubmitterMSP != "InsurerMSP" || record.TransactionID != "tx-z11" {
		t.Fatal("missing submitter or tx metadata")
	}
	for _, key := range []string{"diagnosis", "labValue", "patientSecret", "coverageCeiling", "merkleSiblings", "merkleDirections", "signature"} {
		if strings.Contains(string(mustJSON(t, record)), "\""+key+"\"") {
			t.Fatalf("private witness key %s stored", key)
		}
	}
	auditKey, _ := f.stub.CreateCompositeKey(zkAuditNamespace, []string{record.ClaimID})
	if _, ok := f.stub.state[auditKey]; !ok {
		t.Fatal("accepted claim missing audit record")
	}
	nullKey, _ := f.stub.CreateCompositeKey(zkNullifierNamespace, []string{record.PublicStatement.Nullifier})
	if string(f.stub.state[nullKey]) != record.ClaimID {
		t.Fatal("nullifier was not recorded")
	}
	challengeKey, _ := f.stub.CreateCompositeKey(zkChallengeNamespace, []string{record.PublicStatement.Challenge})
	var challenge ClaimChallenge
	if err = json.Unmarshal(f.stub.state[challengeKey], &challenge); err != nil || challenge.Status != "CONSUMED" {
		t.Fatal("challenge was not consumed")
	}
	reader := newClaimContext(f.stub, "InsurerMSP", "insurer", "insurer")
	queriedChallenge, err := f.contract.GetHealthClaimChallenge(reader, record.PublicStatement.Challenge)
	if err != nil || queriedChallenge.Status != "CONSUMED" || queriedChallenge.ConsumedBy != record.ClaimID {
		t.Fatalf("challenge lifecycle query failed: %+v %v", queriedChallenge, err)
	}
	queriedNullifier, err := f.contract.GetHealthClaimNullifier(reader, record.PublicStatement.Nullifier)
	if err != nil || !queriedNullifier.Used || queriedNullifier.ClaimID != record.ClaimID {
		t.Fatalf("nullifier lifecycle query failed: %+v %v", queriedNullifier, err)
	}
}
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestClaimNullifierAndChallengeReplayAreAtomic(t *testing.T) {
	f := preparedClaim(t)
	if _, e := runClaim(t, f, f.submission); e != nil {
		t.Fatal(e)
	}
	issueNext(t, f, "778")
	again := f.submission
	again.ClaimID = "claim-002"
	again.PublicStatement.Challenge = "778"
	if _, e := runClaim(t, f, again); e == nil || !strings.Contains(e.Error(), "nullifier already used") {
		t.Fatalf("duplicate nullifier not rejected: %v", e)
	}
	issueNext(t, f, "779")
	different := f.submission
	different.ClaimID = "claim-003"
	different.PublicStatement.Challenge = "779"
	different.PublicStatement.Nullifier = "334"
	if _, e := runClaim(t, f, different); e != nil {
		t.Fatalf("different nullifier should succeed: %v", e)
	}
	if e := f.contract.IssueHealthClaimChallenge(newClaimContext(f.stub, "InsurerMSP", "insurer-user", "insurer"), "779", "12", "9", "5", "3"); e == nil {
		t.Fatal("duplicate challenge accepted")
	}
}

func TestConsumedChallengeCannotAcceptAnotherClaim(t *testing.T) {
	f := preparedClaim(t)
	if _, err := runClaim(t, f, f.submission); err != nil {
		t.Fatal(err)
	}
	replay := f.submission
	replay.ClaimID = "claim-challenge-replay"
	replay.PublicStatement.Nullifier = "335"
	if _, err := runClaim(t, f, replay); err == nil || !strings.Contains(err.Error(), "challenge is missing or already consumed") {
		t.Fatalf("consumed challenge reuse was not rejected at challenge state: %v", err)
	}
	replayKey, _ := f.stub.CreateCompositeKey(zkClaimNamespace, []string{replay.ClaimID})
	if f.stub.state[replayKey] != nil {
		t.Fatal("challenge replay wrote another claim")
	}
}

func TestClaimSubmissionRejectsInvalidAnchorsProofAndIdentity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*claimTestFixture, *FabricClaimSubmission, *claimTestContext)
	}{
		{"claim ID", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) { s.ClaimID = "../bad" }},
		{"proof hash", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) { s.ProofHash = "bad" }},
		{"proof length", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) { s.Proof = s.Proof[:32] }},
		{"root version", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			s.PublicStatement.RootVersion = "7"
		}},
		{"root value", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			s.PublicStatement.RegistryRoot = "112"
		}},
		{"policy version", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			s.PublicStatement.PolicyVersion = "4"
		}},
		{"policy commitment", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			s.PublicStatement.PolicyCommitment = "223"
		}},
		{"authority", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) { s.AuthorityID = "other" }},
		{"authority key", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			s.PublicStatement.AuthorityKeyX = "3"
		}},
		{"wrong challenge recipient", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			s.PublicStatement.RecipientID = "13"
		}},
		{"wrong deployment", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			s.PublicStatement.DeploymentID = "10"
		}},
		{"malformed field", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			s.PublicStatement.Nullifier = "01"
		}},
		{"unauthorized MSP", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			c.identity = claimTestIdentity{msp: "HospitalMSP", id: "doctor", attrs: map[string]string{"role": "doctor"}}
		}},
		{"unauthorized insurer role", func(f *claimTestFixture, s *FabricClaimSubmission, c *claimTestContext) {
			c.identity = claimTestIdentity{msp: "InsurerMSP", id: "insurer", attrs: map[string]string{"role": "insurer"}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := preparedClaim(t)
			s := f.submission
			ctx := newClaimContext(f.stub, "InsurerMSP", "zkp-verifier", "zkpVerifier")
			tc.mutate(&f, &s, ctx)
			raw, _ := json.Marshal(s)
			_, err := f.contract.SubmitHealthClaimProof(ctx, string(raw))
			if err == nil {
				t.Fatal("invalid submission accepted")
			}
			claimKey, _ := f.stub.CreateCompositeKey(zkClaimNamespace, []string{f.submission.ClaimID})
			if f.stub.state[claimKey] != nil {
				t.Fatal("failed submission wrote claim state")
			}
		})
	}
}

func TestRegistryAndAccessLogAuthorization(t *testing.T) {
	f := preparedClaim(t)
	insurer := newClaimContext(f.stub, "InsurerMSP", "insurer-user", "insurer")
	if e := f.contract.SetAcceptedClaimRoot(insurer, "9", "6", "113"); e == nil {
		t.Fatal("unauthorized registry update accepted")
	}
	if _, e := f.contract.GetAccessLogs(insurer, "record-1"); e == nil {
		t.Fatal("insurer role could read restricted access logs")
	}
	admin := newClaimContext(f.stub, "HospitalMSP", "admin", "admin")
	if _, e := f.contract.GetAccessLogs(admin, "record-1"); e != nil {
		t.Fatalf("hospital admin log read failed: %v", e)
	}
	// Unconsumed challenges expire based on transaction timestamps, not wall time.
	key, _ := f.stub.CreateCompositeKey(zkChallengeNamespace, []string{"777"})
	var ch ClaimChallenge
	_ = json.Unmarshal(f.stub.state[key], &ch)
	f.stub.txTime = &timestamp.Timestamp{Seconds: ch.ExpiresAt + 1}
	if _, e := runClaim(t, f, f.submission); e == nil || !strings.Contains(e.Error(), "expired") {
		t.Fatalf("expired challenge accepted: %v", e)
	}
}

func TestTrustedAuthorityRegistrationRejectsInvalidEdwardsKeys(t *testing.T) {
	contract := &ZeroTrustBlockContract{}
	ctx := newClaimContext(newClaimTestStub(), "HospitalMSP", "admin", "admin")
	modulusMinusOne := new(big.Int).Sub(bn254ScalarModulus, big.NewInt(1)).String()
	cases := []struct{ name, x, y string }{
		{name: "off-curve", x: "1", y: "2"},
		{name: "identity", x: "0", y: "1"},
		{name: "order-2 torsion", x: "0", y: modulusMinusOne},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := contract.RegisterTrustedAuthority(ctx, "untrusted", tc.x, tc.y); err == nil {
				t.Fatalf("accepted invalid authority key (%s,%s)", tc.x, tc.y)
			}
		})
	}
	if err := contract.RegisterTrustedAuthority(ctx, "trusted", testAuthorityX, testAuthorityY); err != nil {
		t.Fatalf("rejected valid prime-subgroup authority point: %v", err)
	}
}

func TestZ12StorageSerializationSizesAndPrivacy(t *testing.T) {
	f := preparedClaim(t)
	record, err := runClaim(t, f, f.submission)
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, err := json.Marshal(record.PublicStatement)
	if err != nil {
		t.Fatal(err)
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	auditKey, _ := f.stub.CreateCompositeKey(zkAuditNamespace, []string{record.ClaimID})
	var audit HealthClaimAudit
	if err = json.Unmarshal(f.stub.state[auditKey], &audit); err != nil {
		t.Fatal(err)
	}
	auditJSON, err := json.Marshal(audit)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"diagnosis", "labValue", "patientSecret", "coverageCeiling", "merkleSiblings", "merkleDirections", "policyID"} {
		if strings.Contains(string(recordJSON), `"`+forbidden+`"`) || strings.Contains(string(auditJSON), `"`+forbidden+`"`) {
			t.Fatalf("private field %q appeared in serialized ledger data", forbidden)
		}
	}
	t.Logf("proof_bytes=%d proof_hash_hex_chars=%d public_statement_json_bytes=%d claim_record_json_bytes=%d audit_record_json_bytes=%d", len(record.Proof), len(record.ProofHash), len(publicJSON), len(recordJSON), len(auditJSON))
}
