//go:build z12integration

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cryptoed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	hc "zerotrust/healthclaimhardened"
)

// This test is intentionally gated: it submits durable test transactions to the
// configured Fabric channel and must only run when the operator explicitly opts in.
func TestZ12LiveValidClaimAndReplay(t *testing.T) {
	if os.Getenv("ZT_Z12_LIVE") != "1" {
		t.Skip("set ZT_Z12_LIVE=1 to submit real transactions to the configured Fabric channel")
	}
	profile := envOr("ZT_Z12_CONNECTION_PROFILE", "connection-profile-abs.yaml")
	if !filepath.IsAbs(profile) {
		profile = filepath.Join(".", profile)
	}
	wallet := envOr("ZT_Z12_WALLET_DIR", "wallet")
	if !filepath.IsAbs(wallet) {
		wallet = filepath.Join(".", wallet)
	}
	channel := envOr("ZT_Z12_CHANNEL", "healthchannel")
	chaincode := envOr("ZT_Z12_CHAINCODE", "health")
	adminID := envOr("ZT_Z12_HOSPITAL_ADMIN_IDENTITY", "appAdmin")
	verifierID := envOr("ZT_Z12_VERIFIER_IDENTITY", "zkpVerifier")
	admin, err := NewGateway(GatewayConfig{ConnectionProfilePath: profile, WalletPath: wallet, OrgMSP: "HospitalMSP", ChannelName: channel, HealthChaincode: chaincode, UserIdentity: adminID})
	if err != nil {
		t.Fatalf("connect HospitalMSP registry administrator: %v", err)
	}
	defer admin.Close()
	verifierClient, err := NewGateway(GatewayConfig{ConnectionProfilePath: profile, WalletPath: wallet, OrgMSP: "InsurerMSP", ChannelName: channel, HealthChaincode: chaincode, UserIdentity: verifierID})
	if err != nil {
		t.Fatalf("connect InsurerMSP verifier identity: %v", err)
	}
	defer verifierClient.Close()

	engine, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	verifier, req, witness := makeGatewayFixture(t, engine)
	req = z12SetUniqueRecord(t, verifier, req, witness, 10001, "2000")
	rootVersion, _ := decodeField(req.RootVersion)
	policyVersion, _ := decodeField(req.PolicyVersion)
	root, ok := verifier.roots.Root(req.Deployment, rootVersion)
	if !ok {
		t.Fatal("fixture root missing")
	}
	policy, ok := verifier.policies.Policy(req.Deployment, policyVersion)
	if !ok {
		t.Fatal("fixture policy missing")
	}
	keyX, keyY, ok := verifier.authorities.Authority(req.AuthorityID)
	if !ok {
		t.Fatal("fixture authority missing")
	}
	deploymentID, ok := verifier.ids.Deployment(req.Deployment)
	if !ok {
		t.Fatal("fixture deployment missing")
	}
	adminContract := admin.network.GetContract(chaincode)
	for _, tx := range []struct {
		name string
		args []string
	}{
		{"RegisterTrustedAuthority", []string{"z12-authority", keyX.String(), keyY.String()}},
		{"SetAcceptedClaimRoot", []string{deploymentID.String(), req.RootVersion, root.String()}},
		{"SetAcceptedClaimPolicy", []string{deploymentID.String(), req.PolicyVersion, policy.String()}},
	} {
		if _, err = adminContract.SubmitTransaction(tx.name, tx.args...); err != nil {
			t.Fatalf("initialize Fabric trust registry %s: %v", tx.name, err)
		}
	}

	e2eStart := time.Now()
	challenge, err := verifierClient.IssueFabricClaimChallenge(verifier, req.Recipient, req.Deployment, req.RootVersion, req.PolicyVersion)
	if err != nil {
		t.Fatalf("issue and anchor Fabric challenge: %v", err)
	}
	req.Challenge = challenge
	envelope, generated, err := verifier.GenerateHealthClaimProof(req, witness)
	if err != nil {
		t.Fatalf("generate locally verified HealthClaimHardened proof: %v", err)
	}
	claimID := fmt.Sprintf("z12-%d", time.Now().UnixNano())
	fabricStart := time.Now()
	accepted, err := verifierClient.SubmitHealthClaimProof(verifier, req, envelope, claimID, "z12-authority")
	fabricCall := time.Since(fabricStart)
	if err != nil {
		t.Fatalf("submit claim and wait for Fabric commit: %v", err)
	}
	if accepted.Status != "ACCEPTED" || accepted.TransactionID == "" {
		t.Fatalf("missing accepted commit result: %+v", accepted)
	}

	contract := verifierClient.network.GetContract(chaincode)
	queryStart := time.Now()
	recordBytes, err := contract.EvaluateTransaction("GetHealthClaimProof", claimID)
	if err != nil {
		t.Fatalf("query committed claim: %v", err)
	}
	queryDuration := time.Since(queryStart)
	auditBytes, err := contract.EvaluateTransaction("GetHealthClaimAudit", claimID)
	if err != nil {
		t.Fatalf("query claim audit: %v", err)
	}
	challengeBytes, err := contract.EvaluateTransaction("GetHealthClaimChallenge", challenge)
	if err != nil {
		t.Fatalf("query challenge lifecycle: %v", err)
	}
	nullifier := envelope.PublicStatement.Nullifier
	nullifierBytes, err := contract.EvaluateTransaction("GetHealthClaimNullifier", nullifier)
	if err != nil {
		t.Fatalf("query nullifier lifecycle: %v", err)
	}
	var record struct {
		Status            string `json:"status"`
		VerificationTrust string `json:"verificationTrust"`
		TransactionID     string `json:"transactionId"`
		Proof             []byte `json:"proof"`
	}
	var audit struct {
		Status        string `json:"status"`
		TransactionID string `json:"transactionId"`
	}
	var challengeState struct {
		Status     string `json:"status"`
		ConsumedBy string `json:"consumedBy"`
	}
	var nullifierState struct {
		Used    bool   `json:"used"`
		ClaimID string `json:"claimId"`
	}
	for _, item := range []struct {
		name string
		raw  []byte
		out  any
	}{{"claim", recordBytes, &record}, {"audit", auditBytes, &audit}, {"challenge", challengeBytes, &challengeState}, {"nullifier", nullifierBytes, &nullifierState}} {
		if err = json.Unmarshal(item.raw, item.out); err != nil {
			t.Fatalf("decode %s query: %v", item.name, err)
		}
	}
	if record.Status != "ACCEPTED" || record.VerificationTrust != "GATEWAY_VERIFIER_IDENTITY" || record.TransactionID != accepted.TransactionID || audit.Status != "ACCEPTED" || audit.TransactionID != accepted.TransactionID || challengeState.Status != "CONSUMED" || challengeState.ConsumedBy != claimID || !nullifierState.Used || nullifierState.ClaimID != claimID {
		t.Fatalf("committed lifecycle mismatch: record=%+v audit=%+v challenge=%+v nullifier=%+v", record, audit, challengeState, nullifierState)
	}
	for _, forbidden := range []string{"diagnosis", "labValue", "patientSecret", "coverageCeiling", "merkleSiblings", "merkleDirections", "policyID"} {
		if strings.Contains(string(recordBytes), `"`+forbidden+`"`) {
			t.Fatalf("private witness field %q appeared in ledger record", forbidden)
		}
	}
	if len(record.Proof) != len(envelope.Proof) {
		t.Fatalf("stored proof length %d differs from submitted %d", len(record.Proof), len(envelope.Proof))
	}
	if len(envelope.Proof) != 164 {
		t.Fatalf("unexpected proof length: %d", len(envelope.Proof))
	}

	// Local proof tampering must be stopped before Fabric and leave no record.
	badID := fmt.Sprintf("z12-bad-%d", time.Now().UnixNano())
	bad := envelope
	bad.Proof = append([]byte(nil), envelope.Proof...)
	bad.Proof[0] ^= 1
	if _, err = verifierClient.SubmitHealthClaimProof(verifier, req, bad, badID, "z12-authority"); err == nil {
		t.Fatal("mutated Groth16 proof was accepted locally")
	}
	if _, err = contract.EvaluateTransaction("GetHealthClaimProof", badID); err == nil {
		t.Fatal("invalid local proof unexpectedly created a ledger claim")
	}

	// New local verifier state, same patient secret/path => same record nullifier.
	engine2, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	verifier2, req2, witness2 := makeGatewayFixture(t, engine2)
	challenge2, err := verifierClient.IssueFabricClaimChallenge(verifier2, req2.Recipient, req2.Deployment, req2.RootVersion, req2.PolicyVersion)
	if err != nil {
		t.Fatalf("issue duplicate-nullifier challenge: %v", err)
	}
	req2.Challenge = challenge2
	envelope2, _, err := verifier2.GenerateHealthClaimProof(req2, witness2)
	if err != nil {
		t.Fatalf("generate duplicate-nullifier valid proof: %v", err)
	}
	duplicateID := fmt.Sprintf("z12-duplicate-%d", time.Now().UnixNano())
	if _, err = verifierClient.SubmitHealthClaimProof(verifier2, req2, envelope2, duplicateID, "z12-authority"); err == nil {
		t.Fatal("Fabric accepted duplicate nullifier")
	}
	if _, err = contract.EvaluateTransaction("GetHealthClaimProof", duplicateID); err == nil {
		t.Fatal("duplicate-nullifier claim unexpectedly committed")
	}
	nullifierAfter, err := contract.EvaluateTransaction("GetHealthClaimNullifier", nullifier)
	if err != nil || !strings.Contains(string(nullifierAfter), claimID) {
		t.Fatalf("original nullifier state changed after duplicate rejection: %s %v", nullifierAfter, err)
	}

	t.Logf("Z12_LIVE_RESULT claim_id=%s txid=%s block=%d proof_bytes=%d public_statement_bytes=%d record_bytes=%d audit_bytes=%d challenge_state=%s nullifier_used=%t witness_ns=%d prove_ns=%d local_verify_ns=%d gateway_total_ns=%d submit_verify_ns=%d serialization_ns=%d submit_commit_ns=%d submit_call_ns=%d ledger_query_ns=%d e2e_ns=%d invalid_proof_no_record=true duplicate_nullifier_rejected=true", claimID, accepted.TransactionID, accepted.BlockNumber, len(envelope.Proof), len(mustMarshal(t, envelope.PublicStatement)), len(recordBytes), len(auditBytes), challengeState.Status, nullifierState.Used, generated.WitnessConstruction.Nanoseconds(), generated.ProofGeneration.Nanoseconds(), generated.LocalVerification.Nanoseconds(), generated.TotalProcessing.Nanoseconds(), accepted.VerificationNanoseconds, accepted.SerializationNanoseconds, accepted.SubmitCommitNanoseconds, fabricCall.Nanoseconds(), queryDuration.Nanoseconds(), time.Since(e2eStart).Nanoseconds())
}

func z12SetUniqueRecord(t *testing.T, verifier *HealthClaimGateway, req ClaimRequest, witness *HealthClaimWitness, secret int64, rootVersion string) ClaimRequest {
	t.Helper()
	key, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x31}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	witness.PatientSecret = big.NewInt(secret)
	leaf := hc.RecordLeaf(witness.Diagnosis, witness.LabValue, witness.PolicyID, witness.CoverageCeiling, hc.SecretCommitment(witness.PatientSecret))
	witness.Signature, err = hc.SignLeaf(key, leaf)
	if err != nil {
		t.Fatal(err)
	}
	root := hc.RootFromPath(leaf, pathFrom(witness))
	rootV, ok := new(big.Int).SetString(rootVersion, 10)
	if !ok {
		t.Fatalf("invalid test root version %q", rootVersion)
	}
	verifier.roots.(*MemoryRegistries).RegisterRoot(req.Deployment, rootV, root)
	req.RootVersion = rootVersion
	return req
}

func TestZ12LiveSequentialClaimsAndDuplicateNullifierRace(t *testing.T) {
	if os.Getenv("ZT_Z12_LIVE") != "1" {
		t.Skip("set ZT_Z12_LIVE=1 to submit real transactions to the configured Fabric channel")
	}
	profile := envOr("ZT_Z12_CONNECTION_PROFILE", "connection-profile-abs.yaml")
	if !filepath.IsAbs(profile) {
		profile = filepath.Join(".", profile)
	}
	wallet := envOr("ZT_Z12_WALLET_DIR", "wallet")
	if !filepath.IsAbs(wallet) {
		wallet = filepath.Join(".", wallet)
	}
	channel, chaincode := envOr("ZT_Z12_CHANNEL", "healthchannel"), envOr("ZT_Z12_CHAINCODE", "health")
	admin, err := NewGateway(GatewayConfig{ConnectionProfilePath: profile, WalletPath: wallet, OrgMSP: "HospitalMSP", ChannelName: channel, HealthChaincode: chaincode, UserIdentity: envOr("ZT_Z12_HOSPITAL_ADMIN_IDENTITY", "appAdmin")})
	if err != nil {
		t.Fatalf("connect HospitalMSP registry administrator: %v", err)
	}
	defer admin.Close()
	client, err := NewGateway(GatewayConfig{ConnectionProfilePath: profile, WalletPath: wallet, OrgMSP: "InsurerMSP", ChannelName: channel, HealthChaincode: chaincode, UserIdentity: envOr("ZT_Z12_VERIFIER_IDENTITY", "zkpVerifier")})
	if err != nil {
		t.Fatalf("connect InsurerMSP verifier identity: %v", err)
	}
	defer client.Close()
	engine, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	adminContract, contract := admin.network.GetContract(chaincode), client.network.GetContract(chaincode)
	n := 5
	if text := os.Getenv("ZT_Z12_SEQUENTIAL_N"); text != "" {
		if _, err = fmt.Sscanf(text, "%d", &n); err != nil || n < 1 || n > 100 {
			t.Fatalf("ZT_Z12_SEQUENTIAL_N must be in [1,100]")
		}
	}
	var e2e []int64
	var fabric []int64
	var gateway []int64
	for i := 0; i < n; i++ {
		verifier, req, witness := makeGatewayFixture(t, engine)
		version := fmt.Sprint(3000 + i)
		req = z12SetUniqueRecord(t, verifier, req, witness, int64(12000+i), version)
		rootVersion, _ := decodeField(req.RootVersion)
		root, _ := verifier.roots.Root(req.Deployment, rootVersion)
		deploymentID, _ := verifier.ids.Deployment(req.Deployment)
		if _, err = adminContract.SubmitTransaction("SetAcceptedClaimRoot", deploymentID.String(), req.RootVersion, root.String()); err != nil {
			t.Fatalf("register sequential root %s: %v", version, err)
		}
		started := time.Now()
		challenge, issueErr := client.IssueFabricClaimChallenge(verifier, req.Recipient, req.Deployment, req.RootVersion, req.PolicyVersion)
		if issueErr != nil {
			t.Fatalf("issue sequential challenge %d: %v", i, issueErr)
		}
		req.Challenge = challenge
		envelope, gen, genErr := verifier.GenerateHealthClaimProof(req, witness)
		if genErr != nil {
			t.Fatalf("generate sequential proof %d: %v", i, genErr)
		}
		result, submitErr := client.SubmitHealthClaimProof(verifier, req, envelope, fmt.Sprintf("z12-seq-%d-%d", time.Now().UnixNano(), i), "z12-authority")
		if submitErr != nil || result.Status != "ACCEPTED" {
			t.Fatalf("sequential claim %d rejected: %+v %v", i, result, submitErr)
		}
		e2e = append(e2e, time.Since(started).Nanoseconds())
		fabric = append(fabric, result.SubmitCommitNanoseconds)
		gateway = append(gateway, gen.TotalProcessing.Nanoseconds()+result.VerificationNanoseconds+result.SerializationNanoseconds)
		t.Logf("Z12_SEQUENTIAL_SAMPLE index=%d txid=%s block=%d e2e_ns=%d gateway_local_ns=%d submit_verify_ns=%d serialization_ns=%d submit_commit_ns=%d", i, result.TransactionID, result.BlockNumber, e2e[len(e2e)-1], gateway[len(gateway)-1], result.VerificationNanoseconds, result.SerializationNanoseconds, result.SubmitCommitNanoseconds)
	}
	t.Logf("Z12_SEQUENTIAL_SUMMARY N=%d e2e_ns=%v gateway_ns=%v fabric_submit_commit_ns=%v p99=not-reported-small-sample", n, z12Summary(e2e), z12Summary(gateway), z12Summary(fabric))

	// Race two independently generated valid proofs with the same record-derived
	// nullifier, distinct challenges, and distinct claim IDs.
	raceA, reqA, witnessA := makeGatewayFixture(t, engine)
	reqA = z12SetUniqueRecord(t, raceA, reqA, witnessA, 99123, "4000")
	raceB, reqB, witnessB := makeGatewayFixture(t, engine)
	reqB = z12SetUniqueRecord(t, raceB, reqB, witnessB, 99123, "4000")
	raceRootVersion, _ := decodeField(reqA.RootVersion)
	raceRoot, _ := raceA.roots.Root(reqA.Deployment, raceRootVersion)
	raceDeploymentID, _ := raceA.ids.Deployment(reqA.Deployment)
	if _, err = adminContract.SubmitTransaction("SetAcceptedClaimRoot", raceDeploymentID.String(), reqA.RootVersion, raceRoot.String()); err != nil {
		t.Fatalf("register duplicate-race root: %v", err)
	}
	challengeA, err := client.IssueFabricClaimChallenge(raceA, reqA.Recipient, reqA.Deployment, reqA.RootVersion, reqA.PolicyVersion)
	if err != nil {
		t.Fatal(err)
	}
	challengeB, err := client.IssueFabricClaimChallenge(raceB, reqB.Recipient, reqB.Deployment, reqB.RootVersion, reqB.PolicyVersion)
	if err != nil {
		t.Fatal(err)
	}
	reqA.Challenge, reqB.Challenge = challengeA, challengeB
	envA, _, err := raceA.GenerateHealthClaimProof(reqA, witnessA)
	if err != nil {
		t.Fatal(err)
	}
	envB, _, err := raceB.GenerateHealthClaimProof(reqB, witnessB)
	if err != nil {
		t.Fatal(err)
	}
	if envA.PublicStatement.Nullifier != envB.PublicStatement.Nullifier {
		t.Fatal("race fixtures did not derive the same record nullifier")
	}
	claimA := fmt.Sprintf("z12-race-a-%d", time.Now().UnixNano())
	claimB := fmt.Sprintf("z12-race-b-%d", time.Now().UnixNano())
	type raceResult struct {
		id     string
		result FabricClaimSubmitResult
		err    error
	}
	startRace := make(chan struct{})
	results := make(chan raceResult, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for _, input := range []struct {
		id string
		g  *HealthClaimGateway
		r  ClaimRequest
		e  ProofEnvelope
	}{{claimA, raceA, reqA, envA}, {claimB, raceB, reqB, envB}} {
		input := input
		go func() {
			defer workers.Done()
			<-startRace
			result, submitErr := client.SubmitHealthClaimProof(input.g, input.r, input.e, input.id, "z12-authority")
			results <- raceResult{id: input.id, result: result, err: submitErr}
		}()
	}
	started := time.Now()
	close(startRace)
	workers.Wait()
	close(results)
	raceElapsed := time.Since(started)
	acceptedCount := 0
	acceptedID := ""
	for outcome := range results {
		if outcome.err == nil && outcome.result.Status == "ACCEPTED" {
			acceptedCount++
			acceptedID = outcome.id
		}
	}
	if acceptedCount != 1 {
		t.Fatalf("duplicate-nullifier race committed %d claims, want exactly one", acceptedCount)
	}
	for _, id := range []string{claimA, claimB} {
		_, queryErr := contract.EvaluateTransaction("GetHealthClaimProof", id)
		if (queryErr == nil) != (id == acceptedID) {
			t.Fatalf("unexpected ledger presence for race claim %s: %v", id, queryErr)
		}
	}
	t.Logf("Z12_DUPLICATE_NULLIFIER_RACE submissions=2 accepted=%s committed_count=%d elapsed_ns=%d result=PASS", acceptedID, acceptedCount, raceElapsed.Nanoseconds())
}

func z12Summary(samples []int64) string {
	if len(samples) == 0 {
		return "N=0"
	}
	values := append([]int64(nil), samples...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	total := int64(0)
	for _, value := range values {
		total += value
	}
	median := values[len(values)/2]
	if len(values)%2 == 0 {
		median = (values[len(values)/2-1] + median) / 2
	}
	p95Index := int(math.Ceil(0.95*float64(len(values)))) - 1
	return fmt.Sprintf("N=%d mean=%d median=%d min=%d max=%d p95=%d p99=insufficient", len(values), total/int64(len(values)), median, values[0], values[len(values)-1], values[p95Index])
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
