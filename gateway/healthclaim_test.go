package gateway

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	cryptoed "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	hc "zerotrust/healthclaimhardened"
)

func zbi(v int64) *big.Int { return big.NewInt(v) }
func makeGatewayFixture(t testing.TB, engine hardenedProofEngine) (*HealthClaimGateway, ClaimRequest, *HealthClaimWitness) {
	t.Helper()
	key, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x31}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	w := &HealthClaimWitness{Diagnosis: zbi(41), LabValue: zbi(6), PolicyID: zbi(12), CoverageCeiling: zbi(1000), PatientSecret: zbi(999), LabMin: zbi(3), LabMax: zbi(8), PolicyMaxClaim: zbi(1200), CoveredDiagnosis: [4]*big.Int{zbi(41), zbi(9), zbi(77), zbi(103)}}
	for i := range w.MerkleSiblings {
		w.MerkleSiblings[i] = zbi(int64(500 + i))
		w.MerkleDirections[i] = zbi(0)
	}
	leaf := hc.RecordLeaf(w.Diagnosis, w.LabValue, w.PolicyID, w.CoverageCeiling, hc.SecretCommitment(w.PatientSecret))
	path := pathFrom(w)
	root := hc.RootFromPath(leaf, path)
	policy := hc.PolicyDigest(w.PolicyID, w.LabMin, w.LabMax, w.PolicyMaxClaim, w.CoveredDiagnosis)
	sig, err := hc.SignLeaf(key, leaf)
	if err != nil {
		t.Fatal(err)
	}
	w.Signature = sig
	var x, y big.Int
	key.PublicKey.A.X.BigInt(&x)
	key.PublicKey.A.Y.BigInt(&y)
	regs := NewMemoryRegistries()
	regs.RegisterAuthority("hospital", &x, &y)
	regs.RegisterRoot("devnet", zbi(5), root)
	regs.RegisterPolicy("devnet", zbi(3), policy)
	regs.RegisterRecipient("insurer", zbi(12))
	regs.RegisterDeployment("devnet", zbi(9))
	store := NewMemoryChallengeStore()
	gw := NewHealthClaimGateway(regs, regs, regs, regs, store, NewMemoryUsedNullifiers(), engine)
	gw.ChallengeLifetime = time.Minute
	challenge, err := gw.IssueChallenge("insurer", "devnet")
	if err != nil {
		t.Fatal(err)
	}
	req := ClaimRequest{AuthorityID: "hospital", RootVersion: "5", PolicyVersion: "3", ClaimAmount: "900", Challenge: challenge, Recipient: "insurer", Deployment: "devnet"}
	return gw, req, w
}

func BenchmarkGatewayLocalZKPProcessing(b *testing.B) {
	engine, err := NewGnarkHardenedEngine()
	if err != nil {
		b.Fatal(err)
	}
	gw, req, witness := makeGatewayFixture(b, engine)
	b.ResetTimer()
	var witnessNS, proveNS, verifyNS, totalNS int64
	for i := 0; i < b.N; i++ {
		challenge, err := gw.IssueChallenge("insurer", "devnet")
		if err != nil {
			b.Fatal(err)
		}
		req.Challenge = challenge
		gw.nullifiers = NewMemoryUsedNullifiers()
		_, result, err := gw.GenerateHealthClaimProof(req, witness)
		if err != nil {
			b.Fatal(err)
		}
		witnessNS += int64(result.WitnessConstruction)
		proveNS += int64(result.ProofGeneration)
		verifyNS += int64(result.LocalVerification)
		totalNS += int64(result.TotalProcessing)
	}
	b.ReportMetric(float64(witnessNS)/float64(b.N), "witness-ns/op")
	b.ReportMetric(float64(proveNS)/float64(b.N), "prove-ns/op")
	b.ReportMetric(float64(verifyNS)/float64(b.N), "local-verify-ns/op")
	b.ReportMetric(float64(totalNS)/float64(b.N), "gateway-total-ns/op")
}

func TestHealthClaimGatewayValidProofAndPrivateSerialization(t *testing.T) {
	domain, err := ProtocolFieldValue(HealthClaimProtocolIdentifier)
	if err != nil || domain.Cmp(zbi(hc.ProtocolDomainID)) != 0 {
		t.Fatal("protocol identifier mapping is not the frozen Z7 domain")
	}
	if _, err := ProtocolFieldValue("arbitrary-domain"); err == nil {
		t.Fatal("arbitrary protocol identifier accepted")
	}
	engine, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	gw, req, w := makeGatewayFixture(t, engine)
	env, result, err := gw.GenerateHealthClaimProof(req, w)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatal("valid claim result marked invalid")
	}
	verified, err := gw.VerifyHealthClaimProof(req, env)
	if err != nil || !verified.Valid {
		t.Fatalf("proof verify failed: %v", err)
	}
	badHash := env
	badHash.ProofHash = "00"
	if _, err = gw.VerifyHealthClaimProof(req, badHash); err == nil {
		t.Fatal("invalid proof identifier accepted")
	}
	if _, _, err = gw.GenerateHealthClaimProof(req, w); err == nil {
		t.Fatal("consumed challenge was reused")
	}
	pub, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pub, []byte("patientSecret")) || bytes.Contains(pub, []byte("diagnosis")) || bytes.Contains(pub, []byte("labValue")) || bytes.Contains(pub, []byte("coverageCeiling")) || bytes.Contains(pub, []byte("signature")) {
		t.Fatalf("public envelope leaked private witness key: %s", pub)
	}
	if _, err = json.Marshal(w); err == nil {
		t.Fatal("private witness unexpectedly serializable")
	}
}

type failVerificationEngine struct{ hardenedProofEngine }

func (f failVerificationEngine) Prove(a *hc.HealthClaimHardened) ([]byte, error) {
	return []byte("generated"), nil
}
func (f failVerificationEngine) Verify([]byte, PublicStatement) error {
	return errIntentionalVerificationFailure{}
}

type errIntentionalVerificationFailure struct{}

func (errIntentionalVerificationFailure) Error() string { return "intentional verify rejection" }

func TestGatewayRejectsEveryMutatedPublicInput(t *testing.T) {
	engine, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	g, r, w := makeGatewayFixture(t, engine)
	env, _, err := g.GenerateHealthClaimProof(r, w)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*PublicStatement){
		"RegistryRoot": func(s *PublicStatement) { s.RegistryRoot = "1" }, "RootVersion": func(s *PublicStatement) { s.RootVersion = "6" }, "PolicyCommitment": func(s *PublicStatement) { s.PolicyCommitment = "1" }, "PolicyVersion": func(s *PublicStatement) { s.PolicyVersion = "4" }, "ClaimAmount": func(s *PublicStatement) { s.ClaimAmount = "901" }, "AuthorityKeyX": func(s *PublicStatement) { s.AuthorityKeyX = "1" }, "AuthorityKeyY": func(s *PublicStatement) { s.AuthorityKeyY = "1" }, "Nullifier": func(s *PublicStatement) { s.Nullifier = "1" }, "ProtocolDomain": func(s *PublicStatement) { s.ProtocolDomain = "7" }, "Challenge": func(s *PublicStatement) { s.Challenge = "8" }, "RecipientID": func(s *PublicStatement) { s.RecipientID = "9" }, "DeploymentID": func(s *PublicStatement) { s.DeploymentID = "10" }, "ContextCommitment": func(s *PublicStatement) { s.ContextCommitment = "11" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := env
			mutate(&copy.PublicStatement)
			if _, e := g.VerifyHealthClaimProof(r, copy); e == nil {
				t.Fatalf("mutated %s accepted", name)
			}
		})
	}
}

func TestGatewayRejectsUsedNullifier(t *testing.T) {
	engine, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	g, r, w := makeGatewayFixture(t, engine)
	nul := hc.RecordNullifier(w.PatientSecret, hc.IndexFromDirections(pathFrom(w)))
	if err = g.nullifiers.MarkNullifierUsed(nul); err != nil {
		t.Fatal(err)
	}
	_, _, err = g.GenerateHealthClaimProof(r, w)
	if err == nil {
		t.Fatal("used nullifier accepted")
	}
}

func TestGatewayRejectsInvalidClaimAndTrustedCommitmentMismatch(t *testing.T) {
	engine, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("claim exceeds ceiling", func(t *testing.T) {
		g, r, w := makeGatewayFixture(t, engine)
		r.ClaimAmount = "1001"
		_, _, e := g.GenerateHealthClaimProof(r, w)
		if e == nil {
			t.Fatal("invalid claim accepted")
		}
	})
	t.Run("private policy does not match anchor", func(t *testing.T) {
		g, r, w := makeGatewayFixture(t, engine)
		w.PolicyMaxClaim = zbi(1199)
		_, _, e := g.GenerateHealthClaimProof(r, w)
		if e == nil {
			t.Fatal("policy mismatch accepted")
		}
	})
	t.Run("known root value mismatch", func(t *testing.T) {
		g, r, w := makeGatewayFixture(t, engine)
		w.MerkleSiblings[0] = zbi(9999)
		_, _, e := g.GenerateHealthClaimProof(r, w)
		if e == nil {
			t.Fatal("root mismatch accepted")
		}
	})
}

func TestHealthClaimGatewayAdversarialPreflightAndFailClosed(t *testing.T) {
	// Preflight failures are expected to occur before Groth16 proving.
	base, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*HealthClaimGateway, *ClaimRequest, *HealthClaimWitness)
	}{
		{"missing witness", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) {}},
		{"unregistered authority", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { r.AuthorityID = "other" }},
		{"untrusted root", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { r.RootVersion = "88" }},
		{"untrusted policy", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { r.PolicyVersion = "88" }},
		{"invalid claim amount", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { r.ClaimAmount = "not-a-number" }},
		{"invalid signature", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { w.Signature = []byte{1} }},
		{"invalid Merkle witness", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { w.MerkleSiblings[0] = zbi(7000) }},
		{"wrong challenge", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { r.Challenge = "777" }},
		{"wrong recipient", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { r.Recipient = "unknown" }},
		{"wrong deployment", func(g *HealthClaimGateway, r *ClaimRequest, w *HealthClaimWitness) { r.Deployment = "unknown" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, r, w := makeGatewayFixture(t, base)
			tc.mutate(g, &r, w)
			if tc.name == "missing witness" {
				w = nil
			}
			_, _, e := g.GenerateHealthClaimProof(r, w)
			if e == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	t.Run("local verification failure stops result", func(t *testing.T) {
		underlying, err := NewGnarkHardenedEngine()
		if err != nil {
			t.Fatal(err)
		}
		g, r, w := makeGatewayFixture(t, failVerificationEngine{underlying})
		_, _, err = g.GenerateHealthClaimProof(r, w)
		if err == nil {
			t.Fatal("expected locally rejected proof")
		}
	})
	t.Run("registered but wrong authority key", func(t *testing.T) {
		g, r, w := makeGatewayFixture(t, base)
		wrong, err := cryptoed.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x64}, 32)))
		if err != nil {
			t.Fatal(err)
		}
		var x, y big.Int
		wrong.PublicKey.A.X.BigInt(&x)
		wrong.PublicKey.A.Y.BigInt(&y)
		if err = g.authorities.(*MemoryRegistries).RegisterAuthority("hospital", &x, &y); err != nil {
			t.Fatal(err)
		}
		if _, _, err = g.GenerateHealthClaimProof(r, w); err == nil {
			t.Fatal("signature by unregistered key accepted")
		}
	})
}
