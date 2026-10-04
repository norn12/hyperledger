package gateway

import (
	"encoding/json"
	"testing"
)

type countClaimTransport struct{ calls int }

func (t *countClaimTransport) SubmitClaim(string) ([]byte, string, uint64, error) {
	t.calls++
	b, _ := json.Marshal(map[string]string{"claimId": "claim-1", "status": "ACCEPTED"})
	return b, "tx-1", 1, nil
}

func TestFailedLocalVerificationDoesNotCallFabricTransport(t *testing.T) {
	engine, err := NewGnarkHardenedEngine()
	if err != nil {
		t.Fatal(err)
	}
	verifier, req, w := makeGatewayFixture(t, engine)
	env, _, err := verifier.GenerateHealthClaimProof(req, w)
	if err != nil {
		t.Fatal(err)
	}
	env.Proof[0] ^= 1
	transport := &countClaimTransport{}
	if _, err = submitVerifiedHealthClaimProof(verifier, req, env, "claim-local-fail", "hospital", transport); err == nil {
		t.Fatal("invalid local proof accepted")
	}
	if transport.calls != 0 {
		t.Fatalf("Fabric transport called %d times after verification failure", transport.calls)
	}
}
