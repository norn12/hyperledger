package zkp

import (
	"testing"
)

func TestZKPService(t *testing.T) {
	svc := &ZKPService{}
	if err := svc.Setup(); err != nil {
		t.Fatalf("Failed to setup ZKP service: %v", err)
	}

	t.Run("ProveAgeRange - Valid Age (25 in [18, 120])", func(t *testing.T) {
		res, err := svc.ProveAgeRange(25, 18, 120)
		if err != nil {
			t.Fatalf("ProveAgeRange failed: %v", err)
		}
		if !res.IsValid {
			t.Errorf("Expected proof to be valid")
		}
		if res.ProofHash == "" {
			t.Errorf("Expected non-empty proof hash")
		}
		t.Logf("ZKP Proof Generated & Verified in %dms (gen: %dms, verify: %dms, size: %dB)",
			res.GenTimeMs+res.VerifyTimeMs, res.GenTimeMs, res.VerifyTimeMs, res.ProofSizeBytes)
	})

	t.Run("ProveDiagnosisCategory - Valid Diagnosis Code", func(t *testing.T) {
		res, err := svc.ProveDiagnosisCategory(105, 100, 200)
		if err != nil {
			t.Fatalf("ProveDiagnosisCategory failed: %v", err)
		}
		if !res.IsValid {
			t.Errorf("Expected proof to be valid")
		}
	})
}
