package zkp

import (
	"testing"
)

func TestZKPService(t *testing.T) {
	svc := &ZKPService{}
	if err := svc.Setup(); err != nil {
		t.Fatalf("Failed to setup ZKP service: %v", err)
	}

	// ============================================================
	// Age Range Circuit Tests (Positive & Negative)
	// ============================================================

	t.Run("Age 25 in [18, 120] - Valid", func(t *testing.T) {
		res, err := svc.ProveAgeRange(25, 18, 120)
		if err != nil || !res.IsValid {
			t.Fatalf("Expected valid proof for age 25, got err=%v valid=%v", err, res.IsValid)
		}
		t.Logf("✓ Age 25 valid proof: gen=%dms verify=%dms size=%dB", res.GenTimeMs, res.VerifyTimeMs, res.ProofSizeBytes)
	})

	t.Run("Age 18 in [18, 120] - Valid Boundary Min", func(t *testing.T) {
		res, err := svc.ProveAgeRange(18, 18, 120)
		if err != nil || !res.IsValid {
			t.Fatalf("Expected valid proof for age 18 (min boundary), got err=%v valid=%v", err, res.IsValid)
		}
	})

	t.Run("Age 120 in [18, 120] - Valid Boundary Max", func(t *testing.T) {
		res, err := svc.ProveAgeRange(120, 18, 120)
		if err != nil || !res.IsValid {
			t.Fatalf("Expected valid proof for age 120 (max boundary), got err=%v valid=%v", err, res.IsValid)
		}
	})

	t.Run("Age 17 in [18, 120] - Negative (Below Min)", func(t *testing.T) {
		_, err := svc.ProveAgeRange(17, 18, 120)
		if err == nil {
			t.Fatalf("Expected ZKP witness solver failure for age 17 (under 18), but proof succeeded")
		}
		t.Logf("✓ Correctly rejected age 17 under minimum threshold: %v", err)
	})

	t.Run("Age 121 in [18, 120] - Negative (Above Max)", func(t *testing.T) {
		_, err := svc.ProveAgeRange(121, 18, 120)
		if err == nil {
			t.Fatalf("Expected ZKP witness solver failure for age 121 (over 120), but proof succeeded")
		}
		t.Logf("✓ Correctly rejected age 121 over maximum threshold: %v", err)
	})

	// ============================================================
	// Diagnosis Category Circuit Tests (Positive & Negative)
	// ============================================================

	t.Run("Diagnosis 105 in [100, 200] - Valid", func(t *testing.T) {
		res, err := svc.ProveDiagnosisCategory(105, 100, 200)
		if err != nil || !res.IsValid {
			t.Fatalf("Expected valid proof for diagnosis code 105, got err=%v valid=%v", err, res.IsValid)
		}
	})

	t.Run("Diagnosis 99 in [100, 200] - Negative (Below Min)", func(t *testing.T) {
		_, err := svc.ProveDiagnosisCategory(99, 100, 200)
		if err == nil {
			t.Fatalf("Expected ZKP witness solver failure for diagnosis code 99, but proof succeeded")
		}
		t.Logf("✓ Correctly rejected diagnosis code 99: %v", err)
	})

	t.Run("Diagnosis 201 in [100, 200] - Negative (Above Max)", func(t *testing.T) {
		_, err := svc.ProveDiagnosisCategory(201, 100, 200)
		if err == nil {
			t.Fatalf("Expected ZKP witness solver failure for diagnosis code 201, but proof succeeded")
		}
		t.Logf("✓ Correctly rejected diagnosis code 201: %v", err)
	})
}
