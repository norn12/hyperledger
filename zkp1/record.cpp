#include "record.h"

// Central test dataset for the complete zkp1 playground.
//
// ADD A NEW TEST RECORD HERE instead of editing eight different programs.
// Every circuit can select the same record and test its own rule against it.
//
// These values are intentionally fictional/demo data.
std::vector<ClaimRecord> getTestRecords() {
    return {
        {
            "CLM-001", "PAT-001", "POL-HEALTH-001",
            25,
            "D001",                    // Covered diagnosis example
            "T001",                    // Covered treatment example
            50000,
            "2026-01-01",              // Policy start
            "2026-03-15",              // Treatment date
            {"ASTHMA"},                // Medical history
            "PATIENT-COMMITMENT-001",
            "NONCE-001"
        },
        {
            "CLM-002", "PAT-002", "POL-HEALTH-001",
            17,
            "D099",                    // Not covered in the demo set
            "T099",                    // Not covered in the demo set
            50000,
            "2026-01-01",
            "2026-01-10",
            {"DIABETES"},
            "PATIENT-COMMITMENT-002",
            "NONCE-002"
        },
        {
            "CLM-003", "PAT-003", "POL-HEALTH-001",
            45,
            "D005",
            "T005",
            150000,
            "2026-01-01",
            "2026-02-20",
            {"HYPERTENSION", "DIABETES"},
            "PATIENT-COMMITMENT-003",
            "NONCE-003"
        }
    };
}
