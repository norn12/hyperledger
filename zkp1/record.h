#ifndef ZKP1_RECORD_H
#define ZKP1_RECORD_H

#include <string>
#include <vector>

// One shared claim record used by all eight educational ZKP1 circuits.
// The fields are deliberately simple so a beginner can see how one patient
// claim flows through each circuit independently.
struct ClaimRecord {
    std::string recordId;
    std::string patientId;
    std::string policyId;
    int age;
    std::string diagnosisCode;
    std::string treatmentCode;
    int claimAmount;
    std::string policyStartDate;
    std::string treatmentDate;
    std::vector<std::string> medicalHistory;
    std::string patientCommitment;
    std::string nonce;
};

// Return all sample records used by the eight demos.
std::vector<ClaimRecord> getTestRecords();

#endif // ZKP1_RECORD_H
