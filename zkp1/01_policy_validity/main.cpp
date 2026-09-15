#include <iostream>
#include "../record.h"

// Educational policy shared by all records in this demo.
struct Policy {
    int min_age;
    int max_age;
    long long max_claim_amount;
    int waiting_days;
};

// Check all policy rules against one shared claim record.
bool policy_validity(const ClaimRecord& record, const Policy& policy) {
    // Age rule.
    const bool age_ok = record.age >= policy.min_age && record.age <= policy.max_age;

    // Claim amount rule.
    const bool amount_ok = record.claimAmount <= policy.max_claim_amount;

    // For this naive playground, waiting-period checking is delegated to the
    // same date logic demonstrated in circuit 05. Here we keep the overall
    // circuit simple and use the treatment date/policy start as raw record data.
    // A real implementation would perform date arithmetic inside the circuit.
    const bool dates_present = !record.policyStartDate.empty() && !record.treatmentDate.empty();

    return age_ok && amount_ok && dates_present;
}

int main() {
    // The policy is public; claim records come from the central test dataset.
    const Policy policy{18, 65, 500000, 30};
    const auto records = getTestRecords();

    for (const auto& record : records) {
        const bool valid = policy_validity(record, policy);

        std::cout << record.recordId
                  << " | patient=" << record.patientId
                  << " | policy validity: "
                  << (valid ? "VALID" : "INVALID") << '\n';
    }

    return 0;
}
