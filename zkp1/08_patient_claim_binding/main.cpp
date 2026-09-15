#include <iostream>
#include <string>
#include <functional>
#include "../record.h"

// Educational binding function. It models the idea of committing to context.
// std::hash is NOT cryptographically secure and must never be used for production.
std::string bind_context(const std::string& patient_commitment,
                         const std::string& policy_id,
                         const std::string& claim_id,
                         const std::string& nonce) {
    // Delimit fields so the conceptual tuple has an unambiguous structure.
    const std::string message = patient_commitment + "|" + policy_id + "|" + claim_id + "|" + nonce;
    return std::to_string(std::hash<std::string>{}(message));
}

int main() {
    const auto records = getTestRecords();

    for (const auto& record : records) {
        const std::string binding = bind_context(record.patientCommitment,
                                                  record.policyId,
                                                  record.recordId,
                                                  record.nonce);

        std::cout << record.recordId
                  << " | bound context: " << binding
                  << " | same context reproduces binding: "
                  << (binding == bind_context(record.patientCommitment,
                                              record.policyId,
                                              record.recordId,
                                              record.nonce) ? "YES" : "NO")
                  << '\n';
    }

    return 0;
}
