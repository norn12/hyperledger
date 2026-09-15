#include <iostream>
#include <set>
#include <string>
#include "../record.h"

// The medical history is represented as a set of condition identifiers.
// In a real design, the set would be committed/authenticated rather than exposed.
bool history_satisfies_policy(const std::set<std::string>& private_history,
                              const std::string& excluded_condition) {
    return private_history.find(excluded_condition) == private_history.end();
}

int main() {
    // Example policy property: a specific excluded condition must not exist.
    const std::string excluded_condition = "HEART_FAILURE";
    const auto records = getTestRecords();

    for (const auto& record : records) {
        const std::set<std::string> history(record.medicalHistory.begin(),
                                             record.medicalHistory.end());
        const bool valid = history_satisfies_policy(history, excluded_condition);

        std::cout << record.recordId
                  << " | medical-history rule: "
                  << (valid ? "VALID" : "INVALID") << '\n';
    }

    return 0;
}
