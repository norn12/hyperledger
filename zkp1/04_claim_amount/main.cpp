#include <iostream>
#include "../record.h"

// Naive model of a confidential amount-range statement.
// A real ZKP would keep claimAmount private inside the witness.
bool amount_is_allowed(long long claim_amount,
                       long long minimum_allowed,
                       long long maximum_allowed) {
    return claim_amount >= minimum_allowed && claim_amount <= maximum_allowed;
}

int main() {
    const long long policy_minimum = 0;
    const long long policy_maximum = 500000;
    const auto records = getTestRecords();

    for (const auto& record : records) {
        const bool valid = amount_is_allowed(record.claimAmount,
                                              policy_minimum,
                                              policy_maximum);
        std::cout << record.recordId
                  << " | claim amount=" << record.claimAmount
                  << " | amount rule: " << (valid ? "VALID" : "INVALID") << '\n';
    }

    return 0;
}
