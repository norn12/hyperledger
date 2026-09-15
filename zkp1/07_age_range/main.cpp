#include <iostream>
#include "../record.h"

// Naive model of an age-range circuit.
// The actual ZKP would keep age inside the private witness.
bool age_is_eligible(int private_age, int policy_min_age, int policy_max_age) {
    return private_age >= policy_min_age && private_age <= policy_max_age;
}

int main() {
    // Policy bounds are public inputs in this educational example.
    const int policy_min_age = 18;
    const int policy_max_age = 65;
    const auto records = getTestRecords();

    for (const auto& record : records) {
        const bool valid = age_is_eligible(record.age, policy_min_age, policy_max_age);

        std::cout << record.recordId
                  << " | age=" << record.age
                  << " | age rule: " << (valid ? "VALID" : "INVALID") << '\n';
    }

    return 0;
}
