#include <iostream>

// Naive model of a confidential amount-range statement.
// A real ZKP would keep claim_amount private inside the witness.
bool amount_is_allowed(long long claim_amount,
                       long long minimum_allowed,
                       long long maximum_allowed) {
    // Check both policy boundaries.
    return claim_amount >= minimum_allowed && claim_amount <= maximum_allowed;
}

int main() {
    const long long private_claim_amount = 180000;
    const long long policy_minimum = 0;
    const long long policy_maximum = 500000;

    std::cout << "Claim amount rule: "
              << (amount_is_allowed(private_claim_amount, policy_minimum, policy_maximum)
                      ? "VALID" : "INVALID") << '\n';
    return 0;
}
