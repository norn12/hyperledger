#include <iostream>

// Naive model of an age-range circuit.
// The actual ZKP would keep age inside the private witness.
bool age_is_eligible(int private_age, int policy_min_age, int policy_max_age) {
    // Both inequalities are required by the policy.
    return private_age >= policy_min_age && private_age <= policy_max_age;
}

int main() {
    const int private_age = 34;
    const int policy_min_age = 18;
    const int policy_max_age = 65;

    std::cout << "Age rule: "
              << (age_is_eligible(private_age, policy_min_age, policy_max_age)
                      ? "VALID" : "INVALID") << '\n';
    return 0;
}
