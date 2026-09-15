#include <iostream>
#include <string>
#include <functional>

// Small helper representing a hidden claim attribute in the naive model.
struct ClaimData {
    int age;
    std::string diagnosis;
    std::string treatment;
    long long amount;
};

// A deliberately simple policy evaluator that composes the other properties.
bool policy_validity(const ClaimData& claim,
                     int min_age,
                     int max_age,
                     long long max_amount,
                     const std::string& covered_diagnosis,
                     const std::string& covered_treatment) {
    // Check the age range rule.
    const bool age_ok = claim.age >= min_age && claim.age <= max_age;

    // Check the financial upper bound.
    const bool amount_ok = claim.amount <= max_amount;

    // Naively model membership using equality to one covered value.
    const bool diagnosis_ok = claim.diagnosis == covered_diagnosis;
    const bool treatment_ok = claim.treatment == covered_treatment;

    // The overall policy is valid only if every required condition passes.
    return age_ok && amount_ok && diagnosis_ok && treatment_ok;
}

int main() {
    ClaimData claim{34, "diabetes", "MRI", 180000};

    const bool valid = policy_validity(
        claim,
        18,
        65,
        500000,
        "diabetes",
        "MRI");

    std::cout << "Overall policy validity: " << (valid ? "VALID" : "INVALID") << '\n';
    return 0;
}
