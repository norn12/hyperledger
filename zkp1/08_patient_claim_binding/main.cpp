#include <iostream>
#include <string>
#include <functional>
#include <sstream>

// Educational binding function. It models the idea of a commitment to context.
// std::hash is NOT cryptographically secure and must never be used for production ZKP binding.
std::string bind_context(const std::string& patient_commitment,
                         const std::string& policy_id,
                         const std::string& claim_id,
                         const std::string& nonce) {
    // Delimit fields so the conceptual tuple has an unambiguous structure.
    const std::string message = patient_commitment + "|" + policy_id + "|" + claim_id + "|" + nonce;
    return std::to_string(std::hash<std::string>{}(message));
}

int main() {
    const std::string patient = "patient-commitment-demo";
    const std::string policy = "P001";
    const std::string claim = "C001";
    const std::string nonce = "847291";

    const std::string binding = bind_context(patient, policy, claim, nonce);

    std::cout << "Bound context: " << binding << '\n';
    std::cout << "Same context reproduces binding: "
              << (binding == bind_context(patient, policy, claim, nonce) ? "YES" : "NO") << '\n';
    std::cout << "Changing claim changes binding: "
              << (binding != bind_context(patient, policy, "C002", nonce) ? "YES" : "NO") << '\n';
    return 0;
}
