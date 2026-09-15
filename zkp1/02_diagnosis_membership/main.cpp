#include <iostream>
#include <string>
#include <vector>

// Educational hash placeholder. It is deterministic but NOT cryptographically secure.
// A real Merkle circuit must use a ZKP-friendly cryptographic hash.
std::string hash_value(const std::string& value) {
    std::hash<std::string> h;
    return std::to_string(h(value));
}

// Build a tiny Merkle root from a list of leaf strings.
std::string merkle_root(std::vector<std::string> level) {
    if (level.empty()) return "";
    for (auto& item : level) item = hash_value(item);

    while (level.size() > 1) {
        std::vector<std::string> next;
        for (size_t i = 0; i < level.size(); i += 2) {
            // Duplicate the final node when the level has an odd number of nodes.
            const std::string& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(hash_value(level[i] + right));
        }
        level = next;
    }
    return level[0];
}

// Naive membership statement: "diagnosis is one of the covered diagnoses."
bool diagnosis_is_covered(const std::string& diagnosis,
                          const std::vector<std::string>& covered) {
    for (const auto& item : covered) {
        if (item == diagnosis) return true;
    }
    return false;
}

int main() {
    const std::vector<std::string> covered = {"diabetes", "asthma", "hypertension", "pneumonia"};
    const std::string root = merkle_root(covered);
    const std::string secret_diagnosis = "diabetes";

    std::cout << "Covered-set Merkle root (demo): " << root << '\n';
    std::cout << "Hidden diagnosis membership: "
              << (diagnosis_is_covered(secret_diagnosis, covered) ? "VALID" : "INVALID") << '\n';

    return 0;
}
