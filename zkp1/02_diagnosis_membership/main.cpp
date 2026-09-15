#include <iostream>
#include <string>
#include <vector>
#include "../record.h"

// Educational hash placeholder. It is deterministic but NOT cryptographically secure.
// A real Merkle circuit must use a ZKP-friendly cryptographic hash.
std::string hash_value(const std::string& value) {
    return std::to_string(std::hash<std::string>{}(value));
}

// Build a tiny Merkle root from the insurer's covered diagnosis set.
std::string merkle_root(std::vector<std::string> level) {
    if (level.empty()) return "";
    for (auto& item : level) item = hash_value(item);

    while (level.size() > 1) {
        std::vector<std::string> next;
        for (size_t i = 0; i < level.size(); i += 2) {
            const std::string& right = (i + 1 < level.size()) ? level[i + 1] : level[i];
            next.push_back(hash_value(level[i] + right));
        }
        level = next;
    }
    return level[0];
}

// Naive membership statement: diagnosis is one of the covered diagnoses.
bool diagnosis_is_covered(const std::string& diagnosis,
                          const std::vector<std::string>& covered) {
    for (const auto& item : covered) {
        if (item == diagnosis) return true;
    }
    return false;
}

int main() {
    const std::vector<std::string> covered = {"D001", "D005", "D010", "D015"};
    const std::string root = merkle_root(covered);
    const auto records = getTestRecords();

    std::cout << "Covered-set Merkle root (demo): " << root << '\n';

    for (const auto& record : records) {
        const bool valid = diagnosis_is_covered(record.diagnosisCode, covered);
        std::cout << record.recordId
                  << " | diagnosis=" << record.diagnosisCode
                  << " | membership: " << (valid ? "VALID" : "INVALID") << '\n';
    }

    return 0;
}
