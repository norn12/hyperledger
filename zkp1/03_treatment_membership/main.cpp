#include <iostream>
#include <string>
#include <vector>
#include "../record.h"

// Simple deterministic demo hash. NOT suitable for cryptography or a real ZKP.
std::string hash_value(const std::string& value) {
    return std::to_string(std::hash<std::string>{}(value));
}

// Construct the root of a small binary Merkle tree.
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

// Naive membership check for the covered treatment set.
bool treatment_is_covered(const std::string& treatment,
                          const std::vector<std::string>& covered) {
    for (const auto& item : covered) {
        if (item == treatment) return true;
    }
    return false;
}

int main() {
    const std::vector<std::string> covered = {"T001", "T005", "T010", "T015"};
    const std::string root = merkle_root(covered);
    const auto records = getTestRecords();

    std::cout << "Covered-treatment Merkle root (demo): " << root << '\n';

    for (const auto& record : records) {
        const bool valid = treatment_is_covered(record.treatmentCode, covered);
        std::cout << record.recordId
                  << " | treatment=" << record.treatmentCode
                  << " | membership: " << (valid ? "VALID" : "INVALID") << '\n';
    }

    return 0;
}
