#include <iostream>
#include <set>
#include <string>

// The medical history is represented as a set of condition identifiers.
// In a real design, the set would be committed/authenticated rather than exposed.

// Example policy property: a specific excluded pre-existing condition must not exist.
bool history_satisfies_policy(const std::set<std::string>& private_history,
                              const std::string& excluded_condition) {
    // Return true only when the excluded condition is absent.
    return private_history.find(excluded_condition) == private_history.end();
}

int main() {
    // This set is "private" only conceptually; naive C++ can see it directly.
    const std::set<std::string> history = {"asthma", "fracture"};
    const std::string excluded_condition = "heart_failure";

    std::cout << "Medical-history property: "
              << (history_satisfies_policy(history, excluded_condition)
                      ? "VALID" : "INVALID") << '\n';
    return 0;
}
