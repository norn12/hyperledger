#include <ctime>
#include <iostream>
#include <string>

// Convert a YYYY-MM-DD date into a day count using the C++ standard library.
// This is a teaching implementation, not a circuit-friendly date representation.
std::time_t parse_date(const std::string& date) {
    std::tm tm{};
    tm.tm_year = std::stoi(date.substr(0, 4)) - 1900;
    tm.tm_mon  = std::stoi(date.substr(5, 2)) - 1;
    tm.tm_mday = std::stoi(date.substr(8, 2));
    tm.tm_hour = 12; // Reduce daylight-saving boundary surprises in local time.
    return std::mktime(&tm);
}

// Naive statement: treatment date is at least waiting_days after policy start.
bool waiting_period_satisfied(const std::string& policy_start,
                              const std::string& treatment_date,
                              int waiting_days) {
    const double seconds = std::difftime(parse_date(treatment_date), parse_date(policy_start));
    const long long elapsed_days = static_cast<long long>(seconds / (60 * 60 * 24));
    return elapsed_days >= waiting_days;
}

int main() {
    std::cout << "Waiting-period rule: "
              << (waiting_period_satisfied("2026-01-01", "2026-02-15", 30)
                      ? "VALID" : "INVALID") << '\n';
    return 0;
}
