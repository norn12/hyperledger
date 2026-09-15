#include <ctime>
#include <iostream>
#include <string>
#include "../record.h"

// Convert a YYYY-MM-DD date into a day count using the C++ standard library.
// This is a teaching implementation, not a circuit-friendly date representation.
std::time_t parse_date(const std::string& date) {
    std::tm tm{};
    tm.tm_year = std::stoi(date.substr(0, 4)) - 1900;
    tm.tm_mon  = std::stoi(date.substr(5, 2)) - 1;
    tm.tm_mday = std::stoi(date.substr(8, 2));
    tm.tm_hour = 12;
    return std::mktime(&tm);
}

// Treatment must occur at least waiting_days after policy start.
bool waiting_period_satisfied(const std::string& policy_start,
                              const std::string& treatment_date,
                              int waiting_days) {
    const double seconds = std::difftime(parse_date(treatment_date), parse_date(policy_start));
    const long long elapsed_days = static_cast<long long>(seconds / (60 * 60 * 24));
    return elapsed_days >= waiting_days;
}

int main() {
    const int policy_waiting_days = 30;
    const auto records = getTestRecords();

    for (const auto& record : records) {
        const bool valid = waiting_period_satisfied(record.policyStartDate,
                                                    record.treatmentDate,
                                                    policy_waiting_days);
        std::cout << record.recordId
                  << " | " << record.policyStartDate << " -> " << record.treatmentDate
                  << " | waiting period: " << (valid ? "VALID" : "INVALID") << '\n';
    }

    return 0;
}
