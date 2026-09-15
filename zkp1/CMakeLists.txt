cmake_minimum_required(VERSION 3.16)
project(zkp1_experiment LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Shared test-record implementation used by every circuit demo.
set(RECORD_SOURCE record.cpp)

add_executable(policy_validity 01_policy_validity/main.cpp ${RECORD_SOURCE})
add_executable(diagnosis_membership 02_diagnosis_membership/main.cpp ${RECORD_SOURCE})
add_executable(treatment_membership 03_treatment_membership/main.cpp ${RECORD_SOURCE})
add_executable(claim_amount 04_claim_amount/main.cpp ${RECORD_SOURCE})
add_executable(waiting_period 05_waiting_period/main.cpp ${RECORD_SOURCE})
add_executable(medical_history 06_medical_history/main.cpp ${RECORD_SOURCE})
add_executable(age_range 07_age_range/main.cpp ${RECORD_SOURCE})
add_executable(patient_claim_binding 08_patient_claim_binding/main.cpp ${RECORD_SOURCE})
