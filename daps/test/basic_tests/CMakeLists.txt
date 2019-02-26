
include_directories(${gtest_SOURCE_DIR}/includes ${gtest_SOURCE_DIR})

add_executable(runBasicDapsTests key_gen_checks.cpp signature_checks.cpp extraction_checks.cpp speed_test.cpp)

target_link_libraries(runBasicDapsTests gtest gtest_main)
target_link_libraries(runBasicDapsTests daps)