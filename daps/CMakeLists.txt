cmake_minimum_required(VERSION 3.8)
project(DAPS)

set(CMAKE_C_STANDARD 11)

include_directories(src)

add_subdirectory(src)
add_subdirectory(test)
