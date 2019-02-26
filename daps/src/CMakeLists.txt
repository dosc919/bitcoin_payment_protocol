cmake_minimum_required(VERSION 3.8)
project(daps)

set(CMAKE_C_STANDARD 11)

set(HEADER_FILES daps.h data_structures.h const_and_error.h)

set(SOURCE_FILES daps.c)

find_package(OpenSSL)
pkg_search_module(OPENSSL REQUIRED openssl)

add_library(daps STATIC ${SOURCE_FILES} ${HEADER_FILES})

target_link_libraries(daps ${OPENSSL_LIBRARIES})