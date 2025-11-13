cmake_minimum_required(VERSION 3.10)
project(ESSDSS CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

# -----------------------------
# RELIC and OpenSSL setup
# -----------------------------
# Try to locate RELIC (adjust if installed elsewhere)
find_path(RELIC_INCLUDE_DIR relic.h PATHS /usr/local/include/relic /usr/include)
find_library(RELIC_LIB NAMES relic_s relic PATHS /usr/local/lib /usr/lib)

find_package(OpenSSL REQUIRED)

if(NOT RELIC_INCLUDE_DIR OR NOT RELIC_LIB)
    message(FATAL_ERROR "RELIC not found! Please install it or set RELIC_INCLUDE_DIR and RELIC_LIB manually.")
endif()

message(STATUS "Found RELIC include dir: ${RELIC_INCLUDE_DIR}")
message(STATUS "Found RELIC library: ${RELIC_LIB}")
message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")

# -----------------------------
# Include directories
# -----------------------------
include_directories(
    ${CMAKE_SOURCE_DIR}/lib
    ${RELIC_INCLUDE_DIR}
)

# -----------------------------
# Shared static library
# -----------------------------
add_library(ps_core STATIC
    lib/ps_crypto.cpp
    lib/ta.cpp
    lib/sp.cpp
    lib/vehicle.cpp
    lib/edge.cpp
)

target_link_libraries(ps_core PUBLIC ${RELIC_LIB} gmp OpenSSL::Crypto)

# -----------------------------
# Executables
# -----------------------------
add_executable(ps_demo demo/main.cpp)
target_link_libraries(ps_demo PRIVATE ps_core)

add_executable(ta_demo demo/ta_demo.cpp)
target_link_libraries(ta_demo PRIVATE ps_core)

add_executable(sp_demo demo/sp_demo.cpp)
target_link_libraries(sp_demo PRIVATE ps_core)

add_executable(edge_demo demo/edge_demo.cpp)
target_link_libraries(edge_demo PRIVATE ps_core)

add_executable(vehicle_demo demo/vehicle_demo.cpp)
target_link_libraries(vehicle_demo PRIVATE ps_core)

# -----------------------------
# Output organization
# -----------------------------
# Put all executables into ./bin folder inside build/
set_target_properties(ps_demo ta_demo sp_demo edge_demo vehicle_demo
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Optional: Also put the static library in ./lib inside build/
set_target_properties(ps_core PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

message(STATUS "Build setup complete! Run 'make' and find executables under build/bin/")


# cmake_minimum_required(VERSION 3.10)
# project(ps_demo CXX)

# set(RELIC_INCLUDE_DIR "/usr/local/include/relic")
# set(RELIC_LIB "/usr/local/lib/librelic_s.a")
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_BUILD_TYPE Debug)

# include_directories(${CMAKE_SOURCE_DIR}/lib)   # <-- Add this line

# # Add your source files
# add_executable(ps_demo
#     demo/main.cpp
#     lib/ps_crypto.cpp
#     lib/ta.cpp
#     lib/sp.cpp
#     lib/vehicle.cpp
#     lib/edge.cpp
# )

# # Find RELIC (if installed globally)
# find_path(RELIC_INCLUDE_DIR relic.h)
# find_library(RELIC_LIB relic)

# if(NOT RELIC_INCLUDE_DIR OR NOT RELIC_LIB)
#     message(FATAL_ERROR "RELIC not found. Please set RELIC_INCLUDE_DIR and RELIC_LIB manually.")
# endif()

# target_include_directories(ps_demo PRIVATE ${RELIC_INCLUDE_DIR})
# # target_link_libraries(ps_demo PRIVATE ${RELIC_LIB} gmp)
# find_package(OpenSSL REQUIRED)
# target_link_libraries(ps_demo PRIVATE ${RELIC_LIB} gmp OpenSSL::Crypto)

# add_executable(ta_demo
#     demo/ta_demo.cpp
#     lib/ps_crypto.cpp
#     lib/ta.cpp
# )

# #Find RELIC (if installed globally)
# find_path(RELIC_INCLUDE_DIR relic.h)
# find_library(RELIC_LIB relic)

# if(NOT RELIC_INCLUDE_DIR OR NOT RELIC_LIB)
#     message(FATAL_ERROR "RELIC not found. Please set RELIC_INCLUDE_DIR and RELIC_LIB manually.")
# endif()

# target_include_directories(ps_demo PRIVATE ${RELIC_INCLUDE_DIR})
# # target_link_libraries(ps_demo PRIVATE ${RELIC_LIB} gmp)
# find_package(OpenSSL REQUIRED)
# target_link_libraries(ps_demo PRIVATE ${RELIC_LIB} gmp OpenSSL::Crypto)
# add_executable(sp_demo
#     demo/sp_demo.cpp
#     lib/ps_crypto.cpp
#     lib/sp.cpp
# )

# add_executable(edge_demo
#     demo/edge_demo.cpp
#     lib/ps_crypto.cpp
#     lib/edge.cpp
# )
# # Find RELIC (if installed globally)
# find_path(RELIC_INCLUDE_DIR relic.h)
# find_library(RELIC_LIB relic)

# if(NOT RELIC_INCLUDE_DIR OR NOT RELIC_LIB)
#     message(FATAL_ERROR "RELIC not found. Please set RELIC_INCLUDE_DIR and RELIC_LIB manually.")
# endif()

# target_include_directories(ps_demo PRIVATE ${RELIC_INCLUDE_DIR})
# # target_link_libraries(ps_demo PRIVATE ${RELIC_LIB} gmp)
# find_package(OpenSSL REQUIRED)
# target_link_libraries(ps_demo PRIVATE ${RELIC_LIB} gmp OpenSSL::Crypto)

# add_executable(vehicle_demo
#     demo/vehicle_demo.cpp
#     lib/ps_crypto.cpp
#     lib/vehicle.cpp
# )
# # Find RELIC (if installed globally)
# find_path(RELIC_INCLUDE_DIR relic.h)
# find_library(RELIC_LIB relic)

# if(NOT RELIC_INCLUDE_DIR OR NOT RELIC_LIB)
#     message(FATAL_ERROR "RELIC not found. Please set RELIC_INCLUDE_DIR and RELIC_LIB manually.")
# endif()

# target_include_directories(ps_demo PRIVATE ${RELIC_INCLUDE_DIR})
# # target_link_libraries(ps_demo PRIVATE ${RELIC_LIB} gmp)
# find_package(OpenSSL REQUIRED)
# target_link_libraries(ps_demo PRIVATE ${RELIC_LIB} gmp OpenSSL::Crypto)