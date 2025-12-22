cmake_minimum_required(VERSION 3.25)
project(nest VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -Wpedantic)

# --- Dependencies ---
find_package(OpenSSL 3.0 REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Threads REQUIRED)

# 1. ZeroMQ (PkgConfig)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZMQ REQUIRED IMPORTED_TARGET libzmq)

# 2. Protobuf (Hybrid)
# A) Use standard Module mode to get 'protobuf_generate_cpp' and 'protoc'
#    (We explicitly DISABLE Config mode here to avoid the target conflict error)
find_package(Protobuf REQUIRED MODULE)

# B) Use PkgConfig to get the actual Link Libraries (includes Abseil deps automatically)
pkg_check_modules(PROTOBUF_PKG REQUIRED IMPORTED_TARGET protobuf)

# --- Subdirectories ---
add_subdirectory(protos)
add_subdirectory(src)