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

# --- ZeroMQ Setup (macOS Robust) ---
# 1. Find the C++ Header (zmq.hpp) explicitly
find_path(CPPZMQ_INCLUDE_DIR
        NAMES zmq.hpp
        HINTS
        /opt/homebrew/include
        /usr/local/include
        /usr/include
        DOC "Path to zmq.hpp"
)

if(NOT CPPZMQ_INCLUDE_DIR)
    message(FATAL_ERROR "Could not find zmq.hpp. Run 'brew install cppzmq' on macOS or ensure it is installed.")
endif()

# 2. Find the C Library (libzmq)
find_library(ZMQ_LIBRARY
        NAMES zmq libzmq
        HINTS
        /opt/homebrew/lib
        /usr/local/lib
        /usr/lib
)

if(NOT ZMQ_LIBRARY)
    message(FATAL_ERROR "Could not find libzmq.")
endif()

message(STATUS "Found ZMQ Header: ${CPPZMQ_INCLUDE_DIR}")
message(STATUS "Found ZMQ Lib: ${ZMQ_LIBRARY}")

# --- Protobuf Setup ---
# Find protoc executable for manual generation
find_program(PROTOC_EXECUTABLE protoc REQUIRED)

# Use PkgConfig for the library links (handles Abseil deps)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PROTOBUF_PKG REQUIRED IMPORTED_TARGET protobuf)

# --- Subdirectories ---
add_subdirectory(protos)
add_subdirectory(src)