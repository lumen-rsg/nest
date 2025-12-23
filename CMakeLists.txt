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

# --- GUI Client (Nectar) Dependencies ---
include(FetchContent)

# GLFW (Windowing)
FetchContent_Declare(
        glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG        3.3.8
)
FetchContent_MakeAvailable(glfw)

# ImGui
FetchContent_Declare(
        imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.89.9
)
# This downloads the sources into ${imgui_SOURCE_DIR} but doesn't run their CMakeLists
FetchContent_GetProperties(imgui)
if(NOT imgui_POPULATED)
    FetchContent_Populate(imgui)
endif()

# --- Manually create a library from the fetched ImGui sources ---
# This is more reliable than relying on their build system.
file(GLOB IMGUI_SOURCES
        "${imgui_SOURCE_DIR}/imgui.cpp"
        "${imgui_SOURCE_DIR}/imgui_draw.cpp"
        "${imgui_SOURCE_DIR}/imgui_tables.cpp"
        "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
)
add_library(imgui_lib STATIC ${IMGUI_SOURCES})

# Make sure targets that link against us get the include path
target_include_directories(imgui_lib PUBLIC
        ${imgui_SOURCE_DIR}
)

# --- Subdirectories ---
add_subdirectory(protos)
add_subdirectory(src)