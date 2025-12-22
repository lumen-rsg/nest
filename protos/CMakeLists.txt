# Find the compiler explicitly
find_program(PROTOC_EXECUTABLE protoc REQUIRED)

# Define inputs and expected outputs
set(PROTO_FILE "${CMAKE_CURRENT_SOURCE_DIR}/venom.proto")
set(PROTO_SRC "${CMAKE_CURRENT_BINARY_DIR}/venom.pb.cc")
set(PROTO_HDR "${CMAKE_CURRENT_BINARY_DIR}/venom.pb.h")

# Manually run protoc
# This avoids the "target pattern" Make error by being explicit
add_custom_command(
        OUTPUT ${PROTO_SRC} ${PROTO_HDR}
        COMMAND ${PROTOC_EXECUTABLE}
        ARGS --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
        --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
        ${PROTO_FILE}
        DEPENDS ${PROTO_FILE}
        COMMENT "Compiling venom.proto to C++"
        VERBATIM
)

# Create the library
add_library(nest_proto STATIC ${PROTO_SRC} ${PROTO_HDR})

# Include paths
target_include_directories(nest_proto PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link using PkgConfig (same as before)
target_link_libraries(nest_proto PUBLIC PkgConfig::PROTOBUF_PKG)

# C++ Standard
target_compile_features(nest_proto PUBLIC cxx_std_23)