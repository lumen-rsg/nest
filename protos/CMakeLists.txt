set(PROTO_FILES venom.proto)

# This comes from find_package(Protobuf MODULE)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})

add_library(nest_proto STATIC ${PROTO_SRCS} ${PROTO_HDRS})

target_include_directories(nest_proto PUBLIC
        ${CMAKE_CURRENT_BINARY_DIR}
        ${Protobuf_INCLUDE_DIRS} # From Module mode
)

# LINK FIX: Use PkgConfig target which has all the -labsl_... flags
target_link_libraries(nest_proto PUBLIC PkgConfig::PROTOBUF_PKG)

target_compile_features(nest_proto PUBLIC cxx_std_23)