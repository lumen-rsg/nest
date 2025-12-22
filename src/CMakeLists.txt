# --- Nest Daemon Executable ---
add_executable(nestd
        daemon/main.cpp
        daemon/beacon.hpp
        daemon/beacon.cpp
        common/crypto.hpp
        common/crypto.cpp
        common/db.hpp
        common/db.cpp
        daemon/router.hpp
        daemon/router.cpp
        # Add other sources here as we build them:
        # daemon/network.cpp
        # common/crypto.cpp
)

# --- Include Paths ---
target_include_directories(nestd PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${ZMQ_INCLUDE_DIR}  # Use the explicitly found include path
)

# --- Linking ---

target_include_directories(nestd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(nestd PRIVATE
        nest_proto
        OpenSSL::SSL
        OpenSSL::Crypto
        SQLite::SQLite3
        Threads::Threads
        PkgConfig::ZMQ  # Cleaner than using ${ZMQ_LIBRARIES}
)

# ZMQ Include dirs (PkgConfig puts them in variables)
target_include_directories(nestd PRIVATE ${ZMQ_INCLUDE_DIRS})