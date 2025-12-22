# --- Client Daemon (nestd) ---
add_executable(nestd
        daemon/main.cpp
        daemon/beacon.cpp
        daemon/router.cpp
        common/crypto.cpp
        common/db.cpp
)

target_include_directories(nestd PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CPPZMQ_INCLUDE_DIR}
)

target_link_libraries(nestd PRIVATE
        nest_proto
        OpenSSL::SSL
        OpenSSL::Crypto
        SQLite::SQLite3
        Threads::Threads
        ${ZMQ_LIBRARY}
)

# --- Server (hive) ---
add_executable(hive
        hive/main.cpp
        # hive/server.cpp (We will create this next)
        common/crypto.cpp # Needs crypto to verify signatures
        common/db.cpp
        hive/main.cpp
        hive/server_db.hpp
        hive/server_db.cpp     # Needs DB to store offline messages
)

target_include_directories(hive PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CPPZMQ_INCLUDE_DIR}
)

target_link_libraries(hive PRIVATE
        nest_proto
        OpenSSL::SSL
        OpenSSL::Crypto
        SQLite::SQLite3
        Threads::Threads
        ${ZMQ_LIBRARY}
)