# --- Client Daemon (nestd) ---
add_executable(nestd
        daemon/main.cpp
        daemon/router.cpp
        common/crypto.cpp
        common/db.cpp
        common/file_crypto.hpp
        common/file_crypto.cpp
        daemon/transfer_manager.hpp
        daemon/transfer_manager.cpp
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
        common/crypto.cpp # Needs crypto to verify signatures
        common/db.cpp
        hive/main.cpp
        hive/server_db.hpp
        hive/storage.hpp
        hive/storage.cpp
        common/file_crypto.cpp     # Needs DB to store offline messages
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