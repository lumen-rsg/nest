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