# --- Server (hive) ---
add_executable(hive
        hive/main.cpp
        common/crypto.cpp # Needs crypto to verify signatures
        common/db.cpp
        hive/main.cpp
        hive/server_db.hpp
        hive/storage.hpp
        hive/storage.cpp
        common/file_crypto.cpp
        common/notifier_mac.cpp     # Needs DB to store offline messages
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

# --- Platform Specific Notification Sources ---
if(APPLE)
    set(NOTIFIER_SRC common/notifier_mac.cpp)
    find_library(FOUNDATION_LIB Foundation)
    set(PLATFORM_LIBS ${FOUNDATION_LIB})
elseif(UNIX AND NOT APPLE)
    set(NOTIFIER_SRC common/notifier_linux.cpp)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBNOTIFY REQUIRED libnotify)
    set(PLATFORM_LIBS ${LIBNOTIFY_LIBRARIES})
    # Include paths for Glib/Libnotify
    include_directories(${LIBNOTIFY_INCLUDE_DIRS})
else()
    set(NOTIFIER_SRC common/notifier_dummy.cpp)
endif()

# --- Client Daemon (nestd) ---
add_executable(nestd
        daemon/main.cpp
        daemon/router.cpp
        daemon/transfer_manager.cpp
        common/crypto.cpp
        common/db.cpp
        common/file_crypto.cpp
        ${NOTIFIER_SRC}
        daemon/ipc_server.hpp
        daemon/ipc_server.cpp  # <--- Add the platform specific file
)

target_include_directories(nestd PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CPPZMQ_INCLUDE_DIR}
        ${LIBNOTIFY_INCLUDE_DIRS} # Helpful for Linux
)

target_link_libraries(nestd PRIVATE
        nest_proto
        OpenSSL::SSL
        OpenSSL::Crypto
        SQLite::SQLite3
        Threads::Threads
        ${ZMQ_LIBRARY}
        ${PLATFORM_LIBS} # <--- Link Cocoa (Mac) or Libnotify (Linux)
)

# --- GUI Client (Nectar) ---

# You might need this at the top of the file or in the root CMake
find_package(OpenGL REQUIRED)

add_executable(nectar
        nectar/main.cpp
)

# ImGui sources (backends)
target_sources(nectar PRIVATE
        ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)

# Includes
target_include_directories(nectar PRIVATE
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends
        ${glfw_SOURCE_DIR}/include
        ${CPPZMQ_INCLUDE_DIR}
)

# Linking
target_link_libraries(nectar PRIVATE
        imgui_lib           # <--- CHANGE: Link against our custom library
        glfw
        ${OPENGL_LIBRARIES}
        ${ZMQ_LIBRARY}
)

# --- TUI Client (Nectar TUI) ---
find_package(Curses REQUIRED)
find_package(PkgConfig REQUIRED)


add_executable(nectar-tui
        nectar-tui/main.cpp
)

target_include_directories(nectar-tui PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CPPZMQ_INCLUDE_DIR}
        ${CURSES_INCLUDE_DIRS}
)

target_link_libraries(nectar-tui PRIVATE
        ${CURSES_LIBRARIES} # Links ncurses
        ${ZMQ_LIBRARY}
)