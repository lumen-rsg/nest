//
// Created by cv2 on 23.12.2025.
//

#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <expected>
#include <optional>
#include "../common/crypto.hpp" // For SHA256 hashing

namespace nest {

    enum class StorageError {
        IOError,
        FileExists,
        NotFound,
        QuotaExceeded,
        InvalidHash,
        AccessDenied
    };

    struct FileInfo {
        std::string file_hash; // The ID
        uint64_t size_bytes;
        std::string uploader_key_hex;
        uint64_t uploaded_at;
    };

    class StorageEngine {
    public:
        // root_path: where files live (e.g., "/var/lib/nest/data")
        StorageEngine(const std::string& root_path);

        // Initialize directories
        bool init();

        // 1. Start an upload session
        // Returns a temporary path or ID to write chunks to
        std::expected<std::string, StorageError> begin_upload();

        // 2. Append chunk to temporary file
        std::expected<void, StorageError> append_chunk(const std::string& temp_id, const std::vector<uint8_t>& data);

        // 3. Finalize upload
        // Calculates hash, moves temp file to permanent storage (CAS), updates DB.
        // Returns the final file_hash (the ID used by clients).
        std::expected<std::string, StorageError> finalize_upload(
            const std::string& temp_id,
            const std::string& uploader_pubkey_hex
        );

        // 4. Read file chunk (Random Access)
        std::expected<std::vector<uint8_t>, StorageError> read_chunk(
            const std::string& file_hash,
            uint64_t offset,
            size_t length
        );

        // 5. Get Metadata
        std::optional<FileInfo> get_file_info(const std::string& file_hash);

    private:
        std::filesystem::path root_;
        std::filesystem::path temp_dir_;
        std::filesystem::path final_dir_;

        // Helper to validate hash structure (prevent ../ attacks)
        bool is_valid_hash(const std::string& hash);

        // Helper to calculate SHA256 of a file on disk
        std::string calculate_file_hash(const std::filesystem::path& path);
    };

} // namespace nest