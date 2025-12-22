//
// Created by cv2 on 23.12.2025.
//

#pragma once
#include <string>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include <filesystem>

#include "router.hpp"
#include "venom.pb.h"

namespace nest {

    struct UploadJob {
        std::string filepath;
        RemoteUser target; // Who gets the file link after upload?
        std::string caption;
    };

    struct DownloadJob {
        venom::Attachment metadata;
        std::string output_path;
        std::string sender_name; // For notification
    };

    class TransferManager {
    public:
        // Router reference needed to perform network calls
        explicit TransferManager(Router& router);
        ~TransferManager();

        void start();
        void stop();

        // Queue a file to be sent
        void queue_upload(const std::string& filepath, const RemoteUser& target, const std::string& caption = "");

        // Queue a file to be downloaded
        void queue_download(const venom::Attachment& att, const std::string& output_dir, const std::string& sender_name);

    private:
        void worker_loop();

        Router& router_;

        std::atomic<bool> running_{false};
        std::jthread worker_thread_;

        // Job Queues
        std::mutex queue_mutex_;
        std::condition_variable cv_;
        std::queue<UploadJob> upload_queue_;
        std::queue<DownloadJob> download_queue_;
    };

} // namespace nest