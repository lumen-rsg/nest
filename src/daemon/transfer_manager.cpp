//
// Created by cv2 on 23.12.2025.
//
#include "transfer_manager.hpp"
#include <iostream>
#include <print>
#include <chrono>

namespace nest {

TransferManager::TransferManager(Router& router) : router_(router) {}

TransferManager::~TransferManager() { stop(); }

void TransferManager::start() {
    running_ = true;
    worker_thread_ = std::jthread([this] { worker_loop(); });
}

void TransferManager::stop() {
    {
        std::lock_guard lock(queue_mutex_);
        running_ = false;
    }
    cv_.notify_all();
}

void TransferManager::queue_upload(const std::string& filepath, const RemoteUser& target, const std::string& caption) {
    {
        std::lock_guard lock(queue_mutex_);
        upload_queue_.push(UploadJob{filepath, target, caption});
    }
    cv_.notify_one();
}

void TransferManager::queue_download(const venom::Attachment& att, const std::string& output_dir, const std::string& sender_name) {
    {
        std::lock_guard lock(queue_mutex_);
        // Construct full path
        std::filesystem::path out_path = std::filesystem::path(output_dir) / att.filename();
        download_queue_.push(DownloadJob{att, out_path.string(), sender_name});
    }
    cv_.notify_one();
}

void TransferManager::worker_loop() {
    std::println("[Transfer] Worker started.");

    while (running_) {
        std::unique_lock lock(queue_mutex_);

        // Wait for work
        cv_.wait(lock, [this] {
            return !running_ || !upload_queue_.empty() || !download_queue_.empty();
        });

        if (!running_) break;

        // PRIORITIZE DOWNLOADS (Quick wins)
        if (!download_queue_.empty()) {
            auto job = download_queue_.front();
            download_queue_.pop();
            lock.unlock(); // Release lock during I/O

            std::println("\n[Transfer] Downloading '{}' from {}...", job.metadata.filename(), job.sender_name);

            bool success = router_.download_file(job.metadata, job.output_path);

            if (success) {
                std::println("[Transfer] Download finished: {}", job.output_path);
            } else {
                std::println(stderr, "[Transfer] Download FAILED: {}", job.metadata.filename());
            }
            std::print("> "); std::cout.flush(); // Restore prompt
            continue;
        }

        // PROCESS UPLOADS
        if (!upload_queue_.empty()) {
            auto job = upload_queue_.front();
            upload_queue_.pop();
            lock.unlock();

            std::println("\n[Transfer] Uploading '{}' to @{}...", job.filepath, job.target.username);

            venom::Attachment attachment_meta;
            bool success = router_.upload_file(job.filepath, attachment_meta);

            if (success) {
                std::println("[Transfer] Upload complete. Sending key to target...");

                venom::Payload pay;
                pay.set_type(venom::Payload::MEDIA);
                pay.set_timestamp(time(nullptr));

                // USE THE JOB'S CAPTION
                pay.set_body(job.caption.empty() ? attachment_meta.filename() : job.caption);

                *pay.mutable_attachment() = attachment_meta;

                if (router_.send_payload(job.target, pay)) {
                    std::println("[Transfer] Message sent successfully.");
                } else {
                    std::println(stderr, "[Transfer] Failed to send message metadata!");
                }
            } else {
                std::println(stderr, "[Transfer] Upload FAILED.");
            }
            std::print("> "); std::cout.flush();
            continue;
        }
    }
}

} // namespace nest