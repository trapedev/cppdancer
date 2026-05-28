#pragma once
// proxy.hpp  ─  PTP transparent MITM proxy + fuzzing engine
//
// Architecture:
//
//   iPad (Initiator)
//     ↕  USB Bulk OUT (commands) / Bulk IN (responses) / Interrupt IN (events)
//   Cynthion TARGET port  ←→  Moondancer RPC ←→  [this process]
//     ↕  libusb direct to real camera
//   Camera (Responder)
//
// For each PTP transaction the proxy:
//   1. Reads command from iPad via Moondancer
//   2. Forwards command to real camera via libusb
//   3. Reads data + response from camera
//   4. Passes through PtpFuzzer (may mutate)
//   5. Returns (possibly mutated) data + response to iPad
//   6. Logs everything to a JSONL file

#include "moondancer.hpp"
#include "ptp.hpp"
#include "fuzzer.hpp"
#include <libusb-1.0/libusb.h>
#include <atomic>
#include <memory>
#include <vector>
#include <string>
#include <cstdio>
#include <functional>

// ── Camera-side endpoint layout (standard PTP/MTP over USB) ───────────────
struct CameraEndpoints
{
    uint8_t bulk_in = 0x81;  // camera → host (responses, data)
    uint8_t bulk_out = 0x01; // host → camera (commands, data)
    uint8_t intr_in = 0x83;  // camera → host (events) — optional
};

// ── Transaction log entry ──────────────────────────────────────────────────
struct TxnLog
{
    uint32_t seq;
    uint16_t op_code;
    const char *op_name;
    uint32_t txn_id;
    bool fuzzed;
    FuzzStrategy strategy;
    std::string note;
    size_t data_len_real;    // actual camera data size
    size_t data_len_sent;    // what was delivered to iPad
    uint16_t resp_code_real; // camera's response code
    uint16_t resp_code_sent; // what iPad received
};
using LogCallback = std::function<void(const TxnLog &)>;

// ── Main proxy class ───────────────────────────────────────────────────────
class PtpMitmProxy
{
public:
    PtpMitmProxy(uint16_t cam_vid, uint16_t cam_pid,
                 libusb_context *ctx = nullptr)
        : cam_vid_(cam_vid), cam_pid_(cam_pid), ctx_(ctx) {}

    // Wire up the fuzzer (takes ownership)
    void set_fuzzer(std::unique_ptr<PtpFuzzer> f) { fuzzer_ = std::move(f); }
    PtpFuzzer *fuzzer() { return fuzzer_.get(); }

    // Set a callback to receive structured log entries
    void set_log_callback(LogCallback cb) { log_cb_ = std::move(cb); }

    // Log file path (JSONL)
    void set_log_file(const std::string &path) { log_path_ = path; }

    // USB timeout for camera communication (ms)
    int usb_timeout_ms = 2000;

    // Run (blocks until stop() is called)
    void run();
    void stop() { running_ = false; }

private:
    uint16_t cam_vid_, cam_pid_;
    libusb_context *ctx_;
    std::unique_ptr<PtpFuzzer> fuzzer_;
    LogCallback log_cb_;
    std::string log_path_;
    FILE *log_fp_ = nullptr;
    std::atomic<bool> running_{true};
    uint32_t seq_{0};

    // Moondancer (Cynthion side – acts as USB device toward iPad)
    libusb_device_handle *cynthion_handle_ = nullptr;
    std::unique_ptr<Moondancer> md_;

    // Camera (real PTP responder)
    libusb_device_handle *cam_handle_ = nullptr;
    CameraEndpoints cam_ep_;
    int cam_iface_ = 0;

    // ── Lifecycle ─────────────────────────────────────────────────────────
    void open_cynthion();
    void open_camera();
    void configure_moondancer_from_camera();
    void close_all();

    // ── Main event loop ───────────────────────────────────────────────────
    void event_loop();

    // ── PTP transaction handling ──────────────────────────────────────────
    // Receive one complete PTP transaction from iPad via Moondancer IRQ,
    // forward to camera, (optionally fuzz), return to iPad.
    void handle_receive_control(const MdEvent &ev);
    void handle_receive_packet(const MdEvent &ev);
    void handle_ep_in_nak(const MdEvent &ev);

    // Camera I/O helpers
    std::vector<uint8_t> cam_bulk_read(size_t max_len);
    void cam_bulk_write(const std::vector<uint8_t> &data);

    // Moondancer I/O helpers
    void md_send(const std::vector<uint8_t> &data, uint8_t ep = 0x00);

    // Execute a full PTP transaction on the camera side
    // cmd_bytes = raw command bytes from iPad
    // Returns: {data_packet (optional), response_packet}
    struct CamResult
    {
        std::optional<std::vector<uint8_t>> data;
        std::vector<uint8_t> response;
    };
    CamResult forward_to_camera(const std::vector<uint8_t> &cmd_bytes);

    // Logging
    void log_txn(const TxnLog &t);
    void open_log_file();
};