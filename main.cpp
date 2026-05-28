// main.cpp  ─  PTP MITM Proxy + Fuzzer entry point
//
// Usage:
//   sudo ./usb_proxy --vid 0x04a9 --pid 0x3218 [options]
//
//   --vid / --pid       Camera VID/PID (hex)
//   --fuzz              Enable fuzzing (default: passthrough only)
//   --seed N            PRNG seed (0 = random)
//   --log FILE          Append JSONL log to FILE
//   --verbose           Extra console output
//
// Fuzzing rules (hardcoded defaults, easily customised below):
//   GetDeviceInfo       → MUTATE_BYTES  (corrupt device descriptor payload)
//   GetStorageInfo      → TRUNCATE      (trigger length underrun)
//   GetObjectInfo       → MUTATE_PARAMS (corrupt object handle params)
//   GetDevicePropValue  → WRONG_RESPCODE(unexpected error codes)
//   GetLiveViewImage    → MUTATE_BYTES  (corrupt live view JPEG/MJPEG)
//   SetDevicePropValue  → DROP          (no-data response)
//   All others          → PASSTHROUGH

#include "proxy.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <stdexcept>

static PtpMitmProxy *g_proxy = nullptr;
static void on_signal(int)
{
    printf("\n[main] Shutting down...\n");
    if (g_proxy)
        g_proxy->stop();
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s --vid <VID> --pid <PID> [options]\n"
            "  --vid HEX       Camera vendor ID  (e.g. 0x04a9 for Canon)\n"
            "  --pid HEX       Camera product ID\n"
            "  --fuzz          Enable fuzzing (default: passthrough)\n"
            "  --seed N        PRNG seed (0 = random device)\n"
            "  --log FILE      Append JSONL transaction log to FILE\n"
            "  --verbose       Print raw PTP payloads\n",
            prog);
    exit(1);
}

int main(int argc, char *argv[])
{
    uint16_t vid = 0, pid = 0;
    bool fuzz = false;
    uint64_t seed = 0;
    std::string log_path;
    bool verbose = false;

    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "--vid") && i + 1 < argc)
            vid = (uint16_t)strtol(argv[++i], nullptr, 16);
        else if (!strcmp(argv[i], "--pid") && i + 1 < argc)
            pid = (uint16_t)strtol(argv[++i], nullptr, 16);
        else if (!strcmp(argv[i], "--fuzz"))
            fuzz = true;
        else if (!strcmp(argv[i], "--seed") && i + 1 < argc)
            seed = (uint64_t)strtoull(argv[++i], nullptr, 10);
        else if (!strcmp(argv[i], "--log") && i + 1 < argc)
            log_path = argv[++i];
        else if (!strcmp(argv[i], "--verbose"))
            verbose = true;
        else if (!strcmp(argv[i], "--help"))
            usage(argv[0]);
    }
    if (!vid || !pid)
        usage(argv[0]);

    // ── libusb ────────────────────────────────────────────────────────────
    libusb_context *ctx = nullptr;
    if (libusb_init(&ctx) < 0)
    {
        fprintf(stderr, "libusb_init failed\n");
        return 1;
    }
    if (verbose)
        libusb_set_option(ctx, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_WARNING);

    // ── Proxy ─────────────────────────────────────────────────────────────
    PtpMitmProxy proxy(vid, pid, ctx);
    if (!log_path.empty())
        proxy.set_log_file(log_path);

    // ── Fuzzer ────────────────────────────────────────────────────────────
    auto fuzzer = std::make_unique<PtpFuzzer>(seed);
    fuzzer->enabled = fuzz;

    if (fuzz)
    {
        printf("[main] Fuzzing rules:\n");

        // GetDeviceInfo: corrupt the device descriptor payload
        // → app may fail camera recognition or crash parsing model name
        FuzzRule r1;
        r1.op_code = (uint16_t)PtpOp::GetDeviceInfo;
        r1.strategy = FuzzStrategy::MUTATE_BYTES;
        r1.probability = 0.3f; // 30% of GetDeviceInfo responses
        r1.trigger_after = 1;  // let first one through (recognition)
        r1.mutation_rate = 0.08f;
        fuzzer->add_rule(r1);
        printf("  GetDeviceInfo       → MUTATE_BYTES  (p=0.30, after 1)\n");

        // GetStorageInfo: truncate → length underrun bug
        FuzzRule r2;
        r2.op_code = (uint16_t)PtpOp::GetStorageInfo;
        r2.strategy = FuzzStrategy::TRUNCATE;
        r2.probability = 0.5f;
        r2.truncate_to = 0; // 0 = random length
        fuzzer->add_rule(r2);
        printf("  GetStorageInfo      → TRUNCATE      (p=0.50)\n");

        // GetObjectInfo: corrupt object handle params
        FuzzRule r3;
        r3.op_code = (uint16_t)PtpOp::GetObjectInfo;
        r3.strategy = FuzzStrategy::MUTATE_PARAMS;
        r3.probability = 0.4f;
        fuzzer->add_rule(r3);
        printf("  GetObjectInfo       → MUTATE_PARAMS (p=0.40)\n");

        // GetDevicePropValue: inject unexpected error codes
        FuzzRule r4;
        r4.op_code = (uint16_t)PtpOp::GetDevicePropValue;
        r4.strategy = FuzzStrategy::WRONG_RESPCODE;
        r4.probability = 0.5f;
        r4.inject_resp_code = 0; // 0 = random error code
        fuzzer->add_rule(r4);
        printf("  GetDevicePropValue  → WRONG_RESPCODE(p=0.50)\n");

        // GetLiveViewImage: corrupt JPEG/MJPEG frame data
        // → tests frame parser robustness in the app
        FuzzRule r5;
        r5.op_code = (uint16_t)PtpOp::GetLiveViewImage;
        r5.strategy = FuzzStrategy::MUTATE_BYTES;
        r5.probability = 0.8f;
        r5.mutation_rate = 0.02f; // 2% byte flip – still decodable-ish
        fuzzer->add_rule(r5);
        printf("  GetLiveViewImage    → MUTATE_BYTES  (p=0.80, rate=0.02)\n");

        // SetDevicePropValue: drop response entirely
        FuzzRule r6;
        r6.op_code = (uint16_t)PtpOp::SetDevicePropValue;
        r6.strategy = FuzzStrategy::DROP;
        r6.probability = 0.3f;
        fuzzer->add_rule(r6);
        printf("  SetDevicePropValue  → DROP          (p=0.30)\n");

        // Extend: append garbage to GetObject payloads
        FuzzRule r7;
        r7.op_code = (uint16_t)PtpOp::GetObject;
        r7.strategy = FuzzStrategy::EXTEND;
        r7.probability = 0.2f;
        r7.extend_by = 0; // 0 = random 1..512 bytes
        fuzzer->add_rule(r7);
        printf("  GetObject           → EXTEND        (p=0.20)\n");

        // All other commands → passthrough (ensures app stays alive
        // between fuzz cases and camera stays recognised)
        FuzzRule passthru;
        passthru.op_code = 0; // wildcard
        passthru.strategy = FuzzStrategy::PASSTHROUGH;
        passthru.probability = 1.0f;
        fuzzer->add_rule(passthru);
        printf("  *                   → PASSTHROUGH\n");
    }

    proxy.set_fuzzer(std::move(fuzzer));

    // ── Signals ───────────────────────────────────────────────────────────
    g_proxy = &proxy;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    // ── Run ───────────────────────────────────────────────────────────────
    try
    {
        proxy.run();
    }
    catch (const std::exception &e)
    {
        fprintf(stderr, "[main] Fatal: %s\n", e.what());
        libusb_exit(ctx);
        return 1;
    }

    libusb_exit(ctx);
    printf("[main] Exited cleanly.\n");
    return 0;
}