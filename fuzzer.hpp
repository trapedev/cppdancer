#pragma once
// fuzzer.hpp  ─  PTP response mutation engine
//
// Fuzzing strategy per transaction:
//
//   PASSTHROUGH   – forward real camera response unmodified  (baseline)
//   MUTATE_BYTES  – bit-flip / byte-substitute random bytes in payload
//   MUTATE_PARAMS – corrupt response parameter values
//   TRUNCATE      – shorten payload to trigger length-check bugs
//   EXTEND        – append random bytes beyond declared length
//   WRONG_RESPCODE– replace PTP_RC_OK with random/invalid response code
//   INJECT_EXTRA  – insert extra bytes mid-payload
//   REPLAY        – resend a previously recorded response
//   DROP          – return empty / no data (tests null-deref paths)
//   CUSTOM        – user-supplied lambda

#include "ptp.hpp"
#include <random>
#include <functional>
#include <vector>
#include <map>
#include <string>
#include <cstdio>

enum class FuzzStrategy
{
    PASSTHROUGH,
    MUTATE_BYTES,
    MUTATE_PARAMS,
    TRUNCATE,
    EXTEND,
    WRONG_RESPCODE,
    INJECT_EXTRA,
    REPLAY,
    DROP,
};

inline const char *fuzz_strategy_name(FuzzStrategy s)
{
    switch (s)
    {
    case FuzzStrategy::PASSTHROUGH:
        return "PASSTHROUGH";
    case FuzzStrategy::MUTATE_BYTES:
        return "MUTATE_BYTES";
    case FuzzStrategy::MUTATE_PARAMS:
        return "MUTATE_PARAMS";
    case FuzzStrategy::TRUNCATE:
        return "TRUNCATE";
    case FuzzStrategy::EXTEND:
        return "EXTEND";
    case FuzzStrategy::WRONG_RESPCODE:
        return "WRONG_RESPCODE";
    case FuzzStrategy::INJECT_EXTRA:
        return "INJECT_EXTRA";
    case FuzzStrategy::REPLAY:
        return "REPLAY";
    case FuzzStrategy::DROP:
        return "DROP";
    }
    return "?";
}

// Per-opcode fuzzing rule
struct FuzzRule
{
    uint16_t op_code; // which PTP command this applies to (0 = all)
    FuzzStrategy strategy = FuzzStrategy::PASSTHROUGH;
    float probability = 1.0f;   // 0.0–1.0: chance of applying this rule
    uint32_t trigger_after = 0; // only fuzz after N passthroughs of this op
    // For MUTATE_BYTES: mutation rate
    float mutation_rate = 0.05f; // fraction of bytes to flip
    // For TRUNCATE: keep this many bytes of payload (0 = keep none)
    size_t truncate_to = 0;
    // For EXTEND: append this many random bytes
    size_t extend_by = 128;
    // For WRONG_RESPCODE: which code to inject (0 = random)
    uint16_t inject_resp_code = 0;
    // For INJECT_EXTRA: how many bytes and where (0 = random position)
    size_t inject_bytes = 16;
    size_t inject_at = SIZE_MAX; // SIZE_MAX = random
};

// A single recorded transaction for REPLAY strategy
struct RecordedTransaction
{
    uint16_t op_code;
    PtpPacket command;
    std::optional<PtpPacket> data_in; // data FROM camera
    PtpPacket response;
};

// ── Fuzzer ─────────────────────────────────────────────────────────────────
class PtpFuzzer
{
public:
    explicit PtpFuzzer(uint64_t seed = 0)
        : rng_(seed ? seed : std::random_device{}()) {}

    // Add a rule.  Rules are evaluated in insertion order; first match wins.
    void add_rule(FuzzRule r) { rules_.push_back(r); }

    // Record a real transaction for later REPLAY use
    void record(const RecordedTransaction &t)
    {
        corpus_[t.op_code].push_back(t);
    }

    // Enable/disable fuzzing globally
    bool enabled = false;

    // Called for every data packet going from camera → iPad.
    // cmd   = the PTP command the initiator sent
    // data  = the DATA phase packet from the real camera (may be absent)
    // resp  = the RESPONSE phase packet from the real camera
    // Returns: {mutated_data (optional), mutated_response}
    struct MutatedTxn
    {
        std::optional<PtpPacket> data;
        PtpPacket response;
        FuzzStrategy applied;
        std::string note;
    };

    MutatedTxn process(const PtpPacket &cmd,
                       std::optional<PtpPacket> data,
                       const PtpPacket &resp)
    {
        uint16_t op = cmd.code;
        seen_count_[op]++;

        if (!enabled)
            return {data, resp, FuzzStrategy::PASSTHROUGH, "disabled"};

        // Find matching rule
        const FuzzRule *rule = find_rule(op);
        if (!rule)
            return {data, resp, FuzzStrategy::PASSTHROUGH, "no rule"};

        // Probability gate
        if (uniform01_(rng_) > rule->probability)
            return {data, resp, FuzzStrategy::PASSTHROUGH, "prob gate"};

        // Trigger-after gate
        if (rule->trigger_after > 0 && seen_count_[op] <= rule->trigger_after)
            return {data, resp, FuzzStrategy::PASSTHROUGH, "not yet"};

        return apply(*rule, cmd, data, resp);
    }

    // How many times has each op been seen?
    const std::map<uint16_t, uint32_t> &stats() const { return seen_count_; }

private:
    std::mt19937_64 rng_;
    std::vector<FuzzRule> rules_;
    std::map<uint16_t, std::vector<RecordedTransaction>> corpus_;
    std::map<uint16_t, uint32_t> seen_count_;

    std::uniform_real_distribution<float> uniform01_{0.0f, 1.0f};

    const FuzzRule *find_rule(uint16_t op) const
    {
        for (auto &r : rules_)
        {
            if (r.op_code == 0 || r.op_code == op)
                return &r;
        }
        return nullptr;
    }

    uint8_t rand_byte()
    {
        return (uint8_t)(rng_() & 0xff);
    }
    size_t rand_range(size_t lo, size_t hi)
    {
        if (lo >= hi)
            return lo;
        return lo + (size_t)(rng_() % (hi - lo));
    }

    MutatedTxn apply(const FuzzRule &rule,
                     const PtpPacket &cmd,
                     std::optional<PtpPacket> data,
                     const PtpPacket &resp)
    {
        MutatedTxn out{data, resp, rule.strategy, ""};
        char note[128];

        switch (rule.strategy)
        {

        case FuzzStrategy::PASSTHROUGH:
            break;

        // ── Flip/substitute random bytes in data payload ────────────────
        case FuzzStrategy::MUTATE_BYTES:
            if (out.data)
            {
                auto &pl = out.data->payload;
                size_t mutations = 0;
                for (auto &b : pl)
                {
                    if (uniform01_(rng_) < rule.mutation_rate)
                    {
                        b = rand_byte();
                        mutations++;
                    }
                }
                snprintf(note, sizeof(note),
                         "mutated %zu/%zu bytes in data payload",
                         mutations, pl.size());
            }
            else
            {
                snprintf(note, sizeof(note), "MUTATE_BYTES: no data phase");
            }
            out.note = note;
            break;

        // ── Corrupt response parameters ─────────────────────────────────
        case FuzzStrategy::MUTATE_PARAMS:
            for (auto &p : out.response.params)
            {
                if (uniform01_(rng_) < 0.5f)
                {
                    // Choose: zero / max / random
                    int choice = (int)(rng_() % 3);
                    if (choice == 0)
                        p = 0;
                    else if (choice == 1)
                        p = 0xFFFFFFFF;
                    else
                        p = (uint32_t)rng_();
                }
            }
            out.note = "params corrupted";
            break;

        // ── Shorten data payload ────────────────────────────────────────
        case FuzzStrategy::TRUNCATE:
            if (out.data)
            {
                size_t keep = rule.truncate_to;
                if (keep == 0)
                    keep = rand_range(0, out.data->payload.size());
                out.data->payload.resize(keep);
                snprintf(note, sizeof(note), "truncated to %zu bytes", keep);
                out.note = note;
            }
            break;

        // ── Extend data payload with garbage ───────────────────────────
        case FuzzStrategy::EXTEND:
            if (out.data)
            {
                size_t add = rule.extend_by
                                 ? rule.extend_by
                                 : rand_range(1, 512);
                for (size_t i = 0; i < add; i++)
                    out.data->payload.push_back(rand_byte());
                snprintf(note, sizeof(note),
                         "extended by %zu bytes (total %zu)",
                         add, out.data->payload.size());
                out.note = note;
            }
            break;

        // ── Replace PTP_RC_OK with unexpected code ─────────────────────
        case FuzzStrategy::WRONG_RESPCODE:
        {
            uint16_t new_code = rule.inject_resp_code;
            if (new_code == 0)
            {
                // pick a random non-OK response code
                static const uint16_t errs[] = {
                    0x2002, 0x2003, 0x2005, 0x2006,
                    0x2008, 0x2009, 0x200A, 0x2019,
                    0x201E, 0x9999, 0xDEAD};
                new_code = errs[rng_() % (sizeof(errs) / sizeof(errs[0]))];
            }
            snprintf(note, sizeof(note),
                     "resp code: 0x%04x → 0x%04x",
                     out.response.code, new_code);
            out.response.code = new_code;
            out.note = note;
            break;
        }

        // ── Insert garbage bytes at random position ─────────────────────
        case FuzzStrategy::INJECT_EXTRA:
            if (out.data)
            {
                size_t at = rule.inject_at;
                if (at == SIZE_MAX || at > out.data->payload.size())
                    at = rand_range(0, out.data->payload.size() + 1);
                for (size_t i = 0; i < rule.inject_bytes; i++)
                    out.data->payload.insert(
                        out.data->payload.begin() + (ptrdiff_t)(at + i),
                        rand_byte());
                snprintf(note, sizeof(note),
                         "injected %zu bytes at offset %zu",
                         rule.inject_bytes, at);
                out.note = note;
            }
            break;

        // ── Replay a previously seen response ───────────────────────────
        case FuzzStrategy::REPLAY:
        {
            auto it = corpus_.find(cmd.code);
            if (it != corpus_.end() && !it->second.empty())
            {
                size_t idx = rng_() % it->second.size();
                const auto &rec = it->second[idx];
                out.data = rec.data_in;
                out.response = rec.response;
                // Patch transaction ID to match current
                out.response.txn = resp.txn;
                if (out.data)
                    out.data->txn = resp.txn;
                out.note = "replayed from corpus";
            }
            break;
        }

        // ── Return no data at all (tests null-ptr / empty-response paths) ─
        case FuzzStrategy::DROP:
            out.data = std::nullopt;
            out.response.code = (uint16_t)PtpResp::GeneralError;
            out.note = "dropped data, injected GeneralError";
            break;
        }

        return out;
    }
};