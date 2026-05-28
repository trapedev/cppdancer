#pragma once
// ptp.hpp  ─  PTP/MTP wire structures, op-codes, serialisation helpers

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <optional>
#include <algorithm>

// ── Packet type field ──────────────────────────────────────────────────────
enum class PtpType : uint16_t
{
    Command = 0x0001,
    Data = 0x0002,
    Response = 0x0003,
    Event = 0x0004,
};

// ── Standard operation codes (Initiator → Responder) ──────────────────────
enum class PtpOp : uint16_t
{
    GetDeviceInfo = 0x1001,
    OpenSession = 0x1002,
    CloseSession = 0x1003,
    GetStorageIDs = 0x1004,
    GetStorageInfo = 0x1005,
    GetNumObjects = 0x1006,
    GetObjectHandles = 0x1007,
    GetObjectInfo = 0x1008,
    GetObject = 0x1009,
    GetThumb = 0x100A,
    DeleteObject = 0x100B,
    SendObjectInfo = 0x100C,
    SendObject = 0x100D,
    InitiateCapture = 0x100E,
    ResetDevice = 0x1010,
    GetDevicePropDesc = 0x1014,
    GetDevicePropValue = 0x1015,
    SetDevicePropValue = 0x1016,
    GetPartialObject = 0x101B,
    // Common vendor LiveView ops (Canon/Sony/Nikon style — app may probe these)
    GetLiveViewImage = 0x9153, // Canon
    StartLiveView = 0x9201,
    StopLiveView = 0x9202,
};

inline const char *ptp_op_name(uint16_t c)
{
    switch (static_cast<PtpOp>(c))
    {
    case PtpOp::GetDeviceInfo:
        return "GetDeviceInfo";
    case PtpOp::OpenSession:
        return "OpenSession";
    case PtpOp::CloseSession:
        return "CloseSession";
    case PtpOp::GetStorageIDs:
        return "GetStorageIDs";
    case PtpOp::GetStorageInfo:
        return "GetStorageInfo";
    case PtpOp::GetNumObjects:
        return "GetNumObjects";
    case PtpOp::GetObjectHandles:
        return "GetObjectHandles";
    case PtpOp::GetObjectInfo:
        return "GetObjectInfo";
    case PtpOp::GetObject:
        return "GetObject";
    case PtpOp::DeleteObject:
        return "DeleteObject";
    case PtpOp::InitiateCapture:
        return "InitiateCapture";
    case PtpOp::GetDevicePropDesc:
        return "GetDevicePropDesc";
    case PtpOp::GetDevicePropValue:
        return "GetDevicePropValue";
    case PtpOp::SetDevicePropValue:
        return "SetDevicePropValue";
    case PtpOp::GetLiveViewImage:
        return "GetLiveViewImage";
    case PtpOp::StartLiveView:
        return "StartLiveView";
    case PtpOp::StopLiveView:
        return "StopLiveView";
    default:
        if (c >= 0x9000)
            return "VendorCmd";
        return "Unknown";
    }
}

// ── Response codes ─────────────────────────────────────────────────────────
enum class PtpResp : uint16_t
{
    OK = 0x2001,
    GeneralError = 0x2002,
    SessionNotOpen = 0x2003,
    InvalidTransactionID = 0x2004,
    OperationNotSupported = 0x2005,
    ParameterNotSupported = 0x2006,
    InvalidStorageID = 0x2008,
    InvalidObjectHandle = 0x2009,
    DevicePropNotSupported = 0x200A,
    DeviceBusy = 0x2019,
    SessionAlreadyOpen = 0x201E,
};

// ── 12-byte wire header ────────────────────────────────────────────────────
#pragma pack(push, 1)
struct PtpHeader
{
    uint32_t length; // total packet bytes incl. this header
    uint16_t type;
    uint16_t code;
    uint32_t txn; // transaction ID
};
#pragma pack(pop)
static_assert(sizeof(PtpHeader) == 12);

// ── In-memory parsed packet ────────────────────────────────────────────────
struct PtpPacket
{
    PtpType type{};
    uint16_t code{};
    uint32_t txn{};
    std::vector<uint32_t> params{}; // Command / Response (≤5)
    std::vector<uint8_t> payload{}; // Data phase body

    // Deserialise from raw bytes received off the wire
    static std::optional<PtpPacket> parse(const std::vector<uint8_t> &raw)
    {
        if (raw.size() < 12)
            return std::nullopt;
        const auto *h = reinterpret_cast<const PtpHeader *>(raw.data());
        PtpPacket p;
        p.type = static_cast<PtpType>(h->type);
        p.code = h->code;
        p.txn = h->txn;
        const uint8_t *body = raw.data() + 12;
        size_t body_len = raw.size() - 12;
        if (p.type == PtpType::Command || p.type == PtpType::Response)
        {
            size_t n = std::min(body_len / 4, (size_t)5);
            for (size_t i = 0; i < n; i++)
            {
                uint32_t v = 0;
                memcpy(&v, body + i * 4, 4);
                p.params.push_back(v);
            }
        }
        else
        {
            p.payload.assign(body, body + body_len);
        }
        return p;
    }

    // Serialise back to wire bytes
    std::vector<uint8_t> serialize() const
    {
        size_t total = 12 + params.size() * 4 + payload.size();
        std::vector<uint8_t> out(total);
        auto *h = reinterpret_cast<PtpHeader *>(out.data());
        h->length = (uint32_t)total;
        h->type = (uint16_t)type;
        h->code = code;
        h->txn = txn;
        uint8_t *b = out.data() + 12;
        for (auto v : params)
        {
            memcpy(b, &v, 4);
            b += 4;
        }
        if (!payload.empty())
            memcpy(b, payload.data(), payload.size());
        return out;
    }
};

// ── Serialisation builder (for synthesising response payloads) ─────────────
struct PtpWriter
{
    std::vector<uint8_t> buf;
    void u8(uint8_t v) { buf.push_back(v); }
    void u16(uint16_t v)
    {
        buf.push_back(v & 0xff);
        buf.push_back(v >> 8);
    }
    void u32(uint32_t v)
    {
        for (int i = 0; i < 4; i++)
        {
            buf.push_back(v & 0xff);
            v >>= 8;
        }
    }
    void u64(uint64_t v)
    {
        for (int i = 0; i < 8; i++)
        {
            buf.push_back(v & 0xff);
            v >>= 8;
        }
    }
    // PTP string: uint8 numChars (incl NUL), then UTF-16LE
    void str(const char *s)
    {
        if (!s || !*s)
        {
            buf.push_back(0);
            return;
        }
        uint8_t n = (uint8_t)(strlen(s) + 1);
        buf.push_back(n);
        for (uint8_t i = 0; i < n; i++)
        {
            buf.push_back((uint8_t)s[i]);
            buf.push_back(0);
        }
    }
    void arr16(const std::vector<uint16_t> &v)
    {
        u32((uint32_t)v.size());
        for (auto x : v)
            u16(x);
    }
    void arr32(const std::vector<uint32_t> &v)
    {
        u32((uint32_t)v.size());
        for (auto x : v)
            u32(x);
    }
    void bytes(const std::vector<uint8_t> &v) { buf.insert(buf.end(), v.begin(), v.end()); }
};