#pragma once
// moondancer.hpp
// High-level wrapper around the Moondancer RPC API.
// Manages connection to Cynthion's CONTROL port and drives the TARGET port.

#include "libgreat.hpp"
#include <vector>
#include <optional>
#include <functional>
#include <atomic>
#include <chrono>

// USB speed constants (match moondancer firmware)
enum class USBSpeed : uint8_t
{
    LOW_SPEED = 0,
    FULL_SPEED = 1,
    HIGH_SPEED = 2,
};

// A setup packet (8 bytes) parsed into fields
struct SetupPacket
{
    uint8_t request_type;
    uint8_t request;
    uint16_t value;
    uint16_t index;
    uint16_t length;
    std::vector<uint8_t> data; // OUT data phase (if any)

    static SetupPacket from_bytes(const uint8_t *b)
    {
        SetupPacket p;
        p.request_type = b[0];
        p.request = b[1];
        p.value = b[2] | (uint16_t(b[3]) << 8);
        p.index = b[4] | (uint16_t(b[5]) << 8);
        p.length = b[6] | (uint16_t(b[7]) << 8);
        return p;
    }
    bool is_in() const { return (request_type & 0x80) != 0; }
    bool is_out() const { return !is_in(); }
};

// ── Moondancer ─────────────────────────────────────────────────────────────
class Moondancer
{
public:
    explicit Moondancer(libusb_device_handle *ctrl_handle, int timeout_ms = 2000)
        : rpc_(ctrl_handle, timeout_ms) {}

    // Connect the TARGET port at the given speed, presenting given
    // device/config descriptors to the host.
    void connect(USBSpeed speed = USBSpeed::FULL_SPEED)
    {
        std::vector<uint8_t> payload = {static_cast<uint8_t>(speed)};
        rpc_.call(MoondancerClass::CLASS_ID, MoondancerClass::Verb::CONNECT, payload);
    }

    void disconnect()
    {
        rpc_.call(MoondancerClass::CLASS_ID, MoondancerClass::Verb::DISCONNECT);
    }

    void bus_reset()
    {
        rpc_.call(MoondancerClass::CLASS_ID, MoondancerClass::Verb::BUS_RESET);
    }

    void set_address(uint8_t addr)
    {
        rpc_.call(MoondancerClass::CLASS_ID, MoondancerClass::Verb::SET_ADDRESS,
                  {addr});
    }

    // Configure the data endpoints (not EP0).
    // Each EndpointDescriptor contributes 4 bytes: address, max_packet(2), type
    void set_up_endpoints(const std::vector<EndpointDescriptor> &eps)
    {
        std::vector<uint8_t> payload;
        for (auto &ep : eps)
        {
            payload.push_back(ep.address);
            payload.push_back(ep.max_packet & 0xff);
            payload.push_back((ep.max_packet >> 8) & 0xff);
            payload.push_back(ep.transfer_type);
        }
        rpc_.call(MoondancerClass::CLASS_ID,
                  MoondancerClass::Verb::SET_UP_ENDPOINTS, payload);
    }

    // Poll for a pending IRQ event. Returns empty if nothing pending.
    std::optional<MdEvent> get_interrupt()
    {
        auto resp = rpc_.call(MoondancerClass::CLASS_ID,
                              MoondancerClass::Verb::GET_INTERRUPT, {}, 8);
        if (resp.empty() || resp[0] == static_cast<uint8_t>(MdIrq::NONE))
            return std::nullopt;

        MdEvent ev;
        ev.irq = static_cast<MdIrq>(resp[0]);
        ev.ep_num = resp.size() > 1 ? resp[1] : 0;
        ev.length = resp.size() > 3
                        ? uint16_t(resp[2]) | (uint16_t(resp[3]) << 8)
                        : 0;
        return ev;
    }

    // Read 8-byte setup packet from EP0
    std::vector<uint8_t> read_control()
    {
        return rpc_.call(MoondancerClass::CLASS_ID,
                         MoondancerClass::Verb::READ_CONTROL, {}, 64);
    }

    // Read data from an OUT endpoint
    std::vector<uint8_t> read_endpoint(uint8_t ep_num, uint16_t max_len = 512)
    {
        return rpc_.call(MoondancerClass::CLASS_ID,
                         MoondancerClass::Verb::READ_ENDPOINT,
                         {ep_num}, max_len + 4);
    }

    // Send data on an IN endpoint
    void write_endpoint(uint8_t ep_num, const std::vector<uint8_t> &data,
                        bool zlp = false)
    {
        std::vector<uint8_t> payload;
        payload.push_back(ep_num);
        payload.push_back(zlp ? 1 : 0);
        payload.insert(payload.end(), data.begin(), data.end());
        rpc_.call(MoondancerClass::CLASS_ID,
                  MoondancerClass::Verb::WRITE_ENDPOINT, payload);
    }

    void ack_status_stage(uint8_t ep_num = 0)
    {
        rpc_.call(MoondancerClass::CLASS_ID,
                  MoondancerClass::Verb::ACK_STATUS_STAGE, {ep_num});
    }

    void stall_endpoint(uint8_t ep_addr)
    {
        rpc_.call(MoondancerClass::CLASS_ID,
                  MoondancerClass::Verb::STALL_ENDPOINT, {ep_addr});
    }

    void prime_out_endpoint(uint8_t ep_num)
    {
        rpc_.call(MoondancerClass::CLASS_ID,
                  MoondancerClass::Verb::EP_OUT_PRIME_ENDPOINT, {ep_num});
    }

private:
    LibGreat rpc_;
};