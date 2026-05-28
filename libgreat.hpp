#pragma once
// libgreat.hpp
// C++ implementation of the libgreat RPC protocol used to communicate
// with the Moondancer firmware on Cynthion via the CONTROL USB port.
//
// Protocol reference: https://github.com/greatscottgadgets/cynthion
// Cynthion CONTROL port: VID=0x1d50, PID=0x615b (Facedancer bitstream)

#include <libusb-1.0/libusb.h>
#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>

// ── Cynthion USB identifiers ──────────────────────────────────────────────
static constexpr uint16_t CYNTHION_VID = 0x1d50;
static constexpr uint16_t CYNTHION_PID_FACEDANCER = 0x615b;

// libgreat command endpoint numbers (on the CONTROL port)
static constexpr uint8_t LIBGREAT_EP_COMMAND_OUT = 0x01; // bulk OUT
static constexpr uint8_t LIBGREAT_EP_COMMAND_IN = 0x81;  // bulk IN

// libgreat vendor bRequest values
static constexpr uint8_t LIBGREAT_REQUEST_SET_UP = 0x00;
static constexpr uint8_t LIBGREAT_REQUEST_EXECUTE = 0x01;

// Moondancer class / verb IDs (from cynthion firmware source)
// firmware/moondancer/src/class/moondancer.rs
namespace MoondancerClass
{
    static constexpr uint32_t CLASS_ID = 0x00;
    namespace Verb
    {
        static constexpr uint32_t CONNECT = 0x00;
        static constexpr uint32_t DISCONNECT = 0x01;
        static constexpr uint32_t BUS_RESET = 0x02;
        static constexpr uint32_t SET_ADDRESS = 0x03;
        static constexpr uint32_t SET_UP_ENDPOINTS = 0x04;
        static constexpr uint32_t GET_INTERRUPT = 0x05; // poll for IRQ
        static constexpr uint32_t READ_CONTROL = 0x06;
        static constexpr uint32_t READ_ENDPOINT = 0x07;
        static constexpr uint32_t WRITE_ENDPOINT = 0x08;
        static constexpr uint32_t ACK_STATUS_STAGE = 0x09;
        static constexpr uint32_t STALL_ENDPOINT = 0x0a;
        static constexpr uint32_t EP_OUT_PRIME_ENDPOINT = 0x0b;
    }
}

// Interrupt event codes returned by GET_INTERRUPT
enum class MdIrq : uint8_t
{
    NONE = 0x00,
    USB_BUS_RESET = 0x01,
    USB_RECEIVE_CONTROL = 0x02,
    USB_RECEIVE_PACKET = 0x03,
    USB_SEND_COMPLETE = 0x04,
    USB_EP_IN_NAK = 0x05,
};

struct MdEvent
{
    MdIrq irq;
    uint8_t ep_num;
    uint16_t length; // payload length for RECEIVE_PACKET
};

// USB endpoint descriptor as sent to set_up_endpoints
struct EndpointDescriptor
{
    uint8_t address; // e.g. 0x81 = IN ep 1
    uint16_t max_packet;
    uint8_t transfer_type; // 0=Control 1=Isochronous 2=Bulk 3=Interrupt
};

// ── LibGreat – thin RPC transport over libusb ────────────────────────────
class LibGreat
{
public:
    explicit LibGreat(libusb_device_handle *handle, int timeout_ms = 2000)
        : handle_(handle), timeout_(timeout_ms) {}

    // Send a command (class_id + verb + payload) and receive response.
    // Returns response bytes.
    std::vector<uint8_t> call(uint32_t class_id,
                              uint32_t verb,
                              const std::vector<uint8_t> &payload = {},
                              size_t response_size = 512)
    {
        // Build command packet: [class_id:4][verb:4][payload]
        std::vector<uint8_t> cmd(8 + payload.size());
        write_le32(cmd.data() + 0, class_id);
        write_le32(cmd.data() + 4, verb);
        if (!payload.empty())
            std::memcpy(cmd.data() + 8, payload.data(), payload.size());

        // Send command over BULK OUT
        int transferred = 0;
        int r = libusb_bulk_transfer(handle_,
                                     LIBGREAT_EP_COMMAND_OUT,
                                     cmd.data(),
                                     static_cast<int>(cmd.size()),
                                     &transferred,
                                     timeout_);
        if (r < 0)
            throw std::runtime_error(
                std::string("libgreat TX error: ") + libusb_strerror(static_cast<libusb_error>(r)));

        // Receive response over BULK IN
        std::vector<uint8_t> resp(response_size);
        int rx = 0;
        r = libusb_bulk_transfer(handle_,
                                 LIBGREAT_EP_COMMAND_IN,
                                 resp.data(),
                                 static_cast<int>(resp.size()),
                                 &rx,
                                 timeout_);
        if (r < 0 && r != LIBUSB_ERROR_TIMEOUT)
            throw std::runtime_error(
                std::string("libgreat RX error: ") + libusb_strerror(static_cast<libusb_error>(r)));

        resp.resize(rx);
        return resp;
    }

    // Fire-and-forget (no response expected)
    void send(uint32_t class_id, uint32_t verb, const std::vector<uint8_t> &payload = {})
    {
        call(class_id, verb, payload, 0);
    }

private:
    libusb_device_handle *handle_;
    int timeout_;

    static void write_le32(uint8_t *dst, uint32_t v)
    {
        dst[0] = v & 0xff;
        dst[1] = (v >> 8) & 0xff;
        dst[2] = (v >> 16) & 0xff;
        dst[3] = (v >> 24) & 0xff;
    }
};