// proxy.cpp  ─  PTP transparent MITM proxy implementation

#include "proxy.hpp"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <cinttypes>
#include <ctime>

// ── Cynthion CONTROL port IDs (Facedancer bitstream) ──────────────────────

// ── open_cynthion ──────────────────────────────────────────────────────────
void PtpMitmProxy::open_cynthion()
{
    cynthion_handle_ = libusb_open_device_with_vid_pid(
        ctx_, CYNTHION_VID, CYNTHION_PID_FACEDANCER);
    if (!cynthion_handle_)
        throw std::runtime_error(
            "Cynthion not found (VID=1d50 PID=615b). "
            "Run: cynthion run facedancer");

    if (libusb_kernel_driver_active(cynthion_handle_, 0) == 1)
        libusb_detach_kernel_driver(cynthion_handle_, 0);
    int r = libusb_claim_interface(cynthion_handle_, 0);
    if (r < 0)
        throw std::runtime_error(
            std::string("Cannot claim Cynthion interface: ") +
            libusb_strerror((libusb_error)r));

    md_ = std::make_unique<Moondancer>(cynthion_handle_, usb_timeout_ms);
    printf("[proxy] Cynthion opened\n");
}

// ── open_camera ────────────────────────────────────────────────────────────
void PtpMitmProxy::open_camera()
{
    cam_handle_ = libusb_open_device_with_vid_pid(ctx_, cam_vid_, cam_pid_);
    if (!cam_handle_)
    {
        char buf[80];
        snprintf(buf, sizeof(buf),
                 "Camera not found (VID=%04x PID=%04x)", cam_vid_, cam_pid_);
        throw std::runtime_error(buf);
    }

    // Find PTP interface and endpoints
    libusb_device *dev = libusb_get_device(cam_handle_);
    libusb_config_descriptor *cfg = nullptr;
    libusb_get_active_config_descriptor(dev, &cfg);
    if (!cfg)
        throw std::runtime_error("Cannot get camera config descriptor");

    bool found = false;
    for (int i = 0; i < cfg->bNumInterfaces && !found; i++)
    {
        const auto &alt = cfg->interface[i].altsetting[0];
        // PTP/MTP interface class = 0x06 (Still Image)
        if (alt.bInterfaceClass != 0x06)
            continue;
        cam_iface_ = i;
        for (int e = 0; e < alt.bNumEndpoints; e++)
        {
            const auto &ep = alt.endpoint[e];
            uint8_t addr = ep.bEndpointAddress;
            uint8_t attr = ep.bmAttributes & 0x03;
            if (attr == 2)
            { // Bulk
                if (addr & 0x80)
                    cam_ep_.bulk_in = addr;
                else
                    cam_ep_.bulk_out = addr;
            }
            else if (attr == 3 && (addr & 0x80))
            { // Interrupt IN
                cam_ep_.intr_in = addr;
            }
        }
        found = true;
    }
    libusb_free_config_descriptor(cfg);
    if (!found)
        throw std::runtime_error("No PTP/Still-Image interface on camera");

    if (libusb_kernel_driver_active(cam_handle_, cam_iface_) == 1)
        libusb_detach_kernel_driver(cam_handle_, cam_iface_);
    libusb_claim_interface(cam_handle_, cam_iface_);

    printf("[proxy] Camera opened VID=%04x PID=%04x  "
           "bulk_in=0x%02x bulk_out=0x%02x intr=0x%02x\n",
           cam_vid_, cam_pid_,
           cam_ep_.bulk_in, cam_ep_.bulk_out, cam_ep_.intr_in);
}

// ── configure_moondancer_from_camera ──────────────────────────────────────
// Mirror the camera's endpoint layout onto the Cynthion TARGET port
// so that the iPad sees an identical USB device descriptor.
void PtpMitmProxy::configure_moondancer_from_camera()
{
    std::vector<EndpointDescriptor> eps;
    // Bulk IN  (camera→host direction, from iPad's perspective = IN)
    eps.push_back({cam_ep_.bulk_in, 512, 2}); // Bulk
    // Bulk OUT (host→camera, from iPad's perspective = OUT)
    eps.push_back({cam_ep_.bulk_out, 512, 2});
    // Interrupt IN for events
    eps.push_back({cam_ep_.intr_in, 64, 3}); // Interrupt
    md_->set_up_endpoints(eps);
    printf("[proxy] Moondancer endpoints configured to mirror camera\n");
}

// ── run ────────────────────────────────────────────────────────────────────
void PtpMitmProxy::run()
{
    open_log_file();
    open_cynthion();
    open_camera();
    configure_moondancer_from_camera();

    printf("[proxy] Connecting to iPad (TARGET port)...\n");
    md_->connect(USBSpeed::FULL_SPEED);
    printf("[proxy] Running. Ctrl-C to stop.\n");
    if (fuzzer_ && fuzzer_->enabled)
        printf("[proxy] FUZZING ENABLED\n");
    else
        printf("[proxy] Fuzzing disabled (passthrough mode)\n");

    event_loop();

    md_->disconnect();
    close_all();
}

void PtpMitmProxy::close_all()
{
    if (cam_handle_)
    {
        libusb_release_interface(cam_handle_, cam_iface_);
        libusb_close(cam_handle_);
        cam_handle_ = nullptr;
    }
    if (cynthion_handle_)
    {
        libusb_release_interface(cynthion_handle_, 0);
        libusb_close(cynthion_handle_);
        cynthion_handle_ = nullptr;
    }
    if (log_fp_)
    {
        fclose(log_fp_);
        log_fp_ = nullptr;
    }
}

// ── event_loop ─────────────────────────────────────────────────────────────
void PtpMitmProxy::event_loop()
{
    using namespace std::chrono_literals;
    while (running_)
    {
        auto ev = md_->get_interrupt();
        if (!ev)
        {
            std::this_thread::sleep_for(std::chrono::microseconds(50));
            continue;
        }
        switch (ev->irq)
        {
        case MdIrq::USB_BUS_RESET:
            printf("[proxy] BUS RESET\n");
            md_->bus_reset();
            break;
        case MdIrq::USB_RECEIVE_CONTROL:
            handle_receive_control(*ev);
            break;
        case MdIrq::USB_RECEIVE_PACKET:
            handle_receive_packet(*ev);
            break;
        case MdIrq::USB_EP_IN_NAK:
            handle_ep_in_nak(*ev);
            break;
        default:
            break;
        }
    }
}

// ── handle_receive_control ─────────────────────────────────────────────────
// Control transfer (EP0) – enumeration / SET_ADDRESS / class requests.
// We forward these to the camera verbatim (no fuzzing at this layer;
// the camera must enumerate correctly for the app to recognise it).
void PtpMitmProxy::handle_receive_control(const MdEvent &)
{
    auto raw = md_->read_control();
    if (raw.size() < 8)
    {
        md_->stall_endpoint(0);
        return;
    }

    auto *b = raw.data();
    uint8_t bmReq = b[0], bReq = b[1];
    uint16_t wVal = b[2] | ((uint16_t)b[3] << 8);
    uint16_t wIdx = b[4] | ((uint16_t)b[5] << 8);
    uint16_t wLen = b[6] | ((uint16_t)b[7] << 8);

    bool is_in = (bmReq & 0x80) != 0;

    if (is_in)
    {
        // Read from camera, forward to iPad
        std::vector<uint8_t> buf(wLen);
        int xferred = 0;
        libusb_control_transfer(cam_handle_, bmReq, bReq, wVal, wIdx,
                                buf.data(), wLen, usb_timeout_ms);
        buf.resize(std::max(0, xferred));
        md_->write_endpoint(0, buf);
    }
    else
    {
        // Read OUT data if any, forward to camera
        std::vector<uint8_t> out_data;
        if (wLen > 0)
            out_data = md_->read_endpoint(0, wLen);
        libusb_control_transfer(cam_handle_, bmReq, bReq, wVal, wIdx,
                                out_data.data(), (uint16_t)out_data.size(),
                                usb_timeout_ms);
        md_->ack_status_stage(0);
    }

    // Handle SET_ADDRESS
    if (bReq == 0x05 && (bmReq & 0x1f) == 0x00)
        md_->set_address(wVal & 0xff);
}

// ── handle_receive_packet ──────────────────────────────────────────────────
// Bulk OUT from iPad → a PTP command (or data phase of an OUT transaction).
// We buffer the raw bytes and kick off the full transaction.
void PtpMitmProxy::handle_receive_packet(const MdEvent &ev)
{
    uint8_t ep_num = ev.ep_num;
    auto raw = md_->read_endpoint(ep_num, 512);
    if (raw.size() < 12)
    {
        md_->prime_out_endpoint(ep_num);
        return;
    }

    // Parse to understand what phase this is
    auto pkt = PtpPacket::parse(raw);
    if (!pkt)
    {
        md_->prime_out_endpoint(ep_num);
        return;
    }

    if (pkt->type == PtpType::Command)
    {
        // ── Full PTP transaction ─────────────────────────────────────────
        // 1. Forward command to camera; get data+response back
        CamResult cam = forward_to_camera(raw);

        // 2. Parse camera packets for fuzzer
        std::optional<PtpPacket> data_pkt;
        if (cam.data)
            data_pkt = PtpPacket::parse(*cam.data);

        PtpPacket resp_pkt;
        auto rp = PtpPacket::parse(cam.response);
        if (rp)
            resp_pkt = *rp;
        else
        {
            resp_pkt.type = PtpType::Response;
            resp_pkt.code = (uint16_t)PtpResp::GeneralError;
            resp_pkt.txn = pkt->txn;
        }

        // 3. Run fuzzer
        PtpFuzzer::MutatedTxn mutated{data_pkt, resp_pkt,
                                      FuzzStrategy::PASSTHROUGH, ""};
        if (fuzzer_)
            mutated = fuzzer_->process(*pkt, data_pkt, resp_pkt);

        // 4. Send (possibly mutated) data phase to iPad
        if (mutated.data)
        {
            auto bytes = mutated.data->serialize();
            md_->write_endpoint(ep_num | 0x80, bytes); // IN endpoint
        }

        // 5. Send response phase to iPad
        {
            auto bytes = mutated.response.serialize();
            md_->write_endpoint(ep_num | 0x80, bytes);
        }

        // 6. Log the transaction
        TxnLog tl;
        tl.seq = ++seq_;
        tl.op_code = pkt->code;
        tl.op_name = ptp_op_name(pkt->code);
        tl.txn_id = pkt->txn;
        tl.fuzzed = mutated.applied != FuzzStrategy::PASSTHROUGH;
        tl.strategy = mutated.applied;
        tl.note = mutated.note;
        tl.data_len_real = cam.data ? cam.data->size() : 0;
        tl.data_len_sent = mutated.data ? mutated.data->payload.size() : 0;
        tl.resp_code_real = resp_pkt.code;
        tl.resp_code_sent = mutated.response.code;
        log_txn(tl);

        // 7. Record in corpus for REPLAY strategy
        if (fuzzer_)
        {
            RecordedTransaction rec;
            rec.op_code = pkt->code;
            rec.command = *pkt;
            rec.data_in = data_pkt;
            rec.response = resp_pkt;
            fuzzer_->record(rec);
        }
    }

    md_->prime_out_endpoint(ep_num);
}

// ── handle_ep_in_nak ───────────────────────────────────────────────────────
// iPad is polling an IN endpoint (e.g. interrupt event endpoint).
// Forward any pending event from the camera.
void PtpMitmProxy::handle_ep_in_nak(const MdEvent &ev)
{
    // Read from camera's interrupt endpoint (non-blocking, short timeout)
    uint8_t buf[64] = {};
    int xferred = 0;
    int r = libusb_interrupt_transfer(cam_handle_, cam_ep_.intr_in,
                                      buf, sizeof(buf), &xferred, 10);
    if (r == 0 && xferred > 0)
    {
        std::vector<uint8_t> data(buf, buf + xferred);
        md_->write_endpoint(ev.ep_num, data);
    }
    // If nothing, just let the iPad NAK (no-op)
}

// ── forward_to_camera ──────────────────────────────────────────────────────
PtpMitmProxy::CamResult
PtpMitmProxy::forward_to_camera(const std::vector<uint8_t> &cmd_bytes)
{
    CamResult result;

    // Send command to camera
    cam_bulk_write(cmd_bytes);

    // Check if this is a command that has an OUT data phase
    // (app is sending data to camera, e.g. SendObject)
    // In that case we'll receive data from iPad first — but for MITM we
    // forward the camera's responses, so we read the IN data from camera.

    // Read first response packet from camera (may be DATA or RESPONSE)
    auto first = cam_bulk_read(65536 + 12);
    if (first.size() < 12)
    {
        // timeout or error → synthesise error response
        PtpHeader h{};
        const auto *ch = reinterpret_cast<const PtpHeader *>(cmd_bytes.data());
        h.length = 12;
        h.type = (uint16_t)PtpType::Response;
        h.code = (uint16_t)PtpResp::GeneralError;
        h.txn = ch->txn;
        result.response.resize(12);
        memcpy(result.response.data(), &h, 12);
        return result;
    }

    auto first_type = static_cast<PtpType>(
        reinterpret_cast<const PtpHeader *>(first.data())->type);

    if (first_type == PtpType::Data)
    {
        // DATA phase followed by RESPONSE phase
        result.data = first;
        result.response = cam_bulk_read(256);
    }
    else
    {
        // RESPONSE phase directly (no data)
        result.response = first;
    }

    return result;
}

// ── Camera bulk helpers ────────────────────────────────────────────────────
std::vector<uint8_t> PtpMitmProxy::cam_bulk_read(size_t max_len)
{
    std::vector<uint8_t> buf(max_len);
    int xferred = 0;
    libusb_bulk_transfer(cam_handle_, cam_ep_.bulk_in,
                         buf.data(), (int)max_len,
                         &xferred, usb_timeout_ms);
    buf.resize(std::max(0, xferred));
    return buf;
}

void PtpMitmProxy::cam_bulk_write(const std::vector<uint8_t> &data)
{
    int xferred = 0;
    libusb_bulk_transfer(cam_handle_, cam_ep_.bulk_out,
                         const_cast<uint8_t *>(data.data()),
                         (int)data.size(),
                         &xferred, usb_timeout_ms);
}

// ── Logging ────────────────────────────────────────────────────────────────
void PtpMitmProxy::open_log_file()
{
    if (log_path_.empty())
        return;
    log_fp_ = fopen(log_path_.c_str(), "a");
    if (!log_fp_)
        fprintf(stderr, "[proxy] Warning: cannot open log file %s\n",
                log_path_.c_str());
}

void PtpMitmProxy::log_txn(const TxnLog &t)
{
    // Console output
    const char *fuzz_mark = t.fuzzed ? " *** FUZZED ***" : "";
    printf("[%4u] txn=%-4u  %-22s (0x%04x)  "
           "data=%zu→%zu  resp=0x%04x→0x%04x%s",
           t.seq, t.txn_id, t.op_name, t.op_code,
           t.data_len_real, t.data_len_sent,
           t.resp_code_real, t.resp_code_sent,
           fuzz_mark);
    if (!t.note.empty())
        printf("  [%s]", t.note.c_str());
    if (t.fuzzed)
        printf("  strategy=%s", fuzz_strategy_name(t.strategy));
    printf("\n");

    // JSONL log file
    if (!log_fp_)
        return;
    time_t now = time(nullptr);
    fprintf(log_fp_,
            "{\"seq\":%u,\"ts\":%ld,\"txn\":%u,\"op\":\"0x%04x\","
            "\"op_name\":\"%s\",\"data_real\":%zu,\"data_sent\":%zu,"
            "\"resp_real\":\"0x%04x\",\"resp_sent\":\"0x%04x\","
            "\"fuzzed\":%s,\"strategy\":\"%s\",\"note\":\"%s\"}\n",
            t.seq, (long)now, t.txn_id, t.op_code, t.op_name,
            t.data_len_real, t.data_len_sent,
            t.resp_code_real, t.resp_code_sent,
            t.fuzzed ? "true" : "false",
            fuzz_strategy_name(t.strategy),
            t.note.c_str());
    fflush(log_fp_);

    // Notify callback
    if (log_cb_)
        log_cb_(t);
}