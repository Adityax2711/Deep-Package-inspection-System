#ifndef LIVE_CAPTURE_H
#define LIVE_CAPTURE_H

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <cstdint>
#include "pcap_reader.h"

namespace DPI {

struct LiveInterface {
    int index;
    std::string name;
    std::string description;
    std::string ip_address;
    std::string mac_address;
    bool is_up = false;
};

// Callback type when a live packet is captured
using LivePacketCallback = std::function<void(const PacketAnalyzer::RawPacket&)>;

class LiveCapture {
public:
    enum class Backend {
        AUTO,
        RAW_SOCKET,
        NPCAP
    };

    LiveCapture();
    ~LiveCapture();

    // List all network interfaces available on this machine
    static std::vector<LiveInterface> listInterfaces();

    // Open live capture on an interface (by index or IPv4 address)
    bool open(const std::string& interface_ip_or_name, Backend backend = Backend::AUTO);

    // Start capturing packets asynchronously
    bool startCapture(LivePacketCallback callback, int max_packets = 0);

    // Stop capturing
    void stopCapture();

    // Check if capture is running
    bool isRunning() const { return running_; }

    // Get statistics
    uint64_t getCapturedPackets() const { return captured_packets_; }
    uint64_t getCapturedBytes() const { return captured_bytes_; }
    std::string getActiveBackendName() const;

private:
    std::atomic<bool> running_{false};
    std::thread capture_thread_;
    std::atomic<uint64_t> captured_packets_{0};
    std::atomic<uint64_t> captured_bytes_{0};

    LiveInterface selected_interface_;
    Backend active_backend_ = Backend::RAW_SOCKET;

    // Platform-specific socket handle / pointer
    uintptr_t raw_socket_handle_ = 0;
    void* npcap_handle_ = nullptr;

    bool initWinsock();
    bool openRawSocket(const std::string& ip);
    bool openNpcap(const std::string& dev_name);
    void captureLoopRawSocket(LivePacketCallback callback, int max_packets);
    void captureLoopNpcap(LivePacketCallback callback, int max_packets);
};

} // namespace DPI

#endif // LIVE_CAPTURE_H
