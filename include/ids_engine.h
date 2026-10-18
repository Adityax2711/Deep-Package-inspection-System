#ifndef IDS_ENGINE_H
#define IDS_ENGINE_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <set>
#include <deque>
#include <chrono>
#include <mutex>
#include <atomic>
#include <cmath>
#include <memory>
#include <iostream>
#include <iomanip>
#include "types.h"

namespace DPI {

// ============================================================================
// Security Alert Definition
// ============================================================================
enum class AlertType {
    PORT_SCAN,
    SYN_FLOOD,
    DNS_TUNNELING,
    TCP_ANOMALY
};

inline std::string alertTypeToString(AlertType type) {
    switch (type) {
        case AlertType::PORT_SCAN:     return "PORT_SCAN";
        case AlertType::SYN_FLOOD:    return "SYN_FLOOD";
        case AlertType::DNS_TUNNELING: return "DNS_TUNNELING";
        case AlertType::TCP_ANOMALY:   return "TCP_ANOMALY";
        default:                      return "UNKNOWN_ALERT";
    }
}

struct SecurityAlert {
    uint64_t timestamp_sec;
    uint32_t timestamp_usec;
    AlertType type;
    std::string source_ip;
    std::string dest_ip;
    uint16_t dest_port;
    std::string details;
    bool auto_blocked = false;
};

// ============================================================================
// 1. SYN Flood & Port Scan Detector (Embryonic Connection Tracker)
// ============================================================================
class SynTracker {
public:
    struct Config {
        int window_seconds = 3;           // Time window to monitor
        int port_scan_threshold = 12;     // Distinct destination ports in window
        int syn_flood_threshold = 40;     // Total unacknowledged SYNs in window
    };

    SynTracker();
    explicit SynTracker(const Config& config);

    // Record an incoming SYN packet. Returns true if an alert is triggered.
    bool recordSyn(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                   uint64_t ts_sec, SecurityAlert& alert);

    // Record an ACK / Handshake completion to remove from embryonic count
    void recordAck(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port);

    // Clean up expired history
    void cleanup(uint64_t current_ts_sec);

    const Config& getConfig() const { return config_; }

private:
    struct SynEvent {
        uint64_t ts_sec;
        uint32_t dst_ip;
        uint16_t dst_port;
    };

    struct IPActivity {
        std::deque<SynEvent> syn_events;
        std::set<uint16_t> active_ports;
        bool flagged_port_scan = false;
        bool flagged_syn_flood = false;
    };

    Config config_;
    std::mutex mutex_;
    std::unordered_map<uint32_t, IPActivity> activity_;
};

// ============================================================================
// 2. DNS Tunneling Detector (Shannon Entropy & Length Analysis)
// ============================================================================
class DNSTunnelDetector {
public:
    struct Config {
        double max_entropy = 3.65;        // Threshold for Shannon entropy
        size_t max_query_length = 45;     // Threshold for total query length
        size_t max_label_length = 24;     // Threshold for single label length
        size_t max_subdomains = 4;        // Maximum subdomain nesting depth
    };

    DNSTunnelDetector();
    explicit DNSTunnelDetector(const Config& config);

    // Calculate Shannon entropy of a string: H(X) = -sum(p * log2(p))
    static double calculateEntropy(const std::string& str);

    // Inspect a domain extracted from a DNS query. Returns true if suspicious tunneling.
    bool inspectDomain(const std::string& domain, const std::string& src_ip,
                       uint64_t ts_sec, uint32_t ts_usec, SecurityAlert& alert);

    const Config& getConfig() const { return config_; }

private:
    Config config_;
    std::mutex mutex_;
};

// ============================================================================
// 3. TCP Out-of-Order & Reassembly Engine
// ============================================================================
class TCPReassembler {
public:
    struct Segment {
        uint32_t seq;
        std::vector<uint8_t> data;
    };

    struct StreamState {
        uint32_t expected_seq = 0;
        bool initialized = false;
        uint64_t in_order_packets = 0;
        uint64_t out_of_order_packets = 0;
        uint64_t retransmissions = 0;
        std::map<uint32_t, std::vector<uint8_t>> pending_segments; // Keyed by seq
        std::vector<uint8_t> assembled_buffer; // Contiguous reassembled payload
    };

    TCPReassembler(size_t max_buffer_per_flow = 65536)
        : max_buffer_per_flow_(max_buffer_per_flow) {}

    // Process a TCP segment for a given flow tuple.
    // Returns any newly available contiguous payload chunk.
    std::vector<uint8_t> processSegment(const FiveTuple& tuple, uint32_t seq,
                                       const uint8_t* payload, size_t length,
                                       bool syn_flag, bool fin_flag);

    // Get statistics for a flow
    bool getStreamStats(const FiveTuple& tuple, uint64_t& in_order,
                        uint64_t& out_of_order, uint64_t& retransmits) const;

    uint64_t getTotalOutOfOrder() const { return total_out_of_order_; }
    uint64_t getTotalRetransmissions() const { return total_retransmits_; }
    uint64_t getTotalReassembledStreams() const { return total_reassembled_streams_; }

private:
    size_t max_buffer_per_flow_;
    mutable std::mutex mutex_;
    std::unordered_map<FiveTuple, StreamState, FiveTupleHash> streams_;
    std::atomic<uint64_t> total_out_of_order_{0};
    std::atomic<uint64_t> total_retransmits_{0};
    std::atomic<uint64_t> total_reassembled_streams_{0};
};

// ============================================================================
// Main IDS Engine (Orchestrator for Security & Anomaly Detection)
// ============================================================================
class IDSEngine {
public:
    struct Config {
        bool enable_syn_flood_detection = true;
        bool enable_port_scan_detection = true;
        bool enable_dns_tunnel_detection = true;
        bool enable_tcp_reassembly = true;
        bool auto_block_attackers = true;
        SynTracker::Config syn_config;
        DNSTunnelDetector::Config dns_config;
    };

    IDSEngine();
    explicit IDSEngine(const Config& config);

    // Inspect incoming packet for threats
    void inspectPacket(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                       uint16_t dst_port, uint8_t protocol, uint8_t tcp_flags,
                       uint32_t seq, const uint8_t* payload, size_t payload_len,
                       uint64_t ts_sec, uint32_t ts_usec);

    // Inspect DNS domain specifically
    void inspectDNSQuery(const std::string& domain, const std::string& src_ip,
                         uint64_t ts_sec, uint32_t ts_usec);

    // Check if an IP has been auto-blacklisted by IDS
    bool isAutoBlocked(uint32_t ip) const;

    // Get list of all generated alerts
    std::vector<SecurityAlert> getAlerts() const;

    // Accessors
    TCPReassembler& getReassembler() { return reassembler_; }
    const Config& getConfig() const { return config_; }

    // Print IDS Security Report
    void printReport() const;

private:
    Config config_;
    SynTracker syn_tracker_;
    DNSTunnelDetector dns_detector_;
    TCPReassembler reassembler_;

    mutable std::mutex alerts_mutex_;
    std::vector<SecurityAlert> alerts_;
    std::set<uint32_t> auto_blocked_ips_;

    void emitAlert(const SecurityAlert& alert);
};

} // namespace DPI

#endif // IDS_ENGINE_H
