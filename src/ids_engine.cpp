#include "ids_engine.h"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>

namespace DPI {

// Helper to convert uint32 IPv4 to string matching internal little-endian octet layout
static std::string ipToString(uint32_t ip) {
    std::ostringstream oss;
    oss << (ip & 0xFF) << "."
        << ((ip >> 8)  & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 24) & 0xFF);
    return oss.str();
}

// ============================================================================
// 1. SynTracker Implementation
// ============================================================================
SynTracker::SynTracker() : config_() {}
SynTracker::SynTracker(const Config& config) : config_(config) {}

bool SynTracker::recordSyn(uint32_t src_ip, uint32_t dst_ip, uint16_t dst_port,
                           uint64_t ts_sec, SecurityAlert& alert) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Periodic cleanup of expired events
    cleanup(ts_sec);

    auto& act = activity_[src_ip];
    act.syn_events.push_back({ts_sec, dst_ip, dst_port});
    act.active_ports.insert(dst_port);

    // Check Port Scan: Probing many distinct destination ports in the window
    if (!act.flagged_port_scan &&
        act.active_ports.size() >= static_cast<size_t>(config_.port_scan_threshold)) {
        act.flagged_port_scan = true;
        alert.timestamp_sec = ts_sec;
        alert.timestamp_usec = 0;
        alert.type = AlertType::PORT_SCAN;
        alert.source_ip = ipToString(src_ip);
        alert.dest_ip = ipToString(dst_ip);
        alert.dest_port = dst_port;
        alert.auto_blocked = true;

        std::ostringstream oss;
        oss << "Scanned " << act.active_ports.size() << " distinct ports within "
            << config_.window_seconds << "s window";
        alert.details = oss.str();
        return true;
    }

    // Check SYN Flood: Flooding unanswered SYNs in the window
    if (!act.flagged_syn_flood &&
        act.syn_events.size() >= static_cast<size_t>(config_.syn_flood_threshold)) {
        act.flagged_syn_flood = true;
        alert.timestamp_sec = ts_sec;
        alert.timestamp_usec = 0;
        alert.type = AlertType::SYN_FLOOD;
        alert.source_ip = ipToString(src_ip);
        alert.dest_ip = ipToString(dst_ip);
        alert.dest_port = dst_port;
        alert.auto_blocked = true;

        std::ostringstream oss;
        oss << "Sent " << act.syn_events.size() << " unacknowledged SYNs in "
            << config_.window_seconds << "s window (possible DoS)";
        alert.details = oss.str();
        return true;
    }

    return false;
}

void SynTracker::recordAck(uint32_t src_ip, uint32_t /*dst_ip*/, uint16_t /*dst_port*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = activity_.find(src_ip);
    if (it != activity_.end()) {
        if (!it->second.syn_events.empty()) {
            it->second.syn_events.pop_front();
        }
    }
}

void SynTracker::cleanup(uint64_t current_ts_sec) {
    if (current_ts_sec < static_cast<uint64_t>(config_.window_seconds)) return;
    uint64_t cutoff = current_ts_sec - static_cast<uint64_t>(config_.window_seconds);

    for (auto it = activity_.begin(); it != activity_.end();) {
        auto& events = it->second.syn_events;
        while (!events.empty() && events.front().ts_sec < cutoff) {
            events.pop_front();
        }

        // Recompute active ports
        it->second.active_ports.clear();
        for (const auto& ev : events) {
            it->second.active_ports.insert(ev.dst_port);
        }

        if (events.empty() && !it->second.flagged_port_scan && !it->second.flagged_syn_flood) {
            it = activity_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// 2. DNSTunnelDetector Implementation
// ============================================================================
// 2. DNSTunnelDetector Implementation
// ============================================================================
DNSTunnelDetector::DNSTunnelDetector() : config_() {}
DNSTunnelDetector::DNSTunnelDetector(const Config& config) : config_(config) {}

double DNSTunnelDetector::calculateEntropy(const std::string& str) {
    if (str.empty()) return 0.0;

    std::unordered_map<char, int> freq;
    for (char c : str) {
        freq[c]++;
    }

    double entropy = 0.0;
    double len = static_cast<double>(str.length());

    for (const auto& pair : freq) {
        double p = static_cast<double>(pair.second) / len;
        entropy -= p * (std::log(p) / std::log(2.0));
    }

    return entropy;
}

bool DNSTunnelDetector::inspectDomain(const std::string& domain, const std::string& src_ip,
                                     uint64_t ts_sec, uint32_t ts_usec, SecurityAlert& alert) {
    if (domain.empty()) return false;

    std::lock_guard<std::mutex> lock(mutex_);

    // Split domain into labels
    std::vector<std::string> labels;
    std::stringstream ss(domain);
    std::string item;
    size_t max_label = 0;

    while (std::getline(ss, item, '.')) {
        if (!item.empty()) {
            labels.push_back(item);
            if (item.length() > max_label) {
                max_label = item.length();
            }
        }
    }

    // Calculate entropy of domain without dots
    std::string clean_domain;
    for (const auto& l : labels) clean_domain += l;

    double entropy = calculateEntropy(clean_domain);

    // Detection heuristics for DNS tunneling:
    // 1. Long label (e.g. Base64/Hex payload chunk > 24 chars) AND high entropy > 3.65
    // 2. Or total length > 45 chars AND entropy > 3.75
    // 3. Or subdomain nesting depth > 4 with elevated entropy
    bool is_tunnel = false;
    std::string reason;

    if (max_label >= config_.max_label_length && entropy >= config_.max_entropy) {
        is_tunnel = true;
        reason = "Abnormally long encoded label with high entropy";
    } else if (domain.length() >= config_.max_query_length && entropy >= config_.max_entropy) {
        is_tunnel = true;
        reason = "Excessive query length with high entropy";
    } else if (labels.size() > config_.max_subdomains && entropy >= 3.8) {
        is_tunnel = true;
        reason = "Deeply nested subdomain structure with high entropy";
    }

    if (is_tunnel) {
        alert.timestamp_sec = ts_sec;
        alert.timestamp_usec = ts_usec;
        alert.type = AlertType::DNS_TUNNELING;
        alert.source_ip = src_ip;
        alert.dest_ip = "DNS Server";
        alert.dest_port = 53;
        alert.auto_blocked = true;

        std::ostringstream oss;
        oss << reason << " (Domain: \"" << domain << "\", Entropy: " 
            << std::fixed << std::setprecision(2) << entropy 
            << ", MaxLabel: " << max_label << ", TotalLen: " << domain.length() << ")";
        alert.details = oss.str();
        return true;
    }

    return false;
}

// ============================================================================
// 3. TCPReassembler Implementation
// ============================================================================
std::vector<uint8_t> TCPReassembler::processSegment(const FiveTuple& tuple, uint32_t seq,
                                                   const uint8_t* payload, size_t length,
                                                   bool syn_flag, bool fin_flag) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& stream = streams_[tuple];
    std::vector<uint8_t> newly_assembled;

    if (syn_flag || !stream.initialized) {
        stream.initialized = true;
        stream.expected_seq = seq + (syn_flag ? 1 : 0);
        if (length == 0) return newly_assembled;
    }

    if (length == 0) return newly_assembled;

    // Case 1: In-order segment
    if (seq == stream.expected_seq) {
        stream.in_order_packets++;
        newly_assembled.insert(newly_assembled.end(), payload, payload + length);
        stream.expected_seq += static_cast<uint32_t>(length);

        // Check if any pending out-of-order segments can now be stitched in
        while (!stream.pending_segments.empty()) {
            auto it = stream.pending_segments.begin();
            if (it->first == stream.expected_seq) {
                newly_assembled.insert(newly_assembled.end(), it->second.begin(), it->second.end());
                stream.expected_seq += static_cast<uint32_t>(it->second.size());
                stream.pending_segments.erase(it);
                total_reassembled_streams_++;
            } else if (it->first < stream.expected_seq) {
                // Overlapping or already covered segment
                stream.pending_segments.erase(it);
            } else {
                // Gap still exists
                break;
            }
        }
    }
    // Case 2: Out-of-order future segment (seq > expected_seq)
    else if (seq > stream.expected_seq) {
        stream.out_of_order_packets++;
        total_out_of_order_++;

        // Buffer the segment if under max flow memory limit
        size_t current_buffered = 0;
        for (const auto& p : stream.pending_segments) current_buffered += p.second.size();

        if (current_buffered + length <= max_buffer_per_flow_) {
            stream.pending_segments[seq] = std::vector<uint8_t>(payload, payload + length);
        }
    }
    // Case 3: Retransmission or duplicate (seq < expected_seq)
    else {
        stream.retransmissions++;
        total_retransmits_++;
    }

    if (fin_flag) {
        // Stream completed
        streams_.erase(tuple);
    }

    return newly_assembled;
}

bool TCPReassembler::getStreamStats(const FiveTuple& tuple, uint64_t& in_order,
                                    uint64_t& out_of_order, uint64_t& retransmits) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = streams_.find(tuple);
    if (it == streams_.end()) return false;
    in_order = it->second.in_order_packets;
    out_of_order = it->second.out_of_order_packets;
    retransmits = it->second.retransmissions;
    return true;
}

// ============================================================================
// 4. Main IDSEngine Implementation
// ============================================================================
IDSEngine::IDSEngine()
    : config_(),
      syn_tracker_(config_.syn_config),
      dns_detector_(config_.dns_config) {}

IDSEngine::IDSEngine(const Config& config)
    : config_(config),
      syn_tracker_(config.syn_config),
      dns_detector_(config.dns_config) {}

void IDSEngine::inspectPacket(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                              uint16_t dst_port, uint8_t protocol, uint8_t tcp_flags,
                              uint32_t seq, const uint8_t* payload, size_t payload_len,
                              uint64_t ts_sec, uint32_t ts_usec) {
    // 1. TCP Analysis
    if (protocol == 6) { // TCP
        bool syn = (tcp_flags & 0x02) != 0;
        bool ack = (tcp_flags & 0x10) != 0;
        bool fin = (tcp_flags & 0x01) != 0;

        // Port Scan and SYN Flood checking
        if (config_.enable_syn_flood_detection || config_.enable_port_scan_detection) {
            if (syn && !ack) {
                SecurityAlert alert;
                if (syn_tracker_.recordSyn(src_ip, dst_ip, dst_port, ts_sec, alert)) {
                    emitAlert(alert);
                }
            } else if (ack) {
                syn_tracker_.recordAck(src_ip, dst_ip, dst_port);
            }
        }

        // TCP Reassembly & Out-of-order tracking
        if (config_.enable_tcp_reassembly && payload_len > 0) {
            FiveTuple tuple{src_ip, dst_ip, src_port, dst_port, protocol};
            reassembler_.processSegment(tuple, seq, payload, payload_len, syn, fin);
        }
    }
}

void IDSEngine::inspectDNSQuery(const std::string& domain, const std::string& src_ip,
                                uint64_t ts_sec, uint32_t ts_usec) {
    if (!config_.enable_dns_tunnel_detection) return;

    SecurityAlert alert;
    if (dns_detector_.inspectDomain(domain, src_ip, ts_sec, ts_usec, alert)) {
        emitAlert(alert);
    }
}

void IDSEngine::emitAlert(const SecurityAlert& alert) {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    alerts_.push_back(alert);

    // Auto-blacklist IP if configured
    if (config_.auto_block_attackers && alert.auto_blocked) {
        // Parse IP to uint32
        auto parseIP = [](const std::string& ip_str) -> uint32_t {
            uint32_t a, b, c, d;
            char dot;
            std::istringstream iss(ip_str);
            if (iss >> a >> dot >> b >> dot >> c >> dot >> d) {
                return a | (b << 8) | (c << 16) | (d << 24);
            }
            return 0;
        };
        auto raw_ip = parseIP(alert.source_ip);
        if (raw_ip != 0) {
            auto_blocked_ips_.insert(raw_ip);
        }
    }

    // Print immediate red alert banner in terminal
    std::cout << "\n\033[1;31m[IDS ALERT - " << alertTypeToString(alert.type) << "]\033[0m\n"
              << "  Source:      " << alert.source_ip << "\n"
              << "  Target:      " << alert.dest_ip << ":" << alert.dest_port << "\n"
              << "  Details:     " << alert.details << "\n"
              << "  Action:      \033[1;33m" 
              << (alert.auto_blocked ? "BLOCKED (Source auto-blacklisted)" : "FLAGGED") 
              << "\033[0m\n";
}

bool IDSEngine::isAutoBlocked(uint32_t ip) const {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    return auto_blocked_ips_.count(ip) > 0;
}

std::vector<SecurityAlert> IDSEngine::getAlerts() const {
    std::lock_guard<std::mutex> lock(alerts_mutex_);
    return alerts_;
}

void IDSEngine::printReport() const {
    std::lock_guard<std::mutex> lock(alerts_mutex_);

    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                 IDS / IPS SECURITY REPORT                    ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║ Total Security Alerts:        " << std::setw(6) << alerts_.size() << "                         ║\n";
    std::cout << "║ Auto-Blacklisted Attackers:   " << std::setw(6) << auto_blocked_ips_.size() << "                         ║\n";
    std::cout << "║ TCP Out-of-Order Packets:     " << std::setw(6) << reassembler_.getTotalOutOfOrder() << "                         ║\n";
    std::cout << "║ TCP Retransmissions:          " << std::setw(6) << reassembler_.getTotalRetransmissions() << "                         ║\n";
    std::cout << "║ TCP Stream Reassemblies:      " << std::setw(6) << reassembler_.getTotalReassembledStreams() << "                         ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";

    if (alerts_.empty()) {
        std::cout << "║ [Status] No suspicious intrusions or anomalies detected.     ║\n";
    } else {
        std::cout << "║ RECENT DETECTED THREATS:                                     ║\n";
        for (size_t i = 0; i < std::min(alerts_.size(), static_cast<size_t>(8)); i++) {
            const auto& a = alerts_[i];
            std::cout << "║ • [" << alertTypeToString(a.type) << "] " 
                      << std::setw(15) << a.source_ip << " -> " << a.details.substr(0, 32) << "... ║\n";
        }
    }
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

} // namespace DPI
