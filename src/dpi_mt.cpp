// Multi-threaded DPI Engine with IDS / IPS & Live Sniffing
// Architecture: Reader/LiveCapture -> LB threads -> FP threads -> Output

#include <iostream>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>
#include <csignal>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"
#include "ids_engine.h"
#include "live_capture.h"

using namespace PacketAnalyzer;
using namespace DPI;

// Global flag for graceful Ctrl+C interruption
static std::atomic<bool> g_stop_requested{false};

void signalHandler(int) {
    g_stop_requested = true;
}

// =============================================================================
// Thread-Safe Queue
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 10000) : max_size_(max_size), shutdown_(false) {}
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                  [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    bool is_shutdown() const { return shutdown_; }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    std::atomic<bool> shutdown_;
};

// =============================================================================
// Packet Job - Contains all packet data (self-contained, no pointers)
// =============================================================================
struct Packet {
    uint32_t id;
    uint32_t ts_sec;
    uint32_t ts_usec;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags = 0;
    uint32_t seq = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
};

// =============================================================================
// Flow Entry
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool blocked = false;
    bool classified = false;
};

// =============================================================================
// Blocking Rules
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP(ip));
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }
    
    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked app: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown app: " << app << "\n";
    }
    
    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_domains_.push_back(domain);
        std::cout << "[Rules] Blocked domain: " << domain << "\n";
    }
    
    bool isBlocked(uint32_t src_ip, AppType app, const std::string& sni) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (blocked_ips_.count(src_ip)) return true;
        if (blocked_apps_.count(app)) return true;
        for (const auto& dom : blocked_domains_) {
            if (sni.find(dom) != std::string::npos) return true;
        }
        return false;
    }

private:
    static uint32_t parseIP(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }
    
    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
};

// =============================================================================
// Statistics
// =============================================================================
struct Stats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};
    
    std::mutex app_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::vector<std::pair<std::string, AppType>> detected_snis;
    
    void recordApp(AppType app, const std::string& sni) {
        std::lock_guard<std::mutex> lock(app_mutex);
        app_counts[app]++;
        if (!sni.empty()) {
            bool found = false;
            for (const auto& [s, _] : detected_snis) {
                if (s == sni) { found = true; break; }
            }
            if (!found) {
                detected_snis.push_back({sni, app});
            }
        }
    }
};

// =============================================================================
// Fast Path (Worker thread)
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, Stats* stats, IDSEngine* ids, TSQueue<Packet>* output_queue)
        : id_(id), rules_(rules), stats_(stats), ids_(ids), output_queue_(output_queue) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    uint64_t processed() const { return processed_; }

private:
    int id_;
    Rules* rules_;
    Stats* stats_;
    IDSEngine* ids_;
    TSQueue<Packet>* output_queue_;
    TSQueue<Packet> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, FiveTupleHash> flows_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    
    static std::string ipToStr(uint32_t ip) {
        return std::to_string(ip & 0xFF) + "." +
               std::to_string((ip >> 8) & 0xFF) + "." +
               std::to_string((ip >> 16) & 0xFF) + "." +
               std::to_string((ip >> 24) & 0xFF);
    }
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            processed_++;
            Packet& pkt = *pkt_opt;
            
            // Check IDS Auto-Blacklist (Instant drop if IP was blacklisted by IDS)
            if (ids_ && ids_->isAutoBlocked(pkt.tuple.src_ip)) {
                stats_->dropped++;
                continue;
            }
            
            // Get or create flow
            FlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets == 0) {
                flow.tuple = pkt.tuple;
            }
            flow.packets++;
            flow.bytes += pkt.data.size();
            
            // Inspect with IDS / IPS Engine (SYN Flood, Port Scan, TCP Reassembly)
            const uint8_t* payload_ptr = pkt.data.data() + pkt.payload_offset;
            if (ids_) {
                ids_->inspectPacket(pkt.tuple.src_ip, pkt.tuple.dst_ip,
                                    pkt.tuple.src_port, pkt.tuple.dst_port,
                                    pkt.tuple.protocol, pkt.tcp_flags,
                                    pkt.seq, payload_ptr, pkt.payload_length,
                                    pkt.ts_sec, pkt.ts_usec);
            }
            
            // Try to classify if not done yet
            if (!flow.classified) {
                classifyFlow(pkt, flow);
            }
            
            // Check blocking rules
            if (!flow.blocked) {
                flow.blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni);
            }
            
            // Also check if IDS flagged it
            if (!flow.blocked && ids_ && ids_->isAutoBlocked(pkt.tuple.src_ip)) {
                flow.blocked = true;
            }
            
            // Record stats
            stats_->recordApp(flow.app_type, flow.sni);
            
            // Forward or drop
            if (flow.blocked) {
                stats_->dropped++;
            } else {
                stats_->forwarded++;
                output_queue_->push(std::move(pkt));
            }
        }
    }
    
    void classifyFlow(Packet& pkt, FlowEntry& flow) {
        const uint8_t* payload = pkt.data.data() + pkt.payload_offset;

        // Try SNI extraction for HTTPS
        if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
            auto sni = SNIExtractor::extract(payload, pkt.payload_length);
            if (sni) {
                flow.sni = *sni;
                flow.app_type = sniToAppType(*sni);
                flow.classified = true;
                return;
            }
        }
        
        // Try HTTP Host extraction
        if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
            auto host = HTTPHostExtractor::extract(payload, pkt.payload_length);
            if (host) {
                flow.sni = *host;
                flow.app_type = sniToAppType(*host);
                flow.classified = true;
                return;
            }
        }
        
        // DNS inspection + DNS Tunneling Detection
        if (pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) {
            flow.app_type = AppType::DNS;
            flow.classified = true;
            
            if (pkt.payload_length > 12) {
                auto domain_opt = DNSExtractor::extractQuery(payload, pkt.payload_length);
                if (domain_opt) {
                    flow.sni = *domain_opt;
                    if (ids_) {
                        ids_->inspectDNSQuery(*domain_opt, ipToStr(pkt.tuple.src_ip),
                                              pkt.ts_sec, pkt.ts_usec);
                    }
                }
            }
            return;
        }
        
        // Port-based fallback
        if (pkt.tuple.dst_port == 443) {
            flow.app_type = AppType::HTTPS;
        } else if (pkt.tuple.dst_port == 80) {
            flow.app_type = AppType::HTTP;
        }
    }
};

// =============================================================================
// Load Balancer (one per LB thread)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    uint64_t dispatched() const { return dispatched_; }

private:
    int id_;
    std::vector<FastPath*> fps_;
    size_t num_fps_;
    TSQueue<Packet> input_queue_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            FiveTupleHash hasher;
            size_t fp_idx = hasher(pkt_opt->tuple) % num_fps_;
            fps_[fp_idx]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// DPI Engine Orchestrator
// =============================================================================
class DPIEngine {
public:
    struct Config {
        int num_lbs = 2;
        int fps_per_lb = 2;
        IDSEngine::Config ids_config;
    };
    
    DPIEngine(const Config& cfg) : config_(cfg), ids_engine_(cfg.ids_config) {
        int total_fps = cfg.num_lbs * cfg.fps_per_lb;
        
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║         DPI ENGINE v2.5 (Multi-threaded + IDS/IPS)            ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Load Balancers: " << std::setw(2) << cfg.num_lbs 
                  << "    FPs per LB: " << std::setw(2) << cfg.fps_per_lb
                  << "    Total FPs: " << std::setw(2) << total_fps << "     ║\n";
        std::cout << "║ Security Suite: SYN Flood, Port Scan, DNS Tunneling, TCP OOO ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
        
        // Create FP threads
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(i, &rules_, &stats_, &ids_engine_, &output_queue_));
        }
        
        // Create LB threads
        for (int lb = 0; lb < cfg.num_lbs; lb++) {
            std::vector<FastPath*> lb_fps;
            int start = lb * cfg.fps_per_lb;
            for (int i = 0; i < cfg.fps_per_lb; i++) {
                lb_fps.push_back(fps_[start + i].get());
            }
            lbs_.push_back(std::make_unique<LoadBalancer>(lb, std::move(lb_fps)));
        }
    }
    
    void blockIP(const std::string& ip) { rules_.blockIP(ip); }
    void blockApp(const std::string& app) { rules_.blockApp(app); }
    void blockDomain(const std::string& dom) { rules_.blockDomain(dom); }
    
    // Process pre-recorded PCAP file
    bool process(const std::string& input_file, const std::string& output_file) {
        PcapReader reader;
        if (!reader.open(input_file)) return false;
        
        std::ofstream output(output_file, std::ios::binary);
        if (!output.is_open()) {
            std::cerr << "Cannot open output file\n";
            return false;
        }
        
        const auto& hdr = reader.getGlobalHeader();
        output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        
        startWorkers();
        
        std::atomic<bool> output_running{true};
        std::thread output_thread([&]() {
            writeOutputLoop(output, output_running);
        });
        
        std::cout << "[Reader] Processing PCAP packets...\n";
        RawPacket raw;
        uint32_t pkt_id = 0;
        
        while (reader.readNextPacket(raw)) {
            dispatchRawPacket(std::move(raw), pkt_id++);
        }
        
        std::cout << "[Reader] Done reading " << pkt_id << " packets\n";
        reader.close();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        stopWorkers();
        
        output_running = false;
        output_queue_.shutdown();
        output_thread.join();
        output.close();
        
        printReports();
        return true;
    }
    
    // Process live network traffic from interface
    bool processLive(const std::string& interface_target, const std::string& output_file, int max_packets) {
        LiveCapture live;
        if (!live.open(interface_target, LiveCapture::Backend::RAW_SOCKET)) {
            std::cerr << "[LiveCapture] Could not open interface " << interface_target << "\n";
            return false;
        }
        
        std::ofstream output;
        bool write_output = !output_file.empty();
        if (write_output) {
            output.open(output_file, std::ios::binary);
            if (output.is_open()) {
                PcapGlobalHeader hdr;
                hdr.magic_number = 0xa1b2c3d4;
                hdr.version_major = 2;
                hdr.version_minor = 4;
                hdr.thiszone = 0;
                hdr.sigfigs = 0;
                hdr.snaplen = 65535;
                hdr.network = 1; // Ethernet
                output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
            } else {
                write_output = false;
            }
        }
        
        startWorkers();
        
        std::atomic<bool> output_running{true};
        std::thread output_thread;
        if (write_output) {
            output_thread = std::thread([&]() {
                writeOutputLoop(output, output_running);
            });
        }
        
        std::atomic<uint32_t> pkt_id{0};
        std::signal(SIGINT, signalHandler);
        
        std::cout << "\n>>> LIVE SNIFFING ACTIVE - Press Ctrl+C to stop capture <<<\n\n";
        
        live.startCapture([this, &pkt_id](const RawPacket& raw) {
            dispatchRawPacket(raw, pkt_id++);
        }, max_packets);
        
        while (live.isRunning() && !g_stop_requested) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (max_packets > 0 && pkt_id >= static_cast<uint32_t>(max_packets)) break;
        }
        
        live.stopCapture();
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        stopWorkers();
        
        if (write_output) {
            output_running = false;
            output_queue_.shutdown();
            if (output_thread.joinable()) output_thread.join();
            output.close();
            std::cout << "[LiveCapture] Filtered live capture saved to: " << output_file << "\n";
        }
        
        printReports();
        return true;
    }

private:
    Config config_;
    Rules rules_;
    Stats stats_;
    IDSEngine ids_engine_;
    TSQueue<Packet> output_queue_;
    std::vector<std::unique_ptr<FastPath>> fps_;
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
    
    void startWorkers() {
        for (auto& fp : fps_) fp->start();
        for (auto& lb : lbs_) lb->start();
    }
    
    void stopWorkers() {
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();
    }
    
    void writeOutputLoop(std::ofstream& output, std::atomic<bool>& output_running) {
        while (output_running || output_queue_.size() > 0) {
            auto pkt_opt = output_queue_.pop(50);
            if (!pkt_opt) continue;
            
            PcapPacketHeader phdr;
            phdr.ts_sec = pkt_opt->ts_sec;
            phdr.ts_usec = pkt_opt->ts_usec;
            phdr.incl_len = pkt_opt->data.size();
            phdr.orig_len = pkt_opt->data.size();
            
            output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
            output.write(reinterpret_cast<const char*>(pkt_opt->data.data()), pkt_opt->data.size());
        }
    }
    
    void dispatchRawPacket(RawPacket raw, uint32_t pkt_id) {
        ParsedPacket parsed;
        if (!PacketParser::parse(raw, parsed)) return;
        if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) return;
        
        Packet pkt;
        pkt.id = pkt_id;
        pkt.ts_sec = raw.header.ts_sec;
        pkt.ts_usec = raw.header.ts_usec;
        pkt.tcp_flags = parsed.tcp_flags;
        pkt.seq = parsed.seq_number;
        pkt.data = std::move(raw.data);
        
        auto parseIP = [](const std::string& ip) -> uint32_t {
            uint32_t result = 0;
            int octet = 0, shift = 0;
            for (char c : ip) {
                if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
            }
            return result | (octet << shift);
        };
        
        pkt.tuple.src_ip = parseIP(parsed.src_ip);
        pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
        pkt.tuple.src_port = parsed.src_port;
        pkt.tuple.dst_port = parsed.dest_port;
        pkt.tuple.protocol = parsed.protocol;
        
        // Calculate payload offset
        pkt.payload_offset = 14;
        if (pkt.data.size() > 14) {
            uint8_t ip_ihl = pkt.data[14] & 0x0F;
            pkt.payload_offset += ip_ihl * 4;
            
            if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.size()) {
                uint8_t tcp_off = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
                pkt.payload_offset += tcp_off * 4;
            } else if (parsed.has_udp) {
                pkt.payload_offset += 8;
            }
            
            if (pkt.payload_offset < pkt.data.size()) {
                pkt.payload_length = pkt.data.size() - pkt.payload_offset;
            } else {
                pkt.payload_length = 0;
            }
        }
        
        stats_.total_packets++;
        stats_.total_bytes += pkt.data.size();
        if (parsed.has_tcp) stats_.tcp_packets++;
        else if (parsed.has_udp) stats_.udp_packets++;
        
        FiveTupleHash hasher;
        size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
        lbs_[lb_idx]->queue().push(std::move(pkt));
    }
    
    void printReports() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                      PROCESSING REPORT                        ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Packets:      " << std::setw(12) << stats_.total_packets.load() << "                           ║\n";
        std::cout << "║ Total Bytes:        " << std::setw(12) << stats_.total_bytes.load() << "                           ║\n";
        std::cout << "║ TCP Packets:        " << std::setw(12) << stats_.tcp_packets.load() << "                           ║\n";
        std::cout << "║ UDP Packets:        " << std::setw(12) << stats_.udp_packets.load() << "                           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Forwarded:          " << std::setw(12) << stats_.forwarded.load() << "                           ║\n";
        std::cout << "║ Dropped:            " << std::setw(12) << stats_.dropped.load() << "                           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ THREAD STATISTICS                                             ║\n";
        for (size_t i = 0; i < lbs_.size(); i++) {
            std::cout << "║   LB" << i << " dispatched:   " << std::setw(12) << lbs_[i]->dispatched() << "                           ║\n";
        }
        for (size_t i = 0; i < fps_.size(); i++) {
            std::cout << "║   FP" << i << " processed:    " << std::setw(12) << fps_[i]->processed() << "                           ║\n";
        }
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║                   APPLICATION BREAKDOWN                       ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        
        std::lock_guard<std::mutex> lock(stats_.app_mutex);
        std::vector<std::pair<AppType, uint64_t>> sorted_apps(
            stats_.app_counts.begin(), stats_.app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });
        
        uint64_t total = stats_.total_packets.load();
        for (const auto& [app, count] : sorted_apps) {
            double pct = total > 0 ? (100.0 * count / total) : 0;
            int bar = static_cast<int>(pct / 5);
            std::string bar_str(bar, '#');
            
            std::cout << "║ " << std::setw(15) << std::left << appTypeToString(app)
                      << std::setw(8) << std::right << count
                      << " " << std::setw(5) << std::fixed << std::setprecision(1) << pct << "% "
                      << std::setw(20) << std::left << bar_str << "  ║\n";
        }
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        
        if (!stats_.detected_snis.empty()) {
            std::cout << "\n[Detected Domains/SNIs]\n";
            for (const auto& [sni, app] : stats_.detected_snis) {
                std::cout << "  - " << sni << " -> " << appTypeToString(app) << "\n";
            }
        }
        
        // Print IDS Security Report
        ids_engine_.printReport();
    }
};

// =============================================================================
// CLI Usage & Main
// =============================================================================
void printUsage(const char* prog) {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║     DPI ENGINE v2.5 - Deep Packet Inspection & Mini-IDS      ║
╚══════════════════════════════════════════════════════════════╝

Usage:
  )" << prog << R"( <input.pcap> <output.pcap> [options]
  )" << prog << R"( --live [interface] [output.pcap] [options]
  )" << prog << R"( --list-interfaces

Modes:
  <input.pcap>           Analyze an existing PCAP capture file
  --live [iface]         Capture live packets from network interface (e.g., Wi-Fi)
  --list-interfaces      List all active network interfaces on this PC

Security & Filtering Options:
  --block-ip <ip>        Block packets from source IP
  --block-app <app>      Block application (YouTube, Facebook, Discord, etc.)
  --block-domain <dom>   Block domain (supports substrings)
  --lbs <n>              Number of load balancer threads (default: 2)
  --fps <n>              FP threads per LB (default: 2)
  --max-packets <n>      Stop after N packets (useful for live mode)

Examples:
  )" << prog << R"( --list-interfaces
  )" << prog << R"( test_dpi.pcap filtered.pcap --block-app YouTube
  )" << prog << R"( --live Wi-Fi live_filtered.pcap --block-app TikTok --max-packets 100
)";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string arg1 = argv[1];
    if (arg1 == "--help" || arg1 == "-h") {
        printUsage(argv[0]);
        return 0;
    }
    
    // Check --list-interfaces
    if (arg1 == "--list-interfaces") {
        auto ifaces = LiveCapture::listInterfaces();
        std::cout << "\nActive Network Interfaces:\n";
        std::cout << "--------------------------------------------------------------------------------------\n";
        std::cout << std::left << std::setw(6) << "Index"
                  << std::setw(25) << "Name"
                  << std::setw(18) << "IPv4 Address"
                  << std::setw(20) << "MAC Address"
                  << "Description\n";
        std::cout << "--------------------------------------------------------------------------------------\n";
        for (const auto& iface : ifaces) {
            std::cout << std::left << std::setw(6) << iface.index
                      << std::setw(25) << iface.name
                      << std::setw(18) << iface.ip_address
                      << std::setw(20) << iface.mac_address
                      << iface.description << "\n";
        }
        std::cout << "--------------------------------------------------------------------------------------\n";
        return 0;
    }
    
    bool is_live = false;
    std::string live_iface = "";
    std::string input = "";
    std::string output = "";
    int max_packets = 0;
    int opt_start = 1;
    
    if (arg1 == "--live") {
        is_live = true;
        opt_start = 2;
        if (argc > 2 && argv[2][0] != '-') {
            live_iface = argv[2];
            opt_start = 3;
            if (argc > 3 && argv[3][0] != '-') {
                output = argv[3];
                opt_start = 4;
            }
        }
    } else {
        if (argc < 3) {
            printUsage(argv[0]);
            return 1;
        }
        input = argv[1];
        output = argv[2];
        opt_start = 3;
    }
    
    DPIEngine::Config cfg;
    std::vector<std::string> block_ips, block_apps, block_domains;
    
    for (int i = opt_start; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        else if (arg == "--lbs" && i + 1 < argc) cfg.num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc) cfg.fps_per_lb = std::stoi(argv[++i]);
        else if (arg == "--max-packets" && i + 1 < argc) max_packets = std::stoi(argv[++i]);
    }
    
    DPIEngine engine(cfg);
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);
    
    if (is_live) {
        if (!engine.processLive(live_iface, output, max_packets)) {
            return 1;
        }
    } else {
        if (!engine.process(input, output)) {
            return 1;
        }
        std::cout << "\nOutput written to: " << output << "\n";
    }
    
    return 0;
}
