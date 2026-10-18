#include "live_capture.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <chrono>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

namespace DPI {

LiveCapture::LiveCapture() {
    initWinsock();
}

LiveCapture::~LiveCapture() {
    stopCapture();
#ifdef _WIN32
    if (raw_socket_handle_ != 0 && raw_socket_handle_ != (uintptr_t)INVALID_SOCKET) {
        closesocket((SOCKET)raw_socket_handle_);
        raw_socket_handle_ = 0;
    }
#endif
}

bool LiveCapture::initWinsock() {
#ifdef _WIN32
    static bool initialized = false;
    if (!initialized) {
        WSADATA wsaData;
        int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (res == 0) {
            initialized = true;
        } else {
            std::cerr << "[LiveCapture] Failed to initialize Winsock (error " << res << ")\n";
            return false;
        }
    }
    return true;
#else
    return true;
#endif
}

std::vector<LiveInterface> LiveCapture::listInterfaces() {
    std::vector<LiveInterface> result;

#ifdef _WIN32
    ULONG outBufLen = 15000;
    std::vector<uint8_t> buffer(outBufLen);
    PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    DWORD ret = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(outBufLen);
        pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        ret = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    }

    if (ret == NO_ERROR) {
        int idx = 0;
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != NULL; pCurr = pCurr->Next) {
            // Find IPv4 address
            std::string ipv4;
            for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurr->FirstUnicastAddress; 
                 pUnicast != NULL; pUnicast = pUnicast->Next) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    char ipStr[INET_ADDRSTRLEN];
                    sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(pUnicast->Address.lpSockaddr);
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, INET_ADDRSTRLEN);
                    ipv4 = ipStr;
                    break;
                }
            }

            if (ipv4.empty()) continue;

            LiveInterface iface;
            iface.index = idx++;

            // Convert friendly name
            if (pCurr->FriendlyName) {
                char nameBuf[256];
                WideCharToMultiByte(CP_UTF8, 0, pCurr->FriendlyName, -1, nameBuf, sizeof(nameBuf), NULL, NULL);
                iface.name = nameBuf;
            } else {
                iface.name = "Unknown";
            }

            // Description
            if (pCurr->Description) {
                char descBuf[256];
                WideCharToMultiByte(CP_UTF8, 0, pCurr->Description, -1, descBuf, sizeof(descBuf), NULL, NULL);
                iface.description = descBuf;
            }

            iface.ip_address = ipv4;
            iface.is_up = (pCurr->OperStatus == IfOperStatusUp);

            // MAC Address
            if (pCurr->PhysicalAddressLength > 0) {
                std::ostringstream oss;
                for (ULONG i = 0; i < pCurr->PhysicalAddressLength; i++) {
                    if (i > 0) oss << ":";
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)pCurr->PhysicalAddress[i];
                }
                iface.mac_address = oss.str();
            }

            result.push_back(iface);
        }
    }
#endif

    return result;
}

bool LiveCapture::open(const std::string& interface_ip_or_name, Backend backend) {
    auto interfaces = listInterfaces();
    if (interfaces.empty()) {
        std::cerr << "[LiveCapture] No active network interfaces found\n";
        return false;
    }

    // Match interface by IP or Name or Index
    bool found = false;
    for (const auto& iface : interfaces) {
        if (iface.ip_address == interface_ip_or_name || 
            iface.name == interface_ip_or_name ||
            std::to_string(iface.index) == interface_ip_or_name) {
            selected_interface_ = iface;
            found = true;
            break;
        }
    }

    if (!found) {
        // Auto-select first active interface with a valid routable IP
        for (const auto& iface : interfaces) {
            if (iface.is_up && iface.ip_address.rfind("169.254.", 0) == std::string::npos && 
                iface.ip_address != "127.0.0.1") {
                selected_interface_ = iface;
                found = true;
                break;
            }
        }
        if (!found) {
            selected_interface_ = interfaces[0];
        }
    }

    std::cout << "[LiveCapture] Selected Interface: " << selected_interface_.name 
              << " (" << selected_interface_.ip_address << ") - " 
              << selected_interface_.description << "\n";

    if (backend == Backend::NPCAP) {
        if (openNpcap(selected_interface_.name)) {
            active_backend_ = Backend::NPCAP;
            return true;
        }
        std::cout << "[LiveCapture] Npcap not available, falling back to Native Windows Raw Sockets...\n";
    }

    // Default to Raw Socket
    if (openRawSocket(selected_interface_.ip_address)) {
        active_backend_ = Backend::RAW_SOCKET;
        return true;
    }

    return false;
}

bool LiveCapture::openRawSocket(const std::string& ip) {
#ifdef _WIN32
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (s == INVALID_SOCKET) {
        int err = WSAGetLastError();
        std::cerr << "[LiveCapture] Error creating RAW socket (code " << err << ").\n"
                  << "  -> Note: Raw socket promiscuous capture on Windows requires running as Administrator.\n";
        return false;
    }

    sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = 0;
    inet_pton(AF_INET, ip.c_str(), &dest.sin_addr);

    if (bind(s, reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        std::cerr << "[LiveCapture] Error binding RAW socket to " << ip << " (code " << err << ")\n";
        closesocket(s);
        return false;
    }

    // Enable Promiscuous Mode via SIO_RCVALL
    DWORD flag = 1;
    DWORD bytesReturned = 0;
    if (WSAIoctl(s, SIO_RCVALL, &flag, sizeof(flag), NULL, 0, &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        std::cerr << "[LiveCapture] Failed to set SIO_RCVALL promiscuous mode (code " << err << ").\n"
                  << "  -> Run the terminal as Administrator to enable promiscuous mode.\n";
        closesocket(s);
        return false;
    }

    raw_socket_handle_ = static_cast<uintptr_t>(s);
    return true;
#else
    return false;
#endif
}

bool LiveCapture::openNpcap(const std::string& /*dev_name*/) {
#ifdef _WIN32
    HMODULE hPcap = LoadLibraryA("wpcap.dll");
    if (!hPcap) {
        return false;
    }
    // Npcap dynamic loading available
    FreeLibrary(hPcap);
#endif
    return false;
}

std::string LiveCapture::getActiveBackendName() const {
    switch (active_backend_) {
        case Backend::RAW_SOCKET: return "Native Windows Raw Sockets (SIO_RCVALL)";
        case Backend::NPCAP:      return "Npcap / WinPcap Kernel Driver";
        default:                 return "Unknown";
    }
}

bool LiveCapture::startCapture(LivePacketCallback callback, int max_packets) {
    if (running_) return false;
    running_ = true;

    capture_thread_ = std::thread([this, callback, max_packets]() {
        if (active_backend_ == Backend::RAW_SOCKET) {
            captureLoopRawSocket(callback, max_packets);
        } else {
            captureLoopNpcap(callback, max_packets);
        }
    });

    return true;
}

void LiveCapture::stopCapture() {
    running_ = false;
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
}

void LiveCapture::captureLoopRawSocket(LivePacketCallback callback, int max_packets) {
#ifdef _WIN32
    SOCKET s = static_cast<SOCKET>(raw_socket_handle_);
    std::vector<uint8_t> buffer(65536);

    std::cout << "[LiveCapture] Listening on " << selected_interface_.ip_address 
              << " (" << getActiveBackendName() << ")...\n";

    while (running_) {
        // Use select with 100ms timeout so thread responds to stopCapture()
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(s, &readSet);

        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms

        int ret = select(0, &readSet, NULL, NULL, &tv);
        if (ret > 0 && FD_ISSET(s, &readSet)) {
            int bytesRecv = recv(s, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
            if (bytesRecv > 0) {
                // Synthesize a 14-byte Ethernet frame around the raw IPv4 packet
                // so the downstream PacketParser & DPI pipeline works seamlessly!
                PacketAnalyzer::RawPacket rawPkt;
                auto now = std::chrono::system_clock::now();
                auto duration = now.time_since_epoch();
                auto sec = std::chrono::duration_cast<std::chrono::seconds>(duration);
                auto usec = std::chrono::duration_cast<std::chrono::microseconds>(duration - sec);

                rawPkt.header.ts_sec = static_cast<uint32_t>(sec.count());
                rawPkt.header.ts_usec = static_cast<uint32_t>(usec.count());
                rawPkt.header.orig_len = static_cast<uint32_t>(14 + bytesRecv);
                rawPkt.header.incl_len = rawPkt.header.orig_len;

                rawPkt.data.resize(14 + bytesRecv);
                // Destination MAC (Dummy: 00:11:22:33:44:55)
                rawPkt.data[0] = 0x00; rawPkt.data[1] = 0x11; rawPkt.data[2] = 0x22;
                rawPkt.data[3] = 0x33; rawPkt.data[4] = 0x44; rawPkt.data[5] = 0x55;
                // Source MAC (Dummy: AA:BB:CC:DD:EE:FF)
                rawPkt.data[6] = 0xAA; rawPkt.data[7] = 0xBB; rawPkt.data[8] = 0xCC;
                rawPkt.data[9] = 0xDD; rawPkt.data[10] = 0xEE; rawPkt.data[11] = 0xFF;
                // EtherType: IPv4 (0x0800)
                rawPkt.data[12] = 0x08; rawPkt.data[13] = 0x00;

                // Copy IP packet bytes
                std::memcpy(rawPkt.data.data() + 14, buffer.data(), bytesRecv);

                captured_packets_++;
                captured_bytes_ += rawPkt.data.size();

                callback(rawPkt);

                if (max_packets > 0 && captured_packets_ >= static_cast<uint64_t>(max_packets)) {
                    running_ = false;
                    break;
                }
            }
        }
    }
    std::cout << "[LiveCapture] Capture stopped. Total packets captured: " << captured_packets_ << "\n";
#endif
}

void LiveCapture::captureLoopNpcap(LivePacketCallback /*callback*/, int /*max_packets*/) {
    // Fallback if needed
}

} // namespace DPI
