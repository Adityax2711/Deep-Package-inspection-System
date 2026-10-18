#!/usr/bin/env python3
"""
Generates test_security.pcap containing:
1. Normal traffic (HTTPS YouTube, Google, DNS)
2. Port Scan attack from 192.168.1.99
3. SYN Flood attack from 10.0.0.88
4. DNS Tunneling attack from 192.168.1.50
5. TCP Out-of-order packets
"""
import struct

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        # Magic 0xa1b2c3d4, version 2.4, snaplen 65535, Ethernet
        self.file.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        self.ts_sec = 1700000000
        self.ts_usec = 100000

    def write_packet(self, data):
        self.file.write(struct.pack('<IIII', self.ts_sec, self.ts_usec, len(data), len(data)))
        self.file.write(data)
        self.ts_usec += 1000
        if self.ts_usec >= 1000000:
            self.ts_sec += 1
            self.ts_usec = 0

    def close(self):
        self.file.close()

def eth_ip_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b''):
    # Ethernet
    eth = bytes.fromhex('001122334455aabbccddeeff0800')
    # IPv4
    total_len = 20 + 20 + len(payload)
    ip = struct.pack('>BBHHHBBH', 0x45, 0, total_len, 1234, 0x4000, 64, 6, 0)
    ip += bytes([int(x) for x in src_ip.split('.')])
    ip += bytes([int(x) for x in dst_ip.split('.')])
    # TCP
    tcp = struct.pack('>HHIIBBHHH', src_port, dst_port, seq, ack, (5 << 4), flags, 65535, 0, 0)
    return eth + ip + tcp + payload

def eth_ip_udp_dns(src_ip, dst_ip, src_port, dst_port, domain):
    eth = bytes.fromhex('001122334455aabbccddeeff0800')
    # DNS payload
    dns_header = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0) # Standard query
    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode('ascii')
    qname += b'\x00'
    qtype_qclass = struct.pack('>HH', 1, 1) # A record, IN class
    dns_payload = dns_header + qname + qtype_qclass

    # UDP
    udp_len = 8 + len(dns_payload)
    udp = struct.pack('>HHHH', src_port, dst_port, udp_len, 0)

    # IPv4
    total_len = 20 + udp_len
    ip = struct.pack('>BBHHHBBH', 0x45, 0, total_len, 5678, 0x4000, 64, 17, 0)
    ip += bytes([int(x) for x in src_ip.split('.')])
    ip += bytes([int(x) for x in dst_ip.split('.')])

    return eth + ip + udp + dns_payload

pcap = PCAPWriter('test_security.pcap')

# 1. Normal DNS query
pcap.write_packet(eth_ip_udp_dns('192.168.1.100', '8.8.8.8', 54321, 53, 'www.google.com'))

# 2. Port Scan from 192.168.1.99 (scanning 20 distinct ports with SYN packets)
for port in range(20, 40):
    pcap.write_packet(eth_ip_tcp('192.168.1.99', '192.168.1.1', 40000 + port, port, 1000, 0, 0x02))

# 3. SYN Flood from 10.0.0.88 (45 unacknowledged SYNs)
for i in range(45):
    pcap.write_packet(eth_ip_tcp('10.0.0.88', '192.168.1.10', 30000 + i, 80, 5000 + i, 0, 0x02))

# 4. DNS Tunneling from 192.168.1.50 (Data exfiltration query with high Shannon entropy)
tunnel_domain = "aW5mb3NlY3VyaXR5ZGF0YTEyMzQ1Njc4OQ==.c2-exfil.darkweb-channel.org"
pcap.write_packet(eth_ip_udp_dns('192.168.1.50', '8.8.8.8', 52345, 53, tunnel_domain))

# 5. Out-of-order TCP packets for flow 192.168.1.100 -> 142.250.185.206
# Packet 1 (SYN)
pcap.write_packet(eth_ip_tcp('192.168.1.100', '142.250.185.206', 50000, 443, 1000, 0, 0x02))
# Packet 3 arrives first (seq 1050, length 50) -> Out of order!
pcap.write_packet(eth_ip_tcp('192.168.1.100', '142.250.185.206', 50000, 443, 1050, 2000, 0x18, b'B' * 50))
# Packet 2 arrives later (seq 1001, length 49) -> Gap filled, triggers reassembly!
pcap.write_packet(eth_ip_tcp('192.168.1.100', '142.250.185.206', 50000, 443, 1001, 2000, 0x18, b'A' * 49))

pcap.close()
print("Generated test_security.pcap successfully!")
