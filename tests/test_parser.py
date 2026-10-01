"""Unit tests for the Packet Parsing and Normalization layer."""

import time
import pytest
import scapy.all as scapy

from backend.parser.dissector import PacketDissector
from backend.parser.models import NormalizedPacket


# ==============================================================================
# 1. Ethernet Packet
# ==============================================================================
def test_parse_ethernet_packet():
    """Verify parsing a pure Ethernet frame with no higher layers."""
    pkt = scapy.Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
    parsed = PacketDissector.parse(pkt)

    assert parsed.src_mac == "00:11:22:33:44:55"
    assert parsed.dst_mac == "aa:bb:cc:dd:ee:ff"
    assert parsed.src_ip is None
    assert parsed.dst_ip is None
    assert parsed.protocol == "UNKNOWN"
    assert parsed.src_port is None
    assert parsed.packet_length == len(pkt)


# ==============================================================================
# 2. IPv4 Packet
# ==============================================================================
def test_parse_ipv4_packet():
    """Verify parsing an IPv4 packet without transport layer."""
    pkt = (
        scapy.Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / scapy.IP(src="192.168.1.10", dst="192.168.1.20")
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.src_mac == "00:11:22:33:44:55"
    assert parsed.dst_mac == "66:77:88:99:aa:bb"
    assert parsed.src_ip == "192.168.1.10"
    assert parsed.dst_ip == "192.168.1.20"
    assert parsed.protocol == "IP"
    assert parsed.src_port is None
    assert parsed.dst_port is None


# ==============================================================================
# 3. TCP Packet
# ==============================================================================
def test_parse_tcp_packet():
    """Verify parsing standard TCP packet ports and protocol."""
    pkt = (
        scapy.Ether()
        / scapy.IP(src="10.0.0.1", dst="10.0.0.2")
        / scapy.TCP(sport=54321, dport=80)
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "TCP"
    assert parsed.src_port == 54321
    assert parsed.dst_port == 80
    assert parsed.src_ip == "10.0.0.1"
    assert parsed.dst_ip == "10.0.0.2"


# ==============================================================================
# 4. TCP SYN Packet
# ==============================================================================
def test_parse_tcp_syn_packet():
    """Verify TCP SYN flag is detected and isolated."""
    pkt = (
        scapy.Ether()
        / scapy.IP(src="192.168.1.100", dst="192.168.1.200")
        / scapy.TCP(sport=40000, dport=443, flags="S")
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "TCP"
    assert parsed.tcp_flags == "SYN"
    assert parsed.raw_tcp_flags == "S"
    assert parsed.has_flag("SYN") is True
    assert parsed.has_flag("ACK") is False
    assert parsed.has_flag("RST") is False


# ==============================================================================
# 5. TCP Packet with Multiple Flags
# ==============================================================================
def test_parse_tcp_multiple_flags():
    """Verify deterministic decoding of multiple TCP flags."""
    # SYN+ACK
    pkt_sa = scapy.IP() / scapy.TCP(flags="SA")
    parsed_sa = PacketDissector.parse(pkt_sa)
    assert parsed_sa.has_flag("SYN") is True
    assert parsed_sa.has_flag("ACK") is True
    assert parsed_sa.has_flag("FIN") is False
    assert "SYN" in parsed_sa.tcp_flags
    assert "ACK" in parsed_sa.tcp_flags

    # FIN+PSH+ACK
    pkt_fpa = scapy.IP() / scapy.TCP(flags="FPA")
    parsed_fpa = PacketDissector.parse(pkt_fpa)
    assert parsed_fpa.has_flag("FIN") is True
    assert parsed_fpa.has_flag("PSH") is True
    assert parsed_fpa.has_flag("ACK") is True
    assert parsed_fpa.has_flag("SYN") is False


# ==============================================================================
# 6. UDP Packet
# ==============================================================================
def test_parse_udp_packet():
    """Verify standard UDP packet extraction."""
    pkt = (
        scapy.Ether()
        / scapy.IP(src="172.16.0.5", dst="172.16.0.1")
        / scapy.UDP(sport=45678, dport=5353)
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "UDP"
    assert parsed.src_port == 45678
    assert parsed.dst_port == 5353
    assert parsed.tcp_flags is None


# ==============================================================================
# 7. ICMP Echo Request
# ==============================================================================
def test_parse_icmp_echo_request():
    """Verify ICMP Echo Request (Type 8) extraction."""
    pkt = (
        scapy.Ether()
        / scapy.IP(src="192.168.1.10", dst="192.168.1.1")
        / scapy.ICMP(type=8, code=0)
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "ICMP"
    assert parsed.icmp_type == 8
    assert parsed.icmp_code == 0
    assert parsed.src_ip == "192.168.1.10"
    assert parsed.dst_ip == "192.168.1.1"
    assert parsed.src_port is None


# ==============================================================================
# 8. ICMP Echo Reply
# ==============================================================================
def test_parse_icmp_echo_reply():
    """Verify ICMP Echo Reply (Type 0) extraction."""
    pkt = (
        scapy.Ether()
        / scapy.IP(src="192.168.1.1", dst="192.168.1.10")
        / scapy.ICMP(type=0, code=0)
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "ICMP"
    assert parsed.icmp_type == 0
    assert parsed.icmp_code == 0


# ==============================================================================
# 9. ARP Request
# ==============================================================================
def test_parse_arp_request():
    """Verify ARP Request (who-has, op=1) parsing."""
    pkt = (
        scapy.Ether(src="00:aa:bb:cc:dd:ee", dst="ff:ff:ff:ff:ff:ff")
        / scapy.ARP(
            op=1,
            hwsrc="00:aa:bb:cc:dd:ee",
            psrc="192.168.1.50",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1",
        )
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "ARP"
    assert parsed.arp_op == 1
    assert parsed.arp_sender_mac == "00:aa:bb:cc:dd:ee"
    assert parsed.arp_sender_ip == "192.168.1.50"
    assert parsed.arp_target_mac == "00:00:00:00:00:00"
    assert parsed.arp_target_ip == "192.168.1.1"
    assert parsed.src_ip == "192.168.1.50"
    assert parsed.dst_ip == "192.168.1.1"


# ==============================================================================
# 10. ARP Reply
# ==============================================================================
def test_parse_arp_reply():
    """Verify ARP Reply (is-at, op=2) parsing."""
    pkt = (
        scapy.Ether(src="11:22:33:44:55:66", dst="00:aa:bb:cc:dd:ee")
        / scapy.ARP(
            op=2,
            hwsrc="11:22:33:44:55:66",
            psrc="192.168.1.1",
            hwdst="00:aa:bb:cc:dd:ee",
            pdst="192.168.1.50",
        )
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "ARP"
    assert parsed.arp_op == 2
    assert parsed.arp_sender_mac == "11:22:33:44:55:66"
    assert parsed.arp_sender_ip == "192.168.1.1"
    assert parsed.arp_target_mac == "00:aa:bb:cc:dd:ee"
    assert parsed.arp_target_ip == "192.168.1.50"


# ==============================================================================
# 11. DNS Query
# ==============================================================================
def test_parse_dns_query():
    """Verify DNS query name and query type extraction."""
    pkt = (
        scapy.Ether()
        / scapy.IP(src="192.168.1.10", dst="8.8.8.8")
        / scapy.UDP(sport=53000, dport=53)
        / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="portal.corp.internal", qtype="A"))
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "DNS"
    assert parsed.dns_query == "portal.corp.internal"
    assert parsed.dns_query_type == "A"
    assert parsed.src_port == 53000
    assert parsed.dst_port == 53


# ==============================================================================
# 12. DNS Packet Without Question
# ==============================================================================
def test_parse_dns_without_question():
    """Verify DNS packet with no question record is handled safely."""
    pkt = (
        scapy.Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / scapy.IP()
        / scapy.UDP(sport=53, dport=53000)
        / scapy.DNS(qr=1, qdcount=0, qd=[], ancount=0)
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "DNS"
    assert parsed.dns_query is None


# ==============================================================================
# 13. DHCP Packet
# ==============================================================================
def test_parse_dhcp_packet():
    """Verify DHCP discover message type extraction."""
    pkt = (
        scapy.Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
        / scapy.IP(src="0.0.0.0", dst="255.255.255.255")
        / scapy.UDP(sport=68, dport=67)
        / scapy.BOOTP(chaddr=b"\x00\x11\x22\x33\x44\x55")
        / scapy.DHCP(options=[("message-type", "discover"), "end"])
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "DHCP"
    assert parsed.dhcp_message_type == "discover"
    assert parsed.src_port == 68
    assert parsed.dst_port == 67


# ==============================================================================
# 14. HTTP Request Metadata
# ==============================================================================
def test_parse_http_request_metadata():
    """Verify HTTP method, host, and path extraction from Raw TCP payload."""
    payload = b"GET /v1/telemetry HTTP/1.1\r\nHost: metrics.lab.local\r\nUser-Agent: agent/1.0\r\n\r\n"
    pkt = (
        scapy.Ether()
        / scapy.IP(src="10.0.1.5", dst="10.0.1.100")
        / scapy.TCP(sport=49152, dport=80, flags="PA")
        / scapy.Raw(load=payload)
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.protocol == "HTTP"
    assert parsed.http_method == "GET"
    assert parsed.http_path == "/v1/telemetry"
    assert parsed.http_host == "metrics.lab.local"
    assert parsed.has_flag("PSH") is True
    assert parsed.has_flag("ACK") is True


# ==============================================================================
# 15. Unknown / Minimal Packet
# ==============================================================================
def test_parse_unknown_minimal_packet():
    """Verify unadorned Raw payload packet is parsed safely without errors."""
    raw_pkt = scapy.Raw(load=b"\xde\xad\xbe\xef\xca\xfe")
    parsed = PacketDissector.parse(raw_pkt)

    assert parsed.protocol == "UNKNOWN"
    assert parsed.packet_length == 6
    assert parsed.src_ip is None
    assert parsed.dst_ip is None
    assert parsed.src_port is None


# ==============================================================================
# 16. Missing Optional Layers
# ==============================================================================
def test_parse_missing_optional_layers():
    """Verify IP without Ethernet, and TCP without IP layers are parsed safely."""
    # IP without Ethernet
    ip_only = scapy.IP(src="172.20.0.1", dst="172.20.0.2") / scapy.TCP(sport=22, dport=33000, flags="S")
    parsed_ip = PacketDissector.parse(ip_only)
    assert parsed_ip.src_mac is None
    assert parsed_ip.dst_mac is None
    assert parsed_ip.src_ip == "172.20.0.1"
    assert parsed_ip.dst_ip == "172.20.0.2"
    assert parsed_ip.protocol == "TCP"
    assert parsed_ip.src_port == 22
    assert parsed_ip.dst_port == 33000

    # TCP without IP or Ethernet
    tcp_only = scapy.TCP(sport=8080, dport=9090)
    parsed_tcp = PacketDissector.parse(tcp_only)
    assert parsed_tcp.src_ip is None
    assert parsed_tcp.dst_ip is None
    assert parsed_tcp.protocol == "TCP"
    assert parsed_tcp.src_port == 8080
    assert parsed_tcp.dst_port == 9090


# ==============================================================================
# 17. Malformed Packet Handling
# ==============================================================================
def test_parse_malformed_packet_handling():
    """Verify passing non-packet objects or malformed data returns a safe fallback model."""
    class BrokenObject:
        def __len__(self):
            return 42

    broken = BrokenObject()
    parsed = PacketDissector.parse(broken)

    assert isinstance(parsed, NormalizedPacket)
    assert parsed.protocol == "UNKNOWN"
    assert parsed.packet_length == 42


# ==============================================================================
# 18. Packet Length Extraction
# ==============================================================================
def test_packet_length_extraction():
    """Verify exact packet length matches Scapy raw byte count."""
    pkt = (
        scapy.Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / scapy.IP()
        / scapy.TCP()
        / scapy.Raw(load=b"1234567890")
    )
    parsed = PacketDissector.parse(pkt)

    assert parsed.packet_length == len(pkt)
    assert parsed.packet_length > 0


# ==============================================================================
# 19. Timestamp Handling
# ==============================================================================
def test_timestamp_handling():
    """Verify custom packet timestamps from PCAPs or capture feeds are preserved."""
    pkt = scapy.IP() / scapy.UDP()
    explicit_time = 1609459200.123456
    pkt.time = explicit_time

    parsed = PacketDissector.parse(pkt)
    assert parsed.timestamp == pytest.approx(explicit_time, rel=1e-5)


# ==============================================================================
# 20. Normalized Field Defaults and None Behavior
# ==============================================================================
def test_normalized_field_defaults_none_behavior():
    """Verify default initialization of NormalizedPacket has None for all optional fields."""
    p = NormalizedPacket()

    assert p.protocol == "UNKNOWN"
    assert p.src_mac is None
    assert p.dst_mac is None
    assert p.src_ip is None
    assert p.dst_ip is None
    assert p.src_port is None
    assert p.dst_port is None
    assert p.tcp_flags is None
    assert p.raw_tcp_flags is None
    assert p.icmp_type is None
    assert p.icmp_code is None
    assert p.arp_op is None
    assert p.arp_sender_mac is None
    assert p.arp_sender_ip is None
    assert p.arp_target_mac is None
    assert p.arp_target_ip is None
    assert p.dns_query is None
    assert p.dns_query_type is None
    assert p.dhcp_message_type is None
    assert p.http_method is None
    assert p.http_host is None
    assert p.http_path is None
    assert p.raw_summary is None

    assert p.has_flag("SYN") is False
    assert isinstance(p.to_dict(), dict)
    assert "<UNKNOWN" in str(p)
