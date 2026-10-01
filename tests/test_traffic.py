"""Unit tests for the Traffic Analysis and Connection Tracking layer."""

import pytest

from backend.analysis.models import FlowKey, FlowRecord, TrafficStatistics
from backend.analysis.traffic import TrafficAnalyzer
from backend.parser.models import NormalizedPacket


# ==============================================================================
# Helper fixture for synthetic NormalizedPackets
# ==============================================================================
@pytest.fixture
def make_packet():
    """Helper factory for generating synthetic NormalizedPacket instances."""
    def _create(
        timestamp=1000.0,
        length=100,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        protocol="TCP",
        src_port=12345,
        dst_port=80,
        tcp_flags=None,
        icmp_type=None,
        arp_op=None,
        dns_query=None,
    ):
        return NormalizedPacket(
            timestamp=timestamp,
            packet_length=length,
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            raw_tcp_flags=tcp_flags[0] if tcp_flags else None,
            icmp_type=icmp_type,
            arp_op=arp_op,
            dns_query=dns_query,
        )
    return _create


# ==============================================================================
# 1. Empty Analyzer
# ==============================================================================
def test_empty_analyzer():
    """Verify state of an unpopulated TrafficAnalyzer."""
    analyzer = TrafficAnalyzer()

    assert len(analyzer.get_flows()) == 0
    assert len(analyzer.get_active_flows()) == 0
    assert len(analyzer.get_completed_flows()) == 0

    stats = analyzer.get_statistics()
    assert stats.total_packets == 0
    assert stats.total_bytes == 0
    assert stats.unique_source_ip_count == 0
    assert stats.unique_destination_ip_count == 0


# ==============================================================================
# 2. Single TCP Packet
# ==============================================================================
def test_single_tcp_packet(make_packet):
    """Verify processing a single TCP packet tracks metrics."""
    analyzer = TrafficAnalyzer()
    pkt = make_packet(length=150, protocol="TCP")
    record = analyzer.process_packet(pkt)

    assert len(analyzer.get_flows()) == 1
    assert record.packet_count == 1
    assert record.byte_count == 150
    assert record.protocol == "TCP"
    assert record.initiator_ip == "192.168.1.10"
    assert record.responder_ip == "192.168.1.20"


# ==============================================================================
# 3. TCP SYN Packet
# ==============================================================================
def test_tcp_syn_packet(make_packet):
    """Verify TCP SYN packet initiates SYN_SENT state."""
    analyzer = TrafficAnalyzer()
    pkt = make_packet(tcp_flags="SYN")
    flow = analyzer.process_packet(pkt)

    assert flow.syn_seen is True
    assert flow.syn_ack_seen is False
    assert flow.state == "SYN_SENT"
    assert flow.is_active is True
    assert flow.is_completed is False


# ==============================================================================
# 4. TCP Handshake (SYN -> SYN-ACK -> ACK)
# ==============================================================================
def test_tcp_three_way_handshake(make_packet):
    """Verify full 3-way handshake transitions flow to ESTABLISHED."""
    analyzer = TrafficAnalyzer()

    # Step 1: Client -> Server [SYN]
    p1 = make_packet(src_ip="10.0.0.1", src_port=50000, dst_ip="10.0.0.2", dst_port=80, tcp_flags="SYN")
    f1 = analyzer.process_packet(p1)
    assert f1.state == "SYN_SENT"

    # Step 2: Server -> Client [SYN,ACK]
    p2 = make_packet(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=50000, tcp_flags="SYN,ACK")
    f2 = analyzer.process_packet(p2)
    assert f2.state == "SYN_RECEIVED"
    assert f2.syn_ack_seen is True

    # Step 3: Client -> Server [ACK]
    p3 = make_packet(src_ip="10.0.0.1", src_port=50000, dst_ip="10.0.0.2", dst_port=80, tcp_flags="ACK")
    f3 = analyzer.process_packet(p3)
    assert f3.state == "ESTABLISHED"
    assert f3.ack_seen is True
    assert f3.packet_count == 3


# ==============================================================================
# 5. TCP FIN
# ==============================================================================
def test_tcp_fin_closing(make_packet):
    """Verify TCP FIN transitions connection to CLOSING / CLOSED."""
    analyzer = TrafficAnalyzer()
    p1 = make_packet(src_ip="10.0.0.1", src_port=50000, dst_ip="10.0.0.2", dst_port=80, tcp_flags="SYN")
    analyzer.process_packet(p1)

    p2 = make_packet(src_ip="10.0.0.1", src_port=50000, dst_ip="10.0.0.2", dst_port=80, tcp_flags="FIN")
    flow = analyzer.process_packet(p2)

    assert flow.fin_seen is True
    assert flow.state in ("CLOSING", "CLOSED")


# ==============================================================================
# 6. TCP RST
# ==============================================================================
def test_tcp_rst(make_packet):
    """Verify TCP RST marks connection as RESET and completed."""
    analyzer = TrafficAnalyzer()
    p1 = make_packet(src_ip="10.0.0.1", src_port=50000, dst_ip="10.0.0.2", dst_port=80, tcp_flags="SYN")
    analyzer.process_packet(p1)

    p2 = make_packet(src_ip="10.0.0.2", src_port=80, dst_ip="10.0.0.1", dst_port=50000, tcp_flags="RST")
    flow = analyzer.process_packet(p2)

    assert flow.rst_seen is True
    assert flow.state == "RESET"
    assert flow.is_completed is True
    assert flow.is_active is False


# ==============================================================================
# 7. Bidirectional TCP Forms Single Flow
# ==============================================================================
def test_bidirectional_tcp_forms_single_flow(make_packet):
    """Verify bidirectional packets between endpoints map to identical FlowKey."""
    analyzer = TrafficAnalyzer()

    # Forward
    p1 = make_packet(src_ip="192.168.1.100", src_port=44444, dst_ip="192.168.1.200", dst_port=8080, length=60)
    # Reverse
    p2 = make_packet(src_ip="192.168.1.200", src_port=8080, dst_ip="192.168.1.100", dst_port=44444, length=120)

    analyzer.process_packet(p1)
    analyzer.process_packet(p2)

    flows = analyzer.get_flows()
    assert len(flows) == 1
    flow = flows[0]
    assert flow.packet_count == 2
    assert flow.byte_count == 180
    assert flow.forward_packets == 1
    assert flow.reverse_packets == 1
    assert flow.forward_bytes == 60
    assert flow.reverse_bytes == 120


# ==============================================================================
# 8. UDP Flow
# ==============================================================================
def test_udp_flow(make_packet):
    """Verify UDP packets are grouped and tracked as ACTIVE flows."""
    analyzer = TrafficAnalyzer()
    p1 = make_packet(src_ip="10.1.1.1", src_port=1234, dst_ip="10.1.1.2", dst_port=53, protocol="UDP", length=80)
    flow = analyzer.process_packet(p1)

    assert flow.protocol == "UDP"
    assert flow.state == "ACTIVE"
    assert flow.packet_count == 1


# ==============================================================================
# 9. ICMP Flow
# ==============================================================================
def test_icmp_flow(make_packet):
    """Verify ICMP packets form an ICMP flow without port numbers."""
    analyzer = TrafficAnalyzer()
    # Echo request
    p1 = make_packet(src_ip="192.168.0.5", dst_ip="192.168.0.1", protocol="ICMP", src_port=None, dst_port=None, icmp_type=8)
    # Echo reply
    p2 = make_packet(src_ip="192.168.0.1", dst_ip="192.168.0.5", protocol="ICMP", src_port=None, dst_port=None, icmp_type=0)

    analyzer.process_packet(p1)
    analyzer.process_packet(p2)

    flows = analyzer.get_flows()
    assert len(flows) == 1
    assert flows[0].protocol == "ICMP"
    assert flows[0].packet_count == 2


# ==============================================================================
# 10. ARP Statistics
# ==============================================================================
def test_arp_statistics(make_packet):
    """Verify ARP packets update ARP protocol counters."""
    analyzer = TrafficAnalyzer()
    p1 = make_packet(protocol="ARP", src_ip="192.168.1.1", dst_ip="192.168.1.2", src_port=None, dst_port=None, arp_op=1)
    p2 = make_packet(protocol="ARP", src_ip="192.168.1.2", dst_ip="192.168.1.1", src_port=None, dst_port=None, arp_op=2)

    analyzer.process_packet(p1)
    analyzer.process_packet(p2)

    stats = analyzer.get_statistics()
    assert stats.arp_packets == 2
    assert stats.protocol_counts["ARP"] == 2


# ==============================================================================
# 11. Protocol Counting
# ==============================================================================
def test_protocol_counting(make_packet):
    """Verify protocol breakdown tallies correctly for multiple protocols."""
    analyzer = TrafficAnalyzer()
    packets = [
        make_packet(protocol="TCP"),
        make_packet(protocol="TCP"),
        make_packet(protocol="UDP"),
        make_packet(protocol="ICMP", src_port=None, dst_port=None),
        make_packet(protocol="ARP", src_port=None, dst_port=None),
        make_packet(protocol="DNS", dns_query="test.local"),
    ]
    analyzer.process_packets(packets)

    stats = analyzer.get_statistics()
    assert stats.tcp_packets == 2
    assert stats.udp_packets == 1
    assert stats.icmp_packets == 1
    assert stats.arp_packets == 1
    assert stats.dns_packets == 1
    assert stats.total_packets == 6


# ==============================================================================
# 12. Packet Counting
# ==============================================================================
def test_packet_counting(make_packet):
    """Verify total packet counter increments accurately."""
    analyzer = TrafficAnalyzer()
    for _ in range(25):
        analyzer.process_packet(make_packet())

    assert analyzer.get_statistics().total_packets == 25


# ==============================================================================
# 13. Byte Counting
# ==============================================================================
def test_byte_counting(make_packet):
    """Verify total byte counter accumulates payload sizes."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet(length=100))
    analyzer.process_packet(make_packet(length=250))
    analyzer.process_packet(make_packet(length=400))

    assert analyzer.get_statistics().total_bytes == 750


# ==============================================================================
# 14. Unique Source IP Counting
# ==============================================================================
def test_unique_source_ip_counting(make_packet):
    """Verify set of unique source IPs is tracked."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet(src_ip="10.0.0.1"))
    analyzer.process_packet(make_packet(src_ip="10.0.0.2"))
    analyzer.process_packet(make_packet(src_ip="10.0.0.1"))  # duplicate
    analyzer.process_packet(make_packet(src_ip="10.0.0.3"))

    stats = analyzer.get_statistics()
    assert stats.unique_source_ip_count == 3
    assert stats.unique_source_ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


# ==============================================================================
# 15. Unique Destination IP Counting
# ==============================================================================
def test_unique_destination_ip_counting(make_packet):
    """Verify set of unique destination IPs is tracked."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet(dst_ip="172.16.0.1"))
    analyzer.process_packet(make_packet(dst_ip="172.16.0.2"))
    analyzer.process_packet(make_packet(dst_ip="172.16.0.2"))

    stats = analyzer.get_statistics()
    assert stats.unique_destination_ip_count == 2
    assert stats.unique_destination_ips == {"172.16.0.1", "172.16.0.2"}


# ==============================================================================
# 16. Port Statistics
# ==============================================================================
def test_port_statistics(make_packet):
    """Verify unique source and destination port counts."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet(src_port=1001, dst_port=80))
    analyzer.process_packet(make_packet(src_port=1002, dst_port=80))
    analyzer.process_packet(make_packet(src_port=1001, dst_port=443))

    stats = analyzer.get_statistics()
    assert stats.unique_source_port_count == 2  # 1001, 1002
    assert stats.unique_destination_port_count == 2  # 80, 443


# ==============================================================================
# 17. Multiple Independent Flows
# ==============================================================================
def test_multiple_independent_flows(make_packet):
    """Verify distinct endpoint pairs produce independent FlowRecords."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=100, dst_port=200))
    analyzer.process_packet(make_packet(src_ip="3.3.3.3", dst_ip="4.4.4.4", src_port=300, dst_port=400))
    analyzer.process_packet(make_packet(src_ip="5.5.5.5", dst_ip="6.6.6.6", src_port=500, dst_port=600))

    assert len(analyzer.get_flows()) == 3


# ==============================================================================
# 18. Active Flow Retrieval
# ==============================================================================
def test_active_flow_retrieval(make_packet):
    """Verify get_active_flows returns only non-completed flows."""
    analyzer = TrafficAnalyzer()
    # Active flow
    analyzer.process_packet(make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", tcp_flags="SYN"))
    # Completed flow (RST)
    analyzer.process_packet(make_packet(src_ip="3.3.3.3", dst_ip="4.4.4.4", tcp_flags="RST"))

    active = analyzer.get_active_flows()
    assert len(active) == 1
    assert active[0].flow_key.endpoint_a_ip in ("1.1.1.1", "2.2.2.2")


# ==============================================================================
# 19. Completed Flow Retrieval
# ==============================================================================
def test_completed_flow_retrieval(make_packet):
    """Verify get_completed_flows returns closed/reset flows."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet(src_ip="1.1.1.1", dst_ip="2.2.2.2", tcp_flags="SYN"))
    analyzer.process_packet(make_packet(src_ip="3.3.3.3", dst_ip="4.4.4.4", tcp_flags="RST"))

    completed = analyzer.get_completed_flows()
    assert len(completed) == 1
    assert completed[0].state == "RESET"


# ==============================================================================
# 20. Time Window Filtering
# ==============================================================================
def test_time_window_filtering(make_packet):
    """Verify time-based packet window retrieval."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet(timestamp=100.0))
    analyzer.process_packet(make_packet(timestamp=105.0))
    analyzer.process_packet(make_packet(timestamp=110.0))
    analyzer.process_packet(make_packet(timestamp=120.0))

    # Window of last 15 seconds (from latest t=120 -> 105 to 120)
    in_window = analyzer.get_packets_in_window(time_window_seconds=15.0, end_time=120.0)
    assert len(in_window) == 3  # 105.0, 110.0, 120.0

    # Range between 102.0 and 112.0
    between = analyzer.get_packets_between(start_time=102.0, end_time=112.0)
    assert len(between) == 2  # 105.0, 110.0


# ==============================================================================
# 21. Reset Functionality
# ==============================================================================
def test_reset_functionality(make_packet):
    """Verify reset clears all internal buffers, flows, and metrics."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet())
    analyzer.process_packet(make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2"))

    assert len(analyzer.get_flows()) > 0
    assert analyzer.get_statistics().total_packets > 0

    analyzer.reset()

    assert len(analyzer.get_flows()) == 0
    assert analyzer.get_statistics().total_packets == 0
    assert len(analyzer.get_packets_in_window(60.0)) == 0


# ==============================================================================
# 22. Missing Optional Fields
# ==============================================================================
def test_missing_optional_fields():
    """Verify packet with all optional fields None is processed safely."""
    analyzer = TrafficAnalyzer()
    bare_packet = NormalizedPacket(
        timestamp=100.0,
        packet_length=50,
        protocol="UNKNOWN",
    )

    record = analyzer.process_packet(bare_packet)
    assert record is not None
    assert record.packet_count == 1
    assert analyzer.get_statistics().total_packets == 1


# ==============================================================================
# 23. Empty Packet Collections
# ==============================================================================
def test_empty_packet_collections():
    """Verify processing an empty sequence returns empty list safely."""
    analyzer = TrafficAnalyzer()
    result = analyzer.process_packets([])
    assert result == []
    assert analyzer.get_statistics().total_packets == 0


# ==============================================================================
# 24. Repeated Packets
# ==============================================================================
def test_repeated_packets(make_packet):
    """Verify processing identical packet repeatedly updates counters accurately."""
    analyzer = TrafficAnalyzer()
    pkt = make_packet(length=100)

    for _ in range(5):
        analyzer.process_packet(pkt)

    flows = analyzer.get_flows()
    assert len(flows) == 1
    assert flows[0].packet_count == 5
    assert flows[0].byte_count == 500
    assert analyzer.get_statistics().total_packets == 5


# ==============================================================================
# 25. Out-of-Order Timestamps
# ==============================================================================
def test_out_of_order_timestamps(make_packet):
    """Verify out-of-order packet timestamps maintain accurate global min/max."""
    analyzer = TrafficAnalyzer()
    analyzer.process_packet(make_packet(timestamp=500.0))
    analyzer.process_packet(make_packet(timestamp=200.0))
    analyzer.process_packet(make_packet(timestamp=800.0))

    stats = analyzer.get_statistics()
    assert stats.start_time == 200.0
    assert stats.end_time == 800.0

    flow = analyzer.get_flows()[0]
    assert flow.first_seen == 500.0
    assert flow.last_seen == 800.0
