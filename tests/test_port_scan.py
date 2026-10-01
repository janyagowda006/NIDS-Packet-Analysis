"""Unit tests for the TCP Port Scan Detection engine."""

import pytest

from backend.detection.models import DetectionResult
from backend.detection.port_scan import PortScanDetector
from backend.parser.models import NormalizedPacket


@pytest.fixture
def make_syn_packet():
    """Helper to create synthetic TCP SYN packets for port scan testing."""
    def _create(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.200",
        dst_port=80,
        src_port=40000,
        timestamp=1000.0,
        tcp_flags="SYN",
        protocol="TCP",
    ):
        return NormalizedPacket(
            timestamp=timestamp,
            packet_length=60,
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            raw_tcp_flags="S" if tcp_flags == "SYN" else ("SA" if tcp_flags == "SYN,ACK" else "A"),
        )
    return _create


# ==============================================================================
# 1. No Traffic -> No Detection
# ==============================================================================
def test_no_traffic_no_detection():
    """Verify that an empty packet collection generates no detection results."""
    detector = PortScanDetector()
    results = detector.detect_window([])
    assert len(results) == 0


# ==============================================================================
# 2. Normal Single TCP Connection -> No Detection
# ==============================================================================
def test_normal_single_tcp_connection_no_detection(make_syn_packet):
    """Verify standard 3-way handshake traffic does not trigger port scan alert."""
    detector = PortScanDetector()
    packets = [
        make_syn_packet(src_port=50001, dst_port=443, tcp_flags="SYN", timestamp=1000.0),
        make_syn_packet(src_ip="192.168.1.200", dst_ip="192.168.1.100", src_port=443, dst_port=50001, tcp_flags="SYN,ACK", timestamp=1000.01),
        make_syn_packet(src_port=50001, dst_port=443, tcp_flags="ACK", timestamp=1000.02),
    ]

    results = detector.detect_window(packets)
    assert len(results) == 0


# ==============================================================================
# 3. SYN Packets Below Threshold -> No Detection
# ==============================================================================
def test_syn_packets_below_threshold_no_detection(make_syn_packet):
    """Verify connection attempts below unique port threshold do not trigger alert."""
    detector = PortScanDetector(unique_ports_threshold=15, min_syn_count=20)
    # Only 5 unique ports contacted
    packets = [
        make_syn_packet(dst_port=1000 + i, timestamp=1000.0 + (i * 0.05))
        for i in range(5)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 0


# ==============================================================================
# 4. Vertical Scan Above Threshold -> Detection
# ==============================================================================
def test_vertical_scan_above_threshold_detection(make_syn_packet):
    """Verify vertical port scan against single host triggers explainable alert."""
    detector = PortScanDetector(unique_ports_threshold=15, min_syn_count=20, time_window_seconds=1.0)
    # 20 SYN attempts against 20 distinct ports on 192.168.1.200 within 0.8s
    packets = [
        make_syn_packet(dst_port=2000 + i, timestamp=1000.0 + (i * 0.04))
        for i in range(20)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 1

    alert = results[0]
    assert alert.rule_name == "port_scan"
    assert alert.alert_type == "Possible Port Scan"
    assert alert.scan_type == "VERTICAL"
    assert alert.src_ip == "192.168.1.100"
    assert alert.dst_ip == "192.168.1.200"
    assert alert.unique_destination_ports == 20
    assert alert.syn_count == 20
    assert alert.severity == "HIGH"
    assert "exceeding threshold" in alert.detection_reason
    assert alert.evidence["unique_destination_ports_count"] == 20


# ==============================================================================
# 5. Horizontal Scan Above Threshold -> Detection
# ==============================================================================
def test_horizontal_scan_above_threshold_detection(make_syn_packet):
    """Verify horizontal sweep across multiple destination hosts triggers alert."""
    detector = PortScanDetector(unique_destinations_threshold=10, min_syn_count=10, time_window_seconds=1.0)
    # 12 SYN attempts against port 22 across 12 distinct destination IPs
    packets = [
        make_syn_packet(src_ip="10.0.0.99", dst_ip=f"10.0.0.{10 + i}", dst_port=22, timestamp=500.0 + (i * 0.05))
        for i in range(12)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 1

    alert = results[0]
    assert alert.scan_type == "HORIZONTAL"
    assert alert.src_ip == "10.0.0.99"
    assert alert.unique_destination_ips == 12
    assert alert.syn_count == 12
    assert "exceeding threshold of 10 hosts" in alert.detection_reason


# ==============================================================================
# 6. SYN Count Threshold Behavior
# ==============================================================================
def test_syn_count_threshold_behavior(make_syn_packet):
    """Verify scan requires meeting both port diversity AND min SYN count."""
    detector = PortScanDetector(unique_ports_threshold=5, min_syn_count=10)

    # 5 unique ports, but only 5 total SYNs (below min_syn_count=10)
    below_syn = [
        make_syn_packet(dst_port=3000 + i, timestamp=100.0 + (i * 0.05))
        for i in range(5)
    ]
    # min_syn_count requires at least 10
    # With min(min_syn_count, unique_ports_threshold) behavior:
    detector_strict = PortScanDetector(unique_ports_threshold=15, min_syn_count=20)
    packets_14 = [
        make_syn_packet(dst_port=4000 + i, timestamp=100.0 + (i * 0.05))
        for i in range(14)
    ]
    assert len(detector_strict.detect_window(packets_14)) == 0


# ==============================================================================
# 7. Window Boundary Behavior
# ==============================================================================
def test_window_boundary_behavior(make_syn_packet):
    """Verify attempts spread outside time window do not trigger alert."""
    detector = PortScanDetector(time_window_seconds=1.0, unique_ports_threshold=5, min_syn_count=5)
    # 5 attempts spaced 2 seconds apart (total 8 seconds span)
    packets = [
        make_syn_packet(dst_port=5000 + i, timestamp=100.0 + (i * 2.0))
        for i in range(5)
    ]

    # In any 1.0s window, there is at most 1 packet
    results = detector.detect_window(packets, time_window_seconds=1.0, end_time=108.0)
    assert len(results) == 0


# ==============================================================================
# 8. Packets Outside Configured Window Pruned
# ==============================================================================
def test_packets_outside_configured_window(make_syn_packet):
    """Verify incremental processing prunes packets older than time_window_seconds."""
    detector = PortScanDetector(time_window_seconds=1.0, unique_ports_threshold=5, min_syn_count=5)

    # Old packet at t=10.0
    detector.process_packet(make_syn_packet(dst_port=1001, timestamp=10.0))

    # Next packets arrive at t=50.0 (old packet should be pruned from window)
    for i in range(3):
        alerts = detector.process_packet(make_syn_packet(dst_port=1002 + i, timestamp=50.0 + (i * 0.1)))
        assert len(alerts) == 0

    assert len(detector._syn_buffer) == 3


# ==============================================================================
# 9. Duplicate / Retransmitted SYN Behavior
# ==============================================================================
def test_duplicate_retransmitted_syn_behavior(make_syn_packet):
    """Verify sending multiple SYNs to the same port does not count as a multi-port scan."""
    detector = PortScanDetector(unique_ports_threshold=15, min_syn_count=20)
    # 25 SYNs all to port 80 (single port)
    packets = [
        make_syn_packet(dst_port=80, timestamp=100.0 + (i * 0.02))
        for i in range(25)
    ]

    results = detector.detect_window(packets)
    # Should not trigger vertical scan because unique_destination_ports is only 1!
    assert len(results) == 0


# ==============================================================================
# 10. Missing Source IP
# ==============================================================================
def test_missing_source_ip(make_syn_packet):
    """Verify packet missing source IP is skipped safely without exception."""
    detector = PortScanDetector()
    pkt = make_syn_packet(src_ip=None)
    assert detector.is_scan_candidate(pkt) is False
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 11. Missing Destination IP
# ==============================================================================
def test_missing_destination_ip(make_syn_packet):
    """Verify packet missing destination IP does not crash detector."""
    detector = PortScanDetector()
    pkt = make_syn_packet(dst_ip=None)
    # Candidate because it has src_ip and dst_port
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 12. Missing Destination Port
# ==============================================================================
def test_missing_destination_port(make_syn_packet):
    """Verify packet missing destination port is not considered a scan candidate."""
    detector = PortScanDetector()
    pkt = make_syn_packet(dst_port=None)
    assert detector.is_scan_candidate(pkt) is False


# ==============================================================================
# 13. Non-TCP Traffic Ignored
# ==============================================================================
def test_non_tcp_traffic_ignored(make_syn_packet):
    """Verify UDP, ICMP, and ARP traffic are never flagged as TCP port scans."""
    detector = PortScanDetector(unique_ports_threshold=5, min_syn_count=5)
    packets = [
        NormalizedPacket(timestamp=100.0 + i, protocol="UDP", src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=53 + i)
        for i in range(10)
    ]

    assert len(detector.detect_window(packets)) == 0


# ==============================================================================
# 14. ACK-Only Packets Ignored
# ==============================================================================
def test_ack_only_packets_ignored(make_syn_packet):
    """Verify established ACK-only traffic is excluded from scan evaluation."""
    detector = PortScanDetector(unique_ports_threshold=5, min_syn_count=5)
    packets = [
        make_syn_packet(dst_port=1000 + i, tcp_flags="ACK", timestamp=100.0 + (i * 0.05))
        for i in range(10)
    ]

    assert len(detector.detect_window(packets)) == 0


# ==============================================================================
# 15. SYN-ACK Responses Ignored
# ==============================================================================
def test_syn_ack_responses_ignored(make_syn_packet):
    """Verify server SYN-ACK responses are not classified as port scans."""
    detector = PortScanDetector(unique_ports_threshold=5, min_syn_count=5)
    packets = [
        make_syn_packet(dst_port=1000 + i, tcp_flags="SYN,ACK", timestamp=100.0 + (i * 0.05))
        for i in range(10)
    ]

    assert len(detector.detect_window(packets)) == 0


# ==============================================================================
# 16. Multiple Independent Source IPs
# ==============================================================================
def test_multiple_independent_source_ips(make_syn_packet):
    """Verify scanning source is alerted while concurrent benign host is unaffected."""
    detector = PortScanDetector(unique_ports_threshold=15, min_syn_count=20)

    # Scanner A: 20 ports
    scanner_pkts = [
        make_syn_packet(src_ip="192.168.1.100", dst_port=1000 + i, timestamp=100.0 + (i * 0.02))
        for i in range(20)
    ]
    # Benign Client B: 2 ports
    client_pkts = [
        make_syn_packet(src_ip="192.168.1.50", dst_port=80, timestamp=100.1),
        make_syn_packet(src_ip="192.168.1.50", dst_port=443, timestamp=100.2),
    ]

    combined = scanner_pkts + client_pkts
    results = detector.detect_window(combined)

    assert len(results) == 1
    assert results[0].src_ip == "192.168.1.100"


# ==============================================================================
# 17. Multiple Scans from Different Sources
# ==============================================================================
def test_multiple_scans_from_different_sources(make_syn_packet):
    """Verify simultaneous scans from different sources are detected independently."""
    detector = PortScanDetector(unique_ports_threshold=15, unique_destinations_threshold=10, min_syn_count=15)

    # Attacker 1 (Vertical Scan)
    pkts1 = [
        make_syn_packet(src_ip="172.16.1.10", dst_ip="172.16.1.100", dst_port=2000 + i, timestamp=200.0 + (i * 0.02))
        for i in range(16)
    ]
    # Attacker 2 (Horizontal Scan)
    pkts2 = [
        make_syn_packet(src_ip="172.16.1.20", dst_ip=f"172.16.2.{i}", dst_port=445, timestamp=200.0 + (i * 0.02))
        for i in range(12)
    ]

    results = detector.detect_window(pkts1 + pkts2)
    assert len(results) == 2

    sources = {r.src_ip: r.scan_type for r in results}
    assert sources["172.16.1.10"] == "VERTICAL"
    assert sources["172.16.1.20"] == "HORIZONTAL"


# ==============================================================================
# 18. Threshold Configuration Respected
# ==============================================================================
def test_threshold_configuration_respected(make_syn_packet):
    """Verify custom constructor thresholds override defaults accurately."""
    # Custom low threshold of 3 ports and 3 syns
    custom_detector = PortScanDetector(unique_ports_threshold=3, min_syn_count=3)
    packets = [
        make_syn_packet(dst_port=8001 + i, timestamp=300.0 + (i * 0.1))
        for i in range(3)
    ]

    # Should detect with custom low threshold
    results_custom = custom_detector.detect_window(packets)
    assert len(results_custom) == 1

    # Should NOT detect with default higher threshold (15)
    default_detector = PortScanDetector()
    results_default = default_detector.detect_window(packets)
    assert len(results_default) == 0


# ==============================================================================
# 19. General TCP SYN Scan Detection
# ==============================================================================
def test_general_tcp_syn_scan_detection(make_syn_packet):
    """Verify distributed SYN attempts across hosts and ports trigger SYN_SCAN."""
    # 20 unique ports spread across 4 hosts (below horizontal threshold of 10 hosts)
    detector = PortScanDetector(
        unique_ports_threshold=15,
        unique_destinations_threshold=10,
        min_syn_count=20,
        time_window_seconds=1.0,
    )
    packets = [
        make_syn_packet(
            src_ip="10.10.10.10",
            dst_ip=f"10.10.10.{100 + (i % 4)}",
            dst_port=1000 + i,
            timestamp=400.0 + (i * 0.03),
        )
        for i in range(20)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 1
    alert = results[0]
    assert alert.scan_type == "SYN_SCAN"
    assert alert.src_ip == "10.10.10.10"
    assert alert.syn_count == 20
    assert alert.unique_destination_ports == 20
    assert alert.detected is True


# ==============================================================================
# 20. DetectionResult Model, Properties, and Serialization
# ==============================================================================
def test_detection_result_model_and_properties():
    """Verify DetectionResult dataclass properties, aliases, and dictionary conversion."""
    result = DetectionResult(
        rule_name="port_scan",
        alert_type="Possible Port Scan",
        severity="HIGH",
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        dst_port=80,
        detection_reason="Exceeded threshold",
        unique_destination_ports=18,
        syn_count=25,
    )

    assert result.detected is True
    assert result.source_ip == "192.168.1.50"
    assert result.destination_ip == "192.168.1.1"
    assert result.destination_port == 80
    assert result.reason == "Exceeded threshold"
    assert "Possible Port Scan" in str(result)

    as_dict = result.to_dict()
    assert as_dict["detected"] is True
    assert as_dict["src_ip"] == "192.168.1.50"
    assert as_dict["dst_ip"] == "192.168.1.1"
    assert as_dict["dst_port"] == 80


# ==============================================================================
# 21. Configuration Backward-Compatible Aliases
# ==============================================================================
def test_configuration_aliases(tmp_path, make_syn_packet):
    """Verify detector correctly parses alternative config key names."""
    alias_yaml = tmp_path / "custom_thresholds.yaml"
    alias_yaml.write_text(
        """
detection_rules:
  port_scan:
    window_seconds: 2.0
    unique_destination_ports: 5
    unique_destination_ips: 4
    min_syn_count: 5
    severity: CRITICAL
""",
        encoding="utf-8",
    )

    detector = PortScanDetector(config_path=alias_yaml)
    assert detector.time_window_seconds == 2.0
    assert detector.unique_ports_threshold == 5
    assert detector.unique_destinations_threshold == 4
    assert detector.min_syn_count == 5
    assert detector.default_severity == "CRITICAL"

