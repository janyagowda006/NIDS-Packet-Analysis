"""Unit tests for the TCP SYN Anomaly and Flood Detection engine."""

import pytest

from backend.analysis.traffic import TrafficAnalyzer
from backend.detection.models import DetectionResult
from backend.detection.syn_anomaly import SynAnomalyDetector
from backend.parser.models import NormalizedPacket


@pytest.fixture
def make_tcp_packet():
    """Helper fixture to create synthetic NormalizedPackets for TCP testing."""
    def _create(
        src_ip="192.168.1.100",
        dst_ip="192.168.1.200",
        src_port=40000,
        dst_port=80,
        tcp_flags="SYN",
        protocol="TCP",
        timestamp=1000.0,
        packet_length=60,
    ):
        return NormalizedPacket(
            timestamp=timestamp,
            packet_length=packet_length,
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
# 1. Empty Traffic -> No Detection
# ==============================================================================
def test_empty_traffic_no_detection():
    """Verify that empty packet collections produce zero detection results."""
    detector = SynAnomalyDetector()
    assert detector.detect_window([]) == []


# ==============================================================================
# 2. Normal TCP Traffic -> No Detection
# ==============================================================================
def test_normal_tcp_traffic_no_detection(make_tcp_packet):
    """Verify standard completed 3-way handshakes do not trigger anomaly alerts."""
    detector = SynAnomalyDetector()
    packets = [
        make_tcp_packet(src_port=50001, dst_port=443, tcp_flags="SYN", timestamp=100.0),
        make_tcp_packet(src_ip="192.168.1.200", dst_ip="192.168.1.100", src_port=443, dst_port=50001, tcp_flags="SYN,ACK", timestamp=100.01),
        make_tcp_packet(src_port=50001, dst_port=443, tcp_flags="ACK", timestamp=100.02),
    ]

    results = detector.detect_window(packets)
    assert len(results) == 0


# ==============================================================================
# 3. SYN Count Below Threshold -> No Detection
# ==============================================================================
def test_syn_count_below_threshold_no_detection(make_tcp_packet):
    """Verify SYN packet volume below rate threshold does not alert."""
    detector = SynAnomalyDetector(syn_rate_threshold=50, min_syn_for_ratio=50)
    packets = [
        make_tcp_packet(src_port=40000 + i, timestamp=100.0 + (i * 0.01))
        for i in range(25)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 0


# ==============================================================================
# 4. SYN Count Above Threshold -> Detection
# ==============================================================================
def test_syn_count_above_threshold_detection(make_tcp_packet):
    """Verify SYN burst exceeding rate threshold triggers explainable SYN_RATE_ANOMALY."""
    detector = SynAnomalyDetector(syn_rate_threshold=50, time_window_seconds=1.0)
    # 55 SYN packets within a 0.5s window
    packets = [
        make_tcp_packet(src_port=40000 + i, timestamp=100.0 + (i * 0.008))
        for i in range(55)
    ]

    results = detector.detect_window(packets)
    rate_alerts = [r for r in results if r.detection_type == "SYN_RATE_ANOMALY"]
    assert len(rate_alerts) == 1

    alert = rate_alerts[0]
    assert alert.rule_name == "syn_anomaly"
    assert alert.alert_type == "Possible SYN Flood / SYN Anomaly"
    assert alert.src_ip == "192.168.1.100"
    assert alert.dst_ip == "192.168.1.200"
    assert alert.syn_count == 55
    assert "exceeding configured threshold of 50" in alert.detection_reason
    assert alert.evidence["observed_syn_count"] == 55


# ==============================================================================
# 5. Exact Threshold Behavior
# ==============================================================================
def test_exact_threshold_behavior(make_tcp_packet):
    """Verify boundary behavior: count == threshold triggers, count < threshold does not."""
    detector = SynAnomalyDetector(syn_rate_threshold=50, min_syn_for_ratio=100)

    # 49 packets -> Below threshold
    pkts_49 = [
        make_tcp_packet(src_port=40000 + i, timestamp=100.0 + (i * 0.01))
        for i in range(49)
    ]
    assert len([r for r in detector.detect_window(pkts_49) if r.detection_type == "SYN_RATE_ANOMALY"]) == 0

    # 50 packets -> Exact threshold triggers
    pkts_50 = [
        make_tcp_packet(src_port=40000 + i, timestamp=100.0 + (i * 0.01))
        for i in range(50)
    ]
    results_50 = [r for r in detector.detect_window(pkts_50) if r.detection_type == "SYN_RATE_ANOMALY"]
    assert len(results_50) == 1
    assert results_50[0].syn_count == 50

    # 51 packets -> Above threshold triggers
    pkts_51 = [
        make_tcp_packet(src_port=40000 + i, timestamp=100.0 + (i * 0.01))
        for i in range(51)
    ]
    results_51 = [r for r in detector.detect_window(pkts_51) if r.detection_type == "SYN_RATE_ANOMALY"]
    assert len(results_51) == 1
    assert results_51[0].syn_count == 51


# ==============================================================================
# 6. SYN-ACK Packets Ignored
# ==============================================================================
def test_syn_ack_packets_ignored(make_tcp_packet):
    """Verify server SYN-ACK response packets are never counted as SYN candidates."""
    detector = SynAnomalyDetector(syn_rate_threshold=10)
    packets = [
        make_tcp_packet(src_port=80, dst_port=40000 + i, tcp_flags="SYN,ACK", timestamp=100.0 + (i * 0.01))
        for i in range(30)
    ]
    assert detector.detect_window(packets) == []


# ==============================================================================
# 7. ACK-Only Packets Ignored
# ==============================================================================
def test_ack_only_packets_ignored(make_tcp_packet):
    """Verify established ACK-only traffic is excluded from candidate evaluation."""
    detector = SynAnomalyDetector(syn_rate_threshold=10)
    packets = [
        make_tcp_packet(src_port=40000 + i, dst_port=80, tcp_flags="ACK", timestamp=100.0 + (i * 0.01))
        for i in range(30)
    ]
    assert detector.detect_window(packets) == []


# ==============================================================================
# 8. UDP Traffic Ignored
# ==============================================================================
def test_udp_ignored():
    """Verify UDP packets are never treated as TCP SYN candidates."""
    detector = SynAnomalyDetector(syn_rate_threshold=10)
    packets = [
        NormalizedPacket(timestamp=100.0 + i, protocol="UDP", src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=53)
        for i in range(30)
    ]
    assert detector.detect_window(packets) == []


# ==============================================================================
# 9. ICMP Traffic Ignored
# ==============================================================================
def test_icmp_ignored():
    """Verify ICMP packets are never counted towards SYN anomaly rates."""
    detector = SynAnomalyDetector(syn_rate_threshold=10)
    packets = [
        NormalizedPacket(timestamp=100.0 + i, protocol="ICMP", src_ip="1.1.1.1", dst_ip="2.2.2.2", icmp_type=8)
        for i in range(30)
    ]
    assert detector.detect_window(packets) == []


# ==============================================================================
# 10. RST and FIN Packets Ignored
# ==============================================================================
def test_rst_fin_packets_ignored(make_tcp_packet):
    """Verify TCP RST and FIN packets are excluded from candidate evaluation."""
    detector = SynAnomalyDetector(syn_rate_threshold=10)
    packets = [
        make_tcp_packet(src_port=40000 + i, tcp_flags="RST", timestamp=100.0 + (i * 0.01))
        for i in range(15)
    ] + [
        make_tcp_packet(src_port=40000 + i, tcp_flags="FIN", timestamp=100.2 + (i * 0.01))
        for i in range(15)
    ]
    assert detector.detect_window(packets) == []


# ==============================================================================
# 11. SYN Retransmissions Handled Correctly
# ==============================================================================
def test_syn_retransmissions_handled_correctly(make_tcp_packet):
    """Verify duplicate SYNs for same flow count toward packet volume but represent 1 attempt."""
    detector = SynAnomalyDetector(
        syn_rate_threshold=50,
        incomplete_ratio_threshold=0.8,
        min_syn_for_ratio=5,
    )
    # 20 retransmitted SYNs for the exact same connection (same src_port=45000)
    packets = [
        make_tcp_packet(src_port=45000, dst_port=80, timestamp=100.0 + (i * 0.02))
        for i in range(20)
    ]

    results = detector.detect_window(packets)
    # 20 is below syn_rate_threshold of 50
    # And total unique connection attempts is 1 (< min_syn_for_ratio of 5), so no ratio false-positive
    assert len(results) == 0


# ==============================================================================
# 12. Incomplete Connection Ratio Below Threshold
# ==============================================================================
def test_incomplete_connection_ratio_below_threshold(make_tcp_packet):
    """Verify that when the ratio of incomplete connections is low, no anomaly is alerted."""
    detector = SynAnomalyDetector(
        syn_rate_threshold=100,
        incomplete_ratio_threshold=0.8,
        min_syn_for_ratio=10,
    )

    # 10 connection attempts total:
    # 6 completed handshakes (SYN, SYN-ACK, ACK)
    # 4 incomplete (only SYN)
    packets = []
    for i in range(6):
        c_port = 50000 + i
        t = 100.0 + (i * 0.05)
        packets.append(make_tcp_packet(src_port=c_port, dst_port=80, tcp_flags="SYN", timestamp=t))
        packets.append(make_tcp_packet(src_ip="192.168.1.200", dst_ip="192.168.1.100", src_port=80, dst_port=c_port, tcp_flags="SYN,ACK", timestamp=t + 0.005))
        packets.append(make_tcp_packet(src_port=c_port, dst_port=80, tcp_flags="ACK", timestamp=t + 0.010))

    for i in range(4):
        c_port = 51000 + i
        t = 100.4 + (i * 0.05)
        packets.append(make_tcp_packet(src_port=c_port, dst_port=80, tcp_flags="SYN", timestamp=t))

    results = detector.detect_window(packets)
    # Incomplete ratio is 4/10 = 0.40 (< 0.80) -> No detection
    ratio_alerts = [r for r in results if r.detection_type == "SYN_INCOMPLETE_ANOMALY"]
    assert len(ratio_alerts) == 0


# ==============================================================================
# 13. Incomplete Connection Ratio Above Threshold
# ==============================================================================
def test_incomplete_connection_ratio_above_threshold(make_tcp_packet):
    """Verify that high incomplete ratio triggers explainable SYN_INCOMPLETE_ANOMALY."""
    detector = SynAnomalyDetector(
        syn_rate_threshold=100,
        incomplete_ratio_threshold=0.8,
        min_syn_for_ratio=10,
    )

    # 10 connection attempts total:
    # 1 completed handshake
    # 9 incomplete (only SYN)
    packets = []
    # 1 completed connection
    packets.append(make_tcp_packet(src_port=50000, dst_port=80, tcp_flags="SYN", timestamp=100.0))
    packets.append(make_tcp_packet(src_ip="192.168.1.200", dst_ip="192.168.1.100", src_port=80, dst_port=50000, tcp_flags="SYN,ACK", timestamp=100.01))
    packets.append(make_tcp_packet(src_port=50000, dst_port=80, tcp_flags="ACK", timestamp=100.02))

    # 9 incomplete connections
    for i in range(1, 10):
        c_port = 50000 + i
        packets.append(make_tcp_packet(src_port=c_port, dst_port=80, tcp_flags="SYN", timestamp=100.05 + (i * 0.02)))

    results = detector.detect_window(packets)
    ratio_alerts = [r for r in results if r.detection_type == "SYN_INCOMPLETE_ANOMALY"]
    assert len(ratio_alerts) == 1

    alert = ratio_alerts[0]
    assert alert.scan_type == "SYN_INCOMPLETE_ANOMALY"
    assert alert.incomplete_ratio == 0.9
    assert alert.src_ip == "192.168.1.100"
    assert "incomplete connection attempts out of 10" in alert.detection_reason
    assert alert.evidence["incomplete_connections_count"] == 9
    assert alert.evidence["completed_connections_count"] == 1


# ==============================================================================
# 14. Completed TCP Handshakes Reduce Incomplete Ratio
# ==============================================================================
def test_completed_handshakes_reduce_incomplete_ratio(make_tcp_packet):
    """Verify that established handshakes dynamically lower the incomplete ratio."""
    detector = SynAnomalyDetector(
        syn_rate_threshold=100,
        incomplete_ratio_threshold=0.8,
        min_syn_for_ratio=10,
    )

    # 10 attempts without responses -> 100% incomplete -> triggers alert
    incomplete_pkts = [
        make_tcp_packet(src_port=60000 + i, dst_port=80, tcp_flags="SYN", timestamp=200.0 + (i * 0.01))
        for i in range(10)
    ]
    results_incomplete = detector.detect_window(incomplete_pkts)
    assert len([r for r in results_incomplete if r.detection_type == "SYN_INCOMPLETE_ANOMALY"]) == 1

    # Now add handshakes for 5 of those connections
    handshake_responses = []
    for i in range(5):
        c_port = 60000 + i
        t = 200.0 + (i * 0.01)
        handshake_responses.append(make_tcp_packet(src_ip="192.168.1.200", dst_ip="192.168.1.100", src_port=80, dst_port=c_port, tcp_flags="SYN,ACK", timestamp=t + 0.002))
        handshake_responses.append(make_tcp_packet(src_port=c_port, dst_port=80, tcp_flags="ACK", timestamp=t + 0.004))

    all_packets = incomplete_pkts + handshake_responses
    results_reduced = detector.detect_window(all_packets)
    # Ratio is now 5/10 = 0.50 (< 0.80) -> Alert clears!
    assert len([r for r in results_reduced if r.detection_type == "SYN_INCOMPLETE_ANOMALY"]) == 0


# ==============================================================================
# 15. Multiple Source IPs Handled Independently
# ==============================================================================
def test_multiple_source_ips_handled_independently(make_tcp_packet):
    """Verify that flooding source is alerted while concurrent benign host is unflagged."""
    detector = SynAnomalyDetector(syn_rate_threshold=50, min_syn_for_ratio=50)

    # Attacker A: 55 SYNs
    attacker_pkts = [
        make_tcp_packet(src_ip="10.0.0.100", src_port=30000 + i, timestamp=300.0 + (i * 0.005))
        for i in range(55)
    ]
    # Benign User B: 3 SYNs
    benign_pkts = [
        make_tcp_packet(src_ip="10.0.0.200", src_port=40000 + i, timestamp=300.1 + (i * 0.05))
        for i in range(3)
    ]

    results = detector.detect_window(attacker_pkts + benign_pkts)
    rate_alerts = [r for r in results if r.detection_type == "SYN_RATE_ANOMALY"]
    assert len(rate_alerts) == 1
    assert rate_alerts[0].src_ip == "10.0.0.100"


# ==============================================================================
# 16. Multiple Destinations Handled Correctly
# ==============================================================================
def test_multiple_destinations_handled_correctly(make_tcp_packet):
    """Verify that SYN floods fanning across multiple destinations record evidence."""
    detector = SynAnomalyDetector(syn_rate_threshold=50)
    packets = [
        make_tcp_packet(
            src_ip="172.16.0.50",
            dst_ip=f"172.16.1.{10 + (i % 5)}",
            src_port=50000 + i,
            timestamp=400.0 + (i * 0.005),
        )
        for i in range(60)
    ]

    results = detector.detect_window(packets)
    assert len(results) >= 1
    alert = results[0]
    assert alert.src_ip == "172.16.0.50"
    assert alert.unique_destination_ips == 5
    assert len(alert.evidence["sample_destination_ips"]) == 5


# ==============================================================================
# 17. Sliding Window Expiration
# ==============================================================================
def test_sliding_window_expiration(make_tcp_packet):
    """Verify incremental processing discards packets outside active time window."""
    detector = SynAnomalyDetector(time_window_seconds=1.0, syn_rate_threshold=50, min_syn_for_ratio=50)

    # 40 packets at t=10.0
    for i in range(40):
        detector.process_packet(make_tcp_packet(src_port=20000 + i, timestamp=10.0 + (i * 0.01)))

    assert len(detector._syn_buffer) == 40

    # Advance time to t=50.0 (past 1.0s window) with 20 packets
    for i in range(20):
        alerts = detector.process_packet(make_tcp_packet(src_port=30000 + i, timestamp=50.0 + (i * 0.01)))
        assert len(alerts) == 0

    # Window should only contain the 20 new packets
    assert len(detector._syn_buffer) == 20


# ==============================================================================
# 18. Packets Outside Configured Window Ignored
# ==============================================================================
def test_packets_outside_configured_window_ignored(make_tcp_packet):
    """Verify connection attempts spread across long intervals do not accumulate."""
    detector = SynAnomalyDetector(time_window_seconds=1.0, syn_rate_threshold=20)
    # 30 SYNs spaced 2.0s apart (span of 60 seconds)
    packets = [
        make_tcp_packet(src_port=40000 + i, timestamp=100.0 + (i * 2.0))
        for i in range(30)
    ]

    results = detector.detect_window(packets, time_window_seconds=1.0, end_time=160.0)
    assert len(results) == 0


# ==============================================================================
# 19. Missing Source IP Handled Safely
# ==============================================================================
def test_missing_source_ip_handled_safely(make_tcp_packet):
    """Verify packet with missing source IP is safely ignored."""
    detector = SynAnomalyDetector()
    pkt = make_tcp_packet(src_ip=None)
    assert detector.is_syn_candidate(pkt) is False
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 20. Missing Destination IP Handled Safely
# ==============================================================================
def test_missing_destination_ip_handled_safely(make_tcp_packet):
    """Verify packet missing destination IP does not crash detector."""
    detector = SynAnomalyDetector()
    pkt = make_tcp_packet(dst_ip=None)
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 21. Missing TCP Ports Handled Safely
# ==============================================================================
def test_missing_tcp_ports_handled_safely(make_tcp_packet):
    """Verify packets missing source or destination port do not cause errors."""
    detector = SynAnomalyDetector()
    pkt1 = make_tcp_packet(src_port=None)
    pkt2 = make_tcp_packet(dst_port=None)

    assert detector.is_syn_candidate(pkt2) is False
    assert detector.process_packet(pkt1) == []
    assert detector.process_packet(pkt2) == []


# ==============================================================================
# 22. Malformed / Incomplete Packet Objects Do Not Crash
# ==============================================================================
def test_malformed_incomplete_packets_do_not_crash():
    """Verify raw or empty NormalizedPacket instances are handled gracefully."""
    detector = SynAnomalyDetector()
    empty_pkt = NormalizedPacket()
    assert detector.is_syn_candidate(empty_pkt) is False
    assert detector.process_packet(empty_pkt) == []


# ==============================================================================
# 23. Custom Configuration Thresholds Respected
# ==============================================================================
def test_custom_configuration_thresholds_respected(make_tcp_packet):
    """Verify constructor parameters override defaults accurately."""
    custom_detector = SynAnomalyDetector(syn_rate_threshold=10, min_syn_for_ratio=5)
    packets = [
        make_tcp_packet(src_port=40000 + i, timestamp=100.0 + (i * 0.02))
        for i in range(12)
    ]

    # Should detect on custom detector
    custom_results = custom_detector.detect_window(packets)
    assert len([r for r in custom_results if r.detection_type == "SYN_RATE_ANOMALY"]) == 1

    # Should NOT detect on default detector (threshold=50)
    default_detector = SynAnomalyDetector()
    default_results = default_detector.detect_window(packets)
    assert len([r for r in default_results if r.detection_type == "SYN_RATE_ANOMALY"]) == 0


# ==============================================================================
# 24. Detection Result Contains Explainable Evidence
# ==============================================================================
def test_detection_result_contains_explainable_evidence(make_tcp_packet):
    """Verify DetectionResult exposes clear evidence, properties, and dictionary format."""
    detector = SynAnomalyDetector(
        syn_rate_threshold=20,
        incomplete_ratio_threshold=0.7,
        min_syn_for_ratio=10,
    )
    packets = [
        make_tcp_packet(src_port=50000 + i, dst_ip="192.168.1.50", timestamp=100.0 + (i * 0.01))
        for i in range(25)
    ]

    results = detector.detect_window(packets)
    assert len(results) >= 1

    for res in results:
        assert res.detected is True
        assert res.source_ip == "192.168.1.100"
        assert res.destination_ip == "192.168.1.50"
        assert len(res.reason) > 0
        assert res.syn_count == 25
        assert "evidence" in res.to_dict()
        assert res.to_dict()["rule_name"] == "syn_anomaly"


# ==============================================================================
# 25. No Duplicate / Unbounded Detections During Continuous Traffic
# ==============================================================================
def test_no_duplicate_unbounded_detections_during_continuous_traffic(make_tcp_packet):
    """Verify alert cooldown suppresses flood of identical alerts during sustained stream."""
    detector = SynAnomalyDetector(
        syn_rate_threshold=30,
        alert_cooldown_seconds=10.0,
        time_window_seconds=1.0,
    )

    alert_count = 0
    # Stream 100 consecutive SYN packets within a 0.5s burst
    for i in range(100):
        alerts = detector.process_packet(
            make_tcp_packet(src_port=40000 + i, timestamp=100.0 + (i * 0.005))
        )
        alert_count += len(alerts)

    # First threshold crossing emits alert; subsequent packets in the burst are suppressed by cooldown
    assert alert_count == 2  # 1 for SYN_RATE_ANOMALY, 1 for SYN_INCOMPLETE_ANOMALY
