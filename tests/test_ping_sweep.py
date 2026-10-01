"""Unit tests for the ICMP Ping Sweep Detection engine."""

import pytest

from backend.detection.arp_anomaly import ARPAnomalyDetector
from backend.detection.models import DetectionResult
from backend.detection.ping_sweep import PingSweepDetector
from backend.detection.port_scan import PortScanDetector
from backend.detection.syn_anomaly import SynAnomalyDetector
from backend.parser.models import NormalizedPacket


@pytest.fixture
def make_icmp_packet():
    """Helper fixture to create synthetic NormalizedPackets representing ICMP frames."""
    def _create(
        src_ip="10.0.0.5",
        dst_ip="10.0.0.1",
        icmp_type=8,
        icmp_code=0,
        timestamp=1000.0,
        protocol="ICMP",
    ):
        return NormalizedPacket(
            timestamp=timestamp,
            packet_length=64,
            src_mac="00:11:22:33:44:55",
            dst_mac="66:77:88:99:aa:bb",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
        )
    return _create


# ==============================================================================
# 1. Normal Single Ping Does Not Alert
# ==============================================================================
def test_normal_single_ping_no_alert(make_icmp_packet):
    """Verify a single standard ping request generates zero alerts."""
    detector = PingSweepDetector()
    pkt = make_icmp_packet(src_ip="192.168.1.50", dst_ip="192.168.1.1", icmp_type=8)

    results = detector.process_packet(pkt)
    assert len(results) == 0


# ==============================================================================
# 2. Repeated Ping to One Destination Does Not Alert
# ==============================================================================
def test_repeated_ping_single_destination_no_alert(make_icmp_packet):
    """Verify multiple ICMP requests sent to a single target host do not trigger sweep alert."""
    detector = PingSweepDetector(unique_dst_ips_threshold=10, min_icmp_count=10)
    # 25 pings all targeting 192.168.1.1
    packets = [
        make_icmp_packet(src_ip="192.168.1.50", dst_ip="192.168.1.1", timestamp=100.0 + (i * 0.05))
        for i in range(25)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 0


# ==============================================================================
# 3. Below-Threshold Unique Destinations Does Not Alert
# ==============================================================================
def test_below_threshold_unique_destinations_no_alert(make_icmp_packet):
    """Verify ICMP requests below the unique host threshold produce zero alerts."""
    detector = PingSweepDetector(unique_dst_ips_threshold=10, min_icmp_count=10)
    # 5 targets (threshold is 10)
    packets = [
        make_icmp_packet(dst_ip=f"10.0.0.{10 + i}", timestamp=100.0 + (i * 0.1))
        for i in range(5)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 0


# ==============================================================================
# 4. Ping Sweep Above Threshold Alerts
# ==============================================================================
def test_ping_sweep_above_threshold_alerts(make_icmp_packet):
    """Verify ICMP echo requests targeting many unique hosts triggers explainable alert."""
    detector = PingSweepDetector(
        time_window_seconds=2.0,
        unique_dst_ips_threshold=10,
        min_icmp_count=10,
    )
    # 12 unique targets pinged within 1.0 second
    packets = [
        make_icmp_packet(src_ip="10.0.0.5", dst_ip=f"10.0.0.{100 + i}", timestamp=100.0 + (i * 0.08))
        for i in range(12)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 1

    alert = results[0]
    assert alert.rule_name == "ping_sweep"
    assert alert.alert_type == "Possible Ping Sweep"
    assert alert.scan_type == "PING_SWEEP"
    assert alert.detection_type == "PING_SWEEP"
    assert alert.src_ip == "10.0.0.5"
    assert alert.unique_destination_ips == 12
    assert alert.icmp_count == 12
    assert alert.severity == "MEDIUM"
    assert "Possible ping sweep detected" in alert.detection_reason
    assert "exceeding configured threshold of 10" in alert.detection_reason
    assert alert.evidence["unique_destination_ips_count"] == 12


# ==============================================================================
# 5. Minimum ICMP Request Threshold is Respected
# ==============================================================================
def test_minimum_icmp_request_threshold_respected(make_icmp_packet):
    """Verify sweep requires meeting both unique destinations count AND min request volume."""
    detector = PingSweepDetector(unique_dst_ips_threshold=5, min_icmp_count=15)

    # 10 unique destinations (meets unique threshold 5, but only 10 total requests < min_icmp_count 15)
    packets = [
        make_icmp_packet(dst_ip=f"10.0.0.{10 + i}", timestamp=100.0 + (i * 0.05))
        for i in range(10)
    ]

    assert len(detector.detect_window(packets)) == 0


# ==============================================================================
# 6. Unique Destination Counting Works Correctly
# ==============================================================================
def test_unique_destination_counting_works(make_icmp_packet):
    """Verify unique_destination_ips accurately matches distinct targets."""
    detector = PingSweepDetector(unique_dst_ips_threshold=10, min_icmp_count=10)
    packets = [
        make_icmp_packet(dst_ip=f"172.16.1.{i}", timestamp=200.0 + (i * 0.05))
        for i in range(15)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 1
    assert results[0].unique_destination_ips == 15
    assert len(results[0].evidence["sample_destination_ips"]) == 15


# ==============================================================================
# 7. Duplicate Destination Packets Do Not Inflate Unique Count
# ==============================================================================
def test_duplicate_destination_packets_do_not_inflate_count(make_icmp_packet):
    """Verify repeated probes to the same hosts do not artificially increase unique target count."""
    detector = PingSweepDetector(unique_dst_ips_threshold=10, min_icmp_count=10)

    # 15 total requests, but targeting only 3 unique hosts (5 requests each)
    packets = []
    for host_id in range(3):
        for req in range(5):
            packets.append(
                make_icmp_packet(
                    dst_ip=f"10.0.0.{10 + host_id}",
                    timestamp=300.0 + (host_id * 0.2) + (req * 0.02),
                )
            )

    assert len(packets) == 15
    results = detector.detect_window(packets)
    # Unique destinations is only 3 (< threshold 10), so no alert
    assert len(results) == 0


# ==============================================================================
# 8. ICMP Echo Replies Are Ignored
# ==============================================================================
def test_icmp_echo_replies_ignored(make_icmp_packet):
    """Verify server Echo Replies (type 0) are never counted as outbound sweep probes."""
    detector = PingSweepDetector(unique_dst_ips_threshold=5, min_icmp_count=5)
    packets = [
        make_icmp_packet(dst_ip=f"10.0.0.{i}", icmp_type=0, timestamp=100.0 + (i * 0.05))
        for i in range(20)
    ]

    assert len(detector.detect_window(packets)) == 0


# ==============================================================================
# 9. Non-ICMP Traffic is Ignored
# ==============================================================================
def test_non_icmp_traffic_ignored():
    """Verify TCP, UDP, and ARP traffic are completely excluded from sweep tracking."""
    detector = PingSweepDetector(unique_dst_ips_threshold=5, min_icmp_count=5)
    packets = [
        NormalizedPacket(protocol="TCP", src_ip="10.0.0.1", dst_ip=f"10.0.0.{i}", dst_port=80, timestamp=100.0 + i)
        for i in range(20)
    ]

    assert len(detector.detect_window(packets)) == 0


# ==============================================================================
# 10. Other ICMP Message Types Ignored
# ==============================================================================
def test_other_icmp_types_ignored(make_icmp_packet):
    """Verify ICMP Destination Unreachable (3) and Time Exceeded (11) are ignored."""
    detector = PingSweepDetector(unique_dst_ips_threshold=5, min_icmp_count=5)
    unreachable_pkts = [
        make_icmp_packet(dst_ip=f"10.0.0.{i}", icmp_type=3, icmp_code=1, timestamp=100.0 + (i * 0.05))
        for i in range(10)
    ]
    ttl_exceeded_pkts = [
        make_icmp_packet(dst_ip=f"10.0.0.{i}", icmp_type=11, icmp_code=0, timestamp=100.5 + (i * 0.05))
        for i in range(10)
    ]

    assert len(detector.detect_window(unreachable_pkts + ttl_exceeded_pkts)) == 0


# ==============================================================================
# 11. Missing Source IP Handled Safely
# ==============================================================================
def test_missing_source_ip_handled_safely(make_icmp_packet):
    """Verify packet with missing source IP is safely skipped without exception."""
    detector = PingSweepDetector()
    pkt = make_icmp_packet(src_ip=None)

    assert detector.is_echo_request_candidate(pkt) is False
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 12. Missing Destination IP Handled Safely
# ==============================================================================
def test_missing_destination_ip_handled_safely(make_icmp_packet):
    """Verify packet with missing destination IP is safely skipped without exception."""
    detector = PingSweepDetector()
    pkt = make_icmp_packet(dst_ip=None)

    assert detector.is_echo_request_candidate(pkt) is False
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 13. Empty Input Handled Safely
# ==============================================================================
def test_empty_input_handled_safely():
    """Verify empty packet collections or blank models produce zero detections."""
    detector = PingSweepDetector()
    assert detector.detect_window([]) == []
    empty_pkt = NormalizedPacket(protocol="ICMP")
    assert detector.process_packet(empty_pkt) == []


# ==============================================================================
# 14. Packets Outside Time Window Excluded
# ==============================================================================
def test_packets_outside_time_window_excluded(make_icmp_packet):
    """Verify incremental processing discards packets that have aged out of active window."""
    detector = PingSweepDetector(time_window_seconds=2.0, unique_dst_ips_threshold=10, min_icmp_count=10)

    # 8 packets at t=10.0
    for i in range(8):
        detector.process_packet(make_icmp_packet(dst_ip=f"10.0.0.{i}", timestamp=10.0 + (i * 0.05)))

    assert len(detector._icmp_buffer) == 8

    # Advance time to t=50.0 (past 2.0s window) with 4 packets
    for i in range(4):
        alerts = detector.process_packet(make_icmp_packet(dst_ip=f"10.0.0.{20 + i}", timestamp=50.0 + (i * 0.05)))
        assert len(alerts) == 0

    # Old packets from t=10 were pruned
    assert len(detector._icmp_buffer) == 4


# ==============================================================================
# 15. Window Boundary Behavior
# ==============================================================================
def test_window_boundary_behavior(make_icmp_packet):
    """Verify probes spaced outside the sliding window span do not accumulate into an alert."""
    detector = PingSweepDetector(time_window_seconds=2.0, unique_dst_ips_threshold=5, min_icmp_count=5)
    # 10 pings spaced 2.5s apart across 10 hosts (total 22.5s span)
    packets = [
        make_icmp_packet(dst_ip=f"10.0.0.{i}", timestamp=100.0 + (i * 2.5))
        for i in range(10)
    ]

    results = detector.detect_window(packets, time_window_seconds=2.0, end_time=125.0)
    assert len(results) == 0


# ==============================================================================
# 16. Multiple Source IPs Tracked Independently
# ==============================================================================
def test_multiple_source_ips_tracked_independently(make_icmp_packet):
    """Verify scanning host is alerted while concurrent benign host is unflagged."""
    detector = PingSweepDetector(unique_dst_ips_threshold=10, min_icmp_count=10)

    # Attacker A: 12 pings to 12 hosts
    attacker_pkts = [
        make_icmp_packet(src_ip="10.0.0.99", dst_ip=f"10.0.0.{100 + i}", timestamp=200.0 + (i * 0.05))
        for i in range(12)
    ]
    # Benign Host B: 2 pings to 2 hosts
    benign_pkts = [
        make_icmp_packet(src_ip="10.0.0.50", dst_ip=f"10.0.0.{200 + i}", timestamp=200.1 + (i * 0.05))
        for i in range(2)
    ]

    results = detector.detect_window(attacker_pkts + benign_pkts)
    assert len(results) == 1
    assert results[0].src_ip == "10.0.0.99"


# ==============================================================================
# 17. Alert Cooldown Suppresses Duplicate Alerts
# ==============================================================================
def test_alert_cooldown_suppresses_duplicate_alerts(make_icmp_packet):
    """Verify cooldown stops repeated alerts for every packet during sustained sweep."""
    detector = PingSweepDetector(
        unique_dst_ips_threshold=10,
        min_icmp_count=10,
        alert_cooldown_seconds=10.0,
        time_window_seconds=2.0,
    )

    alert_count = 0
    # Stream 30 consecutive requests across 30 hosts within 1.0 second
    for i in range(30):
        alerts = detector.process_packet(
            make_icmp_packet(src_ip="10.0.0.5", dst_ip=f"10.0.0.{100 + i}", timestamp=100.0 + (i * 0.03))
        )
        alert_count += len(alerts)

    # First threshold crossing at packet 10 alerts; subsequent packets in the burst are suppressed
    assert alert_count == 1


# ==============================================================================
# 18. Configured Thresholds Are Respected
# ==============================================================================
def test_configured_thresholds_respected(make_icmp_packet):
    """Verify constructor parameters accurately override default thresholds."""
    custom_detector = PingSweepDetector(unique_dst_ips_threshold=5, min_icmp_count=5)
    packets = [
        make_icmp_packet(dst_ip=f"10.0.0.{i}", timestamp=100.0 + (i * 0.05))
        for i in range(6)
    ]

    # Should detect on custom detector (threshold 5)
    assert len(custom_detector.detect_window(packets)) == 1

    # Should NOT detect on default detector (threshold 10)
    default_detector = PingSweepDetector()
    assert len(default_detector.detect_window(packets)) == 0


# ==============================================================================
# 19. Configured Severity is Respected
# ==============================================================================
def test_configured_severity_is_respected(make_icmp_packet):
    """Verify default_severity override is populated accurately in DetectionResult."""
    detector = PingSweepDetector(default_severity="HIGH", unique_dst_ips_threshold=5, min_icmp_count=5)
    packets = [
        make_icmp_packet(dst_ip=f"10.0.0.{i}", timestamp=100.0 + (i * 0.05))
        for i in range(6)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 1
    assert results[0].severity == "HIGH"


# ==============================================================================
# 20. DetectionResult Contains Useful Evidence
# ==============================================================================
def test_detection_result_contains_useful_evidence(make_icmp_packet):
    """Verify DetectionResult exposes clear evidence, properties, and dictionary format."""
    detector = PingSweepDetector(unique_dst_ips_threshold=10, min_icmp_count=10)
    packets = [
        make_icmp_packet(src_ip="10.0.0.5", dst_ip=f"10.0.0.{i}", timestamp=100.0 + (i * 0.05))
        for i in range(12)
    ]

    results = detector.detect_window(packets)
    assert len(results) == 1
    alert = results[0]

    assert alert.detected is True
    assert alert.source_ip == "10.0.0.5"
    assert alert.protocol == "ICMP"
    assert alert.observed_icmp_count == 12
    assert alert.unique_destination_ips == 12
    assert "Possible ping sweep" in alert.description

    as_dict = alert.to_dict()
    assert as_dict["rule_name"] == "ping_sweep"
    assert as_dict["icmp_count"] == 12
    assert as_dict["evidence"]["observed_icmp_count"] == 12
    assert len(as_dict["evidence"]["sample_destination_ips"]) == 12


# ==============================================================================
# 21. Detector Reset Clears State
# ==============================================================================
def test_detector_reset_clears_state(make_icmp_packet):
    """Verify reset() empties candidate buffers and cooldown caches."""
    detector = PingSweepDetector()
    for i in range(8):
        detector.process_packet(make_icmp_packet(dst_ip=f"10.0.0.{i}", timestamp=100.0 + (i * 0.1)))

    assert len(detector._icmp_buffer) == 8
    detector.reset()
    assert len(detector._icmp_buffer) == 0
    assert len(detector._last_alerted) == 0


# ==============================================================================
# 22. Existing Phase 5-7 Functionality Compatibility
# ==============================================================================
def test_existing_phase_5_to_7_compatibility():
    """Verify all detector engines operate seamlessly alongside PingSweepDetector."""
    port_scan = PortScanDetector()
    syn_anomaly = SynAnomalyDetector()
    arp_detector = ARPAnomalyDetector()
    ping_sweep = PingSweepDetector()

    assert port_scan.enabled is True
    assert syn_anomaly.enabled is True
    assert arp_detector.enabled is True
    assert ping_sweep.enabled is True

    result = DetectionResult(
        rule_name="ping_sweep",
        alert_type="Possible Ping Sweep",
        severity="MEDIUM",
        src_ip="10.0.0.5",
        protocol="ICMP",
        icmp_count=15,
        unique_destination_ips=15,
    )
    assert result.protocol == "ICMP"
    assert result.observed_icmp_count == 15
    assert result.to_dict()["icmp_count"] == 15
