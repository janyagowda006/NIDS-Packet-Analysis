"""Unit tests for the DNS Anomaly Detection engine."""

import pytest

from backend.detection import (
    ARPAnomalyDetector,
    DNSAnomalyDetector,
    DetectionResult,
    PingSweepDetector,
    PortScanDetector,
    SynAnomalyDetector,
)
from backend.parser.models import NormalizedPacket


@pytest.fixture
def make_dns_packet():
    """Helper fixture to create synthetic NormalizedPackets representing DNS queries."""
    def _create(
        src_ip="192.168.1.100",
        dst_ip="8.8.8.8",
        dns_query="example.com",
        dns_query_type="A",
        dns_is_response=False,
        src_port=54321,
        dst_port=53,
        timestamp=1000.0,
        protocol="DNS",
        packet_length=75,
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
            dns_query=dns_query,
            dns_query_type=dns_query_type,
            dns_is_response=dns_is_response,
        )
    return _create


# ==============================================================================
# RULE A — RATE DETECTION TESTS (1 to 10)
# ==============================================================================

def test_1_normal_dns_rate_no_alert(make_dns_packet):
    """1. Normal DNS query rate below the configured threshold produces no alert."""
    detector = DNSAnomalyDetector(rate_window_seconds=5.0, max_queries_per_window=25)
    # 10 queries over 2 seconds (well below threshold of 25)
    packets = [
        make_dns_packet(timestamp=100.0 + (i * 0.2))
        for i in range(10)
    ]
    alerts = []
    for pkt in packets:
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) == 0


def test_2_exactly_threshold_rate_no_alert(make_dns_packet):
    """2. Exactly threshold number of DNS queries produces no alert (strictly > threshold required)."""
    detector = DNSAnomalyDetector(rate_window_seconds=5.0, max_queries_per_window=25)
    # Exactly 25 queries in 2.5 seconds
    packets = [
        make_dns_packet(timestamp=100.0 + (i * 0.1))
        for i in range(25)
    ]
    alerts = []
    for pkt in packets:
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) == 0


def test_3_threshold_exceeded_rate_alerts(make_dns_packet):
    """3. Exceeding configured rate threshold triggers an explainable alert."""
    detector = DNSAnomalyDetector(rate_window_seconds=5.0, max_queries_per_window=25)
    # 26 queries (25 + 1) in 2.6 seconds
    packets = [
        make_dns_packet(src_ip="192.168.1.100", timestamp=100.0 + (i * 0.1))
        for i in range(26)
    ]
    alerts = []
    for pkt in packets:
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "dns_anomaly"
    assert alert.alert_type == "Possible DNS Anomaly"
    assert alert.detection_type == "DNS_QUERY_RATE_ANOMALY"
    assert alert.severity == "LOW"
    assert alert.src_ip == "192.168.1.100"
    assert alert.protocol == "DNS"
    assert alert.dns_query_count == 26
    assert alert.observed_query_count == 26
    assert alert.evidence["observed_query_count"] == 26
    assert alert.evidence["threshold_max_queries"] == 25
    assert "exceeding configured threshold of 25" in alert.detection_reason


def test_4_packets_outside_time_window_are_pruned(make_dns_packet):
    """4. Old queries outside the sliding window are pruned and do not count toward rate."""
    detector = DNSAnomalyDetector(rate_window_seconds=5.0, max_queries_per_window=25)

    # 20 queries at t=1.0 to t=2.9
    for i in range(20):
        alerts = detector.process_packet(make_dns_packet(timestamp=1.0 + (i * 0.1)))
        assert len(alerts) == 0

    # Advance time to t=8.0 (5s window is [3.0, 8.0], so t=1.0-2.9 queries are pruned)
    # Send 6 queries at t=8.0 to t=8.5 (total in active window is 6, well below 25)
    for i in range(6):
        alerts = detector.process_packet(make_dns_packet(timestamp=8.0 + (i * 0.1)))
        assert len(alerts) == 0

    # Now send 20 more at t=8.6 to t=8.9 (total in active window becomes 6 + 20 = 26 > 25)
    rate_alerts = []
    for i in range(20):
        rate_alerts.extend(detector.process_packet(make_dns_packet(timestamp=8.6 + (i * 0.01))))

    assert len(rate_alerts) == 1
    assert rate_alerts[0].dns_query_count == 26


def test_5_multiple_source_ips_tracked_independently(make_dns_packet):
    """5. Multiple source IPs are tracked independently for rate anomalies."""
    detector = DNSAnomalyDetector(rate_window_seconds=5.0, max_queries_per_window=25)

    # Source A sends 20 queries, Source B sends 15 queries (neither crosses 25)
    for i in range(20):
        alerts = detector.process_packet(make_dns_packet(src_ip="10.0.0.1", timestamp=100.0 + (i * 0.1)))
        assert len(alerts) == 0

    for i in range(15):
        alerts = detector.process_packet(make_dns_packet(src_ip="10.0.0.2", timestamp=100.0 + (i * 0.1)))
        assert len(alerts) == 0

    # Source A sends 6 more queries (total 26 > 25) -> triggers alert for Source A only
    alerts_a = []
    for i in range(6):
        alerts_a.extend(detector.process_packet(make_dns_packet(src_ip="10.0.0.1", timestamp=102.1 + (i * 0.1))))

    assert len(alerts_a) == 1
    assert alerts_a[0].src_ip == "10.0.0.1"

    # Source B sends 1 more query (total 16 <= 25) -> no alert
    alerts_b = detector.process_packet(make_dns_packet(src_ip="10.0.0.2", timestamp=102.7))
    assert len(alerts_b) == 0


def test_6_non_dns_packets_ignored(make_dns_packet):
    """6. Non-DNS packets (e.g., TCP HTTP, ICMP, ARP) are ignored and do not count toward rate."""
    detector = DNSAnomalyDetector(rate_window_seconds=5.0, max_queries_per_window=25)

    # 30 non-DNS packets
    packets = [
        NormalizedPacket(
            timestamp=100.0 + (i * 0.1),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=12345,
            dst_port=80,
            tcp_flags="SYN",
            dns_query=None,
        )
        for i in range(30)
    ]
    alerts = []
    for pkt in packets:
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) == 0


def test_7_dns_responses_ignored(make_dns_packet):
    """7. DNS responses are ignored and do not count as client queries."""
    detector = DNSAnomalyDetector(rate_window_seconds=5.0, max_queries_per_window=25)

    # 30 DNS response packets with dns_is_response=True
    packets = [
        make_dns_packet(
            src_ip="8.8.8.8",
            dst_ip="192.168.1.100",
            src_port=53,
            dst_port=54321,
            dns_is_response=True,
            timestamp=100.0 + (i * 0.1),
        )
        for i in range(30)
    ]
    alerts = []
    for pkt in packets:
        alerts.extend(detector.process_packet(pkt))

    assert len(alerts) == 0


def test_8_missing_source_ip_handled_safely(make_dns_packet):
    """8. Packets with missing or empty source IP are handled safely without crashing."""
    detector = DNSAnomalyDetector()

    pkt_none = make_dns_packet(src_ip=None)
    pkt_empty = make_dns_packet(src_ip="")

    assert detector.process_packet(pkt_none) == []
    assert detector.process_packet(pkt_empty) == []


def test_9_cooldown_prevents_duplicate_alerts(make_dns_packet):
    """9. Cooldown period suppresses duplicate alert floods from the same source IP."""
    detector = DNSAnomalyDetector(
        rate_window_seconds=5.0,
        max_queries_per_window=25,
        alert_cooldown_seconds=10.0,
    )

    # First burst: 26 queries at t=100.0 to t=102.5 -> triggers 1 alert
    alerts = []
    for i in range(26):
        alerts.extend(detector.process_packet(make_dns_packet(timestamp=100.0 + (i * 0.1))))

    assert len(alerts) == 1

    # Immediate additional 10 queries at t=103.0 to t=104.0 (within 10s cooldown)
    cooldown_alerts = []
    for i in range(10):
        cooldown_alerts.extend(detector.process_packet(make_dns_packet(timestamp=103.0 + (i * 0.1))))

    assert len(cooldown_alerts) == 0


def test_10_cooldown_expires_and_allows_another_alert(make_dns_packet):
    """10. After the cooldown window expires, a subsequent burst triggers another alert."""
    detector = DNSAnomalyDetector(
        rate_window_seconds=5.0,
        max_queries_per_window=25,
        alert_cooldown_seconds=10.0,
    )

    # First burst at t=100.0
    alerts_1 = []
    for i in range(26):
        alerts_1.extend(detector.process_packet(make_dns_packet(timestamp=100.0 + (i * 0.05))))

    assert len(alerts_1) == 1

    # Advance time to t=115.0 (> 10s cooldown elapsed since t=101.25)
    # Send 26 new queries in window [110.0, 115.0]
    alerts_2 = []
    for i in range(26):
        alerts_2.extend(detector.process_packet(make_dns_packet(timestamp=113.0 + (i * 0.05))))

    assert len(alerts_2) == 1
    assert alerts_2[0].timestamp >= 113.0


# ==============================================================================
# RULE B — LONG QUERY TESTS (11 to 14)
# ==============================================================================

def test_11_query_below_threshold_no_alert(make_dns_packet):
    """11. Query name length below configured threshold triggers no alert."""
    detector = DNSAnomalyDetector(max_query_length=100)
    # Normal query length: 15 chars
    pkt = make_dns_packet(dns_query="www.example.com")
    alerts = detector.process_packet(pkt)
    assert len(alerts) == 0


def test_12_query_exactly_at_threshold_no_alert(make_dns_packet):
    """12. Query name length exactly equal to threshold triggers no alert (strictly > required)."""
    detector = DNSAnomalyDetector(max_query_length=100, max_label_length=50)
    # Construct a 100-char domain where each label is <= 50 chars
    # "a"*45 + "." + "b"*45 + "." + "c"*8 = 45 + 1 + 45 + 1 + 8 = 100 chars
    query_100 = f"{'a' * 45}.{'b' * 45}.{'c' * 8}"
    assert len(query_100) == 100

    pkt = make_dns_packet(dns_query=query_100)
    alerts = detector.process_packet(pkt)
    assert len(alerts) == 0


def test_13_query_above_threshold_alerts(make_dns_packet):
    """13. Query name length exceeding configured threshold triggers long query alert."""
    detector = DNSAnomalyDetector(max_query_length=100, max_label_length=50)
    # Construct a 101-char domain where each label is <= 50 chars
    # "a"*45 + "." + "b"*45 + "." + "c"*9 = 45 + 1 + 45 + 1 + 9 = 101 chars
    query_101 = f"{'a' * 45}.{'b' * 45}.{'c' * 9}"
    assert len(query_101) == 101

    pkt = make_dns_packet(src_ip="192.168.1.100", dst_ip="8.8.8.8", dns_query=query_101)
    alerts = detector.process_packet(pkt)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "dns_anomaly"
    assert alert.detection_type == "DNS_LONG_QUERY_ANOMALY"
    assert alert.src_ip == "192.168.1.100"
    assert alert.dst_ip == "8.8.8.8"
    assert alert.query_name == query_101
    assert alert.query_length == 101


def test_14_evidence_contains_observed_query_length_and_threshold(make_dns_packet):
    """14. Long query alert evidence details observed length, threshold, query, and hosts."""
    detector = DNSAnomalyDetector(max_query_length=100, max_label_length=50)
    query_105 = f"{'a' * 45}.{'b' * 45}.{'c' * 13}"  # 105 chars
    assert len(query_105) == 105

    pkt = make_dns_packet(src_ip="10.10.10.5", dst_ip="1.1.1.1", dns_query=query_105)
    alerts = detector.process_packet(pkt)

    assert len(alerts) == 1
    evidence = alerts[0].evidence
    assert evidence["source_ip"] == "10.10.10.5"
    assert evidence["destination_ip"] == "1.1.1.1"
    assert evidence["query_name"] == query_105
    assert evidence["observed_query_length"] == 105
    assert evidence["configured_max_query_length"] == 100
    assert evidence["threshold_max_query_length"] == 100
    assert "105 chars" in alerts[0].detection_reason
    assert "threshold of 100" in alerts[0].detection_reason


# ==============================================================================
# RULE C — LONG LABEL TESTS (15 to 18)
# ==============================================================================

def test_15_normal_labels_no_alert(make_dns_packet):
    """15. Normal domain labels below configured label threshold trigger no alert."""
    detector = DNSAnomalyDetector(max_label_length=50)
    pkt = make_dns_packet(dns_query="subdomain.lab.example.org")
    alerts = detector.process_packet(pkt)
    assert len(alerts) == 0


def test_16_label_exactly_at_threshold_no_alert(make_dns_packet):
    """16. Label length exactly equal to threshold triggers no alert (strictly > required)."""
    detector = DNSAnomalyDetector(max_query_length=200, max_label_length=50)
    # Label of exactly 50 chars + short domain
    label_50 = "x" * 50
    query = f"{label_50}.example.com"

    pkt = make_dns_packet(dns_query=query)
    alerts = detector.process_packet(pkt)
    assert len(alerts) == 0


def test_17_label_above_threshold_alerts(make_dns_packet):
    """17. Label length exceeding configured label threshold triggers long label alert."""
    detector = DNSAnomalyDetector(max_query_length=200, max_label_length=50)
    # Label of 51 chars
    label_51 = "y" * 51
    query = f"{label_51}.example.com"

    pkt = make_dns_packet(src_ip="192.168.1.55", dst_ip="8.8.4.4", dns_query=query)
    alerts = detector.process_packet(pkt)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "dns_anomaly"
    assert alert.detection_type == "DNS_LONG_LABEL_ANOMALY"
    assert alert.src_ip == "192.168.1.55"
    assert alert.dst_ip == "8.8.4.4"
    assert alert.query_name == query


def test_18_evidence_identifies_the_long_label(make_dns_packet):
    """18. Evidence precisely identifies the offending long label and its length."""
    detector = DNSAnomalyDetector(max_query_length=200, max_label_length=50)
    label_55 = "z" * 55
    query = f"prefix.{label_55}.corp.internal"

    pkt = make_dns_packet(src_ip="192.168.1.55", dst_ip="8.8.4.4", dns_query=query)
    alerts = detector.process_packet(pkt)

    assert len(alerts) == 1
    evidence = alerts[0].evidence
    assert evidence["source_ip"] == "192.168.1.55"
    assert evidence["destination_ip"] == "8.8.4.4"
    assert evidence["longest_label"] == label_55
    assert evidence["observed_label_length"] == 55
    assert evidence["threshold_max_label_length"] == 50
    assert label_55 in evidence["long_labels"]
    assert "containing label" in alerts[0].detection_reason
    assert "55 chars" in alerts[0].detection_reason


# ==============================================================================
# ROBUSTNESS AND INTEGRATION TESTS (19 to 24)
# ==============================================================================

def test_19_empty_input(make_dns_packet):
    """19. Empty input or None returns empty results without crashing."""
    detector = DNSAnomalyDetector()
    assert detector.process_packet(None) == []  # type: ignore[arg-type]
    assert detector.detect_window([]) == []


def test_20_malformed_incomplete_dns_packet(make_dns_packet):
    """20. Malformed or incomplete packets do not crash the detector."""
    detector = DNSAnomalyDetector()

    # Packet with dns_query as None
    pkt_none_query = NormalizedPacket(protocol="DNS", src_ip="1.2.3.4", dns_query=None)
    assert detector.process_packet(pkt_none_query) == []

    # Packet with empty query string
    pkt_empty_query = NormalizedPacket(protocol="DNS", src_ip="1.2.3.4", dns_query="   ")
    assert detector.process_packet(pkt_empty_query) == []

    # Packet with non-string query
    pkt_int_query = NormalizedPacket(protocol="DNS", src_ip="1.2.3.4", dns_query=12345)  # type: ignore[arg-type]
    assert detector.process_packet(pkt_int_query) == []


def test_21_multiple_dns_queries_from_different_sources(make_dns_packet):
    """21. Interleaved traffic from different sources detects long queries accurately."""
    detector = DNSAnomalyDetector(max_query_length=80, max_label_length=40)

    pkt_normal_1 = make_dns_packet(src_ip="10.0.0.1", dns_query="normal.com")
    pkt_long_query = make_dns_packet(
        src_ip="10.0.0.2",
        dns_query="sub." + ("a" * 35) + "." + ("b" * 35) + ".example.com",  # len 4+35+1+35+1+11 = 87 > 80
    )
    pkt_normal_2 = make_dns_packet(src_ip="10.0.0.3", dns_query="google.com")
    pkt_long_label = make_dns_packet(
        src_ip="10.0.0.4",
        dns_query=("z" * 45) + ".lab.test",  # label 45 > 40, total 54 <= 80
    )

    r1 = detector.process_packet(pkt_normal_1)
    assert len(r1) == 0

    r2 = detector.process_packet(pkt_long_query)
    assert len(r2) == 1
    assert r2[0].src_ip == "10.0.0.2"
    assert r2[0].detection_type == "DNS_LONG_QUERY_ANOMALY"

    r3 = detector.process_packet(pkt_normal_2)
    assert len(r3) == 0

    r4 = detector.process_packet(pkt_long_label)
    assert len(r4) == 1
    assert r4[0].src_ip == "10.0.0.4"
    assert r4[0].detection_type == "DNS_LONG_LABEL_ANOMALY"


def test_22_configuration_thresholds_are_respected(make_dns_packet):
    """22. Custom configured thresholds are strictly respected."""
    detector = DNSAnomalyDetector(
        rate_window_seconds=2.0,
        max_queries_per_window=5,
        max_query_length=30,
        max_label_length=15,
    )

    # 1. Long query with custom threshold 30 (len 31 triggers)
    q31 = "a" * 14 + "." + "b" * 14 + ".com"  # 14 + 1 + 14 + 1 + 3 = 33 chars
    res_q = detector.process_packet(make_dns_packet(dns_query=q31))
    assert any(r.detection_type == "DNS_LONG_QUERY_ANOMALY" for r in res_q)

    # 2. Long label with custom threshold 15 (len 16 triggers)
    lbl16 = ("c" * 16) + ".io"
    res_l = detector.process_packet(make_dns_packet(src_ip="10.0.0.99", dns_query=lbl16))
    assert any(r.detection_type == "DNS_LONG_LABEL_ANOMALY" for r in res_l)

    # 3. Rate with custom threshold 5 (6 queries triggers)
    detector.reset()
    rate_res = []
    for i in range(6):
        rate_res.extend(detector.process_packet(make_dns_packet(src_ip="10.0.0.50", timestamp=10.0 + (i * 0.1))))
    assert any(r.detection_type == "DNS_QUERY_RATE_ANOMALY" for r in rate_res)


def test_23_configured_severity_is_respected(make_dns_packet):
    """23. Configured severity level is attached to all generated detection results."""
    detector = DNSAnomalyDetector(
        max_query_length=20,
        default_severity="MEDIUM",
    )
    long_q = "a" * 25 + ".org"
    alerts = detector.process_packet(make_dns_packet(dns_query=long_q))

    assert len(alerts) == 1
    assert alerts[0].severity == "MEDIUM"


def test_24_reset_clear_state_works(make_dns_packet):
    """24. Reset clears internal packet buffers, timestamp tracking, and cooldown cache."""
    detector = DNSAnomalyDetector(
        rate_window_seconds=5.0,
        max_queries_per_window=25,
        alert_cooldown_seconds=10.0,
    )

    # Trigger rate alert
    for i in range(26):
        detector.process_packet(make_dns_packet(timestamp=100.0 + (i * 0.1)))

    assert len(detector._dns_buffer) > 0
    assert len(detector._last_alerted) > 0
    assert detector._max_timestamp > 0.0

    # Call reset
    detector.reset()

    assert len(detector._dns_buffer) == 0
    assert len(detector._last_alerted) == 0
    assert detector._max_timestamp == 0.0

    # After reset, sending queries immediately triggers alert without being blocked by previous cooldown
    fresh_alerts = []
    for i in range(26):
        fresh_alerts.extend(detector.process_packet(make_dns_packet(timestamp=101.0 + (i * 0.1))))

    assert len(fresh_alerts) == 1


# ==============================================================================
# ARCHITECTURAL INTEGRATION & UTILITY TESTS (25 to 28)
# ==============================================================================

def test_25_detect_window_stateless_batch(make_dns_packet):
    """25. Stateless detect_window correctly evaluates a batch of packets."""
    detector = DNSAnomalyDetector(rate_window_seconds=5.0, max_queries_per_window=10)
    packets = [
        make_dns_packet(src_ip="10.2.2.2", timestamp=50.0 + (i * 0.2))
        for i in range(12)
    ]
    results = detector.detect_window(packets)
    assert len(results) == 1
    assert results[0].src_ip == "10.2.2.2"
    assert results[0].dns_query_count == 12


def test_26_all_detectors_coexist():
    """26. All five modular detectors can be imported together and instantiated cleanly."""
    p_scan = PortScanDetector()
    s_anom = SynAnomalyDetector()
    a_anom = ARPAnomalyDetector()
    p_swep = PingSweepDetector()
    d_anom = DNSAnomalyDetector()

    assert p_scan.enabled is True
    assert s_anom.enabled is True
    assert a_anom.enabled is True
    assert p_swep.enabled is True
    assert d_anom.enabled is True


def test_27_to_dict_serialization(make_dns_packet):
    """27. DetectionResult dictionary serialization includes DNS-specific attributes."""
    detector = DNSAnomalyDetector(max_query_length=50, max_label_length=100)
    long_q = "x" * 60 + ".com"
    alerts = detector.process_packet(make_dns_packet(dns_query=long_q))

    assert len(alerts) == 1
    res_dict = alerts[0].to_dict()

    assert res_dict["rule_name"] == "dns_anomaly"
    assert res_dict["detection_type"] == "DNS_LONG_QUERY_ANOMALY"
    assert res_dict["query_name"] == long_q
    assert res_dict["query_length"] == len(long_q)
    assert "observed_query_length" in res_dict["evidence"]


def test_28_extract_labels_edge_cases():
    """28. extract_labels helper handles trailing/leading dots and malformed queries safely."""
    assert DNSAnomalyDetector.extract_labels("abc.example.com") == ["abc", "example", "com"]
    assert DNSAnomalyDetector.extract_labels("abc.example.com.") == ["abc", "example", "com"]
    assert DNSAnomalyDetector.extract_labels(".abc..example.com..") == ["abc", "example", "com"]
    assert DNSAnomalyDetector.extract_labels("") == []
    assert DNSAnomalyDetector.extract_labels("...") == []
    assert DNSAnomalyDetector.extract_labels(None) == []  # type: ignore[arg-type]
    assert DNSAnomalyDetector.extract_labels(12345) == []  # type: ignore[arg-type]
