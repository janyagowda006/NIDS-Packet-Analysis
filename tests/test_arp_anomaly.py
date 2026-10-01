"""Unit tests for the ARP Anomaly and Spoofing Detection engine."""

import pytest

from backend.detection.arp_anomaly import ARPAnomalyDetector
from backend.detection.models import DetectionResult
from backend.detection.port_scan import PortScanDetector
from backend.detection.syn_anomaly import SynAnomalyDetector
from backend.parser.models import NormalizedPacket


@pytest.fixture
def make_arp_packet():
    """Helper fixture to create synthetic NormalizedPackets representing ARP frames."""
    def _create(
        arp_op=1,
        sender_ip="192.168.1.100",
        sender_mac="00:11:22:33:44:55",
        target_ip="192.168.1.1",
        target_mac="00:00:00:00:00:00",
        timestamp=1000.0,
        protocol="ARP",
    ):
        return NormalizedPacket(
            timestamp=timestamp,
            packet_length=42,
            protocol=protocol,
            src_mac=sender_mac,
            dst_mac="ff:ff:ff:ff:ff:ff" if arp_op == 1 else target_mac,
            src_ip=sender_ip,
            dst_ip=target_ip,
            arp_op=arp_op,
            arp_sender_ip=sender_ip,
            arp_sender_mac=sender_mac,
            arp_target_ip=target_ip,
            arp_target_mac=target_mac,
        )
    return _create


# ==============================================================================
# 1. Normal ARP Request
# ==============================================================================
def test_normal_arp_request(make_arp_packet):
    """Verify single ARP request establishes baseline mapping without alerting."""
    detector = ARPAnomalyDetector()
    pkt = make_arp_packet(arp_op=1, sender_ip="192.168.1.50", sender_mac="aa:bb:cc:dd:ee:01")

    results = detector.process_packet(pkt)
    assert len(results) == 0
    assert detector.get_mapping("192.168.1.50") == "aa:bb:cc:dd:ee:01"


# ==============================================================================
# 2. Normal ARP Reply
# ==============================================================================
def test_normal_arp_reply(make_arp_packet):
    """Verify single ARP reply establishes baseline mapping without alerting."""
    detector = ARPAnomalyDetector()
    pkt = make_arp_packet(arp_op=2, sender_ip="192.168.1.1", sender_mac="00:50:56:c0:00:08")

    results = detector.process_packet(pkt)
    assert len(results) == 0
    assert detector.get_mapping("192.168.1.1") == "00:50:56:c0:00:08"


# ==============================================================================
# 3. Stable IP -> MAC Mapping
# ==============================================================================
def test_stable_ip_mac_mapping(make_arp_packet):
    """Verify consistent IP-to-MAC associations over time generate zero alerts."""
    detector = ARPAnomalyDetector()
    packets = [
        make_arp_packet(arp_op=1, sender_ip="192.168.1.10", sender_mac="11:22:33:44:55:66", timestamp=100.0 + i)
        for i in range(10)
    ]

    for pkt in packets:
        assert detector.process_packet(pkt) == []


# ==============================================================================
# 4. Repeated Identical IP -> MAC Observations
# ==============================================================================
def test_repeated_identical_observations_no_false_alert(make_arp_packet):
    """Verify high-frequency identical ARP announcements produce no false alerts."""
    detector = ARPAnomalyDetector()
    pkt = make_arp_packet(arp_op=2, sender_ip="10.0.0.1", sender_mac="aa:bb:cc:11:22:33")

    for _ in range(25):
        assert detector.process_packet(pkt) == []

    assert detector.get_mapping("10.0.0.1") == "aa:bb:cc:11:22:33"


# ==============================================================================
# 5. IP -> MAC Mapping Changes
# ==============================================================================
def test_ip_mac_mapping_changes(make_arp_packet):
    """Verify sudden MAC change for known IP triggers explainable anomaly alert."""
    detector = ARPAnomalyDetector(alert_cooldown_seconds=10.0)

    # Initial mapping
    pkt1 = make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=100.0)
    assert detector.process_packet(pkt1) == []

    # New MAC claims the same IP
    pkt2 = make_arp_packet(sender_ip="192.168.1.1", sender_mac="bb:bb:bb:bb:bb:bb", timestamp=105.0)
    results = detector.process_packet(pkt2)

    assert len(results) == 1
    alert = results[0]
    assert alert.rule_name == "arp_spoofing"
    assert alert.alert_type == "Possible ARP Spoofing / ARP Mapping Anomaly"
    assert alert.scan_type == "ARP_MAPPING_CHANGE"
    assert alert.detection_type == "ARP_MAPPING_CHANGE"
    assert alert.src_ip == "192.168.1.1"
    assert alert.previous_mac == "aa:aa:aa:aa:aa:aa"
    assert alert.new_mac == "bb:bb:bb:bb:bb:bb"
    assert alert.severity == "CRITICAL"
    assert "IP-to-MAC mapping changed" in alert.detection_reason
    assert alert.evidence["previous_mac"] == "aa:aa:aa:aa:aa:aa"
    assert alert.evidence["new_mac"] == "bb:bb:bb:bb:bb:bb"


# ==============================================================================
# 6. Conflicting MAC Addresses for the Same IP
# ==============================================================================
def test_conflicting_mac_addresses_for_same_ip(make_arp_packet):
    """Verify alternating claims for identical IP trigger ARP_CONFLICTING_OWNERSHIP."""
    detector = ARPAnomalyDetector(alert_cooldown_seconds=0.0)

    # 1. Initial mapping learned for AA
    pkt1 = make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=100.0)
    assert detector.process_packet(pkt1) == []

    # 2. BB claims the IP -> Mapping change alert
    pkt2 = make_arp_packet(sender_ip="192.168.1.1", sender_mac="bb:bb:bb:bb:bb:bb", timestamp=101.0)
    res2 = detector.process_packet(pkt2)
    assert len(res2) == 1
    assert res2[0].detection_type == "ARP_MAPPING_CHANGE"

    # 3. AA claims the IP again -> Conflicting ownership alert
    pkt3 = make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=102.0)
    res3 = detector.process_packet(pkt3)
    assert len(res3) == 1
    alert3 = res3[0]
    assert alert3.detection_type == "ARP_CONFLICTING_OWNERSHIP"
    assert "Conflicting MAC ownership" in alert3.detection_reason
    assert alert3.evidence["is_conflicting_ownership"] is True


# ==============================================================================
# 7. Multiple IPs with Stable Mappings
# ==============================================================================
def test_multiple_ips_with_stable_mappings(make_arp_packet):
    """Verify detector tracks multiple distinct hosts concurrently without cross-contamination."""
    detector = ARPAnomalyDetector()

    for i in range(5):
        ip = f"192.168.1.{10 + i}"
        mac = f"00:11:22:33:44:{10 + i:02x}"
        pkt = make_arp_packet(sender_ip=ip, sender_mac=mac, timestamp=100.0 + i)
        assert detector.process_packet(pkt) == []

    all_maps = detector.get_all_mappings()
    assert len(all_maps) == 5
    assert all_maps["192.168.1.10"] == "00:11:22:33:44:0a"
    assert all_maps["192.168.1.14"] == "00:11:22:33:44:0e"


# ==============================================================================
# 8. Missing Sender IP Handled Safely
# ==============================================================================
def test_missing_sender_ip(make_arp_packet):
    """Verify packet with missing sender IP is ignored safely without crash."""
    detector = ARPAnomalyDetector()
    pkt = make_arp_packet(sender_ip=None)
    assert detector.is_arp_candidate(pkt) is False
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 9. Missing Sender MAC Handled Safely
# ==============================================================================
def test_missing_sender_mac(make_arp_packet):
    """Verify packet with missing sender MAC is ignored safely without crash."""
    detector = ARPAnomalyDetector()
    pkt = make_arp_packet(sender_mac=None)
    assert detector.is_arp_candidate(pkt) is False
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 10. Malformed / Incomplete ARP Packet
# ==============================================================================
def test_malformed_incomplete_arp_packet():
    """Verify empty NormalizedPacket is safely rejected without raising exceptions."""
    detector = ARPAnomalyDetector()
    empty_pkt = NormalizedPacket(protocol="ARP")
    assert detector.is_arp_candidate(empty_pkt) is False
    assert detector.process_packet(empty_pkt) == []


# ==============================================================================
# 11. Unknown ARP Operation Code
# ==============================================================================
def test_unknown_arp_operation(make_arp_packet):
    """Verify unknown or unhandled ARP opcode (e.g., 99) is safely ignored."""
    detector = ARPAnomalyDetector()
    pkt = make_arp_packet(arp_op=99)
    assert detector.is_arp_candidate(pkt) is False
    assert detector.process_packet(pkt) == []


# ==============================================================================
# 12. Multiple Independent Mapping Changes
# ==============================================================================
def test_multiple_mapping_changes(make_arp_packet):
    """Verify changes across different IPs generate distinct independent alerts."""
    detector = ARPAnomalyDetector(alert_cooldown_seconds=0.0)

    # Establish baselines
    detector.process_packet(make_arp_packet(sender_ip="10.0.0.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=100.0))
    detector.process_packet(make_arp_packet(sender_ip="10.0.0.2", sender_mac="cc:cc:cc:cc:cc:cc", timestamp=101.0))

    # Host 1 change
    res1 = detector.process_packet(make_arp_packet(sender_ip="10.0.0.1", sender_mac="bb:bb:bb:bb:bb:bb", timestamp=105.0))
    assert len(res1) == 1
    assert res1[0].src_ip == "10.0.0.1"
    assert res1[0].new_mac == "bb:bb:bb:bb:bb:bb"

    # Host 2 change
    res2 = detector.process_packet(make_arp_packet(sender_ip="10.0.0.2", sender_mac="dd:dd:dd:dd:dd:dd", timestamp=106.0))
    assert len(res2) == 1
    assert res2[0].src_ip == "10.0.0.2"
    assert res2[0].new_mac == "dd:dd:dd:dd:dd:dd"


# ==============================================================================
# 13. Alert Cooldown Behavior
# ==============================================================================
def test_alert_cooldown_behavior(make_arp_packet):
    """Verify cooldown suppresses alert storms for continuous packets with same spoofed MAC."""
    detector = ARPAnomalyDetector(alert_cooldown_seconds=10.0)

    # Baseline
    detector.process_packet(make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=100.0))

    # Burst of 20 spoofed packets with MAC BB within 2 seconds
    alert_count = 0
    for i in range(20):
        alerts = detector.process_packet(
            make_arp_packet(sender_ip="192.168.1.1", sender_mac="bb:bb:bb:bb:bb:bb", timestamp=101.0 + (i * 0.1))
        )
        alert_count += len(alerts)

    # Exactly 1 alert emitted during the burst
    assert alert_count == 1

    # After cooldown elapses (15 seconds later), another packet with CC triggers
    alerts_after = detector.process_packet(
        make_arp_packet(sender_ip="192.168.1.1", sender_mac="cc:cc:cc:cc:cc:cc", timestamp=120.0)
    )
    assert len(alerts_after) == 1


# ==============================================================================
# 14. Configured Severity is Respected
# ==============================================================================
def test_configured_severity_is_respected(make_arp_packet):
    """Verify constructor default_severity overrides default CRITICAL appropriately."""
    detector = ARPAnomalyDetector(default_severity="HIGH", alert_cooldown_seconds=0.0)
    detector.process_packet(make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=100.0))

    res = detector.process_packet(make_arp_packet(sender_ip="192.168.1.1", sender_mac="bb:bb:bb:bb:bb:bb", timestamp=105.0))
    assert len(res) == 1
    assert res[0].severity == "HIGH"


# ==============================================================================
# 15. alert_on_mac_change: False Suppresses Alerts
# ==============================================================================
def test_mac_change_alert_false_suppresses_alerts(make_arp_packet):
    """Verify disabling mac_change_alert updates mapping silently without alerting."""
    detector = ARPAnomalyDetector(alert_on_mac_change=False)

    detector.process_packet(make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=100.0))
    res = detector.process_packet(make_arp_packet(sender_ip="192.168.1.1", sender_mac="bb:bb:bb:bb:bb:bb", timestamp=105.0))

    assert len(res) == 0
    # Mapping was still successfully updated to BB
    assert detector.get_mapping("192.168.1.1") == "bb:bb:bb:bb:bb:bb"


# ==============================================================================
# 16. Detection Result Contains Useful Evidence
# ==============================================================================
def test_detection_result_contains_useful_evidence(make_arp_packet):
    """Verify DetectionResult exposes all required evidence, properties, and dictionary fields."""
    detector = ARPAnomalyDetector(alert_cooldown_seconds=0.0)
    detector.process_packet(make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=100.0))

    res = detector.process_packet(
        make_arp_packet(sender_ip="192.168.1.1", sender_mac="bb:bb:bb:bb:bb:bb", timestamp=105.0, arp_op=2)
    )
    assert len(res) == 1
    alert = res[0]

    assert alert.detected is True
    assert alert.source_ip == "192.168.1.1"
    assert alert.previous_mac == "aa:aa:aa:aa:aa:aa"
    assert alert.new_mac == "bb:bb:bb:bb:bb:bb"
    assert alert.protocol == "ARP"
    assert len(alert.description) > 0

    as_dict = alert.to_dict()
    assert as_dict["previous_mac"] == "aa:aa:aa:aa:aa:aa"
    assert as_dict["new_mac"] == "bb:bb:bb:bb:bb:bb"
    assert as_dict["evidence"]["arp_operation"] == "REPLY"
    assert "aa:aa:aa:aa:aa:aa" in as_dict["evidence"]["all_observed_macs"]


# ==============================================================================
# 17. Detector Reset Clears Learned Mapping State
# ==============================================================================
def test_detector_reset_clears_learned_state(make_arp_packet):
    """Verify reset() empties mapping tables so subsequent packets are treated as fresh baseline."""
    detector = ARPAnomalyDetector()
    detector.process_packet(make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa"))
    assert detector.get_mapping("192.168.1.1") == "aa:aa:aa:aa:aa:aa"

    detector.reset()
    assert detector.get_mapping("192.168.1.1") is None

    # Next packet with MAC BB is treated as initial observation, not a mapping change
    res = detector.process_packet(make_arp_packet(sender_ip="192.168.1.1", sender_mac="bb:bb:bb:bb:bb:bb"))
    assert len(res) == 0
    assert detector.get_mapping("192.168.1.1") == "bb:bb:bb:bb:bb:bb"


# ==============================================================================
# 18. Existing Phase 5 and Phase 6 Functionality Compatibility
# ==============================================================================
def test_existing_phase_5_and_6_compatibility():
    """Verify PortScanDetector, SynAnomalyDetector, and DetectionResult interoperate cleanly."""
    port_scan = PortScanDetector()
    syn_anomaly = SynAnomalyDetector()
    arp_detector = ARPAnomalyDetector()

    assert port_scan.enabled is True
    assert syn_anomaly.enabled is True
    assert arp_detector.enabled is True

    result = DetectionResult(
        rule_name="arp_spoofing",
        alert_type="Possible ARP Spoofing / ARP Mapping Anomaly",
        severity="CRITICAL",
        src_ip="192.168.1.1",
        protocol="ARP",
        previous_mac="aa:aa:aa:aa:aa:aa",
        new_mac="bb:bb:bb:bb:bb:bb",
    )
    assert result.previous_mac == "aa:aa:aa:aa:aa:aa"
    assert result.new_mac == "bb:bb:bb:bb:bb:bb"
    assert result.protocol == "ARP"


# ==============================================================================
# 19. Gratuitous ARP Announcement Evidence
# ==============================================================================
def test_gratuitous_arp_announcement_evidence(make_arp_packet):
    """Verify gratuitous ARP (sender IP == target IP) flags is_gratuitous in evidence."""
    detector = ARPAnomalyDetector(alert_cooldown_seconds=0.0)

    # Normal baseline
    detector.process_packet(make_arp_packet(sender_ip="192.168.1.50", sender_mac="11:11:11:11:11:11", target_ip="192.168.1.1"))

    # Gratuitous ARP announcement with a different MAC claiming 192.168.1.50
    garp = make_arp_packet(
        arp_op=2,
        sender_ip="192.168.1.50",
        sender_mac="22:22:22:22:22:22",
        target_ip="192.168.1.50",  # sender_ip == target_ip
        timestamp=105.0,
    )
    results = detector.process_packet(garp)
    assert len(results) == 1
    alert = results[0]
    assert alert.evidence["is_gratuitous"] is True
    assert "gratuitous ARP" in alert.detection_reason


# ==============================================================================
# 20. Case-Insensitive MAC Address Handling
# ==============================================================================
def test_case_insensitive_mac_handling(make_arp_packet):
    """Verify uppercase and lowercase MAC addresses are treated as identical."""
    detector = ARPAnomalyDetector()

    pkt_upper = make_arp_packet(sender_ip="192.168.1.1", sender_mac="AA:BB:CC:DD:EE:FF")
    pkt_lower = make_arp_packet(sender_ip="192.168.1.1", sender_mac="aa:bb:cc:dd:ee:ff")

    assert detector.process_packet(pkt_upper) == []
    # Lowercase observation of identical MAC must not trigger mapping change
    assert detector.process_packet(pkt_lower) == []
    assert detector.get_mapping("192.168.1.1") == "aa:bb:cc:dd:ee:ff"


# ==============================================================================
# 21. inspect_replies_only Configuration Behavior
# ==============================================================================
def test_inspect_replies_only_configuration(make_arp_packet):
    """Verify inspect_replies_only=True ignores requests and only processes replies."""
    detector = ARPAnomalyDetector(inspect_replies_only=True, alert_cooldown_seconds=0.0)

    # Establish baseline with a Reply
    detector.process_packet(make_arp_packet(arp_op=2, sender_ip="192.168.1.1", sender_mac="aa:aa:aa:aa:aa:aa"))

    # Request with different MAC should be ignored under inspect_replies_only
    req_change = make_arp_packet(arp_op=1, sender_ip="192.168.1.1", sender_mac="bb:bb:bb:bb:bb:bb")
    assert detector.process_packet(req_change) == []

    # Reply with different MAC triggers alert
    reply_change = make_arp_packet(arp_op=2, sender_ip="192.168.1.1", sender_mac="cc:cc:cc:cc:cc:cc")
    res = detector.process_packet(reply_change)
    assert len(res) == 1
    assert res[0].new_mac == "cc:cc:cc:cc:cc:cc"


# ==============================================================================
# 22. Non-ARP Traffic Ignored Safely
# ==============================================================================
def test_non_arp_traffic_ignored():
    """Verify TCP, UDP, and ICMP packets are ignored safely by ARP detector."""
    detector = ARPAnomalyDetector()
    pkt_tcp = NormalizedPacket(protocol="TCP", src_ip="192.168.1.1", dst_ip="192.168.1.2", dst_port=80)
    pkt_udp = NormalizedPacket(protocol="UDP", src_ip="192.168.1.1", dst_ip="192.168.1.2", dst_port=53)

    assert detector.process_packet(pkt_tcp) == []
    assert detector.process_packet(pkt_udp) == []


# ==============================================================================
# 23. ARP Probe (0.0.0.0) Ignored Safely
# ==============================================================================
def test_arp_probe_zero_ip_ignored(make_arp_packet):
    """Verify RFC 5227 DAD probe with sender IP 0.0.0.0 is not learned as a binding."""
    detector = ARPAnomalyDetector()
    probe_pkt = make_arp_packet(sender_ip="0.0.0.0", sender_mac="11:22:33:44:55:66")

    assert detector.is_arp_candidate(probe_pkt) is False
    assert detector.process_packet(probe_pkt) == []
    assert detector.get_mapping("0.0.0.0") is None


# ==============================================================================
# 24. Batch detect_window Method Evaluation
# ==============================================================================
def test_batch_detect_window_evaluation(make_arp_packet):
    """Verify stateless batch window processing accurately identifies anomalies."""
    detector = ARPAnomalyDetector()
    packets = [
        make_arp_packet(sender_ip="10.0.0.1", sender_mac="aa:aa:aa:aa:aa:aa", timestamp=100.0),
        make_arp_packet(sender_ip="10.0.0.1", sender_mac="bb:bb:bb:bb:bb:bb", timestamp=105.0),
    ]

    results = detector.detect_window(packets)
    assert len(results) == 1
    assert results[0].src_ip == "10.0.0.1"
    assert results[0].new_mac == "bb:bb:bb:bb:bb:bb"
