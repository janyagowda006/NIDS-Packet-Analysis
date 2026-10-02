"""Comprehensive test suite for Phase 10: Alert Manager + SQLite persistence.

Tests database creation, schema initialization, DetectionResult persistence,
filtering, querying, status lifecycle, robustness, security against SQL injection,
and integration across Phase 5-9 detection engines.
"""

from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from backend.alert import Alert, AlertDatabase, AlertManager, AlertStatus
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
def temp_db_path(tmp_path: Path) -> Path:
    """Fixture providing a temporary SQLite database file path."""
    return tmp_path / "nids_test_alerts.db"


@pytest.fixture
def alert_manager(temp_db_path: Path) -> AlertManager:
    """Fixture providing an AlertManager instance backed by a temporary SQLite file."""
    return AlertManager(db_path=temp_db_path)


@pytest.fixture
def sample_detection_result() -> DetectionResult:
    """Helper fixture creating a standard explainable DetectionResult."""
    return DetectionResult(
        rule_name="port_scan",
        alert_type="Possible Port Scan",
        severity="HIGH",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        protocol="TCP",
        scan_type="VERTICAL",
        detection_type="VERTICAL",
        timestamp=1700000000.0,
        window_seconds=1.0,
        syn_count=25,
        unique_destination_ports=20,
        detection_reason="Possible vertical port scan detected: 20 ports contacted.",
        evidence={
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.1",
            "unique_ports_count": 20,
            "sample_ports": [22, 80, 443, 8080],
            "threshold_ports": 15,
        },
    )


# ==============================================================================
# DATABASE TESTS (1 to 3)
# ==============================================================================

def test_1_database_creation(tmp_path: Path):
    """1. Verify database file and parent directories are automatically created."""
    db_file = tmp_path / "subfolder" / "deep" / "test_nids.db"
    assert not db_file.exists()

    db = AlertDatabase(db_path=db_file)
    assert db_file.exists()
    assert db_file.is_file()
    db.close()


def test_2_table_creation(alert_manager: AlertManager):
    """2. Verify alerts table and required performance indexes are properly created."""
    with alert_manager.db.get_connection() as conn:
        cursor = conn.cursor()

        # Check alerts table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts';")
        assert cursor.fetchone() is not None

        # Check columns
        cursor.execute("PRAGMA table_info(alerts);")
        columns = {row["name"]: row["type"].upper() for row in cursor.fetchall()}
        expected_columns = {
            "id": "INTEGER",
            "timestamp": "TEXT",
            "alert_type": "TEXT",
            "severity": "TEXT",
            "src_ip": "TEXT",
            "dst_ip": "TEXT",
            "protocol": "TEXT",
            "description": "TEXT",
            "detection_reason": "TEXT",
            "evidence": "TEXT",
            "status": "TEXT",
        }
        for col_name, col_type in expected_columns.items():
            assert col_name in columns
            assert columns[col_name] == col_type

        # Check indexes
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='alerts';")
        index_names = {row["name"] for row in cursor.fetchall()}
        expected_indexes = {
            "idx_alerts_timestamp",
            "idx_alerts_alert_type",
            "idx_alerts_severity",
            "idx_alerts_status",
            "idx_alerts_src_ip",
        }
        for idx in expected_indexes:
            assert idx in index_names


def test_3_repeated_initialization(temp_db_path: Path):
    """3. Verify safe repeated schema initialization does not corrupt existing data or raise errors."""
    db = AlertDatabase(db_path=temp_db_path)
    aid = db.insert_alert(
        timestamp="2026-10-02T10:00:00+00:00",
        alert_type="Test Alert",
        severity="LOW",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        protocol="TCP",
        description="First alert",
        detection_reason="Initial run",
        evidence="{}",
        status="NEW",
    )
    assert aid == 1

    # Re-run init_db multiple times
    db.init_db()
    db.init_db()

    # Verify row is still intact
    row = db.get_alert_by_id(aid)
    assert row is not None
    assert row["alert_type"] == "Test Alert"
    db.close()


# ==============================================================================
# SAVING TESTS (4 to 8)
# ==============================================================================

def test_4_save_detection_result(alert_manager: AlertManager, sample_detection_result: DetectionResult):
    """4. Verify saving a DetectionResult succeeds and returns a positive integer ID."""
    alert_id = alert_manager.save_alert(sample_detection_result)
    assert isinstance(alert_id, int)
    assert alert_id > 0


def test_5_generated_alert_id(alert_manager: AlertManager, sample_detection_result: DetectionResult):
    """5. Verify generated alert IDs increment sequentially."""
    id1 = alert_manager.save_alert(sample_detection_result)
    id2 = alert_manager.save_alert(sample_detection_result)
    id3 = alert_manager.save_alert(sample_detection_result)
    assert id2 == id1 + 1
    assert id3 == id2 + 1


def test_6_all_fields_persisted(alert_manager: AlertManager, sample_detection_result: DetectionResult):
    """6. Verify all fields from DetectionResult are stored and retrieved accurately."""
    alert_id = alert_manager.save_alert(sample_detection_result)
    alert = alert_manager.get_alert(alert_id)

    assert alert is not None
    assert alert.id == alert_id
    assert alert.alert_type == "Possible Port Scan"
    assert alert.severity == "HIGH"
    assert alert.src_ip == "192.168.1.100"
    assert alert.dst_ip == "192.168.1.1"
    assert alert.protocol == "TCP"
    assert alert.description == sample_detection_result.description
    assert alert.detection_reason == sample_detection_result.detection_reason
    assert alert.status == AlertStatus.NEW
    assert isinstance(alert.timestamp, str)
    assert len(alert.timestamp) > 0


def test_7_evidence_preserved_as_json(alert_manager: AlertManager):
    """7. Verify structured evidence is preserved as JSON and deserialized to machine-readable dict."""
    evidence_payload = {
        "source_ip": "10.0.0.5",
        "nested_details": {
            "observed_rate": 55.4,
            "sample_ports": [80, 443, 8080],
            "is_flagged": True,
        },
        "flags_list": ["SYN", "ACK"],
    }
    res = DetectionResult(
        rule_name="syn_anomaly",
        alert_type="Possible SYN Flood",
        severity="HIGH",
        src_ip="10.0.0.5",
        evidence=evidence_payload,
    )
    alert_id = alert_manager.save_alert(res)
    alert = alert_manager.get_alert(alert_id)

    assert alert is not None
    assert isinstance(alert.evidence, dict)
    assert alert.evidence["source_ip"] == "10.0.0.5"
    assert alert.evidence["nested_details"]["observed_rate"] == 55.4
    assert alert.evidence["nested_details"]["sample_ports"] == [80, 443, 8080]
    assert alert.evidence["nested_details"]["is_flagged"] is True
    assert alert.evidence["flags_list"] == ["SYN", "ACK"]


def test_8_multiple_alerts(alert_manager: AlertManager):
    """8. Verify multiple alerts are persisted independently without collision."""
    for i in range(10):
        res = DetectionResult(
            rule_name="port_scan",
            alert_type="Possible Port Scan",
            severity="LOW" if i % 2 == 0 else "HIGH",
            src_ip=f"10.0.0.{i + 1}",
            detection_reason=f"Scan event {i}",
        )
        alert_manager.save_alert(res)

    alerts = alert_manager.get_alerts()
    assert len(alerts) == 10
    assert alert_manager.get_alert_count() == 10


# ==============================================================================
# RETRIEVAL TESTS (9 to 16)
# ==============================================================================

def test_9_get_alert_by_id(alert_manager: AlertManager, sample_detection_result: DetectionResult):
    """9. Verify get_alert retrieves matching alert and returns None for nonexistent ID."""
    alert_id = alert_manager.save_alert(sample_detection_result)

    alert = alert_manager.get_alert(alert_id)
    assert alert is not None
    assert alert.id == alert_id

    # Nonexistent ID
    assert alert_manager.get_alert(99999) is None
    assert alert_manager.get_alert(-1) is None


def test_10_get_multiple_alerts(alert_manager: AlertManager):
    """10. Verify retrieving all alerts returns a list of Alert dataclasses."""
    for i in range(5):
        alert_manager.save_alert({
            "alert_type": f"Alert {i}",
            "severity": "MEDIUM",
            "src_ip": "1.1.1.1",
        })

    alerts = alert_manager.get_alerts()
    assert len(alerts) == 5
    assert all(isinstance(a, Alert) for a in alerts)


def test_11_newest_first_ordering(alert_manager: AlertManager):
    """11. Verify get_alerts orders results newest first by timestamp and ID."""
    t1 = "2026-01-01T10:00:00+00:00"
    t2 = "2026-01-02T10:00:00+00:00"
    t3 = "2026-01-03T10:00:00+00:00"

    alert_manager.save_alert({"timestamp": t1, "alert_type": "Oldest", "severity": "LOW"})
    alert_manager.save_alert({"timestamp": t2, "alert_type": "Middle", "severity": "LOW"})
    alert_manager.save_alert({"timestamp": t3, "alert_type": "Newest", "severity": "LOW"})

    alerts = alert_manager.get_alerts()
    assert len(alerts) == 3
    assert alerts[0].alert_type == "Newest"
    assert alerts[1].alert_type == "Middle"
    assert alerts[2].alert_type == "Oldest"


def test_12_limit(alert_manager: AlertManager):
    """12. Verify limit parameter bounds the number of returned alerts."""
    for i in range(10):
        alert_manager.save_alert({"alert_type": f"Type {i}", "severity": "LOW"})

    limited = alert_manager.get_alerts(limit=4)
    assert len(limited) == 4


def test_13_severity_filter(alert_manager: AlertManager):
    """13. Verify filtering alerts by severity."""
    alert_manager.save_alert({"alert_type": "A1", "severity": "LOW"})
    alert_manager.save_alert({"alert_type": "A2", "severity": "HIGH"})
    alert_manager.save_alert({"alert_type": "A3", "severity": "CRITICAL"})
    alert_manager.save_alert({"alert_type": "A4", "severity": "HIGH"})

    high_alerts = alert_manager.get_alerts(severity="HIGH")
    assert len(high_alerts) == 2
    assert all(a.severity == "HIGH" for a in high_alerts)

    crit_alerts = alert_manager.get_alerts(severity="CRITICAL")
    assert len(crit_alerts) == 1
    assert crit_alerts[0].alert_type == "A3"


def test_14_alert_type_filter(alert_manager: AlertManager):
    """14. Verify filtering alerts by alert_type."""
    alert_manager.save_alert({"alert_type": "Possible Port Scan", "severity": "HIGH"})
    alert_manager.save_alert({"alert_type": "Possible Ping Sweep", "severity": "MEDIUM"})
    alert_manager.save_alert({"alert_type": "Possible Port Scan", "severity": "HIGH"})

    results = alert_manager.get_alerts(alert_type="Possible Port Scan")
    assert len(results) == 2
    assert all(r.alert_type == "Possible Port Scan" for r in results)

    sweep_results = alert_manager.get_alerts(alert_type="Possible Ping Sweep")
    assert len(sweep_results) == 1


def test_15_source_ip_filter(alert_manager: AlertManager):
    """15. Verify filtering alerts by source IP address."""
    alert_manager.save_alert({"alert_type": "A1", "severity": "LOW", "src_ip": "192.168.1.100"})
    alert_manager.save_alert({"alert_type": "A2", "severity": "LOW", "src_ip": "10.0.0.50"})
    alert_manager.save_alert({"alert_type": "A3", "severity": "LOW", "src_ip": "192.168.1.100"})

    filtered = alert_manager.get_alerts(src_ip="192.168.1.100")
    assert len(filtered) == 2
    assert all(a.src_ip == "192.168.1.100" for a in filtered)


def test_16_status_filter(alert_manager: AlertManager):
    """16. Verify filtering alerts by lifecycle status."""
    id1 = alert_manager.save_alert({"alert_type": "A1", "severity": "LOW"})
    id2 = alert_manager.save_alert({"alert_type": "A2", "severity": "LOW"})
    id3 = alert_manager.save_alert({"alert_type": "A3", "severity": "LOW"})

    alert_manager.update_status(id2, AlertStatus.ACKNOWLEDGED)
    alert_manager.update_status(id3, AlertStatus.RESOLVED)

    new_alerts = alert_manager.get_alerts(status=AlertStatus.NEW)
    assert len(new_alerts) == 1
    assert new_alerts[0].id == id1

    ack_alerts = alert_manager.get_alerts(status=AlertStatus.ACKNOWLEDGED)
    assert len(ack_alerts) == 1
    assert ack_alerts[0].id == id2

    res_alerts = alert_manager.get_alerts(status=AlertStatus.RESOLVED)
    assert len(res_alerts) == 1
    assert res_alerts[0].id == id3


# ==============================================================================
# STATUS LIFECYCLE TESTS (17 to 21)
# ==============================================================================

def test_17_default_status_new(alert_manager: AlertManager, sample_detection_result: DetectionResult):
    """17. Verify newly saved alerts default to status 'NEW'."""
    aid = alert_manager.save_alert(sample_detection_result)
    alert = alert_manager.get_alert(aid)
    assert alert is not None
    assert alert.status == AlertStatus.NEW


def test_18_status_update_acknowledged(alert_manager: AlertManager, sample_detection_result: DetectionResult):
    """18. Verify updating alert status to 'ACKNOWLEDGED'."""
    aid = alert_manager.save_alert(sample_detection_result)
    success = alert_manager.update_status(aid, AlertStatus.ACKNOWLEDGED)
    assert success is True

    alert = alert_manager.get_alert(aid)
    assert alert is not None
    assert alert.status == AlertStatus.ACKNOWLEDGED


def test_19_status_update_resolved(alert_manager: AlertManager, sample_detection_result: DetectionResult):
    """19. Verify updating alert status to 'RESOLVED'."""
    aid = alert_manager.save_alert(sample_detection_result)
    success = alert_manager.update_status(aid, AlertStatus.RESOLVED)
    assert success is True

    alert = alert_manager.get_alert(aid)
    assert alert is not None
    assert alert.status == AlertStatus.RESOLVED


def test_20_invalid_status_rejected(alert_manager: AlertManager, sample_detection_result: DetectionResult):
    """20. Verify invalid alert statuses are rejected with ValueError."""
    aid = alert_manager.save_alert(sample_detection_result)

    with pytest.raises(ValueError, match="Invalid alert status"):
        alert_manager.update_status(aid, "INVALID_STATUS")

    with pytest.raises(ValueError, match="Invalid alert status"):
        alert_manager.update_status(aid, "CLOSED")

    with pytest.raises(ValueError, match="Invalid alert status"):
        alert_manager.save_alert(sample_detection_result, status="BOGUS")


def test_21_nonexistent_alert_handled_safely(alert_manager: AlertManager):
    """21. Verify status update on nonexistent alert returns False without raising an error."""
    result = alert_manager.update_status(99999, AlertStatus.RESOLVED)
    assert result is False


# ==============================================================================
# ROBUSTNESS TESTS (22 to 26)
# ==============================================================================

def test_22_empty_database(alert_manager: AlertManager):
    """22. Verify querying an empty database returns empty results safely."""
    assert alert_manager.get_alerts() == []
    assert alert_manager.get_alert(1) is None
    assert alert_manager.get_alert_count() == 0
    assert alert_manager.get_severity_counts() == {}
    assert alert_manager.get_alert_type_counts() == {}


def test_23_missing_optional_ip_fields(alert_manager: AlertManager):
    """23. Verify alerts with missing or None IP addresses are saved and retrieved safely."""
    res = DetectionResult(
        rule_name="dns_anomaly",
        alert_type="Possible DNS Anomaly",
        severity="LOW",
        src_ip="192.168.1.5",
        dst_ip=None,
        protocol="DNS",
    )
    aid = alert_manager.save_alert(res)
    alert = alert_manager.get_alert(aid)
    assert alert is not None
    assert alert.src_ip == "192.168.1.5"
    assert alert.dst_ip is None


def test_24_empty_malformed_evidence(alert_manager: AlertManager):
    """24. Verify empty or malformed stored JSON evidence is handled safely without crashing."""
    # 1. Empty evidence
    aid1 = alert_manager.save_alert({
        "alert_type": "Test",
        "severity": "LOW",
        "evidence": {},
    })
    a1 = alert_manager.get_alert(aid1)
    assert a1 is not None
    assert a1.evidence == {}

    # 2. None evidence
    aid2 = alert_manager.save_alert({
        "alert_type": "Test",
        "severity": "LOW",
        "evidence": None,
    })
    a2 = alert_manager.get_alert(aid2)
    assert a2 is not None
    assert a2.evidence == {}

    # 3. Corrupt stored JSON in database directly
    with alert_manager.db.get_connection() as conn:
        conn.execute("UPDATE alerts SET evidence = '{invalid-json' WHERE id = ?;", (aid1,))

    a1_corrupt = alert_manager.get_alert(aid1)
    assert a1_corrupt is not None
    assert isinstance(a1_corrupt.evidence, dict)
    assert "raw" in a1_corrupt.evidence
    assert a1_corrupt.evidence["raw"] == "{invalid-json"


def test_25_special_characters(alert_manager: AlertManager):
    """25. Verify Unicode, single quotes, quotes, and emojis in text fields are preserved intact."""
    special_text = "O'Connor's test: \"Attack\" <script>alert(1)</script> 🚀 ñ 日本語 \n\t"
    res = DetectionResult(
        rule_name="test_rule",
        alert_type=special_text,
        severity="HIGH",
        src_ip="192.168.1.1",
        detection_reason=special_text,
        evidence={"special_field": special_text},
    )
    aid = alert_manager.save_alert(res)
    alert = alert_manager.get_alert(aid)

    assert alert is not None
    assert alert.alert_type == special_text
    assert alert.detection_reason == special_text
    assert alert.evidence["special_field"] == special_text


def test_26_sql_injection_style_filter_values(alert_manager: AlertManager):
    """26. Verify SQL injection strings in filter parameters are safely bound without executing."""
    alert_manager.save_alert({"alert_type": "Standard", "severity": "HIGH", "src_ip": "10.0.0.1"})

    # Injection attempts in filters
    malicious_inputs = [
        "'; DROP TABLE alerts; --",
        "' OR '1'='1",
        "HIGH' OR 1=1 --",
        "admin'--",
    ]

    for bad_input in malicious_inputs:
        # None of these should execute SQL injection or crash
        assert alert_manager.get_alerts(src_ip=bad_input) == []
        assert alert_manager.get_alerts(alert_type=bad_input) == []

    # Table must still exist and retain its data
    assert alert_manager.get_alert_count() == 1


# ==============================================================================
# INTEGRATION TESTS (27 to 30)
# ==============================================================================

def test_27_alerts_from_multiple_detectors(alert_manager: AlertManager):
    """27. Verify AlertManager successfully ingests alerts from all five detection engines (Phases 5-9)."""
    detector_alerts = [
        DetectionResult(rule_name="port_scan", alert_type="Possible Port Scan", severity="HIGH", src_ip="10.0.0.1"),
        DetectionResult(rule_name="syn_anomaly", alert_type="Possible SYN Flood / SYN Anomaly", severity="HIGH", src_ip="10.0.0.2"),
        DetectionResult(rule_name="arp_spoofing", alert_type="Possible ARP Spoofing / ARP Mapping Anomaly", severity="CRITICAL", src_ip="10.0.0.3"),
        DetectionResult(rule_name="ping_sweep", alert_type="Possible Ping Sweep", severity="MEDIUM", src_ip="10.0.0.4"),
        DetectionResult(rule_name="dns_anomaly", alert_type="Possible DNS Anomaly", severity="LOW", src_ip="10.0.0.5"),
    ]

    ids = [alert_manager.save_alert(r) for r in detector_alerts]
    assert len(ids) == 5
    assert len(set(ids)) == 5

    stored = alert_manager.get_alerts()
    assert len(stored) == 5
    stored_types = {a.alert_type for a in stored}
    assert "Possible Port Scan" in stored_types
    assert "Possible SYN Flood / SYN Anomaly" in stored_types
    assert "Possible ARP Spoofing / ARP Mapping Anomaly" in stored_types
    assert "Possible Ping Sweep" in stored_types
    assert "Possible DNS Anomaly" in stored_types


def test_28_compatibility_with_detection_results(alert_manager: AlertManager):
    """28. Verify direct compatibility with DetectionResult objects produced by detector logic."""
    detector = PortScanDetector(unique_ports_threshold=3, min_syn_count=3)
    packets = [
        NormalizedPacket(
            timestamp=100.0 + (i * 0.1),
            src_ip="192.168.1.50",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=50000 + i,
            dst_port=100 + i,
            tcp_flags="SYN",
        )
        for i in range(4)
    ]
    detection_results = detector.detect_window(packets)
    assert len(detection_results) == 1

    alert_id = alert_manager.save_alert(detection_results[0])
    alert = alert_manager.get_alert(alert_id)

    assert alert is not None
    assert alert.alert_type == "Possible Port Scan"
    assert alert.src_ip == "192.168.1.50"
    assert "unique_destination_ports_count" in alert.evidence


def test_29_evidence_survives_serialization_deserialization(alert_manager: AlertManager):
    """29. Verify complex data types like sets and custom dicts survive serialization roundtrip."""
    res = DetectionResult(
        rule_name="test_serialization",
        alert_type="Serialization Test",
        severity="MEDIUM",
        src_ip="10.10.10.10",
        evidence={
            "port_set": {22, 80, 443},  # Set must be converted cleanly
            "metric_float": 99.875,
            "metric_int": 42,
            "metric_bool": True,
            "metric_none": None,
            "threshold_values": {"sub_rule": "active", "limits": [1, 2, 3]},
        },
    )
    aid = alert_manager.save_alert(res)
    alert = alert_manager.get_alert(aid)

    assert alert is not None
    ev = alert.evidence
    assert sorted(ev["port_set"]) == [22, 80, 443]
    assert ev["metric_float"] == 99.875
    assert ev["metric_int"] == 42
    assert ev["metric_bool"] is True
    assert ev["metric_none"] is None
    assert ev["threshold_values"]["limits"] == [1, 2, 3]


def test_30_temporary_database_cleanup(tmp_path: Path):
    """30. Verify temporary databases can be closed and cleanly deleted from the filesystem."""
    temp_file = tmp_path / "temp_to_delete.db"
    manager = AlertManager(db_path=temp_file)
    manager.save_alert({"alert_type": "Disposable", "severity": "LOW"})
    assert temp_file.exists()

    # Close connection
    manager.db.close()

    # File can be safely removed
    temp_file.unlink()
    assert not temp_file.exists()


# ==============================================================================
# DASHBOARD SUPPORT & ACCESSOR TESTS (31 to 35)
# ==============================================================================

def test_31_dashboard_aggregation_methods(alert_manager: AlertManager):
    """31. Verify severity, alert-type, and status aggregations for the future dashboard."""
    alert_manager.save_alert({"alert_type": "Port Scan", "severity": "HIGH", "status": "NEW"})
    alert_manager.save_alert({"alert_type": "Port Scan", "severity": "HIGH", "status": "ACKNOWLEDGED"})
    alert_manager.save_alert({"alert_type": "Ping Sweep", "severity": "MEDIUM", "status": "NEW"})
    alert_manager.save_alert({"alert_type": "ARP Spoofing", "severity": "CRITICAL", "status": "RESOLVED"})

    sev_counts = alert_manager.get_severity_counts()
    assert sev_counts == {"HIGH": 2, "MEDIUM": 1, "CRITICAL": 1}

    type_counts = alert_manager.get_alert_type_counts()
    assert type_counts == {"Port Scan": 2, "Ping Sweep": 1, "ARP Spoofing": 1}

    status_counts = alert_manager.get_status_counts()
    assert status_counts == {"NEW": 2, "ACKNOWLEDGED": 1, "RESOLVED": 1}


def test_32_alert_dataclass_dict_access(alert_manager: AlertManager):
    """32. Verify Alert dataclass supports dictionary-like indexing and get()."""
    aid = alert_manager.save_alert({
        "alert_type": "Dict Test",
        "severity": "LOW",
        "src_ip": "1.2.3.4",
    })
    alert = alert_manager.get_alert(aid)
    assert alert is not None

    # Key access
    assert alert["id"] == aid
    assert alert["alert_type"] == "Dict Test"
    assert alert["severity"] == "LOW"
    assert alert["src_ip"] == "1.2.3.4"

    # 'in' operator
    assert "severity" in alert
    assert "nonexistent_field" not in alert

    # get()
    assert alert.get("severity") == "LOW"
    assert alert.get("missing", "default_val") == "default_val"

    # to_dict()
    d = alert.to_dict()
    assert isinstance(d, dict)
    assert d["id"] == aid


def test_33_recent_alerts_and_counts(alert_manager: AlertManager):
    """33. Verify get_recent_alerts and filtered get_alert_count."""
    for i in range(15):
        alert_manager.save_alert({
            "alert_type": f"T{i}",
            "severity": "CRITICAL" if i < 5 else "LOW",
            "status": "NEW",
        })

    recent = alert_manager.get_recent_alerts(limit=5)
    assert len(recent) == 5

    assert alert_manager.get_alert_count() == 15
    assert alert_manager.get_alert_count(severity="CRITICAL") == 5
    assert alert_manager.get_alert_count(severity="LOW") == 10
    assert alert_manager.get_alert_count(status="NEW") == 15
    assert alert_manager.get_alert_count(status="RESOLVED") == 0


def test_34_delete_and_clear_alerts(alert_manager: AlertManager):
    """34. Verify delete_alert and clear_all_alerts functionality."""
    id1 = alert_manager.save_alert({"alert_type": "A1", "severity": "LOW"})
    id2 = alert_manager.save_alert({"alert_type": "A2", "severity": "LOW"})

    assert alert_manager.get_alert_count() == 2

    # Delete single
    del_res = alert_manager.delete_alert(id1)
    assert del_res is True
    assert alert_manager.get_alert(id1) is None
    assert alert_manager.get_alert_count() == 1

    # Delete nonexistent
    assert alert_manager.delete_alert(99999) is False

    # Clear all
    cleared = alert_manager.clear_all_alerts()
    assert cleared == 1
    assert alert_manager.get_alert_count() == 0


def test_35_time_range_filtering(alert_manager: AlertManager):
    """35. Verify start_time and end_time filtering in get_alerts."""
    t1 = "2026-05-01T10:00:00+00:00"
    t2 = "2026-05-02T10:00:00+00:00"
    t3 = "2026-05-03T10:00:00+00:00"

    alert_manager.save_alert({"timestamp": t1, "alert_type": "Day 1", "severity": "LOW"})
    alert_manager.save_alert({"timestamp": t2, "alert_type": "Day 2", "severity": "LOW"})
    alert_manager.save_alert({"timestamp": t3, "alert_type": "Day 3", "severity": "LOW"})

    # Filter with start_time and end_time
    range_alerts = alert_manager.get_alerts(
        start_time="2026-05-01T12:00:00+00:00",
        end_time="2026-05-02T12:00:00+00:00",
    )
    assert len(range_alerts) == 1
    assert range_alerts[0].alert_type == "Day 2"
