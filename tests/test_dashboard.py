"""Comprehensive unit and integration tests for Phase 11: Streamlit Dashboard."""

from __future__ import annotations

import inspect
from pathlib import Path

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from backend.alert import Alert, AlertDatabase, AlertManager, AlertStatus
from backend.detection.models import DetectionResult
from frontend.dashboard import (
    build_alerts_dataframe,
    format_alert_row,
    get_alert_manager,
    get_alert_type_dataframe,
    get_severity_dataframe,
    get_status_dataframe,
    get_summary_metrics,
    render_dashboard,
)


@pytest.fixture
def temp_manager(tmp_path: Path) -> AlertManager:
    """Fixture providing an AlertManager backed by a temporary SQLite database."""
    db_file = tmp_path / "dashboard_test.db"
    return AlertManager(db_path=db_file)


@pytest.fixture
def populated_manager(temp_manager: AlertManager) -> AlertManager:
    """Fixture providing an AlertManager populated with diverse sample alerts."""
    alerts_data = [
        DetectionResult(
            rule_name="port_scan",
            alert_type="Possible Port Scan",
            severity="HIGH",
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP",
            detection_reason="Vertical port scan observed.",
            evidence={"ports": [22, 80, 443], "count": 3},
        ),
        DetectionResult(
            rule_name="syn_anomaly",
            alert_type="Possible SYN Flood / SYN Anomaly",
            severity="CRITICAL",
            src_ip="10.0.0.50",
            dst_ip="10.0.0.1",
            protocol="TCP",
            detection_reason="SYN flood rate exceeded.",
            evidence={"syn_count": 100},
        ),
        DetectionResult(
            rule_name="arp_spoofing",
            alert_type="Possible ARP Spoofing / ARP Mapping Anomaly",
            severity="CRITICAL",
            src_ip="192.168.1.5",
            protocol="ARP",
            detection_reason="MAC binding conflicting.",
            evidence={"ip": "192.168.1.1", "new_mac": "aa:bb:cc:dd:ee:ff"},
        ),
        DetectionResult(
            rule_name="ping_sweep",
            alert_type="Possible Ping Sweep",
            severity="MEDIUM",
            src_ip="172.16.0.10",
            protocol="ICMP",
            detection_reason="ICMP sweep across hosts.",
            evidence={"hosts_count": 15},
        ),
        DetectionResult(
            rule_name="dns_anomaly",
            alert_type="Possible DNS Anomaly",
            severity="LOW",
            src_ip="192.168.1.80",
            dst_ip="8.8.8.8",
            protocol="DNS",
            detection_reason="Unusually long DNS label.",
            evidence={"query": "test.corp.internal", "label_len": 55},
        ),
    ]

    id1 = temp_manager.save_alert(alerts_data[0], status=AlertStatus.NEW)
    id2 = temp_manager.save_alert(alerts_data[1], status=AlertStatus.NEW)
    id3 = temp_manager.save_alert(alerts_data[2], status=AlertStatus.ACKNOWLEDGED)
    id4 = temp_manager.save_alert(alerts_data[3], status=AlertStatus.RESOLVED)
    id5 = temp_manager.save_alert(alerts_data[4], status=AlertStatus.NEW)

    return temp_manager


# ==============================================================================
# 1. IMPORTS & PUBLIC API INTEGRITY
# ==============================================================================

def test_1_dashboard_imports_successfully():
    """1. Verify frontend.dashboard imports cleanly and exports required functions."""
    import frontend.dashboard as dash

    assert hasattr(dash, "get_alert_manager")
    assert hasattr(dash, "get_summary_metrics")
    assert hasattr(dash, "get_severity_dataframe")
    assert hasattr(dash, "get_alert_type_dataframe")
    assert hasattr(dash, "get_status_dataframe")
    assert hasattr(dash, "format_alert_row")
    assert hasattr(dash, "build_alerts_dataframe")
    assert hasattr(dash, "render_dashboard")


# ==============================================================================
# 2. ALERT MANAGER INITIALIZATION
# ==============================================================================

def test_2_alert_manager_initialization(tmp_path: Path):
    """2. Verify get_alert_manager initializes with custom or default paths."""
    custom_db = tmp_path / "custom.db"
    manager = get_alert_manager(db_path=custom_db)

    assert isinstance(manager, AlertManager)
    assert manager.db.db_path == str(custom_db.resolve())
    assert custom_db.exists()


# ==============================================================================
# 3. EMPTY DATABASE BEHAVIOR
# ==============================================================================

def test_3_empty_database_handling(temp_manager: AlertManager):
    """3. Verify all dashboard presentation utilities handle an empty database safely."""
    metrics = get_summary_metrics(temp_manager)
    assert metrics == {
        "total": 0,
        "new": 0,
        "high_critical": 0,
        "resolved": 0,
        "acknowledged": 0,
    }

    df_sev = get_severity_dataframe(temp_manager)
    assert isinstance(df_sev, pd.DataFrame)
    assert df_sev.empty
    assert list(df_sev.columns) == ["Severity", "Count"]

    df_types = get_alert_type_dataframe(temp_manager)
    assert isinstance(df_types, pd.DataFrame)
    assert df_types.empty
    assert list(df_types.columns) == ["Alert Type", "Count"]

    df_status = get_status_dataframe(temp_manager)
    assert isinstance(df_status, pd.DataFrame)
    assert df_status.empty
    assert list(df_status.columns) == ["Status", "Count"]

    df_empty_alerts = build_alerts_dataframe([])
    assert isinstance(df_empty_alerts, pd.DataFrame)
    assert df_empty_alerts.empty
    assert "ID" in df_empty_alerts.columns
    assert "Timestamp" in df_empty_alerts.columns
    assert "Alert Type" in df_empty_alerts.columns
    assert "Severity" in df_empty_alerts.columns
    assert "Source IP" in df_empty_alerts.columns
    assert "Destination IP" in df_empty_alerts.columns
    assert "Protocol" in df_empty_alerts.columns
    assert "Status" in df_empty_alerts.columns


# ==============================================================================
# 4. ALERTS RETRIEVAL & TABLE FORMATTING
# ==============================================================================

def test_4_alerts_retrieval_and_table_formatting(populated_manager: AlertManager):
    """4. Verify alerts are retrieved and formatted into a clean tabular DataFrame."""
    alerts = populated_manager.get_alerts()
    assert len(alerts) == 5

    df = build_alerts_dataframe(alerts)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 5
    assert list(df.columns) == [
        "ID",
        "Timestamp",
        "Alert Type",
        "Severity",
        "Source IP",
        "Destination IP",
        "Protocol",
        "Status",
    ]

    # Check fallback for None destination IP
    arp_row = df[df["Alert Type"] == "Possible ARP Spoofing / ARP Mapping Anomaly"].iloc[0]
    assert arp_row["Destination IP"] == "N/A"
    assert arp_row["Protocol"] == "ARP"


def test_4b_format_alert_row_unit():
    """4b. Verify format_alert_row handles missing optional fields gracefully."""
    alert = Alert(
        id=42,
        timestamp="2026-10-02T12:00:00+00:00",
        alert_type="Mock Alert",
        severity="MEDIUM",
        src_ip=None,
        dst_ip=None,
        protocol=None,
        status="NEW",
    )
    row = format_alert_row(alert)
    assert row["ID"] == 42
    assert row["Source IP"] == "N/A"
    assert row["Destination IP"] == "N/A"
    assert row["Protocol"] == "UNKNOWN"
    assert row["Status"] == "NEW"


# ==============================================================================
# 5. SUMMARY METRICS CALCULATION
# ==============================================================================

def test_5_summary_metrics_calculation(populated_manager: AlertManager):
    """5. Verify summary metric counts match persisted alert states."""
    metrics = get_summary_metrics(populated_manager)

    # 5 total: 3 NEW, 1 ACKNOWLEDGED, 1 RESOLVED
    # Severities: 1 HIGH, 2 CRITICAL (total 3 high/crit), 1 MEDIUM, 1 LOW
    assert metrics["total"] == 5
    assert metrics["new"] == 3
    assert metrics["high_critical"] == 3
    assert metrics["resolved"] == 1
    assert metrics["acknowledged"] == 1


# ==============================================================================
# 6. SEVERITY DATAFRAME AGGREGATION
# ==============================================================================

def test_6_severity_dataframe_aggregation(populated_manager: AlertManager):
    """6. Verify severity aggregation returns ordered DataFrame."""
    df_sev = get_severity_dataframe(populated_manager)
    assert not df_sev.empty

    sev_dict = dict(zip(df_sev["Severity"], df_sev["Count"]))
    assert sev_dict["CRITICAL"] == 2
    assert sev_dict["HIGH"] == 1
    assert sev_dict["MEDIUM"] == 1
    assert sev_dict["LOW"] == 1


# ==============================================================================
# 7. ALERT TYPE DATAFRAME AGGREGATION
# ==============================================================================

def test_7_alert_type_dataframe_aggregation(populated_manager: AlertManager):
    """7. Verify alert type aggregation dynamically reflects all detected types."""
    df_types = get_alert_type_dataframe(populated_manager)
    assert not df_types.empty

    types_dict = dict(zip(df_types["Alert Type"], df_types["Count"]))
    assert types_dict["Possible Port Scan"] == 1
    assert types_dict["Possible SYN Flood / SYN Anomaly"] == 1
    assert types_dict["Possible ARP Spoofing / ARP Mapping Anomaly"] == 1
    assert types_dict["Possible Ping Sweep"] == 1
    assert types_dict["Possible DNS Anomaly"] == 1


# ==============================================================================
# 8. STATUS DATAFRAME AGGREGATION
# ==============================================================================

def test_8_status_dataframe_aggregation(populated_manager: AlertManager):
    """8. Verify status aggregation returns accurate status distribution."""
    df_status = get_status_dataframe(populated_manager)
    assert not df_status.empty

    status_dict = dict(zip(df_status["Status"], df_status["Count"]))
    assert status_dict[AlertStatus.NEW] == 3
    assert status_dict[AlertStatus.ACKNOWLEDGED] == 1
    assert status_dict[AlertStatus.RESOLVED] == 1


# ==============================================================================
# 9. ALERT DETAILS PRESERVATION
# ==============================================================================

def test_9_alert_details_preserved_from_alert_data(populated_manager: AlertManager):
    """9. Verify alert details, explanations, and evidence are retrieved accurately."""
    alerts = populated_manager.get_alerts(alert_type="Possible Port Scan")
    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.description == "Vertical port scan observed."
    assert alert.detection_reason == "Vertical port scan observed."
    assert isinstance(alert.evidence, dict)
    assert alert.evidence["count"] == 3
    assert alert.evidence["ports"] == [22, 80, 443]


# ==============================================================================
# 10. STATUS UPDATE VIA ALERT MANAGER
# ==============================================================================

def test_10_status_update_via_alert_manager(populated_manager: AlertManager):
    """10. Verify updating alert status through AlertManager reflects in queries."""
    alerts = populated_manager.get_alerts(status=AlertStatus.NEW)
    target = alerts[0]

    success = populated_manager.update_status(target.id, AlertStatus.RESOLVED)
    assert success is True

    updated = populated_manager.get_alert(target.id)
    assert updated is not None
    assert updated.status == AlertStatus.RESOLVED

    # Counts updated
    metrics = get_summary_metrics(populated_manager)
    assert metrics["new"] == 2
    assert metrics["resolved"] == 2


# ==============================================================================
# 11. NO DETECTION LOGIC IN DASHBOARD
# ==============================================================================

def test_11_no_detection_logic_in_dashboard():
    """11. Verify frontend.dashboard does not define or duplicate any detection logic."""
    import frontend.dashboard as dash

    source_code = inspect.getsource(dash)

    # Prohibited detector imports or definitions
    assert "class PortScanDetector" not in source_code
    assert "class SynAnomalyDetector" not in source_code
    assert "class ARPAnomalyDetector" not in source_code
    assert "class PingSweepDetector" not in source_code
    assert "class DNSAnomalyDetector" not in source_code

    # Prohibited packet sniffing or dissection
    assert "scapy.sniff" not in source_code
    assert "PacketCaptureEngine" not in source_code
    assert "PacketDissector" not in source_code


# ==============================================================================
# 12 & 13. STREAMLIT APPTEST EXECUTION
# ==============================================================================

def test_12_streamlit_app_test_execution_empty(tmp_path: Path, monkeypatch):
    """12. Execute dashboard top-to-bottom via Streamlit AppTest on an empty database."""
    empty_db = tmp_path / "empty_nids.db"
    # Ensure AlertDatabase creates the schema
    AlertDatabase(db_path=empty_db)

    # Point default loader to empty_db
    monkeypatch.setenv("NIDS_DB_PATH", str(empty_db))

    app_path = str(Path(__file__).resolve().parent.parent / "frontend" / "dashboard.py")
    at = AppTest.from_file(app_path)
    at.run()

    assert not at.exception
    # Title rendered
    assert len(at.title) > 0
    assert "NIDS Security Dashboard" in at.title[0].value


def test_13_streamlit_app_test_execution_populated(tmp_path: Path, monkeypatch):
    """13. Execute dashboard top-to-bottom via Streamlit AppTest with seeded alerts."""
    db_file = tmp_path / "seeded_nids.db"
    mgr = AlertManager(db_path=db_file)
    mgr.save_alert(
        DetectionResult(
            rule_name="port_scan",
            alert_type="Possible Port Scan",
            severity="HIGH",
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            detection_reason="Test scan alert",
            evidence={"ports": [80, 443]},
        )
    )

    app_path = str(Path(__file__).resolve().parent.parent / "frontend" / "dashboard.py")
    monkeypatch.setenv("NIDS_DB_PATH", str(db_file))

    at = AppTest.from_file(app_path)
    at.run()

    assert not at.exception
    # Verify metric rendered
    assert len(at.metric) >= 4
    assert at.metric[0].value in ("1", 1)  # Total Alerts
