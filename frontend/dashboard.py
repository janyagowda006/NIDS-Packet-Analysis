"""Streamlit Presentation Layer for Network Intrusion Detection System (NIDS).

Displays security alerts, summary statistics, severity distributions, and explainable
evidence retrieved from the Phase 10 AlertManager and SQLite storage.
Adheres strictly to the core principle: "Analyze first, detect second, explain every alert."
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is present in sys.path regardless of execution working directory
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pandas as pd
import streamlit as st

from backend.alert import Alert, AlertDatabase, AlertManager, AlertStatus


def get_alert_manager(
    db_path: Optional[str | Path] = None,
    config_path: Optional[str | Path] = None,
) -> AlertManager:
    """Initialize and return an AlertManager instance."""
    resolved_db = db_path if db_path is not None else os.environ.get("NIDS_DB_PATH")
    return AlertManager(db_path=resolved_db, config_path=config_path)


def safe_rerun() -> None:
    """Trigger a Streamlit rerun safely across different Streamlit versions."""
    if hasattr(st, "rerun"):
        st.rerun()
    elif hasattr(st, "experimental_rerun"):
        st.experimental_rerun()  # pragma: no cover


def get_summary_metrics(manager: AlertManager) -> Dict[str, int]:
    """Retrieve high-level summary counts from the AlertManager."""
    total = manager.get_alert_count()
    new_alerts = manager.get_alert_count(status=AlertStatus.NEW)
    high_count = manager.get_alert_count(severity="HIGH")
    crit_count = manager.get_alert_count(severity="CRITICAL")
    resolved_count = manager.get_alert_count(status=AlertStatus.RESOLVED)
    ack_count = manager.get_alert_count(status=AlertStatus.ACKNOWLEDGED)

    return {
        "total": total,
        "new": new_alerts,
        "high_critical": high_count + crit_count,
        "resolved": resolved_count,
        "acknowledged": ack_count,
    }


def get_severity_dataframe(manager: AlertManager) -> pd.DataFrame:
    """Return aggregated severity counts as a structured DataFrame."""
    counts = manager.get_severity_counts()
    if not counts:
        return pd.DataFrame(columns=["Severity", "Count"])

    # Standard presentation ordering if available
    desired_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    ordered_data: List[Dict[str, Any]] = []

    for sev in desired_order:
        if sev in counts:
            ordered_data.append({"Severity": sev, "Count": counts[sev]})

    # Any other dynamic severities
    for k, v in counts.items():
        if k not in desired_order:
            ordered_data.append({"Severity": k, "Count": v})

    return pd.DataFrame(ordered_data)


def get_alert_type_dataframe(manager: AlertManager) -> pd.DataFrame:
    """Return aggregated alert type counts as a structured DataFrame."""
    counts = manager.get_alert_type_counts()
    if not counts:
        return pd.DataFrame(columns=["Alert Type", "Count"])

    data = [{"Alert Type": k, "Count": v} for k, v in sorted(counts.items(), key=lambda x: -x[1])]
    return pd.DataFrame(data)


def get_status_dataframe(manager: AlertManager) -> pd.DataFrame:
    """Return aggregated status counts as a structured DataFrame."""
    counts = manager.get_status_counts()
    if not counts:
        return pd.DataFrame(columns=["Status", "Count"])

    desired_order = [AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED]
    ordered_data: List[Dict[str, Any]] = []

    for st_name in desired_order:
        if st_name in counts:
            ordered_data.append({"Status": st_name, "Count": counts[st_name]})

    for k, v in counts.items():
        if k not in desired_order:
            ordered_data.append({"Status": k, "Count": v})

    return pd.DataFrame(ordered_data)


def format_alert_row(alert: Alert) -> Dict[str, Any]:
    """Format an Alert dataclass into a clean tabular representation."""
    return {
        "ID": alert.id,
        "Timestamp": alert.timestamp,
        "Alert Type": alert.alert_type,
        "Severity": alert.severity,
        "Source IP": alert.src_ip if alert.src_ip else "N/A",
        "Destination IP": alert.dst_ip if alert.dst_ip else "N/A",
        "Protocol": alert.protocol if alert.protocol else "UNKNOWN",
        "Status": alert.status,
    }


def build_alerts_dataframe(alerts: List[Alert]) -> pd.DataFrame:
    """Convert a list of Alert dataclasses into a pandas DataFrame."""
    if not alerts:
        return pd.DataFrame(
            columns=[
                "ID",
                "Timestamp",
                "Alert Type",
                "Severity",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Status",
            ]
        )
    return pd.DataFrame([format_alert_row(a) for a in alerts])


def render_dashboard(manager: Optional[AlertManager] = None) -> None:
    """Main rendering routine for the Streamlit dashboard."""
    st.set_page_config(
        page_title="NIDS Security Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    if manager is None:
        manager = get_alert_manager()

    # --------------------------------------------------------------------------
    # SIDEBAR: Controls & Filters
    # --------------------------------------------------------------------------
    with st.sidebar:
        st.header("⚙️ Dashboard Controls")
        st.caption(f"Database: `{manager.db.db_path}`")

        if st.button("🔄 Refresh Dashboard", use_container_width=True):
            safe_rerun()

        st.divider()
        st.subheader("🔍 Alert Filters")

        severity_choice = st.selectbox(
            "Severity",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
            help="Filter alerts by severity level.",
        )

        status_choice = st.selectbox(
            "Status",
            options=["All", AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED],
            index=0,
            help="Filter alerts by lifecycle triage status.",
        )

        # Dynamic alert types from database
        existing_types = sorted(list(manager.get_alert_type_counts().keys()))
        type_options = ["All"] + existing_types
        type_choice = st.selectbox(
            "Alert Type",
            options=type_options,
            index=0,
            help="Filter alerts by specific threat or anomaly type.",
        )

        source_ip_input = st.text_input(
            "Source IP",
            value="",
            placeholder="e.g. 192.168.1.100",
            help="Filter alerts originating from a specific IP.",
        )

        limit_choice = st.selectbox(
            "Alert Limit",
            options=[25, 50, 100, 200],
            index=1,
            help="Maximum number of alerts to display in the table.",
        )

    # --------------------------------------------------------------------------
    # SECTION 1: HEADER
    # --------------------------------------------------------------------------
    st.title("🛡️ NIDS Security Dashboard")
    st.caption("Network Intrusion Detection System — Presentation & Triage Layer")
    st.markdown(
        "Real-time visibility into detected network anomalies and security alerts.  \n"
        "*Core principle: **“Analyze first, detect second, explain every alert.”***"
    )
    st.write("")

    # --------------------------------------------------------------------------
    # SECTION 2: SUMMARY METRICS
    # --------------------------------------------------------------------------
    metrics = get_summary_metrics(manager)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Alerts", metrics["total"])
    with col2:
        st.metric("New Alerts", metrics["new"])
    with col3:
        st.metric("High / Critical Severity", metrics["high_critical"])
    with col4:
        st.metric("Resolved Alerts", metrics["resolved"])

    st.write("")

    # --------------------------------------------------------------------------
    # SECTION 10: EMPTY DATABASE CHECK
    # --------------------------------------------------------------------------
    if metrics["total"] == 0:
        st.info(
            "ℹ️ **No alerts have been detected yet.**  \n"
            "Run the NIDS detection pipeline on live traffic or a PCAP capture to populate the dashboard."
        )

    # --------------------------------------------------------------------------
    # SECTIONS 3, 4, 5: VISUALIZATIONS & DISTRIBUTIONS
    # --------------------------------------------------------------------------
    st.subheader("📊 Threat Distribution Analytics")

    chart_col1, chart_col2, chart_col3 = st.columns(3)

    # Section 3: Severity
    with chart_col1:
        st.markdown("**Severity Distribution**")
        df_sev = get_severity_dataframe(manager)
        if df_sev.empty:
            st.info("No severity data available.")
        else:
            st.bar_chart(df_sev.set_index("Severity")["Count"], color="#ff4b4b")

    # Section 4: Alert Type
    with chart_col2:
        st.markdown("**Alert Type Distribution**")
        df_types = get_alert_type_dataframe(manager)
        if df_types.empty:
            st.info("No alert type data available.")
        else:
            st.bar_chart(df_types.set_index("Alert Type")["Count"], color="#29b5e8")

    # Section 5: Status
    with chart_col3:
        st.markdown("**Status Distribution**")
        df_status = get_status_dataframe(manager)
        if df_status.empty:
            st.info("No status data available.")
        else:
            st.bar_chart(df_status.set_index("Status")["Count"], color="#00d26a")

    st.divider()

    # --------------------------------------------------------------------------
    # SECTION 6 & 7: FILTERED ALERTS TABLE
    # --------------------------------------------------------------------------
    st.subheader("📋 Detected Security Alerts")

    filtered_alerts = manager.get_alerts(
        limit=int(limit_choice),
        severity=severity_choice if severity_choice != "All" else None,
        status=status_choice if status_choice != "All" else None,
        alert_type=type_choice if type_choice != "All" else None,
        src_ip=source_ip_input.strip() if source_ip_input.strip() else None,
    )

    df_alerts = build_alerts_dataframe(filtered_alerts)

    if df_alerts.empty:
        if metrics["total"] > 0:
            st.warning("No alerts match the active filter criteria.")
    else:
        st.dataframe(
            df_alerts,
            use_container_width=True,
            hide_index=True,
        )

    st.divider()

    # --------------------------------------------------------------------------
    # SECTION 8 & 9: ALERT DETAILS & STATUS UPDATE
    # --------------------------------------------------------------------------
    st.subheader("🔍 Alert Details & Explainability Investigation")

    if not filtered_alerts:
        st.info("Select or filter alerts above to inspect explainability evidence and perform triage.")
    else:
        alert_options = {
            f"Alert #{a.id} — [{a.severity}] {a.alert_type} ({a.src_ip or 'unknown'} -> {a.dst_ip or 'unknown'})": a.id
            for a in filtered_alerts
        }

        selected_label = st.selectbox(
            "Select Alert to Inspect",
            options=list(alert_options.keys()),
            help="Choose a specific alert from the filtered results to inspect detection rationale and raw evidence.",
        )

        selected_id = alert_options[selected_label]
        selected_alert = manager.get_alert(selected_id)

        if selected_alert is not None:
            # Metadata Grid
            detail_col1, detail_col2, detail_col3, detail_col4 = st.columns(4)
            with detail_col1:
                st.markdown(f"**Alert ID:** `{selected_alert.id}`")
                st.markdown(f"**Status:** `{selected_alert.status}`")
            with detail_col2:
                st.markdown(f"**Severity:** `{selected_alert.severity}`")
                st.markdown(f"**Protocol:** `{selected_alert.protocol or 'N/A'}`")
            with detail_col3:
                st.markdown(f"**Source IP:** `{selected_alert.src_ip or 'N/A'}`")
                st.markdown(f"**Destination IP:** `{selected_alert.dst_ip or 'N/A'}`")
            with detail_col4:
                st.markdown(f"**Timestamp:** `{selected_alert.timestamp}`")
                st.markdown(f"**Alert Type:** `{selected_alert.alert_type}`")

            st.write("")

            # Explainable Rationale
            with st.expander("📖 Detection Rationale & Description", expanded=True):
                st.markdown(f"**Description:**  \n{selected_alert.description or 'No description provided.'}")
                st.markdown(f"**Detection Reason:**  \n{selected_alert.detection_reason or 'No technical reason provided.'}")

            # Machine-readable Evidence
            with st.expander("🔬 Detection Evidence & Technical Telemetry", expanded=True):
                if selected_alert.evidence:
                    st.json(selected_alert.evidence)
                else:
                    st.info("No structured evidence attached to this alert.")

            # Section 9: Status Update Form
            st.write("")
            st.markdown("##### ✏️ Update Alert Status")
            up_col1, up_col2 = st.columns([3, 1])

            status_choices = [AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED]
            current_idx = status_choices.index(selected_alert.status) if selected_alert.status in status_choices else 0

            with up_col1:
                new_status = st.selectbox(
                    "Assign New Status",
                    options=status_choices,
                    index=current_idx,
                    key=f"status_select_{selected_alert.id}",
                    label_visibility="collapsed",
                )
            with up_col2:
                if st.button("Apply Status", use_container_width=True, key=f"btn_update_{selected_alert.id}"):
                    if new_status != selected_alert.status:
                        manager.update_status(selected_alert.id, new_status)
                        st.success(f"Alert #{selected_alert.id} status successfully updated to '{new_status}'!")
                        safe_rerun()
                    else:
                        st.info(f"Alert #{selected_alert.id} already has status '{new_status}'.")


if __name__ == "__main__":
    render_dashboard()
