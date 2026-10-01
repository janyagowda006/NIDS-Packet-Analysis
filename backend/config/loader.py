"""Configuration loader for NIDS thresholds and operational settings."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

logger = logging.getLogger(__name__)

# Default fallback thresholds in case thresholds.yaml is not found or fails to parse
DEFAULT_CONFIG: Dict[str, Any] = {
    "system": {
        "sliding_window_seconds": 60,
        "alert_cooldown_seconds": 10,
        "db_path": "nids_events.db",
    },
    "detection_rules": {
        "port_scan": {
            "enabled": True,
            "alert_type": "Possible Port Scan",
            "default_severity": "HIGH",
            "time_window_seconds": 1.0,
            "unique_ports_threshold": 15,
            "unique_destinations_threshold": 10,
            "min_syn_count": 20,
            "description": "High rate of connection attempts across multiple destination ports or hosts.",
        },
        "syn_anomaly": {
            "enabled": True,
            "alert_type": "Possible SYN Flood / SYN Anomaly",
            "default_severity": "HIGH",
            "time_window_seconds": 1.0,
            "syn_rate_threshold": 50,
            "incomplete_ratio_threshold": 0.8,
            "min_syn_for_ratio": 5,
            "description": "Abnormally high SYN packet rate with incomplete TCP handshakes.",
        },
        "arp_spoofing": {
            "enabled": True,
            "alert_type": "Possible ARP Spoofing / ARP Mapping Anomaly",
            "default_severity": "CRITICAL",
            "alert_on_mac_change": True,
            "description": "IP address previously mapped to one MAC address is now claimed by another.",
        },
        "ping_sweep": {
            "enabled": True,
            "alert_type": "Possible Ping Sweep",
            "default_severity": "MEDIUM",
            "time_window_seconds": 2.0,
            "unique_dst_ips_threshold": 10,
            "min_icmp_count": 10,
            "description": "ICMP Echo Requests sent to multiple destination IPs in a short time frame.",
        },
        "dns_anomaly": {
            "enabled": True,
            "alert_type": "Possible DNS Anomaly",
            "default_severity": "LOW",
            "rate_window_seconds": 5.0,
            "time_window_seconds": 5.0,
            "max_queries_per_window": 25,
            "query_rate_threshold": 25,
            "max_query_length": 100,
            "max_label_length": 50,
            "alert_cooldown_seconds": 10.0,
            "description": "DNS query exhibits unusual length, structure, or high repetition frequency.",
        },
    },
}


def get_default_config_path() -> Path:
    """Return the default path to backend/config/thresholds.yaml."""
    return Path(__file__).parent / "thresholds.yaml"


def load_thresholds(config_path: Optional[str | Path] = None) -> Dict[str, Any]:
    """Load and return detection thresholds dictionary from a YAML file.

    Falls back gracefully to DEFAULT_CONFIG if the file is missing or invalid.
    """
    path = Path(config_path) if config_path else get_default_config_path()

    if not path.is_file():
        logger.warning("Config file not found at '%s'. Using built-in default thresholds.", path)
        return DEFAULT_CONFIG.copy()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if isinstance(data, dict):
                return data
            logger.warning("Config at '%s' is not a dictionary. Using default thresholds.", path)
    except Exception as exc:
        logger.error("Failed to load thresholds from '%s': %s. Using default thresholds.", path, exc)

    return DEFAULT_CONFIG.copy()
