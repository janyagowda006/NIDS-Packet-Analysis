"""ARP Anomaly and ARP Spoofing Detection Engine for NIDS.

Detects suspicious ARP behavior including IP-to-MAC mapping changes, conflicting
MAC ownership, and suspicious gratuitous/unsolicited ARP announcements.
Adheres to the core principle: "Analyze first, detect second, explain every alert."

Consumes `NormalizedPacket` instances and configurable baseline thresholds from `thresholds.yaml`.
Maintains stateful IP-to-MAC binding tables to track address ownership over time.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.config.loader import load_thresholds
from backend.detection.models import DetectionResult
from backend.parser.models import NormalizedPacket

logger = logging.getLogger(__name__)


class ARPAnomalyDetector:
    """Stateful rule-based detector for ARP spoofing and mapping anomalies."""

    def __init__(
        self,
        alert_on_mac_change: Optional[bool] = None,
        inspect_replies_only: Optional[bool] = None,
        alert_cooldown_seconds: Optional[float] = None,
        default_severity: Optional[str] = None,
        config_path: Optional[str | Path] = None,
    ) -> None:
        """Initialize ARPAnomalyDetector with configurable baseline thresholds.

        If thresholds are not explicitly supplied, they are loaded from thresholds.yaml.
        """
        raw_config = load_thresholds(config_path)
        rule_cfg = raw_config.get("detection_rules", {}).get("arp_spoofing", {})
        sys_cfg = raw_config.get("system", {})

        self.enabled: bool = bool(rule_cfg.get("enabled", True))
        self.alert_type: str = str(
            rule_cfg.get("alert_type", "Possible ARP Spoofing / ARP Mapping Anomaly")
        )
        self.default_severity: str = str(
            default_severity
            or rule_cfg.get("default_severity")
            or rule_cfg.get("severity")
            or "CRITICAL"
        )

        # Configurable thresholds with backward-compatible alias resolution
        if alert_on_mac_change is not None:
            self.alert_on_mac_change: bool = bool(alert_on_mac_change)
        elif "alert_on_mac_change" in rule_cfg:
            self.alert_on_mac_change = bool(rule_cfg["alert_on_mac_change"])
        elif "mac_change_alert" in rule_cfg:
            self.alert_on_mac_change = bool(rule_cfg["mac_change_alert"])
        else:
            self.alert_on_mac_change = True

        self.inspect_replies_only: bool = bool(
            inspect_replies_only
            if inspect_replies_only is not None
            else rule_cfg.get("inspect_replies_only", False)
        )

        self.alert_cooldown_seconds: float = float(
            alert_cooldown_seconds
            if alert_cooldown_seconds is not None
            else (
                rule_cfg.get("alert_cooldown_seconds")
                or sys_cfg.get("alert_cooldown_seconds", 10.0)
            )
        )

        # Stateful IP -> MAC mapping table: IP -> active MAC (normalized lowercase)
        self._ip_to_mac: Dict[str, str] = {}
        # History of unique MAC addresses observed claiming each IP
        self._ip_to_mac_history: Dict[str, List[str]] = defaultdict(list)
        # Timestamps when each (ip, mac) pairing was last observed
        self._ip_mac_timestamps: Dict[Tuple[str, str], float] = {}
        # Cooldown tracker: (ip, new_mac) -> last_alerted_timestamp
        self._last_alerted: Dict[Tuple[str, str], float] = {}

    def is_arp_candidate(self, packet: NormalizedPacket) -> bool:
        """Determine whether a packet represents a valid ARP observation for binding analysis.

        Candidate criteria:
        - Protocol must be ARP (or packet has an ARP operation code)
        - Must have a valid sender IP (excludes missing or 0.0.0.0 probe addresses)
        - Must have a valid sender MAC (excludes missing, broadcast, or all-zero MACs)
        - ARP operation must be a recognized opcode (1=Request, 2=Reply)
        - If inspect_replies_only is enabled, operation must be an ARP Reply (2)
        """
        proto = packet.protocol.upper()
        if proto != "ARP" and packet.arp_op is None:
            return False

        # Recognize only standard Request (1) and Reply (2) opcodes
        if packet.arp_op not in (1, 2):
            return False

        if self.inspect_replies_only and packet.arp_op != 2:
            return False

        sender_ip = packet.arp_sender_ip or packet.src_ip
        sender_mac = packet.arp_sender_mac or packet.src_mac

        if not sender_ip or not sender_mac:
            return False

        sender_ip_clean = sender_ip.strip()
        sender_mac_clean = sender_mac.strip().lower()

        # Ignore unassigned ARP probes (RFC 5227 DAD probe uses 0.0.0.0)
        if sender_ip_clean in ("0.0.0.0", ""):
            return False

        # Ignore invalid/broadcast sender MACs
        if sender_mac_clean in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", ""):
            return False

        return True

    def process_packet(self, packet: NormalizedPacket) -> List[DetectionResult]:
        """Process a single packet incrementally and evaluate IP-to-MAC binding stability.

        Returns a list of DetectionResult objects if a suspicious mapping change
        or conflicting MAC ownership is observed.
        """
        if not self.enabled:
            return []

        if not self.is_arp_candidate(packet):
            return []

        sender_ip = str(packet.arp_sender_ip or packet.src_ip).strip()
        sender_mac = str(packet.arp_sender_mac or packet.src_mac).strip().lower()
        current_time = packet.timestamp

        # Check for Gratuitous ARP (sender IP == target IP)
        target_ip = packet.arp_target_ip or packet.dst_ip
        is_gratuitous = bool(target_ip and sender_ip == str(target_ip).strip())

        previous_mac = self._ip_to_mac.get(sender_ip)

        # ----------------------------------------------------------------------
        # Case 1: Initial observation of sender IP (baseline learning)
        # ----------------------------------------------------------------------
        if previous_mac is None:
            self._ip_to_mac[sender_ip] = sender_mac
            self._ip_to_mac_history[sender_ip].append(sender_mac)
            self._ip_mac_timestamps[(sender_ip, sender_mac)] = current_time
            logger.debug("Learned initial ARP mapping: %s -> %s", sender_ip, sender_mac)
            return []

        # ----------------------------------------------------------------------
        # Case 2: Stable, identical mapping (no change)
        # ----------------------------------------------------------------------
        if previous_mac == sender_mac:
            self._ip_mac_timestamps[(sender_ip, sender_mac)] = current_time
            return []

        # ----------------------------------------------------------------------
        # Case 3: Suspicious IP -> MAC mapping change detected
        # ----------------------------------------------------------------------
        # If mapping change alerts are disabled via config, update binding silently
        if not self.alert_on_mac_change:
            self._ip_to_mac[sender_ip] = sender_mac
            if sender_mac not in self._ip_to_mac_history[sender_ip]:
                self._ip_to_mac_history[sender_ip].append(sender_mac)
            self._ip_mac_timestamps[(sender_ip, sender_mac)] = current_time
            return []

        # Cooldown check per (IP, new_mac) to prevent alert flooding during ARP storms
        cooldown_key = (sender_ip, sender_mac)
        if not self._can_alert(cooldown_key, current_time):
            # Still update tracking timestamps even while suppressing duplicate alert
            self._ip_to_mac[sender_ip] = sender_mac
            self._ip_mac_timestamps[(sender_ip, sender_mac)] = current_time
            return []

        self._last_alerted[cooldown_key] = current_time

        # Distinguish between first-time change vs. conflicting/alternating ownership
        is_conflicting = sender_mac in self._ip_to_mac_history[sender_ip]
        detection_type = (
            "ARP_CONFLICTING_OWNERSHIP" if is_conflicting else "ARP_MAPPING_CHANGE"
        )

        op_name = "REPLY" if packet.arp_op == 2 else "REQUEST"

        if is_conflicting:
            reason = (
                f"Possible ARP spoofing: Conflicting MAC ownership for IP {sender_ip}. "
                f"MAC address {sender_mac} is competing with previously observed {previous_mac}."
            )
        else:
            reason = (
                f"Possible ARP spoofing: IP-to-MAC mapping changed for {sender_ip}. "
                f"Previously associated with {previous_mac}, now claimed by {sender_mac}."
            )

        if is_gratuitous:
            reason += " Packet is an unsolicited/gratuitous ARP announcement."

        evidence: Dict[str, Any] = {
            "ip_address": sender_ip,
            "previous_mac": previous_mac,
            "new_mac": sender_mac,
            "all_observed_macs": list(dict.fromkeys(self._ip_to_mac_history[sender_ip] + [sender_mac])),
            "arp_operation": op_name,
            "arp_op_code": packet.arp_op,
            "is_gratuitous": is_gratuitous,
            "target_ip": target_ip,
            "target_mac": packet.arp_target_mac or packet.dst_mac,
            "previous_seen_timestamp": self._ip_mac_timestamps.get((sender_ip, previous_mac)),
            "current_timestamp": current_time,
            "is_conflicting_ownership": is_conflicting,
        }

        alert = DetectionResult(
            rule_name="arp_spoofing",
            alert_type=self.alert_type,
            severity=self.default_severity,
            scan_type=detection_type,
            detection_type=detection_type,
            src_ip=sender_ip,
            dst_ip=target_ip,
            protocol="ARP",
            timestamp=current_time,
            window_seconds=self.alert_cooldown_seconds,
            start_time=self._ip_mac_timestamps.get((sender_ip, previous_mac), current_time),
            end_time=current_time,
            syn_count=0,
            threshold_values={
                "alert_on_mac_change": self.alert_on_mac_change,
                "inspect_replies_only": self.inspect_replies_only,
                "alert_cooldown_seconds": self.alert_cooldown_seconds,
            },
            detection_reason=reason,
            evidence=evidence,
            previous_mac=previous_mac,
            new_mac=sender_mac,
        )

        # Update persistent mapping state
        self._ip_to_mac[sender_ip] = sender_mac
        if sender_mac not in self._ip_to_mac_history[sender_ip]:
            self._ip_to_mac_history[sender_ip].append(sender_mac)
        self._ip_mac_timestamps[(sender_ip, sender_mac)] = current_time

        return [alert]

    def detect_window(
        self,
        packets: List[NormalizedPacket],
        bypass_cooldown: bool = True,
    ) -> List[DetectionResult]:
        """Evaluate a batch sequence of packets for ARP anomalies.

        Uses an isolated detector instance to process the packet collection
        without mutating the persistent state of this detector instance.
        """
        if not self.enabled or not packets:
            return []

        local_detector = ARPAnomalyDetector(
            alert_on_mac_change=self.alert_on_mac_change,
            inspect_replies_only=self.inspect_replies_only,
            alert_cooldown_seconds=0.0 if bypass_cooldown else self.alert_cooldown_seconds,
            default_severity=self.default_severity,
        )

        alerts: List[DetectionResult] = []
        for pkt in packets:
            alerts.extend(local_detector.process_packet(pkt))
        return alerts

    def get_mapping(self, ip: str) -> Optional[str]:
        """Return the current known MAC address for the given IP address."""
        return self._ip_to_mac.get(ip.strip())

    def get_all_mappings(self) -> Dict[str, str]:
        """Return a copy of all current IP-to-MAC mappings."""
        return dict(self._ip_to_mac)

    def get_mac_history(self, ip: str) -> List[str]:
        """Return the list of all unique MAC addresses seen claiming the given IP."""
        return list(self._ip_to_mac_history.get(ip.strip(), []))

    def _can_alert(self, cooldown_key: Tuple[str, str], current_time: float) -> bool:
        """Check whether alert cooldown duration has elapsed for (ip, mac)."""
        last_time = self._last_alerted.get(cooldown_key)
        if last_time is None:
            return True
        return (current_time - last_time) >= self.alert_cooldown_seconds

    def reset(self) -> None:
        """Reset internal IP-to-MAC mapping tables, history, and cooldown caches."""
        self._ip_to_mac.clear()
        self._ip_to_mac_history.clear()
        self._ip_mac_timestamps.clear()
        self._last_alerted.clear()
        logger.debug("ARPAnomalyDetector state reset.")
