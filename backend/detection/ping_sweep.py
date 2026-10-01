"""ICMP Ping Sweep Detection Engine for NIDS.

Detects network reconnaissance behavior where a single source IP transmits
ICMP Echo Requests (Type 8) across many unique destination hosts within a sliding time window.
Adheres to the core principle: "Analyze first, detect second, explain every alert."

Consumes `NormalizedPacket` instances and configurable baseline thresholds from `thresholds.yaml`.
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


class PingSweepDetector:
    """Stateful rule-based detector for ICMP ping sweeps and host discovery activity."""

    def __init__(
        self,
        time_window_seconds: Optional[float] = None,
        unique_dst_ips_threshold: Optional[int] = None,
        min_icmp_count: Optional[int] = None,
        alert_cooldown_seconds: Optional[float] = None,
        default_severity: Optional[str] = None,
        config_path: Optional[str | Path] = None,
    ) -> None:
        """Initialize PingSweepDetector with configurable baseline thresholds.

        If thresholds are not explicitly supplied, they are loaded from thresholds.yaml.
        """
        raw_config = load_thresholds(config_path)
        rule_cfg = raw_config.get("detection_rules", {}).get("ping_sweep", {})
        sys_cfg = raw_config.get("system", {})

        self.enabled: bool = bool(rule_cfg.get("enabled", True))
        self.alert_type: str = str(rule_cfg.get("alert_type", "Possible Ping Sweep"))
        self.default_severity: str = str(
            default_severity
            or rule_cfg.get("default_severity")
            or rule_cfg.get("severity")
            or "MEDIUM"
        )

        # Configurable thresholds with backward-compatible alias resolution
        self.time_window_seconds: float = float(
            time_window_seconds
            if time_window_seconds is not None
            else (
                rule_cfg.get("time_window_seconds")
                if "time_window_seconds" in rule_cfg
                else rule_cfg.get("window_seconds", 2.0)
            )
        )
        self.unique_dst_ips_threshold: int = int(
            unique_dst_ips_threshold
            if unique_dst_ips_threshold is not None
            else (
                rule_cfg.get("unique_dst_ips_threshold")
                if "unique_dst_ips_threshold" in rule_cfg
                else rule_cfg.get("unique_targets_threshold", 10)
            )
        )
        self.min_icmp_count: int = int(
            min_icmp_count
            if min_icmp_count is not None
            else (
                rule_cfg.get("min_icmp_count")
                if "min_icmp_count" in rule_cfg
                else rule_cfg.get("min_echo_requests", 10)
            )
        )
        self.alert_cooldown_seconds: float = float(
            alert_cooldown_seconds
            if alert_cooldown_seconds is not None
            else (
                rule_cfg.get("alert_cooldown_seconds")
                or sys_cfg.get("alert_cooldown_seconds", 10.0)
            )
        )

        # Sliding window buffer of ICMP Echo Request packets
        self._icmp_buffer: List[NormalizedPacket] = []
        self._max_timestamp: float = 0.0

        # Cooldown tracker: (src_ip, detection_type) -> last_alerted_timestamp
        self._last_alerted: Dict[Tuple[str, str], float] = {}

    def is_echo_request_candidate(self, packet: NormalizedPacket) -> bool:
        """Determine whether a packet represents an outbound ICMP Echo Request probe.

        Candidate criteria:
        - Protocol must be ICMP (or packet has icmp_type populated)
        - icmp_type must be 8 (Echo Request); Replies (0) and other types are excluded
        - Must have valid non-empty source IP and destination IP
        """
        proto = packet.protocol.upper()
        if proto != "ICMP" and packet.icmp_type is None:
            return False

        # Only ICMP Echo Request (type 8) indicates an outbound host probe
        if packet.icmp_type != 8:
            return False

        if not packet.src_ip or not packet.dst_ip:
            return False

        return True

    def process_packet(self, packet: NormalizedPacket) -> List[DetectionResult]:
        """Process a single packet incrementally and evaluate active sliding windows.

        Appends valid Echo Requests, prunes packets outside the active window,
        and returns detection results if sweep thresholds are crossed.
        """
        if not self.enabled:
            return []

        if not self.is_echo_request_candidate(packet):
            return []

        self._icmp_buffer.append(packet)
        self._max_timestamp = max(self._max_timestamp, packet.timestamp)

        # Prune packets outside the active sliding window
        window_start = self._max_timestamp - self.time_window_seconds
        self._icmp_buffer = [p for p in self._icmp_buffer if p.timestamp >= window_start]

        return self._evaluate_window(
            icmp_packets=self._icmp_buffer,
            current_time=self._max_timestamp,
            duration=self.time_window_seconds,
            bypass_cooldown=False,
        )

    def detect_window(
        self,
        packets: List[NormalizedPacket],
        time_window_seconds: Optional[float] = None,
        end_time: Optional[float] = None,
        bypass_cooldown: bool = True,
    ) -> List[DetectionResult]:
        """Statelessly evaluate a batch of packets over a specified time window."""
        if not self.enabled or not packets:
            return []

        duration = (
            time_window_seconds if time_window_seconds is not None else self.time_window_seconds
        )
        candidates = [p for p in packets if self.is_echo_request_candidate(p)]
        if not candidates:
            return []

        ref_end = end_time if end_time is not None else max(p.timestamp for p in candidates)
        ref_start = ref_end - duration
        window_slice = [p for p in candidates if ref_start <= p.timestamp <= ref_end]

        return self._evaluate_window(
            icmp_packets=window_slice,
            current_time=ref_end,
            duration=duration,
            bypass_cooldown=bypass_cooldown,
        )

    def _evaluate_window(
        self,
        icmp_packets: List[NormalizedPacket],
        current_time: float,
        duration: float,
        bypass_cooldown: bool = False,
    ) -> List[DetectionResult]:
        """Core detection logic evaluating candidate Echo Requests across all source IPs."""
        results: List[DetectionResult] = []
        window_start = current_time - duration

        # Group candidate Echo Requests by source IP
        by_source: Dict[str, List[NormalizedPacket]] = defaultdict(list)
        for pkt in icmp_packets:
            if pkt.src_ip:
                by_source[pkt.src_ip].append(pkt)

        for src_ip, pkts in by_source.items():
            total_requests = len(pkts)
            dst_ips: Set[str] = {p.dst_ip for p in pkts if p.dst_ip}

            # Threshold check: requires sufficient unique destinations and minimum request volume
            if (
                len(dst_ips) >= self.unique_dst_ips_threshold
                and total_requests >= self.min_icmp_count
            ):
                cooldown_key = (src_ip, "PING_SWEEP")
                if bypass_cooldown or self._can_alert(cooldown_key, current_time):
                    self._last_alerted[cooldown_key] = current_time
                    reason = (
                        f"Possible ping sweep detected: source {src_ip} sent {total_requests} "
                        f"ICMP Echo Requests to {len(dst_ips)} unique destination IPs within a "
                        f"{duration:.1f}s window, exceeding configured threshold of {self.unique_dst_ips_threshold}."
                    )
                    evidence: Dict[str, Any] = {
                        "source_ip": src_ip,
                        "observed_icmp_count": total_requests,
                        "unique_destination_ips_count": len(dst_ips),
                        "sample_destination_ips": sorted(list(dst_ips))[:30],
                        "window_seconds": duration,
                        "threshold_unique_dst_ips": self.unique_dst_ips_threshold,
                        "threshold_min_icmp_count": self.min_icmp_count,
                    }
                    results.append(
                        DetectionResult(
                            rule_name="ping_sweep",
                            alert_type=self.alert_type,
                            severity=self.default_severity,
                            scan_type="PING_SWEEP",
                            detection_type="PING_SWEEP",
                            src_ip=src_ip,
                            dst_ip=None,
                            protocol="ICMP",
                            timestamp=current_time,
                            window_seconds=duration,
                            start_time=window_start,
                            end_time=current_time,
                            syn_count=0,
                            icmp_count=total_requests,
                            unique_destination_ports=0,
                            unique_destination_ips=len(dst_ips),
                            threshold_values={
                                "unique_dst_ips_threshold": self.unique_dst_ips_threshold,
                                "min_icmp_count": self.min_icmp_count,
                                "time_window_seconds": duration,
                            },
                            detection_reason=reason,
                            evidence=evidence,
                        )
                    )

        return results

    def _can_alert(self, cooldown_key: Tuple[str, str], current_time: float) -> bool:
        """Check whether alert cooldown duration has elapsed for a specific (src_ip, detection_type)."""
        last_time = self._last_alerted.get(cooldown_key)
        if last_time is None:
            return True
        return (current_time - last_time) >= self.alert_cooldown_seconds

    def reset(self) -> None:
        """Reset internal candidate packet buffer and cooldown cache."""
        self._icmp_buffer.clear()
        self._last_alerted.clear()
        self._max_timestamp = 0.0
        logger.debug("PingSweepDetector state reset.")
