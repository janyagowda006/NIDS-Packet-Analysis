"""TCP SYN Anomaly and SYN Flood Detection Engine for NIDS.

Detects abnormal TCP SYN activity, including high-rate SYN surges (SYN flood-like behavior)
and unusually high incomplete connection ratios.
Adheres to the core principle: "Analyze first, detect second, explain every alert."

Consumes `NormalizedPacket` instances and configurable baseline thresholds from `thresholds.yaml`.
Uses stateful flow information from `TrafficAnalyzer` to track completed vs. incomplete handshakes.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.analysis.models import FlowKey
from backend.analysis.traffic import TrafficAnalyzer
from backend.config.loader import load_thresholds
from backend.detection.models import DetectionResult
from backend.parser.models import NormalizedPacket

logger = logging.getLogger(__name__)


class SynAnomalyDetector:
    """Modular rule-based detector for abnormal TCP SYN rates and incomplete connection ratios."""

    def __init__(
        self,
        time_window_seconds: Optional[float] = None,
        syn_rate_threshold: Optional[int] = None,
        incomplete_ratio_threshold: Optional[float] = None,
        min_syn_for_ratio: Optional[int] = None,
        alert_cooldown_seconds: Optional[float] = None,
        config_path: Optional[str | Path] = None,
        analyzer: Optional[TrafficAnalyzer] = None,
    ) -> None:
        """Initialize SynAnomalyDetector with configurable baseline thresholds.

        If thresholds are not explicitly supplied, they are loaded from thresholds.yaml.
        """
        raw_config = load_thresholds(config_path)
        rule_cfg = raw_config.get("detection_rules", {}).get("syn_anomaly", {})
        sys_cfg = raw_config.get("system", {})

        self.enabled: bool = bool(rule_cfg.get("enabled", True))
        self.alert_type: str = str(rule_cfg.get("alert_type", "Possible SYN Flood / SYN Anomaly"))
        self.default_severity: str = str(
            rule_cfg.get("default_severity") or rule_cfg.get("severity") or "HIGH"
        )

        # Configurable thresholds with backward-compatible alias resolution
        self.time_window_seconds: float = float(
            time_window_seconds
            if time_window_seconds is not None
            else (
                rule_cfg.get("time_window_seconds")
                if "time_window_seconds" in rule_cfg
                else rule_cfg.get("window_seconds", 1.0)
            )
        )
        self.syn_rate_threshold: int = int(
            syn_rate_threshold
            if syn_rate_threshold is not None
            else rule_cfg.get("syn_rate_threshold", 50)
        )
        self.incomplete_ratio_threshold: float = float(
            incomplete_ratio_threshold
            if incomplete_ratio_threshold is not None
            else rule_cfg.get("incomplete_ratio_threshold", 0.8)
        )
        self.min_syn_for_ratio: int = int(
            min_syn_for_ratio
            if min_syn_for_ratio is not None
            else rule_cfg.get("min_syn_for_ratio", 5)
        )
        self.alert_cooldown_seconds: float = float(
            alert_cooldown_seconds
            if alert_cooldown_seconds is not None
            else sys_cfg.get("alert_cooldown_seconds", 10.0)
        )

        # Shared or internal TrafficAnalyzer for stateful connection tracking
        self._analyzer: TrafficAnalyzer = analyzer if analyzer is not None else TrafficAnalyzer()

        # Sliding window candidate buffer
        self._syn_buffer: List[NormalizedPacket] = []
        self._max_timestamp: float = 0.0

        # Cooldown tracker: (src_ip, detection_type) -> last_alerted_timestamp
        self._last_alerted: Dict[Tuple[str, str], float] = {}

    def is_syn_candidate(self, packet: NormalizedPacket) -> bool:
        """Determine whether a packet represents an outbound connection attempt.

        Candidate criteria:
        - Must be TCP (or HTTP layer over TCP)
        - Must have valid source IP and destination port
        - SYN flag MUST be set
        - ACK flag MUST NOT be set (excludes server SYN-ACK replies and ACK-only packets)
        - RST and FIN flags MUST NOT be set
        """
        if not packet.src_ip or packet.dst_port is None:
            return False

        proto = packet.protocol.upper()
        if proto not in ("TCP", "HTTP") and packet.tcp_flags is None:
            return False

        has_syn = packet.has_flag("SYN")
        has_ack = packet.has_flag("ACK")
        has_rst = packet.has_flag("RST")
        has_fin = packet.has_flag("FIN")

        return has_syn and not has_ack and not has_rst and not has_fin

    def process_packet(self, packet: NormalizedPacket) -> List[DetectionResult]:
        """Process a single packet incrementally and evaluate active sliding windows.

        Updates flow records in the traffic analyzer, prunes expired candidate packets,
        and returns detection results if thresholds are crossed.
        """
        # Always feed the traffic analyzer so flow state remains accurate
        self._analyzer.process_packet(packet)

        if not self.enabled:
            return []

        if not self.is_syn_candidate(packet):
            return []

        # Buffer candidate packet
        self._syn_buffer.append(packet)
        self._max_timestamp = max(self._max_timestamp, packet.timestamp)

        # Prune packets outside the sliding window
        window_start = self._max_timestamp - self.time_window_seconds
        self._syn_buffer = [p for p in self._syn_buffer if p.timestamp >= window_start]

        return self._evaluate_window(
            syn_packets=self._syn_buffer,
            current_time=self._max_timestamp,
            analyzer=self._analyzer,
            window_duration=self.time_window_seconds,
            bypass_cooldown=False,
        )

    def detect_window(
        self,
        packets: List[NormalizedPacket],
        time_window_seconds: Optional[float] = None,
        end_time: Optional[float] = None,
        bypass_cooldown: bool = True,
    ) -> List[DetectionResult]:
        """Statelessly evaluate a batch of packets over a specified time window.

        Creates an isolated local TrafficAnalyzer to evaluate handshake completeness
        across the window without mutating the detector's persistent streaming state.
        """
        if not self.enabled or not packets:
            return []

        duration = (
            time_window_seconds if time_window_seconds is not None else self.time_window_seconds
        )
        ref_end = end_time if end_time is not None else max(p.timestamp for p in packets)
        ref_start = ref_end - duration

        # Extract packets that fall within the time window
        window_packets = [p for p in packets if ref_start <= p.timestamp <= ref_end]
        if not window_packets:
            return []

        # Build isolated flow state for this window
        local_analyzer = TrafficAnalyzer()
        local_analyzer.process_packets(window_packets)

        candidates = [p for p in window_packets if self.is_syn_candidate(p)]
        if not candidates:
            return []

        return self._evaluate_window(
            syn_packets=candidates,
            current_time=ref_end,
            analyzer=local_analyzer,
            window_duration=duration,
            bypass_cooldown=bypass_cooldown,
        )

    def _evaluate_window(
        self,
        syn_packets: List[NormalizedPacket],
        current_time: float,
        analyzer: TrafficAnalyzer,
        window_duration: Optional[float] = None,
        bypass_cooldown: bool = False,
    ) -> List[DetectionResult]:
        """Evaluate candidate SYN packets across all observed source IPs."""
        results: List[DetectionResult] = []
        duration = window_duration if window_duration is not None else self.time_window_seconds
        window_start = current_time - duration

        # Group SYN packets by source IP
        by_source: Dict[str, List[NormalizedPacket]] = defaultdict(list)
        for pkt in syn_packets:
            if pkt.src_ip:
                by_source[pkt.src_ip].append(pkt)

        for src_ip, pkts in by_source.items():
            syn_count = len(pkts)
            dst_ips: Set[str] = {p.dst_ip for p in pkts if p.dst_ip}
            dst_ports: Set[int] = {p.dst_port for p in pkts if p.dst_port is not None}
            primary_target = next(iter(dst_ips)) if len(dst_ips) == 1 else None

            # ------------------------------------------------------------------
            # 1. SYN Rate Anomaly Detection
            # ------------------------------------------------------------------
            if syn_count >= self.syn_rate_threshold:
                cooldown_key = (src_ip, "SYN_RATE_ANOMALY")
                if bypass_cooldown or self._can_alert(cooldown_key, current_time):
                    self._last_alerted[cooldown_key] = current_time
                    reason = (
                        f"Possible SYN anomaly: {syn_count} TCP SYN attempts observed from source {src_ip} "
                        f"within a {duration:.1f}s window, exceeding configured threshold of {self.syn_rate_threshold}."
                    )
                    evidence = {
                        "source_ip": src_ip,
                        "destination_ip": primary_target,
                        "observed_syn_count": syn_count,
                        "syn_rate_threshold": self.syn_rate_threshold,
                        "window_seconds": duration,
                        "unique_destination_ips_count": len(dst_ips),
                        "sample_destination_ips": sorted(list(dst_ips))[:20],
                        "unique_destination_ports_count": len(dst_ports),
                        "sample_destination_ports": sorted(list(dst_ports))[:20],
                    }
                    results.append(
                        DetectionResult(
                            rule_name="syn_anomaly",
                            alert_type=self.alert_type,
                            severity=self.default_severity,
                            scan_type="SYN_RATE_ANOMALY",
                            detection_type="SYN_RATE_ANOMALY",
                            src_ip=src_ip,
                            dst_ip=primary_target,
                            protocol="TCP",
                            timestamp=current_time,
                            window_seconds=duration,
                            start_time=window_start,
                            end_time=current_time,
                            syn_count=syn_count,
                            unique_destination_ports=len(dst_ports),
                            unique_destination_ips=len(dst_ips),
                            threshold_values={
                                "syn_rate_threshold": self.syn_rate_threshold,
                                "time_window_seconds": duration,
                            },
                            detection_reason=reason,
                            evidence=evidence,
                        )
                    )

            # ------------------------------------------------------------------
            # 2. Incomplete Connection Ratio Evaluation
            # ------------------------------------------------------------------
            # Deduplicate connection attempts by 4-tuple to handle retransmissions correctly
            connection_keys: Set[Tuple[str, int, str, int]] = {
                (p.src_ip, p.src_port or 0, p.dst_ip or "0.0.0.0", p.dst_port or 0)
                for p in pkts
            }
            total_attempts = len(connection_keys)

            if total_attempts >= self.min_syn_for_ratio:
                completed_count = 0
                for s_ip, s_port, d_ip, d_port in connection_keys:
                    flow_key = FlowKey.from_packet(
                        NormalizedPacket(
                            timestamp=current_time,
                            src_ip=s_ip,
                            src_port=s_port,
                            dst_ip=d_ip,
                            dst_port=d_port,
                            protocol="TCP",
                        )
                    )
                    flow = analyzer.get_flow(flow_key)
                    if flow is not None:
                        # Handshake succeeded if ESTABLISHED, CLOSING, or seen SYN+SYN_ACK+ACK
                        handshake_completed = (
                            (flow.syn_seen and flow.syn_ack_seen and flow.ack_seen)
                            or flow.state in ("ESTABLISHED", "CLOSING")
                            or (flow.state == "CLOSED" and flow.syn_ack_seen)
                        )
                        if handshake_completed:
                            completed_count += 1

                incomplete_count = total_attempts - completed_count
                incomplete_ratio = incomplete_count / total_attempts if total_attempts > 0 else 0.0

                if incomplete_ratio >= self.incomplete_ratio_threshold:
                    cooldown_key = (src_ip, "SYN_INCOMPLETE_ANOMALY")
                    if bypass_cooldown or self._can_alert(cooldown_key, current_time):
                        self._last_alerted[cooldown_key] = current_time
                        reason = (
                            f"Possible SYN anomaly: Source {src_ip} had {incomplete_count} incomplete connection "
                            f"attempts out of {total_attempts} total attempts (incomplete ratio {incomplete_ratio:.2f}) "
                            f"within a {duration:.1f}s window, exceeding threshold of {self.incomplete_ratio_threshold:.2f}."
                        )
                        evidence = {
                            "source_ip": src_ip,
                            "destination_ip": primary_target,
                            "total_connection_attempts": total_attempts,
                            "incomplete_connections_count": incomplete_count,
                            "completed_connections_count": completed_count,
                            "incomplete_ratio": round(incomplete_ratio, 4),
                            "threshold_incomplete_ratio": self.incomplete_ratio_threshold,
                            "min_syn_for_ratio": self.min_syn_for_ratio,
                            "window_seconds": duration,
                            "sample_destination_ips": sorted(list(dst_ips))[:20],
                        }
                        results.append(
                            DetectionResult(
                                rule_name="syn_anomaly",
                                alert_type=self.alert_type,
                                severity=self.default_severity,
                                scan_type="SYN_INCOMPLETE_ANOMALY",
                                detection_type="SYN_INCOMPLETE_ANOMALY",
                                src_ip=src_ip,
                                dst_ip=primary_target,
                                protocol="TCP",
                                timestamp=current_time,
                                window_seconds=duration,
                                start_time=window_start,
                                end_time=current_time,
                                syn_count=syn_count,
                                incomplete_ratio=round(incomplete_ratio, 4),
                                unique_destination_ports=len(dst_ports),
                                unique_destination_ips=len(dst_ips),
                                threshold_values={
                                    "incomplete_ratio_threshold": self.incomplete_ratio_threshold,
                                    "min_syn_for_ratio": self.min_syn_for_ratio,
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
        """Reset internal candidate packet buffer, flow tracker, and cooldown cache."""
        self._syn_buffer.clear()
        self._last_alerted.clear()
        self._max_timestamp = 0.0
        self._analyzer.reset()
        logger.debug("SynAnomalyDetector state reset.")
