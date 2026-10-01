"""TCP Port Scan Detection Engine for NIDS.

Detects Vertical Port Scans, Horizontal Port Scans, and General TCP SYN sweeps.
Adheres to the core principle: "Analyze first, detect second, explain every alert."

Consumes `NormalizedPacket` instances and configurable thresholds from `thresholds.yaml`.
Avoids false positives from normal TCP handshakes, server SYN-ACK replies, and ACK-only traffic.
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


class PortScanDetector:
    """Modular rule-based detector for TCP port-scanning activity."""

    def __init__(
        self,
        time_window_seconds: Optional[float] = None,
        unique_ports_threshold: Optional[int] = None,
        unique_destinations_threshold: Optional[int] = None,
        min_syn_count: Optional[int] = None,
        config_path: Optional[str | Path] = None,
        alert_cooldown_seconds: Optional[float] = None,
    ) -> None:
        """Initialize the PortScanDetector with configurable baseline thresholds.

        If thresholds are not explicitly supplied, they are loaded from thresholds.yaml.
        """
        raw_config = load_thresholds(config_path)
        rule_cfg = raw_config.get("detection_rules", {}).get("port_scan", {})
        sys_cfg = raw_config.get("system", {})

        self.enabled: bool = bool(rule_cfg.get("enabled", True))
        self.alert_type: str = str(rule_cfg.get("alert_type", "Possible Port Scan"))
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
        self.unique_ports_threshold: int = int(
            unique_ports_threshold
            if unique_ports_threshold is not None
            else (
                rule_cfg.get("unique_ports_threshold")
                if "unique_ports_threshold" in rule_cfg
                else rule_cfg.get("unique_destination_ports", 15)
            )
        )
        self.unique_destinations_threshold: int = int(
            unique_destinations_threshold
            if unique_destinations_threshold is not None
            else (
                rule_cfg.get("unique_destinations_threshold")
                if "unique_destinations_threshold" in rule_cfg
                else rule_cfg.get("unique_destination_ips", 10)
            )
        )
        self.min_syn_count: int = int(
            min_syn_count
            if min_syn_count is not None
            else rule_cfg.get("min_syn_count", 20)
        )
        self.alert_cooldown_seconds: float = float(
            alert_cooldown_seconds
            if alert_cooldown_seconds is not None
            else sys_cfg.get("alert_cooldown_seconds", 10.0)
        )

        # Internal sliding buffer: list of (timestamp, NormalizedPacket)
        self._syn_buffer: List[NormalizedPacket] = []
        # Cooldown tracker: (src_ip, scan_type) -> last_alerted_timestamp
        self._last_alerted: Dict[Tuple[str, str], float] = {}

    def is_scan_candidate(self, packet: NormalizedPacket) -> bool:
        """Determine whether a packet represents an outbound connection attempt (SYN without ACK).

        Filters out non-TCP, server SYN-ACK responses, ACK-only packets, and packets without IPs.
        """
        if not packet.src_ip or packet.dst_port is None:
            return False

        proto = packet.protocol.upper()
        if proto not in ("TCP", "HTTP") and packet.tcp_flags is None:
            return False

        # Must have SYN flag set, and MUST NOT have ACK set (distinguishes SYN attempt from SYN-ACK reply)
        has_syn = packet.has_flag("SYN")
        has_ack = packet.has_flag("ACK")
        return has_syn and not has_ack

    def process_packet(self, packet: NormalizedPacket) -> List[DetectionResult]:
        """Process a single packet incrementally and evaluate active sliding windows.

        Returns a list of DetectionResult objects if a scan threshold is crossed.
        """
        if not self.enabled:
            return []

        if not self.is_scan_candidate(packet):
            return []

        # Ingest candidate into sliding buffer
        self._syn_buffer.append(packet)
        current_time = packet.timestamp

        # Prune packets outside the sliding window
        window_start = current_time - self.time_window_seconds
        self._syn_buffer = [p for p in self._syn_buffer if p.timestamp >= window_start]

        # Evaluate window
        return self._evaluate_window(self._syn_buffer, current_time)

    def detect_window(
        self,
        packets: List[NormalizedPacket],
        time_window_seconds: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> List[DetectionResult]:
        """Statelessly evaluate a batch of packets over a specified time window."""
        if not self.enabled or not packets:
            return []

        window_duration = (
            time_window_seconds if time_window_seconds is not None else self.time_window_seconds
        )
        candidates = [p for p in packets if self.is_scan_candidate(p)]
        if not candidates:
            return []

        ref_end = end_time if end_time is not None else max(p.timestamp for p in candidates)
        ref_start = ref_end - window_duration
        window_slice = [p for p in candidates if ref_start <= p.timestamp <= ref_end]

        return self._evaluate_window(window_slice, ref_end, window_duration=window_duration, bypass_cooldown=True)

    def _evaluate_window(
        self,
        syn_packets: List[NormalizedPacket],
        current_time: float,
        window_duration: Optional[float] = None,
        bypass_cooldown: bool = False,
    ) -> List[DetectionResult]:
        """Core detection logic evaluating candidate SYN packets across all sources."""
        results: List[DetectionResult] = []
        duration = window_duration if window_duration is not None else self.time_window_seconds
        window_start = current_time - duration

        # Group by source IP
        by_source: Dict[str, List[NormalizedPacket]] = defaultdict(list)
        for pkt in syn_packets:
            if pkt.src_ip:
                by_source[pkt.src_ip].append(pkt)

        for src_ip, pkts in by_source.items():
            total_syns = len(pkts)
            all_dst_ports: Set[int] = {p.dst_port for p in pkts if p.dst_port is not None}
            all_dst_ips: Set[str] = {p.dst_ip for p in pkts if p.dst_ip}

            # Map destination IP -> Set of destination ports
            dst_map: Dict[str, Set[int]] = defaultdict(set)
            dst_syn_counts: Dict[str, int] = defaultdict(int)
            for p in pkts:
                if p.dst_ip and p.dst_port is not None:
                    dst_map[p.dst_ip].add(p.dst_port)
                    dst_syn_counts[p.dst_ip] += 1

            # ------------------------------------------------------------------
            # 1. Vertical Port Scan Check (Single target host, multiple ports)
            # ------------------------------------------------------------------
            for target_ip, ports in dst_map.items():
                target_syns = dst_syn_counts[target_ip]
                if len(ports) >= self.unique_ports_threshold and target_syns >= min(self.min_syn_count, self.unique_ports_threshold):
                    cooldown_key = (src_ip, f"VERTICAL:{target_ip}")
                    if bypass_cooldown or self._can_alert(cooldown_key, current_time):
                        self._last_alerted[cooldown_key] = current_time
                        reason = (
                            f"Source IP {src_ip} attempted connections to {len(ports)} unique destination ports "
                            f"on target {target_ip} with {target_syns} SYN packets within a {duration:.1f}s window, "
                            f"exceeding threshold of {self.unique_ports_threshold} ports."
                        )
                        evidence = {
                            "source_ip": src_ip,
                            "destination_ip": target_ip,
                            "syn_count": target_syns,
                            "unique_destination_ports_count": len(ports),
                            "sample_targeted_ports": sorted(list(ports))[:30],
                            "window_seconds": duration,
                            "threshold_unique_ports": self.unique_ports_threshold,
                            "threshold_min_syns": self.min_syn_count,
                        }
                        results.append(
                            DetectionResult(
                                rule_name="port_scan",
                                alert_type=self.alert_type,
                                severity=self.default_severity,
                                scan_type="VERTICAL",
                                src_ip=src_ip,
                                dst_ip=target_ip,
                                protocol="TCP",
                                timestamp=current_time,
                                window_seconds=duration,
                                start_time=window_start,
                                end_time=current_time,
                                syn_count=target_syns,
                                unique_destination_ports=len(ports),
                                unique_destination_ips=1,
                                threshold_values={
                                    "unique_ports_threshold": self.unique_ports_threshold,
                                    "min_syn_count": self.min_syn_count,
                                    "time_window_seconds": duration,
                                },
                                detection_reason=reason,
                                evidence=evidence,
                            )
                        )

            # ------------------------------------------------------------------
            # 2. Horizontal Port Scan Check (Multiple target hosts, same/few ports)
            # ------------------------------------------------------------------
            if len(all_dst_ips) >= self.unique_destinations_threshold and total_syns >= min(self.min_syn_count, self.unique_destinations_threshold):
                cooldown_key = (src_ip, "HORIZONTAL")
                if bypass_cooldown or self._can_alert(cooldown_key, current_time):
                    self._last_alerted[cooldown_key] = current_time
                    reason = (
                        f"Source IP {src_ip} attempted connections to {len(all_dst_ips)} unique destination hosts "
                        f"across {len(all_dst_ports)} ports with {total_syns} SYN packets within a {duration:.1f}s window, "
                        f"exceeding threshold of {self.unique_destinations_threshold} hosts."
                    )
                    evidence = {
                        "source_ip": src_ip,
                        "unique_destination_ips_count": len(all_dst_ips),
                        "sample_targeted_ips": sorted(list(all_dst_ips))[:20],
                        "unique_destination_ports_count": len(all_dst_ports),
                        "sample_targeted_ports": sorted(list(all_dst_ports))[:20],
                        "syn_count": total_syns,
                        "window_seconds": duration,
                        "threshold_unique_destinations": self.unique_destinations_threshold,
                        "threshold_min_syns": self.min_syn_count,
                    }
                    results.append(
                        DetectionResult(
                            rule_name="port_scan",
                            alert_type=self.alert_type,
                            severity=self.default_severity,
                            scan_type="HORIZONTAL",
                            src_ip=src_ip,
                            dst_ip=None,
                            protocol="TCP",
                            timestamp=current_time,
                            window_seconds=duration,
                            start_time=window_start,
                            end_time=current_time,
                            syn_count=total_syns,
                            unique_destination_ports=len(all_dst_ports),
                            unique_destination_ips=len(all_dst_ips),
                            threshold_values={
                                "unique_destinations_threshold": self.unique_destinations_threshold,
                                "min_syn_count": self.min_syn_count,
                                "time_window_seconds": duration,
                            },
                            detection_reason=reason,
                            evidence=evidence,
                        )
                    )

            # ------------------------------------------------------------------
            # 3. General TCP SYN Scan Check (Distributed / Multiple targets & ports)
            # ------------------------------------------------------------------
            # Triggered if neither pure vertical nor horizontal triggered, but overall
            # volume crosses both unique ports and min SYN count
            if (
                not results
                and total_syns >= self.min_syn_count
                and len(all_dst_ports) >= self.unique_ports_threshold
            ):
                cooldown_key = (src_ip, "SYN_SCAN")
                if bypass_cooldown or self._can_alert(cooldown_key, current_time):
                    self._last_alerted[cooldown_key] = current_time
                    reason = (
                        f"Source IP {src_ip} generated {total_syns} TCP SYN attempts to {len(all_dst_ports)} "
                        f"unique ports across {len(all_dst_ips)} destination hosts within a {duration:.1f}s window."
                    )
                    evidence = {
                        "source_ip": src_ip,
                        "syn_count": total_syns,
                        "unique_destination_ports_count": len(all_dst_ports),
                        "unique_destination_ips_count": len(all_dst_ips),
                        "window_seconds": duration,
                    }
                    results.append(
                        DetectionResult(
                            rule_name="port_scan",
                            alert_type=self.alert_type,
                            severity=self.default_severity,
                            scan_type="SYN_SCAN",
                            src_ip=src_ip,
                            dst_ip=None,
                            protocol="TCP",
                            timestamp=current_time,
                            window_seconds=duration,
                            start_time=window_start,
                            end_time=current_time,
                            syn_count=total_syns,
                            unique_destination_ports=len(all_dst_ports),
                            unique_destination_ips=len(all_dst_ips),
                            threshold_values={
                                "unique_ports_threshold": self.unique_ports_threshold,
                                "min_syn_count": self.min_syn_count,
                                "time_window_seconds": duration,
                            },
                            detection_reason=reason,
                            evidence=evidence,
                        )
                    )

        return results

    def _can_alert(self, cooldown_key: Tuple[str, str], current_time: float) -> bool:
        """Check whether alert cooldown duration has elapsed for a specific (src_ip, scan_type)."""
        last_time = self._last_alerted.get(cooldown_key)
        if last_time is None:
            return True
        return (current_time - last_time) >= self.alert_cooldown_seconds

    def reset(self) -> None:
        """Reset internal candidate packet buffer and cooldown state."""
        self._syn_buffer.clear()
        self._last_alerted.clear()
        logger.debug("PortScanDetector state reset.")
