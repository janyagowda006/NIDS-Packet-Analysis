"""DNS Anomaly Detection Engine for NIDS.

Detects suspicious DNS query behavior:
1. Rule A: Excessive DNS Query Rate (DNS query storms / tunneling activity)
2. Rule B: Unusually Long DNS Query (Potential data exfiltration or tunneling)
3. Rule C: Unusually Long DNS Label (Obfuscated or encoded subdomains)

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


class DNSAnomalyDetector:
    """Stateful rule-based detector for DNS query anomalies and exfiltration patterns."""

    def __init__(
        self,
        rate_window_seconds: Optional[float] = None,
        max_queries_per_window: Optional[int] = None,
        max_query_length: Optional[int] = None,
        max_label_length: Optional[int] = None,
        alert_cooldown_seconds: Optional[float] = None,
        default_severity: Optional[str] = None,
        config_path: Optional[str | Path] = None,
        # Backward-compatible aliases:
        time_window_seconds: Optional[float] = None,
        query_rate_threshold: Optional[int] = None,
    ) -> None:
        """Initialize DNSAnomalyDetector with configurable baseline thresholds.

        If thresholds are not explicitly supplied, they are loaded from thresholds.yaml.
        """
        raw_config = load_thresholds(config_path)
        rule_cfg = raw_config.get("detection_rules", {}).get("dns_anomaly", {})
        sys_cfg = raw_config.get("system", {})

        self.enabled: bool = bool(rule_cfg.get("enabled", True))
        self.alert_type: str = str(rule_cfg.get("alert_type", "Possible DNS Anomaly"))
        self.default_severity: str = str(
            default_severity
            or rule_cfg.get("default_severity")
            or rule_cfg.get("severity")
            or "LOW"
        )

        # Sliding window for query rate evaluation
        resolved_window = (
            rate_window_seconds
            if rate_window_seconds is not None
            else (
                time_window_seconds
                if time_window_seconds is not None
                else (
                    rule_cfg.get("rate_window_seconds")
                    if "rate_window_seconds" in rule_cfg
                    else rule_cfg.get("time_window_seconds", 5.0)
                )
            )
        )
        self.rate_window_seconds: float = float(resolved_window)

        # Query rate threshold (trigger when queries strictly exceed this value)
        resolved_max_queries = (
            max_queries_per_window
            if max_queries_per_window is not None
            else (
                query_rate_threshold
                if query_rate_threshold is not None
                else (
                    rule_cfg.get("max_queries_per_window")
                    if "max_queries_per_window" in rule_cfg
                    else rule_cfg.get("query_rate_threshold", 25)
                )
            )
        )
        self.max_queries_per_window: int = int(resolved_max_queries)

        # Query length threshold (trigger when length strictly exceeds this value)
        self.max_query_length: int = int(
            max_query_length
            if max_query_length is not None
            else rule_cfg.get("max_query_length", 100)
        )

        # Label length threshold (trigger when any label strictly exceeds this value)
        self.max_label_length: int = int(
            max_label_length
            if max_label_length is not None
            else rule_cfg.get("max_label_length", 50)
        )

        # Cooldown duration in seconds
        self.alert_cooldown_seconds: float = float(
            alert_cooldown_seconds
            if alert_cooldown_seconds is not None
            else (
                rule_cfg.get("alert_cooldown_seconds")
                or sys_cfg.get("alert_cooldown_seconds", 10.0)
            )
        )

        # Internal sliding-window query buffer and cooldown state
        self._dns_buffer: List[NormalizedPacket] = []
        self._max_timestamp: float = 0.0
        self._last_alerted: Dict[Tuple[str, str], float] = {}

    @property
    def time_window_seconds(self) -> float:
        """Alias for rate_window_seconds."""
        return self.rate_window_seconds

    @time_window_seconds.setter
    def time_window_seconds(self, value: float) -> None:
        self.rate_window_seconds = value

    @property
    def query_rate_threshold(self) -> int:
        """Alias for max_queries_per_window."""
        return self.max_queries_per_window

    @query_rate_threshold.setter
    def query_rate_threshold(self, value: int) -> None:
        self.max_queries_per_window = value

    @staticmethod
    def extract_labels(query: Optional[str]) -> List[str]:
        """Extract individual labels from a DNS query domain name without dots.

        Leading and trailing dots are stripped, and consecutive dots are handled safely.
        Does NOT treat dots or the complete domain name incorrectly as a label.
        """
        if not query or not isinstance(query, str):
            return []
        cleaned = query.strip().strip(".")
        if not cleaned:
            return []
        return [lbl for lbl in cleaned.split(".") if lbl]

    def is_dns_query_candidate(self, packet: Any) -> bool:
        """Determine whether a packet represents an actual client DNS query.

        Candidate criteria:
        - Must be a NormalizedPacket instance
        - Must have a non-empty source IP
        - Must not be flagged as a DNS response (dns_is_response is False or None)
        - Must not be an incoming server response (src_port 53 with non-53 dst_port)
        - Protocol must not be ICMP or ARP
        - Must have a valid non-empty DNS query string
        """
        if not isinstance(packet, NormalizedPacket):
            return False

        if not packet.src_ip or not isinstance(packet.src_ip, str) or not packet.src_ip.strip():
            return False

        if packet.dns_is_response is True:
            return False

        proto = (packet.protocol or "").upper()
        if proto in ("ICMP", "ARP"):
            return False

        # If incoming from standard DNS port 53 to client ephemeral port, it's a response
        if packet.src_port == 53 and packet.dst_port != 53:
            return False

        if not packet.dns_query or not isinstance(packet.dns_query, str):
            return False

        if not packet.dns_query.strip():
            return False

        return True

    def process_packet(self, packet: NormalizedPacket) -> List[DetectionResult]:
        """Process a single packet incrementally and evaluate active DNS anomaly rules.

        Evaluates:
        - Rule B: Unusually Long DNS Query (> max_query_length)
        - Rule C: Unusually Long DNS Label (> max_label_length)
        - Rule A: Excessive DNS Query Rate (> max_queries_per_window in rate_window_seconds)

        Returns DetectionResult instances if thresholds are exceeded.
        """
        if not self.enabled:
            return []

        if not self.is_dns_query_candidate(packet):
            return []

        results: List[DetectionResult] = []
        src_ip = packet.src_ip
        assert src_ip is not None  # Guaranteed by is_dns_query_candidate
        query = packet.dns_query or ""

        # ----------------------------------------------------------------------
        # Rule B: Unusually Long DNS Query
        # ----------------------------------------------------------------------
        query_len = len(query)
        if query_len > self.max_query_length:
            cooldown_key = (src_ip, "DNS_LONG_QUERY_ANOMALY")
            if self._can_alert(cooldown_key, packet.timestamp):
                self._last_alerted[cooldown_key] = packet.timestamp
                results.append(self._create_long_query_result(packet))

        # ----------------------------------------------------------------------
        # Rule C: Unusually Long DNS Label
        # ----------------------------------------------------------------------
        labels = self.extract_labels(query)
        long_labels = [lbl for lbl in labels if len(lbl) > self.max_label_length]
        if long_labels:
            cooldown_key = (src_ip, "DNS_LONG_LABEL_ANOMALY")
            if self._can_alert(cooldown_key, packet.timestamp):
                self._last_alerted[cooldown_key] = packet.timestamp
                results.append(self._create_long_label_result(packet, long_labels))

        # ----------------------------------------------------------------------
        # Rule A: Excessive DNS Query Rate (Sliding Window)
        # ----------------------------------------------------------------------
        self._dns_buffer.append(packet)
        self._max_timestamp = max(self._max_timestamp, packet.timestamp)

        # Sliding window pruning
        window_start = self._max_timestamp - self.rate_window_seconds
        self._dns_buffer = [p for p in self._dns_buffer if p.timestamp >= window_start]

        rate_results = self._evaluate_rate_window(
            dns_packets=self._dns_buffer,
            current_time=self._max_timestamp,
            duration=self.rate_window_seconds,
            bypass_cooldown=False,
        )
        results.extend(rate_results)

        return results

    def detect_window(
        self,
        packets: List[NormalizedPacket],
        rate_window_seconds: Optional[float] = None,
        end_time: Optional[float] = None,
        bypass_cooldown: bool = True,
        time_window_seconds: Optional[float] = None,
    ) -> List[DetectionResult]:
        """Statelessly evaluate a batch of packets over a specified time window.

        Evaluates Rule A (Query Rate), Rule B (Long Query), and Rule C (Long Label).
        """
        if not self.enabled or not packets:
            return []

        duration = (
            rate_window_seconds
            if rate_window_seconds is not None
            else (
                time_window_seconds
                if time_window_seconds is not None
                else self.rate_window_seconds
            )
        )

        candidates = [p for p in packets if self.is_dns_query_candidate(p)]
        if not candidates:
            return []

        ref_end = end_time if end_time is not None else max(p.timestamp for p in candidates)
        ref_start = ref_end - duration
        window_slice = [p for p in candidates if ref_start <= p.timestamp <= ref_end]

        results: List[DetectionResult] = []

        # Evaluate Rule B and Rule C for candidates in window_slice
        for p in window_slice:
            src_ip = p.src_ip
            if not src_ip:
                continue
            query = p.dns_query or ""

            # Rule B
            if len(query) > self.max_query_length:
                cooldown_key = (src_ip, "DNS_LONG_QUERY_ANOMALY")
                if bypass_cooldown or self._can_alert(cooldown_key, p.timestamp):
                    if not bypass_cooldown:
                        self._last_alerted[cooldown_key] = p.timestamp
                    results.append(self._create_long_query_result(p))

            # Rule C
            labels = self.extract_labels(query)
            long_labels = [lbl for lbl in labels if len(lbl) > self.max_label_length]
            if long_labels:
                cooldown_key = (src_ip, "DNS_LONG_LABEL_ANOMALY")
                if bypass_cooldown or self._can_alert(cooldown_key, p.timestamp):
                    if not bypass_cooldown:
                        self._last_alerted[cooldown_key] = p.timestamp
                    results.append(self._create_long_label_result(p, long_labels))

        # Evaluate Rule A for window_slice
        rate_results = self._evaluate_rate_window(
            dns_packets=window_slice,
            current_time=ref_end,
            duration=duration,
            bypass_cooldown=bypass_cooldown,
        )
        results.extend(rate_results)

        return results

    def _evaluate_rate_window(
        self,
        dns_packets: List[NormalizedPacket],
        current_time: float,
        duration: float,
        bypass_cooldown: bool = False,
    ) -> List[DetectionResult]:
        """Evaluate candidate DNS queries across all source IPs for query-rate anomalies."""
        results: List[DetectionResult] = []
        window_start = current_time - duration

        by_source: Dict[str, List[NormalizedPacket]] = defaultdict(list)
        for pkt in dns_packets:
            if pkt.src_ip:
                by_source[pkt.src_ip].append(pkt)

        for src_ip, pkts in by_source.items():
            total_queries = len(pkts)
            # Rule A triggers strictly when total queries EXCEEDS the threshold
            if total_queries > self.max_queries_per_window:
                cooldown_key = (src_ip, "DNS_QUERY_RATE_ANOMALY")
                if bypass_cooldown or self._can_alert(cooldown_key, current_time):
                    self._last_alerted[cooldown_key] = current_time
                    reason = (
                        f"Excessive DNS query rate detected: source {src_ip} sent {total_queries} "
                        f"DNS queries within a {duration:.1f}s window, exceeding configured "
                        f"threshold of {self.max_queries_per_window}."
                    )
                    evidence: Dict[str, Any] = {
                        "source_ip": src_ip,
                        "observed_query_count": total_queries,
                        "window_seconds": duration,
                        "threshold_max_queries": self.max_queries_per_window,
                        "configured_max_queries_per_window": self.max_queries_per_window,
                        "sample_queries": [p.dns_query for p in pkts if p.dns_query][:20],
                    }
                    results.append(
                        DetectionResult(
                            rule_name="dns_anomaly",
                            alert_type=self.alert_type,
                            severity=self.default_severity,
                            scan_type="DNS_QUERY_RATE_ANOMALY",
                            detection_type="DNS_QUERY_RATE_ANOMALY",
                            src_ip=src_ip,
                            dst_ip=None,
                            protocol="DNS",
                            timestamp=current_time,
                            window_seconds=duration,
                            start_time=window_start,
                            end_time=current_time,
                            dns_query_count=total_queries,
                            threshold_values={
                                "max_queries_per_window": self.max_queries_per_window,
                                "rate_window_seconds": duration,
                                "time_window_seconds": duration,
                            },
                            detection_reason=reason,
                            evidence=evidence,
                        )
                    )

        return results

    def _create_long_query_result(self, packet: NormalizedPacket) -> DetectionResult:
        """Construct an explainable DetectionResult for an unusually long DNS query name."""
        src_ip = packet.src_ip or "unknown"
        query = packet.dns_query or ""
        query_len = len(query)
        target = f" to {packet.dst_ip}" if packet.dst_ip else ""

        reason = (
            f"Unusually long DNS query detected: source {src_ip} queried '{query}' "
            f"({query_len} chars){target}, exceeding configured threshold of {self.max_query_length} chars."
        )
        evidence: Dict[str, Any] = {
            "source_ip": src_ip,
            "destination_ip": packet.dst_ip,
            "query_name": query,
            "observed_query_length": query_len,
            "configured_max_query_length": self.max_query_length,
            "threshold_max_query_length": self.max_query_length,
        }
        return DetectionResult(
            rule_name="dns_anomaly",
            alert_type=self.alert_type,
            severity=self.default_severity,
            scan_type="DNS_LONG_QUERY_ANOMALY",
            detection_type="DNS_LONG_QUERY_ANOMALY",
            src_ip=src_ip,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol="DNS",
            timestamp=packet.timestamp,
            window_seconds=0.0,
            start_time=packet.timestamp,
            end_time=packet.timestamp,
            query_name=query,
            query_length=query_len,
            threshold_values={
                "max_query_length": self.max_query_length,
            },
            detection_reason=reason,
            evidence=evidence,
        )

    def _create_long_label_result(
        self, packet: NormalizedPacket, long_labels: List[str]
    ) -> DetectionResult:
        """Construct an explainable DetectionResult for an unusually long DNS label."""
        src_ip = packet.src_ip or "unknown"
        query = packet.dns_query or ""
        longest_label = max(long_labels, key=len)
        label_len = len(longest_label)
        target = f" to {packet.dst_ip}" if packet.dst_ip else ""

        reason = (
            f"Unusually long DNS label detected: source {src_ip} queried '{query}' "
            f"containing label '{longest_label}' ({label_len} chars){target}, "
            f"exceeding configured threshold of {self.max_label_length} chars."
        )
        evidence: Dict[str, Any] = {
            "source_ip": src_ip,
            "destination_ip": packet.dst_ip,
            "query_name": query,
            "longest_label": longest_label,
            "observed_label_length": label_len,
            "long_labels": list(long_labels),
            "configured_max_label_length": self.max_label_length,
            "threshold_max_label_length": self.max_label_length,
        }
        return DetectionResult(
            rule_name="dns_anomaly",
            alert_type=self.alert_type,
            severity=self.default_severity,
            scan_type="DNS_LONG_LABEL_ANOMALY",
            detection_type="DNS_LONG_LABEL_ANOMALY",
            src_ip=src_ip,
            dst_ip=packet.dst_ip,
            dst_port=packet.dst_port,
            protocol="DNS",
            timestamp=packet.timestamp,
            window_seconds=0.0,
            start_time=packet.timestamp,
            end_time=packet.timestamp,
            query_name=query,
            query_length=len(query),
            threshold_values={
                "max_label_length": self.max_label_length,
            },
            detection_reason=reason,
            evidence=evidence,
        )

    def _can_alert(self, cooldown_key: Tuple[str, str], current_time: float) -> bool:
        """Check whether alert cooldown duration has elapsed for a specific (src_ip, detection_type)."""
        last_time = self._last_alerted.get(cooldown_key)
        if last_time is None:
            return True
        return (current_time - last_time) >= self.alert_cooldown_seconds

    def reset(self) -> None:
        """Reset internal candidate packet buffer and cooldown cache."""
        self._dns_buffer.clear()
        self._last_alerted.clear()
        self._max_timestamp = 0.0
        logger.debug("DNSAnomalyDetector state reset.")
