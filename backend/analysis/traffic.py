"""Traffic analyzer and stateful connection tracking engine for NIDS.

Maintains bidirectional connection states, sliding time-window history,
and cumulative traffic statistics across processed `NormalizedPacket` instances.
Adheres to the core principle: "Analyze first, detect second, explain every alert."
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, Sequence, Union

from backend.analysis.models import FlowKey, FlowRecord, TrafficStatistics
from backend.parser.models import NormalizedPacket

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """Stateful traffic analyzer for session tracking and flow metric extraction."""

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, FlowRecord] = {}
        self._statistics: TrafficStatistics = TrafficStatistics()
        self._packets: List[NormalizedPacket] = []

    def process_packet(self, packet: NormalizedPacket) -> FlowRecord:
        """Process a single NormalizedPacket and update flow and aggregate statistics.

        Parameters
        ----------
        packet : NormalizedPacket
            Dissected packet instance.

        Returns
        -------
        FlowRecord
            The updated stateful record for the connection/flow.
        """
        # Maintain history buffer and cumulative metrics
        self._packets.append(packet)
        self._statistics.update(packet)

        # Derive canonical bidirectional flow key
        flow_key = FlowKey.from_packet(packet)

        if flow_key not in self._flows:
            flow_record = FlowRecord(
                flow_key=flow_key,
                protocol=flow_key.protocol,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
                initiator_ip=packet.src_ip,
                responder_ip=packet.dst_ip,
                initiator_port=packet.src_port,
                responder_port=packet.dst_port,
            )
            self._flows[flow_key] = flow_record
        else:
            flow_record = self._flows[flow_key]

        flow_record.update(packet)
        return flow_record

    def process_packets(self, packets: Iterable[NormalizedPacket]) -> List[FlowRecord]:
        """Process an iterable collection of NormalizedPackets sequentially."""
        records: List[FlowRecord] = []
        for pkt in packets:
            records.append(self.process_packet(pkt))
        return records

    def get_flow(self, key: Union[FlowKey, str]) -> Optional[FlowRecord]:
        """Look up a flow record by its FlowKey object or string representation."""
        if isinstance(key, FlowKey):
            return self._flows.get(key)

        key_str = str(key).strip().lower()
        for flow_k, flow_rec in self._flows.items():
            if str(flow_k).lower() == key_str:
                return flow_rec
        return None

    def get_flows(self) -> List[FlowRecord]:
        """Return all tracked flow records."""
        return list(self._flows.values())

    def get_active_flows(
        self,
        now: Optional[float] = None,
        timeout_seconds: Optional[float] = None,
    ) -> List[FlowRecord]:
        """Return all flows currently considered active.

        Parameters
        ----------
        now : float, optional
            Reference timestamp (defaults to analyzer's maximum observed timestamp).
        timeout_seconds : float, optional
            If specified, flows idle longer than this duration are excluded.
        """
        ref_time = now if now is not None else self._statistics.end_time
        active: List[FlowRecord] = []

        for flow in self._flows.values():
            if not flow.is_active:
                continue

            if timeout_seconds is not None and ref_time is not None:
                if (ref_time - flow.last_seen) > timeout_seconds:
                    continue

            active.append(flow)

        return active

    def get_completed_flows(self) -> List[FlowRecord]:
        """Return all flows marked as completed (e.g. TCP CLOSED or RESET)."""
        return [f for f in self._flows.values() if f.is_completed]

    def get_statistics(self) -> TrafficStatistics:
        """Return current cumulative traffic statistics."""
        return self._statistics

    def get_packets_in_window(
        self,
        time_window_seconds: float,
        end_time: Optional[float] = None,
    ) -> List[NormalizedPacket]:
        """Return all packets observed within the specified sliding time window.

        Parameters
        ----------
        time_window_seconds : float
            Window duration in seconds.
        end_time : float, optional
            End boundary timestamp. Defaults to latest packet timestamp.
        """
        if not self._packets:
            return []

        ref_end = end_time if end_time is not None else max(p.timestamp for p in self._packets)
        ref_start = ref_end - time_window_seconds

        return [p for p in self._packets if ref_start <= p.timestamp <= ref_end]

    def get_packets_between(
        self,
        start_time: float,
        end_time: float,
    ) -> List[NormalizedPacket]:
        """Return all packets observed between start_time and end_time (inclusive)."""
        return [p for p in self._packets if start_time <= p.timestamp <= end_time]

    def get_flows_in_window(
        self,
        time_window_seconds: float,
        end_time: Optional[float] = None,
    ) -> List[FlowRecord]:
        """Return all flows that had activity within the specified time window."""
        if not self._flows:
            return []

        ref_end = end_time if end_time is not None else self._statistics.end_time
        if ref_end is None:
            return []

        ref_start = ref_end - time_window_seconds
        return [
            f for f in self._flows.values()
            if f.last_seen >= ref_start and f.first_seen <= ref_end
        ]

    def reset(self) -> None:
        """Completely reset all tracking state, statistics, and flow caches."""
        self._flows.clear()
        self._statistics = TrafficStatistics()
        self._packets.clear()
        logger.info("TrafficAnalyzer state successfully reset.")
