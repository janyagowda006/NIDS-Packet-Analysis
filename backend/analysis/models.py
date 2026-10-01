"""Traffic analysis and connection tracking data models for NIDS.

Defines canonical bidirectional flow identifiers (`FlowKey`), stateful flow records
(`FlowRecord`), and aggregate traffic statistics (`TrafficStatistics`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.parser.models import NormalizedPacket


@dataclass(frozen=True)
class FlowKey:
    """Canonical bidirectional flow identifier.

    Guarantees that traffic from A->B and B->A maps to the identical FlowKey.
    """

    endpoint_a_ip: str
    endpoint_a_port: int
    endpoint_b_ip: str
    endpoint_b_port: int
    protocol: str

    @classmethod
    def from_packet(cls, packet: NormalizedPacket) -> FlowKey:
        """Create a canonical bidirectional FlowKey from a NormalizedPacket."""
        proto = packet.protocol.upper()

        # Transport protocols with ports (TCP, UDP, or higher layers like HTTP, DNS, DHCP)
        if proto in ("TCP", "HTTP") or packet.tcp_flags is not None:
            base_proto = "TCP"
            ip1 = packet.src_ip or packet.src_mac or "0.0.0.0"
            port1 = packet.src_port or 0
            ip2 = packet.dst_ip or packet.dst_mac or "0.0.0.0"
            port2 = packet.dst_port or 0
        elif proto in ("UDP", "DNS", "DHCP"):
            base_proto = "UDP"
            ip1 = packet.src_ip or packet.src_mac or "0.0.0.0"
            port1 = packet.src_port or 0
            ip2 = packet.dst_ip or packet.dst_mac or "0.0.0.0"
            port2 = packet.dst_port or 0
        elif proto == "ICMP":
            base_proto = "ICMP"
            ip1 = packet.src_ip or "0.0.0.0"
            port1 = 0
            ip2 = packet.dst_ip or "0.0.0.0"
            port2 = 0
        elif proto == "ARP":
            base_proto = "ARP"
            ip1 = packet.src_ip or packet.arp_sender_ip or packet.src_mac or "0.0.0.0"
            port1 = 0
            ip2 = packet.dst_ip or packet.arp_target_ip or packet.dst_mac or "0.0.0.0"
            port2 = 0
        else:
            base_proto = proto or "UNKNOWN"
            ip1 = packet.src_ip or packet.src_mac or "0.0.0.0"
            port1 = packet.src_port or 0
            ip2 = packet.dst_ip or packet.dst_mac or "0.0.0.0"
            port2 = packet.dst_port or 0

        # Deterministic bidirectional canonical ordering
        endpoint1 = (ip1, port1)
        endpoint2 = (ip2, port2)
        if endpoint1 <= endpoint2:
            ea_ip, ea_port = endpoint1
            eb_ip, eb_port = endpoint2
        else:
            ea_ip, ea_port = endpoint2
            eb_ip, eb_port = endpoint1

        return cls(
            endpoint_a_ip=ea_ip,
            endpoint_a_port=ea_port,
            endpoint_b_ip=eb_ip,
            endpoint_b_port=eb_port,
            protocol=base_proto,
        )

    def __str__(self) -> str:
        return (
            f"{self.protocol}:{self.endpoint_a_ip}:{self.endpoint_a_port}"
            f"<->{self.endpoint_b_ip}:{self.endpoint_b_port}"
        )


@dataclass
class FlowRecord:
    """Stateful record tracking an observed bidirectional connection or flow."""

    flow_key: FlowKey
    protocol: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0

    # Direction endpoints
    initiator_ip: Optional[str] = None
    responder_ip: Optional[str] = None
    initiator_port: Optional[int] = None
    responder_port: Optional[int] = None

    forward_packets: int = 0
    reverse_packets: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0

    # TCP flag observation
    syn_seen: bool = False
    syn_ack_seen: bool = False
    ack_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False

    # State tracking
    state: str = "NEW"  # TCP: NEW, SYN_SENT, ESTABLISHED, CLOSING, CLOSED, RESET; Others: ACTIVE, IDLE

    @property
    def duration(self) -> float:
        """Calculate duration of the flow in seconds."""
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def is_completed(self) -> bool:
        """Determine if flow has completed (e.g. TCP CLOSED or RESET)."""
        return self.state in ("CLOSED", "RESET")

    @property
    def is_active(self) -> bool:
        """Determine if flow is currently active."""
        return not self.is_completed

    def update(self, packet: NormalizedPacket) -> None:
        """Update flow metrics and connection state with a new packet."""
        pkt_time = packet.timestamp
        self.last_seen = max(self.last_seen, pkt_time)
        self.packet_count += 1
        self.byte_count += packet.packet_length

        # Identify direction
        is_forward = True
        if self.initiator_ip and packet.src_ip:
            if packet.src_ip == self.initiator_ip:
                is_forward = True
            elif packet.src_ip == self.responder_ip:
                is_forward = False

        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += packet.packet_length
        else:
            self.reverse_packets += 1
            self.reverse_bytes += packet.packet_length

        # TCP state machine updates
        if self.protocol == "TCP":
            has_syn = packet.has_flag("SYN")
            has_ack = packet.has_flag("ACK")
            has_fin = packet.has_flag("FIN")
            has_rst = packet.has_flag("RST")

            if has_rst:
                self.rst_seen = True
                self.state = "RESET"
            elif has_fin:
                self.fin_seen = True
                self.state = "CLOSING" if self.state == "ESTABLISHED" else "CLOSED"
            elif has_syn and has_ack:
                self.syn_ack_seen = True
                if self.state in ("NEW", "SYN_SENT"):
                    self.state = "SYN_RECEIVED"
            elif has_syn:
                self.syn_seen = True
                if self.state == "NEW":
                    self.state = "SYN_SENT"
            elif has_ack:
                self.ack_seen = True
                if self.state in ("SYN_RECEIVED", "SYN_SENT"):
                    self.state = "ESTABLISHED"
                elif self.state == "CLOSING":
                    self.state = "CLOSED"
        else:
            self.state = "ACTIVE"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize flow record to dictionary."""
        return {
            "flow_key": str(self.flow_key),
            "protocol": self.protocol,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "initiator_ip": self.initiator_ip,
            "responder_ip": self.responder_ip,
            "initiator_port": self.initiator_port,
            "responder_port": self.responder_port,
            "forward_packets": self.forward_packets,
            "reverse_packets": self.reverse_packets,
            "forward_bytes": self.forward_bytes,
            "reverse_bytes": self.reverse_bytes,
            "syn_seen": self.syn_seen,
            "syn_ack_seen": self.syn_ack_seen,
            "ack_seen": self.ack_seen,
            "fin_seen": self.fin_seen,
            "rst_seen": self.rst_seen,
            "state": self.state,
            "is_completed": self.is_completed,
            "is_active": self.is_active,
        }


@dataclass
class TrafficStatistics:
    """Aggregate statistics computed across analyzed traffic."""

    total_packets: int = 0
    total_bytes: int = 0

    # Protocol breakdown
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0
    dns_packets: int = 0
    http_packets: int = 0
    other_packets: int = 0

    protocol_counts: Dict[str, int] = field(default_factory=dict)

    # Unique endpoints
    unique_source_ips: Set[str] = field(default_factory=set)
    unique_destination_ips: Set[str] = field(default_factory=set)
    unique_source_ports: Set[int] = field(default_factory=set)
    unique_destination_ports: Set[int] = field(default_factory=set)

    start_time: Optional[float] = None
    end_time: Optional[float] = None

    @property
    def unique_source_ip_count(self) -> int:
        return len(self.unique_source_ips)

    @property
    def unique_destination_ip_count(self) -> int:
        return len(self.unique_destination_ips)

    @property
    def unique_source_port_count(self) -> int:
        return len(self.unique_source_ports)

    @property
    def unique_destination_port_count(self) -> int:
        return len(self.unique_destination_ports)

    def update(self, packet: NormalizedPacket) -> None:
        """Update aggregate counters with a NormalizedPacket."""
        self.total_packets += 1
        self.total_bytes += packet.packet_length

        pkt_time = packet.timestamp
        if self.start_time is None or pkt_time < self.start_time:
            self.start_time = pkt_time
        if self.end_time is None or pkt_time > self.end_time:
            self.end_time = pkt_time

        proto = packet.protocol.upper()
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        if proto == "TCP":
            self.tcp_packets += 1
        elif proto == "UDP":
            self.udp_packets += 1
        elif proto == "ICMP":
            self.icmp_packets += 1
        elif proto == "ARP":
            self.arp_packets += 1
        elif proto == "DNS":
            self.dns_packets += 1
        elif proto == "HTTP":
            self.http_packets += 1
            self.tcp_packets += 1  # HTTP runs over TCP
        else:
            self.other_packets += 1

        # Also account for higher layer indicators if protocol was marked as TCP/UDP
        if proto == "UDP" and packet.dns_query is not None:
            self.dns_packets += 1

        if packet.src_ip:
            self.unique_source_ips.add(packet.src_ip)
        if packet.dst_ip:
            self.unique_destination_ips.add(packet.dst_ip)
        if packet.src_port is not None:
            self.unique_source_ports.add(packet.src_port)
        if packet.dst_port is not None:
            self.unique_destination_ports.add(packet.dst_port)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize traffic statistics to dictionary."""
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "icmp_packets": self.icmp_packets,
            "arp_packets": self.arp_packets,
            "dns_packets": self.dns_packets,
            "http_packets": self.http_packets,
            "other_packets": self.other_packets,
            "protocol_counts": dict(self.protocol_counts),
            "unique_source_ip_count": self.unique_source_ip_count,
            "unique_destination_ip_count": self.unique_destination_ip_count,
            "unique_source_port_count": self.unique_source_port_count,
            "unique_destination_port_count": self.unique_destination_port_count,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }
