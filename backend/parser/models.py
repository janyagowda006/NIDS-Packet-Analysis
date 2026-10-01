"""Normalized packet data models for the NIDS parsing layer.

Defines strongly-typed, immutable dataclasses representing dissected network packets.
All fields that do not apply to a specific packet type default to None rather than
falsified or placeholder values.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class NormalizedPacket:
    """Represents a normalized, protocol-agnostic view of a captured network packet.

    Follows the core principle: "Analyze first, detect second, explain every alert."
    """

    # Packet metadata
    timestamp: float = field(default_factory=time.time)
    packet_length: int = 0

    # Layer 2 (Data Link)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    # Layer 3 (Network)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: str = "UNKNOWN"  # e.g., "TCP", "UDP", "ICMP", "ARP", "DNS", "UNKNOWN"

    # Layer 4 (Transport)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None  # Formatted human-readable flags: e.g., "SYN", "SYN,ACK"
    raw_tcp_flags: Optional[str] = None  # Scapy compact flag letters: e.g., "S", "SA"

    # ICMP Metadata
    icmp_type: Optional[int] = None  # e.g., 8 (Echo Request), 0 (Echo Reply)
    icmp_code: Optional[int] = None

    # ARP Metadata
    arp_op: Optional[int] = None  # 1 (Request), 2 (Reply)
    arp_sender_mac: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None

    # DNS Metadata
    dns_query: Optional[str] = None  # FQDN query name, e.g. "example.com"
    dns_query_type: Optional[str] = None  # e.g., "A", "AAAA", "PTR", "TXT"
    dns_is_response: Optional[bool] = None  # True if DNS response/reply, False if query

    # DHCP Metadata
    dhcp_message_type: Optional[str] = None  # e.g., "discover", "offer", "request", "ack"

    # HTTP Metadata
    http_method: Optional[str] = None  # e.g., "GET", "POST"
    http_host: Optional[str] = None  # e.g., "api.internal.lab"
    http_path: Optional[str] = None  # e.g., "/login"

    # Summary
    raw_summary: Optional[str] = None

    def has_flag(self, flag_name: str) -> bool:
        """Check whether a specific TCP flag is present in tcp_flags."""
        if not self.tcp_flags:
            return False
        flags = [f.strip().upper() for f in self.tcp_flags.split(",")]
        return flag_name.strip().upper() in flags

    def to_dict(self) -> Dict[str, Any]:
        """Convert the normalized packet into a dictionary representation."""
        return {
            "timestamp": self.timestamp,
            "packet_length": self.packet_length,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "raw_tcp_flags": self.raw_tcp_flags,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "arp_op": self.arp_op,
            "arp_sender_mac": self.arp_sender_mac,
            "arp_sender_ip": self.arp_sender_ip,
            "arp_target_mac": self.arp_target_mac,
            "arp_target_ip": self.arp_target_ip,
            "dns_query": self.dns_query,
            "dns_query_type": self.dns_query_type,
            "dns_is_response": self.dns_is_response,
            "dhcp_message_type": self.dhcp_message_type,
            "http_method": self.http_method,
            "http_host": self.http_host,
            "http_path": self.http_path,
            "raw_summary": self.raw_summary,
        }

    def __str__(self) -> str:
        """Return a readable single-line summary of the packet."""
        src = f"{self.src_ip}:{self.src_port}" if self.src_port else (self.src_ip or self.src_mac or "unknown")
        dst = f"{self.dst_ip}:{self.dst_port}" if self.dst_port else (self.dst_ip or self.dst_mac or "unknown")
        extra = ""
        if self.protocol == "TCP" and self.tcp_flags:
            extra = f" [{self.tcp_flags}]"
        elif self.protocol == "DNS" and self.dns_query:
            extra = f" (query: {self.dns_query})"
        elif self.protocol == "ICMP" and self.icmp_type is not None:
            extra = f" (type: {self.icmp_type})"
        elif self.protocol == "ARP" and self.arp_op:
            op_name = "Request" if self.arp_op == 1 else ("Reply" if self.arp_op == 2 else str(self.arp_op))
            extra = f" (ARP {op_name})"
        return f"<{self.protocol} {src} -> {dst}{extra} len={self.packet_length}>"
