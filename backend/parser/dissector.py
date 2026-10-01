"""Protocol dissector and normalization engine for NIDS.

Dissects raw captured Scapy packets into strongly-typed `NormalizedPacket` events.
Adheres to the core principle: "Analyze first, detect second, explain every alert."

Safely handles malformed packets, missing protocol layers, and incomplete frames
without raising unhandled exceptions or interrupting packet processing loops.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.parser.models import NormalizedPacket

logger = logging.getLogger(__name__)

# Standard TCP flag character mapping
TCP_FLAG_MAP: Dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

# Recognized standard HTTP request verbs
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}


class PacketDissector:
    """Dissects raw packets and extracts normalized metadata for intrusion analysis."""

    @staticmethod
    def format_tcp_flags(flags_val: Any) -> Tuple[Optional[str], Optional[str]]:
        """Convert Scapy TCP flags into a deterministic, human-readable format.

        Returns (formatted_flags, raw_flags), e.g., ("SYN,ACK", "SA").
        """
        if flags_val is None:
            return None, None

        raw_str = str(flags_val).strip()
        if not raw_str:
            return None, None

        readable: List[str] = []
        for char in raw_str:
            readable.append(TCP_FLAG_MAP.get(char, char))

        formatted = ",".join(readable) if readable else raw_str
        return formatted, raw_str

    @staticmethod
    def extract_http_metadata(payload: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Safely extract basic HTTP metadata (method, host, path) from a payload.

        Does not store full payloads and avoids regex performance pitfalls.
        Returns (method, host, path).
        """
        if not payload:
            return None, None, None

        try:
            # Inspect only the initial header bytes (up to 1KB)
            sample = payload[:1024].decode("utf-8", errors="ignore")
            lines = sample.splitlines()
            if not lines:
                return None, None, None

            first_line = lines[0].strip()
            tokens = first_line.split()
            if len(tokens) >= 2 and tokens[0].upper() in HTTP_METHODS:
                method = tokens[0].upper()
                path = tokens[1]
                host = None

                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            host = parts[1].strip()
                        break

                return method, host, path

        except Exception as exc:
            logger.debug("Failed parsing HTTP metadata from payload: %s", exc)

        return None, None, None

    @classmethod
    def parse(cls, packet: Any) -> NormalizedPacket:
        """Parse a captured Scapy packet into a normalized, immutable `NormalizedPacket`.

        Never raises unhandled exceptions on malformed frames or partial layers.
        """
        try:
            import scapy.all as scapy
        except ImportError:
            # Fallback if Scapy is unexpectedly missing at runtime
            return NormalizedPacket(protocol="UNKNOWN", packet_length=len(packet) if hasattr(packet, "__len__") else 0)

        # Baseline metadata safely extracted
        packet_len = 0
        try:
            packet_len = len(packet)
        except Exception:
            packet_len = 0

        try:
            pkt_time = float(getattr(packet, "time", time.time()))
        except Exception:
            pkt_time = time.time()

        src_mac: Optional[str] = None
        dst_mac: Optional[str] = None
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        protocol: str = "UNKNOWN"
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: Optional[str] = None
        raw_tcp_flags: Optional[str] = None
        icmp_type: Optional[int] = None
        icmp_code: Optional[int] = None
        arp_op: Optional[int] = None
        arp_sender_mac: Optional[str] = None
        arp_sender_ip: Optional[str] = None
        arp_target_mac: Optional[str] = None
        arp_target_ip: Optional[str] = None
        dns_query: Optional[str] = None
        dns_query_type: Optional[str] = None
        dns_is_response: Optional[bool] = None
        dhcp_message_type: Optional[str] = None
        http_method: Optional[str] = None
        http_host: Optional[str] = None
        http_path: Optional[str] = None

        try:
            summary = packet.summary() if hasattr(packet, "summary") else str(packet)
        except Exception:
            summary = None

        # ----------------------------------------------------------------------
        # Layer 2: Ethernet / Data Link
        # ----------------------------------------------------------------------
        try:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.Ether):
                eth = packet[scapy.Ether]
                src_mac = str(eth.src).lower() if getattr(eth, "src", None) else None
                dst_mac = str(eth.dst).lower() if getattr(eth, "dst", None) else None
        except Exception as l2_err:
            logger.debug("Error extracting Ethernet layer: %s", l2_err)

        # ----------------------------------------------------------------------
        # Layer 2/3: ARP
        # ----------------------------------------------------------------------
        try:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.ARP):
                arp = packet[scapy.ARP]
                protocol = "ARP"
                arp_op = int(arp.op) if getattr(arp, "op", None) is not None else None
                arp_sender_mac = str(arp.hwsrc).lower() if getattr(arp, "hwsrc", None) else None
                arp_sender_ip = str(arp.psrc) if getattr(arp, "psrc", None) else None
                arp_target_mac = str(arp.hwdst).lower() if getattr(arp, "hwdst", None) else None
                arp_target_ip = str(arp.pdst) if getattr(arp, "pdst", None) else None

                # Correlate source/destination IP from ARP frame
                src_ip = arp_sender_ip
                dst_ip = arp_target_ip
        except Exception as arp_err:
            logger.debug("Error extracting ARP layer: %s", arp_err)

        # ----------------------------------------------------------------------
        # Layer 3: IPv4 / IPv6
        # ----------------------------------------------------------------------
        try:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.IP):
                ip = packet[scapy.IP]
                src_ip = str(ip.src) if getattr(ip, "src", None) else None
                dst_ip = str(ip.dst) if getattr(ip, "dst", None) else None
                if protocol == "UNKNOWN":
                    protocol = "IP"
            elif hasattr(packet, "haslayer") and packet.haslayer(scapy.IPv6):
                ip6 = packet[scapy.IPv6]
                src_ip = str(ip6.src) if getattr(ip6, "src", None) else None
                dst_ip = str(ip6.dst) if getattr(ip6, "dst", None) else None
                if protocol == "UNKNOWN":
                    protocol = "IPv6"
        except Exception as l3_err:
            logger.debug("Error extracting IP layer: %s", l3_err)

        # ----------------------------------------------------------------------
        # Layer 4: TCP
        # ----------------------------------------------------------------------
        try:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.TCP):
                tcp = packet[scapy.TCP]
                protocol = "TCP"
                src_port = int(tcp.sport) if getattr(tcp, "sport", None) is not None else None
                dst_port = int(tcp.dport) if getattr(tcp, "dport", None) is not None else None
                tcp_flags, raw_tcp_flags = cls.format_tcp_flags(getattr(tcp, "flags", None))
        except Exception as tcp_err:
            logger.debug("Error extracting TCP layer: %s", tcp_err)

        # ----------------------------------------------------------------------
        # Layer 4: UDP
        # ----------------------------------------------------------------------
        try:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.UDP):
                udp = packet[scapy.UDP]
                protocol = "UDP"
                src_port = int(udp.sport) if getattr(udp, "sport", None) is not None else None
                dst_port = int(udp.dport) if getattr(udp, "dport", None) is not None else None
        except Exception as udp_err:
            logger.debug("Error extracting UDP layer: %s", udp_err)

        # ----------------------------------------------------------------------
        # Layer 4: ICMP
        # ----------------------------------------------------------------------
        try:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.ICMP):
                icmp = packet[scapy.ICMP]
                protocol = "ICMP"
                icmp_type = int(icmp.type) if getattr(icmp, "type", None) is not None else None
                icmp_code = int(icmp.code) if getattr(icmp, "code", None) is not None else None
        except Exception as icmp_err:
            logger.debug("Error extracting ICMP layer: %s", icmp_err)

        # ----------------------------------------------------------------------
        # Application Layer: DNS
        # ----------------------------------------------------------------------
        try:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.DNS):
                dns = packet[scapy.DNS]
                protocol = "DNS"
                qr_val = getattr(dns, "qr", None)
                if qr_val is not None:
                    try:
                        dns_is_response = bool(int(qr_val) == 1)
                    except Exception:
                        dns_is_response = None
                qdcount = getattr(dns, "qdcount", None)
                qd = getattr(dns, "qd", None)
                if qdcount == 0:
                    qd = None
                if qd is not None:
                    qd_item = None
                    if hasattr(qd, "__iter__") and not isinstance(qd, (bytes, str)):
                        try:
                            for item in qd:
                                qd_item = item
                                break
                        except Exception:
                            qd_item = qd
                    else:
                        qd_item = qd

                    if qd_item is not None:
                        qname_raw = getattr(qd_item, "qname", None)
                        if qname_raw:
                            if isinstance(qname_raw, bytes):
                                dns_query = qname_raw.decode("utf-8", errors="replace").rstrip(".")
                            else:
                                dns_query = str(qname_raw).rstrip(".")

                        qtype_raw = getattr(qd_item, "qtype", None)
                        if qtype_raw is not None:
                            try:
                                dns_query_type = str(scapy.dnstypes.get(qtype_raw, qtype_raw))
                            except Exception:
                                dns_query_type = str(qtype_raw)
        except Exception as dns_err:
            logger.debug("Error extracting DNS layer: %s", dns_err)

        # ----------------------------------------------------------------------
        # Application Layer: DHCP
        # ----------------------------------------------------------------------
        try:
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.DHCP):
                dhcp = packet[scapy.DHCP]
                protocol = "DHCP"
                options = getattr(dhcp, "options", [])
                for opt in options:
                    if isinstance(opt, tuple) and len(opt) >= 2 and opt[0] == "message-type":
                        dhcp_message_type = str(opt[1])
                        break
        except Exception as dhcp_err:
            logger.debug("Error extracting DHCP layer: %s", dhcp_err)

        # ----------------------------------------------------------------------
        # Application Layer: HTTP (Metadata only)
        # ----------------------------------------------------------------------
        try:
            # Check for HTTP on typical web ports or if Raw payload is present
            if hasattr(packet, "haslayer") and packet.haslayer(scapy.Raw):
                raw_layer = packet[scapy.Raw]
                payload_bytes = bytes(getattr(raw_layer, "load", b""))
                if payload_bytes:
                    method, host, path = cls.extract_http_metadata(payload_bytes)
                    if method:
                        http_method = method
                        http_host = host
                        http_path = path
                        protocol = "HTTP"
        except Exception as http_err:
            logger.debug("Error extracting HTTP metadata: %s", http_err)

        return NormalizedPacket(
            timestamp=pkt_time,
            packet_length=packet_len,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            raw_tcp_flags=raw_tcp_flags,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            arp_op=arp_op,
            arp_sender_mac=arp_sender_mac,
            arp_sender_ip=arp_sender_ip,
            arp_target_mac=arp_target_mac,
            arp_target_ip=arp_target_ip,
            dns_query=dns_query,
            dns_query_type=dns_query_type,
            dns_is_response=dns_is_response,
            dhcp_message_type=dhcp_message_type,
            http_method=http_method,
            http_host=http_host,
            http_path=http_path,
            raw_summary=summary,
        )
