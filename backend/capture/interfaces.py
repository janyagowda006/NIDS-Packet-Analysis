"""Network interface discovery module for NIDS.

Provides cross-platform representation and enumeration of local network
interfaces (Windows and Linux VM) with safe handling of missing metadata.
"""

from __future__ import annotations

import logging
import platform
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class NetworkInterface:
    """Represents a discovered network interface and its basic properties."""

    name: str
    description: Optional[str] = None
    mac_address: Optional[str] = None
    ipv4_address: Optional[str] = None
    status: str = "unknown"
    is_loopback: bool = False
    guid: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str | bool]]:
        """Return a dictionary representation suitable for display/serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "mac_address": self.mac_address,
            "ipv4_address": self.ipv4_address,
            "status": self.status,
            "is_loopback": self.is_loopback,
            "guid": self.guid,
        }

    def __str__(self) -> str:
        ip_display = self.ipv4_address or "No IPv4"
        mac_display = self.mac_address or "No MAC"
        desc = f" ({self.description})" if self.description else ""
        return f"[{self.name}]{desc} - IP: {ip_display}, MAC: {mac_display}, Status: {self.status}"


def is_pcap_driver_available() -> bool:
    """Check whether a live packet-capture driver (e.g.

    Npcap on Windows, libpcap on Linux) is available for layer-2 raw packet sniffing.
    """
    try:
        import scapy.all as scapy

        # On Windows, scapy.conf.use_pcap indicates whether winpcap/npcap is loaded
        if platform.system() == "Windows":
            return bool(getattr(scapy.conf, "use_pcap", False))
        # On Linux/Unix, raw sockets (AF_PACKET) are generally supported
        return True
    except Exception as exc:
        logger.debug("Failed checking packet capture driver availability: %s", exc)
        return False


def get_network_interfaces() -> List[NetworkInterface]:
    """Discover and return all available network interfaces on the host.

    Handles missing metadata gracefully without raising exceptions.
    Compatible with both Windows host environments and Linux VM environments.
    """
    interfaces: List[NetworkInterface] = []

    try:
        import scapy.all as scapy

        conf_ifaces = getattr(scapy.conf, "ifaces", {})

        for key, iface in conf_ifaces.items():
            try:
                # Resolve primary name
                display_name = getattr(iface, "name", None) or str(key)
                description = getattr(iface, "description", None)

                # MAC address (clean or None)
                mac = getattr(iface, "mac", None)
                if mac and str(mac).strip():
                    mac_clean = str(mac).strip().lower()
                else:
                    mac_clean = None

                # IPv4 address (clean or None)
                ip = getattr(iface, "ip", None)
                if ip and str(ip).strip() and str(ip).strip() != "0.0.0.0":
                    ip_clean = str(ip).strip()
                else:
                    ip_clean = None

                # Loopback check
                is_loopback = False
                name_lower = display_name.lower()
                desc_lower = (description or "").lower()
                if (
                    "loopback" in name_lower
                    or "loopback" in desc_lower
                    or ip_clean == "127.0.0.1"
                ):
                    is_loopback = True

                # Determine basic status
                # If an interface has an active non-APIPA IP and MAC, consider it up
                status = "unknown"
                if is_loopback:
                    status = "up"
                elif ip_clean and not ip_clean.startswith("169.254."):
                    status = "up"
                elif mac_clean and not ip_clean:
                    status = "down"

                guid = str(key) if str(key).startswith("\\Device\\") else None

                net_if = NetworkInterface(
                    name=display_name,
                    description=description,
                    mac_address=mac_clean,
                    ipv4_address=ip_clean,
                    status=status,
                    is_loopback=is_loopback,
                    guid=guid,
                )
                interfaces.append(net_if)

            except Exception as item_err:
                logger.debug("Error parsing single interface entry [%s]: %s", key, item_err)
                continue

    except Exception as exc:
        logger.error("Failed discovering network interfaces: %s", exc)

    logger.info("Discovered %d network interfaces", len(interfaces))
    return interfaces


def find_interface_by_name(name: str) -> Optional[NetworkInterface]:
    """Find a network interface by matching name, description, or GUID (case-insensitive)."""
    if not name or not name.strip():
        return None

    target = name.strip().lower()
    for iface in get_network_interfaces():
        if iface.name.lower() == target:
            return iface
        if iface.description and iface.description.lower() == target:
            return iface
        if iface.guid and iface.guid.lower() == target:
            return iface

    return None
