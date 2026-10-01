"""Packet capture package for NIDS.

Provides cross-platform network interface enumeration and a unified capture engine
supporting live interface sniffing, offline PCAP replay, and synthetic mock streams.
"""

from backend.capture.interfaces import (
    NetworkInterface,
    find_interface_by_name,
    get_network_interfaces,
    is_pcap_driver_available,
)
from backend.capture.sniffer import (
    CaptureError,
    CaptureMetadata,
    DriverMissingError,
    InterfaceNotFoundError,
    InvalidCaptureParameterError,
    PacketCaptureEngine,
    PCAPReadError,
)

__all__ = [
    "NetworkInterface",
    "get_network_interfaces",
    "find_interface_by_name",
    "is_pcap_driver_available",
    "PacketCaptureEngine",
    "CaptureMetadata",
    "CaptureError",
    "DriverMissingError",
    "InterfaceNotFoundError",
    "PCAPReadError",
    "InvalidCaptureParameterError",
]
