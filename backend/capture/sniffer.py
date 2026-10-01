"""Packet capture abstraction module for NIDS.

Provides a unified interface for capturing network packets from:
1. Live network interfaces (via Scapy)
2. Offline PCAP files (via Scapy)
3. Mock / synthetic packet streams (for deterministic unit and integration tests)

Follows the core principle: "Analyze first, detect second, explain every alert."
Handles missing capture drivers (e.g. Npcap on Windows) and errors gracefully.
"""

from __future__ import annotations

import logging
import os
import platform
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class CaptureError(Exception):
    """Base exception for all packet capture failures in the NIDS capture layer."""
    pass


class DriverMissingError(CaptureError):
    """Raised when live packet capture is attempted without the required driver.

    (e.g., Npcap/WinPcap not installed on a Windows host).
    """
    pass


class InterfaceNotFoundError(CaptureError):
    """Raised when a specified network interface cannot be identified or accessed."""
    pass


class PCAPReadError(CaptureError):
    """Raised when a PCAP file does not exist, is unreadable, or is malformed."""
    pass


class InvalidCaptureParameterError(CaptureError):
    """Raised when invalid capture parameters (negative counts, bad timeouts) are passed."""
    pass


# ==============================================================================
# Metadata Model
# ==============================================================================

@dataclass
class CaptureMetadata:
    """Metadata recorded for every capture session (live, pcap, or mock)."""

    source_type: str  # "live", "pcap", or "mock"
    packet_count: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    duration_seconds: float = 0.0
    interface_name: Optional[str] = None
    pcap_source: Optional[str] = None
    bpf_filter: Optional[str] = None

    def finalize(self, count: int) -> None:
        """Finalize the metadata with end timestamp and packet count."""
        self.end_time = time.time()
        self.duration_seconds = max(0.0, self.end_time - self.start_time)
        self.packet_count = count


# ==============================================================================
# Packet Capture Engine
# ==============================================================================

class PacketCaptureEngine:
    """Reusable engine for capturing or ingesting network packets.

    Supports live capture, PCAP replay, and synthetic mock packet streams.
    """

    def __init__(self) -> None:
        pass

    # --------------------------------------------------------------------------
    # 1. Live Packet Capture
    # --------------------------------------------------------------------------
    def capture_live(
        self,
        interface: Optional[str] = None,
        count: int = 0,
        timeout: Optional[float] = None,
        bpf_filter: Optional[str] = None,
        packet_callback: Optional[Callable[[Any], None]] = None,
    ) -> Tuple[List[Any], CaptureMetadata]:
        """Capture packets from a live network interface.

        Parameters
        ----------
        interface : str, optional
            Name or identifier of the interface to capture on. If None, default
            system interface is used.
        count : int, default 0
            Number of packets to capture. 0 means continuous capture until timeout.
        timeout : float, optional
            Maximum duration in seconds to wait for packets.
        bpf_filter : str, optional
            Berkeley Packet Filter string (e.g., 'tcp', 'ip', 'port 80').
        packet_callback : callable, optional
            Optional function called for each captured packet in real time.

        Returns
        -------
        Tuple[List[scapy.packet.Packet], CaptureMetadata]
            Captured packets list and associated session metadata.
        """
        # Validate parameters
        if count < 0:
            raise InvalidCaptureParameterError(
                f"Packet count cannot be negative: received {count}"
            )
        if timeout is not None and timeout <= 0:
            raise InvalidCaptureParameterError(
                f"Capture timeout must be greater than zero: received {timeout}"
            )

        metadata = CaptureMetadata(
            source_type="live",
            interface_name=interface or "default",
            bpf_filter=bpf_filter,
            start_time=time.time(),
        )

        logger.info(
            "Live packet capture started [interface=%s, count=%d, timeout=%s, bpf='%s']",
            interface or "default",
            count,
            str(timeout),
            bpf_filter or "none",
        )

        try:
            import scapy.all as scapy
        except ImportError as exc:
            raise CaptureError(f"Scapy is required for packet capture: {exc}") from exc

        # Windows driver check
        if platform.system() == "Windows":
            from backend.capture.interfaces import is_pcap_driver_available

            if not is_pcap_driver_available():
                msg = (
                    "Live packet capture on Windows requires the Npcap driver (installed with "
                    "'WinPcap API-compatible Mode'). Npcap was not detected on this system. "
                    "Please install Npcap from https://npcap.com or run tests in an authorized "
                    "Linux VM / using offline PCAP replay."
                )
                logger.error(msg)
                raise DriverMissingError(msg)

        captured_packets: List[Any] = []

        def _internal_handler(pkt: Any) -> None:
            captured_packets.append(pkt)
            if packet_callback:
                try:
                    packet_callback(pkt)
                except Exception as cb_err:
                    logger.warning("Packet callback error: %s", cb_err)

        sniff_kwargs: dict[str, Any] = {
            "prn": _internal_handler,
            "store": False,  # Store manually via handler to avoid duplicating memory
        }

        if interface:
            sniff_kwargs["iface"] = interface
        if count > 0:
            sniff_kwargs["count"] = count
        if timeout is not None:
            sniff_kwargs["timeout"] = timeout
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter

        try:
            scapy.sniff(**sniff_kwargs)
        except PermissionError as perm_err:
            msg = f"Insufficient permissions for live packet capture on interface '{interface}': {perm_err}"
            logger.error(msg)
            raise CaptureError(msg) from perm_err
        except RuntimeError as rt_err:
            err_msg = str(rt_err)
            if "winpcap is not installed" in err_msg.lower() or "libpcap" in err_msg.lower():
                msg = (
                    f"Packet capture driver missing: {err_msg}. "
                    "Ensure Npcap is installed on Windows or libpcap on Linux."
                )
                logger.error(msg)
                raise DriverMissingError(msg) from rt_err
            raise CaptureError(f"Live capture error: {err_msg}") from rt_err
        except Exception as exc:
            msg = f"Unexpected failure during live packet capture: {exc}"
            logger.error(msg)
            raise CaptureError(msg) from exc

        metadata.finalize(len(captured_packets))
        logger.info(
            "Live packet capture completed [packets=%d, duration=%.2fs]",
            metadata.packet_count,
            metadata.duration_seconds,
        )
        return captured_packets, metadata

    # --------------------------------------------------------------------------
    # 2. PCAP Replay / Offline Capture
    # --------------------------------------------------------------------------
    def read_pcap(
        self,
        filepath: str | Path,
        count: Optional[int] = None,
    ) -> Tuple[List[Any], CaptureMetadata]:
        """Read packets from a local PCAP or PCAPNG file.

        Parameters
        ----------
        filepath : str or Path
            Path to the local PCAP file.
        count : int, optional
            Maximum number of packets to read. If None or 0, reads all packets.

        Returns
        -------
        Tuple[List[scapy.packet.Packet], CaptureMetadata]
            List of packets read from the file and capture metadata.
        """
        if count is not None and count < 0:
            raise InvalidCaptureParameterError(
                f"Packet count cannot be negative: received {count}"
            )

        path = Path(filepath)
        if not path.is_file():
            raise PCAPReadError(f"PCAP file not found or is not a file: {filepath}")

        metadata = CaptureMetadata(
            source_type="pcap",
            pcap_source=str(path.resolve()),
            start_time=time.time(),
        )

        logger.info("Reading offline PCAP file [path=%s, max_count=%s]", path.name, str(count))

        try:
            import scapy.all as scapy
        except ImportError as exc:
            raise CaptureError(f"Scapy is required for PCAP processing: {exc}") from exc

        try:
            limit = count if (count and count > 0) else -1
            # scapy.rdpcap loads packets into a PacketList
            pkts = scapy.rdpcap(str(path), count=limit)
            packet_list = list(pkts)
        except Exception as exc:
            msg = f"Failed to read PCAP file '{path}': {exc}"
            logger.error(msg)
            raise PCAPReadError(msg) from exc

        metadata.finalize(len(packet_list))
        logger.info(
            "PCAP reading completed [path=%s, packets=%d, duration=%.2fs]",
            path.name,
            metadata.packet_count,
            metadata.duration_seconds,
        )
        return packet_list, metadata

    def stream_pcap(
        self,
        filepath: str | Path,
        count: Optional[int] = None,
    ) -> Iterator[Any]:
        """Stream packets generator-style from a local PCAP file.

        Avoids reading all packets into memory at once. Useful for large captures.
        """
        if count is not None and count < 0:
            raise InvalidCaptureParameterError(
                f"Packet count cannot be negative: received {count}"
            )

        path = Path(filepath)
        if not path.is_file():
            raise PCAPReadError(f"PCAP file not found: {filepath}")

        try:
            import scapy.all as scapy
        except ImportError as exc:
            raise CaptureError(f"Scapy is required for PCAP streaming: {exc}") from exc

        try:
            reader = scapy.PcapReader(str(path))
            yielded = 0
            for pkt in reader:
                if count and 0 < count <= yielded:
                    break
                yield pkt
                yielded += 1
            reader.close()
        except Exception as exc:
            raise PCAPReadError(f"Error while streaming PCAP '{path}': {exc}") from exc

    # --------------------------------------------------------------------------
    # 3. Mock / Synthetic Packet Stream (For Tests and Simulation)
    # --------------------------------------------------------------------------
    def capture_mock(
        self,
        packets: Sequence[Any],
        count: Optional[int] = None,
    ) -> Tuple[List[Any], CaptureMetadata]:
        """Ingest an in-memory list or sequence of mock packets for testing.

        Does not require any network hardware, drivers, or elevated privileges.
        """
        if count is not None and count < 0:
            raise InvalidCaptureParameterError(
                f"Packet count cannot be negative: received {count}"
            )

        metadata = CaptureMetadata(
            source_type="mock",
            start_time=time.time(),
        )

        logger.info("Ingesting synthetic mock packets [provided_count=%d]", len(packets))

        if count and 0 < count < len(packets):
            selected = list(packets[:count])
        else:
            selected = list(packets)

        metadata.finalize(len(selected))
        logger.info("Mock packet ingestion completed [packets=%d]", metadata.packet_count)
        return selected, metadata

    def stream_mock(
        self,
        packets: Sequence[Any],
        count: Optional[int] = None,
    ) -> Iterator[Any]:
        """Stream mock packets one by one as an iterator."""
        yielded = 0
        for pkt in packets:
            if count and 0 < count <= yielded:
                break
            yield pkt
            yielded += 1
