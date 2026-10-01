"""Unit tests for the Packet Capture abstraction module."""

import os
import platform
import tempfile
import pytest

from backend.capture.sniffer import (
    CaptureMetadata,
    DriverMissingError,
    InvalidCaptureParameterError,
    PacketCaptureEngine,
    PCAPReadError,
)


@pytest.fixture
def synthetic_packets():
    """Generate harmless synthetic Scapy packets for testing without network transmission."""
    import scapy.all as scapy

    pkts = [
        scapy.Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / scapy.IP(src="192.168.1.100", dst="192.168.1.200")
        / scapy.TCP(sport=12345, dport=80, flags="S"),
        scapy.Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")
        / scapy.IP(src="192.168.1.200", dst="192.168.1.100")
        / scapy.TCP(sport=80, dport=12345, flags="SA"),
        scapy.Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / scapy.IP(src="192.168.1.100", dst="192.168.1.200")
        / scapy.TCP(sport=12345, dport=80, flags="A"),
    ]
    return pkts


@pytest.fixture
def temp_pcap_file(synthetic_packets):
    """Create a temporary PCAP file containing harmless synthetic test packets."""
    import scapy.all as scapy

    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    scapy.wrpcap(path, synthetic_packets)

    yield path

    if os.path.exists(path):
        os.remove(path)


def test_mock_packet_capture_basic(synthetic_packets):
    """Verify mock capture ingests synthetic packets and generates proper metadata."""
    engine = PacketCaptureEngine()
    packets, meta = engine.capture_mock(synthetic_packets)

    assert len(packets) == 3
    assert isinstance(meta, CaptureMetadata)
    assert meta.source_type == "mock"
    assert meta.packet_count == 3
    assert meta.duration_seconds >= 0.0


def test_mock_packet_capture_empty():
    """Verify mock capture handles an empty packet list safely."""
    engine = PacketCaptureEngine()
    packets, meta = engine.capture_mock([])

    assert len(packets) == 0
    assert meta.packet_count == 0
    assert meta.source_type == "mock"


def test_mock_packet_capture_count_limit(synthetic_packets):
    """Verify mock capture respects packet count limit."""
    engine = PacketCaptureEngine()
    packets, meta = engine.capture_mock(synthetic_packets, count=2)

    assert len(packets) == 2
    assert meta.packet_count == 2


def test_mock_packet_streaming(synthetic_packets):
    """Verify mock stream yields packets as an iterator."""
    engine = PacketCaptureEngine()
    stream = engine.stream_mock(synthetic_packets, count=2)

    streamed = list(stream)
    assert len(streamed) == 2


def test_invalid_capture_parameters(synthetic_packets):
    """Verify invalid capture parameters raise InvalidCaptureParameterError."""
    engine = PacketCaptureEngine()

    with pytest.raises(InvalidCaptureParameterError):
        engine.capture_mock(synthetic_packets, count=-1)

    with pytest.raises(InvalidCaptureParameterError):
        engine.read_pcap("dummy.pcap", count=-5)

    with pytest.raises(InvalidCaptureParameterError):
        engine.capture_live(count=-10)

    with pytest.raises(InvalidCaptureParameterError):
        engine.capture_live(timeout=-1.0)


def test_pcap_read_and_stream(temp_pcap_file):
    """Verify reading and streaming from a valid PCAP file."""
    engine = PacketCaptureEngine()

    # Batch read
    packets, meta = engine.read_pcap(temp_pcap_file)
    assert len(packets) == 3
    assert meta.source_type == "pcap"
    assert meta.packet_count == 3
    assert meta.pcap_source == os.path.abspath(temp_pcap_file)

    # Batch read with count limit
    limited_packets, limited_meta = engine.read_pcap(temp_pcap_file, count=1)
    assert len(limited_packets) == 1
    assert limited_meta.packet_count == 1

    # Generator streaming
    streamed = list(engine.stream_pcap(temp_pcap_file))
    assert len(streamed) == 3


def test_pcap_read_invalid_path_raises_error():
    """Verify attempting to read a non-existent PCAP raises PCAPReadError."""
    engine = PacketCaptureEngine()

    with pytest.raises(PCAPReadError):
        engine.read_pcap("non_existent_file_xyz_12345.pcap")

    with pytest.raises(PCAPReadError):
        list(engine.stream_pcap("non_existent_file_xyz_12345.pcap"))


def test_live_capture_on_windows_without_driver_raises_gracefully():
    """Verify live capture fails gracefully with DriverMissingError when Npcap is absent."""
    if platform.system() != "Windows":
        pytest.skip("Test specifically validates Windows Npcap driver absence behavior")

    import scapy.all as scapy
    use_pcap = getattr(scapy.conf, "use_pcap", False)

    if not use_pcap:
        engine = PacketCaptureEngine()
        with pytest.raises(DriverMissingError) as exc_info:
            engine.capture_live(count=1, timeout=0.5)

        assert "Npcap" in str(exc_info.value)
    else:
        # If Npcap happens to be installed in the future, it should not throw DriverMissingError
        pass


def test_live_capture_mocked_success(synthetic_packets):
    """Verify live capture logic when driver is present (via mock)."""
    from unittest.mock import patch
    engine = PacketCaptureEngine()
    received_in_callback = []

    def callback(pkt):
        received_in_callback.append(pkt)

    def mock_sniff(**kwargs):
        prn = kwargs.get("prn")
        assert kwargs.get("iface") == "mock_eth0"
        assert kwargs.get("filter") == "tcp"
        for pkt in synthetic_packets:
            prn(pkt)

    with patch("backend.capture.interfaces.is_pcap_driver_available", return_value=True), \
         patch("scapy.all.sniff", side_effect=mock_sniff):
        packets, meta = engine.capture_live(
            interface="mock_eth0",
            count=3,
            timeout=5.0,
            bpf_filter="tcp",
            packet_callback=callback,
        )

    assert len(packets) == 3
    assert len(received_in_callback) == 3
    assert meta.source_type == "live"
    assert meta.interface_name == "mock_eth0"
    assert meta.bpf_filter == "tcp"
    assert meta.packet_count == 3
    assert meta.duration_seconds >= 0.0


def test_live_capture_permission_error_raises_capture_error():
    """Verify permission error during sniff is wrapped in CaptureError."""
    from unittest.mock import patch
    from backend.capture.sniffer import CaptureError
    engine = PacketCaptureEngine()

    with patch("backend.capture.interfaces.is_pcap_driver_available", return_value=True), \
         patch("scapy.all.sniff", side_effect=PermissionError("Access denied")):
        with pytest.raises(CaptureError) as exc_info:
            engine.capture_live(interface="mock_eth0")

        assert "Insufficient permissions" in str(exc_info.value)

