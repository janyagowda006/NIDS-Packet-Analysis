"""Unit tests for the Network Interface Discovery module."""

from backend.capture.interfaces import (
    NetworkInterface,
    find_interface_by_name,
    get_network_interfaces,
    is_pcap_driver_available,
)


def test_network_interface_dataclass_initialization():
    """Verify that NetworkInterface initializes correctly with full metadata."""
    iface = NetworkInterface(
        name="eth0",
        description="Intel Gigabit Ethernet",
        mac_address="00:11:22:33:44:55",
        ipv4_address="192.168.1.50",
        status="up",
        is_loopback=False,
        guid="{12345678-ABCD-EF01-2345-6789ABCDEF01}",
    )

    assert iface.name == "eth0"
    assert iface.description == "Intel Gigabit Ethernet"
    assert iface.mac_address == "00:11:22:33:44:55"
    assert iface.ipv4_address == "192.168.1.50"
    assert iface.status == "up"
    assert iface.is_loopback is False
    assert iface.guid == "{12345678-ABCD-EF01-2345-6789ABCDEF01}"

    d = iface.to_dict()
    assert d["name"] == "eth0"
    assert d["ipv4_address"] == "192.168.1.50"
    assert str(iface).startswith("[eth0]")


def test_network_interface_missing_metadata_handled_safely():
    """Verify that NetworkInterface safely handles missing or null metadata."""
    iface = NetworkInterface(name="minimal_iface")

    assert iface.name == "minimal_iface"
    assert iface.description is None
    assert iface.mac_address is None
    assert iface.ipv4_address is None
    assert iface.status == "unknown"
    assert iface.is_loopback is False
    assert iface.guid is None

    # Serialization and string representation must not throw
    d = iface.to_dict()
    assert d["name"] == "minimal_iface"
    assert d["mac_address"] is None
    assert "No IPv4" in str(iface)
    assert "No MAC" in str(iface)


def test_get_network_interfaces_returns_list_of_interfaces():
    """Verify that get_network_interfaces runs safely and returns a list."""
    ifaces = get_network_interfaces()
    assert isinstance(ifaces, list)
    # Even if some platforms return 0 or multiple, every element must be a NetworkInterface
    for iface in ifaces:
        assert isinstance(iface, NetworkInterface)
        assert isinstance(iface.name, str)
        assert len(iface.name) > 0


def test_find_interface_by_name():
    """Verify find_interface_by_name behavior."""
    # Searching for empty or blank name returns None
    assert find_interface_by_name("") is None
    assert find_interface_by_name("   ") is None
    assert find_interface_by_name("non_existent_adapter_xyz_999") is None

    # If any interfaces exist, searching for one by exact name succeeds
    all_ifaces = get_network_interfaces()
    if all_ifaces:
        target = all_ifaces[0]
        found = find_interface_by_name(target.name)
        assert found is not None
        assert found.name.lower() == target.name.lower()


def test_is_pcap_driver_available_returns_bool():
    """Verify is_pcap_driver_available returns a boolean without throwing."""
    res = is_pcap_driver_available()
    assert isinstance(res, bool)


def test_find_interface_by_description_or_guid():
    """Verify find_interface_by_name can match by description or GUID."""
    all_ifaces = get_network_interfaces()
    for iface in all_ifaces:
        if iface.description:
            found = find_interface_by_name(iface.description)
            assert found is not None
            break
        if iface.guid:
            found = find_interface_by_name(iface.guid)
            assert found is not None
            break

