"""Tests for StageLinq device discovery."""

from __future__ import annotations

import asyncio

import pytest

from stagelinq.discovery import (
    Device,
    DeviceState,
    DiscoveryConfig,
    StageLinqDiscovery,
    StageLinqError,
    discover_stagelinq_devices,
)
from stagelinq.messages import (
    DISCOVERER_EXIT,
    DISCOVERER_HOWDY,
    DiscoveryMessage,
    Token,
)


def test_device_creation():
    """Test device creation and validation."""
    token = Token(b"test" + b"\x00" * 12)  # 16 bytes total

    device = Device(
        ip="192.168.1.100",
        name="Test Device",
        software_name="TestSoft",
        software_version="1.0.0",
        port=51337,
        token=token,
    )

    assert device.ip == "192.168.1.100"
    assert device.name == "Test Device"
    assert device.software_name == "TestSoft"
    assert device.software_version == "1.0.0"
    assert device.port == 51337
    assert device.token == token
    assert device.state == DeviceState.PRESENT


def test_device_validation():
    """Test device validation in __post_init__."""
    token = Token(b"test" + b"\x00" * 12)  # 16 bytes total

    # Test empty IP
    with pytest.raises(ValueError, match="Device IP cannot be empty"):
        Device(
            ip="",
            name="Test",
            software_name="Test",
            software_version="1.0",
            port=51337,
            token=token,
        )

    # Test empty name
    with pytest.raises(ValueError, match="Device name cannot be empty"):
        Device(
            ip="192.168.1.100",
            name="",
            software_name="Test",
            software_version="1.0",
            port=51337,
            token=token,
        )

    # Test invalid port
    with pytest.raises(ValueError, match="Device port must be positive"):
        Device(
            ip="192.168.1.100",
            name="Test",
            software_name="Test",
            software_version="1.0",
            port=0,
            token=token,
        )


def test_device_endpoint_property():
    """Test device endpoint property."""
    token = Token(b"test" + b"\x00" * 12)  # 16 bytes total
    device = Device(
        ip="192.168.1.100",
        name="Test Device",
        software_name="TestSoft",
        software_version="1.0.0",
        port=51337,
        token=token,
    )

    assert device.endpoint == ("192.168.1.100", 51337)


def test_device_string_representation():
    """Test device string representation."""
    token = Token(b"test" + b"\x00" * 12)  # 16 bytes total
    device = Device(
        ip="192.168.1.100",
        name="Test Device",
        software_name="TestSoft",
        software_version="1.0.0",
        port=51337,
        token=token,
    )

    expected = "Test Device (TestSoft 1.0.0) at 192.168.1.100:51337"
    assert str(device) == expected


def test_device_equality():
    """Test device equality comparison."""
    token1 = Token(b"test1" + b"\x00" * 11)
    token2 = Token(b"test2" + b"\x00" * 11)

    device1 = Device(
        ip="192.168.1.100",
        name="Test Device",
        software_name="TestSoft",
        software_version="1.0.0",
        port=51337,
        token=token1,
    )

    device2 = Device(
        ip="192.168.1.100",
        name="Test Device",
        software_name="TestSoft",
        software_version="1.0.0",
        port=51337,
        token=token1,
    )

    device3 = Device(
        ip="192.168.1.101",
        name="Test Device",
        software_name="TestSoft",
        software_version="1.0.0",
        port=51337,
        token=token2,
    )

    assert device1 == device2
    assert device1 != device3
    assert device1 != "not a device"


def test_device_from_discovery_message():
    """Test creating device from discovery message."""
    token = Token(b"msg_token" + b"\x00" * 7)
    msg = DiscoveryMessage(
        token=token,
        source="Prime 4",
        action=DISCOVERER_HOWDY,
        software_name="Engine OS",
        software_version="2.4.1",
        port=51337,
    )

    addr = ("192.168.1.200", 51337)
    device = Device.from_discovery_message(addr, msg)

    assert device.ip == "192.168.1.200"
    assert device.name == "Prime 4"
    assert device.software_name == "Engine OS"
    assert device.software_version == "2.4.1"
    assert device.port == 51337
    assert device.token == token
    assert device.state == DeviceState.PRESENT


def test_device_from_discovery_message_leaving():
    """Test creating device from leaving discovery message."""
    token = Token(b"leaving_token" + b"\x00" * 3)
    msg = DiscoveryMessage(
        token=token,
        source="Prime 4",
        action=DISCOVERER_EXIT,
        software_name="Engine OS",
        software_version="2.4.1",
        port=51337,
    )

    addr = ("192.168.1.200", 51337)
    device = Device.from_discovery_message(addr, msg)

    assert device.state == DeviceState.LEAVING


def test_discovery_config_defaults():
    """Test discovery configuration defaults."""
    config = DiscoveryConfig()

    assert config.name == "Python StageLinq"
    assert config.software_name == "python-stagelinq"
    assert config.software_version == "0.1.0"
    assert config.port == 51337
    assert config.announce_interval == 1.0
    assert config.discovery_timeout == 5.0
    assert config.token is not None
    assert len(config.token.data) == 16


def test_discovery_config_custom():
    """Test discovery configuration with custom values."""
    custom_token = Token(b"custom" + b"\x00" * 10)
    config = DiscoveryConfig(
        name="Custom App",
        software_name="custom-stagelinq",
        software_version="2.0.0",
        token=custom_token,
        port=12345,
        announce_interval=0.5,
        discovery_timeout=10.0,
    )

    assert config.name == "Custom App"
    assert config.software_name == "custom-stagelinq"
    assert config.software_version == "2.0.0"
    assert config.token == custom_token
    assert config.port == 12345
    assert config.announce_interval == 0.5
    assert config.discovery_timeout == 10.0


@pytest.mark.asyncio
async def test_stagelinq_discovery_context_manager():
    """Test StageLinq discovery context manager."""
    config = DiscoveryConfig(port=51340)  # Use different port to avoid conflicts

    async with StageLinqDiscovery(config) as discovery:
        assert discovery.config == config
        assert discovery._transport is not None
        assert discovery._protocol is not None


@pytest.mark.asyncio
async def test_stagelinq_discovery_start_stop():
    """Test explicit start/stop of discovery."""
    config = DiscoveryConfig(port=51341)
    discovery = StageLinqDiscovery(config)

    # Should start successfully
    await discovery.start()
    assert discovery._transport is not None

    # Should stop successfully
    await discovery.stop()
    assert discovery._transport is None


@pytest.mark.asyncio
async def test_stagelinq_discovery_double_start():
    """Test that double start is handled gracefully."""
    config = DiscoveryConfig(port=51342)
    discovery = StageLinqDiscovery(config)

    await discovery.start()
    transport1 = discovery._transport

    # Second start should be no-op
    await discovery.start()
    assert discovery._transport is transport1

    await discovery.stop()


@pytest.mark.asyncio
async def test_discover_stagelinq_devices_context_manager():
    """Test the discover_stagelinq_devices context manager."""
    config = DiscoveryConfig(port=51343)

    async with discover_stagelinq_devices(config) as discovery:
        assert isinstance(discovery, StageLinqDiscovery)
        assert discovery.config == config


@pytest.mark.asyncio
async def test_discovery_get_devices_empty():
    """Test getting devices when none are available."""
    config = DiscoveryConfig(port=51344, discovery_timeout=0.1)

    async with StageLinqDiscovery(config) as discovery:
        devices = await discovery.get_devices()
        assert devices == []


@pytest.mark.asyncio
async def test_discovery_announce_loop():
    """Test the announcement loop."""
    config = DiscoveryConfig(port=51345, announce_interval=0.1)

    async with StageLinqDiscovery(config) as discovery:
        # Start announcing
        await discovery.start_announcing()
        assert discovery._announce_task is not None
        assert not discovery._announce_task.done()

        # Let it run for a short time
        await asyncio.sleep(0.25)

        # Should still be running
        assert not discovery._announce_task.done()


@pytest.mark.asyncio
async def test_discovery_broadcast_addresses():
    """Test getting broadcast addresses."""
    config = DiscoveryConfig(port=51346)
    discovery = StageLinqDiscovery(config)

    addresses = discovery._get_broadcast_addresses()

    # Should always include general broadcast
    assert "255.255.255.255" in addresses
    # Should be a list of strings
    assert all(isinstance(addr, str) for addr in addresses)


def test_discovery_message_handler():
    """Test the message handler with mock data."""
    config = DiscoveryConfig()
    discovery = StageLinqDiscovery(config)

    # Create a mock discovery message
    token = Token(b"remote_device_" + b"\x00" * 2)
    msg = DiscoveryMessage(
        token=token,
        source="Remote Device",
        action=DISCOVERER_HOWDY,
        software_name="Remote OS",
        software_version="1.0.0",
        port=51337,
    )

    # Serialize the message
    import io

    writer = io.BytesIO()
    msg.write_to(writer)
    data = writer.getvalue()

    # Handle the message
    addr = ("192.168.1.50", 51337)
    discovery._on_message_received(data, addr)

    # Should have discovered the device
    assert len(discovery._discovered_devices) == 1
    device = next(iter(discovery._discovered_devices.values()))
    assert device.name == "Remote Device"
    assert device.ip == "192.168.1.50"
    assert device.software_name == "Remote OS"


def test_discovery_message_handler_own_message():
    """Test that we ignore our own messages."""
    config = DiscoveryConfig()
    discovery = StageLinqDiscovery(config)

    # Create a message with our own token
    msg = DiscoveryMessage(
        token=config.token,
        source="Our Device",
        action=DISCOVERER_HOWDY,
        software_name="Our OS",
        software_version="1.0.0",
        port=51337,
    )

    # Serialize the message
    import io

    writer = io.BytesIO()
    msg.write_to(writer)
    data = writer.getvalue()

    # Handle the message
    addr = ("192.168.1.50", 51337)
    discovery._on_message_received(data, addr)

    # Should not have discovered any devices
    assert len(discovery._discovered_devices) == 0


def test_discovery_message_handler_leaving():
    """Test handling of leaving messages."""
    config = DiscoveryConfig()
    discovery = StageLinqDiscovery(config)

    # First add a device
    token = Token(b"leaving_device" + b"\x00" * 2)
    msg_howdy = DiscoveryMessage(
        token=token,
        source="Leaving Device",
        action=DISCOVERER_HOWDY,
        software_name="Device OS",
        software_version="1.0.0",
        port=51337,
    )

    import io

    writer = io.BytesIO()
    msg_howdy.write_to(writer)
    data = writer.getvalue()

    addr = ("192.168.1.60", 51337)
    discovery._on_message_received(data, addr)

    # Should have one device
    assert len(discovery._discovered_devices) == 1

    # Now send leaving message
    msg_exit = DiscoveryMessage(
        token=token,
        source="Leaving Device",
        action=DISCOVERER_EXIT,
        software_name="Device OS",
        software_version="1.0.0",
        port=51337,
    )

    writer = io.BytesIO()
    msg_exit.write_to(writer)
    data = writer.getvalue()

    discovery._on_message_received(data, addr)

    # Should have no devices now
    assert len(discovery._discovered_devices) == 0


def test_discovery_message_handler_invalid_data():
    """Test handling of invalid message data."""
    config = DiscoveryConfig()
    discovery = StageLinqDiscovery(config)

    # Send invalid data
    invalid_data = b"not a valid message"
    addr = ("192.168.1.70", 51337)

    # Should not raise exception, just log warning
    discovery._on_message_received(invalid_data, addr)

    # Should not have discovered any devices
    assert len(discovery._discovered_devices) == 0


def test_discovery_message_handler_malformed_but_valid_length():
    """Test handling of messages with valid length but invalid field values."""
    config = DiscoveryConfig()
    discovery = StageLinqDiscovery(config)

    # Test 1: Valid length but wrong magic bytes
    malformed_data = bytearray(48)
    malformed_data[:4] = b"BAD!"
    # Add a valid token (16 bytes)
    malformed_data[4:20] = b"test_token_12345"

    addr = ("192.168.1.71", 51337)

    # Should not raise exception, just log warning
    discovery._on_message_received(bytes(malformed_data), addr)

    # Should not have discovered any devices
    assert len(discovery._discovered_devices) == 0

    # Test 2: Correct magic but corrupted token (wrong length)
    malformed_data2 = bytearray(24)  # Too short for a complete message
    malformed_data2[:4] = b"airD"
    malformed_data2[4:8] = b"bad!"  # Corrupted/truncated token

    addr2 = ("192.168.1.72", 51337)

    # Should not raise exception, just log warning
    discovery._on_message_received(bytes(malformed_data2), addr2)

    # Should not have discovered any devices
    assert len(discovery._discovered_devices) == 0

    # Test 3: Correct magic and token but excessive string length
    from stagelinq.messages import DISCOVERY_MAGIC

    malformed_data3 = bytearray()
    malformed_data3.extend(DISCOVERY_MAGIC)  # Correct magic
    malformed_data3.extend(b"valid_token_16b")  # Valid 16-byte token
    # Add a string length that's too large (will trigger our new validation)
    malformed_data3.extend(
        b"\x00\x01\x00\x00"
    )  # 65536 bytes - exceeds our 512 byte limit for device name

    addr3 = ("192.168.1.73", 51337)

    # Should not raise exception, just log warning
    discovery._on_message_received(bytes(malformed_data3), addr3)

    # Should not have discovered any devices
    assert len(discovery._discovered_devices) == 0


@pytest.mark.asyncio
async def test_discovery_discovered_devices_property():
    """Test the discovered_devices property."""
    config = DiscoveryConfig()
    discovery = StageLinqDiscovery(config)

    # Initially empty
    devices = discovery.discovered_devices
    assert devices == {}

    # Add a device manually
    token = Token(b"prop_test_token" + b"\x00" * 1)
    msg = DiscoveryMessage(
        token=token,
        source="Property Test Device",
        action=DISCOVERER_HOWDY,
        software_name="Test OS",
        software_version="1.0.0",
        port=51337,
    )

    import io

    writer = io.BytesIO()
    msg.write_to(writer)
    data = writer.getvalue()

    addr = ("192.168.1.80", 51337)
    discovery._on_message_received(data, addr)

    # Should return a copy, not the original dict
    devices = discovery.discovered_devices
    assert len(devices) == 1
    assert devices is not discovery._discovered_devices


@pytest.mark.parametrize("state", [DeviceState.PRESENT, DeviceState.LEAVING])
def test_device_state_enum(state):
    """Test DeviceState enum values."""
    assert isinstance(state, DeviceState)
    assert state.value in ["present", "leaving"]
