"""
Test suite using real SC6000 packet captures as the authoritative reference.

This test suite validates our Pythonic StageLinq implementation against
real-world data from actual DJ equipment, ensuring protocol correctness.
"""

import binascii
import json
from pathlib import Path

import pytest

from stagelinq.messages import (
    DISCOVERER_HOWDY,
    DiscoveryMessage,
    StateEmitMessage,
    StateSubscribeMessage,
    Token,
)

# Import test fixtures
try:
    from .fixtures.sc6000_packets import SC6000_PACKET_DATA
except ImportError:
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from fixtures.sc6000_packets import SC6000_PACKET_DATA


@pytest.fixture
def packet_data():
    """Load real SC6000 packet data."""
    return SC6000_PACKET_DATA


def test_discovery_packet_parsing(packet_data):
    """Test parsing of real SC6000 discovery packets."""
    # Use the first discovery packet as reference
    packet_hex = packet_data["discovery_packets"][0]
    packet_bytes = binascii.unhexlify(packet_hex)

    # Parse using our implementation
    message = DiscoveryMessage.deserialize(packet_bytes)

    # Validate against real SC6000 data
    assert message.source == "DN-X1800Prime"
    assert message.software_name == "JM08"
    assert message.software_version == "1.00"
    assert message.action == DISCOVERER_HOWDY
    assert message.port == 50010
    assert isinstance(message.token, Token)
    assert len(message.token.data) == 16

    # Verify token matches real data
    expected_token = binascii.unhexlify("0000000000000000800000059504141c")
    assert message.token.data == expected_token


def test_discovery_packet_consistency(packet_data):
    """Test that all discovery packets are consistent."""
    packets = packet_data["discovery_packets"]

    # Parse all packets
    messages = []
    for packet_hex in packets:
        packet_bytes = binascii.unhexlify(packet_hex)
        message = DiscoveryMessage.deserialize(packet_bytes)
        messages.append(message)

    # Verify all are identical (same device announcing itself)
    first_message = messages[0]
    for message in messages[1:]:
        assert message.source == first_message.source
        assert message.software_name == first_message.software_name
        assert message.software_version == first_message.software_version
        assert message.action == first_message.action
        assert message.port == first_message.port
        assert message.token == first_message.token


def test_state_subscribe_packet_parsing(packet_data):
    """Test parsing of real SC6000 state subscribe packets."""
    # Find state subscribe packets (magic ID 0x000007d2)
    state_subscribe_packets = []
    for packet_hex in packet_data["state_packets"]:
        packet_bytes = binascii.unhexlify(packet_hex)
        # Check magic ID
        import struct

        magic_id = struct.unpack(">I", packet_bytes[8:12])[0]
        if magic_id == 0x000007D2:
            state_subscribe_packets.append(packet_hex)

    assert state_subscribe_packets, "No state subscribe packets found"

    # Parse the first state subscribe packet
    packet_bytes = binascii.unhexlify(state_subscribe_packets[0])
    message = StateSubscribeMessage.deserialize(packet_bytes)

    # Validate against real SC6000 data
    assert message.name == "/Mixer/NumberOfChannels"
    assert message.interval == 0xFFFFFFFF  # -1 in unsigned


def test_state_emit_packet_parsing(packet_data):
    """Test parsing of real SC6000 state emit packets."""
    # Find state emit packets (magic ID 0x00000000)
    state_emit_packets = []
    for packet_hex in packet_data["state_packets"]:
        packet_bytes = binascii.unhexlify(packet_hex)
        # Check magic ID
        import struct

        magic_id = struct.unpack(">I", packet_bytes[8:12])[0]
        if magic_id == 0x00000000:
            state_emit_packets.append(packet_hex)

    assert state_emit_packets, "No state emit packets found"

    # Parse the state emit packet (BPM data)
    packet_bytes = binascii.unhexlify(state_emit_packets[0])
    message = StateEmitMessage.deserialize(packet_bytes)

    # Validate against real SC6000 data
    assert message.name == "/Engine/Deck1/Track/CurrentBPM"

    # Parse and validate JSON data

    bpm_data = json.loads(message.json_data)
    assert bpm_data["type"] == 0
    assert bpm_data["value"] == 121.9754638671875


def test_discovery_roundtrip_serialization(packet_data):
    """Test round-trip serialization preserves real data exactly."""
    packet_hex = packet_data["discovery_packets"][0]
    original_bytes = binascii.unhexlify(packet_hex)

    # Parse and re-serialize
    message = DiscoveryMessage.deserialize(original_bytes)
    serialized_bytes = message.serialize()

    # Verify byte-for-byte identical
    assert serialized_bytes == original_bytes

    # Verify re-parsing produces identical message
    roundtrip_message = DiscoveryMessage.deserialize(serialized_bytes)
    assert message.source == roundtrip_message.source
    assert message.software_name == roundtrip_message.software_name
    assert message.software_version == roundtrip_message.software_version
    assert message.action == roundtrip_message.action
    assert message.port == roundtrip_message.port
    assert message.token == roundtrip_message.token


def test_protocol_constants_match_real_data(packet_data):
    """Test that our protocol constants match real SC6000 behavior."""
    # Discovery magic should be "airD"
    packet_hex = packet_data["discovery_packets"][0]
    packet_bytes = binascii.unhexlify(packet_hex)

    magic = packet_bytes[:4]
    assert magic == b"airD"

    # State magic should be "smaa"
    state_packet_hex = packet_data["state_packets"][0]
    state_packet_bytes = binascii.unhexlify(state_packet_hex)

    state_magic = state_packet_bytes[4:8]
    assert state_magic == b"smaa"


def test_real_device_characteristics(packet_data):
    """Test that we correctly identify real SC6000 device characteristics."""
    packet_hex = packet_data["discovery_packets"][0]
    packet_bytes = binascii.unhexlify(packet_hex)
    message = DiscoveryMessage.deserialize(packet_bytes)

    # Real SC6000 characteristics from packet capture
    assert message.source == "DN-X1800Prime"  # Actual device model
    assert message.software_name == "JM08"  # Real firmware name
    assert message.software_version == "1.00"  # Real firmware version
    assert message.port == 50010  # Real port used

    # Token should be 16 bytes (not 32)
    assert len(message.token.data) == 16


def test_packet_capture_metadata(packet_data):
    """Test that packet capture metadata is correctly understood."""
    summary = packet_data["summary"]

    # Verify capture statistics
    assert summary["total_discovery"] == 74
    assert summary["total_state"] == 34
    assert summary["total_beat"] == 0  # No beat packets in this capture

    # Verify packet counts match actual data
    assert len(packet_data["discovery_packets"]) <= summary["total_discovery"]
    assert len(packet_data["state_packets"]) <= summary["total_state"]
    assert len(packet_data["beat_packets"]) == summary["total_beat"]


def test_state_packet_types(packet_data):
    """Test identification of different state packet types."""
    state_subscribe_count = 0
    state_emit_count = 0

    for packet_hex in packet_data["state_packets"]:
        packet_bytes = binascii.unhexlify(packet_hex)
        import struct

        magic_id = struct.unpack(">I", packet_bytes[8:12])[0]

        if magic_id == 0x000007D2:  # State subscribe
            state_subscribe_count += 1
        elif magic_id == 0x00000000:  # State emit
            state_emit_count += 1

    # Should have both types in real capture
    assert state_subscribe_count > 0
    assert state_emit_count > 0

    # Total should match packet count
    assert state_subscribe_count + state_emit_count == len(packet_data["state_packets"])


def test_utf16_string_encoding(packet_data):
    """Test UTF-16 string encoding matches real SC6000 format."""
    packet_hex = packet_data["discovery_packets"][0]
    packet_bytes = binascii.unhexlify(packet_hex)
    message = DiscoveryMessage.deserialize(packet_bytes)

    # Re-serialize and verify UTF-16 encoding
    serialized = message.serialize()

    # Check that device name is properly encoded
    # Should contain "DN-X1800Prime" in UTF-16BE
    device_name_utf16 = "DN-X1800Prime".encode("utf-16be")
    assert device_name_utf16 in serialized

    # Check that software name is properly encoded
    software_name_utf16 = "JM08".encode("utf-16be")
    assert software_name_utf16 in serialized


@pytest.mark.parametrize("packet_index", range(5))
def test_all_discovery_packets_parseable(packet_data, packet_index):
    """Test that all discovery packets in the capture are parseable."""
    packet_hex = packet_data["discovery_packets"][packet_index]
    packet_bytes = binascii.unhexlify(packet_hex)

    # Should not raise any exceptions
    message = DiscoveryMessage.deserialize(packet_bytes)

    # All should be from the same device
    assert message.source == "DN-X1800Prime"
    assert message.action == DISCOVERER_HOWDY


def test_real_world_token_format(packet_data):
    """Test that token format matches real SC6000 usage."""
    packet_hex = packet_data["discovery_packets"][0]
    packet_bytes = binascii.unhexlify(packet_hex)
    message = DiscoveryMessage.deserialize(packet_bytes)

    # Real SC6000 token characteristics
    token_data = message.token.data
    assert len(token_data) == 16  # 16 bytes, not 32

    # Token should be the same across all packets from same device
    for packet_hex in packet_data["discovery_packets"]:
        packet_bytes = binascii.unhexlify(packet_hex)
        msg = DiscoveryMessage.deserialize(packet_bytes)
        assert msg.token.data == token_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
