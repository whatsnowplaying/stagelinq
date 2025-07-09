"""Tests for TCP service messages from sc6000-mac-tcponly.pcapng capture."""

from __future__ import annotations

import binascii
from pathlib import Path

import pytest

from stagelinq.file_transfer import FileAnnouncementMessage
from stagelinq.messages import ServiceAnnouncementMessage, Token

# Import TCP test fixtures
try:
    from .fixtures.tcp_packets import TCP_PACKET_DATA, TCP_SERVICE_PACKETS
except ImportError:
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from fixtures.tcp_packets import TCP_PACKET_DATA, TCP_SERVICE_PACKETS


@pytest.fixture
def tcp_packet_data():
    """Load TCP service message data."""
    return TCP_PACKET_DATA


def test_tcp_service_message_parsing(tcp_packet_data):
    """Test parsing of TCP service messages."""
    service_messages = tcp_packet_data["service_messages"]

    # Should have found multiple service types
    assert len(service_messages) > 0

    # Check that we have the expected service types
    services = [msg["service"] for msg in service_messages]
    expected_services = ["StateMap", "Broadcast", "Syncing", "BeatInfo", "FileTransfer"]

    for expected in expected_services:
        assert expected in services, f"Expected service '{expected}' not found"


def test_service_announcement_message_from_tcp_data(tcp_packet_data):
    """Test parsing ServiceAnnouncementMessage from TCP capture data."""
    service_messages = tcp_packet_data["service_messages"]

    # Test parsing the first few service messages
    for i, msg_data in enumerate(service_messages[:3]):
        packet_hex = msg_data["raw_data"]
        packet_bytes = binascii.unhexlify(packet_hex)

        # Parse as ServiceAnnouncementMessage
        message = ServiceAnnouncementMessage.deserialize(packet_bytes)

        # Verify the parsed data matches the captured data
        assert message.service == msg_data["service"]
        assert message.port == msg_data["port"]
        assert isinstance(message.token, Token)
        assert len(message.token.data) == 16


def test_state_map_service_message(tcp_packet_data):
    """Test StateMap service message specifically."""
    service_messages = tcp_packet_data["service_messages"]

    # Find StateMap service message
    state_map_msg = None
    for msg in service_messages:
        if msg["service"] == "StateMap":
            state_map_msg = msg
            break

    assert state_map_msg is not None, "StateMap service message not found"

    # Parse the message
    packet_bytes = binascii.unhexlify(state_map_msg["raw_data"])
    message = ServiceAnnouncementMessage.deserialize(packet_bytes)

    # Verify StateMap-specific properties
    assert message.service == "StateMap"
    assert message.port == 41137
    assert message.token.data == binascii.unhexlify("4be141125ead4848a07db37ca8a7220e")


def test_beat_info_service_message(tcp_packet_data):
    """Test BeatInfo service message specifically."""
    service_messages = tcp_packet_data["service_messages"]

    # Find BeatInfo service message
    beat_info_msg = None
    for msg in service_messages:
        if msg["service"] == "BeatInfo":
            beat_info_msg = msg
            break

    assert beat_info_msg is not None, "BeatInfo service message not found"

    # Parse the message
    packet_bytes = binascii.unhexlify(beat_info_msg["raw_data"])
    message = ServiceAnnouncementMessage.deserialize(packet_bytes)

    # Verify BeatInfo-specific properties
    assert message.service == "BeatInfo"
    assert message.port == 39835
    assert message.token.data == binascii.unhexlify("4be141125ead4848a07db37ca8a7220e")


def test_file_transfer_service_messages(tcp_packet_data):
    """Test FileTransfer service messages."""
    service_messages = tcp_packet_data["service_messages"]

    # Find FileTransfer service messages
    file_transfer_msgs = [
        msg for msg in service_messages if msg["service"] == "FileTransfer"
    ]

    assert len(file_transfer_msgs) >= 2, "Expected at least 2 FileTransfer messages"

    # Test parsing each FileTransfer message
    for msg in file_transfer_msgs:
        packet_bytes = binascii.unhexlify(msg["raw_data"])
        message = ServiceAnnouncementMessage.deserialize(packet_bytes)

        assert message.service == "FileTransfer"
        assert isinstance(message.port, int)
        assert isinstance(message.token, Token)


def test_tcp_service_message_roundtrip(tcp_packet_data):
    """Test round-trip serialization of TCP service messages."""
    service_messages = tcp_packet_data["service_messages"]

    # Test round-trip for first few messages
    for msg_data in service_messages[:3]:
        original_bytes = binascii.unhexlify(msg_data["raw_data"])

        # Parse and re-serialize
        message = ServiceAnnouncementMessage.deserialize(original_bytes)
        serialized_bytes = message.serialize()

        # Should be identical
        assert serialized_bytes == original_bytes


def test_tcp_service_message_token_consistency(tcp_packet_data):
    """Test that messages from the same device have consistent tokens."""
    service_messages = tcp_packet_data["service_messages"]

    # Group messages by token
    token_groups = {}
    for msg in service_messages:
        packet_bytes = binascii.unhexlify(msg["raw_data"])

        # Skip fltx messages (they don't have tokens in the same format)
        if packet_bytes[4:8] == b"fltx":
            continue

        message = ServiceAnnouncementMessage.deserialize(packet_bytes)

        token_hex = message.token.data.hex()
        if token_hex not in token_groups:
            token_groups[token_hex] = []
        token_groups[token_hex].append(message)

    # Should have at least one token group
    assert len(token_groups) > 0

    # Each token group should have multiple services
    for token_hex, messages in token_groups.items():
        if len(messages) > 1:
            # All messages from same token should have same source
            first_token = messages[0].token
            for msg in messages[1:]:
                assert msg.token.data == first_token.data


def test_tcp_service_message_utf16_encoding(tcp_packet_data):
    """Test UTF-16 encoding in TCP service messages."""
    service_messages = tcp_packet_data["service_messages"]

    # Test encoding for first message
    msg_data = service_messages[0]
    packet_bytes = binascii.unhexlify(msg_data["raw_data"])
    message = ServiceAnnouncementMessage.deserialize(packet_bytes)

    # Re-serialize and check for UTF-16 encoding
    serialized = message.serialize()

    # Service name should be encoded in UTF-16BE
    service_name_utf16 = message.service.encode("utf-16be")
    assert service_name_utf16 in serialized


@pytest.mark.parametrize("packet_hex", TCP_SERVICE_PACKETS)
def test_all_tcp_service_packets_parseable(packet_hex):
    """Test that all TCP service packets are parseable."""
    packet_bytes = binascii.unhexlify(packet_hex)

    # Check if this is a file announcement (fltx) message
    if packet_bytes[4:8] == b"fltx":
        # Parse as FileAnnouncementMessage
        message = FileAnnouncementMessage.deserialize(packet_bytes)

        # Should have valid path
        assert message.path
        assert len(message.path) > 0
        assert message.path.startswith("/")

        # Should have valid message type and size
        assert isinstance(message.message_type, int)
        assert isinstance(message.size, int)

    else:
        # Parse as ServiceAnnouncementMessage
        message = ServiceAnnouncementMessage.deserialize(packet_bytes)

        # Should have valid service name
        assert message.service
        assert len(message.service) > 0
        assert len(message.service) < 100  # Reasonable length

        # Should have valid port
        assert isinstance(message.port, int)
        assert 0 <= message.port <= 65535

        # Should have valid token
        assert isinstance(message.token, Token)
        assert len(message.token.data) == 16


def test_tcp_capture_metadata(tcp_packet_data):
    """Test TCP capture metadata."""
    summary = tcp_packet_data["summary"]

    # Verify capture statistics
    assert summary["total_service_messages"] == 9
    assert summary["capture_file"] == "sc6000-mac-tcponly.pcapng"

    # Should have found multiple service types
    services_found = summary["services_found"]
    assert len(services_found) >= 5
    assert "StateMap" in services_found
    assert "BeatInfo" in services_found
    assert "FileTransfer" in services_found


def test_tcp_service_types_coverage(tcp_packet_data):
    """Test that we have good coverage of service types."""
    service_messages = tcp_packet_data["service_messages"]
    services = [msg["service"] for msg in service_messages]

    # Should cover the main StageLinQ services
    expected_services = [
        "StateMap",  # State synchronization
        "BeatInfo",  # Beat information
        "FileTransfer",  # File transfer
        "Broadcast",  # Broadcasting
        "Syncing",  # Synchronization
    ]

    for expected in expected_services:
        assert expected in services, f"Service type '{expected}' not found in capture"


def test_file_announcement_message_parsing():
    """Test parsing of FileAnnouncementMessage from TCP data."""
    # Test the two fltx messages from the capture
    fltx_packets = [
        "00000050666c747800000000000007d100000040002f0044004a003200200028005500530042002000310029002f0045006e00670069006e00650020004c006900620072006100720079002f006d002e00640062",
        "00000054666c747800000000000007d400000040002f0044004a003200200028005500530042002000310029002f0045006e00670069006e00650020004c006900620072006100720079002f006d002e0064006200000000",
    ]

    for packet_hex in fltx_packets:
        packet_bytes = binascii.unhexlify(packet_hex)
        message = FileAnnouncementMessage.deserialize(packet_bytes)

        # Should parse the file path correctly
        assert message.path == "/DJ2 (USB 1)/Engine Library/m.db"

        # Should have reasonable message type and size
        assert message.message_type in [0x7D1, 0x7D4]
        assert message.size == 0x40  # 64 bytes


def test_file_announcement_message_roundtrip():
    """Test round-trip serialization of FileAnnouncementMessage."""
    # Test with first fltx packet
    original_hex = "00000050666c747800000000000007d100000040002f0044004a003200200028005500530042002000310029002f0045006e00670069006e00650020004c006900620072006100720079002f006d002e00640062"
    original_bytes = binascii.unhexlify(original_hex)

    # Parse and re-serialize
    message = FileAnnouncementMessage.deserialize(original_bytes)
    serialized_bytes = message.serialize()

    # Should be identical
    assert serialized_bytes == original_bytes


def test_file_announcement_message_creation():
    """Test creating FileAnnouncementMessage from scratch."""
    message = FileAnnouncementMessage(
        path="/DJ2 (USB 1)/Engine Library/m.db", message_type=0x7D1, size=0x40
    )

    # Serialize and parse back
    serialized = message.serialize()
    parsed = FileAnnouncementMessage.deserialize(serialized)

    # Should match original
    assert parsed.path == message.path
    assert parsed.message_type == message.message_type
    assert parsed.size == message.size


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
