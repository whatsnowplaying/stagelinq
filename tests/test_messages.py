"""Tests for StageLinq message parsing and serialization."""

from __future__ import annotations

import io
import struct

import pytest

from stagelinq.messages import (
    BEAT_EMIT_MAGIC,
    DISCOVERER_EXIT,
    DISCOVERER_HOWDY,
    DISCOVERY_MAGIC,
    SMAA_MAGIC,
    BeatEmitMessage,
    DiscoveryMessage,
    PlayerInfo,
    ReferenceMessage,
    ServiceAnnouncementMessage,
    ServicesRequestMessage,
    StateEmitMessage,
    StateSubscribeMessage,
    Token,
)


def test_token_creation():
    """Test token creation and equality."""
    # Test random token generation
    token1 = Token()
    token2 = Token()
    assert token1 != token2
    assert len(token1.data) == 16  # SC6000 uses 16-byte tokens
    assert len(token2.data) == 16

    # Test token from data
    data = b"a" * 16
    token3 = Token(data)
    assert token3.data == data
    assert bytes(token3) == data

    # Test token equality
    token4 = Token(data)
    assert token3 == token4

    # Test invalid token length
    with pytest.raises(ValueError, match="Token must be exactly 16 bytes"):
        Token(b"too short")


def test_token_string_representation():
    """Test token string representation."""
    data = b"\x01\x02\x03\x04" + b"\x00" * 12  # 16 bytes total
    token = Token(data)
    assert str(token) == "01020304" + "00" * 12


def test_discovery_message_serialization():
    """Test discovery message serialization and deserialization."""
    token = Token(b"test_token_16b!!")  # 16 bytes

    # Create discovery message
    msg = DiscoveryMessage(
        token=token,
        source="Test Device",
        action=DISCOVERER_HOWDY,
        software_name="TestSoft",
        software_version="1.0.0",
        port=12345,
    )

    # Serialize
    writer = io.BytesIO()
    msg.write_to(writer)
    data = writer.getvalue()

    # Should start with magic bytes
    assert data.startswith(DISCOVERY_MAGIC)

    # Deserialize
    reader = io.BytesIO(data)
    parsed_msg = DiscoveryMessage(Token())
    parsed_msg.read_from(reader)

    # Verify fields
    assert parsed_msg.token == token
    assert parsed_msg.source == "Test Device"
    assert parsed_msg.action == DISCOVERER_HOWDY
    assert parsed_msg.software_name == "TestSoft"
    assert parsed_msg.software_version == "1.0.0"
    assert parsed_msg.port == 12345


def test_discovery_message_leaving():
    """Test discovery message with leaving action."""
    token = Token(b"a" * 16)
    msg = DiscoveryMessage(
        token=token,
        source="Leaving Device",
        action=DISCOVERER_EXIT,
        software_name="TestSoft",
        software_version="1.0.0",
        port=54321,
    )

    # Round trip
    writer = io.BytesIO()
    msg.write_to(writer)

    reader = io.BytesIO(writer.getvalue())
    parsed_msg = DiscoveryMessage(Token())
    parsed_msg.read_from(reader)

    assert parsed_msg.action == DISCOVERER_EXIT
    assert parsed_msg.source == "Leaving Device"
    assert parsed_msg.port == 54321


def test_state_subscribe_message():
    """Test state subscribe message serialization."""
    msg = StateSubscribeMessage(name="/Engine/Deck1/Play", interval=100)

    # Serialize
    writer = io.BytesIO()
    msg.write_to(writer)
    data = writer.getvalue()

    # Should have length prefix
    assert len(data) >= 4
    length = struct.unpack(">I", data[:4])[0]
    assert len(data) == 4 + length

    # Should contain SMAA magic
    assert SMAA_MAGIC in data

    # Deserialize
    reader = io.BytesIO(data)
    parsed_msg = StateSubscribeMessage()
    parsed_msg.read_from(reader)

    assert parsed_msg.name == "/Engine/Deck1/Play"
    assert parsed_msg.interval == 100


def test_state_emit_message():
    """Test state emit message serialization."""
    msg = StateEmitMessage(
        name="/Engine/Deck1/CurrentBPM", json_data='{"value": 128.5}'
    )

    # Round trip
    writer = io.BytesIO()
    msg.write_to(writer)

    reader = io.BytesIO(writer.getvalue())
    parsed_msg = StateEmitMessage()
    parsed_msg.read_from(reader)

    assert parsed_msg.name == "/Engine/Deck1/CurrentBPM"
    assert parsed_msg.json_data == '{"value": 128.5}'


def test_beat_emit_message():
    """Test beat emit message serialization."""
    players = [
        PlayerInfo(beat=1.5, total_beats=256.0, bpm=128.0),
        PlayerInfo(beat=2.0, total_beats=512.0, bpm=140.0),
    ]
    timelines = [10.5, 20.3]

    msg = BeatEmitMessage(clock=1234567890, players=players, timelines=timelines)

    # Serialize
    writer = io.BytesIO()
    msg.write_to(writer)
    data = writer.getvalue()

    # Should have basic structure (length + magic + clock + count + players + timelines)
    # 4 (length) + 4 (magic) + 8 (clock) + 4 (count) + 48 (2 players * 24 bytes) + 16 (2 timelines * 8 bytes)
    assert len(data) >= 4 + 4 + 8 + 4 + 48 + 16

    # Should contain beat emit magic
    assert BEAT_EMIT_MAGIC in data

    # Deserialize
    reader = io.BytesIO(data)
    parsed_msg = BeatEmitMessage()
    parsed_msg.read_from(reader)

    assert parsed_msg.clock == 1234567890
    assert len(parsed_msg.players) == 2
    assert len(parsed_msg.timelines) == 2

    # Check first player
    assert parsed_msg.players[0].beat == 1.5
    assert parsed_msg.players[0].total_beats == 256.0
    assert parsed_msg.players[0].bpm == 128.0

    # Check second player
    assert parsed_msg.players[1].beat == 2.0
    assert parsed_msg.players[1].total_beats == 512.0
    assert parsed_msg.players[1].bpm == 140.0

    # Check timelines
    assert parsed_msg.timelines[0] == 10.5
    assert parsed_msg.timelines[1] == 20.3


def test_beat_emit_message_validation():
    """Test beat emit message validation."""
    players = [PlayerInfo(beat=1.0, total_beats=100.0, bpm=120.0)]
    timelines = [1.0, 2.0]  # Mismatched length

    msg = BeatEmitMessage(clock=123, players=players, timelines=timelines)

    # Should raise error on mismatched lengths
    writer = io.BytesIO()
    with pytest.raises(
        ValueError, match="Number of players must match number of timelines"
    ):
        msg.write_to(writer)


def test_beat_emit_message_go_compatibility():
    """Test beat emit message compatibility with Go implementation."""
    # This is the exact test data from the Go test suite
    go_test_bytes = bytes(
        [
            0x00,
            0x00,
            0x00,
            0x90,
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x06,
            0x73,
            0xFC,
            0x64,
            0x81,
            0xAC,
            0x00,
            0x00,
            0x00,
            0x04,
            0x40,
            0x71,
            0xD6,
            0xA3,
            0x0E,
            0xF9,
            0xC6,
            0x44,
            0x40,
            0x79,
            0x0F,
            0xE1,
            0xE8,
            0x2D,
            0x23,
            0xBD,
            0x40,
            0x5B,
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            0x71,
            0xB9,
            0x22,
            0x53,
            0x6D,
            0xC5,
            0x20,
            0x40,
            0x80,
            0x61,
            0xB1,
            0x01,
            0x76,
            0x7D,
            0xCE,
            0x40,
            0x5A,
            0x40,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            0x5E,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x40,
            0x5E,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x41,
            0x5A,
            0x30,
            0x9C,
            0xE0,
            0x16,
            0xD3,
            0x64,
            0x41,
            0x5B,
            0x5B,
            0x1C,
            0x8B,
            0xD2,
            0x15,
            0xF2,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )

    # Parse the Go test data
    reader = io.BytesIO(go_test_bytes)
    msg = BeatEmitMessage()
    msg.read_from(reader)

    # Expected values from Go test
    assert msg.clock == 7095225450924
    assert len(msg.players) == 4
    assert len(msg.timelines) == 4

    # Check player values (with small tolerance for floating point precision)
    assert abs(msg.players[0].beat - 285.41480920379786) < 1e-10
    assert abs(msg.players[0].total_beats - 400.99265306122453) < 1e-10
    assert abs(msg.players[0].bpm - 110.0) < 1e-10

    assert abs(msg.players[1].beat - 283.57088034514345) < 1e-10
    assert abs(msg.players[1].total_beats - 524.2114285714285) < 1e-10
    assert abs(msg.players[1].bpm - 105.0) < 1e-10

    assert msg.players[2].beat == 0.0
    assert msg.players[2].total_beats == 0.0
    assert msg.players[2].bpm == 120.0

    assert msg.players[3].beat == 0.0
    assert msg.players[3].total_beats == 0.0
    assert msg.players[3].bpm == 120.0

    # Check timeline values
    assert abs(msg.timelines[0] - 6865523.501393173) < 1e-6
    assert abs(msg.timelines[1] - 7171186.184697615) < 1e-6
    assert msg.timelines[2] == 0.0
    assert msg.timelines[3] == 0.0

    # Test round-trip - serialize and compare
    writer = io.BytesIO()
    msg.write_to(writer)
    serialized = writer.getvalue()

    # Should produce identical bytes
    assert serialized == go_test_bytes


def test_service_announcement_message():
    """Test service announcement message."""
    token = Token(b"x" * 16)
    msg = ServiceAnnouncementMessage(token=token, service="StateMap", port=51338)

    # Round trip
    writer = io.BytesIO()
    msg.write_to(writer)

    reader = io.BytesIO(writer.getvalue())
    parsed_msg = ServiceAnnouncementMessage(Token())
    parsed_msg.read_from(reader)

    assert parsed_msg.token == token
    assert parsed_msg.service == "StateMap"
    assert parsed_msg.port == 51338


def test_reference_message():
    """Test reference message."""
    token1 = Token(b"a" * 16)
    token2 = Token(b"b" * 16)
    msg = ReferenceMessage(token=token1, token2=token2, reference=9876543210)

    # Round trip
    writer = io.BytesIO()
    msg.write_to(writer)

    reader = io.BytesIO(writer.getvalue())
    parsed_msg = ReferenceMessage(Token())
    parsed_msg.read_from(reader)

    assert parsed_msg.token == token1
    assert parsed_msg.token2 == token2
    assert parsed_msg.reference == 9876543210


def test_services_request_message():
    """Test services request message."""
    token = Token(b"z" * 16)
    msg = ServicesRequestMessage(token=token)

    # Round trip
    writer = io.BytesIO()
    msg.write_to(writer)

    reader = io.BytesIO(writer.getvalue())
    parsed_msg = ServicesRequestMessage(Token())
    parsed_msg.read_from(reader)

    assert parsed_msg.token == token


def test_empty_strings():
    """Test handling of empty strings in messages."""
    token = Token(b"e" * 16)
    msg = DiscoveryMessage(
        token=token, source="", action="", software_name="", software_version="", port=0
    )

    # Round trip
    writer = io.BytesIO()
    msg.write_to(writer)

    reader = io.BytesIO(writer.getvalue())
    parsed_msg = DiscoveryMessage(Token())
    parsed_msg.read_from(reader)

    assert parsed_msg.source == ""
    assert parsed_msg.action == ""
    assert parsed_msg.software_name == ""
    assert parsed_msg.software_version == ""
    assert parsed_msg.port == 0


def test_unicode_strings():
    """Test handling of Unicode strings in messages."""
    token = Token(b"u" * 16)
    msg = DiscoveryMessage(
        token=token,
        source="Test Device 🎵",
        action=DISCOVERER_HOWDY,
        software_name="TestSoft™",
        software_version="1.0.0-β",
        port=12345,
    )

    # Round trip
    writer = io.BytesIO()
    msg.write_to(writer)

    reader = io.BytesIO(writer.getvalue())
    parsed_msg = DiscoveryMessage(Token())
    parsed_msg.read_from(reader)

    assert parsed_msg.source == "Test Device 🎵"
    assert parsed_msg.software_name == "TestSoft™"
    assert parsed_msg.software_version == "1.0.0-β"


@pytest.mark.parametrize(
    "message_id,expected_class",
    [
        (0x00000000, ServiceAnnouncementMessage),
        (0x00000001, ReferenceMessage),
        (0x00000002, ServicesRequestMessage),
    ],
)
def test_message_id_constants(message_id, expected_class):
    """Test message ID constants are correct."""
    instance = expected_class()
    assert instance.MESSAGE_ID == message_id


def test_packet_capture_discovery_message():
    """Test parsing a real discovery message from packet capture."""
    # This would be a real packet capture - for now, create a realistic one
    token_data = b"\x12\x34\x56\x78" + b"\x00" * 12
    token = Token(token_data)

    # Create what a real Prime 4 might send
    msg = DiscoveryMessage(
        token=token,
        source="Prime 4",
        action=DISCOVERER_HOWDY,
        software_name="Engine OS",
        software_version="2.4.1",
        port=51337,
    )

    # Serialize to get packet data
    writer = io.BytesIO()
    msg.write_to(writer)
    packet_data = writer.getvalue()

    # Parse it back
    reader = io.BytesIO(packet_data)
    parsed_msg = DiscoveryMessage(Token())
    parsed_msg.read_from(reader)

    assert parsed_msg.source == "Prime 4"
    assert parsed_msg.software_name == "Engine OS"
    assert parsed_msg.software_version == "2.4.1"
    assert parsed_msg.action == DISCOVERER_HOWDY
