"""Tests using real SC6000 packet capture data."""

from __future__ import annotations

import io
import json

import pytest

from stagelinq.messages import (
    DISCOVERER_HOWDY,
    DISCOVERY_MAGIC,
    SMAA_MAGIC,
    DiscoveryMessage,
    StateEmitMessage,
    StateSubscribeMessage,
    Token,
)

# Real packet data from SC6000 boot capture
SC6000_DISCOVERY_PACKET = "616972440000000000000000800000059504141c0000001a0044004e002d00580031003800300030005000720069006d0065000000220044004900530043004f00560045005200450052005f0048004f005700440059005f00000008004a004d00300038000000080031002e00300030c35a"

SC6000_STATE_PACKETS = [
    "0000003e736d6161000007d20000002e002f004d0069007800650072002f004e0075006d006200650072004f0066004300680061006e006e0065006c0073ffffffff",
    "0000004c736d6161000007d20000003c002f0045006e00670069006e0065002f004400650063006b0031002f0054007200610063006b002f00430075007200720065006e007400420050004d00000064",
    "0000004c736d6161000007d20000003c002f0045006e00670069006e0065002f004400650063006b0032002f0054007200610063006b002f00430075007200720065006e007400420050004d00000064",
    "00000056736d6161000007d200000046002f0043006c00690065006e0074002f0050007200650066006500720065006e006300650073002f0050006c0061007900650072004a006f00670043006f006c006f0072004100000064",
    "00000094736d6161000000000000003c002f0045006e00670069006e0065002f004400650063006b0031002f0054007200610063006b002f00430075007200720065006e007400420050004d00000048007b002200740079007000650022003a0030002c002200760061006c007500650022003a003100320031002e0039003700350034003600330038003600370031003800370035007d",
]


def test_parse_real_sc6000_discovery_packet():
    """Test parsing real SC6000 discovery packet."""
    # Convert hex string to bytes
    packet_data = bytes.fromhex(SC6000_DISCOVERY_PACKET)

    # Parse the message
    reader = io.BytesIO(packet_data)
    msg = DiscoveryMessage(Token())
    msg.read_from(reader)

    # Verify the parsed data matches expected SC6000 values
    assert msg.source == "DN-X1800Prime"
    assert msg.action == DISCOVERER_HOWDY
    assert msg.software_name == "JM08"
    assert msg.software_version == "1.00"
    assert msg.port == 50010  # 0xc35a in hex

    # Verify token is present and correct length (SC6000 uses 16-byte tokens)
    assert len(msg.token.data) == 16

    # Verify magic bytes are present
    assert packet_data.startswith(DISCOVERY_MAGIC)


def test_sc6000_discovery_packet_roundtrip():
    """Test that we can parse and recreate the SC6000 discovery packet."""
    # Parse original packet
    packet_data = bytes.fromhex(SC6000_DISCOVERY_PACKET)
    reader = io.BytesIO(packet_data)
    msg = DiscoveryMessage(Token())
    msg.read_from(reader)

    # Recreate packet
    writer = io.BytesIO()
    msg.write_to(writer)
    recreated_data = writer.getvalue()

    # Should be identical
    assert recreated_data == packet_data


def test_parse_real_sc6000_state_subscribe_packet():
    """Test parsing real SC6000 state subscribe packet."""
    # Use the first state packet (NumberOfChannels subscription)
    packet_data = bytes.fromhex(SC6000_STATE_PACKETS[0])

    # Parse the message
    reader = io.BytesIO(packet_data)
    msg = StateSubscribeMessage()
    msg.read_from(reader)

    # Verify the parsed data
    assert msg.name == "/Mixer/NumberOfChannels"
    assert msg.interval == 0xFFFFFFFF  # Special interval value

    # Verify SMAA magic is present
    assert SMAA_MAGIC in packet_data


def test_parse_real_sc6000_state_emit_packet():
    """Test parsing real SC6000 state emit packet."""
    # Use the last state packet (CurrentBPM with JSON data)
    packet_data = bytes.fromhex(SC6000_STATE_PACKETS[4])

    # Parse the message
    reader = io.BytesIO(packet_data)
    msg = StateEmitMessage()
    msg.read_from(reader)

    # Verify the parsed data
    assert msg.name == "/Engine/Deck1/Track/CurrentBPM"

    # Parse the JSON data
    json_data = json.loads(msg.json_data)
    assert json_data["type"] == 0
    assert json_data["value"] == 121.9754638671875  # Real SC6000 BPM value


@pytest.mark.parametrize("packet_hex", SC6000_STATE_PACKETS[:3])
def test_parse_sc6000_state_packets(packet_hex):
    """Test parsing various SC6000 state packets."""
    packet_data = bytes.fromhex(packet_hex)

    # Should start with length prefix
    assert len(packet_data) >= 4

    # Should contain SMAA magic
    assert SMAA_MAGIC in packet_data

    # Should be parseable as either subscribe or emit message
    reader = io.BytesIO(packet_data)

    # Try parsing as subscribe message first
    try:
        msg = StateSubscribeMessage()
        msg.read_from(reader)
        assert msg.name.startswith("/")
        assert isinstance(msg.interval, int)
    except ValueError:
        # Try as emit message
        reader.seek(0)
        msg = StateEmitMessage()
        msg.read_from(reader)
        assert msg.name.startswith("/")
        assert isinstance(msg.json_data, str)


def test_sc6000_state_packet_names():
    """Test that SC6000 state packets have expected names."""
    expected_names = [
        "/Mixer/NumberOfChannels",
        "/Engine/Deck1/Track/CurrentBPM",
        "/Engine/Deck2/Track/CurrentBPM",
        "/Client/Preferences/PlayerJogColorA",
        "/Engine/Deck1/Track/CurrentBPM",  # Emit version
    ]

    for i, packet_hex in enumerate(SC6000_STATE_PACKETS):
        packet_data = bytes.fromhex(packet_hex)
        reader = io.BytesIO(packet_data)

        # Determine message type by magic ID
        reader.seek(8)  # Skip length and SMAA magic
        magic_id = int.from_bytes(reader.read(4), byteorder="big")
        reader.seek(0)

        if magic_id == 0x000007D2:  # Subscribe message
            msg = StateSubscribeMessage()
            msg.read_from(reader)
            assert msg.name == expected_names[i]
        elif magic_id == 0x00000000:  # Emit message
            msg = StateEmitMessage()
            msg.read_from(reader)
            assert msg.name == expected_names[i]


def test_sc6000_token_consistency():
    """Test that the SC6000 uses consistent token across packets."""
    # Extract token from discovery packet
    packet_data = bytes.fromhex(SC6000_DISCOVERY_PACKET)
    reader = io.BytesIO(packet_data)
    msg = DiscoveryMessage(Token())
    msg.read_from(reader)

    sc6000_token = msg.token

    # The token should be consistent - this is the actual SC6000 token
    expected_token = b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
    # This is the real token from the SC6000 capture
    assert sc6000_token.data == expected_token


def test_sc6000_device_identification():
    """Test SC6000 device identification from discovery packet."""
    packet_data = bytes.fromhex(SC6000_DISCOVERY_PACKET)
    reader = io.BytesIO(packet_data)
    msg = DiscoveryMessage(Token())
    msg.read_from(reader)

    # This should identify as a DN-X1800Prime (mixer, not SC6000)
    # The capture name was misleading - it's actually from DN-X1800Prime
    assert "DN-X1800" in msg.source
    assert "Prime" in msg.source
    assert msg.software_name == "JM08"  # Denon's internal software name
    assert msg.software_version == "1.00"


def test_sc6000_port_number():
    """Test SC6000 port number from discovery packet."""
    packet_data = bytes.fromhex(SC6000_DISCOVERY_PACKET)
    reader = io.BytesIO(packet_data)
    msg = DiscoveryMessage(Token())
    msg.read_from(reader)

    # Port should be 50010 (0xc35a)
    assert msg.port == 50010
    assert msg.port != 51337  # Not the discovery port


def test_sc6000_bpm_value_parsing():
    """Test parsing BPM value from SC6000 state emit packet."""
    # Use the packet with BPM JSON data
    packet_data = bytes.fromhex(SC6000_STATE_PACKETS[4])
    reader = io.BytesIO(packet_data)
    msg = StateEmitMessage()
    msg.read_from(reader)

    # Parse the BPM value
    bpm_data = json.loads(msg.json_data)
    bpm_value = float(bpm_data["value"])

    # Should be a reasonable BPM value
    assert 80.0 <= bpm_value <= 200.0
    assert bpm_value == pytest.approx(121.975, rel=1e-3)


def test_sc6000_utf16_encoding():
    """Test UTF-16 encoding in SC6000 packets."""
    packet_data = bytes.fromhex(SC6000_DISCOVERY_PACKET)
    reader = io.BytesIO(packet_data)
    msg = DiscoveryMessage(Token())
    msg.read_from(reader)

    # All string fields should be properly decoded from UTF-16
    assert isinstance(msg.source, str)
    assert isinstance(msg.action, str)
    assert isinstance(msg.software_name, str)
    assert isinstance(msg.software_version, str)

    # Should not contain null bytes or encoding artifacts
    assert "\x00" not in msg.source
    assert "\x00" not in msg.action
    assert "\x00" not in msg.software_name
    assert "\x00" not in msg.software_version


def test_sc6000_packet_lengths():
    """Test that SC6000 packets have correct length prefixes."""
    for packet_hex in SC6000_STATE_PACKETS:
        packet_data = bytes.fromhex(packet_hex)

        # Extract length prefix
        length = int.from_bytes(packet_data[:4], byteorder="big")

        # Verify length matches actual payload
        assert len(packet_data) == 4 + length

        # Length should be reasonable
        assert 0 < length < 1000  # Reasonable bounds for StagelinQ messages


def test_sc6000_magic_bytes():
    """Test that SC6000 packets contain expected magic bytes."""
    # Discovery packet should start with "airD"
    discovery_data = bytes.fromhex(SC6000_DISCOVERY_PACKET)
    assert discovery_data.startswith(DISCOVERY_MAGIC)

    # State packets should contain "smaa"
    for packet_hex in SC6000_STATE_PACKETS:
        packet_data = bytes.fromhex(packet_hex)
        assert SMAA_MAGIC in packet_data


def test_sc6000_capture_metadata():
    """Test metadata about the SC6000 capture."""
    # This test documents what we know about the capture
    capture_info = {
        "device": "DN-X1800Prime",  # Actually a mixer, not SC6000
        "software": "JM08 v1.00",
        "discovery_packets": 74,
        "state_packets": 34,
        "beat_packets": 0,
        "date": "2022-09-03",
    }

    # Parse discovery packet to verify device info
    packet_data = bytes.fromhex(SC6000_DISCOVERY_PACKET)
    reader = io.BytesIO(packet_data)
    msg = DiscoveryMessage(Token())
    msg.read_from(reader)

    assert msg.source == "DN-X1800Prime"
    assert msg.software_name == "JM08"
    assert msg.software_version == "1.00"
