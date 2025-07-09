"""Tests for StageLinq message parsing using authoritative SC6000 packet captures."""

from __future__ import annotations

import io
import json
import struct
import pytest
import binascii
from pathlib import Path

from stagelinq.messages import (
    Token,
    DiscoveryMessage,
    StateSubscribeMessage,
    StateEmitMessage,
    BeatEmitMessage,
    PlayerInfo,
    ServiceAnnouncementMessage,
    ReferenceMessage,
    ServicesRequestMessage,
    DISCOVERER_HOWDY,
    DISCOVERER_EXIT,
    DISCOVERY_MAGIC,
    SMAA_MAGIC,
    BEAT_EMIT_MAGIC,
)


@pytest.fixture
def sc6000_packet_data():
    """Load real SC6000 packet capture data."""
    packets_file = Path(__file__).parent.parent.parent / "sc6000_packets.json"
    with open(packets_file, 'r') as f:
        return json.load(f)


class TestTokenWithSC6000Data:
    """Test token functionality using real SC6000 data."""
    
    def test_token_creation_16_bytes(self):
        """Test token creation with correct 16-byte size."""
        # Test random token generation
        token1 = Token()
        token2 = Token()
        assert token1 != token2
        assert len(token1.data) == 16  # SC6000 uses 16-byte tokens
        assert len(token2.data) == 16
    
    def test_token_from_sc6000_data(self, sc6000_packet_data):
        """Test token creation from real SC6000 packet data."""
        # Extract token from real SC6000 packet
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        # Token is bytes 4-20 (after magic bytes)
        real_token_data = packet_bytes[4:20]
        assert len(real_token_data) == 16
        
        # Create token from real data
        token = Token(real_token_data)
        assert token.data == real_token_data
        assert bytes(token) == real_token_data
    
    def test_token_invalid_length(self):
        """Test token validation with incorrect lengths."""
        # 32-byte token should fail (old assumption)
        with pytest.raises(ValueError, match="Token must be exactly 16 bytes"):
            Token(b"a" * 32)  # This should fail with 32 bytes
        
        # Too short should fail
        with pytest.raises(ValueError, match="Token must be exactly 16 bytes"):
            Token(b"too short")
        
        # Just right should work
        token = Token(b"a" * 16)
        assert len(token.data) == 16
    
    def test_token_string_representation(self, sc6000_packet_data):
        """Test token string representation with real data."""
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        real_token_data = packet_bytes[4:20]
        
        token = Token(real_token_data)
        expected_hex = real_token_data.hex()
        assert str(token) == expected_hex


class TestDiscoveryMessageWithSC6000Data:
    """Test discovery message functionality using real SC6000 data."""
    
    def test_discovery_message_parsing_real_data(self, sc6000_packet_data):
        """Test parsing of real SC6000 discovery message."""
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        # Parse the real packet
        message = DiscoveryMessage.deserialize(packet_bytes)
        
        # Verify against known SC6000 characteristics
        assert message.source == "DN-X1800Prime"
        assert message.software_name == "JM08"
        assert message.software_version == "1.00"
        assert message.action == DISCOVERER_HOWDY
        assert message.port == 50010
        assert len(message.token.data) == 16
    
    def test_discovery_message_roundtrip_sc6000(self, sc6000_packet_data):
        """Test round-trip serialization with real SC6000 data."""
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        original_bytes = binascii.unhexlify(packet_hex)
        
        # Parse and re-serialize
        message = DiscoveryMessage.deserialize(original_bytes)
        serialized_bytes = message.serialize()
        
        # Should be identical
        assert serialized_bytes == original_bytes
    
    def test_discovery_message_all_packets_consistent(self, sc6000_packet_data):
        """Test that all discovery packets are consistent."""
        packets = sc6000_packet_data["discovery_packets"]
        
        # Parse all packets
        messages = []
        for packet_hex in packets:
            packet_bytes = binascii.unhexlify(packet_hex)
            message = DiscoveryMessage.deserialize(packet_bytes)
            messages.append(message)
        
        # All should be identical (same device)
        first_message = messages[0]
        for message in messages[1:]:
            assert message.source == first_message.source
            assert message.software_name == first_message.software_name
            assert message.software_version == first_message.software_version
            assert message.action == first_message.action
            assert message.port == first_message.port
            assert message.token == first_message.token
    
    def test_discovery_message_magic_bytes(self, sc6000_packet_data):
        """Test that discovery messages have correct magic bytes."""
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        # Should start with "airD"
        assert packet_bytes[0:4] == DISCOVERY_MAGIC
        
        # Parse and verify magic is preserved
        message = DiscoveryMessage.deserialize(packet_bytes)
        serialized = message.serialize()
        assert serialized[0:4] == DISCOVERY_MAGIC
    
    def test_discovery_message_utf16_encoding(self, sc6000_packet_data):
        """Test UTF-16 encoding in discovery messages."""
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        message = DiscoveryMessage.deserialize(packet_bytes)
        serialized = message.serialize()
        
        # Device name should be encoded in UTF-16BE
        device_name_utf16 = message.source.encode('utf-16be')
        assert device_name_utf16 in serialized
        
        # Software name should be encoded in UTF-16BE  
        software_name_utf16 = message.software_name.encode('utf-16be')
        assert software_name_utf16 in serialized


class TestStateMessagesWithSC6000Data:
    """Test state message functionality using real SC6000 data."""
    
    def test_state_subscribe_message_parsing(self, sc6000_packet_data):
        """Test parsing of real SC6000 state subscribe messages."""
        # Find state subscribe packets (magic ID 0x000007d2)
        for packet_hex in sc6000_packet_data["state_packets"]:
            packet_bytes = binascii.unhexlify(packet_hex)
            magic_id = struct.unpack('>I', packet_bytes[8:12])[0]
            
            if magic_id == 0x000007d2:  # State subscribe
                message = StateSubscribeMessage.deserialize(packet_bytes)
                
                # Verify against known SC6000 state names
                assert message.name in [
                    "/Mixer/NumberOfChannels",
                    "/Engine/Deck1/Track/CurrentBPM",
                    "/Engine/Deck2/Track/CurrentBPM",
                    "/Client/Preferences/PlayerJogColorA"
                ]
                
                # Interval should be set appropriately
                assert isinstance(message.interval, int)
                break
        else:
            pytest.fail("No state subscribe packets found in SC6000 data")
    
    def test_state_emit_message_parsing(self, sc6000_packet_data):
        """Test parsing of real SC6000 state emit messages."""
        # Find state emit packets (magic ID 0x00000000)
        for packet_hex in sc6000_packet_data["state_packets"]:
            packet_bytes = binascii.unhexlify(packet_hex)
            magic_id = struct.unpack('>I', packet_bytes[8:12])[0]
            
            if magic_id == 0x00000000:  # State emit
                message = StateEmitMessage.deserialize(packet_bytes)
                
                # Should be BPM data from real SC6000
                assert message.name == "/Engine/Deck1/Track/CurrentBPM"
                
                # JSON data should be valid
                bpm_data = json.loads(message.json_data)
                assert bpm_data["type"] == 0
                assert bpm_data["value"] == 121.9754638671875
                break
        else:
            pytest.fail("No state emit packets found in SC6000 data")
    
    def test_state_message_smaa_magic(self, sc6000_packet_data):
        """Test that state messages have correct SMAA magic."""
        packet_hex = sc6000_packet_data["state_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        # Should have SMAA magic at position 4-8
        assert packet_bytes[4:8] == SMAA_MAGIC


class TestProtocolConstantsWithSC6000Data:
    """Test protocol constants against real SC6000 data."""
    
    def test_discovery_magic_constant(self, sc6000_packet_data):
        """Test that DISCOVERY_MAGIC matches real data."""
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        # First 4 bytes should match our constant
        assert packet_bytes[0:4] == DISCOVERY_MAGIC
        assert DISCOVERY_MAGIC == b"airD"
    
    def test_smaa_magic_constant(self, sc6000_packet_data):
        """Test that SMAA_MAGIC matches real data."""
        packet_hex = sc6000_packet_data["state_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        # Bytes 4-8 should match our constant
        assert packet_bytes[4:8] == SMAA_MAGIC
        assert SMAA_MAGIC == b"smaa"
    
    def test_discoverer_howdy_constant(self, sc6000_packet_data):
        """Test that DISCOVERER_HOWDY matches real data."""
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        message = DiscoveryMessage.deserialize(packet_bytes)
        assert message.action == DISCOVERER_HOWDY
        assert DISCOVERER_HOWDY == "DISCOVERER_HOWDY_"


class TestRealWorldCompatibility:
    """Test real-world compatibility with SC6000 data."""
    
    def test_packet_capture_metadata(self, sc6000_packet_data):
        """Test that packet capture metadata is correct."""
        summary = sc6000_packet_data["summary"]
        
        # Verify capture statistics match real data
        assert summary["total_discovery"] == 74
        assert summary["total_state"] == 34
        assert summary["total_beat"] == 0
        assert summary["capture_file"] == "sc6000_boot_2022-09-03_01.pcap"
    
    def test_real_device_characteristics(self, sc6000_packet_data):
        """Test that we correctly identify real SC6000 characteristics."""
        packet_hex = sc6000_packet_data["discovery_packets"][0]
        packet_bytes = binascii.unhexlify(packet_hex)
        message = DiscoveryMessage.deserialize(packet_bytes)
        
        # These are the actual characteristics from the real device
        assert message.source == "DN-X1800Prime"
        assert message.software_name == "JM08"
        assert message.software_version == "1.00"
        assert message.port == 50010
        assert len(message.token.data) == 16
    
    def test_all_packets_parseable(self, sc6000_packet_data):
        """Test that all packets in the capture are parseable."""
        # Test all discovery packets
        for packet_hex in sc6000_packet_data["discovery_packets"]:
            packet_bytes = binascii.unhexlify(packet_hex)
            message = DiscoveryMessage.deserialize(packet_bytes)
            assert message.source == "DN-X1800Prime"
        
        # Test all state packets
        for packet_hex in sc6000_packet_data["state_packets"]:
            packet_bytes = binascii.unhexlify(packet_hex)
            magic_id = struct.unpack('>I', packet_bytes[8:12])[0]
            
            if magic_id == 0x000007d2:  # State subscribe
                message = StateSubscribeMessage.deserialize(packet_bytes)
                assert message.name.startswith("/")
            elif magic_id == 0x00000000:  # State emit
                message = StateEmitMessage.deserialize(packet_bytes)
                assert message.name.startswith("/")
    
    @pytest.mark.parametrize("packet_index", range(5))
    def test_discovery_packet_consistency(self, sc6000_packet_data, packet_index):
        """Test that all discovery packets have consistent format."""
        packet_hex = sc6000_packet_data["discovery_packets"][packet_index]
        packet_bytes = binascii.unhexlify(packet_hex)
        
        # Should parse without error
        message = DiscoveryMessage.deserialize(packet_bytes)
        
        # Should have consistent device info
        assert message.source == "DN-X1800Prime"
        assert message.action == DISCOVERER_HOWDY
        assert message.port == 50010
        assert len(message.token.data) == 16


if __name__ == "__main__":
    pytest.main([__file__, "-v"])