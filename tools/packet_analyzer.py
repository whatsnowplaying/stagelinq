#!/usr/bin/env python3
"""StageLinq packet capture analyzer."""

from __future__ import annotations

import argparse
import io
import json
import logging
import struct
import sys
from pathlib import Path
from typing import Any

try:
    import scapy.all as scapy
except ImportError:
    print("scapy is required for packet analysis. Install with: pip install scapy")
    sys.exit(1)

from stagelinq.messages import (
    DiscoveryMessage,
    StateEmitMessage,
    StateSubscribeMessage,
    ServiceAnnouncementMessage,
    Token,
    DISCOVERY_MAGIC,
    SMAA_MAGIC,
)
from stagelinq.beat_info import BeatInfoConnection
from unittest.mock import Mock

logger = logging.getLogger(__name__)


class PacketAnalyzer:
    """Analyzer for StageLinq packet captures."""

    def __init__(self, pcap_file: Path) -> None:
        self.pcap_file = pcap_file
        self.packets = []
        self.discovery_messages = []
        self.state_messages = []
        self.beat_messages = []
        self.service_messages = []

    def load_packets(self) -> None:
        """Load packets from PCAP file."""
        try:
            self.packets = scapy.rdpcap(str(self.pcap_file))
            logger.info(f"Loaded {len(self.packets)} packets from {self.pcap_file}")
        except Exception as e:
            logger.error(f"Failed to load PCAP file: {e}")
            raise

    def analyze_discovery_packets(self) -> None:
        """Analyze UDP discovery packets on port 51337."""
        for packet in self.packets:
            if not packet.haslayer(scapy.UDP):
                continue

            udp = packet[scapy.UDP]
            if udp.dport != 51337 and udp.sport != 51337:
                continue

            payload = bytes(udp.payload)
            if not payload.startswith(DISCOVERY_MAGIC):
                continue

            try:
                reader = io.BytesIO(payload)
                msg = DiscoveryMessage(Token())
                msg.read_from(reader)

                self.discovery_messages.append({
                    'timestamp': float(packet.time),
                    'src_ip': packet[scapy.IP].src,
                    'dst_ip': packet[scapy.IP].dst,
                    'message': {
                        'source': msg.source,
                        'action': msg.action,
                        'software_name': msg.software_name,
                        'software_version': msg.software_version,
                        'port': msg.port,
                        'token': msg.token.data.hex()
                    },
                    'raw_data': payload.hex()
                })

                logger.debug(f"Parsed discovery message from {msg.source}")

            except Exception as e:
                logger.warning(f"Failed to parse discovery packet: {e}")

    def analyze_service_messages(self) -> None:
        """Analyze TCP service announcement messages."""
        for packet in self.packets:
            if not packet.haslayer(scapy.TCP):
                continue

            tcp = packet[scapy.TCP]
            payload = bytes(tcp.payload)

            if len(payload) < 24:  # Minimum size for service announcement
                continue

            # Skip packets that look like state messages (contain SMAA magic)
            if SMAA_MAGIC in payload:
                continue

            # Skip packets that look like beat messages (contain 0x00000002 marker)
            if len(payload) >= 8 and payload[4:8] == b'\x00\x00\x00\x02':
                continue

            # Skip packets that are clearly not service announcements
            # Service announcements should start with a token (16 bytes) followed by message ID
            # and have a reasonable structure
            if len(payload) < 20:  # Need at least token + message ID
                continue

            try:

                # Try to parse as length-prefixed message
                if len(payload) >= 4:
                    # Check if first 4 bytes are a reasonable length
                    length = struct.unpack(">I", payload[:4])[0]
                    if length == 0 or length > len(payload) - 4:
                        # Not a length-prefixed message, try direct parsing
                        reader = io.BytesIO(payload)
                    else:
                        # Length-prefixed message
                        if len(payload) < 4 + length:
                            continue
                        reader = io.BytesIO(payload[4:4+length])
                else:
                    reader = io.BytesIO(payload)

                # Try to parse as service announcement
                # Check for different message formats
                reader_pos = reader.tell()

                # First, try to parse as standard ServiceAnnouncementMessage
                try:
                    msg = ServiceAnnouncementMessage()
                    msg.read_from(reader)
                except:
                    # If that fails, try to parse as the variant we found in the TCP capture
                    reader.seek(reader_pos)
                    msg = self._parse_service_announcement_variant(reader)

                # Additional validation: service names should be reasonable
                if msg.service and len(msg.service) > 0 and len(msg.service) < 100:
                    # Check if service name contains mostly printable characters
                    printable_chars = sum(1 for c in msg.service if c.isprintable())
                    if printable_chars / len(msg.service) < 0.7:
                        continue  # Skip if too many non-printable characters

                self.service_messages.append({
                    'timestamp': float(packet.time),
                    'src_ip': packet[scapy.IP].src,
                    'dst_ip': packet[scapy.IP].dst,
                    'src_port': tcp.sport,
                    'dst_port': tcp.dport,
                    'message': {
                        'service': msg.service,
                        'port': msg.port,
                        'token': msg.token.data.hex()
                    },
                    'raw_data': payload.hex()
                })

                logger.debug(f"Parsed service announcement: {msg.service} on port {msg.port}")

            except Exception as e:
                # Only log if it's not a known non-service message type
                if len(payload) >= 4:
                    # Check if it's a TCP handshake or other protocol message
                    if payload[:4] == b'\x00\x00\x00\x00' or len(payload) < 10:
                        continue  # Skip obvious non-service messages
                logger.debug(f"Failed to parse service message: {e} (payload: {payload[:20].hex()})")

    def _parse_service_announcement_variant(self, reader) -> ServiceAnnouncementMessage:
        """Parse the service announcement variant found in TCP captures."""

        # Read token (16 bytes)
        token_data = reader.read(16)
        if len(token_data) != 16:
            raise ValueError("Failed to read token")

        token = Token(token_data)

        # Read message ID (4 bytes)
        msg_id_data = reader.read(4)
        if len(msg_id_data) != 4:
            raise ValueError("Failed to read message ID")

        msg_id = struct.unpack('>I', msg_id_data)[0]

        # Read the remaining data
        remaining_data = reader.read()
        if len(remaining_data) < 2:
            raise ValueError("Insufficient data for service announcement")

        # Port is the last 2 bytes
        port = struct.unpack('>H', remaining_data[-2:])[0]

        # Service name is UTF-16 between message ID and port
        service_name_bytes = remaining_data[:-2]

        try:
            service_name = service_name_bytes.decode('utf-16be')
        except Exception as e:
            raise ValueError(f"Failed to decode service name: {e}")

        # Create a ServiceAnnouncementMessage with the parsed data
        msg = ServiceAnnouncementMessage(token=token, service=service_name, port=port)
        return msg

    def analyze_state_packets(self) -> None:
        """Analyze TCP state map packets."""
        for packet in self.packets:
            if not packet.haslayer(scapy.TCP):
                continue

            tcp = packet[scapy.TCP]
            payload = bytes(tcp.payload)

            if len(payload) < 4:
                continue

            # Check for SMAA magic in payload
            if SMAA_MAGIC not in payload:
                continue

            try:

                # Read length prefix
                length = struct.unpack(">I", payload[:4])[0]
                if len(payload) < 4 + length:
                    continue

                # Parse state message - determine type by magic ID
                message_data = payload[4:4+length]
                reader = io.BytesIO(message_data)

                # Parse the message based on its magic ID
                parsed_msg = self._parse_state_message(reader)
                if parsed_msg:
                    self.state_messages.append({
                        'timestamp': float(packet.time),
                        'src_ip': packet[scapy.IP].src,
                        'dst_ip': packet[scapy.IP].dst,
                        'src_port': tcp.sport,
                        'dst_port': tcp.dport,
                        'message': parsed_msg,
                        'raw_data': payload[:4+length].hex()
                    })

                    logger.debug(f"Parsed state message: {parsed_msg.get('name', 'unknown')}")

            except Exception as e:
                logger.warning(f"Failed to parse state packet: {e}")

    def _parse_state_message(self, reader):
        """Parse state message based on magic ID."""

        # Peek at the magic ID to determine message type
        current_pos = reader.tell()

        # Skip SMAA magic
        smaa = reader.read(4)
        if smaa != SMAA_MAGIC:
            return None

        # Read magic ID
        magic_id = struct.unpack('>I', reader.read(4))[0]
        reader.seek(current_pos)

        try:
            if magic_id == 0x00000000:
                # StateEmitMessage
                msg = StateEmitMessage()
                msg.read_from(reader)
                return {
                    'type': 'state_emit',
                    'name': msg.name,
                    'json_data': msg.json_data
                }
            elif magic_id == 0x000007d2:
                # StateSubscribeMessage - parse manually since read_from expects length prefix
                reader.seek(current_pos)

                # Skip SMAA magic
                reader.read(4)

                # Skip magic ID
                reader.read(4)

                # Read name as UTF-16 string
                name_length = struct.unpack('>I', reader.read(4))[0]
                name_data = reader.read(name_length)
                name = name_data.decode('utf-16be')

                # Read interval
                interval = struct.unpack('>I', reader.read(4))[0]

                return {
                    'type': 'state_subscribe',
                    'name': name,
                    'interval': interval
                }
            else:
                # Unknown magic ID
                return {
                    'type': 'unknown_state',
                    'magic_id': f'0x{magic_id:08x}',
                    'name': 'unknown'
                }
        except Exception as e:
            return {
                'type': 'parse_error',
                'error': str(e),
                'magic_id': f'0x{magic_id:08x}',
                'name': 'error'
            }

    def analyze_beat_packets(self) -> None:
        """Analyze TCP beat info packets using the core BeatInfo parsing."""

        # Create a mock connection to use the parsing method
        mock_socket = Mock()
        mock_socket.makefile.return_value = Mock()
        token = Token(b"\x00" * 16)
        temp_conn = BeatInfoConnection(mock_socket, token)

        for packet in self.packets:
            if not packet.haslayer(scapy.TCP):
                continue

            tcp = packet[scapy.TCP]
            payload = bytes(tcp.payload)

            if len(payload) < 4:
                continue

            try:

                # Read length prefix
                length = struct.unpack(">I", payload[:4])[0]
                if len(payload) < 4 + length:
                    continue

                # Get the message data (skip the 4-byte length prefix)
                message_data = payload[4:4+length]

                # Use the core BeatInfo parsing from beat_info.py
                beat_info = temp_conn._parse_beat_info_message(message_data)
                if beat_info:
                    self.beat_messages.append({
                        'timestamp': float(packet.time),
                        'src_ip': packet[scapy.IP].src,
                        'dst_ip': packet[scapy.IP].dst,
                        'src_port': tcp.sport,
                        'dst_port': tcp.dport,
                        'message': {
                            'clock': beat_info.clock,
                            'players': [
                                {
                                    'beat': p.beat,
                                    'total_beats': p.total_beats,
                                    'bpm': p.bpm
                                } for p in beat_info.players
                            ],
                            'timelines': beat_info.timelines
                        },
                        'raw_data': payload[:4+length].hex()
                    })

                    logger.debug(f"Parsed beat message: clock={beat_info.clock}")

            except Exception as e:
                logger.warning(f"Failed to parse beat packet: {e}")

        # Clean up the temporary connection
        temp_conn.close()




    def analyze_all(self) -> None:
        """Analyze all packet types."""
        self.load_packets()
        self.analyze_discovery_packets()
        self.analyze_service_messages()
        self.analyze_state_packets()
        self.analyze_beat_packets()

    def generate_test_data(self) -> dict[str, Any]:
        """Generate test data from analyzed packets."""
        return {
            'discovery_messages': self.discovery_messages,
            'service_messages': self.service_messages,
            'state_messages': self.state_messages,
            'beat_messages': self.beat_messages,
            'summary': {
                'total_packets': len(self.packets),
                'discovery_count': len(self.discovery_messages),
                'service_count': len(self.service_messages),
                'state_count': len(self.state_messages),
                'beat_count': len(self.beat_messages)
            }
        }

    def extract_sample_packets(self, count: int = 5) -> dict[str, list[str]]:
        """Extract sample packet data for unit tests."""
        return {
            'discovery_packets': [
                msg['raw_data'] for msg in self.discovery_messages[:count]
            ],
            'service_packets': [
                msg['raw_data'] for msg in self.service_messages[:count]
            ],
            'state_packets': [
                msg['raw_data'] for msg in self.state_messages[:count]
            ],
            'beat_packets': [
                msg['raw_data'] for msg in self.beat_messages[:count]
            ]
        }


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Analyze StageLinq packet captures")
    parser.add_argument("pcap_file", type=Path, help="Path to PCAP file")
    parser.add_argument("--output", "-o", type=Path, help="Output JSON file")
    parser.add_argument("--samples", "-s", type=Path, help="Output sample packets for tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

    if not args.pcap_file.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)

    # Analyze packets
    analyzer = PacketAnalyzer(args.pcap_file)
    analyzer.analyze_all()

    # Print summary
    print(f"\nPacket Analysis Summary:")
    print(f"Total packets: {len(analyzer.packets)}")
    print(f"Discovery messages: {len(analyzer.discovery_messages)}")
    print(f"Service messages: {len(analyzer.service_messages)}")
    print(f"State messages: {len(analyzer.state_messages)}")
    print(f"Beat messages: {len(analyzer.beat_messages)}")

    # Show sample discovery messages
    if analyzer.discovery_messages:
        print(f"\nSample Discovery Messages:")
        for msg in analyzer.discovery_messages[:3]:
            print(f"  {msg['message']['source']} ({msg['message']['software_name']} {msg['message']['software_version']})")

    # Show sample service messages
    if analyzer.service_messages:
        print(f"\nSample Service Messages:")
        for msg in analyzer.service_messages[:3]:
            print(f"  {msg['message']['service']} on port {msg['message']['port']}")

    # Show sample state messages with parsed JSON
    if analyzer.state_messages:
        print(f"\nState Messages:")
        # Group messages by type for better display
        track_info = {}
        deck_states = {}
        other_states = {}

        for msg in analyzer.state_messages:
            msg_data = msg['message']
            if msg_data['type'] == 'state_emit':
                name = msg_data['name']
                json_data = msg_data['json_data']

                # Parse JSON data for display
                try:
                    parsed = json.loads(json_data)

                    # Categorize important state information
                    if '/Track/CurrentBPM' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        track_info[f'{deck}_BPM'] = parsed.get('value', 0)
                    elif '/Track/Title' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        track_info[f'{deck}_Title'] = parsed.get('string', parsed.get('value', ''))
                    elif '/Track/Artist' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        track_info[f'{deck}_Artist'] = parsed.get('string', parsed.get('value', ''))
                    elif '/Track/Album' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        track_info[f'{deck}_Album'] = parsed.get('string', parsed.get('value', ''))
                    elif '/Track/TrackName' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        track_info[f'{deck}_TrackName'] = parsed.get('string', parsed.get('value', ''))
                    elif '/Track/ArtistName' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        track_info[f'{deck}_ArtistName'] = parsed.get('string', parsed.get('value', ''))
                    elif '/PlayState' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        deck_states[f'{deck}_Playing'] = parsed.get('state', False)
                    elif '/DeckIsMaster' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        deck_states[f'{deck}_Master'] = parsed.get('state', False)
                    elif '/MasterTempo' in name:
                        other_states['Master_Tempo'] = parsed.get('value', 0)
                    elif '/LoopEnableState' in name:
                        deck = 'Deck1' if 'Deck1' in name else 'Deck2'
                        deck_states[f'{deck}_Loop'] = parsed.get('state', False)
                    elif 'ChannelAssignment' in name:
                        channel = name.split('/')[-1]
                        other_states[channel] = parsed.get('string', '')
                    else:
                        # Show first few characters of other state names
                        display_name = name.split('/')[-1] if '/' in name else name
                        if len(display_name) > 20:
                            display_name = display_name[:20] + "..."
                        other_states[display_name] = str(parsed)[:30] + "..." if len(str(parsed)) > 30 else str(parsed)

                except json.JSONDecodeError:
                    # If JSON parsing fails, show raw data
                    display_name = name.split('/')[-1] if '/' in name else name
                    other_states[display_name] = json_data[:30] + "..."

            elif msg_data['type'] == 'state_subscribe':
                other_states[f"Subscribe_{msg_data['name'].split('/')[-1]}"] = f"interval: {msg_data['interval']}"

        # Display categorized information
        if track_info:
            print("  Track Info:")
            for key, value in track_info.items():
                print(f"    {key}: {value}")

        if deck_states:
            print("  Deck States:")
            for key, value in deck_states.items():
                print(f"    {key}: {value}")

        if other_states:
            print("  Other States:")
            for key, value in list(other_states.items())[:5]:  # Show first 5
                print(f"    {key}: {value}")
            if len(other_states) > 5:
                print(f"    ... and {len(other_states) - 5} more")

    # Show sample beat messages
    if analyzer.beat_messages:
        print(f"\nSample Beat Messages:")
        for msg in analyzer.beat_messages[:3]:
            players = len(msg['message']['players'])
            clock = msg['message']['clock']
            print(f"  Clock: {clock}, Players: {players}")

    # Output full analysis
    if args.output:
        test_data = analyzer.generate_test_data()
        with open(args.output, 'w') as f:
            json.dump(test_data, f, indent=2)
        logger.info(f"Full analysis saved to {args.output}")

    # Output sample packets for tests
    if args.samples:
        samples = analyzer.extract_sample_packets()
        with open(args.samples, 'w') as f:
            json.dump(samples, f, indent=2)
        logger.info(f"Sample packets saved to {args.samples}")


if __name__ == "__main__":
    main()