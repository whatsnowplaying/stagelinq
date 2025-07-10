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

# Add the parent directory to the path so we can import the local stagelinq module
sys.path.insert(0, str(Path(__file__).parent.parent))

from stagelinq.device import DeviceRegistry
from stagelinq.discovery import Device
from stagelinq.file_transfer import FLTX_MAGIC, FileAnnouncementMessage
from stagelinq.messages import (
    DISCOVERY_MAGIC,
    SMAA_MAGIC,
    BeatEmitMessage,
    BeatInfoStartStreamMessage,
    BeatInfoStopStreamMessage,
    DiscoveryMessage,
    ServiceAnnouncementMessage,
    StateEmitMessage,
    Token,
    format_interval,
    parse_beat_message,
)

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
        self.other_messages = []
        self.device_registry = DeviceRegistry()

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

                self.discovery_messages.append(
                    {
                        "timestamp": float(packet.time),
                        "src_ip": packet[scapy.IP].src,
                        "dst_ip": packet[scapy.IP].dst,
                        "message": {
                            "source": msg.source,
                            "action": msg.action,
                            "software_name": msg.software_name,
                            "software_version": msg.software_version,
                            "port": msg.port,
                            "token": msg.token.data.hex(),
                        },
                        "raw_data": payload.hex(),
                    }
                )

                # Register device in registry
                device = Device(
                    ip=packet[scapy.IP].src,
                    name=msg.source,
                    software_name=msg.software_name,
                    software_version=msg.software_version,
                    port=msg.port,
                    token=msg.token,
                )
                self.device_registry.add_device(device)

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
            if len(payload) >= 8 and payload[4:8] == b"\x00\x00\x00\x02":
                continue

            # Check if this is a file announcement (fltx) message
            if len(payload) >= 8 and payload[4:8] == FLTX_MAGIC:
                try:
                    file_msg = FileAnnouncementMessage.deserialize(payload)
                    # Convert to service announcement format for compatibility
                    msg = ServiceAnnouncementMessage()
                    msg.service = f"File: {file_msg.path}"
                    msg.port = (
                        file_msg.message_type
                    )  # Use message type as port for display
                    msg.token = Token(b"\x00" * 16)  # Placeholder token

                    self.service_messages.append(
                        {
                            "timestamp": float(packet.time),
                            "src_ip": packet[scapy.IP].src,
                            "dst_ip": packet[scapy.IP].dst,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "message": {
                                "service": msg.service,
                                "port": msg.port,
                                "token": msg.token.data.hex(),
                            },
                            "raw_data": payload.hex(),
                        }
                    )
                    continue
                except Exception as e:
                    logger.warning(f"Failed to parse file announcement: {e}")
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
                    elif len(payload) < 4 + length:
                        continue
                    else:
                        reader = io.BytesIO(payload[4 : 4 + length])
                else:
                    reader = io.BytesIO(payload)

                # Try to parse as service announcement
                # Check for different message formats
                reader_pos = reader.tell()

                # First, try to parse as standard ServiceAnnouncementMessage
                try:
                    msg = ServiceAnnouncementMessage()
                    msg.read_from(reader)
                except Exception:
                    # If that fails, try to parse as the variant we found in the TCP capture
                    reader.seek(reader_pos)
                    msg = self._parse_service_announcement_variant(reader)

                # Additional validation: service names should be reasonable
                if msg.service and len(msg.service) > 0 and len(msg.service) < 100:
                    # Check if service name contains mostly printable characters
                    printable_chars = sum(bool(c.isprintable()) for c in msg.service)
                    if printable_chars / len(msg.service) < 0.7:
                        continue  # Skip if too many non-printable characters

                self.service_messages.append(
                    {
                        "timestamp": float(packet.time),
                        "src_ip": packet[scapy.IP].src,
                        "dst_ip": packet[scapy.IP].dst,
                        "src_port": tcp.sport,
                        "dst_port": tcp.dport,
                        "message": {
                            "service": msg.service,
                            "port": msg.port,
                            "token": msg.token.data.hex(),
                        },
                        "raw_data": payload.hex(),
                    }
                )

                logger.debug(
                    f"Parsed service announcement: {msg.service} on port {msg.port}"
                )

            except Exception as e:
                # Only log if it's not a known non-service message type
                if len(payload) >= 4 and (
                    payload[:4] == b"\x00\x00\x00\x00" or len(payload) < 10
                ):
                    continue
                logger.debug(
                    f"Failed to parse service message: {e} (payload: {payload[:20].hex()})"
                )

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

        msg_id = struct.unpack(">I", msg_id_data)[0]

        # Read the remaining data
        remaining_data = reader.read()
        if len(remaining_data) < 2:
            raise ValueError("Insufficient data for service announcement")

        # Port is the last 2 bytes
        port = struct.unpack(">H", remaining_data[-2:])[0]

        # Service name is UTF-16 between message ID and port
        service_name_bytes = remaining_data[:-2]

        try:
            service_name = service_name_bytes.decode("utf-16be")
        except Exception as e:
            raise ValueError(f"Failed to decode service name: {e}") from e

        return ServiceAnnouncementMessage(token=token, service=service_name, port=port)

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
                message_data = payload[4 : 4 + length]
                reader = io.BytesIO(message_data)

                if parsed_msg := self._parse_state_message(reader):
                    self.state_messages.append(
                        {
                            "timestamp": float(packet.time),
                            "src_ip": packet[scapy.IP].src,
                            "dst_ip": packet[scapy.IP].dst,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "message": parsed_msg,
                            "raw_data": payload[: 4 + length].hex(),
                        }
                    )

                    logger.debug(
                        f"Parsed state message: {parsed_msg.get('name', 'unknown')}"
                    )

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
        magic_id = struct.unpack(">I", reader.read(4))[0]
        reader.seek(current_pos)

        try:
            if magic_id == 0x00000000:
                # StateEmitMessage
                msg = StateEmitMessage()
                msg.read_from(reader)
                return {
                    "type": "state_emit",
                    "name": msg.name,
                    "json_data": msg.json_data,
                }
            elif magic_id == 0x000007D2:
                # StateSubscribeMessage - parse manually since read_from expects length prefix
                reader.seek(current_pos)

                # Skip SMAA magic
                reader.read(4)

                # Skip magic ID
                reader.read(4)

                # Read name as UTF-16 string
                name_length = struct.unpack(">I", reader.read(4))[0]
                name_data = reader.read(name_length)
                name = name_data.decode("utf-16be")

                # Read interval
                interval = struct.unpack(">I", reader.read(4))[0]

                return {"type": "state_subscribe", "name": name, "interval": interval}
            else:
                # Unknown magic ID
                return {
                    "type": "unknown_state",
                    "magic_id": f"0x{magic_id:08x}",
                    "name": "unknown",
                }
        except Exception as e:
            return {
                "type": "parse_error",
                "error": str(e),
                "magic_id": f"0x{magic_id:08x}",
                "name": "error",
            }

    def analyze_beat_packets(self) -> None:
        """Analyze TCP beat info packets using the core BeatInfo parsing."""

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

                # Use the utility function to parse beat messages
                beat_msg = parse_beat_message(payload[: 4 + length])
                if beat_msg is None:
                    continue

                # Handle different message types
                if isinstance(beat_msg, BeatInfoStartStreamMessage):
                    self.beat_messages.append(
                        {
                            "timestamp": float(packet.time),
                            "src_ip": packet[scapy.IP].src,
                            "dst_ip": packet[scapy.IP].dst,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "message_type": "start_stream",
                            "raw_data": payload[: 4 + length].hex(),
                        }
                    )
                    logger.debug("Parsed beat start stream message")

                elif isinstance(beat_msg, BeatInfoStopStreamMessage):
                    self.beat_messages.append(
                        {
                            "timestamp": float(packet.time),
                            "src_ip": packet[scapy.IP].src,
                            "dst_ip": packet[scapy.IP].dst,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "message_type": "stop_stream",
                            "raw_data": payload[: 4 + length].hex(),
                        }
                    )
                    logger.debug("Parsed beat stop stream message")

                elif isinstance(beat_msg, BeatEmitMessage):
                    self.beat_messages.append(
                        {
                            "timestamp": float(packet.time),
                            "src_ip": packet[scapy.IP].src,
                            "dst_ip": packet[scapy.IP].dst,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "message": {
                                "clock": beat_msg.clock,
                                "players": [
                                    {
                                        "beat": p.beat,
                                        "total_beats": p.total_beats,
                                        "bpm": p.bpm,
                                    }
                                    for p in beat_msg.players
                                ],
                                "timelines": beat_msg.timelines,
                            },
                            "raw_data": payload[: 4 + length].hex(),
                        }
                    )
                    logger.debug(f"Parsed beat message: clock={beat_msg.clock}")

            except Exception:
                # Skip packets that don't have valid length prefixes
                pass

    def analyze_other_packets(self) -> None:
        """Analyze unrecognized packets with data payloads."""

        processed_packets = {msg["timestamp"] for msg in self.discovery_messages}
        # Add service packet timestamps
        for msg in self.service_messages:
            processed_packets.add(msg["timestamp"])

        # Add state packet timestamps
        for msg in self.state_messages:
            processed_packets.add(msg["timestamp"])

        # Add beat packet timestamps
        for msg in self.beat_messages:
            processed_packets.add(msg["timestamp"])

        # Look for unprocessed packets with data
        for packet in self.packets:
            timestamp = float(packet.time)
            if timestamp in processed_packets:
                continue

            # Check TCP packets with data payloads
            if packet.haslayer(scapy.TCP):
                tcp = packet[scapy.TCP]
                payload = bytes(tcp.payload)

                # Only look at packets with meaningful data (8+ bytes)
                if len(payload) >= 8:
                    self.other_messages.append(
                        {
                            "timestamp": timestamp,
                            "src_ip": packet[scapy.IP].src,
                            "dst_ip": packet[scapy.IP].dst,
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "protocol": "TCP",
                            "payload_length": len(payload),
                            "payload_hex": payload[:32].hex(),  # First 32 bytes
                            "payload_ascii": "".join(
                                chr(b) if 32 <= b <= 126 else "." for b in payload[:32]
                            ),
                            "raw_data": payload.hex(),
                        }
                    )

            # Check UDP packets (non-discovery)
            elif packet.haslayer(scapy.UDP):
                udp = packet[scapy.UDP]
                payload = bytes(udp.payload)

                # Skip discovery packets (port 51337)
                if udp.sport == 51337 or udp.dport == 51337:
                    continue

                if len(payload) >= 8:
                    self.other_messages.append(
                        {
                            "timestamp": timestamp,
                            "src_ip": packet[scapy.IP].src,
                            "dst_ip": packet[scapy.IP].dst,
                            "src_port": udp.sport,
                            "dst_port": udp.dport,
                            "protocol": "UDP",
                            "payload_length": len(payload),
                            "payload_hex": payload[:32].hex(),  # First 32 bytes
                            "payload_ascii": "".join(
                                chr(b) if 32 <= b <= 126 else "." for b in payload[:32]
                            ),
                            "raw_data": payload.hex(),
                        }
                    )

    def analyze_all(self) -> None:
        """Analyze all packet types."""
        self.load_packets()
        self.analyze_discovery_packets()
        self.analyze_service_messages()
        self.analyze_state_packets()
        self.analyze_beat_packets()
        self.analyze_other_packets()

    def generate_test_data(self) -> dict[str, Any]:
        """Generate test data from analyzed packets."""
        return {
            "discovery_messages": self.discovery_messages,
            "service_messages": self.service_messages,
            "state_messages": self.state_messages,
            "beat_messages": self.beat_messages,
            "other_messages": self.other_messages,
            "summary": {
                "total_packets": len(self.packets),
                "discovery_count": len(self.discovery_messages),
                "service_count": len(self.service_messages),
                "state_count": len(self.state_messages),
                "beat_count": len(self.beat_messages),
                "other_count": len(self.other_messages),
            },
        }

    def extract_sample_packets(self, count: int = 5) -> dict[str, list[str]]:
        """Extract sample packet data for unit tests."""
        return {
            "discovery_packets": [
                msg["raw_data"] for msg in self.discovery_messages[:count]
            ],
            "service_packets": [
                msg["raw_data"] for msg in self.service_messages[:count]
            ],
            "state_packets": [msg["raw_data"] for msg in self.state_messages[:count]],
            "beat_packets": [msg["raw_data"] for msg in self.beat_messages[:count]],
            "other_packets": [msg["raw_data"] for msg in self.other_messages[:count]],
        }


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Analyze StageLinq packet captures")
    parser.add_argument("pcap_file", type=Path, help="Path to PCAP file")
    parser.add_argument("--output", "-o", type=Path, help="Output JSON file")
    parser.add_argument(
        "--samples", "-s", type=Path, help="Output sample packets for tests"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--show",
        help="Show parsed message contents for types: discovery,services,states,beats,other (comma-separated)",
    )

    args = parser.parse_args()

    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s - %(levelname)s - %(message)s")

    if not args.pcap_file.exists():
        logger.error(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)

    # Parse show argument
    show_types = set()
    if args.show:
        show_types = set(args.show.lower().split(","))
        valid_types = {"discovery", "services", "states", "beats", "other"}
        if invalid_types := show_types - valid_types:
            logger.error(
                f"Invalid show types: {', '.join(invalid_types)}. Valid types: {', '.join(valid_types)}"
            )
            sys.exit(1)

    # Analyze packets
    analyzer = PacketAnalyzer(args.pcap_file)
    analyzer.analyze_all()

    # Calculate packet breakdown
    total_packets = len(analyzer.packets)
    discovery_count = len(analyzer.discovery_messages)
    service_count = len(analyzer.service_messages)
    state_count = len(analyzer.state_messages)
    beat_count = len(analyzer.beat_messages)
    other_count = len(analyzer.other_messages)

    # Calculate remaining packets
    accounted_packets = (
        discovery_count + service_count + state_count + beat_count + other_count
    )
    remaining_packets = total_packets - accounted_packets

    # Analyze remaining packets
    tcp_control_packets = 0
    udp_control_packets = 0
    small_packets = 0

    for packet in analyzer.packets:
        timestamp = float(packet.time)

        is_accounted = any(
            any(abs(msg["timestamp"] - timestamp) < 0.001 for msg in msg_list)
            for msg_list in [
                analyzer.discovery_messages,
                analyzer.service_messages,
                analyzer.state_messages,
                analyzer.beat_messages,
                analyzer.other_messages,
            ]
        )
        if is_accounted:
            continue

        # Categorize remaining packets
        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            payload = bytes(tcp.payload)
            if len(payload) < 8:
                if not payload:
                    tcp_control_packets += 1
                else:
                    small_packets += 1
        elif packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            payload = bytes(udp.payload)
            if len(payload) < 8 and (udp.sport != 51337 and udp.dport != 51337):
                udp_control_packets += 1

    # Print summary
    print("\nPacket Analysis Summary:")
    print(f"Total packets: {total_packets}")
    print(f"Discovery messages: {discovery_count}")
    print(f"Service messages: {service_count}")
    print(f"State messages: {state_count}")
    print(f"Beat messages: {beat_count}")
    print(f"Other messages: {other_count}")
    print(f"TCP control packets: {tcp_control_packets}")
    print(f"UDP control packets: {udp_control_packets}")
    print(f"Small packets: {small_packets}")
    print(
        f"Unaccounted packets: {remaining_packets - tcp_control_packets - udp_control_packets - small_packets}"
    )
    print("---")
    print(
        f"Total accounted: {accounted_packets + tcp_control_packets + udp_control_packets + small_packets + (remaining_packets - tcp_control_packets - udp_control_packets - small_packets)}"
    )

    # Show sample discovery messages
    if analyzer.discovery_messages:
        print("\nSample Discovery Messages:")
        for msg in analyzer.discovery_messages[:3]:
            print(
                f"  {msg['message']['source']} ({msg['message']['software_name']} {msg['message']['software_version']})"
            )

    # Show sample service messages
    if analyzer.service_messages:
        print("\nSample Service Messages:")
        for msg in analyzer.service_messages[:3]:
            print(f"  {msg['message']['service']} on port {msg['message']['port']}")

    # Show sample state messages with parsed JSON
    if analyzer.state_messages:
        print("\nState Messages:")
        # Group messages by type for better display
        track_info = {}
        deck_states = {}
        other_states = {}

        for msg in analyzer.state_messages:
            msg_data = msg["message"]
            if msg_data["type"] == "state_emit":
                name = msg_data["name"]
                json_data = msg_data["json_data"]

                # Parse JSON data for display
                try:
                    parsed = json.loads(json_data)

                    # Categorize important state information
                    if "/Track/CurrentBPM" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        track_info[f"{deck}_BPM"] = parsed.get("value", 0)
                    elif "/Track/Title" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        track_info[f"{deck}_Title"] = parsed.get(
                            "string", parsed.get("value", "")
                        )
                    elif "/Track/Artist" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        track_info[f"{deck}_Artist"] = parsed.get(
                            "string", parsed.get("value", "")
                        )
                    elif "/Track/Album" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        track_info[f"{deck}_Album"] = parsed.get(
                            "string", parsed.get("value", "")
                        )
                    elif "/Track/TrackName" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        track_info[f"{deck}_TrackName"] = parsed.get(
                            "string", parsed.get("value", "")
                        )
                    elif "/Track/ArtistName" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        track_info[f"{deck}_ArtistName"] = parsed.get(
                            "string", parsed.get("value", "")
                        )
                    elif "/PlayState" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        deck_states[f"{deck}_Playing"] = parsed.get("state", False)
                    elif "/DeckIsMaster" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        deck_states[f"{deck}_Master"] = parsed.get("state", False)
                    elif "/MasterTempo" in name:
                        other_states["Master_Tempo"] = parsed.get("value", 0)
                    elif "/LoopEnableState" in name:
                        deck = "Deck1" if "Deck1" in name else "Deck2"
                        deck_states[f"{deck}_Loop"] = parsed.get("state", False)
                    elif "ChannelAssignment" in name:
                        channel = name.split("/")[-1]
                        assignment_str = parsed.get("string", "")

                        # Use device registry to parse channel assignment
                        parsed_assignment = (
                            analyzer.device_registry.parse_channel_assignment(
                                assignment_str
                            )
                        )
                        other_states[channel] = parsed_assignment
                    else:
                        # Show first few characters of other state names
                        display_name = name.split("/")[-1] if "/" in name else name
                        if len(display_name) > 20:
                            display_name = f"{display_name[:20]}..."
                        other_states[display_name] = (
                            f"{str(parsed)[:30]}..."
                            if len(str(parsed)) > 30
                            else str(parsed)
                        )

                except json.JSONDecodeError:
                    # If JSON parsing fails, show raw data
                    display_name = name.split("/")[-1] if "/" in name else name
                    other_states[display_name] = f"{json_data[:30]}..."

            elif msg_data["type"] == "state_subscribe":
                interval = msg_data["interval"]
                interval_str = f"interval: {format_interval(interval)}"
                other_states[f"Subscribe_{msg_data['name'].split('/')[-1]}"] = (
                    interval_str
                )

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
            for key, value in other_states.items():
                print(f"    {key}: {value}")

    # Show sample beat messages
    if analyzer.beat_messages:
        print("\nSample Beat Messages:")
        for msg in analyzer.beat_messages[:3]:
            players = len(msg["message"]["players"])
            clock = msg["message"]["clock"]
            print(f"  Clock: {clock}, Players: {players}")

    # Output full analysis
    if args.output:
        test_data = analyzer.generate_test_data()
        with open(args.output, "w") as f:
            json.dump(test_data, f, indent=2)
        logger.info(f"Full analysis saved to {args.output}")

    # Output sample packets for tests
    if args.samples:
        samples = analyzer.extract_sample_packets()
        with open(args.samples, "w") as f:
            json.dump(samples, f, indent=2)
        logger.info(f"Sample packets saved to {args.samples}")

    # Show detailed message contents if requested
    if show_types:
        print("\n" + "=" * 60)
        print("DETAILED MESSAGE CONTENTS")
        print("=" * 60)

        if "discovery" in show_types and analyzer.discovery_messages:
            print(f"\nDISCOVERY MESSAGES ({len(analyzer.discovery_messages)}):")
            for i, msg in enumerate(analyzer.discovery_messages[:10]):  # Show first 10
                print(f"\n--- Discovery Message {i + 1} ---")
                print(f"Source: {msg['message']['source']}")
                print(
                    f"Software: {msg['message']['software_name']} {msg['message']['software_version']}"
                )
                print(f"Action: {msg['message']['action']}")
                print(f"Port: {msg['message']['port']}")
                print(f"Token: {msg['message']['token']}")
                print(f"From: {msg['src_ip']} -> {msg['dst_ip']}")
                print(f"Time: {msg['timestamp']}")
            if len(analyzer.discovery_messages) > 10:
                print(f"\n... and {len(analyzer.discovery_messages) - 10} more")

        if "services" in show_types and analyzer.service_messages:
            print(f"\nSERVICE MESSAGES ({len(analyzer.service_messages)}):")
            for i, msg in enumerate(analyzer.service_messages):
                print(f"\n--- Service Message {i + 1} ---")
                print(f"Service: {msg['message']['service']}")
                print(f"Port: {msg['message']['port']}")
                print(f"Token: {msg['message']['token']}")
                print(
                    f"From: {msg['src_ip']}:{msg['src_port']} -> {msg['dst_ip']}:{msg['dst_port']}"
                )
                print(f"Time: {msg['timestamp']}")

        if "states" in show_types and analyzer.state_messages:
            print(f"\nSTATE MESSAGES ({len(analyzer.state_messages)}):")
            for i, msg in enumerate(analyzer.state_messages[:20]):  # Show first 20
                print(f"\n--- State Message {i + 1} ---")
                state_data = msg["message"]
                if state_data["type"] == "state_emit":
                    print("Type: State Emit")
                    print(f"Name: {state_data['name']}")
                    print(f"JSON Data: {state_data['json_data']}")
                elif state_data["type"] == "state_subscribe":
                    print("Type: State Subscribe")
                    print(f"Name: {state_data['name']}")
                    print(f"Interval: {format_interval(state_data['interval'])}")
                else:
                    print(f"Type: {state_data['type']}")
                    print(f"Data: {state_data}")
                print(
                    f"From: {msg['src_ip']}:{msg['src_port']} -> {msg['dst_ip']}:{msg['dst_port']}"
                )
                print(f"Time: {msg['timestamp']}")
            if len(analyzer.state_messages) > 20:
                print(f"\n... and {len(analyzer.state_messages) - 20} more")

        if "beats" in show_types and analyzer.beat_messages:
            print(f"\nBEAT MESSAGES ({len(analyzer.beat_messages)}):")
            for i, msg in enumerate(analyzer.beat_messages[:10]):  # Show first 10
                print(f"\n--- Beat Message {i + 1} ---")
                if "message_type" in msg:
                    print(f"Type: {msg['message_type']}")
                else:
                    print("Type: Beat Emit")
                    beat_data = msg["message"]
                    print(f"Clock: {beat_data['clock']}")
                    print(f"Players: {len(beat_data['players'])}")
                    for j, player in enumerate(beat_data["players"]):
                        print(
                            f"  Player {j + 1}: beat={player['beat']:.2f}, bpm={player['bpm']:.1f}, total_beats={player['total_beats']:.0f}"
                        )
                    print(f"Timelines: {len(beat_data['timelines'])} entries")
                print(
                    f"From: {msg['src_ip']}:{msg['src_port']} -> {msg['dst_ip']}:{msg['dst_port']}"
                )
                print(f"Time: {msg['timestamp']}")
            if len(analyzer.beat_messages) > 10:
                print(f"\n... and {len(analyzer.beat_messages) - 10} more")

        if "other" in show_types and analyzer.other_messages:
            print(f"\nOTHER MESSAGES ({len(analyzer.other_messages)}):")
            for i, msg in enumerate(analyzer.other_messages[:20]):  # Show first 20
                print(f"\n--- Other Message {i + 1} ---")
                print(f"Protocol: {msg['protocol']}")
                print(f"Payload Length: {msg['payload_length']} bytes")
                print(f"Hex: {msg['payload_hex']}")
                print(f"ASCII: {msg['payload_ascii']}")
                print(
                    f"From: {msg['src_ip']}:{msg['src_port']} -> {msg['dst_ip']}:{msg['dst_port']}"
                )
                print(f"Time: {msg['timestamp']}")
            if len(analyzer.other_messages) > 20:
                print(f"\n... and {len(analyzer.other_messages) - 20} more")


if __name__ == "__main__":
    main()
