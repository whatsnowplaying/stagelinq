#!/usr/bin/env python3
"""
Debug script to understand the packet structure.
"""

import binascii
import json
import struct
from pathlib import Path


def debug_discovery_packet():
    """Debug the discovery packet structure."""
    print("DEBUG: Debugging Discovery Packet Structure...")

    # Load real packet data
    packets_file = Path(__file__).parent.parent / "sc6000_packets.json"
    with open(packets_file) as f:
        packet_data = json.load(f)

    packet_hex = packet_data["discovery_packets"][0]
    packet_bytes = binascii.unhexlify(packet_hex)

    print(f"Total packet size: {len(packet_bytes)} bytes")
    print(f"Raw hex: {packet_hex}")
    print(f"First 20 bytes: {packet_bytes[:20].hex()}")

    # Manual parsing to understand structure
    pos = 0

    # Magic bytes
    magic = packet_bytes[pos : pos + 4]
    pos += 4
    print(f"Magic: {magic} ({'airD' if magic == b'airD' else 'UNKNOWN'})")

    # Token (16 bytes)
    token = packet_bytes[pos : pos + 16]
    pos += 16
    print(f"Token: {token.hex()}")

    # Now we need to parse UTF-16 strings
    # Let's see what's at the current position
    print(f"Position after token: {pos}")
    print(f"Next 20 bytes: {packet_bytes[pos : pos + 20].hex()}")

    def read_utf16_string(data, pos):
        """Read a UTF-16 string with length prefix."""
        if pos + 4 > len(data):
            return None, pos

        length_bytes = data[pos : pos + 4]
        length = struct.unpack(">I", length_bytes)[0]
        pos += 4

        if pos + length > len(data):
            return None, pos

        string_data = data[pos : pos + length]
        pos += length

        try:
            decoded = string_data.decode("utf-16be")
            return decoded, pos
        except Exception as e:
            print(f"Failed to decode UTF-16 string: {e}")
            return None, pos

    # Parse all strings in the discovery message
    strings = []
    port = None

    # Source string
    source, pos = read_utf16_string(packet_bytes, pos)
    if source is not None:
        strings.append(("Source", source))
        print(f"Source: '{source}'")

    # Action string
    action, pos = read_utf16_string(packet_bytes, pos)
    if action is not None:
        strings.append(("Action", action))
        print(f"Action: '{action}'")

    # Software name string
    software_name, pos = read_utf16_string(packet_bytes, pos)
    if software_name is not None:
        strings.append(("Software Name", software_name))
        print(f"Software Name: '{software_name}'")

    # Software version string
    software_version, pos = read_utf16_string(packet_bytes, pos)
    if software_version is not None:
        strings.append(("Software Version", software_version))
        print(f"Software Version: '{software_version}'")

    # Port (2 bytes)
    if pos + 2 <= len(packet_bytes):
        port_bytes = packet_bytes[pos : pos + 2]
        port = struct.unpack(">H", port_bytes)[0]
        pos += 2
        print(f"Port: {port}")

    # Print remaining bytes
    print(f"Remaining bytes: {packet_bytes[pos:].hex()}")

    # Summary
    print("\nSUMMARY: Discovery Message Summary:")
    print("Magic: airD")
    print(f"Token: {token.hex()}")
    for name, value in strings:
        print(f"{name}: '{value}'")
    if port is not None:
        print(f"Port: {port}")


if __name__ == "__main__":
    debug_discovery_packet()
