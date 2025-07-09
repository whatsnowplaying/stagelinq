#!/usr/bin/env python3
"""
Debug script to understand state packet structure.
"""

import binascii
import json
import struct
from pathlib import Path


def debug_state_packet():
    """Debug the state packet structure."""
    print("DEBUG: Debugging State Packet Structure...")

    # Load real packet data
    packets_file = Path(__file__).parent.parent / "sc6000_packets.json"
    with open(packets_file) as f:
        packet_data = json.load(f)

    packet_hex = packet_data["state_packets"][0]
    packet_bytes = binascii.unhexlify(packet_hex)

    print(f"Total packet size: {len(packet_bytes)} bytes")
    print(f"Raw hex: {packet_hex}")

    # Manual parsing to understand structure
    pos = 0

    # Length prefix (4 bytes)
    length_bytes = packet_bytes[pos : pos + 4]
    length = struct.unpack(">I", length_bytes)[0]
    pos += 4
    print(f"Length: {length}")

    # Magic bytes (4 bytes)
    magic = packet_bytes[pos : pos + 4]
    pos += 4
    print(f"Magic: {magic} ({'smaa' if magic == b'smaa' else 'UNKNOWN'})")

    # Magic ID (4 bytes)
    magic_id_bytes = packet_bytes[pos : pos + 4]
    magic_id = struct.unpack(">I", magic_id_bytes)[0]
    pos += 4
    print(f"Magic ID: {magic_id} (0x{magic_id:08x})")

    # String length (4 bytes)
    string_length_bytes = packet_bytes[pos : pos + 4]
    string_length = struct.unpack(">I", string_length_bytes)[0]
    pos += 4
    print(f"String length: {string_length}")

    # String data (UTF-16)
    string_data = packet_bytes[pos : pos + string_length]
    pos += string_length
    print(f"String data: {string_data.hex()}")

    try:
        decoded = string_data.decode("utf-16be")
        print(f"Decoded string: '{decoded}'")
    except Exception as e:
        print(f"Failed to decode: {e}")

    # JSON data length (4 bytes)
    if pos + 4 <= len(packet_bytes):
        json_length_bytes = packet_bytes[pos : pos + 4]
        json_length = struct.unpack(">I", json_length_bytes)[0]
        pos += 4
        print(f"JSON length: {json_length}")

        # JSON data
        json_data = packet_bytes[pos : pos + json_length]
        print(f"JSON data: {json_data.hex()}")

        try:
            decoded_json = json_data.decode("utf-16be")
            print(f"Decoded JSON: '{decoded_json}'")
        except Exception as e:
            print(f"Failed to decode JSON: {e}")

    print(f"Remaining bytes: {packet_bytes[pos:].hex()}")


if __name__ == "__main__":
    debug_state_packet()
