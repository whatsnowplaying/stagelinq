#!/usr/bin/env python3
"""Simple packet extractor for StageLinq captures using tshark."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def run_tshark(pcap_file: Path, filter_expr: str) -> list[str]:
    """Run tshark to extract packets."""
    try:
        result = subprocess.run([
            'tshark', 
            '-r', str(pcap_file),
            '-Y', filter_expr,
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'data.data',
            '-E', 'separator=|'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"tshark error: {result.stderr}")
            return []
        
        return result.stdout.strip().split('\n') if result.stdout.strip() else []
    
    except FileNotFoundError:
        print("tshark not found. Please install Wireshark or use the scapy version.")
        return []


def extract_discovery_packets(pcap_file: Path) -> list[dict[str, Any]]:
    """Extract StageLinq discovery packets (UDP port 51337)."""
    lines = run_tshark(pcap_file, 'udp.port == 51337')
    packets = []
    
    for line in lines:
        if not line.strip():
            continue
        
        parts = line.split('|')
        if len(parts) < 8:
            continue
        
        timestamp, src_ip, dst_ip, src_port, dst_port, _, _, data = parts[:8]
        
        if data and data.startswith('61697244'):  # "airD" in hex
            packets.append({
                'timestamp': float(timestamp),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port) if src_port else 0,
                'dst_port': int(dst_port) if dst_port else 0,
                'raw_data': data,
                'type': 'discovery'
            })
    
    return packets


def extract_tcp_packets(pcap_file: Path, port_filter: str = '') -> list[dict[str, Any]]:
    """Extract TCP packets that might contain StageLinq data."""
    filter_expr = 'tcp'
    if port_filter:
        filter_expr = f'tcp and ({port_filter})'
    
    lines = run_tshark(pcap_file, filter_expr)
    packets = []
    
    for line in lines:
        if not line.strip():
            continue
        
        parts = line.split('|')
        if len(parts) < 8:
            continue
        
        timestamp, src_ip, dst_ip, _, _, src_port, dst_port, data = parts[:8]
        
        if data and len(data) > 8:  # Has some data
            # Check for SMAA magic (state map) - 736d6161 in hex
            # Check for beat info patterns
            packet_type = 'unknown'
            if '736d6161' in data.lower():
                packet_type = 'state_map'
            elif data.startswith('00000004'):  # Common beat info pattern
                packet_type = 'beat_info'
            
            packets.append({
                'timestamp': float(timestamp),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port) if src_port else 0,
                'dst_port': int(dst_port) if dst_port else 0,
                'raw_data': data,
                'type': packet_type
            })
    
    return packets


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Extract StageLinq packets using tshark")
    parser.add_argument("pcap_file", type=Path, help="Path to PCAP file")
    parser.add_argument("--output", "-o", type=Path, help="Output JSON file")
    
    args = parser.parse_args()
    
    if not args.pcap_file.exists():
        print(f"PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    print(f"Analyzing {args.pcap_file}...")
    
    # Extract different packet types
    discovery_packets = extract_discovery_packets(args.pcap_file)
    tcp_packets = extract_tcp_packets(args.pcap_file)
    
    # Separate TCP packets by type
    state_packets = [p for p in tcp_packets if p['type'] == 'state_map']
    beat_packets = [p for p in tcp_packets if p['type'] == 'beat_info']
    other_tcp = [p for p in tcp_packets if p['type'] == 'unknown']
    
    print(f"\nResults:")
    print(f"Discovery packets: {len(discovery_packets)}")
    print(f"State map packets: {len(state_packets)}")
    print(f"Beat info packets: {len(beat_packets)}")
    print(f"Other TCP packets: {len(other_tcp)}")
    
    # Show sample discovery packets
    if discovery_packets:
        print(f"\nSample discovery packets:")
        for i, packet in enumerate(discovery_packets[:3]):
            print(f"  {i+1}. {packet['src_ip']} -> {packet['dst_ip']} (port {packet['dst_port']})")
            print(f"      Data: {packet['raw_data'][:80]}...")
    
    # Prepare data for tests
    test_data = {
        'discovery_packets': [p['raw_data'] for p in discovery_packets[:5]],
        'state_packets': [p['raw_data'] for p in state_packets[:5]],
        'beat_packets': [p['raw_data'] for p in beat_packets[:5]],
        'summary': {
            'total_discovery': len(discovery_packets),
            'total_state': len(state_packets),
            'total_beat': len(beat_packets),
            'capture_file': str(args.pcap_file)
        }
    }
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(test_data, f, indent=2)
        print(f"\nTest data saved to {args.output}")
    else:
        print(f"\nTest data preview:")
        print(json.dumps(test_data, indent=2)[:500] + "...")


if __name__ == "__main__":
    main()