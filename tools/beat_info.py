#!/usr/bin/env python3
"""
StageLinq Beat Info Example

This example demonstrates how to receive beat timing information from StageLinq devices.
"""

import argparse
import json
import logging
import time

import stagelinq
from stagelinq import DeviceState


def setup_logging(level: str = "INFO"):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def main():
    parser = argparse.ArgumentParser(description="Monitor StageLinq beat information")
    parser.add_argument("--timeout", type=float, default=5.0,
                       help="Discovery timeout in seconds (default: 5.0)")
    parser.add_argument("--duration", type=float, default=30.0,
                       help="Duration to monitor beat info in seconds (default: 30.0)")
    parser.add_argument("--output", choices=["text", "json"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("--log-level", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Log level (default: INFO)")

    args = parser.parse_args()
    setup_logging(args.log_level)

    # Create listener configuration
    config = stagelinq.ListenerConfiguration(
        name="Python StageLinq Beat Monitor",
        software_name="python-stagelinq",
        software_version="0.1.0",
        discovery_timeout=args.timeout
    )

    # Start listener
    with stagelinq.Listener(config) as listener:
        listener.announce_every(1.0)

        logging.info(f"Listening for devices for {args.timeout} seconds...")

        found_devices = []
        start_time = time.time()

        while time.time() - start_time < args.timeout:
            try:
                device, device_state = listener.discover(timeout=1.0)

                if device is None:
                    continue

                # Skip devices that are leaving
                if device_state != DeviceState.PRESENT:
                    continue

                # Check if we already found this device
                if any(d.is_equal(device) for d in found_devices):
                    continue

                found_devices.append(device)

                logging.info(f"Found device: {device.ip} - {device.name} "
                           f"({device.software_name} {device.software_version})")

                # Connect to device and get services
                try:
                    with device.connect(listener.token) as main_conn:
                        logging.info("  Requesting device services...")
                        services = main_conn.request_services()

                        for service in services:
                            logging.info(f"  Service: {service.name} on port {service.port}")

                            # Connect to BeatInfo service
                            if service.name == "BeatInfo":
                                try:
                                    beat_conn = device.dial(service.port)
                                    with stagelinq.BeatInfoConnection(beat_conn, listener.token) as beat_info:
                                        logging.info("  Starting beat info stream...")
                                        beat_info.start_stream()

                                        # Monitor beat info for specified duration
                                        monitor_start = time.time()
                                        beat_count = 0

                                        while time.time() - monitor_start < args.duration:
                                            beat_data = beat_info.get_beat_info(timeout=1.0)
                                            if beat_data:
                                                beat_count += 1

                                                if args.output == "text":
                                                    logging.info(f"  Beat #{beat_count} - Clock: {beat_data.clock}")
                                                    for i, player in enumerate(beat_data.players):
                                                        timeline = beat_data.timelines[i] if i < len(beat_data.timelines) else 0.0
                                                        logging.info(f"    Player {i+1}: Beat={player.beat:.2f}, "
                                                                   f"Total={player.total_beats:.2f}, "
                                                                   f"BPM={player.bpm:.2f}, "
                                                                   f"Timeline={timeline:.2f}")
                                                elif args.output == "json":
                                                    print(json.dumps({
                                                        "device": {
                                                            "ip": device.ip,
                                                            "name": device.name
                                                        },
                                                        "beat_info": {
                                                            "clock": beat_data.clock,
                                                            "players": [
                                                                {
                                                                    "beat": p.beat,
                                                                    "total_beats": p.total_beats,
                                                                    "bpm": p.bpm
                                                                } for p in beat_data.players
                                                            ],
                                                            "timelines": beat_data.timelines
                                                        }
                                                    }))

                                        logging.info(f"  Received {beat_count} beat updates")

                                except Exception as e:
                                    logging.error(f"  Error connecting to BeatInfo: {e}")

                except Exception as e:
                    logging.error(f"  Error connecting to device: {e}")

            except stagelinq.TooShortDiscoveryMessageError:
                logging.warning("Received too short discovery message")
                continue
            except stagelinq.InvalidMessageError as e:
                logging.warning(f"Invalid message received: {e}")
                continue
            except stagelinq.InvalidDiscovererActionError as e:
                logging.warning(f"Invalid discoverer action: {e}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                continue

        logging.info(f"Discovery complete. Found {len(found_devices)} devices.")


if __name__ == "__main__":
    main()