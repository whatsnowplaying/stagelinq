#!/usr/bin/env python3
"""
StagelinQ Beat Info Example

This example demonstrates how to receive beat timing information from StagelinQ devices.
"""

import argparse
import asyncio
import json
import logging

from stagelinq.discovery import DiscoveryConfig, discover_stagelinq_devices
from stagelinq.messages import Token


def setup_logging(level: str = "INFO") -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


async def monitor_beat_info(device, duration: float, output_format: str) -> None:
    """Monitor beat information from a device."""
    try:
        # Use a real SC6000 token
        client_token = Token(
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
        )

        connection = device.connect(client_token)
        async with connection:
            logging.info("  Requesting device services...")
            services = await connection.discover_services()

            for service in services:
                logging.info(f"  Service: {service.name} on port {service.port}")

            # Connect to BeatInfo service
            async with connection.beat_info() as beat_info:
                logging.info("  Connected to BeatInfo service")

                # Monitor beat info for specified duration
                beat_count = 0

                async def monitor_with_timeout():
                    nonlocal beat_count
                    async for beat_data in beat_info.beats():
                        beat_count += 1

                        if output_format == "text":
                            logging.info(
                                f"  Beat #{beat_count} - Clock: {beat_data.clock}"
                            )
                            for i, player in enumerate(beat_data.players):
                                timeline = (
                                    beat_data.timelines[i]
                                    if i < len(beat_data.timelines)
                                    else 0.0
                                )
                                logging.info(
                                    f"    Player {i + 1}: Beat={player.beat:.2f}, "
                                    f"Total={player.total_beats:.2f}, "
                                    f"BPM={player.bpm:.2f}, "
                                    f"Timeline={timeline:.2f}"
                                )
                        elif output_format == "json":
                            print(
                                json.dumps(
                                    {
                                        "device": {
                                            "ip": device.ip,
                                            "name": device.name,
                                        },
                                        "beat_info": {
                                            "clock": beat_data.clock,
                                            "players": [
                                                {
                                                    "beat": p.beat,
                                                    "total_beats": p.total_beats,
                                                    "bpm": p.bpm,
                                                }
                                                for p in beat_data.players
                                            ],
                                            "timelines": beat_data.timelines,
                                        },
                                    }
                                )
                            )

                try:
                    await asyncio.wait_for(monitor_with_timeout(), timeout=duration)
                except asyncio.TimeoutError:
                    logging.info(f"  Monitoring complete after {duration}s")

                logging.info(f"  Received {beat_count} beat updates")

    except Exception as e:
        logging.error(f"  Error connecting to device: {e}")


async def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Monitor StagelinQ beat information")
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Discovery timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Duration to monitor beat info in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )

    args = parser.parse_args()
    setup_logging(args.log_level)

    # Create discovery configuration
    config = DiscoveryConfig(
        name="Python StagelinQ Beat Monitor",
        software_name="python-stagelinq",
        software_version="0.1.0",
        discovery_timeout=args.timeout,
    )

    # Discover devices
    logging.info(f"Listening for devices for {args.timeout} seconds...")

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()

        # Wait for device discovery
        await asyncio.sleep(args.timeout)

        devices = await discovery.get_devices()

        if not devices:
            logging.info("No devices found")
            return

        for device in devices:
            logging.info(
                f"Found device: {device.ip} - {device.name} "
                f"({device.software_name} {device.software_version})"
            )

            # Monitor beat info for this device
            await monitor_beat_info(device, args.duration, args.output)

    logging.info(f"Discovery complete. Found {len(devices)} devices.")


if __name__ == "__main__":
    asyncio.run(main())
