#!/usr/bin/env python3
"""StageLinq device discovery example."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Any

from stagelinq.discovery import DiscoveryConfig, discover_stagelinq_devices
from stagelinq.messages import Token
from stagelinq.value_names import DeckValueNames


def setup_logging(level: str = "INFO") -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def get_state_names() -> list[str]:
    """Get list of state names to monitor."""
    deck1 = DeckValueNames(1)
    deck2 = DeckValueNames(2)

    return [
        deck1.play(),
        deck1.play_state(),
        deck1.track_artist_name(),
        deck1.track_song_name(),
        deck1.track_current_bpm(),
        deck2.play(),
        deck2.play_state(),
        deck2.track_artist_name(),
        deck2.track_song_name(),
        deck2.track_current_bpm(),
    ]


async def collect_device_states(
    device: Any, state_names: list[str], timeout: float = 2.0
) -> dict[str, Any]:
    """Collect state information from a device."""
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

            # Connect to StateMap service
            async with connection.state_map() as state_map:
                logging.info("  Connected to StateMap service")

                # Subscribe to state values
                for state_name in state_names:
                    await state_map.subscribe(state_name, 100)  # 100ms interval

                # Collect states with timeout
                collected_states: dict[str, Any] = {}

                async def collect_with_timeout():
                    async for state in state_map.states():
                        collected_states[state.name] = state.get_typed_value()
                        logging.info("    %s = %s", state.name, state.get_typed_value())

                        # Check if we have enough states
                        if len(collected_states) >= len(state_names):
                            break

                try:
                    await asyncio.wait_for(collect_with_timeout(), timeout=timeout)
                except asyncio.TimeoutError:
                    logging.info(
                        f"  Timeout after {timeout}s, collected {len(collected_states)} states"
                    )

                return collected_states

    except Exception as e:
        logging.error(f"  Error connecting to device: {e}")
        return {}


async def discover_devices(config: DiscoveryConfig, timeout: float) -> list[Any]:
    """Discover StageLinq devices on the network."""
    found_devices: list[Any] = []

    logging.info(f"Listening for devices for {timeout} seconds...")

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()

        # Wait for device discovery
        await asyncio.sleep(timeout)

        devices = await discovery.get_devices()

        for device in devices:
            logging.info(
                f"Found device: {device.ip} - {device.name} "
                f"({device.software_name} {device.software_version})"
            )
            found_devices.append(device)

    return found_devices


async def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Discover StageLinq devices")
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Discovery timeout in seconds (default: 5.0)",
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
        name="Python StageLinq Example",
        software_name="python-stagelinq",
        software_version="0.1.0",
        discovery_timeout=args.timeout,
    )

    # Discover devices
    devices = await discover_devices(config, args.timeout)

    if not devices:
        logging.info("No devices found")
        return

    # Collect state information from each device
    state_names = get_state_names()

    for device in devices:
        states = await collect_device_states(device, state_names)

        if args.output == "json":
            print(
                json.dumps(
                    {
                        "device": {
                            "ip": device.ip,
                            "name": device.name,
                            "software_name": device.software_name,
                            "software_version": device.software_version,
                        },
                        "states": states,
                    },
                    indent=2,
                )
            )

    logging.info(f"Discovery complete. Found {len(devices)} devices.")


if __name__ == "__main__":
    asyncio.run(main())
