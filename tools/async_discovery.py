#!/usr/bin/env python3
"""StageLinq async discovery example."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncIterator

from stagelinq.discovery import StageLinqDiscovery, DiscoveryConfig
from stagelinq.value_names import EngineDeck1, EngineDeck2

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def discover_and_monitor() -> None:
    """Discover devices and monitor their states."""
    config = DiscoveryConfig(
        name="Modern Python StageLinq",
        software_name="async-stagelinq",
        software_version="1.0.0"
    )

    async with StageLinqDiscovery(config) as discovery:
        logger.info("Starting device discovery...")

        # Get all devices found within 10 seconds
        devices = await discovery.get_devices(timeout=10.0)

        if not devices:
            logger.info("No devices found")
            return

        logger.info(f"Found {len(devices)} devices")

        # Monitor state from the first device
        device = devices[0]
        logger.info(f"Monitoring device: {device}")

        async with device.connect(discovery.config.token) as conn:
            async with conn.state_map() as state_map:
                # Subscribe to interesting states
                await state_map.subscribe(EngineDeck1.track_song_name())
                await state_map.subscribe(EngineDeck1.track_artist_name())
                await state_map.subscribe(EngineDeck1.current_bpm())
                await state_map.subscribe(EngineDeck2.track_song_name())
                await state_map.subscribe(EngineDeck2.track_artist_name())
                await state_map.subscribe(EngineDeck2.current_bpm())

                # Stream state updates
                async for state in state_map.states():
                    logger.info(f"State update: {state}")


async def monitor_beat_info() -> None:
    """Monitor beat information from devices."""
    config = DiscoveryConfig(name="Beat Monitor")

    async with StageLinqDiscovery(config) as discovery:
        devices = await discovery.get_devices(timeout=5.0)

        if not devices:
            logger.info("No devices found for beat monitoring")
            return

        device = devices[0]
        logger.info(f"Monitoring beats from: {device}")

        async with device.connect(discovery.config.token) as conn:
            async with conn.beat_info() as beat_info:
                count = 0
                async for beat in beat_info.beats():
                    count += 1
                    logger.info(f"Beat #{count}: {beat}")

                    # Show detailed player info
                    for i, player in enumerate(beat.players):
                        logger.info(f"  Player {i+1}: {player}")

                    # Stop after 20 beats
                    if count >= 20:
                        break


async def stream_all_devices() -> None:
    """Stream updates from all discovered devices."""
    config = DiscoveryConfig(name="Multi-Device Monitor")

    async with StageLinqDiscovery(config) as discovery:
        logger.info("Streaming from all devices...")

        # Stream devices as they're discovered
        async for device in discovery.discover_devices(timeout=30.0):
            logger.info(f"New device discovered: {device}")

            # Start monitoring this device in the background
            asyncio.create_task(monitor_device(device, discovery.config.token))


async def monitor_device(device, token) -> None:
    """Monitor a single device in the background."""
    try:
        async with device.connect(token) as conn:
            async with conn.state_map() as state_map:
                await state_map.subscribe(EngineDeck1.track_song_name())

                async for state in state_map.states():
                    logger.info(f"[{device.name}] {state}")

    except Exception as e:
        logger.error(f"Error monitoring {device.name}: {e}")


async def main() -> None:
    """Main async entry point."""
    logger.info("Starting modern StageLinq examples...")

    # Run examples
    try:
        await discover_and_monitor()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())