#!/usr/bin/env python3
"""
Modern StageLinq async discovery examples.

This demonstrates the async API for StageLinq device discovery and interaction.
"""

import asyncio
import logging

from stagelinq.discovery import DiscoveryConfig, discover_stagelinq_devices
from stagelinq.messages import Token
from stagelinq.value_names import DeckValueNames


async def discover_devices_example() -> None:
    """Example of discovering StageLinq devices."""
    logging.info("Starting device discovery...")

    config = DiscoveryConfig(
        name="Python StageLinq Async Example",
        software_name="python-stagelinq",
        software_version="0.1.0",
        discovery_timeout=5.0,
    )

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()

        # Wait for device discovery
        await asyncio.sleep(5.0)

        devices = await discovery.get_devices()

        if not devices:
            logging.info("No devices found")
            return

        for device in devices:
            logging.info(f"Found device: {device.name} at {device.ip}")
            logging.info(
                f"  Software: {device.software_name} {device.software_version}"
            )


async def state_subscription_example() -> None:
    """Example of subscribing to device state changes."""
    logging.info("Starting state subscription example...")

    config = DiscoveryConfig(
        name="Python StageLinq State Example",
        software_name="python-stagelinq",
        software_version="0.1.0",
        discovery_timeout=3.0,
    )

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()

        # Wait for device discovery
        await asyncio.sleep(3.0)

        devices = await discovery.get_devices()

        if not devices:
            logging.info("No devices found")
            return

        device = devices[0]
        logging.info(f"Connecting to: {device.name}")

        # Use a real SC6000 token
        client_token = Token(
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
        )

        connection = device.connect(client_token)
        async with connection:
            logging.info("Connected to device")

            services = await connection.discover_services()
            logging.info(f"Available services: {[s.name for s in services]}")

            # Connect to StateMap service
            async with connection.state_map() as state_map:
                logging.info("Connected to StateMap service")

                # Subscribe to deck 1 track info
                deck1 = DeckValueNames(1)
                track_states = [
                    deck1.track_artist_name(),
                    deck1.track_song_name(),
                    deck1.track_current_bpm(),
                    deck1.play(),
                    deck1.play_state(),
                ]

                for state_name in track_states:
                    await state_map.subscribe(state_name, 500)  # 500ms interval
                    logging.info(f"Subscribed to: {state_name}")

                # Listen for state updates for 10 seconds
                logging.info("Listening for state updates (10 seconds)...")

                async def listen_with_timeout():
                    async for state in state_map.states():
                        logging.info(f"State update: {state.name} = {state.value}")

                try:
                    await asyncio.wait_for(listen_with_timeout(), timeout=10.0)
                except asyncio.TimeoutError:
                    logging.info("State listening timeout")


async def beat_info_example() -> None:
    """Example of receiving beat information."""
    logging.info("Starting beat info example...")

    config = DiscoveryConfig(
        name="Python StageLinq Beat Example",
        software_name="python-stagelinq",
        software_version="0.1.0",
        discovery_timeout=3.0,
    )

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()

        # Wait for device discovery
        await asyncio.sleep(3.0)

        devices = await discovery.get_devices()

        if not devices:
            logging.info("No devices found")
            return

        device = devices[0]
        logging.info(f"Connecting to: {device.name}")

        # Use a real SC6000 token
        client_token = Token(
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
        )

        connection = device.connect(client_token)
        async with connection:
            logging.info("Connected to device")

            # Connect to BeatInfo service
            async with connection.beat_info() as beat_info:
                logging.info("Connected to BeatInfo service")

                # Listen for beat updates for 10 seconds
                logging.info("Listening for beat updates (10 seconds)...")

                async def listen_with_timeout():
                    async for beat_data in beat_info.beats():
                        logging.info(f"Beat clock: {beat_data.clock}")
                        for i, player in enumerate(beat_data.players):
                            logging.info(
                                f"  Player {i + 1}: Beat={player.beat:.2f}, BPM={player.bpm:.1f}"
                            )

                try:
                    await asyncio.wait_for(listen_with_timeout(), timeout=10.0)
                except asyncio.TimeoutError:
                    logging.info("Beat listening timeout")


async def main() -> None:
    """Main entry point."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    logging.info("Starting modern StageLinq examples...")

    try:
        logging.info("Starting device discovery...")
        await discover_devices_example()

        logging.info("Starting state subscription example...")
        await state_subscription_example()

        logging.info("Starting beat info example...")
        await beat_info_example()

    except Exception as e:
        logging.error(f"Error in examples: {e}")
        logging.info("This is expected if no real devices are available")


if __name__ == "__main__":
    asyncio.run(main())
