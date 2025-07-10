#!/usr/bin/env python3
"""Enhanced StageLinq now playing app with multi-device support.

This version uses the new Listener architecture to monitor multiple DJ devices
simultaneously, providing a comprehensive view of all connected equipment.
"""

import asyncio
import logging
import signal
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Add the parent directory to the path so we can import the local stagelinq module
sys.path.insert(0, str(Path(__file__).parent.parent))

from stagelinq import StageLinqListener
from stagelinq.device import State
from stagelinq.listener import StateMapService
from stagelinq.messages import Token
from stagelinq.protocol import StageLinqConnection

# Suppress noisy protocol errors
logging.getLogger("stagelinq.protocol").setLevel(logging.CRITICAL)


class MultiDeviceStateMapService(StateMapService):
    """StateMap service that handles multiple device connections."""

    def __init__(self, port: int, token: Token, now_playing_app):
        super().__init__(port, token)
        self.app = now_playing_app

    async def handle_device_connection(
        self, device_id: str, connection: StageLinqConnection
    ) -> None:
        """Handle StateMap service protocol for a device."""
        try:
            logger = logging.getLogger(__name__)
            logger.info("Device %s connected to StateMap service", device_id)
            self.app.register_device(device_id)

            async for message_data in connection.messages():
                try:
                    # Parse state message using existing logic
                    from stagelinq.messages import (
                        LengthPrefixedReader,
                        StateEmitMessage,
                    )

                    reader = LengthPrefixedReader(message_data)
                    message_content = reader.read_message()

                    if not message_content:
                        continue

                    # Try to parse as StateEmitMessage
                    try:
                        state_msg = StateEmitMessage()
                        state_msg.read_from(message_content)

                        # Convert to typed state
                        state = State.from_json_data(
                            state_msg.name, state_msg.json_data
                        )

                        # Process the state update
                        self.app.process_state_update(device_id, state)

                    except Exception as e:
                        logger.debug("Failed to parse state message: %s", e)

                except Exception as e:
                    logger.debug(
                        "Error processing state map message from %s: %s", device_id, e
                    )
                    continue

        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error("StateMap service error with %s: %s", device_id, e)
        finally:
            self.app.unregister_device(device_id)


class MultiDeviceNowPlayingApp:
    """Enhanced now playing app that supports multiple devices."""

    def __init__(self):
        self.running = True
        self.devices: dict[str, dict] = {}  # device_id -> device_info
        self.deck_info: dict[str, dict] = {}  # device_id:deck_num -> deck_info
        self.last_update = datetime.now()
        self.listener: StageLinqListener | None = None

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print("\n\nShutting down multi-device now-playing app...")
        self.running = False

    def register_device(self, device_id: str):
        """Register a new device connection."""
        if device_id not in self.devices:
            self.devices[device_id] = {
                "name": device_id,
                "connected_at": datetime.now(),
                "last_seen": datetime.now(),
            }

            # Initialize deck info for this device
            for deck_num in range(1, 5):
                deck_key = f"{device_id}:Deck{deck_num}"
                self.deck_info[deck_key] = {
                    "device_id": device_id,
                    "deck_num": deck_num,
                    "artist": "",
                    "track": "",
                    "bpm": 0,
                    "playing": False,
                    "master": False,
                }

            print(f"\n🟢 Device connected: {device_id}")

    def unregister_device(self, device_id: str):
        """Unregister a device connection."""
        if device_id in self.devices:
            print(f"\n🔴 Device disconnected: {device_id}")
            # Keep device info but mark as disconnected
            self.devices[device_id]["disconnected_at"] = datetime.now()

    def process_state_update(self, device_id: str, state: State):
        """Process a state update from a specific device."""
        self.last_update = datetime.now()

        if device_id in self.devices:
            self.devices[device_id]["last_seen"] = datetime.now()

        # Extract deck number from state name
        deck_num = self._extract_deck_number(state.name)
        if deck_num is None:
            return

        deck_key = f"{device_id}:Deck{deck_num}"

        # Ensure deck exists
        if deck_key not in self.deck_info:
            self.deck_info[deck_key] = {
                "device_id": device_id,
                "deck_num": deck_num,
                "artist": "",
                "track": "",
                "bpm": 0,
                "playing": False,
                "master": False,
            }

        # Update deck information based on state type using typed values
        if "ArtistName" in state.name:
            self.deck_info[deck_key]["artist"] = state.get_typed_value() or ""
        elif "SongName" in state.name or "TrackTitle" in state.name:
            self.deck_info[deck_key]["track"] = state.get_typed_value() or ""
        elif "CurrentBPM" in state.name:
            self.deck_info[deck_key]["bpm"] = state.get_typed_value() or 0.0
        elif "PlayState" in state.name:
            self.deck_info[deck_key]["playing"] = state.get_typed_value()
        elif "DeckIsMaster" in state.name:
            self.deck_info[deck_key]["master"] = state.get_typed_value()

        # Update display after each state change
        self.display_status()

    def _extract_deck_number(self, state_name: str) -> int | None:
        """Extract deck number from state path."""
        # Look for deck identifiers in the state name
        parts = state_name.split("/")
        for part in parts:
            if part.startswith("Deck") and len(part) > 4:
                try:
                    return int(part[4:])
                except ValueError:
                    continue
            elif part in ["Deck1", "Deck2", "Deck3", "Deck4"]:
                return int(part[4:])
        return None

    def display_status(self):
        """Display current status of all devices and decks."""
        # Clear screen and show header
        print("\033[H\033[J")  # Clear screen
        print("StageLinq Multi-Device Now Playing")
        print("=" * 80)
        print(f"Last update: {self.last_update.strftime('%H:%M:%S')}")
        print(
            f"Connected devices: {len([d for d in self.devices.values() if 'disconnected_at' not in d])}"
        )
        print("-" * 80)

        if not self.devices:
            print("Waiting for DJ devices to connect...")
            print(
                "Make sure your equipment is on the same network and configured to connect."
            )
            print("Press Ctrl+C to exit")
            return

        # Group decks by device
        devices_with_decks = defaultdict(list)
        for deck_key, deck_info in self.deck_info.items():
            device_id = deck_info["device_id"]
            devices_with_decks[device_id].append(deck_info)

        # Display each device and its decks
        for device_id, device_info in self.devices.items():
            is_connected = "disconnected_at" not in device_info
            status_icon = "🟢" if is_connected else "🔴"

            print(f"\n{status_icon} Device: {device_info['name']}")
            if is_connected:
                time_connected = datetime.now() - device_info["connected_at"]
                print(f"   Connected: {time_connected.total_seconds():.0f}s ago")
            else:
                print(
                    f"   Disconnected: {device_info['disconnected_at'].strftime('%H:%M:%S')}"
                )

            # Show decks for this device
            device_decks = devices_with_decks.get(device_id, [])
            device_decks.sort(key=lambda d: d["deck_num"])

            for deck in device_decks:
                deck_num = deck["deck_num"]
                status = "▶️" if deck["playing"] else "⏸️"
                master = " 👑" if deck["master"] else ""

                print(f"   {status} Deck {deck_num}{master}: {deck['bpm']:.1f} BPM")

                if deck["artist"] or deck["track"]:
                    print(f"      Artist: {deck['artist'] or 'Unknown'}")
                    print(f"      Track:  {deck['track'] or 'Unknown'}")
                else:
                    print("      No track loaded")

        print("\nPress Ctrl+C to exit")

    async def start_listener_mode(self, state_port: int = 51338):
        """Start in listener mode where devices connect to us."""
        print(f"Starting in Listener mode on port {state_port}")
        print("Devices will connect TO this application")

        # Create custom listener with our state service
        self.listener = StageLinqListener()

        # Add custom state service
        state_service = MultiDeviceStateMapService(
            state_port, self.listener.token, self
        )
        self.listener.services["StateMap"] = state_service

        # Update offered services
        from stagelinq.listener import ServiceInfo

        self.listener.offered_services = [
            ServiceInfo(
                name="StateMap",
                port=state_port,
                handler_class=MultiDeviceStateMapService,
            )
        ]

        await self.listener.start()

        # Display initial status
        self.display_status()

        # Keep running until shutdown
        try:
            while self.running:
                await asyncio.sleep(1.0)
        finally:
            await self.listener.stop()

    async def start_discovery_mode(self, discovery_timeout: float = 3.0):
        """Start in discovery mode (traditional approach)."""
        print("Starting in Discovery mode")
        print("Searching for StageLinq devices on the network...")

        config = DiscoveryConfig(discovery_timeout=discovery_timeout)
        devices_found = []

        # Discovery loop to find all devices
        while self.running and not devices_found:
            try:
                async with discover_stagelinq_devices(config) as discovery:
                    await discovery.start_announcing()
                    devices_found = await discovery.get_devices()

                    if devices_found:
                        print(f"Found {len(devices_found)} device(s):")
                        for device in devices_found:
                            print(f"  - {device.name} ({device.ip})")
                        break
                    else:
                        print("Waiting for devices... (searching)")
                        await asyncio.sleep(2)

            except Exception as e:
                print(f"Discovery error: {e}")
                await asyncio.sleep(2)

        if not devices_found or not self.running:
            return

        # Connect to all found devices
        connections = []
        for device in devices_found:
            try:
                device_id = f"{device.name}@{device.ip}"
                self.register_device(device_id)

                # Create client token
                client_token = Token(
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
                )

                # Connect to device
                connection = device.connect(client_token)
                await connection.connect()

                # Subscribe to state updates
                async with connection.state_map() as state_map:
                    print(f"Connected to {device.name} StateMap service")

                    # Subscribe to track information for all decks
                    for deck_num in range(1, 5):
                        deck = DeckValueNames(deck_num)
                        track_states = [
                            deck.track_artist_name(),
                            deck.track_song_name(),
                            deck.track_current_bpm(),
                            deck.play_state(),
                            deck.deck_is_master(),
                        ]

                        for state_name in track_states:
                            try:
                                await state_map.subscribe(
                                    state_name, 100
                                )  # 100ms interval
                            except Exception:
                                # Some states might not be available, continue
                                pass

                    # Store connection for monitoring
                    connections.append((device_id, state_map))

            except Exception as e:
                print(f"Failed to connect to {device.name}: {e}")

        if not connections:
            print("No successful connections established")
            return

        # Display initial status
        self.display_status()

        # Monitor all connections simultaneously
        async def monitor_device(device_id, state_map):
            try:
                async for state in state_map.states():
                    if not self.running:
                        break
                    self.process_state_update(device_id, state)
            except Exception as e:
                print(f"Connection lost to {device_id}: {e}")
                self.unregister_device(device_id)

        # Start monitoring tasks for all devices
        monitor_tasks = [
            asyncio.create_task(monitor_device(device_id, state_map))
            for device_id, state_map in connections
        ]

        try:
            # Wait for all tasks to complete or shutdown
            await asyncio.gather(*monitor_tasks, return_exceptions=True)
        except Exception as e:
            print(f"Monitoring error: {e}")
        finally:
            # Cancel remaining tasks
            for task in monitor_tasks:
                if not task.done():
                    task.cancel()


async def main():
    """Main function."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Enhanced StageLinq Now Playing with multi-device support"
    )
    parser.add_argument(
        "--mode",
        choices=["discovery", "listener"],
        default="listener",
        help="Operation mode: 'discovery' (find devices) or 'listener' (devices connect to us)",
    )
    parser.add_argument(
        "--state-port",
        type=int,
        default=51338,
        help="Port for StateMap service in listener mode (default: 51338)",
    )
    parser.add_argument(
        "--discovery-timeout",
        type=float,
        default=3.0,
        help="Discovery timeout in seconds for discovery mode (default: 3.0)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    app = MultiDeviceNowPlayingApp()

    # Set up signal handler
    signal.signal(signal.SIGINT, app.signal_handler)

    print("StageLinq Multi-Device Now Playing App")
    print("=" * 50)

    try:
        if args.mode == "listener":
            print(f"🎧 Starting Listener Mode on port {args.state_port}")
            print("Devices will connect TO this application")
            print("Configure your DJ equipment to connect to this computer's IP")
            print("Press Ctrl+C to exit\n")
            await app.start_listener_mode(args.state_port)
        else:
            print("🔍 Starting Discovery Mode")
            print("Searching for StageLinq devices on the network")
            print("Press Ctrl+C to exit\n")
            await app.start_discovery_mode(args.discovery_timeout)

    except KeyboardInterrupt:
        pass
    finally:
        print("\nThanks for using StageLinq Multi-Device Now Playing!")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nThanks for using StageLinq Multi-Device Now Playing!")
        sys.exit(0)
