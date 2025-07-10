#!/usr/bin/env python3
"""StageLinq now playing app."""

import asyncio
import logging
import signal
import sys
from datetime import datetime

from stagelinq.discovery import DiscoveryConfig, discover_stagelinq_devices
from stagelinq.messages import Token
from stagelinq.value_names import DeckValueNames

# Suppress noisy protocol errors - these are expected when IPv6 is available
# but StageLinq devices only support IPv4
logging.getLogger("stagelinq.protocol").setLevel(logging.CRITICAL)


class NowPlayingApp:
    def __init__(self):
        self.running = True
        self.deck_info = {
            1: {"artist": "", "track": "", "bpm": 0, "playing": False, "master": False},
            2: {"artist": "", "track": "", "bpm": 0, "playing": False, "master": False},
            3: {"artist": "", "track": "", "bpm": 0, "playing": False, "master": False},
            4: {"artist": "", "track": "", "bpm": 0, "playing": False, "master": False},
        }
        self.last_update = datetime.now()

    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print("\n\nShutting down now-playing app...")
        self.running = False

    def display_status(self):
        """Display current deck status."""
        # Clear screen and show header
        print("\033[H\033[J")  # Clear screen
        print("StageLinq Now Playing")
        print("=" * 60)
        print(f"Last update: {self.last_update.strftime('%H:%M:%S')}")
        print("-" * 60)

        # Show deck information
        for deck_num in range(1, 5):
            deck = self.deck_info[deck_num]
            status = "PLAYING" if deck["playing"] else "STOPPED"
            master = " [MASTER]" if deck["master"] else ""

            print(f"Deck {deck_num}: {status}{master}")

            if deck["artist"] or deck["track"]:
                print(f"  Artist: {deck['artist'] or 'Unknown'}")
                print(f"  Track:  {deck['track'] or 'Unknown'}")
                print(f"  BPM:    {deck['bpm']:.1f}")
            else:
                print("  No track loaded")
            print()

        print("Press Ctrl+C to exit")

    async def run(self):
        """Main app loop."""
        # Set up signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

        print("StageLinq Now Playing App Starting...")
        print("Waiting for StageLinq devices to appear...")
        print("(Make sure your DJ equipment is connected to the same network)")
        print("Press Ctrl+C to exit\n")

        # Discover StageLinq devices with retry loop
        config = DiscoveryConfig(discovery_timeout=3.0)

        device = None
        while self.running and device is None:
            try:
                async with discover_stagelinq_devices(config) as discovery:
                    await discovery.start_announcing()
                    devices = await discovery.get_devices()

                    if devices:
                        device = devices[0]
                        print(f"Found device: {device.name}")
                        print(f"Connecting to {device.name}...")
                        break
                    else:
                        print("Waiting for devices... (searching)")
                        await asyncio.sleep(2)

            except Exception as e:
                print(f"Discovery error: {e}")
                await asyncio.sleep(2)

        if not device or not self.running:
            return

        # Connect to device with retry loop
        while self.running:
            try:
                # Create client token
                client_token = Token(
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
                )

                # Connect to device
                connection = device.connect(client_token)
                async with connection:
                    services = await connection.discover_services()
                    print(f"Available services: {[s.name for s in services]}")

                    # Connect to StateMap service
                    async with connection.state_map() as state_map:
                        print("Connected to StateMap service")

                        # Subscribe to track information for all decks
                        print("Subscribing to track information...")

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

                        print("Now listening for track updates...")
                        print("Play some music to see track information!\n")

                        # Display initial status
                        self.display_status()

                        # Listen for state updates
                        async for state in state_map.states():
                            if not self.running:
                                break

                            # Parse state updates
                            self.process_state_update(state)

                            # Update display
                            self.display_status()

                        # If we get here, connection was lost
                        if self.running:
                            print("Connection lost. Attempting to reconnect...")

            except Exception as e:
                print(f"Connection error: {e}")
                print("Retrying connection in 5 seconds...")
                await asyncio.sleep(5)

    def process_state_update(self, state):
        """Process a state update and update deck information."""
        self.last_update = datetime.now()

        deck_num = next((i for i in range(1, 5) if f"Deck{i}" in state.name), None)
        if deck_num is None:
            return

        # Update deck information based on state type using typed values
        if "ArtistName" in state.name:
            self.deck_info[deck_num]["artist"] = state.get_typed_value() or ""
        elif "SongName" in state.name:
            self.deck_info[deck_num]["track"] = state.get_typed_value() or ""
        elif "CurrentBPM" in state.name:
            # BPM values are already properly typed as float
            self.deck_info[deck_num]["bpm"] = state.get_typed_value() or 0.0
        elif "PlayState" in state.name:
            # Boolean states are already properly typed
            self.deck_info[deck_num]["playing"] = state.get_typed_value()
        elif "DeckIsMaster" in state.name:
            # Boolean states are already properly typed
            self.deck_info[deck_num]["master"] = state.get_typed_value()


async def main():
    """Main function."""
    app = NowPlayingApp()
    await app.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nThanks for using StageLinq Now Playing!")
        sys.exit(0)
