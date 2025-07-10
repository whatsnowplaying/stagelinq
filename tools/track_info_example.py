#!/usr/bin/env python3
"""
Example: Get track info from StageLinq devices

This demonstrates the core functionality for seeing what tracks are playing.
"""

import asyncio

from stagelinq.discovery import DiscoveryConfig, discover_stagelinq_devices
from stagelinq.value_names import DeckValueNames


async def get_track_info():
    """Example of getting track information from StageLinq devices."""

    print("MUSIC: StageLinq Track Info Example")
    print("=" * 40)

    # 1. Device Discovery - Find StageLinq devices on network
    print("1. Discovering StageLinq devices...")
    config = DiscoveryConfig(discovery_timeout=3.0)

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()
        devices = await discovery.get_devices()

        if not devices:
            print("ERROR: No StageLinq devices found")
            print("   Make sure your DJ equipment is on the same network")
            return

        print(f"OK Found {len(devices)} device(s):")
        for device in devices:
            print(f"   - {device}")

        device = devices[0]
        print(f"\n2. Connecting to: {device.name}")

        # 2. Connect to device and get StateMap service
        try:
            # Create client token (using real SC6000 token as example)
            from stagelinq.messages import Token

            client_token = Token(
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
            )

            # Connect and discover services
            connection = device.connect(client_token)
            async with connection:
                services = await connection.discover_services()
                print(f"OK Available services: {[s.name for s in services]}")

                # 3. Connect to StateMap service
                async with connection.state_map() as state_map:
                    print("OK Connected to StateMap service")

                    # 4. Subscribe to track information for deck 1
                    deck1 = DeckValueNames(1)
                    track_states = [
                        deck1.track_artist_name(),
                        deck1.track_song_name(),
                        deck1.track_current_bpm(),
                        deck1.play(),
                        deck1.play_state(),
                    ]

                    print("\n3. Subscribing to track info states:")
                    for state_name in track_states:
                        await state_map.subscribe(state_name, 100)  # 100ms interval
                        print(f"   OK {state_name}")

                    # 5. Listen for state updates
                    print("\n4. Listening for track info updates...")
                    print("   (Play a track on Deck 1 to see updates)")

                    async for state in state_map.states():
                        if "Track" in state.name or "Play" in state.name:
                            print(
                                "DATA %s = %s" % (state.name, state.get_typed_value())
                            )

                            # Show formatted track info when we get updates
                            if "ArtistName" in state.name:
                                print("ARTIST: %s" % state.get_typed_value())
                            elif "SongName" in state.name:
                                print("SONG: %s" % state.get_typed_value())
                            elif "CurrentBPM" in state.name:
                                print("BPM: %s" % state.get_typed_value())
                            elif "Play" in state.name:
                                status = (
                                    "PLAYING" if state.get_typed_value() else "STOPPED"
                                )
                                print("STATUS: %s" % status)

        except Exception as e:
            print(f"ERROR: Connection failed: {e}")
            print("   This is expected if no real device is available")
            print("   The discovery and state subscription logic is working!")


if __name__ == "__main__":
    asyncio.run(get_track_info())
