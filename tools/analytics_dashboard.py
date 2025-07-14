#!/usr/bin/env python3
"""Enhanced DJ Analytics Dashboard using StagelinQ Listener Architecture.

This tool creates a comprehensive analytics server that multiple DJ devices
can connect to simultaneously, providing real-time monitoring of:
- Track information and transitions
- BPM and tempo analysis
- Beat synchronization across decks
- Device status and performance metrics
- Multi-device session analytics

Based on the revolutionary Listener approach from @honusz that allows
devices to connect TO software instead of software discovering devices.
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# Add the parent directory to the path so we can import the local stagelinq module
sys.path.insert(0, str(Path(__file__).parent.parent))

from stagelinq import StagelinQListener
from stagelinq.device import State, StateValueType
from stagelinq.listener import BeatInfoService, StateMapService
from stagelinq.messages import BeatEmitMessage, Token, parse_beat_message
from stagelinq.protocol import StagelinQConnection

logger = logging.getLogger(__name__)


@dataclass
class TrackInfo:
    """Information about a currently playing track."""

    title: str = ""
    artist: str = ""
    album: str = ""
    bpm: float = 0.0
    key: str = ""
    genre: str = ""
    duration: float = 0.0
    play_position: float = 0.0
    load_time: datetime = field(default_factory=datetime.now)

    def is_complete(self) -> bool:
        """Check if we have the essential track information."""
        return bool(self.title and self.artist and self.bpm > 0)


@dataclass
class DeckState:
    """Current state of a DJ deck."""

    deck_id: str
    device_id: str
    is_playing: bool = False
    is_master: bool = False
    is_synced: bool = False
    current_bpm: float = 0.0
    pitch_fader: float = 0.0
    volume: float = 0.0
    crossfader_assign: str = ""
    loop_enabled: bool = False
    hot_cue_states: dict[int, bool] = field(default_factory=dict)
    current_track: TrackInfo = field(default_factory=TrackInfo)
    last_beat_time: datetime | None = None
    beat_count: int = 0


@dataclass
class DeviceMetrics:
    """Performance and connection metrics for a device."""

    device_id: str
    device_name: str = ""
    software_name: str = ""
    software_version: str = ""
    connection_time: datetime = field(default_factory=datetime.now)
    last_heartbeat: datetime = field(default_factory=datetime.now)
    state_updates_count: int = 0
    beat_updates_count: int = 0
    is_connected: bool = True


class AnalyticsStateMapService(StateMapService):
    """Enhanced StateMap service with analytics tracking."""

    def __init__(self, port: int, token: Token, analytics_dashboard):
        super().__init__(port, token)
        self.dashboard = analytics_dashboard

    async def handle_device_connection(
        self, device_id: str, connection: StagelinQConnection
    ) -> None:
        """Handle StateMap service protocol with analytics."""
        try:
            logger.info("Device %s connected to StateMap service", device_id)
            self.dashboard.register_device(device_id, "StateMap")

            async for message_data in connection.messages():
                try:
                    # Parse state map messages and update analytics
                    await self.dashboard.handle_state_message(device_id, message_data)

                except Exception as e:
                    logger.debug(
                        "Error processing state map message from %s: %s", device_id, e
                    )
                    continue

        except Exception as e:
            logger.error("StateMap service error with %s: %s", device_id, e)
        finally:
            self.dashboard.unregister_device(device_id, "StateMap")


class AnalyticsBeatInfoService(BeatInfoService):
    """Enhanced BeatInfo service with analytics tracking."""

    def __init__(self, port: int, token: Token, analytics_dashboard):
        super().__init__(port, token)
        self.dashboard = analytics_dashboard

    async def handle_device_connection(
        self, device_id: str, connection: StagelinQConnection
    ) -> None:
        """Handle BeatInfo service protocol with analytics."""
        try:
            logger.info("Device %s connected to BeatInfo service", device_id)
            self.dashboard.register_device(device_id, "BeatInfo")

            async for message_data in connection.messages():
                try:
                    # Parse beat info messages and update analytics
                    await self.dashboard.handle_beat_message(device_id, message_data)

                except Exception as e:
                    logger.debug(
                        "Error processing beat info message from %s: %s", device_id, e
                    )
                    continue

        except Exception as e:
            logger.error("BeatInfo service error with %s: %s", device_id, e)
        finally:
            self.dashboard.unregister_device(device_id, "BeatInfo")


class AnalyticsDashboard:
    """Main analytics dashboard that processes data from multiple devices."""

    def __init__(self, state_port: int = 51338, beat_port: int = 51339):
        self.state_port = state_port
        self.beat_port = beat_port
        self.listener: StagelinQListener | None = None

        # Analytics data storage
        self.devices: dict[str, DeviceMetrics] = {}
        self.decks: dict[str, DeckState] = {}  # deck_key -> DeckState
        self.session_start_time = datetime.now()

        # Track transition detection
        self.track_history: list[dict[str, Any]] = []
        self.transition_events: list[dict[str, Any]] = []

        # Beat sync analysis
        self.beat_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.sync_analysis: dict[str, Any] = {}

        # Performance metrics
        self.state_update_rate = defaultdict(
            lambda: deque(maxlen=60)
        )  # Last 60 seconds
        self.beat_update_rate = defaultdict(lambda: deque(maxlen=60))

    def _get_deck_key(self, device_id: str, deck_name: str) -> str:
        """Generate unique key for a deck across devices."""
        return f"{device_id}:{deck_name}"

    def register_device(self, device_id: str, service_type: str) -> None:
        """Register a new device connection."""
        if device_id not in self.devices:
            self.devices[device_id] = DeviceMetrics(device_id=device_id)
            logger.info("Registered new device: %s", device_id)

        self.devices[device_id].last_heartbeat = datetime.now()
        self.devices[device_id].is_connected = True

    def unregister_device(self, device_id: str, service_type: str) -> None:
        """Unregister a device connection."""
        if device_id in self.devices:
            self.devices[device_id].is_connected = False
            logger.info("Device disconnected: %s (%s)", device_id, service_type)

    async def handle_state_message(self, device_id: str, message_data: bytes) -> None:
        """Process incoming state map messages."""
        try:
            # Update device metrics
            if device_id in self.devices:
                self.devices[device_id].state_updates_count += 1
                self.devices[device_id].last_heartbeat = datetime.now()

                # Track update rate
                current_time = time.time()
                self.state_update_rate[device_id].append(current_time)

            # Parse state message using existing logic
            from stagelinq.messages import LengthPrefixedReader, StateEmitMessage

            reader = LengthPrefixedReader(message_data)
            message_content = reader.read_message()

            if not message_content:
                return

            # Try to parse as StateEmitMessage
            try:
                state_msg = StateEmitMessage()
                state_msg.read_from(message_content)

                # Convert to typed state
                state = State.from_json_data(state_msg.name, state_msg.json_data)

                # Process the state update
                await self._process_state_update(device_id, state)

            except Exception as e:
                logger.debug("Failed to parse state message: %s", e)

        except Exception as e:
            logger.warning("Error handling state message from %s: %s", device_id, e)

    async def handle_beat_message(self, device_id: str, message_data: bytes) -> None:
        """Process incoming beat info messages."""
        try:
            # Update device metrics
            if device_id in self.devices:
                self.devices[device_id].beat_updates_count += 1
                self.devices[device_id].last_heartbeat = datetime.now()

                # Track update rate
                current_time = time.time()
                self.beat_update_rate[device_id].append(current_time)

            # Parse beat message
            beat_msg = parse_beat_message(message_data)
            if beat_msg and isinstance(beat_msg, BeatEmitMessage):
                await self._process_beat_update(device_id, beat_msg)

        except Exception as e:
            logger.warning("Error handling beat message from %s: %s", device_id, e)

    async def _process_state_update(self, device_id: str, state: State) -> None:
        """Process a state update and update analytics."""
        # Extract deck information from state name
        deck_name = self._extract_deck_name(state.name)
        if not deck_name:
            return

        deck_key = self._get_deck_key(device_id, deck_name)

        # Ensure deck exists
        if deck_key not in self.decks:
            self.decks[deck_key] = DeckState(deck_id=deck_name, device_id=device_id)

        deck = self.decks[deck_key]

        # Update deck state based on the state name and value
        typed_value = state.get_typed_value()

        if "PlayState" in state.name:
            was_playing = deck.is_playing
            deck.is_playing = state.is_boolean_state() and typed_value

            # Detect play state changes
            if was_playing != deck.is_playing:
                await self._handle_play_state_change(deck, deck.is_playing)

        elif "CurrentBPM" in state.name:
            if state.is_float_value():
                deck.current_bpm = typed_value
                deck.current_track.bpm = typed_value

        elif "DeckIsMaster" in state.name:
            deck.is_master = state.is_boolean_state() and typed_value

        elif "PitchFaderPosition" in state.name:
            if state.is_float_value():
                deck.pitch_fader = typed_value

        elif "ChannelVolume" in state.name:
            if state.is_float_value():
                deck.volume = typed_value

        elif "LoopEnableState" in state.name:
            deck.loop_enabled = state.is_boolean_state() and typed_value

        elif "TrackTitle" in state.name or "Track/Title" in state.name:
            if state.value_type == StateValueType.STRING:
                old_title = deck.current_track.title
                deck.current_track.title = typed_value

                # Detect track changes
                if old_title and old_title != typed_value:
                    await self._handle_track_change(deck, old_title, typed_value)

        elif "TrackArtist" in state.name or "Track/Artist" in state.name:
            if state.value_type == StateValueType.STRING:
                deck.current_track.artist = typed_value

        elif "TrackAlbum" in state.name or "Track/Album" in state.name:
            if state.value_type == StateValueType.STRING:
                deck.current_track.album = typed_value

        elif "TrackKey" in state.name:
            if state.value_type == StateValueType.STRING:
                deck.current_track.key = typed_value

        elif "PlayPosition" in state.name:
            if state.is_float_value():
                deck.current_track.play_position = typed_value

            # Try to extract device name from state paths
        if "Engine" in state.name and (
            device_id in self.devices and not self.devices[device_id].device_name
        ):
            self.devices[device_id].device_name = "Denon Engine"

    def _extract_deck_name(self, state_name: str) -> str | None:
        """Extract deck name from state path."""
        # Look for deck identifiers in the state name
        parts = state_name.split("/")
        for part in parts:
            if part.startswith("Deck") and len(part) > 4:
                return part
            elif part in ["Deck1", "Deck2", "Deck3", "Deck4"]:
                return part
        return None

    async def _process_beat_update(
        self, device_id: str, beat_msg: BeatEmitMessage
    ) -> None:
        """Process a beat message and update beat analytics."""
        current_time = datetime.now()

        # Store beat information for each player
        for i, player in enumerate(beat_msg.players):
            deck_name = f"Deck{i + 1}"
            deck_key = self._get_deck_key(device_id, deck_name)

            if deck_key in self.decks:
                deck = self.decks[deck_key]
                deck.last_beat_time = current_time
                deck.beat_count += 1

                # Update BPM from beat message if more accurate
                if player.bpm > 0:
                    deck.current_bpm = player.bpm
                    deck.current_track.bpm = player.bpm

            # Store beat history for sync analysis
            beat_data = {
                "timestamp": current_time.timestamp(),
                "beat": player.beat,
                "bpm": player.bpm,
                "total_beats": player.total_beats,
            }
            self.beat_history[deck_key].append(beat_data)

        # Analyze beat synchronization across decks
        await self._analyze_beat_sync()

    async def _handle_play_state_change(
        self, deck: DeckState, is_playing: bool
    ) -> None:
        """Handle play state changes for transition detection."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "device_id": deck.device_id,
            "deck_id": deck.deck_id,
            "event_type": "play" if is_playing else "pause",
            "track": {
                "title": deck.current_track.title,
                "artist": deck.current_track.artist,
                "bpm": deck.current_track.bpm,
            },
        }

        self.transition_events.append(event)
        logger.info(
            "Play state change: %s %s on %s",
            deck.deck_id,
            "started" if is_playing else "paused",
            deck.device_id,
        )

    async def _handle_track_change(
        self, deck: DeckState, old_title: str, new_title: str
    ) -> None:
        """Handle track changes and add to history."""
        # Save previous track to history
        if old_title:
            track_end = {
                "timestamp": datetime.now().isoformat(),
                "device_id": deck.device_id,
                "deck_id": deck.deck_id,
                "track": {
                    "title": old_title,
                    "artist": deck.current_track.artist,
                    "bpm": deck.current_track.bpm,
                },
                "play_duration": (
                    datetime.now() - deck.current_track.load_time
                ).total_seconds(),
            }
            self.track_history.append(track_end)

        # Reset track load time for new track
        deck.current_track.load_time = datetime.now()

        logger.info(
            "Track change on %s %s: '%s' -> '%s'",
            deck.device_id,
            deck.deck_id,
            old_title,
            new_title,
        )

    async def _analyze_beat_sync(self) -> None:
        """Analyze beat synchronization between decks."""
        if len(self.beat_history) < 2:
            return

        current_time = time.time()
        # Get recent beats from all decks (last 5 seconds)
        recent_beats = {}
        for deck_key, beats in self.beat_history.items():
            if recent := [b for b in beats if current_time - b["timestamp"] < 5.0]:
                recent_beats[deck_key] = recent

        # Analyze sync between playing decks
        playing_decks = [k for k, deck in self.decks.items() if deck.is_playing]

        if len(playing_decks) >= 2:
            sync_analysis = {
                "timestamp": current_time,
                "playing_decks": len(playing_decks),
                "sync_pairs": [],
            }

            sync_threshold = 0.1  # 100ms tolerance for sync

            # Compare each pair of playing decks
            for i, deck1_key in enumerate(playing_decks):
                for deck2_key in playing_decks[i + 1 :]:
                    if deck1_key in recent_beats and deck2_key in recent_beats:
                        sync_quality = self._calculate_sync_quality(
                            recent_beats[deck1_key],
                            recent_beats[deck2_key],
                            sync_threshold,
                        )

                        sync_analysis["sync_pairs"].append(
                            {
                                "deck1": deck1_key,
                                "deck2": deck2_key,
                                "sync_quality": sync_quality,
                            }
                        )

            self.sync_analysis = sync_analysis

    def _calculate_sync_quality(
        self, beats1: list[dict], beats2: list[dict], threshold: float
    ) -> float:
        """Calculate sync quality between two sets of beats."""
        if not beats1 or not beats2:
            return 0.0

        # Find beat pairs within threshold
        sync_count = 0
        total_comparisons = 0

        for beat1 in beats1[-10:]:  # Last 10 beats
            for beat2 in beats2[-10:]:
                time_diff = abs(beat1["timestamp"] - beat2["timestamp"])
                if time_diff < threshold:
                    sync_count += 1
                total_comparisons += 1

        return sync_count / total_comparisons if total_comparisons > 0 else 0.0

    def get_analytics_summary(self) -> dict[str, Any]:
        """Get comprehensive analytics summary."""
        current_time = datetime.now()
        session_duration = current_time - self.session_start_time

        # Calculate update rates
        device_rates = {}
        for device_id in self.devices:
            state_rate = (
                len(
                    [
                        t
                        for t in self.state_update_rate[device_id]
                        if time.time() - t < 60
                    ]
                )
                / 60.0
            )  # Updates per second
            beat_rate = (
                len(
                    [
                        t
                        for t in self.beat_update_rate[device_id]
                        if time.time() - t < 60
                    ]
                )
                / 60.0
            )
            device_rates[device_id] = {
                "state_updates_per_sec": round(state_rate, 2),
                "beat_updates_per_sec": round(beat_rate, 2),
            }

        # Active decks summary
        active_decks = []
        for _deck_key, deck in self.decks.items():
            if deck.is_playing or deck.current_track.is_complete():
                active_decks.append(
                    {
                        "device_id": deck.device_id,
                        "deck_id": deck.deck_id,
                        "is_playing": deck.is_playing,
                        "is_master": deck.is_master,
                        "current_bpm": deck.current_bpm,
                        "track": {
                            "title": deck.current_track.title,
                            "artist": deck.current_track.artist,
                            "bpm": deck.current_track.bpm,
                        },
                    }
                )

        return {
            "session": {
                "start_time": self.session_start_time.isoformat(),
                "duration_seconds": session_duration.total_seconds(),
                "connected_devices": len(
                    [d for d in self.devices.values() if d.is_connected]
                ),
            },
            "devices": {
                device_id: {
                    "name": metrics.device_name or device_id,
                    "connected": metrics.is_connected,
                    "connection_time": metrics.connection_time.isoformat(),
                    "state_updates": metrics.state_updates_count,
                    "beat_updates": metrics.beat_updates_count,
                    "update_rates": device_rates.get(device_id, {}),
                }
                for device_id, metrics in self.devices.items()
            },
            "active_decks": active_decks,
            "sync_analysis": self.sync_analysis,
            "recent_transitions": self.transition_events[-10:],  # Last 10 events
            "track_history_count": len(self.track_history),
            "statistics": {
                "total_tracks_played": len(self.track_history),
                "total_transitions": len(self.transition_events),
                "average_track_duration": self._calculate_average_track_duration(),
            },
        }

    def _calculate_average_track_duration(self) -> float:
        """Calculate average track duration from history."""
        if not self.track_history:
            return 0.0

        durations = [
            track.get("play_duration", 0)
            for track in self.track_history
            if track.get("play_duration", 0) > 0
        ]
        return sum(durations) / len(durations) if durations else 0.0

    async def start(self) -> None:
        """Start the analytics dashboard."""
        # Create custom listener with analytics services
        self.listener = StagelinQListener()

        # Add custom analytics services
        # Note: These services need the dashboard instance as a 3rd argument
        # TODO: Refactor services to take dashboard as kwarg for cleaner API
        state_service = AnalyticsStateMapService(
            self.state_port, self.listener.token, self
        )
        beat_service = AnalyticsBeatInfoService(
            self.beat_port, self.listener.token, self
        )

        self.listener.services["StateMap"] = state_service
        self.listener.services["BeatInfo"] = beat_service

        # Update offered services
        from stagelinq.listener import ServiceInfo

        self.listener.offered_services.extend(
            [
                ServiceInfo(
                    name="StateMap",
                    port=self.state_port,
                    handler_class=AnalyticsStateMapService,
                ),
                ServiceInfo(
                    name="BeatInfo",
                    port=self.beat_port,
                    handler_class=AnalyticsBeatInfoService,
                ),
            ]
        )

        await self.listener.start()
        logger.info("Analytics Dashboard started - listening for device connections")

    async def stop(self) -> None:
        """Stop the analytics dashboard."""
        if self.listener:
            await self.listener.stop()

    async def print_status_loop(self, interval: float = 10.0) -> None:
        """Print periodic status updates."""
        while True:
            try:
                summary = self.get_analytics_summary()

                print(f"\n{'=' * 60}")
                print(f"DJ ANALYTICS DASHBOARD - {datetime.now().strftime('%H:%M:%S')}")
                print(f"{'=' * 60}")

                # Session info
                session = summary["session"]
                duration = timedelta(seconds=int(session["duration_seconds"]))
                print(f"Session Duration: {duration}")
                print(f"Connected Devices: {session['connected_devices']}")

                # Device status
                if summary["devices"]:
                    print("\nDEVICE STATUS:")
                    for _device_id, device in summary["devices"].items():
                        status = "[ONLINE]" if device["connected"] else "[OFFLINE]"
                        rates = device["update_rates"]
                        print(f"  {status} {device['name']}")
                        print(
                            f"     States: {device['state_updates']} total ({rates.get('state_updates_per_sec', 0)}/sec)"
                        )
                        print(
                            f"     Beats: {device['beat_updates']} total ({rates.get('beat_updates_per_sec', 0)}/sec)"
                        )

                # Active decks
                if summary["active_decks"]:
                    print("\nACTIVE DECKS:")
                    for deck in summary["active_decks"]:
                        status = "▶️" if deck["is_playing"] else "⏸️"
                        master = "👑" if deck["is_master"] else "  "
                        track = deck["track"]
                        print(
                            f"  {status}{master} {deck['device_id']} {deck['deck_id']}: {deck['current_bpm']:.1f} BPM"
                        )
                        if track["title"]:
                            print(f"      '{track['title']}' by {track['artist']}")

                # Beat sync analysis
                if summary["sync_analysis"] and summary["sync_analysis"].get(
                    "sync_pairs"
                ):
                    print("\nBEAT SYNC ANALYSIS:")
                    for pair in summary["sync_analysis"]["sync_pairs"]:
                        quality = pair["sync_quality"] * 100
                        sync_icon = (
                            "🔄" if quality > 80 else "⚠️" if quality > 50 else "❌"
                        )
                        print(
                            f"  {sync_icon} {pair['deck1']} ↔ {pair['deck2']}: {quality:.1f}% sync"
                        )

                # Statistics
                stats = summary["statistics"]
                print("\nSESSION STATISTICS:")
                print(f"  Tracks Played: {stats['total_tracks_played']}")
                print(f"  Transitions: {stats['total_transitions']}")
                if stats["average_track_duration"] > 0:
                    avg_duration = timedelta(
                        seconds=int(stats["average_track_duration"])
                    )
                    print(f"  Avg Track Duration: {avg_duration}")

                await asyncio.sleep(interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in status loop: %s", e)
                await asyncio.sleep(interval)


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Enhanced DJ Analytics Dashboard using StagelinQ Listener"
    )
    parser.add_argument(
        "--state-port",
        type=int,
        default=51338,
        help="Port for StateMap service (default: 51338)",
    )
    parser.add_argument(
        "--beat-port",
        type=int,
        default=51339,
        help="Port for BeatInfo service (default: 51339)",
    )
    parser.add_argument(
        "--status-interval",
        type=float,
        default=10.0,
        help="Status update interval in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--export", type=Path, help="Export analytics data to JSON file on exit"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Create analytics dashboard
    dashboard = AnalyticsDashboard(state_port=args.state_port, beat_port=args.beat_port)

    # Setup graceful shutdown
    shutdown_event = asyncio.Event()

    def signal_handler():
        logger.info("Shutdown signal received")
        shutdown_event.set()

    signal.signal(signal.SIGINT, lambda s, f: signal_handler())
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler())

    try:
        # Start dashboard
        await dashboard.start()

        # Start status monitoring
        status_task = asyncio.create_task(
            dashboard.print_status_loop(args.status_interval)
        )

        print("\n[ANALYTICS] DJ Analytics Dashboard Running")
        print(f"StateMap Service: Port {args.state_port}")
        print(f"BeatInfo Service: Port {args.beat_port}")
        print("Waiting for DJ devices to connect...")
        print("Press Ctrl+C to stop\n")

        # Wait for shutdown
        await shutdown_event.wait()

        # Cancel status task
        status_task.cancel()
        try:
            await status_task
        except asyncio.CancelledError:
            pass

    finally:
        # Export analytics if requested
        if args.export:
            try:
                summary = dashboard.get_analytics_summary()
                summary["export_time"] = datetime.now().isoformat()
                summary["full_track_history"] = dashboard.track_history
                summary["full_transition_events"] = dashboard.transition_events

                with open(args.export, "w") as f:
                    json.dump(summary, f, indent=2)
                logger.info("Analytics data exported to %s", args.export)
            except Exception as e:
                logger.error("Failed to export analytics: %s", e)

        # Stop dashboard
        await dashboard.stop()
        logger.info("Analytics Dashboard stopped")


if __name__ == "__main__":
    asyncio.run(main())
