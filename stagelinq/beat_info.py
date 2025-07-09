"""
StageLinq Beat Info Connection

This module implements the BeatInfo connection for receiving beat timing information.
Based on the reference implementation from denon-stageLinQ-BeatInfo.
"""

import socket
import struct
import threading
import time
from typing import Iterator
from dataclasses import dataclass
from queue import Queue, Empty
from .messages import (
    Token, BeatInfoStartStreamMessage, BeatInfoStopStreamMessage,
    BeatEmitMessage, PlayerInfo
)


@dataclass
class BeatInfo:
    """Beat information for all players."""
    clock: int
    players: list[PlayerInfo]
    timelines: list[float]


class BeatInfoConnection:
    """Connection for receiving beat timing information from a StageLinq device."""

    def __init__(self, conn: socket.socket, token: Token):
        self.token = token
        self._conn = conn
        self._reader = conn.makefile('rb')
        self._writer = conn.makefile('wb')

        self._beat_queue = Queue()
        self._error_queue = Queue()
        self._shutdown_event = threading.Event()
        self._streaming = False

        # Start background read thread
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._read_thread.start()

    def close(self) -> None:
        """Close the connection."""
        if self._streaming:
            self.stop_stream()

        self._shutdown_event.set()
        try:
            self._reader.close()
            self._writer.close()
            self._conn.close()
        except Exception:
            pass

    def start_stream(self) -> None:
        """Start receiving beat info stream."""
        if self._streaming:
            return

        msg = BeatInfoStartStreamMessage()
        try:
            msg.write_to(self._writer)
            self._writer.flush()
            self._streaming = True
        except Exception as e:
            self._error_queue.put(e)

    def stop_stream(self) -> None:
        """Stop receiving beat info stream."""
        if not self._streaming:
            return

        msg = BeatInfoStopStreamMessage()
        try:
            msg.write_to(self._writer)
            self._writer.flush()
            self._streaming = False
        except Exception as e:
            self._error_queue.put(e)

    def beats(self) -> Iterator[BeatInfo]:
        """
        Iterate over incoming beat info updates.

        Yields:
            BeatInfo objects as they arrive
        """
        while not self._shutdown_event.is_set():
            try:
                # Check for errors first
                try:
                    error = self._error_queue.get_nowait()
                    raise error
                except Empty:
                    pass

                # Get next beat info with timeout
                try:
                    beat_info = self._beat_queue.get(timeout=0.1)
                    yield beat_info
                except Empty:
                    continue

            except Exception:
                break

    def get_beat_info(self, timeout: float = 1.0) -> BeatInfo | None:
        """
        Get the next beat info update.

        Args:
            timeout: Timeout in seconds

        Returns:
            BeatInfo object or None if timeout
        """
        try:
            # Check for errors first
            try:
                error = self._error_queue.get_nowait()
                raise error
            except Empty:
                pass

            return self._beat_queue.get(timeout=timeout)
        except Empty:
            return None

    def _read_loop(self) -> None:
        """Background thread that reads beat info messages."""
        try:
            while not self._shutdown_event.is_set():
                try:
                    # Read the length prefix first
                    size_data = self._reader.read(4)
                    if not size_data or len(size_data) != 4:
                        break

                    size = struct.unpack('>I', size_data)[0]
                    if size == 0:
                        continue

                    # Read the message payload
                    raw_data = self._reader.read(size)
                    if not raw_data or len(raw_data) != size:
                        break

                    # Parse the beat info message using the reference format
                    beat_info = self._parse_beat_info_message(raw_data)
                    if beat_info:
                        self._beat_queue.put(beat_info)

                except Exception as e:
                    if not self._shutdown_event.is_set():
                        self._error_queue.put(e)
                    break

        except Exception:
            pass  # Thread is shutting down

    def _parse_beat_info_message(self, raw_data: bytes) -> BeatInfo | None:
        """Parse beat info message - handles both 80-byte and 288-byte formats."""
        try:
            # Check for the message marker (0x00000002)
            if raw_data[:4] != b'\x00\x00\x00\x02':
                return None

            # Determine format based on message length
            if len(raw_data) == 80:
                # 80-byte format (actual capture format)
                return self._parse_beat_info_80_byte(raw_data)
            elif len(raw_data) >= 288:
                # 288-byte format (reference implementation format)
                return self._parse_beat_info_288_byte(raw_data)
            else:
                return None

        except Exception:
            return None

    def _parse_beat_info_80_byte(self, raw_data: bytes) -> BeatInfo | None:
        """Parse the 80-byte BeatInfo format found in actual captures."""
        try:
            # Basic structure analysis from captured data:
            # 0-4: marker (0x00000002)
            # 4-8: unknown field (0x00000008)
            # 8-12: clock/timestamp (changes between packets)
            # 12-16: unknown field
            # Rest: appears to be mostly zeros with some patterns

            # Extract clock value (appears to be at offset 8-12)
            clock = struct.unpack('>I', raw_data[8:12])[0]

            # For now, create minimal player info since the 80-byte format
            # doesn't seem to contain the same detailed player data as 288-byte format
            # This is a simplified representation
            players = []
            timelines = []

            # Create placeholder player data (we need to study more captures to understand the format)
            for i in range(4):
                player = PlayerInfo(
                    beat=0.0,
                    total_beats=0.0,
                    bpm=120.0  # Default BPM
                )
                players.append(player)
                timelines.append(0.0)

            return BeatInfo(
                clock=clock,
                players=players,
                timelines=timelines
            )

        except Exception:
            return None

    def _parse_beat_info_288_byte(self, raw_data: bytes) -> BeatInfo | None:
        """Parse the 288-byte BeatInfo format from reference implementation."""
        try:
            # Parse the data according to the reference bit map
            # Clock is at bytes 8-16 (8 bytes, big endian)
            clock = struct.unpack('>Q', raw_data[8:16])[0]

            # Parse player data
            players = []
            timelines = []

            # Player 1: beats 32-48, beatTotal 48-64, bpm 64-80, timeline 224-240
            # Player 2: beats 80-96, beatTotal 96-112, bpm 112-128, timeline 240-256
            # Player 3: beats 128-144, beatTotal 144-160, bpm 160-176, timeline 256-272
            # Player 4: beats 176-192, beatTotal 192-208, bpm 208-224, timeline 272-288

            player_offsets = [
                (32, 48, 64, 224),  # Player 1
                (80, 96, 112, 240),  # Player 2
                (128, 144, 160, 256),  # Player 3
                (176, 192, 208, 272)   # Player 4
            ]

            for beat_offset, beat_total_offset, bmp_offset, timeline_offset in player_offsets:
                # Extract player data (all doubles, big endian)
                beat = struct.unpack('>d', raw_data[beat_offset:beat_offset+8])[0]
                beat_total = struct.unpack('>d', raw_data[beat_total_offset:beat_total_offset+8])[0]
                bpm = struct.unpack('>d', raw_data[bmp_offset:bmp_offset+8])[0]
                timeline = struct.unpack('>Q', raw_data[timeline_offset:timeline_offset+8])[0]

                # Create PlayerInfo object
                player = PlayerInfo(
                    beat=beat,
                    total_beats=beat_total,
                    bpm=bpm
                )
                players.append(player)
                timelines.append(float(timeline))

            return BeatInfo(
                clock=clock,
                players=players,
                timelines=timelines
            )

        except Exception:
            return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()