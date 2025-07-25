"""StagelinQ Protocol Implementation for Python

This library implements Denon's StagelinQ protocol, allowing Python applications
to communicate with DJ equipment like Denon Prime series devices.

This implementation uses modern async/await patterns for all I/O operations.
"""

from __future__ import annotations

from .device import DeviceConnection, DeviceRegistry, StateCategory
from .discovery import Device, DeviceState, DiscoveryConfig, discover_stagelinq_devices
from .file_transfer import FileInfo, FileTransferConnection
from .listener import StagelinQListener
from .messages import (
    NO_UPDATES_INTERVAL,
    BeatInfoStartStreamMessage,
    BeatInfoStopStreamMessage,
    PlayerInfo,
    Token,
    format_interval,
    is_no_updates_interval,
    parse_beat_message,
)
from .value_names import DeckValueNames

__version__ = "0.1.0"
__all__ = [
    "Device",
    "DeviceState",
    "DeviceConnection",
    "DeviceRegistry",
    "StateCategory",
    "discover_stagelinq_devices",
    "DiscoveryConfig",
    "Token",
    "PlayerInfo",
    "BeatInfoStartStreamMessage",
    "BeatInfoStopStreamMessage",
    "FileTransferConnection",
    "FileInfo",
    "DeckValueNames",
    "StagelinQListener",
    "NO_UPDATES_INTERVAL",
    "format_interval",
    "is_no_updates_interval",
    "parse_beat_message",
]
