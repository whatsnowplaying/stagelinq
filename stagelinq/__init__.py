"""StageLinq Protocol Implementation for Python

This library implements Denon's StageLinq protocol, allowing Python applications
to communicate with DJ equipment like Denon Prime series devices.
"""

from __future__ import annotations

from .beat_info import BeatInfoConnection
from .connection import MainConnection, Service
from .discovery import Device, DeviceState
from .file_transfer import FileTransferConnection, FileInfo
from .listener import Listener, ListenerConfiguration
from .messages import PlayerInfo, Token
from .state_map import State, StateMapConnection
from .value_names import EngineDeck1, EngineDeck2, EngineDeck3, EngineDeck4

# Re-export exceptions for convenience
from .listener import (
    InvalidDiscovererActionError,
    InvalidMessageError,
    StageLinqError,
    TooShortDiscoveryMessageError,
)

__version__ = "0.1.0"
__all__ = [
    "Device",
    "DeviceState",
    "Listener",
    "ListenerConfiguration",
    "MainConnection",
    "Service",
    "Token",
    "StateMapConnection",
    "State",
    "BeatInfoConnection",
    "PlayerInfo",
    "FileTransferConnection",
    "FileInfo",
    "EngineDeck1",
    "EngineDeck2",
    "EngineDeck3",
    "EngineDeck4",
    # Exceptions
    "StageLinqError",
    "TooShortDiscoveryMessageError",
    "InvalidMessageError",
    "InvalidDiscovererActionError",
]