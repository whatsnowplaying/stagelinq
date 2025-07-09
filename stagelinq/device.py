"""StageLinq device connection implementation."""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

from .discovery import Device
from .messages import Token, StateSubscribeMessage, StateEmitMessage, BeatInfoStartStreamMessage, BeatEmitMessage
from .protocol import StageLinqConnection, MessageStream
from .file_transfer import FileTransferConnection

logger = logging.getLogger(__name__)


@dataclass
class Service:
    """Represents a StageLinq service."""
    name: str
    port: int

    def __str__(self) -> str:
        return f"{self.name}:{self.port}"


@dataclass
class State:
    """Represents a device state value."""
    name: str
    value: any

    def __str__(self) -> str:
        return f"{self.name}={self.value}"


@dataclass
class BeatInfo:
    """Represents beat timing information."""
    clock: int
    players: list[PlayerInfo]
    timelines: list[float]

    def __str__(self) -> str:
        return f"BeatInfo(clock={self.clock}, players={len(self.players)})"


@dataclass
class PlayerInfo:
    """Information about a player's beat state."""
    beat: float
    total_beats: float
    bpm: float

    def __str__(self) -> str:
        return f"Player(beat={self.beat:.2f}, bpm={self.bpm:.1f})"


class DeviceConnection:
    """Pythonic async connection to a StageLinq device."""

    def __init__(self, device: Device, token: Token) -> None:
        self.device = device
        self.token = token
        self._connection: StageLinqConnection | None = None
        self._services: list[Service] | None = None

    async def __aenter__(self) -> DeviceConnection:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()

    async def connect(self) -> None:
        """Connect to the device."""
        if self._connection is not None:
            return

        try:
            self._connection = StageLinqConnection(self.device.ip, self.device.port)
            await self._connection.connect()
            logger.info(f"Connected to device {self.device}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.device}: {e}")

    async def disconnect(self) -> None:
        """Disconnect from the device."""
        if self._connection:
            await self._connection.disconnect()
            self._connection = None
        logger.info(f"Disconnected from device {self.device}")

    async def discover_services(self) -> list[Service]:
        """Discover available services on the device."""
        if self._services is not None:
            return self._services

        # Implement proper service discovery protocol
        # Connect to main port and request services
        main_conn = StageLinqConnection(self.device.ip, self.device.port)
        services = []

        try:
            await main_conn.connect()

            # Send services request message
            from .messages import ServicesRequestMessage
            request = ServicesRequestMessage(token=self.token)
            await main_conn.send_message(request.serialize())

            # Collect service announcements until we get a reference message
            async for message_data in main_conn.messages():
                try:
                    # Try to parse as service announcement
                    from .messages import ServiceAnnouncementMessage
                    service_msg = ServiceAnnouncementMessage.deserialize(message_data)
                    services.append(Service(service_msg.service, service_msg.port))
                    continue
                except Exception:
                    pass

                try:
                    # Try to parse as reference message (signals end of services)
                    from .messages import ReferenceMessage
                    ReferenceMessage.deserialize(message_data)
                    break  # End of services list
                except Exception:
                    pass

        finally:
            await main_conn.disconnect()

        self._services = services
        return self._services

    @asynccontextmanager
    async def state_map(self) -> AsyncIterator[StateMap]:
        """Get a StateMap connection."""
        services = await self.discover_services()
        state_service = next((s for s in services if s.name == "StateMap"), None)
        if not state_service:
            raise ValueError("StateMap service not available")

        state_map = StateMap(self.device.ip, state_service.port, self.token)
        try:
            await state_map.connect()
            yield state_map
        finally:
            await state_map.disconnect()

    @asynccontextmanager
    async def beat_info(self) -> AsyncIterator[BeatInfoStream]:
        """Get a BeatInfo connection."""
        services = await self.discover_services()
        beat_service = next((s for s in services if s.name == "BeatInfo"), None)
        if not beat_service:
            raise ValueError("BeatInfo service not available")

        beat_info = BeatInfoStream(self.device.ip, beat_service.port, self.token)
        try:
            await beat_info.connect()
            yield beat_info
        finally:
            await beat_info.disconnect()

    @asynccontextmanager
    async def file_transfer(self) -> AsyncIterator[FileTransferConnection]:
        """Get a FileTransfer connection."""
        services = await self.discover_services()
        file_service = next((s for s in services if s.name == "FileTransfer"), None)
        if not file_service:
            raise ValueError("FileTransfer service not available")

        file_transfer = FileTransferConnection(self.device.ip, file_service.port, self.token)
        try:
            await file_transfer.connect()
            yield file_transfer
        finally:
            await file_transfer.disconnect()


class StateMap:
    """Pythonic StateMap connection for monitoring device state."""

    def __init__(self, host: str, port: int, token: Token) -> None:
        self.host = host
        self.port = port
        self.token = token
        self._connection: StageLinqConnection | None = None
        self._subscriptions: set[str] = set()

    async def connect(self) -> None:
        """Connect to StateMap service."""
        if self._connection:
            return

        self._connection = StageLinqConnection(self.host, self.port)
        await self._connection.connect()

        # Send service announcement message (required by protocol)
        # This announces our local port to the device, as observed in commercial DJ software
        from .messages import ServiceAnnouncementMessage
        announcement = ServiceAnnouncementMessage(
            token=self.token,
            service="StateMap",
            port=self._connection.local_port
        )
        await self._connection.send_message(announcement.serialize())

        logger.info(f"Connected to StateMap at {self.host}:{self.port}")

    async def disconnect(self) -> None:
        """Disconnect from StateMap service."""
        if self._connection:
            await self._connection.disconnect()
            self._connection = None
        logger.info(f"Disconnected from StateMap at {self.host}:{self.port}")

    async def subscribe(self, state_name: str, interval: int = 0) -> None:
        """Subscribe to state updates."""
        if not self._connection:
            raise RuntimeError("Not connected")

        if state_name in self._subscriptions:
            return

        msg = StateSubscribeMessage(name=state_name, interval=interval)
        await self._connection.send_message(msg.serialize())

        self._subscriptions.add(state_name)
        logger.debug(f"Subscribed to state: {state_name}")

    async def states(self) -> AsyncIterator[State]:
        """Stream state updates."""
        if not self._connection:
            raise RuntimeError("Not connected")

        async for message_data in self._connection.messages():
            try:
                msg = StateEmitMessage.deserialize(message_data)

                # Parse JSON value
                try:
                    value = json.loads(msg.json_data)
                except json.JSONDecodeError:
                    value = msg.json_data

                yield State(name=msg.name, value=value)

            except Exception as e:
                logger.error(f"Error parsing state message: {e}")
                continue


class BeatInfoStream:
    """Pythonic BeatInfo connection for monitoring beat timing."""

    def __init__(self, host: str, port: int, token: Token) -> None:
        self.host = host
        self.port = port
        self.token = token
        self._connection: StageLinqConnection | None = None
        self._streaming = False

    async def connect(self) -> None:
        """Connect to BeatInfo service."""
        if self._connection:
            return

        self._connection = StageLinqConnection(self.host, self.port)
        await self._connection.connect()
        logger.info(f"Connected to BeatInfo at {self.host}:{self.port}")

    async def disconnect(self) -> None:
        """Disconnect from BeatInfo service."""
        if self._streaming:
            await self.stop_stream()

        if self._connection:
            await self._connection.disconnect()
            self._connection = None
        logger.info(f"Disconnected from BeatInfo at {self.host}:{self.port}")

    async def start_stream(self) -> None:
        """Start beat info streaming."""
        if not self._connection:
            raise RuntimeError("Not connected")

        if self._streaming:
            return

        msg = BeatInfoStartStreamMessage()
        await self._connection.send_message(msg.serialize())

        self._streaming = True
        logger.debug("Started beat info streaming")

    async def stop_stream(self) -> None:
        """Stop beat info streaming."""
        self._streaming = False
        logger.debug("Stopped beat info streaming")

    async def beats(self) -> AsyncIterator[BeatInfo]:
        """Stream beat information."""
        if not self._connection:
            raise RuntimeError("Not connected")

        if not self._streaming:
            await self.start_stream()

        async for message_data in self._connection.messages():
            if not self._streaming:
                break

            try:
                msg = BeatEmitMessage.deserialize(message_data)

                yield BeatInfo(
                    clock=msg.clock,
                    players=msg.players,
                    timelines=msg.timelines
                )

            except Exception as e:
                logger.error(f"Error parsing beat message: {e}")
                continue


# Extend the Device class with async methods
class AsyncDevice(Device):
    """Extended device with async connection methods."""

    def connect(self, token: Token) -> DeviceConnection:
        """Create a connection to this device."""
        return DeviceConnection(self, token)

    @asynccontextmanager
    async def state_map(self, token: Token) -> AsyncIterator[StateMap]:
        """Direct state map connection."""
        async with self.connect(token) as conn:
            async with conn.state_map() as state_map:
                yield state_map

    @asynccontextmanager
    async def beat_info(self, token: Token) -> AsyncIterator[BeatInfoStream]:
        """Direct beat info connection."""
        async with self.connect(token) as conn:
            async with conn.beat_info() as beat_info:
                yield beat_info

    @asynccontextmanager
    async def file_transfer(self, token: Token) -> AsyncIterator[FileTransferConnection]:
        """Direct file transfer connection."""
        async with self.connect(token) as conn:
            async with conn.file_transfer() as file_transfer:
                yield file_transfer