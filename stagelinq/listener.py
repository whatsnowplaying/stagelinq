"""StagelinQ Listener implementation.

Based on @honusz's Listener approach that allows devices to connect TO software
instead of software discovering and connecting to devices.

This greatly simplifies connection management and enables support for devices
like X1800/X1850 mixers that were previously difficult to work with.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from .discovery import DiscoveryConfig, StagelinQDiscovery
from .file_transfer import FileTransferRequestMessage
from .messages import (
    BeatEmitMessage,
    ReferenceMessage,
    ServiceAnnouncementMessage,
    ServicesRequestMessage,
    StateEmitMessage,
    Token,
)
from .protocol import StagelinQConnection

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """Information about a service offered by the listener."""

    name: str
    port: int
    handler_class: type


class StagelinQService(ABC):
    """Base class for StagelinQ services that can accept device connections."""

    def __init__(self, port: int, token: Token):
        self.port = port
        self.token = token
        self.connections: dict[str, StagelinQConnection] = {}
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        """Start the service listener."""
        self._server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.port
        )
        logger.info("Started %s service on port %d", self.__class__.__name__, self.port)

    async def stop(self) -> None:
        """Stop the service listener."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # Close all connections
        for conn in self.connections.values():
            await conn.disconnect()
        self.connections.clear()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming device connection."""
        try:
            # Get peer address for identification
            peer_addr = writer.get_extra_info("peername")
            device_id = f"{peer_addr[0]}:{peer_addr[1]}"

            logger.info(
                "Device connected to %s: %s", self.__class__.__name__, device_id
            )

            # Create StagelinQ connection wrapper
            connection = StagelinQConnection.from_streams(reader, writer)
            self.connections[device_id] = connection

            # Handle the specific service protocol
            await self.handle_device_connection(device_id, connection)

        except Exception as e:
            logger.error(
                "Error handling connection to %s: %s", self.__class__.__name__, e
            )
        finally:
            if device_id in self.connections:
                del self.connections[device_id]
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as close_exc:
                logger.warning("Error closing writer for %s: %s", device_id, close_exc)

    @abstractmethod
    async def handle_device_connection(
        self, device_id: str, connection: StagelinQConnection
    ) -> None:
        """Handle device-specific protocol for this service."""


class DirectoryService(StagelinQService):
    """Directory service that handles initial device connections and service announcements."""

    def __init__(self, port: int, token: Token, offered_services: list[ServiceInfo]):
        super().__init__(port, token)
        self.offered_services = offered_services

    async def handle_device_connection(
        self, device_id: str, connection: StagelinQConnection
    ) -> None:
        """Handle directory service protocol.

        The Directory Service performs a single handshake:
        1. Wait for ServicesRequestMessage (0x2) from device
        2. Send service announcements for all offered services
        3. Send reference message to complete handshake
        4. Exit - handshake complete, device will connect to actual services

        This avoids blocking indefinitely waiting for additional messages
        after the handshake is complete.
        """
        try:
            # Directory service performs a single handshake then exits
            logger.debug("Waiting for services request from %s", device_id)

            # Wait for the initial services request (0x2) with timeout
            message_data = await asyncio.wait_for(
                connection.receive_message(),
                timeout=30.0,  # 30 second timeout for handshake
            )

            if not message_data:
                logger.warning("No services request received from %s", device_id)
                return

            try:
                request = ServicesRequestMessage.deserialize(message_data)
                logger.debug("Received services request from %s", device_id)
            except Exception as e:
                logger.error("Invalid services request from %s: %s", device_id, e)
                return

            # Send service announcements for all offered services
            for service_info in self.offered_services:
                announcement = ServiceAnnouncementMessage(
                    token=self.token,
                    service=service_info.name,
                    port=service_info.port,
                )
                await connection.send_message(announcement.serialize())
                logger.debug(
                    "Announced %s service on port %d to %s",
                    service_info.name,
                    service_info.port,
                    device_id,
                )

            # Send reference message to complete handshake
            reference = ReferenceMessage(
                token=self.token, token2=request.token, reference=0
            )
            await connection.send_message(reference.serialize())

            logger.info("Directory service handshake completed for %s", device_id)
            # Handshake complete - connection will be closed by caller

        except asyncio.TimeoutError:
            logger.warning("Directory service handshake timeout for %s", device_id)
        except Exception as e:
            logger.error("Directory service error with %s: %s", device_id, e)


class FileTransferService(StagelinQService):
    """File transfer service that can serve files to devices."""

    def __init__(self, port: int, token: Token, file_handler=None):
        super().__init__(port, token)
        self.file_handler = file_handler  # Custom file serving logic
        self.error_counts: dict[str, int] = {}
        self.max_parsing_errors = 10  # Higher threshold for file transfer

    async def handle_device_connection(
        self, device_id: str, connection: StagelinQConnection
    ) -> None:
        """Handle file transfer service protocol."""
        try:
            # Initialize error count for this device
            self.error_counts[device_id] = 0
            logger.info("Device %s connected to FileTransfer service", device_id)

            async for message_data in connection.messages():
                try:
                    # Try to parse as FileTransferRequestMessage (fltx protocol)
                    # Parse the fltx header to determine message type
                    reader = io.BytesIO(message_data)
                    request = FileTransferRequestMessage()
                    request.read_from(reader)

                    logger.debug(
                        "Received file transfer request 0x%x from %s",
                        request.request_type,
                        device_id,
                    )

                    # TODO: Implement actual request handling based on request_type:
                    # - 0x7D2: DIRECTORY_LIST - respond with directory contents
                    # - 0x7D4: DATABASE_INFO - respond with file metadata
                    # - 0x7D5: DATABASE_READ - respond with file chunks
                    # - 0x7D3: SESSION_CLEANUP - clean up session

                    # For now, log the request details
                    logger.info(
                        "FileTransfer request: type=0x%x, id=%d, path='%s'",
                        request.request_type,
                        request.request_id,
                        request.path,
                    )

                    # Reset error count on successful parse
                    self.error_counts[device_id] = 0

                except Exception as e:
                    self.error_counts[device_id] += 1

                    if self.error_counts[device_id] <= 3:
                        logger.debug(
                            "Error parsing file transfer message from %s: %s",
                            device_id,
                            e,
                        )
                    else:
                        logger.warning(
                            "Repeated file transfer parsing errors from %s (%d/%d): %s",
                            device_id,
                            self.error_counts[device_id],
                            self.max_parsing_errors,
                            e,
                        )

                    if self.error_counts[device_id] >= self.max_parsing_errors:
                        logger.error(
                            "Device %s exceeded maximum file transfer parsing errors (%d), disconnecting",
                            device_id,
                            self.max_parsing_errors,
                        )
                        break

                    continue

        except Exception as e:
            logger.error("File transfer service error with %s: %s", device_id, e)
        finally:
            # Clean up error count and device state
            self.error_counts.pop(device_id, None)
            logger.info("Device %s disconnected from FileTransfer service", device_id)


class StateMapService(StagelinQService):
    """StateMap service for monitoring device states."""

    def __init__(self, port: int, token: Token):
        super().__init__(port, token)
        self.error_counts: dict[str, int] = {}
        self.max_parsing_errors = 15  # Higher threshold for streaming data

    async def handle_device_connection(
        self, device_id: str, connection: StagelinQConnection
    ) -> None:
        """Handle StateMap service protocol."""
        try:
            # Initialize error count for this device
            self.error_counts[device_id] = 0
            logger.info("Device %s connected to StateMap service", device_id)

            async for message_data in connection.messages():
                try:
                    # Try to parse as StateEmitMessage (smaa protocol)
                    # Parse state message
                    msg = StateEmitMessage.deserialize(message_data)

                    # Parse the JSON value
                    try:
                        value = json.loads(msg.json_data)
                    except (json.JSONDecodeError, ValueError):
                        # If JSON parsing fails, use the raw string
                        value = msg.json_data

                    logger.debug(
                        "Received state update from %s: %s = %s",
                        device_id,
                        msg.name,
                        value,
                    )

                    # TODO: Implement actual state handling:
                    # - Store state updates in database/cache
                    # - Trigger callbacks for specific state changes
                    # - Forward updates to connected clients
                    # - Handle state subscription requests

                    # For now, log significant state changes
                    if any(
                        keyword in msg.name.lower()
                        for keyword in ["play", "track", "bpm", "position", "loaded"]
                    ):
                        logger.info(
                            "StateMap update from %s: %s = %s",
                            device_id,
                            msg.name,
                            value,
                        )

                    # Reset error count on successful parse
                    self.error_counts[device_id] = 0

                except Exception as e:
                    self.error_counts[device_id] += 1

                    if self.error_counts[device_id] <= 5:
                        logger.debug(
                            "Error parsing state message from %s: %s", device_id, e
                        )
                    else:
                        logger.warning(
                            "Repeated state parsing errors from %s (%d/%d): %s",
                            device_id,
                            self.error_counts[device_id],
                            self.max_parsing_errors,
                            e,
                        )

                    if self.error_counts[device_id] >= self.max_parsing_errors:
                        logger.error(
                            "Device %s exceeded maximum state parsing errors (%d), disconnecting",
                            device_id,
                            self.max_parsing_errors,
                        )
                        break

                    continue

        except Exception as e:
            logger.error("StateMap service error with %s: %s", device_id, e)
        finally:
            # Clean up error count and device state
            self.error_counts.pop(device_id, None)
            logger.info("Device %s disconnected from StateMap service", device_id)


class BeatInfoService(StagelinQService):
    """BeatInfo service for receiving beat timing information."""

    def __init__(self, port: int, token: Token):
        super().__init__(port, token)
        self.error_counts: dict[str, int] = {}
        self.max_parsing_errors = 20  # Highest threshold for high-frequency beat data

    async def handle_device_connection(
        self, device_id: str, connection: StagelinQConnection
    ) -> None:
        """Handle BeatInfo service protocol."""
        try:
            # Initialize error count for this device
            self.error_counts[device_id] = 0
            logger.info("Device %s connected to BeatInfo service", device_id)

            async for message_data in connection.messages():
                try:
                    # Try to parse as BeatEmitMessage (beat protocol)

                    # Parse beat message
                    msg = BeatEmitMessage.deserialize(message_data)

                    logger.debug(
                        "Received beat info from %s: clock=%d, players=%d",
                        device_id,
                        msg.clock,
                        len(msg.players),
                    )

                    # TODO: Implement actual beat handling:
                    # - Store beat timing for sync analysis
                    # - Trigger beat-aligned effects/lighting
                    # - Calculate tempo changes and drift
                    # - Sync multiple devices to master clock

                    # For now, log significant tempo/beat changes from players
                    for i, player in enumerate(msg.players):
                        if player.bpm > 0:
                            # Only log occasionally to avoid spam (every 16 beats)
                            if int(player.beat) % 16 == 0:
                                logger.info(
                                    "BeatInfo from %s player %d: BPM=%.2f, beat=%.2f",
                                    device_id,
                                    i + 1,
                                    player.bpm,
                                    player.beat,
                                )

                    # Reset error count on successful parse
                    self.error_counts[device_id] = 0

                except Exception as e:
                    self.error_counts[device_id] += 1

                    if self.error_counts[device_id] <= 5:
                        logger.debug(
                            "Error parsing beat message from %s: %s", device_id, e
                        )
                    else:
                        logger.warning(
                            "Repeated beat parsing errors from %s (%d/%d): %s",
                            device_id,
                            self.error_counts[device_id],
                            self.max_parsing_errors,
                            e,
                        )

                    if self.error_counts[device_id] >= self.max_parsing_errors:
                        logger.error(
                            "Device %s exceeded maximum beat parsing errors (%d), disconnecting",
                            device_id,
                            self.max_parsing_errors,
                        )
                        break

                    continue

        except Exception as e:
            logger.error("BeatInfo service error with %s: %s", device_id, e)
        finally:
            # Clean up error count and device state
            self.error_counts.pop(device_id, None)
            logger.info("Device %s disconnected from BeatInfo service", device_id)


class StagelinQListener:
    """Main listener that manages all StagelinQ services and device connections."""

    def __init__(self, discovery_port: int = 51337):
        # Use special token format that devices accept (starts with 0xFF...)
        self.token = Token(
            b"\xff\xff\xff\xff\xff\xff\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
        )
        self.discovery_port = discovery_port
        self.services: dict[str, StagelinQService] = {}
        self.offered_services: list[ServiceInfo] = []
        self._discovery_task: asyncio.Task | None = None

    def add_service(
        self, service_name: str, port: int, service_class: type, **kwargs
    ) -> None:
        """Add a service that devices can connect to."""
        service_info = ServiceInfo(
            name=service_name, port=port, handler_class=service_class
        )
        self.offered_services.append(service_info)

        # Create service instance with additional kwargs
        service = service_class(port, self.token, **kwargs)
        self.services[service_name] = service

        logger.info("Added %s service on port %d", service_name, port)

    async def start(self) -> None:
        """Start the listener with all configured services."""
        # Start directory service (required)
        directory_service = DirectoryService(
            self.discovery_port, self.token, self.offered_services
        )
        self.services["Directory"] = directory_service
        await directory_service.start()

        # Start all other services
        for service in self.services.values():
            if service != directory_service:
                await service.start()

        # Start discovery announcements
        self._discovery_task = asyncio.create_task(self._announce_discovery())

        logger.info(
            "StagelinQ Listener started on port %d with %d services",
            self.discovery_port,
            len(self.services),
        )

    async def stop(self) -> None:
        """Stop the listener and all services."""
        if self._discovery_task:
            self._discovery_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._discovery_task
        # Stop all services
        for service in self.services.values():
            await service.stop()

        self.services.clear()
        logger.info("StagelinQ Listener stopped")

    async def _announce_discovery(self) -> None:
        """Continuously announce discovery to attract device connections."""
        config = DiscoveryConfig(
            name="Python StagelinQ Listener",
            software_name="python-stagelinq",
            software_version="0.2.0",
            port=self.discovery_port,
            token=self.token,
            announce_interval=5.0,  # Announce every 5 seconds
        )

        discovery = StagelinQDiscovery(config)

        try:
            await discovery.start()
            await discovery.start_announcing()
            # The announce loop runs in a background task and sends periodic announcements.
            # We just need to keep this coroutine alive until cancelled.
            while True:
                await asyncio.sleep(1.0)  # Check for cancellation every second
        except asyncio.CancelledError:
            pass
        finally:
            await discovery.stop()
