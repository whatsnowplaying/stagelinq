"""StageLinq file transfer implementation.

Based on the FileTransfer protocol analysis from:
https://github.com/icedream/go-stagelinq/issues/8
"""

from __future__ import annotations

import asyncio
import io
import logging
import struct
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator, Union

from .messages import Token, Message, serializer
from .protocol import StageLinqConnection

logger = logging.getLogger(__name__)

# FileTransfer protocol constants
FLTX_MAGIC = b"fltx"
FILE_TRANSFER_REQUEST_SOURCES = 0x7d2
FILE_TRANSFER_REQUEST_END = 0x0


@dataclass
class FileInfo:
    """Information about a file on the StageLinq device."""
    path: str
    name: str
    size: int | None = None
    modified_time: str | None = None
    is_directory: bool = False

    def __str__(self) -> str:
        type_str = "DIR" if self.is_directory else "FILE"
        size_str = f" ({self.size} bytes)" if self.size is not None else ""
        return f"{type_str}: {self.name}{size_str}"


@dataclass
class FileSource:
    """Information about a file source on the StageLinq device."""
    name: str
    database_path: str
    database_size: int

    def __str__(self) -> str:
        return f"{self.name} -> {self.database_path} ({self.database_size} bytes)"


class FileTransferRequestMessage(Message):
    """Request message for FileTransfer operations."""

    def __init__(self, request_type: int = FILE_TRANSFER_REQUEST_SOURCES):
        self.request_type = request_type

    def read_from(self, reader: io.BinaryIO) -> None:
        """Read message from stream."""
        # Read request type
        self.request_type = serializer.read_uint32(reader)

    def write_to(self, writer: io.BinaryIO) -> None:
        """Write message to stream."""
        # Write request type
        serializer.write_uint32(writer, self.request_type)
        # Write end marker
        serializer.write_uint32(writer, FILE_TRANSFER_REQUEST_END)
        # Write final marker
        writer.write(b'\x01')


class FileTransferResponseMessage(Message):
    """Response message for FileTransfer operations."""

    def __init__(self):
        self.sources: list[FileSource] = []

    def read_from(self, reader: io.BinaryIO) -> None:
        """Read message from stream."""
        # Read all available data
        data = reader.read()
        if not data:
            return

        # Parse the response data
        pos = 0
        while pos < len(data):
            try:
                # Look for source information in the data
                # This is a simplified parser - the actual protocol might be more complex
                if pos + 4 < len(data):
                    # Try to find UTF-16 strings (source names)
                    if data[pos:pos+2] == b'\x00\x00':
                        pos += 2
                        continue

                    # Look for string patterns
                    if pos + 10 < len(data):
                        # Try to extract string
                        try:
                            # Check for UTF-16 string
                            string_data = data[pos:pos+50]
                            if b'\x00' in string_data:
                                # Might be UTF-16
                                null_pos = string_data.find(b'\x00')
                                if null_pos > 0 and null_pos % 2 == 0:
                                    utf16_data = string_data[:null_pos+1]
                                    source_name = utf16_data.decode('utf-16le').rstrip('\x00')
                                    if source_name and len(source_name) > 2:
                                        # Found a potential source name
                                        logger.debug(f"Found potential source: {source_name}")
                        except:
                            pass
                pos += 1
            except:
                break

    def write_to(self, writer: io.BinaryIO) -> None:
        """Write message to stream."""
        # FileTransferResponseMessage is typically only read, not written
        # But we need to implement this for the abstract base class
        pass


class FileTransferConnection:
    """Pythonic FileTransfer connection for accessing device files."""

    def __init__(self, host: str, port: int, token: Token) -> None:
        self.host = host
        self.port = port
        self.token = token
        self._connection: StageLinqConnection | None = None
        self._sources: list[FileSource] = []

    async def __aenter__(self) -> FileTransferConnection:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.disconnect()

    async def connect(self) -> None:
        """Connect to FileTransfer service."""
        if self._connection is not None:
            return

        try:
            self._connection = StageLinqConnection(self.host, self.port)
            await self._connection.connect()
            logger.info(f"Connected to FileTransfer at {self.host}:{self.port}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to FileTransfer service: {e}")

    async def disconnect(self) -> None:
        """Disconnect from FileTransfer service."""
        if self._connection:
            await self._connection.disconnect()
            self._connection = None
        logger.info(f"Disconnected from FileTransfer at {self.host}:{self.port}")

    async def get_sources(self) -> list[FileSource]:
        """Get available file sources from the device."""
        if not self._connection:
            raise RuntimeError("Not connected")

        # Send request for sources
        request = FileTransferRequestMessage(FILE_TRANSFER_REQUEST_SOURCES)

        writer = io.BytesIO()
        request.write_to(writer)
        request_data = writer.getvalue()

        await self._connection.send_message(request_data)

        # Receive response
        response_data = await self._connection.receive_message()
        if not response_data:
            return []

        # Parse response
        response = FileTransferResponseMessage()
        reader = io.BytesIO(response_data)
        response.read_from(reader)

        self._sources = response.sources
        return self._sources

    async def download_database(self, source_name: str, local_path: Union[str, Path] | None = None) -> bytes:
        """Download the Engine Library database from a specific source.

        Args:
            source_name: Name of the source (e.g., "Music (SD)")
            local_path: Optional local path to save the database

        Returns:
            Database file content as bytes
        """
        if not self._connection:
            raise RuntimeError("Not connected")

        # Get sources if not already loaded
        if not self._sources:
            await self.get_sources()

        # Find the requested source
        source = None
        for s in self._sources:
            if s.name == source_name:
                source = s
                break

        if not source:
            raise FileNotFoundError(f"Source not found: {source_name}")

        # TODO: Implement actual file download protocol
        # For now, this is a placeholder that would need to be implemented
        # based on the actual StageLinq file transfer protocol

        logger.warning("File download not yet implemented - placeholder return")
        return b""

    async def get_database_info(self, source_name: str) -> dict:
        """Get database information for a specific source.

        Args:
            source_name: Name of the source (e.g., "Music (SD)")

        Returns:
            Dictionary with database information
        """
        if not self._connection:
            raise RuntimeError("Not connected")

        # Get sources if not already loaded
        if not self._sources:
            await self.get_sources()

        # Find the requested source
        for source in self._sources:
            if source.name == source_name:
                return {
                    'source_name': source.name,
                    'database_path': source.database_path,
                    'database_size': source.database_size
                }

        raise FileNotFoundError(f"Source not found: {source_name}")

    async def list_sources(self) -> list[str]:
        """List all available sources on the device.

        Returns:
            List of source names
        """
        sources = await self.get_sources()
        return [source.name for source in sources]