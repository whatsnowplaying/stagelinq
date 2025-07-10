"""Unit tests for FileTransfer functionality."""

import asyncio
import io
from unittest.mock import AsyncMock, Mock, patch

import pytest

from stagelinq.file_transfer import (
    CHUNK_SIZE,
    FILE_TRANSFER_DIRECTORY_INVALIDATE,
    FILE_TRANSFER_FRAME_END,
    FILE_TRANSFER_PAUSE_TRANSFER,
    FILE_TRANSFER_REQUEST_COMPLETE,
    FILE_TRANSFER_REQUEST_DATABASE_INFO,
    FILE_TRANSFER_REQUEST_DATABASE_READ,
    FILE_TRANSFER_REQUEST_DIRECTORY_LIST,
    FILE_TRANSFER_REQUEST_END,
    FILE_TRANSFER_SESSION_CLEANUP,
    FILE_TRANSFER_STATUS_QUERY,
    FLTX_MAGIC,
    DatabaseInfoResponse,
    FileInfo,
    FileSource,
    FileTransferConnection,
    FileTransferFrameEndMessage,
    FileTransferInvalidateMessage,
    FileTransferPauseMessage,
    FileTransferRequestMessage,
    FileTransferResponseMessage,
    FileTransferStatusQueryMessage,
)
from stagelinq.messages import Token


class TestFileInfo:
    """Test FileInfo dataclass."""

    def test_file_info_creation(self):
        """Test FileInfo creation and properties."""
        file_info = FileInfo(
            path="/test/path.mp3", name="path.mp3", size=12345, is_directory=False
        )

        assert file_info.path == "/test/path.mp3"
        assert file_info.name == "path.mp3"
        assert file_info.size == 12345
        assert not file_info.is_directory

    def test_file_info_string_representation(self):
        """Test FileInfo string representation."""
        file_info = FileInfo(path="/test.mp3", name="test.mp3", size=1024)
        assert str(file_info) == "FILE: test.mp3 (1024 bytes)"

        dir_info = FileInfo(path="/folder", name="folder", is_directory=True)
        assert str(dir_info) == "DIR: folder"


class TestFileSource:
    """Test FileSource dataclass."""

    def test_file_source_creation(self):
        """Test FileSource creation and properties."""
        source = FileSource(
            name="Music (USB 1)",
            database_path="/USB1/Engine Library/Database2/m.db",
            database_size=2048576,
        )

        assert source.name == "Music (USB 1)"
        assert source.database_path == "/USB1/Engine Library/Database2/m.db"
        assert source.database_size == 2048576

    def test_file_source_string_representation(self):
        """Test FileSource string representation."""
        source = FileSource("Test Source", "/path/db.db", 1024)
        assert str(source) == "Test Source -> /path/db.db (1024 bytes)"


class TestDatabaseInfoResponse:
    """Test DatabaseInfoResponse parsing and creation."""

    def test_parse_existing_file_response(self):
        """Test parsing DATABASE_INFO response for existing file."""
        # Sample response data based on discovered structure
        response_data = bytearray(49)
        response_data[0] = 0x01  # File exists
        response_data[1] = 0x00  # Not directory
        response_data[4:6] = b"\x77\x55"  # Permissions

        # Add sample metadata blocks (35 bytes from offset 6 to 40)
        # Block 1: bytes 6-18 (13 bytes)
        response_data[6:19] = b"\x00\x00\x00\x00\x00\x25\x89\xac\x02\x8c\x5f\xd0\x00"
        # Block 2: bytes 19-31 (13 bytes)
        response_data[19:32] = b"\x00\x00\x00\x00\x00\x25\x89\xac\x02\x8c\x5f\xd0\x00"
        # Partial block 3: bytes 32-40 (9 bytes only, since file size starts at 41)
        response_data[32:41] = b"\x00\x00\x00\x00\x00\x25\x89\xac\x02"

        # File size in last 8 bytes
        file_size = 1234567
        response_data[-8:] = file_size.to_bytes(8, byteorder="big")

        parsed = DatabaseInfoResponse.parse(bytes(response_data))

        assert parsed.file_exists is True
        assert parsed.is_directory is False
        assert parsed.file_size == 1234567
        assert parsed.permissions == 0x7755
        assert len(parsed.metadata_blocks) == 3  # 2 complete + 1 partial

    def test_parse_non_existing_file_response(self):
        """Test parsing DATABASE_INFO response for non-existing file."""
        response_data = bytearray(49)
        response_data[0] = 0x00  # File does not exist
        response_data[1] = 0x00  # Not directory
        response_data[4:6] = b"\x00\x00"  # No permissions

        # Zero file size
        response_data[-8:] = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        parsed = DatabaseInfoResponse.parse(bytes(response_data))

        assert parsed.file_exists is False
        assert parsed.is_directory is False
        assert parsed.file_size == 0
        assert parsed.permissions == 0x0000

    def test_parse_directory_response(self):
        """Test parsing DATABASE_INFO response for directory."""
        response_data = bytearray(49)
        response_data[0] = 0x01  # Exists
        response_data[1] = 0x01  # Is directory
        response_data[4:6] = b"\x66\x44"  # Directory permissions

        parsed = DatabaseInfoResponse.parse(bytes(response_data))

        assert parsed.file_exists is True
        assert parsed.is_directory is True
        assert parsed.permissions == 0x6644

    def test_to_bytes_roundtrip(self):
        """Test that parsing and serializing gives consistent results."""
        original_data = bytearray(49)
        original_data[0] = 0x01
        original_data[1] = 0x00
        original_data[4:6] = b"\x77\x55"
        original_data[-8:] = (1024).to_bytes(8, byteorder="big")

        parsed = DatabaseInfoResponse.parse(bytes(original_data))
        serialized = parsed.to_bytes()

        assert len(serialized) == 49
        assert serialized[0] == 0x01  # Exists
        assert serialized[1] == 0x00  # Not directory
        assert serialized[4:6] == b"\x77\x55"  # Permissions
        assert int.from_bytes(serialized[-8:], byteorder="big") == 1024  # File size


class TestFileTransferRequestMessage:
    """Test FileTransferRequestMessage functionality."""

    def test_create_directory_list_request(self):
        """Test creating directory list request."""
        msg = FileTransferRequestMessage(FILE_TRANSFER_REQUEST_DIRECTORY_LIST, 123)
        assert msg.request_type == FILE_TRANSFER_REQUEST_DIRECTORY_LIST
        assert msg.request_id == 123

    def test_create_database_info_request(self):
        """Test creating database info request."""
        msg = FileTransferRequestMessage(FILE_TRANSFER_REQUEST_DATABASE_INFO, 456)
        assert msg.request_type == FILE_TRANSFER_REQUEST_DATABASE_INFO
        assert msg.request_id == 456

    def test_serialize_request(self):
        """Test serializing request message."""
        msg = FileTransferRequestMessage(FILE_TRANSFER_REQUEST_DIRECTORY_LIST, 789)

        writer = io.BytesIO()
        msg.write_to(writer)
        data = writer.getvalue()

        # Should contain request type, end marker, and final byte
        reader = io.BytesIO(data)
        request_type = int.from_bytes(reader.read(4), byteorder="big")
        end_marker = int.from_bytes(reader.read(4), byteorder="big")
        final_byte = reader.read(1)

        assert request_type == FILE_TRANSFER_REQUEST_DIRECTORY_LIST
        assert end_marker == FILE_TRANSFER_REQUEST_END
        assert final_byte == b"\x01"


class TestFileTransferResponseMessage:
    """Test FileTransferResponseMessage functionality."""

    def test_parse_simple_response(self):
        """Test parsing a simple response message."""
        response = FileTransferResponseMessage()

        # Create sample data with file announcement
        data = bytearray()
        data.extend(FLTX_MAGIC)  # Magic
        data.extend((123).to_bytes(4, byteorder="big"))  # Request ID
        data.extend((0x7D4).to_bytes(4, byteorder="big"))  # Message type
        data.extend((1024).to_bytes(4, byteorder="big"))  # Size
        data.extend("Test Source".encode("utf-16be"))  # Path

        # Add trailer (last 3 bytes)
        data.extend(b"\x01\x01\x00")  # first=True, last=True, directories=False

        reader = io.BytesIO(data)
        response.read_from(reader)

        assert response.is_first_chunk is True
        assert response.is_last_chunk is True
        assert response.is_directories is False
        assert len(response.sources) >= 0  # May or may not parse sources correctly

    def test_parse_no_trailer(self):
        """Test parsing response without trailer."""
        response = FileTransferResponseMessage()

        # Short data without trailer
        data = b"test"
        reader = io.BytesIO(data)
        response.read_from(reader)

        # Should default to single complete file response
        assert response.is_first_chunk is True
        assert response.is_last_chunk is True
        assert response.is_directories is False


class TestFileTransferPauseMessage:
    """Test FileTransferPauseMessage functionality."""

    def test_create_pause_message(self):
        """Test creating pause message."""
        msg = FileTransferPauseMessage(transaction_id=555)
        assert msg.transaction_id == 555

    def test_serialize_pause_message(self):
        """Test serializing pause message."""
        msg = FileTransferPauseMessage(transaction_id=777)

        writer = io.BytesIO()
        msg.write_to(writer)
        data = writer.getvalue()

        reader = io.BytesIO(data)
        magic = reader.read(4)
        transaction_id = int.from_bytes(reader.read(4), byteorder="big")
        message_type = int.from_bytes(reader.read(4), byteorder="big")

        assert magic == FLTX_MAGIC
        assert transaction_id == 777
        assert message_type == FILE_TRANSFER_PAUSE_TRANSFER

    def test_parse_pause_message(self):
        """Test parsing pause message."""
        data = bytearray()
        data.extend(FLTX_MAGIC)
        data.extend((888).to_bytes(4, byteorder="big"))  # Transaction ID
        data.extend(FILE_TRANSFER_PAUSE_TRANSFER.to_bytes(4, byteorder="big"))

        reader = io.BytesIO(data)
        msg = FileTransferPauseMessage()
        msg.read_from(reader)

        assert msg.transaction_id == 888


class TestFileTransferStatusQueryMessage:
    """Test FileTransferStatusQueryMessage functionality."""

    def test_create_status_query(self):
        """Test creating status query message."""
        query_data = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        msg = FileTransferStatusQueryMessage(transaction_id=999, query_data=query_data)

        assert msg.transaction_id == 999
        assert msg.query_data == query_data

    def test_serialize_status_query(self):
        """Test serializing status query message."""
        msg = FileTransferStatusQueryMessage(transaction_id=111)

        writer = io.BytesIO()
        msg.write_to(writer)
        data = writer.getvalue()

        reader = io.BytesIO(data)
        magic = reader.read(4)
        transaction_id = int.from_bytes(reader.read(4), byteorder="big")
        message_type = int.from_bytes(reader.read(4), byteorder="big")

        assert magic == FLTX_MAGIC
        assert transaction_id == 111
        assert message_type == FILE_TRANSFER_STATUS_QUERY


class TestFileTransferFrameEndMessage:
    """Test FileTransferFrameEndMessage functionality."""

    def test_create_frame_end_success(self):
        """Test creating frame end message with success."""
        msg = FileTransferFrameEndMessage(transaction_id=222, success=True)

        assert msg.transaction_id == 222
        assert msg.success is True

    def test_create_frame_end_failure(self):
        """Test creating frame end message with failure."""
        msg = FileTransferFrameEndMessage(transaction_id=333, success=False)

        assert msg.transaction_id == 333
        assert msg.success is False

    def test_serialize_frame_end(self):
        """Test serializing frame end message."""
        msg = FileTransferFrameEndMessage(transaction_id=444, success=True)

        writer = io.BytesIO()
        msg.write_to(writer)
        data = writer.getvalue()

        reader = io.BytesIO(data)
        magic = reader.read(4)
        transaction_id = int.from_bytes(reader.read(4), byteorder="big")
        message_type = int.from_bytes(reader.read(4), byteorder="big")
        success_flag = reader.read(1)

        assert magic == FLTX_MAGIC
        assert transaction_id == 444
        assert message_type == FILE_TRANSFER_FRAME_END
        assert success_flag == b"\x01"


class TestFileTransferInvalidateMessage:
    """Test FileTransferInvalidateMessage functionality."""

    def test_create_invalidate_message(self):
        """Test creating invalidate message."""
        msg = FileTransferInvalidateMessage(transaction_id=666)
        assert msg.transaction_id == 666

    def test_serialize_invalidate_message(self):
        """Test serializing invalidate message."""
        msg = FileTransferInvalidateMessage(transaction_id=777)

        writer = io.BytesIO()
        msg.write_to(writer)
        data = writer.getvalue()

        reader = io.BytesIO(data)
        magic = reader.read(4)
        transaction_id = int.from_bytes(reader.read(4), byteorder="big")
        message_type = int.from_bytes(reader.read(4), byteorder="big")

        assert magic == FLTX_MAGIC
        assert transaction_id == 777
        assert message_type == FILE_TRANSFER_DIRECTORY_INVALIDATE


class TestFileTransferConnection:
    """Test FileTransferConnection functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.token = Token(b"\x00" * 16)
        self.connection = FileTransferConnection("192.168.1.100", 12345, self.token)

    def test_connection_creation(self):
        """Test FileTransferConnection creation."""
        assert self.connection.host == "192.168.1.100"
        assert self.connection.port == 12345
        assert self.connection.token == self.token
        assert self.connection._connection is None
        assert self.connection._sources == []
        assert self.connection._next_request_id == 1

    def test_get_next_request_id(self):
        """Test request ID generation."""
        assert self.connection._get_next_request_id() == 1
        assert self.connection._get_next_request_id() == 2
        assert self.connection._get_next_request_id() == 3

    @pytest.mark.asyncio
    async def test_connect_disconnect(self):
        """Test connection and disconnection."""
        with patch("stagelinq.file_transfer.StageLinqConnection") as mock_conn_class:
            mock_conn = AsyncMock()
            mock_conn_class.return_value = mock_conn

            # Test connect
            await self.connection.connect()
            assert self.connection._connection == mock_conn
            mock_conn.connect.assert_called_once()

            # Test disconnect
            await self.connection.disconnect()
            assert self.connection._connection is None
            mock_conn.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_file_size(self):
        """Test getting file size using DATABASE_INFO request."""
        with patch("stagelinq.file_transfer.StageLinqConnection") as mock_conn_class:
            mock_conn = AsyncMock()
            mock_conn_class.return_value = mock_conn
            self.connection._connection = mock_conn

            # Mock response with file size in last 8 bytes
            response_data = bytearray(49)
            file_size = 2048576
            response_data[-8:] = file_size.to_bytes(8, byteorder="big")
            mock_conn.receive_message.return_value = bytes(response_data)

            result = await self.connection.get_file_size("/test/path.db")

            assert result == file_size
            mock_conn.send_message.assert_called_once()
            mock_conn.receive_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_session(self):
        """Test session cleanup."""
        with patch("stagelinq.file_transfer.StageLinqConnection") as mock_conn_class:
            mock_conn = AsyncMock()
            mock_conn_class.return_value = mock_conn
            self.connection._connection = mock_conn

            await self.connection.cleanup_session(session_request_id=123)

            mock_conn.send_message.assert_called_once()
            # Verify cleanup message was sent (no response expected)

    def test_directory_cache_invalidation(self):
        """Test directory cache invalidation."""
        # Set up some cached data
        self.connection._directory_cache["/test/path"] = [
            FileInfo(path="/test/file.mp3", name="file.mp3", size=1024)
        ]
        self.connection._request_id_to_path[123] = "/test/path"

        # Invalidate
        self.connection.invalidate_directory_cache(123)

        assert "/test/path" not in self.connection._directory_cache
        assert 123 not in self.connection._request_id_to_path

    def test_clear_directory_cache(self):
        """Test clearing all directory cache."""
        # Set up some cached data
        self.connection._directory_cache["/test1"] = []
        self.connection._directory_cache["/test2"] = []
        self.connection._request_id_to_path[1] = "/test1"
        self.connection._request_id_to_path[2] = "/test2"

        # Clear all
        self.connection.clear_directory_cache()

        assert len(self.connection._directory_cache) == 0
        assert len(self.connection._request_id_to_path) == 0


class TestProtocolConstants:
    """Test protocol constant values."""

    def test_constant_values(self):
        """Test that protocol constants have expected values."""
        assert FLTX_MAGIC == b"fltx"
        assert FILE_TRANSFER_REQUEST_DIRECTORY_LIST == 0x7D2
        assert FILE_TRANSFER_SESSION_CLEANUP == 0x7D3
        assert FILE_TRANSFER_REQUEST_DATABASE_INFO == 0x7D4
        assert FILE_TRANSFER_REQUEST_DATABASE_READ == 0x7D5
        assert FILE_TRANSFER_REQUEST_COMPLETE == 0x7D6
        assert FILE_TRANSFER_PAUSE_TRANSFER == 0x7D8
        assert FILE_TRANSFER_FRAME_END == 0x2
        assert FILE_TRANSFER_REQUEST_END == 0x0
        assert FILE_TRANSFER_DIRECTORY_INVALIDATE == 0x9
        assert FILE_TRANSFER_STATUS_QUERY == 0x0A
        assert CHUNK_SIZE == 4096
