"""Unit tests for FileTransfer functionality."""

import asyncio
import io
import pytest
from unittest.mock import Mock, AsyncMock, patch

from stagelinq.file_transfer import (
    FileTransferConnection,
    FileTransferRequestMessage,
    FileTransferResponseMessage,
    FileInfo,
    FileSource,
    FLTX_MAGIC,
    FILE_TRANSFER_REQUEST_SOURCES,
    FILE_TRANSFER_REQUEST_END,
)
from stagelinq.messages import Token


class TestFileInfo:
    """Test FileInfo data class."""
    
    def test_file_info_creation(self):
        """Test FileInfo creation and string representation."""
        file_info = FileInfo(
            path="/Music/track.mp3",
            name="track.mp3",
            size=1024,
            modified_time="2024-01-01T10:00:00Z",
            is_directory=False
        )
        
        assert file_info.path == "/Music/track.mp3"
        assert file_info.name == "track.mp3"
        assert file_info.size == 1024
        assert file_info.modified_time == "2024-01-01T10:00:00Z"
        assert file_info.is_directory is False
        assert "FILE: track.mp3 (1024 bytes)" in str(file_info)
    
    def test_directory_info_creation(self):
        """Test FileInfo for directory."""
        dir_info = FileInfo(
            path="/Music",
            name="Music",
            is_directory=True
        )
        
        assert dir_info.is_directory is True
        assert "DIR: Music" in str(dir_info)


class TestFileSource:
    """Test FileSource data class."""
    
    def test_file_source_creation(self):
        """Test FileSource creation and string representation."""
        source = FileSource(
            name="Music (SD)",
            database_path="/Music/database.db",
            database_size=2048
        )
        
        assert source.name == "Music (SD)"
        assert source.database_path == "/Music/database.db"
        assert source.database_size == 2048
        assert "Music (SD) -> /Music/database.db (2048 bytes)" in str(source)


class TestFileTransferRequestMessage:
    """Test FileTransferRequestMessage."""
    
    def test_request_message_creation(self):
        """Test request message creation."""
        msg = FileTransferRequestMessage(FILE_TRANSFER_REQUEST_SOURCES)
        assert msg.request_type == FILE_TRANSFER_REQUEST_SOURCES
    
    def test_request_message_serialization(self):
        """Test request message serialization."""
        msg = FileTransferRequestMessage(FILE_TRANSFER_REQUEST_SOURCES)
        
        writer = io.BytesIO()
        msg.write_to(writer)
        data = writer.getvalue()
        
        # Check that data contains the request type, end marker, and final marker
        assert len(data) > 0
        
        # Read back the data
        reader = io.BytesIO(data)
        read_msg = FileTransferRequestMessage()
        read_msg.read_from(reader)
        
        assert read_msg.request_type == FILE_TRANSFER_REQUEST_SOURCES
    
    def test_request_message_default_type(self):
        """Test request message with default type."""
        msg = FileTransferRequestMessage()
        assert msg.request_type == FILE_TRANSFER_REQUEST_SOURCES


class TestFileTransferResponseMessage:
    """Test FileTransferResponseMessage."""
    
    def test_response_message_creation(self):
        """Test response message creation."""
        msg = FileTransferResponseMessage()
        assert msg.sources == []
    
    def test_response_message_parsing_empty(self):
        """Test parsing empty response."""
        msg = FileTransferResponseMessage()
        reader = io.BytesIO(b"")
        msg.read_from(reader)
        
        assert msg.sources == []
    
    def test_response_message_parsing_with_data(self):
        """Test parsing response with some data."""
        # Create mock response data
        test_data = b"\x00\x00\x10\x00some test data\x00\x00"
        
        msg = FileTransferResponseMessage()
        reader = io.BytesIO(test_data)
        msg.read_from(reader)
        
        # The current implementation is a placeholder parser
        # so we just verify it doesn't crash
        assert isinstance(msg.sources, list)


class TestFileTransferConnection:
    """Test FileTransferConnection class."""
    
    def test_connection_creation(self):
        """Test FileTransferConnection creation."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        assert conn.host == "192.168.1.100"
        assert conn.port == 50000
        assert conn.token == token
        assert conn._connection is None
        assert conn._sources == []
    
    @pytest.mark.asyncio
    async def test_connection_context_manager(self):
        """Test FileTransferConnection as async context manager."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        with patch.object(conn, 'connect', new_callable=AsyncMock) as mock_connect:
            with patch.object(conn, 'disconnect', new_callable=AsyncMock) as mock_disconnect:
                async with conn:
                    pass
                
                mock_connect.assert_called_once()
                mock_disconnect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful connection."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        
        with patch('stagelinq.file_transfer.StageLinqConnection', return_value=mock_stagelinq_conn):
            await conn.connect()
            
            assert conn._connection == mock_stagelinq_conn
            mock_stagelinq_conn.connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connect_failure(self):
        """Test connection failure."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        mock_stagelinq_conn.connect.side_effect = Exception("Connection failed")
        
        with patch('stagelinq.file_transfer.StageLinqConnection', return_value=mock_stagelinq_conn):
            with pytest.raises(ConnectionError, match="Failed to connect to FileTransfer service"):
                await conn.connect()
    
    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test disconnection."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        conn._connection = mock_stagelinq_conn
        
        await conn.disconnect()
        
        mock_stagelinq_conn.disconnect.assert_called_once()
        assert conn._connection is None
    
    @pytest.mark.asyncio
    async def test_get_sources_not_connected(self):
        """Test get_sources when not connected."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        with pytest.raises(RuntimeError, match="Not connected"):
            await conn.get_sources()
    
    @pytest.mark.asyncio
    async def test_get_sources_success(self):
        """Test successful source discovery."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        mock_stagelinq_conn.receive_message.return_value = b"mock_response_data"
        conn._connection = mock_stagelinq_conn
        
        sources = await conn.get_sources()
        
        assert isinstance(sources, list)
        mock_stagelinq_conn.send_message.assert_called_once()
        mock_stagelinq_conn.receive_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_sources_no_response(self):
        """Test get_sources with no response."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        mock_stagelinq_conn.receive_message.return_value = None
        conn._connection = mock_stagelinq_conn
        
        sources = await conn.get_sources()
        
        assert sources == []
    
    @pytest.mark.asyncio
    async def test_download_database_not_connected(self):
        """Test download_database when not connected."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        with pytest.raises(RuntimeError, match="Not connected"):
            await conn.download_database("Music (SD)")
    
    @pytest.mark.asyncio
    async def test_download_database_source_not_found(self):
        """Test download_database with unknown source."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        conn._connection = mock_stagelinq_conn
        conn._sources = [FileSource("Other Source", "/path", 1024)]
        
        with pytest.raises(FileNotFoundError, match="Source not found: Music \\(SD\\)"):
            await conn.download_database("Music (SD)")
    
    @pytest.mark.asyncio
    async def test_download_database_placeholder(self):
        """Test download_database returns placeholder."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        conn._connection = mock_stagelinq_conn
        conn._sources = [FileSource("Music (SD)", "/Music/database.db", 2048)]
        
        result = await conn.download_database("Music (SD)")
        
        # Currently returns placeholder empty bytes
        assert result == b""
    
    @pytest.mark.asyncio
    async def test_get_database_info_not_connected(self):
        """Test get_database_info when not connected."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        with pytest.raises(RuntimeError, match="Not connected"):
            await conn.get_database_info("Music (SD)")
    
    @pytest.mark.asyncio
    async def test_get_database_info_success(self):
        """Test successful database info retrieval."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        conn._connection = mock_stagelinq_conn
        
        test_source = FileSource("Music (SD)", "/Music/database.db", 2048)
        conn._sources = [test_source]
        
        info = await conn.get_database_info("Music (SD)")
        
        assert info == {
            'source_name': 'Music (SD)',
            'database_path': '/Music/database.db',
            'database_size': 2048
        }
    
    @pytest.mark.asyncio
    async def test_get_database_info_not_found(self):
        """Test get_database_info with unknown source."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        conn._connection = mock_stagelinq_conn
        conn._sources = [FileSource("Other Source", "/path", 1024)]
        
        with pytest.raises(FileNotFoundError, match="Source not found: Music \\(SD\\)"):
            await conn.get_database_info("Music (SD)")
    
    @pytest.mark.asyncio
    async def test_list_sources(self):
        """Test list_sources method."""
        token = Token(b"\x00" * 16)
        conn = FileTransferConnection("192.168.1.100", 50000, token)
        
        mock_stagelinq_conn = AsyncMock()
        mock_stagelinq_conn.receive_message.return_value = b"mock_response_data"
        conn._connection = mock_stagelinq_conn
        
        # Mock the _sources to simulate discovered sources
        test_sources = [
            FileSource("Music (SD)", "/Music/database.db", 2048),
            FileSource("Music (USB)", "/USB/database.db", 1024)
        ]
        
        with patch.object(conn, 'get_sources', return_value=test_sources):
            source_names = await conn.list_sources()
            
            assert source_names == ["Music (SD)", "Music (USB)"]


class TestFileTransferConstants:
    """Test FileTransfer constants."""
    
    def test_constants_defined(self):
        """Test that required constants are defined."""
        assert FLTX_MAGIC == b"fltx"
        assert FILE_TRANSFER_REQUEST_SOURCES == 0x7d2
        assert FILE_TRANSFER_REQUEST_END == 0x0


if __name__ == "__main__":
    pytest.main([__file__])