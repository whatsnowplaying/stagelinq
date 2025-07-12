"""Tests for StagelinQ device connections."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from stagelinq.device import (
    AsyncDevice,
    BeatInfo,
    BeatInfoStream,
    DeviceConnection,
    PlayerInfo,
    Service,
    State,
    StateMap,
)
from stagelinq.discovery import Device, DeviceState
from stagelinq.messages import Token


def test_service_creation():
    """Test service creation and string representation."""
    service = Service(name="StateMap", port=51338)
    assert service.name == "StateMap"
    assert service.port == 51338
    assert str(service) == "StateMap:51338"


def test_state_creation():
    """Test state creation and string representation."""
    state = State(name="/Engine/Deck1/Play", value=True)
    assert state.name == "/Engine/Deck1/Play"
    assert state.value is True
    assert str(state) == "/Engine/Deck1/Play=True"


def test_player_info_creation():
    """Test player info creation and string representation."""
    player = PlayerInfo(beat=1.5, total_beats=256.0, bpm=128.0)
    assert player.beat == 1.5
    assert player.total_beats == 256.0
    assert player.bpm == 128.0
    assert str(player) == "Player(beat=1.50, bpm=128.0)"


def test_beat_info_creation():
    """Test beat info creation and string representation."""
    players = [
        PlayerInfo(beat=1.0, total_beats=100.0, bpm=120.0),
        PlayerInfo(beat=2.0, total_beats=200.0, bpm=140.0),
    ]
    timelines = [10.0, 20.0]

    beat_info = BeatInfo(clock=12345, players=players, timelines=timelines)
    assert beat_info.clock == 12345
    assert len(beat_info.players) == 2
    assert beat_info.timelines == [10.0, 20.0]
    assert str(beat_info) == "BeatInfo(clock=12345, players=2)"


@pytest.fixture
def mock_device():
    """Create a mock device for testing."""
    token = Token(b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c")
    return Device(
        ip="192.168.1.100",
        name="Test Device",
        software_name="Test OS",
        software_version="1.0.0",
        port=51337,
        token=token,
    )


@pytest.fixture
def mock_token():
    """Create a mock token for testing."""
    return Token(b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c")


@pytest.mark.asyncio
async def test_device_connection_context_manager(mock_device, mock_token):
    """Test DeviceConnection as async context manager."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        async with DeviceConnection(mock_device, mock_token) as conn:
            assert conn.device == mock_device
            assert conn.token == mock_token
            assert conn._connection is mock_conn

        # Should close connection
        mock_conn.disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_device_connection_connect_disconnect(mock_device, mock_token):
    """Test explicit connect/disconnect."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        conn = DeviceConnection(mock_device, mock_token)

        # Test connect
        await conn.connect()
        assert conn._connection is mock_conn
        mock_conn_class.assert_called_once_with("192.168.1.100", 51337)
        mock_conn.connect.assert_called_once()

        # Test disconnect
        await conn.disconnect()
        assert conn._connection is None
        mock_conn.disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_device_connection_connect_error(mock_device, mock_token):
    """Test connection error handling."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn_class.side_effect = OSError("Connection failed")

        conn = DeviceConnection(mock_device, mock_token)

        with pytest.raises(ConnectionError, match="Failed to connect"):
            await conn.connect()


@pytest.mark.asyncio
async def test_device_connection_double_connect(mock_device, mock_token):
    """Test that double connect is handled gracefully."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        conn = DeviceConnection(mock_device, mock_token)

        # First connect
        await conn.connect()
        call_count = mock_conn_class.call_count
        connect_call_count = mock_conn.connect.call_count

        # Second connect should be no-op
        await conn.connect()
        assert mock_conn_class.call_count == call_count
        assert mock_conn.connect.call_count == connect_call_count

        await conn.disconnect()


@pytest.mark.asyncio
async def test_device_connection_discover_services(mock_device, mock_token):
    """Test service discovery."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        # Create mock service discovery responses
        from stagelinq.messages import ReferenceMessage, ServiceAnnouncementMessage

        # Mock service announcements
        statemap_service = ServiceAnnouncementMessage(
            token=mock_token, service="StateMap", port=51338
        )
        beatinfo_service = ServiceAnnouncementMessage(
            token=mock_token, service="BeatInfo", port=51339
        )
        reference_msg = ReferenceMessage(
            token=mock_token, token2=mock_device.token, reference=0
        )

        # Mock the service discovery message sequence
        async def mock_messages():
            yield statemap_service.serialize()
            yield beatinfo_service.serialize()
            yield reference_msg.serialize()

        mock_conn.messages = mock_messages

        conn = DeviceConnection(mock_device, mock_token)
        await conn.connect()

        # First call should discover services
        services = await conn.discover_services()
        assert len(services) == 2
        assert any(s.name == "StateMap" and s.port == 51338 for s in services)
        assert any(s.name == "BeatInfo" and s.port == 51339 for s in services)

        # Verify the services request was sent
        mock_conn.send_message.assert_called()
        call_args = mock_conn.send_message.call_args[0][0]
        from stagelinq.messages import ServicesRequestMessage

        request_msg = ServicesRequestMessage.deserialize(call_args)
        assert request_msg.token == mock_token

        # Second call should return cached services
        mock_conn.send_message.reset_mock()
        services2 = await conn.discover_services()
        assert services2 is services
        mock_conn.send_message.assert_not_called()  # Should not request again

        await conn.disconnect()


@pytest.mark.asyncio
async def test_device_connection_state_map_context(mock_device, mock_token):
    """Test state map context manager."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        conn = DeviceConnection(mock_device, mock_token)
        await conn.connect()

        # Mock service discovery to return StateMap service
        from stagelinq.device import Service

        mock_services = [Service("StateMap", 51338), Service("BeatInfo", 51339)]
        conn._services = mock_services

        # Mock the StateMap connection
        with patch("stagelinq.device.StateMap") as mock_state_map_class:
            mock_state_map = AsyncMock()
            mock_state_map_class.return_value = mock_state_map

            async with conn.state_map() as state_map:
                assert state_map is mock_state_map
                mock_state_map.connect.assert_called_once()

            mock_state_map.disconnect.assert_called_once()

        await conn.disconnect()


@pytest.mark.asyncio
async def test_device_connection_beat_info_context(mock_device, mock_token):
    """Test beat info context manager."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        conn = DeviceConnection(mock_device, mock_token)
        await conn.connect()

        # Mock service discovery to return BeatInfo service
        from stagelinq.device import Service

        mock_services = [Service("StateMap", 51338), Service("BeatInfo", 51339)]
        conn._services = mock_services

        # Mock the BeatInfoStream connection
        with patch("stagelinq.device.BeatInfoStream") as mock_beat_info_class:
            mock_beat_info = AsyncMock()
            mock_beat_info_class.return_value = mock_beat_info

            async with conn.beat_info() as beat_info:
                assert beat_info is mock_beat_info
                mock_beat_info.connect.assert_called_once()

            mock_beat_info.disconnect.assert_called_once()

        await conn.disconnect()


@pytest.mark.asyncio
async def test_state_map_connect_disconnect(mock_token):
    """Test StateMap connect/disconnect."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        state_map = StateMap("192.168.1.100", 51338, mock_token)

        # Test connect
        await state_map.connect()
        assert state_map._connection is mock_conn
        mock_conn_class.assert_called_once_with("192.168.1.100", 51338)
        mock_conn.connect.assert_called_once()
        mock_conn.send_message.assert_called_once()  # Service announcement

        # Test disconnect
        await state_map.disconnect()
        assert state_map._connection is None
        mock_conn.disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_state_map_subscribe(mock_token):
    """Test StateMap subscription."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        state_map = StateMap("192.168.1.100", 51338, mock_token)
        await state_map.connect()

        # Reset mock to ignore service announcement call
        mock_conn.send_message.reset_mock()

        # Test subscription
        await state_map.subscribe("/Engine/Deck1/Play", 100)

        # Should have sent subscription message
        mock_conn.send_message.assert_called_once()

        # Verify the subscription message content
        call_args = mock_conn.send_message.call_args[0][0]
        from stagelinq.messages import StateSubscribeMessage

        sub_msg = StateSubscribeMessage.deserialize(call_args)
        assert sub_msg.name == "/Engine/Deck1/Play"
        assert sub_msg.interval == 100

        # Should track subscription
        assert "/Engine/Deck1/Play" in state_map._subscriptions

        # Double subscription should be no-op
        mock_conn.send_message.reset_mock()
        await state_map.subscribe("/Engine/Deck1/Play", 100)
        mock_conn.send_message.assert_not_called()

        await state_map.disconnect()


@pytest.mark.asyncio
async def test_state_map_states_iterator(mock_token):
    """Test StateMap states async iterator."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        # Create a mock state message
        from stagelinq.messages import StateEmitMessage

        msg = StateEmitMessage(name="/Engine/Deck1/Play", json_data='{"value": true}')

        # Serialize the message to bytes (this is what the protocol layer would provide)
        message_data = msg.serialize()

        # Mock the connection to return our test message
        async def mock_messages():
            yield message_data
            # End of stream

        mock_conn.messages = mock_messages

        state_map = StateMap("192.168.1.100", 51338, mock_token)
        await state_map.connect()

        # Collect states
        states = []
        async for state in state_map.states():
            states.append(state)

        # Should have received one state
        assert len(states) == 1
        assert states[0].name == "/Engine/Deck1/Play"
        assert states[0].value is True

        await state_map.disconnect()


@pytest.mark.asyncio
async def test_beat_info_stream_connect_disconnect(mock_token):
    """Test BeatInfoStream connect/disconnect."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        beat_info = BeatInfoStream("192.168.1.100", 51339, mock_token)

        # Test connect
        await beat_info.connect()
        assert beat_info._connection is mock_conn
        mock_conn_class.assert_called_once_with("192.168.1.100", 51339)
        mock_conn.connect.assert_called_once()

        # Test disconnect
        await beat_info.disconnect()
        assert beat_info._connection is None
        mock_conn.disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_beat_info_stream_start_stream(mock_token):
    """Test BeatInfoStream start_stream."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        beat_info = BeatInfoStream("192.168.1.100", 51339, mock_token)
        await beat_info.connect()

        # Reset mock to ignore connection calls
        mock_conn.send_message.reset_mock()

        # Test start stream
        await beat_info.start_stream()

        # Should have sent start message
        mock_conn.send_message.assert_called_once()

        # Verify the start message content
        call_args = mock_conn.send_message.call_args[0][0]
        from stagelinq.messages import BeatInfoStartStreamMessage

        start_msg = BeatInfoStartStreamMessage.deserialize(call_args)
        # BeatInfoStartStreamMessage doesn't have a token field

        assert beat_info._streaming is True

        # Double start should be no-op
        mock_conn.send_message.reset_mock()
        await beat_info.start_stream()
        mock_conn.send_message.assert_not_called()

        await beat_info.disconnect()


@pytest.mark.asyncio
async def test_beat_info_stream_beats_iterator(mock_token):
    """Test BeatInfoStream beats async iterator."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        # Create a mock beat message
        from stagelinq.messages import BeatEmitMessage, PlayerInfo

        players = [PlayerInfo(beat=1.0, total_beats=100.0, bpm=120.0)]
        timelines = [10.0]
        msg = BeatEmitMessage(clock=12345, players=players, timelines=timelines)

        # Serialize the message to bytes (this is what the protocol layer would provide)
        message_data = msg.serialize()

        # Mock the connection to return our test message
        async def mock_messages():
            yield message_data
            # End of stream

        mock_conn.messages = mock_messages

        beat_info = BeatInfoStream("192.168.1.100", 51339, mock_token)
        await beat_info.connect()

        # Collect beats
        beats = []
        async for beat in beat_info.beats():
            beats.append(beat)

        # Should have received one beat
        assert len(beats) == 1
        assert beats[0].clock == 12345
        assert len(beats[0].players) == 1
        assert beats[0].players[0].beat == 1.0
        assert beats[0].timelines == [10.0]

        await beat_info.disconnect()


@pytest.mark.asyncio
async def test_async_device_connect(mock_token):
    """Test AsyncDevice connect method."""
    token = Token(b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c")
    device = AsyncDevice(
        ip="192.168.1.100",
        name="Test Device",
        software_name="Test OS",
        software_version="1.0.0",
        port=51337,
        token=token,
    )

    connection = device.connect(mock_token)
    assert isinstance(connection, DeviceConnection)
    assert connection.device == device
    assert connection.token == mock_token


@pytest.mark.asyncio
async def test_async_device_state_map_context(mock_token):
    """Test AsyncDevice state_map context manager."""
    token = Token(b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c")
    device = AsyncDevice(
        ip="192.168.1.100",
        name="Test Device",
        software_name="Test OS",
        software_version="1.0.0",
        port=51337,
        token=token,
    )

    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        # Mock service discovery to return StateMap service
        with patch.object(DeviceConnection, "discover_services") as mock_discover:
            from stagelinq.device import Service

            mock_services = [Service("StateMap", 51338), Service("BeatInfo", 51339)]
            mock_discover.return_value = mock_services

            with patch("stagelinq.device.StateMap") as mock_state_map_class:
                mock_state_map = AsyncMock()
                mock_state_map_class.return_value = mock_state_map

                async with device.state_map(mock_token) as state_map:
                    assert state_map is mock_state_map


@pytest.mark.asyncio
async def test_async_device_beat_info_context(mock_token):
    """Test AsyncDevice beat_info context manager."""
    token = Token(b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c")
    device = AsyncDevice(
        ip="192.168.1.100",
        name="Test Device",
        software_name="Test OS",
        software_version="1.0.0",
        port=51337,
        token=token,
    )

    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        # Mock service discovery to return BeatInfo service
        with patch.object(DeviceConnection, "discover_services") as mock_discover:
            from stagelinq.device import Service

            mock_services = [Service("StateMap", 51338), Service("BeatInfo", 51339)]
            mock_discover.return_value = mock_services

            with patch("stagelinq.device.BeatInfoStream") as mock_beat_info_class:
                mock_beat_info = AsyncMock()
                mock_beat_info_class.return_value = mock_beat_info

                async with device.beat_info(mock_token) as beat_info:
                    assert beat_info is mock_beat_info


@pytest.mark.asyncio
async def test_state_map_json_parse_error(mock_token):
    """Test StateMap handling of JSON parse errors."""
    # Mock at the protocol layer instead of core asyncio
    with patch("stagelinq.device.StagelinQConnection") as mock_conn_class:
        mock_conn = AsyncMock()
        mock_conn_class.return_value = mock_conn

        # Create a state message with invalid JSON
        from stagelinq.messages import StateEmitMessage

        msg = StateEmitMessage(name="/Engine/Deck1/Play", json_data="invalid json{")

        # Serialize the message to bytes (this is what the protocol layer would provide)
        message_data = msg.serialize()

        # Mock the connection to return our test message
        async def mock_messages():
            yield message_data
            # End of stream

        mock_conn.messages = mock_messages

        state_map = StateMap("192.168.1.100", 51338, mock_token)
        await state_map.connect()

        # Verify connection was called correctly
        mock_conn.connect.assert_called_once()
        mock_conn.send_message.assert_called_once()  # Service announcement

        # Collect states
        states = []
        async for state in state_map.states():
            states.append(state)

        # Should have received one state with raw string value
        assert len(states) == 1
        assert states[0].name == "/Engine/Deck1/Play"
        assert states[0].value == "invalid json{"

        await state_map.disconnect()
        mock_conn.disconnect.assert_called_once()
