"""Unit tests for message utility functions."""

import pytest

from stagelinq.messages import (
    NO_UPDATES_INTERVAL,
    BeatEmitMessage,
    BeatInfoStartStreamMessage,
    BeatInfoStopStreamMessage,
    PlayerInfo,
    format_interval,
    is_no_updates_interval,
    parse_beat_message,
)


class TestIntervalUtilities:
    """Test interval utility functions."""

    def test_format_interval_normal(self):
        """Test formatting normal interval values."""
        assert format_interval(0) == "0"
        assert format_interval(1000) == "1000"
        assert format_interval(500) == "500"
        assert format_interval(2147483647) == "2147483647"  # Max int32

    def test_format_interval_no_updates(self):
        """Test formatting NO_UPDATES_INTERVAL."""
        assert format_interval(NO_UPDATES_INTERVAL) == "no-updates"
        assert format_interval(4294967295) == "no-updates"

    def test_is_no_updates_interval_true(self):
        """Test is_no_updates_interval returns True for NO_UPDATES_INTERVAL."""
        assert is_no_updates_interval(NO_UPDATES_INTERVAL) is True
        assert is_no_updates_interval(4294967295) is True

    def test_is_no_updates_interval_false(self):
        """Test is_no_updates_interval returns False for other values."""
        assert is_no_updates_interval(0) is False
        assert is_no_updates_interval(1000) is False
        assert (
            is_no_updates_interval(4294967294) is False
        )  # One less than NO_UPDATES_INTERVAL

    def test_no_updates_interval_constant(self):
        """Test that NO_UPDATES_INTERVAL has the expected value."""
        assert NO_UPDATES_INTERVAL == 4294967295
        assert NO_UPDATES_INTERVAL == 0xFFFFFFFF


class TestBeatMessageParsing:
    """Test beat message parsing utility."""

    def test_parse_beat_message_start_stream(self):
        """Test parsing BeatInfoStartStreamMessage."""
        # Create a start stream message
        start_msg = BeatInfoStartStreamMessage()
        data = start_msg.serialize()

        # Parse it back
        result = parse_beat_message(data)

        assert isinstance(result, BeatInfoStartStreamMessage)

    def test_parse_beat_message_stop_stream(self):
        """Test parsing BeatInfoStopStreamMessage."""
        # Create a stop stream message
        stop_msg = BeatInfoStopStreamMessage()
        data = stop_msg.serialize()

        # Parse it back
        result = parse_beat_message(data)

        assert isinstance(result, BeatInfoStopStreamMessage)

    def test_parse_beat_message_emit(self):
        """Test parsing BeatEmitMessage."""
        # Create a beat emit message
        players = [
            PlayerInfo(beat=1.0, total_beats=100.0, bpm=120.0),
            PlayerInfo(beat=2.0, total_beats=200.0, bpm=130.0),
        ]
        timelines = [1.5, 2.5]

        beat_msg = BeatEmitMessage(clock=12345, players=players, timelines=timelines)
        data = beat_msg.serialize()

        # Parse it back
        result = parse_beat_message(data)

        assert isinstance(result, BeatEmitMessage)
        assert result.clock == 12345
        assert len(result.players) == 2
        assert len(result.timelines) == 2
        assert result.players[0].beat == 1.0
        assert result.players[0].bpm == 120.0
        assert result.timelines[0] == 1.5

    def test_parse_beat_message_empty_data(self):
        """Test parsing with empty data."""
        result = parse_beat_message(b"")
        assert result is None

    def test_parse_beat_message_insufficient_data(self):
        """Test parsing with insufficient data."""
        result = parse_beat_message(b"\x00\x00\x00\x04")  # Only 4 bytes
        assert result is None

    def test_parse_beat_message_invalid_data(self):
        """Test parsing with invalid data."""
        # Random bytes that don't match any beat message format
        invalid_data = b"\x00\x00\x00\x10" + b"\xff" * 16
        result = parse_beat_message(invalid_data)
        assert result is None

    def test_parse_beat_message_corrupted_data(self):
        """Test parsing with corrupted data."""
        # Start with a valid message and corrupt it
        start_msg = BeatInfoStartStreamMessage()
        data = bytearray(start_msg.serialize())

        # Corrupt the data
        data[5] = 0xFF  # Change magic bytes

        result = parse_beat_message(bytes(data))
        assert result is None

    def test_parse_beat_message_partial_data(self):
        """Test parsing with partial data."""
        # Create a valid message and truncate it
        players = [PlayerInfo(beat=1.0, total_beats=100.0, bpm=120.0)]
        timelines = [1.5]

        beat_msg = BeatEmitMessage(clock=12345, players=players, timelines=timelines)
        data = beat_msg.serialize()

        # Truncate the data
        partial_data = data[: len(data) // 2]

        result = parse_beat_message(partial_data)
        assert result is None


class TestBeatEmitMessageDetails:
    """Test detailed BeatEmitMessage functionality."""

    def test_beat_emit_message_single_player(self):
        """Test BeatEmitMessage with single player."""
        players = [PlayerInfo(beat=1.5, total_beats=150.0, bpm=128.0)]
        timelines = [2.0]

        msg = BeatEmitMessage(clock=54321, players=players, timelines=timelines)
        data = msg.serialize()

        # Parse it back
        result = parse_beat_message(data)

        assert isinstance(result, BeatEmitMessage)
        assert result.clock == 54321
        assert len(result.players) == 1
        assert len(result.timelines) == 1
        assert result.players[0].beat == 1.5
        assert result.players[0].total_beats == 150.0
        assert result.players[0].bpm == 128.0
        assert result.timelines[0] == 2.0

    def test_beat_emit_message_multiple_players(self):
        """Test BeatEmitMessage with multiple players."""
        players = [
            PlayerInfo(beat=1.0, total_beats=100.0, bpm=120.0),
            PlayerInfo(beat=2.0, total_beats=200.0, bpm=130.0),
            PlayerInfo(beat=3.0, total_beats=300.0, bpm=140.0),
        ]
        timelines = [1.5, 2.5, 3.5]

        msg = BeatEmitMessage(clock=99999, players=players, timelines=timelines)
        data = msg.serialize()

        # Parse it back
        result = parse_beat_message(data)

        assert isinstance(result, BeatEmitMessage)
        assert result.clock == 99999
        assert len(result.players) == 3
        assert len(result.timelines) == 3

        for i, player in enumerate(result.players):
            assert player.beat == float(i + 1)
            assert player.total_beats == float((i + 1) * 100)
            assert player.bpm == float(120 + i * 10)

        for i, timeline in enumerate(result.timelines):
            assert timeline == float(i + 1) + 0.5

    def test_beat_emit_message_empty_players(self):
        """Test BeatEmitMessage with no players."""
        msg = BeatEmitMessage(clock=0, players=[], timelines=[])
        data = msg.serialize()

        # Parse it back
        result = parse_beat_message(data)

        assert isinstance(result, BeatEmitMessage)
        assert result.clock == 0
        assert len(result.players) == 0
        assert len(result.timelines) == 0

    def test_beat_emit_message_zero_values(self):
        """Test BeatEmitMessage with zero values."""
        players = [PlayerInfo(beat=0.0, total_beats=0.0, bpm=0.0)]
        timelines = [0.0]

        msg = BeatEmitMessage(clock=0, players=players, timelines=timelines)
        data = msg.serialize()

        # Parse it back
        result = parse_beat_message(data)

        assert isinstance(result, BeatEmitMessage)
        assert result.clock == 0
        assert len(result.players) == 1
        assert len(result.timelines) == 1
        assert result.players[0].beat == 0.0
        assert result.players[0].total_beats == 0.0
        assert result.players[0].bpm == 0.0
        assert result.timelines[0] == 0.0

    def test_beat_emit_message_negative_values(self):
        """Test BeatEmitMessage with negative values."""
        players = [PlayerInfo(beat=-1.0, total_beats=-100.0, bpm=-120.0)]
        timelines = [-1.5]

        msg = BeatEmitMessage(clock=0, players=players, timelines=timelines)
        data = msg.serialize()

        # Parse it back
        result = parse_beat_message(data)

        assert isinstance(result, BeatEmitMessage)
        assert result.clock == 0
        assert len(result.players) == 1
        assert len(result.timelines) == 1
        assert result.players[0].beat == -1.0
        assert result.players[0].total_beats == -100.0
        assert result.players[0].bpm == -120.0
        assert result.timelines[0] == -1.5


class TestPlayerInfo:
    """Test PlayerInfo data class."""

    def test_player_info_creation(self):
        """Test PlayerInfo creation."""
        player = PlayerInfo(beat=1.5, total_beats=150.0, bpm=128.0)

        assert player.beat == 1.5
        assert player.total_beats == 150.0
        assert player.bpm == 128.0

    def test_player_info_string_representation(self):
        """Test PlayerInfo string representation."""
        player = PlayerInfo(beat=1.5, total_beats=150.0, bpm=128.0)

        str_repr = str(player)
        assert "beat=1.50" in str_repr
        assert "bpm=128.0" in str_repr

    def test_player_info_defaults(self):
        """Test PlayerInfo with default values."""
        player = PlayerInfo()

        assert player.beat == 0.0
        assert player.total_beats == 0.0
        assert player.bpm == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
