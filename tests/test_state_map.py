"""Unit tests for StateMap functionality."""

import json
from unittest.mock import Mock

import pytest

from stagelinq.device import StateCategory, StateMap
from stagelinq.messages import Token


class TestStateMap:
    """Test StateMap class methods."""

    def test_state_map_creation(self):
        """Test StateMap creation."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        assert state_map.host == "192.168.1.100"
        assert state_map.port == 8080
        assert state_map.token == token
        assert state_map._connection is None
        assert state_map._subscriptions == set()

    def test_categorize_state_subscription(self):
        """Test categorizing subscription states."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test subscription states
        assert (
            state_map.categorize_state("Subscribe_Something")
            == StateCategory.SUBSCRIPTION
        )
        assert (
            state_map.categorize_state("Subscribe_Deck1/Track/Title")
            == StateCategory.SUBSCRIPTION
        )

    def test_categorize_state_channel_assignment(self):
        """Test categorizing channel assignment states."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test channel assignment states
        assert (
            state_map.categorize_state("Main/ChannelAssignment/1")
            == StateCategory.CHANNEL_ASSIGNMENT
        )
        assert (
            state_map.categorize_state("Mixer/ChannelAssignment/A")
            == StateCategory.CHANNEL_ASSIGNMENT
        )

    def test_categorize_state_track_info(self):
        """Test categorizing track info states."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test track info states
        assert (
            state_map.categorize_state("Deck1/Track/CurrentBPM")
            == StateCategory.TRACK_INFO
        )
        assert (
            state_map.categorize_state("Deck2/Track/Title") == StateCategory.TRACK_INFO
        )
        assert (
            state_map.categorize_state("Deck3/Track/Artist") == StateCategory.TRACK_INFO
        )
        assert (
            state_map.categorize_state("Deck1/Track/Album") == StateCategory.TRACK_INFO
        )
        assert (
            state_map.categorize_state("Deck2/Track/TrackName")
            == StateCategory.TRACK_INFO
        )
        assert (
            state_map.categorize_state("Deck1/Track/ArtistName")
            == StateCategory.TRACK_INFO
        )

    def test_categorize_state_deck_state(self):
        """Test categorizing deck state."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test deck state
        assert state_map.categorize_state("Deck1/PlayState") == StateCategory.DECK_STATE
        assert (
            state_map.categorize_state("Deck2/DeckIsMaster") == StateCategory.DECK_STATE
        )
        assert (
            state_map.categorize_state("Deck1/LoopEnableState")
            == StateCategory.DECK_STATE
        )
        assert (
            state_map.categorize_state("Deck2/LayerB/Something")
            == StateCategory.DECK_STATE
        )
        assert (
            state_map.categorize_state("Deck1/MasterStatus") == StateCategory.DECK_STATE
        )

    def test_categorize_state_other(self):
        """Test categorizing other states."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test other states
        assert state_map.categorize_state("MasterTempo") == StateCategory.OTHER
        assert state_map.categorize_state("System/Volume") == StateCategory.OTHER
        assert state_map.categorize_state("Unknown/State") == StateCategory.OTHER

    def test_extract_deck_info_with_deck(self):
        """Test extracting deck information from state names."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test with different deck numbers
        deck_name, base_name = state_map.extract_deck_info("Deck1/Track/Title")
        assert deck_name == "Deck1"
        assert base_name == "Title"

        deck_name, base_name = state_map.extract_deck_info("Deck2/PlayState")
        assert deck_name == "Deck2"
        assert base_name == "PlayState"

        deck_name, base_name = state_map.extract_deck_info("Deck10/Track/Artist")
        assert deck_name == "Deck10"
        assert base_name == "Artist"

        # Test with deeper paths
        deck_name, base_name = state_map.extract_deck_info("Deck1/Layer/A/Track/Title")
        assert deck_name == "Deck1"
        assert base_name == "Title"

    def test_extract_deck_info_without_deck(self):
        """Test extracting deck information from state names without deck."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test without deck
        deck_name, base_name = state_map.extract_deck_info("MasterTempo")
        assert deck_name is None
        assert base_name == "MasterTempo"

        deck_name, base_name = state_map.extract_deck_info("System/Volume/Main")
        assert deck_name is None
        assert base_name == "Main"

        # Test with no slash
        deck_name, base_name = state_map.extract_deck_info("SimpleState")
        assert deck_name is None
        assert base_name == "SimpleState"

    def test_parse_state_value_valid_json(self):
        """Test parsing valid JSON state values."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test valid JSON
        json_data = '{"value": 120.5, "type": "float"}'
        result = state_map.parse_state_value(json_data)
        assert result == {"value": 120.5, "type": "float"}

        # Test simple values
        json_data = '{"state": true}'
        result = state_map.parse_state_value(json_data)
        assert result == {"state": True}

    def test_parse_state_value_invalid_json(self):
        """Test parsing invalid JSON state values."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test invalid JSON - should return original string
        invalid_json = "not valid json"
        result = state_map.parse_state_value(invalid_json)
        assert result == invalid_json

        # Test malformed JSON
        malformed_json = '{"incomplete": '
        result = state_map.parse_state_value(malformed_json)
        assert result == malformed_json

    def test_format_interval_special_value(self):
        """Test formatting special interval values."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test NO_UPDATES_INTERVAL
        result = state_map.format_interval(4294967295)
        assert result == "no-updates"

        # Test normal interval
        result = state_map.format_interval(1000)
        assert result == "1000"

        # Test zero interval
        result = state_map.format_interval(0)
        assert result == "0"

    def test_categorize_state_comprehensive(self):
        """Test comprehensive state categorization."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test cases covering all categories
        test_cases = [
            # Subscription states
            ("Subscribe_Deck1/Track/Title", StateCategory.SUBSCRIPTION),
            ("Subscribe_MasterTempo", StateCategory.SUBSCRIPTION),
            # Channel assignment states
            ("Main/ChannelAssignment/1", StateCategory.CHANNEL_ASSIGNMENT),
            ("Mixer/ChannelAssignment/A", StateCategory.CHANNEL_ASSIGNMENT),
            ("SomeOtherChannelAssignment", StateCategory.CHANNEL_ASSIGNMENT),
            # Track info states
            ("Deck1/Track/CurrentBPM", StateCategory.TRACK_INFO),
            ("Deck2/Track/Title", StateCategory.TRACK_INFO),
            ("Deck3/Track/Artist", StateCategory.TRACK_INFO),
            ("Deck1/Track/Album", StateCategory.TRACK_INFO),
            ("Deck2/Track/TrackName", StateCategory.TRACK_INFO),
            ("Deck1/Track/ArtistName", StateCategory.TRACK_INFO),
            # Deck state
            ("Deck1/PlayState", StateCategory.DECK_STATE),
            ("Deck2/DeckIsMaster", StateCategory.DECK_STATE),
            ("Deck1/LoopEnableState", StateCategory.DECK_STATE),
            ("Deck2/LayerB/Something", StateCategory.DECK_STATE),
            ("Deck1/MasterStatus", StateCategory.DECK_STATE),
            # Other states
            ("MasterTempo", StateCategory.OTHER),
            ("System/Volume", StateCategory.OTHER),
            ("Deck1/SomeUnknownState", StateCategory.OTHER),
        ]

        for state_name, expected_category in test_cases:
            result = state_map.categorize_state(state_name)
            assert result == expected_category, (
                f"Failed for {state_name}: expected {expected_category}, got {result}"
            )

    def test_extract_deck_info_edge_cases(self):
        """Test edge cases for deck info extraction."""
        token = Token(b"\x01" * 16)
        state_map = StateMap("192.168.1.100", 8080, token)

        # Test edge cases
        test_cases = [
            # Multiple deck references - should match first
            ("Deck1/Something/Deck2/Other", "Deck1", "Other"),
            # Deck with additional text
            ("DeckInfoDeck3/Track/Title", "Deck3", "Title"),
            # Empty string
            ("", None, ""),
            # Only slashes
            ("///", None, ""),
            # Single slash
            ("/", None, ""),
            # Deck at end
            ("Something/Deck1", "Deck1", "Deck1"),
        ]

        for state_name, expected_deck, expected_base in test_cases:
            deck_name, base_name = state_map.extract_deck_info(state_name)
            assert deck_name == expected_deck, (
                f"Failed deck for {state_name}: expected {expected_deck}, got {deck_name}"
            )
            assert base_name == expected_base, (
                f"Failed base for {state_name}: expected {expected_base}, got {base_name}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
