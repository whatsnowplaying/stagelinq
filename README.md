# Python StageLinq

A Python implementation of Denon's StageLinq protocol for communicating with DJ equipment like Denon Prime series devices.

This implementation uses modern async/await patterns for all I/O operations and provides comprehensive tools for device discovery, state monitoring, beat information, and file transfer.

## Features

- **Device Discovery**: Automatic discovery of StageLinq devices on the network
- **State Monitoring**: Real-time track information and deck state updates
- **Beat Information**: Live beat timing and BPM data
- **File Transfer**: Access to Engine Library databases and files
- **Packet Analysis**: Tools for analyzing StageLinq protocol traffic
- **Comprehensive Testing**: 84% test coverage with extensive unit tests

## Requirements

- Python 3.10+
- `netifaces-plus>=0.2.0` for network interface detection
- `aiofiles>=23.0.0` for async file operations

## Installation

```bash
pip install python-stagelinq
```

For development with packet analysis tools:
```bash
pip install python-stagelinq[dev]
```

## Quick Start

### Device Discovery

```python
import asyncio
from stagelinq import discover_stagelinq_devices, DiscoveryConfig

async def main():
    # Create discovery configuration
    config = DiscoveryConfig(
        name="My DJ App",
        software_name="python-stagelinq",
        software_version="0.1.0"
    )

    async with discover_stagelinq_devices(config) as discovery:
        # Start announcing our presence
        await discovery.start_announcing()

        # Wait for devices to respond
        await asyncio.sleep(5.0)

        # Get discovered devices
        devices = await discovery.get_devices()
        for device in devices:
            print(f"Found device: {device.name} at {device.ip}")

            # Connect to device
            async with device.connect(config.token) as connection:
                services = await connection.discover_services()
                print(f"Available services: {[s.name for s in services]}")

asyncio.run(main())
```

### State Map (Track Info)

```python
import asyncio
from stagelinq import discover_stagelinq_devices, DiscoveryConfig, DeckValueNames

async def main():
    config = DiscoveryConfig(
        name="Track Info Monitor",
        software_name="python-stagelinq",
        software_version="0.1.0"
    )

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()
        await asyncio.sleep(3.0)

        devices = await discovery.get_devices()
        if devices:
            device = devices[0]
            async with device.connect(config.token) as connection:
                async with connection.state_map() as state_map:
                    # Subscribe to deck 1 track info
                    deck_names = DeckValueNames()
                    await state_map.subscribe(deck_names.deck1_track_song_name(), 100)
                    await state_map.subscribe(deck_names.deck1_track_artist_name(), 100)
                    await state_map.subscribe(deck_names.deck1_play_state(), 100)

                    # Get state updates
                    async for state in state_map.states():
                        print(f"{state.name}: {state.value}")

asyncio.run(main())
```

### Beat Info

```python
import asyncio
from stagelinq import discover_stagelinq_devices, DiscoveryConfig

async def main():
    config = DiscoveryConfig(
        name="Beat Monitor",
        software_name="python-stagelinq",
        software_version="0.1.0"
    )

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()
        await asyncio.sleep(3.0)

        devices = await discovery.get_devices()
        if devices:
            device = devices[0]
            async with device.connect(config.token) as connection:
                async with connection.beat_info() as beat_info:
                    await beat_info.start_stream()

                    # Get beat updates
                    async for beat_data in beat_info.beats():
                        for i, player in enumerate(beat_data.players):
                            print(f"Player {i+1}: {player.bpm:.1f} BPM, Beat {player.beat:.2f}")

asyncio.run(main())
```

### File Transfer

```python
import asyncio
from stagelinq import discover_stagelinq_devices, DiscoveryConfig

async def main():
    config = DiscoveryConfig(
        name="File Transfer Client",
        software_name="python-stagelinq",
        software_version="0.1.0"
    )

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()
        await asyncio.sleep(3.0)

        devices = await discovery.get_devices()
        if devices:
            device = devices[0]
            async with device.connect(config.token) as connection:
                async with connection.file_transfer() as file_transfer:
                    # List available sources
                    sources = await file_transfer.list_sources()
                    print(f"Available sources: {sources}")

                    # Get database info
                    if sources:
                        info = await file_transfer.get_database_info(sources[0])
                        print(f"Database info: {info}")

asyncio.run(main())
```

## API Reference

### Core Classes

#### Discovery
- `discover_stagelinq_devices(config)`: Context manager for device discovery
- `DiscoveryConfig`: Configuration for device discovery
- `Device`: Represents a StageLinq device
- `DeviceState`: Enum for device states (PRESENT, LEAVING)
- `DeviceRegistry`: Collection of discovered devices with lookup capabilities

#### Connections
- `DeviceConnection`: Main connection to a device for service discovery
- `StateMap`: Connection for receiving state updates with categorization
- `BeatInfoStream`: Connection for receiving beat timing information
- `FileTransferConnection`: Connection for file transfer operations

#### Data Types
- `Token`: 16-byte authentication token
- `PlayerInfo`: Beat information for a single player
- `FileInfo`: File information from device
- `StateCategory`: Enum for categorizing state types

#### Utility Functions
- `format_interval(interval)`: Format interval values for display
- `is_no_updates_interval(interval)`: Check for no-updates interval
- `parse_beat_message(data)`: Parse beat message from raw data

### State Categories

The library automatically categorizes states into:
- `StateCategory.TRACK_INFO`: Track metadata (title, artist, BPM)
- `StateCategory.DECK_STATE`: Deck control states (play, loop, master)
- `StateCategory.SUBSCRIPTION`: Subscription management
- `StateCategory.CHANNEL_ASSIGNMENT`: Channel routing
- `StateCategory.OTHER`: Other device states

### Value Names

Use the `DeckValueNames` class for predefined state names:

```python
from stagelinq import DeckValueNames

deck_names = DeckValueNames()

# Track information
deck_names.deck1_track_song_name()
deck_names.deck1_track_artist_name()
deck_names.deck1_current_bpm()

# Deck states
deck_names.deck1_play_state()
deck_names.deck1_is_master()
deck_names.deck1_loop_enable_state()

# Available for all 4 decks
deck_names.deck2_track_song_name()
deck_names.deck3_track_song_name()
deck_names.deck4_track_song_name()
```

## Tools

The `tools/` directory contains several useful utilities:

### Analysis Tools
- `packet_analyzer.py`: Comprehensive packet analysis with filtering options
- `debug_packets.py`: Debug packet parsing and validation
- `simple_packet_extractor.py`: Extract packets from PCAP files

### Examples
- `discover_devices.py`: Basic device discovery example
- `beat_info.py`: Beat information monitoring example
- `nowplaying.py`: Track information monitoring
- `track_info_example.py`: Advanced track info processing
- `file_transfer_example.py`: File transfer operations

### Usage Examples

```bash
# Discover devices
python tools/discover_devices.py

# Monitor beat information
python tools/beat_info.py

# Analyze packet capture
python tools/packet_analyzer.py capture.pcap --show beats,states

# Monitor current track
python tools/nowplaying.py
```

## Protocol Details

### Message Types
- **Discovery**: UDP broadcast for device discovery
- **Service Announcements**: Available services on each device
- **State Updates**: Real-time state changes
- **Beat Information**: Timing and BPM data
- **File Transfer**: Engine Library access

### Special Values
- `NO_UPDATES_INTERVAL` (0xFFFFFFFF): Indicates no periodic updates
- Magic bytes for different message types (discovery, state, beat)

## Testing

The library includes comprehensive tests with 84% coverage:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=stagelinq

# Run specific test categories
pytest tests/test_device_registry.py
pytest tests/test_state_map.py
pytest tests/test_message_utilities.py
```

## Development

### Setting up Development Environment

```bash
git clone https://github.com/your-username/python-stagelinq.git
cd python-stagelinq
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .[dev]
```

### Code Quality

```bash
# Run tests
pytest

# Format code
ruff format stagelinq/

# Lint code
ruff check stagelinq/

# Type checking
mypy stagelinq/
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Areas for Contribution
- Additional device compatibility
- Enhanced file transfer functionality
- Protocol analysis tools
- Performance optimizations
- Documentation improvements

## Acknowledgments

This implementation is based on the Go implementation at https://github.com/icedream/go-stagelinq and research into the StageLinq protocol by the open-source DJ community.