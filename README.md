# Python StageLinq

A Python implementation of Denon's StageLinq protocol for communicating with DJ equipment like Denon Prime series devices.
It is a hacky port of https://github.com/icedream/go-stagelinq with some help from automated tooling.

This port is likely missing things, but the more complete OSS Stagelinq implementations are GPL3 so can't
be legally used in closed commercial software.

## Requirements

- Python 3.10+
- `netifaces` package for network interface detection

## Quick Start

### Device Discovery

```python
import stagelinq
import time

# Create a listener
config = stagelinq.ListenerConfiguration(
    name="My DJ App",
    software_name="python-stagelinq",
    software_version="1.0.0"
)

with stagelinq.Listener(config) as listener:
    listener.announce_every(1.0)  # Announce every second
    
    # Discover devices
    start_time = time.time()
    while time.time() - start_time < 5.0:  # 5 second timeout
        device, state = listener.discover(timeout=1.0)
        if device and state == stagelinq.DeviceState.PRESENT:
            print(f"Found device: {device.name} at {device.ip}")
            
            # Connect to device
            with device.connect(listener.token) as conn:
                services = conn.request_services()
                print(f"Available services: {[s.name for s in services]}")
            break
```

### State Map (Track Info)

```python
import stagelinq
import time

# Connect to device and get state information
config = stagelinq.ListenerConfiguration(
    name="Track Info Monitor",
    software_name="python-stagelinq",
    software_version="0.1.0"
)

with stagelinq.Listener(config) as listener:
    listener.announce_every(1.0)
    
    # Discover device
    start_time = time.time()
    while time.time() - start_time < 5.0:
        device, device_state = listener.discover(timeout=1.0)
        if device and device_state == stagelinq.DeviceState.PRESENT:
            with device.connect(listener.token) as conn:
                services = conn.request_services()
                
                # Find StateMap service
                state_map_service = next(
                    (s for s in services if s.name == "StateMap"), 
                    None
                )
                
                if state_map_service:
                    state_conn = device.dial(state_map_service.port)
                    with stagelinq.StateMapConnection(state_conn, listener.token) as state_map:
                        # Subscribe to deck 1 track info
                        state_map.subscribe(stagelinq.EngineDeck1.track_song_name())
                        state_map.subscribe(stagelinq.EngineDeck1.track_artist_name())
                        
                        # Get state updates
                        timeout_time = time.time() + 10.0  # 10 second timeout
                        while time.time() < timeout_time:
                            state = state_map.get_state(timeout=1.0)
                            if state:
                                print(f"{state.name}: {state.value}")
            break
```

### Beat Info

```python
import stagelinq
import time

# Connect to device and get beat information
config = stagelinq.ListenerConfiguration(
    name="Beat Monitor",
    software_name="python-stagelinq",
    software_version="0.1.0"
)

with stagelinq.Listener(config) as listener:
    listener.announce_every(1.0)
    
    # Discover device
    start_time = time.time()
    while time.time() - start_time < 5.0:
        device, device_state = listener.discover(timeout=1.0)
        if device and device_state == stagelinq.DeviceState.PRESENT:
            with device.connect(listener.token) as conn:
                services = conn.request_services()
                
                # Find BeatInfo service
                beat_service = next(
                    (s for s in services if s.name == "BeatInfo"), 
                    None
                )
                
                if beat_service:
                    beat_conn = device.dial(beat_service.port)
                    with stagelinq.BeatInfoConnection(beat_conn, listener.token) as beat_info:
                        beat_info.start_stream()
                        
                        # Get beat updates
                        timeout_time = time.time() + 10.0  # 10 second timeout
                        while time.time() < timeout_time:
                            beat_data = beat_info.get_beat_info(timeout=1.0)
                            if beat_data:
                                for i, player in enumerate(beat_data.players):
                                    print(f"Player {i+1}: {player.bpm:.1f} BPM, Beat {player.beat:.2f}")
            break
```

## API Reference

### Core Classes

- `Listener`: Discovers StageLinq devices on the network
- `ListenerConfiguration`: Configuration for the listener
- `Device`: Represents a StageLinq device
- `DeviceState`: Enum for device states (PRESENT, LEAVING)
- `MainConnection`: Main connection to a device for service discovery
- `StateMapConnection`: Connection for receiving state updates
- `BeatInfoConnection`: Connection for receiving beat timing information
- `FileTransferConnection`: Connection for file transfer operations

### State Names

Use the predefined state name helpers:

```python
# Deck-specific values
stagelinq.EngineDeck1.track_song_name()
stagelinq.EngineDeck1.track_artist_name()
stagelinq.EngineDeck1.play_state()
stagelinq.EngineDeck1.play()

# Available for all 4 decks
stagelinq.EngineDeck2.track_song_name()
stagelinq.EngineDeck3.track_song_name()
stagelinq.EngineDeck4.track_song_name()
```

## Examples

See the `tools/` directory for complete examples:

- `discover_devices.py`: Device discovery and state monitoring
- `beat_info.py`: Beat timing information monitoring
- `async_discovery.py`: Async device discovery example

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
