#!/usr/bin/env python3
"""StageLinq device discovery example."""

from __future__ import annotations

import argparse
import json
import logging
import time
from typing import Any

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import stagelinq


def setup_logging(level: str = "INFO") -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )


def get_state_names() -> list[str]:
    """Get list of state names to monitor."""
    return [
        stagelinq.EngineDeck1.play(),
        stagelinq.EngineDeck1.play_state(),
        stagelinq.EngineDeck1.play_state_path(),
        stagelinq.EngineDeck1.track_artist_name(),
        stagelinq.EngineDeck1.track_track_network_path(),
        stagelinq.EngineDeck1.track_song_loaded(),
        stagelinq.EngineDeck1.track_song_name(),
        stagelinq.EngineDeck1.track_track_data(),
        stagelinq.EngineDeck1.track_track_name(),
        stagelinq.EngineDeck2.play(),
        stagelinq.EngineDeck2.play_state(),
        stagelinq.EngineDeck2.play_state_path(),
        stagelinq.EngineDeck2.track_artist_name(),
        stagelinq.EngineDeck2.track_track_network_path(),
        stagelinq.EngineDeck2.track_song_loaded(),
        stagelinq.EngineDeck2.track_song_name(),
        stagelinq.EngineDeck2.track_track_data(),
        stagelinq.EngineDeck2.track_track_name(),
    ]


def collect_device_states(
    device: stagelinq.Device,
    token: stagelinq.Token,
    state_names: list[str],
    timeout: float = 2.0
) -> dict[str, Any]:
    """Collect state information from a device."""
    try:
        with device.connect(token) as main_conn:
            logging.info("  Requesting device services...")
            services = main_conn.request_services()

            for service in services:
                logging.info(f"  Service: {service.name} on port {service.port}")

                # Connect to StateMap service
                if service.name == "StateMap":
                    try:
                        state_conn = device.dial(service.port)
                        with stagelinq.StateMapConnection(state_conn, token) as state_map:
                            # Subscribe to state values
                            for state_name in state_names:
                                state_map.subscribe(state_name)

                            # Collect states
                            collected_states: dict[str, Any] = {}
                            timeout_time = time.time() + timeout

                            while time.time() < timeout_time:
                                state = state_map.get_state(timeout=0.1)
                                if state:
                                    collected_states[state.name] = state.value
                                    logging.info(f"    {state.name} = {state.value}")

                                    # Check if we have all states
                                    if len(collected_states) >= len(state_names):
                                        break

                            return collected_states

                    except Exception as e:
                        logging.error(f"  Error connecting to StateMap: {e}")

    except Exception as e:
        logging.error(f"  Error connecting to device: {e}")

    return {}


def discover_devices(config: stagelinq.ListenerConfiguration, timeout: float) -> list[stagelinq.Device]:
    """Discover StageLinq devices on the network."""
    found_devices: list[stagelinq.Device] = []

    with stagelinq.Listener(config) as listener:
        listener.announce_every(1.0)

        logging.info(f"Listening for devices for {timeout} seconds...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                device, device_state = listener.discover(timeout=1.0)

                if device is None:
                    continue

                # Skip devices that are leaving
                if device_state != stagelinq.DeviceState.PRESENT:
                    continue

                # Check if we already found this device
                if any(d.is_equal(device) for d in found_devices):
                    continue

                found_devices.append(device)

                logging.info(
                    f"Found device: {device.ip} - {device.name} "
                    f"({device.software_name} {device.software_version})"
                )

            except stagelinq.TooShortDiscoveryMessageError:
                logging.warning("Received too short discovery message")
                continue
            except stagelinq.InvalidMessageError as e:
                logging.warning(f"Invalid message received: {e}")
                continue
            except stagelinq.InvalidDiscovererActionError as e:
                logging.warning(f"Invalid discoverer action: {e}")
                continue
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                continue

    return found_devices


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Discover StageLinq devices")
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Discovery timeout in seconds (default: 5.0)"
    )
    parser.add_argument(
        "--output",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)"
    )

    args = parser.parse_args()
    setup_logging(args.log_level)

    # Create listener configuration
    config = stagelinq.ListenerConfiguration(
        name="Python StageLinq Example",
        software_name="python-stagelinq",
        software_version="0.1.0",
        discovery_timeout=args.timeout
    )

    # Discover devices
    devices = discover_devices(config, args.timeout)

    if not devices:
        logging.info("No devices found")
        return

    # Collect state information from each device
    state_names = get_state_names()

    with stagelinq.Listener(config) as listener:
        for device in devices:
            states = collect_device_states(device, listener.token, state_names)

            if args.output == "json":
                print(json.dumps({
                    "device": {
                        "ip": device.ip,
                        "name": device.name,
                        "software_name": device.software_name,
                        "software_version": device.software_version
                    },
                    "states": states
                }, indent=2))

    logging.info(f"Discovery complete. Found {len(devices)} devices.")


if __name__ == "__main__":
    main()