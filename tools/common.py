#!/usr/bin/env python3
"""Common utilities for StagelinQ CLI tools."""

import asyncio
import logging
from typing import Any

from stagelinq.discovery import Device, DiscoveryConfig, discover_stagelinq_devices
from stagelinq.messages import Token

# Default client token from SC6000 reference
DEFAULT_CLIENT_TOKEN = Token(
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c"
)


async def discover_and_connect(
    app_name: str = "Python StagelinQ Tool",
    software_name: str = "python-stagelinq",
    software_version: str = "0.1.0",
    discovery_timeout: float = 5.0,
    client_token: Token | None = None,
) -> tuple[Device | None, Any | None]:
    """
    Discover StagelinQ devices and connect to the first one found.

    Args:
        app_name: Application name for discovery
        software_name: Software name for discovery
        software_version: Software version for discovery
        discovery_timeout: How long to wait for devices
        client_token: Token to use for connection (uses default if None)

    Returns:
        Tuple of (device, connection) or (None, None) if no device found
    """
    if client_token is None:
        client_token = DEFAULT_CLIENT_TOKEN

    # Create discovery configuration
    config = DiscoveryConfig(
        name=app_name,
        software_name=software_name,
        software_version=software_version,
        discovery_timeout=discovery_timeout,
    )

    # Discover devices
    logging.info("Discovering StagelinQ devices for %s seconds...", discovery_timeout)

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()

        # Wait for device discovery
        await asyncio.sleep(discovery_timeout)

        devices = await discovery.get_devices()

        if not devices:
            logging.info("No StagelinQ devices found")
            return None, None

        device = devices[0]
        logging.info(
            f"Found device: {device.ip} - {device.name} "
            f"({device.software_name} {device.software_version})"
        )

        # Connect to device
        try:
            connection = device.connect(client_token)
            await connection.connect()
            logging.info("Connected to %s", device.name)
            return device, connection
        except Exception as e:
            logging.error("Failed to connect to device: %s", e)
            return device, None


async def setup_discovery_only(
    app_name: str = "Python StagelinQ Tool",
    software_name: str = "python-stagelinq",
    software_version: str = "0.1.0",
    discovery_timeout: float = 5.0,
) -> list[Device]:
    """
    Just discover devices without connecting.

    Args:
        app_name: Application name for discovery
        software_name: Software name for discovery
        software_version: Software version for discovery
        discovery_timeout: How long to wait for devices

    Returns:
        List of discovered devices
    """
    config = DiscoveryConfig(
        name=app_name,
        software_name=software_name,
        software_version=software_version,
        discovery_timeout=discovery_timeout,
    )

    logging.info("Discovering StagelinQ devices for %s seconds...", discovery_timeout)

    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()
        await asyncio.sleep(discovery_timeout)
        devices = await discovery.get_devices()

        for device in devices:
            logging.info(
                f"Found device: {device.ip} - {device.name} "
                f"({device.software_name} {device.software_version})"
            )

        return devices
