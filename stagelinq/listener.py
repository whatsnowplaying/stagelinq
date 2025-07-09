"""
StageLinq Listener Implementation

This module implements the Listener class for discovering StageLinq devices.
"""

import socket
import threading
import time
import io
from typing import Tuple
from dataclasses import dataclass
from .messages import Token, DiscoveryMessage, DISCOVERER_HOWDY, DISCOVERER_EXIT
from .discovery import Device, DeviceState


@dataclass
class ListenerConfiguration:
    """Configuration for StageLinq listener."""
    token: Token | None = None
    name: str = "Python StageLinq"
    software_name: str = "python-stagelinq"
    software_version: str = "0.1.0"
    discovery_timeout: float = 5.0


class StageLinqError(Exception):
    """Base exception for StageLinq errors."""
    pass


class TooShortDiscoveryMessageError(StageLinqError):
    """Raised when a discovery message is too short."""
    pass


class InvalidMessageError(StageLinqError):
    """Raised when an invalid message is received."""
    pass


class InvalidDiscovererActionError(StageLinqError):
    """Raised when an invalid discoverer action is received."""
    pass


class Listener:
    """Listens for StageLinq devices and announces itself on UDP port 51337."""

    DISCOVERY_PORT = 51337

    def __init__(self, config: ListenerConfiguration | None = None):
        if config is None:
            config = ListenerConfiguration()

        self.config = config
        self.token = config.token or Token()
        self.name = config.name
        self.software_name = config.software_name
        self.software_version = config.software_version

        self._socket: socket.socket | None = None
        self._shutdown_event = threading.Event()
        self._announce_thread: threading.Thread | None = None

        # Set up UDP socket with reuse port (matching Go code behavior)
        # Try IPv6 first, fall back to IPv4 if needed
        try:
            self._socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # Dual stack
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(('', self.DISCOVERY_PORT))
        except (socket.error, OSError):
            # Fall back to IPv4 only
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind(('', self.DISCOVERY_PORT))

        # Enable broadcast
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def close(self) -> None:
        """Close the listener and stop all background threads."""
        if self._socket:
            self._shutdown_event.set()
            if self._announce_thread:
                self._announce_thread.join()
            self._socket.close()
            self._socket = None

    def announce(self) -> None:
        """Announce this listener to the network."""
        self._announce(DISCOVERER_HOWDY)

    def unannounce(self) -> None:
        """Announce this listener leaving the network."""
        self._announce(DISCOVERER_EXIT)

    def announce_every(self, interval: float) -> None:
        """
        Start a background thread to announce every interval seconds.

        Args:
            interval: Announcement interval in seconds (recommended: 1.0)
        """
        def announce_loop():
            self.announce()  # Initial announcement

            while not self._shutdown_event.wait(interval):
                if self._shutdown_event.is_set():
                    break
                try:
                    self.announce()
                except Exception:
                    # Ignore errors in background thread
                    pass

            # Send exit announcement on shutdown
            try:
                self.unannounce()
            except Exception:
                pass

        self._announce_thread = threading.Thread(target=announce_loop, daemon=True)
        self._announce_thread.start()

    def discover(self, timeout: float = 0.0) -> Tuple[Device | None, DeviceState]:
        """
        Listen for StageLinq devices on the network.

        Args:
            timeout: Timeout in seconds (0 = no timeout)

        Returns:
            Tuple of (Device, DeviceState) or (None, DeviceState) if timeout

        Raises:
            TooShortDiscoveryMessageError: Message too short
            InvalidMessageError: Invalid message format
            InvalidDiscovererActionError: Invalid discoverer action
        """
        if not self._socket:
            raise StageLinqError("Listener is closed")

        # Set timeout if specified
        if timeout > 0:
            self._socket.settimeout(timeout)
        else:
            self._socket.settimeout(None)

        while True:
            try:
                data, addr = self._socket.recvfrom(8192)
            except socket.timeout:
                return None, DeviceState.PRESENT
            except Exception as e:
                raise StageLinqError(f"Socket error: {e}")

            # Check minimum message length
            if len(data) < 4:
                raise TooShortDiscoveryMessageError("Discovery message too short")

            # Parse discovery message
            try:
                reader = io.BytesIO(data)
                msg = DiscoveryMessage(Token())
                msg.read_from(reader)
            except Exception as e:
                raise InvalidMessageError(f"Failed to parse discovery message: {e}")

            # Create device from message
            device = Device.from_discovery(addr, msg)

            # Skip our own messages
            if (device.token == self.token and
                device.name == self.name and
                device.software_name == self.software_name and
                device.software_version == self.software_version):
                continue

            # Determine device state
            if msg.action == DISCOVERER_HOWDY:
                device_state = DeviceState.PRESENT
            elif msg.action == DISCOVERER_EXIT:
                device_state = DeviceState.LEAVING
            else:
                raise InvalidDiscovererActionError(f"Invalid discoverer action: {msg.action}")

            return device, device_state

    def _announce(self, action: str) -> None:
        """Send announcement message to all broadcast addresses."""
        msg = DiscoveryMessage(
            token=self.token,
            source=self.name,
            action=action,
            software_name=self.software_name,
            software_version=self.software_version,
            port=0  # We don't provide services in this basic implementation
        )

        # Serialize message
        writer = io.BytesIO()
        msg.write_to(writer)
        data = writer.getvalue()

        # Send to all broadcast addresses
        broadcast_addrs = self._get_broadcast_addresses()
        for addr in broadcast_addrs:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(data, (addr, self.DISCOVERY_PORT))
                sock.close()
            except Exception:
                # Ignore errors for individual broadcast addresses
                pass

    def _get_broadcast_addresses(self) -> list[str]:
        """Get list of broadcast addresses for all network interfaces."""
        import netifaces

        broadcast_addrs = []

        # Add general broadcast
        broadcast_addrs.append('255.255.255.255')

        # Add interface-specific broadcasts
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                # Include both IPv4 and IPv6 addresses like Go code does
                for family in [netifaces.AF_INET, netifaces.AF_INET6]:
                    if family in addrs:
                        for addr_info in addrs[family]:
                            if 'broadcast' in addr_info:
                                broadcast_addrs.append(addr_info['broadcast'])
            except Exception:
                # Skip interfaces that can't be queried
                continue

        return list(set(broadcast_addrs))  # Remove duplicates

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def listen(config: ListenerConfiguration | None = None) -> Listener:
    """
    Create a new StageLinq listener.

    Args:
        config: Optional listener configuration

    Returns:
        Listener instance
    """
    return Listener(config)