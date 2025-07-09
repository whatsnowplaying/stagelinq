"""
StageLinq Connection Implementation

This module implements connection classes for StageLinq communication.
"""

import socket
import threading
import time
import io
from typing import Any
from dataclasses import dataclass
from .messages import (
    Token, ServiceAnnouncementMessage, ReferenceMessage, ServicesRequestMessage
)


@dataclass
class Service:
    """Information about a service provided by a device."""
    name: str
    port: int


class MessageConnection:
    """Low-level message connection for reading/writing StageLinq messages."""

    def __init__(self, conn: socket.socket):
        self.conn = conn
        self._lock = threading.Lock()
        self._reader = conn.makefile('rb')
        self._writer = conn.makefile('wb')

    def read_message(self) -> Any:
        """Read a message from the connection."""
        with self._lock:
            # Try to identify message type by peeking at message ID
            try:
                # Read message ID to determine message type
                message_id_data = self._reader.read(4)
                if len(message_id_data) != 4:
                    raise EOFError("Failed to read message ID")

                # Create a new reader with the message ID at the start
                import struct
                message_id = struct.unpack(">I", message_id_data)[0]

                # Put the message ID back for the message parser
                full_reader = io.BytesIO(message_id_data + self._reader.read())

                # Determine message type and parse
                if message_id == ServiceAnnouncementMessage.MESSAGE_ID:
                    msg = ServiceAnnouncementMessage(Token())
                    msg.read_from(full_reader)
                    return msg
                elif message_id == ReferenceMessage.MESSAGE_ID:
                    msg = ReferenceMessage(Token())
                    msg.read_from(full_reader)
                    return msg
                elif message_id == ServicesRequestMessage.MESSAGE_ID:
                    msg = ServicesRequestMessage(Token())
                    msg.read_from(full_reader)
                    return msg
                else:
                    raise ValueError(f"Unknown message ID: {message_id}")

            except Exception as e:
                raise ConnectionError(f"Failed to read message: {e}")

    def write_message(self, msg: Any) -> None:
        """Write a message to the connection."""
        with self._lock:
            try:
                msg.write_to(self._writer)
                self._writer.flush()
            except Exception as e:
                raise ConnectionError(f"Failed to write message: {e}")

    def close(self) -> None:
        """Close the connection."""
        try:
            self._reader.close()
            self._writer.close()
            self.conn.close()
        except Exception:
            pass


class MainConnection:
    """Main connection to a StageLinq device."""

    def __init__(self, conn: socket.socket, token: Token, target_token: Token,
                 offered_services: list[Service] | None = None):
        self.token = token
        self.target_token = target_token
        self.offered_services = offered_services or []
        self.reference = 0

        self._msg_conn = MessageConnection(conn)
        self._lock = threading.Lock()
        self._services_channel: list[Service] | None = None
        self._error_channel: Exception | None = None
        self._shutdown_event = threading.Event()

        # Start background threads
        self._reference_thread = threading.Thread(target=self._reference_loop, daemon=True)
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)

        self._reference_thread.start()
        self._read_thread.start()

    def close(self) -> None:
        """Close the connection."""
        self._shutdown_event.set()
        self._msg_conn.close()

    def request_services(self) -> list[Service]:
        """Request list of services from the device."""
        with self._lock:
            self._services_channel = []
            self._error_channel = None

        # Send services request
        msg = ServicesRequestMessage(self.token)
        self._msg_conn.write_message(msg)

        # Wait for services or error
        timeout = 10.0  # 10 second timeout
        start_time = time.time()

        while time.time() - start_time < timeout:
            with self._lock:
                if self._error_channel:
                    raise self._error_channel

                if self._services_channel is not None:
                    # Services collection is complete
                    services = self._services_channel.copy()
                    self._services_channel = None
                    return services

            time.sleep(0.1)

        raise TimeoutError("Timeout waiting for services response")

    def _reference_loop(self) -> None:
        """Background thread that sends reference messages."""
        while not self._shutdown_event.is_set():
            try:
                with self._lock:
                    ref = self.reference

                msg = ReferenceMessage(
                    token=self.token,
                    token2=self.target_token,
                    reference=ref
                )
                self._msg_conn.write_message(msg)

                # Wait 250ms or until shutdown
                if self._shutdown_event.wait(0.25):
                    break

            except Exception:
                # Stop on any error
                break

    def _read_loop(self) -> None:
        """Background thread that reads messages."""
        try:
            while not self._shutdown_event.is_set():
                try:
                    msg = self._msg_conn.read_message()
                    self._handle_message(msg)
                except Exception as e:
                    with self._lock:
                        self._error_channel = e
                    break
        except Exception:
            pass  # Thread is shutting down

    def _handle_message(self, msg: Any) -> None:
        """Handle incoming message."""
        with self._lock:
            if isinstance(msg, ServiceAnnouncementMessage):
                if self._services_channel is not None:
                    service = Service(name=msg.service, port=msg.port)
                    self._services_channel.append(service)

            elif isinstance(msg, ReferenceMessage):
                # End of services list
                if self._services_channel is not None:
                    # Keep services_channel as-is, it will be read by request_services
                    pass

            elif isinstance(msg, ServicesRequestMessage):
                # Device is requesting our services
                for service in self.offered_services:
                    try:
                        response = ServiceAnnouncementMessage(
                            token=self.token,
                            service=service.name,
                            port=service.port
                        )
                        self._msg_conn.write_message(response)
                    except Exception:
                        # Ignore write errors
                        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()