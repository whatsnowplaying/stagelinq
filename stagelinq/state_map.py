"""
StageLinq State Map Connection

This module implements the StateMap connection for receiving device state updates.
"""

import socket
import threading
import json
from typing import Any
from collections.abc import Iterator
from dataclasses import dataclass
from queue import Queue, Empty
from .messages import Token, StateSubscribeMessage, StateEmitMessage


@dataclass
class State:
    """Represents a state value from the device."""
    name: str
    value: Any


class StateMapConnection:
    """Connection for receiving state updates from a StageLinq device."""

    def __init__(self, conn: socket.socket, token: Token):
        self.token = token
        self._conn = conn
        self._reader = conn.makefile('rb')
        self._writer = conn.makefile('wb')

        self._state_queue = Queue()
        self._error_queue = Queue()
        self._shutdown_event = threading.Event()
        self._subscriptions: dict[str, int] = {}

        # Start background read thread
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._read_thread.start()

    def close(self) -> None:
        """Close the connection."""
        self._shutdown_event.set()
        try:
            self._reader.close()
            self._writer.close()
            self._conn.close()
        except Exception:
            pass

    def subscribe(self, state_name: str, interval: int = 0) -> None:
        """
        Subscribe to state updates for a specific state name.

        Args:
            state_name: Name of the state to subscribe to
            interval: Update interval (0 for default)
        """
        if state_name in self._subscriptions:
            return  # Already subscribed

        self._subscriptions[state_name] = interval

        msg = StateSubscribeMessage(name=state_name, interval=interval)
        try:
            msg.write_to(self._writer)
            self._writer.flush()
        except Exception as e:
            self._error_queue.put(e)

    def unsubscribe(self, state_name: str) -> None:
        """
        Unsubscribe from state updates for a specific state name.

        Args:
            state_name: Name of the state to unsubscribe from
        """
        if state_name in self._subscriptions:
            del self._subscriptions[state_name]

        # Note: The StageLinq protocol doesn't seem to have explicit unsubscribe
        # This just removes it from our local tracking

    def states(self) -> Iterator[State]:
        """
        Iterate over incoming state updates.

        Yields:
            State objects as they arrive
        """
        while not self._shutdown_event.is_set():
            try:
                # Check for errors first
                try:
                    error = self._error_queue.get_nowait()
                    raise error
                except Empty:
                    pass

                # Get next state with timeout
                try:
                    state = self._state_queue.get(timeout=0.1)
                    yield state
                except Empty:
                    continue

            except Exception:
                break

    def get_state(self, timeout: float = 1.0) -> State | None:
        """
        Get the next state update.

        Args:
            timeout: Timeout in seconds

        Returns:
            State object or None if timeout
        """
        try:
            # Check for errors first
            try:
                error = self._error_queue.get_nowait()
                raise error
            except Empty:
                pass

            return self._state_queue.get(timeout=timeout)
        except Empty:
            return None

    def _read_loop(self) -> None:
        """Background thread that reads state messages."""
        try:
            while not self._shutdown_event.is_set():
                try:
                    msg = StateEmitMessage()
                    msg.read_from(self._reader)

                    # Parse JSON value
                    try:
                        value = json.loads(msg.json_data)
                    except json.JSONDecodeError:
                        # If JSON parsing fails, use the raw string
                        value = msg.json_data

                    state = State(name=msg.name, value=value)
                    self._state_queue.put(state)

                except Exception as e:
                    if not self._shutdown_event.is_set():
                        self._error_queue.put(e)
                    break

        except Exception:
            pass  # Thread is shutting down

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()