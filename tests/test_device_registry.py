"""Unit tests for DeviceRegistry functionality."""

from unittest.mock import Mock

import pytest

from stagelinq.device import DeviceRegistry, StateCategory
from stagelinq.discovery import Device
from stagelinq.messages import Token


class TestDeviceRegistry:
    """Test DeviceRegistry class methods."""

    def test_device_registry_creation(self):
        """Test DeviceRegistry creation."""
        registry = DeviceRegistry()
        assert len(registry) == 0
        assert not list(registry)

    def test_add_device(self):
        """Test adding a device to the registry."""
        registry = DeviceRegistry()
        token = Token(b"\x01" * 16)
        device = Device(
            ip="192.168.1.100",
            name="SC6000",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token,
        )

        registry.add_device(device)
        assert len(registry) == 1
        assert device in registry

    def test_add_device_no_duplicates(self):
        """Test that adding the same device twice doesn't create duplicates."""
        registry = DeviceRegistry()
        token = Token(b"\x01" * 16)
        device1 = Device(
            ip="192.168.1.100",
            name="SC6000",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token,
        )
        device2 = Device(
            ip="192.168.1.101",  # Different IP
            name="SC6000-2",  # Different name
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token,  # Same token
        )

        registry.add_device(device1)
        registry.add_device(device2)  # Should not be added due to same token

        assert len(registry) == 1
        assert device1 in registry
        assert device2 not in registry

    def test_find_device_by_uuid(self):
        """Test finding a device by UUID."""
        registry = DeviceRegistry()
        token = Token(
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
        )
        device = Device(
            ip="192.168.1.100",
            name="SC6000",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token,
        )

        registry.add_device(device)

        # Test finding with hex string (no hyphens)
        found = registry.find_device_by_uuid("0102030405060708090a0b0c0d0e0f10")
        assert found == device

        # Test finding with UUID format (with hyphens)
        found = registry.find_device_by_uuid("01020304-0506-0708-090a-0b0c0d0e0f10")
        assert found == device

        # Test not found
        not_found = registry.find_device_by_uuid("ffffffffffffffffffffffffffffffff")
        assert not_found is None

    def test_find_device_by_token(self):
        """Test finding a device by token."""
        registry = DeviceRegistry()
        token = Token(b"\x01" * 16)
        device = Device(
            ip="192.168.1.100",
            name="SC6000",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token,
        )

        registry.add_device(device)

        # Test finding with matching token
        found = registry.find_device_by_token(token)
        assert found == device

        # Test finding with different token
        different_token = Token(b"\x02" * 16)
        not_found = registry.find_device_by_token(different_token)
        assert not_found is None

    def test_parse_channel_assignment_simple(self):
        """Test parsing simple channel assignment strings."""
        registry = DeviceRegistry()

        # Test empty or invalid strings
        assert registry.parse_channel_assignment("") == ""
        assert registry.parse_channel_assignment("simple string") == "simple string"

    def test_parse_channel_assignment_with_device(self):
        """Test parsing channel assignment with device lookup."""
        registry = DeviceRegistry()
        token = Token(bytes.fromhex("0102030405060708090a0b0c0d0e0f10"))
        device = Device(
            ip="192.168.1.100",
            name="SC6000",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token,
        )
        registry.add_device(device)

        # Test with device UUID and channel
        assignment = "{01020304-0506-0708-090a-0b0c0d0e0f10},1"
        result = registry.parse_channel_assignment(assignment)
        assert result == "SC6000 channel 1"

        # Test with device UUID only
        assignment = "{01020304-0506-0708-090a-0b0c0d0e0f10}"
        result = registry.parse_channel_assignment(assignment)
        assert result == "SC6000 ({01020304-0506-0708-090a-0b0c0d0e0f10})"

        # Test with unknown device
        assignment = "{ffffffff-ffff-ffff-ffff-ffffffffffff},2"
        result = registry.parse_channel_assignment(assignment)
        assert result == assignment  # Should return original string

    def test_parse_channel_assignment_malformed(self):
        """Test parsing malformed channel assignment strings."""
        registry = DeviceRegistry()

        # Test malformed strings
        assert registry.parse_channel_assignment("{malformed") == "{malformed"
        assert registry.parse_channel_assignment("malformed}") == "malformed}"
        assert registry.parse_channel_assignment("{}") == "{}"

    def test_list_devices(self):
        """Test listing all devices."""
        registry = DeviceRegistry()
        token1 = Token(b"\x01" * 16)
        token2 = Token(b"\x02" * 16)

        device1 = Device(
            ip="192.168.1.100",
            name="SC6000-1",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token1,
        )
        device2 = Device(
            ip="192.168.1.101",
            name="SC6000-2",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token2,
        )

        registry.add_device(device1)
        registry.add_device(device2)

        devices = registry.list_devices()
        assert len(devices) == 2
        assert device1 in devices
        assert device2 in devices

        # Test that it returns a copy
        devices.clear()
        assert len(registry) == 2

    def test_iteration(self):
        """Test iterating over devices."""
        registry = DeviceRegistry()
        token1 = Token(b"\x01" * 16)
        token2 = Token(b"\x02" * 16)

        device1 = Device(
            ip="192.168.1.100",
            name="SC6000-1",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token1,
        )
        device2 = Device(
            ip="192.168.1.101",
            name="SC6000-2",
            software_name="Engine OS",
            software_version="3.0.0",
            port=51337,
            token=token2,
        )

        registry.add_device(device1)
        registry.add_device(device2)

        devices = list(registry)
        assert len(devices) == 2
        assert device1 in devices
        assert device2 in devices


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
