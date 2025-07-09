#!/usr/bin/env python3
"""
Example: Access file transfer services from StageLinq devices

This demonstrates how to connect to FileTransfer services and list available sources.
"""

import asyncio
from stagelinq.discovery import discover_stagelinq_devices, DiscoveryConfig
from stagelinq.messages import Token


async def file_transfer_example():
    """Example of accessing file transfer services."""
    
    print("START: StageLinq FileTransfer Example")
    print("=" * 40)
    
    # 1. Device Discovery
    print("1. Discovering StageLinq devices...")
    config = DiscoveryConfig(discovery_timeout=3.0)
    
    async with discover_stagelinq_devices(config) as discovery:
        await discovery.start_announcing()
        devices = await discovery.get_devices()
        
        if not devices:
            print("ERROR: No StageLinq devices found")
            return
        
        print(f"OK Found {len(devices)} device(s):")
        for device in devices:
            print(f"   - {device}")
        
        device = devices[0]
        print(f"\n2. Connecting to: {device.name}")
        
        # 2. Connect to device
        try:
            # Create client token
            client_token = Token(b'\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x05\x95\x04\x14\x1c')
            
            # Connect and discover services
            connection = device.connect(client_token)
            async with connection:
                services = await connection.discover_services()
                print(f"OK Available services: {[s.name for s in services]}")
                
                # 3. Check if FileTransfer is available
                file_transfer_service = None
                for service in services:
                    if service.name == "FileTransfer":
                        file_transfer_service = service
                        break
                
                if not file_transfer_service:
                    print("INFO: FileTransfer service not available on this device")
                    return
                
                print(f"OK FileTransfer service found on port {file_transfer_service.port}")
                
                # 4. Connect to FileTransfer service
                try:
                    async with connection.file_transfer() as file_transfer:
                        print("OK Connected to FileTransfer service")
                        
                        # 5. List available sources
                        print("\n3. Listing available sources...")
                        try:
                            sources = await file_transfer.list_sources()
                            if sources:
                                print(f"OK Found {len(sources)} source(s):")
                                for source in sources:
                                    print(f"   - {source}")
                                    
                                    # Get database info for each source
                                    try:
                                        db_info = await file_transfer.get_database_info(source)
                                        print(f"     Database: {db_info['database_path']}")
                                        print(f"     Size: {db_info['database_size']} bytes")
                                    except Exception as e:
                                        print(f"     Error getting database info: {e}")
                            else:
                                print("INFO: No sources found")
                        except Exception as e:
                            print(f"ERROR: Failed to list sources: {e}")
                            
                except Exception as e:
                    print(f"ERROR: Failed to connect to FileTransfer service: {e}")
                    
        except Exception as e:
            print(f"ERROR: Connection failed: {e}")
            print("   This is expected if no real device is available")


if __name__ == "__main__":
    asyncio.run(file_transfer_example())