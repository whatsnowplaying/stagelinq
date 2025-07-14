# StagelinQ File Transfer Protocol (FLTX) Documentation

This document provides a comprehensive analysis of the StagelinQ File Transfer protocol, based on packet capture analysis, GitHub issue research, and behavioral observations.

## Table of Contents

- [Protocol Overview](#protocol-overview)
- [Message Structure](#message-structure)
- [Message Types](#message-types)
- [Protocol Flow](#protocol-flow)
- [Implementation Details](#implementation-details)
- [Known Issues](#known-issues)
- [References](#references)

## Protocol Overview

The StagelinQ File Transfer protocol uses the magic bytes `fltx` and enables DJ software and hardware to:
- Browse directory structures on connected storage devices
- Request file metadata and transfer files
- Manage persistent directory subscriptions
- Handle cache invalidation when storage devices are removed

### Key Characteristics

- **Asynchronous**: Request ID field enables correlation of requests and responses
- **Subscription-based**: Directory listings establish persistent subscriptions for automatic updates
- **Cache-aware**: Explicit cache invalidation when storage devices change
- **Chunk-based transfers**: Large files transferred in 4KB chunks

## Message Structure

All FLTX messages follow this wire-level structure:

```
[4 bytes: total_length] [4 bytes: "fltx"] [4 bytes: request_id] [4 bytes: message_type] [variable: payload]
```

### Header Fields

- **total_length**: Size of everything after this field (excludes the 4-byte length field itself)
- **magic**: Always `0x666c7478` ("fltx" in ASCII)
- **request_id**: Unique identifier for async request/response correlation
- **message_type**: Determines payload format and protocol behavior

### Common Payload Patterns

For request messages, the payload typically starts with:
```
[4 bytes: size_field] [variable: path_data] [optional: null_terminators] [optional: additional_data]
```

- **size_field**: Byte length of the path data (UTF-16BE encoded)
- **path_data**: File/directory path in UTF-16BE encoding
- **null_terminators**: Some message types append 4 null bytes (`0x00000000`)
- **additional_data**: Message-specific parameters (e.g., chunk offset/size)

## Message Types

### Request Messages

#### 0x7D2 - DIRECTORY_LIST
Lists directory contents or retrieves root sources.

**Request Format:**
```
[length] [fltx] [request_id] [0x7D2] [path_size] [path_data]
```

**Examples:**
- Root listing: `00000010 666c7478 00000000 000007d2 00000000`
- Directory: `00000050 666c7478 00000000 000007d2 00000040 [64 bytes UTF-16BE path]`

**Response:** Directory listing with trailer flags indicating chunk position and content type.

#### 0x7D1 - DATABASE_PATH_REQUEST
Requests database/file information.

**Request Format:**
```
[length] [fltx] [request_id] [0x7D1] [path_size] [path_data]
```

**Example:**
```
00000050 666c7478 00000000 000007d1 00000040 002f0044...
```

#### 0x7D4 - DATABASE_INFO
Requests detailed file metadata (file size, permissions, timestamps).

**Request Format:**
```
[length] [fltx] [request_id] [0x7D4] [path_size] [path_data] [00000000]
```

**Key Difference:** Always includes 4 null bytes after path data.

**Response:** 49-byte metadata structure:
- Byte 0: File exists flag (0x01 = exists, 0x00 = not found)
- Byte 1: Directory flag (0x01 = directory, 0x00 = file)
- Bytes 2-3: Reserved/unknown
- Bytes 4-5: Permissions (e.g., 0x7755, 0x6644)
- Bytes 6-40: Metadata blocks (timestamps, user/group IDs, etc.) - **still being researched**
- Bytes 41-48: File size (8 bytes, big-endian)

#### 0x7D5 - DATABASE_READ
Requests specific chunks of a file for download.

**Request Format:**
```
[length] [fltx] [request_id] [0x7D5] [path_size] [path_data] [0x0000] [4 bytes: offset] [4 bytes: chunk_size]
```

**Notes:**
- Includes null terminator between path and chunk parameters
- Default chunk size is 4096 bytes
- Offset specifies byte position in file

#### 0x7D6 - REQUEST_COMPLETE
Signals completion of a file transfer session.

**Request Format:**
```
[length] [fltx] [request_id] [0x7D6] [0x00000000]
```

#### 0x7D3 - SESSION_CLEANUP
Signals end of inquiry session (no response expected).

**Request Format:**
```
[length] [fltx] [request_id] [0x7D3] [0x00000000]
```

### Response/Control Messages

#### 0x02 - FRAME_END
Indicates successful completion of a transfer frame. Can control persistent requests.

**Payload:**
```
[transaction_id] [message_type] [success_flag] [additional_data]
```

- **success_flag**: 0x01 = success, 0x00 = error
- Used to silence continuous device inquiries
- May trigger device to crawl reported directories

#### 0x03 - LIST_RESPONSE
Response to directory listing requests.

**Payload:** Variable-length directory entries followed by 3-byte trailer:
- Byte -3: First chunk flag (0x01 = first chunk)
- Byte -2: Last chunk flag (0x01 = last chunk)  
- Byte -1: Content type (0x01 = directories/volumes, 0x00 = files)

#### 0x09 - DIRECTORY_INVALIDATE
Sent when storage device is ejected to invalidate cached directory listings.

**Payload:**
```
[original_transaction_id] [additional_data]
```

- References the TransactionId from original LIST request
- Enables precise cache invalidation

#### 0x0A - TRANSFER_STATUS_QUERY
Queries if a transfer ID is still active.

#### 0x7D8 - PAUSE_TRANSFER
Indicates temporary pause of a specific transaction.

#### 0x7D9 - PAUSE_REQUEST
Requests to pause a transfer session.

#### 0x07 - PAUSE_RESPONSE
Response to pause request.

## Protocol Flow

### 1. Discovery and Connection
1. Client discovers StagelinQ devices via UDP broadcast
2. Device announces FileTransfer service on specific TCP port
3. Client connects to FileTransfer port

### 2. Directory Browsing
1. Client sends 0x7D2 request for root directory (`path=""`)
2. Device responds with source list (USB drives, etc.)
3. **Subscription established** - device will send updates if storage changes
4. Client sends 0x7D2 for specific directories
5. Device responds with file/directory listings

### 3. File Information
1. Client sends 0x7D4 request for file metadata
2. Device responds with 49-byte stat structure
3. Client validates response for transfer compatibility

### 4. File Transfer
1. Client sends series of 0x7D5 requests for file chunks
2. Device responds with chunk data
3. Client sends 0x7D6 to signal completion
4. Optional: Client sends 0x7D3 for session cleanup

### 5. Cache Management
- Device sends 0x09 messages when storage removed
- Messages reference original TransactionIds for precise invalidation
- Clients should purge corresponding cache entries

## Implementation Details

### Path Encoding
- All paths are UTF-16BE encoded
- No byte-order mark (BOM)
- Forward slashes as directory separators
- Examples: `/DJ2 (USB 1)/Engine Library/m.db`

### Error Handling
- Invalid stat responses cause "corrupt database" errors
- Devices may skip chunks if metadata is malformed
- Network errors should trigger session cleanup

### Performance Considerations
- Directory subscriptions reduce polling overhead
- Cache invalidation prevents stale data
- 4KB chunk size balances throughput and latency

### Critical Implementation Notes

1. **Stat Response Accuracy**: The 49-byte metadata structure must be precisely formatted. Incorrect data leads to transfer failures.

2. **TransactionId Tracking**: Essential for subscription management and cache invalidation.

3. **Null Terminator Handling**: 0x7D4 requests require null terminators; others don't.

4. **Length Field Calculation**: Excludes the length field itself in the total.

## Known Issues

### Research Areas
1. **Metadata Blob Decoding**: Bytes 6-40 in stat response contain unknown fields (likely timestamps, permissions, user/group IDs)
2. **Chunk Jumping**: Devices may request non-sequential chunks when stat responses are malformed
3. **Pause/Resume Logic**: 0x7D8/0x7D9/0x07 message interactions need further analysis

### Implementation Challenges
1. Maintaining consistent TransactionId mapping across sessions
2. Handling device disconnections during transfers
3. Managing multiple concurrent file transfers

## References

### Primary Sources
- **GitHub Issue**: [icedream/go-stagelinq#8](https://github.com/icedream/go-stagelinq/issues/8)
- **Packet Captures**: Real device communication traces
- **honusz's Listener Implementation**: Device-to-software connection approach

### Packet Examples
All hex examples in this document are from actual Denon device communications captured during testing with Prime 4, SC6000, and other StagelinQ-compatible hardware.

### Implementation
Reference implementation available in the `stagelinq.file_transfer` module, validated against real packet captures for byte-perfect compatibility.

---

*Last updated: Based on packet analysis and GitHub issue research as of July 2025*