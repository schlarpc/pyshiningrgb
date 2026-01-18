"""Helper functions to build semantic RPC messages.

This module provides high-level builder functions that construct properly formatted
protocol messages for various operations like mode selection, library loading,
and data transfer.
"""

from __future__ import annotations

from pyshiningrgb.protocol import MAX_C2S_PAYLOAD, build_c2s_message
from pyshiningrgb.semantic import (
    AnimationType,
    ApplyAttributesPayload,
    DataTransferPayload,
    LibraryLoadPayload,
    Method06Payload,
    Method09Payload,
    ModeSelectPayload,
    RenderMode,
    SetAttributesPayload,
    TransferCompletePayload,
)

# Data transfer limits
DATA_TRANSFER_HEADER_SIZE = 7  # submethod(1) + write_offset(2) + unknown(2) + payload_length(2)
DATA_TRANSFER_INNER_HEADER_SIZE = 8  # unknown(4) + width(2) + height(2)
MAX_DATA_FIRST_CHUNK = (
    MAX_C2S_PAYLOAD - DATA_TRANSFER_HEADER_SIZE - DATA_TRANSFER_INNER_HEADER_SIZE
)  # 1576 bytes
MAX_DATA_CHUNK = MAX_C2S_PAYLOAD - DATA_TRANSFER_HEADER_SIZE  # 1584 bytes


def build_mode_select(mode: RenderMode) -> bytes:
    """Build a mode selection message (method 0x08).

    Args:
        mode: RenderMode enum value (UPLOADED_IMAGE, MUSIC_VIZ, TEXT, FLAT_COLOR)

    Returns:
        Complete C2S message bytes ready to send
    """
    payload = ModeSelectPayload.build({"mode": mode})
    return build_c2s_message(0x08, payload)


def build_library_load(
    path: str | bytes,
    unknown1: int = 0x48,
    unknown2: int = 0x15,
    unknown3: bytes = b"\x00\x00",
) -> bytes:
    """Build a library load message (method 0x03, submethod 0x01).

    Args:
        path: Library path string (e.g., "/Text.lib") or bytes
        unknown1: Unknown byte (default 0x48)
        unknown2: Unknown byte (default 0x15)
        unknown3: Unknown 2 bytes (default 0x00 0x00)

    Returns:
        Complete C2S message bytes ready to send
    """
    path_bytes = path.encode("utf-8") if isinstance(path, str) else path
    payload = LibraryLoadPayload.build(
        {
            "unknown1": unknown1,
            "unknown2": unknown2,
            "unknown3": unknown3,
            "path_length": len(path_bytes),
            "path": path_bytes,
        }
    )
    return build_c2s_message(0x03, payload)


def build_data_transfer_first_chunk(
    width: int, height: int, data: bytes, unknown_header: bytes = b"\x00\x00\x00\x00"
) -> bytes:
    """Build first chunk of data transfer (method 0x03, submethod 0x02, offset 0).

    Args:
        width: Image width in pixels (max 0x3a = 58)
        height: Image height in pixels (max 0x50 = 80)
        data: Pixel data for this chunk (max 1576 bytes)
        unknown_header: Unknown 4 bytes in inner header (default 0x00 0x00 0x00 0x00)

    Returns:
        Complete C2S message bytes ready to send

    Raises:
        ValueError: If dimensions or data size exceed limits
    """
    if width > 0x3A:
        raise ValueError(f"Width {width} exceeds maximum 0x3a (58 pixels)")
    if height > 0x50:
        raise ValueError(f"Height {height} exceeds maximum 0x50 (80 pixels)")
    if len(data) > MAX_DATA_FIRST_CHUNK:
        raise ValueError(
            f"Data size {len(data)} exceeds maximum {MAX_DATA_FIRST_CHUNK} bytes for first chunk"
        )

    payload_length = 8 + len(data)  # 8-byte inner header + data

    payload = DataTransferPayload.build(
        {
            "write_offset": 0,
            "unknown": b"\x00\x00",
            "payload_length": payload_length,
            "data": {
                "header": {
                    "unknown": unknown_header,
                    "width": width,
                    "height": height,
                },
                "chunk_data": data,
            },
        }
    )
    return build_c2s_message(0x03, payload)


def build_data_transfer_chunk(write_offset: int, data: bytes) -> bytes:
    """Build subsequent chunk of data transfer (method 0x03, submethod 0x02, offset > 0).

    Args:
        write_offset: Offset where this chunk should be written (must be > 0)
        data: Data for this chunk (max 1584 bytes)

    Returns:
        Complete C2S message bytes ready to send

    Raises:
        ValueError: If write_offset is 0 or data size exceeds limits
    """
    if write_offset == 0:
        raise ValueError("Use build_data_transfer_first_chunk for offset 0")
    if len(data) > MAX_DATA_CHUNK:
        raise ValueError(f"Data size {len(data)} exceeds maximum {MAX_DATA_CHUNK} bytes for chunk")

    payload = DataTransferPayload.build(
        {
            "write_offset": write_offset,
            "unknown": b"\x00\x00",
            "payload_length": len(data),
            "data": {
                "chunk_data": data,
            },
        }
    )
    return build_c2s_message(0x03, payload)


def build_transfer_complete() -> bytes:
    """Build transfer complete message (method 0x03, submethod 0x03).

    Returns:
        Complete C2S message bytes ready to send
    """
    payload = TransferCompletePayload.build({})
    return build_c2s_message(0x03, payload)


def build_method_06(unknown_byte: int = 0x02) -> bytes:
    """Build method 0x06 message (purpose unknown).

    Args:
        unknown_byte: Payload byte (default 0x02)

    Returns:
        Complete C2S message bytes ready to send
    """
    payload = Method06Payload.build({"unknown_byte": unknown_byte})
    return build_c2s_message(0x06, payload)


def build_method_09(unknown1: int = 0x02, unknown2: int = 0x00) -> bytes:
    """Build method 0x09 message (purpose unknown).

    Args:
        unknown1: First byte (default 0x02)
        unknown2: Second byte (default 0x00)

    Returns:
        Complete C2S message bytes ready to send
    """
    payload = Method09Payload.build(
        {
            "unknown1": unknown1,
            "unknown2": unknown2,
        }
    )
    return build_c2s_message(0x09, payload)


def build_method_0a(payload_data: bytes) -> bytes:
    """Build method 0x0a message with raw payload.

    Args:
        payload_data: Raw payload bytes

    Returns:
        Complete C2S message bytes ready to send
    """
    return build_c2s_message(0x0A, payload_data)


def build_set_attributes(
    animation_type: AnimationType = AnimationType.NONE,
    background_color: bytes = b"\x00\x00",
    animation_speed: int = 0,
    unknown1: bytes = b"\x00\x00\x00",
    unknown2: int = 0x01,
) -> bytes:
    """Build set attributes message (method 0x0a, submethod 0x06).

    Args:
        animation_type: Animation type (see AnimationType enum)
        background_color: Background color in RGB565 format (2 bytes, little-endian)
        animation_speed: Animation speed from 0 (slowest) to 10 (fastest)
        unknown1: Unknown 3 bytes (default 0x00 0x00 0x00)
        unknown2: Unknown byte (default 0x01)

    Returns:
        Complete C2S message bytes ready to send

    Raises:
        ValueError: If animation_speed is out of range (0-10)
    """
    if not 0 <= animation_speed <= 10:
        raise ValueError(f"animation_speed must be 0-10, got {animation_speed}")

    payload = SetAttributesPayload.build(
        {
            "unknown1": unknown1,
            "unknown2": unknown2,
            "background_color": background_color,
            "animation_type": animation_type,
            "animation_speed": animation_speed,
        }
    )
    return build_c2s_message(0x0A, payload)


def build_apply_attributes() -> bytes:
    """Build apply attributes message (method 0x0a, submethod 0x04).

    This acts as an end-of-message marker after setting attributes and
    transferring image data.

    Returns:
        Complete C2S message bytes ready to send
    """
    payload = ApplyAttributesPayload.build({})
    return build_c2s_message(0x0A, payload)


def build_data_transfer_auto(
    width: int, height: int, data: bytes, unknown_header: bytes = b"\x00\x00\x00\x00"
) -> list[tuple[str, bytes]]:
    """Automatically chunk image data into properly sized data transfer messages.

    Args:
        width: Image width in pixels (max 0x3a = 58)
        height: Image height in pixels (max 0x50 = 80)
        data: Full image data to transfer
        unknown_header: Unknown 4 bytes in inner header (default 0x00 0x00 0x00 0x00)

    Returns:
        List of (description, message_bytes) tuples ready to send

    Raises:
        ValueError: If dimensions exceed limits
    """
    if width > 0x3A:
        raise ValueError(f"Width {width} exceeds maximum 0x3a (58 pixels)")
    if height > 0x50:
        raise ValueError(f"Height {height} exceeds maximum 0x50 (80 pixels)")

    messages: list[tuple[str, bytes]] = []
    offset = 0

    # First chunk includes dimensions header
    first_chunk_size = min(len(data), MAX_DATA_FIRST_CHUNK)
    messages.append(
        (
            f"Data transfer chunk 0: dimensions {width} x {height}, {first_chunk_size} bytes",
            build_data_transfer_first_chunk(
                width, height, data[:first_chunk_size], unknown_header
            ),
        )
    )
    offset += first_chunk_size

    # Subsequent chunks
    while offset < len(data):
        chunk_size = min(len(data) - offset, MAX_DATA_CHUNK)
        messages.append(
            (
                f"Data transfer chunk at offset 0x{offset:04x} ({chunk_size} bytes)",
                build_data_transfer_chunk(offset, data[offset : offset + chunk_size]),
            )
        )
        offset += chunk_size

    return messages
