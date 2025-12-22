"""Semantic RPC message constructs - higher level protocol understanding.

This module provides semantic parsing of protocol payloads, mapping method bytes
to their specific payload structures and enums.
"""

from __future__ import annotations

from enum import IntEnum

from construct import (
    Bytes,
    Computed,
    Const,
    Container,
    Construct,
    Enum,
    GreedyBytes,
    Int8ul,
    Int16ul,
    Select,
    Struct,
    Switch,
)


class RenderMode(IntEnum):
    """Mode selection for method 0x08."""

    UPLOADED_IMAGE = 0x01
    MUSIC_VIZ = 0x02
    TEXT = 0x03
    FLAT_COLOR = 0x04


class Method03Submethod(IntEnum):
    """Submethods for method 0x03."""

    LIBRARY_LOAD = 0x01
    DATA_TRANSFER = 0x02
    TRANSFER_COMPLETE = 0x03


# Method 0x08: Mode selection
ModeSelectPayload: Construct = Struct(
    "mode" / Enum(Int8ul, RenderMode),
)


# Method 0x03 submessages
# Submethod 0x01: Library load
LibraryLoadPayload: Construct = Struct(
    "submethod" / Const(0x01, Int8ul),
    "unknown1" / Int8ul,  # 0x48
    "unknown2" / Int8ul,  # 0x15
    "unknown3" / Bytes(2),  # 0x00 0x00
    "path_length" / Int16ul,
    "path" / Bytes(lambda this: this.path_length),
)


# Method 0x03, Submethod 0x02: Data transfer
# Header format:
#   offset 0x00: submethod (0x02)
#   offset 0x01-0x02: write_offset (u16le)
#   offset 0x03-0x04: unknown (0x00 0x00)
#   offset 0x05-0x06: payload_length (u16le)
#
# First chunk (write_offset == 0) has additional 8-byte inner header:
#   offset 0x00-0x03: unknown
#   offset 0x04-0x05: width (u16le, max 0x3a = 58 pixels)
#   offset 0x06-0x07: height (u16le, max 0x50 = 80 pixels)
#
# Subsequent chunks have raw data starting at offset 7

DataTransferInnerHeader: Construct = Struct(
    "unknown" / Bytes(4),
    "width" / Int16ul,  # max 0x3a
    "height" / Int16ul,  # max 0x50
)

DataTransferPayload: Construct = Struct(
    "submethod" / Const(0x02, Int8ul),
    "write_offset" / Int16ul,
    "unknown" / Bytes(2),
    "payload_length" / Int16ul,
    "data"
    / Switch(
        lambda this: this.write_offset,
        {
            # First chunk: inner header + data
            0: Struct(
                "header" / DataTransferInnerHeader,
                "chunk_data" / Bytes(lambda this: this._.payload_length - 8),
            ),
        },
        # Subsequent chunks: just data
        default=Struct(
            "chunk_data" / Bytes(lambda this: this._.payload_length),
        ),
    ),
)


# Method 0x03, Submethod 0x03: Transfer complete
TransferCompletePayload: Construct = Struct(
    "submethod" / Const(0x03, Int8ul),
    # Payload meaning unclear
    # 0x00: normal completion
    # 0x01: may trigger reboot/crash?
)


# Top-level Method 0x03 payload dispatcher
# Switch doesn't work well with Peek, so we'll use Select to try each construct
Method03Payload: Construct = Select(
    LibraryLoadPayload,
    DataTransferPayload,
    TransferCompletePayload,
)


# Method 0x06: Unknown (seen with payload 0x02)
Method06Payload: Construct = Struct(
    "unknown_byte" / Int8ul,
)


# Method 0x09: Unknown (seen with payload 0x02 0x00)
Method09Payload: Construct = Struct(
    "unknown1" / Int8ul,
    "unknown2" / Int8ul,
)


# Method 0x0a: Unknown (seen with two different payload lengths)
Method0aPayload: Construct = Struct(
    "payload_data" / GreedyBytes,
)


# Top-level semantic payload dispatcher
# This wraps the raw payload and dispatches to the appropriate semantic structure
SemanticPayload: Construct = Struct(
    "method" / Computed(lambda this: this._params.method),
    "data"
    / Switch(
        lambda this: this._params.method,
        {
            0x03: Method03Payload,
            0x06: Method06Payload,
            0x08: ModeSelectPayload,
            0x09: Method09Payload,
            0x0A: Method0aPayload,
        },
        default=Struct(
            "raw" / GreedyBytes,
        ),
    ),
)


def parse_semantic_payload(method: int, payload_bytes: bytes) -> Container:
    """Parse a payload into its semantic structure based on method.

    Args:
        method: Method byte (0x03, 0x08, etc.)
        payload_bytes: Raw payload bytes

    Returns:
        Parsed semantic structure (construct Container)

    Raises:
        construct exceptions if parsing fails
    """
    return SemanticPayload.parse(payload_bytes, method=method)


def get_submethod(method: int, payload_bytes: bytes) -> int | None:
    """Extract submethod byte if this method uses submethods.

    Args:
        method: Method byte
        payload_bytes: Raw payload bytes

    Returns:
        Submethod byte or None if method doesn't use submethods
    """
    if method == 0x03 and len(payload_bytes) > 0:
        return payload_bytes[0]
    return None
