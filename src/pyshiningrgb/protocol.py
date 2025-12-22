"""Low-level RPC protocol parser using construct.

This module provides sans-io parsing and building of the ShiningRGB protocol messages.
It defines the wire format for client-to-server (C2S) and server-to-client (S2C) messages.
"""

from __future__ import annotations

import operator
from functools import reduce
from typing import Generator, Literal, cast

from construct import (
    Bytes,
    Check,
    Const,
    Container,
    Construct,
    Int8ul,
    Int16ul,
    Rebuild,
    Struct,
)

# Protocol limits
MAX_MESSAGE_SIZE = 1599  # Maximum total message size in bytes
C2S_OVERHEAD = 8  # magic(2) + unknown(2) + length(2) + method(1) + checksum(1)
S2C_OVERHEAD = 7  # magic(2) + method(1) + unknown(1) + length(2) + checksum(1)
MAX_C2S_PAYLOAD = MAX_MESSAGE_SIZE - C2S_OVERHEAD  # 1591 bytes
MAX_S2C_PAYLOAD = MAX_MESSAGE_SIZE - S2C_OVERHEAD  # 1592 bytes


def xor_bytes(data: bytes | list[int]) -> int:
    """XOR all bytes in data.

    Args:
        data: Bytes or list of integers to XOR together

    Returns:
        XOR result as an integer (0-255)
    """
    if not data:
        return 0
    return reduce(operator.xor, data, 0)


def c2s_checksum_compute(ctx: Container) -> int:
    """Compute C->S checksum: XOR(unknown + length + method + payload).

    Args:
        ctx: construct Container with message fields

    Returns:
        Computed checksum byte (0-255)
    """
    data: list[int] = []
    data.extend(ctx.unknown)
    data.append(ctx.length & 0xFF)
    data.append((ctx.length >> 8) & 0xFF)
    data.append(ctx.method)
    data.extend(ctx.payload)
    return xor_bytes(data)


def s2c_checksum_compute(ctx: Container) -> int:
    """Compute S->C checksum: ~XOR(payload).

    Args:
        ctx: construct Container with message fields

    Returns:
        Computed checksum byte (0-255)
    """
    xor_val = xor_bytes(ctx.payload)
    return (~xor_val) & 0xFF


# Client to Server message structure
C2SMessage: Construct = Struct(
    "magic" / Const(b"\x5a\xa5"),
    "unknown" / Bytes(2),  # Always 0x00 0x00 so far
    "length" / Int16ul,  # Length of method + payload
    "method" / Int8ul,
    "payload" / Bytes(lambda this: this.length - 1),
    "checksum_byte" / Rebuild(Int8ul, c2s_checksum_compute),
    Check(lambda ctx: ctx.checksum_byte == c2s_checksum_compute(ctx)),
)


# Server to Client message structure
S2CMessage: Construct = Struct(
    "magic" / Const(b"\x5a\xa5"),
    "method" / Int8ul,
    "unknown" / Int8ul,  # Always 0x00 so far
    "length" / Int16ul,  # Length of payload only
    "payload" / Bytes(lambda this: this.length),
    "checksum_byte" / Rebuild(Int8ul, s2c_checksum_compute),
    Check(lambda ctx: ctx.checksum_byte == s2c_checksum_compute(ctx)),
)


Direction = Literal["c2s", "s2c"]


def parse_message(data: bytes) -> tuple[Direction, Container]:
    """Parse a message, automatically detecting direction based on structure.

    Args:
        data: Raw message bytes to parse

    Returns:
        Tuple of (direction, parsed_container) where direction is 'c2s' or 's2c'

    Raises:
        ValueError: If message is invalid or cannot be parsed
    """
    if len(data) < 7:
        raise ValueError(f"Message too short: {len(data)} bytes")

    # Check magic
    if data[0:2] != b"\x5a\xa5":
        raise ValueError(f"Invalid magic: {data[0:2].hex()}")

    # Heuristic: C->S has 0x00 0x00 at offset 2-3, S->C has a method byte at offset 2
    # and 0x00 at offset 3
    if data[2:4] == b"\x00\x00":
        # Likely C->S
        return ("c2s", C2SMessage.parse(data))
    else:
        # Likely S->C (method byte at offset 2, 0x00 at offset 3)
        return ("s2c", S2CMessage.parse(data))


def build_c2s_message(method: int, payload: bytes = b"", unknown: bytes = b"\x00\x00") -> bytes:
    """Build a C->S message with correct checksum.

    Args:
        method: Method byte (0x00-0xff)
        payload: Optional payload bytes
        unknown: Unknown 2-byte field (default: 0x00 0x00)

    Returns:
        Complete serialized message ready to send

    Raises:
        ValueError: If payload is too large
    """
    if len(payload) > MAX_C2S_PAYLOAD:
        raise ValueError(f"Payload too large: {len(payload)} bytes (max {MAX_C2S_PAYLOAD})")

    msg = Container(
        unknown=unknown,
        length=len(payload) + 1,  # method + payload
        method=method,
        payload=payload,
    )
    return cast(bytes, C2SMessage.build(msg))


def build_s2c_message(method: int, payload: bytes = b"", unknown: int = 0x00) -> bytes:
    """Build a S->C message with correct checksum.

    Args:
        method: Method byte (0x00-0xff)
        payload: Optional payload bytes
        unknown: Unknown byte field (default: 0x00)

    Returns:
        Complete serialized message ready to send

    Raises:
        ValueError: If payload is too large
    """
    if len(payload) > MAX_S2C_PAYLOAD:
        raise ValueError(f"Payload too large: {len(payload)} bytes (max {MAX_S2C_PAYLOAD})")

    msg = Container(
        method=method,
        unknown=unknown,
        length=len(payload),
        payload=payload,
    )
    return cast(bytes, S2CMessage.build(msg))


def parse_message_stream(
    data: bytes, direction_hint: Direction | None = None
) -> Generator[tuple[int, int, Direction, Container], None, None]:
    """Parse multiple messages from a byte stream.

    Args:
        data: Raw byte stream containing one or more messages
        direction_hint: Optional hint for message direction (currently unused)

    Yields:
        Tuples of (offset, msg_num, direction, parsed_message)
    """
    offset = 0
    msg_count = 0

    while offset < len(data):
        # Find next magic bytes
        if offset + 2 > len(data):
            break

        if data[offset : offset + 2] != b"\x5a\xa5":
            # Skip to next potential magic
            offset += 1
            continue

        try:
            # Try to parse message starting at current offset
            remaining = data[offset:]
            direction, parsed = parse_message(remaining)

            # All messages are 7 bytes + length field
            msg_len = 7 + parsed.length

            yield (offset, msg_count, direction, parsed)
            offset += msg_len
            msg_count += 1

        except Exception:
            # Failed to parse, skip this byte and try next
            offset += 1
            continue
