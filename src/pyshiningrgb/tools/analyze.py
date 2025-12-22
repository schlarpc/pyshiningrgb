#!/usr/bin/env python3
"""Analyze RPC messages from captured JSON files with semantic parsing."""

from __future__ import annotations

import argparse
import json

from pyshiningrgb.protocol import (
    c2s_checksum_compute,
    parse_message_stream,
    s2c_checksum_compute,
)
from pyshiningrgb.semantic import (
    Method03Submethod,
    get_submethod,
    parse_semantic_payload,
)


def format_semantic_info(method, payload_bytes, verbose=False):
    """
    Format semantic information about a payload.

    Args:
        method: Method byte
        payload_bytes: Raw payload bytes
        verbose: Include extra details

    Returns:
        List of formatted strings
    """
    lines = []
    try:
        semantic = parse_semantic_payload(method, payload_bytes)
        submethod = get_submethod(method, payload_bytes)

        if submethod is not None:
            try:
                submethod_enum = Method03Submethod(submethod)
                lines.append(f"  Submethod: 0x{submethod:02x} ({submethod_enum.name})")
            except ValueError:
                lines.append(f"  Submethod: 0x{submethod:02x}")

        # Method-specific semantic information
        if method == 0x08:
            # Mode selection
            mode = semantic.data.mode
            lines.append(f"  → Mode: {mode}")

        elif method == 0x03 and submethod == 0x01:
            # Library load
            lib = semantic.data
            lib_path = lib.path.decode("utf-8", errors="replace")
            lines.append(f"  → Library: {lib_path}")
            if verbose:
                lines.append(f"  → Path length: {lib.path_length}")
                lines.append(
                    f"  → Unknown bytes: {lib.unknown1:02x} {lib.unknown2:02x} {lib.unknown3.hex()}"
                )

        elif method == 0x03 and submethod == 0x02:
            # Data transfer
            dt = semantic.data
            lines.append(f"  → Write offset: 0x{dt.write_offset:04x}")
            lines.append(
                f"  → Payload length: 0x{dt.payload_length:04x} ({dt.payload_length} bytes)"
            )

            if dt.write_offset == 0:
                # First chunk - show dimensions
                header = dt.data.header
                lines.append(f"  → Dimensions: {header.width} x {header.height} pixels")
                lines.append(f"  → Data size: {len(dt.data.chunk_data)} bytes")
                if verbose:
                    lines.append(f"  → Header unknown: {header.unknown.hex()}")
            else:
                # Subsequent chunk
                lines.append(f"  → Data size: {len(dt.data.chunk_data)} bytes")

        elif method == 0x03 and submethod == 0x03:
            # Transfer complete
            lines.append("  → Transfer complete")

        elif method == 0x06:
            # Unknown method
            unk = semantic.data.unknown_byte
            lines.append(f"  → Unknown byte: 0x{unk:02x}")

        elif method == 0x09:
            # Unknown method
            unk = semantic.data
            lines.append(f"  → Unknown bytes: 0x{unk.unknown1:02x} 0x{unk.unknown2:02x}")

        elif method == 0x0A:
            # Unknown method
            lines.append(f"  → Raw payload: {len(semantic.data.payload_data)} bytes")

    except Exception as e:
        if verbose:
            lines.append(f"  [!] Semantic parse error: {e}")

    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Parse RPC messages from captured JSON file with semantic info"
    )
    parser.add_argument("json_file", help="Path to JSON file containing captured messages")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Show detailed hex dumps and semantic details"
    )
    args = parser.parse_args()

    # Load JSON file
    with open(args.json_file, "r") as f:
        capture = json.load(f)

    print("=" * 80)
    print(f"Analyzing capture: {args.json_file}")
    print("=" * 80)

    if "flow" in capture:
        flow = capture["flow"]
        print(f"\nFlow: {flow.get('src_ip')}:{flow.get('port')} <-> {flow.get('dst_ip')}")

    # Parse Client-to-Server messages
    if "client_to_server" in capture:
        c2s_data = bytes(capture["client_to_server"]["data"])
        print(f"\n\nClient-to-Server Messages ({len(c2s_data)} bytes)")
        print("=" * 80)

        for offset, msg_num, direction, parsed in parse_message_stream(c2s_data, "c2s"):
            print(f"\n[C->S #{msg_num}] @ offset {offset}")
            print(f"  Method:   0x{parsed.method:02x}")
            print(f"  Length:   {parsed.length} (0x{parsed.length:04x})")
            print(f"  Payload:  {len(parsed.payload)} bytes")

            # Show semantic info
            semantic_lines = format_semantic_info(
                parsed.method, parsed.payload, verbose=args.verbose
            )
            for line in semantic_lines:
                print(line)

            # Show payload hex
            if args.verbose or len(parsed.payload) <= 16:
                print(f"  Raw:      {parsed.payload.hex(' ')}")
            else:
                print(f"  Raw:      {parsed.payload[:16].hex(' ')} ... (truncated)")

            expected_checksum = c2s_checksum_compute(parsed)
            print(
                f"  Checksum: 0x{parsed.checksum_byte:02x} (expected: 0x{expected_checksum:02x}) {'✓' if parsed.checksum_byte == expected_checksum else '✗'}"
            )

    # Parse Server-to-Client messages
    if "server_to_client" in capture:
        s2c_data = bytes(capture["server_to_client"]["data"])
        print(f"\n\nServer-to-Client Messages ({len(s2c_data)} bytes)")
        print("=" * 80)

        for offset, msg_num, direction, parsed in parse_message_stream(s2c_data, "s2c"):
            print(f"\n[S->C #{msg_num}] @ offset {offset}")
            print(f"  Method:   0x{parsed.method:02x}")
            print(f"  Length:   {parsed.length} (0x{parsed.length:04x})")
            print(f"  Payload:  {len(parsed.payload)} bytes")

            # Show semantic info for S2C if we add it later
            semantic_lines = format_semantic_info(
                parsed.method, parsed.payload, verbose=args.verbose
            )
            for line in semantic_lines:
                print(line)

            if args.verbose or len(parsed.payload) <= 16:
                print(f"  Raw:      {parsed.payload.hex(' ')}")
            else:
                print(f"  Raw:      {parsed.payload[:16].hex(' ')} ... (truncated)")

            expected_checksum = s2c_checksum_compute(parsed)
            print(
                f"  Checksum: 0x{parsed.checksum_byte:02x} (expected: 0x{expected_checksum:02x}) {'✓' if parsed.checksum_byte == expected_checksum else '✗'}"
            )


if __name__ == "__main__":
    main()
