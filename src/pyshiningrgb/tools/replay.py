#!/usr/bin/env python3
"""Replay RPC messages from captured JSON files."""

from __future__ import annotations

import argparse
import json
import socket
import sys

from pyshiningrgb.protocol import (
    build_c2s_message,
    c2s_checksum_compute,
    parse_message,
    parse_message_stream,
    s2c_checksum_compute,
)
from pyshiningrgb.semantic import (
    Method03Submethod,
    get_submethod,
    parse_semantic_payload,
)


def format_semantic_summary(method, payload_bytes):
    """
    Format a one-line semantic summary of a payload.

    Args:
        method: Method byte
        payload_bytes: Raw payload bytes

    Returns:
        Summary string or None
    """
    try:
        semantic = parse_semantic_payload(method, payload_bytes)
        submethod = get_submethod(method, payload_bytes)

        if method == 0x08:
            return f"Mode: {semantic.data.mode}"
        elif method == 0x03 and submethod == 0x01:
            lib_path = semantic.data.path.decode("utf-8", errors="replace")
            return f"Load library: {lib_path}"
        elif method == 0x03 and submethod == 0x02:
            dt = semantic.data
            if dt.write_offset == 0:
                return f"Data transfer @ 0x{dt.write_offset:04x} ({dt.data.header.width}x{dt.data.header.height})"
            else:
                return f"Data transfer @ 0x{dt.write_offset:04x} ({dt.payload_length} bytes)"
        elif method == 0x03 and submethod == 0x03:
            return "Transfer complete"
        else:
            return None
    except Exception:
        return None


def read_response(sock, timeout=1.0):
    """Read a single RPC response from socket"""
    sock.settimeout(timeout)

    # Read until we have enough for magic + minimum header
    buffer = b""
    try:
        # Read until we get magic bytes
        while len(buffer) < 7:
            chunk = sock.recv(1)
            if not chunk:
                return None
            buffer += chunk

            # Check if we have magic bytes at the start
            if len(buffer) >= 2 and buffer[:2] != b"\x5a\xa5":
                # Not magic, keep looking
                buffer = buffer[1:]

        # We have at least 7 bytes starting with magic
        # Parse to determine actual message length
        # S2C format: magic(2) + method(1) + unknown(1) + length(2) + payload(length) + checksum(1)
        if buffer[0:2] == b"\x5a\xa5":
            # Extract length field (bytes 4-5 for S2C)
            payload_len = buffer[4] | (buffer[5] << 8)
            total_len = 7 + payload_len

            # Read remaining bytes
            while len(buffer) < total_len:
                needed = total_len - len(buffer)
                chunk = sock.recv(needed)
                if not chunk:
                    return None
                buffer += chunk

            return buffer

    except socket.timeout:
        if len(buffer) > 0:
            return buffer
        return None

    return None


def replay_messages(json_file, host, port, timeout=1.0):
    """
    Replay C->S messages from JSON file:
    1. Deserialize C->S messages
    2. Round-trip through construct (parse + rebuild)
    3. Send to server
    4. Read and parse S->C response
    5. Print parsed response with semantic info
    """
    print(f"[*] Loading messages from {json_file}...")
    with open(json_file, "r") as f:
        capture = json.load(f)

    if "client_to_server" not in capture:
        print("[!] No client_to_server data in JSON file")
        return 1

    c2s_data = bytes(capture["client_to_server"]["data"])

    # Parse all C->S messages first
    c2s_messages = list(parse_message_stream(c2s_data, "c2s"))

    print(f"[*] Found {len(c2s_messages)} C->S messages")
    print(f"[*] Connecting to {host}:{port}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print("[*] Connected successfully\n")
        print("=" * 80)

        for offset, msg_num, direction, parsed in c2s_messages:
            # Get semantic summary
            summary = format_semantic_summary(parsed.method, parsed.payload)
            submethod = get_submethod(parsed.method, parsed.payload)

            # Round-trip through construct
            print(f"\n[C->S #{msg_num}]")
            if summary:
                print(f"  {summary}")
            print(f"  Original offset: {offset}")
            print(f"  Method: 0x{parsed.method:02x}")
            if submethod is not None:
                try:
                    submethod_enum = Method03Submethod(submethod)
                    print(f"  Submethod: 0x{submethod:02x} ({submethod_enum.name})")
                except ValueError:
                    print(f"  Submethod: 0x{submethod:02x}")

            print(f"  Payload: {len(parsed.payload)} bytes")
            if len(parsed.payload) <= 32:
                print(f"           {parsed.payload.hex(' ')}")
            else:
                print(f"           {parsed.payload[:32].hex(' ')} ... (truncated)")

            # Rebuild message using construct
            rebuilt = build_c2s_message(parsed.method, parsed.payload, parsed.unknown)

            # Verify round-trip
            direction_check, parsed_check = parse_message(rebuilt)
            checksum_ok = c2s_checksum_compute(parsed_check) == parsed_check.checksum_byte
            print(f"  Round-trip: {'✓' if checksum_ok else '✗'}")

            # Send to server
            print(f"  Sending {len(rebuilt)} bytes to server...")
            sock.send(rebuilt)

            # Read response
            print("  Waiting for response...")
            response = read_response(sock, timeout=timeout)

            if response is None:
                print("  [!] No response received (timeout)")
                continue

            print(f"  Received {len(response)} bytes")

            # Parse response
            try:
                s2c_direction, s2c_parsed = parse_message(response)

                # Get semantic summary for response
                s2c_summary = format_semantic_summary(s2c_parsed.method, s2c_parsed.payload)

                print("\n  [S->C Response]")
                if s2c_summary:
                    print(f"    {s2c_summary}")
                print(f"    Direction: {s2c_direction}")
                print(f"    Method: 0x{s2c_parsed.method:02x}")
                print(f"    Length: {s2c_parsed.length} (0x{s2c_parsed.length:04x})")
                print(f"    Payload: {len(s2c_parsed.payload)} bytes")
                if len(s2c_parsed.payload) <= 32:
                    print(f"             {s2c_parsed.payload.hex(' ')}")
                else:
                    print(f"             {s2c_parsed.payload[:32].hex(' ')} ... (truncated)")

                expected_checksum = s2c_checksum_compute(s2c_parsed)
                checksum_match = s2c_parsed.checksum_byte == expected_checksum
                print(
                    f"    Checksum: 0x{s2c_parsed.checksum_byte:02x} (expected: 0x{expected_checksum:02x}) {'✓' if checksum_match else '✗'}"
                )

            except Exception as e:
                print(f"  [!] Failed to parse response: {e}")
                print(f"  Raw response: {response.hex(' ')}")

            print("=" * 80)

        return 0

    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        import traceback

        traceback.print_exc()
        return 1

    finally:
        sock.close()
        print("\n[*] Connection closed")


def main():
    parser = argparse.ArgumentParser(
        description="Replay RPC messages from JSON capture with semantic parsing"
    )
    parser.add_argument("json_file", help="JSON file containing captured messages")
    parser.add_argument("--host", required=True, help="Target server IP/hostname")
    parser.add_argument("--port", type=int, help="Target port (default: from flow file)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout when reading server responses in seconds (default: 1.0)",
    )
    args = parser.parse_args()

    # Read port from file if not specified
    if args.port is None:
        with open(args.json_file, "r") as f:
            data = json.load(f)
            if "flow" in data:
                args.port = data["flow"]["port"]
                print(f"[*] Using port {args.port} from flow file")
            else:
                print("[!] No port specified and no flow info in JSON file")
                sys.exit(1)

    try:
        exit_code = replay_messages(args.json_file, args.host, args.port, args.timeout)
        sys.exit(exit_code)
    except Exception as e:
        print(f"\n[!] FATAL ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
