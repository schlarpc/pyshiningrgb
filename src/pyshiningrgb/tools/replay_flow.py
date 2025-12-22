#!/usr/bin/env python3
"""Replay a TCP flow from merged capture JSON and compare server responses."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time


def read_until_block(sock, timeout=0.5):
    """Read from socket until it would block (no more data available)"""
    sock.settimeout(timeout)
    data = b""

    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                # Connection closed
                break
            data += chunk
    except socket.timeout:
        # No more data available - this is expected
        pass

    return data


def hexdump_line(data, base_offset, line_offset):
    """Format a single line of hexdump"""
    offset = base_offset + line_offset
    line = f"    {offset:08x}  "
    ascii_line = ""

    for i in range(16):
        if line_offset + i >= len(data):
            line += "   "
            ascii_line += " "
        else:
            byte = data[line_offset + i]
            if byte is None:
                line += "?? "
                ascii_line += "?"
            else:
                line += f"{byte:02x} "
                if 32 <= byte <= 126:
                    ascii_line += chr(byte)
                else:
                    ascii_line += "."

    return f"{line} {ascii_line}"


def compare_responses(expected, actual, offset):
    """Compare expected and actual server responses with hexdump output"""
    if len(expected) != len(actual):
        print(f"  [!] LENGTH MISMATCH: expected {len(expected)} bytes, got {len(actual)}")
        # Still show hexdumps even with length mismatch
        max_len = max(len(expected), len(actual))
        expected = list(expected) + [None] * (max_len - len(expected))
        actual = list(actual) + [None] * (max_len - len(actual))

    # Check for mismatches
    mismatches = 0
    for i, (exp_byte, act_byte) in enumerate(zip(expected, actual)):
        if exp_byte is None:
            continue  # Skip unknown bytes
        if exp_byte != act_byte:
            mismatches += 1

    if mismatches > 0:
        print(f"  [!] DATA MISMATCH: {mismatches} byte(s) differ")
        print()

        # Show expected hexdump
        print("  Expected:")
        for line_start in range(0, len(expected), 16):
            print(hexdump_line(expected, offset, line_start))

        print()
        print("  Actual:")
        for line_start in range(0, len(actual), 16):
            print(hexdump_line(actual, offset, line_start))

        print()
        print("  Differences:")
        for i, (exp_byte, act_byte) in enumerate(zip(expected, actual)):
            if exp_byte is None:
                continue
            if exp_byte != act_byte:
                act_str = f"{act_byte:02x}" if act_byte is not None else "??"
                print(f"    {offset + i:08x}: expected {exp_byte:02x}, got {act_str}")

        return False

    return True


def replay_flow(flow_file, host, port, delay=0.0, timeout=0.5):
    """Replay TCP flow from JSON file"""
    print(f"[*] Loading flow from {flow_file}...")
    with open(flow_file, "r") as f:
        data = json.load(f)

    src_ip = data["flow"]["src_ip"]
    dst_ip = data["flow"]["dst_ip"]
    dst_port = data["flow"]["port"]
    temporal_packets = data["temporal_packets"]
    s2c_data = data["server_to_client"]["data"]

    print(f"[*] Flow: {src_ip} -> {dst_ip}:{dst_port}")
    print(f"[*] Total packets to replay: {len(temporal_packets)}")
    print(f"[*] Read timeout: {timeout}s")
    print(f"[*] Connecting to {host}:{port}...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print("[*] Connected successfully\n")

        stats = {
            "c2s_packets": 0,
            "s2c_packets": 0,
            "c2s_bytes": 0,
            "s2c_bytes": 0,
            "s2c_matches": 0,
            "s2c_mismatches": 0,
        }

        for i, packet in enumerate(temporal_packets):
            direction = packet["direction"]
            offset = packet["offset"]
            payload = bytes(packet["data"])

            if direction == "c2s":
                # Send client data
                print(f">>> C->S offset {offset:08x} ({len(payload)} bytes)")
                sock.send(payload)
                stats["c2s_packets"] += 1
                stats["c2s_bytes"] += len(payload)

            else:  # s2c
                # Receive server response
                print(f"<<< S->C offset {offset:08x} ({len(payload)} bytes expected)")

                try:
                    response = read_until_block(sock, timeout=timeout)
                    stats["s2c_packets"] += 1
                    stats["s2c_bytes"] += len(response)

                    print(f"  Received {len(response)} bytes")

                    # Get expected data from merged stream
                    # Compare against the length of actual response
                    if len(response) > 0:
                        expected = s2c_data[offset : offset + len(response)]
                    else:
                        expected = []

                    # Compare
                    if len(response) == 0:
                        print("  [!] No data received from server")
                        stats["s2c_mismatches"] += 1
                    elif compare_responses(expected, list(response), offset):
                        print("  [✓] Response matches expected")
                        stats["s2c_matches"] += 1
                    else:
                        stats["s2c_mismatches"] += 1

                except Exception as e:
                    print(f"  [!] ERROR: {e}")
                    stats["s2c_mismatches"] += 1

            # Optional delay between packets
            if delay > 0 and i < len(temporal_packets) - 1:
                time.sleep(delay)

            print()

        print(f"\n{'=' * 70}")
        print("Replay Statistics")
        print(f"{'=' * 70}")
        print("Client -> Server:")
        print(f"  Packets sent: {stats['c2s_packets']}")
        print(f"  Bytes sent: {stats['c2s_bytes']}")
        print("\nServer -> Client:")
        print(f"  Packets received: {stats['s2c_packets']}")
        print(f"  Bytes received: {stats['s2c_bytes']}")
        print(f"  Matches: {stats['s2c_matches']}")
        print(f"  Mismatches: {stats['s2c_mismatches']}")

        if stats["s2c_mismatches"] == 0:
            print("\n✓ All server responses matched expected values")
            return 0
        else:
            print(f"\n✗ {stats['s2c_mismatches']} server responses did not match")
            return 1

    finally:
        sock.close()
        print("\n[*] Connection closed")


def main():
    parser = argparse.ArgumentParser(description="Replay TCP flow from merged capture JSON")
    parser.add_argument("flow_file", help="JSON file from merge_captures.py --export")
    parser.add_argument("--host", required=True, help="Target server IP/hostname")
    parser.add_argument("--port", type=int, help="Target port (default: from flow file)")
    parser.add_argument(
        "--delay", type=float, default=0.0, help="Delay between packets in seconds (default: 0)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout when reading server responses in seconds (default: 0.5)",
    )
    args = parser.parse_args()

    # Read port from file if not specified
    if args.port is None:
        with open(args.flow_file, "r") as f:
            data = json.load(f)
            args.port = data["flow"]["port"]
        print(f"[*] Using port {args.port} from flow file")

    try:
        exit_code = replay_flow(args.flow_file, args.host, args.port, args.delay, args.timeout)
        sys.exit(exit_code)
    except Exception as e:
        print(f"\n[!] FATAL ERROR: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        sys.exit(2)


if __name__ == "__main__":
    main()
