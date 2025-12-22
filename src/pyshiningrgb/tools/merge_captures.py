#!/usr/bin/env python3
"""Merge multiple pcap captures of the same TCP flow, showing consensus bytes."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from scapy.all import rdpcap


def reassemble_stream(packets):
    """Reassemble TCP stream from packets, handling sequence numbers

    Returns: (stream, expected_length, initial_seq, data_packets)
    - stream: dict mapping {offset: byte_value} where offset is 0-based from initial seq
    - expected_length: total expected bytes
    - initial_seq: initial sequence number
    - data_packets: list of (timestamp, offset, payload_bytes) for temporal ordering
    """
    if not packets:
        return {}, None, None, []

    # Find initial sequence (from SYN or first packet)
    initial_seq = packets[0]["TCP"].seq
    if packets[0]["TCP"].flags & 0x02:  # SYN
        initial_seq += 1  # SYN consumes one seq number but no data

    stream = {}
    data_packets = []

    for p in packets:
        seq = p["TCP"].seq
        payload = bytes(p["TCP"].payload) if p["TCP"].payload else b""

        if not payload:
            continue

        # Calculate offset from initial sequence
        offset = seq - initial_seq

        # Add bytes to stream
        for i, byte in enumerate(payload):
            stream[offset + i] = byte

        # Store packet info with timestamp for temporal ordering
        timestamp = float(p.time)
        data_packets.append((timestamp, offset, payload))

    # Calculate final sequence
    final_seq = packets[-1]["TCP"].seq + len(packets[-1]["TCP"].payload)
    expected_length = final_seq - initial_seq

    return stream, expected_length, initial_seq, data_packets


def extract_flow(pcap_file, src_ip, dst_ip, port):
    """Extract TCP flow from pcap file"""
    try:
        pcap = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Error reading {pcap_file}: {e}", file=sys.stderr)
        return None, None

    c2s = []
    s2c = []

    for p in pcap:
        if p.haslayer("TCP") and p.haslayer("IP"):
            if p["IP"].src == src_ip and p["IP"].dst == dst_ip and p["TCP"].dport == port:
                c2s.append(p)
            elif p["IP"].src == dst_ip and p["IP"].dst == src_ip and p["TCP"].sport == port:
                s2c.append(p)

    return c2s, s2c


def merge_streams(streams):
    """Merge multiple stream captures into consensus view

    Args:
        streams: list of dicts {offset: byte_value}

    Returns:
        merged: dict {offset: byte_value or None}
        conflicts: dict {offset: [list of different values]}
    """
    if not streams:
        return {}, {}

    # Find all offsets across all streams
    all_offsets = set()
    for stream in streams:
        all_offsets.update(stream.keys())

    merged: dict[int, int | None] = {}
    conflicts: dict[int, list[int | None]] = {}

    for offset in sorted(all_offsets):
        values = []
        for stream in streams:
            if offset in stream:
                values.append(stream[offset])
            else:
                values.append(None)

        # Check if all non-None values agree
        non_none = [v for v in values if v is not None]

        if not non_none:
            # All streams missing this byte
            merged[offset] = None
        elif len(set(non_none)) == 1:
            # All present values agree
            merged[offset] = non_none[0]
        else:
            # Conflict: different values present
            merged[offset] = None  # Mark as conflict
            conflicts[offset] = values

    return merged, conflicts


def print_interleaved_hexdump(
    c2s_data,
    s2c_data,
    c2s_merged,
    s2c_merged,
    c2s_conflicts,
    s2c_conflicts,
    c2s_length,
    s2c_length,
    src_ip,
    dst_ip,
    port,
):
    """Print temporally-ordered interleaved hexdump of both directions"""
    print(f"\n{'=' * 70}")
    print(f"Temporal Flow: {src_ip} <-> {dst_ip}:{port}")
    print(f"{'=' * 70}\n")

    # Collect all data packets from all captures with direction
    all_packets = []

    # Add C->S packets
    for capture_data in c2s_data:
        for timestamp, offset, payload in capture_data:
            all_packets.append((timestamp, "C->S", offset, payload))

    # Add S->C packets
    for capture_data in s2c_data:
        for timestamp, offset, payload in capture_data:
            all_packets.append((timestamp, "S->C", offset, payload))

    if not all_packets:
        print("  (no data)")
        return

    # Sort by timestamp
    all_packets.sort(key=lambda x: x[0])

    # Print each packet temporally
    for timestamp, direction, offset, payload in all_packets:
        # Choose the right merged stream and conflicts based on direction
        if direction == "C->S":
            merged = c2s_merged
            conflicts = c2s_conflicts
            dir_marker = ">>>"
        else:
            merged = s2c_merged
            conflicts = s2c_conflicts
            dir_marker = "<<<"

        print(f"{dir_marker} {direction} offset {offset:08x} ({len(payload)} bytes)")

        # Print hexdump of this packet's payload
        for line_start in range(0, len(payload), 16):
            line_offset = offset + line_start
            line = f"    {line_offset:08x}  "
            ascii_line = ""
            conflict_notes = []

            for i in range(16):
                pos = line_start + i
                abs_pos = offset + pos

                if pos >= len(payload):
                    line += "   "
                    ascii_line += " "
                    continue

                actual_byte = payload[pos]

                # Check if this byte matches consensus
                if abs_pos in conflicts:
                    line += "?? "
                    ascii_line += "?"
                    values = conflicts[abs_pos]
                    present = [f"{v:02x}" if v is not None else "XX" for v in values]
                    conflict_notes.append(f"      ; offset {abs_pos:08x}: {' '.join(present)}")
                elif abs_pos not in merged or merged[abs_pos] is None:
                    # Missing in consensus (but present here)
                    line += f"\033[33m{actual_byte:02x}\033[0m "  # Yellow for partial
                    if 32 <= actual_byte <= 126:
                        ascii_line += chr(actual_byte)
                    else:
                        ascii_line += "."
                elif merged[abs_pos] == actual_byte:
                    # Matches consensus
                    line += f"{actual_byte:02x} "
                    if 32 <= actual_byte <= 126:
                        ascii_line += chr(actual_byte)
                    else:
                        ascii_line += "."
                else:
                    # Shouldn't happen
                    line += f"{actual_byte:02x} "
                    if 32 <= actual_byte <= 126:
                        ascii_line += chr(actual_byte)
                    else:
                        ascii_line += "."

            print(f"{line}  {ascii_line}")
            for note in conflict_notes:
                print(note)

        print()

    # Summary for each direction
    print(f"\n{'=' * 70}")
    print("Summary")
    print(f"{'=' * 70}\n")

    c2s_confirmed = sum(1 for v in c2s_merged.values() if v is not None)
    c2s_missing = sum(
        1 for pos in range(c2s_length) if pos not in c2s_merged or c2s_merged[pos] is None
    )
    c2s_conflicted = len(c2s_conflicts)

    s2c_confirmed = sum(1 for v in s2c_merged.values() if v is not None)
    s2c_missing = sum(
        1 for pos in range(s2c_length) if pos not in s2c_merged or s2c_merged[pos] is None
    )
    s2c_conflicted = len(s2c_conflicts)

    print("Client -> Server:")
    print(
        f"  {c2s_length} bytes total, {c2s_confirmed} confirmed, {c2s_missing} missing, {c2s_conflicted} conflicts"
    )
    print("\nServer -> Client:")
    print(
        f"  {s2c_length} bytes total, {s2c_confirmed} confirmed, {s2c_missing} missing, {s2c_conflicted} conflicts"
    )


def main():
    parser = argparse.ArgumentParser(
        description="Merge multiple pcap captures of the same TCP flow"
    )
    parser.add_argument("pcaps", nargs="+", help="Pcap files to merge")
    parser.add_argument("--src-ip", default="192.168.4.3", help="Client IP")
    parser.add_argument("--dst-ip", default="192.168.4.1", help="Server IP")
    parser.add_argument("--port", type=int, default=8810, help="TCP port")
    parser.add_argument("--export", help="Export merged data to machine-readable JSON file")
    args = parser.parse_args()

    print(f"[*] Merging {len(args.pcaps)} captures...")
    print(f"[*] Flow: {args.src_ip} <-> {args.dst_ip}:{args.port}\n")

    # First pass: extract all flows and determine dominant length
    all_captures = []

    for pcap_file in args.pcaps:
        print(f"[*] Processing {pcap_file}...")
        c2s, s2c = extract_flow(pcap_file, args.src_ip, args.dst_ip, args.port)

        if c2s is None:
            continue

        # Reassemble streams
        c2s_stream, c2s_len, _, c2s_data = reassemble_stream(c2s)
        s2c_stream, s2c_len, _, s2c_data = reassemble_stream(s2c)

        all_captures.append(
            {
                "file": pcap_file,
                "c2s_stream": c2s_stream,
                "s2c_stream": s2c_stream,
                "c2s_data": c2s_data,
                "s2c_data": s2c_data,
                "c2s_len": c2s_len or 0,
                "s2c_len": s2c_len or 0,
            }
        )

        print(f"    Client->Server: {len(c2s_stream)} bytes captured, expected {c2s_len or 0}")
        print(f"    Server->Client: {len(s2c_stream)} bytes captured, expected {s2c_len or 0}")

    if not all_captures:
        print("[!] No flows found in any pcap")
        sys.exit(1)

    # Find dominant conversation length
    print("\n[*] Finding dominant conversation length...")

    c2s_lengths = [cap["c2s_len"] for cap in all_captures if cap["c2s_len"] > 0]
    s2c_lengths = [cap["s2c_len"] for cap in all_captures if cap["s2c_len"] > 0]

    if c2s_lengths:
        c2s_dominant = Counter(c2s_lengths).most_common(1)[0][0]
        print(
            f"    Client->Server: {c2s_dominant} bytes (appears {Counter(c2s_lengths)[c2s_dominant]} times)"
        )
    else:
        c2s_dominant = 0

    if s2c_lengths:
        s2c_dominant = Counter(s2c_lengths).most_common(1)[0][0]
        print(
            f"    Server->Client: {s2c_dominant} bytes (appears {Counter(s2c_lengths)[s2c_dominant]} times)"
        )
    else:
        s2c_dominant = 0

    # Filter to only captures matching dominant length
    print("\n[*] Filtering captures to match dominant length...")
    matching_captures = []
    for cap in all_captures:
        c2s_match = cap["c2s_len"] == c2s_dominant or c2s_dominant == 0
        s2c_match = cap["s2c_len"] == s2c_dominant or s2c_dominant == 0

        if c2s_match and s2c_match:
            matching_captures.append(cap)
            print(f"    ✓ {cap['file']} - matches")
        else:
            print(
                f"    ✗ {cap['file']} - EXCLUDED (C->S: {cap['c2s_len']}, S->C: {cap['s2c_len']})"
            )

    if not matching_captures:
        print("[!] No captures match the dominant length")
        sys.exit(1)

    print(f"\n[*] Using {len(matching_captures)}/{len(all_captures)} captures for merge")

    # Extract streams and data from matching captures only
    c2s_streams = [cap["c2s_stream"] for cap in matching_captures]
    s2c_streams = [cap["s2c_stream"] for cap in matching_captures]
    c2s_data_list = [cap["c2s_data"] for cap in matching_captures]
    s2c_data_list = [cap["s2c_data"] for cap in matching_captures]

    # Merge streams
    print("\n[*] Merging streams...")
    c2s_merged, c2s_conflicts = merge_streams(c2s_streams)
    s2c_merged, s2c_conflicts = merge_streams(s2c_streams)

    # Print results (interleaved temporal view)
    print_interleaved_hexdump(
        c2s_data_list,
        s2c_data_list,
        c2s_merged,
        s2c_merged,
        c2s_conflicts,
        s2c_conflicts,
        c2s_dominant,
        s2c_dominant,
        args.src_ip,
        args.dst_ip,
        args.port,
    )

    # Export to machine-readable format if requested
    if args.export:
        print(f"\n[*] Exporting to {args.export}...")

        # Build temporal packet list
        temporal_packets = []
        for capture_data in c2s_data_list:
            for timestamp, offset, payload in capture_data:
                temporal_packets.append(
                    {
                        "timestamp": timestamp,
                        "direction": "c2s",
                        "offset": offset,
                        "data": list(payload),  # Convert bytes to list of ints
                    }
                )
        for capture_data in s2c_data_list:
            for timestamp, offset, payload in capture_data:
                temporal_packets.append(
                    {
                        "timestamp": timestamp,
                        "direction": "s2c",
                        "offset": offset,
                        "data": list(payload),
                    }
                )
        temporal_packets.sort(key=lambda x: x["timestamp"])

        # Build merged data (convert to list for JSON)
        c2s_data = []
        for i in range(c2s_dominant):
            if i in c2s_merged and c2s_merged[i] is not None:
                c2s_data.append(c2s_merged[i])
            else:
                c2s_data.append(None)

        s2c_data = []
        for i in range(s2c_dominant):
            if i in s2c_merged and s2c_merged[i] is not None:
                s2c_data.append(s2c_merged[i])
            else:
                s2c_data.append(None)

        export_data = {
            "flow": {"src_ip": args.src_ip, "dst_ip": args.dst_ip, "port": args.port},
            "client_to_server": {
                "length": c2s_dominant,
                "data": c2s_data,
                "conflicts": {str(k): v for k, v in c2s_conflicts.items()},
            },
            "server_to_client": {
                "length": s2c_dominant,
                "data": s2c_data,
                "conflicts": {str(k): v for k, v in s2c_conflicts.items()},
            },
            "temporal_packets": temporal_packets,
        }

        with open(args.export, "w") as f:
            json.dump(export_data, f, indent=2)

        print("[*] Exported successfully")


if __name__ == "__main__":
    main()
