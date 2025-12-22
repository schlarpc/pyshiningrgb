#!/usr/bin/env python3
"""Check if a pcapng file contains a complete TCP flow."""

from __future__ import annotations

import argparse
import sys

from scapy.all import rdpcap


def check_tcp_stream(packets, direction_name):
    """Check a one-directional TCP stream for gaps and retransmissions

    Returns: (is_complete, issues, expected_length, initial_seq, final_seq)
    """
    if not packets:
        return True, [], 0, None, None

    issues = []
    expected_seq = None
    initial_seq = None
    final_seq = None

    for i, p in enumerate(packets):
        seq = p["TCP"].seq
        payload_len = len(p["TCP"].payload) if p["TCP"].payload else 0
        flags = p["TCP"].flags

        # Track initial sequence number (from SYN or first packet)
        if initial_seq is None:
            initial_seq = seq

        if expected_seq is not None and seq != expected_seq:
            if seq > expected_seq:
                gap_size = seq - expected_seq
                issues.append(
                    f"  GAP: Missing {gap_size} bytes (expected seq {expected_seq}, got {seq})"
                )
            elif seq < expected_seq:
                issues.append(f"  RETRANSMISSION: seq {seq}, expected {expected_seq}")

        # Calculate sequence number consumed
        seq_consumed = payload_len
        if flags & 0x02:  # SYN
            seq_consumed += 1
        if flags & 0x01:  # FIN
            seq_consumed += 1

        # Only advance expected sequence if this isn't a retransmission
        if i == 0 or seq >= expected_seq:
            expected_seq = seq + seq_consumed
            final_seq = expected_seq

    # Expected length is the difference between final and initial sequence
    # Subtract 1 for SYN if present (it consumes a seq number but isn't data)
    expected_length = final_seq - initial_seq if final_seq and initial_seq else 0
    if packets and packets[0]["TCP"].flags & 0x02:  # SYN
        expected_length -= 1
    # Subtract 1 for FIN if present
    if packets and packets[-1]["TCP"].flags & 0x01:  # FIN
        expected_length -= 1

    return len(issues) == 0, issues, expected_length, initial_seq, final_seq


def main():
    parser = argparse.ArgumentParser(description="Check pcapng for complete port 8810 TCP flow")
    parser.add_argument("pcapng", help="Path to pcapng file")
    parser.add_argument("--src-ip", default="192.168.4.3", help="Client IP (default: 192.168.4.3)")
    parser.add_argument("--dst-ip", default="192.168.4.1", help="Server IP (default: 192.168.4.1)")
    parser.add_argument("--port", type=int, default=8810, help="TCP port (default: 8810)")
    args = parser.parse_args()

    print(f"[*] Reading {args.pcapng}...")
    try:
        pcap = rdpcap(args.pcapng)
    except Exception as e:
        print(f"[!] Error reading pcap: {e}")
        sys.exit(1)

    print(f"[*] Total packets in capture: {len(pcap)}")

    # Filter for the specific TCP flow
    flow_packets = []
    bssids = set()

    for p in pcap:
        # Extract BSSID if available
        if p.haslayer("Dot11"):
            if hasattr(p["Dot11"], "addr1"):
                bssids.add(p["Dot11"].addr1)
            if hasattr(p["Dot11"], "addr2"):
                bssids.add(p["Dot11"].addr2)
            if hasattr(p["Dot11"], "addr3"):
                bssids.add(p["Dot11"].addr3)

        # Check for our TCP flow
        if p.haslayer("TCP") and p.haslayer("IP"):
            src = p["IP"].src
            dst = p["IP"].dst
            sport = p["TCP"].sport
            dport = p["TCP"].dport

            # Match flow in either direction
            if (src == args.src_ip and dst == args.dst_ip and dport == args.port) or (
                src == args.dst_ip and dst == args.src_ip and sport == args.port
            ):
                flow_packets.append(p)

    if bssids:
        bssids = {b for b in bssids if b is not None}
        if bssids:
            print(f"[*] BSSIDs seen in capture: {', '.join(sorted(bssids))}")

    print(f"\n[*] Flow: {args.src_ip} <-> {args.dst_ip}:{args.port}")
    print(f"[*] Packets found: {len(flow_packets)}")

    if not flow_packets:
        print("[!] FAIL: No packets found for this flow")
        sys.exit(1)

    # Separate by direction
    client_to_server = []
    server_to_client = []

    for p in flow_packets:
        if p["TCP"].dport == args.port:
            client_to_server.append(p)
        else:
            server_to_client.append(p)

    print(f"    Client -> Server: {len(client_to_server)} packets")
    print(f"    Server -> Client: {len(server_to_client)} packets")

    # Calculate data transferred
    client_data = sum(len(p["TCP"].payload) for p in client_to_server if p["TCP"].payload)
    server_data = sum(len(p["TCP"].payload) for p in server_to_client if p["TCP"].payload)

    # Check sequence numbers
    print("\n[*] Checking sequence numbers...")

    c2s_ok, c2s_issues, c2s_expected, c2s_init, c2s_final = check_tcp_stream(
        client_to_server, "Client -> Server"
    )
    s2c_ok, s2c_issues, s2c_expected, s2c_init, s2c_final = check_tcp_stream(
        server_to_client, "Server -> Client"
    )

    print("\n[*] Expected conversation length (based on sequence numbers):")
    print(f"    Client -> Server: {c2s_expected:,} bytes (seq {c2s_init} -> {c2s_final})")
    print(f"    Server -> Client: {s2c_expected:,} bytes (seq {s2c_init} -> {s2c_final})")

    print("\n[*] Actual data captured in TCP payloads:")
    print(f"    Client -> Server: {client_data:,} bytes")
    print(f"    Server -> Client: {server_data:,} bytes")

    print(f"\nClient -> Server ({args.src_ip} -> {args.dst_ip}:{args.port}):")
    if c2s_ok:
        print("  ✓ No gaps detected")
    else:
        print(f"  ✗ {len(c2s_issues)} issue(s) found:")
        for issue in c2s_issues:
            print(issue)

    print(f"\nServer -> Client ({args.dst_ip}:{args.port} -> {args.src_ip}):")
    if s2c_ok:
        print("  ✓ No gaps detected")
    else:
        print(f"  ✗ {len(s2c_issues)} issue(s) found:")
        for issue in s2c_issues:
            print(issue)

    # Overall result
    print("\n" + "=" * 60)
    if c2s_ok and s2c_ok:
        print("✓ PASS: TCP stream appears complete")
        sys.exit(0)
    else:
        print("✗ FAIL: TCP stream has gaps or issues")
        sys.exit(1)


if __name__ == "__main__":
    main()
