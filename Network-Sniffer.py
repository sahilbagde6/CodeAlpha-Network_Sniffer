#!/usr/bin/env python3
"""
Flexible sniffer:
- live mode   : sniff live packets using scapy (needs root/admin + scapy)
- pcap mode   : read packets from a pcap file using scapy (works if scapy installed)
- simulate    : read simple text file with preformatted packet lines (no deps) - works anywhere

Usage examples:
# simulate (best for online compilers)
python3 sniffer_flexible.py --mode simulate --file sample_packets.txt

# pcap (if scapy available and you uploaded capture.pcap)
python3 sniffer_flexible.py --mode pcap --file capture.pcap

# live (run locally with sudo)
sudo python3 sniffer_flexible.py --mode live --iface eth0

Format for simulate file (each line):
<timestamp> <src> <dst> <proto> <sport> <dport> <length>
Example:
2025-09-19T14:00:01 192.168.1.2 8.8.8.8 UDP 54321 53 78
"""

import argparse
import time
import sys
from datetime import datetime

def print_record(ts, proto, src, sport, dst, dport, length):
    # normalize timestamp
    try:
        # if ISO-like
        dt = datetime.fromisoformat(ts)
        ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts_str = ts
    print(f"{ts_str} | {proto:4} | {src:21} : {sport:<5} -> {dst:21} : {dport:<5} | len={length}")

def run_simulate(path):
    try:
        with open(path, "r") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 7:
                    print(f"Skipping malformed line {line_no}: {line}")
                    continue
                ts, src, dst, proto, sport, dport, length = parts[:7]
                print_record(ts, proto, src, sport, dst, dport, length)
    except FileNotFoundError:
        print("Simulate file not found:", path)

def run_pcap(path):
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP
    except Exception as e:
        print("scapy not available. To use pcap mode install scapy (`pip install scapy`) and run locally.")
        return
    try:
        pkts = rdpcap(path)
    except Exception as e:
        print("Error reading pcap:", e)
        return
    for pkt in pkts:
        ts = getattr(pkt, "time", time.time())
        ts_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        length = len(pkt)
        src = dst = sport = dport = "-"
        if pkt.haslayer(IP := type('x',(object,),{}) ):  # trick to avoid lint error
            pass
        # IPv4
        if pkt.haslayer("IP"):
            ip = pkt.getlayer("IP")
            src = ip.src; dst = ip.dst
        elif pkt.haslayer("IPv6"):
            ip6 = pkt.getlayer("IPv6")
            src = ip6.src; dst = ip6.dst
        if pkt.haslayer("TCP"):
            sport = pkt["TCP"].sport; dport = pkt["TCP"].dport; proto = "TCP"
        elif pkt.haslayer("UDP"):
            sport = pkt["UDP"].sport; dport = pkt["UDP"].dport; proto = "UDP"
        else:
            proto = pkt.summary().split()[0]
        print(f"{ts_str} | {proto:4} | {src:21} : {sport:<5} -> {dst:21} : {dport:<5} | len={length}")

def run_live(iface, bpf):
    try:
        from scapy.all import sniff, IP, IPv6, TCP, UDP
    except Exception:
        print("scapy not available. To sniff live install scapy (`pip install scapy`) and run with elevated privileges.")
        return
    import signal
    running = {"v": True}
    def stop(sig, frame):
        running["v"] = False
        print("\nStopping live sniff...")
    signal.signal(signal.SIGINT, stop)

    def proto_name(pkt):
        if pkt.haslayer("TCP"):
            return "TCP"
        if pkt.haslayer("UDP"):
            return "UDP"
        if pkt.haslayer("IP") or pkt.haslayer("IPv6"):
            return "IP"
        return pkt.summary().split()[0]

    def process_packet(pkt):
        if not running["v"]:
            return True
        ts_str = datetime.fromtimestamp(getattr(pkt, "time", time.time())).strftime("%Y-%m-%d %H:%M:%S")
        length = len(pkt)
        src = dst = sport = dport = "-"
        if pkt.haslayer("IP"):
            ip = pkt.getlayer("IP"); src = ip.src; dst = ip.dst
        elif pkt.haslayer("IPv6"):
            ip6 = pkt.getlayer("IPv6"); src = ip6.src; dst = ip6.dst
        if pkt.haslayer("TCP"):
            sport = pkt["TCP"].sport; dport = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            sport = pkt["UDP"].sport; dport = pkt["UDP"].dport
        proto = proto_name(pkt)
        print(f"{ts_str} | {proto:4} | {src:21} : {sport:<5} -> {dst:21} : {dport:<5} | len={length}")

    print("Starting live sniff (Ctrl+C to stop). Interface:", iface or "default")
    try:
        sniff(iface=iface, filter=bpf, prn=process_packet, store=0, stop_filter=lambda x: not running["v"])
    except PermissionError:
        print("Permission denied: run with elevated privileges (sudo / admin).")
    except Exception as e:
        print("Live sniff error:", e)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["live","pcap","simulate"], required=True, help="Mode to run")
    parser.add_argument("--file", help="PCAP file path or simulate text file")
    parser.add_argument("--iface", help="Interface for live mode")
    parser.add_argument("--filter", help="BPF filter for live mode (optional)", default=None)
    args = parser.parse_args()

    if args.mode == "simulate":
        if not args.file:
            print("Provide --file sample_packets.txt for simulate mode.")
            sys.exit(1)
        run_simulate(args.file)
    elif args.mode == "pcap":
        if not args.file:
            print("Provide --file capture.pcap for pcap mode.")
            sys.exit(1)
        run_pcap(args.file)
    elif args.mode == "live":
        run_live(args.iface, args.filter)

if __name__ == "__main__":
    main()