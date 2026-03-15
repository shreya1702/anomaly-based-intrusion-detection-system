#!/usr/bin/env python3
"""
live_website_traffic_heuristic.py  (fixed)

Improvements:
 - Robust port extraction (TCP/UDP)
 - Only check for HTTP GET on port 80 (not HTTPS)
 - --duration to auto-stop for testing
 - Safer sniffer stop and clearer debug prints
 - Faster default test interval for quicker feedback
"""

import os
import time
import socket
import threading
import argparse
from datetime import datetime
from collections import defaultdict, deque
import pandas as pd
import numpy as np
from scapy.all import AsyncSniffer, IP, TCP, ICMP, UDP, Raw, conf, show_interfaces

# ---------------- SETTINGS ----------------
OUTPUT_FILE = "predicted_heuristic_traffic.csv"
FLOW_IDLE_TIMEOUT = 1.0
BATCH_PREDICT_INTERVAL = 1.0   # faster for testing
WEB_PORTS = [80, 443]

# Detection thresholds (tune if needed)
THRESHOLDS = {
    "HTTP_COUNT": 60,
    "SYN_COUNT": 50,
    "ICMP_COUNT": 40,
    "PPS_DOS": 300,
    "BYTESPS_DOS": 200000,
    "PORTS_PER_SRC": 30,
    "DESTS_PER_SRC": 20,
}

flows = {}
flows_lock = threading.Lock()
src_stats = defaultdict(lambda: {"ports": set(), "dsts": set()})

SITE_IPS = set()
WEBSITE_ONLY = False

# ---------------- UTILITIES ----------------
def get_flow_key(pkt):
    """Return a tuple (src, dst, sport, dport) or None if no IP."""
    if IP not in pkt:
        return None
    ip = pkt[IP]
    src, dst = ip.src, ip.dst

    sport = 0
    dport = 0
    if pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport or 0)
        dport = int(pkt[TCP].dport or 0)
    elif pkt.haslayer(UDP):
        sport = int(pkt[UDP].sport or 0)
        dport = int(pkt[UDP].dport or 0)
    else:
        # Non TCP/UDP flows (e.g., ICMP) — keep ports 0
        sport = 0
        dport = 0

    return (src, dst, sport, dport)

def init_flow(ts):
    return {
        "first_ts": ts, "last_ts": ts,
        "pkt_count": 0, "bytes_total": 0,
        "pkt_sizes": [], "iats": [],
        "last_pkt_ts": None,
        "http_get_count": 0, "syn_count": 0, "icmp_count": 0
    }

def update_flow(flow, pkt, ts, sport, dport):
    flow["pkt_count"] += 1
    size = len(pkt)
    flow["bytes_total"] += size
    flow["pkt_sizes"].append(size)
    if flow["last_pkt_ts"]:
        flow["iats"].append(ts - flow["last_pkt_ts"])
    flow["last_pkt_ts"] = ts
    flow["last_ts"] = ts

    # Feature detection
    if pkt.haslayer(TCP):
        # SYN flag detection: check flag value instead of string matching
        try:
            flags = int(pkt[TCP].flags)
            # SYN is 0x02
            if pkt[TCP].flags & 0x02:
                flow["syn_count"] += 1
        except Exception:
            # fallback: string check (less ideal)
            if 'S' in str(pkt[TCP].flags):
                flow["syn_count"] += 1

        # Only attempt to read HTTP GET for plain HTTP (port 80)
        if (dport == 80 or sport == 80) and pkt.haslayer(Raw):
            try:
                raw = bytes(pkt[Raw].load)
                # Basic GET detection (handles normal HTTP)
                if raw.startswith(b"GET ") or b"\r\nGET " in raw:
                    flow["http_get_count"] += 1
            except Exception:
                pass

    if pkt.haslayer(ICMP):
        flow["icmp_count"] += 1

def compute_features(flow):
    dur = max(0.0001, flow["last_ts"] - flow["first_ts"])
    pkt_sizes = np.array(flow["pkt_sizes"]) if flow["pkt_sizes"] else np.array([0])
    iats = np.array(flow["iats"]) if flow["iats"] else np.array([0])
    return {
        "Flow Duration": dur,
        "Packets/s": float(flow["pkt_count"]) / dur,
        "Bytes/s": float(flow["bytes_total"]) / dur,
        "Pkt Len Mean": float(pkt_sizes.mean()),
        "Pkt Len Std": float(pkt_sizes.std(ddof=0)),
        "HTTP Count": flow["http_get_count"],
        "SYN Count": flow["syn_count"],
        "ICMP Count": flow["icmp_count"]
    }

# ---------------- HEURISTIC ENGINE ----------------
def evaluate_heuristics(key, f):
    src, dst, sport, dport = key
    http = f["HTTP Count"]
    syn = f["SYN Count"]
    icmp = f["ICMP Count"]
    pps = f["Packets/s"]
    bps = f["Bytes/s"]

    # Website-only filtering
    if WEBSITE_ONLY and dport not in WEB_PORTS and sport not in WEB_PORTS:
        return None
    if SITE_IPS and dst not in SITE_IPS and src not in SITE_IPS:
        return None

    if icmp >= THRESHOLDS["ICMP_COUNT"]:
        return "ICMP-Flood"
    if syn >= THRESHOLDS["SYN_COUNT"]:
        return "SYN-Flood/Brute"
    if http >= THRESHOLDS["HTTP_COUNT"]:
        return "HTTP-Flood/DDoS"
    if pps >= THRESHOLDS["PPS_DOS"] or bps >= THRESHOLDS["BYTESPS_DOS"]:
        return "DoS Spike"

    # Port scan / multi-target (based on tracked src_stats)
    ports = len(src_stats[src]["ports"])
    dsts = len(src_stats[src]["dsts"])
    if ports >= THRESHOLDS["PORTS_PER_SRC"]:
        return "Port-Scan"
    if dsts >= THRESHOLDS["DESTS_PER_SRC"]:
        return "Multi-Target-Scan"
    return None

# ---------------- CAPTURE HANDLER ----------------
def handle_packet(pkt):
    if IP not in pkt:
        return
    ts = time.time()
    key = get_flow_key(pkt)
    if not key:
        return
    src, dst, sport, dport = key

    # website filter
    if WEBSITE_ONLY and dport not in WEB_PORTS and sport not in WEB_PORTS:
        return
    if SITE_IPS and dst not in SITE_IPS and src not in SITE_IPS:
        return

    with flows_lock:
        if key not in flows:
            flows[key] = init_flow(ts)
        update_flow(flows[key], pkt, ts, sport, dport)

    # Update per-source stats (used for scans)
    src_stats[src]["ports"].add(dport)
    src_stats[src]["dsts"].add(dst)

# ---------------- ANALYSIS LOOP ----------------
def analyzer_loop(stop_event):
    while not stop_event.is_set():
        time.sleep(BATCH_PREDICT_INTERVAL)
        now = time.time()
        finished = []
        with flows_lock:
            for k, f in list(flows.items()):
                # flows with no packets yet will be ignored
                if f["last_pkt_ts"] and now - f["last_pkt_ts"] > FLOW_IDLE_TIMEOUT:
                    finished.append((k, compute_features(f)))
                    flows.pop(k, None)
        if not finished:
            continue
        out_rows = []
        for key, feat in finished:
            label = evaluate_heuristics(key, feat) or "Normal"
            src, dst, sport, dport = key
            emoji = "🚨" if label != "Normal" else "✅"
            print(f"{emoji} {src}:{sport} -> {dst}:{dport} [{label}]  | pkts/s={feat['Packets/s']:.1f} bytes/s={feat['Bytes/s']:.1f} HTTP={feat['HTTP Count']} SYN={feat['SYN Count']} ICMP={feat['ICMP Count']}")
            out_rows.append({
                "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Source": src, "Destination": dst,
                "Src Port": sport, "Dst Port": dport,
                "Packets/s": feat["Packets/s"],
                "Bytes/s": feat["Bytes/s"],
                "HTTP": feat["HTTP Count"],
                "SYN": feat["SYN Count"],
                "ICMP": feat["ICMP Count"],
                "Label": label
            })
        if out_rows:
            df = pd.DataFrame(out_rows)
            header = not os.path.exists(OUTPUT_FILE)
            try:
                df.to_csv(OUTPUT_FILE, mode="a", index=False, header=header)
                print(f"💾 Saved {len(out_rows)} records to {OUTPUT_FILE}")
            except Exception as e:
                print(f"[Error] Could not write CSV: {e}")

# ---------------- MAIN ----------------
def main():
    global SITE_IPS, WEBSITE_ONLY
    parser = argparse.ArgumentParser(description="Heuristic website traffic intrusion detector (no ML)")
    parser.add_argument("--iface", default=None, help="Interface to sniff (e.g. 'Ethernet')")
    parser.add_argument("--site", default=None, help="Website domain to monitor (optional)")
    parser.add_argument("--website-only", action="store_true", help="Monitor only HTTP/HTTPS traffic")
    parser.add_argument("--debug", action="store_true", help="Print packet summaries")
    parser.add_argument("--duration", type=int, default=0, help="Auto-stop after N seconds (0 = run until Ctrl+C)")
    args = parser.parse_args()

    if args.website_only:
        WEBSITE_ONLY = True
        print("🌐 Website-only mode enabled (HTTP/HTTPS)")

    if args.site:
        try:
            ips = socket.gethostbyname_ex(args.site)[2]
            SITE_IPS = set(ips)
            print(f"🌍 Monitoring specific site: {args.site} -> IPs: {SITE_IPS}")
        except Exception as e:
            print(f"[Error] Could not resolve site {args.site}: {e}")

    # Quick environment hints
    if os.name == "nt":
        print("ℹ️ Running on Windows — make sure Npcap is installed and script is run as Administrator.")
    print(f"ℹ️ Scapy default iface: {conf.iface}")

    # If iface not given, sniffer will use default; listing interfaces may help user identify names.
    if args.iface is None:
        print("ℹ️ No --iface provided. To target a specific interface, run: python live_website_traffic_heuristic.py --iface \"Wi-Fi\" --debug")
        print("ℹ️ To list interfaces, run this small snippet in Python:")
        print("   from scapy.all import show_interfaces; show_interfaces()")
    else:
        print(f"ℹ️ Using interface: {args.iface}")

    stop_event = threading.Event()
    analyzer_t = threading.Thread(target=analyzer_loop, args=(stop_event,), daemon=True)
    analyzer_t.start()

    def prn(pkt):
        if args.debug:
            try:
                print(pkt.summary())
            except Exception:
                pass
        handle_packet(pkt)

    print(f"🧠 Sniffing live traffic on: {args.iface or 'ALL interfaces'} (CTRL+C to stop)")
    sniffer = None
    try:
        sniffer = AsyncSniffer(prn=prn, store=False, iface=args.iface)
        sniffer.start()
    except Exception as e:
        print(f"[Error] Could not start sniffer: {e}")
        print("Try running as Administrator and ensure Npcap is installed (Windows).")
        stop_event.set()
        return

    try:
        if args.duration and args.duration > 0:
            # run for a limited duration (useful for testing)
            end_time = time.time() + args.duration
            while time.time() < end_time:
                time.sleep(0.5)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Capture stopped by user.")
    finally:
        stop_event.set()
        # stop sniffer safely
        if sniffer:
            try:
                sniffer.stop()
            except Exception as e:
                print(f"⚠️ Sniffer stop error (non-fatal): {e}")
        print("✅ Program exited safely.")

if __name__ == "__main__":
    main()
