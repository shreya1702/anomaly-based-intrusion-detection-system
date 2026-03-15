#!/usr/bin/env python3
"""
normal_traffic_formatted.py

Heuristics-only live network capture that classifies flows as NORMAL or ABNORMAL
and prints output in a consistent, easy-to-read formatted style.

- No ML / no dataset required.
- Default: log ABNORMAL flows. Use --only-normal to log only NORMAL flows.
- Optional: --website-only (ports 80/443) and --site <domain_or_ip> filter.
- Prints formatted console output like:
    ✅ 2025-11-25 12:34:01  192.168.1.10:54321 -> 93.184.216.34:80 [Normal]
       Info: Flow Bytes/s=1234.5, Packets/s=12.3
  or for abnormal:
    🚨 2025-11-25 12:34:05  192.168.1.10:52222 -> 10.0.0.5:80 [HTTP-Flood]
       Reason: http_gets=200, Flow Packets/s=400.0

Save as `normal_traffic_formatted.py` and run with admin/root privileges.
"""

import os
import time
import threading
import argparse
import socket
from collections import defaultdict, deque
from datetime import datetime

import pandas as pd
import numpy as np
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw, Ether, sendp, get_if_list

# ---------- Configuration ----------
OUTPUT_FILE = "normal_traffic_log.csv"

FLOW_IDLE_TIMEOUT = 1.0        # seconds of inactivity to close a flow
BATCH_INTERVAL = 2.0          # seconds between processing finished flows
WEB_PORTS = {80, 443}

# Heuristic thresholds (tune to your environment)
THRESHOLDS = {
    "SYN_COUNT": 60,
    "ICMP_COUNT": 60,
    "HTTP_COUNT": 80,
    "PPS_DOS": 400,
    "BYTESPS_DOS": 300000,
    "PORTS_PER_SRC": 40,
    "DESTS_PER_SRC": 30,
    "DNS_COUNT": 120,
    "ARP_COUNT": 60
}
SRC_AGG_WINDOW = 10.0

# ---------- State ----------
flows = {}                # key -> flow dict
flows_lock = threading.Lock()
finished_flows = deque()

src_stats = defaultdict(lambda: {"dst_ports": {}, "dst_ips": {}, "last_cleanup": time.time()})
src_lock = threading.Lock()

# ---------- Utilities ----------
def list_ifaces():
    try:
        return get_if_list()
    except Exception:
        return []

def get_flow_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    src = ip.src
    dst = ip.dst
    sport = int(getattr(pkt.payload, "sport", 0) or 0)
    dport = int(getattr(pkt.payload, "dport", 0) or 0)
    proto = int(ip.proto or 0)
    return (src, dst, sport, dport, proto)

def init_flow(ts):
    return {
        "first_ts": ts,
        "last_ts": ts,
        "pkt_count": 0,
        "bytes_total": 0,
        "pkt_sizes": [],
        "iats": [],
        "last_pkt_ts": None,
        "syn_count": 0,
        "icmp_count": 0,
        "http_get_count": 0,
        "dns_count": 0,
        "arp_count": 0
    }

def extract_http_get(payload):
    try:
        if not payload:
            return False
        return payload.startswith(b"GET ") or b"\r\nGET " in payload
    except Exception:
        return False

# ---------- Source aggregation ----------
def update_src_stats(pkt, ts):
    if IP not in pkt:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    dport = getattr(pkt.payload, "dport", None)
    with src_lock:
        stat = src_stats[src]
        if dport:
            stat["dst_ports"][int(dport)] = ts
        stat["dst_ips"][dst] = ts
        stat["last_cleanup"] = ts

def prune_src_stats():
    now = time.time()
    with src_lock:
        for src, stat in list(src_stats.items()):
            for p, t in list(stat["dst_ports"].items()):
                if now - t > SRC_AGG_WINDOW:
                    stat["dst_ports"].pop(p, None)
            for ip, t in list(stat["dst_ips"].items()):
                if now - t > SRC_AGG_WINDOW:
                    stat["dst_ips"].pop(ip, None)
            if not stat["dst_ports"] and not stat["dst_ips"] and now - stat.get("last_cleanup", 0) > SRC_AGG_WINDOW * 2:
                src_stats.pop(src, None)

# ---------- Flow update ----------
def update_flow(flow, pkt, ts):
    flow["pkt_count"] += 1
    size = len(pkt)
    flow["bytes_total"] += size
    flow["pkt_sizes"].append(size)
    if flow["last_pkt_ts"] is not None:
        flow["iats"].append(ts - flow["last_pkt_ts"])
    flow["last_pkt_ts"] = ts
    flow["last_ts"] = ts

    # TCP SYNs
    try:
        if pkt.haslayer(TCP):
            if 'S' in str(pkt[TCP].flags):
                flow["syn_count"] += 1
    except Exception:
        pass

    # ICMP
    try:
        if pkt.haslayer(ICMP):
            flow["icmp_count"] += 1
    except Exception:
        pass

    # HTTP GET detection (unencrypted HTTP)
    try:
        if pkt.haslayer(Raw) and pkt.haslayer(TCP):
            payload = bytes(pkt[Raw].load)
            if extract_http_get(payload):
                flow["http_get_count"] += 1
    except Exception:
        pass

    # DNS
    try:
        if pkt.haslayer(DNS) and pkt.haslayer(UDP):
            if pkt[DNS].qd and isinstance(pkt[DNS].qd, DNSQR):
                flow["dns_count"] += 1
    except Exception:
        pass

    # ARP
    try:
        if pkt.haslayer(ARP):
            flow["arp_count"] = flow.get("arp_count", 0) + 1
    except Exception:
        pass

def compute_features(flow):
    dur = max(0.0001, flow["last_ts"] - flow["first_ts"])
    pkt_sizes = np.array(flow["pkt_sizes"]) if flow["pkt_sizes"] else np.array([0])
    iats = np.array(flow["iats"]) if flow["iats"] else np.array([0])
    return {
        "Flow Duration": dur,
        "Total Packets": flow["pkt_count"],
        "Flow Bytes/s": flow["bytes_total"] / dur,
        "Flow Packets/s": flow["pkt_count"] / dur,
        "Packet Length Mean": float(pkt_sizes.mean()),
        "Packet Length Std": float(pkt_sizes.std(ddof=0)),
        "SYN Count": flow.get("syn_count", 0),
        "ICMP Count": flow.get("icmp_count", 0),
        "HTTP Count": flow.get("http_get_count", 0),
        "DNS Count": flow.get("dns_count", 0),
        "ARP Count": flow.get("arp_count", 0)
    }

# ---------- Heuristics ----------
def evaluate_heuristics(key, features):
    src, dst, sport, dport, proto = key
    syn = int(features.get("SYN Count", 0))
    icmp = int(features.get("ICMP Count", 0))
    http_gets = int(features.get("HTTP Count", 0))
    dns_q = int(features.get("DNS Count", 0))
    arp_c = int(features.get("ARP Count", 0))
    pps = float(features.get("Flow Packets/s", 0.0))
    bytesps = float(features.get("Flow Bytes/s", 0.0))

    if icmp >= THRESHOLDS["ICMP_COUNT"]:
        return "ICMP-Flood", f"icmp_count={icmp}"
    if syn >= THRESHOLDS["SYN_COUNT"]:
        return "SYN-Flood/Brute", f"syn_count={syn}"
    if dns_q >= THRESHOLDS["DNS_COUNT"]:
        return "DNS-Flood", f"dns_queries={dns_q}"
    if arp_c >= THRESHOLDS["ARP_COUNT"]:
        return "ARP-Flood", f"arp_count={arp_c}"
    if http_gets >= THRESHOLDS["HTTP_COUNT"]:
        return "HTTP-Flood", f"http_gets={http_gets}"
    if pps >= THRESHOLDS["PPS_DOS"] or bytesps >= THRESHOLDS["BYTESPS_DOS"]:
        return "DoS", f"pps={pps:.1f}, bytes/s={bytesps:.0f}"

    with src_lock:
        stat = src_stats.get(src, {})
        ports_count = len(stat.get("dst_ports", {}))
        dsts_count = len(stat.get("dst_ips", {}))
    if ports_count >= THRESHOLDS["PORTS_PER_SRC"]:
        return "Port-Scan", f"unique_ports={ports_count}"
    if dsts_count >= THRESHOLDS["DESTS_PER_SRC"]:
        return "Multi-Target-Scan", f"unique_dsts={dsts_count}"

    return None, None

# ---------- Formatting helpers ----------
def fmt_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def print_flow_line(ts, src, sport, dst, dport, label, explanation, features, normal):
    """Print one formatted flow block to console."""
    icon = "✅" if normal else "🚨"
    # First line: icon, timestamp, src:port -> dst:port [Label]
    print(f"{icon} {ts}  {src}:{sport} -> {dst}:{dport} [{label}]")
    # Second line: reason / info
    if explanation:
        print(f"   Reason: {explanation}")
    # Always print a compact stats line for clarity
    stats = f"Flow Bytes/s={features.get('Flow Bytes/s'):.1f}, Packets/s={features.get('Flow Packets/s'):.1f}, MeanPktLen={features.get('Packet Length Mean'):.1f}"
    print(f"   Info: {stats}\n")

# ---------- Batch processing (close idle flows & classify) ----------
def batch_process(output_file, website_only=False, site_ips=None, only_normal=False):
    last_time = time.time()
    while True:
        time.sleep(1)
        prune_src_stats()

        now = time.time()
        # close idle flows
        with flows_lock:
            to_close = []
            for key, f in list(flows.items()):
                if f["last_pkt_ts"] and now - f["last_pkt_ts"] > FLOW_IDLE_TIMEOUT:
                    # website-only filter
                    if website_only:
                        if key[3] not in WEB_PORTS and key[2] not in WEB_PORTS:
                            continue
                    finished_flows.append((key, compute_features(f)))
                    to_close.append(key)
            for k in to_close:
                flows.pop(k, None)

        if time.time() - last_time < BATCH_INTERVAL:
            continue

        if not finished_flows:
            last_time = time.time()
            continue

        rows = []
        while finished_flows:
            key, feat = finished_flows.popleft()
            src, dst, sport, dport, proto = key

            # site filter by IPs if provided
            if site_ips:
                if src not in site_ips and dst not in site_ips:
                    continue

            heur_label, heur_reason = evaluate_heuristics(key, feat)
            is_normal = heur_label is None
            label = "Normal" if is_normal else heur_label

            # If user asked to log only normal flows, skip abnormal ones
            if only_normal and not is_normal:
                continue
            # By default (only_normal False) we log abnormal flows; skip normal if not requested
            if (not only_normal) and is_normal:
                continue

            ts = fmt_timestamp()
            print_flow_line(ts, src, sport, dst, dport, label, heur_reason, feat, is_normal)

            rows.append({
                "Timestamp": ts,
                "Source IP": src,
                "Destination IP": dst,
                "Source Port": sport,
                "Destination Port": dport,
                "Label": label,
                "Explanation": heur_reason or "",
                "Flow Packets/s": feat.get("Flow Packets/s"),
                "Flow Bytes/s": feat.get("Flow Bytes/s"),
                "SYN Count": feat.get("SYN Count"),
                "ICMP Count": feat.get("ICMP Count"),
                "HTTP Count": feat.get("HTTP Count"),
            })

        if rows:
            out_df = pd.DataFrame(rows)
            header = not os.path.exists(output_file)
            out_df.to_csv(output_file, mode="a", index=False, header=header)
            print(f"💾 Appended {len(rows)} rows to {output_file}\n")

        last_time = time.time()

# ---------- Packet handler & optional simulators ----------
def packet_handler(pkt, website_only=False):
    # optional pre-filter to save CPU
    if website_only:
        if IP not in pkt or not pkt.haslayer(TCP):
            return
        try:
            if int(pkt[TCP].dport) not in WEB_PORTS and int(pkt[TCP].sport) not in WEB_PORTS:
                return
        except Exception:
            return

    ts = time.time()
    key = get_flow_key(pkt)
    if not key:
        return
    with flows_lock:
        if key not in flows:
            flows[key] = init_flow(ts)
        update_flow(flows[key], pkt, ts)
    update_src_stats(pkt, ts)

# ---------- DNS helper ----------
def resolve_site(site):
    ips = set()
    if not site:
        return ips
    try:
        data = socket.gethostbyname_ex(site)
        for ip in data[2]:
            ips.add(ip)
    except Exception:
        try:
            ips.add(socket.getaddrinfo(site, None)[0][4][0])
        except Exception:
            pass
    return ips

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Live heuristics-only Normal/Abnormal traffic detector (formatted output)")
    parser.add_argument("--iface", default=None, help="Interface to sniff (e.g. 'Wi-Fi' or 'Ethernet')")
    parser.add_argument("--website-only", action="store_true", help="Only analyze web ports (80/443)")
    parser.add_argument("--site", default=None, help="Optional site (domain or IP) to filter traffic to/from")
    parser.add_argument("--only-normal", action="store_true", help="Log only Normal flows (default logs Abnormal flows)")
    parser.add_argument("--simulate", action="store_true", help="Run a small lab simulator (requires --target)")
    parser.add_argument("--target", default=None, help="Simulator target IP (lab only)")
    parser.add_argument("--sim-mode", choices=["ping","syn","http","ping_flood","syn_scan","http_burst"], default="ping", help="Simulator mode (aliases accepted)")
    parser.add_argument("--debug", action="store_true", help="Print raw packet summaries")
    args = parser.parse_args()

    # normalize sim-mode aliases
    alias_map = {"syn_scan":"syn","ping_flood":"ping","http_burst":"http"}
    sim_mode = alias_map.get(args.sim_mode, args.sim_mode)

    # resolve site to IPs if provided
    site_ips = set()
    if args.site:
        site_ips = resolve_site(args.site)
        print(f"[Info] Site filter: {args.site} -> IPs: {site_ips}")

    # start batch processing thread
    threading.Thread(target=batch_process, args=(OUTPUT_FILE, args.website_only, site_ips if site_ips else None, args.only_normal), daemon=True).start()

    # optional simulator (lab-only)
    if args.simulate:
        if not args.target:
            print("Error: --simulate requires --target")
            return
        print("[Main] Starting lab simulator (be careful!).")
        if sim_mode == "ping":
            threading.Thread(target=lambda: None, daemon=True).start()  # placeholder (user can add sim if desired)

    # start sniffer
    print(f"[Main] Starting live capture on: {args.iface or 'ALL interfaces'} (website-only={args.website_only}, site={args.site})")
    def prn(pkt):
        if args.debug:
            try:
                print(pkt.summary())
            except Exception:
                pass
        try:
            packet_handler(pkt, website_only=args.website_only)
        except Exception:
            pass

    sniffer = AsyncSniffer(prn=prn, store=False, iface=args.iface)
    try:
        sniffer.start()
    except Exception as e:
        print(f"[Error] Could not start sniffer: {e}")
        return

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[Main] Stopping capture.")
        try:
            sniffer.stop()
        except Exception:
            pass
        print("[Main] Exited cleanly.")

if __name__ == "__main__":
    main()
