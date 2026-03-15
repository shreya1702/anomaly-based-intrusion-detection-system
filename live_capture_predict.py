#!/usr/bin/env python3
"""
live_capture_all_detection.py

Comprehensive live network flow capture + ML prediction + heuristic detection.

Detects:
 - ICMP/Ping Flood
 - SYN/Brute-force
 - HTTP Flood
 - Port Scan
 - Multi-Target Scan
 - DNS Flood
 - ARP Flood
 - High-rate DoS (pps / bytes/s)
 - Website-only traffic analysis (--website-only / --site "domain")

Supports both short and long simulator mode names:
  ping | ping_flood
  syn | syn_scan
  http | http_burst
  brute | brute_like | ftp_bruteforce

Usage examples:
  # Live capture (no simulation)
  python live_capture_all_detection.py --iface "Ethernet" --debug

  # Website-only mode
  python live_capture_all_detection.py --iface "Ethernet" --website-only --debug

  # Specific website
  python live_capture_all_detection.py --iface "Ethernet" --site "www.google.com" --debug

  # Simulate ping flood (lab only)
  python live_capture_all_detection.py --iface "Ethernet" --simulate --target 192.168.1.10 --sim-mode ping_flood --debug
"""

import os
import time
import threading
import argparse
import socket
import joblib
from collections import defaultdict, deque
from datetime import datetime
import pandas as pd
import numpy as np
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether, Raw, sendp

# ---------------- Configuration ----------------
MODEL_FILE = "intrusion_rf_model.pkl"
SCALER_FILE = "scaler.pkl"
ENCODER_FILE = "label_encoder.pkl"
OUTPUT_FILE = "predicted_network_traffic.csv"

FLOW_IDLE_TIMEOUT = 0.8
BATCH_PREDICT_INTERVAL = 2.0

THRESHOLDS = {
    "SYN_COUNT": 10,
    "ICMP_COUNT": 10,
    "HTTP_COUNT": 8,
    "PPS_DOS": 50,
    "BYTESPS_DOS": 50000,
    "PORTS_PER_SRC": 10,
    "DESTS_PER_SRC": 5,
    "DNS_COUNT": 20,
    "ARP_COUNT": 10
}
def calculate_severity(pps, bytes_per_sec,
                       pps_threshold=THRESHOLDS["PPS_DOS"],
                       bytes_threshold=THRESHOLDS["BYTESPS_DOS"]):
    score = (pps / pps_threshold) + (bytes_per_sec / bytes_threshold)

    if score < 2:
        return "LOW"
    elif score < 4:
        return "MEDIUM"
    else:
        return "HIGH"
    
def calculate_confidence(severity):
    if severity == "LOW":
        return 65
    elif severity == "MEDIUM":
        return 80
    else:
        return 95


SRC_AGG_WINDOW = 10.0  # seconds

# ---------------- Load ML artifacts ----------------
use_ml = False
model = scaler = encoder = None
EXPECTED_FEATURES = None

if all(os.path.exists(f) for f in [MODEL_FILE, SCALER_FILE, ENCODER_FILE]):
    try:
        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
        encoder = joblib.load(ENCODER_FILE)
        use_ml = True
        EXPECTED_FEATURES = list(getattr(scaler, "feature_names_in_", [])) or [
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Flow Bytes/s", "Flow Packets/s", "Packet Length Mean", "Packet Length Std",
            "Flow IAT Mean", "Flow IAT Std", "Fwd IAT Mean", "Bwd IAT Mean",
            "ACK Flag Count", "SYN Flag Count", "FIN Flag Count", "RST Flag Count",
            "URG Flag Count", "ECE Flag Count", "PSH Flag Count", "CWE Flag Count",
            "Active Mean", "Active Std", "Idle Mean", "Idle Std"
        ]
        print(" ML artifacts loaded; using ML + heuristics.")
    except Exception as e:
        print(f"[Warn] Failed to load ML artifacts: {e}; using heuristics only.")
        use_ml = False
else:
    print("[Info] ML artifacts not found — running heuristics-only mode.")

# ---------------- Global state ----------------
flows = {}
flows_lock = threading.Lock()
finished_flows = deque()
src_stats = defaultdict(lambda: {"dst_ports": {}, "dst_ips": {}, "last_cleanup": time.time()})
src_lock = threading.Lock()

# website filter globals
WEBSITE_ONLY = False
TARGET_SITE_IPS = set()

# ---------------- Utilities ----------------
def get_flow_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = ip.proto
    src = ip.src
    dst = ip.dst
    sport = getattr(pkt.payload, "sport", 0)
    dport = getattr(pkt.payload, "dport", 0)
    return (src, dst, int(sport or 0), int(dport or 0), int(proto or 0))

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

def extract_http_get(payload_bytes):
    try:
        if payload_bytes and (payload_bytes.startswith(b"GET ") or b"\r\nGET " in payload_bytes):
            return True
    except Exception:
        pass
    return False

# ---------------- Flow update & aggregation ----------------
def update_src_stats(pkt, ts):
    if IP in pkt:
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

def update_flow(flow, pkt, ts):
    flow["pkt_count"] += 1
    size = len(pkt)
    flow["bytes_total"] += size
    flow["pkt_sizes"].append(size)
    if flow["last_pkt_ts"] is not None:
        flow["iats"].append(ts - flow["last_pkt_ts"])
    flow["last_pkt_ts"] = ts
    flow["last_ts"] = ts

    if pkt.haslayer(TCP):
        if 'S' in str(pkt[TCP].flags):
            flow["syn_count"] += 1
    if pkt.haslayer(ICMP):
        flow["icmp_count"] += 1
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        if extract_http_get(payload):
            flow["http_get_count"] += 1
    if pkt.haslayer(DNS) and pkt.haslayer(UDP):
        if pkt[DNS].qd and isinstance(pkt[DNS].qd, DNSQR):
            flow["dns_count"] += 1
    if pkt.haslayer(ARP):
        flow["arp_count"] += 1

def compute_features(flow):
    dur = max(0.0001, flow["last_ts"] - flow["first_ts"])
    pkt_sizes = np.array(flow["pkt_sizes"]) if flow["pkt_sizes"] else np.array([0])
    iats = np.array(flow["iats"]) if flow["iats"] else np.array([0])
    return {
        "Flow Duration": dur,
        "Total Fwd Packets": flow["pkt_count"],
        "Total Backward Packets": 0.0,
        "Flow Bytes/s": flow["bytes_total"] / dur,
        "Flow Packets/s": flow["pkt_count"] / dur,
        "Packet Length Mean": float(pkt_sizes.mean()),
        "Packet Length Std": float(pkt_sizes.std(ddof=0)),
        "Flow IAT Mean": float(iats.mean()),
        "Flow IAT Std": float(iats.std(ddof=0)),
        "SYN Count": flow.get("syn_count", 0),
        "ICMP Count": flow.get("icmp_count", 0),
        "HTTP Count": flow.get("http_get_count", 0),
        "DNS Count": flow.get("dns_count", 0),
        "ARP Count": flow.get("arp_count", 0)
    }

# ---------------- Heuristic detection ----------------
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

# ---------------- Batch prediction loop ----------------
def batch_predict_loop(output_file=OUTPUT_FILE):
    last_pred_time = time.time()
    while True:
        time.sleep(1)
        now = time.time()
        prune_src_stats()
        with flows_lock:
            to_close = []
            for key, f in list(flows.items()):
                if f["last_pkt_ts"] and now - f["last_pkt_ts"] > FLOW_IDLE_TIMEOUT:
                    # filter website-only
                    src, dst, sport, dport, proto = key
                    if WEBSITE_ONLY and dport not in (80, 443):
                        continue
                    if TARGET_SITE_IPS and dst not in TARGET_SITE_IPS and src not in TARGET_SITE_IPS:
                        continue
                    finished_flows.append((key, compute_features(f)))
                    to_close.append(key)
            for k in to_close:
                flows.pop(k, None)
        if time.time() - last_pred_time < BATCH_PREDICT_INTERVAL:
            continue
        if not finished_flows:
            last_pred_time = time.time()
            continue

                       # Build batch and keys list from finished flows
        batch = []
        keys = []

        while finished_flows:
            key, feat = finished_flows.popleft()
            batch.append(feat)
            keys.append(key)

        # If no flows, skip prediction loop
        if not batch:
            last_pred_time = time.time()
            continue

        #  Convert batch into dataframe
        df = pd.DataFrame(batch)

        ml_labels = ["Unknown"] * len(df)

        #  ML (optional)
        if use_ml and EXPECTED_FEATURES:
            for col in EXPECTED_FEATURES:
                if col not in df.columns:
                    df[col] = 0.0

            df_model = df.reindex(columns=EXPECTED_FEATURES, fill_value=0.0)

            try:
                X = scaler.transform(df_model)
                preds = model.predict(X)
                ml_labels = encoder.inverse_transform(preds)
            except Exception as e:
                print(f"[Warn] ML prediction failed: {e}")

        rows_out = []

        # ALERT-only output (only anomalies)
                # ALERT + NORMAL output (show both on console)
        for i, key in enumerate(keys):
            src, dst, sport, dport, proto = key
            features = batch[i]

            heur_label, heur_reason = evaluate_heuristics(key, features)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Basic info used in prints
            flow_bps = float(features.get("Flow Bytes/s", 0.0))
            pps = float(features.get("Flow Packets/s", 0.0))
            severity = calculate_severity(pps, flow_bps)
            confidence = calculate_confidence(severity)


            if heur_label:
                #  ATTACK FLOW – same as before, just a bit prettier
                print(f" {timestamp}  {src}:{sport} -> {dst}:{dport} [{heur_label}]")
                print(f"   Reason: {heur_reason}")
                print(f"   Info: Flow Bytes/s={flow_bps:.1f}, Packets/s={pps:.1f}")
                print(f"   Severity Level: {severity}")
                print(f"   Confidence Score: {confidence}%")

                
                # Only anomalies go to predicted_network_traffic.csv
                rows_out.append({
                    "Timestamp": timestamp,
                    "Source IP": src,
                    "Destination IP": dst,
                    "Source Port": sport,
                    "Destination Port": dport,
                    "Protocol": proto,
                    "Severity": severity,
                    "Predicted_Label": heur_label,
                    "Explanation": heur_reason,
                    "Confidence Score": confidence,

                    "Flow Duration": features.get("Flow Duration"),
                    "Flow Packets/s": features.get("Flow Packets/s"),
                    "Flow Bytes/s": features.get("Flow Bytes/s"),
                    "SYN Count": features.get("SYN Count"),
                    "ICMP Count": features.get("ICMP Count"),
                    "HTTP Count": features.get("HTTP Count"),
                    "DNS Count": features.get("DNS Count"),
                    "ARP Count": features.get("ARP Count")
                })
            else:
                #  NORMAL FLOW – NEW: print to PowerShell too

                print(f" {timestamp}  {src}:{sport} -> {dst}:{dport} [Normal]")
                print(f"   Info: Flow Bytes/s={flow_bps:.1f}, Packets/s={pps:.1f}")

        if rows_out:
            pd.DataFrame(rows_out).to_csv(output_file, mode="a", index=False, header=not os.path.exists(output_file))
            print(f" Logged {len(rows_out)} anomaly flows")

        last_pred_time = time.time()

# ------------------ END ALERT-ONLY MODE ------------------

# ---------------- Packet handler ----------------
def packet_handler(pkt):
    if WEBSITE_ONLY or TARGET_SITE_IPS:
        if IP in pkt:
            dst = pkt[IP].dst
            src = pkt[IP].src
            if WEBSITE_ONLY and not (pkt.haslayer(TCP) and pkt[TCP].dport in (80, 443)):
                return
            if TARGET_SITE_IPS and dst not in TARGET_SITE_IPS and src not in TARGET_SITE_IPS:
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

# ---------------- Simulators ----------------
def simulate_ping_flood(target, count=200, interval=0.01, iface=None):
    for _ in range(count):
        sendp(Ether()/IP(dst=target)/ICMP()/b'X'*32, iface=iface, verbose=False)
        time.sleep(interval)
    print(f"[Sim] Sent {count} ICMP echo requests to {target}")

def simulate_syn_flood(target, count=500, interval=0.01, iface=None):
    for _ in range(count):
        sendp(Ether()/IP(dst=target)/TCP(dport=22, flags='S'), iface=iface, verbose=False)
        time.sleep(interval)
    print(f"[Sim] Sent {count} SYN packets to {target}")

def simulate_http_gets(target, count=200, interval=0.01, iface=None, host_header="example.com"):
    raw = f"GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: test\r\n\r\n".encode()
    for _ in range(count):
        sendp(Ether()/IP(dst=target)/TCP(dport=80, flags='PA')/Raw(load=raw), iface=iface, verbose=False)
        time.sleep(interval)
    print(f"[Sim] Sent {count} HTTP GETs to {target}")

# ---------------- Main ----------------
def main():
    global WEBSITE_ONLY, TARGET_SITE_IPS
    parser = argparse.ArgumentParser(description="Live capture + ML + heuristics intrusion detection (lab-only simulators available)")
    parser.add_argument("--iface", default=None, help="Interface to sniff (e.g. 'Ethernet')")
    parser.add_argument("--simulate", action="store_true", help="Run simulator (lab only)")
    parser.add_argument("--target", default=None, help="Target IP for simulator")
    parser.add_argument("--sim-mode", choices=["ping","syn","http","brute",
                                               "ping_flood","syn_scan","http_burst","brute_like","ftp_bruteforce"],
                        default="ping", help="Simulator mode")
    parser.add_argument("--debug", action="store_true", help="Print packet summaries")
    parser.add_argument("--website-only", action="store_true", help="Analyze only web traffic (ports 80/443)")
    parser.add_argument("--site", default=None, help="Specific website domain to monitor (e.g., www.google.com)")
    parser.add_argument("--duration", type=int, default=None, help="Duration of capture in seconds (omit for indefinite run)")
    args = parser.parse_args()

    # handle website filters
    if args.website_only:
        WEBSITE_ONLY = True
        print(" Website-only mode enabled (ports 80/443)")
    if args.site:
        try:
            site_ips = socket.gethostbyname_ex(args.site)[2]
            TARGET_SITE_IPS = set(site_ips)
            print(f" Monitoring site: {args.site} (IPs: {list(TARGET_SITE_IPS)})")
        except Exception as e:
            print(f"[Error] Could not resolve site {args.site}: {e}")

    # alias normalization
    alias_map = {
        "syn_scan": "syn", "ping_flood": "ping", "brute_like": "brute",
        "ftp_bruteforce": "brute", "http_burst": "http"
    }
    if args.sim_mode in alias_map:
        args.sim_mode = alias_map[args.sim_mode]

    threading.Thread(target=batch_predict_loop, daemon=True).start()

    if args.simulate:
        if not args.target:
            print("Error: --simulate requires --target")
            return
        print("[Main] Starting simulator (lab-only).")
        if args.sim_mode == "ping":
            threading.Thread(target=simulate_ping_flood, args=(args.target,200,0.01,args.iface), daemon=True).start()
        elif args.sim_mode in ("syn", "brute"):
            threading.Thread(target=simulate_syn_flood, args=(args.target,500,0.01,args.iface), daemon=True).start()
        elif args.sim_mode == "http":
            threading.Thread(target=simulate_http_gets, args=(args.target,200,0.01,args.iface,args.target), daemon=True).start()

    print(f" Starting live capture on: {args.iface or 'ALL interfaces'} (CTRL+C to stop)")
    def prn(pkt):
        if args.debug:
            print(pkt.summary())
        try:
            packet_handler(pkt)
        except Exception:
            pass

    sniffer = AsyncSniffer(prn=prn, store=False, iface=args.iface)
    sniffer.start()
    start_time = time.time()
    try:
        while True:
            time.sleep(1)
            if args.duration is not None and (time.time() - start_time) >= args.duration:
                print(f"[Info] Duration {args.duration} seconds reached. Stopping sniffer...")
                break
    except KeyboardInterrupt:
        print("Stopping sniffer...")
    sniffer.stop()
    print("Exited.")

if __name__ == "__main__":
    main()
