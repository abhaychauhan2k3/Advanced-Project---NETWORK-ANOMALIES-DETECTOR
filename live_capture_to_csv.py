import csv
import subprocess
import time
import pandas as pd
import numpy as np
import sys
import traceback

# ----------------------------
# Config
# ----------------------------
FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "frame.time_delta",
    "ip.src",
    "ip.dst",
    "ip.proto",
    "ip.ttl",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags",
    "tcp.window_size",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "icmp.type",
    "icmp.code",
    "dns.qry.name",
    "dns.flags.response",
    "dns.qry.type"
]

OUTPUT_CSV = "livecapture_raw.csv"
PROCESSED_FILE = "processed_features.csv"
FINAL_FILE = "final.csv"

# Use interface index (recommended) or name. If using index, set to int (e.g. 1). If using name, keep string.
INTERFACE = "Wi-Fi"  # or use interface number like 1

# Improve capture quality: capture only IPv4 TCP/UDP packets (avoids ARP, beacons etc)
CAPTURE_FILTER = 'ip and (tcp or udp)'

# Required ML columns (53 features list)
REQUIRED_COLS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Length of Fwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
    "Bwd IAT Max", "Bwd IAT Min", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length",
    "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "PSH Flag Count",
    "ACK Flag Count", "Average Packet Size", "Subflow Fwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Max", "Active Min",
    "Idle Mean", "Idle Max", "Idle Min"
]


# ----------------------------
# Helper: build tshark command
# ----------------------------
def build_tshark_cmd():
    # Use interface number or name directly
    cmd = ["tshark", "-i", str(INTERFACE), "-l", "-T", "fields"]

    # Add capture filter if present
    if CAPTURE_FILTER:
        cmd.extend(["-f", CAPTURE_FILTER])

    for f in FIELDS:
        cmd.extend(["-e", f])

    cmd.extend(["-E", "header=y", "-E", "separator=,"])
    return cmd


# ----------------------------
# Start capture and write CSV
# ----------------------------
def start_capture():
    print("[+] Starting live capture using tshark...")
    print("[+] Writing extracted fields to:", OUTPUT_CSV)
    cmd = build_tshark_cmd()
    # Debug: print(' '.join(cmd))
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    print("[+] Capturing... Press CTRL + C to stop.\n")

    with open(OUTPUT_CSV, "w", newline="") as fout:
        writer = csv.writer(fout)
        writer.writerow(FIELDS)

        try:
            for line in process.stdout:
                if not line:
                    continue
                s = line.strip()
                # skip obvious empty rows
                if not s:
                    continue
                # skip lines that are just commas
                if s == "," * (len(FIELDS) - 1):
                    continue

                row = s.split(",")

                # pad to full length
                if len(row) < len(FIELDS):
                    row += [""] * (len(FIELDS) - len(row))

                # write row
                writer.writerow(row)

        except KeyboardInterrupt:
            print("\n[+] Capture stopped by user.")
        except Exception as e:
            print("[!] Capture error:", e)
            traceback.print_exc()
        finally:
            try:
                process.terminate()
            except Exception:
                pass
            print("[+] Saved:", OUTPUT_CSV)


# ----------------------------
# Load raw CSV safely
# ----------------------------
def load_raw_csv():
    # read with low_memory False to avoid mixed dtype warnings
    df = pd.read_csv(OUTPUT_CSV, low_memory=False)

    # convert empty strings to NaN and drop rows that are entirely empty
    df.replace("", np.nan, inplace=True)
    df.dropna(how="all", inplace=True)
    df.reset_index(drop=True, inplace=True)

    # Ensure columns from FIELDS exist (if tshark didn't include some, add them)
    for c in FIELDS:
        if c not in df.columns:
            df[c] = np.nan

    # Force numeric conversions for critical fields (coerce -> NaN -> later fill)
    numeric_cols = [
        "frame.len", "frame.time_epoch", "frame.time_delta",
        "tcp.len", "udp.length", "tcp.window_size",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"
    ]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Replace NaN in ip fields with empty string to preserve existence
    for ipcol in ["ip.src", "ip.dst"]:
        if ipcol in df.columns:
            df[ipcol] = df[ipcol].fillna("")

    # Fill numeric NaN with 0 (safe defaults)
    df = df.fillna(0)

    return df


# ----------------------------
# Compute features (robust)
# ----------------------------
def compute_features(df):
    # Ensure required tshark-derived columns exist
    for col in ["tcp.dstport", "udp.dstport", "tcp.len", "udp.length", "tcp.flags", "tcp.window_size", "frame.len", "frame.time_delta", "frame.time_epoch", "ip.src"]:
        if col not in df.columns:
            df[col] = 0

    # Destination Port: prefer TCP dst, else UDP dst
    dest_port = df["tcp.dstport"].replace(0, np.nan)
    dest_port = dest_port.fillna(df["udp.dstport"]).fillna(0)

    # Flow duration: we captured frame.time_delta; if not present, try diff of epoch
    flow_dur = df.get("frame.time_delta", None)
    if flow_dur is None or (isinstance(flow_dur, (int, float)) and flow_dur == 0):
        if "frame.time_epoch" in df.columns:
            td = pd.to_numeric(df["frame.time_epoch"], errors="coerce").diff().fillna(0)
            flow_dur = td
        else:
            flow_dur = pd.Series(np.zeros(len(df)))

    # Ensure numeric
    frame_len = pd.to_numeric(df["frame.len"], errors="coerce").fillna(0)
    tcp_len = pd.to_numeric(df["tcp.len"], errors="coerce").fillna(0)
    udp_len = pd.to_numeric(df["udp.length"], errors="coerce").fillna(0)

    # Backward length: tcp_len if non-zero else udp_len
    bwd_len = tcp_len.where(tcp_len != 0, udp_len)

    td_safe = pd.to_numeric(flow_dur, errors="coerce").replace(0, 1e-6)

    f = {}
    f["Destination Port"] = dest_port
    f["Flow Duration"] = td_safe
    f["Total Fwd Packets"] = (df["ip.src"].astype(str) != "").astype(int)

    f["Total Length of Fwd Packets"] = frame_len
    f["Fwd Packet Length Max"] = frame_len
    f["Fwd Packet Length Min"] = frame_len
    f["Fwd Packet Length Mean"] = frame_len
    f["Fwd Packet Length Std"] = 0

    f["Bwd Packet Length Max"] = bwd_len
    f["Bwd Packet Length Min"] = bwd_len
    f["Bwd Packet Length Mean"] = bwd_len
    f["Bwd Packet Length Std"] = 0

    f["Flow Bytes/s"] = frame_len / td_safe
    f["Flow Packets/s"] = 1.0 / td_safe

    f["Flow IAT Mean"] = td_safe
    f["Flow IAT Std"] = 0
    f["Flow IAT Max"] = td_safe
    f["Flow IAT Min"] = td_safe

    for key in ["Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min"]:
        f[key] = td_safe

    for key in ["Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min"]:
        f[key] = td_safe

    # Header length: check tcp.flags presence. Accept hex strings or numeric
    def flags_to_int(x):
        try:
            if x == 0 or str(x).strip() == "0":
                return 0
            sx = str(x)
            # remove 0x if present
            if sx.startswith("0x") or sx.startswith("0X"):
                return int(sx, 16)
            return int(float(sx))
        except Exception:
            return 0

    flags_int = df["tcp.flags"].apply(flags_to_int)

    f["Fwd Header Length"] = (flags_int != 0).astype(int) * 20
    f["Bwd Header Length"] = f["Fwd Header Length"]

    f["Fwd Packets/s"] = f["Flow Packets/s"]
    f["Bwd Packets/s"] = f["Flow Packets/s"]

    f["Min Packet Length"] = frame_len
    f["Max Packet Length"] = frame_len
    f["Packet Length Mean"] = frame_len
    f["Packet Length Std"] = 0
    f["Packet Length Variance"] = 0

    def parse_flag_val(val, bit):
        try:
            si = str(val)
            if si.startswith("0x") or si.startswith("0X"):
                ival = int(si, 16)
            else:
                ival = int(float(si))
            return int((ival & bit) != 0)
        except Exception:
            return 0

    f["FIN Flag Count"] = df["tcp.flags"].apply(lambda x: parse_flag_val(x, 0x01))
    f["PSH Flag Count"] = df["tcp.flags"].apply(lambda x: parse_flag_val(x, 0x08))
    f["ACK Flag Count"] = df["tcp.flags"].apply(lambda x: parse_flag_val(x, 0x10))

    f["Average Packet Size"] = frame_len
    f["Subflow Fwd Bytes"] = frame_len
    f["Init_Win_bytes_forward"] = pd.to_numeric(df["tcp.window_size"], errors="coerce").fillna(0)
    f["Init_Win_bytes_backward"] = pd.to_numeric(df["tcp.window_size"], errors="coerce").fillna(0)

    f["act_data_pkt_fwd"] = tcp_len
    f["min_seg_size_forward"] = tcp_len

    f["Active Mean"] = td_safe
    f["Active Max"] = td_safe
    f["Active Min"] = td_safe
    f["Idle Mean"] = 0
    f["Idle Max"] = 0
    f["Idle Min"] = 0

    out = pd.DataFrame(f)

    # Ensure all required columns present (fill 0)
    for col in REQUIRED_COLS:
        if col not in out.columns:
            out[col] = 0

    # Reorder
    out = out[REQUIRED_COLS]
    return out


# ----------------------------
# Process pipeline
# ----------------------------
def compute_processed_features():
    try:
        print("[+] Loading raw CSV…")
        df = load_raw_csv()

        if df.empty:
            print("[!] Raw CSV is empty after cleaning. Creating zero-row processed file.")
            # create a single row of zeros for processed file so downstream doesn't break
            zero_row = {c: 0 for c in REQUIRED_COLS}
            pd.DataFrame([zero_row]).to_csv(PROCESSED_FILE, index=False)
            return

        print("[+] Computing ML features…")
        out = compute_features(df)

        print("[+] Saving:", PROCESSED_FILE)
        out.to_csv(PROCESSED_FILE, index=False)
        print("[+] DONE — processed_features.csv ready!")
    except Exception as e:
        print("[!] Error in compute_processed_features:", e)
        traceback.print_exc()


# ----------------------------
# Create final averaged vector
# ----------------------------
def compute_final_csv():
    try:
        print("[+] Creating final averaged vector…")
        df = pd.read_csv(PROCESSED_FILE, low_memory=False)

        if df.empty:
            print("[!] processed_features.csv empty — writing zeros to final.csv")
            zero_row = {c: 0 for c in REQUIRED_COLS}
            pd.DataFrame([zero_row]).to_csv(FINAL_FILE, index=False)
            print("[+] Final vector saved to", FINAL_FILE)
            return

        encoded = df.copy()
        for col in encoded.columns:
            if encoded[col].dtype == "object":
                encoded[col], _ = pd.factorize(encoded[col])

        final_vector = encoded.mean(axis=0, numeric_only=True)

        # final_vector -> single-row dataframe with proper columns
        final_df = pd.DataFrame([final_vector.values], columns=final_vector.index)
        final_df.to_csv(FINAL_FILE, index=False)
        print("[+] Final vector saved to", FINAL_FILE)
    except Exception as e:
        print("[!] Error in compute_final_csv:", e)
        traceback.print_exc()


# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    try:
        start_capture()
        compute_processed_features()
        compute_final_csv()
        print("[+] Pipeline complete.")
    except Exception as e:
        print("[!] Fatal error:", e)
        traceback.print_exc()
        sys.exit(1)

