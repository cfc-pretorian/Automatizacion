#!/usr/bin/env python3
"""
scripts/check_batch.py

Uso en GitHub Actions: env var ABUSEIPDB_KEY debe estar definida.
Opcional: env var BATCH_SIZE (int), DEFAULT 1000.
"""

import os, csv, json, time, requests, sys
from datetime import datetime
from pathlib import Path

# Config
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "1000"))
INPUT = "ips_master.csv"
STATE_FILE = "state.json"
OUTPUT = "ips_validated.csv"
HISTORY_DIR = "ips_history"
FEEDS_FILE = "feeds.txt"  # opcional: urls de feeds públicas (una por línea)
DAILY_SAFE_LIMIT = int(os.getenv("DAILY_SAFE_LIMIT", str(BATCH_SIZE - 50)))
# (DAILY_SAFE_LIMIT is the maximum number of AbuseIPDB queries we will do in this run)

HEADERS_ABUSE = {"Key": ABUSE_KEY, "Accept": "application/json"}

# Helpers
def read_master(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f) if path.endswith(".csv") else csv.reader(f)
        if path.endswith(".csv"):
            for r in reader:
                rows.append(r)
        else:
            # fallback: one ip per line
            for r in reader:
                ip = r[0].strip()
                if ip: rows.append({"ip": ip})
    return rows

def load_state():
    if not Path(STATE_FILE).exists():
        return {"last_index": 0}
    with open(STATE_FILE) as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def safe_request_abuse(ip, max_retries=3):
    if not ABUSE_KEY:
        return {"error": "no_key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    for attempt in range(1, max_retries+1):
        try:
            r = requests.get(url, headers=HEADERS_ABUSE, params=params, timeout=20)
            if r.status_code == 200:
                return {"ok": True, "data": r.json().get("data", {})}
            elif r.status_code in (401,403):
                return {"error": f"auth_{r.status_code}"}
            elif r.status_code == 429:
                # rate limited: caller should slow down
                return {"error": "rate_limited"}
            else:
                # transient HTTP errors -> retry
                time.sleep(2 * attempt)
        except requests.RequestException as e:
            time.sleep(2 * attempt)
    return {"error": "request_failed"}

def load_feeds():
    feeds = []
    if not Path(FEEDS_FILE).exists():
        return feeds
    with open(FEEDS_FILE) as f:
        for line in f:
            u = line.strip()
            if u: feeds.append(u)
    return feeds

def fetch_feeds(feeds):
    """Return set of IPs found in public feeds (simple approach)."""
    ips = set()
    for url in feeds:
        try:
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # handle CSV lines containing IP, or plain IP per line
                    parts = [p.strip() for p in line.split(",")]
                    candidate = parts[0]
                    # cheap validation (basic IPv4/IPv6-like)
                    if len(candidate) >= 7 and len(candidate) <= 45:
                        ips.add(candidate)
        except Exception:
            # skip failing feed
            continue
    return ips

def write_outputs(rows):
    # write ips_validated.csv (overwrite)
    fieldnames = ["ip","last_checked","status","sources","evidence"]
    with open(OUTPUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    # snapshot to history
    Path(HISTORY_DIR).mkdir(exist_ok=True)
    snap = Path(HISTORY_DIR) / f"ips_{datetime.utcnow().strftime('%Y-%m-%d')}.csv"
    with open(snap, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def main():
    if not Path(INPUT).exists():
        print(f"ERROR: {INPUT} no existe.")
        sys.exit(1)

    master = read_master(INPUT)
    total = len(master)
    state = load_state()
    last = int(state.get("last_index", 0))
    start = last
    end = min(start + BATCH_SIZE, total)
    if start >= total:
        # ciclo terminado -> reiniciar a 0 para re-check continuo
        start = 0
        end = min(BATCH_SIZE, total)

    batch = master[start:end]
    print(f"Total IPs: {total}. Procesando índice {start}..{end-1} ({len(batch)} IPs).")

    # load previously validated if exists, to preserve older rows
    existing = {}
    if Path(OUTPUT).exists():
        with open(OUTPUT, newline="") as f:
            reader = csv.DictReader(f)
            for r in reader:
                existing[r["ip"]] = r

    feeds = load_feeds()
    feeds_ips = fetch_feeds(feeds) if feeds else set()
    print(f"Feeds cargados: {len(feeds)} urls. IPs en feeds: {len(feeds_ips)}")

    new_rows = []
    abuse_queries = 0

    for item in batch:
        ip = item.get("ip") if isinstance(item, dict) else item
        ip = ip.strip()
        if not ip:
            continue

        last_checked = datetime.utcnow().isoformat()
        sources = []
        evidence = []

        # check feeds membership first (no API cost)
        if ip in feeds_ips:
            sources.append("public_feeds")
            evidence.append("found_in_feed")

        # AbuseIPDB query if we still under safe limit
        abuse_res = None
        if ABUSE_KEY and abuse_queries < DAILY_SAFE_LIMIT:
            abuse_res = safe_request_abuse(ip)
            abuse_queries += 1
            # gentle pause to avoid bursts (very small)
            time.sleep(0.5)
            if abuse_res.get("ok"):
                data = abuse_res["data"]
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                sources.append("AbuseIPDB")
                evidence.append(f"AbuseScore={score};reports={reports}")
                # if score >= 50 mark malicious
            else:
                # handle rate limit: if we got rate_limited, break loop early
                if abuse_res.get("error") == "rate_limited":
                    print("Rate limited por AbuseIPDB, deteniendo consultas API por seguridad.")
                    # stop further abuse queries this run
                    ABUSE_STOP = True
                    # continue but do not query further
                    ABUSE_KEY_local = None
                    # we set abuse_queries to limit to avoid further queries
                    abuse_queries = DAILY_SAFE_LIMIT
                else:
                    # log error in evidence
                    evidence.append(f"AbuseErr={abuse_res.get('error')}")
        else:
            if not ABUSE_KEY:
                evidence.append("NoAbuseKey")
            else:
                evidence.append("AbuseLimitReachedForRun")

        # Decide status
        status = "unknown"
        # If any strong indicator:
        malicious_flag = False
        # from abuse score
        if abuse_res and abuse_res.get("ok"):
            s = abuse_res["data"].get("abuseConfidenceScore", 0)
            if s and int(s) >= 50:
                malicious_flag = True
        # from feeds presence
        if ip in feeds_ips:
            malicious_flag = True

        if malicious_flag:
            status = "malicious"
        else:
            # fallback: if any evidence but not malicious -> unknown, else clean
            if evidence:
                # if only evidence are errors or "NoAbuseKey", mark unknown
                status = "unknown"
            else:
                status = "clean"

        row = {
            "ip": ip,
            "last_checked": last_checked,
            "status": status,
            "sources": ",".join(sources) if sources else "",
            "evidence": "; ".join(evidence) if evidence else ""
        }
        # keep previous notes if existed
        if ip in existing:
            # prefer latest last_checked but keep previous evidence?
            pass
        new_rows.append(row)

    # Merge new_rows with existing rows (replace entries for processed IPs)
    merged = {r["ip"]: r for r in existing.values()}
    for r in new_rows:
        merged[r["ip"]] = r

    # For IPs never touched, keep existing; then write sorted by ip
    out_list = sorted(merged.values(), key=lambda x: x["ip"])
    write_outputs(out_list)

    # update state
    state["last_index"] = end
    save_state(state)
    print(f"Terminado batch. Abuse queries this run: {abuse_queries}. Estado guardado: last_index={end}")

if __name__ == "__main__":
    main()

