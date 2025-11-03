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
INPUT = "ips_master.csv"          # Tu lista de IPs (una por línea)
STATE_FILE = "state.json"
OUTPUT = "ips_validated.csv"
HISTORY_DIR = "ips_history"
FEEDS_FILE = "feeds.txt"          # opcional: urls de feeds públicas
DAILY_SAFE_LIMIT = int(os.getenv("DAILY_SAFE_LIMIT", str(BATCH_SIZE - 50)))
HEADERS_ABUSE = {"Key": ABUSE_KEY, "Accept": "application/json"}

# ---------- Funciones auxiliares ----------

def read_master(path):
    """Lee lista de IPs, ya sea CSV o texto plano."""
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip:
                rows.append(ip)
    return rows

def load_state():
    """Carga el índice del último lote procesado."""
    if not Path(STATE_FILE).exists():
        return {"last_index": 0}
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except json.JSONDecodeError:
        # Si está vacío o corrupto, reiniciar
        return {"last_index": 0}

def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)

def safe_request_abuse(ip, max_retries=3):
    """Consulta AbuseIPDB con manejo de errores y reintentos."""
    if not ABUSE_KEY:
        return {"error": "no_key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    for attempt in range(1, max_retries + 1):
        try:
            r = requests.get(url, headers=HEADERS_ABUSE, params=params, timeout=20)
            if r.status_code == 200:
                return {"ok": True, "data": r.json().get("data", {})}
            elif r.status_code in (401, 403):
                return {"error": f"auth_{r.status_code}"}
            elif r.status_code == 429:
                return {"error": "rate_limited"}
            else:
                time.sleep(2 * attempt)
        except requests.RequestException:
            time.sleep(2 * attempt)
    return {"error": "request_failed"}

def load_feeds():
    """Carga URLs desde feeds.txt."""
    feeds = []
    if not Path(FEEDS_FILE).exists():
        return feeds
    with open(FEEDS_FILE) as f:
        for line in f:
            u = line.strip()
            if u:
                feeds.append(u)
    return feeds

def fetch_feeds(feeds):
    """Descarga feeds públicos y devuelve IPs encontradas."""
    ips = set()
    for url in feeds:
        try:
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    candidate = parts[0]
                    if 7 <= len(candidate) <= 45:
                        ips.add(candidate)
        except Exception:
            continue
    return ips

def write_outputs(rows):
    """Guarda resultados actualizados y crea snapshot diario."""
    fieldnames = ["ip", "last_checked", "status", "sources", "evidence"]
    Path(HISTORY_DIR).mkdir(exist_ok=True)
    with open(OUTPUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    snap = Path(HISTORY_DIR) / f"ips_{datetime.utcnow().strftime('%Y-%m-%d')}.csv"
    with open(snap, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

# ---------- Función principal ----------

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
        start = 0
        end = min(BATCH_SIZE, total)

    batch = master[start:end]
    print(f"Total IPs: {total}. Procesando índice {start}..{end-1} ({len(batch)} IPs).")

    existing = {}
    if Path(OUTPUT).exists():
        with open(OUTPUT, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                existing[r["ip"]] = r

    feeds = load_feeds()
    feeds_ips = fetch_feeds(feeds) if feeds else set()
    print(f"Feeds cargados: {len(feeds)} urls. IPs en feeds: {len(feeds_ips)}")

    new_rows = []
    abuse_queries = 0

    for item in batch:
        ip = str(item).strip()
        if not ip:
            continue

        last_checked = datetime.utcnow().isoformat()
        sources, evidence = [], []

        # 1️⃣ Validación en feeds públicos
        if ip in feeds_ips:
            sources.append("public_feeds")
            evidence.append("found_in_feed")

        # 2️⃣ Consulta a AbuseIPDB
        abuse_res = None
        if ABUSE_KEY and abuse_queries < DAILY_SAFE_LIMIT:
            abuse_res = safe_request_abuse(ip)
            abuse_queries += 1
            time.sleep(0.5)

            if abuse_res.get("ok"):
                data = abuse_res["data"]
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                sources.append("AbuseIPDB")
                evidence.append(f"AbuseScore={score};reports={reports}")
            else:
                if abuse_res.get("error") == "rate_limited":
                    print("Rate limited por AbuseIPDB, deteniendo consultas API por seguridad.")
                    abuse_queries = DAILY_SAFE_LIMIT
                else:
                    evidence.append(f"AbuseErr={abuse_res.get('error')}")
        else:
            evidence.append("NoAbuseKey" if not ABUSE_KEY else "AbuseLimitReachedForRun")

        # 3️⃣ Determinación de estado
        status = "unknown"
        malicious_flag = False

        if abuse_res and abuse_res.get("ok"):
            s = abuse_res["data"].get("abuseConfidenceScore", 0)
            if s and int(s) >= 50:
                malicious_flag = True
        if ip in feeds_ips:
            malicious_flag = True

        if malicious_flag:
            status = "malicious"
        elif evidence:
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
        new_rows.append(row)

    # 4️⃣ Combinar con resultados previos
    merged = {r["ip"]: r for r in existing.values()}
    for r in new_rows:
        merged[r["ip"]] = r
    out_list = sorted(merged.values(), key=lambda x: x["ip"])
    write_outputs(out_list)

    # 5️⃣ Actualizar estado
    state["last_index"] = end
    save_state(state)
    print(f"Terminado batch. Abuse queries this run: {abuse_queries}. Estado guardado: last_index={end}")

# ---------- Entrypoint ----------
if __name__ == "__main__":
    main()
