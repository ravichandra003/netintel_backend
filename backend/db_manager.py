from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from report_generator import generate_pdf

DB_ROOT = Path(__file__).resolve().parent / ".intelligence_db"


def _ensure():
    for d in ["raw/sessions", "ipv4", "ipv6", "domains", "emails", "hashes", "urls", "metadata"]:
        (DB_ROOT / d).mkdir(parents=True, exist_ok=True)
    DB_ROOT.chmod(0o700)


def write_ioc(validation_result: dict) -> None:
    _ensure()
    all_path = DB_ROOT / "raw/all_iocs.json"
    rows = json.loads(all_path.read_text()) if all_path.exists() else []
    rows.append(validation_result)
    all_path.write_text(json.dumps(rows, indent=2))


def read_category(ioc_type: str, category: str) -> list[str]:
    p = DB_ROOT / ioc_type / f"{category}.txt"
    if not p.exists(): return []
    return [ln.split("|")[0] for ln in p.read_text().splitlines() if ln and not ln.startswith("#")]


def get_stats() -> dict:
    _ensure(); stats = {}
    for t in ["ipv4", "ipv6", "domains", "emails", "hashes", "urls", "metadata"]:
        stats[t] = {}
        for f in (DB_ROOT / t).glob("*.txt"):
            stats[t][f.stem] = len(read_category(t, f.stem))
    return stats


def search_ioc(value: str):
    hist = get_history(value)
    return hist[-1] if hist else None


def get_history(ioc_value: str) -> list[dict]:
    all_path = DB_ROOT / "raw/all_iocs.json"
    if not all_path.exists(): return []
    return [r for r in json.loads(all_path.read_text()) if r.get("value", "").lower() == ioc_value.lower()]


def get_session(session_id: str) -> dict:
    p = DB_ROOT / "raw/sessions" / f"{session_id}.json"
    return json.loads(p.read_text()) if p.exists() else {}


def export_report(session_id: str, format: str) -> bytes:
    session = get_session(session_id)
    if format == "json":
        return json.dumps(session, indent=2).encode()
    if format == "csv":
        out = []
        for i in session.get("iocs", []):
            out.append([i.get("type"), i.get("value"), i.get("risk_score"), i.get("classification")])
        from io import StringIO
        s = StringIO(); w = csv.writer(s); w.writerow(["type","value","risk_score","classification"]); w.writerows(out)
        return s.getvalue().encode()
    return generate_pdf(session)
