from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import db_manager
import extractor
import validate_domain
import validate_email
import validate_ip


def analyze(input_data, session_id=None) -> dict:
    session_id = session_id or str(uuid.uuid4())
    raw = extractor.extract(input_data)
    results = []

    def run(ioc):
        if ioc["type"] in {"IPv4", "IPv6"}:
            return {**ioc, **validate_ip.validate(ioc)}
        if ioc["type"] == "Email":
            return {**ioc, **validate_email.validate(ioc)}
        if ioc["type"] == "Domain":
            return {**ioc, **validate_domain.validate(ioc)}
        return {**ioc, "classification": "clean", "risk_score": 0}

    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(run, raw):
            results.append(r)
            db_manager.write_ioc(r)

    session = {"session_id": session_id, "created_at": datetime.now(timezone.utc).isoformat(), "iocs": results, "stats": db_manager.get_stats()}
    sp = db_manager.DB_ROOT / "raw/sessions" / f"{session_id}.json"
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text(__import__("json").dumps(session, indent=2))
    return session
