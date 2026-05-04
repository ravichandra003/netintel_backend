from __future__ import annotations

import ipaddress
import time

from dns_resolver import query
from network_checks import fetch_geoip, scan_ports, tcp_ping

SUSPICIOUS = {23: "telnet", 445: "smb", 3389: "rdp"}
PORTS = [21,22,23,25,53,80,110,143,443,445,587,993,995,1433,3306,3389,5432,8080,8443]


def validate(ioc: dict) -> dict:
    start = time.perf_counter()
    value = ioc["value"]
    out = {"ioc_id": ioc["ioc_id"], "type": ioc["type"], "value": value, "risk_factors": []}
    try:
        ip = ipaddress.ip_address(value)
        if ip.is_private:
            out.update({"risk_score": 0, "classification": "internal", "validation_time_ms": 0})
            return out
        out["ping"] = tcp_ping(value)
        ports = scan_ports(value, PORTS)
        out["ports"] = ports
        out["suspicious_ports"] = [f"{p}:{SUSPICIOUS[p]}" for p, s in ports.items() if p in SUSPICIOUS and s == "open"]
        rev = ".".join(reversed(value.split("."))) + ".in-addr.arpa" if ioc["type"] == "IPv4" else ""
        ptr = query(rev, "PTR") if rev else []
        out["ptr"] = {"record": ptr[0] if ptr else None, "status": "present" if ptr else "absent"}
        geo = fetch_geoip(value)
        out["geo"] = geo
        rep = {}
        for name, zone in {"spamhaus":"zen.spamhaus.org", "sorbs":"dnsbl.sorbs.net", "barracuda":"b.barracudacentral.org", "spamcop":"bl.spamcop.net"}.items():
            listed = bool(query(f"{'.'.join(reversed(value.split('.')))}.{zone}", "A")) if ioc["type"] == "IPv4" else False
            rep[name] = {"listed": listed}
        rep["any_listed"] = any(v.get("listed") for v in rep.values())
        out["reputation"] = rep
        score = 0
        if rep["any_listed"]:
            score += 40 * sum(1 for v in rep.values() if isinstance(v, dict) and v.get("listed"))
            out["risk_factors"].append("Blacklist hit")
        score += 15 * len(out["suspicious_ports"])
        if out["ptr"]["status"] == "absent":
            score += 10
        if geo.get("org") and any(k in geo.get("org", "").lower() for k in ["amazon", "google", "azure", "digitalocean", "ovh", "linode", "vultr"]):
            score += 20
            out["cloud_hosted"] = True
        else:
            out["cloud_hosted"] = False
        out["risk_score"] = min(100, score)
        out["classification"] = "malicious" if score >= 70 else "suspicious" if score >= 40 else "clean"
    except Exception as exc:
        out["error"] = str(exc)
        out["status"] = "check_failed"
    out["validation_time_ms"] = int((time.perf_counter() - start) * 1000)
    return out
