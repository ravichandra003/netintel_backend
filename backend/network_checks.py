from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests


def tcp_ping(ip: str, ports=(80, 443, 22), timeout=1.5):
    def check(port: int):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True, (time.perf_counter() - start) * 1000, f"TCP:{port}"
        except TimeoutError:
            return None, None, f"TCP:{port}"
        except Exception:
            return False, None, f"TCP:{port}"

    with ThreadPoolExecutor(max_workers=len(ports)) as ex:
        for alive, rtt, method in ex.map(check, ports):
            if alive:
                return {"alive": True, "rtt_ms": round(rtt, 2), "method": method}
    return {"alive": False, "rtt_ms": None, "method": "TCP"}


def scan_ports(host: str, ports: list[int], timeout=1.0):
    def probe(port: int):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port, "open"
        except TimeoutError:
            return port, "filtered"
        except Exception:
            return port, "closed"

    with ThreadPoolExecutor(max_workers=min(20, len(ports))) as ex:
        return dict(ex.map(probe, ports))


def fetch_geoip(ip: str):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=4)
        data = r.json()
        return {
            "city": data.get("city"), "country": data.get("country"), "country_code": data.get("countryCode"),
            "isp": data.get("isp"), "org": data.get("org"), "asn": data.get("as"), "lat": data.get("lat"),
            "lon": data.get("lon"), "timezone": data.get("timezone"),
        }
    except Exception as exc:
        return {"error": str(exc), "status": "check_failed"}


def ssl_details(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expiry - datetime.now(timezone.utc)).days
        return {"supported": True, "issuer": str(cert.get("issuer")), "expires": expiry.isoformat(), "days_remaining": days,
                "san": [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"], "self_signed": False,
                "expired": days < 0, "grade": "B"}
    except Exception as exc:
        return {"supported": False, "error": str(exc), "status": "check_failed"}


def ip_is_private(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except Exception:
        return False
