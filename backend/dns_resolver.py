"""Raw DNS resolver using UDP sockets (no dnspython)."""
from __future__ import annotations

import random
import socket
import struct
from typing import List

DNS_SERVER = ("8.8.8.8", 53)

QTYPE = {"A": 1, "NS": 2, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}


def _encode_name(name: str) -> bytes:
    parts = name.strip(".").split(".")
    return b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    jump_offset = offset
    while True:
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", packet[offset: offset + 2])[0] & 0x3FFF
            if not jumped:
                jump_offset = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(packet[offset: offset + length].decode(errors="ignore"))
        offset += length
    return ".".join(labels), (jump_offset if jumped else offset)


def query(name: str, record_type: str, timeout: float = 3.0) -> List[str]:
    qtype = QTYPE.get(record_type.upper())
    if not qtype:
        return []
    txid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, 1)
    message = header + question
    for _ in range(2):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(message, DNS_SERVER)
                data, _ = sock.recvfrom(4096)
            if struct.unpack("!H", data[:2])[0] != txid:
                continue
            _, _, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
            off = 12
            for _ in range(qd):
                _, off = _read_name(data, off)
                off += 4
            out: List[str] = []
            for _ in range(an):
                _, off = _read_name(data, off)
                typ, _, _, rdlen = struct.unpack("!HHIH", data[off: off + 10])
                off += 10
                rdata = data[off: off + rdlen]
                off += rdlen
                if typ == 1 and qtype == 1:
                    out.append(socket.inet_ntoa(rdata))
                elif typ == 28 and qtype == 28:
                    out.append(socket.inet_ntop(socket.AF_INET6, rdata))
                elif typ in (2, 12):
                    val, _ = _read_name(data, off - rdlen)
                    out.append(val)
                elif typ == 15:
                    pref = struct.unpack("!H", rdata[:2])[0]
                    val, _ = _read_name(data, off - rdlen + 2)
                    out.append(f"{pref} {val}")
                elif typ == 16:
                    ln = rdata[0]
                    out.append(rdata[1:1 + ln].decode(errors="ignore"))
            return out
        except Exception:
            continue
    return []
