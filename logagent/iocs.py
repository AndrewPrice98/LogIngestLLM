"""Indicators (IOCs) in log events: IPs, domains, URLs, emails, file hashes and user names.

Extracted from every event at scan time, so counts are exact and each indicator knows which patterns (cluster
keys) it appears in. Older scans that predate this are rebuilt from their stored samples, marked approximate.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter

_IPV4 = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.]|\.\d)")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,7}(?::|(?::[0-9A-Fa-f]{1,4}){1,6}|[0-9A-Fa-f]{1,4})(?![\w:])")
_URL = re.compile(r"\bhttps?://[^\s\"'<>()\[\]{}|\\^`]+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_DOMAIN = re.compile(r"(?<![\w@/\\.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))(?![\w-]|\.[A-Za-z0-9])")
_HASH = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_USER_RX = [
    re.compile(r"\bfor (?:invalid user )?([\w.@$-]{1,64}) from\b"),
    re.compile(r"\bInvalid user ([\w.@$-]{1,64}) from\b"),
    re.compile(r"\bsession (?:opened|closed) for user ([\w.@$-]{1,64})"),
    re.compile(r"\bsudo(?:\[\d+\])?: +([\w.-]{1,64}) :"),
    re.compile(r"\b(?:ruser|user)=([\w.@$-]{1,64})"),
    re.compile(r"\bnew user: name=([\w.-]{1,64})"),
]
_USER_FIELDS = ("TargetUserName", "SubjectUserName", "AccountName", "SamAccountName", "user", "USER", "username")
_IGNORED_USERS = {"-", "", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "null", "none", "unknown"}

# Real TLDs common in logs. File extensions that are also TLDs (.sh .py .so .rs .pl .md .ps .pm .in) are left
# out on purpose: in logs they are nearly always file names.
_TLDS = set("""com net org edu gov mil int io co ai app dev cloud info biz me tv us uk de fr nl be es it pl ru ua cn jp kr
in au ca br mx ar ch at se no dk fi ie pt cz sk hu ro bg gr tr il ir za ng ke eg sa ae sg hk tw vn th id my ph nz cl
pe xyz top online site club live tech store shop link click space website one pro ly gg cc ws to su su local lan
internal home arpa onion""".split()) - {"in", "id", "me", "pro"}


_PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                                    "fc00::/7")]


def _ip_scope(v: str) -> str:
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return ""
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_global:
        return "public"
    if any(ip in n for n in _PRIVATE_NETS if n.version == ip.version):
        return "private"
    return "reserved"  # documentation, multicast, unspecified, benchmarking...


def extract(text: str, fields: dict | None = None) -> list[tuple[str, str, str]]:
    """(type, value, scope) found in one message and its structured fields."""
    out: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind, value, scope=""):
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append((kind, value, scope))

    text = text[:4000]
    if fields:
        for k in ("IpAddress", "SourceAddress", "DestAddress", "SourceIp", "DestinationIp", "ClientAddress"):
            v = str(fields.get(k, "")).strip()
            if v and v not in ("-", "::1", "127.0.0.1") and _ip_scope(v):
                add("ip", v, _ip_scope(v))
        for k in _USER_FIELDS:
            v = str(fields.get(k, "")).strip()
            if v and v not in _IGNORED_USERS and not v.endswith("$") and len(v) <= 64:
                add("user", v)
        for k in ("Hashes", "Hash", "sha256", "md5"):
            for h in _HASH.findall(str(fields.get(k, ""))):
                add("hash", h.lower(), {32: "md5", 40: "sha1", 64: "sha256"}[len(h)])
    for m in _URL.finditer(text):
        url = m.group(0).rstrip(".,;:")
        add("url", url)
    stripped = _URL.sub(" ", text)
    for m in _EMAIL.finditer(stripped):
        tld = m.group(0).rsplit(".", 1)[-1].lower()
        if tld in _TLDS:
            add("email", m.group(0).lower())
    for v in _IPV4.findall(stripped):
        add("ip", v, _ip_scope(v))
    for m in _IPV6.finditer(stripped):
        v = m.group(0)
        if v.count(":") >= 2 and ("::" in v or any(c.isalpha() for c in v)) and _ip_scope(v):
            add("ip", v.lower(), _ip_scope(v))
    no_email = _EMAIL.sub(" ", stripped)
    for m in _DOMAIN.finditer(no_email):
        name, tld = m.group(1).lower(), m.group(2).lower()
        if tld in _TLDS and not _IPV4.fullmatch(name) and name.count(".") >= 1:
            add("domain", name)
    for h in _HASH.findall(stripped):
        hl = h.lower()
        if not h.isdigit() and not (len(hl) == 32 and hl[12] == "4" and hl[16] in "89ab"):  # skip dashless UUIDv4
            add("hash", hl, {32: "md5", 40: "sha1", 64: "sha256"}[len(h)])
    for rx in _USER_RX:
        for v in rx.findall(text):
            if v not in _IGNORED_USERS:
                add("user", v)
    return out


class Collector:
    """Aggregates indicators over a scan."""

    def __init__(self):
        self.data: dict[tuple[str, str], dict] = {}

    def add(self, text: str, fields: dict | None, key: str, host: str, ts) -> None:
        for kind, value, scope in extract(text, fields):
            d = self.data.get((kind, value))
            if d is None:
                d = self.data[(kind, value)] = {"type": kind, "value": value, "scope": scope, "count": 0,
                                                "first": ts, "last": ts, "hosts": set(), "keys": Counter()}
            d["count"] += 1
            d["first"] = min(d["first"], ts)
            d["last"] = max(d["last"], ts)
            d["hosts"].add(host)
            d["keys"][key] += 1

    def result(self, limit: int = 1000) -> list[dict]:
        order = {"ip": 0, "domain": 1, "url": 2, "email": 3, "hash": 4, "user": 5}
        rows = sorted(self.data.values(), key=lambda d: (order.get(d["type"], 9), -d["count"], d["value"]))[:limit]
        return [{"type": d["type"], "value": d["value"], "scope": d["scope"], "count": d["count"],
                 "first": d["first"].isoformat(), "last": d["last"].isoformat(), "hosts": sorted(d["hosts"])[:20],
                 "keys": [k for k, _ in d["keys"].most_common(50)]} for d in rows]


def from_clusters(clusters: list[dict]) -> list[dict]:
    """Approximate indicators for scans saved before extraction existed: samples + fields only."""
    from datetime import datetime
    col = Collector()
    for c in clusters:
        first = datetime.fromisoformat(c["first"])
        for s in c.get("samples", []):
            col.add(s, c.get("fields"), c["key"], c["host"], first)
    rows = col.result()
    for r in rows:
        r["approx"] = True
    return rows
