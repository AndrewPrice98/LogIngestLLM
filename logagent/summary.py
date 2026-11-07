"""Whole-log summary: a compact digest of everything collected (the model never sees the raw log),
the OS the log came from vs the OS the user is on, and a rules-only fallback summary."""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone

from .collectors.sources import _files, detect_format
from .model import Event

SEV_BAD = {"emerg", "alert", "crit", "err"}

# (os, detail, regex) evidence in messages/programs; weights add up per event sampled
_HINTS = [
    ("Windows", None, re.compile(r"[A-Za-z]:\\|\.exe\b|\bHKLM\\|\bsvchost\b|Service Control Manager|\bWin32\b|\bNTFS\b", re.I)),
    ("Linux", None, re.compile(r"\bsystemd\b|\.service\b|NetworkManager|\b(apt|dnf|yum|pacman)\b|/usr/|/etc/|/var/|"
                               r"\bdbus-daemon\b|\bselinux\b|\bkernel: ", re.I)),
    ("macOS", None, re.compile(r"\bcom\.apple\.|\blaunchd\b|/Library/|/Users/|\bkernel\[0\]|\bmdworker\b")),
    ("Linux", "Raspberry Pi OS", re.compile(r"vcgencmd|Undervoltage|raspberrypi|bcm2835|brcmfmac|mmcblk0", re.I)),
    ("Linux", "NVIDIA Jetson (L4T)", re.compile(r"\bnvgpu\b|\btegra\b|jetson|nvpmodel", re.I)),
]
_PROGRAM_OS = {"kernel": "Linux", "systemd": "Linux", "sshd": "Linux", "sudo": "Linux", "cron": "Linux",
               "CRON": "Linux", "NetworkManager": "Linux", "launchd": "macOS"}


def guess_origin(sources: list[dict], events: list[Event]) -> dict:
    """Which OS produced these logs: from the source types, then message/program evidence."""
    votes: Counter = Counter()
    details: Counter = Counter()
    evidence: list[str] = []
    for s in sources:
        t = s.get("type")
        if t in ("windows", "evtx"):
            votes["Windows"] += 50
            evidence.append(f"{t} source")
        elif t == "journald":
            votes["Linux"] += 50
            evidence.append("systemd journal")
    step = max(1, len(events) // 2000)
    for e in events[::step]:
        if e.source.startswith("windows:"):
            votes["Windows"] += 1
        elif e.source == "journald":
            votes["Linux"] += 1
        if e.program in _PROGRAM_OS:
            votes[_PROGRAM_OS[e.program]] += 1
        text = e.message[:400]
        for os_name, detail, rx in _HINTS:
            if rx.search(text):
                votes[os_name] += 1
                if detail:
                    details[detail] += 3
    for h in {e.host.lower() for e in events[::step]}:
        if "raspberrypi" in h:
            details["Raspberry Pi OS"] += 5
        if "jetson" in h:
            details["NVIDIA Jetson (L4T)"] += 5
    if not votes:
        return {"os": "unknown", "detail": "", "confidence": "none", "evidence": evidence}
    (top, n), total = votes.most_common(1)[0], sum(votes.values())
    detail = next((d for d, k in details.most_common() if d and k >= 3), "") if top == "Linux" else ""
    conf = "high" if n >= 20 and n / total >= 0.8 else "medium" if n / total >= 0.6 else "low"
    evidence += [f"{k}: {v} hints" for k, v in votes.most_common(3)]
    return {"os": top if conf != "low" or n >= 5 else "unknown", "detail": detail, "confidence": conf,
            "evidence": evidence[:6]}


# fields worth naming in a summary line (Windows event data); given to the model separately so they stand out
KEY_FIELDS = ("ServiceName", "TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName", "CommandLine",
              "NewProcessName", "ImagePath", "TaskName", "ShareName", "MemberName", "TicketEncryptionType", "LogonType",
              "Status", "SubStatus", "TargetImage", "TargetObject", "DestinationIp")


def _details(c: dict) -> dict:
    f = c.get("fields") or {}
    return {k: str(f[k])[:160] for k in KEY_FIELDS if f.get(k) not in (None, "", "-")}


def _utc(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (TypeError, ValueError):
        return str(iso)[:19]


def _bucket(ts: datetime, daily: bool) -> str:
    t = ts.astimezone(timezone.utc)
    return t.strftime("%Y-%m-%d") if daily else t.strftime("%Y-%m-%d %H:00Z")


def build_digest(sources: list[dict], events: list[Event], clusters: list[dict], analysis: dict,
                 viewer: dict, origin: dict) -> dict:
    files = []
    for s in sources:
        if s.get("path"):
            for f in _files(s["path"])[:12]:
                try:
                    files.append({"file": f, "format": s.get("format") or detect_format(f)})
                except OSError:
                    files.append({"file": f, "format": "?"})
    ts = sorted(e.ts for e in events)
    span_s = (ts[-1] - ts[0]).total_seconds() if ts else 0
    daily = span_s > 3 * 86400
    tl_all: Counter = Counter()
    tl_bad: Counter = Counter()
    for e in events:
        b = _bucket(e.ts, daily)
        tl_all[b] += 1
        if e.severity_name in SEV_BAD:
            tl_bad[b] += 1
    timeline = sorted(tl_all)
    if len(timeline) > 48:  # keep the busiest buckets, in time order
        keep = {b for b, _ in tl_all.most_common(48)}
        timeline = [b for b in timeline if b in keep]
    by_count = sorted(clusters, key=lambda c: c["count"], reverse=True)
    byk = {c["key"]: c for c in clusters}
    ranked, refs = [], {}
    for f in (analysis.get("findings") or [])[:10]:
        c = next((byk[k] for k in f.get("keys", []) if k in byk), None)
        cite = None
        if c and (c.get("sample_locs") or [None])[0]:
            cite = f"E{len(refs) + 1}"
            refs[cite] = f"c/{c['key']}/0"
        ranked.append({"cite": cite, "importance": f.get("importance"), "title": f.get("title"), "why": (f.get("why") or "")[:300],
                       **({"count": c["count"], "first": _utc(c["first"]), "last": _utc(c["last"]), "program": c["program"],
                           "details": _details(c),
                           "sample": c["samples"][0][:300]} if c else {})})
    errors = [c for c in by_count if c["severity"] in SEV_BAD][:8]
    utc_s = lambda t: t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return {
        "viewer_os": viewer.get("pretty") or viewer.get("os"),
        "origin_os": origin.get("os"), "origin_detail": origin.get("detail"),
        "origin_confidence": origin.get("confidence"), "origin_evidence": origin.get("evidence"),
        "sources": [{k: s[k] for k in ("name", "type", "path", "channels", "units") if s.get(k)}
                    for s in sources],
        "files": files[:12],
        "events": len(events), "first_utc": utc_s(ts[0]) if ts else None,
        "last_utc": utc_s(ts[-1]) if ts else None,
        "hosts": sorted({e.host for e in events})[:10],
        "by_severity": dict(Counter(e.severity_name for e in events)),
        "top_programs": dict(Counter(e.program or e.source for e in events).most_common(10)),
        "timeline": [{"t": b, "events": tl_all[b], "errors": tl_bad[b]} for b in timeline],
        "frequent_patterns": [{"count": c["count"], "severity": c["severity"], "program": c["program"],
                               "pattern": c["template"][:200]} for c in by_count[:12]],
        "ranked_findings": ranked,
        "error_patterns": [{"count": c["count"], "program": c["program"], "first": _utc(c["first"]),
                            "last": _utc(c["last"]), "sample": c["samples"][0][:300]} for c in errors],
        "_refs": refs,
    }


def heuristic_summary(d: dict) -> str:
    """Readable summary from the digest alone, for rules-only mode or when the model is down."""
    if not d["events"]:
        return "WHAT: no events in the selected window.\nHEALTH: unknown - nothing to read."
    where = ", ".join(f["file"].replace("\\", "/").rsplit("/", 1)[-1] for f in d["files"][:3]) or \
        ", ".join(s["name"] for s in d["sources"][:3])
    origin = d["origin_os"] if d["origin_os"] != "unknown" else "unknown OS"
    if d.get("origin_detail"):
        origin += f" ({d['origin_detail']})"
    imps = [f.get("importance") for f in d["ranked_findings"]]
    health = ("critical" if "critical" in imps else "needs attention" if "high" in imps else
              "minor issues" if imps else "healthy")
    lines = [f"WHAT: {d['events']} events from {where}, {d['first_utc']}Z to {d['last_utc']}Z; produced by {origin}.",
             f"HEALTH: {health} - " + (f"top item: {d['ranked_findings'][0]['title']}" if imps else
                                       "no pattern scored above the threshold")]
    if d["ranked_findings"]:
        lines.append("KEY EVENTS:")
        for f in d["ranked_findings"][:6]:
            when = f"{f.get('first', '?')}Z" + (f"..{f['last']}Z" if f.get("last") and f.get("last") != f.get("first") else "")
            lines.append(f"- {when}: [{f['importance']}] {f['title']}" + (f" ({f['count']}x)" if f.get("count") else "") +
                         (f" [{f['cite']}]" if f.get("cite") else ""))
    risky = [t for t in d.get("tools_seen", []) if t["category"] in ("attacker", "miner", "lolbin", "tunnel")]
    if risky:
        lines.append("TOOLS: " + "; ".join(f"{t['tool']} ({t['uses']}x)" + (f" [{t['cite']}]" if t.get("cite") else "")
                                         for t in risky[:6]))
    if d["frequent_patterns"]:
        p = d["frequent_patterns"][0]
        lines.append(f"NOISE: {p['count'] * 100 // max(1, d['events'])}% of events are \"{p['pattern'][:100]}\" "
                     f"from {p['program'] or 'unknown program'}.")
    if d["origin_os"] != "unknown" and d["viewer_os"] and d["origin_os"].split()[0] not in d["viewer_os"]:
        lines.append(f"NOTE: this log came from {origin}; you are on {d['viewer_os']}, so run any fix on that machine.")
    return "\n".join(lines)
