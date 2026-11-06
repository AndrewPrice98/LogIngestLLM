"""'Explain this event': a deterministic, field-by-field breakdown of one log pattern for people learning to read
logs, plus the native commands that would show the same events ('check it yourself') for the OS it came from."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from . import knowledge as K
from .iocs import _ip_scope

WELL_KNOWN_PORTS = {"22": "SSH", "21": "FTP", "23": "Telnet", "25": "SMTP", "53": "DNS", "80": "HTTP", "443": "HTTPS",
                    "445": "SMB (Windows file sharing)", "135": "RPC", "139": "NetBIOS", "3389": "RDP (Remote Desktop)",
                    "5985": "WinRM", "5986": "WinRM over HTTPS", "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
                    "8080": "HTTP (alt)", "1433": "MS SQL"}

_TOKENS = [  # (kind, regex) in priority order; first match at a position wins
    ("url", re.compile(r"https?://[^\s\"'<>]+")),
    ("ip", re.compile(r"(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]*[0-9a-fA-F](?![\w:])")),
    ("port", re.compile(r"(?<=\bport )\d{1,5}\b|(?<=\bDPT=)\d{1,5}|(?<=\bSPT=)\d{1,5}")),
    ("user", re.compile(r"(?<=\bfor invalid user )[\w.@$-]+|(?<=\bInvalid user )[\w.@$-]+|(?<=\bfor )[\w.@$-]+(?= from\b)|"
                        r"(?<=\bfor user )[\w.@$-]+|(?<=\buser=)[\w.@$-]+|(?<=\bruser=)[\w.@$-]+")),
    ("code", re.compile(r"\b0x[0-9a-fA-F]+\b")),
    ("pid", re.compile(r"(?<=\[)\d+(?=\])|(?<=\bpid[= ])\d+|(?<=\bprocess )\d+")),
    ("path", re.compile(r"(?:[A-Za-z]:\\|/)(?:[\w.$@+-]+[\\/])*[\w.$@+-]+")),
    ("time", re.compile(r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?\b|\b\d\d:\d\d:\d\d\b")),
    ("number", re.compile(r"\b\d+(?:\.\d+)?\b")),
]


def _token_note(kind: str, text: str) -> str:
    if kind == "ip":
        scope = _ip_scope(text)
        return {"public": "public IP address: a machine on the internet", "private": "private IP: a machine on a local network",
                "loopback": "loopback: this same machine", "link-local": "link-local: same network segment, no router",
                "reserved": "reserved/documentation range"}.get(scope, "IP address")
    if kind == "port":
        return f"network port {text}" + (f" = {WELL_KNOWN_PORTS[text]}" if text in WELL_KNOWN_PORTS else
                                         " (a high number on the client side is just a temporary source port)")
    if kind == "user":
        return "user name involved in this event"
    if kind == "code":
        low = text.lower()
        return K.STATUS_CODES.get(low) or K.KERBEROS_ENC.get(low) or "hexadecimal code (flags, status or address)"
    if kind == "pid":
        return "process id: identifies the running program instance"
    if kind == "path":
        return "file or folder path"
    if kind == "time":
        return "timestamp inside the message"
    if kind == "url":
        return "web address the program connected to or logged"
    return ""


def segments(message: str) -> list[dict]:
    """Split a message into plain text and annotated tokens, for highlighting."""
    msg = message[:1500]
    spans: list[tuple[int, int, str]] = []
    taken = [False] * len(msg)
    for kind, rx in _TOKENS:
        for m in rx.finditer(msg):
            a, b = m.span()
            if a == b or any(taken[a:b]):
                continue
            if kind == "number" and len(m.group(0)) < 2:
                continue
            spans.append((a, b, kind))
            for i in range(a, b):
                taken[i] = True
    out, pos = [], 0
    for a, b, kind in sorted(spans):
        if a > pos:
            out.append({"t": msg[pos:a]})
        if kind == "number":
            out.append({"t": msg[a:b]})
        else:
            out.append({"t": msg[a:b], "kind": kind, "note": _token_note(kind, msg[a:b])})
        pos = b
    if pos < len(msg):
        out.append({"t": msg[pos:]})
    return out


def _source_note(source: str) -> str:
    if source.startswith("windows:"):
        return f"Windows Event Log, channel '{source.split(':', 1)[1]}'"
    if source == "journald":
        return "systemd journal (Linux): structured log of the kernel and all services"
    if source == "syslog":
        return "syslog text file: one line per event, 'timestamp host program[pid]: message'"
    if source.startswith("app:"):
        return f"application log file of '{source[4:]}'"
    dev, _, rest = source.partition(":")
    if dev in ("pi", "jetson", "linux"):
        return f"{ {'pi': 'Raspberry Pi', 'jetson': 'NVIDIA Jetson', 'linux': 'Linux box'}[dev]} over SSH ({rest})"
    return source


def _program_note(program: str) -> str:
    if not program:
        return ""
    if program in K.PROGRAMS:
        return K.PROGRAMS[program]
    for k, v in K.PROGRAMS.items():
        if program.lower().startswith(k.lower()):
            return v
    return ""


def _field_note(name: str, value: str) -> str:
    base = K.WINDOWS_FIELDS.get(name) or K.JOURNAL_FIELDS.get(name) or ""
    v = str(value).strip().lower()
    if name == "LogonType" and v in K.LOGON_TYPES:
        n, m = K.LOGON_TYPES[v]
        return f"{n}: {m}"
    if name in ("Status", "SubStatus", "FailureCode") and v in K.STATUS_CODES:
        return K.STATUS_CODES[v]
    if name == "TicketEncryptionType" and v in K.KERBEROS_ENC:
        return K.KERBEROS_ENC[v]
    if name in ("IpAddress", "SourceAddress") and _ip_scope(v):
        return f"{base}; {_token_note('ip', v)}"
    return base


def _utc(iso: str) -> datetime:
    return datetime.fromisoformat(iso).astimezone(timezone.utc)


def _keyword(template: str, sample: str) -> str:
    """Longest literal chunk of the template (no placeholders): a safe fixed string to search for."""
    first_line = template.split(" | ")[0]  # multi-line records (tracebacks) are folded with " | "
    parts = [p.strip(" :;,.[]()=|'\"") for p in re.split(r"<[a-z]+>", first_line)]
    parts = [p for p in parts if len(p) >= 4]
    kw = max(parts, key=len) if parts else sample.split(" | ")[0][:40]
    return kw[:60]


def _sq(s: str) -> str:  # single-quote for POSIX shells
    return "'" + s.replace("'", "'\\''") + "'"


def _ps(s: str) -> str:  # single-quote for PowerShell
    return "'" + s.replace("'", "''") + "'"


def _matching_files(cluster: dict, specs: list[dict]) -> list[str]:
    """The picked/configured files this pattern can have come from (by format, or by app name)."""
    from .collectors.sources import _files, detect_format
    src = cluster.get("source", "")
    want = "syslog" if src == "syslog" else "journal" if src == "journald" else "app" if src.startswith("app:") else None
    app = src[4:] if src.startswith("app:") else None
    out = []
    for s in specs:
        if not s.get("path") or s.get("type") not in ("files", "syslog", "app"):
            continue
        for f in _files(s["path"])[:200]:
            fmt = s.get("format") or {"syslog": "syslog", "app": "app"}.get(s["type"]) or detect_format(f)
            if fmt == want and (not app or s.get("app") == app or re.split(r"[.]", f.replace("\\", "/").rsplit("/", 1)[-1])[0] == app):
                out.append(f)
    return out[:20]


def _hour_prefix(path: str) -> int:
    """How many leading characters of a line identify its hour: 13 for ISO dates, 9 for 'Nov  6 15'."""
    from .collectors.sources import _read_lines
    try:
        line = next((l for l in _read_lines(path, lambda m: None) if l.strip()), "")
    except OSError:
        return 0
    if re.match(r"\d{4}-\d\d-\d\d[T ]\d\d", line):
        return 13
    if re.match(r"[A-Z][a-z]{2} [ \d]\d \d\d:", line):
        return 9
    return 0


def commands(cluster: dict, scan: dict) -> list[dict]:
    """Native commands that show these events, for the OS that produced them."""
    out: list[dict] = []
    src, prog, eid = cluster.get("source", ""), cluster.get("program") or "", str(cluster.get("event_id") or "")
    first, last = _utc(cluster["first"]), _utc(cluster["last"]) + timedelta(seconds=1)
    since, until = first.strftime("%Y-%m-%d %H:%M:%S UTC"), last.strftime("%Y-%m-%d %H:%M:%S UTC")
    kw = _keyword(cluster.get("template", ""), (cluster.get("samples") or [""])[0])
    specs = scan.get("sources") or []
    origin = ((scan.get("stats") or {}).get("os") or {}).get("origin", "")

    if src.startswith("windows:"):
        chan = src.split(":", 1)[1]
        evtx = next((s.get("path") for s in specs if s.get("type") in ("evtx", "files") and
                     str(s.get("path", "")).lower().endswith((".evtx", ".xml"))), None)
        where = f"-Path {_ps(evtx)}" if evtx else f"-LogName {_ps(chan)}"
        if eid.isdigit():
            filt = (f"Get-WinEvent {where} -FilterXPath \"*[System[EventID={eid}]]\" -MaxEvents 20" if evtx else
                    f"Get-WinEvent -FilterHashtable @{{LogName={_ps(chan)}; Id={eid}; StartTime=[datetime]{_ps(first.isoformat())}}} -MaxEvents 20")
            out.append({"os": "Windows", "label": "PowerShell: the same events, newest first", "cmd": filt + " | Format-List TimeCreated, Id, ProviderName, Message"})
            out.append({"os": "Windows", "label": "PowerShell: every field of the newest one (the XML behind the event)",
                        "cmd": filt.replace("-MaxEvents 20", "-MaxEvents 1") + " | ForEach-Object { $_.ToXml() }"})
            out.append({"os": "Windows", "label": "Event Viewer",
                        "cmd": f"eventvwr.msc → Windows Logs → {chan} → Filter Current Log… → Event IDs: {eid}"})
        return out

    dev, _, rest = src.partition(":")
    ssh = next((s for s in specs if s.get("type") == "ssh" and (s.get("name") == cluster.get("host") or
                                                               s.get("host", "").split("@")[-1] == cluster.get("host"))), None)
    if src == "journald" or (ssh and rest == "journald"):
        sel = "-k" if prog == "kernel" else f"-t {_sq(prog)}" if prog else ""
        j = f"journalctl {sel} --since {_sq(since)} --until {_sq(until)} -g {_sq(kw)} --no-pager".replace("  ", " ")
        jv = f"journalctl {sel} --since {_sq(since)} -g {_sq(kw)} -o verbose -n 1 --no-pager".replace("  ", " ")
        if ssh:
            j, jv = f"ssh {ssh['host']} {_sq(j)}", f"ssh {ssh['host']} {_sq(jv)}"
        out.append({"os": "Linux", "label": "the same events from the journal", "cmd": j})
        out.append({"os": "Linux", "label": "every field the journal stored for the newest one", "cmd": jv})
        if prog and prog != "kernel":
            out.append({"os": "Linux", "label": "is that program's service healthy right now?",
                        "cmd": (f"ssh {ssh['host']} " if ssh else "") + f"systemctl status {_sq(prog)} --no-pager"})
        return out

    files = _matching_files(cluster, specs)
    if files:
        gz = any(f.endswith(".gz") for f in files)
        paths = " ".join(_sq(f) for f in files[:6])
        if origin == "Windows":
            out.append({"os": "Windows", "label": "PowerShell: find the lines in the file",
                        "cmd": f"Select-String -SimpleMatch -Pattern {_ps(kw)} -Path {', '.join(_ps(f) for f in files[:6])}"})
        else:
            grep = "zgrep" if gz else "grep"
            out.append({"os": origin or "Linux/macOS", "label": "find the lines in the file" + ("s" if len(files) > 1 else ""),
                        "cmd": f"{grep} -nF {_sq(kw)} {paths}"})
            cut = _hour_prefix(files[0])
            if cut:
                out.append({"os": origin or "Linux/macOS", "label": "count them per hour (spot bursts)",
                            "cmd": f"{grep} -hF {_sq(kw)} {paths} | cut -c1-{cut} | sort | uniq -c"})
    if origin == "macOS":
        out.append({"os": "macOS", "label": "unified log (live system)",
                    "cmd": f"log show --start {_sq(first.astimezone().strftime('%Y-%m-%d %H:%M:%S'))} --predicate "
                           f"{_sq('eventMessage CONTAINS ' + chr(34) + kw + chr(34))} --info"})
    return out


def explain(cluster: dict, scan: dict) -> dict:
    sample = (cluster.get("samples") or [cluster.get("template", "")])[0]
    first, last = cluster["first"], cluster["last"]
    header = [
        {"part": "when", "value": f"{_utc(first):%Y-%m-%d %H:%M:%SZ}" + ("" if first == last else f" → {_utc(last):%Y-%m-%d %H:%M:%SZ}"),
         "meaning": f"{cluster['count']} occurrence(s) of this pattern; times are converted to UTC"},
        {"part": "host", "value": cluster.get("host"), "meaning": "the machine that wrote the event"},
        {"part": "source", "value": cluster.get("source"), "meaning": _source_note(cluster.get("source", ""))},
    ]
    if cluster.get("program"):
        header.append({"part": "program", "value": cluster["program"], "meaning": _program_note(cluster["program"]) or
                       "the program (or Windows provider) that wrote the event"})
    eid = str(cluster.get("event_id") or "")
    if eid:
        w = K.windows_entry(eid, cluster.get("program", ""), cluster.get("source", "")) if cluster.get("source", "").startswith("windows") else None
        header.append({"part": "event id", "value": eid, "meaning": w["title"] if w else
                       "identifier the program uses for this kind of message"})
    header.append({"part": "severity", "value": cluster.get("severity"),
                   "meaning": K.SEVERITIES.get(cluster.get("severity", ""), "") + " (worst level seen in this pattern)"})
    fields = [{"name": k, "value": str(v)[:300], "meaning": _field_note(k, v)}
              for k, v in list((cluster.get("fields") or {}).items())[:30]]
    refs = K.references(cluster)
    mapped = K.attack_for(cluster)
    related = [t for r in refs for t in r.get("attack", []) if t not in mapped]
    return {
        "key": cluster["key"], "sample": sample, "segments": segments(sample), "header": header, "fields": fields,
        "template": cluster.get("template", ""),
        "template_note": "logagent groups lines that differ only in values like <ip>, <n> (numbers), <path>, <hex>; "
                         "this is the shared shape of every line in the group",
        "references": refs,
        "attack": [{"id": t, "name": K.TECHNIQUES[t][0], "url": K.attack_url(t), "mapped": True} for t in mapped] +
                  [{"id": t, "name": K.TECHNIQUES[t][0], "url": K.attack_url(t), "mapped": False}
                   for t in dict.fromkeys(related) if t in K.TECHNIQUES],
        "commands": commands(cluster, scan),
        "rule": cluster.get("rule"),
        "score_reasons": cluster.get("reasons", []),
    }
