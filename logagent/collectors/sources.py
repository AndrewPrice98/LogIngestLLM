"""Turn a source spec (from config or the UI) into a stream of Events.

Source spec dict keys:
  type:    windows | evtx | journald | syslog | app | ssh
  name:    label shown in the UI (optional)
  since:   e.g. "24h", "7d" (optional; falls back to the scan window)
  windows: channels = ["System", "Application", "Security"]
  evtx:    path = "C:/exports/System.evtx"  (or .xml)
  journald:units = ["nginx.service"] (optional)
  syslog:  path = "/var/log/syslog" (globs ok)
  app:     path = "D:/myapp/logs/*.log", app = "myapp"
  ssh:     host = "pi@raspberrypi.local", device = "pi" | "jetson" | "linux",
           port = 22, identity = "~/.ssh/id_ed25519", logs = ["/home/pi/app/*.log"]
"""
from __future__ import annotations

import glob
import gzip
import os
import shlex
import socket
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from ..model import Event, WARNING, ERR, CRIT, INFO
from . import windows
from .textlogs import parse_syslog, parse_journal_json, parse_app_log


class SourceError(RuntimeError):
    pass


def parse_window(s: str | None, default: timedelta = timedelta(hours=24)) -> timedelta:
    if not s:
        return default
    s = str(s).strip().lower()
    unit = s[-1]
    try:
        n = float(s[:-1])
    except ValueError:
        return default
    return {"m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n), "w": timedelta(weeks=n)}.get(unit, default)


def _open_text(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _files(pattern: str) -> list[str]:
    pattern = os.path.expanduser(pattern)
    files = sorted(glob.glob(pattern)) if any(c in pattern for c in "*?[") else [pattern]
    return [f for f in files if os.path.isfile(f)]


def _since_filter(events: Iterator[Event], cutoff: datetime) -> Iterator[Event]:
    for e in events:
        if e.ts >= cutoff:
            yield e


def collect(spec: dict, window: timedelta, warn=print, max_events: int = 20000) -> Iterator[Event]:
    kind = spec.get("type", "").lower()
    window = parse_window(spec.get("since"), window)
    cutoff = datetime.now(timezone.utc) - window
    host = socket.gethostname()

    if kind == "windows":
        yield from windows.collect(spec.get("channels"), since=window, max_events=max_events, warn=warn)
    elif kind == "evtx":
        yield from windows.collect(path=spec["path"], max_events=max_events, warn=warn)
    elif kind == "journald":
        cmd = ["journalctl", "-o", "json", "--no-pager", "--since", f"-{int(window.total_seconds())}s", "-n", str(max_events)]
        for u in spec.get("units", []):
            cmd += ["-u", u]
        try:
            out = subprocess.run(cmd, capture_output=True, timeout=300).stdout.decode("utf-8", errors="replace")
        except FileNotFoundError as exc:
            raise SourceError("journalctl not available on this machine") from exc
        yield from parse_journal_json(out.splitlines(), host)
    elif kind == "syslog":
        files = _files(spec["path"])
        if not files:
            raise SourceError(f"no files match {spec['path']}")
        for f in files:
            with _open_text(f) as fh:
                yield from _since_filter(parse_syslog(fh, host), cutoff)
    elif kind == "app":
        files = _files(spec["path"])
        if not files:
            raise SourceError(f"no files match {spec['path']}")
        name = spec.get("app") or spec.get("name") or Path(files[0]).stem
        for f in files:
            with _open_text(f) as fh:
                yield from _since_filter(parse_app_log(fh, name, host), cutoff)
    elif kind == "ssh":
        yield from _collect_ssh(spec, window, cutoff, warn, max_events)
    else:
        raise SourceError(f"unknown source type {kind!r}")


# ---------------------------------------------------------------- remote (Pi / Jetson / any Linux box)
_PI_THROTTLE_BITS = {
    0: ("Under-voltage detected right now", CRIT),
    1: ("ARM frequency capped right now", WARNING),
    2: ("CPU currently throttled", ERR),
    3: ("Soft temperature limit active right now", WARNING),
    16: ("Under-voltage has occurred since boot (check the power supply/cable)", ERR),
    17: ("ARM frequency capping has occurred since boot", WARNING),
    18: ("Throttling has occurred since boot", WARNING),
    19: ("Soft temperature limit has occurred since boot", WARNING),
}

_HEALTH_SCRIPT = r"""
echo "@@uptime $(cat /proc/uptime 2>/dev/null | cut -d' ' -f1)"
echo "@@disk $(df -P / 2>/dev/null | awk 'NR==2{print $5}')"
echo "@@mem $(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{if(t)printf "%d", 100-a*100/t}' /proc/meminfo 2>/dev/null)"
for z in /sys/class/thermal/thermal_zone*; do [ -r "$z/temp" ] && echo "@@temp $(cat $z/type 2>/dev/null) $(cat $z/temp)"; done
command -v vcgencmd >/dev/null 2>&1 && echo "@@throttled $(vcgencmd get_throttled 2>/dev/null | cut -d= -f2)"
[ -r /etc/nv_tegra_release ] && echo "@@tegra $(head -1 /etc/nv_tegra_release)"
echo "@@failed $(systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}' | tr '\n' ' ')"
"""


def _ssh_cmd(spec: dict) -> list[str]:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if spec.get("port"):
        cmd += ["-p", str(spec["port"])]
    if spec.get("identity"):
        cmd += ["-i", os.path.expanduser(spec["identity"])]
    cmd.append(spec["host"])
    return cmd


def _ssh_run(spec: dict, remote: str, timeout: int = 300) -> str:
    try:
        p = subprocess.run(_ssh_cmd(spec) + [remote], capture_output=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise SourceError("ssh client not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise SourceError(f"ssh to {spec['host']} timed out") from exc
    if p.returncode == 255:
        raise SourceError(f"ssh to {spec['host']} failed: {p.stderr.decode(errors='replace').strip()} "
                          "(set up key-based login: ssh-copy-id " + spec["host"] + ")")
    return p.stdout.decode("utf-8", errors="replace")


def _collect_ssh(spec: dict, window: timedelta, cutoff: datetime, warn, max_events: int) -> Iterator[Event]:
    label = spec.get("name") or spec["host"].split("@")[-1]
    device = spec.get("device", "linux")
    secs = int(window.total_seconds())

    out = _ssh_run(spec, f"journalctl -o json --no-pager --since -{secs}s -n {max_events} 2>/dev/null "
                         f"|| echo '@@nojournal'")
    if out.strip() == "@@nojournal":
        out = _ssh_run(spec, "cat /var/log/syslog /var/log/messages 2>/dev/null | tail -n " + str(max_events))
        evs = parse_syslog(out.splitlines(), label)
    else:
        evs = parse_journal_json(out.splitlines(), label)
    for e in evs:
        e.host = label
        e.source = f"{device}:{e.source}"
        yield e

    for pattern in spec.get("logs", []):
        out = _ssh_run(spec, f"tail -n 5000 {shlex.quote(pattern)} 2>/dev/null" if "*" not in pattern
                       else f"for f in {pattern}; do tail -n 2000 \"$f\"; done 2>/dev/null")
        for e in _since_filter(parse_app_log(out.splitlines(), Path(pattern).stem.replace("*", "") or "app", label), cutoff):
            e.source = f"{device}:{e.source}"
            yield e

    try:
        yield from _health_events(_ssh_run(spec, _HEALTH_SCRIPT, timeout=60), label, device)
    except SourceError as exc:
        warn(f"[{label}] health probe failed: {exc}")


def _health_events(out: str, host: str, device: str) -> Iterator[Event]:
    now = datetime.now(timezone.utc)

    def ev(sev, msg, eid, **f):
        return Event(ts=now, host=host, source=f"{device}:health", severity=sev, message=msg,
                     program="health-probe", event_id=eid, fields=f)

    for line in out.splitlines():
        if not line.startswith("@@"):
            continue
        key, _, val = line[2:].partition(" ")
        val = val.strip()
        if key == "disk" and val.endswith("%"):
            pct = int(val[:-1] or 0)
            if pct >= 85:
                yield ev(CRIT if pct >= 95 else ERR, f"Root filesystem is {pct}% full", "disk_full", percent=pct)
        elif key == "mem" and val.isdigit() and int(val) >= 90:
            yield ev(WARNING, f"Memory {val}% used", "mem_high", percent=int(val))
        elif key == "temp":
            parts = val.rsplit(" ", 1)
            if len(parts) == 2 and parts[1].lstrip("-").isdigit():
                c = int(parts[1]) / 1000
                if c >= 80:
                    yield ev(ERR if c >= 85 else WARNING, f"Thermal zone {parts[0]} at {c:.1f}°C", "temp_high",
                             zone=parts[0], celsius=c)
        elif key == "throttled" and val.startswith("0x"):
            bits = int(val, 16)
            for bit, (msg, sev) in _PI_THROTTLE_BITS.items():
                if bits & (1 << bit):
                    yield ev(sev, f"{msg} (vcgencmd get_throttled={val})", f"pi_throttle_{bit}", raw=val)
        elif key == "failed" and val:
            for unit in val.split():
                yield ev(ERR, f"systemd unit {unit} is in failed state", "unit_failed", unit=unit)
