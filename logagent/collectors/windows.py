"""Windows Event Log collector.

Uses the built-in `wevtutil` (no pywin32 needed). Reads live channels, or an
exported .evtx / XML file. The Security channel needs an elevated prompt.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterator

from ..model import Event, CRIT, ERR, WARNING, INFO, NOTICE, DEBUG, ensure_aware

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
DEFAULT_CHANNELS = ["System", "Application", "Security"]
# Windows Level -> syslog severity
_LEVEL = {1: CRIT, 2: ERR, 3: WARNING, 4: INFO, 0: INFO, 5: DEBUG}
AUDIT_FAILURE = 0x10000000000000


class CollectorError(RuntimeError):
    pass


def _run_wevtutil(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["wevtutil", *args], capture_output=True, timeout=180,
        )
    except FileNotFoundError as exc:
        raise CollectorError("wevtutil not found (Windows only)") from exc
    out = proc.stdout.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        err = " ".join(proc.stderr.decode("utf-8", errors="replace").split())
        raise CollectorError(f"wevtutil {' '.join(args[:2])}: {err or 'exit ' + str(proc.returncode)}")
    return out


def parse_events_xml(xml_text: str, source_label: str = "windows") -> Iterator[Event]:
    """Parse wevtutil /f:RenderedXml output (a run of <Event> elements, no root)."""
    xml_text = xml_text.strip()
    if not xml_text:
        return
    if xml_text.startswith("<?xml"):
        xml_text = xml_text.split("?>", 1)[1]
    root = ET.fromstring(f"<Events>{xml_text}</Events>") if not xml_text.startswith("<Events") else ET.fromstring(xml_text)
    for ev in root.iter(f"{{{NS['e']}}}Event"):
        e = _parse_one(ev, source_label)
        if e:
            yield e


def _words(name: str) -> str:
    """TicketEncryptionType -> Ticket Encryption Type (close to how Windows renders field labels)."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", name)


def _fallback_message(provider: str, event_id: str, data: dict) -> str:
    from ..knowledge import SYSMON_EVENTS, WINDOWS_EVENTS
    if "sysmon" in provider.lower() and event_id in SYSMON_EVENTS:
        title = "Sysmon: " + SYSMON_EVENTS[event_id][0]
    elif event_id in WINDOWS_EVENTS and event_id != "25":
        title = WINDOWS_EVENTS[event_id][0]
    else:
        title = f"{provider} event {event_id}"
    parts = [f"{_words(k)}: {' '.join(str(v).split())[:2000]}" for k, v in data.items()
             if v not in ("", "-", None) and not k.startswith("param")]
    return title + (". " + "  ".join(parts) if parts else "")


def _text(node, path: str) -> str:
    found = node.find(path, NS)
    return (found.text or "").strip() if found is not None and found.text else ""


def _parse_one(ev: ET.Element, source_label: str) -> Event | None:
    sysn = ev.find("e:System", NS)
    if sysn is None:
        return None
    provider = sysn.find("e:Provider", NS)
    provider_name = provider.get("Name", "") if provider is not None else ""
    event_id = _text(sysn, "e:EventID")
    level = int(_text(sysn, "e:Level") or 4)
    channel = _text(sysn, "e:Channel")
    computer = _text(sysn, "e:Computer") or socket.gethostname()
    tc = sysn.find("e:TimeCreated", NS)
    raw_ts = tc.get("SystemTime") if tc is not None else None
    try:
        ts = ensure_aware(datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))) if raw_ts else None
    except ValueError:
        ts = None
    if ts is None:
        return None

    data: dict[str, str] = {}
    ed = ev.find("e:EventData", NS)
    if ed is not None:
        for i, d in enumerate(ed.findall("e:Data", NS)):
            data[d.get("Name") or f"param{i + 1}"] = (d.text or "").strip()
    ud = ev.find("e:UserData", NS)
    if ud is not None:
        for child in ud.iter():
            if child is not ud and child.text and child.text.strip() and len(child) == 0:
                data[child.tag.split("}")[-1]] = child.text.strip()

    msg = _text(ev, "e:RenderingInfo/e:Message")
    if not msg:  # read without Windows (no message templates): describe it from the reference + its fields
        msg = _fallback_message(provider_name, event_id, data)

    sev = _LEVEL.get(level, INFO)
    kw = _text(sysn, "e:Keywords")
    try:
        if kw and int(kw, 16) & AUDIT_FAILURE:
            sev = min(sev, NOTICE)  # audit failures are interesting even at Level 0
            data["audit"] = "failure"
    except ValueError:
        pass

    return Event(
        ts=ts, host=computer, source=f"{source_label}:{channel or '?'}",
        severity=sev, message=" ".join(msg.split()), program=provider_name,
        event_id=event_id, fields=data,
        loc={k: v for k, v in (("record", _text(sysn, "e:EventRecordID")), ("channel", channel)) if v},
    )


def read_evtx(path: str, max_events: int | None = None, warn=print) -> Iterator[Event]:
    from .evtx import EvtxError, read_records
    batch: list[str] = []
    try:
        for _rid, xml in read_records(path, warn, max_events):
            batch.append(xml)
            if len(batch) >= 500:
                yield from parse_events_xml("".join(batch))
                batch = []
    except EvtxError as exc:
        raise CollectorError(str(exc)) from exc
    if batch:
        yield from parse_events_xml("".join(batch))


def collect(channels: list[str] | None = None, since: timedelta = timedelta(hours=24),
            max_events: int = 5000, path: str | None = None,
            warn=print) -> Iterator[Event]:
    """Yield events from live channels, or from an exported .evtx/.xml file."""
    if path:
        p = Path(path)
        if p.suffix.lower() == ".xml":
            yield from parse_events_xml(p.read_text(encoding="utf-8", errors="replace"))
            return
        if not shutil.which("wevtutil"):  # Linux/macOS: decode the .evtx ourselves
            yield from read_evtx(path, max_events, warn)
            return
        out = _run_wevtutil(["qe", str(p), "/lf:true", "/f:RenderedXml", f"/c:{max_events}", "/rd:true"])
        yield from parse_events_xml(out)
        return

    ms = int(since.total_seconds() * 1000)
    query = f"*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    for ch in channels or DEFAULT_CHANNELS:
        try:
            out = _run_wevtutil(["qe", ch, f"/q:{query}", "/f:RenderedXml", f"/c:{max_events}", "/rd:true"])
        except CollectorError as exc:
            hint = " (run from an elevated/admin terminal to read Security)" if ch.lower() == "security" else ""
            warn(f"[windows] skipped {ch}: {exc}{hint}")
            continue
        yield from parse_events_xml(out)
