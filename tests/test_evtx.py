"""The stdlib .evtx reader, against a tiny file built here (BinXML with inline names, a template and substitutions)."""
import struct
from datetime import datetime, timezone

from logagent.collectors import evtx, windows

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


class BinXml:
    """Minimal BinXML writer: just enough of the format to produce real-looking Security events."""

    def __init__(self, chunk: bytearray, base: int):
        self.c, self.base = chunk, base  # chunk-relative offsets matter: names and templates are found by offset

    def pos(self):
        return self.base + len(self.buf)

    def name(self, s):
        self.buf += struct.pack("<I", self.pos() + 4)  # name stored inline, right after its offset
        self.buf += struct.pack("<IHH", 0, 0, len(s)) + s.encode("utf-16-le") + b"\0\0"

    def open(self, tag, attrs=()):
        self.buf += bytes([0x41 if attrs else 0x01]) + struct.pack("<HI", 0xFFFF, 0)
        self.name(tag)
        if attrs:
            self.buf += struct.pack("<I", 0)
            for i, (k, v) in enumerate(attrs):
                self.buf += bytes([0x46 if i < len(attrs) - 1 else 0x06])
                self.name(k)
                self.value_or_sub(v)

    def value_or_sub(self, v):
        if isinstance(v, int):  # substitution index
            self.buf += bytes([0x0D]) + struct.pack("<HB", v, 0)
        else:
            self.buf += bytes([0x05, 0x01]) + struct.pack("<H", len(v)) + v.encode("utf-16-le")

    def leaf(self, tag, v, attrs=()):
        self.open(tag, attrs)
        self.buf += b"\x02"
        self.value_or_sub(v)
        self.buf += b"\x04"


def build_evtx(path, events):
    """events: list of (record id, filetime, event id, {data name: value})"""
    chunk = bytearray(0x10000)
    chunk[:8] = b"ElfChnk\x00"
    off = 0x200
    for rid, ft, eid, data in events:
        rec_start = off
        w = BinXml(chunk, rec_start + 24)
        w.buf = bytearray(b"\x0f\x01\x01\x00")
        # template instance with its definition inline
        w.buf += b"\x0c\x01" + struct.pack("<I", 1)
        def_off = w.pos() + 4
        w.buf += struct.pack("<I", def_off)
        body = BinXml(chunk, def_off + 24)
        body.buf = bytearray(b"\x0f\x01\x01\x00")
        body.open("Event", [("xmlns", NS)]); body.buf += b"\x02"
        body.open("System"); body.buf += b"\x02"
        body.open("Provider", [("Name", "Microsoft-Windows-Security-Auditing")]); body.buf += b"\x03"
        body.leaf("EventID", 0)
        body.leaf("Level", "0")
        body.leaf("Keywords", 1)
        body.open("TimeCreated", [("SystemTime", 2)]); body.buf += b"\x03"
        body.leaf("EventRecordID", 3)
        body.leaf("Channel", "Security")
        body.leaf("Computer", "DC01.lab.local")
        body.open("Security", [("UserID", 4)]); body.buf += b"\x03"
        body.buf += b"\x04"  # </System>
        body.open("EventData"); body.buf += b"\x02"
        for i, k in enumerate(data):
            body.leaf("Data", 5 + i, [("Name", k)])
        body.buf += b"\x04\x04\x00"  # </EventData></Event> EOF
        w.buf += struct.pack("<I", 0) + b"\0" * 16 + struct.pack("<I", len(body.buf)) + body.buf
        sid = bytes([1, 1, 0, 0, 0, 0, 0, 5]) + struct.pack("<I", 18)  # S-1-5-18
        values = [(struct.pack("<H", eid), 0x06), (struct.pack("<Q", 0x8020000000000000), 0x15),
                  (struct.pack("<Q", ft), 0x11), (struct.pack("<Q", rid), 0x0A), (sid, 0x13)]
        values += [((v + "\0").encode("utf-16-le"), 0x01) for v in data.values()]
        w.buf += struct.pack("<I", len(values)) + b"".join(struct.pack("<HBx", len(b), t) for b, t in values)
        w.buf += b"".join(b for b, _ in values) + b"\x00"
        size = 24 + len(w.buf) + 4
        chunk[rec_start:rec_start + size] = (b"\x2a\x2a\x00\x00" + struct.pack("<IQQ", size, rid, ft) + bytes(w.buf) +
                                             struct.pack("<I", size))
        off += size
    struct.pack_into("<I", chunk, 0x30, off)
    with open(path, "wb") as fh:
        fh.write(b"ElfFile\x00".ljust(4096, b"\0") + bytes(chunk))


def _ft(dt):
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10_000_000)


def test_evtx_reader_round_trip(tmp_path):
    p = tmp_path / "sec.evtx"
    t = datetime(2024, 5, 21, 3, 18, 9, tzinfo=timezone.utc)
    build_evtx(p, [
        (6417, _ft(t), 4769, {"TargetUserName": "alonzo.spire@LAB.LOCAL", "ServiceName": "MSSQLService",
                              "TicketEncryptionType": "0x17", "IpAddress": "::ffff:172.17.79.129"}),
        (6418, _ft(t) + 10_000_000, 4769, {"TargetUserName": "pc1$@LAB.LOCAL", "ServiceName": "DC01$",
                                           "TicketEncryptionType": "0x12", "IpAddress": "::1"}),
    ])
    recs = list(evtx.read_records(str(p), warn=print))
    assert [r for r, _ in recs] == [6417, 6418]
    assert 'SystemTime="2024-05-21T03:18:09.0000000Z"' in recs[0][1] and 'UserID="S-1-5-18"' in recs[0][1]
    evs = list(windows.read_evtx(str(p)))
    e = evs[0]
    assert e.event_id == "4769" and e.host == "DC01.lab.local" and e.ts == t and e.loc["record"] == "6417"
    assert e.fields["ServiceName"] == "MSSQLService"
    assert e.message.startswith("A Kerberos service ticket was requested. ") and "Ticket Encryption Type: 0x17" in e.message


def test_evtx_kerberoast_rule_and_indicators(tmp_path, monkeypatch):
    import shutil
    from logagent import engine
    monkeypatch.setattr(shutil, "which", lambda name: None)  # behave as on Linux even on Windows
    p = tmp_path / "sec.evtx"
    t = _ft(datetime(2024, 5, 21, 3, 18, 9, tzinfo=timezone.utc))
    build_evtx(p, [(1, t, 4769, {"TargetUserName": "alonzo.spire@LAB.LOCAL", "ServiceName": "MSSQLService",
                                 "TicketEncryptionType": "0x17", "IpAddress": "::ffff:172.17.79.129"}),
                   (2, t, 4769, {"TargetUserName": "pc1$@LAB.LOCAL", "ServiceName": "krbtgt",
                                 "TicketEncryptionType": "0x17", "IpAddress": "::1"})])
    cfg = engine.load_config(None)
    cfg["data_dir"] = str(tmp_path / "d")
    scan = engine.run_scan(cfg, [{"name": "sec", "type": "files", "path": str(p)}], "all", False, lambda m: None)
    roast = [f for f in scan["findings"] if (f["rule"] or {}).get("id") == "win_kerberoast"]
    assert len(roast) == 1 and "MSSQLService" in roast[0]["samples"][0] and roast[0]["attack"] == ["T1558.003"]
    assert {(i["type"], i["value"]) for i in scan["iocs"]} >= {("ip", "172.17.79.129")}
    from logagent import logview
    v = logview.view(scan, f"c/{roast[0]['key']}/0", 1, 1)
    assert any(l["hit"] and "MSSQLService" in l["text"] for l in v["lines"])


def test_not_evtx(tmp_path):
    p = tmp_path / "x.evtx"
    p.write_bytes(b"hello")
    import pytest
    with pytest.raises(evtx.EvtxError):
        list(evtx.read_records(str(p)))


def test_linux_rules_do_not_fire_on_windows_text():
    from logagent.model import Event
    from logagent.signals import load_rules, match_rules
    e = Event(ts=datetime.now(timezone.utc), host="h", source="windows:Microsoft-Windows-PowerShell/Operational",
              severity=4, message="PowerShell script block logging. Script Block Text: # parses I/O error and kernel panic text",
              program="Microsoft-Windows-PowerShell", event_id="4104")
    assert not [r.id for r in match_rules(e, load_rules()) if r.id.startswith(("lx_", "app_"))]
