import gzip
import json
import tomllib
from datetime import datetime, timedelta, timezone

import pytest

from logagent import locations, summary
from logagent.collectors.sources import _files, collect, detect_format, parse_window
from logagent.model import Event, ERR, INFO

CONFIG = """# my settings
data_dir = "data"
window = "24h"

[llm]
provider = "none"   # keep comment

[[sources]]
name = "old"
type = "journald"

# A Raspberry Pi over SSH
# [[sources]]
# name = "pi"

[[sources]]
name = "app"
type = "app"
path = "/tmp/x.log"

[[rules]]
id = "r1"
title = "t"
score = 50
pattern = "boom"
"""


def test_save_sources_keeps_rest_of_file(tmp_path):
    p = tmp_path / "logagent.toml"
    p.write_text(CONFIG)
    cfg = {"_path": str(p), "sources": []}
    new = [{"name": "var log", "type": "files", "path": "/var/log"},
           {"name": "pi", "type": "ssh", "host": "pi@raspberrypi.local", "device": "pi", "logs": ["/home/pi/*.log"]}]
    saved = locations.save_sources(cfg, new)
    text = p.read_text()
    data = tomllib.loads(text)
    assert data["sources"] == saved == cfg["sources"]
    assert data["rules"][0]["id"] == "r1" and data["llm"]["provider"] == "none"
    assert "# keep comment" in text and "# A Raspberry Pi over SSH" in text and "# my settings" in text
    assert (tmp_path / "logagent.toml.bak").read_text() == CONFIG


def test_save_sources_empty_and_missing_file(tmp_path):
    p = tmp_path / "logagent.toml"
    p.write_text(CONFIG)
    locations.save_sources({"_path": str(p)}, [])
    assert "sources" not in tomllib.loads(p.read_text())
    q = tmp_path / "new.toml"
    locations.save_sources({"_path": str(q)}, [{"name": "a", "type": "files", "path": "C:\\logs\\app.log"}])
    assert tomllib.loads(q.read_text())["sources"][0]["path"] == "C:\\logs\\app.log"


@pytest.mark.parametrize("spec, msg", [
    ({"name": "x", "type": "nope"}, "type must be"),
    ({"name": "", "type": "journald"}, "name is required"),
    ({"name": "x", "type": "files"}, "path is required"),
    ({"name": "x", "type": "ssh", "host": "-oProxyCommand=sh"}, "host must look like"),
    ({"name": "x", "type": "ssh", "host": "pi@h; rm -rf /"}, "host must look like"),
    ({"name": "x", "type": "ssh", "host": "pi@h", "logs": ["/x/*.log; reboot"]}, "logs: not allowed"),
    ({"name": "x", "type": "ssh", "host": "pi@h", "port": "99999"}, "port must be"),
    ({"name": "x", "type": "journald", "units": ["a.service", "$(id)"]}, "units: not allowed"),
])
def test_validate_rejects(spec, msg):
    with pytest.raises(ValueError, match=msg):
        locations.validate_source(spec)


def test_validate_cleans_and_dedupes():
    s = locations.validate_source({"name": " web ", "type": "ssh", "host": "pi@pi.local", "port": "2222",
                                   "logs": "/a/*.log, /b.log", "junk": 1, "enabled": True})
    assert s == {"name": "web", "type": "ssh", "host": "pi@pi.local", "device": "linux", "port": 2222,
                 "logs": ["/a/*.log", "/b.log"]}
    with pytest.raises(ValueError, match="two sources"):
        locations.validate_sources([{"name": "A", "type": "journald"}, {"name": "a", "type": "journald"}])


def test_detect_format_and_folder(tmp_path):
    (tmp_path / "messages").write_text("Nov  6 10:00:00 pi kernel: hello\nNov  6 10:00:01 pi sshd[1]: hi\n")
    (tmp_path / "app.log").write_text("2026-11-06 10:00:00,1 ERROR worker: failed\n")
    (tmp_path / "j.json").write_text(json.dumps({"MESSAGE": "m", "__REALTIME_TIMESTAMP": "1"}) + "\n")
    (tmp_path / "wtmp.log").write_bytes(b"\x00\x01\x02binary")
    with gzip.open(tmp_path / "old.log.gz", "wt") as fh:
        fh.write("<11>1 2026-11-06T10:00:00Z jetson app 12 - - boom\n")
    (tmp_path / "notes.md").write_text("not a log")
    sub = tmp_path / "nginx"
    sub.mkdir()
    (sub / "error.log").write_text("2026/11/06 10:00:00 [error] 1#1: boom\n")
    assert detect_format(str(tmp_path / "messages")) == "syslog"
    assert detect_format(str(tmp_path / "app.log")) == "app"
    assert detect_format(str(tmp_path / "j.json")) == "journal"
    assert detect_format(str(tmp_path / "wtmp.log")) == "binary"
    assert detect_format(str(tmp_path / "old.log.gz")) == "syslog"
    names = sorted(p.rsplit("/", 1)[-1] for p in _files(str(tmp_path)))
    assert names == ["app.log", "error.log", "j.json", "messages", "old.log.gz", "wtmp.log"]
    warns = []
    evs = list(collect({"type": "files", "path": str(tmp_path)}, parse_window("all"), warn=warns.append))
    assert any("binary" in w for w in warns)
    assert {"kernel", "sshd", "app", "error"} <= {e.program for e in evs}


def test_big_file_reads_newest_part(tmp_path, monkeypatch):
    from logagent.collectors import sources
    f = tmp_path / "big.log"
    f.write_text("".join(f"2026-11-06 10:00:{i % 60:02d},1 INFO line {i}\n" for i in range(2000)))
    warns = []
    lines = list(sources._read_lines(str(f), warns.append, max_bytes=2000))
    assert warns and lines[-1].endswith("line 1999\n") and len(lines) < 100


def _ev(msg, program="", source="syslog", host="h"):
    return Event(ts=datetime.now(timezone.utc), host=host, source=source, severity=INFO, message=msg, program=program)


def test_guess_origin():
    assert summary.guess_origin([{"type": "evtx"}], [])["os"] == "Windows"
    pi = summary.guess_origin([], [_ev("hwmon hwmon1: Undervoltage detected!", "kernel", host="raspberrypi")] * 30)
    assert pi["os"] == "Linux" and pi["detail"] == "Raspberry Pi OS"
    win = summary.guess_origin([], [_ev(r"Faulting application C:\Program Files\x\x.exe", "Application Error")] * 30)
    assert win["os"] == "Windows"
    assert summary.guess_origin([], [_ev("user clicked button", "myapp", "app:myapp")] * 30)["os"] == "unknown"


def test_digest_and_heuristic_summary_use_utc():
    local = timezone(timedelta(hours=-7))
    t0 = datetime(2026, 11, 6, 6, 0, tzinfo=local)
    evs = [Event(ts=t0 + timedelta(minutes=i), host="pi", source="syslog", severity=ERR if i == 5 else INFO,
                 message="boom" if i == 5 else "tick", program="kernel") for i in range(10)]
    cluster = {"key": "k1", "count": 1, "first": evs[5].ts.isoformat(), "last": evs[5].ts.isoformat(), "program": "kernel",
               "severity": "err", "template": "boom", "samples": ["boom"]}
    d = summary.build_digest([], evs, [cluster], {"findings": [{"keys": ["k1"], "importance": "high", "title": "Boom"}]},
                             {"pretty": "Fedora Linux 44", "os": "Linux"}, {"os": "Linux", "detail": "", "confidence": "high"})
    assert d["first_utc"] == "2026-11-06T13:00:00" and d["ranked_findings"][0]["first"] == "2026-11-06T13:05:00"
    text = summary.heuristic_summary(d)
    assert "HEALTH: needs attention" in text and "2026-11-06T13:05:00Z" in text


def test_collapse_discovered_dirs():
    found = {"/var/log": ["/var/log/messages"], "/var/log/nginx": ["/var/log/nginx/error.log"],
             "/home/u/.cache/x/a": ["1.log"], "/home/u/.cache/x/b": ["2.log"], "/home/u/.cache/x/c": ["3.log"],
             "/srv/app/logs": ["app.log"]}
    out = locations._collapse(found)
    assert set(out) == {"/var/log", "/home/u/.cache/x", "/srv/app/logs"}
    assert len(out["/var/log"]) == 2 and len(out["/home/u/.cache/x"]) == 3


def test_run_scan_keeps_label_and_summarizes(tmp_path):
    from logagent import engine
    cfg = engine.load_config(None)
    cfg["data_dir"] = str(tmp_path)
    srcs = [{"name": "pi-syslog.log", "type": "files", "path": "samples/pi-syslog.log"},
            {"name": "myapp.log", "type": "files", "path": "samples/myapp.log"}]
    scan = engine.run_scan(cfg, srcs, "all", False, lambda m: None, summarize=True, label="pi-syslog.log, myapp.log")
    assert scan["label"] == "pi-syslog.log, myapp.log"
    assert scan["summary"]["by"] == "rules" and scan["summary"]["text"].startswith("WHAT:")
    assert scan["stats"]["per_source"] == {"pi-syslog.log": 105, "myapp.log": 36}
