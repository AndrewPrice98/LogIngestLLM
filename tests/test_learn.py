from datetime import datetime, timezone

from logagent import engine, explain, iocs, knowledge as K


def test_attack_mapping_is_evidence_based():
    ssh = {"source": "syslog", "program": "sshd", "rule": {"id": "lx_ssh_bruteforce"},
           "samples": ["Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"]}
    assert K.attack_for(ssh) == ["T1110.001", "T1021.004"]
    assert K.attack_for({"source": "windows:Security", "event_id": "1102", "samples": [""]}) == ["T1070.001"]
    # routine events only give context, never a mapping
    assert K.attack_for({"source": "windows:Security", "event_id": "4769", "samples": [""]}) == []
    assert K.attack_for({"source": "syslog", "program": "CRON", "samples": ["(root) CMD (run-parts)"]}) == []
    # Windows IDs are not applied to Linux sources (event_id 25 from syslog is not volsnap)
    assert K.references({"source": "syslog", "event_id": "25", "program": "x", "samples": ["hello"]}) == []
    cat = K.reference_catalog()
    assert all(t in cat["techniques"] for e in cat["windows"] for t in e["attack"])
    assert all(t in K.TECHNIQUES for ts in K.RULE_ATTACK.values() for t in ts)


def test_rule_attack_ids_exist():
    from logagent.signals import load_rules
    ids = {r.id for r in load_rules()}
    assert set(K.RULE_ATTACK) <= ids


def test_ioc_extraction():
    got = iocs.extract("Failed password for invalid user admin from 45.13.22.4 port 51234 ssh2")
    assert ("ip", "45.13.22.4", "public") in got and ("user", "admin", "") in got
    assert iocs.extract("loaded /usr/lib/x.py; script.sh ran; nginx.service started; 12:34:56; v1.2.3.4.5") == []
    got = iocs.extract("GET https://evil.example.com/a.sh from 10.0.0.5 md5 d41d8cd98f00b204e9800998ecf8427e")
    assert ("url", "https://evil.example.com/a.sh", "") in got and ("ip", "10.0.0.5", "private") in got
    assert ("hash", "d41d8cd98f00b204e9800998ecf8427e", "md5") in got
    assert iocs.extract("x", {"IpAddress": "203.0.113.9", "TargetUserName": "bob", "SubjectUserName": "PC1$"}) == \
        [("ip", "203.0.113.9", "reserved"), ("user", "bob", "")]
    assert ("ip", "fe80::1", "link-local") in iocs.extract("via fe80::1 at 10:00:00")


def test_scan_counts_iocs_exactly_and_pivots(tmp_path):
    cfg = engine.load_config(None)
    cfg["data_dir"] = str(tmp_path)
    scan = engine.run_scan(cfg, [{"name": "pi", "type": "files", "path": "samples/pi-syslog.log"}], "all", False, lambda m: None)
    ips = {i["value"]: i for i in scan["iocs"] if i["type"] == "ip"}
    assert ips["45.13.22.4"]["count"] == 8 and ips["45.13.22.4"]["scope"] == "public"
    brute = next(f for f in scan["findings"] if (f["rule"] or {}).get("id") == "lx_ssh_bruteforce")
    assert brute["attack"] == ["T1110.001", "T1021.004"] and brute["key"] in ips["45.13.22.4"]["keys"]
    hits = engine.pivot(cfg, "ip", "45.13.22.4")
    assert len(hits) == 1 and hits[0]["patterns"][0]["title"] == "SSH password guessing"


def test_old_scans_are_enriched(tmp_path):
    cfg = engine.load_config(None)
    cfg["data_dir"] = str(tmp_path)
    scan = engine.run_scan(cfg, [{"name": "pi", "type": "files", "path": "samples/pi-syslog.log"}], "all", False, lambda m: None)
    p = tmp_path / "scans" / f"{scan['id']}.json"
    import json
    old = json.loads(p.read_text())
    del old["iocs"]
    for c in old["findings"] + old["others"]:
        del c["attack"]
    p.write_text(json.dumps(old))
    again = engine.load_scan(cfg, scan["id"])
    assert again["iocs"] and all(i.get("approx") for i in again["iocs"])
    assert any(c["attack"] for c in again["findings"])


def test_explain_breakdown_and_commands(tmp_path):
    cfg = engine.load_config(None)
    cfg["data_dir"] = str(tmp_path)
    scan = engine.run_scan(cfg, [{"name": "pi", "type": "files", "path": "samples/pi-syslog.log"}], "all", False, lambda m: None)
    c = next(f for f in scan["findings"] if (f["rule"] or {}).get("id") == "lx_ssh_bruteforce")
    x = explain.explain(c, scan)
    kinds = {s.get("kind"): s["t"] for s in x["segments"] if s.get("kind")}
    assert kinds["user"] == "admin" and kinds["ip"].startswith("45.13.22.") and "port" in kinds
    assert {h["part"] for h in x["header"]} >= {"when", "host", "source", "program", "severity"}
    assert x["references"][0]["title"] == "SSH login failed"
    cmd = x["commands"][0]["cmd"]
    assert cmd.startswith("grep -nF 'Failed password for invalid user admin from'") and "pi-syslog.log" in cmd
    assert "cut -c1-9" in x["commands"][1]["cmd"]  # 'Nov  6 08' is the hour prefix of classic syslog


def test_windows_fields_decoded():
    t = datetime(2026, 11, 6, 10, tzinfo=timezone.utc).isoformat()
    c = {"key": "k", "source": "windows:Security", "program": "Microsoft-Windows-Security-Auditing", "event_id": "4625",
         "host": "PC", "count": 12, "first": t, "last": t, "severity": "notice", "template": "An account failed to log on",
         "samples": ["An account failed to log on."], "fields": {"LogonType": "10", "Status": "0xC000006D",
                                                                "SubStatus": "0xC0000064", "IpAddress": "45.1.2.3"}}
    x = explain.explain(c, {"sources": [], "stats": {}})
    notes = {f["name"]: f["meaning"] for f in x["fields"]}
    assert notes["LogonType"].startswith("RemoteInteractive") and "does not exist" in notes["SubStatus"]
    assert "public IP" in notes["IpAddress"]
    assert any("Id=4625" in cm["cmd"] for cm in x["commands"]) and x["attack"][0]["id"] == "T1110"
