import json
from datetime import datetime, timedelta, timezone

from logagent.analysis import Baseline, cluster_events, score_clusters, select_findings, template_of
from logagent.collectors.textlogs import parse_app_log, parse_journal_json, parse_syslog
from logagent.collectors.windows import parse_events_xml
from logagent.signals import load_rules

RULES = load_rules()


def rule_ids(events):
    clusters = score_clusters(cluster_events(events, RULES))
    return {c.rule.id for c in clusters if c.rule}, clusters


def test_template_masks_variables():
    a = template_of("Failed password for root from 1.2.3.4 port 5555 ssh2")
    b = template_of("Failed password for root from 9.8.7.6 port 4444 ssh2")
    assert a == b


def test_syslog_pi_signals():
    lines = [
        "Nov  6 10:00:00 pi kernel: [ 12.3] hwmon hwmon1: Undervoltage detected!",
        "Nov  6 10:00:05 pi kernel: [ 13.0] blk_update_request: I/O error, dev mmcblk0, sector 99",
        "Nov  6 10:01:00 pi kernel: [ 20.0] Out of memory: Killed process 42 (python3)",
    ] + [f"Nov  6 10:02:{i:02d} pi sshd[{i}]: Failed password for invalid user admin from 10.0.0.{i} port 22 ssh2"
         for i in range(10)]
    ids, clusters = rule_ids(list(parse_syslog(lines, year=2026)))
    assert {"pi_undervoltage", "lx_io_error", "lx_oom", "lx_ssh_bruteforce"} <= ids
    assert clusters[0].score >= 80


def test_ssh_single_failure_is_not_bruteforce():
    ids, _ = rule_ids(list(parse_syslog(
        ["Nov  6 10:02:00 pi sshd[1]: Failed password for mreyes from 10.0.0.2 port 22 ssh2"], year=2026)))
    assert "lx_ssh_bruteforce" not in ids


def test_rfc5424_priority():
    ev = next(parse_syslog(["<11>1 2026-11-06T10:00:00Z jetson app 12 - - boom"]))
    assert ev.severity == 3 and ev.host == "jetson" and ev.program == "app"


def test_journald_json():
    line = json.dumps({"MESSAGE": "nvgpu: 17000000.gv11b gk20a_fifo_handle_pbdma_intr: error",
                       "PRIORITY": "3", "_HOSTNAME": "jetson", "SYSLOG_IDENTIFIER": "kernel",
                       "__REALTIME_TIMESTAMP": str(int(datetime.now().timestamp() * 1e6))})
    ids, _ = rule_ids(list(parse_journal_json([line])))
    assert "jetson_gpu" in ids


def test_app_traceback_grouped():
    lines = ["2026-11-06 10:00:00,1 ERROR worker: failed", "Traceback (most recent call last):",
             '  File "x.py", line 1, in f', "ValueError: bad", "2026-11-06 10:00:01,1 INFO ok"]
    evs = list(parse_app_log(lines, "myapp"))
    assert len(evs) == 2 and "ValueError" in evs[0].message
    ids, _ = rule_ids(evs)
    assert "app_traceback" in ids


def test_app_json_lines():
    evs = list(parse_app_log(['{"time": "2026-11-06T10:00:00Z", "level": "error", "msg": "db is down"}']))
    assert evs[0].severity == 3 and evs[0].message == "db is down"


WIN_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-WHEA-Logger'/><EventID>17</EventID><Level>3</Level><Keywords>0x8000000000000000</Keywords>
<TimeCreated SystemTime='2026-11-06T18:19:10.8355980Z'/><Channel>System</Channel><Computer>PC</Computer></System>
<EventData><Data Name='ErrorSource'>4</Data></EventData><RenderingInfo Culture='en-US'>
<Message>A corrected hardware error has occurred.</Message></RenderingInfo></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>
<Provider Name='Microsoft-Windows-DistributedCOM'/><EventID>10016</EventID><Level>3</Level>
<TimeCreated SystemTime='2026-11-06T18:19:11Z'/><Channel>System</Channel><Computer>PC</Computer></System>
<RenderingInfo Culture='en-US'><Message>permission settings do not grant Local Activation</Message></RenderingInfo></Event>"""


def test_windows_xml_and_noise():
    evs = list(parse_events_xml(WIN_XML))
    assert len(evs) == 2 and evs[0].event_id == "17"
    clusters = score_clusters(cluster_events(evs, RULES))
    found = select_findings(clusters)
    assert [c.rule.id for c in found] == ["win_whea"]  # DCOM 10016 suppressed


def test_novelty_bonus(tmp_path):
    base = Baseline(tmp_path / "b.json")
    mk = lambda msg: list(parse_syslog([f"Nov  6 10:00:00 pi kernel: {msg}"], year=2026))
    base.update(score_clusters(cluster_events(mk("usb 1-1: new device"), RULES), base))
    c = score_clusters(cluster_events(mk("EXT4-fs error (device sda1): bad"), RULES), base)[0]
    assert c.novel and "first time seen on this host" in c.reasons


def test_dataset_build_uses_feedback(tmp_path):
    import json as _json
    from logagent import feedback
    from logagent.train.dataset import build
    scans = tmp_path / "scans"
    scans.mkdir()
    evs = list(parse_syslog(["Nov  6 10:00:00 pi kernel: EXT4-fs error (device sda1): bad",
                             "Nov  6 10:00:01 pi systemd[1]: Started foo.service."], year=2026))
    cl = score_clusters(cluster_events(evs, RULES))
    scan = {"id": "20261106-100000", "analysis": {"findings": []},
            "findings": [c.to_dict() for c in cl if c.score >= 30], "others": [c.to_dict() for c in cl if c.score < 30]}
    (scans / "20261106-100000.json").write_text(_json.dumps(scan, default=str))
    cfg = {"data_dir": str(tmp_path), "rules": []}
    feedback.save(cfg, scan["id"], scan["others"][0]["key"], "useful", "medium", "I care about foo")
    stats = build(cfg, tmp_path / "out", n_synthetic=3)
    assert stats["sources"]["gold"] == 1
    rows = [_json.loads(l) for l in open(tmp_path / "out" / "train.jsonl", encoding="utf-8")]
    gold = [r for r in rows if r["meta"]["src"] == "you"]
    if gold:  # may be held out to eval by hash
        assert _json.loads(gold[0]["messages"][2]["content"])["importance"] == "medium"
