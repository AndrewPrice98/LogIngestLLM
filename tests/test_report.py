from logagent import engine, report


def _scan(tmp_path, path, summarize=True):
    cfg = engine.load_config(None)
    cfg["data_dir"] = str(tmp_path)
    return engine.run_scan(cfg, [{"name": "x", "type": "files", "path": path}], "all", False, lambda m: None,
                           summarize=summarize, label="case 42")


def test_markdown_report_resolves_citations(tmp_path):
    scan = _scan(tmp_path, "samples/windows-security.xml")
    md = report.markdown(scan)
    assert md.startswith("# Log analysis report: case 42")
    for section in ("## Summary", "## Findings", "## Tools seen", "## MITRE ATT&CK", "## Indicators", "## Timeline"):
        assert section in md, section
    assert "samples/windows-security.xml, record 812" in md          # citations -> file + Windows record
    assert "T1070.001" in md and "LSASS dump via comsvcs.dll" in md and "198.51.100.23" in md
    assert "No log data left this machine" in md


def test_report_text_logs_cite_file_and_line(tmp_path):
    md = report.markdown(_scan(tmp_path, "samples/intrusion-auth.log"))
    assert "samples/intrusion-auth.log:19" in md   # the reverse shell line


def test_html_report(tmp_path):
    md = report.markdown(_scan(tmp_path, "samples/web-access.log"))
    html = report.to_html(md, "t <x>")
    assert html.startswith("<!doctype html>") and "<title>t &lt;x&gt;</title>" in html
    assert html.count("<table>") >= 3 and "<script" not in html


def test_timeline_is_sorted_and_filtered(tmp_path):
    tl = report.timeline(_scan(tmp_path, "samples/intrusion-auth.log", summarize=False), "high")
    assert tl and all(x["imp"] in ("critical", "high") for x in tl)
    assert [x["t"] for x in tl] == sorted(x["t"] for x in tl)


def test_models_overview_reads_models_folder():
    from logagent.server import _models_overview
    d = _models_overview()
    assert set(d) >= {"active", "versions", "base", "promotions"}
