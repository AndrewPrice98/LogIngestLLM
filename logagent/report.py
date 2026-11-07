"""Incident report for one scan: Markdown, or self-contained HTML for printing / saving as PDF.

Citations ([E3]) are resolved to where the line is (file:line, Windows record, journal cursor), so the report
stands on its own outside the dashboard.
"""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone

from . import knowledge as K
from . import logview

LEVELS = ["critical", "high", "medium", "low", "noise"]
TOOL_LEVEL = {"attacker": "critical", "miner": "critical", "lolbin": "high", "tunnel": "high", "scanner": "medium",
              "remote-access": "medium"}


def _utc(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        return datetime.fromisoformat(iso).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    except ValueError:
        return iso


def where(loc: dict | None) -> str:
    if not loc:
        return "position not recorded"
    if loc.get("record"):
        return f"{loc.get('file') or loc.get('channel', 'Windows Event Log')}, record {loc['record']}"
    if loc.get("cursor"):
        return "systemd journal, cursor " + loc["cursor"][:40] + "…"
    if loc.get("file"):
        return f"{loc['file']}:{loc['line']}" if loc.get("line") else f"{loc['file']} @ byte {loc.get('pos')}"
    return "?"


def _ref_loc(scan: dict, ref: str) -> str:
    try:
        return where(logview.resolve(scan, ref))
    except logview.ViewError:
        return "position not recorded"


def _rows(scan: dict) -> list[dict]:
    """Model/rules verdicts joined with cluster data, most important first."""
    a = scan.get("analysis", {})
    by = {c["key"]: c for c in scan.get("findings", []) + scan.get("others", [])}
    out = []
    for f in a.get("findings", []):
        cs = [by[k] for k in f.get("keys", []) if k in by]
        if not cs:
            continue
        c = cs[0]
        out.append({"imp": (f.get("importance") or "low").lower(), "title": f.get("title") or c["template"][:80],
                    "why": f.get("why") or "", "action": f.get("action") or "", "host": c["host"], "count": sum(x["count"] for x in cs),
                    "first": min(x["first"] for x in cs), "last": max(x["last"] for x in cs), "c": c,
                    "attack": sorted({t for x in cs for t in x.get("attack", [])})})
    out.sort(key=lambda r: (LEVELS.index(r["imp"]) if r["imp"] in LEVELS else 9, -r["c"]["score"]))
    return out


def timeline(scan: dict, min_level: str = "medium", limit: int = 200) -> list[dict]:
    rows = _rows(scan)
    items = []
    for r in rows:
        if LEVELS.index(r["imp"]) <= LEVELS.index(min_level):
            items.append({"t": r["first"], "imp": r["imp"], "kind": "finding", "what": r["title"], "host": r["host"],
                          "detail": f"{r['count']}x" + (f" until {_utc(r['last'])}" if r["count"] > 1 else ""),
                          "where": where(r["c"].get("first_loc"))})
    for t in scan.get("tools", []):
        lvl = TOOL_LEVEL.get(t["category"])
        if not lvl or LEVELS.index(lvl) > LEVELS.index(min_level):
            continue
        for u in t.get("uses", []):
            items.append({"t": u["ts"], "imp": lvl, "kind": "tool", "what": t["name"], "host": u["host"],
                          "detail": u["evidence"][:200], "where": where(u.get("loc"))})
    items.sort(key=lambda x: datetime.fromisoformat(x["t"]).astimezone(timezone.utc))
    return items[:limit]


def markdown(scan: dict) -> str:
    st, a = scan.get("stats", {}), scan.get("analysis", {})
    osinfo = st.get("os") or {}
    rows = _rows(scan)
    L = [f"# Log analysis report: {scan.get('label') or ', '.join(s.get('name', s.get('type', '')) for s in scan.get('sources', []))}", ""]
    L += [f"- **Scan** {scan['id']}, created {_utc(scan['created'])}",
          f"- **Logs** " + "; ".join(s.get("path") or s.get("name") or s.get("type") for s in scan.get("sources", [])),
          f"- **Events** {st.get('events')} in {st.get('clusters')} patterns · window {st.get('window')} · hosts {', '.join(st.get('hosts', []))}",
          f"- **Log origin** {osinfo.get('origin', '?')}{' / ' + osinfo['origin_detail'] if osinfo.get('origin_detail') else ''} · "
          f"**reviewed by** {(a.get('_meta') or {}).get('model') or 'rules only'}", ""]
    L += ["## Headline", "", a.get("headline", ""), ""]
    if scan.get("summary"):
        text = scan["summary"]["text"]
        refs = scan["summary"].get("refs") or {}
        L += ["## Summary", "", text.strip(), ""]
        if refs:
            L += ["Evidence cited above:", ""]
            L += [f"- **{k}**: {_ref_loc(scan, v)}" for k, v in sorted(refs.items(), key=lambda kv: int(kv[0][1:]))]
            L.append("")
    L += ["## Findings", "", "| # | Importance | Finding | Host | Count | First (UTC) | Last (UTC) | ATT&CK |",
          "|---|---|---|---|---|---|---|---|"]
    for i, r in enumerate(rows, 1):
        L.append(f"| {i} | {r['imp']} | {r['title']} | {r['host']} | {r['count']} | {_utc(r['first'])} | {_utc(r['last'])} | "
                 f"{', '.join(r['attack']) or '—'} |")
    L.append("")
    for i, r in enumerate(rows, 1):
        if r["imp"] in ("low", "noise"):
            continue
        L += [f"### {i}. {r['title']} ({r['imp']})", ""]
        if r["why"]:
            L += [f"**Why it matters:** {r['why']}", ""]
        if r["action"]:
            L += [f"**What to do:** {r['action']}", ""]
        L += [f"**Evidence** ({where((r['c'].get('sample_locs') or [None])[0])}):", "", "```", r["c"]["samples"][0][:1500], "```", ""]
    tools = [t for t in scan.get("tools", []) if t["category"] not in ("system", "developer")]
    if tools:
        L += ["## Tools seen", "", "| Tool | Category | Uses | First (UTC) | Location on disk | First use |", "|---|---|---|---|---|---|"]
        L += [f"| {t['name']} | {t['category']} | {t['count']} | {_utc(t.get('first'))} | "
              + ("; ".join(("⚠ " if l["unusual"] else "") + f"`{l['path']}`" for l in (t.get("locations") or [])[:3]) or "—")
              + f" | {where((t.get('uses') or [{}])[0].get('loc'))} |" for t in tools]
        L += ["", "⚠ = user-writable or temporary folder (Public, Temp, AppData, /tmp, /dev/shm, hidden folders): "
                  "a common place for attackers to drop tools.", ""]
        L.append("")
    techs = {}
    for c in scan.get("findings", []) + scan.get("others", []):
        for t in c.get("attack", []):
            techs[t] = techs.get(t, 0) + c["count"]
    if techs:
        L += ["## MITRE ATT&CK", "", "| Technique | Name | Tactics | Events |", "|---|---|---|---|"]
        tac = dict(K.TACTICS)
        for t, n in sorted(techs.items()):
            name, tactics = K.TECHNIQUES.get(t, (t, []))
            L.append(f"| {t} | {name} | {', '.join(tac.get(x, x) for x in tactics)} | {n} |")
        L.append("")
    iocs = [i for i in scan.get("iocs", []) if not (i["type"] == "ip" and i["scope"] in ("loopback", "link-local"))][:60]
    if iocs:
        L += ["## Indicators", "", "| Type | Value | Scope | Events | First (UTC) |", "|---|---|---|---|---|"]
        L += [f"| {i['type']} | `{i['value']}` | {i.get('scope') or '—'} | {i['count']} | {_utc(i['first'])} |" for i in iocs]
        L.append("")
    tl = timeline(scan)
    if tl:
        L += ["## Timeline (medium and above)", "", "| Time (UTC) | Importance | Kind | What | Host | Detail | Where |",
              "|---|---|---|---|---|---|---|"]
        L += [f"| {_utc(x['t'])} | {x['imp']} | {x['kind']} | {x['what']} | {x['host']} | "
              f"{x['detail'].replace('|', '/')} | {x['where']} |" for x in tl]
        L.append("")
    L += ["---", f"Generated locally by LogIngestLLM on {datetime.now(timezone.utc):%Y-%m-%d %H:%M}Z. No log data left this machine."]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- tiny Markdown -> HTML (only what markdown() emits)
def _inline(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)


def to_html(md: str, title: str) -> str:
    out, in_code, table = [], False, []

    def flush_table():
        if table:
            head, body = table[0], table[2:]
            cells = lambda row, tag: "".join(f"<{tag}>{_inline(c.strip())}</{tag}>" for c in row.strip().strip("|").split("|"))
            out.append("<table><tr>" + cells(head, "th") + "</tr>" + "".join("<tr>" + cells(r, "td") + "</tr>" for r in body) + "</table>")
            table.clear()

    for line in md.splitlines():
        if line.startswith("```"):
            flush_table()
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            continue
        if in_code:
            out.append(html.escape(line))
            continue
        if line.startswith("|"):
            table.append(line)
            continue
        flush_table()
        if line.startswith("#"):
            n = len(line) - len(line.lstrip("#"))
            out.append(f"<h{n}>{_inline(line[n:].strip())}</h{n}>")
        elif line.startswith("- "):
            out.append(f"<li>{_inline(line[2:])}</li>")
        elif line == "---":
            out.append("<hr>")
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
    flush_table()
    css = ("body{font:13px/1.5 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#111}"
           "h1{font-size:20px}h2{font-size:16px;border-bottom:1px solid #ccc;padding-bottom:3px;margin-top:28px}"
           "h3{font-size:14px}table{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}"
           "th,td{border:1px solid #ccc;padding:3px 6px;text-align:left;vertical-align:top}th{background:#f3f3f3}"
           "pre{background:#f6f6f6;border:1px solid #ddd;padding:8px;white-space:pre-wrap;word-break:break-all;font-size:11.5px}"
           "code{font-size:11.5px}li{margin:2px 0}@media print{h2{break-after:avoid}tr{break-inside:avoid}}")
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>{css}</style></head>"
            f"<body>{chr(10).join(out)}</body></html>")
