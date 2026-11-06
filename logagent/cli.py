"""Command line: `python -m logagent ui | scan | check-llm`."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import engine, llm


def _print_report(scan: dict) -> None:
    a = scan["analysis"]
    st = scan["stats"]
    print()
    print("=" * 72)
    print(a.get("headline", ""))
    print("=" * 72)
    if a.get("summary"):
        print(a["summary"], "\n")
    print(f"{st['events']} events, {st['clusters']} patterns, {st['flagged']} flagged, hosts: {', '.join(st['hosts'])}\n")
    for f in a.get("findings", []):
        print(f"[{f.get('importance', '?').upper():8}] {f.get('title')}  ({f.get('host', '')})")
        for k in ("what", "why", "action", "related"):
            if f.get(k):
                print(f"    {k:7} {f[k]}")
        print()
    for w in scan.get("warnings", []):
        print("warning:", w)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="logagent", description="Find the log events worth your attention.")
    ap.add_argument("-c", "--config", default="logagent.toml", help="config file (default: logagent.toml)")
    sub = ap.add_subparsers(dest="cmd")

    u = sub.add_parser("ui", help="start the web dashboard")
    u.add_argument("--host", default="127.0.0.1")
    u.add_argument("--port", type=int, default=8765)
    u.add_argument("--no-browser", action="store_true")

    s = sub.add_parser("scan", help="run one scan and print the report")
    s.add_argument("--window", help="e.g. 1h, 24h, 7d")
    s.add_argument("--source", action="append", help="only these configured source names")
    s.add_argument("--file", action="append", metavar="TYPE:PATH",
                   help="ad-hoc file, e.g. syslog:/var/log/syslog, app:./app.log, evtx:System.evtx")
    s.add_argument("--no-llm", action="store_true")
    s.add_argument("--json", action="store_true", help="print the full scan as JSON")

    sub.add_parser("check-llm", help="verify the configured LLM answers")

    args = ap.parse_args(argv)
    cfg = engine.load_config(args.config)
    if args.config and not Path(args.config).exists():
        print(f"note: {args.config} not found; using defaults (copy config.example.toml to start)", file=sys.stderr)

    if args.cmd == "ui":
        from .server import serve
        serve(cfg, args.host, args.port, not args.no_browser)
        return 0
    if args.cmd == "scan":
        sources = cfg.get("sources", [])
        if args.source:
            sources = [x for x in sources if (x.get("name") or x.get("type")) in args.source]
        if args.file:
            sources = list(sources) if args.source else []
            for spec in args.file:
                kind, _, path = spec.partition(":")
                sources.append({"type": kind, "path": path, "name": f"{kind}:{Path(path).name}",
                                **({"app": Path(path).stem} if kind == "app" else {})})
        scan = engine.run_scan(cfg, sources, args.window, not args.no_llm,
                               progress=lambda m: print(m, file=sys.stderr))
        if args.json:
            print(json.dumps(scan, indent=1, default=str))
        else:
            _print_report(scan)
        return 0
    if args.cmd == "check-llm":
        try:
            text, usage = llm.chat("Reply with exactly: OK", "ping", cfg["llm"])
        except llm.LLMError as exc:
            print("LLM check failed:", exc)
            return 1
        print(f"{cfg['llm'].get('provider')} / {cfg['llm'].get('model')} replied: {text.strip()[:80]!r}  usage={usage}")
        return 0
    ap.print_help()
    return 0
