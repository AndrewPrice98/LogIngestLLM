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
    if scan.get("summary"):
        o = scan["summary"]["origin"]
        print(f"--- whole-log summary ({scan['summary']['by']}; origin {o['os']}{' / ' + o['detail'] if o['detail'] else ''}, "
              f"viewer {scan['summary']['viewer']})")
        print(scan["summary"]["text"], "\n")
    print(f"{st['events']} events, {st['clusters']} patterns, {st['flagged']} flagged, hosts: {', '.join(st['hosts'])}\n")
    for f in a.get("findings", []):
        print(f"[{f.get('importance', '?').upper():8}] {f.get('title')}  ({f.get('host', '')})")
        for k in ("what", "why", "action", "related"):
            if f.get(k):
                print(f"    {k:7} {f[k]}")
        print()
    for w in scan.get("warnings", []):
        print("warning:", w)


DEMO = [  # (file, label, host) investigations shipped in samples/
    ("windows-security.xml", "Windows intrusion: guessing, LSASS dump, new admin, log cleared", None),
    ("intrusion-auth.log", "Linux break-in: SSH login, LinPEAS, reverse shell, cron miner", None),
    ("web-access.log", "Web server scanned: Nikto, gobuster, sqlmap", "web01"),
    ("pi-syslog.log", "Small Linux box: failing SD card, under-voltage, OOM", None),
    ("benign-laptop.log", "A healthy laptop (what normal looks like)", None),
]


def _demo(cfg: dict, args) -> int:
    import shutil
    from . import paths
    root = paths.resource(".")
    data = paths.user_dir() / "demo_data"
    if args.fresh and data.exists():
        shutil.rmtree(data)
    demo = {**cfg, "data_dir": str(data), "schedule": "", "_path": str(data / "demo.toml"),
            "sources": [{"name": f, "type": "files", "path": str(root / "samples" / f), **({"host": h} if h else {})}
                        for f, _, h in DEMO]}
    if not demo["llm"].get("provider") or not args.model:
        demo["llm"] = {**demo["llm"], "provider": "none"} if not args.model else demo["llm"]
    if not list((data / "scans").glob("*.json")):
        print(f"analyzing {len(DEMO)} example logs into {data} ...")
        for f, label, h in DEMO:
            engine.run_scan(demo, [{"name": f, "type": "files", "path": str(root / "samples" / f), **({"host": h} if h else {})}],
                            "all", args.model, lambda m: None, summarize=True, label=label)
            print(f"  ✓ {label}")
    from .server import serve
    serve(demo, "127.0.0.1", args.port, not args.no_browser)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="logagent", description="Find the log events worth your attention.")
    from . import paths
    default_cfg = str(paths.user_dir() / "logagent.toml") if paths.FROZEN else "logagent.toml"
    ap.add_argument("-c", "--config", default=default_cfg, help=f"config file (default: {default_cfg})")
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
    s.add_argument("--summarize", action="store_true", help="also write an OS-aware summary of the whole log")
    s.add_argument("--json", action="store_true", help="print the full scan as JSON")

    sub.add_parser("check-llm", help="verify the configured LLM answers")

    dm = sub.add_parser("demo", help="open the dashboard on the bundled example logs (no setup needed)")
    dm.add_argument("--model", action="store_true", help="have your model review them too (needs it running)")
    dm.add_argument("--fresh", action="store_true", help="re-analyze the examples")
    dm.add_argument("--port", type=int, default=8765)
    dm.add_argument("--no-browser", action="store_true")

    ev = sub.add_parser("eval", help="known-answer checks of rules, tools and (with --model) your model")
    ev.add_argument("--model", action="store_true", help="also check the model: triage, summary, cited answers")
    ev.add_argument("--scenario", action="append", help="only these scenarios (see evals/scenarios.json)")

    d = sub.add_parser("dataset", help="build training data for your own model")
    d.add_argument("--out", default="train_data")
    d.add_argument("--synthetic", type=int, default=400, help="number of synthetic host-days to add")

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
                               progress=lambda m: print(m, file=sys.stderr), summarize=args.summarize)
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
    if args.cmd == "demo":
        return _demo(cfg, args)
    if args.cmd == "eval":
        from . import evals
        report = evals.run(cfg, args.model, args.scenario)
        path, prev = evals.save(report)
        print(f"\n{report['passed']}/{report['total']} checks passed  (report: {path})")
        if prev:
            print(f"previous run {prev['created']}: {prev['passed']}/{prev['total']}"
                  + (f"  ({report['passed'] - prev['passed']:+d})" if prev.get("total") == report["total"] else ""))
        return 0 if report["passed"] == report["total"] else 1
    if args.cmd == "dataset":
        from .train.dataset import build
        print(json.dumps(build(cfg, args.out, args.synthetic), indent=1))
        return 0
    ap.print_help()
    return 0
