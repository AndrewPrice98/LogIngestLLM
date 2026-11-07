"""Known-answer evaluation of the whole co-pilot: `python -m logagent eval [--model]`.

Deterministic checks (rules, tools, indicators, ATT&CK, false alarms) also run in the test suite. Model checks
(triage importance, summary must-say / must-not-say, citations, cited answers) run against the configured model
and are saved as a report in models/ so a new model or prompt can be compared with the last one.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from datetime import datetime
from pathlib import Path

from . import engine, llm

from .paths import REPO as ROOT, resource
LEVELS = ["critical", "high", "medium", "low", "noise"]


def active_adapter() -> str | None:
    """Name of the adapter the model server loads (models/ACTIVE, else the newest), for the reports."""
    models = ROOT / "models"
    act = models / "ACTIVE"
    if act.exists():
        return Path(act.read_text(encoding="utf-8").strip()).parent.name
    runs = sorted(models.glob("logagent-*/adapter"))
    return runs[-1].parent.name if runs else None


def load_scenarios(path: str | Path | None = None) -> dict:
    spec = json.loads(Path(path or resource("evals/scenarios.json")).read_text(encoding="utf-8"))
    if path is None:  # private cases (data you can't publish) live in evals/local/*.json, which git ignores
        for extra in sorted(Path(resource("evals")).glob("local/*.json")):
            spec["scenarios"] += json.loads(extra.read_text(encoding="utf-8")).get("scenarios", [])
    return spec


def files_for(sc: dict) -> list[str] | None:
    """Absolute paths of a scenario's logs, or None when it should be skipped (optional data not present)."""
    base = resource(".")
    if sc.get("files_env"):
        d = os.environ.get(sc["files_env"])
        if not d:
            return None
        base = Path(d)
    paths = [str(base / f) for f in sc["files"]]
    return paths if all(os.path.exists(p) for p in paths) else None


def run_scan(sc: dict, cfg: dict, use_llm: bool) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        c = {**cfg, "data_dir": tmp}
        specs = [{"name": Path(p).name, "type": "files", "path": p} for p in files_for(sc)]
        return engine.run_scan(c, specs, "all", use_llm, lambda m: None, summarize=use_llm, label=sc["name"])


def _check(out: list, name: str, ok: bool, detail: str = "") -> None:
    out.append({"check": name, "ok": bool(ok), "detail": detail})


def static_checks(sc: dict, scan: dict) -> list[dict]:
    exp, out = sc.get("expect", {}), []
    clusters = scan["findings"] + scan["others"]
    rule_ids = {(c.get("rule") or {}).get("id") for c in clusters} - {None}
    tools = {t["name"]: t for t in scan["tools"]}
    for r in exp.get("rules", []):
        _check(out, f"rule {r}", r in rule_ids)
    for r in exp.get("not_rules", []):
        _check(out, f"no rule {r}", r not in rule_ids)
    top = max(scan["findings"], key=lambda f: f["score"], default=None)
    top_rule = (top.get("rule") or {}).get("id") if top else None
    if exp.get("top_rule"):
        _check(out, f"top finding is {exp['top_rule']}", top_rule == exp["top_rule"], f"top was {top_rule}")
    if exp.get("top_rule_in"):
        _check(out, f"top finding in {exp['top_rule_in']}", top_rule in exp["top_rule_in"], f"top was {top_rule}")
    for t in exp.get("tools", []):
        _check(out, f"tool {t}", t in tools and all(u.get("loc") for u in tools[t]["uses"]),
               "" if t in tools else "not detected")
    if exp.get("no_tools"):
        risky = [t for t in tools if tools[t]["category"] in ("attacker", "lolbin", "miner", "tunnel", "scanner")]
        _check(out, "no risky tools (false alarm guard)", not risky, ", ".join(risky))
    have = {(i["type"], i["value"]) for i in scan["iocs"]}
    for kind, value in exp.get("iocs", []):
        _check(out, f"indicator {kind} {value}", (kind, value) in have)
    techniques = {t for c in clusters for t in c.get("attack", [])}
    for t in exp.get("attack", []):
        _check(out, f"ATT&CK {t}", t in techniques)
    if exp.get("no_attack"):
        _check(out, "no ATT&CK mapping (false alarm guard)", not techniques, ", ".join(sorted(techniques)))
    if "max_rule_score" in exp:
        worst = max((f["score"] for f in scan["findings"]), default=0)
        _check(out, f"no finding scored over {exp['max_rule_score']}", worst <= exp["max_rule_score"], f"max {worst}")
    for t in exp.get("finding_with_tool", []):
        keys = set(tools[t]["keys"]) if t in tools else set()
        _check(out, f"{t} reaches the findings", any(f["key"] in keys for f in scan["findings"]))
    return out


def _contains_groups(text: str, groups: list[list[str]]) -> list[str]:
    low = text.lower()
    return [" / ".join(g) for g in groups if not any(w.lower() in low for w in g)]


def model_checks(sc: dict, scan: dict, cfg: dict, forbidden: list[str]) -> list[dict]:
    m, out = sc.get("model", {}), []
    imp_of = {}
    for f in scan["analysis"].get("findings", []):
        for k in f.get("keys", []):
            imp_of[k] = (f.get("importance") or "low").lower()
    for d in scan["analysis"].get("dismissed", []):
        for k in d.get("keys", []):
            imp_of.setdefault(k, "noise")
    reviewed = scan["analysis"].get("_meta", {}).get("provider") not in (None, "none")
    _check(out, "model reviewed the findings", reviewed, scan.get("llm_error") or "")

    def at_least(level, want):
        return level in LEVELS and LEVELS.index(level) <= LEVELS.index(want)

    clusters = scan["findings"] + scan["others"]
    for rule, want in m.get("min_importance", {}).items():
        keys = [c["key"] for c in clusters if (c.get("rule") or {}).get("id") == rule]
        got = [imp_of.get(k, "unreviewed") for k in keys]
        _check(out, f"model rates {rule} >= {want}", keys and all(at_least(g, want) for g in got), ", ".join(got))
    tools = {t["name"]: t for t in scan["tools"]}
    for tool, want in m.get("tool_min_importance", {}).items():
        keys = (tools.get(tool) or {}).get("keys", [])
        got = [imp_of.get(k, "unreviewed") for k in keys]
        _check(out, f"model rates patterns with {tool} >= {want}", got and any(at_least(g, want) for g in got), ", ".join(got))
    if m.get("max_importance"):
        worst = min((LEVELS.index(v) for v in imp_of.values() if v in LEVELS), default=4)
        _check(out, f"nothing rated above {m['max_importance']} (false alarm guard)",
               worst >= LEVELS.index(m["max_importance"]), f"worst {LEVELS[worst]}")

    summary = (scan.get("summary") or {}).get("text") or ""
    by = (scan.get("summary") or {}).get("by")
    _check(out, "summary written by the model", by not in (None, "rules"), (scan.get("summary") or {}).get("error") or "")
    if m.get("summary_all"):
        missing = _contains_groups(summary, m["summary_all"])
        _check(out, "summary mentions the key facts", not missing, "missing: " + "; ".join(missing))
    for pat in m.get("summary_none", []):
        _check(out, f"summary does not say /{pat}/", not re.search(pat, summary, re.I))
    bad = [p for p in forbidden if re.search(p, summary, re.I)]
    _check(out, "summary has no unsafe advice", not bad, ", ".join(bad))
    cited = set(llm.cited_ids(summary))
    refs = (scan.get("summary") or {}).get("refs") or {}
    _check(out, "summary citations all resolve", cited <= set(refs), f"dangling: {sorted(cited - set(refs))}")

    if m.get("ask"):
        a = m["ask"]
        try:
            answer, arefs = llm.ask(scan, a["q"], cfg["llm"])
        except llm.LLMError as exc:
            _check(out, "cited answer", False, str(exc))
            return out
        ids = llm.cited_ids(answer)
        _check(out, f"answer cites >= {a.get('min_cites', 1)} real events", len(set(ids) & set(arefs)) >= a.get("min_cites", 1),
               f"{len(set(ids) & set(arefs))} resolved of {len(set(ids))} cited")
        if a.get("all"):
            missing = _contains_groups(answer, a["all"])
            _check(out, "answer mentions the key facts", not missing, "missing: " + "; ".join(missing))
        bad = [p for p in forbidden if re.search(p, answer, re.I)]
        _check(out, "answer has no unsafe advice", not bad, ", ".join(bad))
    return out


def run(cfg: dict, with_model: bool = False, only: list[str] | None = None, progress=print) -> dict:
    spec = load_scenarios()
    report = {"created": datetime.now().isoformat(timespec="seconds"), "model": cfg["llm"].get("model") if with_model else None,
              "adapter": active_adapter() if with_model else None, "partial": bool(only),
              "summary_model": cfg["llm"].get("summary_model") if with_model else None, "scenarios": []}
    for sc in spec["scenarios"]:
        if only and sc["name"] not in only:
            continue
        if files_for(sc) is None:
            progress(f"- {sc['name']}: skipped (set {sc.get('files_env')} to the folder with its logs)")
            report["scenarios"].append({"name": sc["name"], "skipped": True})
            continue
        t0 = time.time()
        scan = run_scan(sc, cfg, with_model)
        checks = static_checks(sc, scan)
        if with_model:
            checks += model_checks(sc, scan, cfg, spec.get("forbidden", []))
        ok = sum(c["ok"] for c in checks)
        progress(f"- {sc['name']}: {ok}/{len(checks)} passed ({time.time() - t0:.0f}s)")
        for c in checks:
            if not c["ok"]:
                progress(f"    FAIL {c['check']}" + (f"  ({c['detail']})" if c["detail"] else ""))
        report["scenarios"].append({"name": sc["name"], "passed": ok, "total": len(checks), "checks": checks})
    done = [s for s in report["scenarios"] if not s.get("skipped")]
    report["passed"], report["total"] = sum(s["passed"] for s in done), sum(s["total"] for s in done)
    return report


def save(report: dict) -> tuple[Path, dict | None]:
    """Write the report next to the models and return the previous comparable one (same mode)."""
    d = ROOT / "models"
    d.mkdir(exist_ok=True)
    mode = ("model" if report["model"] else "static") if not report.get("partial") else "partial"
    prev = None
    for p in sorted(d.glob(f"copilot-eval-{mode}-*.json"), reverse=True):
        try:
            prev = json.loads(p.read_text(encoding="utf-8"))
            break
        except (OSError, json.JSONDecodeError):
            continue
    p = d / f"copilot-eval-{mode}-{datetime.now():%Y%m%d-%H%M}.json"
    p.write_text(json.dumps(report, indent=1), encoding="utf-8")
    return p, prev
