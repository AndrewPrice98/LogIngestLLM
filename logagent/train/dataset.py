"""Turn scans + your feedback (+ synthetic scenarios) into chat-format training data.

Label priority for each log pattern:
  1. your feedback in the dashboard          (gold, weighted x3)
  2. the built-in rules / severity heuristics (weak, gets the model started)
Output: train.jsonl / eval.jsonl with {"messages": [...], "meta": {...}}.
Eval holds out ~15% of your real scans (by scan id), so evaluation measures agreement with *you*.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path

from ..analysis import cluster_events, score_clusters
from ..feedback import load_all
from ..llm import TRIAGE_PROMPT, triage_input
from ..signals import load_rules
from .synth import synthetic_events


LEVELS = ["critical", "high", "medium", "low", "noise"]


def imp_of(score: float) -> str:
    return "critical" if score >= 100 else "high" if score >= 75 else "medium" if score >= 50 else "low"


def _facts(f: dict) -> str:
    """Specific facts, taken only from what the model sees in triage_input() (count, host, times, samples, fields)."""
    from ..iocs import extract
    n, first, last = f["count"], f["first"][:19], f["last"][:19]
    s = f"Seen {n} time{'s' if n != 1 else ''} on {f['host']}"
    if n > 1 and first != last:
        s += f" between {first[11:16]} and {last[11:16]}" if first[:10] == last[:10] else f" from {first[:16]} to {last[:16]}"
    else:
        s += f" at {first[11:16]}"
    fields = {k: str(v)[:80] for k, v in list((f.get("fields") or {}).items())[:8]}
    found = extract((f.get("samples") or [""])[0][:400], fields)
    ips = [(v, sc) for k, v, sc in found if k == "ip" and sc not in ("loopback",)][:2]
    users = [v for k, v, _ in found if k == "user"][:2]
    if ips:
        s += ", from " + " and ".join(f"{v}{' (' + sc + ')' if sc in ('public', 'private') else ''}" for v, sc in ips)
    if users:
        s += ", user " + " and ".join(users)
    if f.get("novel"):
        s += ", the first time this pattern has appeared on this host"
    return s + "."


TOOL_LEVEL = {"attacker": "critical", "miner": "high", "lolbin": "high", "tunnel": "high", "scanner": "medium",
              "remote-access": "medium"}
TOOL_ACTION = {
    "attacker": "Treat the host as compromised: isolate it, find how the attacker got in, and reset credentials used on it.",
    "miner": "Kill the miner, remove what restarts it (cron jobs, services), and find how it got onto the machine.",
    "lolbin": "Check whether you or an admin tool ran this; if not, look at what it downloaded or changed and what ran next.",
    "tunnel": "Find who started the tunnel and close it unless it is yours.",
    "scanner": "Block the scanning address if it isn't yours and check the targeted URLs or ports for successful hits.",
    "remote-access": "Confirm this remote-access software is expected on this machine and who uses it.",
}


def _tool_of(f: dict) -> tuple[str, str, str] | None:
    """(name, category, what) when a catalog tool was detected in this pattern (tools.boost adds the reason)."""
    from ..tools import CATALOG
    for r in f.get("reasons") or []:
        if r.startswith("tool: "):
            name = re.sub(r" \(\+\d+\)$", "", r[6:])
            hit = next((c for c in CATALOG if c[0] == name), None)
            if hit:
                return hit[0], hit[1], hit[2]
    return None


def weak_label(f: dict) -> dict:
    r = f.get("rule")
    tool = _tool_of(f)
    if tool:
        name, cat, what = tool
        imp = TOOL_LEVEL.get(cat, "medium")
        if r and f["score"] >= 30 and LEVELS.index(imp_of(f["score"])) < LEVELS.index(imp):
            imp = imp_of(f["score"])
        return {"importance": imp, "title": r["title"] if r else name,
                "why": f"{name}: {what}. {_facts(f)}", "action": TOOL_ACTION.get(cat, "Check who ran it and why.")}
    if r and f["score"] >= 30:
        return {"importance": imp_of(f["score"]), "title": r["title"], "why": f"{r['why']} {_facts(f)}",
                "action": r["action"]}
    if f["severity"] in ("emerg", "alert", "crit", "err") and f["score"] >= 30:
        return {"importance": "low", "title": f["template"][:70],
                "why": f"Error-level message from {f['program'] or f['source']} with no known significance. {_facts(f)}",
                "action": "Ignore unless it keeps recurring or something else is misbehaving at the same time."}
    return {"importance": "noise", "title": f["template"][:70],
            "why": "Routine operational message.", "action": "None needed."}


def gold_label(f: dict, fb: dict, analysis_by_key: dict) -> dict:
    base = analysis_by_key.get(f["key"]) or weak_label(f)
    if fb["verdict"] == "noise":
        why = "Routine for this machine; not worth attention."
        if fb.get("note"):
            why += " " + fb["note"]
        return {"importance": "noise", "title": base.get("title") or f["template"][:70], "why": why, "action": "None needed."}
    imp = fb.get("importance") or (base["importance"] if base.get("importance") not in (None, "noise") else "medium")
    why = base.get("why") or ""
    if not why or base.get("importance") == "noise":
        why = f"Worth knowing about. {_facts(f)}"
    if fb.get("note"):
        why += " " + fb["note"]
    return {"importance": imp, "title": base.get("title") or f["template"][:70], "why": why,
            "action": base.get("action") or "Investigate the program named in the sample."}


def example(f: dict, label: dict, meta: dict, rnd: random.Random) -> dict:
    # Hide the rule hint half the time so the model learns to recognise events on its own.
    hint = rnd.random() < 0.5
    return {"messages": [{"role": "system", "content": TRIAGE_PROMPT},
                         {"role": "user", "content": triage_input(f, with_hint=hint)},
                         {"role": "assistant", "content": json.dumps(label, ensure_ascii=False)}],
            "meta": meta}


def _is_eval(scan_id: str) -> bool:
    return int(hashlib.md5(scan_id.encode()).hexdigest(), 16) % 100 < 15


def build(cfg: dict, out_dir: str | Path, n_synthetic: int = 400, seed: int = 7, noise_ratio: float = 1.0) -> dict:
    rnd = random.Random(seed)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    feedback = load_all(cfg)
    train, evals = [], []
    counts = Counter()

    for p in sorted((Path(cfg["data_dir"]) / "scans").glob("*.json")):
        scan = json.loads(p.read_text(encoding="utf-8"))
        sid = scan["id"]
        by_key = {}
        for a in scan.get("analysis", {}).get("findings", []):
            for k in a.get("keys", []):
                by_key[k] = a
        has_gold = any(k.startswith(sid + "/") for k in feedback)
        held_out = has_gold and _is_eval(sid)
        for f in scan.get("findings", []) + scan.get("others", []):
            fb = feedback.get(f"{sid}/{f['key']}")
            if fb:
                ex = example(f, gold_label(f, fb, by_key), {"src": "you", "scan": sid, "key": f["key"]}, rnd)
                counts["gold"] += 1
                (evals if held_out else train).extend([ex] if held_out else [ex] * 3)
            elif not held_out:
                train.append(example(f, weak_label(f), {"src": "rules", "scan": sid, "key": f["key"]}, rnd))
                counts["weak_real"] += 1

    rules = load_rules(cfg.get("rules"))
    synth_eval_every = 10
    from ..tools import Collector, boost
    for i, evs in enumerate(synthetic_events(n_synthetic, seed)):
        col = Collector()
        clusters = score_clusters(cluster_events(evs, rules, lambda e, k: col.add(e, k)))
        boost(clusters, col)
        for c in clusters:
            f = c.to_dict()
            ex = example(f, weak_label(f), {"src": "synthetic", "scan": f"synth-{i}", "key": f["key"]}, rnd)
            (evals if i % synth_eval_every == 0 else train).append(ex)
            counts["synthetic"] += 1

    # Keep "noise" from drowning out the interesting cases.
    imp = lambda ex: json.loads(ex["messages"][2]["content"])["importance"]
    signal = [e for e in train if imp(e) != "noise" or e["meta"]["src"] == "you"]
    noise = [e for e in train if imp(e) == "noise" and e["meta"]["src"] != "you"]
    rnd.shuffle(noise)
    train = signal + noise[: int(len(signal) * noise_ratio)]
    rnd.shuffle(train)

    for name, rows in (("train.jsonl", train), ("eval.jsonl", evals)):
        with open(out_dir / name, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    stats = {"train": len(train), "eval": len(evals), "sources": dict(counts),
             "train_labels": dict(Counter(imp(e) for e in train)),
             "eval_from_you": sum(1 for e in evals if e["meta"]["src"] == "you")}
    (out_dir / "stats.json").write_text(json.dumps(stats, indent=1), encoding="utf-8")
    return stats
