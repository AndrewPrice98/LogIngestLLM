"""Score a model version against held-out labels.

    .venv-train\\Scripts\\python trainer\\evaluate.py                      # latest trained adapter
    .venv-train\\Scripts\\python trainer\\evaluate.py --adapter none       # the untrained base model, for comparison

Metrics: valid JSON rate, exact importance match, within-one-level match, and how well it separates
"worth knowing" from "noise" (precision / recall of flagging). Examples you labeled are reported separately.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import time
from collections import Counter, defaultdict

from common import ROOT, latest_adapter, load, generate, read_jsonl

LEVELS = ["critical", "high", "medium", "low", "noise"]


def parse(text: str):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip().strip("`")
    text = text[4:] if text.startswith("json") else text
    m = re.search(r"\{.*\}", text, re.S)
    try:
        return json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default=None, help="path, or 'none' for the base model (default: latest)")
    ap.add_argument("--data", default=str(ROOT / "train_data" / "eval.jsonl"))
    ap.add_argument("--n", type=int, default=150, help="examples to score (balanced by label)")
    args = ap.parse_args()
    adapter = None if args.adapter == "none" else (args.adapter or latest_adapter())
    rows = read_jsonl(args.data)

    # Balanced sample: every example you labeled, then an equal share of each importance level.
    rnd = random.Random(1)
    yours = [r for r in rows if r["meta"]["src"] == "you"]
    by = defaultdict(list)
    for r in rows:
        if r["meta"]["src"] != "you":
            by[json.loads(r["messages"][2]["content"])["importance"]].append(r)
    per = max(1, (args.n - len(yours)) // max(1, len(by)))
    sample = yours + [x for lv in by.values() for x in rnd.sample(lv, min(per, len(lv)))]

    tok, model = load(adapter)
    print(f"evaluating {'base model' if not adapter else adapter} on {len(sample)} examples")
    res = defaultdict(Counter)
    confusion = Counter()
    t0 = time.time()
    for i, r in enumerate(sample):
        gold = json.loads(r["messages"][2]["content"])["importance"]
        pred_raw = generate(tok, model, r["messages"][:2], max_new_tokens=300)
        pred = parse(pred_raw)
        p = str(pred.get("importance", "")).lower() if isinstance(pred, dict) else ""
        for group in ("all", r["meta"]["src"]):
            c = res[group]
            c["n"] += 1
            c["json_ok"] += pred is not None and p in LEVELS
            c["exact"] += p == gold
            c["within1"] += p in LEVELS and abs(LEVELS.index(p) - LEVELS.index(gold)) <= 1 and (p == "noise") == (gold == "noise")
            g_flag, p_flag = gold != "noise", p in LEVELS[:4]
            c["tp"] += g_flag and p_flag
            c["fp"] += (not g_flag) and p_flag
            c["fn"] += g_flag and not p_flag
        confusion[(gold, p or "invalid")] += 1
        if (i + 1) % 25 == 0:
            print(f"  {i + 1}/{len(sample)}  {(time.time() - t0) / (i + 1):.1f}s each", flush=True)

    report = {}
    for g, c in res.items():
        prec = c["tp"] / max(1, c["tp"] + c["fp"])
        rec = c["tp"] / max(1, c["tp"] + c["fn"])
        report[g] = {"n": c["n"], "valid_json": round(c["json_ok"] / c["n"], 3), "exact": round(c["exact"] / c["n"], 3),
                     "within_one_level": round(c["within1"] / c["n"], 3), "flag_precision": round(prec, 3),
                     "flag_recall": round(rec, 3)}
    report["confusion(gold->pred)"] = {f"{a}->{b}": n for (a, b), n in sorted(confusion.items())}
    print(json.dumps(report, indent=1))
    name = "base" if not adapter else str(adapter).replace("\\", "/").split("/")[-2]
    out = ROOT / "models" / f"eval-{name}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"adapter": str(adapter), "report": report}, indent=1))
    print("saved", out)


if __name__ == "__main__":
    main()
