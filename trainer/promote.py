"""Switch to a newly trained model only if it is better.

    .venv-train/bin/python trainer/promote.py                 # newest adapter vs the one in use
    .venv-train/bin/python trainer/promote.py --candidate models/logagent-XXXX/adapter

Both are scored on the same held-out examples (train_data/eval.jsonl, fixed sample). Your own labels decide when
there are at least 10 of them; otherwise all held-out examples do. The winner is written to models/ACTIVE, which
trainer/serve.py loads. Then run `python -m logagent eval --model` to check the whole co-pilot with it.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime

from common import MODELS, ROOT, latest_adapter, newest_adapter, read_jsonl
from evaluate import balanced_sample, score


def quality(r: dict) -> float:
    """One number: exact level, near-miss credit, and how well it separates real findings from noise."""
    p, rc = r["flag_precision"], r["flag_recall"]
    f1 = 2 * p * rc / (p + rc) if p + rc else 0.0
    return round(0.5 * r["exact"] + 0.2 * r["within_one_level"] + 0.3 * f1, 4)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidate", help="adapter folder (default: newest trained)")
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--min-gain", type=float, default=0.005, help="required improvement to switch")
    args = ap.parse_args()
    cand = ROOT / args.candidate if args.candidate else newest_adapter()
    cur = latest_adapter()
    if cur and cand and cur.resolve() == cand.resolve() and not (MODELS / "ACTIVE").exists():
        # no pointer yet: the one in use is the newest adapter before the candidate
        older = sorted(p for p in MODELS.glob("logagent-*/adapter") if p.parent.name < cand.parent.name)
        cur = older[-1] if older else None
    if not cand:
        raise SystemExit("no trained adapter found in models/")
    if cur and cand.resolve() == cur.resolve():
        raise SystemExit(f"{cand} is already the model in use; train a new one first")
    sample = balanced_sample(read_jsonl(ROOT / "train_data" / "eval.jsonl"), args.n)
    group = "you" if sum(1 for r in sample if r["meta"]["src"] == "you") >= 10 else "all"
    rc = score(cand, sample, lambda m: print(m, flush=True))
    ru = score(cur, sample, lambda m: print(m, flush=True)) if cur else None
    qc, qu = quality(rc[group]), (quality(ru[group]) if ru else -1)
    valid = rc["all"]["valid_json"] >= 0.95
    promote = valid and qc >= qu + args.min_gain
    verdict = {"created": datetime.now().isoformat(timespec="seconds"), "decided_on": group,
               "candidate": str(cand.relative_to(ROOT)), "candidate_quality": qc, "candidate_report": rc,
               "current": str(cur.relative_to(ROOT)) if cur else None, "current_quality": qu, "current_report": ru,
               "promoted": promote}
    (MODELS / f"promote-{datetime.now():%Y%m%d-%H%M}.json").write_text(json.dumps(verdict, indent=1))
    # same held-out set for both, so the dashboard's MODELS page compares like with like
    for adapter, rep in ((cand, rc), (cur, ru)):
        if adapter and rep:
            (MODELS / f"eval-{adapter.parent.name}.json").write_text(json.dumps(
                {"adapter": str(adapter.relative_to(ROOT)), "data": "train_data/eval.jsonl", "n": args.n, "report": rep}, indent=1))
    print(f"\ncandidate {cand.parent.name}: quality {qc}  |  current {cur.parent.name if cur else '-'}: quality {qu}  "
          f"(decided on: {group})")
    if promote:
        (MODELS / "ACTIVE").write_text(str(cand.parent.relative_to(ROOT) / "adapter").replace("\\", "/") + "\n")
        print(f"PROMOTED: models/ACTIVE -> {cand.parent.name}. Restart the model server to use it, then run "
              f"`python -m logagent eval --model`.")
    else:
        print("kept the current model" + ("" if valid else " (candidate produced invalid JSON too often)"))


if __name__ == "__main__":
    main()
