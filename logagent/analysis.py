"""Cluster events into templates and score them so only the valuable ones reach the LLM.

Score = best matching rule score
      + severity bonus
      + novelty bonus   (template never seen on a previous scan of this host)
      + burst bonus     (many hits in the window)
      - chatter penalty (a template that shows up every scan with no rule hit)
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .model import Event, WARNING, NOTICE, SEVERITY_NAMES
from .signals import Rule, match_rules

_MASKS = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I), "<mac>"),
    (re.compile(r"\b0x[0-9a-f]+\b", re.I), "<hex>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?Z?"), "<ts>"),
    (re.compile(r"(?:[A-Za-z]:)?[\\/](?:[\w.$-]+[\\/])+[\w.$-]*"), "<path>"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<n>"),
]


def template_of(msg: str) -> str:
    t = msg[:400]
    for rx, rep in _MASKS:
        t = rx.sub(rep, t)
    return " ".join(t.split())


@dataclass
class Cluster:
    key: str
    template: str
    host: str
    source: str
    program: str
    event_id: str
    events: list[Event] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    worst: int = 7
    score: float = 0.0
    novel: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def first(self):
        return min(e.ts for e in self.events)

    @property
    def last(self):
        return max(e.ts for e in self.events)

    @property
    def rule(self) -> Rule | None:
        return max(self.rules, key=lambda r: r.score) if self.rules else None

    def samples(self, n: int = 3) -> list[str]:
        seen, out = set(), []
        for e in sorted(self.events, key=lambda e: e.ts, reverse=True):
            m = e.message[:700]
            if m not in seen:
                seen.add(m)
                out.append(m)
            if len(out) >= n:
                break
        return out

    def to_dict(self) -> dict:
        r = self.rule
        last = sorted(self.events, key=lambda e: e.ts)[-1]
        return {
            "key": self.key, "host": self.host, "source": self.source, "program": self.program,
            "event_id": self.event_id, "count": self.count, "first": self.first.isoformat(),
            "last": self.last.isoformat(), "severity": SEVERITY_NAMES[self.worst],
            "score": round(self.score, 1), "novel": self.novel, "template": self.template,
            "samples": self.samples(), "reasons": self.reasons,
            "rule": None if not r else {"id": r.id, "title": r.title, "category": r.category,
                                        "why": r.why, "action": r.action},
            "fields": {k: v for k, v in last.fields.items() if v not in (None, "", "-")} if last.fields else {},
        }


def cluster_events(events: Iterable[Event], rules: list[Rule], each=None) -> list[Cluster]:
    """Group events by template. `each(event, key)` is called for every event (used for indicator extraction)."""
    clusters: dict[str, Cluster] = {}
    for e in events:
        tmpl = template_of(e.message)
        key = hashlib.sha1(f"{e.host}|{e.source}|{e.program}|{e.event_id}|{tmpl}".encode()).hexdigest()[:16]
        if each:
            each(e, key)
        c = clusters.get(key)
        if c is None:
            c = clusters[key] = Cluster(key, tmpl, e.host, e.source, e.program, e.event_id)
            c.rules = match_rules(e, rules)
        c.events.append(e)
        c.worst = min(c.worst, e.severity)
    return list(clusters.values())


class Baseline:
    """Per-host memory of which templates have been seen before and how often."""

    def __init__(self, path: Path):
        self.path = path
        try:
            self.data: dict = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            self.data = {}

    def seen_scans(self, key: str) -> int:
        return self.data.get(key, {}).get("scans", 0)

    def is_empty_for(self, host: str) -> bool:
        return not any(v.get("host") == host for v in self.data.values())

    def update(self, clusters: list[Cluster]) -> None:
        for c in clusters:
            d = self.data.setdefault(c.key, {"host": c.host, "template": c.template[:200], "scans": 0, "total": 0})
            d["scans"] += 1
            d["total"] += c.count
            d["last"] = c.last.isoformat()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data), encoding="utf-8")


_SEV_BONUS = {0: 40, 1: 35, 2: 30, 3: 18, 4: 8, 5: 3}


def score_clusters(clusters: list[Cluster], baseline: Baseline | None = None) -> list[Cluster]:
    fresh_hosts = {c.host for c in clusters if baseline is None or baseline.is_empty_for(c.host)}
    for c in clusters:
        reasons = []
        if any(r.score < 0 for r in c.rules):  # known-benign noise
            c.rules, c.score, c.reasons = [], 0.0, ["known benign noise"]
            continue
        rule_hits = [r for r in c.rules if c.count >= r.min_count]
        c.rules = rule_hits
        base = max((r.score for r in rule_hits), default=0)
        if rule_hits:
            reasons.append(f"matches '{c.rule.title}'")
        sev = _SEV_BONUS.get(c.worst, 0)
        if sev >= 18:
            reasons.append(f"severity {['emerg','alert','crit','err','warning'][c.worst]}")
        burst = min(20, 6 * math.log10(c.count)) if c.count > 1 else 0
        if c.count >= 10:
            reasons.append(f"{c.count} occurrences")
        novelty = 0
        if baseline is not None and c.host not in fresh_hosts:
            seen = baseline.seen_scans(c.key)
            if seen == 0 and (rule_hits or c.worst <= WARNING):
                novelty = 15
                c.novel = True
                reasons.append("first time seen on this host")
            elif seen >= 5 and not rule_hits:
                novelty = -15  # routine chatter
        c.score = max(0.0, base + sev + burst + novelty) if (rule_hits or c.worst <= NOTICE) else min(10.0, burst)
        c.reasons = reasons
    clusters.sort(key=lambda c: (c.score, c.count), reverse=True)
    return clusters


def select_findings(clusters: list[Cluster], limit: int = 40, min_score: float = 30) -> list[Cluster]:
    return [c for c in clusters if c.score >= min_score][:limit]
