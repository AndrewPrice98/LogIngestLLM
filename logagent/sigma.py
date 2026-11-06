"""Sigma rule support (https://sigmahq.io): drop .yml rules into rules/sigma/ (or set sigma_dir in logagent.toml).

Stdlib only, so it includes a small YAML reader for the subset Sigma rules use. Supported: selections (maps,
lists of maps, keyword lists), field modifiers contains / startswith / endswith / all / re / cidr / windash /
exists, wildcards (* ?), and conditions with and / or / not / parentheses / "1 of x*" / "all of x*" / "them".
A rule using something else (aggregations, base64 modifiers, correlation) is skipped and counted, never half-applied.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from pathlib import Path

from .model import Event
from .signals import Rule


# ---------------------------------------------------------------- tiny YAML (Sigma subset)
_BLOCKS: list[str] = []  # block scalars (| and >) of the document being read, referenced by placeholder


def _scalar(v: str):
    v = v.strip()
    if not v:
        return None
    m = re.fullmatch(r"\x00BLOCK(\d+)\x00", v)
    if m:
        return _BLOCKS[int(m.group(1))]
    if v[0] in "'\"" and v[-1] == v[0] and len(v) >= 2:
        inner = v[1:-1]
        return inner.replace("''", "'") if v[0] == "'" else bytes(inner, "utf-8").decode("unicode_escape")
    if v.startswith("[") and v.endswith("]"):
        return [_scalar(x) for x in _split_flow(v[1:-1])] if v[1:-1].strip() else []
    low = v.lower()
    if low in ("null", "~"):
        return None
    if low in ("true", "false"):
        return low == "true"
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    return v


def _split_flow(s: str) -> list[str]:
    out, cur, q = [], "", None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
            cur += ch
        elif ch == ",":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    return [x for x in out if x.strip()]


def _strip_comment(line: str) -> str:
    q = None
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def yaml_load(text: str):
    _BLOCKS.clear()
    lines = []
    raw = text.splitlines()
    i = 0
    while i < len(raw):  # fold block scalars (| and >) into one line value first
        line = _strip_comment(raw[i]) if not raw[i].lstrip().startswith("#") else ""
        m = re.match(r"^(\s*)(- )?([^:]+):\s*([|>])[-+]?\s*$", line)
        if m:
            ind = len(m.group(1))
            body = []
            i += 1
            while i < len(raw) and (not raw[i].strip() or len(raw[i]) - len(raw[i].lstrip()) > ind):
                body.append(raw[i].strip())
                i += 1
            joiner = "\n" if m.group(4) == "|" else " "
            _BLOCKS.append(joiner.join(body).strip())
            lines.append(f"{m.group(1)}{m.group(2) or ''}{m.group(3)}: \x00BLOCK{len(_BLOCKS) - 1}\x00")
            continue
        if line.strip() and line.strip() != "---":
            lines.append(line)
        i += 1
    pos = 0

    def ind(l):
        return len(l) - len(l.lstrip(" "))

    def block(level):
        nonlocal pos
        if pos >= len(lines):
            return None
        if lines[pos].lstrip().startswith("- "):
            out = []
            while pos < len(lines) and ind(lines[pos]) == level and lines[pos].lstrip().startswith("- "):
                item = lines[pos].lstrip()[2:]
                if re.match(r"^[^'\"\[{][^:]*:(\s|$)", item):  # "- key: value" starts a map inside the list
                    lines[pos] = " " * (level + 2) + item
                    out.append(block(level + 2))
                else:
                    pos += 1
                    out.append(_scalar(item))
            return out
        out = {}
        while pos < len(lines) and ind(lines[pos]) == level and not lines[pos].lstrip().startswith("- "):
            key, _, rest = lines[pos].strip().partition(":")
            key = key.strip().strip("'\"")
            pos += 1
            if rest.strip():
                out[key] = _scalar(rest)
            elif pos < len(lines) and ind(lines[pos]) > level:
                out[key] = block(ind(lines[pos]))
            elif pos < len(lines) and ind(lines[pos]) == level and lines[pos].lstrip().startswith("- "):
                out[key] = block(level)
            else:
                out[key] = None
        return out

    return block(ind(lines[0])) if lines else {}


# ---------------------------------------------------------------- matching
class Unsupported(ValueError):
    pass


# Sigma field names -> where logagent keeps them (Security 4688 names differ from Sysmon's)
ALIASES = {
    "Image": ("Image", "NewProcessName"), "ParentImage": ("ParentImage", "ParentProcessName"),
    "CommandLine": ("CommandLine", "ProcessCommandLine"), "ParentCommandLine": ("ParentCommandLine",),
    "User": ("User", "SubjectUserName", "TargetUserName"), "OriginalFileName": ("OriginalFileName",),
    "ScriptBlockText": ("ScriptBlockText",), "TargetFilename": ("TargetFilename",), "TargetObject": ("TargetObject",),
    "DestinationIp": ("DestinationIp", "IpAddress"), "SourceIp": ("SourceIp", "IpAddress"),
}
CATEGORY = {  # logsource.category -> (Windows event ids, provider substring)
    "process_creation": ({"1", "4688"}, None), "ps_script": ({"4104"}, "PowerShell"), "ps_module": ({"4103"}, "PowerShell"),
    "network_connection": ({"3"}, "Sysmon"), "image_load": ({"7"}, "Sysmon"), "file_event": ({"11"}, "Sysmon"),
    "process_access": ({"10"}, "Sysmon"), "registry_set": ({"13"}, "Sysmon"), "registry_event": ({"12", "13", "14"}, "Sysmon"),
    "dns_query": ({"22"}, "Sysmon"), "create_remote_thread": ({"8"}, "Sysmon"),
}
SERVICE = {"security": "Security", "system": "System", "sysmon": "Sysmon", "powershell": "PowerShell",
           "application": "Application", "windefend": "Defender"}
MODS = {"contains", "startswith", "endswith", "all", "re", "cidr", "windash", "exists", "i", "m", "s"}


def _field(e: Event, name: str):
    if name == "EventID":
        return e.event_id
    if name in ("Provider_Name", "Provider"):
        return e.program
    if name == "Channel":
        return e.source.split(":", 1)[-1]
    f = e.fields or {}
    for k in ALIASES.get(name, (name,)):
        if k in f and f[k] not in (None, ""):
            return f[k]
    return None


def _one(value: str, pat, mods: set) -> bool:
    if pat is None:
        return value is None or value == ""
    v, p = str(value), str(pat)
    if "re" in mods:
        return re.search(p, v) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(v.replace("::ffff:", "")) in ipaddress.ip_network(p, strict=False)
        except ValueError:
            return False
    v, p = v.lower(), p.lower()
    variants = [p, p.replace("-", "/"), p.replace("/", "-")] if "windash" in mods else [p]
    for p in variants:
        if "contains" in mods:
            p = f"*{p}*"
        elif "startswith" in mods:
            p = f"{p}*"
        elif "endswith" in mods:
            p = f"*{p}"
        if ("*" in p or "?" in p) and fnmatch.fnmatchcase(v, p):
            return True
        if "*" not in p and "?" not in p and v == p:
            return True
    return False


def _compile_selection(sel):
    if isinstance(sel, list) and all(isinstance(x, dict) for x in sel):
        subs = [_compile_selection(x) for x in sel]
        return lambda e: any(f(e) for f in subs)
    if isinstance(sel, list) or isinstance(sel, (str, int)):  # keywords: search the whole message
        words = [str(w) for w in (sel if isinstance(sel, list) else [sel])]
        return lambda e: any(_one(e.message, w, {"contains"}) for w in words)
    if not isinstance(sel, dict):
        raise Unsupported("selection must be a map or a list")
    checks = []
    for key, pats in sel.items():
        name, *mods = key.split("|")
        mods = set(mods)
        if not mods <= MODS:
            raise Unsupported(f"modifier {sorted(mods - MODS)}")
        pats = pats if isinstance(pats, list) else [pats]
        if "exists" in mods:
            want = bool(pats[0])
            checks.append(lambda e, n=name, w=want: (_field(e, n) not in (None, "")) == w)
            continue
        all_mode = "all" in mods

        def check(e, n=name, ps=pats, m=mods, a=all_mode):
            v = _field(e, n)
            if v is None:
                return any(p is None for p in ps)
            hits = (_one(v, p, m) for p in ps)
            return all(hits) if a else any(hits)
        checks.append(check)
    return lambda e: all(c(e) for c in checks)


def _compile_condition(cond: str, sels: dict):
    toks = re.findall(r"\(|\)|[\w*]+", cond)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def names(pat):
        hits = [n for n in sels if pat == "them" or fnmatch.fnmatchcase(n, pat)]
        if not hits:
            raise Unsupported(f"no selection matches {pat}")
        return hits

    def atom():
        t = take()
        if t == "(":
            f = orexp()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return f
        if t == "not":
            f = atom()
            return lambda e: not f(e)
        if t in ("1", "all", "any") and peek() == "of":
            take()
            fs = [sels[n] for n in names(take())]
            return (lambda e: all(f(e) for f in fs)) if t == "all" else (lambda e: any(f(e) for f in fs))
        if t in sels:
            return sels[t]
        raise Unsupported(f"condition token {t!r}")

    def andexp():
        f = atom()
        while peek() == "and":
            take()
            g, h = f, atom()
            f = lambda e, g=g, h=h: g(e) and h(e)
        return f

    def orexp():
        f = andexp()
        while peek() == "or":
            take()
            g, h = f, andexp()
            f = lambda e, g=g, h=h: g(e) or h(e)
        return f

    fn = orexp()
    if pos != len(toks):
        raise Unsupported(f"trailing condition tokens {toks[pos:]}")
    return fn


LEVEL_SCORE = {"informational": 20, "low": 40, "medium": 60, "high": 80, "critical": 95}


class SigmaRule(Rule):
    def __init__(self, doc: dict, path: str):
        det = dict(doc.get("detection") or {})
        cond = det.pop("condition", None)
        det.pop("timeframe", None)
        if isinstance(cond, list):
            cond = " or ".join(f"({c})" for c in cond)
        if not cond or "|" in str(cond) or re.search(r"\b(count|near|min|max|sum|avg)\b", str(cond)):
            raise Unsupported("aggregation conditions")
        sels = {k: _compile_selection(v) for k, v in det.items()}
        self._fn = _compile_condition(str(cond), sels)
        ls = doc.get("logsource") or {}
        self._product, self._service, self._category = ls.get("product"), ls.get("service"), ls.get("category")
        if self._category and self._category not in CATEGORY:
            raise Unsupported(f"logsource category {self._category}")
        tags = [str(t) for t in doc.get("tags") or []]
        attack = [t.split(".", 1)[1].upper() for t in tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
        fp = doc.get("falsepositives") or []
        super().__init__(
            id="sigma:" + str(doc.get("id") or Path(path).stem), title=str(doc.get("title") or Path(path).stem),
            category="security", score=LEVEL_SCORE.get(str(doc.get("level", "medium")).lower(), 60),
            why=str(doc.get("description") or "Matched a Sigma rule.").strip(),
            action=("Possible false positives: " + "; ".join(map(str, fp)) + ". " if fp else "") +
                   f"Sigma rule {Path(path).name}" + (f" by {doc['author']}" if doc.get("author") else "") + ".")
        self.attack = tuple(attack)

    def matches(self, e: Event) -> bool:
        win = e.source.startswith("windows")
        if self._product == "windows" and not win or self._product == "linux" and win:
            return False
        if self._service and SERVICE.get(self._service, self._service).lower() not in (e.source + " " + e.program).lower():
            return False
        if self._category:
            ids, prov = CATEGORY[self._category]
            if e.event_id not in ids or (prov and prov.lower() not in (e.program + e.source).lower()):
                return False
        try:
            return self._fn(e)
        except (re.error, TypeError):
            return False


def load_dir(path: str | Path) -> tuple[list[Rule], list[tuple[str, str]]]:
    """All rules in a folder (recursively). Returns (rules, [(file, why skipped)])."""
    rules, skipped = [], []
    p = Path(path).expanduser()
    if not p.is_dir():
        return rules, skipped
    for f in sorted(list(p.rglob("*.yml")) + list(p.rglob("*.yaml"))):
        try:
            doc = yaml_load(f.read_text(encoding="utf-8", errors="replace"))
            if not isinstance(doc, dict) or "detection" not in doc:
                raise Unsupported("not a Sigma rule")
            if str(doc.get("status", "")).lower() in ("deprecated", "unsupported"):
                raise Unsupported(f"status {doc['status']}")
            rules.append(SigmaRule(doc, str(f)))
        except (Unsupported, ValueError, KeyError, AttributeError, TypeError) as exc:
            skipped.append((str(f), str(exc)[:200]))
    return rules, skipped
