"""Render the LinkedIn carousel (docs/promo/carousel.html) to PNG slides + a PDF, with numbers from models/.

    uv run --no-project --with playwright python docs/promo/render.py [--browser /usr/bin/microsoft-edge]

Reads the latest promotion decision and co-pilot evaluation, and the screenshots in docs/img/.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODELS = ROOT / "models"


def latest(pattern: str) -> dict | None:
    files = sorted(MODELS.glob(pattern))
    return json.loads(files[-1].read_text()) if files else None


def img(name: str) -> str:
    p = ROOT / "docs" / "img" / name
    return "data:image/png;base64," + base64.b64encode(p.read_bytes()).decode() if p.exists() else ""


def bar(label: str, value: float, color: str) -> str:
    return (f'<div class="bar"><div class="t">{label}<span>{value * 100:.0f}%</span></div>'
            f'<div class="track"><div class="fill" style="width:{value * 100:.1f}%;background:{color}"></div></div></div>')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--browser", default="/usr/bin/microsoft-edge")
    a = ap.parse_args()
    promo = latest("promote-*.json") or {}
    base = json.loads((MODELS / "eval-base.json").read_text()) if (MODELS / "eval-base.json").exists() else None
    cur, cand = (promo.get("current_report") or {}).get("all", {}), (promo.get("candidate_report") or {}).get("all", {})
    names = [(promo.get("current") or "v1").split("/")[1] if promo.get("current") else "v1",
             (promo.get("candidate") or "v2").split("/")[1] if promo.get("candidate") else "v2"]
    bars = []
    if base:
        bars.append(bar("Base model, no fine-tune", base["report"]["all"]["exact"], "var(--line2)"))
    if cur:
        bars.append(bar("v1: rules + synthetic data", cur["exact"], "var(--accent2)"))
    if cand:
        bars.append(bar("v2: rebalanced, tool-aware data", cand["exact"], "var(--accent)"))
    reports = {}
    for p in sorted(MODELS.glob("copilot-eval-model-*.json")):
        r = json.loads(p.read_text())
        reports[r.get("adapter")] = f"{r['passed']}/{r['total']}"
    copilot = " → ".join(f"{v}" for v in reports.values()) or "see the MODELS page"
    checks = sum(s.get("total", 0) for s in (latest("copilot-eval-model-*.json") or {}).get("scenarios", []))
    train = json.loads((ROOT / "models" / names[1] / "train_info.json").read_text()) if (ROOT / "models" / names[1] / "train_info.json").exists() else {}
    html = (HERE / "carousel.html").read_text()
    for k, v in {"{{SHOT_OVERVIEW}}": img("overview.png"), "{{SHOT_LOG}}": img("log-viewer.png"),
                 "{{BARS}}": "\n".join(bars), "{{COPILOT}}": copilot, "{{CHECKS}}": str(checks or 108),
                 "{{TRAIN_MIN}}": str(round(train.get("minutes", 44)))}.items():
        html = html.replace(k, v)
    built = HERE / "carousel.built.html"
    built.write_text(html)

    from playwright.sync_api import sync_playwright
    out = HERE / "slides"
    out.mkdir(exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=a.browser, headless=True)
        pg = b.new_page(viewport={"width": 1080, "height": 1350}, device_scale_factor=1)
        pg.goto(built.as_uri())
        pg.wait_for_timeout(500)
        for i, s in enumerate(pg.locator("section.s").all(), 1):
            s.screenshot(path=str(out / f"slide-{i}.png"))
        pg.pdf(path=str(HERE / "LogIngestLLM-carousel.pdf"), width="1080px", height="1350px", print_background=True)
        b.close()
    built.unlink()
    print(f"slides in {out}, PDF at {HERE / 'LogIngestLLM-carousel.pdf'}")


if __name__ == "__main__":
    main()
