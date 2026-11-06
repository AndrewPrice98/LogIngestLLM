"""Package your trained model for the downloadable app (built-in llama.cpp engine, no CUDA or Python needed).

    .venv-train/bin/python trainer/export.py --llama-cpp ~/src/llama.cpp            # -> dist/model/ (for the release)
    .venv-train/bin/python trainer/export.py --llama-cpp ~/src/llama.cpp --install  # ... and into ./model (use it now)

Produces:
    logingestllm-base-<Q>.gguf.part1, .part2 ...   the base model, quantized, split under GitHub's 2 GB file limit
    logingestllm-triage.lora.gguf                  your active adapter as a GGUF LoRA (switched on per request)
    SHA256SUMS                                     checked by the app when it joins the parts

Needs a llama.cpp checkout (for convert_hf_to_gguf.py / convert_lora_to_gguf.py, which use this venv's torch and
transformers) and llama-quantize (taken from ./engine, fetched by packaging/fetch_llama.py, or from the checkout).
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

from common import BASE_MODEL, ROOT, latest_adapter

PART = 1900 * 2**20  # < 2 GiB per release file


def run(cmd: list) -> None:
    print("$", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run([str(c) for c in cmd], check=True)


def base_dir() -> Path:
    from huggingface_hub import snapshot_download
    return Path(snapshot_download(BASE_MODEL, local_files_only=True))  # cached by training/serving; no download


def quantizer(llama: Path) -> Path:
    exe = ".exe" if sys.platform == "win32" else ""
    for p in [*(ROOT / "engine").rglob(f"llama-quantize{exe}"), llama / "build" / "bin" / f"llama-quantize{exe}"]:
        if p.exists():
            return p
    q = shutil.which("llama-quantize")
    if q:
        return Path(q)
    raise SystemExit("llama-quantize not found: run `python packaging/fetch_llama.py` first (puts it in ./engine)")


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(8 << 20):
            h.update(chunk)
    return h.hexdigest()


def split(src: Path, out: Path) -> list[Path]:
    parts, i = [], 1
    with open(src, "rb") as f:
        while chunk := f.read(PART):
            p = out / f"{src.name}.part{i}"
            p.write_bytes(chunk)
            parts.append(p)
            i += 1
    return parts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llama-cpp", required=True, help="llama.cpp checkout (git clone https://github.com/ggml-org/llama.cpp)")
    ap.add_argument("--adapter", help="default: the active adapter (models/ACTIVE) or the newest")
    ap.add_argument("--quant", default="Q4_K_M")
    ap.add_argument("--convert-python", help="python with llama.cpp's converter requirements (default: <llama-cpp>/.venv, "
                                              "else this venv)")
    ap.add_argument("--out", default=str(ROOT / "dist" / "model"))
    ap.add_argument("--install", action="store_true", help="also put the joined files in ./model for local use")
    args = ap.parse_args()
    llama = Path(args.llama_cpp).expanduser()
    for script in ("convert_hf_to_gguf.py", "convert_lora_to_gguf.py"):
        if not (llama / script).exists():
            raise SystemExit(f"{llama / script} not found: point --llama-cpp at a llama.cpp checkout")
    adapter = Path(args.adapter) if args.adapter else latest_adapter()
    if not adapter:
        raise SystemExit("no trained adapter in models/")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    work = ROOT / "dist" / "work-model"
    work.mkdir(parents=True, exist_ok=True)
    hf = base_dir()
    cands = [Path(args.convert_python).expanduser()] if args.convert_python else \
        [llama / ".venv" / "bin" / "python", llama / ".venv" / "Scripts" / "python.exe"]
    py = next((str(p) for p in cands if p.exists()), sys.executable)

    base = work / f"logingestllm-base-{args.quant}.gguf"
    if not base.exists():
        f16 = work / "logingestllm-base-f16.gguf"
        if not f16.exists():
            run([py, llama / "convert_hf_to_gguf.py", hf, "--outfile", f16, "--outtype", "f16"])
        run([quantizer(llama), f16, base, args.quant])
        f16.unlink()
    lora = work / "logingestllm-triage.lora.gguf"
    if not lora.exists() or lora.stat().st_mtime < (adapter / "adapter_model.safetensors").stat().st_mtime:
        run([py, llama / "convert_lora_to_gguf.py", adapter, "--base", hf, "--outfile", lora, "--outtype", "f16"])

    for old in out.glob("logingestllm-*"):
        old.unlink()
    parts = split(base, out)
    shutil.copy(lora, out / lora.name)
    (out / "SHA256SUMS").write_text(f"{sha256(base)}  {base.name}\n{sha256(lora)}  {lora.name}\n")
    (out / "MODEL-INFO.txt").write_text(f"adapter: {adapter.parent.name}\nbase: {BASE_MODEL} ({args.quant})\n")
    print(f"\nrelease files in {out}: " + ", ".join(p.name for p in sorted(out.iterdir())))
    if args.install:
        model = ROOT / "model"
        model.mkdir(exist_ok=True)
        shutil.copy(base, model / base.name)
        shutil.copy(lora, model / lora.name)
        print(f"installed into {model}: the app now uses the built-in engine when no other model is configured")


if __name__ == "__main__":
    main()
