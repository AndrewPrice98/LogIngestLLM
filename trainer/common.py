"""Shared model loading for train / evaluate / serve. Run with .venv-train (Python 3.12 + CUDA torch)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

BASE_MODEL = os.environ.get("LOGAGENT_BASE", "Qwen/Qwen3-4B-Instruct-2507")
ROOT = Path(__file__).resolve().parents[1]
MODELS = ROOT / "models"


def quant_config() -> BitsAndBytesConfig:
    return BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
                              bnb_4bit_compute_dtype=torch.bfloat16)


def load(adapter: str | Path | None = None, base: str = BASE_MODEL, for_training: bool = False):
    tok = AutoTokenizer.from_pretrained(base)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(base, quantization_config=quant_config(), device_map={"": 0},
                                                 dtype=torch.bfloat16, attn_implementation="sdpa")
    if adapter:
        from peft import PeftModel
        model = PeftModel.from_pretrained(model, str(adapter), is_trainable=for_training)
    if not for_training:
        model.eval()
    return tok, model


@torch.inference_mode()
def generate(tok, model, messages: list[dict], max_new_tokens: int = 400, temperature: float = 0.0) -> str:
    ids = tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt", return_dict=True)
    ids = {k: v.to(model.device) for k, v in ids.items()}
    kw = {"do_sample": temperature > 0, "max_new_tokens": max_new_tokens, "pad_token_id": tok.pad_token_id}
    if temperature > 0:
        kw["temperature"] = temperature
    out = model.generate(**ids, **kw)
    return tok.decode(out[0, ids["input_ids"].shape[1]:], skip_special_tokens=True).strip()


def read_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def latest_adapter() -> Path | None:
    runs = sorted((MODELS).glob("logagent-*/adapter"), key=lambda p: p.stat().st_mtime) if MODELS.exists() else []
    return runs[-1] if runs else None
