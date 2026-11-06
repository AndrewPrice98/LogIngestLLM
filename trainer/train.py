"""QLoRA fine-tune of a small open model on your log-triage data.

    .venv-train\\Scripts\\python trainer\\train.py                 # uses train_data/train.jsonl
    .venv-train\\Scripts\\python trainer\\train.py --epochs 2 --resume models\\logagent-XXXX\\adapter

Only the assistant's answer is trained on (the prompt tokens are masked out).
Output: models/logagent-<timestamp>/adapter  (small LoRA weights, ~60 MB; the base model stays untouched)
"""
from __future__ import annotations

import argparse
import json
import math
import random
import time
from datetime import datetime

import torch
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

from common import BASE_MODEL, MODELS, ROOT, load, read_jsonl


def tokenize(tok, ex: dict, max_len: int):
    msgs = ex["messages"]
    prompt = tok.apply_chat_template(msgs[:-1], add_generation_prompt=True, tokenize=False)
    full = prompt + msgs[-1]["content"] + tok.eos_token
    p_ids = tok(prompt, add_special_tokens=False)["input_ids"]
    f_ids = tok(full, add_special_tokens=False)["input_ids"][:max_len]
    labels = [-100] * min(len(p_ids), len(f_ids)) + f_ids[len(p_ids):]
    return f_ids, labels[: len(f_ids)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(ROOT / "train_data" / "train.jsonl"))
    ap.add_argument("--base", default=BASE_MODEL)
    ap.add_argument("--resume", help="continue training an existing adapter")
    ap.add_argument("--epochs", type=float, default=1.0)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--rank", type=int, default=16)
    ap.add_argument("--max-len", type=int, default=768)
    ap.add_argument("--batch-tokens", type=int, default=1024, help="tokens per micro-batch (fit to 8 GB)")
    ap.add_argument("--accum", type=int, default=16)
    ap.add_argument("--limit", type=int, help="use only N examples (smoke test)")
    args = ap.parse_args()

    torch.manual_seed(0)
    rows = read_jsonl(args.data)
    if args.limit:
        rows = rows[: args.limit]
    tok, model = load(args.resume, args.base, for_training=True)
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True,
                                            gradient_checkpointing_kwargs={"use_reentrant": False})
    if not args.resume:
        model = get_peft_model(model, LoraConfig(
            r=args.rank, lora_alpha=args.rank * 2, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]))
    model.print_trainable_parameters()

    data = [tokenize(tok, r, args.max_len) for r in rows]
    data = [d for d in data if any(l != -100 for l in d[1])]
    print(f"{len(data)} examples, avg {sum(len(d[0]) for d in data) / len(data):.0f} tokens")

    # Length-bucketed micro-batches: little padding, steady memory use.
    def batches():
        order = list(range(len(data)))
        random.shuffle(order)
        chunks = [sorted(order[i:i + 256], key=lambda j: len(data[j][0])) for i in range(0, len(order), 256)]
        out = []
        for ch in chunks:
            cur, longest = [], 0
            for j in ch:
                L = len(data[j][0])
                if cur and max(longest, L) * (len(cur) + 1) > args.batch_tokens:
                    out.append(cur)
                    cur, longest = [], 0
                cur.append(j)
                longest = max(longest, L)
            if cur:
                out.append(cur)
        random.shuffle(out)
        return out

    def collate(idx):
        L = max(len(data[j][0]) for j in idx)
        ids = torch.full((len(idx), L), tok.pad_token_id)
        lab = torch.full((len(idx), L), -100)
        att = torch.zeros((len(idx), L), dtype=torch.long)
        for r, j in enumerate(idx):
            a, b = data[j]
            ids[r, :len(a)], lab[r, :len(b)], att[r, :len(a)] = torch.tensor(a), torch.tensor(b), 1
        return ids.cuda(), lab.cuda(), att.cuda()

    per_epoch = batches()
    total_micro = int(len(per_epoch) * args.epochs)
    total_steps = math.ceil(total_micro / args.accum)
    params = [p for p in model.parameters() if p.requires_grad]
    opt = torch.optim.AdamW(params, lr=args.lr, weight_decay=0.0)
    warm = max(1, total_steps // 20)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1.0, (s + 1) / warm) * 0.5 * (1 + math.cos(math.pi * min(1.0, s / total_steps))))

    out_dir = MODELS / f"logagent-{datetime.now():%Y%m%d-%H%M}"
    print(f"training {total_steps} steps ({total_micro} micro-batches) -> {out_dir}")
    model.train()
    t0, step, micro, run_loss, since = time.time(), 0, 0, 0.0, 0
    queue = []
    while micro < total_micro:
        if not queue:
            queue = batches()
        ids, lab, att = collate(queue.pop())
        loss = model(input_ids=ids, attention_mask=att, labels=lab).loss / args.accum
        loss.backward()
        run_loss += loss.item()
        micro += 1
        if micro % args.accum == 0 or micro == total_micro:
            torch.nn.utils.clip_grad_norm_(params, 1.0)
            opt.step()
            sched.step()
            opt.zero_grad(set_to_none=True)
            step += 1
            since += 1
            if step % 5 == 0 or step == total_steps:
                el = time.time() - t0
                print(f"step {step}/{total_steps} loss {run_loss / since:.4f} "
                      f"lr {sched.get_last_lr()[0]:.2e} {el / 60:.1f}m elapsed, ~{el / step * (total_steps - step) / 60:.0f}m left "
                      f"mem {torch.cuda.max_memory_allocated() / 2**30:.1f}GB", flush=True)
                run_loss, since = 0.0, 0

    model.save_pretrained(out_dir / "adapter")
    tok.save_pretrained(out_dir / "adapter")
    (out_dir / "train_info.json").write_text(json.dumps({
        "base": args.base, "examples": len(data), "epochs": args.epochs, "lr": args.lr, "rank": args.rank,
        "steps": total_steps, "minutes": round((time.time() - t0) / 60, 1), "data": args.data,
        "resumed_from": args.resume}, indent=1))
    print(f"saved {out_dir / 'adapter'}")


if __name__ == "__main__":
    main()
