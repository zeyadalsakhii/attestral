"""Threshold calibration for the Attestral ML layer (Tier 1 - no training).

Runs a model over a labeled JSONL of your own surfaces and prints
precision/recall/F1 at each candidate threshold, so you can pick the
`--ml-threshold` that fits your risk appetite without touching weights.

    python evaluate.py --data data/my-surfaces.jsonl
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_jsonl(path: str) -> list[dict]:
    rows = []
    for line in Path(path).read_text().splitlines():
        if line.strip():
            obj = json.loads(line)
            rows.append({"text": str(obj["text"]), "label": int(obj["label"])})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", required=True, help="Labeled JSONL ({text, label}).")
    ap.add_argument("--model", default="protectai/deberta-v3-base-prompt-injection-v2")
    ap.add_argument("--revision", default="main")
    args = ap.parse_args()

    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        TextClassificationPipeline,
    )

    tok = AutoTokenizer.from_pretrained(args.model, revision=args.revision)
    mdl = AutoModelForSequenceClassification.from_pretrained(args.model, revision=args.revision)
    pipe = TextClassificationPipeline(model=mdl, tokenizer=tok, truncation=True,
                                      max_length=512, top_k=None)

    rows = load_jsonl(args.data)

    def inj_prob(text: str) -> float:
        out = pipe(text)
        scores = out[0] if out and isinstance(out[0], list) else out
        for e in scores:
            if "inject" in str(e.get("label", "")).lower():
                return float(e["score"])
        return 0.0

    probs = [(inj_prob(r["text"]), r["label"]) for r in rows]
    print(f"{'thresh':>7}  {'precision':>9}  {'recall':>7}  {'f1':>6}")
    for t in [i / 20 for i in range(2, 20)]:
        tp = sum(1 for p, y in probs if p >= t and y == 1)
        fp = sum(1 for p, y in probs if p >= t and y == 0)
        fn = sum(1 for p, y in probs if p < t and y == 1)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        print(f"{t:>7.2f}  {prec:>9.3f}  {rec:>7.3f}  {f1:>6.3f}")


if __name__ == "__main__":
    main()
