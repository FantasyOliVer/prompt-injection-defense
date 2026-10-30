# -*- coding: utf-8 -*-
"""运行全部实验，结果写入 results/。"""
import argparse
import csv
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pibench import datasets, detectors, gate, metrics   # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "results")


def save_corpus(samples):
    os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
    path = os.path.join(ROOT, "data", "corpus.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    return path


def run_detectors(samples, quick):
    protocols = ["random"] if quick else ["random", "group"]
    rows = []
    for key, factory in detectors.ALL.items():
        for proto in protocols:
            t0 = time.time()
            recs = metrics.cross_validate(samples, factory, protocol=proto)
            m = metrics.summarize(recs)
            rows.append(dict(detector=factory.name, key=key, protocol=proto,
                             precision=m["precision"], recall=m["recall"], f1=m["f1"],
                             fpr=m["fpr"], macro_recall=m["macro_recall"],
                             per_cat=m["per_category_recall"], sec=time.time() - t0))
    return rows


def run_gate():
    samples = gate.build_output_samples()
    rows = []
    for lvl in (0, 1, 2, 3):
        hit = tot = fp = neg = 0
        for text, exfil, kid, _kind in samples:
            removed, _ = gate.apply_gate(text, lvl)
            if exfil:
                tot += 1
                hit += 1 if kid in removed else 0
            else:
                chans = gate.extract_channels(text)
                if not chans:
                    continue
                neg += 1
                if any(c[0] in removed for c in chans):
                    fp += 1
        rows.append(dict(level=lvl, block_rate=hit / max(tot, 1),
                         fp_rate=fp / max(neg, 1), n_pos=tot, n_neg=neg))
    return rows


def write_csv(path, rows, fields):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 4) if isinstance(v, float) else v)
                        for k, v in r.items() if k in fields})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    samples = datasets.build()
    pos = sum(1 for s in samples if s["label"] == 1)
    print("corpus: %d (pos %d / neg %d), templates %d"
          % (len(samples), pos, len(samples) - pos, len({s["tpl"] for s in samples})))
    save_corpus(samples)
    det_rows = run_detectors(samples, args.quick)
    gate_rows = run_gate()

    write_csv(os.path.join(OUT, "detectors.csv"), det_rows,
              ["detector", "protocol", "precision", "recall", "f1", "fpr",
               "macro_recall", "sec"])
    write_csv(os.path.join(OUT, "gate.csv"), gate_rows,
              ["level", "block_rate", "fp_rate", "n_pos", "n_neg"])
    summary = dict(corpus=dict(n=len(samples), pos=pos, neg=len(samples) - pos,
                               templates=len({s["tpl"] for s in samples})),
                   detectors=[{k: v for k, v in r.items() if k != "sec"} for r in det_rows],
                   gate=gate_rows)
    with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    for r in det_rows:
        print("%s / %s: P=%.3f R=%.3f F1=%.3f FPR=%.3f"
              % (r["detector"], r["protocol"], r["precision"], r["recall"],
                 r["f1"], r["fpr"]))
    for r in gate_rows:
        print("G%d: block=%.3f fp=%.3f" % (r["level"], r["block_rate"], r["fp_rate"]))


if __name__ == "__main__":
    main()
