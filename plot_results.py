# -*- coding: utf-8 -*-
"""由 results/summary.json 生成实验图（SVG）。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pibench import chart   # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(ROOT, "results", "summary.json")


def main():
    if not os.path.exists(RES):
        sys.exit("缺少 results/summary.json")

    with open(RES, encoding="utf-8") as f:
        data = json.load(f)

    by = {(r["detector"], r["protocol"]): r for r in data["detectors"]}
    cats = ["A1", "A2", "A3", "A4", "A5", "A6"]
    labels = ["A1 直接", "A2 间接", "A3 多轮", "A4 编码", "A5 后缀", "A6 角色"]
    series = []
    for key, name in (("D2 朴素贝叶斯", "朴素贝叶斯"),
                      ("D4 逻辑回归（原始特征）", "LR(原始)"),
                      ("D6 级联（本文）", "级联(本文)")):
        row = by.get((key, "group"))
        if row:
            series.append((name, [row["per_cat"][c] for c in cats]))
    if not series:
        sys.exit("summary.json 中没有 P2 结果")

    p1 = chart.grouped_bars(labels, series,
                            os.path.join(ROOT, "results", "fig_recall.svg"),
                            ylabel="召回率", title="六类攻击的召回率（未见过模板的 5 折）")

    gates = data["gate"]
    xs = ["G0", "G1", "G2", "G3"]
    p2 = chart.two_lines(xs, [("拦截率", [g["block_rate"] for g in gates], False),
                              ("误伤率", [g["fp_rate"] for g in gates], True)],
                         os.path.join(ROOT, "results", "fig_gate.svg"),
                         ylabel="比例", title="出网管控四档关口")
    print("saved: %s" % os.path.relpath(p1, ROOT))
    print("saved: %s" % os.path.relpath(p2, ROOT))


if __name__ == "__main__":
    main()
