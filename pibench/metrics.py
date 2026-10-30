# -*- coding: utf-8 -*-
"""指标与交叉验证协议：P1 随机 5 折，P2 按模板分组 5 折。"""
import random


def prf(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=rec, f1=f1, fpr=fpr)


def tune_threshold(scores, labels):
    """按宏平均 F1 选阈值。

    语料中攻击样本偏多（约 7:3），若直接最大化正类 F1，“全部判为攻击”会取得虚高分数；
    宏平均 F1 对两类等权，可避免阈值退化。
    """
    cand = sorted(set(scores))
    if not cand:
        return 0.5
    best, best_t = -1.0, cand[-1]
    for t in cand:
        pred = [1 if s >= t else 0 for s in scores]
        m = prf(labels, pred)
        f1_neg = 0.0
        tp0 = m["tn"]
        prec0 = tp0 / (tp0 + m["fn"]) if (tp0 + m["fn"]) else 0.0
        rec0 = tp0 / (tp0 + m["fp"]) if (tp0 + m["fp"]) else 0.0
        if prec0 + rec0:
            f1_neg = 2 * prec0 * rec0 / (prec0 + rec0)
        macro = (m["f1"] + f1_neg) / 2
        if macro > best:
            best, best_t = macro, t
    return best_t


def _stratified_random_folds(samples, k=5, seed=7):
    rng = random.Random(seed)
    idx_by_label = {}
    for i, s in enumerate(samples):
        idx_by_label.setdefault(s["label"], []).append(i)
    folds = [[] for _ in range(k)]
    for label, idxs in idx_by_label.items():
        rng.shuffle(idxs)
        for j, i in enumerate(idxs):
            folds[j % k].append(i)
    return folds


def _group_folds(samples, k=5, seed=7):
    """按模板分组，同一模板的样本不跨训练/测试。"""
    rng = random.Random(seed)
    groups = {}
    for i, s in enumerate(samples):
        groups.setdefault(s["tpl"], []).append(i)
    keys = sorted(groups)
    rng.shuffle(keys)
    loads = [0] * k
    folds = [[] for _ in range(k)]
    for key in keys:
        j = min(range(k), key=lambda x: loads[x])
        folds[j].extend(groups[key])
        loads[j] += len(groups[key])
    return folds


def cross_validate(samples, factory, protocol="random", k=5, seed=7):
    """返回每条样本的预测记录。"""
    folds = (_stratified_random_folds(samples, k, seed) if protocol == "random"
             else _group_folds(samples, k, seed))
    rng = random.Random(seed + 1)
    recs = []
    for fi, test_idx in enumerate(folds):
        test_set = set(test_idx)
        train_idx = [i for i in range(len(samples)) if i not in test_set]
        # 训练折内部再切 80/20 用于调阈值
        rng.shuffle(train_idx)
        cut = max(int(len(train_idx) * 0.8), 1)
        fit_idx, val_idx = train_idx[:cut], train_idx[cut:]
        det = factory()
        det.fit([samples[i] for i in fit_idx])
        val_scores = det.score([samples[i] for i in val_idx])
        thr = tune_threshold(val_scores, [samples[i]["label"] for i in val_idx])
        test_scores = det.score([samples[i] for i in test_idx])
        for i, sc in zip(test_idx, test_scores):
            recs.append(dict(idx=i, fold=fi, score=sc, thr=thr,
                             y=samples[i]["label"], pred=1 if sc >= thr else 0,
                             cat=samples[i]["cat"], tpl=samples[i]["tpl"]))
    recs.sort(key=lambda r: r["idx"])
    return recs


def summarize(recs, cats=("A1", "A2", "A3", "A4", "A5", "A6")):
    y = [r["y"] for r in recs]
    p = [r["pred"] for r in recs]
    m = prf(y, p)
    per_cat = {}
    for c in cats:
        sub = [r for r in recs if r["cat"] == c]
        if sub:
            per_cat[c] = sum(1 for r in sub if r["pred"] == 1) / len(sub)
    benign = [r for r in recs if r["y"] == 0]
    hard = [r for r in benign if r["tpl"].startswith("B2")]
    per_cat["BENIGN"] = (sum(1 for r in benign if r["pred"] == 1) / len(benign)) if benign else 0.0
    per_cat["B2_hard_fpr"] = (sum(1 for r in hard if r["pred"] == 1) / len(hard)) if hard else 0.0
    m["per_category_recall"] = per_cat
    m["macro_recall"] = sum(v for k, v in per_cat.items()
                            if k in cats) / max(len([k for k in per_cat if k in cats]), 1)
    # 负类（良性）的 F1 与宏平均
    prec0 = m["tn"] / (m["tn"] + m["fn"]) if (m["tn"] + m["fn"]) else 0.0
    rec0 = m["tn"] / (m["tn"] + m["fp"]) if (m["tn"] + m["fp"]) else 0.0
    f1_neg = 2 * prec0 * rec0 / (prec0 + rec0) if prec0 + rec0 else 0.0
    m["macro_f1"] = (m["f1"] + f1_neg) / 2
    return m
