# -*- coding: utf-8 -*-
"""检测器：统一接口 fit(samples) / score(samples)，分值越大越可疑。"""
import math
import re
import zlib

from .preprocess import normalize, ngrams, structural_features, URL_RE


def _h(s):
    """确定性哈希，避免内置 hash 的随机化。"""
    return zlib.crc32(s.encode("utf-8"))

# D1 规则
RULES = [
    (r"忽略.{0,8}(以上|之前|前面|上面).{0,8}(指令|规则|要求|提示)", 1.0),
    (r"ignore\s+(all\s+)?(the\s+)?previous", 1.0),
    (r"(全部作废|规则作废|void|新目标|新的目标)", 0.8),
    (r"(system prompt|系统提示词|初始化设定)", 0.6),
    (r"(假设你是|扮演|角色设定|dan mode|you are now)", 0.6),
    (r"(请勿在回答中提及|不要提及|do not mention|隐藏指令|hidden instruction)", 0.8),
    (r"(输出系统|泄露|导出|外泄|列出会话|会话历史)", 0.5),
    (r"(上传|发送|转发).{0,12}(https?://|至\s*[a-z0-9._%+-]+@)", 0.7),
    (r"<\s*(img|iframe|script)\b", 0.7),
    (r"(data:|javascript:)", 0.8),
    (r"\[[^\]]+\]:\s*https?://", 0.5),
    (r"[A-Za-z0-9+/]{24,}={0,2}", 0.6),
    (r"如果你不|只有你能|有人的安全", 0.5),
]
RULES = [(re.compile(p, re.I), w) for p, w in RULES]


class RuleDetector:
    """分值 = 命中的最高规则权重；阈值 0.5。"""

    name = "D1 规则"

    def fit(self, samples):
        return self

    def score(self, samples):
        out = []
        for s in samples:
            text = s["text"]
            body, hints = normalize(text)
            blob = body + "\n" + hints
            best = 0.0
            for rx, w in RULES:
                if rx.search(blob):
                    best = max(best, w)
            out.append(best)
        return out


# D2 朴素贝叶斯
class NBDetector:
    name = "D2 朴素贝叶斯"

    def __init__(self, alpha=1.0):
        self.alpha = alpha
        self.pc = {}
        self.fc = {}
        self.vocab = set()

    def fit(self, samples):
        for s in samples:
            y = s["label"]
            self.pc[y] = self.pc.get(y, 0) + 1
            d = self.fc.setdefault(y, {})
            for g in ngrams(s["text"]):
                d[g] = d.get(g, 0) + 1
                self.vocab.add(g)
        self.vsize = max(len(self.vocab), 1)
        self.tot = {y: sum(self.fc[y].values()) for y in self.fc}
        self.ntrain = sum(self.pc.values())
        return self

    def score(self, samples):
        out = []
        for s in samples:
            gs = ngrams(s["text"])
            lps = {}
            for y in (0, 1):
                lp = math.log((self.pc.get(y, 0) + 1) / (self.ntrain + 2))
                denom = self.tot.get(y, 0) + self.alpha * self.vsize
                d = self.fc.get(y, {})
                for g in gs:
                    lp += math.log((d.get(g, 0) + self.alpha) / denom)
                lps[y] = lp
            out.append(lps[1] - lps[0])
        return out


# D3 困惑度
class PPLDetector:
    """字符三元组语言模型，用良性文本训练。"""

    name = "D3 困惑度"

    def __init__(self, n=3, alpha=0.5):
        self.n = n
        self.alpha = alpha

    def fit(self, samples):
        self.cnt = {}
        self.ctx = {}
        benign = [s for s in samples if s["label"] == 0]
        for s in benign:
            body, _ = normalize(s["text"])
            t = "\x02" + re.sub(r"\s+", " ", body.lower()) + "\x03"
            for i in range(len(t) - self.n + 1):
                g = t[i:i + self.n]
                self.cnt[g] = self.cnt.get(g, 0) + 1
                self.ctx[g[:-1]] = self.ctx.get(g[:-1], 0) + 1
        self.vsize = 2000
        return self

    def score(self, samples):
        out = []
        for s in samples:
            body, hints = normalize(s["text"])
            t = ("\x02" + re.sub(r"\s+", " ", (body + " " + hints).lower()) + "\x03")
            tot, k = 0.0, 0
            for i in range(len(t) - self.n + 1):
                g = t[i:i + self.n]
                c = self.cnt.get(g, 0)
                c_ctx = self.ctx.get(g[:-1], 0)
                p = (c + self.alpha) / (c_ctx + self.alpha * self.vsize)
                tot += -math.log(p)
                k += 1
            out.append(tot / max(k, 1))
        return out


# D4 逻辑回归族
def _strong_rule_hit(blob):
    """强指示规则命中返回 1.0。"""
    for rx, w in RULES:
        if w >= 0.8 and rx.search(blob):
            return 1.0
    return 0.0


def _raw_grams(text, ns=(2, 3)):
    s = re.sub(r"\s+", " ", text.lower())
    out = set()
    for n in ns:
        for i in range(len(s) - n + 1):
            g = s[i:i + n]
            if g.strip():
                out.add(g)
    return out


class LRDetector:
    """稀疏逻辑回归；三个开关用于消融实验。"""

    name = "D4 逻辑回归"

    def __init__(self, dim=1 << 14, epochs=30, lr=0.25, l2=1e-4,
                 use_norm=True, use_struct=True, use_rule_feat=True):
        self.dim = dim
        self.epochs = epochs
        self.lr = lr
        self.l2 = l2
        self.use_norm = use_norm
        self.use_struct = use_struct
        self.use_rule_feat = use_rule_feat
        self.w = [0.0] * dim

    def _feats(self, s):
        f = {}
        raw = s["text"]
        grams = ngrams(raw, ns=(2, 3)) if self.use_norm else _raw_grams(raw)
        for g in grams:
            f[_h("g" + g) % self.dim] = 1.0
        if self.use_struct:
            for k, v in structural_features(raw).items():
                if v:
                    f[_h("s" + k) % self.dim] = float(v)
        if self.use_rule_feat:
            blob = "\n".join(normalize(raw)) if self.use_norm else raw
            rule = 0.0
            for rx, wt in RULES:
                if rx.search(blob):
                    rule = max(rule, wt)
            if rule:
                f[_h("r-hit") % self.dim] = rule
        return f

    def fit(self, samples):
        data = [self._feats(s) for s in samples]
        y = [s["label"] for s in samples]
        for _ in range(self.epochs):
            for f, label in zip(data, y):
                z = 0.0
                for i, v in f.items():
                    z += self.w[i] * v
                p = 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))
                g = p - label
                for i, v in f.items():
                    self.w[i] -= self.lr * (g * v + self.l2 * self.w[i])
        return self

    def prob(self, s):
        f = self._feats(s)
        z = sum(self.w[i] * v for i, v in f.items())
        return 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))

    def score(self, samples):
        return [self.prob(s) for s in samples]


class LRRawDetector(LRDetector):
    """消融基线：不做归一化、不加结构特征、不用规则特征。"""
    name = "D4 逻辑回归（原始特征）"

    def __init__(self, **kw):
        kw.update(use_norm=False, use_struct=False, use_rule_feat=False)
        LRDetector.__init__(self, **kw)


class LRNormDetector(LRDetector):
    """消融：归一化 + 结构特征，但无规则特征与快通道。"""
    name = "D5 逻辑回归（归一化+结构特征）"

    def __init__(self, **kw):
        kw.update(use_norm=True, use_struct=True, use_rule_feat=False)
        LRDetector.__init__(self, **kw)


class CascadeDetector(LRDetector):
    """本文方法：归一化 + 结构特征 + 规则特征，并以强规则做快通道（取最大值）。"""
    name = "D6 级联（本文）"

    def __init__(self, strong_blend=0.9, **kw):
        kw.update(use_norm=True, use_struct=True, use_rule_feat=True)
        LRDetector.__init__(self, **kw)
        self.strong_blend = strong_blend

    def prob(self, s):
        base = LRDetector.prob(self, s)
        hit = _strong_rule_hit("\n".join(normalize(s["text"])))
        return max(base, self.strong_blend * hit)


ALL = {
    "rule": RuleDetector,
    "nb": NBDetector,
    "ppl": PPLDetector,
    "lr_raw": LRRawDetector,
    "lr_norm": LRNormDetector,
    "cascade": CascadeDetector,
}
