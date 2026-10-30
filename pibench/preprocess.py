# -*- coding: utf-8 -*-
"""文本归一化与结构特征抽取（针对编码混淆类攻击）。"""
import base64
import codecs
import functools
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\ufeff\u2060"), None)

HOMOGLYPH = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u04bb": "h",
    "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P", "\u0421": "C",
    "\u0425": "X", "\u0406": "I",
}

TRIGGER_HINTS = ("ignore", "instruction", "system prompt", "导出", "输出系统", "越权",
                 "reveal", "bypass", "忽略", "提示词")

B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
REF_DEF_RE = re.compile(r"^\s*\[([^\]]+)\]:\s*(\S+)\s*$", re.M)
INLINE_LINK_RE = re.compile(r"!?\[([^\]]*)\]\((https?://[^)\s]+)\)")
IMG_REF_RE = re.compile(r"!\[([^\]]*)\]\[([^\]]*)\]")
LINK_REF_RE = re.compile(r"(?<!!)\[([^\]]*)\]\[([^\]]*)\]")
URL_RE = re.compile(r"https?://[^\s\)\]\"'<>，。；）]+")
HTML_TAG_RE = re.compile(r"<(img|a|iframe|script)\b[^>]*>", re.I)


def _decode_b64_candidates(text):
    out = []
    for m in B64_RE.finditer(text):
        blob = m.group(0)
        if len(blob) % 4:
            continue
        try:
            dec = base64.b64decode(blob, validate=True).decode("utf-8")
        except Exception:
            continue
        printable = sum(1 for ch in dec if ch.isprintable())
        if dec and printable / len(dec) > 0.9:
            out.append(dec)
    return out


def _rot13_candidates(text):
    """ROT13 解码后命中触发词才视为编码载荷。"""
    dec = codecs.encode(text, "rot13").lower()
    hits = [h for h in TRIGGER_HINTS if h in dec]
    return [dec] if len(hits) >= 1 else []


def normalize(text):
    """返回 (归一化文本, 线索文本)；线索文本把隐藏信息摊开供检测器使用。"""
    t = unicodedata.normalize("NFKC", text)
    t = t.translate(ZERO_WIDTH)
    for src, dst in HOMOGLYPH.items():
        t = t.replace(src, dst)

    hints = []
    for c in COMMENT_RE.findall(t):
        hints.append("[html-comment] " + c.strip())
    for name, url in REF_DEF_RE.findall(t):
        hints.append("[ref-def] %s -> %s" % (name, url))
    for url in URL_RE.findall(t):
        if len(url) > 60:
            hints.append("[long-url] " + url)
    for dec in _decode_b64_candidates(t):
        hints.append("[base64] " + dec)
    for dec in _rot13_candidates(t):
        hints.append("[rot13] " + dec)

    body = REF_DEF_RE.sub(" ", t)
    body = INLINE_LINK_RE.sub(lambda m: "%s %s" % (m.group(1), m.group(2)), body)
    return body, "\n".join(hints)


@functools.lru_cache(maxsize=8192)
def structural_features(raw):
    """结构特征，取值 0/1 或小整数。"""
    body, hints = normalize(raw)
    low = body.lower()
    f = {}
    f["zw"] = 1 if any(ch in raw for ch in "\u200b\u200c\u200d\u200e\u200f\ufeff") else 0
    f["b64"] = 1 if "[base64]" in hints else 0
    f["rot13"] = 1 if "[rot13]" in hints else 0
    f["comment"] = 1 if "[html-comment]" in hints else 0
    f["refdef"] = 1 if "[ref-def]" in hints else 0
    f["longurl"] = 1 if "[long-url]" in hints else 0
    f["imgref"] = 1 if IMG_REF_RE.search(body) else 0
    f["htmltag"] = 1 if HTML_TAG_RE.search(body) else 0
    f["imgsrc"] = 1 if re.search(r"!\[[^\]]*\]\(http", body) else 0
    f["datalink"] = 1 if re.search(r"(data:|javascript:)", low) else 0
    f["urlcnt"] = min(len(URL_RE.findall(body)), 3)
    f["override"] = 1 if re.search(r"(忽略.{0,6}(以上|之前|前面).{0,6}(指令|规则|要求))|"
                                   r"ignore (all )?(the )?previous|"
                                   r"(全部作废|作废|void|失效)|新目标", low) else 0
    f["sysword"] = 1 if re.search(r"(system prompt|系统提示|初始化设定|你的设定)", low) else 0
    f["roleplay"] = 1 if re.search(r"(假设你是|扮演|角色设定|dan mode|you are now|作为我的)", low) else 0
    f["persuade"] = 1 if re.search(r"(如果你不|务必|只有你能|有人的安全|立刻|请马上)", low) else 0
    f["covert"] = 1 if re.search(r"(请勿在回答中提及|不要提及|do not mention|hidden|隐藏指令|白色小字)", low) else 0
    f["multi"] = 1 if re.search(r"(我们刚才|上一条|既然你|前面已|previous turn|continue)", low) else 0
    f["noise"] = 1 if re.search(r"[!@#$%^&*]{5,}|[▁▂▃▄▅]|qwerty|asdfg|zxcv", low) else 0
    punct = sum(1 for ch in body if ch in "!?！？#@$%^&*")
    f["punct"] = 1 if punct >= 6 else 0
    f["len"] = min(len(body) // 100, 5)
    return f


@functools.lru_cache(maxsize=8192)
def ngrams(text, ns=(2, 3)):
    body, hints = normalize(text)
    s = body.lower() + " " + hints.lower()
    s = re.sub(r"\s+", " ", s)
    out = set()
    for n in ns:
        for i in range(len(s) - n + 1):
            g = s[i:i + n]
            if g.strip():
                out.add(g)
    return out
