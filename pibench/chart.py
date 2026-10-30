# -*- coding: utf-8 -*-
"""绘图：输出 SVG，仅用标准库。"""
import os


def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _save(path, w, h, body):
    w_, h_ = w, h
    head = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
            'viewBox="0 0 %d %d">\n' % (w_, h_, w_, h_))
    svg = (head
           + '<rect width="100%" height="100%" fill="#ffffff"/>\n'
           + '<g font-family="SimHei, Microsoft YaHei, sans-serif">\n'
           + body + '</g>\n</svg>\n')
    with open(path, "w", encoding="utf-8") as f:
        f.write(svg)
    return path


def _axes(x0, y0, pw, ph, ymax, ylabel, ticks=5):
    b = []
    b.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#000" stroke-width="2"/>'
             % (x0, y0 + ph, x0 + pw, y0 + ph))
    b.append('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#000" stroke-width="2"/>'
             % (x0, y0, x0, y0 + ph))
    for i in range(ticks + 1):
        v = ymax * i / ticks
        y = y0 + ph - v / ymax * ph
        b.append('<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#b0b0b0" '
                 'stroke-width="1" stroke-dasharray="5,5"/>' % (x0, y, x0 + pw, y))
        b.append('<text x="%d" y="%.1f" font-size="14" text-anchor="end" '
                 'dominant-baseline="middle">%.1f</text>' % (x0 - 8, y, v))
    if ylabel:
        b.append('<text x="%d" y="%d" font-size="15" text-anchor="middle" '
                 'transform="rotate(-90 %d %d)">%s</text>'
                 % (x0 - 50, y0 + ph // 2, x0 - 50, y0 + ph // 2, _esc(ylabel)))
    return "".join(b)


def grouped_bars(categories, series, out, ylabel="数值", title="", ymax=1.0):
    """series: [(名称, [值...]), ...]；输出分组柱状图。"""
    W, H = 900, 500
    x0, y0, pw, ph = 110, 90, 740, 320
    fills = ["#ffffff", "#c8c8c8", "#707070", "#282828"]
    body = [_axes(x0, y0, pw, ph, ymax, ylabel)]
    if title:
        body.append('<text x="%d" y="26" font-size="17" text-anchor="middle">%s</text>'
                    % (W // 2, _esc(title)))
    n, m = len(categories), len(series)
    gw = pw / n
    bw = min(46.0, gw / (m + 1.6))
    for gi, cat in enumerate(categories):
        gx = x0 + gi * gw
        body.append('<text x="%.1f" y="%d" font-size="13" text-anchor="middle">%s</text>'
                    % (gx + gw / 2, y0 + ph + 24, _esc(cat)))
        for si, (name, vals) in enumerate(series):
            v = (vals[gi] / ymax) if ymax else 0
            bx = gx + (gw - bw * m) / 2 + si * bw
            by = y0 + ph - v * ph
            body.append('<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" '
                        'fill="%s" stroke="#000" stroke-width="1.2"/>'
                        % (bx, by, bw - 2, max(v * ph, 0.6), fills[si % len(fills)]))
            dark = (si % len(fills)) >= 2
            body.append('<text x="%.1f" y="%.1f" font-size="11" text-anchor="middle" '
                        'fill="%s">%.2f</text>'
                        % (bx + bw / 2, by - 5, "#ffffff" if dark else "#000000", vals[gi]))
    lx, ly = x0, y0 - 34
    for si, (name, vals) in enumerate(series):
        bx = lx + si * 190
        body.append('<rect x="%d" y="%d" width="20" height="13" fill="%s" '
                    'stroke="#000" stroke-width="1"/>' % (bx, ly, fills[si % len(fills)]))
        body.append('<text x="%d" y="%d" font-size="13">%s</text>'
                    % (bx + 26, ly + 11, _esc(name)))
    return _save(out, W, H, "".join(body))


def two_lines(xs, lines, out, ylabel="比例", title=""):
    """lines: [(名称, [值...], 是否虚线), ...]；输出折线图。"""
    W, H = 820, 470
    x0, y0, pw, ph = 100, 90, 660, 300
    body = [_axes(x0, y0, pw, ph, 1.0, ylabel)]
    if title:
        body.append('<text x="%d" y="26" font-size="17" text-anchor="middle">%s</text>'
                    % (W // 2, _esc(title)))
    step = pw / (len(xs) - 1)
    for i, x in enumerate(xs):
        body.append('<text x="%.1f" y="%d" font-size="13" text-anchor="middle">%s</text>'
                    % (x0 + i * step, y0 + ph + 24, _esc(x)))
    for li, (name, vals, dashed) in enumerate(lines):
        pts = [(x0 + i * step, y0 + ph - v * ph) for i, v in enumerate(vals)]
        path = " ".join("%.1f,%.1f" % p for p in pts)
        body.append('<polyline points="%s" fill="none" stroke="#000" stroke-width="2"%s/>'
                    % (path, ' stroke-dasharray="7,5"' if dashed else ""))
        for (px, py), v in zip(pts, vals):
            body.append('<circle cx="%.1f" cy="%.1f" r="4" fill="%s" stroke="#000" '
                        'stroke-width="1.5"/>'
                        % (px, py, "#ffffff" if dashed else "#000000"))
            body.append('<text x="%.1f" y="%.1f" font-size="11" text-anchor="middle">'
                        '%.3f</text>' % (px, py - 10, v))
        bx, by = x0 + li * 150, y0 - 34
        body.append('<rect x="%d" y="%d" width="18" height="4" fill="#000"/>'
                    % (bx, by + 5))
        body.append('<text x="%d" y="%d" font-size="13">%s</text>'
                    % (bx + 24, by + 11, _esc(name)))
    return _save(out, W, H, "".join(body))
