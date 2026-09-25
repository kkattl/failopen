#!/usr/bin/env python3
"""Render ANSI terminal output to a PNG terminal "window".

Usage: <command> | render.py --prompt '$ failopen audit' --out docs/img/audit.png

Lines longer than --cols soft-wrap like a real terminal. Only the SGR codes
failopen emits are understood: 0 reset, 1 bold, 31 red, 33 yellow, 90 gray.
"""
import argparse
import re
import sys

from PIL import Image, ImageDraw, ImageFont

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"  # glyph fallback

BG, TITLE_BG = (30, 30, 46), (24, 24, 37)
FG = (205, 214, 244)
COLORS = {"31": (243, 139, 168), "33": (249, 226, 175), "90": (127, 132, 156)}
PROMPT = (166, 227, 161)
SGR = re.compile(r"\x1b\[([0-9;]*)m")


def spans(line):
    """Split a line into (text, color, bold) runs."""
    color, bold, pos, out = FG, False, 0, []
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], color, bold))
        for code in (m.group(1) or "0").split(";"):
            if code == "0":
                color, bold = FG, False
            elif code == "1":
                bold = True
            elif code in COLORS:
                color = COLORS[code]
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], color, bold))
    return out


def soft_wrap(runs, cols):
    """Break a list of runs into rows of at most cols characters."""
    rows, row, n = [], [], 0
    for text, color, bold in runs:
        while text:
            take = min(len(text), cols - n)
            row.append((text[:take], color, bold))
            n += take
            text = text[take:]
            if n == cols and text:
                rows.append(row)
                row, n = [], 0
    rows.append(row)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompt", default="")
    ap.add_argument("--out", required=True)
    ap.add_argument("--cols", type=int, default=100)
    ap.add_argument("--size", type=int, default=15)
    args = ap.parse_args()

    mono = ImageFont.truetype(MONO, args.size)
    mono_bold = ImageFont.truetype(MONO_BOLD, args.size)
    sans = ImageFont.truetype(SANS, args.size)
    cw = mono.getlength("M")
    lh = int(args.size * 1.45)

    lines = sys.stdin.read().rstrip("\n").split("\n")
    rows = []
    if args.prompt:
        rows.append([(args.prompt, PROMPT, True)])
        rows.append([])
    for line in lines:
        rows.extend(soft_wrap(spans(line), args.cols))

    pad, title_h = 22, 34
    width = int(pad * 2 + cw * args.cols)
    height = title_h + pad * 2 + lh * len(rows)
    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, title_h], fill=TITLE_BG)
    for i, c in enumerate([(243, 139, 168), (249, 226, 175), (166, 227, 161)]):
        x = 18 + i * 20
        d.ellipse([x, 12, x + 11, 23], fill=c)

    y = title_h + pad
    for row in rows:
        x = pad
        for text, color, bold in row:
            for ch in text:
                font = mono_bold if bold else mono
                if font.getmask(ch).getbbox() is None and ch.strip():
                    font = sans  # glyph missing from the mono font
                d.text((x, y), ch, font=font, fill=color)
                x += cw
        y += lh
    img.save(args.out, optimize=True)
    print(f"wrote {args.out} ({width}x{height})")


if __name__ == "__main__":
    main()
