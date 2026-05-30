#!/usr/bin/env python3
"""
Render ASCII diagrams to clean dark-themed PNG images.
Usage: python3 scripts/render_diagram.py "diagram text" -o output.png
       python3 scripts/render_diagram.py -f input.txt -o output.png
"""

import os, sys, re, argparse
from PIL import Image, ImageDraw, ImageFont

# Cyber dark theme colors
BG      = "#0a0e14"
TEXT    = "#bfc7d5"
ACCENT  = "#e63946"
GREEN   = "#44d7b6"
BLUE    = "#54a0ff"
ORANGE  = "#ff9f43"
PURPLE  = "#a55eea"
MUTED   = "#6b7a8d"
BORDER  = "#1e2d3d"
YELLOW  = "#ff9f43"

COLOR_MAP = {
    "┌": ACCENT, "┐": ACCENT, "└": ACCENT, "┘": ACCENT,
    "├": ACCENT, "┤": ACCENT, "┬": ACCENT, "┴": ACCENT,
    "│": ACCENT, "─": ACCENT, "═": ACCENT, "║": ACCENT,
    "►": ORANGE, "→": ORANGE, "←": ORANGE, "▼": ORANGE, "▲": ORANGE,
    "█": GREEN,  "▌": GREEN,  "▐": GREEN,  "▀": GREEN,  "▄": GREEN,
    "✗": ACCENT, "✓": GREEN, "⚠": YELLOW, "★": YELLOW,
    "●": ACCENT, "○": MUTED, "◆": BLUE, "◇": MUTED,
    "☰": MUTED, "☷": MUTED, "♻": GREEN, "⚡": YELLOW,
    "⧉": BLUE,  "⬛": MUTED,
}

def get_font(size=14):
    paths = [
        "/usr/share/fonts/truetype/ubuntu/UbuntuMono[wght].ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/opentype/urw-base35/NimbusMonoPS-Regular.otf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    ]
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()

def hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

def colorize_text(text):
    """Apply syntax coloring to diagram text."""
    out, i = [], 0
    while i < len(text):
        ch = text[i]
        if ch in COLOR_MAP:
            out.append((ch, COLOR_MAP[ch]))
            i += 1
            continue
        # TXXXX patterns
        m = re.match(r'T\d{4}', text[i:])
        if m:
            out.append((m.group(), GREEN))
            i += len(m.group())
            continue
        # flag{...} patterns  
        m = re.match(r'flag\{[^}]*\}', text[i:])
        if m:
            out.append((m.group(), ORANGE))
            i += len(m.group())
            continue
        # IPv4 addresses
        m = re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?', text[i:])
        if m:
            out.append((m.group(), BLUE))
            i += len(m.group())
            continue
        # HTTP (port numbers, key names)
        if ch.isdigit() and len(text) > i+1 and text[i+1].isdigit():
            j = i
            while j < len(text) and text[j].isdigit():
                j += 1
            if j > i:
                out.append((text[i:j], BLUE))
                i = j
                continue
        # Keywords
        kw_match = re.match(r'(Tactique|Technique|Sub.?technique|Procédure|Reconnaissance|Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact|Resource Development)(?:\b|(?=\s|$))', text[i:], re.IGNORECASE)
        if kw_match:
            out.append((kw_match.group(), ACCENT))
            i += len(kw_match.group())
            continue
        out.append((ch, TEXT))
        i += 1
    return out

def render_to_png(text, output_path, title=None, padding=28):
    """Render ASCII text to a styled PNG."""
    lines = text.rstrip("\n").split("\n")
    if not lines or (len(lines) == 1 and not lines[0].strip()):
        return

    font = get_font(14)
    char_h = font.getbbox("A")[3] - font.getbbox("A")[1]
    line_spacing = char_h + 4

    # measure width
    max_w = 0
    for line in lines:
        tokens = colorize_text(line)
        tw = sum(font.getbbox(t)[2] - font.getbbox(t)[0] for t, _ in tokens)
        max_w = max(max_w, tw)

    title_h = 0
    if title:
        tf = get_font(16)
        tb = tf.getbbox(title)
        title_w = tb[2] - tb[0]
        title_h = 26 + 8
        max_w = max(max_w, title_w)

    img_w = max_w + padding * 2
    img_h = len(lines) * line_spacing + padding * 2 + title_h

    img = Image.new("RGBA", (max(img_w, 320), max(img_h, 60)), hex_to_rgb(BG))
    draw = ImageDraw.Draw(img)

    y = padding

    if title:
        tf = get_font(16)
        draw.text((padding, y), title, fill=hex_to_rgb(ACCENT), font=tf)
        tb = tf.getbbox(title)
        tw = tb[2] - tb[0]
        y += 26
        draw.rectangle([padding, y, padding + tw, y + 2], fill=hex_to_rgb(BORDER))
        y += 12

    for line in lines:
        cx = padding
        tokens = colorize_text(line)
        for tok, col in tokens:
            draw.text((cx, y), tok, fill=hex_to_rgb(col), font=font)
            cx += font.getbbox(tok)[2] - font.getbbox(tok)[0]
        y += line_spacing

    # Round corners (soften)
    img.save(output_path, "PNG")
    print(f"  -> {output_path} ({img.size[0]}x{img.size[1]}px)")
    return img.size

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-f", "--file", help="Input file with diagram text")
    p.add_argument("-t", "--text", help="Inline diagram text")
    p.add_argument("-o", "--output", required=True, help="Output PNG path")
    p.add_argument("--title", help="Diagram title")
    args = p.parse_args()

    if args.file:
        with open(args.file) as f:
            text = f.read()
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    render_to_png(text, args.output, args.title)

if __name__ == "__main__":
    main()
