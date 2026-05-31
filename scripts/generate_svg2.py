#!/usr/bin/env python3
"""
SVG Diagram Generator v2 — Schemas professionnels style draw.io
Corrige: fleches zero-longueur, couleurs 8-digit, font duplique, alignement
Usage: python3 scripts/generate_svg2.py definition.json output.svg
"""

import json, sys, os, math

# ===== THEME =====
C = {
    "bg": "#0a0e14", "card": "#131820", "border": "#1e2d3d",
    "accent": "#e63946", "accent2": "#ff6b6b", "text": "#bfc7d5",
    "muted": "#6b7a8d", "bright": "#e6ecf3",
    "green": "#44d7b6", "orange": "#ff9f43", "blue": "#54a0ff", "purple": "#a55eea",
}
FONT_BODY = "font-family='system-ui,-apple-system,Inter,sans-serif'"
FONT_MONO = "font-family='monospace'"

# Opacity presets (standard SVG fill-opacity, not 8-digit hex)
OPACITY = {"box": "0.12", "zone": "0.5", "card": "1.0"}

# ===== SVG BUILDER =====
class SVG:
    def __init__(self, w=960, h=540, title=""):
        self.w, self.h = w, h
        self.els = []
        self.defs = self._defs()

    def _defs(self):
        return """
    <filter id="sd"><feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#000" flood-opacity="0.3"/></filter>
    <marker id="aR" viewBox="0 0 10 7" refX="9" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0,10 3.5,0 7" fill="{acc}"/></marker>
    <marker id="aB" viewBox="0 0 10 7" refX="9" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0,10 3.5,0 7" fill="{blu}"/></marker>
    <marker id="aO" viewBox="0 0 10 7" refX="9" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0,10 3.5,0 7" fill="{ora}"/></marker>
    <marker id="aG" viewBox="0 0 10 7" refX="9" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0,10 3.5,0 7" fill="{grn}"/></marker>
    <marker id="aP" viewBox="0 0 10 7" refX="9" refY="3.5" markerWidth="8" markerHeight="6" orient="auto"><polygon points="0 0,10 3.5,0 7" fill="{pur}"/></marker>
    """.format(acc=C["accent"], blu=C["blue"], ora=C["orange"], grn=C["green"], pur=C["purple"])

    def add(self, s): self.els.append(s)
    def _e(self, s): return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def box(self, x, y, w, h, color=C["blue"], shadow=True):
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{color}" fill-opacity="{OPACITY["box"]}" stroke="{color}" stroke-width="1.5" {"filter=\"url(#sd)\"" if shadow else ""}/>')

    def txt(self, x, y, text, color=C["bright"], size=13, anchor="middle", bold=False):
        fw = "font-weight='600' " if bold else ""
        self.add(f'<text x="{x}" y="{y}" text-anchor="{anchor}" {FONT_BODY} {fw}fill="{color}" font-size="{size}px">{self._e(text)}</text>')

    def txt_mono(self, x, y, text, color=C["green"], size=10, anchor="middle"):
        self.add(f'<text x="{x}" y="{y}" text-anchor="{anchor}" {FONT_MONO} fill="{color}" font-size="{size}px">{self._e(text)}</text>')

    def multiline(self, x, y, text, color=C["bright"], size=12, anchor="middle", max_w=180):
        lines = text.split("\n")
        lh = size * 1.5
        total_h = len(lines) * lh
        start_y = y - (total_h / 2) + lh
        for i, line in enumerate(lines):
            self.txt(x, start_y + i * lh, line, color, size, anchor)

    def line(self, x1, y1, x2, y2, color=C["border"], sw=1.5, dash=None, arrow=None):
        d = f'stroke-dasharray="{dash}" ' if dash else ""
        a = f'marker-end="url(#{arrow})" ' if arrow else ""
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}" {d}{a}/>')

    def tag_box(self, x, y, w, text, color=C["green"]):
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="18" rx="4" fill="{C["card"]}" stroke="{color}" stroke-width="0.8"/>')
        self.txt_mono(x + w/2, y + 13, text, color, 9)

    def zone(self, x, y, w, h, label):
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{C["card"]}" fill-opacity="{OPACITY["zone"]}" stroke="{C["border"]}" stroke-width="1.2"/>')
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="24" rx="10" fill="{C["card"]}"/>')
        self.add(f'<rect x="{x}" y="{y}+24" width="{w}" height="{h}-24" rx="0" fill="none"/>')
        self.txt(x + 10, y + 17, label, C["muted"], 11, "start")

    def edge_label(self, mx, my, text, color=C["muted"], size=10):
        tw = len(text) * 7 + 10
        self.add(f'<rect x="{mx-tw/2}" y="{my-10}" width="{tw}" height="18" rx="4" fill="{C["bg"]}" stroke="{C["border"]}" stroke-width="0.8"/>')
        self.txt_mono(mx, my + 3, text, color, size)

    def render(self, title=""):
        tt = ""
        if title:
            tt = f'<text x="40" y="36" text-anchor="start" {FONT_BODY} font-weight="600" fill="{C["bright"]}" font-size="20px">{self._e(title)}</text>\n    <line x1="40" y1="48" x2="280" y2="48" stroke="{C["accent"]}" stroke-width="2"/>'
        els = "\n    ".join(self.els)
        return f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {self.w} {self.h}' width='{self.w}' height='{self.h}'>
  <defs>{self.defs}
  </defs>
  <rect width='{self.w}' height='{self.h}' fill='{C["bg"]}' rx='10'/>
  {tt}
    {els}
</svg>"""

    def save(self, path, title=""):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            f.write(self.render(title))
        print(f"  -> {path} ({self.w}x{self.h})")
        return True


# ===== ICONS =====
ICONS = {
    "server": '<rect x="4" y="4" width="40" height="10" rx="1.5" fill="none" stroke="{c}" stroke-width="1.2"/><rect x="4" y="18" width="40" height="10" rx="1.5" fill="none" stroke="{c}" stroke-width="1.2"/><rect x="4" y="32" width="40" height="10" rx="1.5" fill="none" stroke="{c}" stroke-width="1.2"/><circle cx="14" cy="9" r="2" fill="{c2}"/><circle cx="14" cy="23" r="2" fill="{c2}"/><circle cx="14" cy="37" r="2" fill="{c2}"/>',
    "db": '<ellipse cx="24" cy="8" rx="20" ry="6" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M4 8 L4 36" stroke="{c}" stroke-width="1.2"/><path d="M44 8 L44 36" stroke="{c}" stroke-width="1.2"/><ellipse cx="24" cy="36" rx="20" ry="6" fill="none" stroke="{c}" stroke-width="1.2"/><ellipse cx="24" cy="22" rx="20" ry="6" fill="none" stroke="{c}" stroke-width="1.2" stroke-dasharray="2 2"/>',
    "cloud": '<path d="M10 34 Q10 18 22 14 Q30 4 38 14 Q46 6 48 18 Q54 12 52 22 Q58 28 52 34 Q48 40 32 40 L14 40 Q6 40 6 34 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
    "laptop": '<rect x="6" y="6" width="36" height="22" rx="2" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M2 40 L12 28 L36 28 L46 40 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
    "desktop": '<rect x="4" y="4" width="40" height="28" rx="2" fill="none" stroke="{c}" stroke-width="1.2"/><line x1="24" y1="32" x2="24" y2="40" stroke="{c}" stroke-width="1.2"/><line x1="10" y1="40" x2="38" y2="40" stroke="{c}" stroke-width="1.2"/>',
    "firewall": '<rect x="4" y="4" width="40" height="40" rx="3" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M22 4 L22 44 M26 4 L26 44" stroke="{c}" stroke-width="0.3"/><path d="M12 18 L18 14 L22 22 L26 16 L32 24 L28 28" fill="none" stroke="{c2}" stroke-width="1.5"/>',
    "switch": '<rect x="4" y="4" width="40" height="40" rx="2" fill="none" stroke="{c}" stroke-width="1.2"/><rect x="8" y="10" width="6" height="4" rx="1" fill="{c2}"/><rect x="18" y="10" width="6" height="4" rx="1" fill="{c2}"/><rect x="28" y="10" width="6" height="4" rx="1" fill="{c2}"/><rect x="8" y="18" width="6" height="4" rx="1" fill="{c2}"/><rect x="18" y="18" width="6" height="4" rx="1" fill="{c}"/><rect x="28" y="18" width="6" height="4" rx="1" fill="{c.7}"/>',
    "user": '<circle cx="24" cy="12" r="8" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M8 38 Q8 22 24 22 Q40 22 40 38" fill="none" stroke="{c}" stroke-width="1.2"/>',
    "folder": '<path d="M6 10 L18 10 L22 16 L42 16 L42 38 L6 38 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
    "key": '<circle cx="12" cy="24" r="8" fill="none" stroke="{c}" stroke-width="1.2"/><line x1="20" y1="24" x2="44" y2="24" stroke="{c}" stroke-width="1.2"/><line x1="28" y1="20" x2="28" y2="28" stroke="{c}" stroke-width="1.2"/>',
    "lock": '<path d="M16 16 L16 10 Q16 4 24 4 Q32 4 32 10 L32 16" fill="none" stroke="{c}" stroke-width="1.2"/><rect x="10" y="16" width="28" height="26" rx="3" fill="none" stroke="{c}" stroke-width="1.2"/>',
    "terminal": '<rect x="4" y="4" width="40" height="40" rx="4" fill="none" stroke="{c}" stroke-width="1.2"/><text x="10" y="20" fill="{c2}" font-size="10" font-family="monospace">&gt;_</text><text x="10" y="34" fill="{c}" font-size="8" font-family="monospace">~$</text>',
    "globe": '<circle cx="24" cy="24" r="20" fill="none" stroke="{c}" stroke-width="1.2"/><ellipse cx="24" cy="24" rx="6" ry="20" fill="none" stroke="{c}" stroke-width="0.8"/><line x1="4" y1="24" x2="44" y2="24" stroke="{c}" stroke-width="0.8"/>',
    "email": '<rect x="4" y="6" width="40" height="32" rx="4" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M6 8 L24 24 L42 8" fill="none" stroke="{c}" stroke-width="1.2"/>',
    "wifi": '<path d="M10 18 Q24 8 38 18" fill="none" stroke="{c}" stroke-width="1.5"/><path d="M14 24 Q24 18 34 24" fill="none" stroke="{c}" stroke-width="1.5"/><circle cx="24" cy="30" r="3" fill="{c}"/>',
    "attack": '<path d="M24 4 L28 16 L38 14 L32 22 L42 28 L30 32 L26 44 L22 32 L12 34 L18 24 L8 20 L20 18 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
    "shield": '<path d="M24 4 L44 12 L44 26 Q44 38 24 44 Q4 38 4 26 L4 12 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
}

def draw_icon(svg, cx, cy, name, scale=0.6, color=None):
    c = color or C["text"]
    c2 = C["green"]
    if name not in ICONS:
        return
    raw = ICONS[name].replace("{c}", c).replace("{c2}", c2)
    svg.add(f'<g transform="translate({cx-24*scale},{cy-24*scale}) scale({scale})">{raw}</g>')


# ===== LAYOUT: Attack Chain (horizontal) =====
ARROW_COLORS = ["aR", "aB", "aO", "aG", "aP", "aR", "aB", "aO"]
BOX_COLORS = [C["accent"], C["blue"], C["purple"], C["green"], C["orange"], C["accent2"], C["blue"], C["green"]]

def draw_attack_chain(svg, cfg):
    steps = cfg.get("steps", [])
    n = len(steps)
    if n == 0: return
    margin = 80
    arrow_space = 30  # minimum visible arrow length
    step_w = min(140, (svg.w - margin*2 - arrow_space*(n-1)) / n)
    step_w = max(step_w, 70)
    gap = arrow_space
    total_w = step_w * n + gap * (n - 1)
    x_start = (svg.w - total_w) / 2
    y_center = svg.h / 2 + 10

    for i in range(n - 1):
        x1 = x_start + i * (step_w + gap) + step_w
        x2 = x_start + (i+1) * (step_w + gap)
        ac = ARROW_COLORS[i % len(ARROW_COLORS)]
        svg.line(x1, y_center - 28, x2, y_center - 28, C["accent"], sw=1.8, arrow=ac)

    for i, step in enumerate(steps):
        x = x_start + i * (step_w + gap)
        col = BOX_COLORS[i % len(BOX_COLORS)]
        svg.box(x, y_center - 68, step_w, 78, col)
        icon_name = step.get("icon", "")
        if icon_name:
            draw_icon(svg, x + step_w/2, y_center - 50, icon_name, 0.55, col)
        label = step.get("label", step.get("id", ""))
        if "\n" in label:
            svg.multiline(x + step_w/2, y_center - 18, label, C["bright"], 11)
        else:
            svg.txt(x + step_w/2, y_center - 10, label, C["bright"], 11)
        tag = step.get("tag", "")
        if tag:
            tw = max(44, len(tag) * 7 + 8)
            svg.tag_box(x + step_w/2 - tw/2, y_center + 18, tw, tag, col)


# ===== LAYOUT: Flow Chart (vertical) =====
def draw_flow_chart(svg, cfg):
    steps = cfg.get("steps", [])
    cx = svg.w / 2
    spacing = cfg.get("spacing", 85)
    box_w = cfg.get("box_width") or cfg.get("step_width", 320)
    box_h = cfg.get("box_height") or cfg.get("step_height", 52)
    start_y = cfg.get("padding_top", 70)
    cols = [C["blue"], C["green"], C["purple"], C["accent"], C["orange"], C["purple"], C["blue"]]

    for i, step in enumerate(steps):
        y = start_y + i * spacing
        col = cols[i % len(cols)]
        if step.get("type") == "decision":
            d = 40
            svg.add(f'<polygon points="{cx},{y-d} {cx+d},{y} {cx},{y+d} {cx-d},{y}" fill="{col}" fill-opacity="0.1" stroke="{col}" stroke-width="1.5" filter="url(#sd)"/>')
            svg.multiline(cx, y, step.get("label", ""), C["bright"], 11)
        else:
            svg.box(cx - box_w/2, y - box_h/2, box_w, box_h, col)
            svg.multiline(cx, y, step.get("label", ""), C["bright"], 12)

        sub = step.get("sub_text", "")
        if sub:
            svg.txt(cx, y + box_h/2 + 16, sub, C["muted"], 10)

        if step.get("tag"):
            svg.tag_box(cx - box_w/2 - 56, y - 10, 48, step["tag"], col)

        if i < len(steps) - 1:
            ac = ARROW_COLORS[i % len(ARROW_COLORS)]
            svg.line(cx, y + box_h/2, cx, y + spacing - box_h/2, C["accent"], sw=1.8, arrow=ac)


# ===== LAYOUT: Network Topology =====
def draw_network_topology(svg, cfg):
    zones = cfg.get("zones", [])
    nodes = cfg.get("nodes", [])
    connections = cfg.get("connections", [])

    # Draw zones
    for z in zones:
        zx = z.get("x", 0)
        zy = z.get("y", 0) + 52
        zw = z.get("w", 200)
        zh = z.get("h", svg.h - 70)
        svg.zone(zx, zy, zw, zh, z.get("label", "") + "   ")

    # Map node positions
    pos = {}
    for node in nodes:
        zone = node.get("zone", "")
        z_info = next((z for z in zones if z["id"] == zone), {"x": 0, "y": 0})
        cx = z_info.get("x", 0) + node.get("x", 0)
        cy = z_info.get("y", 0) + 52 + node.get("y", 0)
        col = node.get("color", C["blue"])
        pos[node["id"]] = (cx, cy)

        # Draw node
        svg.box(cx - 42, cy - 40, 84, 60, col, shadow=True)
        draw_icon(svg, cx, cy - 24, node.get("type", "server"), 0.65, col)
        svg.multiline(cx, cy + 6, node.get("label", ""), C["bright"], 10)

    # Draw connections
    for conn in connections:
        f = pos.get(conn["from"])
        t = pos.get(conn["to"])
        if not f or not t:
            continue
        col = C["accent"] if conn.get("style") == "solid" else C["orange"]
        arr = "aR" if conn.get("style") == "solid" else "aO"
        # Curved path
        cy = (f[1] + t[1]) / 2 - 30
        svg.add(f'<path d="M{f[0]},{f[1]-10} Q{f[0]},{cy} {t[0]},{t[1]-10}" fill="none" stroke="{col}" stroke-width="1.8" marker-end="url(#{arr})"/>')
        label = conn.get("label", "")
        if label:
            mx = (f[0] + t[0]) / 2
            my = cy
            svg.edge_label(mx, my, label, C["muted"], 9)


# ===== LAYOUT: Tree =====
def draw_tree(svg, cfg):
    root = cfg.get("root", {})
    cx = svg.w / 2
    children = root.get("children", [])

    # Root
    svg.box(cx - 100, 45, 200, 44, C["accent"])
    svg.txt(cx, 72, root.get("label", ""), C["bright"], 14, bold=True)

    n = len(children)
    if n == 0: return
    spacing = min(220, (svg.w - 100) / n)
    total_w = (n - 1) * spacing
    start_x = cx - total_w / 2
    cols = [C["blue"], C["green"], C["purple"], C["orange"], C["accent"]]

    for i, child in enumerate(children):
        ccx = start_x + i * spacing
        ccy = 160
        col = cols[i % len(cols)]

        svg.line(cx, 89, ccx, ccy - 22, C["border"], sw=1.2)
        svg.box(ccx - 90, ccy - 20, 180, 40, col)
        svg.txt(ccx, ccy + 5, child.get("label", ""), C["bright"], 12)
        if child.get("tag"):
            svg.tag_box(ccx + 50, ccy - 18, 55, child["tag"], col)

        # Grandchildren
        sub = child.get("children", [])
        if sub:
            m = len(sub)
            sub_spacing = min(180, (spacing - 40) / m) if m > 1 else 140
            sub_w = (m - 1) * sub_spacing
            sub_start = ccx - sub_w / 2
            for j, s in enumerate(sub):
                sx = sub_start + j * sub_spacing
                sy = 250
                svg.line(ccx, ccy + 20, sx, sy - 16, C["border"], sw=1)
                s_col = cols[(j+i) % len(cols)]
                svg.box(sx - 68, sy - 12, 136, 26, s_col)
                svg.txt(sx, sy + 6, s.get("label", ""), C["muted"], 10)


# ===== LAYOUT: Comparison Table =====
def draw_comparison(svg, cfg):
    columns = cfg.get("columns", [])
    rows = cfg.get("rows", [])
    if not columns: return
    cols_n = len(columns)
    col_w = (svg.w - 60) / cols_n
    x0 = 30
    y0 = 70
    colors = [C["accent"], C["blue"], C["green"], C["purple"], C["orange"]]

    for ci, col in enumerate(columns):
        ccol = colors[ci % len(colors)]
        svg.box(x0 + ci * col_w, y0, col_w, 32, ccol)
        svg.txt(x0 + ci * col_w + col_w/2, y0 + 22, col, C["bright"], 12, bold=True)

    for ri, row in enumerate(rows):
        ry = y0 + 32 + ri * 32
        bg = C["card"] if ri % 2 == 0 else C["bg"]
        for ci, cell in enumerate(row):
            svg.add(f'<rect x="{x0+ci*col_w}" y="{ry}" width="{col_w}" height="32" fill="{bg}" stroke="{C["border"]}" stroke-width="0.5"/>')
            svg.txt(x0 + ci*col_w + col_w/2, ry + 21, cell, C["text"], 11)

    # Optional bar chart if config specifies
    bars = cfg.get("bars", [])
    if bars:
        bar_y = y0 + 32 + len(rows) * 32 + 30
        bar_h = 24
        bar_max = max(b.get("value", 0) for b in bars) or 1
        for bi, bar in enumerate(bars):
            by = bar_y + bi * (bar_h + 10)
            svg.txt(x0, by + bar_h/2 + 5, bar.get("label", ""), C["text"], 11, "end")
            bw = (bar.get("value", 0) / bar_max) * (svg.w - x0 - 120)
            svg.box(x0 + 10, by, bw, bar_h, bar.get("color", C["green"]))
            svg.txt(x0 + bw + 20, by + bar_h/2 + 5, str(bar.get("value", 0)) + "%", C["bright"], 10, "start")


# ===== LAYOUT: Sequence =====
def draw_sequence(svg, cfg):
    participants = cfg.get("participants", [])
    messages = cfg.get("messages", [])
    n = len(participants)
    if n == 0: return
    spacing = (svg.w - 80) / (n + 1)
    x0 = 40 + spacing
    cols = [C["accent"], C["blue"], C["green"], C["purple"], C["orange"]]
    pos_map = {}

    for i, p in enumerate(participants):
        px = x0 + i * spacing
        pos_map[p["id"]] = px
        col = cols[i % len(cols)]
        svg.box(px - 55, 55, 110, 34, col)
        svg.txt(px, 77, p["label"], C["bright"], 11)
        svg.line(px, 89, px, svg.h - 30, col, sw=0.8, dash="4 4")

    my = 110
    for j, msg in enumerate(messages):
        f = pos_map.get(msg["from"])
        t = pos_map.get(msg["to"])
        if not f or not t: continue
        arr = "aG" if msg.get("type") == "response" else "aR"
        scol = C["green"] if msg.get("type") == "response" else C["accent"]
        svg.line(f, my, t, my, scol, sw=1.5, arrow=arr)
        mx = (f + t) / 2
        svg.edge_label(mx, my - 14, msg.get("label", ""), C["muted"], 9)
        my += 45


# ===== MAIN =====
LAYOUTS = {
    "attack_chain": draw_attack_chain,
    "network_topology": draw_network_topology,
    "flow_chart": draw_flow_chart,
    "tree": draw_tree,
    "comparison": draw_comparison,
    "sequence": draw_sequence,
}

def generate(cfg, output_path):
    dtype = cfg.get("type", "network_topology")
    w = cfg.get("width", 960)
    h = cfg.get("height", 540)
    title = cfg.get("title", "")
    svg = SVG(w, h)
    fn = LAYOUTS.get(dtype)
    if fn:
        fn(svg, cfg)
    return svg.save(output_path, title)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 scripts/generate_svg2.py def.json output.svg")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        generate(json.load(f), sys.argv[2])
