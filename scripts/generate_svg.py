#!/usr/bin/env python3
"""SVG Diagram Generator — Schemas professionnels style draw.io
Usage: python3 scripts/generate_svg.py definition.json output.svg
"""

import json, sys, os, math

# ===== THEME =====
THEME = {
    "bg": "#0a0e14", "card": "#131820", "card_hover": "#1a2332",
    "border": "#1e2d3d", "accent": "#e63946", "accent2": "#ff6b6b",
    "text": "#bfc7d5", "text_muted": "#6b7a8d", "text_bright": "#e6ecf3",
    "green": "#44d7b6", "orange": "#ff9f43", "blue": "#54a0ff",
    "purple": "#a55eea", "yellow": "#ffd166",
    "zone_fill": "rgba(19,24,32,0.5)", "zone_border": "rgba(30,45,61,0.8)",
    "shadow_opacity": "0.25",
}
C = THEME
FONT = "font-family='-apple-system,BlinkMacSystemFont,Segoe UI,Inter,sans-serif'"

# ===== SVG BUILDER =====
class SVG:
    def __init__(self, width=960, height=540, title=""):
        self.w, self.h = width, height
        self.elements = []
        self.defs = []
        self._add_def("""
        <filter id="shadow"><feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#000" flood-opacity="0.3"/></filter>
        <filter id="glow"><feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#e63946" flood-opacity="0.4"/></filter>
        <marker id="arrR" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
          <polygon points="0 0, 10 3.5, 0 7" fill="#e63946"/>
        </marker>
        <marker id="arrB" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
          <polygon points="0 0, 10 3.5, 0 7" fill="#54a0ff"/>
        </marker>
        <marker id="arrO" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
          <polygon points="0 0, 10 3.5, 0 7" fill="#ff9f43"/>
        </marker>
        <marker id="arrG" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
          <polygon points="0 0, 10 3.5, 0 7" fill="#44d7b6"/>
        </marker>
        """)

    def _add_def(self, d): self.defs.append(d)
    def add(self, e): self.elements.append(e)

    def rect(self, x, y, w, h, rx=6, fill=C['card'], stroke=C['border'], sw=1.5, shadow=True, cls=""):
        s = f"filter='url(#shadow)'" if shadow else ""
        self.add(f"<rect x='{x}' y='{y}' width='{w}' height='{h}' rx='{rx}' fill='{fill}' stroke='{stroke}' stroke-width='{sw}' {s} {cls}/>")

    def text(self, x, y, txt, color=C['text'], size=14, anchor="start", bold=False, mono=False):
        styles = [f"fill='{color}'", f"font-size='{size}px'"]
        if bold: styles.append("font-weight='600'")
        if mono: styles.append("font-family='Ubuntu Mono,Fira Code,monospace'")
        self.add(f"<text x='{x}' y='{y}' text-anchor='{anchor}' {FONT} {' '.join(styles)}>{self._esc(txt)}</text>")

    def line(self, x1, y1, x2, y2, color=C['border'], sw=2, dash=None, arrow=None):
        das = f"stroke-dasharray='{dash}'" if dash else ""
        arr = f"marker-end='url(#{arrow})'" if arrow else ""
        self.add(f"<line x1='{x1}' y1='{y1}' x2='{x2}' y2='{y2}' stroke='{color}' stroke-width='{sw}' {das} {arr}/>")

    def path(self, d, color=C['border'], sw=2, fill="none", arrow=None):
        arr = f"marker-end='url(#{arrow})'" if arrow else ""
        self.add(f"<path d='{d}' fill='{fill}' stroke='{color}' stroke-width='{sw}' {arr}/>")

    def multiline_text(self, x, y, txt, color=C['text'], size=13, align="center", max_w=160):
        lines = txt.split("\n")
        lh = size * 1.6
        total_h = len(lines) * lh
        start_y = y + size
        for i, line in enumerate(lines):
            self.text(x, start_y + i * lh, line, color, size, anchor=align)

    def zone(self, x, y, w, h, label):
        self.rect(x, y, w, h, rx=10, fill=C['zone_fill'], stroke=C['zone_border'], sw=1.2, shadow=False)
        self.rect(x, y, w, 26, rx=10, fill=C['card'], stroke="none", sw=0, shadow=False)
        self.rect(x, y+26, w, h-26, rx=0, fill="none", stroke="none", sw=0, shadow=False)
        self.rect(x, y, w, h, rx=10, fill="none", stroke=C['zone_border'], sw=1.2, shadow=False)
        self.text(x + 12, y + 18, label, C['text_muted'], 12)

    def arrow_label(self, x, y, txt, color=C['text_muted'], size=11):
        self.rect(x - 4, y - 4, len(txt) * 7 + 8, 20, rx=4, fill=C['bg'], stroke=C['border'], sw=0.8, shadow=False)
        self.text(x, y + 11, txt, color, size)

    def _esc(self, s): return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def render(self):
        els = "\n    ".join(self.elements)
        defs = "\n    ".join(self.defs)
        return f"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {self.w} {self.h}' width='{self.w}' height='{self.h}'>
  <defs>
    {defs}
  </defs>
  <rect width='{self.w}' height='{self.h}' fill='{C["bg"]}' rx='12'/>
  {els}
</svg>"""

# ===== ICONS =====
class Icon:
    @staticmethod
    def draw(svg, cx, cy, icon_type, scale=1.0, color=None):
        c = color or C['text']
        c2 = C['green']
        s = scale
        g = f"<g transform='translate({cx - 24*s}, {cy - 24*s}) scale({s})'>"
        icons = {
            "server": f'<rect x="4" y="4" width="40" height="10" rx="1" fill="none" stroke="{c}" stroke-width="1.2"/><rect x="4" y="18" width="40" height="10" rx="1" fill="none" stroke="{c}" stroke-width="1.2"/><rect x="4" y="32" width="40" height="10" rx="1" fill="none" stroke="{c}" stroke-width="1.2"/><circle cx="15" cy="9" r="2" fill="{c2}"/><circle cx="15" cy="23" r="2" fill="{c2}"/><circle cx="15" cy="37" r="2" fill="{c2}"/>',
            "db": f'<ellipse cx="24" cy="8" rx="20" ry="6" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M4 8 L4 36" stroke="{c}" stroke-width="1.2"/><path d="M44 8 L44 36" stroke="{c}" stroke-width="1.2"/><ellipse cx="24" cy="36" rx="20" ry="6" fill="none" stroke="{c}" stroke-width="1.2"/><ellipse cx="24" cy="22" rx="20" ry="6" fill="none" stroke="{c}" stroke-width="1.2" stroke-dasharray="2 2"/>',
            "cloud": f'<path d="M10 34 Q10 18 22 14 Q30 4 38 14 Q46 6 48 18 Q54 12 52 22 Q58 28 52 34 Q48 40 32 40 L14 40 Q6 40 6 34 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
            "laptop": f'<rect x="8" y="6" width="32" height="20" rx="2" fill="none" stroke="{c}" stroke-width="1.2"/><line x1="14" y1="26" x2="34" y2="26" stroke="{c}" stroke-width="1.2"/><path d="M4 38 L14 26 L34 26 L44 38 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
            "desktop": f'<rect x="4" y="4" width="40" height="28" rx="2" fill="none" stroke="{c}" stroke-width="1.2"/><line x1="24" y1="32" x2="24" y2="38" stroke="{c}" stroke-width="1.2"/><line x1="12" y1="38" x2="36" y2="38" stroke="{c}" stroke-width="1.2"/><rect x="10" y="10" width="28" height="14" fill="none" stroke="{c2}" stroke-width="0.8"/>',
            "firewall": f'<rect x="4" y="4" width="40" height="40" rx="3" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M22 40 L22 4" stroke="{c}" stroke-width="0.3"/><path d="M26 40 L26 4" stroke="{c}" stroke-width="0.3"/><path d="M14 16 L20 12 L24 20 L28 14 L34 22 L30 26" fill="none" stroke="{c2}" stroke-width="1.5"/>',
            "switch": f'<rect x="4" y="4" width="40" height="40" rx="2" fill="none" stroke="{c}" stroke-width="1.2"/><rect x="8" y="10" width="6" height="4" rx="1" fill="{c2}"/><rect x="18" y="10" width="6" height="4" rx="1" fill="{c2}"/><rect x="28" y="10" width="6" height="4" rx="1" fill="{c2}"/><rect x="8" y="18" width="6" height="4" rx="1" fill="{c2}"/><rect x="18" y="18" width="6" height="4" rx="1" fill="{c}"/><rect x="28" y="18" width="6" height="4" rx="1" fill="{c}"/><rect x="8" y="26" width="6" height="4" rx="1" fill="{c}"/><rect x="18" y="26" width="6" height="4" rx="1" fill="{c}"/><rect x="28" y="26" width="6" height="4" rx="1" fill="{c}"/>',
            "user": f'<circle cx="24" cy="14" r="8" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M8 36 Q8 24 24 24 Q40 24 40 36" fill="none" stroke="{c}" stroke-width="1.2"/>',
            "folder": f'<path d="M6 10 L18 10 L22 16 L42 16 L42 38 L6 38 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
            "key": f'<circle cx="12" cy="24" r="8" fill="none" stroke="{c}" stroke-width="1.2"/><line x1="20" y1="24" x2="44" y2="24" stroke="{c}" stroke-width="1.2"/><line x1="28" y1="20" x2="28" y2="28" stroke="{c}" stroke-width="1.2"/>',
            "lock": f'<path d="M16 16 L16 10 Q16 4 24 4 Q32 4 32 10 L32 16" fill="none" stroke="{c}" stroke-width="1.2"/><rect x="10" y="16" width="28" height="26" rx="3" fill="none" stroke="{c}" stroke-width="1.2"/>',
            "terminal": f'<rect x="4" y="4" width="40" height="40" rx="4" fill="none" stroke="{c}" stroke-width="1.2"/><text x="10" y="20" fill="{c2}" font-size="10" font-family="monospace">&gt;_</text><text x="10" y="34" fill="{c}" font-size="8" font-family="monospace">sh</text>',
            "globe": f'<circle cx="24" cy="24" r="20" fill="none" stroke="{c}" stroke-width="1.2"/><ellipse cx="24" cy="24" rx="8" ry="20" fill="none" stroke="{c}" stroke-width="0.8"/><line x1="4" y1="24" x2="44" y2="24" stroke="{c}" stroke-width="0.8"/>',
            "email": f'<rect x="4" y="4" width="40" height="32" rx="4" fill="none" stroke="{c}" stroke-width="1.2"/><path d="M6 6 L24 22 L42 6" fill="none" stroke="{c}" stroke-width="1.2"/>',
            "wifi": f'<path d="M10 18 Q24 8 38 18" fill="none" stroke="{c}" stroke-width="1.5"/><path d="M14 24 Q24 18 34 24" fill="none" stroke="{c}" stroke-width="1.5"/><circle cx="24" cy="30" r="3" fill="{c}"/>',
            "attack": f'<path d="M24 4 L28 16 L38 14 L32 22 L42 28 L30 32 L26 44 L22 32 L12 34 L18 24 L8 20 L20 18 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
            "shield": f'<path d="M24 4 L44 12 L44 26 Q44 38 24 44 Q4 38 4 26 L4 12 Z" fill="none" stroke="{c}" stroke-width="1.2"/>',
        }
        g += icons.get(icon_type, "") + "</g>"
        svg.add(g)

# ===== LAYOUT ENGINES =====

def draw_attack_chain(svg, cfg):
    steps = cfg.get("steps", [])
    n = len(steps)
    if n == 0: return
    total_w = svg.w - 160
    step_w = min(140, total_w / n)
    gap = (total_w - step_w * n) / (n + 1)
    x_start = 80 + gap
    y_center = svg.h / 2
    # draw connecting arrows
    for i in range(n - 1):
        x1 = x_start + i * (step_w + gap) + step_w
        x2 = x_start + (i+1) * (step_w + gap)
        svg.line(x1, y_center - 30, x2, y_center - 30, C['accent'], sw=2, arrow="arrR")
    # draw steps
    colors = [C['accent'], C['blue'], C['purple'], C['green'], C['orange'], C['yellow'], C['accent2'], C['green']]
    for i, step in enumerate(steps):
        x = x_start + i * (step_w + gap)
        col = colors[i % len(colors)]
        # step box
        svg.rect(x, y_center - 70, step_w, 80, rx=8, fill=col + "18", stroke=col, sw=1.5)
        # icon
        if step.get("icon"):
            Icon.draw(svg, x + step_w/2, y_center - 48, step["icon"], 0.6, col)
        # label
        label = step.get("label", step.get("id", ""))
        svg.multiline_text(x + step_w/2, y_center - 15, label, C['text_bright'], 12)
        # ATT&CK tag
        if step.get("tag"):
            svg.rect(x + step_w/2 - 28, y_center + 20, 56, 18, rx=4, fill=C['card'], stroke=col, sw=0.8, shadow=False)
            svg.text(x + step_w/2, y_center + 33, step["tag"], col, 10, anchor="middle", mono=True)

def draw_network_topology(svg, cfg):
    zones = cfg.get("zones", [])
    nodes = cfg.get("nodes", [])
    connections = cfg.get("connections", [])
    # draw zones
    zone_map = {}
    for z in zones:
        zone_map[z["id"]] = z
        svg.zone(z.get("x", 0), z.get("y", 0), z.get("w", 200), z.get("h", 200), z["label"])
    # node icons mapping
    icon_map = {}
    for node in nodes:
        z = zone_map.get(node.get("zone"), {"x": 0, "y": 0})
        cx = z.get("x", 0) + node.get("x", 0)
        cy = z.get("y", 0) + node.get("y", 0)
        icon_type = node.get("type", "server")
        col = node.get("color", C['blue'])
        # draw node background
        svg.rect(cx - 38, cy - 38, 76, 50, rx=6, fill=C['card'], stroke=col, sw=1.2)
        # draw icon
        Icon.draw(svg, cx, cy - 20, icon_type, 0.7, col)
        # label
        svg.multiline_text(cx, cy + 10, node.get("label", ""), C['text_bright'], 10)
        icon_map[node["id"]] = (cx, cy)
    # draw connections
    for conn in connections:
        f = icon_map.get(conn["from"])
        t = icon_map.get(conn["to"])
        if f and t:
            mid_x = (f[0] + t[0]) / 2
            mid_y = (f[1] + t[1]) / 2 - 30
            col = C['accent'] if conn.get("style") == "solid" else C['orange']
            arrow = "arrR" if conn.get("style") == "solid" else "arrO"
            svg.path(f"M{f[0]},{f[1]-10} Q{mid_x},{mid_y} {t[0]},{t[1]-10}", color=col, sw=1.8, arrow=arrow)
            if conn.get("label"):
                svg.arrow_label(mid_x - 15, mid_y - 8, conn["label"], C['text_muted'], 10)

def draw_flow_chart(svg, cfg):
    steps = cfg.get("steps", [])
    x_center = svg.w / 2
    padding_top = cfg.get("padding_top", 60)
    spacing = cfg.get("spacing", 80)
    step_w = cfg.get("step_width", 260)
    step_h = cfg.get("step_height", 50)
    colors = [C['blue'], C['green'], C['purple'], C['accent'], C['orange']]
    for i, step in enumerate(steps):
        y = padding_top + i * spacing
        col = colors[i % len(colors)]
        # box
        if step.get("type") == "decision":
            pts = f"{x_center},{y-30} {x_center+60},{y} {x_center},{y+30} {x_center-60},{y}"
            svg.path(f"M{pts} Z", color=col, sw=1.5)
        else:
            svg.rect(x_center - step_w/2, y - step_h/2, step_w, step_h, rx=6, fill=col+"15", stroke=col, sw=1.5)
        svg.multiline_text(x_center, y, step.get("label", ""), C['text_bright'], 13)
        # arrow
        if i < len(steps) - 1:
            svg.line(x_center, y + step_h/2, x_center, y + spacing - step_h/2, C['accent'], sw=1.8, arrow="arrR")
        # side label
        if step.get("tag"):
            svg.rect(x_center - step_w/2 - 60, y - 10, 50, 20, rx=4, fill=C['card'], stroke=col, sw=0.8, shadow=False)
            svg.text(x_center - step_w/2 - 35, y + 5, step["tag"], col, 10, anchor="middle", mono=True)

def draw_tree(svg, cfg):
    root = cfg.get("root", {})
    x_center = svg.w / 2
    # root
    svg.rect(x_center - 90, 30, 180, 40, rx=8, fill=C['accent']+"18", stroke=C['accent'], sw=1.5)
    svg.text(x_center, 54, root.get("label", ""), C['text_bright'], 14, anchor="middle")
    children = root.get("children", [])
    if children:
        n = len(children)
        total_w = (n - 1) * 220
        start_x = x_center - total_w / 2
        for i, child in enumerate(children):
            cx = start_x + i * 220
            cy = 130
            col = [C['blue'], C['green'], C['purple'], C['orange'], C['accent']][i % 5]
            # line from root
            svg.line(x_center, 70, cx, cy - 24, C['border'], sw=1.2)
            # child node
            svg.rect(cx - 90, cy - 20, 180, 40, rx=8, fill=C['card'], stroke=col, sw=1.2)
            svg.text(cx, cy + 6, child.get("label", ""), C['text_bright'], 12, anchor="middle")
            if child.get("tag"):
                svg.rect(cx + 50, cy - 18, 55, 16, rx=4, fill=C['card'], stroke=col, sw=0.8, shadow=False)
                svg.text(cx + 77, cy - 6, child["tag"], col, 8, anchor="middle", mono=True)
            # children of children
            sub = child.get("children", [])
            if sub:
                m = len(sub)
                sub_w = (m - 1) * 180
                sub_start = cx - sub_w / 2
                for j, s in enumerate(sub):
                    sx = sub_start + j * 180
                    sy = 220
                    svg.line(cx, cy + 20, sx, sy - 18, C['border'], sw=1)
                    scol = [C['blue'], C['green'], C['purple'], C['orange']][j % 4]
                    svg.rect(sx - 70, sy - 14, 140, 28, rx=6, fill=C['card'], stroke=scol, sw=1)
                    svg.text(sx, sy + 5, s.get("label", ""), C['text_muted'], 10, anchor="middle")

def draw_comparison(svg, cfg):
    title = cfg.get("title", "")
    columns = cfg.get("columns", [])
    rows = cfg.get("rows", [])
    col_w = (svg.w - 80) / len(columns)
    x_start = 40
    y_start = 60
    col_colors = [C['accent'], C['blue'], C['green'], C['purple'], C['orange']]
    # header
    for i, col in enumerate(columns):
        svg.rect(x_start + i * col_w, y_start, col_w, 36, rx=0, fill=C['card'], stroke=C['border'], sw=1, shadow=False)
        svg.text(x_start + i * col_w + col_w/2, y_start + 24, col, col_colors[i%5], 13, anchor="middle", bold=True)
    # rows
    for j, row in enumerate(rows):
        ry = y_start + 36 + j * 34
        bg = C['card'] if j % 2 == 0 else "none"
        for i, cell in enumerate(row):
            if i == 0:
                svg.rect(x_start, ry, col_w, 34, rx=0, fill=bg, stroke=C['border'], sw=0.5, shadow=False)
            else:
                svg.rect(x_start + i * col_w, ry, col_w, 34, rx=0, fill=bg, stroke=C['border'], sw=0.5, shadow=False)
            svg.text(x_start + i * col_w + col_w/2, ry + 23, cell, C['text'], 11, anchor="middle")

def draw_sequence(svg, cfg):
    participants = cfg.get("participants", [])
    messages = cfg.get("messages", [])
    n = len(participants)
    if n == 0: return
    col_spacing = (svg.w - 80) / (n + 1)
    x_start = 40 + col_spacing
    lifeline_colors = [C['accent'], C['blue'], C['green'], C['purple'], C['orange']]
    x_map = {}
    # headers
    for i, p in enumerate(participants):
        cx = x_start + i * col_spacing
        x_map[p["id"]] = cx
        col = lifeline_colors[i % len(lifeline_colors)]
        svg.rect(cx - 55, 30, 110, 36, rx=6, fill=C['card'], stroke=col, sw=1.2)
        svg.text(cx, 52, p["label"], C['text_bright'], 11, anchor="middle")
        # lifeline
        svg.line(cx, 66, cx, svg.h - 30, col, sw=0.8, dash="4,4")
    # messages
    msg_y = 95
    for j, msg in enumerate(messages):
        f = x_map.get(msg["from"])
        t = x_map.get(msg["to"])
        if f and t:
            arrow = "arrG" if msg.get("type") == "response" else "arrR"
            col = C['green'] if msg.get("type") == "response" else C['accent']
            svg.line(f, msg_y, t, msg_y, col, sw=1.5, arrow=arrow)
            mx = (f + t) / 2
            svg.arrow_label(mx - 40, msg_y - 14, msg.get("label", ""), C['text_muted'], 10)
            msg_y += 45

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
    width = cfg.get("width", 960)
    height = cfg.get("height", 540)
    title = cfg.get("title", "")
    svg = SVG(width, height, title)
    if title:
        svg.text(40, 36, title, C['text_bright'], 20, bold=True)
        svg.line(40, 48, 320, 48, C['accent'], sw=2)
    layout_fn = LAYOUTS.get(dtype)
    if layout_fn:
        layout_fn(svg, cfg)
    result = svg.render()
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(result)
    print(f"  -> {output_path} ({width}x{height})")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} definition.json output.svg")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        config = json.load(f)
    generate(config, sys.argv[2])
