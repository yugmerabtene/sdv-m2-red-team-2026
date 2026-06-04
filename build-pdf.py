#!/usr/bin/env python3
"""Consolide tous les modules .md en un seul fichier pour export PDF."""

import os
import re
import subprocess

BASE = "/home/yug/Documents/sdv-m2-red-team-2026"
OUT = os.path.join(BASE, "formation-complete.md")
COVER_OUT = os.path.join(BASE, ".cover.pdf")
CONTENT_OUT = os.path.join(BASE, ".content.pdf")
FINAL_OUT = os.path.join(BASE, "SDV-M2-Red-Team-2026.pdf")
PANDOC = "/tmp/opencode/pandoc-3.6.4/bin/pandoc"

FILES = [
    ("README.md", None),
    ("syllabus.md", None),
    ("J1-environnement-web/m1-mitre-attack.md", "Jour 1"),
    ("J1-environnement-web/m2-injections-avancees.md", "Jour 1"),
    ("J1-environnement-web/m3-authentification-logique.md", "Jour 1"),
    ("J1-environnement-web/m4-exploitation-pivoting.md", "Jour 1"),
    ("J1-environnement-web/m5-scenario-autonome.md", "Jour 1"),
    ("J2-infrastructure-ad/m6-reconnaissance-reseau.md", "Jour 2"),
    ("J2-infrastructure-ad/m7-active-directory.md", "Jour 2"),
    ("J2-infrastructure-ad/m8-elevation-mouvement-lateral.md", "Jour 2"),
    ("J2-infrastructure-ad/m9-attaques-avancees-ad.md", "Jour 2"),
    ("J2-infrastructure-ad/m10-scenario-ad-autonome.md", "Jour 2"),
    ("J3-mobile-transverse/m11-intro-pentest-mobile.md", "Jour 3"),
    ("J3-mobile-transverse/m12-reverse-engineering-dynamique.md", "Jour 3"),
    ("J3-mobile-transverse/m13-evasion-persistance-obfuscation.md", "Jour 3"),
    ("J3-mobile-transverse/m14-synthese-ctf-encadre.md", "Jour 3"),
    ("J3-mobile-transverse/m15-debrief-ctf-corrections.md", "Jour 3"),
    ("J4-synthese-restitution/m16-structuration-rapport-pentest.md", "Jour 4"),
    ("J4-synthese-restitution/m17-atelier-redactionnel.md", "Jour 4"),
    ("J4-synthese-restitution/m18-heatmap-attack-gap-analysis.md", "Jour 4"),
    ("J4-synthese-restitution/m19-restitution-orale-simulee.md", "Jour 4"),
    ("J4-synthese-restitution/m20-debrief-evaluation-acquis.md", "Jour 4"),
]

def strip_toc_and_anchors(text):
    """Supprime la table des matières locale et convertit les ancres en texte simple."""
    lines = text.split('\n')
    result = []
    in_toc = False
    for line in lines:
        # Detect start of TOC section
        if re.match(r'^##\s+Table des mati[èe]res', line):
            in_toc = True
            continue
        # End of TOC when we hit next section heading
        if in_toc and line.startswith('## '):
            in_toc = False
        if in_toc:
            # Convert TOC links to plain text: [Text](#anchor) → Text
            line = re.sub(r'\[([^\]]+)\]\(#[^)]+\)', r'\1', line)
            if line.strip():
                result.append(line)
            continue
        if not in_toc:
            # Also handle inline anchor links outside TOC
            line = re.sub(r'\[([^\]]+)\]\(#[^)]+\)', r'\1', line)
            result.append(line)
    return '\n'.join(result)

# Regex pour supprimer tous les emojis et pictogrammes Unicode
EMOJI_RE = re.compile(
    '[\U0001F300-\U0001F9FF'    # Misc symbols, pictograms, emoticons
    '\U0001FA00-\U0001FA6F'    # Chess symbols
    '\U0001FA70-\U0001FAFF'    # Symbols extended-A
    '\u2600-\u27BF'            # Misc symbols, dingbats
    '\u2B50'                   # Star
    '\u2705'                   # Check mark
    '\u26A0'                   # Warning sign
    '\u274C'                   # Cross mark
    '\u2764'                   # Heart
    '\uFE0F'                   # Variation selector (emoji presentation)
    '\u200D'                   # Zero width joiner
    ']', re.UNICODE
)

def strip_emoji(text):
    return EMOJI_RE.sub('', text)

def process_module(filepath, day_label):
    """Lit un module, nettoie, retourne le contenu."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Remove trailing whitespace
    content = content.strip()

    # Strip local TOC
    content = strip_toc_and_anchors(content)

    # Remove lone hr separators at start
    content = re.sub(r'^---+\s*\n', '', content)

    # Remove emojis
    content = strip_emoji(content)

    # Remove "Document rédigé pour..." footers (several variants)
    content = re.sub(
        r'\*Document rédigé pour .*?SDV 2026\*',
        '', content
    )

    return content

COVER_HTML = r'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<style>
  @page {
    size: A4;
    margin: 0;
  }
  body {
    margin: 0;
    padding: 0;
    background: #1a1a2e;
    color: #ffffff;
    font-family: 'DejaVu Sans', sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100vh;
    text-align: center;
  }
  @page {
    @bottom-center {
      content: counter(page);
      font-size: 10pt;
      color: #888;
    }
  }
  .logo {
    margin-bottom: 2cm;
  }
  .logo img {
    width: 200px;
    height: auto;
  }
  h1 {
    font-size: 28pt;
    color: #e94560;
    margin: 0.5cm 0;
    letter-spacing: 2px;
  }
  .subtitle {
    font-size: 18pt;
    color: #c0c0c0;
    margin: 0.3cm 0;
  }
  .org {
    font-size: 14pt;
    color: #e94560;
    margin-top: 1.5cm;
    text-transform: uppercase;
    letter-spacing: 4px;
  }
  .date {
    font-size: 12pt;
    color: #888;
    margin-top: 0.5cm;
  }
</style>
</head>
<body>
<div class="logo">
  <img src="file:///home/yug/Documents/sdv-m2-red-team-2026/logo.jpg" alt="Logo">
</div>
<h1>Red Team<br>Cybersécurité</h1>
<div class="subtitle">SDV M2</div>
<div class="subtitle" style="font-size:13pt; color:#aaa;">
  Tests d'intrusion avancés — 4 jours (  1–4 Juin 2026)
</div>
<div class="org">Sup de Vinci</div>
<div class="date">Juin 2026</div>
</body>
</html>'''

def build_cover():
    """Génère la page de garde en PDF."""
    html_path = os.path.join(BASE, ".cover.html")
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(COVER_HTML)
    subprocess.run(
        ["weasyprint", html_path, COVER_OUT],
        check=True, capture_output=True
    )
    size = os.path.getsize(COVER_OUT)
    print(f"Page de garde : {COVER_OUT} ({size//1024} Ko)")

def build_content():
    """Consolide et compile le contenu principal."""
    parts = []
    parts.append('---\ntoc: true\ntoc-own-page: true\ntoc-depth: 3\nnumbersections: false\nlang: fr\n---\n')

    for relpath, day_label in FILES:
        fullpath = os.path.join(BASE, relpath)
        if not os.path.exists(fullpath):
            print(f"Fichier introuvable : {fullpath}")
            continue

        print(f"  Traitement : {relpath}")
        content = process_module(fullpath, day_label)

        parts.append('')
        parts.append(r'\newpage')
        parts.append('')
        parts.append(content)
        parts.append('')

    result = '\n'.join(parts)

    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(result)

    lines = result.count('\n')
    print(f"\nformation-complete.md : {lines} lignes")

    css_path = os.path.join(BASE, "pagination.css")
    cmd = (
        f'"{PANDOC}" "{OUT}" -o "{CONTENT_OUT}" '
        f'--pdf-engine=weasyprint '
        f'--toc --toc-depth=3 '
        f'--highlight-style=tango '
        f'--css "{css_path}" '
        f'-V mainfont="DejaVu Sans" '
        f'-V monofont="DejaVu Sans Mono" '
        f'-V fontsize=11pt '
        f'-V geometry:margin=1in'
    )
    print(f"Compilation du contenu...")
    ret = os.system(cmd)
    if ret == 0:
        size = os.path.getsize(CONTENT_OUT)
        print(f"Contenu : {CONTENT_OUT} ({size//1024} Ko)")
    else:
        raise RuntimeError(f"Erreur compilation contenu (code {ret})")

def merge():
    """Fusionne page de garde + contenu."""
    print(f"\nFusion avec pdfunite...")
    subprocess.run(
        ["pdfunite", COVER_OUT, CONTENT_OUT, FINAL_OUT],
        check=True, capture_output=True
    )
    size = os.path.getsize(FINAL_OUT)
    print(f"\nPDF final : {FINAL_OUT} ({size//1024} Ko)")

    # Cleanup temp files
    for f in [COVER_OUT, CONTENT_OUT, os.path.join(BASE, ".cover.html")]:
        if os.path.exists(f):
            os.remove(f)

def build():
    build_cover()
    build_content()
    merge()

if __name__ == '__main__':
    build()
