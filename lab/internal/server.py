#!/usr/bin/env python3
"""Service interne pour l'exercice de pivoting.
   - Port 25 : faux SMTP (écoute les connexions, stocke les messages)
   - Port 8081 : faux serveur de fichiers internes (contient le flag bonus)
"""
import socketserver
import threading
import os
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Faux SMTP ──────────────────────────────────
SMTP_BANNER = b"220 smtp.internal.ecovault.com ESMTP Ready\r\n"

class FakeSMTPHandler(socketserver.StreamRequestHandler):
    messages = []

    def handle(self):
        self.wfile.write(SMTP_BANNER)
        try:
            data = self.rfile.readline()
            if data:
                FakeSMTPHandler.messages.append(data.decode(errors='replace').strip())
                self.wfile.write(b"250 OK\r\n")

                data = self.rfile.readline()
                if data:
                    FakeSMTPHandler.messages.append(data.decode(errors='replace').strip())
                    self.wfile.write(b"250 OK\r\n")

                data = self.rfile.readline()
                if data:
                    FakeSMTPHandler.messages.append(data.decode(errors='replace').strip())
                    self.wfile.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")

                body = b""
                while True:
                    line = self.rfile.readline()
                    if line == b".\r\n" or line == b".\n" or not line:
                        break
                    body += line
                FakeSMTPHandler.messages.append(body.decode(errors='replace').strip())
                self.wfile.write(b"250 2.0.0 Message accepted for delivery\r\n")

            self.wfile.write(b"221 Bye\r\n")
        except Exception:
            pass


# ── Serveur HTTP Interne ───────────────────────
INTERNAL_HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Serveur Interne EcoVault</title>
<style>
  body { font-family: monospace; background:#0a0e14; color:#44d7b6; padding:40px; }
  .file { background:#131820; border:1px solid #1e2d3d; padding:12px; margin:8px 0; border-radius:6px; }
  a { color:#ff6b6b; }
  .flag { color:#ff9f43; font-weight:bold; }
</style>
</head>
<body>
<h1>&#128274; Serveur Interne EcoVault</h1>
<p>Acces restreint — Reseau interne uniquement</p>

<h2>Fichiers disponibles</h2>

<div class="file">
  <h3>&#128196; backup_config.tar.gz</h3>
  <p>Backup des configurations serveur — 12/03/2026</p>
  <a href="/download/backup_config.tar.gz">[Telecharger]</a>
</div>

<div class="file">
  <h3>&#128196; smtp_credentials.enc</h3>
  <p>Identifiants SMTP chiffres (cle dans le backup)</p>
  <a href="/download/smtp_credentials.enc">[Telecharger]</a>
</div>

<div class="file">
  <h3>&#128220; flag_interne.txt</h3>
  <p class="flag">FLAG : flag{pivot_interne_reussi_2026}</p>
</div>
</body>
</html>"""

class InternalHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(INTERNAL_HTML.encode())
        elif self.path.startswith("/download/"):
            filename = self.path.split("/download/")[1]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.end_headers()
            self.wfile.write(b"FLAG{exfiltration_reussie_interne_2026}\n")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # silent


def main():
    # Start fake SMTP
    smtp_server = socketserver.ThreadingTCPServer(("0.0.0.0", 25), FakeSMTPHandler)
    smtp_thread = threading.Thread(target=smtp_server.serve_forever, daemon=True)
    smtp_thread.start()
    print("[+] Fake SMTP listening on port 25")

    # Start internal HTTP
    http_server = HTTPServer(("0.0.0.0", 8081), InternalHTTPHandler)
    print("[+] Internal HTTP server listening on port 8081")
    http_server.serve_forever()


if __name__ == "__main__":
    main()
