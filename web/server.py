"""Servidor del dashboard web, basado en la librería estándar (http.server)."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..core.system import Ctx
from ..core.runner import discover_checks, run_audit, audit_to_dict
from ..core import history
from ..report.html import render_html
from .dashboard import DASHBOARD_HTML


class Handler(BaseHTTPRequestHandler):
    server_version = "Hardenix"

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _audit(self, save=True):
        ctx = Ctx()
        findings = run_audit(ctx, discover_checks())
        data = audit_to_dict(ctx, findings)
        if save:
            history.save_history(ctx, data)
        return data

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        try:
            if path == "/":
                self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
            elif path == "/api/history":
                self._send(200, json.dumps(history.list_history(Ctx())))
            elif path == "/api/audit":
                self._send(200, json.dumps(self._audit(), ensure_ascii=False))
            elif path == "/api/report":
                self._send(200, render_html(self._audit(save=False)), "text/html; charset=utf-8")
            else:
                self._send(404, json.dumps({"error": "no encontrado"}))
        except Exception as e:  # noqa: BLE001
            self._send(500, json.dumps({"error": str(e)}))

    def log_message(self, *args):  # silenciar el log por defecto
        pass


def serve(host="127.0.0.1", port=8080):
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Dashboard de Hardenix en  http://{host}:{port}   (Ctrl+C para detener)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
        httpd.shutdown()
