"""Local web server for the dashboard, built on the Python standard library only."""
from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from ..config import PROJECT_TITLE, ROOT
from ..ingestion import DataValidationError
from . import api

WEB_DIR = ROOT / "web"
MAX_BODY = 30_000_000
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "IDSDashboard"

    def log_message(self, fmt, *args):  # keep the console quiet; errors are printed by the framework
        if "--verbose" in sys.argv:
            super().log_message(fmt, *args)

    # ---- helpers
    def _headers(self, status: int, ctype: str, length: int, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CSP)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, status: int, obj) -> None:
        body = json.dumps(obj, allow_nan=False).encode()
        self._headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _host_ok(self) -> bool:
        """Reject foreign Host/Origin headers (DNS-rebinding and cross-site request protection)."""
        host = (self.headers.get("Host") or "").lower()
        port = self.server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        if getattr(self.server, "allow_remote", False):
            return True
        origin = self.headers.get("Origin")
        if origin and urlparse(origin).netloc.lower() not in allowed:
            return False
        return host in allowed

    # ---- routes
    def do_GET(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._error(403, "Forbidden host.")
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        try:
            if url.path == "/api/config":
                return self._json(200, api.jsonable(api.config_info()))
            if url.path == "/api/evidence":
                return self._json(200, api.evidence_json(q.get("run", ""), q.get("alert", "")))
            if url.path == "/api/evidence.csv":
                return self._csv(api.evidence_csv(q.get("run", ""), q.get("alert", "")), f"{q.get('alert', 'alert')}_evidence.csv")
            if url.path == "/api/template.csv":
                kind = q.get("kind", "")
                return self._csv(api.template_csv(kind), f"example_{kind}.csv")
            if url.path == "/api/findings.csv":
                return self._csv(api.findings_csv(q.get("run", "")), "findings.csv")
            if url.path.startswith("/api/"):
                return self._error(404, "Unknown API endpoint.")
            return self._static(url.path)
        except KeyError as exc:
            return self._error(404, str(exc.args[0]))
        except Exception as exc:  # noqa: BLE001
            return self._error(500, f"Unexpected error: {exc}")

    def do_POST(self) -> None:  # noqa: N802
        if not self._host_ok():
            return self._error(403, "Forbidden host.")
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._error(415, "Content-Type must be application/json.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._error(400, "Invalid Content-Length.")
        if length <= 0 or length > MAX_BODY:
            return self._error(413 if length > MAX_BODY else 400, "Request body is empty or too large (limit about 30 MB).")
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._error(400, "Request body is not valid JSON.")
        try:
            path = urlparse(self.path).path
            if path == "/api/analyze":
                return self._json(200, api.run_analysis(body))
            if path == "/api/evaluate-all":
                return self._json(200, api.evaluate_all(body))
            return self._error(404, "Unknown API endpoint.")
        except DataValidationError as exc:
            return self._error(400, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._error(500, f"Unexpected error while analysing the data: {exc}")

    def _csv(self, text: str, name: str) -> None:
        body = text.encode()
        self._headers(200, "text/csv; charset=utf-8", len(body), {"Content-Disposition": f'attachment; filename="{name}"'})
        self.wfile.write(body)

    def _static(self, raw_path: str) -> None:
        rel = unquote(raw_path).lstrip("/") or "index.html"
        target = (WEB_DIR / rel).resolve()
        if WEB_DIR.resolve() not in target.parents or not target.is_file():
            return self._error(404, "Not found.")
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in {"application/javascript", "text/javascript"}:
            ctype += "; charset=utf-8"
        data = target.read_bytes()
        self._headers(200, ctype, len(data))
        self.wfile.write(data)


def make_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    mimetypes.add_type("text/javascript", ".js")
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.allow_remote = host not in {"127.0.0.1", "localhost", "::1"}
    srv.daemon_threads = True
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=f"{PROJECT_TITLE} - local dashboard")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1", help="default is local only; changing it exposes the tool to your network")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)
    try:
        srv = make_server(args.host, args.port)
    except OSError as exc:
        print(f"Could not start on port {args.port}: {exc}\nTry another port, for example: python app.py --port 8100", file=sys.stderr)
        return 1
    url = f"http://{'127.0.0.1' if args.host in {'127.0.0.1', 'localhost'} else args.host}:{args.port}/"
    print(f"{PROJECT_TITLE}\nDashboard running at {url}\nPress Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        srv.server_close()
    return 0
