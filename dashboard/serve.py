#!/usr/bin/env python3
"""Bayora Enclave posture dashboard.

A single-file static server that also proxies the Referee's read-only API, so
the page can be opened from anywhere without the Referee needing CORS headers
and without the operator having to trust a third-party front end.

    python3 dashboard/serve.py                       # http://127.0.0.1:8090
    python3 dashboard/serve.py --referee http://127.0.0.1:8080 --port 8090

The proxy is deliberately read-only: it forwards `GET /healthz`, `GET
/v1/posture` and `GET /v1/evaluations/{id}` and refuses everything else. A
monitoring surface must never be a way to spend capabilities.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import socketserver
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

#: Paths the proxy will forward. Anything else is a 403, so this process can
#: never be used to create an evaluation or to seal a batch.
ALLOWED_PREFIXES = ("/healthz", "/v1/posture", "/v1/evaluations/")


class Handler(http.server.SimpleHTTPRequestHandler):
    referee = "http://127.0.0.1:8080"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=HERE, **kwargs)

    def _deny(self, code: int, message: str) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server's interface
        if self.path == "/api" or self.path.startswith("/api/"):
            target = self.path[len("/api"):] or "/"
            if not any(target.startswith(p) for p in ALLOWED_PREFIXES):
                self._deny(403, f"the dashboard proxy will not forward {target}")
                return
            try:
                with urllib.request.urlopen(self.referee + target, timeout=10) as reply:
                    payload = reply.read()
                    status = reply.status
                    content_type = reply.headers.get("content-type", "application/json")
            except urllib.error.HTTPError as exc:
                payload = exc.read()
                status = exc.code
                content_type = exc.headers.get("content-type", "application/json")
            except OSError as exc:
                self._deny(502, f"the Referee is unreachable: {exc}")
                return
            self.send_response(status)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(payload)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(payload)
            return

        super().do_GET()

    def end_headers(self) -> None:
        # The dashboard is a local operator tool; never let a browser cache a
        # stale view of the chain head.
        if self.path.endswith((".html", ".js", ".css")):
            self.send_header("cache-control", "no-store")
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("dashboard: " + fmt % args + "\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--referee", default="http://127.0.0.1:8080")
    args = parser.parse_args(argv)

    Handler.referee = args.referee.rstrip("/")
    with Server((args.host, args.port), Handler) as httpd:
        print(f"dashboard: http://{args.host}:{args.port}  ->  {Handler.referee}")
        print("dashboard: proxying GET /healthz, /v1/posture, /v1/evaluations/{id}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\ndashboard: stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
