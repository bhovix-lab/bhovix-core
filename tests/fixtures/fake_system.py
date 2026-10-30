"""fixture-records: a stdlib HTTP server standing in for a client system in tests. Not a real ERP."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class FakeSystem:
    def __init__(self, token: str) -> None:
        self.token = token
        self.records: dict[str, dict] = {}
        self.by_key: dict[str, str] = {}
        self.creates = 0
        self.timeout_once_on_create = False
        self.fail_lookups = False
        self.verify_mismatch = False
        self.redirect_create = False  # answer create with a 302 to /stolen
        self.drop_after_create = False  # create, then close the connection with no reply (once)
        self.garbage_after_create = False  # create, then reply 200 with a non-JSON body (once)
        self.stolen_auth: list[str] = []
        self.delay_s = 1.5
        self._lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.port = self.server.server_address[1]
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> "FakeSystem":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _handler(self):
        system = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body=None):
                raw = b"" if body is None else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _authed(self):
                if self.headers.get("Authorization") != f"Bearer {system.token}":
                    self._send(401)
                    return False
                return True

            def do_POST(self):
                if not self._authed():
                    return
                if urlsplit(self.path).path != "/records":
                    return self._send(404)
                if system.redirect_create:
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{system.port}/stolen")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                key = self.headers.get("Idempotency-Key", "")
                with system._lock:
                    rec_id = system.by_key.get(key)
                    if rec_id is None:
                        rec_id = f"rec-{len(system.records) + 1:03d}"
                        system.records[rec_id] = {"id": rec_id, **body}
                        system.by_key[key] = rec_id
                        system.creates += 1
                    slow = system.timeout_once_on_create
                    system.timeout_once_on_create = False
                    drop, system.drop_after_create = system.drop_after_create, False
                    garbage, system.garbage_after_create = system.garbage_after_create, False
                if slow:
                    time.sleep(system.delay_s)
                if drop:
                    self.close_connection = True
                    return None
                if garbage:
                    self.send_response(200)
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"ok")
                    return None
                self._send(201, {"id": rec_id})

            def do_GET(self):
                if self.path.startswith("/stolen"):
                    system.stolen_auth.append(self.headers.get("Authorization", ""))
                    return self._send(200, {"id": "stolen"})
                if not self._authed():
                    return None
                url = urlsplit(self.path)
                if url.path == "/records":
                    if system.fail_lookups:
                        return self._send(503)
                    key = parse_qs(url.query).get("idempotency_key", [""])[0]
                    rec_id = system.by_key.get(key)
                    return self._send(200, {"id": rec_id}) if rec_id else self._send(404)
                rec = system.records.get(url.path.rsplit("/", 1)[-1])
                if rec is None:
                    return self._send(404)
                if system.verify_mismatch:
                    rec = {**rec, "amount": "0.00"}
                self._send(200, rec)

            def do_DELETE(self):
                if not self._authed():
                    return
                with system._lock:
                    gone = system.records.pop(urlsplit(self.path).path.rsplit("/", 1)[-1], None)
                self._send(200, {"deleted": True}) if gone else self._send(404)

        return Handler
