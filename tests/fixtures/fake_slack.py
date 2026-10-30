"""A local stand-in for the Slack Web API (chat.postMessage, chat.update) on a random loopback port."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeSlack:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict, str]] = []  # (method, body, authorization header)
        self.fail_with: str | None = None  # Slack error code to answer with (ok: false)
        self._n = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                method = self.path.rsplit("/", 1)[-1]
                fake.calls.append((method, body, self.headers.get("Authorization", "")))
                if fake.fail_with:
                    reply = {"ok": False, "error": fake.fail_with}
                else:
                    fake._n += 1
                    reply = {"ok": True, "ts": body.get("ts") or f"1700000000.{fake._n:06d}"}
                out = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *args) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.api_base = f"http://127.0.0.1:{self._server.server_address[1]}/api"

    def start(self) -> "FakeSlack":
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
