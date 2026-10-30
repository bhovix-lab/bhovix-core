"""A local stdlib HTTP server replaying hand-written provider fixtures, in order (design §6 CI substitutes).

A fixture is ``{request_match, status, headers, body}``: ``request_match`` holds the method and, optionally, a
``path_suffix`` the request path must end with. Each request takes the next fixture; a mismatch or an empty queue
answers 418, which no kind retries, so the test fails loudly. Every request is kept for the assertions.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

RECORDED = Path(__file__).parent / "recorded_http"


def fixture(kind: str, name: str) -> dict:
    return json.loads((RECORDED / kind / f"{name}.json").read_text(encoding="utf-8"))


class Replay:
    def __init__(self) -> None:
        self.queue: list[dict] = []
        self.requests: list[dict] = []  # {method, path, headers, body}
        self._lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        ).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def _handler(self):
        replay = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                with replay._lock:
                    replay.requests.append(
                        {
                            "method": "POST",
                            "path": self.path,
                            "headers": {k.lower(): v for k, v in self.headers.items()},
                            "body": json.loads(raw or b"{}"),
                        }
                    )
                    nxt = replay.queue.pop(0) if replay.queue else None
                match = (nxt or {}).get("request_match", {})
                ok = nxt is not None and match.get("method", "POST") == "POST"
                ok = ok and self.path.split("?")[0].endswith(match.get("path_suffix", ""))
                status = nxt["status"] if ok else 418
                body = json.dumps(nxt["body"] if ok else {"error": "no fixture matched"}).encode()
                self.send_response(status)
                for k, v in ((nxt or {}).get("headers") or {}).items() if ok else ():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return Handler
