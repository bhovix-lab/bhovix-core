"""A local fake of the Vault HTTP API (KV v2 read/write, AppRole and Kubernetes sign-in), for laptops without a
Vault server. CI runs the same Vault suite against a real `vault server -dev` (HADAVIN_TEST_VAULT_ADDR).

One server per test session (a daemon thread on a free loopback port); tests keep apart by unique paths.
"""

from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = "root"  # the fake's admin token (a dev-server convention, not a secret)


class FakeVault:
    def __init__(self) -> None:
        self.kv: dict[str, dict] = {}  # "<mount>/<path>" -> data
        self.tokens = {ROOT}
        self.approle: dict[str, str] = {}  # role_id -> secret_id
        self.k8s: dict[str, str] = {}  # role -> jwt
        self.seen_namespaces: list[str | None] = []
        self.reads = 0
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, status, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else {}

            def do_POST(self):
                path = self.path.removeprefix("/v1/")
                if path.startswith("auth/") and path.endswith("/login"):
                    body = self._body()
                    ok = (
                        fake.approle.get(body.get("role_id")) == body.get("secret_id")
                        if "role_id" in body
                        else fake.k8s.get(body.get("role")) == body.get("jwt")
                    )
                    if not ok or not (body.get("role_id") or body.get("role")):
                        return self._send(400, {"errors": ["invalid"]})
                    token = "fake." + secrets.token_hex(8)
                    fake.tokens.add(token)
                    return self._send(200, {"auth": {"client_token": token}})
                if self.headers.get("X-Vault-Token") not in fake.tokens:
                    return self._send(403, {"errors": ["permission denied"]})
                mount, _, rest = path.partition("/data/")
                fake.kv[f"{mount}/{rest}"] = self._body()["data"]
                return self._send(200, {"data": {}})

            def do_GET(self):
                fake.seen_namespaces.append(self.headers.get("X-Vault-Namespace"))
                if self.headers.get("X-Vault-Token") not in fake.tokens:
                    return self._send(403, {"errors": ["permission denied"]})
                mount, _, rest = self.path.removeprefix("/v1/").partition("/data/")
                if rest.endswith(
                    "/moved"
                ):  # a standby node: 307 to the active node (here: a real secret)
                    self.send_response(307)
                    self.send_header("Location", f"/v1/{mount}/data/{rest.removesuffix('moved')}db")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return None
                fake.reads += 1
                data = fake.kv.get(f"{mount}/{rest}")
                if data is None:
                    return self._send(404, {"errors": []})
                return self._send(200, {"data": {"data": data, "metadata": {"version": 1}}})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.address = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


_ONE: FakeVault | None = None


def fake_vault() -> FakeVault:
    global _ONE
    if _ONE is None:
        _ONE = FakeVault()
    return _ONE
