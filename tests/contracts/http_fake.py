"""SDK-level fakes: the real Azure and GCP SDK clients, with HTTP answered in-process by a `requests` adapter
mounted on that one client's session (no global patching, no network). Response bodies follow each REST API's
documented shape; the SDK parses them and raises its own errors (ResourceNotFoundError, NotFound)."""

from __future__ import annotations

import base64
import io
import json
from collections.abc import Callable

import requests
import urllib3
from requests.adapters import BaseAdapter

Handler = Callable[[requests.PreparedRequest], tuple[int, dict, dict | None]]


class FakeAdapter(BaseAdapter):
    def __init__(self, handler: Handler) -> None:
        super().__init__()
        self.handler = handler

    def send(self, request, **kw):
        status, headers, body = self.handler(request)
        content = json.dumps(body).encode() if body is not None else b""
        r = requests.Response()
        r.status_code, r.request, r.url, r.encoding = status, request, request.url, "utf-8"
        r.headers.update({"Content-Type": "application/json", **headers})
        r._content = content
        r.raw = urllib3.HTTPResponse(
            body=io.BytesIO(content), headers=r.headers, status=status, preload_content=False
        )
        return r

    def close(self):
        pass


class FakeAzureCredential:
    def get_token(self, *scopes, **kw):
        from azure.core.credentials import AccessToken

        return AccessToken("fake" + "-access", 4_102_444_800)  # 2100-01-01: never expires in a test


def azure_secret_client(vault_url: str, values: dict[str, str]):
    """A real `SecretClient`. Like Key Vault, the first unauthenticated call gets a 401 bearer challenge."""
    from azure.core.pipeline.transport import RequestsTransport
    from azure.keyvault.secrets import SecretClient

    def handler(req):
        if not req.headers.get("Authorization"):
            challenge = 'Bearer authorization="https://login.example/tenant", resource="https://vault.azure.net"'
            return 401, {"WWW-Authenticate": challenge}, None
        name = req.path_url.split("/secrets/", 1)[1].split("/")[0].split("?")[0]
        if name not in values:
            return 404, {}, {"error": {"code": "SecretNotFound", "message": "not found"}}
        return 200, {}, {"value": values[name], "id": f"{vault_url}/secrets/{name}/v1"}

    session = requests.Session()
    session.mount("https://", FakeAdapter(handler))
    transport = RequestsTransport(session=session, session_owner=False)
    return SecretClient(vault_url, FakeAzureCredential(), transport=transport)


def gcp_secret_client(values: dict[str, str]):
    """A real `SecretManagerServiceClient` on its REST transport."""
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import secretmanager

    def handler(req):
        name = req.path_url.split("/secrets/", 1)[1].split("/")[0]
        if name not in values:
            body = {"error": {"code": 404, "message": "not found", "status": "NOT_FOUND"}}
            return 404, {}, body
        data = base64.b64encode(values[name].encode()).decode()
        return 200, {}, {"name": f"secrets/{name}/versions/1", "payload": {"data": data}}

    client = secretmanager.SecretManagerServiceClient(
        credentials=AnonymousCredentials(), transport="rest"
    )
    client._transport._session.mount("https://", FakeAdapter(handler))
    return client
