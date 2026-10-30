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

Handler = Callable[[requests.PreparedRequest], tuple[int, dict, dict | bytes | None]]


class FakeAdapter(BaseAdapter):
    def __init__(self, handler: Handler) -> None:
        super().__init__()
        self.handler = handler

    def send(self, request, **kw):
        status, headers, body = self.handler(request)
        if isinstance(body, bytes):  # XML, blob bytes: sent as given
            content = body
        else:
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


# --- P3b: signers -----------------------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _azure_session(handler):
    from azure.core.pipeline.transport import RequestsTransport

    session = requests.Session()
    session.mount("https://", FakeAdapter(handler))
    return RequestsTransport(session=session, session_owner=False)


def _challenged(handler):
    """Key Vault answers a first unauthenticated call with a 401 bearer challenge (the SDK's flow)."""

    def wrapped(req):
        if not req.headers.get("Authorization"):
            challenge = 'Bearer authorization="https://login.example/tenant", resource="https://vault.azure.net"'
            return 401, {"WWW-Authenticate": challenge}, None
        return handler(req)

    return wrapped


def azure_key_clients(key_id: str, curve: str = "P-256"):
    """A real `CryptographyClient` and `KeyClient` for one EC key version held in-process (ES256)."""
    import azure.keyvault.keys as azure_keys
    from azure.keyvault.keys.crypto import CryptographyClient
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    ident = azure_keys.KeyVaultKeyIdentifier(key_id)
    key = ec.generate_private_key(ec.SECP256R1())
    nums = key.public_key().public_numbers()
    jwk = {
        "kid": key_id,
        "kty": "EC",
        "crv": curve,
        "x": _b64url(nums.x.to_bytes(32, "big")),
        "y": _b64url(nums.y.to_bytes(32, "big")),
        "key_ops": ["sign", "verify"],
    }

    def handler(req):
        path = req.path_url.split("?")[0]
        if req.method == "GET" and path.startswith(f"/keys/{ident.name}/"):
            return 200, {}, {"key": jwk, "attributes": {"enabled": True}}
        if req.method == "POST" and path.endswith("/sign"):
            digest = _unb64url(json.loads(req.body)["value"])
            der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            r, s = utils.decode_dss_signature(der)
            raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            return 200, {}, {"kid": key_id, "value": _b64url(raw)}
        return 404, {}, {"error": {"code": "KeyNotFound", "message": "not found"}}

    transport = _challenged(handler)
    crypto = CryptographyClient(key_id, FakeAzureCredential(), transport=_azure_session(transport))
    keys = azure_keys.KeyClient(
        ident.vault_url, FakeAzureCredential(), transport=_azure_session(transport)
    )
    return crypto, keys


def gcp_kms_client(key_version: str, algorithm: str = "EC_SIGN_ED25519"):
    """A real `KeyManagementServiceClient` on its REST transport, one Ed25519 key version in-process."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import kms

    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    enum = kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm[algorithm].value

    def handler(req):
        if key_version not in req.url:
            return 404, {}, {"error": {"code": 404, "message": "not found", "status": "NOT_FOUND"}}
        if req.method == "POST" and ":asymmetricSign" in req.url:
            data = base64.b64decode(json.loads(req.body)["data"])
            return (
                200,
                {},
                {"signature": base64.b64encode(key.sign(data)).decode(), "name": key_version},
            )
        if req.method == "GET" and "/publicKey" in req.url:
            return 200, {}, {"pem": pem.decode(), "algorithm": enum, "name": key_version}
        return 400, {}, {"error": {"code": 400, "message": "bad", "status": "INVALID_ARGUMENT"}}

    client = kms.KeyManagementServiceClient(credentials=AnonymousCredentials(), transport="rest")
    client._transport._session.mount("https://", FakeAdapter(handler))
    return client


# --- P3b: anchors -----------------------------------------------------------------------------------------

_DATE = {"ETag": '"1"', "Last-Modified": "Sat, 31 Oct 2026 00:00:00 GMT"}


def azure_container(container: str, *, immutable: bool = True, puts: list | None = None):
    """A real `ContainerClient` over an in-process Blob service: create-if-absent puts, list, download."""
    from azure.storage.blob import ContainerClient

    blobs: dict[str, bytes] = {}

    def handler(req):
        path, _, query = req.path_url.partition("?")
        name = path.split(f"/{container}/", 1)[1] if f"/{container}/" in path else ""
        if req.method == "GET" and "restype=container" in query and "comp=list" not in query:
            flag = "true" if immutable else "false"
            return 200, {**_DATE, "x-ms-immutable-storage-with-versioning-enabled": flag}, b""
        if req.method == "PUT":
            if puts is not None:
                puts.append(dict(req.headers))
            if name in blobs and req.headers.get("If-None-Match") == "*":
                xml = b"<?xml version='1.0'?><Error><Code>BlobAlreadyExists</Code><Message>x</Message></Error>"
                return (
                    409,
                    {"x-ms-error-code": "BlobAlreadyExists", "Content-Type": "application/xml"},
                    xml,
                )
            blobs[name] = req.body if isinstance(req.body, bytes) else req.body.read()
            return 201, _DATE, b""
        if req.method == "GET" and "comp=list" in query:
            items = "".join(
                f"<Blob><Name>{n}</Name><Properties><BlobType>BlockBlob</BlobType></Properties></Blob>"
                for n in sorted(blobs)
            )
            xml = f"<?xml version='1.0'?><EnumerationResults><Blobs>{items}</Blobs><NextMarker/></EnumerationResults>"
            return 200, {"Content-Type": "application/xml"}, xml.encode()
        if req.method == "GET" and name in blobs:
            data = blobs[name]
            headers = {
                **_DATE,
                "Content-Type": "application/octet-stream",
                "Content-Range": f"bytes 0-{len(data) - 1}/{len(data)}",
                "x-ms-blob-type": "BlockBlob",
            }
            return 200, headers, data
        return 404, {"x-ms-error-code": "BlobNotFound"}, b""

    return ContainerClient(
        "https://contract.blob.core.windows.net",
        container,
        credential=FakeAzureCredential(),
        transport=_azure_session(handler),
    )


def gcs_bucket(bucket: str, *, retention_s: int | None = 86400, locked: bool = False):
    """A real `storage.Bucket` over an in-process GCS JSON API: create-only puts, list, download."""
    import re
    from urllib.parse import unquote

    from google.auth.credentials import AnonymousCredentials
    from google.cloud import storage

    objects: dict[str, bytes] = {}

    def handler(req):
        url = req.url
        if f"/upload/storage/v1/b/{bucket}/o" in url:
            body = req.body if isinstance(req.body, bytes) else req.body.encode()
            name = re.search(rb'"name": "([^"]+)"', body).group(1).decode()
            if name in objects and "ifGenerationMatch=0" in url:
                return 412, {}, {"error": {"code": 412, "message": "Precondition Failed"}}
            objects[name] = body.split(b"\r\n\r\n")[-1].rsplit(b"\r\n--", 1)[0]
            return 200, {}, {"name": name, "bucket": bucket, "generation": "1"}
        if f"/download/storage/v1/b/{bucket}/o/" in url:
            name = unquote(url.split("/o/", 1)[1].split("?")[0])
            return 200, {"Content-Type": "application/octet-stream"}, objects[name]
        if f"/storage/v1/b/{bucket}/o" in url:
            return 200, {}, {"items": [{"name": n, "bucket": bucket} for n in sorted(objects)]}
        if f"/storage/v1/b/{bucket}" in url:
            policy = (
                {"retentionPeriod": str(retention_s), "isLocked": locked} if retention_s else None
            )
            return 200, {}, {"name": bucket, **({"retentionPolicy": policy} if policy else {})}
        return 404, {}, {"error": {"code": 404, "message": "not found"}}

    session = requests.Session()
    session.mount("https://", FakeAdapter(handler))
    session.is_mtls = False  # google-cloud-core asks the session (an AuthorizedSession attribute)
    client = storage.Client(project="contract", credentials=AnonymousCredentials(), _http=session)
    return client.bucket(bucket)
