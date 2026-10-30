"""A real boto3 client whose calls are answered in-process, for contract kinds that must not patch botocore
globally (moto's mock stays on until stopped, and the kind fixtures have no teardown).

Each answer is validated against the API's documented output shape, as botocore's Stubber does. Explicit fake
credentials: endpoint resolution reads credentials, and must never reach a real profile on a laptop.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import boto3
from botocore.awsrequest import AWSResponse
from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

# A region botocore knows, read from its own data (no region literal in the repo).
REGION = boto3.session.Session().get_available_regions("secretsmanager")[0]


def not_found(op: str, code: str = "ResourceNotFoundException") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "not found"}}, op)


def stub_client(service: str, answer: Callable[[str, dict], dict]) -> Any:
    """`answer(operation_name, api_params) -> response` (raise `not_found(...)` for errors); `client.calls`
    records (operation_name, api_params)."""
    client = boto3.client(
        service,
        region_name=REGION,
        aws_access_key_id="AKIA" + "IOSFODNN7EXAMPLE",
        aws_secret_access_key="fake" + "-secret-key",
    )
    calls: list[tuple[str, dict]] = []

    def keep(params, context, **_):
        context["api_params"] = dict(params)  # before-call only sees the serialized request

    def respond(model, context, **_):
        params = context["api_params"]
        calls.append((model.name, params))
        out = answer(model.name, params)
        validate_parameters(out, model.output_shape)
        return AWSResponse(None, 200, {}, None), out

    event_id = client.meta.service_model.service_id.hyphenize()  # e.g. "secrets-manager"
    client.meta.events.register(f"before-parameter-build.{event_id}.*", keep)
    client.meta.events.register_first(f"before-call.{event_id}.*", respond)
    client.calls = calls
    return client
