"""Bounded retries for every network llm kind (ported from WARDEN ``llm.py``; design 4.3).

Each SDK's own retries are off, so this loop is the only one. A transient failure (a connection error or socket
timeout, HTTP 429 or 5xx, a throttling error code) is retried with exponential backoff and full jitter, up to
``max_attempts`` requests in all; still failing, it is ``ProviderExhausted``. Anything else (401 bad key,
400 malformed request) fails the same way every time, so it is a ``ProviderError`` at once.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable

from hadavin_sdk.llm.protocol import ProviderError, ProviderExhausted

BASE_DELAY_S = 0.5
MAX_DELAY_S = 8.0

# Network failures with no HTTP status, by class name so no SDK is imported here: stdlib (OSError covers
# URLError and socket timeouts), anthropic, botocore.
_NETWORK = frozenset(
    {
        "OSError",
        "APIConnectionError",
        "APITimeoutError",
        "EndpointConnectionError",
        "ConnectTimeoutError",
        "ReadTimeoutError",
        "ConnectionClosedError",
    }
)
# Bedrock error codes worth another attempt (Converse API reference).
_RETRY_CODES = frozenset(
    {
        "ThrottlingException",
        "ServiceQuotaExceededException",
        "ServiceUnavailableException",
        "InternalServerException",
        "ModelNotReadyException",
        "ModelTimeoutException",
    }
)


def _status(exc: BaseException) -> int | None:
    """The HTTP status an SDK error carries: ``status_code`` (anthropic), ``code`` (urllib), or botocore's
    response metadata."""
    response = getattr(exc, "response", None)
    meta = response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
    for value in (
        getattr(exc, "status_code", None),
        getattr(exc, "code", None),
        meta.get("HTTPStatusCode"),
    ):
        if isinstance(value, int):
            return value
    return None


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    return str(response.get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""


def transient(exc: BaseException) -> bool:
    if _error_code(exc) in _RETRY_CODES:
        return True
    status = _status(exc)
    if status is not None:
        return status == 429 or status >= 500
    return any(c.__name__ in _NETWORK for c in type(exc).__mro__)


def describe(exc: BaseException) -> str:
    """Class, status and error code only: an SDK message can quote the request."""
    parts = [type(exc).__name__, str(_status(exc) or ""), _error_code(exc)]
    return " ".join(p for p in parts if p)


def with_retry[T](
    call: Callable[[], T],
    *,
    label: str,
    max_attempts: int,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    for attempt in range(1, max_attempts + 1):
        try:
            return call()
        except ProviderError:
            raise
        except Exception as exc:  # every failure is classified below, never swallowed
            if not transient(exc):
                raise ProviderError(f"{label}: {describe(exc)}") from exc
            if attempt == max_attempts:
                raise ProviderExhausted(
                    f"{label}: {describe(exc)} after {max_attempts} attempts"
                ) from exc
            # Full jitter: spreads retries from many runs hitting one throttled account. Not crypto.
            sleep(random.uniform(0, min(MAX_DELAY_S, BASE_DELAY_S * 2 ** (attempt - 1))))  # noqa: S311
    raise AssertionError("unreachable")  # max_attempts >= 1 (settings)
