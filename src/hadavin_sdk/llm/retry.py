"""Bounded retries for every network llm kind (ported from WARDEN ``llm.py``; design 4.3).

Each SDK's own retries are off, so this loop is the only one. A transient failure (a connection error or socket
timeout, HTTP 429 or 5xx, a throttling error code) is retried with exponential backoff and full jitter, up to
``max_attempts`` requests in all; still failing, it is ``ProviderExhausted``. Anything else (401 bad key,
400 malformed request) fails the same way every time, so it is a ``ProviderError`` at once.
"""

from __future__ import annotations

import random
import ssl
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
        "TransportError",  # google-auth, refreshing a Vertex token
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


# A peer closing the TLS connection mid-handshake or mid-read: a dropped connection, worth another attempt.
_TLS_DROPS = (ssl.SSLEOFError, ssl.SSLZeroReturnError)


def _chain(exc: BaseException) -> list[BaseException]:
    """The error and what it wraps (urllib's ``reason``, ``__cause__``, ``__context__``), at most 8 deep."""
    seen: list[BaseException] = []
    todo: list[object] = [exc]
    while todo and len(seen) < 8:
        e = todo.pop()
        if isinstance(e, BaseException) and e not in seen:
            seen.append(e)
            todo += [getattr(e, "reason", None), e.__cause__, e.__context__]
    return seen


def transient(exc: BaseException) -> bool:
    if any(isinstance(e, ssl.SSLError) and not isinstance(e, _TLS_DROPS) for e in _chain(exc)):
        return False  # a certificate or protocol problem fails the same way every time
    if _error_code(exc) in _RETRY_CODES:
        return True
    status = _status(exc)
    if status is not None:
        return status in (408, 429) or status >= 500
    return any(c.__name__ in _NETWORK for c in type(exc).__mro__)


def retry_after(exc: BaseException) -> float:
    """Seconds the server asked for (``Retry-After``, numeric form only), capped at MAX_DELAY_S; else 0."""
    headers = getattr(exc, "headers", None) or getattr(
        getattr(exc, "response", None), "headers", None
    )
    try:
        return min(MAX_DELAY_S, max(0.0, float(headers.get("retry-after"))))
    except (AttributeError, TypeError, ValueError):
        return 0.0


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
            # Full jitter spreads retries from many runs hitting one throttled account (not crypto); never
            # sooner than the server asked.
            jitter = random.uniform(0, min(MAX_DELAY_S, BASE_DELAY_S * 2 ** (attempt - 1)))  # noqa: S311
            sleep(max(jitter, retry_after(exc)))
    raise AssertionError("unreachable")  # max_attempts >= 1 (settings)
