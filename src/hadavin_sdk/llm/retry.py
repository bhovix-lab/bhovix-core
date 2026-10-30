"""Bounded retries for every network llm kind (ported from WARDEN ``llm.py``; design 4.3).

Each SDK's own retries are off, so this loop is the only one. A transient failure is retried with exponential
backoff and full jitter, up to ``max_attempts`` requests in all; still failing, it is ``ProviderExhausted``.
Anything else (401 bad key, 400 malformed request) fails the same way every time, so it is a ``ProviderError``
at once.

Vendor-neutral (lock-in audit 2026-10-31, row 2): this module knows HTTP statuses, the standard library's network
errors and TLS, nothing else. Each kind knows its own SDK's errors and passes ``retryable(exc) -> bool | None``
(None: no opinion, the generic rule decides) and ``detail(exc) -> str`` (an error code safe to log).
"""

from __future__ import annotations

import random
import ssl
import time
from collections.abc import Callable

from hadavin_sdk.llm.protocol import ProviderError, ProviderExhausted

BASE_DELAY_S = 0.5
MAX_DELAY_S = 8.0

Retryable = Callable[[BaseException], "bool | None"]

# A peer closing the TLS connection mid-handshake or mid-read: a dropped connection, worth another attempt.
_TLS_DROPS = (ssl.SSLEOFError, ssl.SSLZeroReturnError)


def status(exc: BaseException) -> int | None:
    """The HTTP status an error carries as an int: ``status_code`` (most SDKs) or ``code`` (urllib)."""
    for value in (getattr(exc, "status_code", None), getattr(exc, "code", None)):
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def retryable_status(code: int) -> bool:
    return code in (408, 429) or code >= 500


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


def transient(exc: BaseException, retryable: Retryable | None = None) -> bool:
    if any(isinstance(e, ssl.SSLError) and not isinstance(e, _TLS_DROPS) for e in _chain(exc)):
        return False  # a certificate or protocol problem fails the same way every time
    if retryable is not None and (said := retryable(exc)) is not None:
        return said
    code = status(exc)
    if code is not None:
        return retryable_status(code)
    return isinstance(exc, OSError)  # URLError, socket timeouts, connection resets


def retry_after(exc: BaseException) -> float:
    """Seconds the server asked for (``Retry-After``, numeric form only), capped at MAX_DELAY_S; else 0."""
    headers = getattr(exc, "headers", None) or getattr(
        getattr(exc, "response", None), "headers", None
    )
    try:
        return min(MAX_DELAY_S, max(0.0, float(headers.get("retry-after"))))
    except (AttributeError, TypeError, ValueError):
        return 0.0


def describe(exc: BaseException, detail: Callable[[BaseException], str] | None = None) -> str:
    """Class, status and the kind's error code only: an SDK message can quote the request."""
    parts = [type(exc).__name__, str(status(exc) or ""), detail(exc) if detail else ""]
    return " ".join(p for p in parts if p)


def with_retry[T](
    call: Callable[[], T],
    *,
    label: str,
    max_attempts: int,
    sleep: Callable[[float], None] = time.sleep,
    retryable: Retryable | None = None,
    detail: Callable[[BaseException], str] | None = None,
) -> T:
    for attempt in range(1, max_attempts + 1):
        try:
            return call()
        except ProviderError:
            raise
        except Exception as exc:  # every failure is classified below, never swallowed
            if not transient(exc, retryable):
                raise ProviderError(f"{label}: {describe(exc, detail)}") from exc
            if attempt == max_attempts:
                raise ProviderExhausted(
                    f"{label}: {describe(exc, detail)} after {max_attempts} attempts"
                ) from exc
            # Full jitter spreads retries from many runs hitting one throttled account (not crypto); never
            # sooner than the server asked.
            jitter = random.uniform(0, min(MAX_DELAY_S, BASE_DELAY_S * 2 ** (attempt - 1)))  # noqa: S311
            sleep(max(jitter, retry_after(exc)))
    raise AssertionError("unreachable")  # max_attempts >= 1 (settings)
