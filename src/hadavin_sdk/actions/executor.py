"""Executor: the only component that holds a client-system secret and performs an action.

It re-checks the plan hash, calls with the idempotency key, and after a timeout or a dropped connection looks the
result up instead of retrying blindly. It never writes run state; it returns a ``RunResult``.
"""

from __future__ import annotations

import http.client
import importlib
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from hadavin_sdk.actions.contract import ActionContract
from hadavin_sdk.actions.secrets import SecretProvider
from hadavin_sdk.config import url_allowed
from hadavin_sdk.guard.egress import EgressRefused, egress_check
from hadavin_sdk.models import ApprovalDecision, GateDecision, Plan, RunResult
from hadavin_sdk.registry import Registry

Call = Callable[..., tuple[int, Any]]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would carry the bearer token to a host egress_check never saw: refuse every redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def resolve(ref: str, allowed: list[str]) -> Callable[..., Any]:
    module, _, name = ref.partition(":")
    if module not in allowed:
        raise PermissionError(f"{ref} is outside check_modules")
    return getattr(importlib.import_module(module), name)


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


class Executor:
    def __init__(
        self, registry: Registry, secrets: SecretProvider, timeout_s: float = 10.0
    ) -> None:
        self.registry, self._secrets, self.timeout_s = registry, secrets, timeout_s

    def _caller(
        self, contract: ActionContract, heartbeat: Callable[[], None] | None = None
    ) -> Call:
        cfg = self.registry.config
        base = cfg.systems[contract.executor.system].base_url.rstrip("/")
        token = self._secrets.get(contract.executor.secret_name)

        def call(method: str, path: str, body: Any = None, headers: dict | None = None):
            if heartbeat is not None:
                heartbeat()  # each attempt (call, lookup) marks the run alive for tick's stuck rule
            url = base + path
            if not url_allowed(url, cfg.allow_insecure_loopback):  # re-checked at call time
                raise EgressRefused("https only (http only for loopback when explicitly allowed)")
            egress_check(url, cfg.egress_hosts)
            data = None if body is None else json.dumps(body).encode("utf-8")
            req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - scheme checked
            req.add_header("Authorization", f"Bearer {token}")
            req.add_header("Content-Type", "application/json")
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            try:
                # Scheme limited to http/https above, host allow-listed, redirects refused.
                with _OPENER.open(req, timeout=self.timeout_s) as resp:  # nosec B310
                    return resp.status, _json(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, None

        return call

    @staticmethod
    def _path(template: str, inputs: dict, key: str) -> tuple[str, str]:
        """Every substituted value is percent-encoded, so ``../x`` or ``1?force=true`` stays one segment."""
        method, _, path = template.partition(" ")
        enc = {k: quote(str(v), safe="") for k, v in inputs.items()}
        return method, path.format(key=quote(key, safe=""), **enc)

    def execute(
        self,
        plan: Plan,
        decision: GateDecision,
        approval: ApprovalDecision | None = None,
        heartbeat: Callable[[], None] | None = None,
    ) -> RunResult:
        """`heartbeat` is called before every HTTP attempt. The runtime passes `store.touch` for the run, so the
        executor never holds the store (trust boundary) and long retries never look stuck."""
        h = plan.hash()
        if decision.run_id != plan.run_id:
            return RunResult(outcome="failed", error_code="run_mismatch")
        if h != decision.plan_hash or (approval is not None and approval.plan_hash != h):
            return RunResult(outcome="failed", error_code="plan_hash_mismatch")
        if decision.outcome == "needs_approval" and (
            approval is None or approval.decision != "approve"
        ):
            return RunResult(outcome="failed", error_code="not_approved")
        if decision.outcome == "deny":
            return RunResult(outcome="failed", error_code="denied")
        contract = self.registry.contracts[plan.action_id]
        call = self._caller(contract, heartbeat)
        method, path = self._path(contract.executor.operation, plan.inputs, plan.idempotency_key)
        body = plan.inputs if method in {"POST", "PUT", "PATCH"} else None
        try:
            status, data = call(
                method, path, body, {contract.idempotency_header: plan.idempotency_key}
            )
        except EgressRefused:
            return RunResult(outcome="failed", error_code="egress_refused")
        except urllib.error.URLError as exc:
            if not isinstance(exc.reason, TimeoutError):
                # Could not connect: nothing provably happened, so the outcome is unknown, not failed.
                return RunResult(outcome="unknown", error_code="system_unreachable")
            return self._lookup(contract, plan, call)
        except (TimeoutError, ConnectionError, http.client.HTTPException):
            # The request may have been applied (timeout, reset, cut-off reply): look it up.
            return self._lookup(contract, plan, call)
        if 200 <= status < 300:
            ref = data.get("id") if isinstance(data, dict) else None
            if ref is None and contract.executor.lookup_operation:
                return self._lookup(contract, plan, call)
            return RunResult(outcome="succeeded", external_ref=ref or plan.target.ref)
        if method != "GET" and (status >= 500 or status == 408):
            # A mutating call may have been applied before the server failed: look it up, never retry.
            if contract.executor.lookup_operation:
                return self._lookup(contract, plan, call)
            return RunResult(outcome="unknown", error_code=f"http_{status}")
        return RunResult(outcome="failed", error_code=f"http_{status}")

    def _lookup(self, contract: ActionContract, plan: Plan, call: Call) -> RunResult:
        """Find the result by idempotency key. Never retry blindly."""
        if not contract.executor.lookup_operation:
            return RunResult(outcome="unknown", error_code="timeout_no_lookup")
        method, path = self._path(
            contract.executor.lookup_operation, plan.inputs, plan.idempotency_key
        )
        try:
            status, data = call(method, path)
        except (OSError, http.client.HTTPException):
            return RunResult(outcome="unknown", error_code="lookup_failed")
        if status == 200 and isinstance(data, dict) and data.get("id"):
            return RunResult(outcome="succeeded", external_ref=data["id"])
        return RunResult(outcome="unknown", error_code="lookup_failed")

    def verify(self, plan: Plan, result: RunResult) -> bool:
        contract = self.registry.contracts[plan.action_id]
        fn = resolve(contract.verify_check, self.registry.config.check_modules)
        return bool(fn(plan, result, self._caller(contract)))

    def rollback(self, plan: Plan, result: RunResult) -> RunResult:
        contract = self.registry.contracts[plan.action_id]
        if not contract.rollback:
            return RunResult(outcome="failed", error_code="no_rollback")
        fn = resolve(contract.rollback, self.registry.config.check_modules)
        return fn(plan, result, self._caller(contract))
