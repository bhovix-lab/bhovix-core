"""Executor: the only component that holds a client-system secret and performs an action.

It re-checks the plan hash, calls with the idempotency key, and after a timeout looks the result up instead of
retrying blindly. It never writes run state; it returns a ``RunResult``.
"""

from __future__ import annotations

import importlib
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from bhovix_core.actions.contract import ActionContract
from bhovix_core.actions.secrets import SecretProvider
from bhovix_core.guard.egress import EgressRefused, egress_check
from bhovix_core.models import ApprovalDecision, GateDecision, Plan, RunResult
from bhovix_core.registry import Registry

Call = Callable[..., tuple[int, Any]]


def resolve(ref: str, allowed: list[str]) -> Callable[..., Any]:
    module, _, name = ref.partition(":")
    if module not in allowed:
        raise PermissionError(f"{ref} is outside check_modules")
    return getattr(importlib.import_module(module), name)


class Executor:
    def __init__(
        self, registry: Registry, secrets: SecretProvider, timeout_s: float = 10.0
    ) -> None:
        self.registry, self._secrets, self.timeout_s = registry, secrets, timeout_s

    def _caller(self, contract: ActionContract) -> Call:
        cfg = self.registry.config
        base = cfg.systems[contract.executor.system].base_url.rstrip("/")
        token = self._secrets.get(contract.executor.secret_name)

        def call(method: str, path: str, body: Any = None, headers: dict | None = None):
            url = base + path
            if not url.startswith(("http://", "https://")):
                raise EgressRefused("only http and https are allowed")
            egress_check(url, cfg.egress_hosts)
            data = None if body is None else json.dumps(body).encode("utf-8")
            req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - scheme checked
            req.add_header("Authorization", f"Bearer {token}")
            req.add_header("Content-Type", "application/json")
            for k, v in (headers or {}).items():
                req.add_header(k, v)
            try:
                # Scheme limited to http/https above and host allow-listed by egress_check.
                with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310  # nosec B310
                    raw = resp.read()
                    return resp.status, json.loads(raw) if raw else None
            except urllib.error.HTTPError as exc:
                return exc.code, None

        return call

    @staticmethod
    def _path(template: str, inputs: dict, key: str) -> tuple[str, str]:
        method, _, path = template.partition(" ")
        return method, path.format(key=key, **inputs)

    def execute(
        self, plan: Plan, decision: GateDecision, approval: ApprovalDecision | None = None
    ) -> RunResult:
        h = plan.hash()
        if h != decision.plan_hash or (approval is not None and approval.plan_hash != h):
            return RunResult(outcome="failed", error_code="plan_hash_mismatch")
        if decision.outcome == "needs_approval" and (
            approval is None or approval.decision != "approve"
        ):
            return RunResult(outcome="failed", error_code="not_approved")
        if decision.outcome == "deny":
            return RunResult(outcome="failed", error_code="denied")
        contract = self.registry.contracts[plan.action_id]
        call = self._caller(contract)
        method, path = self._path(contract.executor.operation, plan.inputs, plan.idempotency_key)
        body = plan.inputs if method in {"POST", "PUT", "PATCH"} else None
        try:
            status, data = call(
                method, path, body, {contract.idempotency_header: plan.idempotency_key}
            )
        except EgressRefused:
            return RunResult(outcome="failed", error_code="egress_refused")
        except (TimeoutError, urllib.error.URLError) as exc:
            if isinstance(exc, urllib.error.URLError) and not isinstance(exc.reason, TimeoutError):
                # Refused before anything was sent is still "unknown": we cannot prove nothing happened.
                return RunResult(outcome="unknown", error_code="system_unreachable")
            return self._lookup(contract, plan, call)
        if 200 <= status < 300:
            ref = (data or {}).get("id") if isinstance(data, dict) else None
            return RunResult(outcome="succeeded", external_ref=ref or plan.target.ref)
        return RunResult(outcome="failed", error_code=f"http_{status}", retryable=status >= 500)

    def _lookup(self, contract: ActionContract, plan: Plan, call: Call) -> RunResult:
        """After a timeout: find the result by idempotency key. Never retry blindly."""
        if not contract.executor.lookup_operation:
            return RunResult(outcome="unknown", error_code="timeout_no_lookup")
        method, path = self._path(
            contract.executor.lookup_operation, plan.inputs, plan.idempotency_key
        )
        try:
            status, data = call(method, path)
        except (TimeoutError, OSError):
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
