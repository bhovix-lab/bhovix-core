"""Approval requests and decisions. A timeout escalates and never approves; no model output decides."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta

from bhovix_core.approvals.channel import Channel, clean
from bhovix_core.audit.protocol import AuditSink
from bhovix_core.guard.injection import Detector, injection_check
from bhovix_core.models import (
    ApprovalDecision,
    ApprovalRequest,
    AuditEvent,
    GateDecision,
    Plan,
    canonical_json,
    now,
)
from bhovix_core.registry import Registry
from bhovix_core.store.protocol import StaleState, Store

OnDecided = Callable[[str, str, ApprovalDecision | None], object]


WARNING = "WARNING: the inputs read like instructions to an AI. Check them before approving. "


def summary(plan: Plan, detector: Detector | None = None) -> str:
    """Template-built, never by the model; inputs redacted and link-free. Inputs that read like instructions
    (the model copied them from a document) get a warning so a person does not approve them on autopilot."""
    inputs = canonical_json(plan.inputs)
    flagged = detector is not None and injection_check(detector, inputs, "approval_summary").flagged
    return clean(
        f"{WARNING if flagged else ''}{plan.agent_id} asks to run {plan.action_id} "
        f"v{plan.action_version} ({plan.risk_class}) on {plan.target.system}. Inputs: {inputs}. "
        f"Expected: {plan.expected_outcome}. Plan {plan.hash()[:12]}."
    )


class Approvals:
    """Decisions must come from a channel's verified parse (``receive``), never from caller-supplied fields:
    ``decide`` is the internal step after verification and the one tests drive with a trusted fake."""

    def __init__(
        self,
        store: Store,
        audit: AuditSink,
        registry: Registry,
        channel: Channel,
        on_decided: OnDecided,
        clock: Callable[[], datetime] = now,
        detector: Detector | None = None,
    ) -> None:
        self.store, self.audit, self.registry, self.channel = store, audit, registry, channel
        self.on_decided, self.clock, self.detector = on_decided, clock, detector

    def receive(self, headers: Mapping[str, str], body: bytes) -> tuple[bool, str]:
        """Entry point for a channel callback: the channel verifies the request and names the approver."""
        d = self.channel.parse_decision(headers, body, self.clock().timestamp())
        if d is None:
            return False, "bad_signature"
        return self.decide(d)

    def _audit(self, req: ApprovalRequest, operation: str, principal: str, **kw) -> None:
        self.audit.write_outcome(
            AuditEvent(
                run_id=req.run_id,
                domain="approval",
                operation=operation,
                principal=principal,
                source=self.channel.name,
                object_ref=req.approval_id,
                inputs_hash=req.plan_hash,
                **kw,
            )
        )

    def request(self, plan: Plan, decision: GateDecision, requested_by: str) -> ApprovalRequest:
        chain = self.registry.chains[self.registry.contracts[plan.action_id].chain_id]
        req = ApprovalRequest(
            run_id=plan.run_id,
            plan_hash=decision.plan_hash,
            risk_class=plan.risk_class,
            chain_id=chain.id,
            steps=chain.steps,
            step_expires_at=self.clock() + timedelta(seconds=chain.steps[0].timeout_s),
            requested_by=requested_by,
            summary=summary(plan, self.detector),
        )
        self.store.save_approval_request(req)
        self.channel.send(req, chain.steps[0].approver_ids)
        self._audit(req, "request", requested_by, result="PENDING")
        return req

    def decide(self, d: ApprovalDecision) -> tuple[bool, str]:
        req = self.store.get_approval_request(d.approval_id)
        reason = None
        if req.status != "PENDING":
            reason = "not_pending"
        elif d.step != req.current_step:
            reason = "old_step"
        elif self.clock() >= req.step_expires_at:
            reason = "step_expired"  # the sweep escalates it; a late decision never runs the plan
        elif d.approver_id not in req.steps[req.current_step].approver_ids:
            reason = "not_an_approver_for_this_step"
        elif d.approver_id == req.requested_by:
            reason = "requester_cannot_approve"
        elif d.plan_hash != req.plan_hash:
            reason = "plan_hash_mismatch"
        if reason:
            self._audit(req, "decide", d.approver_id, decision=d.decision, error_code=reason)
            return False, reason
        status = "APPROVED" if d.decision == "approve" else "REJECTED"
        new = req.model_copy(update={"status": status})
        try:
            self.store.update_approval_request(new, "PENDING", req.current_step)
        except StaleState:
            return False, "stale"
        self.store.save_approval_decision(d)
        self._audit(req, "decide", d.approver_id, decision=d.decision, result=status)
        self.channel.update(new)
        self.on_decided(req.run_id, status, d)
        return True, status.lower()

    def sweep(self, at: datetime | None = None) -> list[str]:
        """Escalate each due request one step; after the last step it expires. Returns approval ids touched."""
        at = at or self.clock()
        touched = []
        for req in self.store.list_due_approvals(at):
            nxt = req.current_step + 1
            if nxt < len(req.steps):
                new = req.model_copy(
                    update={
                        "current_step": nxt,
                        "step_expires_at": at + timedelta(seconds=req.steps[nxt].timeout_s),
                    }
                )
                status = "PENDING"
            else:
                new = req.model_copy(update={"status": "EXPIRED"})
                status = "EXPIRED"
            try:
                self.store.update_approval_request(new, "PENDING", req.current_step)
            except StaleState:
                continue
            self._audit(req, "sweep", "system", result=status, decision=f"step{new.current_step}")
            if status == "PENDING":
                self.channel.send(new, req.steps[nxt].approver_ids)
            else:
                self.channel.update(new)
                self.channel.notify(
                    req.requested_by,
                    f"Approval {req.approval_id} expired with no decision. Nothing was run.",
                )
                self.on_decided(req.run_id, "EXPIRED", None)
            touched.append(req.approval_id)
        return touched
