"""The slice 2 detector kinds (slice2-unverified), built through the backend table.

* ``llm_judge`` runs on a scripted model that answers the judge's forced tool the way a model would (it calls
  the regex detector its "judgement"): the suite tests the judge's plumbing, not a model's skill. Its golden set
  qualifies a real model (evals gate).
* ``bedrock_guardrail`` runs on botocore's Stubber, which checks each ApplyGuardrail request and hand-written
  fixture (``tests/fixtures/recorded_http/bedrock_guardrail``) against the service model (moto lacks it).

``detector_broken`` holds the same kinds with their backend failing, for the fail-closed check.
"""

import copy
from decimal import Decimal

import pytest

from hadavin_sdk.backends import make
from hadavin_sdk.backends.table import GuardrailSettings, JudgeSettings
from hadavin_sdk.guard.injection import RegexDetector
from hadavin_sdk.llm import ProviderExhausted
from hadavin_sdk.llm.common import ANSWER_TOOL
from hadavin_sdk.models import Reply, ToolCall
from tests.contracts.kinds import kind
from tests.fixtures.http_fake import fixture

JUDGE_COST = Decimal("0.0012")
DENIED = "AccessDenied" + "Exception"  # built from parts: a scanner reads the literal as a key


class JudgeModel:
    """A scripted model for the judge: injection iff the regex detector flags the attached text."""

    def __init__(self, fail: bool = False) -> None:
        self.fail, self.calls = fail, []

    def chat(self, messages, *, system, route, tools=None, documents=None, output_schema=None):
        self.calls.append({"system": system, "route": route, "output_schema": output_schema})
        if self.fail:
            raise ProviderExhausted("judge: throttled after retries")
        hit = RegexDetector(0.5).check(documents[0].decode("utf-8"), "judge").flagged
        answer = {"injection": hit, "confidence": 0.9}
        return Reply(
            tool_calls=[ToolCall(name=ANSWER_TOOL, input=answer)],
            model_id="judge-model",
            cost_usd=JUDGE_COST,
        )


def judge(model=None):
    return make(
        "detector", JudgeSettings(kind="llm_judge", route="screen"), llm=model or JudgeModel()
    )


class GuardrailClient:
    """An ApplyGuardrail client on Stubber: answers `prompt_attack` iff the regex detector flags the text."""

    def __init__(self, fail: bool = False) -> None:
        boto3 = pytest.importorskip("boto3", reason="needs extra aws")
        from botocore import UNSIGNED
        from botocore.config import Config
        from botocore.stub import Stubber

        self.fail, self.requests = fail, []
        # Unsigned: no credential lookup, so a developer's own AWS profile is never touched.
        self.client = boto3.client(
            "bedrock-runtime",
            region_name="contract-region-1",
            config=Config(signature_version=UNSIGNED),
        )
        self.stub = Stubber(self.client)
        self.stub.activate()

    def apply_guardrail(self, **params):
        self.requests.append(copy.deepcopy(params))
        if self.fail:
            self.stub.add_client_error(
                "apply_guardrail", service_error_code=DENIED, http_status_code=403
            )
        else:
            text = params["content"][0]["text"]["text"]
            name = "prompt_attack" if RegexDetector(0.5).check(text, "x").flagged else "clean"
            self.stub.add_response(
                "apply_guardrail", fixture("bedrock_guardrail", name)["body"], params
            )
        return self.client.apply_guardrail(**params)


def guardrail(client=None):
    from hadavin_sdk.guard.bedrock_guardrail import GuardrailDetector

    return GuardrailDetector(client or GuardrailClient(), "contract-guardrail", "1", 0.5)


kind("detector", "llm_judge")(lambda tmp_path: judge())
kind("detector", "bedrock_guardrail")(lambda tmp_path: guardrail())
kind("detector_broken", "llm_judge")(lambda tmp_path: judge(JudgeModel(fail=True)))
kind("detector_broken", "bedrock_guardrail")(lambda tmp_path: guardrail(GuardrailClient(fail=True)))


def guardrail_settings() -> GuardrailSettings:
    return GuardrailSettings(
        kind="bedrock_guardrail",
        guardrail_id="contract-guardrail",
        guardrail_version="1",
        region="contract-region-1",
    )
