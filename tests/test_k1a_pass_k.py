"""K1a: pass^k on the single-turn gate, abstain rate, cost per task, the error bound, fail-closed qualified.jsonl."""

import json
import logging
import shutil
from decimal import Decimal

import pytest

from hadavin_sdk import cli, evals
from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.app import build
from hadavin_sdk.config import ConfigError, load_config
from hadavin_sdk.models import GateRun, Reply, ToolCall
from hadavin_sdk.registry import load_registry
from hadavin_sdk.runtime.agent_loop import qualified_runs

ACTION = "create_draft_record"
RIGHT = {"action": ACTION, "inputs": {"amount": "249.00", "title": "Standing desk"}}
TRAP = {"action": None, "inputs": {}}


class ScriptedLLM:
    """Replies per input document, in call order; records nothing else."""

    def __init__(self, script: dict[bytes, list[Reply]]) -> None:
        self.script = {doc: list(replies) for doc, replies in script.items()}

    def chat(self, messages, *, system, route, tools=None, documents=None, output_schema=None):
        return self.script[documents[0]].pop(0)


def _reply(expected: dict | None, cost: str = "0") -> Reply:
    calls = [ToolCall(name=expected["action"], input=expected["inputs"])] if expected else []
    return Reply(tool_calls=calls, cost_usd=Decimal(cost), model_id="fake-model")


def _registry(cfg_dir, lines: list[dict]):
    cfg = load_config(cfg_dir)
    (cfg.golden_dir / "test-agent.jsonl").write_text(
        "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
    )
    return load_registry(cfg)


def _doc(cfg_dir, name: str) -> bytes:
    return (load_config(cfg_dir).inputs_dir / name).read_bytes()


def test_one_failure_in_three_gives_pass3_zero(cfg_dir):
    reg = _registry(cfg_dir, [{"id": "a", "input_ref": "golden-01.txt", "expected": RIGHT}])
    wrong = {"action": ACTION, "inputs": {"amount": "1.00", "title": "Standing desk"}}
    llm = ScriptedLLM(
        {_doc(cfg_dir, "golden-01.txt"): [_reply(RIGHT), _reply(wrong), _reply(RIGHT)]}
    )
    run = evals.gate(reg, llm, "test-agent", k=3)
    assert (run.k, run.passed, run.pass_k) == (3, 0, 0.0)
    assert run.pass_rate == pytest.approx(2 / 3)
    assert not run.green and run.upper_error_bound == 1.0


def test_traps_abstain_rate_and_cost_per_task(cfg_dir):
    reg = _registry(
        cfg_dir,
        [
            {"id": "a", "input_ref": "golden-01.txt", "expected": RIGHT},
            {"id": "t", "input_ref": "golden-02.txt", "expected": TRAP, "trap": True},
        ],
    )
    llm = ScriptedLLM(
        {
            _doc(cfg_dir, "golden-01.txt"): [_reply(RIGHT, "0.01"), _reply(RIGHT, "0.02")],
            _doc(cfg_dir, "golden-02.txt"): [_reply(None, "0.03"), _reply(None, "0.04")],
        }
    )
    run = evals.gate(reg, llm, "test-agent", k=2)
    assert run.green and (run.passed, run.pass_k, run.pass_rate) == (2, 1.0, 1.0)
    assert run.abstain_rate == 0.5  # trap pairs count: 2 of 4
    assert run.cost_per_task_usd == Decimal("0.025")  # 0.10 over n * k = 4


def test_k1_keeps_todays_numbers(cfg_dir):
    reg = _registry(cfg_dir, [{"id": "a", "input_ref": "golden-01.txt", "expected": RIGHT}])
    run = evals.gate(
        reg, ScriptedLLM({_doc(cfg_dir, "golden-01.txt"): [_reply(RIGHT)]}), "test-agent"
    )
    assert (run.k, run.passed, run.pass_rate, run.pass_k, run.baseline_pass_rate) == (
        1,
        1,
        1.0,
        None,
        None,
    )
    assert run.green and run.abstain_rate == 0.0


def test_bound_values_and_empty_set(cfg_dir):
    assert evals.upper_error_bound(0, 30) == pytest.approx(0.0950, abs=0.001)
    assert evals.upper_error_bound(1, 30) == pytest.approx(0.1487, abs=0.001)
    assert evals.upper_error_bound(0, 0) is None
    assert evals.upper_error_bound(3, 3) == 1.0
    assert evals.upper_error_bound(0, 300) == pytest.approx(1 - 0.05 ** (1 / 300), abs=1e-6)
    assert 0.0 < evals.upper_error_bound(600, 1200) < 1.0  # no float overflow on a large set
    with pytest.raises(ValueError, match="outside"):
        evals.upper_error_bound(4, 3)
    run = evals.gate(_registry(cfg_dir, []), ScriptedLLM({}), "test-agent", k=3)
    assert not run.green
    assert (run.upper_error_bound, run.cost_per_task_usd, run.abstain_rate, run.pass_k) == (
        None,
    ) * 4


def test_k_below_one_refused(cfg_dir):
    with pytest.raises(ConfigError, match="at least 1"):
        evals.gate(_registry(cfg_dir, []), ScriptedLLM({}), "test-agent", k=0)
    with pytest.raises(SystemExit):  # argparse usage error, not a traceback
        cli.main(["--config", str(cfg_dir), "gate", "test-agent", "--k", "0"])


def _old_line() -> str:
    run = GateRun(
        agent_id="test-agent", model_id="m", prompt_sha256="p", config_hash="c",
        golden_sha256="g", n=1, passed=1, pass_rate=1.0, threshold=1.0, green=True,
    )  # fmt: skip
    data = json.loads(run.model_dump_json())
    for key in (
        "k",
        "pass_k",
        "abstain_rate",
        "cost_per_task_usd",
        "baseline_pass_rate",
        "upper_error_bound",
    ):
        del data[key]  # a line written before K1a
    return json.dumps(data)


def test_old_lines_parse_and_torn_line_warns(cfg_dir, caplog):
    reg = load_registry(load_config(cfg_dir))
    torn = '{"agent_id": "t' + chr(0xE9)  # the tail cuts a two-byte UTF-8 character in half
    (reg.config.root / "qualified.jsonl").write_bytes(
        (_old_line() + "\n" + torn).encode("utf-8")[:-1]
    )
    with caplog.at_level(logging.WARNING, logger="hadavin_sdk.runtime"):
        [run] = qualified_runs(reg)
    assert (run.k, run.pass_k, run.upper_error_bound) == (1, None, None)
    assert "line 2 is not valid JSON" in caplog.text


def test_valid_json_wrong_shape_refuses_start_up(live_cfg_dir, fake_system):
    cfg = load_config(live_cfg_dir)
    (cfg.root / "qualified.jsonl").write_text(
        _old_line() + "\n" + json.dumps({"agent_id": "test-agent", "future_field": 1}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="line 2: not a gate run"):
        build(
            live_cfg_dir,
            ["test-agent"],
            secrets=FakeSecretProvider({"fixture-token": fake_system.token}),
        )


def test_cli_line_k1_and_k3(live_cfg_dir, capsys):
    argv = ["--config", str(live_cfg_dir), "gate", "test-agent"]
    assert cli.main(argv) == 0
    head = "test-agent: 10/10 = 1.00 (threshold 1.00) -> GREEN"
    assert capsys.readouterr().out.strip() == f"{head}, pass^k=-, abstain=0.00, bound=0.259"
    recorded = load_config(live_cfg_dir).backends.llm.recorded_dir
    for first in recorded.glob("*-1.json"):  # same answer on attempts 2 and 3
        for attempt in (2, 3):
            shutil.copy(first, first.with_name(first.name.replace("-1.json", f"-{attempt}.json")))
    assert cli.main([*argv, "--k", "3"]) == 0
    assert capsys.readouterr().out.strip() == f"{head}, pass^k=1.00, abstain=0.00, bound=0.259"
