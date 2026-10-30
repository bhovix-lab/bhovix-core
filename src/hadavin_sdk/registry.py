"""Agent registry: loads agents, principals, chains and action contracts, and checks them together.

Every cross-file problem fails at start-up with ``ConfigError``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from hadavin_sdk.actions.contract import ActionContract, schema_problems
from hadavin_sdk.config import Config, ConfigError, Money, confined
from hadavin_sdk.identity import Principal
from hadavin_sdk.models import ChainStep, sha256_hex


class Budget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    daily: Money
    monthly: Money


class AgentRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    status: Literal["draft", "live", "retired"]
    data_class: Literal["public", "internal", "confidential", "restricted"]
    model_route: str
    prompt_file: str
    scope_allowed: list[str]
    tools_allowed: list[str] = []
    max_steps: int = Field(gt=0)
    budget_usd: Budget


class Chain(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    steps: list[ChainStep]


@dataclass(frozen=True)
class Registry:
    config: Config
    agents: dict[str, AgentRecord]
    principals: dict[str, Principal]
    chains: dict[str, Chain]
    contracts: dict[str, ActionContract]

    def _prompt_path(self, agent_id: str):
        return confined(self.config.root, self.agents[agent_id].prompt_file)

    def prompt(self, agent_id: str) -> str:
        return self._prompt_path(agent_id).read_text(encoding="utf-8")

    def prompt_sha256(self, agent_id: str) -> str:
        return hashlib.sha256(self._prompt_path(agent_id).read_bytes()).hexdigest()

    def golden_path(self, agent_id: str):
        return confined(self.config.golden_dir, f"{agent_id}.jsonl")

    def golden_sha256(self, agent_id: str) -> str:
        path = self.golden_path(agent_id)
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ""

    def config_hash(self, agent_id: str) -> str:
        """What the agent was qualified on. `exclude_defaults`: from this version on, adding an optional field
        with a default never un-qualifies existing agents. The llm backend kind is included, so a backend swap
        with the same model id needs a new gate run.

        Upgrade note (slice 2 P1a): this version changes the hash itself, so every agent needs ONE new gate run
        (`hadavin-sdk gate <agent>`) before the runtime starts it again; see CHANGELOG.md."""
        agent = self.agents[agent_id]

        def dump(model) -> dict:
            return model.model_dump(mode="json", exclude_defaults=True)

        return sha256_hex(
            {
                "agent": dump(agent),
                "route": dump(self.config.routes[agent.model_route]),
                "actions": [dump(self.contracts[a]) for a in sorted(agent.scope_allowed)],
                "llm_backend": self.config.backends.llm,
            }
        )

    def tools_for(self, agent_id: str, available: set[str]) -> list[str]:
        """Non-action tools the loop may offer: only those listed. Empty list means none."""
        return sorted(set(self.agents[agent_id].tools_allowed) & available)


def _yaml(path) -> object:
    return yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None


def _by_id(items: list, model: type, where: str) -> dict:
    """Validated entries keyed by id; a duplicate id fails (a later entry must never shadow an earlier one)."""
    out: dict = {}
    for raw in items or []:
        obj = model(**raw) if isinstance(raw, dict) else model(raw)
        if obj.id in out:
            raise ConfigError(f"{where}: duplicate id {obj.id}")
        out[obj.id] = obj
    return out


def load_registry(config: Config) -> Registry:
    root = config.root
    try:
        agents = _by_id(_yaml(root / "agents.yaml"), AgentRecord, "agents.yaml")
        principals = _by_id(_yaml(root / "principals.yaml"), Principal, "principals.yaml")
        chains = _by_id(_yaml(root / "chains.yaml"), Chain, "chains.yaml")
        contracts = _by_id(
            [_yaml(p) for p in sorted((root / "actions").glob("*.yaml"))],
            ActionContract,
            "actions/",
        )
    except ConfigError:
        raise
    except (ValidationError, TypeError, yaml.YAMLError) as exc:
        raise ConfigError(str(exc)) from exc
    problems = _cross_check(config, agents, chains, contracts)
    if problems:
        raise ConfigError("; ".join(problems))
    return Registry(config, agents, principals, chains, contracts)


def _cross_check(config, agents, chains, contracts) -> list[str]:
    out = []
    for a in agents.values():
        if a.model_route not in config.routes:
            out.append(f"agent {a.id}: unknown model_route {a.model_route}")
        out += [f"agent {a.id}: no contract for {x}" for x in a.scope_allowed if x not in contracts]
        try:
            if not confined(config.root, a.prompt_file).is_file():
                out.append(f"agent {a.id}: prompt_file missing")
        except ConfigError:
            out.append(f"agent {a.id}: prompt_file escapes the config folder")
    for c in chains.values():
        if not c.steps:
            out.append(f"chain {c.id}: no steps")
        for i, s in enumerate(c.steps):
            if not s.approver_ids or s.timeout_s <= 0:
                out.append(f"chain {c.id} step {i}: needs approvers and timeout_s > 0")
    for c in contracts.values():
        out += [f"action {c.id}: {p}" for p in schema_problems(c.input_schema)]
        props = (c.input_schema or {}).get("properties") or {}
        if "key" in props:
            out.append(f"action {c.id}: input 'key' is reserved for the idempotency key")
        for op in filter(None, [c.executor.operation, c.executor.lookup_operation]):
            for field in re.findall(r"{(\w+)}", op):
                if field != "key" and "pattern" not in props.get(field, {}):
                    out.append(f"action {c.id}: path field {field} needs a pattern in input_schema")
        if c.chain_id not in chains:
            out.append(f"action {c.id}: unknown chain {c.chain_id}")
        for ref in filter(None, [c.verify_check, c.rollback]):
            module = ref.split(":", 1)[0]
            if ":" not in ref or module not in config.check_modules:
                out.append(f"action {c.id}: {ref} is outside check_modules")
        if c.executor.system not in config.systems:
            out.append(f"action {c.id}: unknown system {c.executor.system}")
    return out
