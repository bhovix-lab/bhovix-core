# Changelog

## Unreleased

### Upgrade steps
- **Rewrite config.yaml to config v2** (slice 2 P1b). `environment: dev|pilot|prod` is required. Each backend
  is `backends.<capability>: {kind: <name>, ...settings}`. The old top-level keys are refused with a message
  naming the new place: `audit_dir` -> `backends.audit.dir`, `recorded_dir` -> `backends.llm.recorded_dir`,
  `detector_threshold` -> `backends.detector: [{kind: regex, threshold}]`, `region` -> each AWS kind's
  `region`, `slack` -> `backends.channel`. Start-up now refuses dev-only kinds outside `dev`, a secret name used
  by both a backend and an action, and any secret that cannot be read.
- `app.build(config_dir, agents, *, secrets=None, ...)`: `secrets` is now a keyword; `make_llm`,
  `make_detector` and `make_channel` are gone (backends are built from the table in `hadavin_sdk.backends`).
- **Re-gate every agent once** (slice 2 P1a). `config_hash` now hashes with `exclude_defaults` and includes the
  llm backend kind, so every stored green gate run stops matching. Run `hadavin-sdk gate <agent>` for each agent
  before starting the runtime; until then start-up raises `Unqualified`. After this one re-gate, adding an optional
  field with a default no longer un-qualifies agents, and swapping the llm backend does.

### Added
- llm kinds (slice 2 P5, all `slice2-unverified` until the P9 live run): `anthropic` with `platform: api |
  vertex | foundry` (extra `anthropic`), `bedrock` through Converse (extra `aws`), `openai_compat` (OpenAI,
  Groq, OpenRouter, a local Ollama) and `gemini` over stdlib HTTP. Each has `call_timeout_s` (60) and
  `max_attempts` (3): transient failures retry with exponential backoff and jitter, then `ProviderExhausted`.
  `output_schema` is a forced tool call. Model ids that are moving aliases (`sonnet`, `*-latest`) are refused.
  The llm `platform` and `base_url` are part of `config_hash`.

- Detector lists (slice 2 P6): `backends.detector` takes one or more entries (an `llm_judge` never alone); every
  entry runs and any flag flags the run (max score, the flagging names joined by `+`, the first flag's reason).
  New kinds, both `slice2-unverified`: `llm_judge` (`route`, `threshold` 0.7; a fixed prompt hashed into
  `config_hash`, its cost charged to the agent, qualified at its own rate by a non-empty `golden_dir/judge.jsonl`
  in the evals gate; that file is part of `golden_sha256`) and `bedrock_guardrail`
  (`guardrail_id`, `guardrail_version`, `region`; the PROMPT_ATTACK filter, extra `aws`).

### Changed
- `ProviderExhausted` from the model ends the run in `NEEDS_PERSON provider_exhausted` instead of escaping.
- A provider that refuses the request (`ProviderError`, e.g. a bad key) ends the run in
  `NEEDS_PERSON provider_error`; `ProviderExhausted` is now a `ProviderError`.
- `Reply.stop_reason` is one of `end_turn`, `tool_use`, `max_tokens`, `refusal` for the network kinds. A reply
  cut off at the output cap or declined ends the run in `NEEDS_PERSON llm_max_tokens` / `llm_refusal` instead
  of `NO_ACTION`; a cut-off reply's tool calls are dropped (their input may be incomplete).
- Store: `get_approval_decision`, `list_approvals`, `list_runs`, `touch`, `spend_totals`; `add_cost` raises
  `NotFound`; `Limits.blocked` no longer writes a zero-spend row.
- The executor calls a heartbeat before every HTTP attempt, so long retries do not look stuck.
- `Verdict.score` is bounded to 0..1; a detector failure is logged with its cause (still fails closed).
