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
- `postgres` store (`pip install hadavin-sdk[pg]`, slice 2 P2): `backends.store: {kind: postgres,
  dsn_secret_name, iam_auth, region}`; compare-and-set in SQL; RDS IAM login with `iam_auth: true`.
- `hadavin-sdk migrate [--runtime-role R]`: forward-only schema (`store/migrations/0001_core.sql`) applied under
  an advisory lock with the migration role's DSN from `HADAVIN_MIGRATE_DSN`. Rollback = restore the snapshot
  taken before migrating.
- `hadavin-sdk limits stop|reset` now works on a shared (postgres) store.

### Changed
- `ProviderExhausted` from the model ends the run in `NEEDS_PERSON provider_exhausted` instead of escaping.
- Store: `get_approval_decision`, `list_approvals`, `list_runs`, `touch`, `spend_totals`; `add_cost` raises
  `NotFound`; `Limits.blocked` no longer writes a zero-spend row.
- The executor calls a heartbeat before every HTTP attempt, so long retries do not look stuck.
- `Verdict.score` is bounded to 0..1; a detector failure is logged with its cause (still fails closed).
