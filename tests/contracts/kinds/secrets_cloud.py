"""The `env` and `aws_secrets_manager` secrets kinds (slice 2 P4).

Each registers twice: under `secrets` (the shared Secrets suite) and under `secrets_ttl`, which returns
`(provider, change(name, value), advance(seconds), ttl_s)` for the TTL check with an injected clock.
`aws_secrets_manager` answers GetSecretValue in-process (`tests/contracts/aws_stub.py`); the real factory path
through boto3 runs on moto in `tests/test_p4_secrets.py`.
"""

from __future__ import annotations

from hadavin_sdk.actions.secrets_aws import SecretsManagerProvider
from hadavin_sdk.actions.secrets_env import EnvSecretProvider
from tests.contracts.aws_stub import not_found, stub_client
from tests.contracts.kinds import kind

PREFIX = "HADAVIN_SECRET_"
TTL_S = 300


def _env(seed):
    environ: dict[str, str] = {}
    provider = EnvSecretProvider(PREFIX, environ)
    environ.update({provider.var(k): v for k, v in seed.items()})
    return provider, environ


@kind("secrets", "env")
def env(tmp_path, seed):
    return _env(seed)[0]


@kind("secrets_ttl", "env")
def env_ttl(tmp_path, seed):
    provider, environ = _env(seed)
    return provider, lambda k, v: environ.__setitem__(provider.var(k), v), lambda s: None, 0


def _sm(seed):
    values, now = dict(seed), [0.0]

    def answer(op, params):
        name = params["SecretId"]
        if op != "GetSecretValue" or name not in values:
            raise not_found(op)
        return {"Name": name, "SecretString": values[name]}

    provider = SecretsManagerProvider(stub_client("secretsmanager", answer), TTL_S, lambda: now[0])
    return provider, values, now


@kind("secrets", "aws_secrets_manager")
def aws_secrets_manager(tmp_path, seed):
    return _sm(seed)[0]


@kind("secrets_ttl", "aws_secrets_manager")
def aws_secrets_manager_ttl(tmp_path, seed):
    provider, values, now = _sm(seed)

    def advance(seconds):
        now[0] += seconds

    return provider, values.__setitem__, advance, TTL_S
