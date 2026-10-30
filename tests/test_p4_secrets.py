"""Slice 2 P4: `env` and `aws_secrets_manager` secrets through the backend table (design 4.3, 4.4, 4.6).
The AWS kind runs on moto (in-process, $0); no real AWS call is made."""

import boto3
import pytest
import yaml
from moto import mock_aws

from hadavin_sdk.actions.secrets_aws import SecretsManagerProvider
from hadavin_sdk.actions.secrets_env import EnvSecretProvider
from hadavin_sdk.backends import make
from hadavin_sdk.backends.platform_secrets import bound
from hadavin_sdk.backends.table import (
    AwsSecretsManagerSettings,
    EnvSecretsSettings,
    FakeChannelSettings,
)
from hadavin_sdk.config import load_config
from hadavin_sdk.errors import ConfigError
from tests.conftest import make_cfg
from tests.contracts.aws_stub import REGION, stub_client

VALUE = "s" + "-p4-value"  # built from parts


@pytest.fixture
def sm():
    with mock_aws():
        client = boto3.client("secretsmanager", region_name=REGION)
        client.create_secret(Name="slack-signing", SecretString=VALUE)
        client.create_secret(Name="blob", SecretBinary=b"\x00\x01")
        yield client


def test_the_table_builds_secrets_manager_and_reads_through_it(sm):
    provider = make("secrets", AwsSecretsManagerSettings(kind="aws_secrets_manager", region=REGION))
    assert isinstance(provider, SecretsManagerProvider) and provider.ttl_s == 300
    assert provider.get("slack-signing") == VALUE
    with pytest.raises(ConfigError, match="not found"):
        provider.get("nope")
    with pytest.raises(ConfigError, match="binary"):
        provider.get("blob")


def test_a_backend_resolves_only_its_own_secret_names_from_secrets_manager(sm):
    """The per-factory platform resolver (P1b) over the new provider: the channel reads its signing secret."""
    provider = make("secrets", AwsSecretsManagerSettings(kind="aws_secrets_manager", region=REGION))
    settings = FakeChannelSettings(kind="fake", signing_secret_name="slack-signing")  # noqa: S106 - a name
    assert make("channel", settings, provider) is not None
    resolve = bound(provider, settings, "backend channel 'fake'")
    assert resolve("slack-signing") == VALUE
    with pytest.raises(ConfigError, match="may read only"):
        resolve("blob")


def test_ttl_zero_reads_every_time():
    calls = []

    def answer(op, params):
        calls.append(params["SecretId"])
        return {"Name": params["SecretId"], "SecretString": VALUE}

    provider = SecretsManagerProvider(stub_client("secretsmanager", answer), ttl_s=0)
    provider.get("a")
    provider.get("a")
    assert calls == ["a", "a"]


def test_env_secrets_map_names_to_prefixed_variables(monkeypatch):
    monkeypatch.setenv("HADAVIN_SECRET_FIXTURE_TOKEN", VALUE)
    provider = make("secrets", EnvSecretsSettings(kind="env"))
    assert isinstance(provider, EnvSecretProvider)
    assert provider.get("fixture-token") == VALUE
    with pytest.raises(ConfigError, match="HADAVIN_SECRET_MISSING_ONE"):
        provider.get("missing.one")


def _config(tmp_path, secrets, environment="dev"):
    cfg_dir = make_cfg(tmp_path)
    path = cfg_dir / "config.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["environment"], raw["backends"]["secrets"] = environment, secrets
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return cfg_dir


def test_env_secrets_are_dev_only(tmp_path):
    assert load_config(_config(tmp_path, {"kind": "env"})).backends.secrets.kind == "env"
    with pytest.raises(ConfigError, match="secrets: env"):
        load_config(_config(tmp_path, {"kind": "env"}, "pilot"))


@pytest.mark.parametrize(
    "secrets",
    [
        {"kind": "env", "prefx": "X_"},  # a typo
        {"kind": "aws_secrets_manager"},  # region is required
        {"kind": "aws_secrets_manager", "region": REGION, "ttl_s": -1},
    ],
)
def test_bad_secrets_settings_fail_at_start_up(tmp_path, secrets):
    with pytest.raises(ConfigError, match="backends.secrets"):
        load_config(_config(tmp_path, secrets))
