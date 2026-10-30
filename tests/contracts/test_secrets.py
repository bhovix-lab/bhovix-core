"""Secrets suite, the checks P4 adds (design 6, 12.6): the start-up probe, no value in logs, and the TTL rule.
`fake` has no cache, so it has no `secrets_ttl` entry (design 12.6: skipped as "no cache")."""

import logging

import pytest

from hadavin_sdk.backends import platform_secrets
from hadavin_sdk.errors import ConfigError
from tests.contracts.kinds import KINDS

VALUE = "v" + "-contract-value"  # built from parts


def test_a_missing_name_is_a_config_error_at_the_start_up_probe(secrets_factory, caplog):
    provider = secrets_factory({"known": VALUE})
    with caplog.at_level(logging.DEBUG):
        platform_secrets.check(provider, [], {"known"})
        with pytest.raises(ConfigError, match="'missing' cannot be read at start-up"):
            platform_secrets.check(provider, [], {"known", "missing"})
        assert provider.get("known") == VALUE
    assert VALUE not in caplog.text  # a value is never logged


@pytest.fixture(params=sorted(KINDS["secrets_ttl"]))
def ttl_kind(request, tmp_path):
    return KINDS["secrets_ttl"][request.param](tmp_path, {"rotating": "old" + "-value"})


def test_a_changed_value_is_seen_after_ttl_s(ttl_kind):
    provider, change, advance, ttl_s = ttl_kind
    assert provider.get("rotating") == "old-value"
    change("rotating", "new" + "-value")
    if ttl_s:
        advance(ttl_s - 1)
        assert provider.get("rotating") == "old-value"  # still cached
        advance(1)
    assert provider.get("rotating") == "new-value"
