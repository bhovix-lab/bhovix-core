"""Slice 2 P1b: backend table, config v2, environment table, platform secrets, Deps."""

from pathlib import Path

import pytest
import yaml

from hadavin_sdk.actions.secrets import FakeSecretProvider
from hadavin_sdk.app import build
from hadavin_sdk.backends import Deps, make
from hadavin_sdk.backends.table import ALLOWED, TABLE, Entry, KindSettings
from hadavin_sdk.config import MOVED, ConfigError, load_config
from tests.conftest import qualify

TOKEN = "tok" + "-p1b"  # built from parts: not a real-looking credential


def _edit(cfg_dir, fn):
    path = cfg_dir / "config.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")


def _build(cfg_dir, **kw):
    from hadavin_sdk.registry import load_registry

    qualify(load_registry(load_config(cfg_dir)))
    return build(cfg_dir, ["test-agent"], **kw)


# --- config v2: every moved slice 1 key is refused with its new place ----------------------------


@pytest.mark.parametrize("key", sorted(MOVED))
def test_moved_key_refused_with_new_place(cfg_dir, key):
    _edit(cfg_dir, lambda d: d.update({key: "x"}))
    with pytest.raises(ConfigError, match=f"{key} moved to backends"):
        load_config(cfg_dir)


def test_bare_string_for_kind_with_required_settings_refused(cfg_dir):
    _edit(cfg_dir, lambda d: d["backends"].update(llm="fake"))
    with pytest.raises(ConfigError, match=r"backends.llm: \{kind: fake, recorded_dir\}"):
        load_config(cfg_dir)


def test_environment_is_required(cfg_dir):
    _edit(cfg_dir, lambda d: d.pop("environment"))
    with pytest.raises(ConfigError, match="environment"):
        load_config(cfg_dir)


def test_unknown_setting_and_capability_refused(cfg_dir):
    _edit(cfg_dir, lambda d: d["backends"].update(audit={"kind": "local_dir", "dir": "a", "x": 1}))
    with pytest.raises(ConfigError, match="audit"):
        load_config(cfg_dir)
    _edit(
        cfg_dir, lambda d: d["backends"].update(audit={"kind": "local_dir", "dir": "a"}, cache="x")
    )
    with pytest.raises(ConfigError, match="unknown capability"):
        load_config(cfg_dir)


def test_defaults_fill_optional_capabilities(cfg_dir):
    _edit(
        cfg_dir,
        lambda d: [d["backends"].pop(k) for k in ("secrets", "store", "detector", "channel")],
    )
    b = load_config(cfg_dir).backends
    assert (b.secrets.kind, b.store.kind, b.detector[0].kind, b.channel.kind) == (
        "fake",
        "memory",
        "regex",
        "fake",
    )


def test_an_empty_detector_list_refused(cfg_dir):
    # P6 replaced "a list longer than one is refused" with list semantics (tests/test_p6_detectors.py).
    _edit(cfg_dir, lambda d: d["backends"].update(detector=[]))
    with pytest.raises(ConfigError, match="at least one detector"):
        load_config(cfg_dir)


# --- environment table (design 4.6) --------------------------------------------------------------


@pytest.mark.parametrize("env", ["pilot", "prod"])
def test_dev_only_kinds_refused_outside_dev(cfg_dir, env):
    _edit(cfg_dir, lambda d: d.update(environment=env))
    with pytest.raises(ConfigError, match=f"environment {env}: refused outside dev") as err:
        load_config(cfg_dir)
    for item in (
        "llm: fake",
        "store: memory",
        "audit: local_dir",
        "secrets: fake",
        "channel: fake",
    ):
        assert item in str(err.value)
    assert "allow_insecure_loopback" in str(err.value)


def test_unknown_environment_refused(cfg_dir):
    _edit(cfg_dir, lambda d: d.update(environment="staging"))
    with pytest.raises(ConfigError, match="environment"):
        load_config(cfg_dir)


# --- platform secrets (design 4.4) ---------------------------------------------------------------


class _Planted(KindSettings):
    api_key_secret_name: str
    reads: str


def planted_channel(settings, deps):
    """A factory that tries to read whatever name its settings say (planted by the tests below)."""
    from hadavin_sdk.approvals import FakeChannel

    deps.resolve(settings.reads)
    return FakeChannel()


@pytest.fixture
def planted(monkeypatch, cfg_dir):
    monkeypatch.setitem(
        TABLE["channel"], "planted", Entry(_Planted, "tests.test_p1b_backends:planted_channel")
    )

    def use(secret_name, reads):
        _edit(
            cfg_dir,
            lambda d: d["backends"].update(
                channel={"kind": "planted", "api_key_secret_name": secret_name, "reads": reads}
            ),
        )

    return use


def test_factory_reads_its_own_secret(planted, cfg_dir):
    planted("chan-key", reads="chan-key")
    secrets = FakeSecretProvider({"fixture-token": TOKEN, "chan-key": TOKEN})
    _build(cfg_dir, secrets=secrets)


def test_factory_reading_another_secret_refused(planted, cfg_dir):
    planted("chan-key", reads="fixture-token")  # the executor's secret
    secrets = FakeSecretProvider({"fixture-token": TOKEN, "chan-key": TOKEN})
    with pytest.raises(ConfigError, match="may read only the secrets named in its own settings"):
        _build(cfg_dir, secrets=secrets)


def test_platform_and_executor_names_must_not_overlap(planted, cfg_dir):
    planted("fixture-token", reads="fixture-token")
    with pytest.raises(ConfigError, match="both a backend and an action executor"):
        _build(cfg_dir, secrets=FakeSecretProvider({"fixture-token": TOKEN}))


def test_missing_secret_fails_at_start_up(cfg_dir):
    with pytest.raises(ConfigError, match="'fixture-token' cannot be read at start-up"):
        _build(cfg_dir)  # configured `fake` secrets are empty: the executor's secret is missing


def test_missing_platform_secret_fails_at_start_up(planted, cfg_dir):
    planted("chan-key", reads="chan-key")
    with pytest.raises(ConfigError, match="'chan-key' cannot be read"):
        _build(cfg_dir, secrets=FakeSecretProvider({"fixture-token": TOKEN}))


def test_fake_channel_signing_secret_comes_from_platform_secrets(cfg_dir):
    _edit(
        cfg_dir,
        lambda d: d["backends"].update(channel={"kind": "fake", "signing_secret_name": "sig"}),
    )
    app = _build(cfg_dir, secrets=FakeSecretProvider({"fixture-token": TOKEN, "sig": TOKEN}))
    assert app.approvals.channel._secret == TOKEN


# --- Deps and extras -----------------------------------------------------------------------------


def test_factory_sees_only_what_its_capability_may_use(monkeypatch):
    seen = {}

    def factory(settings, deps):
        seen["deps"] = deps

    monkeypatch.setattr("importlib.import_module", lambda name: type("M", (), {"y": factory}))
    everything = {"store": object(), "llm": object(), "routes": {}}
    for cap in TABLE:
        monkeypatch.setitem(TABLE[cap], "spy", Entry(KindSettings, "x:y"))
        make(cap, KindSettings(kind="spy"), None, **everything)
        deps: Deps = seen["deps"]
        for name in ("store", "llm", "routes"):
            assert (getattr(deps, name) is not None) == (name in ALLOWED[cap]), (cap, name)


def test_missing_extra_names_the_install_command(monkeypatch):
    monkeypatch.setitem(
        TABLE["store"], "nope", Entry(KindSettings, "hadavin_sdk_not_here:make", "pg")
    )
    with pytest.raises(ConfigError, match=r"pip install hadavin-sdk\[pg\]"):
        make("store", KindSettings(kind="nope"))


# --- review fixes on #9 ----------------------------------------------------------------------------


def test_config_error_never_echoes_a_mistyped_value(cfg_dir):
    value = "s3cr" + "et-value-p1b"
    _edit(
        cfg_dir,
        lambda d: d["backends"].update(audit={"kind": "local_dir", "dir": "a", "pasword": value}),
    )
    with pytest.raises(ConfigError) as err:
        load_config(cfg_dir)
    assert "pasword" in str(err.value) and value not in str(err.value)
    _edit(
        cfg_dir,
        lambda d: (
            d["backends"].update(audit={"kind": "local_dir", "dir": "a"}) or d.update(tokn=value)
        ),
    )
    with pytest.raises(ConfigError) as err:
        load_config(cfg_dir)
    assert "tokn" in str(err.value) and value not in str(err.value)


def test_broken_hadavin_module_keeps_its_own_import_error(monkeypatch):
    monkeypatch.setitem(
        TABLE["store"], "broken", Entry(KindSettings, "hadavin_sdk.not_a_module:make", "pg")
    )
    with pytest.raises(ModuleNotFoundError, match="hadavin_sdk.not_a_module"):
        make("store", KindSettings(kind="broken"))


def test_import_error_inside_an_installed_module_is_not_an_extra_hint(monkeypatch):
    def boom(name):
        raise ImportError("cannot import name 'x' from 'somepkg'", name="somepkg")

    monkeypatch.setitem(TABLE["store"], "half", Entry(KindSettings, "somepkg:make", "pg"))
    monkeypatch.setattr("importlib.import_module", boom)
    with pytest.raises(ImportError, match="cannot import name"):
        make("store", KindSettings(kind="half"))


class _OptPath(KindSettings):
    dir: Path | None = None


def test_optional_path_settings_are_relative_to_the_config_folder(cfg_dir, monkeypatch):
    from hadavin_sdk.config import _one

    monkeypatch.setitem(TABLE["audit"], "opt", Entry(_OptPath, "m:f"))
    assert _one("audit", {"kind": "opt", "dir": "x"}, cfg_dir).dir == cfg_dir / "x"
    assert _one("audit", {"kind": "opt"}, cfg_dir).dir is None
