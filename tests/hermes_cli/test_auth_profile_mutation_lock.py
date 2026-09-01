"""Profile-lifecycle locking contracts for the active auth store."""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path


def test_file_lock_reentrancy_is_scoped_to_canonical_path(tmp_path, monkeypatch):
    from hermes_cli import auth

    holder = auth.threading.local()
    opened: list[Path] = []

    class FakeLockFile:
        def __init__(self, path: Path):
            self.path = path

        def __enter__(self):
            opened.append(self.path)
            return self

        def __exit__(self, *_args):
            return False

        def fileno(self):
            return 123

    def fake_open(path, *_args, **_kwargs):
        return FakeLockFile(Path(path).resolve())

    monkeypatch.setattr(Path, "open", fake_open)
    monkeypatch.setattr(auth, "fcntl", type("F", (), {
        "LOCK_EX": 1,
        "LOCK_NB": 2,
        "LOCK_UN": 4,
        "flock": staticmethod(lambda *_args: None),
    }))
    monkeypatch.setattr(auth, "msvcrt", None)

    first = tmp_path / "a.lock"
    second = tmp_path / "b.lock"
    with auth._file_lock(first, holder, 1.0, "timeout"):
        with auth._file_lock(first, holder, 1.0, "timeout"):
            with auth._file_lock(second, holder, 1.0, "timeout"):
                pass

    assert opened == [first.resolve(), second.resolve()]


def test_nested_auth_store_lock_reuses_frozen_identity(tmp_path, monkeypatch):
    from hermes_cli import auth

    active_path = tmp_path / "profiles" / "work" / "auth.json"
    global_path = tmp_path / "auth.json"
    calls = {"active": 0, "global": 0, "profiles": 0, "files": 0}

    def active_resolver():
        calls["active"] += 1
        return active_path

    def global_resolver():
        calls["global"] += 1
        return global_path

    @contextmanager
    def fake_profile_locks(_homes, **_kwargs):
        calls["profiles"] += 1
        yield

    @contextmanager
    def fake_file_lock(*_args, **_kwargs):
        calls["files"] += 1
        yield

    monkeypatch.setattr(auth, "_auth_file_path", active_resolver)
    monkeypatch.setattr(auth, "_global_auth_file_path_for_write", global_resolver)
    monkeypatch.setattr(auth, "profile_mutation_locks", fake_profile_locks)
    monkeypatch.setattr(auth, "_file_lock", fake_file_lock)

    with auth._auth_store_lock(include_global_root=True) as outer:
        with auth._auth_store_lock() as inner:
            assert inner is outer
            assert inner.active_path.resolve() == active_path.resolve()
            assert inner.global_path.resolve() == global_path.resolve()

    assert calls == {"active": 1, "global": 1, "profiles": 1, "files": 2}


def test_auth_store_lock_rejects_dynamic_global_expansion(tmp_path, monkeypatch):
    import pytest
    from hermes_cli import auth

    monkeypatch.setattr(auth, "_auth_file_path", lambda: tmp_path / "auth.json")
    monkeypatch.setattr(
        auth,
        "_global_auth_file_path_for_write",
        lambda: tmp_path / "root" / "auth.json",
    )

    with auth._auth_store_lock():
        with pytest.raises(RuntimeError, match="expand.*auth store lock set"):
            with auth._auth_store_lock(include_global_root=True):
                pass


def test_auth_store_lock_predeclares_and_reuses_shared_credential_path(
    tmp_path, monkeypatch
):
    import pytest
    from hermes_cli import auth

    active_path = tmp_path / "profiles" / "work" / "auth.json"
    shared_path = tmp_path / "shared" / "credentials.json"
    other_path = tmp_path / "shared" / "other.json"
    monkeypatch.setattr(auth, "_auth_file_path", lambda: active_path)

    with auth._auth_store_lock(extra_paths=(shared_path,)) as outer:
        assert outer.extra_paths == (shared_path.resolve(),)
        with auth._auth_store_lock(extra_paths=(shared_path,)) as inner:
            assert inner is outer
        with pytest.raises(RuntimeError, match="expand.*shared credential paths"):
            with auth._auth_store_lock(extra_paths=(other_path,)):
                pass


def test_default_auth_io_and_fallback_reuse_outer_frozen_paths(tmp_path, monkeypatch):
    import json
    from hermes_cli import auth

    active_path = tmp_path / "profiles" / "work" / "auth.json"
    global_path = tmp_path / "auth.json"
    active_path.parent.mkdir(parents=True)
    active_path.write_text('{"version": 1, "providers": {}}', encoding="utf-8")
    global_path.write_text(
        json.dumps(
            {
                "version": 1,
                "providers": {"nous": {"access_token": "root-token"}},
            }
        ),
        encoding="utf-8",
    )
    calls = {"active": 0, "global": 0}

    def active_resolver():
        calls["active"] += 1
        return active_path

    def global_resolver():
        calls["global"] += 1
        return global_path

    monkeypatch.setattr(auth, "_auth_file_path", active_resolver)
    monkeypatch.setattr(auth, "_global_auth_file_path_for_write", global_resolver)

    with auth._auth_store_lock(include_global_root=True) as context:
        store = auth._load_auth_store()
        state, source = auth._load_provider_state_with_source(store, "nous")
        assert state == {"access_token": "root-token"}
        assert source == context.global_path
        store["marker"] = "saved"
        assert auth._save_auth_store(store) == context.active_path

    assert calls == {"active": 1, "global": 1}
    assert json.loads(active_path.read_text(encoding="utf-8"))["marker"] == "saved"


def test_nous_resolvers_predeclare_global_source_store(monkeypatch):
    import pytest
    from hermes_cli import auth

    calls: list[bool] = []

    @contextmanager
    def tracking_lock(*_args, **kwargs):
        calls.append(bool(kwargs.get("include_global_root")))
        yield object()

    monkeypatch.setattr(auth, "_auth_store_lock", tracking_lock)
    monkeypatch.setattr(auth, "_load_auth_store", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        auth,
        "_load_provider_state_with_source",
        lambda *_args, **_kwargs: (None, None),
    )

    resolvers = (
        auth.resolve_nous_access_token,
        auth.resolve_nous_runtime_credentials,
    )
    for resolver in resolvers:
        calls.clear()
        with pytest.raises(auth.AuthError, match="not logged into Nous Portal"):
            resolver()
        assert calls == [True]


def test_provider_switch_auth_and_config_publications_share_one_context(
    tmp_path, monkeypatch
):
    import json
    from hermes_cli import auth

    home = tmp_path / "profile"
    home.mkdir()
    (home / "config.yaml").write_text(
        "model:\n  provider: auto\n  default: old-model\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))

    contexts: list[object] = []
    real_save_auth = auth._save_auth_store
    real_write_yaml = auth.atomic_yaml_write

    def recording_save(store, *args, **kwargs):
        contexts.append(auth._current_auth_store_context())
        return real_save_auth(store, *args, **kwargs)

    def recording_write(path, data, **kwargs):
        contexts.append(auth._current_auth_store_context())
        return real_write_yaml(path, data, **kwargs)

    monkeypatch.setattr(auth, "_save_auth_store", recording_save)
    monkeypatch.setattr(auth, "atomic_yaml_write", recording_write)

    config_path = auth._update_config_for_provider(
        "openai-codex",
        "https://example.invalid/v1",
        default_model="gpt-test",
    )

    assert config_path == home / "config.yaml"
    assert len(contexts) == 2
    assert contexts[0] is not None
    assert contexts[1] is contexts[0]
    assert json.loads((home / "auth.json").read_text(encoding="utf-8"))[
        "active_provider"
    ] == "openai-codex"


def test_logout_auth_and_config_publications_share_one_context(
    tmp_path, monkeypatch
):
    import json
    from types import SimpleNamespace
    from hermes_cli import auth

    home = tmp_path / "profile"
    home.mkdir()
    (home / "auth.json").write_text(
        json.dumps(
            {
                "version": 1,
                "active_provider": "openai-codex",
                "providers": {"openai-codex": {"access_token": "token"}},
            }
        ),
        encoding="utf-8",
    )
    (home / "config.yaml").write_text(
        "model:\n  provider: openai-codex\n  base_url: https://example.invalid/v1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))

    contexts: list[object] = []
    real_save_auth = auth._save_auth_store
    real_write_yaml = auth.atomic_yaml_write

    def recording_save(store, *args, **kwargs):
        contexts.append(auth._current_auth_store_context())
        return real_save_auth(store, *args, **kwargs)

    def recording_write(path, data, **kwargs):
        contexts.append(auth._current_auth_store_context())
        return real_write_yaml(path, data, **kwargs)

    monkeypatch.setattr(auth, "_save_auth_store", recording_save)
    monkeypatch.setattr(auth, "atomic_yaml_write", recording_write)

    auth.logout_command(SimpleNamespace(provider="openai-codex"))

    assert len(contexts) == 2
    assert contexts[0] is not None
    assert contexts[1] is contexts[0]


def test_auth_store_context_is_cleared_after_exception(tmp_path, monkeypatch):
    import pytest
    from hermes_cli import auth

    first = tmp_path / "first" / "auth.json"
    second = tmp_path / "second" / "auth.json"
    current = {"path": first}
    monkeypatch.setattr(auth, "_auth_file_path", lambda: current["path"])

    with pytest.raises(ValueError, match="boom"):
        with auth._auth_store_lock() as context:
            assert context.active_path == first
            raise ValueError("boom")

    current["path"] = second
    with auth._auth_store_lock() as context:
        assert context.active_path == second


def test_auth_store_lock_can_predeclare_active_and_global_stores(tmp_path, monkeypatch):
    from hermes_cli import auth

    active_path = tmp_path / "profiles" / "work" / "auth.json"
    global_path = tmp_path / "auth.json"
    state = {"profiles": 0, "auth_locks": 0}
    events: list[tuple[str, object]] = []

    @contextmanager
    def fake_profile_locks(homes, **_kwargs):
        resolved = tuple(sorted(Path(home).resolve() for home in homes))
        assert resolved == tuple(
            sorted((active_path.parent.resolve(), global_path.parent.resolve()))
        )
        assert state == {"profiles": 0, "auth_locks": 0}
        state["profiles"] = 1
        events.append(("profiles-enter", resolved))
        try:
            yield resolved
        finally:
            assert state == {"profiles": 1, "auth_locks": 0}
            events.append(("profiles-exit", resolved))
            state["profiles"] = 0

    @contextmanager
    def fake_file_lock(lock_path, _holder, _timeout, _message):
        assert state["profiles"] == 1
        state["auth_locks"] += 1
        events.append(("auth-enter", Path(lock_path).resolve()))
        try:
            yield
        finally:
            events.append(("auth-exit", Path(lock_path).resolve()))
            state["auth_locks"] -= 1

    monkeypatch.setattr(auth, "_auth_file_path", lambda: active_path)
    monkeypatch.setattr(auth, "_global_auth_file_path_for_write", lambda: global_path, raising=False)
    monkeypatch.setattr(auth, "profile_mutation_locks", fake_profile_locks, raising=False)
    monkeypatch.setattr(auth, "_file_lock", fake_file_lock)

    with auth._auth_store_lock(include_global_root=True):
        assert state == {"profiles": 1, "auth_locks": 2}

    entered = [value for event, value in events if event == "auth-enter"]
    assert entered == sorted(
        (active_path.with_suffix(".lock").resolve(), global_path.with_suffix(".lock").resolve())
    )
    assert state == {"profiles": 0, "auth_locks": 0}


def test_auth_store_lock_orders_profile_before_auth_file_lock(tmp_path, monkeypatch):
    from hermes_cli import auth

    events: list[str] = []
    state = {"profile": 0, "auth": 0}

    @contextmanager
    def fake_profile_lock(home, **_kwargs):
        assert Path(home).resolve() == tmp_path.resolve()
        assert state == {"profile": 0, "auth": 0}
        state["profile"] = 1
        events.append("profile-enter")
        try:
            yield Path(home).resolve()
        finally:
            assert state == {"profile": 1, "auth": 0}
            events.append("profile-exit")
            state["profile"] = 0

    @contextmanager
    def fake_file_lock(lock_path, _holder, _timeout, _message):
        assert Path(lock_path) == tmp_path / "auth.lock"
        assert state == {"profile": 1, "auth": 0}
        state["auth"] = 1
        events.append("auth-enter")
        try:
            yield
        finally:
            assert state == {"profile": 1, "auth": 1}
            events.append("auth-exit")
            state["auth"] = 0

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(auth, "profile_mutation_lock", fake_profile_lock, raising=False)
    monkeypatch.setattr(auth, "_file_lock", fake_file_lock)

    with auth._auth_store_lock():
        assert state == {"profile": 1, "auth": 1}

    assert events == ["profile-enter", "auth-enter", "auth-exit", "profile-exit"]
    assert state == {"profile": 0, "auth": 0}


def test_auth_store_lock_explicit_target_never_re_resolves_active_profile(
    tmp_path, monkeypatch
):
    from hermes_cli import auth

    frozen = tmp_path / "profiles" / "work" / "auth.json"
    frozen.parent.mkdir(parents=True)
    resolver_calls = 0

    def forbidden_resolver():
        nonlocal resolver_calls
        resolver_calls += 1
        raise AssertionError("ambient Profile identity must not be re-resolved")

    monkeypatch.setattr(auth, "_auth_file_path", forbidden_resolver)

    with auth._auth_store_lock(target_path=frozen) as context:
        assert context.active_path == frozen
        store = auth._load_auth_store()
        store["marker"] = "frozen"
        auth._save_auth_store(store)

    assert resolver_calls == 0
    assert json.loads(frozen.read_text(encoding="utf-8"))["marker"] == "frozen"


def test_compare_restore_active_provider_updates_only_expected_frozen_value(
    tmp_path, monkeypatch
):
    from hermes_cli import auth

    frozen = tmp_path / "profiles" / "work" / "auth.json"
    frozen.parent.mkdir(parents=True)
    frozen.write_text(
        json.dumps({"version": 1, "active_provider": "nous", "providers": {}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        auth,
        "_auth_file_path",
        lambda: (_ for _ in ()).throw(
            AssertionError("CAS must use the frozen auth path")
        ),
    )

    assert auth._compare_restore_auth_active_provider(
        frozen,
        expected="nous",
        prior="openrouter",
    ) is True
    restored = json.loads(frozen.read_text(encoding="utf-8"))
    assert restored["active_provider"] == "openrouter"

    restored["active_provider"] = "anthropic"
    frozen.write_text(json.dumps(restored), encoding="utf-8")
    assert auth._compare_restore_auth_active_provider(
        frozen,
        expected="nous",
        prior="openrouter",
    ) is False
    concurrent = json.loads(frozen.read_text(encoding="utf-8"))
    assert concurrent["active_provider"] == "anthropic"


def test_compare_restore_active_provider_preserves_missing_prior_state(tmp_path):
    from hermes_cli import auth

    frozen = tmp_path / "auth.json"
    frozen.write_text(
        json.dumps({"version": 1, "active_provider": "nous", "providers": {}}),
        encoding="utf-8",
    )

    assert auth._compare_restore_auth_active_provider(
        frozen,
        expected="nous",
        prior=auth._AUTH_ACTIVE_PROVIDER_MISSING,
    ) is True
    restored = json.loads(frozen.read_text(encoding="utf-8"))
    assert "active_provider" not in restored


def test_compare_restore_rejects_same_name_profile_recreation(tmp_path):
    from hermes_cli import auth

    profile = tmp_path / "profiles" / "work"
    profile.mkdir(parents=True)
    generation = profile / ".webui-profile-generation"
    generation.write_text(
        "11111111-1111-4111-8111-111111111111\n",
        encoding="ascii",
    )
    auth_path = profile / "auth.json"
    auth_path.write_text(
        json.dumps({"version": 1, "active_provider": "nous", "providers": {}}),
        encoding="utf-8",
    )

    with auth._auth_store_lock(target_path=auth_path) as context:
        incarnation = auth._capture_auth_store_incarnation(context)

    retired = profile.with_name("work-retired")
    profile.rename(retired)
    profile.mkdir()
    (profile / ".webui-profile-generation").write_text(
        "22222222-2222-4222-8222-222222222222\n",
        encoding="ascii",
    )
    auth_path.write_text(
        json.dumps({"version": 1, "active_provider": "nous", "providers": {}}),
        encoding="utf-8",
    )

    assert auth._compare_restore_auth_active_provider(
        auth_path,
        expected="nous",
        prior="openrouter",
        incarnation=incarnation,
    ) is False
    replacement = json.loads(auth_path.read_text(encoding="utf-8"))
    assert replacement["active_provider"] == "nous"
