"""Regression tests for credential-pool OAuth refresh write-through to root.

Companion to ``tests/hermes_cli/test_xai_oauth_writethrough.py``. That file
covers the *non-pool* xAI refresh path (``_save_xai_oauth_tokens``). These
cover the **credential-pool** refresh path
(``CredentialPool._sync_device_code_entry_to_auth_store``): when a profile
that has no own ``providers.<id>`` block refreshes — via the pool — a rotating
OAuth grant it resolved from the global-root fallback, the rotated chain must
be written back to the global root too. Otherwise root keeps a revoked refresh
token and every other profile reading root's stale grant dies with
``refresh_token_reused`` / ``invalid_grant`` once its access token expires
(issue #48415, the Codex/xAI analog of #43589).

The tests drive the real ``_sync_device_code_entry_to_auth_store`` against
real on-disk auth stores (profile + root under ``tmp_path``) rather than
mocking the save boundary, so they exercise the actual atomic write path.
"""

from contextlib import contextmanager
import json
import threading
import time

import pytest

from agent import credential_pool as CP
from agent.credential_pool import (
    AUTH_TYPE_OAUTH,
    CredentialPool,
    PooledCredential,
    load_pool,
)
from hermes_cli import auth as A


def _write_store(path, store):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store), encoding="utf-8")


def _read_store(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _entry(provider: str, *, id: str, access_token: str, refresh_token: str):
    return PooledCredential(
        provider=provider,
        id=id,
        label="cred",
        auth_type=AUTH_TYPE_OAUTH,
        priority=0,
        source="device_code",
        access_token=access_token,
        refresh_token=refresh_token,
    )


@pytest.fixture
def profile_and_root(tmp_path, monkeypatch):
    """Wire a profile auth store + a distinct global-root auth store on disk."""
    profile_path = tmp_path / "profiles" / "work" / "auth.json"
    root_path = tmp_path / "root" / "auth.json"

    monkeypatch.setattr(A, "_auth_file_path", lambda: profile_path)
    monkeypatch.setattr(A, "_global_auth_file_path", lambda: root_path)
    monkeypatch.setenv("HOME", str(tmp_path / "not-the-root"))
    return profile_path, root_path


@pytest.mark.parametrize("provider", ["openai-codex", "xai-oauth"])
def test_pool_sync_back_predeclares_both_auth_stores(
    profile_and_root, provider, monkeypatch
):
    profile_path, root_path = profile_and_root
    _write_store(profile_path, {"version": 1, "providers": {}})
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                provider: {
                    "tokens": {
                        "access_token": "old-access",
                        "refresh_token": "old-refresh",
                    }
                }
            },
        },
    )

    calls: list[bool] = []
    real_lock = A._auth_store_lock

    @contextmanager
    def tracking_lock(*args, **kwargs):
        calls.append(bool(kwargs.get("include_global_root")))
        with real_lock(*args, **kwargs) as context:
            yield context

    monkeypatch.setattr(A, "_auth_store_lock", tracking_lock)
    monkeypatch.setattr(CP, "_auth_store_lock", tracking_lock)

    pool = CredentialPool(provider, [])
    pool._sync_device_code_entry_to_auth_store(
        _entry(
            provider,
            id="e0",
            access_token="new-access",
            refresh_token="new-refresh",
        )
    )

    assert calls == [True]


@pytest.mark.parametrize("provider", ["openai-codex", "xai-oauth"])
def test_pool_refresh_writes_back_only_to_root_when_profile_reads_root(
    profile_and_root, provider
):
    """A root-fallback grant stays root-owned after rotation (#74339)."""
    profile_path, root_path = profile_and_root
    _write_store(profile_path, {"version": 1, "providers": {}})
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                provider: {
                    "tokens": {
                        "access_token": "old-access",
                        "refresh_token": "old-refresh",
                    }
                }
            },
        },
    )

    pool = CredentialPool(provider, [])
    pool._sync_device_code_entry_to_auth_store(
        _entry(
            provider,
            id="e1",
            access_token="new-access",
            refresh_token="new-refresh",
        )
    )

    root = _read_store(root_path)
    assert root["providers"][provider]["tokens"]["access_token"] == "new-access"
    assert root["providers"][provider]["tokens"]["refresh_token"] == "new-refresh"

    profile = _read_store(profile_path)
    assert provider not in profile.get("providers", {})


@pytest.mark.parametrize("provider", ["openai-codex", "xai-oauth"])
def test_pool_refresh_writes_only_profile_when_profile_shadows(
    profile_and_root, provider
):
    """A profile-owned grant must not clobber the independent root grant."""
    profile_path, root_path = profile_and_root
    _write_store(
        profile_path,
        {
            "version": 1,
            "providers": {
                provider: {
                    "tokens": {
                        "access_token": "profile-old",
                        "refresh_token": "profile-old-refresh",
                    }
                }
            },
        },
    )
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                provider: {
                    "tokens": {
                        "access_token": "root-untouched",
                        "refresh_token": "root-untouched-refresh",
                    }
                }
            },
        },
    )

    pool = CredentialPool(provider, [])
    pool._sync_device_code_entry_to_auth_store(
        _entry(
            provider,
            id="e2",
            access_token="profile-new",
            refresh_token="profile-new-refresh",
        )
    )

    profile = _read_store(profile_path)
    assert (
        profile["providers"][provider]["tokens"]["refresh_token"]
        == "profile-new-refresh"
    )
    root = _read_store(root_path)
    assert (
        root["providers"][provider]["tokens"]["refresh_token"]
        == "root-untouched-refresh"
    )


def test_global_write_through_uses_prelocked_root_path_without_nested_lock(
    profile_and_root, monkeypatch
):
    """The helper must merge under the caller's immutable root transaction."""
    _profile_path, root_path = profile_and_root
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                "openai-codex": {
                    "tokens": {
                        "access_token": "codex-a",
                        "refresh_token": "codex-r",
                    }
                }
            },
            "credential_pool": {
                "anthropic": [{"id": "anthropic-existing"}],
                "openrouter": [{"id": "openrouter-existing"}],
            },
        },
    )

    def forbidden_lock(*_args, **_kwargs):
        raise AssertionError("write-through helper must not acquire another auth lock")

    monkeypatch.setattr(A, "_auth_store_lock", forbidden_lock)
    monkeypatch.setattr(CP, "_auth_store_lock", forbidden_lock)

    CP._write_through_provider_state_to_global_root(
        "xai-oauth",
        {"tokens": {"access_token": "new-xai", "refresh_token": "new-r"}},
        root_path,
    )

    root = _read_store(root_path)
    assert root["providers"]["xai-oauth"]["tokens"]["refresh_token"] == "new-r"
    assert root["providers"]["openai-codex"]["tokens"]["refresh_token"] == "codex-r"
    assert root["credential_pool"]["anthropic"] == [{"id": "anthropic-existing"}]
    assert root["credential_pool"]["openrouter"] == [{"id": "openrouter-existing"}]


@pytest.mark.parametrize("provider", ["openai-codex", "xai-oauth"])
def test_single_use_pool_refresh_holds_one_auth_context_across_post_and_writeback(
    profile_and_root, provider, monkeypatch
):
    """Single-use refresh POST and persistence share one frozen lock context."""
    profile_path, root_path = profile_and_root
    _write_store(
        profile_path,
        {
            "version": 1,
            "providers": {
                provider: {
                    "tokens": {
                        "access_token": "stale-access",
                        "refresh_token": "stale-refresh",
                    }
                }
            },
        },
    )
    _write_store(root_path, {"version": 1, "providers": {}})

    real_lock = A._auth_store_lock
    depth = {"n": 0}
    include_global_calls: list[bool] = []
    lock_contexts: list[object] = []
    post_contexts: list[object] = []
    save_contexts: list[object] = []
    resolver_calls = {"active": 0, "global": 0}
    real_save = CP._save_auth_store

    def forbidden_active_resolver():
        resolver_calls["active"] += 1
        raise AssertionError("refresh transaction re-resolved active Profile identity")

    def forbidden_global_resolver():
        resolver_calls["global"] += 1
        raise AssertionError("refresh transaction re-resolved global Profile identity")

    @contextmanager
    def tracking_lock(*args, **kwargs):
        include_global_calls.append(bool(kwargs.get("include_global_root")))
        depth["n"] += 1
        try:
            with real_lock(*args, **kwargs) as context:
                lock_contexts.append(context)
                yield context
        finally:
            depth["n"] -= 1

    def recording_save(store, *args, **kwargs):
        save_contexts.append(A._current_auth_store_context())
        return real_save(store, *args, **kwargs)

    monkeypatch.setattr(A, "_auth_store_lock", tracking_lock)
    monkeypatch.setattr(CP, "_auth_store_lock", tracking_lock)
    monkeypatch.setattr(CP, "_save_auth_store", recording_save)

    def fake_refresh(access_token, refresh_token, **kwargs):
        assert depth["n"] > 0
        post_contexts.append(A._current_auth_store_context())
        monkeypatch.setattr(A, "_auth_file_path", forbidden_active_resolver)
        monkeypatch.setattr(A, "_global_auth_file_path", forbidden_global_resolver)
        return {
            "access_token": "rotated-access",
            "refresh_token": "rotated-refresh",
            "last_refresh": "2020-01-02T00:00:00Z",
        }

    if provider == "openai-codex":
        monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake_refresh)
    else:
        monkeypatch.setattr(A, "refresh_xai_oauth_pure", fake_refresh)

    entry = _entry(
        provider,
        id=f"{provider}-1",
        access_token="stale-access",
        refresh_token="stale-refresh",
    )
    pool = CredentialPool(provider, [entry])

    refreshed = pool._refresh_entry(entry, force=True)

    assert refreshed is not None
    assert refreshed.access_token == "rotated-access"
    assert refreshed.refresh_token == "rotated-refresh"
    assert include_global_calls == [True]
    assert len(lock_contexts) == 1
    assert post_contexts == [lock_contexts[0]]
    assert save_contexts
    assert all(context is lock_contexts[0] for context in save_contexts)
    assert resolver_calls == {"active": 0, "global": 0}


def test_write_through_fires_on_every_refresh_not_just_first(profile_and_root):
    """Root ownership remains visible across repeated refreshes (#74339)."""
    profile_path, root_path = profile_and_root
    provider = "openai-codex"
    _write_store(profile_path, {"version": 1, "providers": {}})
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                provider: {
                    "tokens": {
                        "access_token": "root-ac",
                        "refresh_token": "root-rf",
                    }
                }
            },
        },
    )

    for access_token, refresh_token in (("ac1", "rf1"), ("ac2", "rf2")):
        pool = CredentialPool(provider, [])
        pool._sync_device_code_entry_to_auth_store(
            _entry(
                provider,
                id=access_token,
                access_token=access_token,
                refresh_token=refresh_token,
            )
        )
        root_tokens = _read_store(root_path)["providers"][provider]["tokens"]
        assert root_tokens["access_token"] == access_token
        assert root_tokens["refresh_token"] == refresh_token
        assert provider not in _read_store(profile_path).get("providers", {})


def test_write_through_helper_is_noop_in_classic_mode():
    CP._write_through_provider_state_to_global_root(
        "openai-codex",
        {"tokens": {"access_token": "a", "refresh_token": "r"}},
        None,
    )


def test_global_write_through_preserves_concurrent_root_update(
    profile_and_root, monkeypatch
):
    """A stale profile write-through must not erase a concurrent root login."""
    _profile_path, root_path = profile_and_root
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                "xai-oauth": {
                    "tokens": {"access_token": "old-xai", "refresh_token": "old-r"}
                }
            },
            "credential_pool": {
                "anthropic": [{"id": "anthropic-existing"}],
                "openrouter": [{"id": "openrouter-existing"}],
            },
        },
    )

    helper_loaded = threading.Event()
    helper_has_target_lock = threading.Event()
    allow_helper_save = threading.Event()
    writer_started = threading.Event()
    writer_done = threading.Event()
    real_auth_load = A._load_auth_store

    def paused_helper_load(path=None):
        store = real_auth_load(path)
        if threading.current_thread().name == "profile-write-through":
            target_holder = A._auth_lock_holder_for(root_path)
            if getattr(target_holder, "depth", 0) > 0:
                helper_has_target_lock.set()
            helper_loaded.set()
            assert allow_helper_save.wait(timeout=5)
        return store

    monkeypatch.setattr(A, "_load_auth_store", paused_helper_load)
    # The pre-fix implementation imported the loader directly; patch both
    # bindings so reverting the safe helper still exercises the stale ordering.
    monkeypatch.setattr(CP, "_load_auth_store", paused_helper_load)

    def profile_write_through():
        CP._write_through_provider_state_to_global_root(
            "xai-oauth",
            {"tokens": {"access_token": "new-xai", "refresh_token": "new-r"}},
        )

    def concurrent_codex_login():
        writer_started.set()
        with A._auth_store_lock(target_path=root_path):
            store = A._load_auth_store(root_path)
            A._store_provider_state(
                store,
                "openai-codex",
                {"tokens": {"access_token": "codex-a", "refresh_token": "codex-r"}},
                set_active=False,
            )
            pool = store.setdefault("credential_pool", {})
            pool["openai-codex"] = [{"id": "codex-login"}]
            A._save_auth_store(store, target_path=root_path)
        writer_done.set()

    helper = threading.Thread(target=profile_write_through, name="profile-write-through")
    helper.start()
    assert helper_loaded.wait(timeout=5)

    writer = threading.Thread(target=concurrent_codex_login, name="concurrent-login")
    writer.start()
    assert writer_started.wait(timeout=5)
    # A fixed helper already owns the target lock, so the writer will merge
    # after release. A reverted unlocked helper must first let the competing
    # login finish; only then do we release its stale save. This makes the
    # losing pre-fix ordering deterministic rather than scheduler-dependent.
    if not helper_has_target_lock.is_set():
        assert writer_done.wait(timeout=5)
    allow_helper_save.set()
    helper.join(timeout=5)
    writer.join(timeout=5)
    assert not helper.is_alive()
    assert not writer.is_alive()

    root = _read_store(root_path)
    assert root["providers"]["xai-oauth"]["tokens"]["refresh_token"] == "new-r"
    assert root["providers"]["openai-codex"]["tokens"]["refresh_token"] == "codex-r"
    assert root["credential_pool"]["openai-codex"] == [{"id": "codex-login"}]
    assert root["credential_pool"]["anthropic"] == [{"id": "anthropic-existing"}]
    assert root["credential_pool"]["openrouter"] == [{"id": "openrouter-existing"}]


def test_codex_pool_refresh_holds_auth_store_lock_across_post(monkeypatch, tmp_path):
    """The Codex OAuth pool refresh must POST under the cross-process auth lock.

    Codex refresh tokens are single-use. If two Hermes processes both read the
    same on-disk token and both POST it, the loser gets ``refresh_token_reused``.
    Serializing the sync -> refresh POST -> write-back sequence through the
    shared ``_auth_store_lock`` closes that window: a second process blocks on
    the flock and, once inside, adopts the rotated token instead of re-POSTing.

    This asserts the invariant directly — that ``refresh_codex_oauth_pure`` is
    only ever called while the auth-store lock is held — rather than snapshotting
    any token value.
    """
    provider = "openai-codex"
    profile_path = tmp_path / "auth.json"
    monkeypatch.setattr(A, "_auth_file_path", lambda: profile_path)
    monkeypatch.setattr(A, "_global_auth_file_path", lambda: None)
    monkeypatch.setenv("HOME", str(tmp_path / "not-the-root"))

    lock_held: dict = {"during_post": None}
    real_lock = A._auth_store_lock

    depth = {"n": 0}

    import contextlib

    @contextlib.contextmanager
    def tracking_lock(*args, **kwargs):
        depth["n"] += 1
        try:
            with real_lock(*args, **kwargs):
                yield
        finally:
            depth["n"] -= 1

    monkeypatch.setattr(A, "_auth_store_lock", tracking_lock)
    # credential_pool imported _auth_store_lock by name; patch that binding too.
    monkeypatch.setattr(CP, "_auth_store_lock", tracking_lock)

    def fake_refresh(access_token, refresh_token, **kwargs):
        # The POST to the token endpoint must happen with the lock held.
        lock_held["during_post"] = depth["n"] > 0
        return {
            "access_token": "rotated-access",
            "refresh_token": "rotated-refresh",
            "last_refresh": "2020-01-02T00:00:00Z",
        }

    monkeypatch.setattr(A, "refresh_codex_oauth_pure", fake_refresh)

    entry = _entry(
        provider,
        id="codex-1",
        access_token="stale-access",
        refresh_token="stale-refresh",
    )
    pool = CredentialPool(provider, [entry])

    refreshed = pool._refresh_entry(entry, force=True)

    assert refreshed is not None
    assert refreshed.access_token == "rotated-access"
    assert refreshed.refresh_token == "rotated-refresh"
    # The invariant: the single-use token POST ran inside the auth-store lock.
    assert lock_held["during_post"] is True


def test_hermes_pkce_refresh_writes_back_to_singleton(tmp_path, monkeypatch):
    """A successful hermes_pkce refresh must update
    ~/.hermes/.anthropic_oauth.json, or ``_seed_from_singletons()`` on the
    next ``load_pool()`` re-seeds the pre-refresh (already-consumed,
    single-use) token pair over the freshly rotated one.
    """
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr("hermes_cli.auth.is_provider_explicitly_configured", lambda pid: True)

    oauth_file = hermes_home / ".anthropic_oauth.json"
    oauth_file.write_text(
        json.dumps({"accessToken": "sk-ant-oat-rt0", "refreshToken": "rt0", "expiresAt": 0}),
        encoding="utf-8",
    )
    _write_store(hermes_home / "auth.json", {"version": 1, "providers": {}})

    monkeypatch.setattr(
        "agent.anthropic_credentials.refresh_anthropic_oauth_pure",
        lambda refresh_token, use_json=False: {
            "access_token": "sk-ant-oat-rt1",
            "refresh_token": "rt1",
            "expires_at_ms": int(time.time() * 1000) + 3_600_000,
        },
    )
    monkeypatch.setattr("agent.anthropic_credentials.read_claude_code_credentials", lambda: None)

    entry = PooledCredential(
        provider="anthropic",
        id="pool-entry",
        label="cred",
        auth_type=AUTH_TYPE_OAUTH,
        priority=0,
        source="hermes_pkce",
        access_token="sk-ant-oat-rt0",
        refresh_token="rt0",
    )
    pool = CredentialPool("anthropic", [entry])
    updated = pool._refresh_entry(entry, force=True)
    assert updated is not None
    assert updated.refresh_token == "rt1"

    on_disk = json.loads(oauth_file.read_text(encoding="utf-8"))
    assert on_disk["refreshToken"] == "rt1", (
        "successful hermes_pkce refresh must write back to "
        "~/.hermes/.anthropic_oauth.json, or _seed_from_singletons() will "
        "revert the pool entry to the pre-refresh (spent) token on next load"
    )

    reloaded = load_pool("anthropic")
    reloaded_entries = [e for e in reloaded.entries() if e.source.endswith("hermes_pkce")]
    assert reloaded_entries, "hermes_pkce entry should still be present after reload"
    assert reloaded_entries[0].refresh_token == "rt1", (
        "regression: fresh load_pool() re-seeded the pre-refresh refresh "
        "token from the stale singleton file, reverting a successful "
        "rotation and orphaning the already-consumed rt0"
    )


def test_manual_hermes_pkce_refresh_does_not_create_duplicate_singleton(
    tmp_path, monkeypatch
):
    """A pool-owned manual:hermes_pkce entry must not create a second source."""
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr("hermes_cli.auth.is_provider_explicitly_configured", lambda pid: True)
    monkeypatch.setattr("agent.anthropic_credentials.read_claude_code_credentials", lambda: None)
    monkeypatch.setattr(
        "agent.anthropic_credentials.refresh_anthropic_oauth_pure",
        lambda refresh_token, use_json=False: {
            "access_token": "manual-at-1",
            "refresh_token": "manual-rt-1",
            "expires_at_ms": int(time.time() * 1000) + 3_600_000,
        },
    )
    _write_store(hermes_home / "auth.json", {"version": 1, "providers": {}})

    entry = PooledCredential(
        provider="anthropic",
        id="manual-entry",
        label="cred",
        auth_type=AUTH_TYPE_OAUTH,
        priority=0,
        source="manual:hermes_pkce",
        access_token="manual-at-0",
        refresh_token="manual-rt-0",
        expires_at_ms=0,
    )
    pool = CredentialPool("anthropic", [entry])
    refreshed = pool._refresh_entry(entry, force=True)

    assert refreshed is not None
    assert refreshed.refresh_token == "manual-rt-1"
    oauth_file = hermes_home / ".anthropic_oauth.json"
    assert not oauth_file.exists(), (
        "manual:hermes_pkce is already pool-owned; refreshing it must not "
        "create a second hermes_pkce singleton source"
    )

    reloaded = load_pool("anthropic")
    matching = [e for e in reloaded.entries() if e.id == "manual-entry"]
    assert len(matching) == 1
    assert matching[0].source == "manual:hermes_pkce"
    assert matching[0].refresh_token == "manual-rt-1"
