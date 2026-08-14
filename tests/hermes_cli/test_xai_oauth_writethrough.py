"""Regression tests for xAI OAuth refresh write-through to the global root.

Companion to ``test_xai_oauth_profile_auth.py``. That file covers the READ
fallback (profile -> credential pool -> global root). These cover the WRITE
side: when a profile refreshes a rotating grant resolved from the root
fallback, the transaction must retain one immutable active/root identity and
publish the rotated chain without leaving root stale.
"""

from contextlib import contextmanager
import json

import pytest

from hermes_cli import auth


def _write_store(path, store):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store), encoding="utf-8")


def _read_store(path):
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def profile_and_root(tmp_path, monkeypatch):
    profile_path = tmp_path / "profiles" / "work" / "auth.json"
    root_path = tmp_path / "root" / "auth.json"

    monkeypatch.setattr(auth, "_auth_file_path", lambda: profile_path)
    monkeypatch.setattr(auth, "_global_auth_file_path", lambda: root_path)
    monkeypatch.setenv("HOME", str(tmp_path / "not-the-root"))
    return profile_path, root_path


def test_xai_write_through_predeclares_both_auth_stores(
    profile_and_root, monkeypatch
):
    profile_path, root_path = profile_and_root
    _write_store(profile_path, {"version": 1, "providers": {}})
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                "xai-oauth": {
                    "tokens": {
                        "access_token": "old-access",
                        "refresh_token": "old-refresh",
                    }
                }
            },
        },
    )

    calls: list[bool] = []
    contexts: list[object] = []
    save_contexts: list[object] = []
    real_lock = auth._auth_store_lock
    real_save = auth._save_auth_store

    @contextmanager
    def tracking_lock(*args, **kwargs):
        calls.append(bool(kwargs.get("include_global_root")))
        with real_lock(*args, **kwargs) as context:
            contexts.append(context)
            yield context

    def recording_save(store, *args, **kwargs):
        save_contexts.append(auth._current_auth_store_context())
        return real_save(store, *args, **kwargs)

    monkeypatch.setattr(auth, "_auth_store_lock", tracking_lock)
    monkeypatch.setattr(auth, "_save_auth_store", recording_save)
    auth._save_xai_oauth_tokens(
        {"access_token": "new-access", "refresh_token": "new-refresh"}
    )

    assert calls == [True]
    assert len(contexts) == 1
    assert save_contexts
    assert all(context is contexts[0] for context in save_contexts)


def test_refresh_updates_only_root_when_profile_reads_root(
    profile_and_root
):
    """The rotated chain is published to both prelocked stores atomically."""
    profile_path, root_path = profile_and_root
    _write_store(profile_path, {"version": 1, "providers": {}})
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                "xai-oauth": {
                    "tokens": {
                        "access_token": "old-access",
                        "refresh_token": "old-refresh",
                    }
                }
            },
        },
    )

    auth._save_xai_oauth_tokens(
        {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "token_type": "Bearer",
        }
    )

    profile = _read_store(profile_path)
    root = _read_store(root_path)
    assert "xai-oauth" not in profile.get("providers", {})
    assert root["providers"]["xai-oauth"]["tokens"]["access_token"] == "new-access"
    assert root["providers"]["xai-oauth"]["tokens"]["refresh_token"] == "new-refresh"


def test_refresh_does_not_touch_root_when_profile_has_own_state(profile_and_root):
    """A profile that genuinely shadows root must not clobber the root grant."""
    profile_path, root_path = profile_and_root
    _write_store(
        profile_path,
        {
            "version": 1,
            "providers": {
                "xai-oauth": {
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
                "xai-oauth": {
                    "tokens": {
                        "access_token": "root-untouched",
                        "refresh_token": "root-untouched-refresh",
                    }
                }
            },
        },
    )

    auth._save_xai_oauth_tokens(
        {"access_token": "profile-new", "refresh_token": "profile-new-refresh"}
    )

    profile = _read_store(profile_path)
    root = _read_store(root_path)
    assert (
        profile["providers"]["xai-oauth"]["tokens"]["refresh_token"]
        == "profile-new-refresh"
    )
    assert (
        root["providers"]["xai-oauth"]["tokens"]["refresh_token"]
        == "root-untouched-refresh"
    )


def test_xai_save_uses_frozen_paths_when_profile_resolution_changes(
    tmp_path, monkeypatch
):
    """Profile identity is resolved once and reused for every read/write."""
    first_profile = tmp_path / "profiles" / "first" / "auth.json"
    second_profile = tmp_path / "profiles" / "second" / "auth.json"
    root_path = tmp_path / "root" / "auth.json"
    _write_store(first_profile, {"version": 1, "providers": {}})
    _write_store(second_profile, {"version": 1, "providers": {}})
    _write_store(
        root_path,
        {
            "version": 1,
            "providers": {
                "xai-oauth": {
                    "tokens": {
                        "access_token": "old-access",
                        "refresh_token": "old-refresh",
                    }
                }
            },
        },
    )

    calls = {"active": 0, "global": 0}

    def active_path():
        calls["active"] += 1
        if calls["active"] > 1:
            raise AssertionError("active Profile identity was re-resolved")
        return first_profile

    def global_path():
        calls["global"] += 1
        if calls["global"] > 1:
            raise AssertionError("global Profile identity was re-resolved")
        return root_path

    monkeypatch.setattr(auth, "_auth_file_path", active_path)
    monkeypatch.setattr(auth, "_global_auth_file_path", global_path)
    monkeypatch.setenv("HOME", str(tmp_path / "not-the-root"))

    auth._save_xai_oauth_tokens(
        {"access_token": "new-access", "refresh_token": "new-refresh"}
    )

    assert calls == {"active": 1, "global": 1}
    assert "xai-oauth" not in _read_store(first_profile).get("providers", {})
    assert "xai-oauth" not in _read_store(second_profile).get("providers", {})
    assert (
        _read_store(root_path)["providers"]["xai-oauth"]["tokens"][
            "refresh_token"
        ]
        == "new-refresh"
    )


def test_write_through_is_noop_in_classic_mode(tmp_path, monkeypatch):
    profile_path = tmp_path / "auth.json"
    monkeypatch.setattr(auth, "_auth_file_path", lambda: profile_path)
    monkeypatch.setattr(auth, "_global_auth_file_path", lambda: None)
    _write_store(profile_path, {"version": 1, "providers": {}})

    auth._save_xai_oauth_tokens(
        {"access_token": "a", "refresh_token": "r"}
    )

    store = _read_store(profile_path)
    assert store["providers"]["xai-oauth"]["tokens"]["refresh_token"] == "r"


def test_write_through_failure_does_not_break_profile_save(profile_and_root, monkeypatch):
    """A failed root mirror does not invalidate the active-store publication."""
    profile_path, root_path = profile_and_root
    _write_store(profile_path, {"version": 1, "providers": {}})
    _write_store(root_path, {"version": 1, "providers": {}})

    real_save = auth._save_auth_store

    def exploding_save(store, target_path=None):
        if target_path is not None and target_path == root_path:
            raise OSError("simulated root write failure")
        return real_save(store, target_path)

    monkeypatch.setattr(auth, "_save_auth_store", exploding_save)

    auth._save_xai_oauth_tokens({"access_token": "a", "refresh_token": "r"})

    profile = _read_store(profile_path)
    assert profile["providers"]["xai-oauth"]["tokens"]["refresh_token"] == "r"
