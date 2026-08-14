"""Fixture tests for the uv-stale-exclude lint. No network — publish
dates come from uv.lock's upload-time fields in the fixtures."""

from __future__ import annotations

import sys
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from lints import uv_stale_exclude as mod  # noqa: E402

NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)
OLD = (NOW - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
FRESH = (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
BOUNDARY = (NOW - timedelta(days=14, hours=12)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pyproject(entries: str) -> str:
    return (
        "[project]\n"
        'name = "fixture"\n'
        'version = "0.0.0"\n'
        "\n"
        "[tool.uv]\n"
        'exclude-newer = "14 days"\n'
        "# h2: temporary exception for a CVE fix\n"
        "exclude-newer-package = { " + entries + " }\n"
    )


def _lock(packages: list[tuple[str, str, str | None]], mirror: str = "") -> str:
    """packages: (name, version, upload_time_or_None)."""
    head = (
        "version = 1\n"
        "revision = 3\n"
        "\n"
        "[options]\n"
        'exclude-newer = "2026-07-25T00:00:00Z"\n'
        'exclude-newer-span = "P14D"\n'
    )
    if mirror:
        head += "\n[options.exclude-newer-package]\n" + mirror + "\n"
    body = ""
    for name, version, upload in packages:
        body += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        if upload:
            body += (
                f'sdist = {{ url = "https://x/{name}.tar.gz", '
                f'hash = "sha256:0", size = 1, upload-time = "{upload}" }}\n'
            )
    return head + body


# ── plan ─────────────────────────────────────────────────────────────────


def test_false_replaced_with_stamp_from_lock():
    py = _pyproject("h2 = false")
    lock = _lock([("h2", "4.4.1", FRESH)])
    actions = mod.plan(py, lock, now=NOW)
    assert len(actions) == 1
    key, action, reason, stamp = actions[0]
    assert (key, action) == ("h2", "replace")
    assert "= false" in reason or "false" in reason
    # Stamp = newest upload-time + 1 day.
    expected = (
        datetime.fromisoformat(FRESH.replace("Z", "+00:00")) + timedelta(days=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert stamp == expected


def test_stale_dated_entry_removed():
    py = _pyproject('h2 = "2026-08-04T00:00:00Z"')
    lock = _lock([("h2", "4.4.1", OLD)])
    actions = mod.plan(py, lock, now=NOW)
    assert [(a[0], a[1]) for a in actions] == [("h2", "remove")]


def test_stale_false_entry_removed_not_replaced():
    """Removal wins over replacement when the package is already old —
    replacing first would just leave a stamp for the next run to remove."""
    py = _pyproject("h2 = false")
    lock = _lock([("h2", "4.4.1", OLD)])
    actions = mod.plan(py, lock, now=NOW)
    assert [(a[0], a[1]) for a in actions] == [("h2", "remove")]


def test_fresh_dated_entry_kept():
    py = _pyproject('h2 = "2026-08-04T00:00:00Z"')
    lock = _lock([("h2", "4.4.1", FRESH)])
    assert mod.plan(py, lock, now=NOW) == []


def test_boundary_grace_keeps_entry():
    py = _pyproject('h2 = "2026-08-04T00:00:00Z"')
    lock = _lock([("h2", "4.4.1", BOUNDARY)])
    assert mod.plan(py, lock, now=NOW) == []


def test_unknown_upload_time_fails_open():
    py = _pyproject('h2 = "2026-08-04T00:00:00Z"')
    lock = _lock([("h2", "4.4.1", None)])
    assert mod.plan(py, lock, now=NOW) == []


def test_false_with_no_dated_artifacts_left_alone():
    py = _pyproject("h2 = false")
    lock = _lock([("h2", "4.4.1", None)])
    assert mod.plan(py, lock, now=NOW) == []


def test_entry_matching_no_locked_package_removed():
    py = _pyproject("ghost = false")
    lock = _lock([("h2", "4.4.1", FRESH)])
    actions = mod.plan(py, lock, now=NOW)
    assert [(a[0], a[1]) for a in actions] == [("ghost", "remove")]
    assert "matches no package" in actions[0][2]


def test_name_normalization_bridges_underscore_and_dash():
    """pyproject says huggingface_hub, uv.lock says huggingface-hub."""
    py = _pyproject("huggingface_hub = false")
    lock = _lock([("huggingface-hub", "1.0.0", FRESH)])
    actions = mod.plan(py, lock, now=NOW)
    assert [(a[0], a[1]) for a in actions] == [("huggingface_hub", "replace")]


def test_multiple_locked_versions_any_fresh_keeps():
    py = _pyproject('h2 = "2026-08-04T00:00:00Z"')
    lock = _lock([("h2", "4.4.1", OLD), ("h2", "4.4.2", FRESH)])
    assert mod.plan(py, lock, now=NOW) == []


def test_keep_marker_exempts_table():
    py = _pyproject("h2 = false").replace(
        "# h2: temporary exception for a CVE fix",
        "# lint: keep\n# h2: standing exception",
    )
    lock = _lock([("h2", "4.4.1", OLD)])
    assert mod.plan(py, lock, now=NOW) == []


_SECTION_PYPROJECT = (
    "[project]\nname = \"fixture\"\nversion = \"0.0.0\"\n\n"
    "[tool.uv]\nexclude-newer = \"14 days\"\n\n"
    "# temporary exceptions\n"
    "[tool.uv.exclude-newer-package]\nh2 = false\nvercel = \"2026-08-01T00:00:00Z\"\n"
)


def test_section_form_planned_same_as_inline():
    """The [tool.uv.exclude-newer-package] table form is read as plain
    TOML and planned identically to the inline form."""
    lock = _lock([("h2", "4.4.1", FRESH), ("vercel", "1.0.0", OLD)])
    actions = mod.plan(_SECTION_PYPROJECT, lock, now=NOW)
    assert {(a[0], a[1]) for a in actions} == {("h2", "replace"), ("vercel", "remove")}


def test_section_form_applied_in_pyproject():
    lock = _lock([("h2", "4.4.1", FRESH), ("vercel", "1.0.0", OLD)])
    actions = mod.plan(_SECTION_PYPROJECT, lock, now=NOW)
    out = mod.apply_to_pyproject(_SECTION_PYPROJECT, actions)
    table = tomllib.loads(out)["tool"]["uv"]["exclude-newer-package"]
    assert "vercel" not in table
    assert isinstance(table["h2"], str)  # false -> stamp
    mod.verify_only_age_changed(
        _SECTION_PYPROJECT, out, ("tool", "uv", "exclude-newer-package"), "pyproject"
    )


def test_section_form_emptied_drops_header_and_comment():
    lock = _lock([("vercel", "1.0.0", OLD)])
    py = (
        "[project]\nname = \"fixture\"\nversion = \"0.0.0\"\n\n"
        "[tool.uv]\nexclude-newer = \"14 days\"\n\n"
        "# temporary exceptions\n"
        "[tool.uv.exclude-newer-package]\nvercel = \"2026-08-01T00:00:00Z\"\n"
    )
    actions = mod.plan(py, lock, now=NOW)
    out = mod.apply_to_pyproject(py, actions)
    parsed = tomllib.loads(out)
    assert "exclude-newer-package" not in parsed["tool"]["uv"]
    assert "# temporary exceptions" not in out
    assert parsed["tool"]["uv"]["exclude-newer"] == "14 days"


def test_section_form_keep_marker_respected():
    py = _SECTION_PYPROJECT.replace(
        "# temporary exceptions", "# lint: keep\n# standing exceptions"
    )
    lock = _lock([("h2", "4.4.1", OLD), ("vercel", "1.0.0", OLD)])
    assert mod.plan(py, lock, now=NOW) == []


def test_real_repo_pyproject_parses():
    """The shipped pyproject/uv.lock must be plannable (invariant)."""
    py = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    lock = (REPO_ROOT / "uv.lock").read_text(encoding="utf-8")
    span = mod.parse_span(py)
    assert span is not None and span.days >= 1
    form, _, _ = mod.locate_table(py)
    assert form is not None, "repo pyproject should carry the table"
    mod.plan(py, lock)  # must not raise


# ── apply_to_pyproject ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "entries,actions",
    [
        # remove `h2` while `python-h2` sits beside it
        ("python-h2 = false, h2 = \"2026-08-04T00:00:00Z\"", [("h2", "remove", "r", None)]),
        # …and with the collider on the right of the target
        ("h2 = \"2026-08-04T00:00:00Z\", python-h2 = false", [("h2", "remove", "r", None)]),
        # replace must not rewrite the longer key's value either
        ("python-h2 = false, h2 = false", [("h2", "replace", "r", "2026-09-09T00:00:00Z")]),
    ],
)
def test_key_edit_does_not_eat_a_longer_key_with_the_same_suffix(entries, actions):
    """An unanchored key regex turns `{ python-h2 = false, h2 = ... }` into
    `{ python- }` — valid-looking line surgery, unparseable TOML."""
    py = _pyproject(entries)
    out = mod.apply_to_pyproject(py, actions)

    table = tomllib.loads(out)["tool"]["uv"]["exclude-newer-package"]
    assert "python-h2" in table, f"collider key was clobbered: {out!r}"
    mod.verify_only_age_changed(
        py, out, ("tool", "uv", "exclude-newer-package"), "pyproject"
    )


def test_section_form_key_edit_does_not_eat_a_longer_key():
    py = (
        "[project]\nname = \"fixture\"\nversion = \"0.0.0\"\n\n"
        "[tool.uv]\nexclude-newer = \"14 days\"\n\n"
        "[tool.uv.exclude-newer-package]\n"
        "python-h2 = false\nh2 = \"2026-08-04T00:00:00Z\"\n"
    )
    out = mod.apply_to_pyproject(py, [("h2", "remove", "r", None)])
    table = tomllib.loads(out)["tool"]["uv"]["exclude-newer-package"]
    assert set(table) == {"python-h2"}


def test_lock_mirror_key_edit_does_not_eat_a_longer_key():
    lock = _lock(
        [("h2", "4.4.1", OLD)],
        mirror='python-h2 = false\nh2 = "2026-08-04T00:00:00Z"',
    )
    out = mod.apply_to_lock(lock, [("h2", "remove", "r", None)])
    assert set(tomllib.loads(out)["options"]["exclude-newer-package"]) == {"python-h2"}


def test_apply_replace_false_in_pyproject():
    py = _pyproject("vercel = false, h2 = false")
    actions = [("h2", "replace", "r", "2026-08-04T00:00:00Z")]
    out = mod.apply_to_pyproject(py, actions)
    assert 'h2 = "2026-08-04T00:00:00Z"' in out
    assert "vercel = false" in out  # untouched
    tomllib.loads(out)  # stays valid TOML


def test_apply_remove_entry_in_pyproject():
    py = _pyproject("vercel = false, h2 = false")
    out = mod.apply_to_pyproject(py, [("h2", "remove", "r", None)])
    parsed = tomllib.loads(out)["tool"]["uv"]["exclude-newer-package"]
    assert parsed == {"vercel": False}


def test_apply_remove_last_entry_drops_table_and_comment():
    py = _pyproject("h2 = false")
    out = mod.apply_to_pyproject(py, [("h2", "remove", "r", None)])
    parsed = tomllib.loads(out)
    assert "exclude-newer-package" not in parsed["tool"]["uv"]
    assert "temporary exception" not in out  # comment went with it
    assert parsed["tool"]["uv"]["exclude-newer"] == "14 days"  # untouched


# ── apply_to_lock ────────────────────────────────────────────────────────

MIRROR = "vercel = false\nh2 = false"


def test_apply_replace_in_lock():
    lock = _lock([("h2", "4.4.1", FRESH)], mirror=MIRROR)
    out = mod.apply_to_lock(lock, [("h2", "replace", "r", "2026-08-04T00:00:00Z")])
    parsed = tomllib.loads(out)["options"]["exclude-newer-package"]
    assert parsed == {"vercel": False, "h2": "2026-08-04T00:00:00Z"}


def test_apply_remove_in_lock_normalizes_names():
    lock = _lock([("h2", "4.4.1", FRESH)], mirror="huggingface-hub = false\nh2 = false")
    out = mod.apply_to_lock(lock, [("huggingface_hub", "remove", "r", None)])
    parsed = tomllib.loads(out)["options"]["exclude-newer-package"]
    assert parsed == {"h2": False}


def test_apply_remove_last_entry_drops_lock_section():
    lock = _lock([("h2", "4.4.1", FRESH)], mirror="h2 = false")
    out = mod.apply_to_lock(lock, [("h2", "remove", "r", None)])
    parsed = tomllib.loads(out)
    assert "exclude-newer-package" not in parsed.get("options", {})
    assert parsed["options"]["exclude-newer"]  # rest of options intact


def test_apply_to_lock_without_section_is_noop():
    lock = _lock([("h2", "4.4.1", FRESH)])
    assert mod.apply_to_lock(lock, [("h2", "remove", "r", None)]) == lock


# ── verifier ─────────────────────────────────────────────────────────────


def test_verifier_accepts_age_only_changes():
    py = _pyproject("h2 = false")
    out = mod.apply_to_pyproject(py, [("h2", "replace", "r", "2026-08-04T00:00:00Z")])
    mod.verify_only_age_changed(py, out, ("tool", "uv", "exclude-newer-package"), "pyproject")


def test_verifier_rejects_out_of_scope_change():
    py = _pyproject("h2 = false")
    tampered = py.replace('exclude-newer = "14 days"', 'exclude-newer = "1 days"')
    with pytest.raises(RuntimeError, match="outside"):
        mod.verify_only_age_changed(
            py, tampered, ("tool", "uv", "exclude-newer-package"), "pyproject"
        )


def test_verifier_rejects_dependency_tampering_in_lock():
    lock = _lock([("h2", "4.4.1", FRESH)], mirror="h2 = false")
    tampered = lock.replace("https://x/h2.tar.gz", "https://evil/h2.tar.gz")
    with pytest.raises(RuntimeError, match="outside"):
        mod.verify_only_age_changed(
            lock, tampered, ("options", "exclude-newer-package"), "uv.lock"
        )


# ── end-to-end fix() roundtrip ───────────────────────────────────────────


def test_fix_roundtrip(tmp_path, monkeypatch):
    real_now = datetime.now(timezone.utc)
    old_stamp = (real_now - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fresh_stamp = (real_now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        _pyproject("stale = false, fresh = false"), encoding="utf-8"
    )
    lock = tmp_path / "uv.lock"
    lock.write_text(
        _lock(
            [("stale", "1.0.0", old_stamp), ("fresh", "2.0.0", fresh_stamp)],
            mirror="stale = false\nfresh = false",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "_pyproject_path", lambda: pyproject)
    monkeypatch.setattr(mod, "_uvlock_path", lambda: lock)

    findings = mod.check()
    assert {f.path for f in findings} == {"pyproject.toml"}
    assert all(f.fixable for f in findings)

    changed = mod.fix()
    assert changed == ["pyproject.toml", "uv.lock"]

    py_parsed = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    table = py_parsed["tool"]["uv"]["exclude-newer-package"]
    assert "stale" not in table  # old package's entry removed
    assert isinstance(table["fresh"], str)  # false -> timestamp
    lock_parsed = tomllib.loads(lock.read_text(encoding="utf-8"))
    lock_table = lock_parsed["options"]["exclude-newer-package"]
    assert "stale" not in lock_table
    assert lock_table["fresh"] == table["fresh"]  # mirrored stamp

    # Idempotent.
    assert mod.check() == []
    assert mod.fix() == []


def test_lint_metadata_contract():
    lint = mod.LINT
    assert lint.network is False  # dates come from uv.lock, no registry
    assert lint.autofix is True
    assert set(lint.fix_touches) == {"pyproject.toml", "uv.lock"}
