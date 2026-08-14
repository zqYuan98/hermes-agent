"""Tests for the AGENTS.md-policy lints (hardcoded ~/.hermes, ANSI
erase-to-EOL, skill frontmatter standards, npm age-gate coverage)."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from lints import no_ansi_erase_eol as ansi  # noqa: E402
from lints import no_hardcoded_hermes_home as home  # noqa: E402
from lints import npmrc_age_gate_coverage as agegate  # noqa: E402
from lints import skill_frontmatter_standards as skillstd  # noqa: E402

# ── no-hardcoded-hermes-home ─────────────────────────────────────────────


def test_flags_the_literal_shapes():
    for src in (
        'p = Path.home() / ".hermes" / "state.db"\n',
        "p = os.path.expanduser('~/.hermes/config.yaml')\n",
        'p = Path("~/.hermes/skills")\n',
    ):
        assert home.scan_text(src), src


def test_guard_hint_window_suppresses():
    src = (
        "try:\n"
        "    from hermes_constants import get_hermes_home\n"
        "    return get_hermes_home()\n"
        "except Exception:\n"
        '    return Path.home() / ".hermes"\n'
    )
    assert home.scan_text(src) == []


def test_inline_marker_suppresses():
    src = 'root = Path.home() / ".hermes" / "desktop-ssh"  # hermes-home: ok\n'
    assert home.scan_text(src) == []


def test_comments_and_prose_skipped():
    src = (
        '# never hardcode Path.home() / ".hermes"\n'
        '"guidance: use os.path.expanduser(\'~/.hermes/.env\')"\n'
    )
    assert home.scan_text(src) == []


def test_hermes_home_lint_clean_on_repo():
    assert home.check() == []


# ── no-ansi-erase-eol ────────────────────────────────────────────────────


def test_flags_erase_escapes():
    for esc in ("\\033[K", "\\x1b[K", "\\e[K", "\\033[2K"):
        src = f'sys.stdout.write("\\r{esc}")\n'
        assert ansi.scan_text(src), esc


def test_comments_about_the_pitfall_allowed():
    src = "# Clear with spaces (not \\033[K) to avoid garbled escapes\n"
    assert ansi.scan_text(src) == []


def test_ansi_marker_suppresses():
    src = 'w("\\033[K")  # ansi-erase: ok\n'
    assert ansi.scan_text(src) == []


def test_ansi_lint_clean_on_repo():
    assert ansi.check() == []


# ── skill-frontmatter-standards ──────────────────────────────────────────


def _skill(tmp_path, frontmatter: str, script: str | None = None) -> Path:
    d = tmp_path / "myskill"
    d.mkdir()
    (d / "SKILL.md").write_text(f"---\n{frontmatter}\n---\n# Body\n", encoding="utf-8")
    if script is not None:
        (d / "scripts").mkdir()
        (d / "scripts" / "helper.py").write_text(script, encoding="utf-8")
    return d


def test_good_frontmatter_passes(tmp_path):
    d = _skill(tmp_path, 'name: myskill\ndescription: "Does the thing via CLI."')
    assert skillstd.check_skill(d) == []


def test_long_description_flagged(tmp_path):
    d = _skill(tmp_path, "name: x\ndescription: " + "a" * 61 + ".")
    assert any("62 chars" in m for _, m in skillstd.check_skill(d))


def test_missing_period_and_marketing_words_flagged(tmp_path):
    d = _skill(tmp_path, "name: x\ndescription: A powerful comprehensive tool")
    messages = [m for _, m in skillstd.check_skill(d)]
    assert any("period" in m for m in messages)
    assert any("marketing" in m for m in messages)


def test_missing_fields_flagged(tmp_path):
    d = _skill(tmp_path, "version: 1.0.0")
    messages = [m for _, m in skillstd.check_skill(d)]
    assert any("`name:`" in m for m in messages)
    assert any("`description:`" in m for m in messages)


def test_posix_script_without_platforms_flagged(tmp_path):
    d = _skill(
        tmp_path,
        'name: x\ndescription: "Does the thing."',
        script="import fcntl\n",
    )
    assert any("POSIX-only" in m for _, m in skillstd.check_skill(d))


def test_posix_script_with_platforms_passes(tmp_path):
    d = _skill(
        tmp_path,
        'name: x\ndescription: "Does the thing."\nplatforms: [linux, macos]',
        script="import fcntl\n",
    )
    assert skillstd.check_skill(d) == []


def test_skill_standards_clean_on_repo():
    assert skillstd.check() == []


# ── npmrc-age-gate-coverage ──────────────────────────────────────────────


def test_parses_the_declared_floor():
    assert agegate.parse_min_age("engine-strict=true\nmin-release-age=14\n") == 14
    assert agegate.parse_min_age("engine-strict=true\n") is None
    # A commented-out directive is not in force.
    assert agegate.parse_min_age("# min-release-age=14\n") is None


def test_every_npm_project_dir_has_a_manifest_and_a_lockfile():
    """A project is the lockfile+manifest pair npm resolves against.

    A lockfile with no manifest beside it (nix/ vendors one for a
    hash-pinned fetch) is an artifact, not a project npm ever installs.
    """
    for rel_dir in agegate.npm_project_dirs():
        base = REPO_ROOT if rel_dir == "." else REPO_ROOT / rel_dir
        assert (base / "package.json").is_file(), rel_dir
        assert (base / "package-lock.json").is_file(), rel_dir


def test_every_npm_project_is_age_gated_at_or_above_the_root_floor():
    """The invariant the lint exists for, asserted directly on the tree.

    npm reads only the project's own .npmrc — never a parent's — so the
    root gate protects the root install and nothing else.
    """
    root_floor = agegate.parse_min_age(
        (REPO_ROOT / ".npmrc").read_text(encoding="utf-8")
    )
    assert root_floor is not None, "root .npmrc must declare the standard"

    for rel_dir in agegate.npm_project_dirs():
        base = REPO_ROOT if rel_dir == "." else REPO_ROOT / rel_dir
        npmrc = base / ".npmrc"
        assert npmrc.is_file(), f"{rel_dir} resolves with no age gate"
        declared = agegate.parse_min_age(npmrc.read_text(encoding="utf-8"))
        assert declared is not None and declared >= root_floor, rel_dir


def test_age_gate_coverage_clean_on_repo():
    assert agegate.check() == []
