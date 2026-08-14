"""Tests for the lints migrated from tests/ and workflows, and the new
dependency-specifier lints."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from lints import engines_satisfiable as engines  # noqa: E402
from lints import no_shadowed_test_definitions as shadow  # noqa: E402
from lints import packagejson_exact_versions as pjexact  # noqa: E402
from lints import pyproject_dep_bounds as pybounds  # noqa: E402
from lints import workflow_sha_pins as shapins  # noqa: E402

# ── engines-satisfiable ──────────────────────────────────────────────────


def test_semver_range_subset():
    assert engines.satisfies_range("10.9.8", ">=10.9.8 <11 || >=11.17.0")
    assert engines.satisfies_range("11.17.0", ">=10.9.8 <11 || >=11.17.0")
    assert not engines.satisfies_range("11.16.0", ">=10.9.8 <11 || >=11.17.0")
    assert engines.satisfies_range("22.22.0", "^22.12.0")
    assert not engines.satisfies_range("23.0.0", "^22.12.0")


def test_engines_lint_is_clean_on_repo():
    """The live manifests must satisfy their own floors (the check the
    python-lane pytest could never run on a package.json-only PR)."""
    assert engines.check() == []


# ── no-shadowed-test-definitions ─────────────────────────────────────────


def test_shadow_guard_detects_duplicate():
    tree = ast.parse("def test_a():\n    pass\n\ndef test_a():\n    pass\n")
    assert shadow.duplicates_in(tree.body, "<module>")


def test_shadow_guard_allows_redefining_decorators():
    src = (
        "class C:\n"
        "    def f(self):\n        pass\n"
        "    @x.setter\n"
        "    def f(self):\n        pass\n"
    )
    cls = ast.parse(src).body[0]
    assert not shadow.duplicates_in(cls.body, "C")


def test_shadow_guard_still_flags_bare_property_repeat():
    src = (
        "class C:\n"
        "    def f(self):\n        pass\n"
        "    @property\n"
        "    def f(self):\n        pass\n"
    )
    cls = ast.parse(src).body[0]
    assert shadow.duplicates_in(cls.body, "C")


def test_shadow_lint_is_clean_on_repo():
    assert shadow.check() == []


# ── workflow-sha-pins ────────────────────────────────────────────────────


def test_sha_pin_detection():
    text = (
        "steps:\n"
        "  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6\n"
        "  - uses: ./.github/actions/retry\n"
        "  - uses: actions/setup-node@v4\n"
        "  - uses: hadolint/hadolint-action@main\n"
        "  - uses: docker://alpine:3.20\n"
    )
    problems = shapins.unpinned_uses(text)
    assert [ref for _, ref in problems] == [
        "actions/setup-node@v4",
        "hadolint/hadolint-action@main",
        "docker://alpine:3.20",
    ]


def test_sha_pins_clean_on_repo():
    """Policy check: every workflow/action ref in the live tree is pinned."""
    assert shapins.check() == []


# ── pyproject-dep-bounds ─────────────────────────────────────────────────


def test_upper_bound_detection():
    assert pybounds.has_upper_bound(">=1.2,<2")
    assert pybounds.has_upper_bound("==1.2.3")
    assert pybounds.has_upper_bound("~=1.4")
    assert pybounds.has_upper_bound("<0.32")
    assert not pybounds.has_upper_bound(">=1.2")
    assert not pybounds.has_upper_bound("")
    assert not pybounds.has_upper_bound(">1,!=1.5")


def test_requirement_splitting():
    assert pybounds._split_requirement("httpx>=0.28.1,<1") == ("httpx", "", ">=0.28.1,<1")
    name, url, spec = pybounds._split_requirement(
        "foo @ git+https://github.com/x/foo@" + "a" * 40
    )
    assert name == "foo" and url.startswith("git+") and spec == ""
    assert pybounds._split_requirement("pkg[extra]==1.0; python_version < '3.12'")[2] == "==1.0"


def test_pyproject_bounds_clean_on_repo():
    """Every declared dependency in the live pyproject carries a ceiling
    (the AGENTS.md pinning policy, now enforced instead of reviewed)."""
    assert pybounds.check() == []


# ── packagejson-exact-versions ───────────────────────────────────────────


def test_exact_version_policy():
    manifest = {
        "dependencies": {
            "ok": "1.2.3",
            "prerelease-ok": "7.0.0-rc13",
            "local-ok": "file:../shared",
            "workspace-ok": "workspace:*",
            "caret-bad": "^1.2.3",
            "tilde-bad": "~1.2.3",
            "range-bad": ">=1",
            "tag-bad": "latest",
            "star-bad": "*",
        },
        "devDependencies": {"dev-bad": "^2.0.0"},
    }
    problems = pjexact.non_exact_deps(manifest)
    flagged = {name for _, name, _ in problems}
    assert flagged == {"caret-bad", "tilde-bad", "range-bad", "tag-bad", "star-bad", "dev-bad"}


def test_npm_alias_is_exact_only_when_its_version_tail_is():
    """`npm:<pkg>@<version>` re-points a dependency; the tail is the
    specifier, so it answers to the same exactness rule."""
    assert pjexact.is_exact("npm:@hermes/ink@0.0.1")
    assert pjexact.is_exact("npm:image-size@2.0.3")
    assert not pjexact.is_exact("npm:@hermes/ink@^0.0.1")
    assert not pjexact.is_exact("npm:image-size@latest")


def test_overrides_are_scanned_including_nested_tables():
    """An override forces a version on every transitive consumer, so a
    ranged override floats packages the manifest never names — a wider
    hole than a ranged direct dependency, not a narrower one."""
    manifest = {
        "overrides": {
            "pinned-ok": "1.2.3",
            "alias-ok": "npm:@scope/fork@2.0.0",
            "caret-bad": "^3.3.1",
            "parent": {
                ".": "~4.0.0",
                "nested-bad": ">=5",
                "nested-ok": "6.0.0",
            },
        },
    }
    problems = pjexact.non_exact_deps(manifest)
    assert {name for _, name, _ in problems} == {"caret-bad", ".", "nested-bad"}
    # The nested finding reports the path that locates it in the manifest.
    assert ("overrides.parent", "nested-bad", ">=5") in problems


def test_packagejson_exact_clean_on_repo():
    """Every tracked package.json declares exact versions (or local refs)."""
    assert pjexact.check() == []
