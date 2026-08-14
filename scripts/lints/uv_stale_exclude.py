"""``= false`` and stale entries in uv's ``exclude-newer-package``.

``[tool.uv] exclude-newer = "N days"`` age-gates dependency resolution
(supply-chain quarantine, the Python twin of npm's min-release-age).
``exclude-newer-package`` carves per-package exceptions — but a
``pkg = false`` entry disables the gate for that package FOREVER, an
unbounded hole. The uv-documented form is an explicit timestamp
(``pkg = "2026-08-04T00:00:00Z"``): it admits the one release that
motivated the exception and nothing newer.

Two findings, both autofixable:

- ``pkg = false``      -> replace with the locked version's newest
                          ``upload-time`` (from uv.lock) + 1 day, so the
                          exception admits exactly the release it was
                          added for.
- stale entry          -> remove, when every locked version of the
                          package is already older than the global
                          ``exclude-newer`` span (+1 day boundary
                          grace) — the gate no longer needs the
                          exception. Entries matching no locked package
                          are stale too.

No network: publish dates come from uv.lock's ``upload-time`` fields.
Versions with no recorded upload-time fail open (count as young).

The fixer edits BOTH files — the ``exclude-newer-package`` table in
pyproject.toml (inline ``{ ... }`` or ``[tool.uv.exclude-newer-package]``
section form) and the mirrored ``[options.exclude-newer-package]``
section in uv.lock (so ``uv lock --check`` stays green without
re-resolution; the admitted locked versions are unchanged by
construction). Reading is plain tomllib; writing is line surgery
(tomllib has no writer) so comments and formatting survive. Before
writing, a structural verifier parses old and new with tomllib and
refuses the write unless the ONLY semantic difference in either file
is the exclude-newer-package data.

Opt-out: ``# lint: keep`` in the comment block directly above the
``exclude-newer-package`` line (or section header) exempts the table.
"""

from __future__ import annotations

import re
import tomllib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lints import REPO_ROOT, Finding, Lint

KEEP_MARKER = re.compile(r"#\s*lint:\s*keep\b", re.IGNORECASE)
GRACE = timedelta(days=1)

_INLINE_RE = re.compile(
    r"^(?P<prefix>\s*exclude-newer-package\s*=\s*\{)(?P<body>.*)(?P<suffix>\}\s*)$"
)
_SPAN_RE = re.compile(r"^(?P<days>\d+)\s*days?$")
# One `key = value` line inside a [..exclude-newer-package] section
# (uv.lock's options section or pyproject's table form). Quoted keys OK.
_SECTION_ENTRY_RE = re.compile(
    r'^(?P<key>[A-Za-z0-9._-]+|"[^"]+")\s*=\s*(?P<val>false|"[^"]*")\s*$'
)
_LOCK_SECTION_HEADER = "[options.exclude-newer-package]"
_PYPROJECT_SECTION_HEADER = "[tool.uv.exclude-newer-package]"


def _normalize(name: str) -> str:
    """PEP 503 normalization, matching uv.lock's package names."""
    return re.sub(r"[-_.]+", "-", name.strip("\"'")).lower()


def _parse_iso(stamp: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def parse_span(pyproject_text: str) -> timedelta | None:
    """The global exclude-newer span, from the ``"N days"`` form."""
    uv = tomllib.loads(pyproject_text).get("tool", {}).get("uv", {})
    raw = uv.get("exclude-newer")
    if not isinstance(raw, str):
        return None
    m = _SPAN_RE.match(raw.strip())
    return timedelta(days=int(m.group("days"))) if m else None


def _lock_info(lock_text: str) -> tuple[dict[str, int], dict[str, list[datetime]]]:
    """Per normalized name: locked-version count, and the newest known
    upload-time of each version that has one.

    A version whose artifacts carry no parseable upload-time is counted
    but contributes no stamp — the staleness check requires a known
    stamp per locked version, so unknown age fails open (young).
    """
    data = tomllib.loads(lock_text)
    counts: dict[str, int] = {}
    stamps: dict[str, list[datetime]] = {}
    for pkg in data.get("package", []):
        name = _normalize(pkg.get("name", ""))
        if not name:
            continue
        counts[name] = counts.get(name, 0) + 1
        times: list[datetime] = []
        sdist = pkg.get("sdist") or {}
        if isinstance(sdist, dict) and (t := _parse_iso(str(sdist.get("upload-time", "")))):
            times.append(t)
        for wheel in pkg.get("wheels", []) or []:
            if isinstance(wheel, dict) and (t := _parse_iso(str(wheel.get("upload-time", "")))):
                times.append(t)
        if times:
            stamps.setdefault(name, []).append(max(times))
    return counts, stamps


def _keep_marker_above(lines: list[str], idx: int) -> bool:
    """True when the contiguous comment block directly above ``idx``
    carries ``# lint: keep``."""
    j = idx - 1
    while j >= 0 and lines[j].lstrip().startswith("#"):
        if KEEP_MARKER.search(lines[j]):
            return True
        j -= 1
    return False


def locate_table(pyproject_text: str) -> tuple[str | None, int, bool]:
    """Find the exclude-newer-package table in either TOML form.

    Returns ``(form, line_idx, keep)`` where form is ``"inline"`` (a
    one-line ``exclude-newer-package = { ... }``), ``"section"`` (a
    ``[tool.uv.exclude-newer-package]`` header), or None when absent.
    """
    lines = pyproject_text.splitlines()
    for i, line in enumerate(lines):
        if _INLINE_RE.match(line):
            return "inline", i, _keep_marker_above(lines, i)
        if line.strip() == _PYPROJECT_SECTION_HEADER:
            return "section", i, _keep_marker_above(lines, i)
    return None, -1, False


def table_entries(pyproject_text: str) -> dict[str, object]:
    """The exclude-newer-package entries, read as plain TOML —
    form-independent (tomllib parses both shapes identically)."""
    uv = tomllib.loads(pyproject_text).get("tool", {}).get("uv", {})
    table = uv.get("exclude-newer-package", {})
    return table if isinstance(table, dict) else {}


def plan(
    pyproject_text: str, lock_text: str, now: datetime | None = None
) -> list[tuple[str, str, str, str | None]]:
    """Compute actions as ``(key, action, reason, replacement)`` where
    action is ``remove`` or ``replace`` (replacement = new date string)."""
    now = now or datetime.now(timezone.utc)
    form, _, keep = locate_table(pyproject_text)
    if form is None or keep:
        return []
    span = parse_span(pyproject_text)
    counts, stamps = _lock_info(lock_text)
    threshold = (now - span - GRACE) if span else None

    actions: list[tuple[str, str, str, str | None]] = []
    for key, value in table_entries(pyproject_text).items():
        norm = _normalize(key)
        n_locked = counts.get(norm, 0)
        known = stamps.get(norm, [])

        if n_locked == 0:
            actions.append(
                (key, "remove", "matches no package in uv.lock — nothing to exempt", None)
            )
            continue

        # Stale: every locked version has a KNOWN upload-time older than
        # the threshold. Any unknown-age version fails open (young).
        if (
            threshold is not None
            and len(known) == n_locked
            and all(t < threshold for t in known)
        ):
            actions.append(
                (
                    key,
                    "remove",
                    "every locked version is older than the exclude-newer "
                    "span — the age gate no longer needs this exception",
                    None,
                )
            )
            continue

        if value is False:
            if not known:
                continue  # no dated artifacts to anchor a stamp — fail open
            stamp = (max(known) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            actions.append(
                (
                    key,
                    "replace",
                    "`= false` disables the age gate for this package "
                    "indefinitely — pin an explicit timestamp instead",
                    stamp,
                )
            )
    return actions


def _apply_to_section(
    text: str, header: str, actions: list[tuple[str, str, str, str | None]]
) -> str:
    """Edit one ``key = value`` per-line section (uv.lock's options
    section or pyproject's table form). Drops the header, and the
    comment block above it, when the section empties."""
    lines = text.splitlines()
    header_idx = next(
        (i for i, line in enumerate(lines) if line.strip() == header), None
    )
    if header_idx is None:
        return text
    end = header_idx + 1
    while end < len(lines) and not lines[end].strip().startswith("["):
        end += 1

    by_norm = {
        _normalize(key): (action, replacement)
        for key, action, _, replacement in actions
    }
    section: list[str] = []
    for line in lines[header_idx + 1 : end]:
        lm = _SECTION_ENTRY_RE.match(line.strip())
        if not lm:
            section.append(line)
            continue
        planned = by_norm.get(_normalize(lm.group("key")))
        if planned is None:
            section.append(line)
        elif planned[0] == "replace":
            section.append(f'{lm.group("key")} = "{planned[1]}"')
        # remove: drop the line

    if any(_SECTION_ENTRY_RE.match(line.strip()) for line in section):
        new_lines = lines[: header_idx + 1] + section + lines[end:]
    else:
        # Section emptied — drop the header and its comment block, then
        # collapse any doubled blank left behind.
        start = header_idx
        while start - 1 >= 0 and lines[start - 1].lstrip().startswith("#"):
            start -= 1
        new_lines = lines[:start] + lines[end:]
        collapsed: list[str] = []
        for line in new_lines:
            if line.strip() == "" and collapsed and collapsed[-1].strip() == "":
                continue
            collapsed.append(line)
        new_lines = collapsed
    result = "\n".join(new_lines)
    if text.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def apply_to_pyproject(text: str, actions: list[tuple[str, str, str, str | None]]) -> str:
    form, line_idx, _ = locate_table(text)
    if form is None:
        return text
    if form == "section":
        return _apply_to_section(text, _PYPROJECT_SECTION_HEADER, actions)

    m = _INLINE_RE.match(text.splitlines()[line_idx])
    assert m is not None  # locate_table just matched it
    body = m.group("body")
    removed_all = False

    for key, action, _, replacement in actions:
        # (?<![\w.-]) anchors the key's left edge: without it, removing `h2`
        # eats the tail of `python-h2` and emits `{ python- }`, unparseable
        # TOML. Bare \b is not enough — it does not fire between `-` and `h`.
        key_re = rf"(?<![\w.-]){re.escape(key)}\s*=\s*"
        if action == "replace":
            body = re.sub(
                rf"({key_re})false",
                lambda mm: f'{mm.group(1)}"{replacement}"',
                body,
            )
        else:
            body = re.sub(rf"\s*{key_re}(?:false|\"[^\"]*\")\s*,?", "", body)

    body = body.strip().strip(",").strip()
    lines = text.splitlines()
    if body:
        lines[line_idx] = f"{m.group('prefix').rstrip('{')}{{ {body} }}".replace("{ {", "{")
        lines[line_idx] = re.sub(r",\s*}", " }", lines[line_idx])
    else:
        removed_all = True
        del lines[line_idx]
        # Drop the contiguous comment block that described the (now
        # empty) table, npmrc-style.
        while line_idx - 1 >= 0 and lines[line_idx - 1].lstrip().startswith("#"):
            del lines[line_idx - 1]
            line_idx -= 1

    out: list[str] = []
    for line in lines:
        if removed_all and line.strip() == "" and out and out[-1].strip() == "":
            continue
        out.append(line)
    result = "\n".join(out)
    if text.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result


def apply_to_lock(text: str, actions: list[tuple[str, str, str, str | None]]) -> str:
    return _apply_to_section(text, _LOCK_SECTION_HEADER, actions)


def _strip_age_data(parsed: dict, path: tuple[str, ...]) -> dict:
    node = parsed
    for part in path[:-1]:
        node = node.get(part, {})
        if not isinstance(node, dict):
            return parsed
    if isinstance(node, dict):
        node.pop(path[-1], None)
    return parsed


def verify_only_age_changed(old: str, new: str, path: tuple[str, ...], label: str) -> None:
    """Parse old and new; everything except the exclude-newer-package
    data must be structurally identical, or the write is refused."""
    old_parsed = _strip_age_data(tomllib.loads(old), path)
    new_parsed = _strip_age_data(tomllib.loads(new), path)
    if old_parsed != new_parsed:
        raise RuntimeError(
            f"uv-stale-exclude: fix to {label} changed data outside "
            "exclude-newer-package — refusing to write"
        )


def _pyproject_path() -> Path:
    return REPO_ROOT / "pyproject.toml"


def _uvlock_path() -> Path:
    return REPO_ROOT / "uv.lock"


def _current_plan() -> list[tuple[str, str, str, str | None]]:
    pyproject = _pyproject_path()
    lock = _uvlock_path()
    if not pyproject.exists() or not lock.exists():
        return []
    return plan(
        pyproject.read_text(encoding="utf-8"), lock.read_text(encoding="utf-8")
    )


def check() -> list[Finding]:
    findings = []
    text = _pyproject_path().read_text(encoding="utf-8") if _pyproject_path().exists() else ""
    line_idx = None
    if text:
        form, idx, _ = locate_table(text)
        line_idx = idx + 1 if form else None
    for key, action, reason, replacement in _current_plan():
        detail = f"replace with `\"{replacement}\"`" if action == "replace" else "remove it"
        findings.append(
            Finding(
                lint_id="uv-stale-exclude",
                path="pyproject.toml",
                line=line_idx,
                message=(
                    f"exclude-newer-package entry `{key}`: {reason} — {detail}. "
                    "Add `# lint: keep` above the table if intentional."
                ),
                fixable=True,
            )
        )
    return findings


def fix() -> list[str]:
    actions = _current_plan()
    if not actions:
        return []
    changed: list[str] = []

    pyproject = _pyproject_path()
    old_py = pyproject.read_text(encoding="utf-8")
    new_py = apply_to_pyproject(old_py, actions)
    if new_py != old_py:
        verify_only_age_changed(
            old_py, new_py, ("tool", "uv", "exclude-newer-package"), "pyproject.toml"
        )
        pyproject.write_text(new_py, encoding="utf-8")
        changed.append("pyproject.toml")

    lock = _uvlock_path()
    old_lock = lock.read_text(encoding="utf-8")
    new_lock = apply_to_lock(old_lock, actions)
    if new_lock != old_lock:
        verify_only_age_changed(
            old_lock, new_lock, ("options", "exclude-newer-package"), "uv.lock"
        )
        lock.write_text(new_lock, encoding="utf-8")
        changed.append("uv.lock")
    return changed


LINT = Lint(
    id="uv-stale-exclude",
    description=(
        "exclude-newer-package entries must use explicit timestamps, never "
        "`= false`, and go away once the locked versions outgrow the span."
    ),
    severity="blocking",
    autofix=True,
    check=check,
    fix=fix,
    network=False,
    fix_touches=("pyproject.toml", "uv.lock"),
)
