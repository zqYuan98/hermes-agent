"""Every npm project must carry its own age-gated ``.npmrc``.

``min-release-age`` is the supply-chain quarantine: npm refuses to
resolve a version published less than N days ago, so a compromised
release has to survive N days of public scrutiny before it can enter a
build. It is configured per *project*, and npm does NOT walk up parent
directories looking for one (only cwd, ``$HOME``, and the global
config — walking up is still an open feature request, npm/npm#11437).

So the root ``.npmrc`` protects the root install and nothing else. A
nested project with its own ``package-lock.json`` resolves with the age
gate wide open unless a ``.npmrc`` sits directly beside that lockfile.
That is invisible in review: the nested install just works, and the
protection everyone assumes is repo-wide silently is not.

A project here is a directory holding BOTH ``package-lock.json`` and
``package.json`` — that pair is what ``npm install`` resolves against.
A lockfile with no manifest beside it is a vendored artifact (see
``nix/node-gyp-11-4-0-package-lock.json``, consumed by a hash-pinned
nix fetch that never consults npm config) and is not a project.

The required floor is read from the root ``.npmrc`` rather than
hardcoded, so raising the project standard in one place raises it
everywhere. A nested project may be stricter, never weaker.

Not autofixable: a new age gate changes what a fresh install resolves
in that project, which belongs in a reviewed change rather than a bot
patch.
"""

from __future__ import annotations

import re
import subprocess

from lints import REPO_ROOT, Finding, Lint

_MIN_AGE_RE = re.compile(r"^min-release-age=(?P<days>\d+)\s*$", re.MULTILINE)


def parse_min_age(npmrc_text: str) -> int | None:
    """The ``min-release-age`` value declared in an .npmrc, if any."""
    m = _MIN_AGE_RE.search(npmrc_text)
    return int(m.group("days")) if m else None


def _tracked(pattern: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", pattern, f"**/{pattern}"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return list(dict.fromkeys(out.stdout.split()))


def npm_project_dirs() -> list[str]:
    """Repo-relative dirs holding both a lockfile and a manifest.

    ``.`` for the repo root, matching the relative-path convention the
    rest of the lints report with.
    """
    manifests = {p.rsplit("/", 1)[0] if "/" in p else "." for p in _tracked("package.json")}
    locks = {p.rsplit("/", 1)[0] if "/" in p else "." for p in _tracked("package-lock.json")}
    return sorted(d for d in locks & manifests if not d.startswith("tests/"))


def check() -> list[Finding]:
    root_npmrc = REPO_ROOT / ".npmrc"
    required = (
        parse_min_age(root_npmrc.read_text(encoding="utf-8"))
        if root_npmrc.exists()
        else None
    )

    findings: list[Finding] = []
    for rel_dir in npm_project_dirs():
        base = REPO_ROOT if rel_dir == "." else REPO_ROOT / rel_dir
        npmrc = base / ".npmrc"
        where = ".npmrc" if rel_dir == "." else f"{rel_dir}/.npmrc"

        if not npmrc.exists():
            findings.append(
                Finding(
                    lint_id="npmrc-age-gate-coverage",
                    path=f"{where}",
                    message=(
                        f"npm project `{rel_dir}` has a package-lock.json but no "
                        "sibling .npmrc, so its installs resolve with no "
                        "min-release-age quarantine — npm reads only the "
                        "project's own .npmrc, never a parent's. Add "
                        f"`min-release-age={required}` (and `engine-strict=true`) "
                        "beside the lockfile."
                    ),
                )
            )
            continue

        declared = parse_min_age(npmrc.read_text(encoding="utf-8"))
        if declared is None:
            findings.append(
                Finding(
                    lint_id="npmrc-age-gate-coverage",
                    path=where,
                    message=(
                        "no `min-release-age` directive — this project's "
                        "installs resolve with the supply-chain quarantine "
                        f"disabled. Declare `min-release-age={required}`."
                    ),
                )
            )
        elif required is not None and declared < required:
            findings.append(
                Finding(
                    lint_id="npmrc-age-gate-coverage",
                    path=where,
                    message=(
                        f"min-release-age={declared} is weaker than the repo "
                        f"standard ({required}, from the root .npmrc). A nested "
                        "project may be stricter, never weaker."
                    ),
                )
            )
    return findings


LINT = Lint(
    id="npmrc-age-gate-coverage",
    description=(
        "every npm project needs its own .npmrc min-release-age — npm does "
        "not read a parent directory's."
    ),
    severity="blocking",
    autofix=False,
    check=check,
)
