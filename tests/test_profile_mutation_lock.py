"""Independent-process contracts for the shared Profile mutation lock."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hermes_constants import (
    profile_mutation_lock,
    profile_mutation_lock_path,
    profile_mutation_locks,
)


_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKER = r"""
import sys
import time
from pathlib import Path

from hermes_constants import profile_mutation_lock

profile_home = Path(sys.argv[1])
held = Path(sys.argv[2])
release = Path(sys.argv[3])
done = Path(sys.argv[4])

with profile_mutation_lock(profile_home, timeout=10):
    held.write_text("held\n", encoding="utf-8")
    while not release.exists():
        time.sleep(0.02)
    done.write_text("done\n", encoding="utf-8")
"""

_EDIT_WORKER = r"""
import json
import sys
from pathlib import Path

from tools.skill_manager_tool import _edit_skill

if len(sys.argv) > 2:
    Path(sys.argv[2]).write_text("ready\n", encoding="utf-8")
result = _edit_skill("demo", sys.argv[1])
print(json.dumps(result))
raise SystemExit(0 if result.get("success") else 2)
"""

_USAGE_WORKER = r"""
from tools.skill_usage import save_usage

save_usage({"demo": {"use_count": 1}})
"""

_SYNC_WORKER = r"""
import sys
from pathlib import Path

from tools.skills_sync import sync_skills

Path(sys.argv[1]).write_text("ready\n", encoding="utf-8")
result = sync_skills(quiet=True)
Path(sys.argv[2]).write_text(str(result), encoding="utf-8")
"""

_HUB_UNINSTALL_WORKER = r"""
import sys
from pathlib import Path

from tools.skills_hub import uninstall_skill

Path(sys.argv[1]).write_text("ready\n", encoding="utf-8")
result = uninstall_skill("demo")
Path(sys.argv[2]).write_text(repr(result), encoding="utf-8")
raise SystemExit(0 if result[0] else 2)
"""

_MULTI_LOCK_WORKER = r"""
import sys
import time
from pathlib import Path

from hermes_constants import profile_mutation_locks

homes = [Path(sys.argv[1]), Path(sys.argv[2])]
entered = Path(sys.argv[3])
done = Path(sys.argv[4])
with profile_mutation_locks(homes, timeout=5):
    entered.write_text("entered\n", encoding="utf-8")
    time.sleep(0.35)
    done.write_text("done\n", encoding="utf-8")
"""


def _wait_for(path: Path, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


def _spawn_worker(
    *,
    root: Path,
    profile_home: Path,
    held: Path,
    release: Path,
    done: Path,
) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["HERMES_HOME"] = str(root)
    env["PYTHONPATH"] = str(_REPO_ROOT)
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            _WORKER,
            str(profile_home),
            str(held),
            str(release),
            str(done),
        ],
        cwd=str(_REPO_ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _finish(proc: subprocess.Popen[str], *, timeout: float = 5.0) -> None:
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate(timeout=timeout)
        raise AssertionError(f"worker timed out\nstdout={stdout}\nstderr={stderr}")
    assert proc.returncode == 0, f"stdout={stdout}\nstderr={stderr}"


def test_agent_private_edit_waits_for_shared_profile_lock(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    skill_md = profile_home / "skills" / "demo" / "SKILL.md"
    skill_md.parent.mkdir(parents=True)
    original = "---\nname: demo\ndescription: Original.\n---\n\n# Demo\n"
    updated = "---\nname: demo\ndescription: Updated.\n---\n\n# Demo updated\n"
    skill_md.write_text(original, encoding="utf-8")

    env = os.environ.copy()
    env["HERMES_HOME"] = str(profile_home)
    env["PYTHONPATH"] = str(_REPO_ROOT)

    with profile_mutation_lock(profile_home, timeout=2):
        editor = subprocess.Popen(
            [sys.executable, "-c", _EDIT_WORKER, updated],
            cwd=str(_REPO_ROOT),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            time.sleep(0.4)
            assert editor.poll() is None, "Agent edit bypassed the shared Profile lock"
            assert skill_md.read_text(encoding="utf-8") == original
        finally:
            if editor.poll() is not None and editor.returncode != 0:
                stdout, stderr = editor.communicate()
                raise AssertionError(f"editor exited early\nstdout={stdout}\nstderr={stderr}")

    _finish(editor)
    assert skill_md.read_text(encoding="utf-8") == updated


def test_external_skill_edit_waits_for_shared_root_lock(tmp_path: Path) -> None:
    """Profiles sharing one external root must serialize real Skill edits."""
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    profile_home.mkdir(parents=True)
    external_root = tmp_path / "shared-skills"
    skill_md = external_root / "demo" / "SKILL.md"
    skill_md.parent.mkdir(parents=True)
    original = "---\nname: demo\ndescription: Original.\n---\n\n# Demo\n"
    updated = "---\nname: demo\ndescription: Updated.\n---\n\n# Demo updated\n"
    skill_md.write_text(original, encoding="utf-8")
    (profile_home / "config.yaml").write_text(
        "skills:\n  external_dirs:\n    - " + str(external_root) + "\n",
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["HERMES_HOME"] = str(profile_home)
    env["PYTHONPATH"] = str(_REPO_ROOT)
    ready = tmp_path / "external-editor-ready"

    with profile_mutation_lock(external_root, timeout=2):
        editor = subprocess.Popen(
            [sys.executable, "-c", _EDIT_WORKER, updated, str(ready)],
            cwd=str(_REPO_ROOT),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _wait_for(ready)
        try:
            time.sleep(0.2)
            assert editor.poll() is None, (
                "external Skill edit bypassed the shared root lock"
            )
            assert skill_md.read_text(encoding="utf-8") == original
        finally:
            if editor.poll() is not None and editor.returncode != 0:
                stdout, stderr = editor.communicate()
                raise AssertionError(
                    f"external editor exited early\nstdout={stdout}\nstderr={stderr}"
                )

    _finish(editor)
    assert skill_md.read_text(encoding="utf-8") == updated


def test_usage_writer_waits_for_shared_profile_lock(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    profile_home.mkdir(parents=True)
    usage_file = profile_home / "skills" / ".usage.json"

    env = os.environ.copy()
    env["HERMES_HOME"] = str(profile_home)
    env["PYTHONPATH"] = str(_REPO_ROOT)

    with profile_mutation_lock(profile_home, timeout=2):
        writer = subprocess.Popen(
            [sys.executable, "-c", _USAGE_WORKER],
            cwd=str(_REPO_ROOT),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            time.sleep(0.4)
            assert writer.poll() is None, "usage writer bypassed the shared Profile lock"
            assert not usage_file.exists()
        finally:
            if writer.poll() is not None and writer.returncode != 0:
                stdout, stderr = writer.communicate()
                raise AssertionError(f"usage writer exited early\nstdout={stdout}\nstderr={stderr}")

    _finish(writer)
    assert usage_file.is_file()


def test_bundled_sync_waits_for_shared_profile_lock(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    profile_home.mkdir(parents=True)
    bundled = tmp_path / "bundled"
    skill_md = bundled / "demo" / "SKILL.md"
    skill_md.parent.mkdir(parents=True)
    skill_md.write_text(
        "---\nname: demo\ndescription: Bundled.\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    ready = tmp_path / "sync-ready"
    done = tmp_path / "sync-done"

    env = os.environ.copy()
    env["HERMES_HOME"] = str(profile_home)
    env["HERMES_BUNDLED_SKILLS"] = str(bundled)
    env["PYTHONPATH"] = str(_REPO_ROOT)

    with profile_mutation_lock(profile_home, timeout=2):
        syncer = subprocess.Popen(
            [sys.executable, "-c", _SYNC_WORKER, str(ready), str(done)],
            cwd=str(_REPO_ROOT),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _wait_for(ready)
        try:
            time.sleep(0.4)
            assert syncer.poll() is None, "bundled sync bypassed the shared Profile lock"
            assert not done.exists()
            assert not (profile_home / "skills" / "demo" / "SKILL.md").exists()
        finally:
            if syncer.poll() is not None and syncer.returncode != 0:
                stdout, stderr = syncer.communicate()
                raise AssertionError(f"sync exited early\nstdout={stdout}\nstderr={stderr}")

    _finish(syncer)
    assert done.is_file()
    assert (profile_home / "skills" / "demo" / "SKILL.md").is_file()


def test_hub_uninstall_waits_for_shared_profile_lock(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    skill_md = profile_home / "skills" / "demo" / "SKILL.md"
    skill_md.parent.mkdir(parents=True)
    skill_md.write_text(
        "---\nname: demo\ndescription: Installed.\n---\n\n# Demo\n",
        encoding="utf-8",
    )
    lock_file = profile_home / "skills" / ".hub" / "lock.json"
    lock_file.parent.mkdir(parents=True)
    lock_file.write_text(
        '{"version": 1, "installed": {"demo": {'
        '"source": "test", "trust_level": "community", '
        '"install_path": "demo"}}}\n',
        encoding="utf-8",
    )
    ready = tmp_path / "hub-ready"
    done = tmp_path / "hub-done"

    env = os.environ.copy()
    env["HERMES_HOME"] = str(profile_home)
    env["PYTHONPATH"] = str(_REPO_ROOT)

    with profile_mutation_lock(profile_home, timeout=2):
        uninstaller = subprocess.Popen(
            [sys.executable, "-c", _HUB_UNINSTALL_WORKER, str(ready), str(done)],
            cwd=str(_REPO_ROOT),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _wait_for(ready)
        try:
            time.sleep(0.4)
            assert uninstaller.poll() is None, "Hub uninstall bypassed the shared Profile lock"
            assert skill_md.is_file()
            assert "demo" in lock_file.read_text(encoding="utf-8")
            assert not done.exists()
        finally:
            if uninstaller.poll() is not None and uninstaller.returncode != 0:
                stdout, stderr = uninstaller.communicate()
                raise AssertionError(f"uninstall exited early\nstdout={stdout}\nstderr={stderr}")

    _finish(uninstaller)
    assert done.is_file()
    assert not skill_md.parent.exists()
    assert "demo" not in lock_file.read_text(encoding="utf-8")


def test_multi_profile_locks_sort_canonical_identities_across_processes(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_a = root / "profiles" / "a"
    profile_b = root / "profiles" / "b"
    profile_a.mkdir(parents=True)
    profile_b.mkdir(parents=True)
    entered_ab = tmp_path / "entered-ab"
    entered_ba = tmp_path / "entered-ba"
    done_ab = tmp_path / "done-ab"
    done_ba = tmp_path / "done-ba"

    env = os.environ.copy()
    env["HERMES_HOME"] = str(root)
    env["PYTHONPATH"] = str(_REPO_ROOT)
    first = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _MULTI_LOCK_WORKER,
            str(profile_a),
            str(profile_b),
            str(entered_ab),
            str(done_ab),
        ],
        cwd=str(_REPO_ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    second = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _MULTI_LOCK_WORKER,
            str(profile_b),
            str(profile_a),
            str(entered_ba),
            str(done_ba),
        ],
        cwd=str(_REPO_ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _finish(first, timeout=7)
        _finish(second, timeout=7)
    finally:
        for proc in (first, second):
            if proc.poll() is None:
                proc.kill()
                proc.communicate()

    assert entered_ab.is_file()
    assert entered_ba.is_file()
    assert done_ab.is_file()
    assert done_ba.is_file()


def test_multi_profile_locks_deduplicate_aliases(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile = root / "profiles" / "demo"
    profile.mkdir(parents=True)
    alias = profile / ".." / "demo"
    with profile_mutation_locks([profile, alias], timeout=1) as homes:
        assert homes == (profile.resolve(),)


def test_same_profile_serializes_independent_processes(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    profile_home.mkdir(parents=True)

    held_a = tmp_path / "held-a"
    release_a = tmp_path / "release-a"
    done_a = tmp_path / "done-a"
    held_b = tmp_path / "held-b"
    release_b = tmp_path / "release-b"
    done_b = tmp_path / "done-b"

    first = _spawn_worker(
        root=root,
        profile_home=profile_home,
        held=held_a,
        release=release_a,
        done=done_a,
    )
    try:
        _wait_for(held_a)
        assert first.poll() is None

        second = _spawn_worker(
            root=root,
            profile_home=profile_home,
            held=held_b,
            release=release_b,
            done=done_b,
        )
        try:
            time.sleep(0.35)
            assert second.poll() is None
            assert not held_b.exists(), "second writer entered the same Profile lock"

            release_a.write_text("release\n", encoding="utf-8")
            _wait_for(held_b)
            release_b.write_text("release\n", encoding="utf-8")
            _finish(first)
            _finish(second)
        finally:
            if second.poll() is None:
                second.kill()
                second.communicate()
    finally:
        if first.poll() is None:
            first.kill()
            first.communicate()


def test_path_aliases_share_one_lock_identity(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    profile_home.mkdir(parents=True)
    alias = tmp_path / "profile-alias"
    try:
        alias.symlink_to(profile_home, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")

    assert profile_mutation_lock_path(profile_home) == profile_mutation_lock_path(alias)
    assert profile_mutation_lock_path(profile_home) == profile_mutation_lock_path(
        profile_home / ".." / "demo"
    )


def test_visible_lock_path_replacement_does_not_split_lock_domain(
    tmp_path: Path,
) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    profile_home.mkdir(parents=True)
    held_a = tmp_path / "held-a"
    release_a = tmp_path / "release-a"
    holder = _spawn_worker(
        root=root,
        profile_home=profile_home,
        held=held_a,
        release=release_a,
        done=tmp_path / "done-a",
    )
    contender = None
    try:
        _wait_for(held_a)
        lock_path = profile_mutation_lock_path(profile_home)
        displaced = lock_path.with_suffix(".displaced")
        lock_path.rename(displaced)
        lock_path.touch(mode=0o600)
        assert lock_path.stat().st_ino != displaced.stat().st_ino

        held_b = tmp_path / "held-b"
        release_b = tmp_path / "release-b"
        contender = _spawn_worker(
            root=root,
            profile_home=profile_home,
            held=held_b,
            release=release_b,
            done=tmp_path / "done-b",
        )
        time.sleep(0.35)
        assert contender.poll() is None
        assert not held_b.exists(), "replacement created a split Profile lock domain"

        release_a.write_text("release\n", encoding="utf-8")
        _wait_for(held_b)
        release_b.write_text("release\n", encoding="utf-8")
        _finish(holder)
        _finish(contender)
    finally:
        release_a.write_text("release\n", encoding="utf-8")
        if contender is not None:
            release_b.write_text("release\n", encoding="utf-8")
        for proc in (holder, contender):
            if proc is None:
                continue
            try:
                proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()


def test_absent_profile_becoming_symlink_keeps_one_lock_domain(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profiles_root = root / "profiles"
    profiles_root.mkdir(parents=True)
    profile_home = profiles_root / "demo"
    target = tmp_path / "target-profile"
    target.mkdir()
    held_a = tmp_path / "held-a"
    release_a = tmp_path / "release-a"
    holder = _spawn_worker(
        root=root,
        profile_home=profile_home,
        held=held_a,
        release=release_a,
        done=tmp_path / "done-a",
    )
    contender = None
    try:
        _wait_for(held_a)
        try:
            profile_home.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("directory symlinks unavailable")

        held_b = tmp_path / "held-b"
        release_b = tmp_path / "release-b"
        contender = _spawn_worker(
            root=root,
            profile_home=profile_home,
            held=held_b,
            release=release_b,
            done=tmp_path / "done-b",
        )
        time.sleep(0.35)
        assert contender.poll() is None
        assert not held_b.exists(), "Profile path identity drift split the lock domain"

        release_a.write_text("release\n", encoding="utf-8")
        _wait_for(held_b)
        release_b.write_text("release\n", encoding="utf-8")
        _finish(holder)
        _finish(contender)
    finally:
        release_a.write_text("release\n", encoding="utf-8")
        if contender is not None:
            release_b.write_text("release\n", encoding="utf-8")
        for proc in (holder, contender):
            if proc is None:
                continue
            try:
                proc.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()


def test_lock_timeout_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    profile_home.mkdir(parents=True)

    held = tmp_path / "held"
    release = tmp_path / "release"
    done = tmp_path / "done"
    holder = _spawn_worker(
        root=root,
        profile_home=profile_home,
        held=held,
        release=release,
        done=done,
    )
    try:
        _wait_for(held)
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            with profile_mutation_lock(profile_home, timeout=0.2):
                raise AssertionError("contender entered a held Profile lock")
        assert time.monotonic() - started >= 0.15
    finally:
        release.write_text("release\n", encoding="utf-8")
        _finish(holder)


@pytest.mark.live_system_guard_bypass
@pytest.mark.skipif(os.name == "nt" or not hasattr(signal, "SIGKILL"), reason="POSIX SIGKILL contract")
def test_sigkill_releases_kernel_lock_without_stale_cleanup(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_home = root / "profiles" / "demo"
    profile_home.mkdir(parents=True)

    held_a = tmp_path / "held-a"
    holder = _spawn_worker(
        root=root,
        profile_home=profile_home,
        held=held_a,
        release=tmp_path / "never-release",
        done=tmp_path / "never-done",
    )
    try:
        _wait_for(held_a)
        lock_path = profile_mutation_lock_path(profile_home)
        assert lock_path.is_file()

        os.kill(holder.pid, signal.SIGKILL)
        holder.wait(timeout=5)
        assert holder.returncode == -signal.SIGKILL
        assert lock_path.is_file(), "kernel locks do not require stale-file deletion"

        held_b = tmp_path / "held-b"
        release_b = tmp_path / "release-b"
        successor = _spawn_worker(
            root=root,
            profile_home=profile_home,
            held=held_b,
            release=release_b,
            done=tmp_path / "done-b",
        )
        try:
            _wait_for(held_b, timeout=1.5)
            release_b.write_text("release\n", encoding="utf-8")
            _finish(successor)
        finally:
            if successor.poll() is None:
                successor.kill()
                successor.communicate()
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.communicate()


def test_different_profiles_do_not_block_each_other(tmp_path: Path) -> None:
    root = tmp_path / "hermes"
    profile_a = root / "profiles" / "alpha"
    profile_b = root / "profiles" / "beta"
    profile_a.mkdir(parents=True)
    profile_b.mkdir(parents=True)

    held_a = tmp_path / "held-a"
    release_a = tmp_path / "release-a"
    done_a = tmp_path / "done-a"
    held_b = tmp_path / "held-b"
    release_b = tmp_path / "release-b"
    done_b = tmp_path / "done-b"

    first = _spawn_worker(
        root=root,
        profile_home=profile_a,
        held=held_a,
        release=release_a,
        done=done_a,
    )
    second = None
    try:
        _wait_for(held_a)
        second = _spawn_worker(
            root=root,
            profile_home=profile_b,
            held=held_b,
            release=release_b,
            done=done_b,
        )
        _wait_for(held_b, timeout=1.5)
        assert first.poll() is None
        assert second.poll() is None

        release_a.write_text("release\n", encoding="utf-8")
        release_b.write_text("release\n", encoding="utf-8")
        _finish(first)
        _finish(second)
    finally:
        for proc in (first, second):
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.communicate()
