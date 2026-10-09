"""M6 "L2b for code": the baked-code manifest is the honest, fail-closed recorded floor for scripts/kontroll/.

WHY (the failures these guard): Phase B bakes the importable package scripts/kontroll/ into the published,
world-pullable control image at /opt/kontroll, so the network services run their actuation code from the
digest-pinned image. docker/code-manifest.lock.yml is the recorded sha256 floor for that package — the code-world
analogue of L2b's collection-tarball floor. These tests guard: (1) the committed floor silently drifting from the
source that gets baked (validate/publish would publish code the reviewed manifest doesn't describe); (2) the
generator silently UN-COVERING a newly-added baked file (a hole in the floor); (3) the --check / --verify gates
failing OPEN on a tampered tree instead of fail-closed. The covering gate is `gen-code-manifest.py --check` in
validate.sh + the publish-images `gate` job (phase-b synthesis §3).
"""
import importlib.util
import os
import shutil

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load():
    """Import the hyphenated generator as a module (the repo idiom for scripts/<x>-<y>.py)."""
    spec = importlib.util.spec_from_file_location(
        "gen_code_manifest", os.path.join(ROOT, "scripts", "gen-code-manifest.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gcm = _load()


def test_committed_lock_is_in_sync_with_the_source_package():
    """The committed docker/code-manifest.lock.yml must EQUAL a fresh hash of scripts/kontroll/ — so the recorded
    floor is an honest description of exactly the code bytes that get baked into the control image on this commit.
    This is the same comparison validate + the publish gate run via --check; pinning it here makes a forgotten
    regenerate (after editing scripts/kontroll/) fail in the unit suite, not only in validate."""
    problems = gcm.diff(gcm.load(), gcm.compute())
    assert problems == [], "code-manifest.lock.yml is stale — run `python3 scripts/gen-code-manifest.py`: %r" % problems


def test_manifest_covers_exactly_the_baked_python_no_omission():
    """The recorded floor must enumerate EXACTLY the set of scripts/kontroll/**/*.py on disk — no file omitted (a
    hole a tamper could hide in) and none recorded that no longer exists. Independently re-walks the tree (not via
    the generator's own compute) so a bug in the walk can't make both sides agree on the wrong set."""
    pkg = os.path.join(ROOT, "scripts", "kontroll")
    expected = set()
    for dirpath, dirnames, filenames in os.walk(pkg):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in filenames:
            if name.endswith(".py"):
                rel = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
                expected.add(rel)
    assert set(gcm.load()) == expected, "the manifest must cover exactly scripts/kontroll/**/*.py (no omission/extra)"


def test_check_fails_closed_on_a_changed_file(tmp_path):
    """A byte-changed file under a recorded pin must surface as CHANGED (fail-closed) — the tamper-evidence the floor
    exists for. Copies the real package into a tmp tree, mutates one file, and asserts compute(tmp) diffed against the
    committed floor reports CHANGED for it (this is exactly what `--verify <baked-tree>` does on a drifted image)."""
    shutil.copytree(os.path.join(ROOT, "scripts", "kontroll"), tmp_path / "scripts" / "kontroll")
    victim = tmp_path / "scripts" / "kontroll" / "paths.py"
    victim.write_text(victim.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
    problems = gcm.diff(gcm.load(), gcm.compute(str(tmp_path)))
    assert any("CHANGED" in p and "paths.py" in p for p in problems), \
        "a byte-changed baked file must fail closed as CHANGED, not pass silently: %r" % problems


def test_verify_and_check_main_exit_nonzero_on_tamper(tmp_path):
    """The CLI verbs must EXIT NONZERO on drift, not just return a list — so the validate step + the publish gate
    actually fail the build. --verify against a tree with an ADDED file (a stray module a compromise dropped in)
    must SystemExit(1); --check against the real source must return cleanly (exit 0)."""
    shutil.copytree(os.path.join(ROOT, "scripts", "kontroll"), tmp_path / "scripts" / "kontroll")
    (tmp_path / "scripts" / "kontroll" / "evil.py").write_text("# stray\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        gcm.main(["--verify", str(tmp_path)])
    assert exc.value.code == 1, "--verify must fail closed (exit 1) when the tree has an un-recorded file"
    # --check against the real, in-sync source tree must succeed (returns None, no SystemExit).
    assert gcm.main(["--check"]) is None
