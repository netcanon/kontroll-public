"""#134 / P0b — the fail-CLOSED read-only completeness gate.

`assert_read_only` (#132/#133) and `assert_no_git_write` (#131) both fail OPEN: each checks a function's calls
against `WRITE_VERBS`, so a mutator the registry *doesn't know about* is invisible — a read view could call an
unregistered writer and the pin would pass. That silently erodes the read-only / C10 two-key guarantee.

These tests pin the closure: `assert_write_verbs_complete` (every DIRECT mutator in the service+gitio layer is
registered) + `assert_write_verbs_resolve` (no dead/typo'd entry). They make "add every new write verb to
WRITE_VERBS in the same commit" an ENFORCED gate, not a human convention. The detection engine (`_is_direct_mutator`)
and the end-to-end gate are both proven against PLANTED violations so the gate can't silently no-op.
"""
import ast
import textwrap

import pytest

import _readonly_pins
from _readonly_pins import assert_write_verbs_complete, assert_write_verbs_resolve

pytestmark = pytest.mark.unit


def _fn(src):
    """Parse a single-function source snippet → its FunctionDef node (for testing the detection engine directly)."""
    return next(n for n in ast.walk(ast.parse(textwrap.dedent(src))) if isinstance(n, ast.FunctionDef))


def test_detection_flags_every_write_primitive_and_no_read():
    """`_is_direct_mutator` (the engine under the gate) flags each DIRECT write primitive — a write-mode open, a
    `git commit`/`push`/`update-ref` argv (incl. the `["git","add"] + paths` BinOp form), a `sops --set`, a named
    sops-write call — and does NOT flag a pure read (`open(...,'r')`, `git log`, `sops --decrypt`, the dual-use
    `git remote get-url`, a pure return). This is the proof the gate FAILS CLOSED on a new unregistered writer
    while NOT false-positiving a read helper (the `git remote get-url` case is the real gitio.offsite_remote_exists
    shape that a naive git-write blacklist would mis-flag)."""
    mutators = {
        "open_w":            "def f():\n    with open('x', 'w') as fh: fh.write('a')",
        "open_a_kw":         "def f():\n    open('x', mode='a')",
        "git_commit":        "def f():\n    _run(['git', 'commit', '-m', 'x'])",
        "git_add_binop":     "def f(p):\n    _run(['git', 'add'] + list(p))",
        "git_update_ref":    "def f(ref):\n    subprocess.run(['git', 'update-ref', 'refs/heads/main', ref])",
        "git_reset":         "def f():\n    _run(['git', 'reset', '--hard', 'local/main'])",
        "sops_set_argv":     "def f(path):\n    subprocess.run(['sops', '--set', '[\"k\"] 1', path])",
        "sops_encrypt_argv": "def f(path):\n    subprocess.run(['sops', '--encrypt', path])",
        "sops_rotate_argv":  "def f(path):\n    subprocess.run(['sops', '--rotate', '--in-place', path])",
        "sops_named_call":   "def f(d, m):\n    gitio.sops_write_domain(d, m)",
        "path_write_text":   "def f(p, s):\n    pathlib.Path(p).write_text(s)",
        "shutil_rmtree":     "def f(d):\n    shutil.rmtree(d)",
        "path_open_w":       "def f(p):\n    with pathlib.Path(p).open('w') as fh: fh.write('x')",  # attr-form open, mode-gated
        "os_replace":        "def f(a, b):\n    os.replace(a, b)",         # the atomic-write idiom, receiver-qualified
        "shutil_move":       "def f(a, b):\n    shutil.move(a, b)",
    }
    for key, src in mutators.items():
        assert _readonly_pins._is_direct_mutator(_fn(src)) is True, "engine MISSED a writer: %s" % key
    reads = {
        "open_r_default":    "def f():\n    return open('x').read()",
        "open_rb":           "def f():\n    open('x', 'rb')",
        "git_log":           "def f():\n    _run(['git', 'log', '--oneline'])",
        "git_remote_geturl": "def f():\n    subprocess.run(['git', 'remote', 'get-url', 'origin'])",
        "git_merge_base":    "def f(ref):\n    _run(['git', 'merge-base', '--is-ancestor', 'main', ref])",
        "sops_decrypt":      "def f(path):\n    subprocess.run(['sops', '--decrypt', path])",
        "pure":              "def f(a):\n    return a + 1",
        # the deliberate exclusions — these method NAMES are ubiquitous on reads, so they must NOT flag (else every
        # read view false-positives). The receiver-qualified os.*/shutil.* detection keeps them safe.
        "str_replace":       "def f(s):\n    return s.replace('a', 'b')",     # NOT os.replace — a str method
        "dict_copy":         "def f(d):\n    return d.copy()",                # NOT shutil.copy — a dict method
        "list_remove":       "def f(xs, x):\n    xs.remove(x); return xs",    # NOT os.remove — a list method
        "os_path_join":      "def f(a, b):\n    return os.path.join(a, b)",   # receiver is os.path, not os → not a write
        "path_open_read":    "def f(p):\n    return pathlib.Path(p).open().read()",  # attr-form open, NO write mode
    }
    for key, src in reads.items():
        assert _readonly_pins._is_direct_mutator(_fn(src)) is False, "engine FALSE-POSITIVE on a read: %s" % key


def test_detection_attributes_a_write_to_the_nested_scope_not_the_parent():
    """A write inside a NESTED function belongs to that nested scope, not the enclosing one — `_own_nodes` stops at
    the nested `def`. Guards against a parent being mis-flagged (false positive) because it merely DEFINES a writer
    it never calls; the nested writer is caught on its own (visited as its own FunctionDef by the gate's walk)."""
    src = "def outer():\n    def inner():\n        open('x', 'w')\n    return inner"
    tree = ast.parse(src)
    outer = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "outer")
    inner = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "inner")
    assert _readonly_pins._is_direct_mutator(outer) is False   # outer only DEFINES inner — not a direct mutator
    assert _readonly_pins._is_direct_mutator(inner) is True    # inner is the writer


def test_write_verbs_complete_on_the_real_tree():
    """Every DIRECT mutator in the real service+gitio layer is registered in WRITE_VERBS (or the documented
    WRITE_COMPLETENESS_ALLOWLIST). THE fail-CLOSED #134/P0b gate: a new file-writer / git-writer / sops-writer that
    isn't registered breaks CI here, so assert_read_only stays exhaustive and the read-only/C10 guarantee holds."""
    assert_write_verbs_complete()


def test_write_verbs_resolve_no_rot():
    """Every WRITE_VERBS entry resolves to a real `def` under scripts/ (or is a bare git verb guarding a
    git-library call) — no typo / dead-after-rename entry silently weakens the pin."""
    assert_write_verbs_resolve()


def test_gate_fires_on_an_unregistered_writer(monkeypatch, tmp_path):
    """End-to-end proof the GATE fails closed: point the scan at a throwaway service layer holding an UNREGISTERED
    write-open function → `assert_write_verbs_complete` RAISES, naming `file:func`. Guards a refactor that makes the
    scan silently no-op (the worst failure for a fail-closed gate — passing while blind)."""
    svc = tmp_path / "scripts" / "kontroll" / "service"
    svc.mkdir(parents=True)
    (svc.parent / "gitio.py").write_text("", encoding="utf-8")     # the gate also reads gitio.py; keep it empty
    (svc / "sneaky.py").write_text("def sneaky_write(p):\n    open(p, 'w').write('x')\n", encoding="utf-8")
    monkeypatch.setattr(_readonly_pins, "ROOT", str(tmp_path))
    with pytest.raises(AssertionError, match="sneaky_write"):
        assert_write_verbs_complete()
