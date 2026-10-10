"""The G9 onboard-gui age-key gate accepts exactly the states that actually work, and its refusal is actionable.

G9 is deliberately fail-closed: deploy-stack never mints the GUI's age key, because a service that can create its
own decryption key is not a trust boundary. That part is right and these tests do not challenge it.

What was wrong was everything around it (live-caught 2026-07-28, fresh-box spin-up):

  1. The gate was a bare `failed_when: not stat.exists` with no `fail_msg`, so the operator got Ansible's generic
     failure plus a stat dict — a correct refusal that does not say what to put there. Spin-up friction is not a
     cosmetic problem for a "floating" instance whose whole premise is being rebuilt often.
  2. "Exists" was never the real precondition. The GUI runs as uid 1001 and mounts the key `:ro`, so a root-owned
     0600 key PASSES an exists-check and then fails at runtime as an opaque SOPS decrypt error, one deploy later
     and far from the cause.

Rather than string-match the playbook, these evaluate the gate's real Jinja against synthetic stat results — so
they test the condition's BEHAVIOUR, including the deliberate other-readable escape hatch that keeps a box which
already works that way from being newly broken.
"""
import os
import re

import jinja2
import pytest
import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEPLOY = os.path.join(_ROOT, "ansible", "playbooks", "deploy-stack.yml")
_GUI_DIR = "/var/lib/kontroll/onboard-gui"


def _tasks(node):
    if isinstance(node, list):
        for item in node:
            yield from _tasks(item)
    elif isinstance(node, dict):
        yield node
        for key in ("block", "rescue", "always", "tasks", "pre_tasks", "post_tasks"):
            if key in node:
                yield from _tasks(node[key])


def _gate():
    with open(_DEPLOY, encoding="utf-8") as fh:
        for task in _tasks(yaml.safe_load(fh.read())):
            if "the actual remedy" in str(task.get("name", "")):
                return task["ansible.builtin.assert"]
    raise AssertionError("the G9 remedy assert is gone — if the gate moved, move this test with it")


def _evaluate(stat):
    """Run the gate's real `that:` expressions against a synthetic stat result; return (passed, message)."""
    gate = _gate()
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    ctx = {"_gui_age_key": {"stat": stat}, "kontroll_gui_dir": _GUI_DIR}
    for expr in gate["that"]:
        if not env.compile_expression(expr)(**ctx):
            return False, env.from_string(gate["fail_msg"]).render(**ctx)
    return True, ""


# (label, stat, should_pass)
_CASES = [
    ("missing entirely", {"exists": False, "uid": 0, "roth": False}, False),
    ("present and owned by the runtime uid", {"exists": True, "uid": 1001, "roth": False}, True),
    ("present but root-owned 0600 — the runtime uid cannot read it", {"exists": True, "uid": 0, "roth": False}, False),
    ("present, root-owned, but other-readable", {"exists": True, "uid": 0, "roth": True}, True),
]


@pytest.mark.parametrize("label,stat,should_pass", _CASES, ids=[c[0] for c in _CASES])
def test_the_gate_admits_exactly_the_states_that_work(label, stat, should_pass):
    """A key uid 1001 can actually read is the real precondition — not merely a file that exists. The last case is
    the deliberate escape hatch: other-readable is sloppy but it genuinely works, and a hardening check that
    breaks a running box on the next deploy teaches operators to skip deploys."""
    passed, _ = _evaluate(stat)
    assert passed is should_pass, "gate %s for: %s" % ("passed" if passed else "refused", label)


def test_the_refusal_distinguishes_missing_from_unreadable():
    """Two different problems with two different fixes (put a key there vs. chown the one that is there). One
    generic message would send the operator down the wrong path for whichever case they hit."""
    _, missing = _evaluate({"exists": False, "uid": 0, "roth": False})
    _, unreadable = _evaluate({"exists": True, "uid": 0, "roth": False})
    assert "MISSING" in missing
    assert "not readable" in unreadable
    assert missing != unreadable


def test_the_refusal_carries_a_remedy_that_runs():
    """The whole point of the change. The message must contain a concrete command with the real target path — not
    a pointer to a doc — because this fires mid-deploy on a box the operator is standing up for the first time."""
    _, msg = _evaluate({"exists": False, "uid": 0, "roth": False})
    assert "%s/age.key" % _GUI_DIR in msg, "the remedy must name the actual destination path"
    assert "install -m 0600 -o 1001 -g 1001" in msg, "the remedy must set the ownership the gate itself requires"
    assert "~/.config/sops/age/keys.txt" in msg, "and name the source: the control key (the accepted C10 residual)"


def test_the_doc_pointer_in_the_refusal_actually_resolves():
    """The message cites a SETUP.md section, and the first draft cited the wrong one (§5 is secrets; the
    onboard-gui prerequisite is §6) — a pointer that sends the operator to an unrelated section is worse than no
    pointer, and section numbers move. Assert the cited heading exists verbatim in the doc."""
    _, msg = _evaluate({"exists": False, "uid": 0, "roth": False})
    cited = re.search(r'docs/SETUP\.md "([^"]+)"', msg)
    assert cited, "the refusal should cite a SETUP.md section by NAME (numbers renumber, headings survive)"
    with open(os.path.join(_ROOT, "docs", "SETUP.md"), encoding="utf-8") as fh:
        setup = fh.read()
    assert ("## %s" % cited.group(1)) in setup, \
        "the refusal points at SETUP.md %r, which has no such heading" % cited.group(1)


def test_the_setup_doc_and_the_refusal_agree_on_the_remedy():
    """Two places now tell the operator how to provision this key. If they drift, one of them teaches a command
    that does not produce a key the gate accepts — and the doc is the one people find first."""
    with open(os.path.join(_ROOT, "docs", "SETUP.md"), encoding="utf-8") as fh:
        setup = fh.read()
    assert "install -m 0600 -o 1001 -g 1001" in setup, \
        "SETUP.md must carry the same ownership the gate requires and the refusal prints"


def test_the_refusal_still_refuses_to_mint_the_key():
    """The boundary this gate exists for. Making the refusal friendlier must never slide into auto-provisioning:
    a deploy that can create the GUI's decryption key has dissolved the separation the key represents."""
    with open(_DEPLOY, encoding="utf-8") as fh:
        text = fh.read()
    block = text.split("Stat the onboard-gui age key", 1)[1].split("Generate a self-signed TLS cert", 1)[0]
    assert "age-keygen" not in block.replace("`age-keygen` a", ""), \
        "the gate must not mint a key — age-keygen may appear only as advice inside the refusal text"
    _, msg = _evaluate({"exists": False, "uid": 0, "roth": False})
    assert "never creates it" in msg, "the message should say plainly that this is a boundary, not a bug"
