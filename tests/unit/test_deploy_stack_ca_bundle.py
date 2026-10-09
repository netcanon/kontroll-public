"""deploy-stack.yml device-CA-bundle / file_tail known_hosts: the no-pin DEFAULT still writes a valid file.

WHY (the failure this guards — caught LIVE during the #119 prod cutover): each bundle is written by
`ansible.builtin.copy` with `content` cat'd from the operator's `device_trust` pins. With NO CA / host key pinned
— the DEFAULT `self_signed` / no-`device_trust` posture (e.g. the genericization-era prod `instance.yml`, which
has no `device_trust:` block at all) — a single `{% for %}` task renders `content` to `""`, and copy treats an
empty string as ABSENT: it fails the WHOLE deploy with `src (or content) is required` the moment
`prometheus`/`vector` is in `stack_services`. (A naive trailing-literal-newline fix is also dead — Ansible's Jinja
`trim_blocks=True` strips the newline right after `{% endfor %}`.) The fix SPLITS each bundle into a pinned-case
loop task (`when … length > 0`) and a no-pin task that writes a literal single-newline file (`when … length == 0`),
so the default always writes a valid (whitespace-only) file. These pins assert the no-pin task exists per bundle
and its content is non-empty — so a no-pin instance can never again hit the empty-`content` deploy failure.
"""
import os

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEPLOY = os.path.join(ROOT, "ansible", "playbooks", "deploy-stack.yml")
_COPY_KEYS = ("ansible.builtin.copy", "copy")


def _all_tasks():
    plays = yaml.safe_load(open(DEPLOY, encoding="utf-8"))
    tasks = []
    for play in plays if isinstance(plays, list) else []:
        if not isinstance(play, dict):
            continue
        for section in ("pre_tasks", "tasks", "post_tasks"):
            tasks += play.get(section) or []
    return tasks


def _copy_tasks_for(dest_suffix):
    """(content, when-as-text) for every copy task writing a dest ending in dest_suffix."""
    out = []
    for t in _all_tasks():
        if not isinstance(t, dict):
            continue
        cp = next((t[k] for k in _COPY_KEYS if isinstance(t.get(k), dict)), None)
        if not cp or not str(cp.get("dest", "")).endswith(dest_suffix):
            continue
        when = t.get("when")
        when = " ".join(when) if isinstance(when, list) else str(when or "")
        out.append((cp.get("content"), when))
    return out


@pytest.mark.parametrize("dest_suffix", ["device-ca-bundle.pem", "file_tail_known_hosts"])
def test_no_pin_case_writes_a_non_empty_bundle(dest_suffix):
    """Each pin-bundle has a copy task gated on the EMPTY pin set (`when … length == 0`) whose `content` is
    NON-empty — so the no-pin default (no `device_trust`) writes a valid file instead of failing copy `src (or
    content) is required`. Guards the live #119 cutover regression (the empty-`content` + Ansible-2.19 trap)."""
    tasks = _copy_tasks_for(dest_suffix)
    assert tasks, "no copy task writes %s" % dest_suffix
    empties = [content for content, when in tasks if "length == 0" in when or "not " in when]
    assert empties, "no EMPTY-pin-case (length == 0) copy task for %s — the no-pin default would fail copy" % dest_suffix
    for content in empties:
        assert content not in (None, ""), \
            "the no-pin %s task must write NON-empty content (copy rejects ''); got %r" % (dest_suffix, content)


@pytest.mark.parametrize("dest_suffix", ["device-ca-bundle.pem", "file_tail_known_hosts"])
def test_pinned_case_task_is_gated_on_a_non_empty_pin_set(dest_suffix):
    """The loop (pinned) task is gated `when … length > 0`, so it never runs with an empty list (which is the
    case that rendered ""). Guards a regression that drops the guard and reintroduces the empty-content failure."""
    tasks = _copy_tasks_for(dest_suffix)
    loop_tasks = [(content, when) for content, when in tasks if content and "{% for" in content]
    assert loop_tasks, "expected a {%% for %%}-loop (pinned) copy task for %s" % dest_suffix
    for content, when in loop_tasks:
        assert "length > 0" in when, \
            "the loop task for %s must be gated `length > 0` (else it renders '' on no pins); when=%r" % (dest_suffix, when)
