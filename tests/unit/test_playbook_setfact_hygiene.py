"""No `set_fact` key may reference another key set by the SAME task.

Ansible templates every key of a single `set_fact` against the context as it was BEFORE the task ran. So this
looks entirely reasonable and fails at runtime:

    ansible.builtin.set_fact:
      _requested_services: "{{ stack_services | reject(...) | list }}"
      _up_services:        "{{ _requested_services + [...] }}"   # '_requested_services' is undefined

Live-caught 2026-07-28 on the floating-prod build, in exactly that shape. What makes it worth a guard rather
than a lesson is how far it travelled: `ansible-playbook --syntax-check` passed, `ansible-lint` passed at
production profile, and the unit tests covering the expressions passed too — because they evaluated the two
Jinja strings with the intermediate injected, which is precisely what Ansible does not do. Everything that
parses rather than evaluates was happy. Only the deploy failed.

The fix is always the same and always cheap: make the intermediate a task `vars:` entry, which IS in scope for
module args. This sweeps every playbook so the next one is caught in CI instead of on a control node mid-deploy.
"""
import os
import re

import pytest
import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PLAYBOOKS = os.path.join(_ROOT, "ansible", "playbooks")


def _playbooks():
    return sorted(f for f in os.listdir(_PLAYBOOKS) if f.endswith((".yml", ".yaml")))


def _tasks(node):
    if isinstance(node, list):
        for item in node:
            yield from _tasks(item)
    elif isinstance(node, dict):
        yield node
        for key in ("block", "rescue", "always", "tasks", "pre_tasks", "post_tasks", "handlers"):
            if key in node:
                yield from _tasks(node[key])


def _self_references(task):
    """(key, sibling) pairs where a set_fact key's Jinja names another key of the same set_fact."""
    fact = task.get("ansible.builtin.set_fact") or task.get("set_fact")
    if not isinstance(fact, dict):
        return []
    # cacheable is a set_fact OPTION, not a fact being defined
    keys = [k for k in fact if k != "cacheable"]
    found = []
    for key in keys:
        text = str(fact[key])
        for other in keys:
            if other == key:
                continue
            if re.search(r"(?<![\w.])%s\b" % re.escape(other), text):
                found.append((key, other))
    return found


@pytest.mark.parametrize("name", _playbooks())
def test_no_set_fact_key_references_a_sibling_key(name):
    """The regression, swept across every playbook. A sibling reference is undefined at render time, so this is
    always a bug — not a style preference — and the failure only ever shows up on a real run."""
    with open(os.path.join(_PLAYBOOKS, name), encoding="utf-8") as fh:
        doc = yaml.safe_load(fh.read())
    offenders = []
    for task in _tasks(doc):
        for key, other in _self_references(task):
            offenders.append("%s: set_fact '%s' references sibling '%s' (undefined at render — make '%s' a "
                             "task var)" % (task.get("name", "<unnamed>"), key, other, other))
    assert not offenders, "%s\n  %s" % (name, "\n  ".join(offenders))


def test_the_scanner_actually_catches_a_planted_sibling_reference():
    """A sweep that has never been observed to fail proves nothing — this plants the exact live-caught shape and
    requires the detector to flag it."""
    planted = {
        "name": "planted",
        "ansible.builtin.set_fact": {
            "_requested_services": "{{ stack_services | reject('equalto', 'x') | list }}",
            "_up_services": "{{ _requested_services + ['caddy'] }}",
        },
    }
    assert ("_up_services", "_requested_services") in _self_references(planted)


def test_the_scanner_does_not_flag_an_unrelated_name_or_a_substring():
    """Guards the guard against noise, which is how a sweep gets disabled: a key that merely CONTAINS another
    key's name as a substring (`_up_services_extra`) is not a reference, and neither is a same-named var read
    from outside this task."""
    ok = {
        "name": "fine",
        "ansible.builtin.set_fact": {
            "_up": "{{ stack_services }}",
            "_up_extra": "{{ something_else }}",
        },
    }
    assert _self_references(ok) == []
    substring = {
        "name": "substring only",
        "ansible.builtin.set_fact": {
            "_svc": "{{ a }}",
            "_svc_list": "{{ _svc_list_from_elsewhere | default([]) }}",
        },
    }
    assert not any(pair[1] == "_svc" for pair in _self_references(substring)), \
        "'_svc_list_from_elsewhere' merely starts with '_svc' — the word boundary must not treat it as a hit"
