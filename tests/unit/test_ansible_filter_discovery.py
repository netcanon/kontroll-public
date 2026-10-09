"""ansible/ansible.cfg must make the playbooks' custom Jinja filters DISCOVERABLE.

B1 (the live deploy-stack render) caught this: the filters live in `ansible/filter_plugins/`, but Ansible's
DEFAULT filter search is playbook-adjacent (`ansible/playbooks/filter_plugins/`) + `~/.ansible` — NEITHER of which
is `ansible/filter_plugins/`. With no `filter_plugins` line in ansible.cfg, deploy-stack failed at runtime with
"No filter named 'kontroll_render_token'". This pins that ansible.cfg declares the path AND that every
`| kontroll_*` filter the playbooks reference is actually defined in that dir — so the deploy can find them and a
future filter rename / cfg edit can't silently re-break the render (the bug only surfaces on a live deploy, never
in pytest/lint).
"""
import configparser
import glob
import os
import re

import pytest

pytestmark = pytest.mark.unit

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ANSIBLE_DIR = os.path.join(_ROOT, "ansible")


def _filter_plugins_dir():
    """Resolve ansible.cfg's [defaults] filter_plugins relative to the cfg dir (= the deploy cwd, ansible/)."""
    cfg = configparser.ConfigParser()
    cfg.read(os.path.join(_ANSIBLE_DIR, "ansible.cfg"))
    val = cfg.get("defaults", "filter_plugins", fallback="").strip()
    assert val, ("ansible.cfg [defaults] must declare filter_plugins — Ansible's default search does NOT include "
                 "ansible/filter_plugins/, so deploy-stack can't find kontroll_render_token/kontroll_sops_domain "
                 "(B1-caught: 'No filter named ...' at runtime).")
    return os.path.normpath(os.path.join(_ANSIBLE_DIR, val))


def test_ansible_cfg_filter_plugins_dir_exists_and_holds_the_filters():
    """The configured filter_plugins dir exists and contains the two filter plugin files deploy-stack depends on."""
    d = _filter_plugins_dir()
    assert os.path.isdir(d), "the configured filter_plugins dir must exist: %s" % d
    for fp in ("kontroll_token.py", "kontroll_sops.py"):
        assert os.path.exists(os.path.join(d, fp)), "%s must live in the configured filter_plugins dir %s" % (fp, d)


def test_every_kontroll_filter_used_by_playbooks_is_defined():
    """Every `| kontroll_<name>` filter the playbooks reference is registered by a plugin in the configured dir —
    so the deploy can resolve it. Guards a filter being referenced but unshipped/renamed (the live-only failure)."""
    d = _filter_plugins_dir()
    registered = set()
    for fp in glob.glob(os.path.join(d, "*.py")):
        registered |= set(re.findall(r'"(kontroll_[a-z_]+)"\s*:', open(fp, encoding="utf-8").read()))
    used = set()
    for pb in glob.glob(os.path.join(_ANSIBLE_DIR, "playbooks", "*.yml")):
        used |= set(re.findall(r"\|\s*(kontroll_[a-z_]+)\b", open(pb, encoding="utf-8").read()))
    assert used, "sanity: the playbooks reference at least one kontroll_* filter (deploy-stack's render loop)"
    missing = used - registered
    assert not missing, "playbooks reference kontroll_* filters not registered in %s: %s" % (d, sorted(missing))
