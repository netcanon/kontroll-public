"""Genericization Phase-3 parameterization regression guards: the management IP (${KONTROLL_MGMT_IP}) and the
instance domain (${KONTROLL_DOMAIN}) are sourced from instance/instance.yml and rendered into docker/.env — no
instance literal may stay baked into the shipped tool, and both .env render paths must move together.

Why each guards a real failure:
  * a literal IP/domain back in a compose fragment re-couples the public tool to one instance (the genericization
    regression the cut-line audit set out to kill);
  * a mgmt-IP bind losing its ${KONTROLL_MGMT_IP} prefix would publish a privileged surface on 0.0.0.0 (C3);
  * docker/.env.example and deploy-stack.yml are the TWO .env render paths — if only one gains the keys, validate's
    compose-config gate stays green while the live deploy binds 0.0.0.0 (the top trap the read-only sweep flagged).
"""
import glob
import importlib.util
import os
import sys

import pytest

from kontroll import paths

sys.path.insert(0, os.path.join(paths.ROOT, "tests"))
import _leak_guard as _guard  # noqa: E402  (the shared identifier-leak scanner; private tokens never ship)

pytestmark = pytest.mark.unit

_INSTANCE_TOKENS = _guard.instance_patterns(paths.ROOT)

SERVICES = os.path.join(paths.ROOT, "docker", "services")
ENV_EXAMPLE = os.path.join(paths.ROOT, "docker", ".env.example")
DEPLOY_STACK = os.path.join(paths.ROOT, "ansible", "playbooks", "deploy-stack.yml")


def _load_guard():
    """Load tests/check-mgmt-port-binding.py (hyphenated → not importable by name) as a module."""
    path = os.path.join(paths.ROOT, "tests", "check-mgmt-port-binding.py")
    spec = importlib.util.spec_from_file_location("check_mgmt_port_binding", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def _service_yaml_text():
    return "\n".join(_read(f) for f in sorted(glob.glob(os.path.join(SERVICES, "*.yaml"))))


def test_no_published_port_binds_a_non_mgmt_host():
    """Every published compose port binds ${KONTROLL_MGMT_IP} (or is a documented NPM-fronted UI). Exercises the
    validate guardrail's OWN logic (check-mgmt-port-binding.offending_ports), so a regression fails in both the
    pytest matrix and the validate gate. An unparameterized / 0.0.0.0 privileged bind is the C3 exposure footgun."""
    guard = _load_guard()
    bad = guard.offending_ports()
    assert bad == [], "non-mgmt-bound published ports: %r" % (bad,)


def _identifier_findings(text):
    """Every identifier the leak guard flags in `text`: any RFC-1918 address (dotted, dashed or underscored), a
    non-documentation MAC/IPv6, a key-material shape, a personal identifier, AND any of THIS instance's own names
    (hostnames/domain) from the private token list — reported by index + digest, never the name. Structurally
    stronger than the literal asserts this replaced: those passed on any instance literal other than the two
    hard-coded ones, and published the very tokens they guarded."""
    return _guard.structural_findings(text) + _guard.token_findings(text, _INSTANCE_TOKENS)


def test_no_instance_ip_or_domain_literal_in_shipped_compose():
    """No instance literal (a private address, the instance's domain or hostnames) survives in the shipped compose
    fragments — they are parameterized to ${KONTROLL_MGMT_IP}/${KONTROLL_DOMAIN}. A re-introduced literal
    re-couples the public tool to one instance (the genericization regression)."""
    text = _service_yaml_text()
    assert _identifier_findings(text) == []


def test_env_example_has_no_domain_leak_and_defines_both_keys():
    """docker/.env.example is a SHIPPED public stub copied to docker/.env: it must carry no real domain/address
    (any identifier the leak guard flags) and must define KONTROLL_MGMT_IP + KONTROLL_DOMAIN, so `compose config`
    substitutes them and a manual `cp` path binds mgmt-only. Guards the domain leak the cut-line audit found."""
    env = _read(ENV_EXAMPLE)
    assert _identifier_findings(env) == []                    # the leak is fixed — and cannot quietly return
    assert "KONTROLL_MGMT_IP=" in env and "KONTROLL_DOMAIN=" in env


def test_deploy_stack_renders_both_tokens_from_instance():
    """deploy-stack.yml is the OTHER .env render path (the live deploy). It must render KONTROLL_MGMT_IP +
    KONTROLL_DOMAIN sourced from instance.yml (_mgmt_ip/_domain), so the live .env carries them too — updating only
    .env.example would leave production binding 0.0.0.0 while validate stays green (the top render-path trap)."""
    ds = _read(DEPLOY_STACK)
    assert "KONTROLL_MGMT_IP={{ _mgmt_ip }}" in ds
    assert "KONTROLL_DOMAIN={{ _domain }}" in ds
    assert "_mgmt_ip:" in ds and "_instance.mgmt_ip" in ds     # sourced from instance.yml, not hardcoded
    assert "_domain:" in ds and "_instance.domain" in ds
