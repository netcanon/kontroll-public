"""kontroll/inventory.merged_inventory — the standalone config generators must see GUI-onboarded hosts.

WHY (the failure this guards against): the onboard writes a new host to an ADDITIVE drop-in
`instance/inventory/onboarded-<key>.yml`, never into the curated `hosts.yml`, because ansible reads the inventory
DIRECTORY (`ansible.cfg` `inventory = ../instance/inventory`). Before this loader the config generators
(gen-observability / gen-homepage / gen-logging / gen-validate-live) read `hosts.yml` as a SINGLE file, so a
GUI-onboarded device was invisible to them — no Prometheus scrape target, no Homepage tile, no logging source —
even though every playbook managed it. A live dogfood onboarded a Cisco C9300 through the GUI and its SNMP target
came out as the placeholder host (`192.0.2.2`), never `.252`. These tests pin that a drop-in host (nested at the
TOP level, the shape the onboard writes) is merged, that the curated host is never clobbered, that an absent
drop-in leaves `hosts.yml` byte-identical (so the committed `--example` lockfiles stay stable), and that
gen-observability then emits a scrape target for the onboarded host.
"""
import importlib.util
import os
import textwrap

import pytest

from kontroll import inventory

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytestmark = pytest.mark.unit


def _write(d, name, body):
    with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(body))


def _base_and_dropin(d):
    # curated hosts.yml: the group nests under all.children (the canonical inventory shape)
    _write(d, "hosts.yml", """
        all:
          children:
            core_switch:
              hosts:
                curated-sw:
                  ansible_host: 198.51.100.1
    """)
    # the drop-in the GUI onboard writes: the group at the TOP level, NOT under all.children
    _write(d, "onboarded-cisco_ios.yml", """
        core_switch:
          hosts:
            onboarded-c9300:
              ansible_host: 203.0.113.7
              device_role: cisco_ios
    """)


def test_dropin_host_is_merged_into_its_group(tmp_path):
    """A top-level-group drop-in host is folded into all.children.<group>.hosts alongside the curated host —
    the exact fix for the live-dogfood miss (an onboarded switch invisible to the generators)."""
    _base_and_dropin(str(tmp_path))
    inv = inventory.merged_inventory("hosts.yml", root=str(tmp_path))
    hosts = inv["all"]["children"]["core_switch"]["hosts"]
    assert "onboarded-c9300" in hosts
    assert hosts["onboarded-c9300"]["ansible_host"] == "203.0.113.7"
    assert "curated-sw" in hosts   # never drops the hand-authored host


def test_curated_host_wins_on_name_collision(tmp_path):
    """A drop-in only ADDS; it must never clobber a hand-authored hosts.yml host of the same name."""
    d = str(tmp_path)
    _write(d, "hosts.yml", """
        all:
          children:
            core_switch:
              hosts:
                sw:
                  ansible_host: 198.51.100.1
    """)
    _write(d, "onboarded-cisco_ios.yml", """
        core_switch:
          hosts:
            sw:
              ansible_host: 203.0.113.99
    """)
    inv = inventory.merged_inventory("hosts.yml", root=d)
    assert inv["all"]["children"]["core_switch"]["hosts"]["sw"]["ansible_host"] == "198.51.100.1"


def test_no_dropins_is_identity_on_hosts_yml(tmp_path):
    """With no drop-in present the loader is the identity on hosts.yml — so the committed `--example` lockfiles
    stay byte-stable (instance.example/ ships no onboarded-*.yml)."""
    d = str(tmp_path)
    _write(d, "hosts.yml", """
        all:
          children:
            core_switch:
              hosts:
                sw: {ansible_host: 198.51.100.1}
    """)
    inv = inventory.merged_inventory("hosts.yml", root=d)
    assert set(inv["all"]["children"]["core_switch"]["hosts"]) == {"sw"}


def test_gen_observability_emits_a_target_for_the_onboarded_host(tmp_path):
    """End-to-end: a drop-in-onboarded cisco_ios host flows through merged_inventory into a real SNMP scrape
    target — the precise live failure (the onboarded C9300 must get its OWN target, not just the placeholder)."""
    _base_and_dropin(str(tmp_path))
    inv = inventory.merged_inventory("hosts.yml", root=str(tmp_path))
    spec = importlib.util.spec_from_file_location(
        "gen_observability", os.path.join(ROOT, "scripts", "gen-observability.py"))
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    files = gen.metrics_files({"enabled_modules": ["cisco_ios"]}, inv)
    body = files.get("prometheus/targets/network/cisco_ios.generated.yml", "")
    assert "203.0.113.7" in body   # the onboarded host is now its own scrape target
