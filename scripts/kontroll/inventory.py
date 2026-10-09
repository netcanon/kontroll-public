#!/usr/bin/env python3
"""Merge the inventory `hosts.yml` with its `onboarded-<key>.yml` drop-ins — the standalone-generator
analogue of ansible's directory-inventory merge.

ansible reads the inventory *directory* (`ansible.cfg` sets `inventory = ../instance/inventory`), so a
GUI-onboarded host is a first-class inventory host for every playbook. The onboard writes that host to an
ADDITIVE drop-in `instance/inventory/onboarded-<key>.yml` (banner-owned, "safe to delete to remove the host") —
NEVER into the curated `hosts.yml`. But the standalone config generators (gen-observability, gen-homepage,
gen-logging, gen-validate-live) load `hosts.yml` as a SINGLE file. Without this merge a GUI-onboarded device is
invisible to them — no Prometheus scrape target, no Homepage tile, no logging source — even though ansible
manages it. (Found live: a dogfood-onboarded Cisco C9300 got the placeholder host's SNMP target, never its own.)

`merged_inventory()` folds the drop-ins into the `hosts.yml` shape so the generators fan over the SAME fleet
ansible does. It is READ-ONLY (yaml.safe_load + glob, no writes) and standalone (only `kontroll.paths`), so CI
and deploy-stack can run it. The curated `hosts.yml` always wins on a hostname collision — a drop-in only ADDS.
"""
import glob
import os

import yaml

from kontroll import paths


def _load(abspath):
    with open(abspath, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def merged_inventory(hosts_rel, root=None):
    """Load `hosts_rel` (a repo-ROOT-relative path to the inventory `hosts.yml`, already overlay-resolved by the
    caller via `paths.resolve` for the live overlay, or a literal `instance.example/...` path for the public
    reference) and merge every sibling `onboarded-*.yml` drop-in. Returns a dict in `hosts.yml`'s shape
    (`all.children.<group>.hosts.<host>`), which the generators' `_hosts_in_group()` already reads.

    A drop-in nests its group at the TOP level (`core_switch: {hosts: {...}}`) — the shape the onboard writes —
    or under `all.children`; both are folded in. The curated `hosts.yml` wins on a hostname collision (a drop-in
    never clobbers a hand-authored host). `root` overrides `paths.ROOT` for hermetic tests.
    """
    base = root or paths.ROOT
    hosts_abs = os.path.join(base, hosts_rel)
    inv = _load(hosts_abs) if os.path.exists(hosts_abs) else {}
    children = inv.setdefault("all", {}).setdefault("children", {})
    for dropin in sorted(glob.glob(os.path.join(os.path.dirname(hosts_abs), "onboarded-*.yml"))):
        data = _load(dropin)
        nested = ((data.get("all") or {}).get("children") or {})
        top = {k: v for k, v in data.items() if k != "all"}
        for gname, gbody in {**top, **nested}.items():          # top-level group form OR all.children form
            if not isinstance(gbody, dict):
                continue
            hosts = gbody.get("hosts") or {}
            if not hosts:
                continue
            dest = children.setdefault(gname, {}).setdefault("hosts", {})
            for hname, hvars in hosts.items():
                dest.setdefault(hname, hvars)                    # curated hosts.yml wins; drop-in only ADDS
    return inv
