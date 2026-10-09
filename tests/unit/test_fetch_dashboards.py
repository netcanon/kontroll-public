"""scripts/fetch-dashboards.py — curated Grafana.com community dashboards, declared per device module.

The dashboard analogue of gen-observability.py: a class declares its data-relevant Grafana.com dashboard ids
(modules/<key>/module.yml `dashboards:`), and the fetcher pulls them from the public registry, pins the
Prometheus datasource, and provisions them — no hand-authored JSON. These tests pin the OFFLINE half (the
module join + the datasource munge); the network fetch itself is exercised live (not in the hermetic suite).
The script name is hyphenated, so it is loaded by path (not importable).
"""
import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytestmark = pytest.mark.unit


def _fd():
    spec = importlib.util.spec_from_file_location(
        "fetch_dashboards", os.path.join(ROOT, "scripts", "fetch-dashboards.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fd = _fd()


def test_declared_dashboards_join_and_dedup():
    """declared_dashboards collects every enabled module's `dashboards:` ids and DEDUPS by gnet — so the
    Node Exporter dashboard declared by BOTH proxmox and docker_host is fetched once. Proves the
    'declare per class, fetch the union' join over the real modules+fleet."""
    want = fd.declared_dashboards(fd._load(fd.paths.resolve("config/fleet.yml")))
    assert want.get(1860) == "node" and want.get(10347) == "proxmox"


def test_pin_datasource_rewrites_input_and_strips_import_meta():
    """pin_datasource makes a downloaded community dashboard self-provisioning: the ${DS_*} datasource
    import is replaced with our fixed uid, __inputs/__requires are dropped, id is nulled, and a datasource
    TEMPLATE VARIABLE is defaulted to our datasource — so it renders without an import prompt or a stale
    datasource reference (the two datasource styles community dashboards use)."""
    raw = {"__inputs": [{"name": "DS_PROMETHEUS", "type": "datasource", "pluginId": "prometheus"}],
           "__requires": [{"type": "grafana"}], "id": 99,
           "templating": {"list": [{"type": "datasource", "name": "ds", "current": {"value": "stale-uid"}}]},
           "panels": [{"datasource": "${DS_PROMETHEUS}"}]}
    out = fd.pin_datasource(raw)
    assert "__inputs" not in out and "__requires" not in out and out["id"] is None
    assert out["panels"][0]["datasource"] == "prometheus"                      # input rewritten to the uid
    assert out["templating"]["list"][0]["current"]["value"] == "prometheus"    # ds template var defaulted
