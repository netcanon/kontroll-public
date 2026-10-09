#!/usr/bin/env python3
"""Fetch the curated Grafana.com community dashboards declared by the enabled device modules and provision
them — the dashboard analogue of gen-requirements.py (collections) + gen-observability.py (scrape targets),
sourcing from the PUBLIC Grafana.com registry (grafana.com/grafana/dashboards) instead of hand-authored JSON.

Each device class declares its data-relevant dashboards in modules/<key>/module.yml:

    dashboards:
      - {gnet: 10347, name: proxmox}   # grafana.com/grafana/dashboards/10347 (Proxmox via Prometheus)
      - {gnet: 1860, name: node}       # Node Exporter Full

This fetches each UNIQUE gnet id from grafana.com (latest revision), pins the Prometheus datasource (uid
`prometheus`, the fixed uid the provisioning sets), strips the import `__inputs`, and writes
dashboards/grafana/dashboards/<name>.json — committed + pinned (reproducible, offline at deploy). The Grafana
file provider auto-loads them. Two datasource styles are handled: the `${DS_PROMETHEUS}` import input (older
dashboards, e.g. 10347) and the `type: datasource` template variable (newer, e.g. 1860).

ONLINE (needs grafana.com). Run deliberately when adding/refreshing a dashboard (NOT a hermetic --check).
This is the curated/pinned tier; the onboarding live-search pick-list rides the same fetch path next.

Usage:  python3 scripts/fetch-dashboards.py [--list]
"""
import json
import os
import sys
import urllib.request

import yaml

from kontroll import paths

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GNET = "https://grafana.com/api/dashboards"
DS_UID = "prometheus"   # must match the uid pinned in dashboards/grafana/provisioning/datasources/prometheus.yml
OUT_DIR = os.path.join(ROOT, "dashboards", "grafana", "dashboards")


def _load(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "kontroll-fetch-dashboards"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def declared_dashboards(fleet):
    """-> {gnet: name} unique across every enabled module's `dashboards:` block (first name wins on dup)."""
    out = {}
    for key in fleet.get("enabled_modules") or []:
        mp = "modules/%s/module.yml" % key
        if not os.path.exists(os.path.join(ROOT, mp)):
            continue
        for d in (_load(mp).get("dashboards") or []):
            out.setdefault(d["gnet"], d["name"])
    return out


def pin_datasource(dash):
    """Make a downloaded community dashboard self-provisioning against our fixed Prometheus datasource:
    replace any `${DS_*}` datasource import with the uid, drop the import metadata, and default every
    datasource template variable to it — so it renders without an import prompt or a stale datasource ref."""
    text = json.dumps(dash)
    for inp in dash.get("__inputs", []):
        if inp.get("type") == "datasource":
            text = text.replace("${%s}" % inp["name"], DS_UID)
    dash = json.loads(text)
    dash.pop("__inputs", None)
    dash.pop("__requires", None)
    dash["id"] = None                                   # null id => Grafana treats it as a fresh import
    for var in (dash.get("templating", {}).get("list") or []):
        if var.get("type") == "datasource":
            var["current"] = {"selected": True, "text": "Prometheus", "value": DS_UID}
    return dash


def fetch(gnet):
    """-> (revision, name, pinned_dashboard_dict) for a Grafana.com dashboard id."""
    meta = json.loads(_get("%s/%d" % (GNET, gnet)))
    rev = meta["revision"]
    raw = json.loads(_get("%s/%d/revisions/%d/download" % (GNET, gnet, rev)))
    return rev, meta.get("name"), pin_datasource(raw)


def main(argv):
    want = declared_dashboards(_load(paths.resolve("config/fleet.yml")))
    if "--list" in argv:
        for gnet, name in sorted(want.items()):
            print("%-8d %s" % (gnet, name))
        return 0
    os.makedirs(OUT_DIR, exist_ok=True)
    for gnet, name in sorted(want.items()):
        rev, title, dash = fetch(gnet)
        with open(os.path.join(OUT_DIR, "%s.json" % name), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(dash, fh, indent=2)
            fh.write("\n")
        print("fetched %r (gnet %d rev %d) -> dashboards/grafana/dashboards/%s.json" % (title, gnet, rev, name))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
