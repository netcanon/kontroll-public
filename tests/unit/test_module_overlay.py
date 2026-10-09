"""Phase-B Rung 2 — the modules registry overlay (Fork B) + the config-as-data reads routed off the baked ROOT.

WHY (the failures these guard): in a BAKED deploy the runtime service code is read from the read-only image at
paths.ROOT (/opt/kontroll), while the operator-mutable tree (the C10 propose clone) is paths.write_root() (/propose).
`modules/` is the ONE registry that grows with operator action (onboarding a new device-class) and is edited in place
(reconfigure), so a runtime reader that joined paths.ROOT directly would NEVER see an operator-onboarded or
reconfigured class — onboarding would mis-reuse, reconfigure would prefill stale values, the fleet view would miss
the class (the synthesis §2 Fork B hazard). `paths.module_file()`/`module_keys()` resolve the overlay (the clone
SHADOWS the baked ROOT). DECISION D1 (ratified by the catalog-reader trace): operator classes land in the canonical's
`modules/`, so the deploy-time generators keep reading `modules/` with ZERO change and this overlay is confined to the
baked runtime readers. Separately, config/ + dashboards/ + the trust/image locks are config-as-data in the canonical
clone — NOT baked — so the readers that touched them via paths.ROOT must use write_root() (else a baked api/onboard-gui
silently degrades: empty redactions, no Grafana deep-link uid, an empty provenance surface — the latent Rung-1b api
regression). With write_root()==ROOT (CLI/tests/legacy /repo deploy) every one of these is byte-for-byte identity.
"""
import os

import pytest

from kontroll import paths
from kontroll.service import backups, observe, provenance

pytestmark = pytest.mark.unit


def _mk(p, body="key: x\n"):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(body)


def test_module_file_is_identity_when_write_root_unset(tmp_path, monkeypatch):
    """With KONTROLL_WRITE_ROOT unset, module_file()==os.path.join(ROOT, "modules", key, "module.yml") — the
    byte-for-byte identity the CLI / the ~25 ROOT-monkeypatching unit tests / the legacy /repo deploy rely on.
    Guards a seam that diverts a modules read even when nothing is baked."""
    monkeypatch.delenv("KONTROLL_WRITE_ROOT", raising=False)
    monkeypatch.setattr(paths, "ROOT", str(tmp_path))
    _mk(os.path.join(str(tmp_path), "modules", "cisco_ios", "module.yml"))
    assert paths.module_file("cisco_ios") == os.path.join(str(tmp_path), "modules", "cisco_ios", "module.yml")
    # an absent class still resolves to the same ROOT path (the existence-based fallback, not a divert)
    assert paths.module_file("absent") == os.path.join(str(tmp_path), "modules", "absent", "module.yml")


def test_module_file_clone_shadows_baked_root(tmp_path, monkeypatch):
    """In a baked deploy the write_root CLONE shadows the baked ROOT: a pristine SHIPPED class reads from the baked
    image, an operator-ONBOARDED class reads from the clone, and a RECONFIGURED shipped class (now present in the
    clone) reads the clone copy — never the stale baked one. Guards the baked onboard-gui missing operator/edited
    classes (mis-reuse, stale reconfigure prefill, an invisible class)."""
    baked = tmp_path / "opt" / "kontroll"
    clone = tmp_path / "propose"
    _mk(str(baked / "modules" / "cisco_ios" / "module.yml"))        # shipped, pristine — baked only
    _mk(str(clone / "modules" / "myrouter" / "module.yml"))         # operator-onboarded — clone only
    monkeypatch.setattr(paths, "ROOT", str(baked))
    monkeypatch.setenv("KONTROLL_WRITE_ROOT", str(clone))

    assert paths.module_file("cisco_ios") == str(baked / "modules" / "cisco_ios" / "module.yml")   # baked shipped
    assert paths.module_file("myrouter") == str(clone / "modules" / "myrouter" / "module.yml")     # operator clone
    _mk(str(clone / "modules" / "cisco_ios" / "module.yml"))        # reconfigured shipped lands in the clone
    assert paths.module_file("cisco_ios") == str(clone / "modules" / "cisco_ios" / "module.yml")   # clone now shadows


def test_module_keys_unions_baked_and_clone(tmp_path, monkeypatch):
    """module_keys() enumerates BOTH roots deduped + sorted (shipped baked ∪ operator clone) — the scan analogue of
    module_file() for catalog.module_for_collection, so a newly-onboarded class is found post-promote. Guards a scan
    that saw only the baked shipped classes (a collection→class lookup that fails for an operator class)."""
    baked = tmp_path / "opt" / "kontroll"
    clone = tmp_path / "propose"
    _mk(str(baked / "modules" / "cisco_ios" / "module.yml"))
    _mk(str(clone / "modules" / "cisco_ios" / "module.yml"))        # shared key — deduped
    _mk(str(clone / "modules" / "myrouter" / "module.yml"))         # operator-only key
    monkeypatch.setattr(paths, "ROOT", str(baked))
    monkeypatch.setenv("KONTROLL_WRITE_ROOT", str(clone))
    assert paths.module_keys() == ["cisco_ios", "myrouter"]


def test_config_as_data_reads_resolve_under_write_root(tmp_path, monkeypatch):
    """config/ + dashboards/ + the trust/image locks are config-as-data in the canonical clone, NOT baked — so the
    readers must resolve them under write_root(), else a baked api/onboard-gui reads the read-only image (which has
    no config/ or dashboards/) and silently degrades. Guards the latent Rung-1b api provenance regression + a baked
    onboard-gui that can't read its redactions / Grafana uid."""
    baked = tmp_path / "opt" / "kontroll"
    clone = tmp_path / "propose"
    baked.mkdir(parents=True)
    monkeypatch.setattr(paths, "ROOT", str(baked))
    monkeypatch.setenv("KONTROLL_WRITE_ROOT", str(clone))

    # config/capture-redactions.yml (C14 redaction registry) resolves to the clone, not the baked image.
    assert backups._redactions_path() == os.path.join(str(clone), "config", "capture-redactions.yml")

    # dashboards/<name>.json (the Grafana deep-link uid) is read from the clone.
    _mk(str(clone / "dashboards" / "grafana" / "dashboards" / "node.json"), '{"uid": "abc123"}\n')
    assert observe._dashboard_uid("node") == "abc123"

    # provenance reads the trust sidecar from the clone (a copy in the baked ROOT must NOT be read instead).
    _mk(str(clone / "ansible" / "collections" / "trust.generated.yml"), "default_signature_policy: adaptive\n")
    _mk(str(baked / "ansible" / "collections" / "trust.generated.yml"), "default_signature_policy: WRONG\n")
    assert provenance._read_yaml("ansible/collections/trust.generated.yml")["default_signature_policy"] == "adaptive"
