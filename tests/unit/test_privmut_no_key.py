"""C10 no-key posture — the deployed API compose fragment mounts NO decrypting age key.

Pins the headline safety property of propose-then-promote (SECURITY.md C10 / docs/privileged-mutation-
enablement.md): the always-on API service holds no age key, so a compromise of it can't decrypt a secret.
Guards a careless future volume/env add that would re-introduce a standing decrypt key into a network-reachable
service — the single biggest risk the no-key posture exists to eliminate (1b §4).
"""
import os

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytestmark = pytest.mark.unit


def test_api_fragment_mounts_no_age_key():
    """docker/services/api.yaml sets no SOPS_AGE_KEY_FILE and mounts no age-key/sops path — the no-key
    posture. Guards re-introducing a standing decrypt key (the capability promote carries no creds, so the
    API needs none; onboard's cred-encryption defers out-of-band, C10)."""
    api = yaml.safe_load(open(os.path.join(ROOT, "docker", "services", "api.yaml"),
                              encoding="utf-8"))["services"]["api"]
    assert "SOPS_AGE_KEY_FILE" not in (api.get("environment") or {}), \
        "C10 no-key posture: the API must set no SOPS_AGE_KEY_FILE"
    for vol in (api.get("volumes") or []):
        low = vol.lower()
        # match an actual age-KEY mount (age.key / sops/age / keys.txt), NOT the substring "age" — which now
        # also appears in the relocatable storage var ${KONTROLL_STORAGE_ROOT} (stor-AGE-root).
        assert "age.key" not in low and "keys.txt" not in low and "sops" not in low, \
            "C10: the API must mount no age key (%s)" % vol
