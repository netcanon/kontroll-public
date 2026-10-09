"""Fail-closed retention/size BOUND knobs (the storage paradigm's hard rule).

The blackboard's blocker check: NO .env retention/size var may resolve to empty=infinite. The proof must
exercise the EMPTY/unset case, NOT the populated docker/.env.example (V1 must-fix M-7 — relying on .env.example
being filled conflates documentation with enforcement). So this is a STATIC check that (a) every BOUND retention
var is present + non-empty in .env.example AND (b) every compose CONSUMER reads it via the fail-closed
${VAR:-default} form — never a bare ${VAR} (which resolves empty when unset) nor a hardcoded literal. It also
pins that the Prometheus disk-size HARD CAP exists at all: its absence was the one real metrics fail-open hole
(a runaway scrape / label-explosion could fill the disk and take down the whole control plane).
"""
import os

import pytest

pytestmark = pytest.mark.unit

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _code(rel):
    """File text with comments stripped (full-line `#…` dropped; trailing ` #…` cut) so the fail-closed checks
    match real config, not prose that merely MENTIONS a bare ${VAR} (e.g. loki.yaml's own explanatory comment)."""
    lines = []
    for line in _read(rel).splitlines():
        if line.lstrip().startswith("#"):
            continue
        i = line.find(" #")          # yamllint requires >=1 space before an inline comment
        lines.append(line[:i] if i >= 0 else line)
    return "\n".join(lines)


# BOUND retention var -> (the COMPOSE fragment that consumes it, the non-empty fail-closed default it must carry).
# NB we check the COMPOSE consumer, not loki-config.yml: Loki's -config.expand-env is Go os.Expand and does NOT
# honour ${VAR:-default}, so loki-config.yml intentionally uses a bare ${LOKI_RETENTION_PERIOD} and the default
# lives in loki.yaml's env block. The fail-closed default therefore belongs to (and is asserted on) the compose
# layer for every BOUND var.
_BOUND = {
    "LOKI_RETENTION_PERIOD": ("docker/services/loki.yaml", "720h"),
    "PROM_RETENTION_TIME": ("docker/services/prometheus.yaml", "90d"),
    "PROM_RETENTION_SIZE": ("docker/services/prometheus.yaml", "20GB"),
}


def _env_example_value(name):
    """The value assigned to `name` in docker/.env.example (None if absent or commented out)."""
    for line in _read("docker/.env.example").splitlines():
        s = line.strip()
        if s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        if k.strip() == name:
            return v.split("#", 1)[0].strip()   # drop any inline comment
    return None


def test_bound_retention_vars_nonempty_in_env_example():
    """Every BOUND retention var is present + NON-EMPTY in .env.example — an empty value would document
    'unbounded' as acceptable, the exact fail-open the paradigm forbids."""
    for name in _BOUND:
        val = _env_example_value(name)
        assert val, "%s missing/empty in docker/.env.example (empty = infinite = fail-open)" % name


def test_bound_retention_consumers_are_fail_closed():
    """Every compose consumer reads its BOUND var via the fail-closed ${VAR:-default} form: an empty/unset .env
    value falls to a non-empty default, NEVER to empty (which Prometheus/Loki read as 'no limit' = unbounded
    disk). Guards a regression to a bare ${VAR} (resolves empty) or a hardcoded literal (un-tunable)."""
    for name, (frag, default) in _BOUND.items():
        text = _code(frag)
        assert ("${%s:-%s}" % (name, default)) in text, \
            "%s in %s must use the fail-closed ${%s:-%s} form" % (name, frag, name, default)
        assert ("${%s}" % name) not in text, \
            "%s in %s appears as a bare ${%s} (resolves empty = fail-open); use ${%s:-...}" % (
                name, frag, name, name)


def test_prometheus_disk_size_cap_present():
    """The Prometheus TSDB disk-size HARD CAP must exist — its ABSENCE was the one real metrics fail-open hole
    (a runaway scrape/label-explosion fills the disk; time-based retention alone can't backstop a burst).
    Guards someone dropping the flag again."""
    text = _read("docker/services/prometheus.yaml")
    assert "--storage.tsdb.retention.size=" in text, \
        "Prometheus must set --storage.tsdb.retention.size (the disk fail-open backstop)"
