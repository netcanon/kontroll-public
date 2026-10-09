"""No real homelab topology in the committed GENERATED artifacts (the F3 leak-regression gate, dogfood 2026-06-20).

WHY (the failure this guards, live-caught): the prometheus/targets/*.generated.yml + docker/vector/generated/
*.generated.yaml are GENERATED from the inventory, but they are committed at the REPO level (NOT under instance/,
which make-bundle strips) — so they ship in the PUBLIC release bundle. They were generated from the maintainer's
PRIVATE `instance/` overlay (real homelab IPs/hostnames) and committed, leaking the real topology
(192.168.x/10.x, my-hypervisor-2/my-hypervisor) into every bundle. The fix regenerates them from the PUBLIC example inventory
(instance.example/, TEST-NET addrs) and keys the staleness gate off the example (test_gen_observability /
test_gen_logging). THIS test is the standing regression gate: a real private-range IP committed into a generated
artifact (e.g. a maintainer running deploy-stack against their overlay and committing the regenerated files) fails
HERE, loud, in CI — so the leak can never silently recur. RFC 5737 TEST-NET (192.0.2/198.51.100/203.0.113) and
documentation ranges are NOT private-range and are the intended example addrs.
"""
import glob
import os
import re
import sys

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# make-bundle.sh strips exactly these from the public bundle, so a real value under them does NOT ship — every
# OTHER committed *.generated.* is shippable and must stay TEST-NET-clean. Scanning ALL generated files (not a
# hardcoded list) auto-covers any FUTURE generated tree (review nit A).
_STRIP_DIRS = (os.path.join(ROOT, "instance") + os.sep, os.path.join(ROOT, "docs", "reviews") + os.sep)

# RFC 1918 private ranges — a real homelab address. (TEST-NET 192.0.2/198.51.100/203.0.113 is public-reserved-for-
# docs, never matches, and is the intended example.) Word-bounded so it can't match inside a longer token.
_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b")

# Real homelab host/domain NAMES — the channel an IP-only scan misses (review nit B): a generated artifact could
# carry a real `host:` label with no accompanying private IP. The generators always emit a host LABEL alongside the
# address, so a topology leak shows up here even if the addr were somehow public. The names are THIS instance's
# own identifiers, so they are never written into the shipped tree: tests/_leak_guard.py reads them from the
# private overlay (instance/leak-tokens.txt, or the CI secret), and on a public checkout from the shipped
# canaries — the public-split design (2026-10-08). (The example uses my-hypervisor/my-switch/etc., which never match.)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import _leak_guard as _guard  # noqa: E402

_INSTANCE_TOKENS = _guard.instance_patterns(ROOT)


def _generated_files():
    """Every committed *.generated.{yml,yaml} that SHIPS (i.e. not under an instance/ or docs/reviews/ dir that
    make-bundle strips)."""
    out = []
    for ext in ("yml", "yaml"):
        for path in glob.glob(os.path.join(ROOT, "**", "*.generated." + ext), recursive=True):
            if not any(os.path.abspath(path).startswith(d) for d in _STRIP_DIRS):
                out.append(path)
    return sorted(out)


def test_committed_generated_artifacts_exist():
    """Sanity: the generated trees are non-empty, so the leak scan below is actually scanning something (a glob
    that matched nothing would pass vacuously and hide a regression where the artifacts were removed)."""
    assert _generated_files(), "no committed generated artifacts found — the leak scan would be vacuous"


def test_no_real_topology_in_committed_generated_artifacts():
    """No committed (shippable) generated artifact carries an RFC-1918 private IP OR a real homelab host/domain
    NAME — only TEST-NET example addrs + example names. The F3 leak-regression gate: a real-overlay regeneration
    committed by mistake re-leaks the homelab topology into the public bundle, and fails HERE (IPs AND names, over
    EVERY generated tree)."""
    offenders = {}
    for path in _generated_files():
        text = open(path, encoding="utf-8").read()
        # a matched instance token is reported by index + digest only (never the name — the report must not leak)
        hits = sorted(set(_PRIVATE_IP.findall(text))
                      | {tok for _, _, tok in _guard.token_findings(text, _INSTANCE_TOKENS)})
        if hits:
            offenders[os.path.relpath(path, ROOT).replace(os.sep, "/")] = hits
    assert not offenders, (
        "committed generated artifact(s) carry REAL topology (private IP or homelab host/domain name) — a "
        "re-leak; regenerate from instance.example/ (gen-*.py --example), never the private overlay:\n  "
        + "\n  ".join("%s: %s" % (f, hits) for f, hits in sorted(offenders.items())))
