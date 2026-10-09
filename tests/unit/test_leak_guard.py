"""tests/_leak_guard.py — the identifier-leak guard behind every "no real topology / no personal identifier" gate.

WHY (the failures these guard, found by the 2026-10-08 public-split sweep):
- Capture-filename fixtures spelled a real lab address with DASHES (`cisco_ios_192-168-11-2.cfg`) and every earlier
  guard matched dotted IPs only, over a scope that did not include tests/. The structural layer must catch any
  separator form, over the whole shippable tree.
- The earlier guards EMBEDDED the very hostnames/domain they blocked (a public repo would publish its own denylist).
  The instance-token layer reads them from a private file instead; the canary file keeps the mechanism exercised
  on a checkout that has no private list, and the self-test here proves a scan that finds nothing is not a scan
  that ran nothing (a guard never observed to fail is not a guard).
- Python's `ipaddress.is_private` is true for the RFC-5737 documentation nets — the sanctioned example space — so a
  naive private-range check would flag every TEST-NET example; the RFC-1918 ranges are named explicitly.
- A failure report must never itself be the leak: a matched instance token is reported by index + digest only.
"""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import _leak_guard as guard  # noqa: E402

pytestmark = pytest.mark.unit


def _cats(text):
    return sorted({cat for _, cat, _ in guard.structural_findings(text)})


def test_rfc1918_is_caught_in_dotted_dashed_and_underscored_forms():
    """A private address is flagged however it is spelled — dotted, dashed (capture filenames) or underscored — so
    the dashed-filename leak the sweep found can never recur in any file the public tree ships."""
    # (the samples are private-range SHAPES, deliberately not any real deployment's addresses; this file is the
    #  one file the tree scan skips — see _leak_guard.SELF_TEST — because its job is to hold such samples)
    assert _cats("ip: 192.168.77.252") == ["rfc1918-ipv4"]
    assert _cats('f = cap / "cisco_ios_192-168-77-2.cfg"') == ["rfc1918-ipv4"]
    assert _cats("FortiGate_192-168-88-5_config.cfg") == ["rfc1918-ipv4"]
    assert _cats("name_10_0_0_1") == ["rfc1918-ipv4"]
    assert _cats("172.16.4.9 and 10.9.8.7") == ["rfc1918-ipv4"]


def test_documentation_addresses_oids_and_versions_never_match():
    """The sanctioned example space (RFC-5737 TEST-NET, RFC-7042 MACs, RFC-3849 IPv6, loopback/link-local), a bare
    OID with address-shaped sub-identifiers and a version string are NOT findings — the gate must under-fire rather
    than cry wolf on the examples the docs are told to use (is_private would have flagged all of TEST-NET)."""
    assert _cats("addr 192.0.2.5 and 198.51.100.7 and 203.0.113.9") == []
    assert _cats("oid .1.3.6.1.2.1.10.0.0.1 = x") == []
    assert _cats("v10.0.0.1 release; ansible-core==2.19.4") == []
    assert _cats("mac 00:00:5e:00:53:01 null 00:00:00:00:00:00 bcast ff:ff:ff:ff:ff:ff") == []
    assert _cats("v6 2001:db8::1 fe80::1 ::1") == []
    assert _cats("t 12:30:45 on 2026:06:13") == []


def test_non_documentation_mac_and_global_ipv6_are_caught_in_every_spelling():
    """A real-looking MAC (colon, dash, Cisco dotted, net-snmp space-hex) and a global IPv6 outside the documentation
    prefix are findings — the channels an IPv4-only scan misses."""
    assert _cats("a4:5e:60:12:34:56") == ["mac"]
    assert _cats("a4-5e-60-12-34-56") == ["mac"]
    assert _cats("a45e.6012.3456") == ["mac"]                 # Cisco dotted form
    assert _cats("0011.2233.4455") == []                      # …but the textbook placeholder, dotted, is not
    assert _cats("Hex-STRING: A4 5E 60 12 34 56") == ["mac"]
    assert _cats("v6 2a02:1234:5678::1") == ["ipv6-global"]


def test_personal_identifier_and_key_material_shapes_are_caught():
    """An operator-machine user-profile path (drive-letter and MSYS forms), a real-length age recipient and a real-
    length AGE secret key are findings — the personal / key-material classes gitleaks' generic rules do not cover
    (the age placeholder in instance.example/.sops.yaml is deliberately one character short and never matches)."""
    assert _cats("C:" + chr(92) + "Users" + chr(92) + "someone" + chr(92) + "repo") == ["personal-identifier"]
    assert _cats("/c/Users/someone/repo") == ["personal-identifier"]
    assert _cats("age1" + "q" * 58) == ["age-recipient"]
    assert _cats("age1exampleexampleexampleexampleexampleexampleexampleexa") == []
    assert _cats("AGE-SECRET-KEY-1" + "Q" * 58) == ["age-secret-key"]
    assert _cats("AGE-SECRET-KEY-1FAKEZZ") == []


def test_allow_marker_exempts_exactly_its_line():
    """A same-line `pii-guard: allow <reason>` marker exempts that line only — the review-visible escape hatch for a
    test that MUST hold a private address (e.g. a private-unicast acceptance case). The next line is still scanned."""
    text = "ok 192.168.1.1  # pii-guard: allow private-unicast acceptance case\nbad 192.168.1.2\n"
    assert guard.structural_findings(text) == [(2, "rfc1918-ipv4", "192.168.1.2")]


def test_canary_self_test_the_instance_layer_fires_and_never_prints_the_token(tmp_path, monkeypatch):
    """The shipped canary list (the floor every checkout has, and the active layer on a public clone) is well-formed
    and a canary planted in a file IS flagged — so the token layer can never silently no-op. The report carries the
    token's index + an 8-hex sha256 of the match, never the matched text (a failure log must not itself be the
    leak). Also pins that SOME token source is active on this checkout (private list or canaries)."""
    assert guard.tokens_source(guard.ROOT) is not None, "no token source at all — the layer would be inert"
    canaries = os.path.join(guard.ROOT, "instance.example", "leak-tokens.example.txt")
    monkeypatch.setenv("KONTROLL_LEAK_TOKENS_FILE", canaries)
    pats = guard.instance_patterns(guard.ROOT)
    assert pats, "instance.example/leak-tokens.example.txt must ship at least one canary"
    # the canary is assembled at runtime so this tracked file never carries the token literally (on a public
    # checkout the canaries ARE the active token layer, and the guard scans this file too)
    canary = "kontroll-canary-" + "host"
    hits = guard.token_findings("hostname: %s\n" % canary, pats)
    assert hits and hits[0][1] == "instance-token"
    assert "canary" not in hits[0][2]
    assert hits[0][2].startswith("token#1 sha256:") and hits[0][2].endswith(
        hashlib.sha256(canary.encode()).hexdigest()[:8])


def test_private_token_file_takes_precedence_via_env(tmp_path, monkeypatch):
    """$KONTROLL_LEAK_TOKENS_FILE (how CI injects the private list as a secret) wins over the shipped canaries, is
    case-insensitive and word-bounded, and ignores comments/blank lines."""
    f = tmp_path / "tokens.txt"
    f.write_text("# comment\n\nmy-real-host\nlab\\.example\n", encoding="utf-8")
    monkeypatch.setenv("KONTROLL_LEAK_TOKENS_FILE", str(f))
    pats = guard.instance_patterns(guard.ROOT)
    assert len(pats) == 2
    assert guard.token_findings("host MY-REAL-HOST up; lab.example down", pats)
    assert guard.token_findings("my-real-hostname", pats) == []          # word-bounded: a longer name is not a hit


def test_shippable_tree_is_free_of_identifiers():
    """The standing gate over the WHOLE shippable tree (every tracked file minus instance/, docs/reviews/, local/ —
    the make-bundle strip set): zero structural findings and zero instance-token findings. This is the pytest twin
    of `tests/validate.sh` step `pii-guard` and the public CI's PII-guard workflow; it runs with whatever token
    layer is present (the private list on the instance repo / CI secret, the canaries on a public checkout)."""
    files = guard.shippable_files(guard.ROOT)
    assert files, "git ls-files returned nothing — the scan would be vacuous"
    findings = guard.scan_paths(files, guard.ROOT)
    assert findings == [], "identifier leak(s) in the shippable tree:\n  " + "\n  ".join(
        "%s:%d %s %s" % f for f in findings[:40])
