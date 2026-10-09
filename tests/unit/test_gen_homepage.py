"""scripts/gen-homepage.py — the Homepage **Fleet** tile group GENERATED from the device modules + inventory (B3,
#130), and its agreement with the GUI Homepage editor it produces output for.

WHY (the failures these guard):
- The generated fleet block is a MARKED SPAN inside the operator-owned services.yaml, not a standalone
  `*.generated.yml`. The committed PUBLIC reference (instance.example/.../services.yaml) SHIPS in the make-bundle
  artifact (only `instance/` is stripped), so a real-overlay regeneration committed by mistake would re-leak the
  homelab topology — the F3 class of bug, but in a file the `*.generated.*` leak-gate glob does NOT scan. The
  staleness + TEST-NET pins here are that file's only standing guard.
- The whole point of #130 is that the generator (producer) and the `:8443` editor (consumer) AGREE on the span
  boundary: the editor must parse the emitted block as ONE opaque `fleet` section it flags generated:true and
  refuses to edit (the #124 ownership invariant). If they drifted, the GUI could drop/reorder generated tiles.
  These pins feed the generator's output straight through `homepage._split_services`/`read_board`/`_validate_board`
  to prove they meet at the markers.
- A generator is a SCRIPT (it `sys.exit`s on bad input, unlike the never-exit service): a crafted inventory value
  must not be able to smuggle extra YAML lines or a secret into the unauthenticated board (C11).
"""
import importlib.util
import os
import re
import sys

import pytest

from kontroll import paths
from kontroll.service import homepage

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The committed PUBLIC reference services.yaml — the SHIPPED file the fleet span lives in (instance.example/ is
# NOT stripped by make-bundle). Its fleet span derives from instance.example/ (TEST-NET only); the live instance/
# span is operator state, stripped from the bundle, never committed.
EXAMPLE_SERVICES = os.path.join(ROOT, "instance.example", "dashboards", "homepage", "services.yaml")

# RFC 1918 private ranges — a real homelab address would match; RFC 5737 TEST-NET (192.0.2/198.51.100/203.0.113)
# never does and is the intended example. (Mirrors tests/unit/test_no_topology_leak.py, whose `*.generated.*` glob
# does NOT reach services.yaml — this is the co-located guard for the homepage example span.)
_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b")
# The real host/domain NAMES are this instance's own identifiers and are never written into the shipped tree:
# tests/_leak_guard.py reads them from the private overlay / CI secret, or the shipped canaries on a public checkout.
sys.path.insert(0, os.path.join(ROOT, "tests"))
import _leak_guard as _guard  # noqa: E402

_INSTANCE_TOKENS = _guard.instance_patterns(ROOT)


def _gen():
    """Load the hyphenated generator by path (gen-homepage is not an importable module name)."""
    spec = importlib.util.spec_from_file_location("gen_homepage", os.path.join(ROOT, "scripts", "gen-homepage.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _gen()

# A synthetic fleet+inventory using REAL module keys (so module.inventory_group resolves) but example hosts — the
# JOIN input for the editor-agreement pins (no disk inventory needed).
_FLEET = {"enabled_modules": ["cisco_ios", "fortigate"]}
_INV = {"all": {"children": {
    "core_switch": {"hosts": {"sw1": {"ansible_host": "192.0.2.2"}}},
    "edge_firewall": {"hosts": {"fw1": {"ansible_host": "192.0.2.1"}}}}}}
_PREAMBLE = ("# Homepage tiles (test fixture).\n"
             "- Control plane:\n"
             "    - GUI:\n"
             "        href: https://192.0.2.9:8443\n"
             "        description: onboarding\n")


def _fleet_span(text):
    """The committed services.yaml's fleet span text (begin marker .. end marker, inclusive), via the editor's
    own tokenizer — the exact bytes the editor treats as the opaque generated block."""
    _, blocks = homepage._split_services(text)
    fleet = [b["text"] for b in blocks if b["kind"] == "fleet"]
    return fleet[0] if fleet else ""


# --- the F3 staleness + leak gate over the committed PUBLIC example span ------------------------------------- #

def test_committed_example_fleet_span_is_fresh_and_testnet_only():
    """`gen-homepage --check` is green (the committed instance.example span == generator(instance.example/)) AND
    that span carries only TEST-NET addrs + example names. Guards two regressions: (1) a module/inventory edit not
    regenerated against the example, and (2) a maintainer committing a real-overlay regeneration — re-leaking the
    homelab topology into the SHIPPED example file (the F3 class, in a file the `*.generated.*` leak-gate misses)."""
    assert gen.main(["--check"]) == 0, "gen-homepage --check failed — re-run scripts/gen-homepage.py --example"
    span = _fleet_span(open(EXAMPLE_SERVICES, encoding="utf-8").read())
    assert span and "- Fleet:" in span, "the committed example has no generated fleet group to scan"
    priv = _PRIVATE_IP.findall(span)
    names = [tok for _, _, tok in _guard.token_findings(span, _INSTANCE_TOKENS)]   # index+digest only, never the name
    assert not priv and not names, "the committed example fleet span leaks real topology: %s %s" % (priv, names)


def test_committed_example_fleet_span_is_secret_free():
    """The committed fleet span is href:+description: only — NO `widget:` block, no `{{HOMEPAGE_VAR_*}}` token, no
    `password`. Guards a secret being generated into the unauthenticated board (C11 / SECURITY.md)."""
    span = _fleet_span(open(EXAMPLE_SERVICES, encoding="utf-8").read())
    for marker in ("widget:", "{{HOMEPAGE_VAR_", "password", "token:", "key:"):
        assert marker not in span, "the generated fleet span carries a secret/widget marker: %r" % marker


# --- the #130 producer<->consumer agreement: the editor locks the span the generator emits -------------------- #

def test_emitted_block_is_one_opaque_fleet_section_the_editor_flags_generated(tmp_repo):
    """The block gen-homepage emits, spliced into a services.yaml, is parsed by the editor's `_split_services` as
    EXACTLY ONE `fleet` block whose group `read_board` flags generated:true with the joined tiles — proving the
    span boundary AGREES with the editor (the core #130 deliverable). Guards the generator and editor drifting on
    the marker contract, which would let the GUI treat generated tiles as operator-editable (#124 ownership)."""
    block = gen.render_fleet_block(gen.fleet_rows(_FLEET, _INV))
    full = homepage.splice_fleet_block(_PREAMBLE, block)
    _, blocks = homepage._split_services(full)
    assert len([b for b in blocks if b["kind"] == "fleet"]) == 1     # exactly one opaque fleet span
    assert homepage._fleet_group_names(full) == {"Fleet"}            # the editor learns "Fleet" is generated
    # round-trip identity: the editor re-emits the file (incl. the fleet block verbatim) byte-for-byte
    preamble, blks = homepage._split_services(full)
    assert "".join([preamble] + [b["text"] for b in blks]) == full

    d = tmp_repo / "instance" / "dashboards" / "homepage"
    d.mkdir(parents=True)
    (d / "services.yaml").write_text(full, encoding="utf-8")
    (d / "settings.yaml").write_text("layout:\n  Control plane:\n    style: row\n  Fleet:\n    style: row\n",
                                     encoding="utf-8")
    board = homepage.read_board()
    fleet_sec = next(s for s in board["sections"] if s["name"] == "Fleet")
    assert fleet_sec["generated"] is True
    assert [it["name"] for it in fleet_sec["items"]] == ["core_switch · sw1", "edge_firewall · fw1"]


def test_editor_refuses_to_edit_a_generated_fleet_tile(tmp_repo):
    """With the generated block present, a board that drops (or alters membership of) a generated fleet tile is
    REJECTED by build_homepage_plan ('owned by gen-homepage'). Guards the editor letting an operator silently edit
    a generated tile — the dual of the generator owning the span (the two halves of the #124 ownership contract)."""
    full = homepage.splice_fleet_block(_PREAMBLE, gen.render_fleet_block(gen.fleet_rows(_FLEET, _INV)))
    d = tmp_repo / "instance" / "dashboards" / "homepage"
    d.mkdir(parents=True)
    (d / "services.yaml").write_text(full, encoding="utf-8")
    (d / "settings.yaml").write_text("layout:\n  Fleet:\n    style: row\n", encoding="utf-8")
    board = homepage.read_board()
    fleet_sec = next(s for s in board["sections"] if s["name"] == "Fleet")
    fleet_sec["items"][0]["present"] = False                        # try to drop a generated tile
    err = homepage.build_homepage_plan(board)["error"] or ""
    assert "owned by gen-homepage" in err


# --- generator semantics: idempotent, empty-fleet, injection-refused, optional descriptor -------------------- #

def test_splice_is_byte_idempotent():
    """Re-running the generator is byte-identical: splicing the freshly-rendered block into already-generated text
    reproduces it exactly. Guards a non-idempotent splice (which would make `--check` flap and every deploy show a
    spurious diff). Covers BOTH the append (first run) and replace-in-place (re-run) paths."""
    block = gen.render_fleet_block(gen.fleet_rows(_FLEET, _INV))
    once = homepage.splice_fleet_block(_PREAMBLE, block)             # append
    twice = homepage.splice_fleet_block(once, block)                 # replace-in-place
    assert once == twice


def test_empty_fleet_keeps_the_markers_without_a_group():
    """With no host carrying an address, the block is just the two markers around a comment — no `- Fleet:` group.
    The editor still sees one opaque `fleet` span (so the markers persist across regens) but flags NO generated
    section. Guards the markers vanishing on an empty fleet (which would make the first onboarded device's tile
    land as an editable operator tile instead of in the owned span)."""
    block = gen.render_fleet_block(gen.fleet_rows({"enabled_modules": []}, {}))
    assert "- Fleet:" not in block and gen.FLEET_BEGIN_LINE in block and gen.FLEET_END_LINE in block
    full = homepage.splice_fleet_block(_PREAMBLE, block)
    _, blocks = homepage._split_services(full)
    assert len([b for b in blocks if b["kind"] == "fleet"]) == 1
    assert homepage._fleet_group_names(full) == set()               # opaque span present, zero generated groups


def test_a_newline_in_a_tile_value_is_refused():
    """A crafted inventory `ansible_host` carrying a newline is REFUSED with sys.exit (never interpolated into the
    board) — the config-injection guard (a multi-line value would smuggle extra YAML into the unauthenticated
    portal). Generators fail-closed via sys.exit; the homepage SERVICE never does."""
    bad_inv = {"all": {"children": {"core_switch": {"hosts": {"sw1": {"ansible_host": "192.0.2.2\nevil: true"}}}}}}
    with pytest.raises(SystemExit):
        gen.services_after("", {"enabled_modules": ["cisco_ios"]}, bad_inv)


def test_a_malformed_address_renders_valid_yaml_not_a_broken_board():
    """A typo'd inventory `ansible_host` carrying a `: ` AND a ` #` (YAML mapping/comment metacharacters) is emitted
    as a QUOTED scalar, so the whole services.yaml still parses — a dead tile, never a corrupted board / blank
    :3000. Guards the self-inflicted-availability gap an UNQUOTED emit would open: gethomepage would fail to read
    the board (adversarial review #55, finding #3). The board parses AND the editor still sees one opaque fleet
    span."""
    import yaml
    bad_inv = {"all": {"children": {"core_switch": {"hosts": {"sw1": {"ansible_host": "192.0.2.2: evil # x"}}}}}}
    text, _ = gen.services_after(_PREAMBLE, {"enabled_modules": ["cisco_ios"]}, bad_inv)
    doc = yaml.safe_load(text)                                       # the WHOLE board still parses — no ScannerError
    fleet = next(g["Fleet"] for g in doc if isinstance(g, dict) and "Fleet" in g)
    assert fleet[0]["core_switch · sw1"]["href"] == "https://192.0.2.2: evil # x"   # literal (dead) link, intact
    _, blocks = homepage._split_services(text)
    assert len([b for b in blocks if b["kind"] == "fleet"]) == 1    # the editor still sees one opaque fleet span


def test_optional_homepage_descriptor_overrides_scheme_port_icon(monkeypatch):
    """An optional `homepage: {scheme, port, icon}` block in a module.yml customises the tile (fanned like
    `metrics:`); absent, the tile derives https/no-port/no-icon. Guards the self-describing seam (no-bespoke-config
    doctrine) silently being ignored — a module CAN steer its own tile without a generator edit."""
    monkeypatch.setattr(gen, "_load", lambda rel: {
        "inventory_group": "hypervisors", "homepage": {"scheme": "http", "port": 8006, "icon": "proxmox"}})
    inv = {"all": {"children": {"hypervisors": {"hosts": {"my-hypervisor": {"ansible_host": "192.0.2.10"}}}}}}
    rows = gen.fleet_rows({"enabled_modules": ["proxmox"]}, inv)     # proxmox module.yml exists, so the path check passes
    assert rows[0]["href"] == "http://192.0.2.10:8006" and rows[0]["icon"] == "proxmox"
    assert '        icon: "proxmox"\n' in gen.render_fleet_block(rows)   # emitted quoted (the _q scalar guard)
