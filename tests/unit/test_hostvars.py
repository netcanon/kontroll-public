"""hostvars — the inventory HOST-VAR reconfigure instance + the gitio.owned_merge primitive (Phase 4b, #139).

These pin the routine "the device moved to a new IP" edit and the diff-producing merge under it. WHY (the
failures they guard): before 4b a host-var change went through `write_inventory_host`'s silent `.update()` —
last-writer-wins with NO diff, NO confirm (design 22 §5.3). owned_merge lifts the key-level overwrite into a
REPORTED collision (so the edit can show + gate it), and must PRESERVE the host's other vars + sibling hosts (an
edit may never drop device_role / a co-owner host). The service must classify an ansible_host change as `modify`
(an overwrite-confirm), validate it as an IPv4 BEFORE the write (config-injection), keep the host's TEMPLATED
cred-lookup vars read-only (M-R-B — never an editable knob), and gate the write on the plan_token.
"""
import pytest
import yaml

from kontroll import gitio
from kontroll.service import hostvars, promote
from kontroll.service.onboard import _INV_BANNER

pytestmark = pytest.mark.unit

_GROUP = "core_switch"
_HOST = "sw-1"
# A host with an editable address, a non-editable role, and a TEMPLATED cred-lookup (must stay read-only).
_HOST_VARS = {"ansible_host": "192.0.2.10", "device_role": "backend_network_cli",
              "ansible_user": "{{ (lookup('community.sops.sops', x) | from_yaml).sw_1_username }}"}


def _write_drop(tmp_repo, key="demo_sw", group=_GROUP, hosts=None):
    hosts = hosts if hosts is not None else {_HOST: dict(_HOST_VARS)}
    d = tmp_repo / "ansible" / "inventory"
    d.mkdir(parents=True, exist_ok=True)
    body = _INV_BANNER + yaml.safe_dump({group: {"hosts": hosts}}, sort_keys=False, allow_unicode=True)
    (d / ("onboarded-%s.yml" % key)).write_text(body, encoding="utf-8")
    return d / ("onboarded-%s.yml" % key)


# --- gitio.owned_merge (the diff-producing merge primitive, §5.3) ----------------------------------------- #
def test_owned_merge_reports_collisions_and_preserves_siblings():
    """owned_merge merges a host's new vars, REPORTS each (host, var) whose prior value differs (the silent
    .update lifted into a diff), and never drops a sibling host or an unlisted var. THE anti-silent-clobber
    case: a key-level overwrite must be visible, not last-writer-wins-in-the-dark."""
    text = _INV_BANNER + yaml.safe_dump(
        {_GROUP: {"hosts": {"sw-1": {"ansible_host": "192.0.2.10", "device_role": "r"},
                            "sw-2": {"ansible_host": "192.0.2.20"}}}}, sort_keys=False)
    merged, collisions = gitio.owned_merge(text, _GROUP, {"sw-1": {"ansible_host": "192.0.2.99", "device_role": "r"}})
    assert collisions == [{"host": "sw-1", "var": "ansible_host", "before": "192.0.2.10", "after": "192.0.2.99"}]
    assert merged[_GROUP]["hosts"]["sw-1"]["ansible_host"] == "192.0.2.99"
    assert merged[_GROUP]["hosts"]["sw-1"]["device_role"] == "r"          # unchanged var survives
    assert merged[_GROUP]["hosts"]["sw-2"]["ansible_host"] == "192.0.2.20"  # sibling host survives


# --- the hostvars service ---------------------------------------------------------------------------------- #
def test_propose_is_pure(tmp_repo):
    """build_plan is PURE — computing a host-var plan leaves the drop-in byte-identical. Guards the propose/
    promote boundary (only promote writes)."""
    p = _write_drop(tmp_repo)
    before = p.read_text(encoding="utf-8")
    plan = hostvars.build_plan("demo_sw", _HOST, {"values": {"ansible_host": "192.0.2.99"}})
    assert plan["error"] is None
    assert p.read_text(encoding="utf-8") == before


def test_reconfigure_ansible_host_is_modify_and_preserves_other_vars(tmp_repo):
    """Changing ansible_host is a `modify` (overwrite-confirm), the merged write KEEPS device_role + the templated
    cred-lookup untouched, and the plan_token gates the exact bytes. THE load-bearing case: a re-IP must not drop
    the host's role/creds, and must fire the overwrite-confirm (not silently land)."""
    p = _write_drop(tmp_repo)
    plan = hostvars.build_plan("demo_sw", _HOST, {"values": {"ansible_host": "192.0.2.99"}})
    assert plan["error"] is None and plan["severity"] == "modify"
    assert plan["changes"] == [{"path": "ansible_host", "kind": "modify",
                                "before": "192.0.2.10", "after": "192.0.2.99"}]
    assert plan["will_overwrite"] == ["ansible_host"]
    assert promote.verify_token(plan["plan_token"], *plan["token_parts"]) is True
    hostvars.apply_plan(plan)
    doc = yaml.safe_load(p.read_text(encoding="utf-8"))[_GROUP]["hosts"][_HOST]
    assert doc["ansible_host"] == "192.0.2.99"
    assert doc["device_role"] == "backend_network_cli"                   # other var preserved
    assert "{{" in doc["ansible_user"]                                   # templated cred-lookup untouched


def test_no_drop_struct_is_the_full_group_host_map(tmp_repo):
    """build_plan feeds verify_no_drop the FULL group host-map (every host + every var), NOT the editable
    `{ansible_host}` subset — so a dropped co-owner var (device_role / the cred-lookup) or a vanished SIBLING host
    fails closed at promote. Guards review SHOULD-FIX 1: the machine anti-clobber is load-bearing here, not
    defense-in-name (a too-small input can't express a drop, so it always returned True)."""
    _write_drop(tmp_repo, hosts={_HOST: dict(_HOST_VARS), "sw-2": {"ansible_host": "192.0.2.20"}})
    plan = hostvars.build_plan("demo_sw", _HOST, {"values": {"ansible_host": "192.0.2.99"}})
    assert "sw-2" in plan["current"] and "device_role" in plan["current"][_HOST]   # the FULL map, not {ansible_host}
    assert "sw-2" in plan["proposed"] and "device_role" in plan["proposed"][_HOST]
    from kontroll.service._reconfig import verify_no_drop
    dropped = {k: v for k, v in plan["proposed"].items() if k != "sw-2"}            # a vanished sibling host…
    assert verify_no_drop(plan["current"], dropped, plan["changes"]) is False       # …now fails closed
    assert verify_no_drop(plan["current"], plan["proposed"], plan["changes"]) is True   # the real edit passes


def test_same_value_is_a_noop(tmp_repo):
    """Submitting the current ansible_host unchanged is a no-op: empty change-set, severity None, text_after ==
    text_before. Guards a re-submit being treated as a clobber."""
    _write_drop(tmp_repo)
    plan = hostvars.build_plan("demo_sw", _HOST, {"values": {"ansible_host": "192.0.2.10"}})
    assert plan["error"] is None and plan["changes"] == [] and plan["severity"] is None
    assert plan["text_after"] == plan["text_before"]


def test_templated_cred_var_is_not_an_editable_knob(tmp_repo):
    """current_values SKIPS the host's templated `{{ … }}` cred-lookup var (read-only — rotating a credential is
    the secret path, M-R-B), and submitting a non-declared var is `unknown_field`. Guards the host-var surface
    ever exposing/clobbering a credential."""
    _write_drop(tmp_repo)
    assert "ansible_user" not in hostvars.current_values("demo_sw", _HOST)
    assert hostvars.build_plan("demo_sw", _HOST,
                               {"values": {"ansible_user": "x"}})["error"] == "unknown_field"


def test_a_crafted_ip_is_rejected_before_the_write(tmp_repo):
    """A non-IPv4 ansible_host (here an injection) is `bad_value` — the P0a ipv4 guard, server-side, before any
    byte is written. Guards a crafted address reaching the rendered inventory."""
    _write_drop(tmp_repo)
    bad = hostvars.build_plan("demo_sw", _HOST, {"values": {"ansible_host": "192.0.2.10\nx: y"}})
    assert bad["error"] == "bad_value" and bad["field"] == "ansible_host"


def test_not_onboarded_and_foreign_file(tmp_repo):
    """A class with no drop-in is `not_onboarded`; a drop-in NOT carrying our banner (an operator rewrite) is
    `foreign_file` — never edited in place (the no-clobber-operator-edits guarantee). Guards the edit touching a
    file we don't own."""
    assert hostvars.build_plan("ghost", _HOST, {"values": {"ansible_host": "192.0.2.1"}})["error"] == "not_onboarded"
    d = tmp_repo / "ansible" / "inventory"
    d.mkdir(parents=True, exist_ok=True)
    (d / "onboarded-foreign.yml").write_text("core_switch:\n  hosts:\n    sw-1: {ansible_host: 192.0.2.10}\n",
                                             encoding="utf-8")
    assert hostvars.build_plan("foreign", "sw-1",
                               {"values": {"ansible_host": "192.0.2.1"}})["error"] == "foreign_file"


def test_apply_is_idempotent(tmp_repo):
    """Applying the same host-var plan twice writes once. Guards a non-idempotent host-var write (the 0-changed
    rule)."""
    _write_drop(tmp_repo)
    plan = hostvars.build_plan("demo_sw", _HOST, {"values": {"ansible_host": "192.0.2.77"}})
    assert hostvars.apply_plan(plan)["changed"] is True
    assert hostvars.apply_plan(plan)["changed"] is False
    re_plan = hostvars.build_plan("demo_sw", _HOST, {"values": {"ansible_host": "192.0.2.77"}})
    assert re_plan["changes"] == [] and re_plan["text_after"] == re_plan["text_before"]
