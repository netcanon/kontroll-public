"""hostvars — the inventory HOST-VAR reconfigure instance (Phase 4b, #139).

A safe, diff-able change to an onboarded host's editable connection vars in the banner-owned drop-in
`instance/inventory/onboarded-<key>.yml`. Before 4b, the only path to a host's vars was `gitio.write_inventory_host`'s
silent key-level `.update()` — last-writer-wins with no diff, no confirm (design
`docs/reviews/2026-06-19-gui-paradigm/22-design-reconfigure-overwrite-rework.md` §5.3, G3). This lifts the
key-level collision into the reconfigure spine: a pure `current_values` read-back → `_diff.compute_changes` → the
diff-producing `gitio.owned_merge` (which REPORTS the overwritten vars) → `verify_no_drop` + the overwrite-confirm
+ the C10 two-key promote.

MVP scope: `ansible_host` ONLY — the routine "the device moved to a new IP" case (validated by the P0a ipv4
guard), severity `modify` (a single-host re-IP, blast `this-host` — NOT the control-plane `mgmt_ip`, which is
Phase 5). The host's TEMPLATED credential-lookup vars (`{{ lookup(…) }}`) are NOT editable here — rotating a
credential is the secret path (M-R-B), deliberately out of this surface. The host's OTHER vars (device_role, the
cred lookups) are carried through untouched, so an edit never drops them. The drop-in is machine-generated
(banner + safe_dump), so the write is a banner-preserving re-serialize, not comment-surgery.
"""
import logging
import os

import yaml

from kontroll import catalog, gitio, paths
from kontroll.service import _diff, promote
from kontroll.service._validate import validate_value
from kontroll.service.onboard import _INV_BANNER

log = logging.getLogger("kontroll.service.hostvars")

_AREA = "inventory-host"


def _knobs():
    """The editable host-var knob descriptors (settings/inventory-host.yml `knobs`), or [] if unregistered —
    the closed allow-list of which scalar connection vars may be reconfigured + each one's validator type."""
    doc = next((a for a in catalog.load_knob_descriptors() if a.get("area") == _AREA), None)
    return (doc.get("knobs") or []) if doc else []


def _drop_rel(key):
    """The drop-in inventory file's ROOT-relative path. EXISTENCE-based (`overlay_rel`), so it resolves to the
    SAME file `_find_host` read via `paths.resolve` (= ROOT + overlay_rel) — a host-var EDIT reads, writes, and
    stages ONE file. (Onboard's `overlay_target` is for NEW files; this surface only edits an existing drop-in, so
    read==write==staged — the propose-read and the apply-write can't diverge onto two inventory files.)"""
    return paths.overlay_rel("ansible/inventory/onboarded-%s.yml" % paths.component(key, "device-class key"))


def _find_host(key, host):
    """`(text, group, host_vars)` for `host` in class `key`'s drop-in, or `(text|None, None, None)` if the file
    is missing / not banner-owned / the host is absent. PURE read via paths.resolve (overlay-aware)."""
    path = paths.resolve("ansible/inventory/onboarded-%s.yml" % paths.component(key, "device-class key"))
    if not os.path.exists(path):
        return None, None, None
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return None, None, None
    if not text.startswith(_INV_BANNER):                     # foreign file — never edited in place (no-clobber)
        return text, None, None
    doc = yaml.safe_load(text) or {}
    for group, body in doc.items():
        hosts = (body or {}).get("hosts") or {}
        if host in hosts:
            return text, group, (hosts[host] or {})
    return text, None, None


def current_values(key, host):
    """The DECLARED EDITABLE vars of `host` in class `key` — a FLAT `{var: value}` over the reconfigurable knobs
    PRESENT (and NON-templated: a `{{ … }}` cred-lookup value is skipped — read-only) for pre-filling the
    renderer + the diff. PURE — reads the drop-in via paths.ROOT, writes nothing; {} if the host/file is absent
    (degrade, never raise). The reconfigure read-back (design 22 §5.3); these are non-secret connection vars."""
    _, group, host_vars = _find_host(key, host)
    if group is None:
        return {}
    editable = [k["key"] for k in _knobs() if k.get("key")]
    out = {}
    for var in editable:
        val = host_vars.get(var)
        if val is not None and not (isinstance(val, str) and "{{" in val):   # skip a templated cred-lookup (read-only)
            out[var] = val
    return out


def build_plan(key, host, selection):
    """Compute the host-var reconfigure PLAN for `host` in class `key`. `selection` = `{"values": {var: value}}`
    (the renderer submits the editable knob set, pre-filled from `current_values`). PURE — reads the drop-in,
    writes nothing. Returns {"error": "not_onboarded"|"foreign_file"|"unknown_field"|"bad_value"|None, ...}; on
    success the plan carries the banner-preserving merged `text_after` (via `gitio.owned_merge`, so the host's
    OTHER vars + sibling hosts survive), the field-level `changes`/`will_overwrite`/`severity`, the
    `current`/`proposed` structs `verify_no_drop` checks, the enact hand-off, and `token_parts`/`plan_token`
    (anti-drift + no-quiet-upgrade, M1)."""
    text, group, host_vars = _find_host(key, host)
    if text is None:
        return {"error": "not_onboarded", "key": key, "host": host}
    if group is None:                                        # file present but foreign OR host absent
        return {"error": "foreign_file" if not text.startswith(_INV_BANNER) else "not_onboarded",
                "key": key, "host": host}
    knobs = {k["key"]: k for k in _knobs() if k.get("key")}
    submitted = (selection or {}).get("values") or {}
    proposed = {}
    for var, value in submitted.items():
        knob = knobs.get(var)
        if knob is None:
            return {"error": "unknown_field", "key": key, "host": host, "field": var}
        bad = validate_value(dict(knob, key=var), value)     # the P0a config-injection guard (ipv4), server-side
        if bad:
            return {"error": "bad_value", "key": key, "host": host, "field": var, "detail": bad}
        proposed[var] = value

    current_edit = current_values(key, host)
    current_edit = {k: v for k, v in current_edit.items() if k in proposed}   # diff only what the dialog offered
    diff = _diff.compute_changes(current_edit, proposed, catalog.knob_meta(_AREA))

    # The host's FULL updated var set (other vars carried through untouched), merged via owned_merge — the
    # diff-producing replacement of the prior silent .update; collisions corroborate the field diff (G3).
    full_new = dict(host_vars, **{c["path"]: c["after"] for c in diff["changes"] if c["kind"] in ("add", "modify")})
    merged_doc, _collisions = gitio.owned_merge(text, group, {host: full_new})   # collisions ⊆ will_overwrite (the diff gates)
    text_after = (text if not diff["changes"]
                  else _INV_BANNER + yaml.safe_dump(merged_doc, sort_keys=False, allow_unicode=True, width=4096))

    # verify_no_drop runs over the FULL group host-map (every host + every var), NOT the editable subset — so a
    # dropped co-owner var (device_role, a cred-lookup) or a vanished SIBLING host fails closed at promote
    # (would_drop 409), which is the load-bearing machine anti-clobber the design names (§5.2). The operator-facing
    # diff stays the editable change-set; only the no-drop INPUT widens (review SHOULD-FIX 1).
    before_full = ((yaml.safe_load(text) or {}).get(group) or {}).get("hosts") or {}
    after_full = (merged_doc.get(group) or {}).get("hosts") or {}
    drop_rel = _drop_rel(key)
    sev_dec = _diff.severity_decision(diff)
    return {"error": None, "key": key, "host": host, "group": group, "drop_rel": drop_rel,
            "text_before": text, "text_after": text_after,
            "changes": diff["changes"], "will_overwrite": diff["will_overwrite"], "severity": diff["severity"],
            "current": before_full, "proposed": after_full,   # FULL group host-map — what verify_no_drop checks
            "paths": [drop_rel],
            "enact": hostvars_enact_commands(key, host, diff["changes"]),
            "token_parts": [text_after, sev_dec],
            "plan_token": promote.plan_token(text_after, sev_dec)}


def apply_plan(plan):
    """Write the reconfigured host vars into the drop-in inventory (banner + safe_dump re-serialize — the file is
    machine-generated, so no comment-surgery). Idempotent: identical content → no write. Returns
    {"changed", "paths"} — the drop-in path the route's scoped commit stages. The API runs no play."""
    path = os.path.join(paths.write_root(), plan["drop_rel"])
    changed = False
    before = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            before = fh.read()
    if before != plan["text_after"]:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as out:
            out.write(plan["text_after"])
        changed = True
        log.info("hostvars: wrote %s vars for %s (paths %s)",
                 plan["host"], plan["key"], ",".join(c["path"] for c in plan["changes"]))
    return {"changed": changed, "paths": [plan["drop_rel"]]}


def hostvars_enact_commands(key, host, changes):
    """The hand-off steps to make a promoted host-var change LIVE — the API runs none. A connection-var change
    takes effect on the host's next run; an `ansible_host` re-IP needs the device actually reachable there. Each
    step is `{kind, cmd, why}` (kind 'operator')."""
    fields = ",".join(sorted(c["path"] for c in changes if c["kind"] in ("add", "modify"))) or "none"
    return [{"kind": "operator",
             "cmd": "cd ansible && ansible -i inventory %s -m ping" % host,
             "why": "after promote + deploy, confirm %s is reachable at its new %s (a failed ping = wrong address "
                    "/ device not moved yet)" % (host, fields)}]
