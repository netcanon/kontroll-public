"""units domain — enumerate the RUNNABLE units of an installed collection (the app-store "search → unit" seam).

`service_units` turns one installed collection into its launchable units (collection-shipped playbooks + roles),
keyed by a stable `<collection>/<kind>/<name>` id the later configure/push stages reference. READ-ONLY by
construction (filesystem + `ansible-galaxy collection list` reads only — no actuation, no write verb); pinned by
`tests/unit/test_units.py::test_service_units_is_read_only`.

SEC-3 traversal guard (the load-bearing security property): `collection` is resolved against the ENUMERATED
installed set (`catalog._installed_json`) and only its on-disk `base_path` is then walked. A request param is
NEVER `os.path.join`'d directly, so `../etc`, a null byte, or any absent/crafted name resolves to "not installed"
(→ 404) and can never read outside the installed collections' own directories. This mirrors the design's
report-23 SEC-3 fix: route path params resolve against the installed set, never the raw string.
"""
import os

from kontroll import catalog, paths, probe
from kontroll.service import _validate


def _has_values(key):
    """Whether actuation unit `key` has a committed configure-values file (instance/actuation/<key>/vars.yml) —
    a read-only existence check over the overlay target so the Automations index can show configured-vs-not.
    Degrades to False on any path error (an honest "not configured", never a raise). PURE + READ-ONLY."""
    try:
        return os.path.isfile(os.path.join(paths.write_root(), paths.overlay_target("actuation/%s/vars.yml" % key)))
    except Exception:                            # a malformed key/overlay → "not configured", never a worker crash
        return False


def registered_units_view():
    """Project every REGISTERED actuation unit (instance/actuation/<key>/unit.yml) into a NON-SECRET summary for
    the GUI's Automations index — the entry point the configure dialog opens from. Returns
    `[{key, name, collection, kind, device_class, inventory_group, blast_radius, pin, knobs, configured}]`, sorted
    by key (catalog.load_actuation_units already sorts + skips malformed descriptors). Each row's `key` addresses
    `/api/configurable?kind=actuation-unit` (the knob group) and `POST /api/actuation/<key>` (preview/stage); `pin`
    is the exact `==` install version, `knobs` the curated-knob COUNT (never the values), `configured` whether a
    committed vars.yml exists yet. Distinct from `service_units` (a COLLECTION's runnable units, the create-stage
    source) — this lists the units the operator has already authored. READ-ONLY by construction (registry read +
    a file-exists check, no write verb); pinned by test_units.test_registered_units_view_is_read_only. No field is
    a secret (the descriptor + its values are non-secret config — SEC-2)."""
    out = []
    for u in catalog.load_actuation_units():
        unit = u.get("unit") or {}
        target = u.get("target") or {}
        colls = ((u.get("install") or {}).get("collections")) or []
        pin = colls[0].get("version") if (colls and isinstance(colls[0], dict)) else None
        key = u.get("key")
        out.append({"key": key, "name": unit.get("name") or unit.get("repo_playbook") or key,
                    "collection": unit.get("collection"), "kind": unit.get("kind"),
                    "device_class": target.get("device_class"), "inventory_group": target.get("inventory_group"),
                    "blast_radius": target.get("blast_radius"), "pin": pin,
                    "knobs": len([k for k in (u.get("knobs") or []) if k.get("key")]),
                    "configured": _has_values(key)})
    return out


def service_units(collection, installed=None):
    """Enumerate the runnable units of the INSTALLED collection `collection` →
    `{"collection": <name>, "units": [{"kind", "name", "id"}]}`, or **None** if it is not installed (the route
    maps None → 404). `installed` is the I/O seam tests inject; it defaults to `catalog._installed_json()`
    (`{search_path: {name: info}}`). First search-path wins, mirroring `local_installed`.

    The units list is sorted by (kind, name) for a stable projection; `id` is the `<collection>/<kind>/<name>`
    child key the configure/push stages key off. A collection that ships only modules (the device-management
    fleet — see the worked extraction) yields an empty list, correctly."""
    installed = installed if installed is not None else catalog._installed_json()
    base_path = None
    for base, colls in installed.items():
        if collection in colls:                 # SEC-3: only proceed for a name the installed set actually has
            base_path = base
            break
    if base_path is None:
        return None                             # not installed → 404; never path-join an unresolved param

    by_kind = probe.units_in_collection(collection, base_path)
    units = []
    for kind in probe.UNIT_KINDS:               # closed, ordered kind set — not the dict's iteration order
        for name in by_kind.get(kind, []):
            units.append({"kind": kind, "name": name, "id": "%s/%s/%s" % (collection, kind, name)})
    return {"collection": collection, "units": units}


def validate_unit_config(key, values, unit=None):
    """Validate operator-submitted configure VALUES against actuation unit `key`'s curated knob descriptors (R3
    configure form), via the P0a service/_validate guard — the server-side twin of the GUI widgets (the widget is
    convenience, this is the contract). Returns `{"error": None, "ok": <bool>, "errors": {knob_key: msg}}`, or
    `{"error": "no_unit"}` when the key is absent (the route maps it to 404). `unit` is the I/O seam tests inject;
    it defaults to `catalog.actuation_unit(key)`.

    PURE + READ-ONLY (pinned by test_units.test_validate_unit_config_is_read_only): it reads the descriptor and
    re-checks values — it stages nothing, decrypts nothing, opens no file for writing. FAIL-CLOSED on every axis:
    a CLOSED allow-list (a submitted key the descriptor doesn't declare is rejected, so no un-described var can
    ride to a later stage), a required-but-missing knob is an error, and every present value is checked by its
    knob's validator (an `int` out of range, a `text` not matching its pattern, an `enum` outside its allow-list —
    all rejected). Secret-typed knobs are forbidden at the descriptor layer (gen-actuation), so no value here is
    ever a credential (SEC-2)."""
    unit = unit if unit is not None else catalog.actuation_unit(key)
    if not unit:
        return {"error": "no_unit"}
    knobs = {k["key"]: k for k in (unit.get("knobs") or []) if k.get("key")}
    values = values or {}
    errors = {name: "%r is not a configurable knob of this unit" % name
              for name in values if name not in knobs}        # closed allow-list — an un-described var never proceeds
    for kkey, knob in knobs.items():
        if values.get(kkey) in (None, ""):                    # absent/blank: an error only when the knob is required
            if knob.get("required"):
                errors[kkey] = "%s is required" % kkey
            continue
        verr = _validate.validate_value(knob, values[kkey])
        if verr:
            errors[kkey] = verr
    return {"error": None, "ok": not errors, "errors": errors}
