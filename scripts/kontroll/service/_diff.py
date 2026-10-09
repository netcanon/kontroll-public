"""service/_diff — the capability-NEUTRAL field-level DIFFER for the safe-reconfigure paradigm (Phase 4a, #138).

`compute_changes` turns a (current, proposed) pair of normalized `{entry: {param: value}}` dicts into a
structured, field-level change-set the operator reviews BEFORE anything stages — the central new primitive of the
reconfigure crux (design `docs/reviews/2026-06-19-gui-paradigm/22-design-reconfigure-overwrite-rework.md` §4).
It is descriptor-neutral (no `if cap==…`): it compares the two dicts the instance's `current_values` + the
dialog selection already produce, so adding a capability/knob is a drop-in, never a differ edit. PURE — no I/O,
no write.

`severity` is the MAX over the change-set and drives the UI confirm weight: `add` (a new entry/param —
co-owner-safe, no confirm) < `modify` (an existing value REPLACED — a clobber, needs the overwrite-confirm) <
`remove` (an entry/param dropped — strongest of the value tiers) < `redeploy` (a value whose change only takes
effect after a stack re-deploy — an ack confirm) < `identity` (a RE-CLASSIFY that re-homes hosts / orphans
creds — the heaviest, a type-to-confirm gate). `will_overwrite` is the explicit CLOBBER SET: the exact paths
whose prior value is being replaced (what the overwrite-confirm enumerates, and what the token's severity-fold
locks). A change MISLABELLED `add` when it is really `modify` would skip the confirm — so this classifier is the
load-bearing one the reviewer pins.

Two shapes flow through one differ (Phase 4b, #139): the NESTED `{entry: {param: value}}` capability shape
(telemetry/backup/logging — Phase 4a) AND a FLAT `{key: scalar}` shape (module identity, platform settings),
where each key is its own leaf. The optional `knob_meta` ({path: {severity, blast_radius}}, from
`catalog.knob_meta(area)`) UPGRADES a `modify`/`remove` of a declared identity/redeploy knob to that heavier
severity — design 22 §10's descriptor-driven classification, DATA not code. An `add` (a first-set) is NEVER
upgraded: only a change to an EXISTING value carries the heavier gate (design 22 §10). PURE — no I/O, no write.
"""

_SEV_RANK = {"add": 0, "modify": 1, "remove": 2, "redeploy": 3, "identity": 4}
_MISSING = object()   # distinguishes an ABSENT entry from one whose value is None (a flat knob can be None)


def effective_severity(change):
    """The severity that drives the confirm for one change: the descriptor-declared UPGRADE if present
    (`identity`/`redeploy` stamped on a modify/remove), else the change `kind`. The single seam the diff render +
    the gate read, so a knob upgraded by `knob_meta` fires the heavier confirm without a second classifier."""
    return change.get("severity") or change["kind"]


def compute_changes(current, proposed, knob_meta=None):
    """Field-level change-set of `current` → `proposed`. Each side is either the NESTED `{entry: {param: value}}`
    capability shape OR a FLAT `{key: scalar}` shape (module identity / settings) — the differ handles both per
    entry (a dict proposed value → param-by-param; a scalar → a leaf). Returns `{changes: [{path, kind, before?,
    after?, severity?, blast_radius?}], will_overwrite: [path...], severity: <max effective>|None}`. `kind` per
    change: `add` (absent in current) | `modify` (present, DIFFERENT value — a clobber) | `remove` (present in
    current, absent in proposed). `knob_meta` ({path: {severity, blast_radius}}) UPGRADES a modify/remove of a
    declared identity/redeploy knob (design 22 §10); an add is never upgraded. `severity` is the max EFFECTIVE
    severity, or None for an idempotent no-op. PURE."""
    knob_meta = knob_meta or {}
    changes = []
    for entry in current:                                    # an entry present in current but dropped → remove
        if entry not in proposed:
            changes.append({"path": entry, "kind": "remove", "before": current[entry]})
    for entry, pval in proposed.items():
        cval = current.get(entry, _MISSING)
        if isinstance(pval, dict):                           # NESTED entry — compare param-by-param (Phase 4a)
            if cval is _MISSING:                             # a whole new entry → add
                changes.append({"path": entry, "kind": "add", "after": pval})
                continue
            cvals = cval if isinstance(cval, dict) else {}
            for p, after in (pval or {}).items():
                if p not in cvals:
                    changes.append({"path": "%s.%s" % (entry, p), "kind": "add", "after": after})
                elif cvals[p] != after:
                    changes.append({"path": "%s.%s" % (entry, p), "kind": "modify",
                                    "before": cvals[p], "after": after})
            for p in cvals:                                  # a param dropped from an existing entry → remove
                if p not in (pval or {}):
                    changes.append({"path": "%s.%s" % (entry, p), "kind": "remove", "before": cvals[p]})
        elif cval is _MISSING:                               # FLAT scalar entry, absent → add
            changes.append({"path": entry, "kind": "add", "after": pval})
        elif cval != pval:                                   # FLAT scalar entry, changed → modify
            changes.append({"path": entry, "kind": "modify", "before": cval, "after": pval})
    # Descriptor-driven severity UPGRADE (design 22 §10): a modify/remove of a knob the descriptor marks
    # identity/redeploy fires the heavier confirm; an `add` (a first-set) is co-owner-safe and never upgraded.
    for c in changes:
        meta = knob_meta.get(c["path"]) if c["kind"] in ("modify", "remove") else None
        declared = (meta or {}).get("severity")
        if declared and _SEV_RANK.get(declared, 0) > _SEV_RANK[c["kind"]]:
            c["severity"] = declared
            if meta.get("blast_radius"):
                c["blast_radius"] = meta["blast_radius"]
    will_overwrite = [c["path"] for c in changes if c["kind"] == "modify"]
    severity = None
    for c in changes:
        eff = effective_severity(c)
        if severity is None or _SEV_RANK[eff] > _SEV_RANK[severity]:
            severity = eff
    return {"changes": changes, "will_overwrite": will_overwrite, "severity": severity}


def severity_decision(diff):
    """The canonical, order-stable string of a change-set's `{severity, sorted(will_overwrite)}` that the token
    folds in (design 22 §7.1; synthesis M1) — so a promote whose recomputed plan is MORE destructive (a new
    overwrite, a higher severity) yields a DIFFERENT token and is refused (no-quiet-upgrade). It is NOT an
    authorization control on its own — the anti-clobber controls are `verify_no_drop` + the human confirm + the
    C10 two-key promote. Empty/no-op diff → a stable 'none|' sentinel."""
    sev = diff.get("severity") or "none"
    return "%s|%s" % (sev, ",".join(sorted(diff.get("will_overwrite") or [])))
