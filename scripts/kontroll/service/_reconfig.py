"""service/_reconfig — the no-drop INVARIANT for the safe-reconfigure paradigm (Phase 4a, #138), generalized
from `keygen._verify_additive` (the one already-correct safe-reconfigure in the tree).

`verify_no_drop` is the MACHINE half of anti-clobber, run by the capability spine at PROMOTE after `verify_token`
and before the write. A reconfigure may CHANGE the values its change-set names, but it may NEVER silently DROP an
entry/param a co-owner declared that the change-set did not explicitly authorize as a `remove`. Fail-closed: on
any unauthorized disappearance it returns False → the promote refuses (no write). This is the structural
anti-clobber for the cross-seam same-file race (two reconfigure dialogs on one class): `verify_token` catches the
byte drift, `verify_no_drop` catches a co-owner's VANISHED data. Anti-drift (the token) and anti-clobber (this +
the human severity-confirm + C10's two-key promote) are COMPLEMENTARY — neither is the other, and the token is
NOT an authorization control (design 22 §0/§5.2; synthesis M1). Generalized from `keygen._verify_additive`'s
`prior <= now` no-drop assertion — set-containment, fail-closed, deliberately NOT a policy engine.
"""


def paths(struct):
    """The flat set of `entry` (+ `entry.param` for a NESTED entry) paths present in a struct — the same
    granularity `_diff.compute_changes` emits, so a `remove` authorization is matched path-for-path. Handles
    BOTH the nested capability shape `{entry: {param: value}}` AND a flat scalar shape `{key: value}` (module
    identity / settings, Phase 4b): a scalar value is a leaf (`key`), never descended into — without the
    isinstance guard a string value would be iterated char-by-char into bogus `key.<char>` paths."""
    out = set()
    for entry, params in (struct or {}).items():
        out.add(entry)
        if isinstance(params, dict):
            for p in params:
                out.add("%s.%s" % (entry, p))
    return out


def verify_no_drop(before, after, intended_changes):
    """True iff `after` drops NO path present in `before` that `intended_changes` did not explicitly mark
    `remove`. `before`/`after` are the normalized `{entry: {param: value}}` structs (current vs proposed);
    `intended_changes` is the `compute_changes` change-set. The machine anti-clobber gate: fail-closed — any
    unauthorized disappearance returns False and the promote must refuse. Generalized from
    `keygen._verify_additive`'s prior<=now no-drop assertion."""
    authorized_removes = {c.get("path") for c in (intended_changes or []) if c.get("kind") == "remove"}
    must_survive = paths(before) - authorized_removes
    return must_survive <= paths(after)


def run_promote(build_plan, apply_plan, token, *build_args):
    """The shared single-object PROMOTE half (Phase 4b): RECOMPUTE the plan, refuse on anti-drift token mismatch
    (`drift`) or the machine no-drop gate (`would_drop`), else apply the write. Identity + host-var reconfigure
    both flow through this ONE sequence — token → no_drop → apply — so the anti-clobber ordering is a single seam,
    not re-implemented per surface (the capability spine `capability.promote` is its pre-existing twin; both run
    the identical gates, design 22 §5.2/§9.3). Returns the recomputed `plan`, `changed`, and `paths` on success,
    or `{error: 'drift'|'would_drop', changes}` (the route renders the diff on the 409, G6). `build_plan` is PURE
    (the recompute writes nothing); only `apply_plan` writes — and only AFTER both gates pass."""
    from kontroll.service.promote import verify_token   # local import — keeps this module import-light + cycle-free
    plan = build_plan(*build_args)
    if plan.get("error"):
        return plan
    if not verify_token(token, *plan.get("token_parts", [])):                       # anti-DRIFT (+ no-quiet-upgrade, M1)
        return {"error": "drift", "changes": plan.get("changes")}
    if not verify_no_drop(plan.get("current") or {}, plan.get("proposed") or {}, plan.get("changes") or []):
        return {"error": "would_drop", "changes": plan.get("changes")}             # anti-CLOBBER machine gate (fail-closed)
    result = apply_plan(plan)
    return {"error": None, "plan": plan, **result}
