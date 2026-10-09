"""Three-valued capability predicate engine.

eval_pred -> True / False / None (None = unknown at this probe depth); eval_vector
folds a vector's ordered match rules into a {state, confidence, evidence} cell; classify
picks which execution backend(s) fit a collection's facts. Pure dict->dict, no I/O —
the contract under test in tests/unit/test_predicate_engine.py + test_classify.py.
Lifted verbatim from galaxy.py.
"""


def classify(facts, backends):
    """Which backend(s) fit this collection (ordered; best first). `manual`
    backends are never auto-matched — they're chosen by explicit declaration."""
    out = []
    for b in backends:
        c = b.get("classify") or {}
        if c.get("manual"):
            continue
        if eval_pred(c, facts) is True:
            out.append(b["name"])
    return out


def eval_pred(pred, facts):
    (kind, val), = pred.items()
    if kind == "plugin":
        return bool(facts["plugins"].get(val))
    if kind == "module_suffix":
        return any(m.endswith(val) for m in facts["modules"])
    if kind == "module_option":
        if not facts["module_options"]:
            return None
        return any(m.endswith(val["suffix"]) and val["option"] in opts
                   for m, opts in facts["module_options"].items())
    if kind in ("any_of", "all_of", "none_of"):
        rs = [eval_pred(p, facts) for p in val]
        if kind == "any_of":
            return True if any(r is True for r in rs) else (None if None in rs else False)
        if kind == "all_of":
            return False if any(r is False for r in rs) else (None if None in rs else True)
        return False if any(r is True for r in rs) else (None if None in rs else True)
    return None


def pred_evidence(pred, facts):
    (kind, val), = pred.items()
    if kind == "plugin":
        return "%s:%s" % (val, ",".join(facts["plugins"].get(val, [])))
    if kind == "module_suffix":
        hit = next((m for m in facts["modules"] if m.endswith(val)), val)
        return hit
    if kind == "module_option":
        hit = next((m for m, o in facts["module_options"].items()
                    if m.endswith(val["suffix"]) and val["option"] in o), None)
        return "%s.%s" % (hit, val["option"]) if hit else val["option"]
    return kind


def eval_vector(vector, facts):
    saw_unknown = False
    for m in vector["match"]:
        r = eval_pred(m["rule"], facts)
        if r is True:
            return {"state": "yes", "confidence": m["confidence"],
                    "evidence": pred_evidence(m["rule"], facts)}
        if r is None:
            saw_unknown = True
    return {"state": "maybe" if saw_unknown else "no", "confidence": None, "evidence": None}
