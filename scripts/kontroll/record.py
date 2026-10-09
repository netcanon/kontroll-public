"""facts -> RECORD (the result schema).

A record is top-level metadata + a `capabilities` block (one {state,confidence,evidence}
cell per vector) + the suggested/candidate execution backends, with the overrides/ layer
merged at read time (an override patches a capability cell and stamps provenance). Pure;
the contract under test in tests/unit/test_build_record.py. Lifted verbatim from galaxy.py.
"""
from kontroll import predicate


def build_record(facts, vectors, overrides=None, backends=None):
    matches = predicate.classify(facts, backends or [])
    rec = {
        "collection": facts["collection"],
        "version": facts["version"],
        "origin": facts["origin"],
        "depth": facts["depth"],
        "meta": {"description": facts["description"], "tags": facts["tags"],
                 "certified": facts["certified"]},
        "capabilities": {v["name"]: predicate.eval_vector(v, facts) for v in vectors},
        "suggested_backend": matches[0] if matches else None,
        "backend_candidates": matches,
        "provenance": "derived",
    }
    ov = (overrides or {}).get(facts["collection"])
    if ov:
        for name, patch in (ov.get("capabilities") or {}).items():
            patch = dict(patch)
            # YAML parses `yes`/`no` as booleans; normalize back to our state strings.
            if patch.get("state") is True:
                patch["state"] = "yes"
            elif patch.get("state") is False:
                patch["state"] = "no"
            rec["capabilities"][name] = {**patch, "provenance": "override"}
        if ov.get("note"):
            rec["meta"]["note"] = ov["note"]
        rec["provenance"] = "derived+override"
    return rec
