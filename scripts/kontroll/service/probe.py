"""probe domain — deep-probe one collection into its capability record.

service_probe returns {"facts","record"} (the CLI prints the detail view + evidence),
or None when the collection isn't installed locally — the CLI owns the not-installed
error message + install hint.
"""
from kontroll import catalog, probe, record


def service_probe(collection, vectors=None, overrides=None, backends=None):
    """Deep-probe one locally-installed collection and return {"facts","record"}, or
    None if it isn't installed (no modules/plugins found)."""
    vectors = vectors if vectors is not None else catalog.load_vectors()
    overrides = overrides if overrides is not None else catalog.load_overrides()
    backends = backends if backends is not None else catalog.load_backends()
    f = probe.deep_probe(collection)
    if not f["modules"] and not f["plugins"]:
        return None
    return {"facts": f, "record": record.build_record(f, vectors, overrides, backends)}
