"""Resolve a device class's connection TRUST POSTURE from its module `vendor_defaults` + the instance trust
decision — the SHARED "one vendor fact, N consumers" seam (the no-bespoke-config tenet).

A device-class fact like "Proxmox VE ships a self-signed cert by default" is PUBLIC and CHURNING (a vendor can
change it), so it must live in ONE place (`modules/<key>/module.yml`'s `vendor_defaults:`), captured from a public
source + pinned + visible — NEVER hardcoded per consumer. Both `gen-logging.py` (a Vector pull source's `tls`
block) and `gen-exporters.py`/telemetry (an exporter's `*_VERIFY_SSL` env) derive the SAME TLS posture from here,
so the fact can't drift between them and a vendor change is a one-line edit in the module (a reviewable diff),
not a hunt through bespoke descriptors.

Two layers (the tenet's vendor-FACT vs instance-DECISION split):
  - the VENDOR FACT = `vendor_defaults.tls_posture` (self_signed | ca_signed), the device class's documented
    default — captured from public docs / the device's own presented cert, pinned in the module;
  - the INSTANCE DECISION = an operator's optional CA pin (`device_trust.<key>.tls_ca_file` in instance.yml),
    which HARDENS verification on + supplies the CA — the operator's trust call, kept as instance data.

Fail-CLOSED: a method that opts into class TLS but whose class declares no/an unknown posture RAISES (a typo can
never silently DISABLE certificate verification — the safe direction is to refuse to generate, loudly).
"""

# tls_posture -> the default `verify_certificate` for a connection to that device class. A PUBLIC vendor fact:
# self-signed appliances (homelab PVE, most network gear's mgmt UI) can't be verified against a public CA;
# ca-signed endpoints can. Captured here as the closed mapping the generators consume.
_POSTURE_VERIFY = {"self_signed": False, "ca_signed": True}

# The operator-pinned device CA bundle (a PUBLIC cert — not a SOPS secret). deploy-stack ASSEMBLES it from every
# `device_trust.<key>.tls_ca_file` across all pinned classes into ONE host file; both consumers verify against
# that one bundle, so pinning a CA for a NEW class needs NO hub edit (the no-bespoke / one-fact tenet). The
# generators write these FIXED in-CONTAINER targets (NOT the operator's host path) — the host->container bind is
# the static vector.yaml mount + the gen-exporters volume, both sourced from CA_BUNDLE_HOST (a ${ENV} host path).
CA_BUNDLE_BASENAME = "device-ca-bundle.pem"
CA_BUNDLE_HOST = "${KONTROLL_STORAGE_ROOT:-/var/lib/kontroll}/vector/" + CA_BUNDLE_BASENAME  # bind SOURCE (host)
VECTOR_CA_BUNDLE = "/etc/vector-keys/" + CA_BUNDLE_BASENAME        # Vector source.tls.ca_file target (in-container)
EXPORTER_CA_BUNDLE = "/etc/exporter-certs/" + CA_BUNDLE_BASENAME   # exporter REQUESTS_CA_BUNDLE target (in-container)


def tls_verify(vendor_defaults, instance_trust=None):
    """-> (verify: bool, ca_file: str | None) for a device-class connection.

    The VENDOR DEFAULT comes from `vendor_defaults.tls_posture`; an INSTANCE CA pin
    (`instance_trust.tls_ca_file`) overrides it to verify=True + that CA path (the hardening path). Fail-closed:
    a missing or unknown `tls_posture` raises ValueError (never silently returns verify=False — the generator
    converts the raise into a loud config-as-data exit). Absent `instance_trust` => the pure vendor default."""
    posture = (vendor_defaults or {}).get("tls_posture")
    if posture not in _POSTURE_VERIFY:
        raise ValueError(
            "vendor_defaults.tls_posture is %r; expected one of %s — a class whose method needs TLS MUST "
            "declare a known posture (fail-closed: a typo must never disable cert verification)"
            % (posture, sorted(_POSTURE_VERIFY)))
    ca_file = (instance_trust or {}).get("tls_ca_file")
    if ca_file:
        return True, ca_file          # operator pinned a CA -> verify ON regardless of the vendor default
    return _POSTURE_VERIFY[posture], None
