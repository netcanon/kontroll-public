"""scripts/kontroll/endpoints.py — the shared device-class TLS trust resolver (the no-bespoke vendor-fact ⊕
instance-decision seam, B2). Codifies the contract: a PUBLIC vendor posture maps to a verify default, an operator
CA pin (the instance DECISION) hardens verification on, and a missing/unknown posture FAILS CLOSED — a typo can
never silently DISABLE certificate verification. The point of the seam: the vendor fact ("PVE ships self-signed")
lives ONCE in the module and both the logging pull + the telemetry exporter derive from it, so they can't drift.
"""
import pytest

from kontroll import endpoints

pytestmark = pytest.mark.unit


def test_vendor_posture_maps_to_verify_default():
    """self_signed -> verify OFF (a self-signed appliance cert can't be verified against a public CA); ca_signed
    -> verify ON. The public vendor fact drives the default with NO per-consumer hardcode."""
    assert endpoints.tls_verify({"tls_posture": "self_signed"}) == (False, None)
    assert endpoints.tls_verify({"tls_posture": "ca_signed"}) == (True, None)


def test_instance_ca_pin_overrides_to_verify_on():
    """An operator CA pin (the instance DECISION) HARDENS verification on + supplies the CA path, OVERRIDING the
    self_signed vendor default — the hardening path B2 exists to enable without editing shipped code."""
    assert endpoints.tls_verify({"tls_posture": "self_signed"},
                                {"tls_ca_file": "/etc/vector-keys/pve-ca.pem"}) \
        == (True, "/etc/vector-keys/pve-ca.pem")


def test_ca_bundle_path_constants_are_the_host_to_container_contract():
    """The CA-bundle path constants ARE the host->container mount contract every CA-pin consumer depends on: the
    generators write the FIXED in-CONTAINER targets (gen-logging → VECTOR_CA_BUNDLE; gen-exporters →
    EXPORTER_CA_BUNDLE), while CA_BUNDLE_HOST (a ${KONTROLL_STORAGE_ROOT}-relative path) is the bind SOURCE that
    deploy-stack writes + vector.yaml/gen-exporters mount. A drift between any of these = a consumer opens a path
    nothing mounts (a pinned CA silently un-trusted). Pins the shared basename, the two distinct absolute
    container targets, and the relocatable host source."""
    assert endpoints.CA_BUNDLE_BASENAME == "device-ca-bundle.pem"
    assert endpoints.VECTOR_CA_BUNDLE == "/etc/vector-keys/" + endpoints.CA_BUNDLE_BASENAME
    assert endpoints.EXPORTER_CA_BUNDLE == "/etc/exporter-certs/" + endpoints.CA_BUNDLE_BASENAME
    assert endpoints.VECTOR_CA_BUNDLE != endpoints.EXPORTER_CA_BUNDLE, "distinct container roots, one shared bundle"
    assert endpoints.CA_BUNDLE_HOST.endswith("/" + endpoints.CA_BUNDLE_BASENAME)
    assert "${KONTROLL_STORAGE_ROOT" in endpoints.CA_BUNDLE_HOST, "the host source must be the relocatable .env path"


def test_missing_or_unknown_posture_fails_closed():
    """A method opting into class TLS whose class declares no/an unknown posture RAISES — a typo or a forgotten
    `vendor_defaults` can NEVER silently return verify=False (the unsafe direction). The generator converts this
    into a loud config-as-data exit. The safe failure is 'refuse to generate', not 'disable verification'."""
    for bad in ({}, {"tls_posture": "nope"}, None):
        with pytest.raises(ValueError):
            endpoints.tls_verify(bad)
