"""Guard: a service fragment whose PINNED image needs a writable root fs must NOT set read_only:true.

Why (the failure this guards against): tecnativa/docker-socket-proxy:0.3.0's entrypoint `sed`s its
SHIPPED /usr/local/etc/haproxy/haproxy.cfg.template into haproxy.cfg IN THAT SAME DIR at startup.
`read_only:true` blocks that write → the container crash-loops on EVERY fresh deploy; and a tmpfs
overlay on the dir HIDES the shipped template → a different crash. The committed fragment shipped
`read_only:true` and a long-standing UNCOMMITTED `read_only:false` edit in the deploy tree masked it
until a clean re-deploy detonated the crash (VM-148 fleet-onboard dogfood, 2026-07-07, runbook
finding 15). This pins the image→writable-root requirement so a future edit (or a new image with the
same need) fails OFFLINE in CI, not on a live deploy. DENY-table, not allow-list: additive and
fail-closed for the known-bad combination only.
"""
import glob
import os

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# image (exact, including tag) -> why it needs a writable container root fs.
# Add a row only when an image's entrypoint writes inside its OWN root fs (not just /run or a tmpfs dir).
REQUIRES_WRITABLE_ROOT = {
    "tecnativa/docker-socket-proxy:0.3.0":
        "entrypoint seds a shipped haproxy.cfg.template into haproxy.cfg in /usr/local/etc/haproxy at start",
}


def _services_in(path):
    """Yield (name, spec) for every service across ALL docs of a fragment. safe_load_ALL (not
    safe_load) so a future multi-document (`---`) fragment is never silently half-read (M7)."""
    with open(path, encoding="utf-8") as fh:
        for doc in yaml.safe_load_all(fh):
            if isinstance(doc, dict):
                for name, spec in (doc.get("services") or {}).items():
                    if isinstance(spec, dict):
                        yield name, spec


def test_writable_root_images_are_not_read_only():
    """No committed docker/services/*.yaml sets read_only:true on a service whose pinned image is in
    REQUIRES_WRITABLE_ROOT — that combination crash-loops on every deploy (finding 15)."""
    offenders = []
    for path in sorted(glob.glob(os.path.join(_ROOT, "docker", "services", "*.yaml"))):
        for name, spec in _services_in(path):
            if spec.get("image") in REQUIRES_WRITABLE_ROOT and spec.get("read_only") is True:
                offenders.append("%s (%s): read_only:true but %s" % (
                    name, os.path.basename(path), REQUIRES_WRITABLE_ROOT[spec["image"]]))
    assert not offenders, (
        "read_only:true on a writable-root image (crash-loops on deploy):\n  " + "\n  ".join(offenders))


def test_socket_proxy_specifically_is_not_read_only():
    """docker-socket-proxy pins tecnativa/docker-socket-proxy:0.3.0 and MUST keep read_only:false — the
    exact regression the dogfood caught (a committed read_only:true masked by an uncommitted workaround).
    Pins the image too, so a version bump re-triggers a human check of the writable-root need."""
    spec = dict(_services_in(os.path.join(_ROOT, "docker", "services", "docker-socket-proxy.yaml")))["docker-socket-proxy"]
    assert spec.get("image") == "tecnativa/docker-socket-proxy:0.3.0", \
        "socket-proxy image pin drifted — re-verify the writable-root requirement before changing read_only"
    assert spec.get("read_only") is False, \
        "docker-socket-proxy must set read_only:false (0.3.0 writes haproxy.cfg in its own root fs)"
