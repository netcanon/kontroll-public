"""C0 publish-images guards (report 22 — docs/reviews/2026-06-29-compose-native-install/22-distribution-images.md).

WHY — C0 publishes the runner + vector images to private ghcr and lets the control node pull them BY DIGEST instead
of building locally. Three things must stay true or the supply-chain/deploy posture breaks: (1) the PUBLISHED runner
bakes the all-modules SUPERSET (a prebuilt image can't know a node's fleet), derived offline from the public
catalog; (2) the image digest-lock is well-formed, byte-stable (no hand-edit), and its read path is OFFLINE (the
image-world BRICK-1 — no network at deploy); (3) the deploy is OPT-IN and additive — the local build still runs by
default, and only `use_published_images` flips to pull-by-digest. Each test names the failure it guards.
"""
import importlib.util
import os
import re

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_script(rel, name):
    """Import a hyphenated scripts/*.py as a module (the repo's standard test seam)."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _covered_by_copy(df, rel):
    """True if the Dockerfile bakes `rel` (or a baked ANCESTOR dir) to the mirror path under /opt/kontroll.
    Walk most-specific -> least so `dashboards/derived` matches its own COPY (not the forbidden whole `dashboards/`),
    while `ansible/backends` is covered by the ancestor `COPY ansible/`."""
    parts = rel.split("/")
    for i in range(len(parts), 0, -1):
        p = "/".join(parts[:i])
        if ("COPY %s/" % p) in df and ("/opt/kontroll/%s/" % p) in df:
            return True
    return False


def test_all_modules_superset_covers_every_module_and_the_alternatives():
    """gen-requirements.py --all-modules must resolve the UNION of every public module's collections — including the
    pick-one alternatives a single fleet never enables together (opnsense AND fortigate, routeros AND cisco_ios). A
    published runner baking only one fleet's set would be unusable on a node with a different edge/switch. Guards the
    superset shrinking to a single fleet."""
    g = _load_script("scripts/gen-requirements.py", "genreq")
    keys = g.all_module_keys()
    assert {"fortigate", "opnsense", "cisco_ios", "routeros"} <= set(keys), "the catalog must carry the alternatives"
    out, _ = g.compute(keys, g.paths.resolve("actuation"))
    names = {c["name"] for c in out}
    # both edge firewalls + both core switches resolve in the SAME superset (a fleet only enables one of each).
    assert {"fortinet.fortios", "ansibleguy.opnsense", "cisco.ios", "community.routeros"} <= names, \
        "the superset must union the alternative vendor collections, not just one fleet's"
    assert {"community.sops", "community.general", "community.docker"} <= names, "the control-plane base must be present"


def test_image_lockfile_is_wellformed_and_roundtrips():
    """docker/images.lock.yml must pass the schema check AND re-render byte-identically (the no-hand-edit discipline
    the collection lockfile already enforces). A hand-edited digest or a malformed entry is how a wrong image slips
    past the pin; this catches both."""
    g = _load_script("scripts/gen-image-digests.py", "gid")
    lock = g.load()
    assert g.check(lock) == [], "images.lock.yml must be well-formed"
    assert g.render(lock) == _read("docker/images.lock.yml"), "images.lock.yml must round-trip (not hand-edited)"
    assert set(g.KONTROLL_IMAGES) <= set(lock["images"]), "the lock must carry every kontroll-owned image entry"


def test_emit_env_only_emits_recorded_digests_and_is_offline(monkeypatch):
    """--env (the deploy seam) emits `VAR=ref@sha256` ONLY for an image with a recorded digest, and makes NO network
    call (the image-world BRICK-1 — the control node never resolves a digest at deploy, it uses the committed one). A
    null-digest entry is omitted so the compose `${VAR:-<local>}` falls back to the local build. Guards a regression
    that (a) emits a bare/tagless ref or (b) reaches the registry on the install-gating path."""
    g = _load_script("scripts/gen-image-digests.py", "gid2")
    # any subprocess/network use in the read path is a bug — make it explode if touched.
    monkeypatch.setattr(g.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("--env must not shell out")))
    assert g.emit_env({"images": {}}) == "", "no images ⇒ no env lines"
    # A digest-bearing entry emits VAR=ref@sha256; a null-digest entry is OMITTED (the compose ${VAR:-<local>} falls
    # back to the local build). Use a synthetic lock so the contract holds REGARDLESS of what the committed lock pins
    # — prod pins real v* digests (post-cutover), an unpinned dev tree pins null; both must satisfy omit-null/emit-digest.
    synthetic = {"schema": 1, "images": {
        "kontroll-control": {"ref": "ghcr.io/x/kontroll-control", "tag": "v1", "digest": "sha256:" + "a" * 64},
        "kontroll-vector": {"ref": "ghcr.io/x/kontroll-vector", "tag": "v1", "digest": None},
    }}
    out = g.emit_env(synthetic)
    assert out == "KONTROLL_CONTROL_IMAGE=ghcr.io/x/kontroll-control@sha256:" + "a" * 64, \
        "a recorded digest emits VAR=ref@sha256 (and nothing else)"
    assert "KONTROLL_VECTOR_IMAGE" not in out, "a null-digest entry must be omitted (falls back to the local build)"
    assert g.check(synthetic) == []   # also offline (subprocess.run is trapped above)


def test_deploy_stack_pull_by_digest_is_opt_in_and_gates_the_builds():
    """The two docker_image_build tasks (runner + vector) MUST gate on `not use_published_images`, and the flag
    defaults FALSE — so the default deploy is byte-identical (local build) and only an explicit opt-in pulls by
    digest. Guards (a) the builds running even when published images are requested (wasteful + wrong image) and (b)
    the flag defaulting on (a surprise registry dependency)."""
    ds = _read("ansible/playbooks/deploy-stack.yml")
    assert "use_published_images: false" in ds, "use_published_images must default to false (opt-in)"
    assert ds.count("not use_published_images") >= 3, "both image builds + the .env vector line must gate on the flag"
    assert "gen-image-digests.py --env" in ds, "deploy-stack must pin the digests from the lock when published"


def test_compose_runner_image_is_overridable_by_the_published_digest():
    """The runner image ref in every service that uses it (semaphore/onboard-gui/api) MUST be
    `${KONTROLL_CONTROL_IMAGE:-kontroll/semaphore:latest}` — the env override is how the published digest reaches
    compose; the `:-` default keeps the local-build path working unchanged. Guards a hardcoded `kontroll/semaphore`
    ref that the published digest can't override."""
    for svc in ("docker/services/semaphore.yaml", "docker/services/onboard-gui.yaml", "docker/services/api.yaml"):
        assert "${KONTROLL_CONTROL_IMAGE:-kontroll/semaphore:latest}" in _read(svc), \
            "%s must read the runner image from KONTROLL_CONTROL_IMAGE (with the local default)" % svc


def test_installer_image_is_published_and_digest_pinnable():
    """C1 publishes the installer image too (report 22 §2.1 Image C) so a fresh node PULLS it by digest instead of
    building. FOUR seams must all carry kontroll-installer or the published install silently falls back to a local
    build: the publish-images matrix (CI builds+pushes it), KONTROLL_IMAGES + the lock (the digest pin), and
    installer.yaml's image ref (the override point). Guards any one of them being forgotten — the failure mode is a
    quiet local rebuild on a node that was supposed to pull."""
    g = _load_script("scripts/gen-image-digests.py", "gid_installer")
    assert g.KONTROLL_IMAGES.get("kontroll-installer") == "KONTROLL_INSTALLER_IMAGE", \
        "the installer must map to KONTROLL_INSTALLER_IMAGE in gen-image-digests"
    assert "kontroll-installer" in g.load()["images"], "the lock must carry a kontroll-installer entry"
    wf = _read(".github/workflows/publish-images.yml")
    assert "image: installer" in wf, "publish-images must build+push the installer image"
    assert "docker/installer/Dockerfile" in wf, "the installer matrix entry must point at the installer Dockerfile"
    inst = _read("docker/services/installer.yaml")
    assert "${KONTROLL_INSTALLER_IMAGE:-kontroll/installer:latest}" in inst, \
        "installer.yaml must read the image from KONTROLL_INSTALLER_IMAGE (with the local-build default)"


def test_control_image_bakes_immutable_code_only_no_secrets_no_generated():
    """M9 (Phase-B bake): the control Dockerfile bakes the IMMUTABLE read-root (api/gui/scripts/ansible + EVERY data
    registry) at /opt/kontroll so a baked deploy runs code+data from the image — and must NEVER bake instance/ (the
    private overlay + secrets, .dockerignore-stripped) or a config-as-data dir that carries *.generated.* artifacts
    (prometheus/config rot / the generated dashboards/grafana JSONs leak topology). GUARDS the bake-gap class that
    already shipped TWICE (discovery/ + dashboards/derived/ — post-Phase-B registries added to paths.py but never to
    this Dockerfile, so a baked box read them from a MISSING dir and served an empty Discovery panel / no derived
    dashboard floor): the required registry set is now DERIVED from paths.py's ROOT-relative `*_DIR` constants, so a
    NEW registry that isn't baked fails THIS test loudly instead of an empty panel in prod. Also pins the read-only
    chmod + the secret strip so a future edit can't un-bake the code or leak a secret (review 21 §5.1 / synthesis M9)."""
    paths = _load_script("scripts/kontroll/paths.py", "kontroll_paths_bakecheck")
    df = _read("docker/semaphore-runner/Dockerfile")
    # The baked CODE trees (not paths.*_DIR data registries).
    for d in ("api", "gui", "scripts", "ansible"):
        assert _covered_by_copy(df, d), \
            "the control image must bake the immutable code tree %s/ at /opt/kontroll (a future edit un-baked it)" % d
    # Every ROOT-relative paths.*_DIR is an immutable DATA registry the baked runtime reads from ROOT -> must be baked.
    registries = {}
    for name in dir(paths):
        if not name.endswith("_DIR"):
            continue
        val = getattr(paths, name)
        if not isinstance(val, str):
            continue
        rel = os.path.relpath(val, paths.ROOT).replace(os.sep, "/")
        if rel == "." or rel.startswith(".."):
            continue  # not under ROOT (a write_root()/instance overlay dir) -> not a baked registry
        registries[name] = rel
    assert "discovery" in registries.values() and "dashboards/derived" in registries.values(), \
        "sanity: paths.py must still declare the discovery + dashboards/derived registries this guard was hardened for"
    for name, rel in sorted(registries.items()):
        assert _covered_by_copy(df, rel), (
            "paths.%s (=%s/) is a ROOT data registry the baked runtime reads from /opt/kontroll, but no COPY bakes it "
            "into the control image -> a baked deploy silently serves it EMPTY. Add `COPY %s/ /opt/kontroll/%s/` to "
            "docker/semaphore-runner/Dockerfile (the discovery/dashboards-floor bake-gap class)." % (name, rel, rel, rel))
    assert "chmod -R a-w /opt/kontroll" in df, \
        "the baked read-root must be made read-only (review 30 §1 — make read-only-by-construction physical)"
    # NEVER bake instance/ (secrets) or a config-as-data dir whose *.generated.* artifacts rot / carry real topology.
    for d in ("instance", "prometheus", "config"):
        assert "COPY %s/" % d not in df, \
            "the control image must NOT bake %s/ (instance secrets / rotting generated artifacts / leaked topology)" % d
    # dashboards/derived/ (committed lock pins) IS baked above, but the GENERATED dashboards/ (grafana JSONs) must NOT.
    assert not re.search(r"(?m)^COPY\s+dashboards/\s", df), \
        "the control image must NOT bake the whole dashboards/ (generated grafana JSONs) — only dashboards/derived/"
    di = _read(".dockerignore")
    for strip in ("instance/", "local/", "keys.txt", "*.agekey"):
        assert strip in di, ".dockerignore must strip %s from EVERY image context (the published code image too)" % strip


def test_control_image_ships_net_snmp_cli():
    """The baked control image must install the net-snmp CLI (Alpine `net-snmp-tools`). The discovery `snmp_walk`
    transport (scripts/kontroll-discover.py -> `snmpbulkwalk`) AND gen-validate-live's SNMPv3 GETNEXT
    (`snmpgetnext`) shell out to net-snmp binaries — if the image ships only `age sops`, an SNMPv3 walk raises
    FileNotFoundError and the source is (mis)recorded `unreachable` on EVERY baked deploy, so the entire SNMP
    transport is silently dead. Live-caught on the cisco SNMP-ARP dogfood 2026-07-03 (the base semaphore image has
    no net-snmp; the `.52` container had no `snmpbulkwalk`)."""
    df = _read("docker/semaphore-runner/Dockerfile")
    assert "net-snmp-tools" in df, \
        "the control image must `apk add net-snmp-tools` — the snmp_walk/snmp_getnext CLI the SNMP transport shells out to"


def test_control_image_ships_openssh_client():
    """The baked control image must install the SSH client (Alpine `openssh-client`). The discovery
    `dhcp_leases_openwrt` transport (scripts/kontroll-discover.py -> a read-only forced-command `ssh` read of an
    OpenWrt AP's dnsmasq lease file) shells out to the `ssh` binary — if the image ships only `age sops
    net-snmp-tools`, an OpenWrt lease read raises FileNotFoundError and the source is (mis)recorded `unreachable` on
    EVERY baked deploy, so the entire SSH lease transport is silently dead (the exact failure the net-snmp CLI test
    guards for the SNMP transport; OW-GATE Rung 2)."""
    df = _read("docker/semaphore-runner/Dockerfile")
    assert "openssh-client" in df, \
        "the control image must `apk add openssh-client` — the ssh CLI the dhcp_leases_openwrt transport shells out to"


def test_publish_is_gated_on_the_readonly_pin():
    """M5 (Phase-B bake): publishing a code-baked image must be GATED on the read-only-by-construction pin passing on
    the SAME commit — baking moves the read-only guarantee off the running clone (== the tested source) onto the
    digest-pinned image, so a tag must never publish code the AST pin hasn't cleared. Pins the `gate` job + the
    publish `needs: gate` dependency + that the gate runs the completeness pin (review 21 §3.3 / synthesis M5)."""
    wf = _read(".github/workflows/publish-images.yml")
    assert "\n  gate:\n" in wf, "publish-images must carry a `gate` job that runs the read-only pin before any build"
    assert "needs: gate" in wf, "the publish job must depend on the gate (block the code-baked publish on a pin failure)"
    assert "test_readonly_completeness.py" in wf, "the gate must run the read-only-by-construction completeness pin"
