"""The request boundary: every request field that becomes a path component or an inventory key is a closed charset,
and every repository write is confined to write_root() (SECURITY.md C22; 2026-10-08 review, finding 1).

WHY: the onboard planner validated only that the collection was installed. `key`, `group`, `host`, `host_name` and
`secrets` were bare strings that went straight into `modules/<key>/module.yml`, `onboarded-<key>.yml`,
`ansible/secrets/<domain>.sops.yml` and the rendered inventory YAML — one `../` or `;` away from a write outside the
repository or a YAML/argv injection, on the privileged API and the GUI alike. CodeQL's 45 `py/path-injection` alerts
on the public tree are this single class of join. The fix is a closed charset at the seam AND at every join (so a new
caller cannot forget), plus `confined()` as the last check before any write. These tests are the accept/reject
tables, the "refused before the probe is reached" property, and the write confinement against real paths.
"""
import os

import pytest

from kontroll import gitio, paths, probe
from kontroll.service import onboard

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("value", ["cisco_ios", "edge-fw", "a", "x9", "a" * 64, "docker_host"])
def test_component_accepts_the_names_kontroll_actually_uses(value):
    """Device-class keys, unit keys, inventory groups and secret domains as they exist in the tree — lowercase, digits,
    `_`, `-`, up to 64 chars — pass unchanged. Guards the validator growing stricter than the data it protects."""
    assert paths.component(value) == value


@pytest.mark.parametrize("value", ["../x", "a/b", "a\\b", ".", "..", "", "A", "Edge", "a b", "a;b", "a\nb", "a\x00b",
                                   "x.y", "-a", "_a", "a" * 65, None, 7, ["a"]])
def test_component_rejects_separators_dots_metacharacters_case_and_length(value):
    """A separator, a dot (so no `..`), a NUL, a newline, a shell metacharacter, an uppercase letter, a leading `-`/`_`,
    a 65th char, an empty string or a non-string are all refused with the FIELD named and the value only as a short
    repr. Each is a path or YAML/argv hazard the old bare-string planner would have joined."""
    with pytest.raises(ValueError) as e:
        paths.component(value, "device-class key")
    assert "device-class key" in str(e.value)


@pytest.mark.parametrize("value", ["cisco.ios", "acme.edgeos", "community.docker", "a.b", "n_s.na_me"])
def test_collection_fqcn_accepts_namespace_dot_name(value):
    """Exactly `namespace.name` in Galaxy's charset passes — the form every `ansible_collections/<ns>/<name>` join
    and every `ansible-doc`/`ansible-galaxy` argv word expects."""
    assert paths.collection_fqcn(value) == value


@pytest.mark.parametrize("value", ["cisco", "cisco.ios.extra", "../acme.edgeos", "acme/edgeos", "Cisco.IOS", "a..b",
                                   ".ios", "cisco.", "a b.c", "", None])
def test_collection_fqcn_rejects_anything_else(value):
    """One part, three parts, a path, uppercase, an empty label, a space or a non-string are refused. The probe
    walks `base_path/<ns>/<name>` and hands the name to ansible-doc, so this is both a path and an argv guard."""
    with pytest.raises(ValueError):
        paths.collection_fqcn(value)


@pytest.mark.parametrize("value", ["192.0.2.10", "198.51.100.7", "2001:db8::1", "sw-core-1", "sw.lab.example",
                                   "edgeos-1", "a", "host.", "x" * 63])
def test_hostname_accepts_addresses_and_rfc1123_names(value):
    """IPv4/IPv6 literals and RFC-1123 hostnames (labels of letters/digits/hyphens joined by single dots) pass — the
    values onboard actually receives for `host` and `host_name`."""
    assert paths.hostname(value) == value


@pytest.mark.parametrize("value", ["../x", "a b", "a..b", "-a", "a-", "a/b", "", "192.0.2.50; rm -rf /", "a\nb",
                                   "x" * 64, ("a" * 63 + ".") * 4 + "b", "a_b", None])
def test_hostname_rejects_paths_metacharacters_bad_labels_and_length(value):
    """A `..`, a space, a separator, a leading/trailing hyphen, a label over 63 chars, a name over 253 chars, an
    underscore (not RFC-1123), a newline, a shell payload or a non-string are refused. A host name becomes an
    inventory KEY and is rendered into YAML, so the closed charset is load-bearing even though it is not a path."""
    with pytest.raises(ValueError):
        paths.hostname(value, "host")


def test_confined_accepts_repository_paths_and_refuses_climbing_out(tmp_path, monkeypatch):
    """`confined()` returns the absolute target for a repo-relative path and refuses an absolute path, a `..` that
    climbs out, a path that climbs out and back through a sibling, and a NUL — resolved against the REAL
    write_root(), so a symlink pointing outside is refused too. The last check before every drop-in write."""
    root = tmp_path / "repo"
    (root / "modules").mkdir(parents=True)
    monkeypatch.setenv("KONTROLL_WRITE_ROOT", str(root))
    inside = paths.confined("modules/x/module.yml")
    assert inside == os.path.realpath(os.path.join(str(root), "modules", "x", "module.yml"))
    assert paths.confined("modules/../modules/y.yml").endswith("y.yml")          # climbs but stays inside
    for bad in ("../outside.yml", "modules/../../outside.yml", str(tmp_path / "abs.yml"), "a\x00b", "", None):
        with pytest.raises(ValueError):
            paths.confined(bad)
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "escape"
    try:
        os.symlink(str(outside), str(link), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks need privileges on this host")
    with pytest.raises(ValueError):
        paths.confined("escape/evil.yml")


def test_write_new_and_write_inventory_host_go_through_confined(tmp_path, monkeypatch):
    """The two drop-in writers refuse a climbing path and write NOTHING — the confinement is in the writer, not only
    in the planner, so a future caller that skips the planner is still stopped."""
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setenv("KONTROLL_WRITE_ROOT", str(root))
    with pytest.raises(ValueError):
        gitio._write_new("../evil.yml", "x: 1\n", "# banner\n")
    with pytest.raises(ValueError):
        gitio.write_inventory_host("../../evil.yml", "g", {"h": {}}, "# banner\n")
    assert not (tmp_path / "evil.yml").exists()
    assert gitio._write_new("modules/ok/module.yml", "x: 1\n", "# banner\n") is True
    assert (root / "modules" / "ok" / "module.yml").exists()


def test_module_file_refuses_a_path_shaped_key():
    """`paths.module_file` is the ONE resolver every module read goes through (onboard, identity, capability,
    configurable); it re-checks the key at the join so a caller that never saw the planner is still confined."""
    for bad in ("../x", "a/b", "..", "Key"):
        with pytest.raises(ValueError):
            paths.module_file(bad)
    assert paths.module_file("cisco_ios").endswith(os.path.join("modules", "cisco_ios", "module.yml"))


def test_the_planner_refuses_before_the_probe_is_reached(monkeypatch):
    """`build_onboard_plan` validates every field FIRST: with a bad key the probe (which shells ansible-doc with the
    collection) is never called and no catalog is loaded. Guards the order — a validator after the probe would still
    have handed the request's bytes to a subprocess."""
    def must_not_be_reached(*a, **k):
        raise AssertionError("the probe must not run for a refused request")
    monkeypatch.setattr(probe, "deep_probe", must_not_be_reached)
    with pytest.raises(ValueError) as e:
        onboard.build_onboard_plan("acme.edgeos", "../etc", "edge_router", "192.0.2.50", backends=[], vectors=[])
    assert "device-class key" in str(e.value) and "../etc" in str(e.value)
    for kwargs in ({"group": "edge router"}, {"host": "192.0.2.1; id"}, {"host_name": "../h"},
                   {"secrets": "../network"}, {"collection": "acme/edgeos"}):
        args = dict(collection="acme.edgeos", key="edgeos", group="edge_router", host="192.0.2.50")
        args.update(kwargs)
        with pytest.raises(ValueError):
            onboard.build_onboard_plan(args["collection"], args["key"], args["group"], args["host"],
                                       host_name=args.get("host_name"), secrets=args.get("secrets", "network"),
                                       backends=[], vectors=[])


def test_probe_dir_walks_refuse_an_unvalidated_collection_name(tmp_path):
    """`shallow_from_local` and `units_in_collection` join `base_path/<ns>/<name>`; both re-validate the name so a
    `../` can never be walked even when a caller forgets the SEC-3 contract."""
    for fn in (lambda: probe.units_in_collection("../x", str(tmp_path)),
               lambda: probe.shallow_from_local("acme/edgeos", None, str(tmp_path))):
        with pytest.raises(ValueError):
            fn()
