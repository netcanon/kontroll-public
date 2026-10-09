"""discovery domain — the read-only "what un-onboarded hosts did the sweep see?" view (discovery-inbox Rung 1a).

`read_inbox()` assembles the onboard *inbox*: it loads the git-ignored artifact the TOP-LEVEL sweep actor
(`scripts/kontroll-discover.py`) wrote, normalizes every device-supplied field, hides the leases whose IP is
ALREADY an onboarded host, and returns the un-onboarded candidates for the GUI to render. It is PURE reads — the
artifact + `fleet._inventory_groups()` — and writes NOTHING, actuates NOTHING, reaches NO device: the sweep + its
cache WRITE live in the top-level actor precisely so this module can stay provably read-only (an `open(cache,'w')`
here would trip the read-only completeness gate; keeping it out is the zero-new-authority proof — SECURITY C18,
design-of-record §"the OUT-OF-BAND cached model"). `read_inbox` is `assert_read_only`-pinned in test_discovery.py.

A discovered lease is UNTRUSTED DATA (a hostile/misconfigured device could return an injection string): every field
is re-validated here through the SAME closed guards the config-plane uses (`_validate`), so a bad IP is dropped and
a bad hostname/mac degrades to None — a candidate never carries an un-normalized device byte into the service
result. (The GUI additionally renders every field via `textContent`, Rung 1b — defense in depth, not the boundary.)

The inbox is IP-DIFFED against onboarded inventory (a lease IP == any onboarded `ansible_host` ⇒ already onboarded ⇒
hidden). A human onboards + promotes every surfaced candidate through the EXISTING onboard flow — there is NO
auto-onboard (C10 unchanged); this view only surfaces + (Rung 1b) pre-fills the onboard form.
"""
import json
import logging
import os
import re

from kontroll import paths
from kontroll.service import _validate, fleet

log = logging.getLogger("kontroll.service.discovery")

# A MAC in canonical colon-hex form (RFC-7042 doc MACs `00:00:5e:00:53:xx` validate). Normalized to lowercase; a
# non-matching value degrades to None (advisory only — the IP is the candidate key).
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
# A module key / short token (our own `enabled_modules` key + method name) — a conservative allow-list so even a
# tampered artifact can't smuggle a metacharacter through the provenance fields.
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def inbox_path():
    """The git-ignored discovery artifact path — the ONE source of truth BOTH the sweep actor (write) and this
    reader (read) resolve, so they always agree. `KONTROLL_DISCOVERY_INBOX` overrides (tests); else
    `<write_root>/local/discovery-inbox.generated.json` (`local/` is gitignored; on a baked deploy write_root is the
    writable propose clone, never the read-only image). PURE (an env read + a path join)."""
    return (os.environ.get("KONTROLL_DISCOVERY_INBOX")
            or os.path.join(paths.write_root(), "local", "discovery-inbox.generated.json"))


def _load_artifact(path):
    """The sweep artifact as a dict, or {} when absent/malformed (a missing sweep ⇒ an empty inbox, never a raised
    error — the in-process GUI worker must survive; service-never-sys.exit)."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _onboarded_ips():
    """Every onboarded host's `ansible_host` across the whole inventory (main + drop-ins) — the IP set a discovered
    lease is diffed against. Reuses `fleet._inventory_groups()` (a pure read of instance/inventory/*)."""
    ips = set()
    for hosts in fleet._inventory_groups().values():
        for hv in hosts.values():
            if isinstance(hv, dict) and hv.get("ansible_host"):
                ips.add(hv["ansible_host"])
    return ips


def _clean_ip(value):
    """A validated IPv4-OR-IPv6 host string, or None — through the closed dual-stack `_v_ip` guard (each leg keeps its
    config-injection rejections + the never-a-host loopback/unspecified/multicast/reserved[/v6 link-local] bands). A v6
    neighbour from the dual-stack SNMP table (ipNetToPhysicalTable) now validates + becomes a candidate; a malformed/
    injection value ⇒ None (the row is then dropped, since the IP is the key). NOTE: this deliberately uses `ip`
    (dual-stack), NOT `ipv4` — the config-plane danger knobs (mgmt_ip / ansible_host) keep their v4-only `ipv4` guard
    unchanged, so widening discovery's read key never weakens the onboard/reconfigure validation."""
    if not isinstance(value, str):
        return None
    return value if _validate.validate_value({"type": "ip"}, value) is None else None


def _clean_mac(value):
    """A canonical lower-case colon-hex MAC, or None (advisory display only). A non-matching value degrades to None,
    so no device byte with a metacharacter survives into the result."""
    if isinstance(value, str) and _MAC_RE.match(value):
        return value.lower()
    return None


def _clean_hostname(value):
    """A validated hostname, or None — through the SAME closed `_v_hostname` guard (RFC-1123-ish labels, no
    whitespace/metacharacter/trailing newline). A DHCP name with an underscore/empty value degrades to None
    (advisory only; the IP is the candidate key)."""
    if not isinstance(value, str) or not value:
        return None
    return value if _validate.validate_value({"type": "hostname"}, value) is None else None


def _clean_token(value):
    """A short allow-listed token (our own module key / method name), or None — defense-in-depth on the provenance
    fields even though they originate from our fleet, not the device."""
    if isinstance(value, str) and _TOKEN_RE.match(value):
        return value
    return None


def _load_oui():
    """The pinned IEEE OUI->vendor lookup as a {prefix: vendor} dict, loaded ONCE at import ({} if absent/malformed →
    every vendor degrades to None, never a raise). A PURE committed-file READ — `paths.OUI_DIR` is ROOT-bound (a data
    registry like DISCOVERY_DIR, NOT write_root), so on a baked deploy it reads the read-only image tree. Owned +
    `--check`'d by scripts/gen-oui.py (derive→pin→--check); display-only, never a device byte."""
    path = os.path.join(paths.OUI_DIR, "oui-lookup.generated.json")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    prefixes = doc.get("prefixes") if isinstance(doc, dict) else None
    return prefixes if isinstance(prefixes, dict) else {}


_OUI = _load_oui()


def _vendor_for(mac):
    """The IEEE vendor org for a canonical `aa:bb:cc:dd:ee:ff` MAC via LONGEST-prefix match (36→28→24 bits: probe
    9→7→6 nibbles, longest wins — IEEE re-parcels a /24 into /28+/36 blocks, so a naive first-3-bytes lookup ships the
    WRONG vendor for a small-block device), or None. PURE (a dict probe on the pre-loaded committed lookup — no device,
    no write, no network). A None mac (already degraded) → None. Advisory DISPLAY only; never a class/collection (the
    F8 cut — a MAC's OUI is a manufacturer, not an Ansible collection; the human still searches + picks the class)."""
    if not mac:
        return None
    hexmac = mac.replace(":", "")                  # 12 lowercase hex nibbles (mac is already _clean_mac-normalized)
    for n in (9, 7, 6):                            # MA-S (/36), MA-M (/28), MA-L (/24) — longest wins
        vendor = _OUI.get(hexmac[:n])
        if vendor:
            return vendor
    return None


def _clean_sources(sources):
    """The per-source provenance rows (what the sweep read + its verdict) with each field coerced to a safe shape —
    key/method/status as tokens, host as a validated IP, count as a non-negative int. Provenance for the GUI panel
    ("read opnsense: 3 leases, ok"); never a device-supplied lease value."""
    out = []
    for s in sources or []:
        if not isinstance(s, dict):
            continue
        count = s.get("count")
        out.append({"key": _clean_token(s.get("key")),
                    "method": _clean_token(s.get("method")),
                    "host": _clean_ip(s.get("host")),
                    "status": _clean_token(s.get("status")),
                    "count": count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else 0})
    return out


def read_inbox(path=None):
    """The onboard inbox: the un-onboarded discovered hosts, as {generated_at, sources, candidates}. Each candidate
    is {ip, mac, hostname, vendor, source_key, source_host} — IP validated (else the row is dropped), the rest
    normalized to a safe value or None (`vendor` = the advisory IEEE OUI hint for the MAC, display-only per F8). A lease whose IP is already an onboarded `ansible_host` is HIDDEN (the IP-diff); candidates
    are de-duped by IP (a host seen by two sources appears once) and sorted for a stable view. PURE READ — loads the
    artifact + inventory, writes nothing, reaches no device (`assert_read_only`-pinned). A missing/empty artifact ⇒
    {candidates: []} (never raises)."""
    art = _load_artifact(path or inbox_path())
    onboarded = _onboarded_ips()
    seen, candidates = set(), []
    for lease in (art.get("leases") or []):
        if not isinstance(lease, dict):
            continue
        ip = _clean_ip(lease.get("ip"))
        if not ip or ip in onboarded or ip in seen:
            continue
        seen.add(ip)
        mac = _clean_mac(lease.get("mac"))
        candidates.append({"ip": ip,
                           "mac": mac,
                           "hostname": _clean_hostname(lease.get("hostname")),
                           "vendor": _vendor_for(mac),          # advisory IEEE OUI hint, may be None (display-only, F8)
                           "source_key": _clean_token(lease.get("source_key")),
                           "source_host": _clean_ip(lease.get("source_host"))})
    candidates.sort(key=lambda c: c["ip"])
    generated_at = art.get("generated_at")
    return {"generated_at": generated_at if isinstance(generated_at, str) else None,
            "sources": _clean_sources(art.get("sources")),
            "candidates": candidates}
