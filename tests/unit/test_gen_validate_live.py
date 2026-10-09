"""scripts/gen-validate-live.py — the ONLINE drift-validation seam (the no-bespoke tenet's VALIDATE leg).

The seam reaches live devices read-only, so its dispatch + judgement logic is proven here HERMETICALLY by injecting
a fake fetcher (the only device-reaching code, LiveFetchers, is the lone VM-only part). These pins cover the
load-bearing properties the scoping run flagged as must-fixes:
  * the dispatch is vendor-blind — a function table keyed by `check:` NAME, no vendor literal in the spine (M-3);
  * each verdict is reach-then-judge — transport error = UNREACHABLE (tolerated), a successful mismatch = DRIFT;
  * the token resolves from the descriptor's OWN env ref, never an admin side-channel (M-4), and never reaches the
    audit line or a verdict detail (M-5 / C12);
  * a too-narrow token's audit-filtered 200+empty is disambiguated, never silently OK (M-8);
  * the role name the surface declares is NOT duplicated as a literal in the checks (MF-4 — one declaration).
"""
import importlib.util
import inspect
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
pytestmark = pytest.mark.unit

PVE_ENDPOINT = "https://${DEVICE_ADDR}:8006/api2/json/cluster/tasks"
TOKEN_ENV = "KONTROLL_PVE_LOG_TOKEN"
TOKEN_VALUE = "user@pve!ci=secret-deadbeef"     # a stand-in token VALUE — must NEVER reach audit/stdout/detail


def _mod():
    spec = importlib.util.spec_from_file_location("gen_validate_live",
                                                  os.path.join(ROOT, "scripts", "gen-validate-live.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _mod()


class FakeFetchers:
    """A LiveFetchers stand-in with the same surface — every device-reaching call is canned/recorded, so the
    dispatch + check logic runs fully offline. `calls` records each invocation for header/scope assertions."""
    def __init__(self, verifies=None, gets=None, snmp=None, raise_tls=False, raise_get=False, raise_snmp=False):
        self.verifies, self.gets, self.snmp = verifies, gets or {}, snmp or {}
        self.raise_tls, self.raise_get, self.raise_snmp = raise_tls, raise_get, raise_snmp
        self.calls = []

    def tls_verifies(self, host, port, ca_file=None):
        self.calls.append(("tls", host, port, ca_file))
        if self.raise_tls:
            raise OSError("connection refused")
        return self.verifies

    def http_get(self, url, headers=None, verify=True, ca_file=None):
        self.calls.append(("get", url, dict(headers or {}), verify, ca_file))
        if self.raise_get:
            raise OSError("timed out")
        for suffix, resp in self.gets.items():
            if url.endswith(suffix):
                return resp
        raise AssertionError("FakeFetchers: no canned response for %s" % url)

    def snmp_getnext(self, host, oids, user, auth_pass, priv_pass, **kw):
        self.calls.append(("snmp", host, list(oids), user))
        if self.raise_snmp:
            raise OSError("snmp timeout")
        return {o: self.snmp.get(o, "") for o in oids}


def _target(vendor_defaults=None, cls_trust=None, host="192.0.2.10", key="proxmox"):
    return M.Target(key, host, vendor_defaults or {"tls_posture": "self_signed"}, cls_trust)


def _logging_ctx():
    return {"source": {"endpoint": PVE_ENDPOINT, "auth": {"value": "PVEAPIToken=${%s}" % TOKEN_ENV}},
            "secret_domain": "proxmox"}


def _apidoc_body(tasks_perms, include_tasks=True):
    """A minimal stand-in for the PVE apidoc.js (`const apiSchema = [ … ];`) — the /cluster/tasks node with the
    given GET permissions, nested under /cluster like the real schema. Contains the literal path so api_path's
    substring check also passes off it."""
    inner = ({"path": "/cluster/tasks", "info": {"GET": {"permissions": tasks_perms}}} if include_tasks
             else {"path": "/cluster/other", "info": {"GET": {"permissions": {"user": "all"}}}})
    return "const apiSchema = " + json.dumps([{"path": "/cluster", "children": [inner]}]) + ";\n"


# --- cert_posture: live TLS vs the pinned posture (B2 online) --------------------------------------------------
def test_cert_self_signed_match_is_ok():
    """A self-signed-posture class whose live cert FAILS a system-trust verify is OK (still self-signed as pinned).
    Guards the cert validator flipping the verdict sense — a failed public verify is the EXPECTED state here."""
    v = M.check_cert_posture({"port": 8006}, {}, _target(), FakeFetchers(verifies=False))
    assert v.verdict == M.OK


def test_cert_now_publicly_trusted_is_pending_not_drift():
    """A self-signed-posture device that now presents a PUBLICLY-TRUSTED cert is PENDING-HARDENING, not DRIFT — a
    hardening is a good change, not a cry-wolf failure (M-9). Guards a rollout-time false alarm."""
    v = M.check_cert_posture({"port": 8006}, {}, _target(), FakeFetchers(verifies=True))
    assert v.verdict == M.PENDING


def test_cert_pinned_ca_verifies_ok_else_drift():
    """With an instance CA pin the live chain MUST verify against it: success = OK, failure = DRIFT (the pin no
    longer matches the served cert). Guards the hardened path silently passing when the pinned CA stops matching."""
    trust = {"tls_ca_file": "instance/certs/pve-ca.pem"}
    assert M.check_cert_posture({"port": 8006}, {}, _target(cls_trust=trust), FakeFetchers(verifies=True)).verdict == M.OK
    assert M.check_cert_posture({"port": 8006}, {}, _target(cls_trust=trust),
                                FakeFetchers(verifies=False)).verdict == M.DRIFT


def test_cert_unreachable_is_tolerated():
    """A transport failure (host down) is UNREACHABLE, never DRIFT — a down host must not fail a fleet drift run
    (the ignore_unreachable contract). Guards a maintenance window reading as a false drift alarm."""
    assert M.check_cert_posture({"port": 8006}, {}, _target(), FakeFetchers(raise_tls=True)).verdict == M.UNREACHABLE


# --- api_path: the pinned PVE path still published -------------------------------------------------------------
def test_api_path_present_ok_absent_drift():
    """api_path is OK when the pinned request path is in the published apidoc, DRIFT when it's GONE (endpoint
    moved/removed) — the early warning before the Vector pull silently 404s. Guards both senses."""
    ctx = _logging_ctx()
    ok = M.check_api_path({}, ctx, _target(), FakeFetchers(gets={"apidoc.js": {"status": 200, "body": "…/cluster/tasks…"}}))
    assert ok.verdict == M.OK
    gone = M.check_api_path({}, ctx, _target(), FakeFetchers(gets={"apidoc.js": {"status": 200, "body": "no such path"}}))
    assert gone.verdict == M.DRIFT


def test_api_path_apidoc_unavailable_is_unreachable():
    """If the node-local apidoc isn't served (non-200), the check cannot judge the schema -> UNREACHABLE, never a
    false DRIFT. Guards a missing docs package being mis-reported as a removed endpoint."""
    v = M.check_api_path({}, _logging_ctx(), _target(), FakeFetchers(gets={"apidoc.js": {"status": 404, "body": ""}}))
    assert v.verdict == M.UNREACHABLE


# --- schema_permission (A′): the permission MODEL still matches what we assume (apidoc-verified {user:all}) ----
def test_schema_permission_unchanged_is_ok():
    """A′ is OK when the apidoc still encodes the pinned permission model for the endpoint ({user:all} for
    /cluster/tasks — apidoc-verified live). Guards the M-8 row-filter assumption silently regressing."""
    body = _apidoc_body({"user": "all"})
    v = M.check_schema_permission({"expect": {"user": "all"}}, _logging_ctx(), _target(),
                                  FakeFetchers(gets={"apidoc.js": {"status": 200, "body": body}}))
    assert v.verdict == M.OK


def test_schema_permission_tightened_is_drift():
    """When PVE TIGHTENS the endpoint from {user:all} to a hard `perm` check, A′ is DRIFT — the deterministic,
    pre-wire warning that token_scope's 200+empty/version logic no longer matches the access model. Guards the
    exact upstream-tightening case A′ exists for."""
    body = _apidoc_body({"check": ["perm", "/", ["Sys.Audit"]]})
    v = M.check_schema_permission({"expect": {"user": "all"}}, _logging_ctx(), _target(),
                                  FakeFetchers(gets={"apidoc.js": {"status": 200, "body": body}}))
    assert v.verdict == M.DRIFT


def test_schema_permission_endpoint_absent_is_unreachable():
    """If the endpoint isn't in the apidoc, A′ cannot judge its permission -> UNREACHABLE (path-presence is
    api_path's job, not A′'s). Guards A′ double-reporting a path drift as a permission drift."""
    body = _apidoc_body(None, include_tasks=False)
    v = M.check_schema_permission({"expect": {"user": "all"}}, _logging_ctx(), _target(),
                                  FakeFetchers(gets={"apidoc.js": {"status": 200, "body": body}}))
    assert v.verdict == M.UNREACHABLE


def test_schema_permission_apidoc_unavailable_is_unreachable():
    """A non-200 / unparseable apidoc -> UNREACHABLE, never a false DRIFT. Guards a docs outage reading as a
    permission-model change."""
    v = M.check_schema_permission({"expect": {"user": "all"}}, _logging_ctx(), _target(),
                                  FakeFetchers(gets={"apidoc.js": {"status": 404, "body": ""}}))
    assert v.verdict == M.UNREACHABLE


def _apidoc_node(path, perms):
    """A one-node apidoc.js stand-in for an arbitrary `path` with the given GET permissions (for the api_path
    override — pinning an endpoint OTHER than the descriptor's pull)."""
    return ("const apiSchema = " + json.dumps([{"path": "/cluster", "children": [
        {"path": path, "info": {"GET": {"permissions": perms}}}]}]) + ";\n")


def test_schema_permission_api_path_override_pins_a_gated_endpoint():
    """schema_permission with an `api_path:` override pins the permission model of a DIFFERENT endpoint than the
    descriptor's pull — /cluster/status's hard Sys.Audit gate (the SCHEMA half of the role->privilege-map A′). OK
    when the apidoc still requires exactly that perm; DRIFT if PVE RELAXES it (e.g. to {user:all}), which would make
    our Sys.Audit grant silently over-privileged. Guards the generalization regressing to always read the pull path."""
    expect = {"check": ["perm", "/", ["Sys.Audit"]]}
    ok = M.check_schema_permission({"api_path": "/cluster/status", "expect": expect}, _logging_ctx(), _target(),
                                   FakeFetchers(gets={"apidoc.js": {"status": 200,
                                                                    "body": _apidoc_node("/cluster/status", expect)}}))
    assert ok.verdict == M.OK
    drift = M.check_schema_permission({"api_path": "/cluster/status", "expect": expect}, _logging_ctx(), _target(),
                                      FakeFetchers(gets={"apidoc.js": {"status": 200,
                                                  "body": _apidoc_node("/cluster/status", {"user": "all"})}}))
    assert drift.verdict == M.DRIFT


# --- token_scope: the descriptor token can READ its endpoint (+ M-4/M-5/M-8) ----------------------------------
def test_token_scope_uses_descriptor_domain_not_admin(monkeypatch):
    """M-4: the validator builds its Authorization header from the descriptor's OWN env ref (secret_env_map key),
    resolved at the fetcher boundary — never a privileged side-channel. Guards a too-narrow token falsely PASSING
    because the check authenticated with some broader admin credential."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    f = FakeFetchers(gets={"cluster/tasks": {"status": 200, "body": '{"data": [{"upid": "x"}]}'}})
    v = M.check_token_scope({}, _logging_ctx(), _target(), f)
    assert v.verdict == M.OK
    sent = next(c for c in f.calls if c[0] == "get")[2]            # the headers dict
    assert sent["Authorization"] == "PVEAPIToken=%s" % TOKEN_VALUE  # built from the descriptor env, not elsewhere


def test_token_scope_env_unset_is_unreachable_not_fallback(monkeypatch):
    """M-4: with the descriptor's token env UNSET the check is UNREACHABLE (cannot judge) — it must NOT fall back
    to any other credential. Guards a silent side-channel auth that would make scope validation meaningless."""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    v = M.check_token_scope({}, _logging_ctx(), _target(), FakeFetchers())
    assert v.verdict == M.UNREACHABLE


def test_token_scope_403_is_drift(monkeypatch):
    """A clean 403 on the pinned endpoint = the token's scope is too narrow = DRIFT (the live backing for the
    surfaced grant prerequisite). Guards a missing/under-scoped grant going undetected."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    v = M.check_token_scope({}, _logging_ctx(), _target(), FakeFetchers(gets={"cluster/tasks": {"status": 403, "body": ""}}))
    assert v.verdict == M.DRIFT


def test_token_scope_empty_disambiguated_by_version(monkeypatch):
    """M-8 (the silent-empty trap): a too-narrow token gets an audit-FILTERED 200+empty, NOT a 403. The check must
    corroborate via /version — /version 200 => OK (token valid, just no tasks); /version non-200 => DRIFT. Guards
    a too-narrow token reading as a benign empty list (a silent fail-open)."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    benign = FakeFetchers(gets={"cluster/tasks": {"status": 200, "body": '{"data": []}'},
                                "version": {"status": 200, "body": '{"data": {"version": "8"}}'}})
    assert M.check_token_scope({}, _logging_ctx(), _target(), benign).verdict == M.OK
    narrow = FakeFetchers(gets={"cluster/tasks": {"status": 200, "body": '{"data": []}'},
                                "version": {"status": 403, "body": ""}})
    assert M.check_token_scope({}, _logging_ctx(), _target(), narrow).verdict == M.DRIFT


def test_token_value_never_in_verdict_detail(monkeypatch):
    """M-5/C12: no verdict detail carries the token VALUE — only the secret-domain NAME. Guards a credential
    leaking into the on-screen verdict table (the audit-line hygiene is pinned in the run() test below)."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    for resp in ({"status": 403, "body": ""}, {"status": 200, "body": '{"data":[{"x":1}]}'}):
        v = M.check_token_scope({}, _logging_ctx(), _target(), FakeFetchers(gets={"cluster/tasks": resp,
                                                                                  "version": {"status": 200, "body": "{}"}}))
        assert TOKEN_VALUE not in v.detail and "secret" not in v.detail.lower().replace("secret_domain", "")


# --- grant_covers (A′ heavy): the token COVERS a perm-GATED endpoint — the live backing for the provisioning grant -
def test_grant_covers_200_is_ok(monkeypatch):
    """grant_covers is OK when the descriptor's OWN token reads a perm-GATED endpoint (200) — proof the provisioning
    grant confers the gate's permission (Sys.Audit). The Authorization header is built from the descriptor env, not a
    side-channel (M-4). Guards the live half of the role->privilege-map A′ inverting (a missing grant reading green)."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    f = FakeFetchers(gets={"cluster/status": {"status": 200, "body": '{"data": [{"type": "cluster"}]}'}})
    v = M.check_grant_covers({"api_path": "/cluster/status", "perm": "Sys.Audit"}, _logging_ctx(), _target(), f)
    assert v.verdict == M.OK
    sent = next(c for c in f.calls if c[0] == "get")[2]
    assert sent["Authorization"] == "PVEAPIToken=%s" % TOKEN_VALUE


def test_grant_covers_403_is_drift(monkeypatch):
    """A 403 on the perm-GATED endpoint = the grant no longer confers the required permission = DRIFT (the metrics'
    privileged reads will break). Unlike token_scope's {user:all} pull, a gated endpoint 403s UNAMBIGUOUSLY on
    insufficient privilege — no 200+empty corroboration. Guards a silently-narrowed grant going undetected."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    f = FakeFetchers(gets={"cluster/status": {"status": 403, "body": ""}})
    v = M.check_grant_covers({"api_path": "/cluster/status", "perm": "Sys.Audit"}, _logging_ctx(), _target(), f)
    assert v.verdict == M.DRIFT


def test_grant_covers_env_unset_is_unreachable(monkeypatch):
    """M-4: with the descriptor token env UNSET, grant_covers is UNREACHABLE (cannot judge) — it must NOT fall back
    to another credential. Guards a side-channel auth making the coverage proof meaningless."""
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    v = M.check_grant_covers({"api_path": "/cluster/status"}, _logging_ctx(), _target(), FakeFetchers())
    assert v.verdict == M.UNREACHABLE


def test_grant_covers_transport_is_unreachable(monkeypatch):
    """A transport failure (host down) is UNREACHABLE, never DRIFT — a maintenance window must not read as a lost
    grant. Guards a down host failing the fleet drift run."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    v = M.check_grant_covers({"api_path": "/cluster/status"}, _logging_ctx(), _target(), FakeFetchers(raise_get=True))
    assert v.verdict == M.UNREACHABLE


def test_grant_covers_never_leaks_the_token(monkeypatch):
    """M-5/C12: no grant_covers verdict detail carries the token VALUE — only the secret-domain NAME. Guards a
    credential leaking into the verdict table for the gated-read path too."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    for resp in ({"status": 200, "body": "{}"}, {"status": 403, "body": ""}, {"status": 500, "body": ""}):
        v = M.check_grant_covers({"api_path": "/cluster/status", "perm": "Sys.Audit"}, _logging_ctx(), _target(),
                                 FakeFetchers(gets={"cluster/status": resp}))
        assert TOKEN_VALUE not in v.detail


# --- snmp_oid_support: the 2nd transport (D1) ------------------------------------------------------------------
def test_snmp_supported_ok_dropped_drift(monkeypatch):
    """snmp_oid_support is OK when GETNEXT returns an OID still UNDER the pinned subtree (device supports the MIB),
    DRIFT when it falls outside (support dropped). Proves the dispatch is generic across a 2nd transport (SNMP),
    not HTTPS-only. Guards the if_mib generator silently scraping a device that no longer answers its OIDs."""
    monkeypatch.setenv("KONTROLL_SNMP_V3_USER", "ro")
    monkeypatch.setenv("KONTROLL_SNMP_V3_AUTH_PASS", "a")
    monkeypatch.setenv("KONTROLL_SNMP_V3_PRIV_PASS", "p")
    oid = "1.3.6.1.2.1.2.2.1.10"
    ok = M.check_snmp_oid_support({"oids": [oid]}, {}, _target(key="cisco_ios"),
                                  FakeFetchers(snmp={oid: oid + ".2"}))
    assert ok.verdict == M.OK
    drift = M.check_snmp_oid_support({"oids": [oid]}, {}, _target(key="cisco_ios"),
                                     FakeFetchers(snmp={oid: "1.3.6.1.2.1.99.1"}))
    assert drift.verdict == M.DRIFT


def test_snmp_no_creds_is_unreachable(monkeypatch):
    """Without SNMPv3 creds in the env the check is UNREACHABLE (cannot probe), never a false DRIFT. Guards a
    missing-creds environment reading as a device that dropped MIB support."""
    for k in ("KONTROLL_SNMP_V3_USER", "KONTROLL_SNMP_V3_AUTH_PASS", "KONTROLL_SNMP_V3_PRIV_PASS"):  # gitleaks:allow (env-var NAMES, not values)  # gitleaks:allow (env-var NAMES, not values)  # gitleaks:allow (env-var NAMES, not values)
        monkeypatch.delenv(k, raising=False)
    v = M.check_snmp_oid_support({"oids": ["1.3.6.1.2.1.2.2.1.10"]}, {}, _target(key="cisco_ios"), FakeFetchers())
    assert v.verdict == M.UNREACHABLE


# --- the spine: vendor-blind dispatch, the real fan, audit hygiene, fail-closed --------------------------------
def test_collect_fans_proxmox_to_its_checks():
    """The fan over the REAL tree gathers proxmox's own cert_posture + the api_path/schema_permission/token_scope
    its referenced logging method declares — proving validate: blocks compose across descriptor families (module +
    logging) with a single per-host fan. Guards a descriptor's validate block being silently dropped."""
    items = list(M.collect({"enabled_modules": ["proxmox"]}, {}, only_key="proxmox", target_host="192.0.2.10"))
    assert {e["check"] for e, _ctx, _t in items} == \
        {"cert_posture", "api_path", "schema_permission", "token_scope", "grant_covers"}


def test_run_audits_names_only_never_the_token(tmp_path, monkeypatch):
    """run() emits one run_id-correlated audit line per check carrying NAMES only (class/check/verdict) — the
    token VALUE never appears. Guards C12/M-5 at the audit surface (the most security-sensitive output)."""
    monkeypatch.setenv(TOKEN_ENV, TOKEN_VALUE)
    # the apidoc must carry BOTH the pull path ({user:all}) AND the gated /cluster/status (Sys.Audit) node so the
    # two schema_permission entries both judge OK; grant_covers needs a 200 on /cluster/status.
    apidoc = ("const apiSchema = " + json.dumps([{"path": "/cluster", "children": [
        {"path": "/cluster/tasks", "info": {"GET": {"permissions": {"user": "all"}}}},
        {"path": "/cluster/status",
         "info": {"GET": {"permissions": {"check": ["perm", "/", ["Sys.Audit"]]}}}}]}]) + ";\n")
    fake = FakeFetchers(verifies=False,
                        gets={"apidoc.js": {"status": 200, "body": apidoc},
                              "cluster/tasks": {"status": 200, "body": '{"data":[{"upid":"x"}]}'},
                              "cluster/status": {"status": 200, "body": '{"data":[{"type":"cluster"}]}'}})
    audit = tmp_path / "audit.log"
    verdicts, code = M.run(only_key="proxmox", target_host="192.0.2.10", fetchers=fake, audit_path=str(audit))
    assert {v.verdict for v in verdicts} <= {M.OK, M.PENDING} and code == 0
    body = audit.read_text(encoding="utf-8")
    assert "validate-live" in body and TOKEN_VALUE not in body
    assert body.count("\n") == len(verdicts)                        # one audit line per check


def test_unknown_check_is_fail_closed(monkeypatch):
    """An unknown `check:` name (a descriptor typo) aborts loudly — it is never silently skipped (which would let a
    misnamed check read as 'all green'). Guards a fail-OPEN dispatch."""
    monkeypatch.setattr(M, "collect", lambda *a, **k: iter([({"check": "bogus_typo"}, {}, _target())]))
    with pytest.raises(SystemExit):
        M.run(target_host="192.0.2.10", fetchers=FakeFetchers(), audit_path=os.devnull)


def test_dispatch_spine_has_no_vendor_literal():
    """M-3: the SPINE (the fan + dispatcher, NOT the necessarily-vendor-aware check_* bodies) contains no vendor
    brand literal — machine-enforcing 'zero vendor branch'. A vendor-specific path lives in DATA (the descriptors)
    and inside a validator function, never in the code that decides WHICH validator runs. Guards the seam decaying
    into a per-vendor switch."""
    spine = "".join(inspect.getsource(fn) for fn in (M._pairs_for_module, M.collect, M.run, M.main))
    spine += repr(sorted(M._VALIDATORS))
    low = spine.lower()
    assert not any(brand in low for brand in ("proxmox", "fortigate", "cisco", "pve", "apidoc", "snmpget"))


def test_no_grant_role_literal_in_the_checks():
    """MF-4 (the cross-run DRY obligation): the grant role name lives ONCE in the descriptor's provisioning block
    (read via catalog.module_provisioning) — gen-validate-live.py must not hardcode `PVEAuditor`, or 'one
    declaration, two consumers' decays into two copies that can drift. Guards that decay early (before the deferred
    A' role-map check lands)."""
    src = open(os.path.join(ROOT, "scripts", "gen-validate-live.py"), encoding="utf-8").read()
    assert "PVEAuditor" not in src
