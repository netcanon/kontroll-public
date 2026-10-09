#!/usr/bin/env python3
"""The dashboard-floor DERIVE engine (north-star Rung 4a) — even the grafana.com board *id* is DERIVED from a
consistently-parseable cloud source, never a hand-typed `gnet` constant (the no-bespoke tenet, applied to boards).

A telemetry method opts a floor board in with a `derive_dashboard:` SELECTOR on its `telemetry/<method>.yml`
descriptor (a search query + datasource + a required series token + a soft `prefer_gnet` tie-break — NOT an id).
This engine runs that selector against grafana.com's parseable dashboards API, deterministically ranks the results,
and PINS the chosen `{id, revision, content_sha256, datasource, requires_series}` into a committed
`dashboards/derived/<method>.lock.yml` + fetches the pinned board JSON to `dashboards/grafana/dashboards/<name>.json`
(the same file + `pin_datasource` transform `fetch-dashboards.py` writes, so provisioning needs ZERO change).

Three modes, with the BRICK-1 offline/network split (no network in an install-gating path):
  * --check  (VALIDATE, DEFAULT-safe): OFFLINE coherence gate — schema:1, every derive_dashboard: selector has a
    lock, each lock's committed board hashes to its content_sha256 (the sha256 tamper floor), still contains its
    requires_series (offline re-grep — the series-fit honesty guard), and matches its selector's datasource +
    requires_series. Makes NO grafana.com call. Runs in tests/validate alongside gen-image-digests --check.
  * --resolve [<method>]  (OPERATOR/CONTROL-VM, NETWORK): run the ranked pick against grafana.com search, resolve
    id+revision, fetch + pin the board, write the lock + board. NEVER run in CI/deploy (a validate static gate pins
    that). The reviewable `git diff` on the lock + board IS the churn (mirrors gen-image-digests.py --refresh).
  * --list  (OFFLINE): print the current pins (method -> gnet/rev/name/chosen_by).

The DETERMINISTIC ranked pick, per method carrying derive_dashboard: (a total order over a finite set — no floats,
no timestamps, reproducible):
  1. datasource HARD FILTER: drop any result whose datasourceSlugs lack the selector's datasource (a board that
     cannot query our datasource is disqualified, never ranked below — honesty, not a tie-break).
  2. prefer_gnet: any id in the selector's prefer_gnet that is PRESENT in the live results ranks first (ascending) —
     a SOFT pin, honored only if the live search still returns it (so it can never resurrect a delisted board).
  3. downloads desc, then id ascending on a tie (older = more established; a total order, never a timestamp).
  4. requires_series FIT: walk the ranked candidates, fetch each, take the FIRST whose pinned JSON contains the
     required series token (a downloads-#1 that queries a different exporter is skipped) — else NO board (fail-honest).

Usage:  python3 scripts/gen-dashboard-floor.py [--check | --resolve [<method>] | --list]
"""
import datetime
import hashlib
import importlib.util
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

import yaml

from kontroll import paths

ROOT = paths.ROOT
GNET_API = "https://grafana.com/api/dashboards"
BOARDS_DIR = os.path.join(ROOT, "dashboards", "grafana", "dashboards")   # the provisioned board JSON (fetch-shared)
LOCKS_DIR = os.path.join(ROOT, "dashboards", "derived")                  # the derived-floor pins (this engine owns)
# datasource uids the provisioning declares (dashboards/grafana/provisioning/datasources/*.yml) — a lock's
# datasource MUST be one of these (an unprovisioned uid renders a blank board — a fatal provisioning event).
PROVISIONED_DS = ("prometheus", "loki")
SEARCH_TIMEOUT = 15          # s; a slow/unreachable registry raises → the method is skipped (never a partial pin)
PAGE_SIZE = 25
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _fd():
    """scripts/fetch-dashboards.py loaded by path (hyphenated filename → importlib, the repo's standard seam:
    observe.py/backup.py/logsvc.py do the same with their gen-* scripts). We reuse its fetch()/pin_datasource() so a
    DERIVED-floor board is munged BYTE-IDENTICALLY to a curated fetch — one transform, no drift. Importing runs the
    module body only (its main() is __main__-guarded), so no fetch happens at import."""
    spec = importlib.util.spec_from_file_location(
        "fetch_dashboards", os.path.join(ROOT, "scripts", "fetch-dashboards.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fd = _fd()


# --- descriptor + lock loaders (OFFLINE) ---------------------------------------------------------------------

def _selectors():
    """[(method_name, derive_dashboard_dict)] for every telemetry/<m>.yml carrying a `derive_dashboard:` selector,
    sorted by method (deterministic). The ONE dispatch seam: the method→board map lives on the descriptor, never in
    this generator (no `if method == …`). A method with no selector simply has no floor board (the honest default)."""
    out = []
    if not os.path.isdir(paths.TELEMETRY_DIR):
        return out
    for fn in sorted(os.listdir(paths.TELEMETRY_DIR)):
        if not fn.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(paths.TELEMETRY_DIR, fn), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        sel = doc.get("derive_dashboard")
        if doc.get("name") and sel:
            out.append((doc["name"], sel))
    return sorted(out)


def _load_locks():
    """{method: lock_dict} for every dashboards/derived/<method>.lock.yml (OFFLINE file read). A malformed lock is
    kept (so --check REPORTS it, fail-closed) rather than silently skipped."""
    out = {}
    if not os.path.isdir(LOCKS_DIR):
        return out
    for fn in sorted(os.listdir(LOCKS_DIR)):
        if not fn.endswith(".lock.yml"):
            continue
        method = fn[:-len(".lock.yml")]
        with open(os.path.join(LOCKS_DIR, fn), encoding="utf-8") as fh:
            out[method] = yaml.safe_load(fh) or {}
    return out


# --- the pinned artifacts (byte-exact, yamllint-clean) --------------------------------------------------------

def _sha256_bytes(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def _board_bytes(dash):
    """The committed board bytes — EXACTLY what fetch-dashboards.py writes (json.dump indent=2 + a trailing LF), so
    the lock's content_sha256 matches the on-disk file byte-for-byte and --check's hash compares cleanly."""
    return (json.dumps(dash, indent=2) + "\n").encode("utf-8")


def render_lock(rec):
    """Byte-exact lock content — hand-written (like gen-image-digests.render) so it stays yamllint-clean + diff-
    minimal across re-resolves. `resolved_at` is provenance ONLY (NOT read by --check — determinism, like
    facts.pinned.yml's probed_at)."""
    return ("---\n"
            "# GENERATED/maintained by scripts/gen-dashboard-floor.py --resolve — DO NOT hand-edit id/revision/sha.\n"
            "# The dashboard-floor pin (north-star Rung 4a): the grafana.com board DERIVED for this telemetry\n"
            "# method's derive_dashboard: selector, frozen so gen-dashboard-floor.py --check validates it OFFLINE\n"
            "# (BRICK-1). Re-derive with --resolve (network, operator-run); the diff is the reviewable churn.\n"
            "schema: 1\n"
            "method: %s\n" % rec["method"]
            + "name: %s\n" % rec["name"]
            + "id: %d\n" % rec["id"]
            + "revision: %d\n" % rec["revision"]
            + "datasource: %s\n" % rec["datasource"]
            + "content_sha256: \"%s\"\n" % rec["content_sha256"]
            + "requires_series: %s\n" % rec["requires_series"]
            + "chosen_by: %s\n" % rec["chosen_by"]
            + "search: \"%s\"\n" % rec["search"]
            + "resolved_at: \"%s\"\n" % rec["resolved_at"])


# --- the ranked pick (NETWORK, --resolve only) ---------------------------------------------------------------

def _search(query, datasource):
    """grafana.com dashboards search (NETWORK) → [items] pre-ranked by downloads desc, datasource-filtered. The
    parseable cloud source: GET /api/dashboards?filter=<q>&dataSourceSlugIn=<ds>&orderBy=downloads&direction=desc.
    A slow/unreachable registry RAISES (the caller degrades to leaving the existing lock untouched — never a
    partial/empty pin), mirroring catalog.galaxy_search's best-effort posture."""
    q = urllib.parse.urlencode({"filter": query, "dataSourceSlugIn": datasource,
                                "orderBy": "downloads", "direction": "desc", "page": 1, "pageSize": PAGE_SIZE})
    req = urllib.request.Request("%s?%s" % (GNET_API, q), headers={"User-Agent": "kontroll-gen-dashboard-floor"})
    with urllib.request.urlopen(req, timeout=SEARCH_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8")).get("items") or []


def _rank(items, datasource, prefer):
    """The deterministic candidate order: datasource-HARD-FILTERED, then prefer_gnet ids present (ascending), then
    the rest by (downloads desc, id asc). A total order over a finite set — no floats, no timestamps."""
    cands = [it for it in items if datasource in (it.get("datasourceSlugs") or [])]
    prefer_ids = sorted(int(it["id"]) for it in cands if int(it["id"]) in prefer)
    by_id = {int(it["id"]): it for it in cands}
    rest = sorted((it for it in cands if int(it["id"]) not in prefer_ids),
                  key=lambda it: (-int(it.get("downloads") or 0), int(it["id"])))
    return [by_id[i] for i in prefer_ids] + rest


def resolve_method(method, sel):
    """Run the ranked pick + series-fit for ONE method's selector → a lock record (dict, incl. the fetched `dash`),
    or raise LookupError if no candidate satisfies the datasource + series fit. NETWORK."""
    query, datasource, series = sel["search"], sel["datasource"], sel["requires_series"]
    prefer = [int(g) for g in (sel.get("prefer_gnet") or [])]
    name = sel.get("name") or method
    ranked = _rank(_search(query, datasource), datasource, prefer)
    if not ranked:
        raise LookupError("%s: no %s-datasource board matched %r" % (method, datasource, query))
    if prefer and not any(int(it["id"]) in prefer for it in ranked):
        sys.stderr.write("WARNING %s: prefer_gnet %s absent from live results -- using the downloads rank\n"
                         % (method, prefer))
    for it in ranked:
        gid = int(it["id"])
        rev, title, dash = fd.fetch(gid)                       # NETWORK: meta revision + download + pin_datasource
        if series.encode() not in _board_bytes(dash):          # series-fit fail-closed → try the next candidate
            continue
        return {"method": method, "name": name, "id": gid, "revision": int(rev),
                "datasource": datasource, "content_sha256": _sha256_bytes(_board_bytes(dash)),
                "requires_series": series, "chosen_by": ("prefer_gnet" if gid in prefer else "downloads"),
                "search": query, "title": title, "dash": dash}
    raise LookupError("%s: no candidate board queries the required series %r (fail-honest: no board emitted)"
                      % (method, series))


def resolve(only=None):
    """--resolve: for each method carrying derive_dashboard: (or just `only`), run the ranked pick, WRITE the lock +
    board, print one provenance line. A method that fails to resolve (network error / no fitting board) is WARNED and
    SKIPPED (its existing lock is left untouched — never a partial pin). Returns the count of FAILED methods."""
    os.makedirs(LOCKS_DIR, exist_ok=True)
    os.makedirs(BOARDS_DIR, exist_ok=True)
    selectors = _selectors()
    if only and only not in dict(selectors):   # a typo'd method silently resolving nothing is a footgun -> fail loudly
        sys.stderr.write("resolve: no telemetry method %r carries a derive_dashboard: selector (have: %s)\n"
                         % (only, ", ".join(m for m, _ in selectors) or "none"))
        return 1
    old = _load_locks()
    failed = 0
    for method, sel in selectors:
        if only and method != only:
            continue
        try:
            rec = resolve_method(method, sel)
        except (LookupError, urllib.error.URLError, OSError, ValueError) as exc:
            sys.stderr.write("resolve: %s FAILED (%s) -- leaving the existing lock untouched\n" % (method, exc))
            failed += 1
            continue
        prev = old.get(method) or {}
        if prev.get("id") == rec["id"] and prev.get("content_sha256") == rec["content_sha256"]:
            rec["resolved_at"] = prev.get("resolved_at") or datetime.date.today().isoformat()   # no-churn on no-change
        else:
            rec["resolved_at"] = datetime.date.today().isoformat()
            if prev.get("id") and prev.get("id") != rec["id"]:
                sys.stderr.write("WARNING %s: pinned board SWAPPED gnet %s -> %s (%s) -- review the diff\n"
                                 % (method, prev.get("id"), rec["id"], rec["chosen_by"]))
        with open(os.path.join(BOARDS_DIR, "%s.json" % rec["name"]), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_board_bytes(rec["dash"]).decode("utf-8"))
        with open(os.path.join(LOCKS_DIR, "%s.lock.yml" % method), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_lock(rec))
        print("resolved %s -> gnet %d rev %d (%s) %s -> dashboards/grafana/dashboards/%s.json"
              % (method, rec["id"], rec["revision"], rec["chosen_by"], rec["content_sha256"][:19], rec["name"]))
    return failed


# --- the OFFLINE coherence gate (--check; BRICK-1 — no network) -----------------------------------------------

def _check_lock(method, lock, sel):
    """OFFLINE coherence of ONE lock ↔ its committed board ↔ its selector → [problems] ([] == coherent). Hashes the
    board file on disk + re-greps its bytes for requires_series; NEVER re-fetches (BRICK-1)."""
    p = []
    if lock.get("schema") != 1:
        p.append("%s: schema must be 1" % method)
    if lock.get("method") != method:
        p.append("%s: lock method %r != filename stem %r" % (method, lock.get("method"), method))
    name = lock.get("name")
    if not (isinstance(name, str) and name):
        return p + ["%s: name must be a non-empty string" % method]
    if not isinstance(lock.get("id"), int):
        p.append("%s: id must be an int (the DERIVED grafana.com id)" % method)
    if not isinstance(lock.get("revision"), int):
        p.append("%s: revision must be an int" % method)
    ds = lock.get("datasource")
    if ds not in PROVISIONED_DS:
        p.append("%s: datasource %r is not a provisioned uid %s" % (method, ds, list(PROVISIONED_DS)))
    sha = lock.get("content_sha256")
    if not (isinstance(sha, str) and _SHA256.match(sha)):
        p.append("%s: content_sha256 %r is not a sha256:<64hex>" % (method, sha))
    series = lock.get("requires_series")
    if not (isinstance(series, str) and series):
        p.append("%s: requires_series must be a non-empty string" % method)
    # lock ↔ selector coherence — a descriptor edit (datasource/series) without a re-resolve is caught here.
    if sel is None:
        p.append("%s: lock has no matching telemetry derive_dashboard: selector (orphan lock -- delete or re-add)"
                 % method)
    else:
        if ds != sel.get("datasource"):
            p.append("%s: lock datasource %r != selector %r (re-run --resolve)" % (method, ds, sel.get("datasource")))
        if series != sel.get("requires_series"):
            p.append("%s: lock requires_series %r != selector %r (re-run --resolve)"
                     % (method, series, sel.get("requires_series")))
    # lock ↔ board coherence — the sha256 tamper floor + the offline series-fit re-grep.
    board = os.path.join(BOARDS_DIR, "%s.json" % name)
    if not os.path.exists(board):
        return p + ["%s: committed board dashboards/grafana/dashboards/%s.json is missing (run --resolve)"
                    % (method, name)]
    with open(board, "rb") as fh:
        data = fh.read()
    if isinstance(sha, str) and _SHA256.match(sha) and _sha256_bytes(data) != sha:
        p.append("%s: %s.json sha256 %s != lock %s (board tampered, OR rewritten by fetch-dashboards.py to a newer "
                 "revision of a shared gnet -- re-run gen-dashboard-floor.py --resolve to re-pin)"
                 % (method, name, _sha256_bytes(data), sha))
    if isinstance(series, str) and series and series.encode() not in data:
        p.append("%s: %s.json no longer contains requires_series %r (series-fit broken -- re-run --resolve)"
                 % (method, name, series))
    return p


def check():
    """OFFLINE (BRICK-1): every derive_dashboard: selector has a coherent lock + committed board. → [problems]."""
    problems = []
    selectors = dict(_selectors())
    locks = _load_locks()
    for method in selectors:
        if method not in locks:
            problems.append("%s: derive_dashboard: selector has no dashboards/derived/%s.lock.yml (run --resolve)"
                            % (method, method))
    for method in sorted(locks):
        problems += _check_lock(method, locks[method], selectors.get(method))
    return problems


def _list():
    for method in sorted(_load_locks()):
        lk = _load_locks()[method]
        print("%-12s gnet %-7s rev %-4s %-10s %s"
              % (method, lk.get("id"), lk.get("revision"), lk.get("chosen_by"), lk.get("name")))
    return 0


def main(argv):
    if "--resolve" in argv:
        rest = [a for a in argv if not a.startswith("--")]
        return 1 if resolve(rest[0] if rest else None) else 0
    if "--list" in argv:
        return _list()
    # default + --check: the OFFLINE coherence gate (safe bare invocation — never touches the network).
    problems = check()
    if problems:
        for prob in problems:
            sys.stderr.write("dashboard-floor: %s\n" % prob)
        return 1
    print("gen-dashboard-floor: %d derived-floor lock(s) coherent (--check)" % len(_load_locks()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
