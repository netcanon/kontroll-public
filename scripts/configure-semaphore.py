#!/usr/bin/env python3
"""Idempotently configure Semaphore to run the kontroll playbooks.

Reproducible, declarative setup of the Semaphore project: keys, repository,
environment, inventory, task templates, and the backup schedule. Safe to re-run
(get-or-create by name). Run ON the control node (it reads the local key files
and talks to Semaphore on localhost).

Templates come from two data registries, never hand-listed here: the OPERATIONAL
(manually-run) templates are drop-ins under config/semaphore/templates/<name>.yml
(ping-fleet, promote-proposal — the C10 "approve" task; survey_vars supported); the
SCHEDULED (backup) templates are generated into config/semaphore/schedules.generated.yml
by scripts/gen-backup.py. Adding either is a data change, not a code edit.

Inputs (env):
  SEMAPHORE_URL              default http://localhost:3001
  SEMAPHORE_ADMIN            default admin
  SEMAPHORE_ADMIN_PASSWORD   optional — auto-decrypted from instance/secrets/semaphore.sops.yml if unset
                             (the control node holds the age key, so no manual export is needed)

Key material read from the control node:
  ~/.ssh/kontroll_deploy        read-only GitHub deploy key (repo clone)
  ~/.ssh/ansible_ed25519        device SSH key (reach the fleet)
  ~/.config/semaphore/age.key   scoped SOPS age key (decrypt network/proxmox)

Why env vars instead of the repo ansible.cfg: Semaphore runs from the repo ROOT,
but ansible/ansible.cfg uses paths relative to ansible/. We set the few that
matter as process env so resolution is correct from the root.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

import yaml   # read config/semaphore/schedules.generated.yml (PyYAML ships with ansible on the control node)

BASE = os.environ.get("SEMAPHORE_URL", "http://localhost:3001").rstrip("/")
ADMIN = os.environ.get("SEMAPHORE_ADMIN", "admin")
HOME = os.path.expanduser("~")

REPO_GIT_URL = "git@github.com:netcanon/kontroll.git"   # optional offsite backup remote
LOCAL_GIT_URL = "file:///srv/kontroll.git"              # instance source of truth (mounted bare repo)
REPO_BRANCH = "main"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEMAPHORE_SECRETS = os.path.join(REPO_ROOT, "instance", "secrets", "semaphore.sops.yml")  # self-decrypt source (#4)
# Drop-in registry of OPERATIONAL (manually-run) templates — config/semaphore/templates/<name>.yml.
# Adding an operational task is a new file there, never an edit here (config/semaphore/templates/README.md).
OPERATIONAL_TEMPLATES_DIR = os.path.join(REPO_ROOT, "config", "semaphore", "templates")


def load_operational_templates(directory=OPERATIONAL_TEMPLATES_DIR):
    """Read every config/semaphore/templates/*.yml into a sorted list of template specs (pure — no network).

    Sorted by filename so registration order is deterministic. Each spec must carry `name`, `playbook`, and
    `description`; `arguments` (list) and `survey_vars` (list) are optional. Kept pure + importable so the
    registry can be unit-tested (test_configure_semaphore.py) without a live Semaphore."""
    specs = []
    if not os.path.isdir(directory):
        return specs
    for fn in sorted(os.listdir(directory)):
        if not fn.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(directory, fn), encoding="utf-8") as fh:
            spec = yaml.safe_load(fh) or {}
        spec["_file"] = fn
        specs.append(spec)
    return specs


def template_payload(spec, common):
    """Build the Semaphore template API payload for one operational spec (pure).

    Threads `survey_vars` + `arguments` only when the spec declares them, so a no-input template (ping-fleet)
    never carries an empty survey_vars and a re-run does not churn it. `common` supplies the project-wide
    inventory/repository/environment ids + app defaults."""
    payload = {**common, "name": spec["name"], "playbook": spec["playbook"],
               "description": spec["description"]}
    if spec.get("arguments"):
        payload["arguments"] = json.dumps(spec["arguments"])
    if spec.get("survey_vars"):
        payload["survey_vars"] = spec["survey_vars"]
    return payload


def read_file(path):
    with open(os.path.expanduser(path), "r", encoding="utf-8") as fh:
        return fh.read()


def age_secret():
    # SOPS_AGE_KEY wants the AGE-SECRET-KEY-... line only (skip comments).
    for line in read_file("~/.config/semaphore/age.key").splitlines():
        if line.startswith("AGE-SECRET-KEY-"):
            return line.strip()
    sys.exit("no AGE-SECRET-KEY line in ~/.config/semaphore/age.key")


_cookie = {"v": None}


def api(method, path, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if _cookie["v"]:
        req.add_header("Cookie", _cookie["v"])
    try:
        resp = urllib.request.urlopen(req)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> {e.code}: {e.read().decode()[:300]}")
    sc = resp.headers.get("Set-Cookie")
    if sc:
        _cookie["v"] = sc.split(";")[0]
    raw = resp.read().decode()
    return json.loads(raw) if raw.strip() else None


def get_or_create(list_path, create_path, match, payload, label):
    existing = api("GET", list_path) or []
    for item in existing:
        if all(item.get(k) == v for k, v in match.items()):
            print(f"  = {label} exists (id={item['id']})")
            return item
    created = api("POST", create_path, payload)
    # Some POSTs return the object; some return nothing -> re-fetch.
    if not created:
        for item in api("GET", list_path) or []:
            if all(item.get(k) == v for k, v in match.items()):
                created = item
                break
    print(f"  + {label} created (id={created['id']})")
    return created


def upsert(list_path, base_path, match, payload, label):
    """Like get_or_create, but PUT-updates an existing object so re-runs apply
    changed fields (used for templates whose args/playbook may evolve)."""
    for item in api("GET", list_path) or []:
        if all(item.get(k) == v for k, v in match.items()):
            api("PUT", f"{base_path}/{item['id']}", {**payload, "id": item["id"]})
            print(f"  ~ {label} updated (id={item['id']})")
            return {**item, **payload}
    created = api("POST", base_path, payload)
    if not created:
        for item in api("GET", list_path) or []:
            if all(item.get(k) == v for k, v in match.items()):
                created = item
                break
    print(f"  + {label} created (id={created['id']})")
    return created


def wait_for_semaphore(timeout=120):
    """Semaphore (just started by deploy-stack) accepts API connections a few seconds AFTER its container is up
    — the HTTP server isn't listening immediately. A fresh single-pass install (deploy then configure) otherwise
    races it: ConnectionResetError on the first call. Poll until it responds (ANY HTTP status = listening).
    Raises after `timeout`s. (Found by the live single-pass dogfood re-run.)"""
    deadline = time.monotonic() + timeout
    while True:
        try:
            urllib.request.urlopen(BASE + "/api/ping", timeout=5)
            return
        except urllib.error.HTTPError:
            return                          # responded with a status (e.g. 404) → the server is up
        except (urllib.error.URLError, ConnectionError, OSError):
            if time.monotonic() >= deadline:
                sys.exit(f"Semaphore at {BASE} not reachable after {timeout}s — is the stack up (deploy-stack)?")
            time.sleep(3)


def admin_password():
    """The Semaphore admin password: the SEMAPHORE_ADMIN_PASSWORD env var if set, else SELF-DECRYPTED from the
    `semaphore` SOPS domain (instance/secrets/semaphore.sops.yml) via the sops CLI — the control node already holds
    the age key, so the operator runs `python3 scripts/configure-semaphore.py` with NO manual export (the docstring's
    'decrypt from …' done for them; the live fresh-install dogfood hit 'not set' precisely because the export was
    undocumented). Returns None when neither is available (env unset + sops/file/age-key missing), so main() fails with
    a clear hint. The value is used only for the in-process API login — never printed or logged (SEC: no creds in logs)."""
    env = os.environ.get("SEMAPHORE_ADMIN_PASSWORD")
    if env:
        return env
    if not os.path.exists(SEMAPHORE_SECRETS):
        return None
    try:
        p = subprocess.run(["sops", "-d", "--extract", '["semaphore_admin_password"]', SEMAPHORE_SECRETS],
                           capture_output=True, text=True)
    except OSError:
        return None                        # sops not installed
    return p.stdout.strip() if (p.returncode == 0 and p.stdout.strip()) else None


def main():
    password = admin_password()            # env, else self-decrypt instance/secrets/semaphore.sops.yml (no manual export)
    if not password:
        sys.exit("SEMAPHORE_ADMIN_PASSWORD not set and could not decrypt instance/secrets/semaphore.sops.yml — "
                 "is the control age key present? (try: sops -d instance/secrets/semaphore.sops.yml)")
    wait_for_semaphore()                   # tolerate Semaphore still warming up right after deploy-stack
    print(f"Login to {BASE} as {ADMIN}")
    api("POST", "/api/auth/login", {"auth": ADMIN, "password": password})

    # 1. Project
    proj = get_or_create(
        "/api/projects", "/api/projects",
        {"name": "kontroll"},
        {"name": "kontroll", "alert": False},
        "project kontroll",
    )
    pid = proj["id"]
    P = f"/api/project/{pid}"

    # 2. Keys (device SSH key + an empty 'none' key for the local canonical). The github-deploy key is the
    # OPTIONAL offsite-backup credential — register it ONLY if present. A fresh node has no offsite remote, and
    # the repository below clones file:///srv/kontroll.git with the 'none' key, never this one (so its absence
    # must not abort the wiring). The operator adds it later if they configure an offsite backup remote.
    deploy_key_path = os.path.expanduser("~/.ssh/kontroll_deploy")
    if os.path.exists(deploy_key_path):
        get_or_create(
            f"{P}/keys", f"{P}/keys", {"name": "github-deploy"},
            {"name": "github-deploy", "type": "ssh", "project_id": pid,
             "ssh": {"login": "git", "passphrase": "", "private_key": read_file(deploy_key_path)}},
            "key github-deploy",
        )
    else:
        print("  - github-deploy key skipped (~/.ssh/kontroll_deploy absent — no offsite remote configured yet)")
    ansible_key = get_or_create(
        f"{P}/keys", f"{P}/keys", {"name": "ansible-ssh"},
        {"name": "ansible-ssh", "type": "ssh", "project_id": pid,
         "ssh": {"login": "", "passphrase": "", "private_key": read_file("~/.ssh/ansible_ed25519")}},
        "key ansible-ssh",
    )
    none_key = get_or_create(
        f"{P}/keys", f"{P}/keys", {"name": "none"},
        {"name": "none", "type": "none", "project_id": pid},
        "key none",
    )

    # 3. Repository — the LOCAL CANONICAL bare repo (instance source of truth), NOT
    # GitHub. Mounted into the container at /srv/kontroll.git; cloned via file://, no
    # key needed. The running instance therefore has zero remote-git dependency
    # (docs/local-source-of-truth.md, Phase A). The github-deploy key stays in the
    # store for the OPTIONAL offsite backup remote. upsert so this re-points cleanly.
    repo = upsert(
        f"{P}/repositories", f"{P}/repositories", {"name": "kontroll"},
        {"name": "kontroll", "project_id": pid, "git_url": LOCAL_GIT_URL,
         "git_branch": REPO_BRANCH, "ssh_key_id": none_key["id"]},
        "repository kontroll (local canonical)",
    )

    # 4. Environment — runtime env + the scoped SOPS age key as an injected secret.
    env_vars = {
        "ANSIBLE_HOST_KEY_CHECKING": "False",
        "ANSIBLE_ROLES_PATH": "ansible/roles",
        "ANSIBLE_COLLECTIONS_PATH": "/usr/share/ansible/collections",
    }
    # NB: the operator-owned bare repo cloned by the runner uid trips git's
    # dubious-ownership guard — handled by `safe.directory=*` baked into the runner
    # image (docker/semaphore-runner/Dockerfile), not here (this env is get-or-create;
    # changing it would mean re-creating the injected SOPS_AGE_KEY secret).
    env_body = {"name": "kontroll", "project_id": pid, "json": "{}", "env": json.dumps(env_vars)}
    # The scoped Semaphore age key (~/.config/semaphore/age.key) is minted POST-deploy via the GUI 'Keys'
    # dialog (the scoped-Semaphore role). Inject SOPS_AGE_KEY only once it exists — on a fresh node the runner
    # is wired without decryption; mint the scoped key, then re-run (or add the secret in the Semaphore UI).
    if os.path.exists(os.path.expanduser("~/.config/semaphore/age.key")):
        env_body["secrets"] = [{"type": "env", "name": "SOPS_AGE_KEY", "secret": age_secret(), "operation": "create"}]
    else:
        print("  - SOPS_AGE_KEY env-secret skipped (~/.config/semaphore/age.key absent — mint the scoped "
              "Semaphore key via the GUI 'Keys' dialog, then re-run to inject it)")
    env = get_or_create(
        f"{P}/environment", f"{P}/environment", {"name": "kontroll"},
        env_body,
        "environment kontroll",
    )

    # 5. Inventory — the inventory DIRECTORY (not a single file), so drop-in host
    # files (instance/inventory/onboarded-*.yml from `galaxy.py onboard`) are picked
    # up additively. upsert so a path change applies on re-run.
    inv = upsert(
        f"{P}/inventory", f"{P}/inventory", {"name": "kontroll-fleet"},
        {"name": "kontroll-fleet", "project_id": pid, "type": "file",
         "inventory": "instance/inventory",
         "ssh_key_id": ansible_key["id"], "become_key_id": none_key["id"]},
        "inventory kontroll-fleet",
    )

    # 6. Operational task templates — the drop-in registry (config/semaphore/templates/<name>.yml).
    # One manually-run template per file (ping-fleet, promote-proposal, …); survey_vars (e.g.
    # promote-proposal's run_id) are threaded through template_payload. Adding an operational task is a new
    # file there, never an edit here (config/semaphore/templates/README.md).
    common = {"project_id": pid, "inventory_id": inv["id"], "repository_id": repo["id"],
              "environment_id": env["id"], "app": "ansible", "type": "", "arguments": "[]"}
    operational = {}
    for spec in load_operational_templates():
        tpl = upsert(
            f"{P}/templates", f"{P}/templates", {"name": spec["name"]},
            template_payload(spec, common),
            f"template {spec['name']}",
        )
        operational[spec["name"]] = tpl["id"]
    # 7. Per-class backup templates + schedules — GENERATED from each class's module.yml `backup:` block
    # (scripts/gen-backup.py -> config/semaphore/schedules.generated.yml). Adding or retiming a class's backup
    # is a `backup:` drop-in + a re-gen, NOT an edit here: this loop just registers whatever the spec declares
    # — one template + schedule per class, each backup-configs.yml --limit'd to its inventory group, writing to
    # /backups (the persistent host volume, not the ephemeral job clone). Replaces the former single
    # hand-listed backup-configs template + nightly-backup schedule (the "add an X" hub removal).
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "config", "semaphore", "schedules.generated.yml"), encoding="utf-8") as fh:
        backup_specs = (yaml.safe_load(fh) or {}).get("schedules", [])
    backup_template_ids = []
    for s in backup_specs:
        args = ["-e", "config_backup_dir=/backups", "--limit", s["limit"]]
        # Optional knobs (#123): carry `retention` to the run as kontroll_backup_retention (the retention-prune
        # play in backup-configs.yml ENFORCES it — #125; keep-all = no prune) and record both in the description.
        if s.get("retention"):
            args += ["-e", f"kontroll_backup_retention={s['retention']}"]
        knobs = "".join(f"; {k} {s[k]}" for k in ("retention", "destination") if s.get(k))
        tpl = upsert(
            f"{P}/templates", f"{P}/templates", {"name": s["name"]},
            {**common, "name": s["name"], "playbook": s["playbook"],
             "description": f"Config backup — {s['key']} (--limit {s['limit']}{knobs}; generated, do not hand-edit)",
             "arguments": json.dumps(args)},
            f"template {s['name']}",
        )
        get_or_create(
            f"{P}/schedules", f"{P}/schedules", {"name": s["name"]},
            {"project_id": pid, "template_id": tpl["id"], "name": s["name"],
             "cron_format": s["cron"], "active": True},
            f"schedule {s['name']} ({s['cron']})",
        )
        backup_template_ids.append(tpl["id"])

    print(f"\nDONE. project_id={pid}  operational_templates={len(operational)} "
          f"({', '.join(sorted(operational))})  backup_templates={len(backup_template_ids)} (generated)")
    print(json.dumps({"project_id": pid, "operational_template_ids": operational,
                      "backup_template_ids": backup_template_ids}))


if __name__ == "__main__":
    main()
