# The public split — how the public `kontroll` repository and a private instance repository relate

> Genericization Phase 5 (plan of record since 2026-06-15; executed 2026-10-08). Design-of-record for the
> identifier sweep and the cut: the private review dossier `docs/reviews/2026-10-08-public-split-pii-sweep/`.

## What is public, what is not

| Tree | Public repository (`github.com/netcanon/kontroll`) | Private instance repository |
|---|---|---|
| The tool — code, playbooks, registries, generators, tests, docs | **yes** (this is the source of truth for the tool) | mirrored |
| `instance.example/` — the placeholder overlay (TEST-NET addresses, one fake age recipient, canary tokens) | yes | yes |
| `instance/` — YOUR overlay: inventory, `.sops.yaml` recipients, encrypted secrets, fleet selection, Homepage tiles, `leak-tokens.txt` | **never** (git-ignored there; the PII-guard workflow fails if any path under it is ever tracked) | tracked |
| `docs/reviews/` dossiers written before the split (they quote the maintainer's real topology) | never | tracked |
| `local/` | never (git-ignored everywhere) | never |
| Git history | **fresh** — the public repository starts at the cut commit | the full history |

The public repository has a **fresh history by design**: the private history carries the real
inventory, the real `.sops.yaml` recipients, SOPS ciphertext and lab addresses in hundreds of
commits and commit messages, and a scrub of free text across 600+ commits cannot be verified.
The private repository keeps that history as the archive.

## The cut (one-shot)

```bash
# on the private main, after the public-split prep landed
git archive --format=tar main | tar -x -C /tmp/public-tree
rm -rf /tmp/public-tree/instance /tmp/public-tree/docs/reviews/2026-*   # the strip set (= scripts/make-bundle.sh)
printf '\n# --- the private instance overlay (public repo) ---\ninstance/\n' >> /tmp/public-tree/.gitignore
cd /tmp/public-tree && git init -b main && git add -A && git commit -s   # author: the project's public identity
```

The acceptance gate for the cut is `python3 tests/_leak_guard.py --tree` returning **zero findings on
the public tree with the private token list active** (`KONTROLL_LEAK_TOKENS_FILE=…/instance/leak-tokens.txt`),
plus a green `tests/validate.sh --strict` and the hermetic pytest suite on the public tree — the tree must
pass its own gates with no `instance/` present (`kontroll.paths.resolve` reads the shipped example on an
unconfigured checkout).

## The standing guard (why it cannot recur)

`tests/_leak_guard.py` runs in three places with one implementation: `tests/validate.sh` (step `pii-guard`),
`.github/workflows/pii-guard.yml` (the required check *No leaked personal identifiers*) and the pytest twin
`tests/unit/test_leak_guard.py`.

- **Structural layer** (public, always on): any RFC-1918 address in any spelling (dotted, dashed, underscored),
  a non-documentation MAC or global IPv6, a real-length age recipient / AGE secret key, the maintainer's
  personal email, an operator-machine user-profile path. TEST-NET, RFC-7042 MACs and `2001:db8::/32` are the
  sanctioned examples and never match.
- **Instance-token layer** (private): the names that identify one deployment — hostnames, domain, user names,
  subnets, VLAN ids — one regex per line in `instance/leak-tokens.txt`. It never ships; the public repository
  receives the same list as the repository secret `KONTROLL_LEAK_TOKENS` (fork PRs have no secrets and run on
  the shipped canaries). A match is reported as `token#N sha256:xxxxxxxx`, never the name.
- A line that must carry a private address says so: `pii-guard: allow <reason>`.

## CI in the two repositories

The workflows are identical files. Every job's `runs-on` is
`${{ fromJSON(vars.KONTROLL_RUNS_ON || '"ubuntu-latest"') }}`:

| | public | private instance repo |
|---|---|---|
| `KONTROLL_RUNS_ON` variable | unset → GitHub-hosted `ubuntu-latest` (free for public repos; a public repo must never use a self-hosted runner — a fork PR would run on it) | `["self-hosted","Linux","X64"]` — the org runners |
| `KONTROLL_LEAK_TOKENS` secret | the private token list | not needed (`instance/leak-tokens.txt` is tracked) |
| `validate --strict` | every tool installed in the job (sha256-pinned sops, gitleaks, promtool, vector) | same |
| Rulesets | `main`: require a pull request + every CI check green, no force-push, no deletion; `v*` tags immutable | not available on the plan (checks are advisory) |
| Secret scanning + push protection, CodeQL default setup, Dependabot alerts | on | not available on the plan |
| `publish-images.yml` | publishes `ghcr.io/<owner>/kontroll-*` on a `v*` tag — until the package names move, `docker/images.lock.yml` still pins the private org's packages | publishes the private org's packages |

## Day-to-day

- **Develop on the public repository**: feature branch → pull request → the required checks → merge. That is
  where the enforcement is.
- **The private instance repository tracks it**: add the public repo as `upstream`, merge `upstream/main`
  into the private `main` (`--allow-unrelated-histories` once, at the graft), rebase the instance branch(es)
  on top. The private repo never pushes to the public remote
  (`git remote set-url --push upstream DISABLED` is a cheap belt-and-braces).
- **A private-side fix that belongs to the tool** is cherry-picked onto a public branch and goes through a
  public pull request like everything else — the PII guard runs on it.
- **Your instance's names change** → update `instance/leak-tokens.txt` and the `KONTROLL_LEAK_TOKENS` secret.

## Operator checklist for the first publish

1. Create the public repository **private**, push the cut, let CI run green (GitHub-hosted).
2. Set the repository secret `KONTROLL_LEAK_TOKENS` from `instance/leak-tokens.txt`.
3. Flip the visibility to public; immediately apply the rulesets (`main` required checks, immutable `v*`),
   enable secret scanning + push protection, CodeQL default setup, Dependabot alerts + security updates.
4. Re-run the full identifier sweep (`tests/_leak_guard.py --tree` with the private list) on the pushed tree —
   the same command, the same zero.
