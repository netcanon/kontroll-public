# `oui/` — the pinned IEEE OUI → vendor lookup (discovery display-hint)

A **generated, committed** reduction of the public IEEE MAC-address registries, used to annotate a discovery-inbox
candidate's MAC with its **manufacturer** — a recognition aid for the human deciding *which* device class to search
for. It is a **DISPLAY HINT, never a class guess** (SECURITY [C18](../SECURITY.md), F8): the vendor is inert text on a
row the operator already sees; no code reads it to pick a collection or synthesize an onboard card.

| File | What |
|---|---|
| `oui-lookup.generated.json` | the pinned lookup — a single `{schema, prefixes}` object, `prefixes` = `<hex-prefix> → <vendor>`, keys are lowercase colon-less hex at the assignment's OWN length (**6** = MA-L /24, **7** = MA-M /28, **9** = MA-S /36). Generated; do not hand-edit. |
| `oui-lookup.lock.yml` | the small hand-legible provenance/staleness lock the `--check` reads: `schema`, the 3 IEEE source URLs, `content_sha256` of the `.json`, `prefix_count`, `generated_at`. |

## Longest-prefix match (why a naïve "first 3 bytes" is wrong)

IEEE stopped selling only /24 OUIs years ago — a /24 is now often re-parcelled into /28 (MA-M) and /36 (MA-S) blocks
with different owners. So the reader ([`service/discovery._vendor_for`](../scripts/kontroll/service/discovery.py))
probes **9 → 7 → 6** nibbles (longest wins). A single flat dict serves all three registries because each assignment
is stored at its own length. A missing OUI → `None` (a graceful "unknown vendor", never a crash).

## Derive → pin → `--check` (no-bespoke)

The **whole** registry is derived + pinned, never a hand-curated subset (which would rot). Owned by
[`scripts/gen-oui.py`](../scripts/gen-oui.py), the same shape as `gen-dashboard-floor.py`:

```bash
python3 scripts/gen-oui.py --refresh   # NETWORK (operator/CI-authoring): GET the 3 IEEE CSVs, rebuild the pin
python3 scripts/gen-oui.py --check     # OFFLINE (tests/validate): schema + key-shape + count + sha256 + sources
python3 scripts/gen-oui.py --list      # OFFLINE: the pin summary
```

**BRICK-1:** `--refresh` is the ONLY network leg (hits `standards-oui.ieee.org`) and is **operator/CI-authoring only** —
`tests/validate` + deploy run only the OFFLINE `--check`, and a `validate.sh` static grep-gate
(`oui-refresh-not-in-deploy`) proves the network verb never appears in an install-gating path (mirrors
`dashboard-floor-resolve-not-in-deploy`). Runtime reads the **pinned** `.json` offline. The registrant **address**
column is dropped (bloat + churn + irrelevant); vendor names are collapsed/`.`-stripped/capped at 64 chars.

## Committed-safety

- **P-1:** the artifact has no IPs and no full MACs — only 24/28/36-bit *prefixes* + org names — so the
  `discovery-p1-fixtures` gate's IP/MAC regexes cannot fire (and `oui/` is outside that gate's scope anyway). The
  enrichment **test fixture** uses `00:00:5e` (IANA's real OUI, from the RFC-7042 doc MAC `00:00:5e:00:53:xx`), so it
  is documentation-safe *and* exercises a real longest-prefix hit.
- **gitleaks:** the `.json` (+ the `.lock.yml`) are allowlisted in `.gitleaks.toml` (a GENERATED reduction of the
  public registry — vendor names + one sha; a real secret can't land without subverting the generator, which fails
  `--check` loudly), the same posture as `docker/code-manifest.lock.yml`.
- **Baked:** `COPY oui/ /opt/kontroll/oui/` in the control image; read via the ROOT-bound `paths.OUI_DIR` (a data
  registry, like `DISCOVERY_DIR`).

## See also
- [`discovery/README.md`](../discovery/README.md) — the inbox this enriches. [SECURITY.md C18](../SECURITY.md) — the F8
  display-hint-vs-class-guess boundary.
