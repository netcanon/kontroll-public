# Vendored MIB closure (public, pinned) — inputs to the snmp_exporter generator

These `.txt` MIB modules are the **public, pinned** source from which `scripts/gen-snmp.py` derives
`../modules.generated.yml` (the no-bespoke-config tenet: derive from a pinned public source, never bespoke). They
are committed verbatim so a regeneration is reproducible offline and any MIB churn is a reviewable diff. **A
public IETF MIB is not a secret** — these are committed in the open, no SOPS, no `no_log`.

## The `if_mib` closure (why each file is here)

`IF-MIB` (RFC 2863) `IMPORTS` transitively pull in the following; the snmp_exporter generator runs with
`--fail-on-parse-errors`, so a **missing** import is a hard, loud failure (fail-closed):

| File | Module | Needed because |
|---|---|---|
| `SNMPv2-SMI.txt` | SNMPv2-SMI | base types (Counter32/64, Gauge32, mib-2, …) |
| `SNMPv2-TC.txt` | SNMPv2-TC | textual conventions (DisplayString, PhysAddress, …) |
| `SNMPv2-CONF.txt` | SNMPv2-CONF | MODULE-COMPLIANCE / OBJECT-GROUP (**easy to omit → parse error**) |
| `SNMPv2-MIB.txt` | SNMPv2-MIB | `sysUpTime` (re-added to `if_mib`) + `snmpTraps` |
| `IF-MIB.txt` | IF-MIB | the interface objects themselves |
| `IANA-IFTYPE-MIB.txt` | IANAifType-MIB | `ifType` enum (filename ≠ module name — resolved by module name inside the file) |
| `SNMP-FRAMEWORK-MIB.txt` | SNMP-FRAMEWORK-MIB | transitive resolver insurance (net-snmp ships it) |

## Provenance + re-vendor recipe (pinned)

Standard MIBs are pinned to **net-snmp `v5.9`**; the IANA file is an IANA snapshot. Re-vendoring = re-run this and
review the diff (then regenerate `modules.generated.yml` — see `../README.md`):

```bash
NS=https://raw.githubusercontent.com/net-snmp/net-snmp/v5.9/mibs
for m in SNMPv2-SMI SNMPv2-TC SNMPv2-CONF SNMPv2-MIB IF-MIB SNMP-FRAMEWORK-MIB; do
  curl -fsSL "$NS/$m.txt" -o "$m.txt"
done
curl -fsSL https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib -o IANA-IFTYPE-MIB.txt
```

Files are committed verbatim **with their license headers intact** (net-snmp = BSD/IETF-Trust; IANA = freely
redistributable) and **normalized to LF** (the repo's `.gitattributes eol=lf` applies; innocuous for these
licenses, noted here so the diff-from-upstream is explained). Confirm the root `LICENSE` permits bundling
BSD/IETF-Trust MIB text before adding a new vendor MIB.
