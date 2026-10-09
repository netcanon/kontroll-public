"""capture-exception domain — adversarial-safe append into the sparse capture matrix.

add_capture_exception adds one member to config/capture-exceptions.yml, rendering the
new entry with yaml.safe_dump so ANY operator text (a colon, a YAML-special word like
`yes`/`no`, unicode, a multi-line note) round-trips as a correct STRING and can never
corrupt the file that gates the backup pipeline. The commit/push GATE stays in the CLI
wrapper (galaxy.py cmd_capture_exception_add) — this is the exemplar the whole service
layer generalizes (docs/api-architecture.md §1).
"""
import os
import re
import sys

import yaml

from kontroll import paths


def add_capture_exception(subject, match, behavior, disposition, observed, source):
    """Add an entry to config/capture-exceptions.yml, preserving the header comments. The new
    entry is rendered with yaml.safe_dump — so ANY operator text (a colon, a quote, a
    YAML-special word like `yes`/`no`, unicode) round-trips as a correct STRING and can never
    corrupt the file that gates the backup pipeline — then line-inserted after the last entry
    so the header comments survive. Idempotent: a no-op if an entry with the same `match`
    already exists (checked on the PARSED doc, immune to scalar-content false matches).
    Returns True if a new entry was added, else False."""
    path = os.path.join(paths.write_root(), "config", "capture-exceptions.yml")
    # `match` flows into a rendered .gitignore (a leading '#' would comment it out) and into
    # `git rm` pathspecs (a space would split it) in backup-configs.yml — so constrain it to a
    # capture-filename glob, which is all it should ever be.
    if not re.fullmatch(r"[A-Za-z0-9_.*?\[\]\-]+", match):
        sys.exit("invalid --match %r: use a capture-filename glob (letters/digits and . _ - * ? [ ])" % match)
    lines = open(path, encoding="utf-8").read().splitlines()
    start = next((i for i, ln in enumerate(lines) if ln.strip() == "exceptions:"), None)
    if start is None:
        sys.exit("config/capture-exceptions.yml: no 'exceptions:' key")
    try:
        doc = yaml.safe_load("\n".join(lines)) or {}
    except yaml.YAMLError:
        sys.exit("config/capture-exceptions.yml is not valid YAML — fix it before adding")
    if any((e or {}).get("match") == match for e in (doc.get("exceptions") or [])):
        print("  = capture-exception match=%r already present" % match)
        return False
    last_block = start                                       # insert after the last entry line
    for i in range(start + 1, len(lines)):
        if lines[i].strip() and not lines[i].startswith((" ", "\t")):   # dedented -> block ended
            break
        if lines[i].strip():
            last_block = i
    entry_obj = [{"subject": subject, "match": match, "behavior": behavior,
                  "disposition": disposition, "observed": observed, "source": source}]
    dumped = yaml.safe_dump(entry_obj, sort_keys=False, allow_unicode=True, width=4096)
    entry = ["  " + ln for ln in dumped.rstrip("\n").splitlines()]      # indent the item under exceptions:
    lines[last_block + 1:last_block + 1] = entry
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("  + added capture-exception %r to config/capture-exceptions.yml" % match)
    return True
