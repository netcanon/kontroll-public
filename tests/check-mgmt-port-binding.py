#!/usr/bin/env python3
"""Assert every PUBLISHED docker compose port in docker/services/ binds the management IP
(``${KONTROLL_MGMT_IP}``) — never a literal IP, bare host, or 0.0.0.0 — EXCEPT the two
NPM-fronted UI ports (homepage 3000, semaphore 3001), which are intentionally published on all
interfaces and reached through the operator's reverse proxy.

Why this guards a real failure: the genericization Phase-3 parameterization made the privileged
surfaces (api / onboard-gui / prometheus / grafana / caddy) bind ``${KONTROLL_MGMT_IP}`` so they
listen on the management interface ONLY (SECURITY.md C3). compose ``${KONTROLL_MGMT_IP:?…}`` fails
closed if the var is UNSET, but a future edit could hardcode an IP again, drop the prefix, or add a
new bare privileged port — and the compose-config gate can't catch that (it only WARNS on an
undefined var, then substitutes empty → a silent 0.0.0.0 bind). This static check is the loud
guard. Run by tests/validate.{sh,ps1}; unit-tested via tests/unit/test_mgmt_parameterization.py.
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# A published-port list item: `- "HOST:PORT"` / `"IP:HOST:PORT"` / `"HOST:PORT/proto"`. The quoted
# value must END at a `:<digits>` (optionally `/proto`), which excludes volume binds (…:/path") and
# mode-suffixed mounts (…:${VAR:-ro}") — only real port publishes match.
PORT_RE = re.compile(r'^\s*-\s*"([^"]*:\d+(?:/[a-z]+)?)"')
PARAM = "${KONTROLL_MGMT_IP"                        # the mgmt-only parameterization (compose :? fails closed)
ALLOWED_BARE = {"3000:3000", "3001:3000"}          # NPM-fronted UIs (homepage / semaphore), pre-existing 0.0.0.0


def offending_ports():
    """List of (relpath, lineno, spec) for every published port that is neither ${KONTROLL_MGMT_IP}-bound
    nor a documented NPM-fronted exception. Empty == compliant. Importable for the unit test."""
    out = []
    for f in sorted(glob.glob(os.path.join(ROOT, "docker", "services", "*.yaml"))):
        with open(f, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                m = PORT_RE.match(line)
                if not m:
                    continue
                spec = m.group(1)
                if PARAM in spec or spec in ALLOWED_BARE:
                    continue
                out.append((os.path.relpath(f, ROOT).replace(os.sep, "/"), n, spec))
    return out


def main():
    bad = offending_ports()
    if bad:
        print("non-mgmt-bound published port(s) — must bind ${KONTROLL_MGMT_IP} (SECURITY.md C3):")
        for f, n, spec in bad:
            print("  %s:%d  %s" % (f, n, spec))
        return 1
    print("all published compose ports bind ${KONTROLL_MGMT_IP} (or the NPM-fronted UI exceptions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
