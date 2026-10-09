"""Ansible filter: compose a secret env value (an exporter cred OR a credentialed-logging token) from a SOPS-domain
dict + a descriptor template.

deploy-stack.yml's `.env` render uses this to turn a method's `secret_env_map` VALUE — a `str.format` template over
its `secret_domain`'s SOPS field NAMES, declared in `telemetry/<m>.yml` OR `logging/<m>.yml` — into the actual env
value, GENERICALLY in ONE loop over the generated unified manifest. The SAME filter renders both a 1-field exporter
env var (`"{proxmox_api_user}"`) and an N-field composed logging token (`"{user}!{id}={secret}"`) — a 1-field map is
the degenerate template — so adding a credentialed exporter/pull needs ZERO playbook edit: the env shape is DATA in
the descriptor, not code here.

FAIL-SOFT (preserves the prior ``'' if no secret`` behaviour): if the template is empty, or ANY field it
references is absent/blank in the decrypted domain dict, the whole token renders EMPTY — the method's source then
auths with an empty header and ships nothing until the operator onboards the domain, rather than emitting a
half-formed token. NEVER raises (the `.env` render must not fail a whole deploy over one unset device cred). The
render task stays `no_log: true`; this filter returns the value but never logs it.
"""
import string


def kontroll_render_token(template, domain):
    """template: a str.format string over SOPS field NAMES, e.g. ``{proxmox_api_user}!{...}={...}``.
    domain:   the decrypted SOPS domain dict (field name -> value); may be empty or missing fields.
    -> the composed token, or '' if the template is empty or any referenced field is missing/blank."""
    if not template:
        return ""
    domain = domain or {}
    try:
        fields = [fn for _lit, fn, _spec, _conv in string.Formatter().parse(template) if fn]
    except Exception:
        return ""
    # fail-soft: any referenced field absent or blank -> empty token (never a half-token).
    for fn in fields:
        if not (domain.get(fn) or ""):
            return ""
    try:
        return template.format(**{fn: domain.get(fn, "") for fn in fields})
    except Exception:
        return ""


class FilterModule(object):
    """Registers `kontroll_render_token` for the deploy-stack `.env` render."""

    def filters(self):
        return {"kontroll_render_token": kontroll_render_token}
