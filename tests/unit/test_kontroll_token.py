"""ansible/filter_plugins/kontroll_token.py — the credentialed-logging token composer.

Pins the fail-soft contract the deploy-stack `.env` render depends on: a template str.formatted over a decrypted
SOPS domain dict, returning '' (never raising, never a half-token) when any referenced field is missing/blank.
Guards a credentialed logging method composing a malformed token from a partial/absent domain (which would auth
with garbage instead of failing soft to an empty header) — the data-driven replacement for the old hand-wired
proxmox-shaped `_pve_log_token` composition.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                                "ansible", "filter_plugins"))
from kontroll_token import kontroll_render_token   # noqa: E402

pytestmark = pytest.mark.unit


def test_composes_a_full_token():
    """A template over a complete domain renders the exact token — the PVEAPIToken `user!id=secret` shape comes
    from the descriptor template + the domain values, not hard-coded in the playbook."""
    domain = {"proxmox_api_user": "root@pam", "proxmox_api_token_id": "mon", "proxmox_api_token_secret": "uuid"}
    out = kontroll_render_token("{proxmox_api_user}!{proxmox_api_token_id}={proxmox_api_token_secret}", domain)
    assert out == "root@pam!mon=uuid"


def test_fails_soft_to_empty_on_missing_or_blank_field():
    """A missing field OR a blank field OR an empty template renders '' (never a half-token, never an exception)
    — so an un-onboarded / partially-filled domain auths with an empty header and ships nothing, the prior
    `'' if no secret` behaviour. This is the invariant the .env render relies on to not fail a whole deploy."""
    tmpl = "{a}!{b}={c}"
    assert kontroll_render_token(tmpl, {"a": "x", "b": "y"}) == ""              # missing field c
    assert kontroll_render_token(tmpl, {"a": "x", "b": "", "c": "z"}) == ""     # blank field b
    assert kontroll_render_token(tmpl, {}) == ""                               # empty domain
    assert kontroll_render_token("", {"a": "x"}) == ""                         # empty template
    assert kontroll_render_token(tmpl, None) == ""                            # None domain -> no raise


def test_one_field_template_is_the_degenerate_collapse():
    """A 1-field template `"{field}"` renders the field's value verbatim — the load-bearing collapse that lets a
    telemetry `secret_env_map` entry (PVE_EXPORTER_USER: "{proxmox_api_user}") and an N-field logging token render
    through the SAME filter with NO branch (the unification; docs/reviews/2026-06-17-secret-injection/). A literal
    with no placeholder renders itself (a constant env var). Guards the collapse silently regressing — if this
    broke, every exporter env var rendered through the unified loop would go empty."""
    assert kontroll_render_token("{proxmox_api_user}", {"proxmox_api_user": "root@pam"}) == "root@pam"
    assert kontroll_render_token("literal-no-placeholder", {"x": "v"}) == "literal-no-placeholder"


def test_falsy_field_blanks_the_value_M5():
    """The unified loop's empty-on-absent now comes from THIS filter (FALSY field -> '') instead of a Jinja
    `default('')` (UNDEFINED -> ''). For a real SOPS string token the two agree (a token is a non-empty string),
    but the filter ALSO blanks a present-but-FALSY value (None / 0 / False / ''), where `default('')` would render
    it. Pinned so the falsy contract is DELIBERATE, not an accidental behavioural drift (M5). A truthy string like
    '0' is a real value and is NOT blanked."""
    assert kontroll_render_token("{a}", {"a": ""}) == ""          # blank string -> blank
    assert kontroll_render_token("{a}", {"a": 0}) == ""           # int 0 (falsy) -> blank
    assert kontroll_render_token("{a}", {"a": None}) == ""        # None -> blank
    assert kontroll_render_token("{a}", {"a": "0"}) == "0"        # the STRING "0" is truthy -> a real value
