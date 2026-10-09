"""The frontend-exposure mode resolver (scripts/kontroll/frontend.py) — the per-instance TLS dispatch seam.

Pins the mapping deploy-stack relies on: byo_proxy/acme serve HTTP behind a trusted proxy (and trust
X-Forwarded-* so the rate-limiter keys off the real client IP) while self_signed terminates TLS in uvicorn,
and an unknown/empty mode fails SAFE to self_signed (a typo must never silently serve plaintext).
"""
import pytest

from kontroll.frontend import (DEFAULT_TLS_MODE, backends_for, normalize_mode, provisions_self_signed_cert,
                               render_caddyfile, runs_caddy, uvicorn_extra_args)

pytestmark = pytest.mark.unit


def test_byo_proxy_serves_http_and_trusts_proxy():
    """byo_proxy yields no --ssl-* (HTTP) + --forwarded-allow-ips and provisions no cert — guards that
    mode A serves plaintext for the operator's reverse proxy and the rate-limiter keys off the real
    client IP, not the proxy hop."""
    args = uvicorn_extra_args("byo_proxy")
    assert "--ssl-keyfile" not in args and "--forwarded-allow-ips=*" in args
    assert provisions_self_signed_cert("byo_proxy") is False


def test_self_signed_terminates_tls_in_uvicorn():
    """self_signed yields the --ssl-keyfile/--ssl-certfile pair at the host cert and DOES provision it —
    guards that the zero-config HTTPS default (today's behaviour) stays intact."""
    args = uvicorn_extra_args("self_signed")
    assert "--ssl-keyfile /tls/api.key" in args and "--ssl-certfile /tls/api.crt" in args
    assert provisions_self_signed_cert("self_signed") is True


def test_acme_serves_http_no_cert():
    """acme (Caddy fronts TLS) serves HTTP + trusts the proxy and provisions no per-service cert — guards
    that the planned ACME mode does not double-terminate TLS."""
    assert uvicorn_extra_args("acme") == "--forwarded-allow-ips=*"
    assert provisions_self_signed_cert("acme") is False


@pytest.mark.parametrize("bad", ["", None, "  ", "https", "byoproxy", "selfsigned"])
def test_unknown_mode_fails_safe_to_self_signed(bad):
    """Any unrecognised/empty mode normalizes to self_signed (HTTPS) — guards the fail-safe: a typo in
    instance.yml must never silently drop the API to plaintext."""
    assert normalize_mode(bad) == DEFAULT_TLS_MODE == "self_signed"
    assert "--ssl-keyfile" in uvicorn_extra_args(bad)


def test_mode_is_case_and_whitespace_insensitive():
    """Mixed case / surrounding whitespace still resolves — guards trivial instance.yml formatting
    differences from silently falling back to the default."""
    assert normalize_mode("  BYO_Proxy ") == "byo_proxy"


# --- Caddy ingress (acme mode) --------------------------------------------- #
def test_runs_caddy_only_for_acme():
    """runs_caddy is True only for acme (the bundled Caddy ingress); byo_proxy + self_signed run no Caddy
    — guards that we don't spin up an ingress for the operator's-own-proxy or the uvicorn-TLS case, and
    that the fail-safe default (self_signed) runs none."""
    assert runs_caddy("acme") is True
    assert runs_caddy("byo_proxy") is False and runs_caddy("self_signed") is False
    assert runs_caddy("") is False


def test_backends_for_filters_to_known_http_services():
    """backends_for keeps only Caddy-frontable services from stack_services, in CADDY_BACKENDS order, and
    drops unknown / own-TLS ones (e.g. onboard-gui) — guards the 'add a service = one map entry' contract
    and that a service is fronted only when actually deployed."""
    assert backends_for(["semaphore", "api", "onboard-gui", "nope"]) == \
        [("api", "api:8444"), ("semaphore", "semaphore:3000")]


def test_render_caddyfile_acme_sites_and_dns_from_env():
    """render_caddyfile emits one <sub>.<domain> site per service reverse-proxied to its HTTP backend, a
    global email + a DNS-01 acme_dns line sourcing the token from the ENV (never inline) — guards the acme
    contract and that the DNS token is never written into the committed Caddyfile (SECURITY C1)."""
    out = render_caddyfile("example.com", backends_for(["api", "grafana"]),
                           email="ops@example.com", dns_provider="cloudflare")
    assert "api.example.com {" in out and "reverse_proxy api:8444" in out
    assert "grafana.example.com {" in out and "reverse_proxy grafana:3000" in out
    assert "email ops@example.com" in out
    assert "acme_dns cloudflare {env.KONTROLL_ACME_DNS_TOKEN}" in out


def test_render_caddyfile_staging_uses_le_staging_ca():
    """staging=True points Caddy at Let's Encrypt's staging CA — guards a way to exercise issuance without
    burning the production LE rate limit."""
    assert "acme-staging-v02.api.letsencrypt.org" in render_caddyfile(
        "example.com", backends_for(["api"]), staging=True)
