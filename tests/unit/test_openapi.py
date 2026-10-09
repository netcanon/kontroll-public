"""OpenAPI ingester heuristics — derive_auth / derive_server / classify_endpoints.

The honest-limits surface (docs/capability-matrix.md §5.2): endpoint->capability is
heuristic and the emitted recipe is STAGED. These tests pin the heuristics so a
change is deliberate. Auth derivation must emit VAR NAMES (wired to SOPS), never
values — asserted here as a security-relevant property.
"""
import pytest

import galaxy

pytestmark = pytest.mark.unit


# --- derive_auth: securityScheme -> auth block (names only) ------------------ #
def test_auth_bearer_openapi3():
    """An OpenAPI-3 http/bearer scheme derives a bearer auth block with a *_api_token VAR name."""
    spec = {"components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}}}
    auth = galaxy.derive_auth(spec, "acme")
    assert auth == {"type": "bearer", "token_var": "acme_api_token"}


def test_auth_apikey_header():
    """An apiKey-in-header scheme derives apikey_header auth, carrying the header NAME + a token var."""
    spec = {"components": {"securitySchemes":
                           {"k": {"type": "apiKey", "in": "header", "name": "X-Auth"}}}}
    auth = galaxy.derive_auth(spec, "acme")
    assert auth["type"] == "apikey_header"
    assert auth["header_name"] == "X-Auth"
    assert auth["token_var"] == "acme_api_token"


def test_auth_basic_emits_user_and_pass_vars():
    """A Swagger-2 basic scheme derives basic auth with separate username/password VAR names."""
    spec = {"securityDefinitions": {"b": {"type": "basic"}}}     # Swagger 2 shape
    auth = galaxy.derive_auth(spec, "acme")
    assert auth["type"] == "basic"
    assert auth["username_var"] == "acme_username"
    assert auth["password_var"] == "acme_password"


def test_auth_defaults_bearer_with_unverified_flag():
    """No securityScheme -> a bearer guess, flagged `_unverified` so the operator knows to verify."""
    auth = galaxy.derive_auth({}, "acme")
    assert auth["type"] == "bearer"
    assert "_unverified" in auth            # honestly flags the guess for the operator


def test_auth_emits_only_reference_names():
    """An auth block may carry only a fixed set of keys, and every credential field
    is a *_var/*_token NAME (wired to SOPS) — never a literal secret value."""
    allowed = {"type", "token_var", "username_var", "password_var", "header_name", "_unverified"}
    for spec in ({"components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}}},
                 {"securityDefinitions": {"b": {"type": "basic"}}},
                 {}):
        auth = galaxy.derive_auth(spec, "acme")
        assert set(auth) <= allowed
        for field in ("token_var", "username_var", "password_var"):
            if field in auth:
                assert auth[field].startswith("acme") and field.endswith("_var")


# --- derive_server: -> (port, base_path) ------------------------------------- #
def test_server_openapi3_explicit_port_and_base():
    """An OpenAPI-3 servers[].url with an explicit port + path yields (that port, that base path)."""
    port, base = galaxy.derive_server({"servers": [{"url": "https://fw.local:8443/api/v2"}]})
    assert (port, base) == (8443, "/api/v2")


def test_server_openapi3_default_https_port():
    """An https servers[].url with no explicit port defaults to 443, keeping the base path."""
    port, base = galaxy.derive_server({"servers": [{"url": "https://fw.local/api"}]})
    assert (port, base) == (443, "/api")


def test_server_swagger2_host_basepath():
    """Swagger-2 host:port + basePath + schemes derive the port and base path (the v2 fallback)."""
    port, base = galaxy.derive_server({"host": "fw.local:10443", "basePath": "/restapi",
                                       "schemes": ["https"]})
    assert (port, base) == (10443, "/restapi")


def test_server_empty_defaults():
    """A spec with no server info defaults to (443, "") rather than crashing."""
    assert galaxy.derive_server({}) == (443, "")


# --- classify_endpoints: paths -> backup/check/actuate ----------------------- #
def test_endpoints_backup_check_and_actuate():
    """A spec with a backup GET, a status GET, and a write POST yields a backup endpoint, a check
    endpoint, and actuate=True — the three capabilities derived together."""
    spec = {"paths": {
        "/api/v2/config/backup": {"get": {}},
        "/api/v2/monitor/status": {"get": {}},
        "/api/v2/cmdb/firewall/policy": {"post": {}},      # a write -> actuate
    }}
    backup, check, actuate = galaxy.classify_endpoints(spec, "")
    assert backup["method"] == "GET" and backup["path"].endswith("/backup")
    assert check["path"].endswith("/status")
    assert actuate is True


def test_endpoints_check_regex_overlaps_system_in_backup_path():
    """KNOWN heuristic quirk (recipe is STAGED, verify before trusting): the check
    regex matches `/system` even when it appears INSIDE a backup path, so a
    /.../system/.../backup endpoint is also picked as the liveness check. Pinned so
    any change to the heuristic is deliberate, not accidental."""
    spec = {"paths": {"/api/v2/monitor/system/config/backup": {"get": {}}}}
    backup, check, _actuate = galaxy.classify_endpoints(spec, "")
    assert backup["path"].endswith("/backup")
    assert check is not None and check["path"] == backup["path"]   # overlap: same URL


def test_endpoints_readonly_no_actuate():
    """A read-only spec (a health GET, no writes) yields actuate=False and no backup endpoint —
    the heuristic doesn't invent actuation/backup where none exists."""
    spec = {"paths": {"/health": {"get": {}}}}
    backup, check, actuate = galaxy.classify_endpoints(spec, "")
    assert actuate is False
    assert backup is None                      # nothing backup-shaped matched
    assert check["path"] == "/health"


def test_endpoints_prefers_get_over_post_for_backup():
    """When both a POST and a GET could serve as backup, GET wins (the safe read) even if the
    POST appears first in the spec."""
    spec = {"paths": {
        "/export": {"post": {}},
        "/backup": {"get": {}},
    }}
    backup, _check, _actuate = galaxy.classify_endpoints(spec, "")
    assert backup["method"] == "GET"           # GET preferred even though POST seen first
