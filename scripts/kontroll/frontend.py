"""Frontend exposure mode — the per-instance dispatch seam for HOW kontroll's services are served.

`instance/instance.yml` carries `frontend.tls_mode`; this module maps it to the concrete deploy behaviour
(the uvicorn flags for the API container, and whether a per-service self-signed cert is provisioned).
ansible/playbooks/deploy-stack.yml calls the `__main__` CLI to render those; tests/unit/test_frontend.py
pins the mapping.

Modes (docs/reviews/2026-06-13-roadmap/03-redesign-frontend-exposure.md):
  - byo_proxy   : services serve HTTP; the operator's reverse proxy (e.g. Nginx Proxy Manager) owns TLS.
  - self_signed : services serve HTTPS with a host-provisioned self-signed cert (the zero-config DEFAULT).
  - acme        : (planned) a bundled Caddy ingress terminates TLS via Let's Encrypt — services stay HTTP.
An unknown/empty mode falls back to self_signed (fail-SAFE: a typo never silently serves plaintext).
"""
TLS_MODES = ("byo_proxy", "self_signed", "acme")
DEFAULT_TLS_MODE = "self_signed"

# Container paths of the host-provisioned self-signed material (see docker/services/api.yaml).
_KEY = "/tls/api.key"
_CRT = "/tls/api.crt"


def normalize_mode(mode):
    """Return a known tls_mode, or DEFAULT_TLS_MODE for anything unrecognised/empty — so a typo in
    instance.yml fails SAFE to self-signed HTTPS rather than silently serving plaintext."""
    m = (mode or "").strip().lower()
    return m if m in TLS_MODES else DEFAULT_TLS_MODE


def uvicorn_extra_args(mode):
    """The extra uvicorn flags the API container runs in this mode. self_signed -> terminate TLS in
    uvicorn from the host cert; byo_proxy/acme -> serve HTTP and trust the fronting proxy's
    X-Forwarded-* (so the rate-limiter keys off the real client IP, not the proxy hop)."""
    if normalize_mode(mode) == "self_signed":
        return "--ssl-keyfile %s --ssl-certfile %s" % (_KEY, _CRT)
    return "--forwarded-allow-ips=*"


def provisions_self_signed_cert(mode):
    """True iff this mode needs deploy-stack to generate the per-service self-signed cert (self_signed
    only). byo_proxy/acme terminate TLS at the edge, so kontroll provisions no cert."""
    return normalize_mode(mode) == "self_signed"


def runs_caddy(mode):
    """True iff this mode brings up the bundled Caddy ingress (acme only). byo_proxy uses the operator's
    own reverse proxy; self_signed uses per-service uvicorn TLS (IP-friendly, no hostnames needed)."""
    return normalize_mode(mode) == "acme"


# Known kontroll services Caddy can front, mapped to (subdomain, HTTP backend on the kontroll network).
# Each app serves plain HTTP internally in acme mode; Caddy terminates TLS at <subdomain>.<domain>.
# Adding a service = one entry here (the "add an X" test) — it's only fronted when it's in stack_services.
CADDY_BACKENDS = {
    "api": ("api", "api:8444"),
    "semaphore": ("semaphore", "semaphore:3000"),
    "homepage": ("home", "homepage:3000"),
    "grafana": ("grafana", "grafana:3000"),
    "prometheus": ("prometheus", "prometheus:9090"),
}


def render_caddyfile(domain, services, *, email="", dns_provider="", staging=False):
    """Render a Caddyfile (text) for acme mode: one site per service at <sub>.<domain>, each reverse-
    proxied to its HTTP backend; Caddy obtains + auto-renews Let's Encrypt certs. Because kontroll is
    never WAN-exposed, the global block configures the DNS-01 challenge (the operator's provider + an
    env-sourced token) — the Caddy IMAGE must carry that provider's caddy-dns module (see
    docs/frontend-exposure.md). `staging` points at LE's staging CA (avoid rate limits while testing).
    `services`: iterable of (subdomain, backend_host:port) — typically derived from CADDY_BACKENDS."""
    glob = ["{"]
    if email:
        glob.append("\temail %s" % email)
    if staging:
        glob.append("\tacme_ca https://acme-staging-v02.api.letsencrypt.org/directory")
    if dns_provider:
        # DNS-01: the token comes from the environment (SOPS-rendered), never the committed Caddyfile.
        glob.append("\tacme_dns %s {env.KONTROLL_ACME_DNS_TOKEN}" % dns_provider)
    glob.append("}")
    blocks = ["\n".join(glob)]
    for sub, backend in services:
        host = ("%s.%s" % (sub, domain)) if sub else domain
        blocks.append("%s {\n\treverse_proxy %s\n}" % (host, backend))
    return "\n\n".join(blocks) + "\n"


def backends_for(service_keys):
    """The (subdomain, backend) pairs for the given stack_services keys that Caddy knows how to front,
    preserving the CADDY_BACKENDS order. Unknown/un-frontable services (e.g. onboard-gui, which serves
    its own TLS) are silently skipped — they are simply not behind Caddy."""
    return [CADDY_BACKENDS[k] for k in CADDY_BACKENDS if k in set(service_keys)]


def main(argv):
    """CLI for deploy-stack. Mode query: `frontend.py {mode|uvicorn-extra|needs-cert|runs-caddy} <tls_mode>`.
    Caddyfile render: `frontend.py caddyfile <domain> <email> <dns_provider> <services_csv> [staging]`."""
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "caddyfile":
        domain = argv[2] if len(argv) > 2 else ""
        email = argv[3] if len(argv) > 3 else ""
        provider = argv[4] if len(argv) > 4 else ""
        svc_csv = argv[5] if len(argv) > 5 else ""
        staging = len(argv) > 6 and argv[6] == "staging"
        keys = [s.strip() for s in svc_csv.split(",") if s.strip()]
        return render_caddyfile(domain, backends_for(keys), email=email, dns_provider=provider,
                                staging=staging)
    raw = argv[2] if len(argv) > 2 else ""
    if cmd == "mode":
        return normalize_mode(raw)
    if cmd == "uvicorn-extra":
        return uvicorn_extra_args(raw)
    if cmd == "needs-cert":
        return "yes" if provisions_self_signed_cert(raw) else "no"
    if cmd == "runs-caddy":
        return "yes" if runs_caddy(raw) else "no"
    raise SystemExit("usage: frontend.py {mode|uvicorn-extra|needs-cert|runs-caddy|caddyfile} ...")


if __name__ == "__main__":
    import sys
    print(main(sys.argv))
