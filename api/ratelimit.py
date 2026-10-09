"""In-process rate limiting for the kontroll API — ws6 hardening (docs/api-architecture.md §9 item 6).

One config-driven ASGI middleware is the WHOLE feature: no per-route decorators, no edits to the eight
route files (the "no god files / drop-in" doctrine). Two policy classes by request path:

  - inquiry    (GET /search, /probe/{c}, /classify/{c})  -> keyed per client IP
  - privileged (POST /refresh, /capture-exceptions, /onboard; GET /audit/log) -> keyed per token DIGEST

Meta/liveness paths (/health, /openapi.json, /docs, /redoc) are EXEMPT — a probe or the API's own spec
tooling must never 429.

Store: a fixed-window counter in process memory (justified: one uvicorn container today —
docker/services/api.yaml; the store is an injected seam, so a future multi-replica deploy swaps it for a
shared backend without touching the callers — SECURITY.md C9 accepted-risk).

Fail policy — deliberately the OPPOSITE of auth/audit, and SCOPED so the security invariant holds:
  * a clean breach (limit reached) is ENFORCED -> 429 returned BEFORE require_token / the route run, so a
    flood cannot force expensive probe I/O or spam the fail-closed mutation audit;
  * the limiter FAILS OPEN only on its OWN internal malfunction (a limiter bug) -> it logs and lets the
    request through to require_token / audit_action, which stay FULLY fail-closed. No path lets rate
    limiting admit an unauthenticated or unaudited mutation. Operator-ratified 2026-06-13
    (docs/reviews/2026-06-13-roadmap/01-design-2a-rate-limiting.md §9 Q4).

A breach writes ONE best-effort `rate-limited` audit line (never fail-closed — an availability event must
not turn an unwritable disk into a 503), throttled to one line per key per window, carrying path + class
(+ a non-reversible token digest for privileged) and NEVER a credential (SECURITY.md C9).

Limits are code defaults, overridable at deploy via KONTROLL_API_RATELIMIT (NOT a secret) with a global
`off` switch — e.g. "inquiry=30/min;privileged=10/min" or "off". Defense-in-depth against a runaway
client on the mgmt VLAN, not a public-abuse control; the surface stays mgmt-only, never WAN (C3).
"""
import hashlib
import logging
import os
import threading
import time
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from api.audit import mint_run_id, write_audit

log = logging.getLogger("kontroll.api.ratelimit")

# --- policy (data; overridable via KONTROLL_API_RATELIMIT) --------------------------------------- #
# (max_requests, window_seconds) per class. Generous for a human operator + a polling widget, tight
# enough to stop a runaway loop. The shipped values are pinned by tests/integration/test_api_ratelimit.py
# (no hard-coded numbers in PROSE docs — CLAUDE.md; these live in code that a test asserts).
_DEFAULTS = {"inquiry": (30, 60), "privileged": (10, 60)}
_EXEMPT = ("/health", "/openapi.json", "/docs", "/redoc")
_PRIVILEGED = ("/refresh", "/capture-exceptions", "/onboard", "/capability", "/secrets", "/actuation", "/audit")
_UNITS = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hour": 3600}

# Per-process random salt so the token digest is non-reversible and not cross-process correlatable; the
# window only needs the digest stable WITHIN a process (the store is in-process anyway).
_SALT = os.urandom(16)


def _clock() -> float:
    """The wall clock the store reads. A module-level seam so tests can freeze/advance it (patch
    `api.ratelimit._clock`) without sleeping."""
    return time.time()


def _classify(path: str) -> Optional[str]:
    """Map a request path to its policy class: None (exempt), 'privileged', or 'inquiry'. Privileged is
    matched by the known route prefixes — every privileged route is tags=['privileged'], asserted by a
    test so a new one cannot silently bypass the budget."""
    if any(path == e or path.startswith(e) for e in _EXEMPT):
        return None
    if any(path == p or path.startswith(p) for p in _PRIVILEGED):
        return "privileged"
    return "inquiry"


def _parse_policy(raw: Optional[str]) -> dict:
    """Parse KONTROLL_API_RATELIMIT into {'inquiry': (n,w)|None, 'privileged': (n,w)|None, 'disabled': bool}.
    None/empty -> built-in defaults; 'off' -> globally disabled; 'class=off' -> that class unlimited;
    'class=N/unit' -> override. Unknown tokens are ignored (a bad knob must never crash the API)."""
    policy = {"inquiry": _DEFAULTS["inquiry"], "privileged": _DEFAULTS["privileged"], "disabled": False}
    if not raw:
        return policy
    raw = raw.strip()
    if raw.lower() in ("off", "disabled", "none"):
        policy["disabled"] = True
        return policy
    for part in raw.split(";"):
        cls, _, spec = part.strip().partition("=")
        cls, spec = cls.strip().lower(), spec.strip().lower()
        if cls not in ("inquiry", "privileged"):
            continue
        if spec in ("off", "0", "none", ""):
            policy[cls] = None                     # this class unlimited
            continue
        num, _, unit = spec.partition("/")
        try:
            n, w = int(num), _UNITS.get(unit.strip(), 60)
        except ValueError:
            continue
        if n > 0:
            policy[cls] = (n, w)
    return policy


def _bearer_token(request: Request) -> Optional[str]:
    """The presented Bearer token, or None — parsed from the Authorization header WITHOUT validating it
    (validation is require_token's job; here it is only keying material)."""
    h = request.headers.get("Authorization", "")
    if h[:7].lower() == "bearer ":
        return h[7:].strip() or None
    return None


def _digest(token: str) -> str:
    """A non-reversible, salted SHA-256 prefix of the token — safe to key on and to put in an audit
    `detail`; the raw token NEVER leaves require_token's constant-time compare (SECURITY.md C9)."""
    return hashlib.sha256(_SALT + token.encode("utf-8")).hexdigest()[:16]


def _client_ip(request: Request) -> str:
    """The caller's IP for keying — X-Forwarded-For (when fronted by an operator-controlled proxy on the
    mgmt VLAN) else the socket peer. Mirrors api.auth._client_ip (kept local to avoid coupling the
    limiter to the auth module)."""
    return request.headers.get("X-Forwarded-For", request.client.host if request.client else "-")


class _FixedWindowStore:
    """A tiny fixed-window counter: key -> [expiry_epoch, count], guarded by a lock, with lazy eviction
    of expired buckets so memory stays bounded under a spoofed-key flood. In-process only."""

    _SWEEP_AT = 2048                               # sweep expired buckets when the map grows past this

    def __init__(self):
        self._buckets: dict = {}
        self._lock = threading.Lock()

    def hit(self, key: str, max_requests: int, window_seconds: int):
        """Count one request against `key`. Returns (allowed, retry_after_s, limit, remaining)."""
        now = _clock()
        with self._lock:
            if len(self._buckets) > self._SWEEP_AT:
                self._buckets = {k: b for k, b in self._buckets.items() if b[0] > now}
            bucket = self._buckets.get(key)
            if bucket is None or now >= bucket[0]:
                bucket = [now + window_seconds, 0]
                self._buckets[key] = bucket
            bucket[1] += 1
            expiry, count = bucket[0], bucket[1]
        allowed = count <= max_requests
        remaining = max(0, max_requests - count)
        retry_after = (int(expiry - now) + 1) if not allowed else 0
        return allowed, retry_after, max_requests, remaining


class RateLimitMiddleware(BaseHTTPMiddleware):
    """The single attach-point: added once in create_app(); throttles by request path-class. See the
    module docstring for the policy + fail-open rationale."""

    def __init__(self, app, settings=None):
        super().__init__(app)
        self._policy = _parse_policy(getattr(settings, "ratelimit", None))
        self._store = _FixedWindowStore()
        self._audit_store = _FixedWindowStore()    # throttles the breach audit (1 line / key / window)

    async def dispatch(self, request: Request, call_next):
        cls = _classify(request.url.path)
        limit_spec = None if cls is None else self._policy.get(cls)
        if cls is None or self._policy.get("disabled") or limit_spec is None:
            return await call_next(request)        # exempt / globally off / class unlimited
        try:
            max_req, window = limit_spec
            key = self._key(request, cls)
            allowed, retry_after, limit, remaining = self._store.hit(key, max_req, window)
        except Exception:                          # FAIL OPEN on the limiter's OWN malfunction only
            log.exception("rate limiter failed open (path=%s) — passing through to fail-closed auth",
                          request.url.path)
            return await call_next(request)
        if allowed:
            resp = await call_next(request)
            resp.headers["X-RateLimit-Limit"] = str(limit)
            resp.headers["X-RateLimit-Remaining"] = str(remaining)
            return resp
        self._audit_breach(request, cls, key, window)
        return JSONResponse(
            status_code=429,
            content={"detail": "rate limit exceeded", "retry_after": retry_after},
            headers={"Retry-After": str(retry_after),
                     "X-RateLimit-Limit": str(limit), "X-RateLimit-Remaining": "0"},
        )

    def _key(self, request: Request, cls: str) -> str:
        """Per-IP for inquiry; per-token-digest for privileged (falling back to IP when no token is
        presented, so an unauthenticated flood on a privileged path is still shielded)."""
        if cls == "privileged":
            token = _bearer_token(request)
            if token:
                return "tok:" + _digest(token)
        return "ip:" + _client_ip(request)

    def _audit_breach(self, request: Request, cls: str, key: str, window: int) -> None:
        """Best-effort, throttled (1 line / key / window) `rate-limited` audit — never fail-closed (an
        availability event must not become a 503), never a credential (privileged carries the token
        DIGEST, not the token)."""
        allowed, *_ = self._audit_store.hit("audit:" + key, 1, window)
        if not allowed:
            return                                 # already logged this key's breach this window
        settings = request.app.state.settings
        user = "api-token" if cls == "privileged" else "anonymous"
        detail = "path=%s class=%s" % (request.url.path, cls)
        if cls == "privileged":
            token = _bearer_token(request)
            if token:
                detail += " token=" + _digest(token)
        try:
            write_audit(settings.audit_log, user, _client_ip(request), "rate-limited",
                        mint_run_id(), detail)
        except OSError:
            pass                                   # best-effort: a breach must not escalate to a 503
