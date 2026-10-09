"""Runtime settings, read from the environment (SOPS-backed at deploy, exactly like the GUI's
GUI_PASSWORD). Read-only routes need none of this; the privileged routes require `api_token` and
are **fail-closed** when it is unset (the surface is disabled, never open).
"""
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Settings:
    """API runtime config. `api_token` None ⇒ privileged routes are disabled (503). `ratelimit` is the
    raw KONTROLL_API_RATELIMIT policy string (None ⇒ built-in defaults; "off" ⇒ disabled) — NOT a secret;
    parsed in api/ratelimit.py."""
    api_token: Optional[str]
    audit_log: str
    ratelimit: Optional[str] = None


def _default_audit_log() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(root, "local", "api-audit.log")   # local/ is gitignored


def from_env() -> Settings:
    """Build Settings from the environment: KONTROLL_API_TOKEN (privileged Bearer token; unset ⇒
    privileged surface disabled), KONTROLL_API_AUDIT_LOG (the append-only TSV audit path), and
    KONTROLL_API_RATELIMIT (the rate-limit policy; unset ⇒ built-in defaults, "off" ⇒ disabled).

    FAIL-CLOSED COUPLING (C10): an armed (token-bearing) network service MUST stage. A token set WITHOUT
    KONTROLL_STAGE_PUSHES would let every token-authed write push `main` directly (gitio._push_target),
    silently collapsing the propose-then-promote invariant. deploy-stack renders BOTH under `api_privileged`;
    this guards a hand-edited / partial-deploy divergence by REFUSING to start a direct-main-writing surface."""
    token = os.environ.get("KONTROLL_API_TOKEN") or None
    if token and not os.environ.get("KONTROLL_STAGE_PUSHES"):
        raise RuntimeError(
            "KONTROLL_API_TOKEN is set but KONTROLL_STAGE_PUSHES is not — an armed API must propose-then-promote "
            "(C10). Refusing to start a direct-main-writing surface; deploy with api_privileged (it sets both).")
    return Settings(
        api_token=token,
        audit_log=os.environ.get("KONTROLL_API_AUDIT_LOG", _default_audit_log()),
        ratelimit=os.environ.get("KONTROLL_API_RATELIMIT") or None,
    )
