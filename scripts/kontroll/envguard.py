"""Fail-closed env-knob parsing — shared by the privileged surfaces that size a SECURITY audit log from an env.

The storage paradigm's hard rule (no empty=infinite) must hold in CODE too, not just the .env layer: a
RotatingFileHandler/rotation sized from an env var must NEVER silently fall to maxBytes=0 / backupCount=0 (= NO
rotation = an unbounded audit file, a C12 fail-open). So a rotation knob read from the environment goes through
positive_int(), which clamps an empty / unset / non-numeric / below-minimum value to the safe default — it can
never return 0 or negative for a size/count. (V1 must-fix M-5.)
"""
import os


def positive_int(name, default, minimum=1):
    """Read env var `name` as a positive int, FAIL-CLOSED. Returns `default` when the value is unset, empty,
    non-numeric, or below `minimum` — so a rotation size/count can never become 0 (no rotation = unbounded file).
    `default` must itself be >= `minimum` (a programming error otherwise)."""
    raw = os.environ.get(name)
    try:
        val = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return val if val >= minimum else default
