"""Fail-closed audit-rotation knob parsing (V1 must-fix M-5).

The storage paradigm's no-empty=infinite rule must hold in CODE, not just the .env layer: an audit-log
RotatingFileHandler sized from an env var must NEVER silently become maxBytes=0 / backupCount=0 (= no rotation =
an unbounded C12 audit file). This pins `envguard.positive_int` (the shared clamp) and that BOTH privileged audit
surfaces (api/audit.py, gui/app.py) actually route their rotation knobs through it.
"""
import os

import pytest

from kontroll.envguard import positive_int

pytestmark = pytest.mark.unit

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.mark.parametrize("raw, expect", [
    ("10", 10), ("1", 1), ("  7  ", 7),           # valid -> the value (surrounding whitespace tolerated)
    (None, 5), ("", 5), ("abc", 5), ("5.5", 5),   # unset / empty / non-numeric -> the safe default
    ("0", 5), ("-3", 5),                            # below the minimum (1) -> default; NEVER 0 / negative
])
def test_positive_int_is_fail_closed(monkeypatch, raw, expect):
    """positive_int clamps unset/empty/non-numeric/below-minimum to the safe default and NEVER returns 0 or a
    negative — so a rotation size/count can't collapse to 'no rotation' (an unbounded audit file)."""
    if raw is None:
        monkeypatch.delenv("KT_TEST_ROT", raising=False)
    else:
        monkeypatch.setenv("KT_TEST_ROT", raw)
    assert positive_int("KT_TEST_ROT", 5) == expect


def test_default_is_returned_and_is_usable_for_garbage():
    """A garbage/unset value returns the (>= minimum) default, so the result is always a usable positive
    rotation — never something a RotatingFileHandler reads as 'do not rotate'."""
    assert positive_int("KT_DOES_NOT_EXIST_ANYWHERE", 5) >= 1


def test_both_audit_surfaces_route_rotation_through_the_clamp():
    """api/audit.py AND gui/app.py size their audit-log rotation via positive_int(KONTROLL_AUDIT_MAX_MB/_FILES)
    — a regression to a bare int(os.environ[...]) (throws on garbage) or a hardcode (un-tunable) would reopen
    the M-5 fail-open. Source-pinned (no import side effects)."""
    for rel in ("api/audit.py", "gui/app.py"):
        with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
            src = fh.read()
        assert "positive_int(" in src and "KONTROLL_AUDIT_MAX_MB" in src, \
            "%s must size its audit rotation via the fail-closed positive_int clamp" % rel
