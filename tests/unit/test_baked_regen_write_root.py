"""Phase-B baked-mode capability regen writes to write_root(), never the read-only baked ROOT.

WHY (the failure this guards): when a service runs BAKED (`-e bake_code=true`), service/observe.py + logsvc.py +
backup.py load the config-as-data generator from /opt/kontroll (the baked tree), so `gen.ROOT == paths.ROOT`, the
self-protect guard (`paths.ROOT != gen.ROOT → skip`) PASSES — and `gen.main()` used to write `gen.ROOT/<target>` =
`/opt/kontroll/{prometheus,docker,config}`, which is `chmod -R a-w` READ-ONLY (the Rung-1a bake). So a capability-promote
regen (telemetry / logging / backup) FAILED under baked code. The fix repoints `gen.ROOT` at `paths.write_root()` (the
/propose clone) before `gen.main()`. This was NOT caught by the Rung-2 dogfood (which exercised onboard→promote, not
capability-promote). Found during the Rung-3 closure analysis.
"""
import types

import pytest

from kontroll import paths
from kontroll.service import backup, logsvc, observe

pytestmark = pytest.mark.unit

# (module, regen fn, the per-module generator-loader attr, the regen args) for each config-as-data regenerator.
_REGENS = [
    (observe, "regenerate_observability", "_gen_observability", ("cisco_ios",)),
    (logsvc, "regenerate_logging", "_gen_logging", ("cisco_ios",)),
    (backup, "regenerate_schedules", "_gen_backup", ()),
]


def _fake_gen(seen):
    """A stand-in generator whose ROOT == paths.ROOT (so the self-protect guard PASSES — the production path, not a
    test-skip) and whose main() records gen.ROOT at call time (= where the real generator WOULD read+write)."""
    g = types.SimpleNamespace(ROOT=paths.ROOT, GEN_DIR="docker/vector/generated")
    g.main = lambda argv: seen.update(root=g.ROOT)
    return g


@pytest.mark.parametrize("mod,fn,loader,args", _REGENS, ids=[r[1] for r in _REGENS])
def test_baked_regen_targets_write_root(mod, fn, loader, args, monkeypatch, tmp_path):
    """With KONTROLL_WRITE_ROOT set (a baked deploy), each regen must point the generator at write_root() (the propose
    clone) BEFORE running it — so it regenerates into /propose and never attempts a write to the read-only baked ROOT."""
    clone = str(tmp_path / "propose")
    seen = {}
    monkeypatch.setattr(mod, loader, lambda: _fake_gen(seen))
    monkeypatch.setenv("KONTROLL_WRITE_ROOT", clone)
    getattr(mod, fn)(*args)
    assert seen.get("root") == clone, \
        "%s must run the generator against write_root (the clone), not the read-only baked ROOT" % fn


@pytest.mark.parametrize("mod,fn,loader,args", _REGENS, ids=[r[1] for r in _REGENS])
def test_regen_identity_when_write_root_unset(mod, fn, loader, args, monkeypatch):
    """With KONTROLL_WRITE_ROOT unset, write_root()==ROOT, so the regen runs the generator against ROOT exactly as
    today — the legacy /repo deploy + deploy-stack (which run the generators with ROOT already the writable clone)
    are byte-for-byte unchanged."""
    monkeypatch.delenv("KONTROLL_WRITE_ROOT", raising=False)
    seen = {}
    monkeypatch.setattr(mod, loader, lambda: _fake_gen(seen))
    getattr(mod, fn)(*args)
    assert seen.get("root") == paths.ROOT, \
        "%s identity: write_root()==ROOT, so the generator runs against ROOT (unchanged)" % fn
