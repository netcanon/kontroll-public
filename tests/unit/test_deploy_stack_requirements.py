"""deploy-stack must SELF-GENERATE the runner's collection lockfile before it builds the runner image, so a fresh
node needs no prior bootstrap.yml run.

WHY (the failure this guards): the live blind-human install (2026-06-19) deployed clean EXCEPT the runner image
build, which COPYs `ansible/collections/requirements.generated.yml` — a GENERATED, gitignored artifact derived
from modules/ + the fleet. On a fresh node it is absent (not in the bundle), so the build failed
`failed to compute cache key: "/ansible/collections/requirements.generated.yml": not found`. deploy-stack
regenerates every OTHER config-as-data artifact right before bringing things up; the lockfile was the one
inconsistent omission. The fix adds the regen task — these pins keep it present AND ordered before the build.
"""
import os

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_deploy_stack_regenerates_requirements_before_runner_build():
    """The regen task (calling the single-source gen-requirements.py) MUST exist and appear textually BEFORE the
    'Build the Semaphore runner image' task — the Dockerfile COPYs the lockfile, so it must exist at build time."""
    src = open(os.path.join(ROOT, "ansible", "playbooks", "deploy-stack.yml"), encoding="utf-8").read()
    regen = src.find("gen-requirements.py")
    build = src.find("Build the Semaphore runner image")
    assert regen != -1, "deploy-stack must regenerate requirements.generated.yml via gen-requirements.py (self-sufficient)"
    assert build != -1, "deploy-stack must build the semaphore runner image"
    assert regen < build, "the lockfile regen MUST precede the runner image build (the Dockerfile COPYs the lockfile)"
