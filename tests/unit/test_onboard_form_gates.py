"""Two onboard-form UX gates (operator request, 2026-06-19):
  (1) the 'also push origin (offsite backup)' checkbox shows ONLY when an OFFSITE git remote exists — hidden on a
      fresh node, where `git push origin` would just no-op/fail and the box only confuses;
  (2) the form collapses only while PRISTINE — a peek can be dismissed, but entered text / ticked boxes are never
      silently dropped (the toggle disables itself when the form holds input).

`gitio.offsite_remote_exists` is the server predicate (passed to the template as `has_remote`); the template
wires both gates client-side. The live click behaviour is exercised by e2e (test_onboard_flow.py); here we pin
the server predicate and the template wiring hermetically.
"""
import os
import subprocess

import pytest

from kontroll import gitio

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_offsite_remote_exists_distinguishes_local_from_offsite(tmp_path, monkeypatch):
    """No origin -> False; a local `file://` canonical -> False (not an offsite backup); a real https/ssh remote
    -> True. This is the predicate that hides the push checkbox on a fresh node."""
    monkeypatch.setattr(gitio.paths, "ROOT", str(tmp_path))
    subprocess.run(["git", "init", "-q"], cwd=str(tmp_path), check=True)
    assert gitio.offsite_remote_exists() is False                                              # no origin
    subprocess.run(["git", "remote", "add", "origin", "file:///srv/kontroll.git"],
                   cwd=str(tmp_path), check=True)
    assert gitio.offsite_remote_exists() is False                                              # local file:// canonical
    subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/acme/x.git"],
                   cwd=str(tmp_path), check=True)
    assert gitio.offsite_remote_exists() is True                                               # real offsite target


def test_onboard_form_template_wires_both_gates():
    """The template embeds the server flag, gates the push checkbox on it, defines the collapse predicate +
    disables the toggle while dirty, and guards the now-optional push box in the submit body."""
    html = open(os.path.join(ROOT, "gui", "templates", "index.html"), encoding="utf-8").read()
    assert "const HAS_REMOTE = {{" in html                                  # server flag embedded into the page
    assert "HAS_REMOTE ? '<label" in html and "field-push" in html          # push checkbox rendered only inside it
    assert "function onbPristine" in html                                   # collapse-gate predicate
    assert "btn.disabled = open && !onbPristine" in html                    # toggle disabled while the form is dirty
    assert "push:(g('push') ? g('push').checked : false)" in html           # submit guards the now-optional box
