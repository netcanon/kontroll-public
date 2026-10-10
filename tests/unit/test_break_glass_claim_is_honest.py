"""SECURITY.md's break-glass claim must match the number of age recipients actually shipped.

C1-FALSE (2026-07-28 fleet-restore review). `SECURITY.md` C1 stated:

    "every secret is encrypted to **two** age recipients — the control-VM operational key and an offline
     break-glass recovery key ... losing the VM key is recoverable, not catastrophic"

and the accepted-risks table repeated it ("Mitigated: every secret is encrypted to an offline break-glass
second recipient"). Both were false. Every `key_groups` in the SHIPPED `instance.example/.sops.yaml` names
exactly ONE recipient, so no instance ever created from it had a break-glass key — verified additionally on
both live boxes, each naming only its own control key.

Why this is the worst kind of documentation bug: a security document claiming a control that does not exist
is more dangerous than one admitting the gap, because decisions get made on it. This specific claim is what a
"reclaim the old box" decision would rest on — "losing the VM key is recoverable" is precisely the sentence
that makes destroying the only holder of a key sound safe. It isn't; it is irreversible loss of every device
credential in the instance.

The test is deliberately BIDIRECTIONAL. Asserting only "the doc admits the gap" would go stale the moment
break-glass is actually implemented, leaving a doc that understates its own security. So: the recipient count
in the shipped template decides which claim the doc is required to make.
"""
import os
import re

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TEMPLATE = os.path.join(_ROOT, "instance.example", ".sops.yaml")
_SECURITY = os.path.join(_ROOT, "SECURITY.md")


def _recipients_per_domain():
    """{path_regex: recipient count} for the shipped scaffold template."""
    doc = yaml.safe_load(open(_TEMPLATE, encoding="utf-8"))
    out = {}
    for rule in doc["creation_rules"]:
        groups = rule.get("key_groups") or []
        out[rule["path_regex"]] = sum(len(g.get("age") or []) for g in groups)
    return out


def _security_text():
    return open(_SECURITY, encoding="utf-8").read()


def test_the_template_recipient_count_is_visible_at_all():
    """Guard the guard: if the template stops parsing or loses key_groups, every other assertion here would
    vacuously pass."""
    counts = _recipients_per_domain()
    assert counts, "no creation_rules parsed from the shipped .sops.yaml — the rest of this file proves nothing"
    assert all(n >= 1 for n in counts.values()), \
        "a domain with ZERO recipients would be unencryptable: %r" % counts


def test_the_doc_claim_matches_the_shipped_recipient_count():
    """THE BIDIRECTIONAL CHECK. Single-recipient reality requires the doc to say break-glass is not
    implemented; multi-recipient reality requires it to stop saying so."""
    counts = _recipients_per_domain()
    single = {k: n for k, n in counts.items() if n < 2}
    text = _security_text()

    if single:
        assert "NOT IMPLEMENTED" in text, (
            "%d domain(s) in the shipped template have a single age recipient, so there is no break-glass "
            "key — SECURITY.md C1 must say so plainly: %s" % (len(single), sorted(single))
        )
        assert "R-KEY-1" in text, "the gap must carry an accepted-risk id so it is trackable, not just prose"
        assert not re.search(r"encrypted to \*\*two\*\* age recipients", text), \
            "the old false claim must not survive anywhere in the document"
        assert not re.search(r"encrypted to an offline \*\*break-glass\*\* second recipient", text), \
            "the accepted-risks table repeated the same false claim — it must be corrected too"
    else:
        assert "NOT IMPLEMENTED" not in text, (
            "every shipped domain now has 2+ recipients, so break-glass IS implemented — C1 must be updated "
            "to claim it, and R-KEY-1 retired"
        )


def test_the_correction_states_the_consequence_not_just_the_fact():
    """"One recipient" is a fact an operator can read past. "Losing the key destroys every credential" is the
    decision-relevant consequence, and it is the part that was actively inverted before."""
    text = _security_text()
    if not any(n < 2 for n in _recipients_per_domain().values()):
        return  # break-glass implemented; this assertion no longer applies
    c1 = text.split("### C1 —", 1)[1].split("\n### ", 1)[0]
    assert "catastrophic" in c1, "the correction must name the actual consequence of key loss"
    assert "ONE" in c1, "and state the true recipient count"
    assert "sops updatekeys" in c1, "and name the remedy that would close it"


def test_the_off_box_key_copy_is_not_described_as_break_glass():
    """The mitigation actually in place is a COPY of the single private key. Calling that break-glass would
    re-introduce the same false comfort in new words: a copy shares the single point of failure, a second
    recipient removes it. The distinction is the whole control."""
    text = _security_text()
    if not any(n < 2 for n in _recipients_per_domain().values()):
        return
    c1 = text.split("### C1 —", 1)[1].split("\n### ", 1)[0]
    assert "not a break-glass recipient" in c1, \
        "the off-box key copy must be explicitly distinguished from a break-glass recipient"
