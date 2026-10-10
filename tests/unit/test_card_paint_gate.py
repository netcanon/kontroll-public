"""No third-party-authored record byte may reach `innerHTML` in the GUI.

WHAT THIS VERIFIES: every `E(...)` call site in `gui/templates/index.html` — `E` is the helper whose third
argument is assigned to `innerHTML` (`e.innerHTML = h`) — is checked, and none of them receives an expression
containing a search-record field (`rec.…`), an API error string, or a refusal/dependency field. The safe sibling
`ET(...)` sets `textContent` and is what those values must use. The four testids that paint record data are
additionally pinned to `ET(` by name.

WHY (the failure it guards against): `scripts/kontroll/probe.py` copies a collection's `description` verbatim out
of the public Ansible Galaxy API into the record the search panel renders. Until this commit the card painted that
description — plus the collection name, version and origin — through `E()`/`innerHTML`. Anyone who publishes a
collection whose `galaxy.yml` description is `<img src=x onerror=…>`, with tags matching a plausible device
search, gets script execution in the operator's authenticated session **the moment they search** — before any
onboard or consent dialog can gate it, and with the session able to reach every `POST` route the GUI exposes. The
repo already had the doctrine (`ET()`'s own comment: use it for any DEVICE-controlled byte) and had applied it to
capture/inventory bytes; it was never applied to Galaxy bytes. A comment cannot hold that line across future
edits — this gate can, and it fails loudly the first time someone reaches for `E()` with a `rec.` value.

Scope note: this is a lint-grade source gate, not the security control. The control is the paint itself. The gate
exists so the paint cannot silently regress.
"""
import os
import re

import pytest

pytestmark = pytest.mark.unit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
INDEX = os.path.join(ROOT, "gui", "templates", "index.html")

# Substrings that mark an expression as carrying data kontroll did not author. `rec.` covers the whole search
# record (collection/version/origin/depth/meta.description/…); the rest are the non-record channels that carry
# third-party bytes today or will as this arc lands (a reconcile refusal names an attacker-chosen collection).
# EXTEND THIS LIST when a new externally-authored field reaches the page.
FORBIDDEN = ("rec.", "data.error", ".description", ".reason", ".detail", "h.name", ".ansible_host")

# testid -> the values it paints. Each must be built with ET(, never E(.
MUST_USE_ET = {
    "result-title": "the collection name (Galaxy-authored)",
    "result-meta": "the collection description/note (Galaxy-authored)",
    "search-api-error": "api_search's exception string (can embed a remote response)",
    "suggested-backend-badge": "a rec.* field (locally derived, but the rule is mechanical)",
}


def _strip_js(src):
    """Blank out JS line/block comments and string bodies, quote- and regex-aware, preserving offsets.

    Needed so the scanner neither trips on prose that merely mentions `E(` (the helper's own doc comment) nor
    mistakes a `//` inside a string (`'http://…'`) for a comment. Offsets are preserved by replacing each removed
    character with a space, so reported line numbers stay true.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        if ch in "\"'`":                                  # a string literal: blank its body, keep the quotes
            q, i = ch, i + 1
            while i < n:
                if src[i] == "\\":
                    out[i] = " "
                    if i + 1 < n:
                        out[i + 1] = " "
                    i += 2
                    continue
                if src[i] == q:
                    break
                if src[i] != "\n":                        # keep newlines so line numbers survive
                    out[i] = " "
                i += 1
            i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            while i < n and not (src[i] == "*" and i + 1 < n and src[i + 1] == "/"):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
            i += 2
            continue
        i += 1
    return "".join(out)


def _call_args(src, open_paren):
    """The raw argument strings of the call whose '(' is at `open_paren`, split on TOP-LEVEL commas.

    Returns None if the call does not close (prose, not code). Nesting counts (/[/{ so a comma inside an object,
    array, sub-call or arrow body does not split an argument.
    """
    depth, i, args, cur = 0, open_paren, [], []
    while i < len(src):
        ch = src[i]
        if ch in "([{":
            depth += 1
            if not (depth == 1 and i == open_paren):
                cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args
            cur.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    return None


def _innerhtml_args(src):
    """[(line, arg)] — the third argument of every `E(` call site (the one assigned to innerHTML)."""
    found = []
    for m in re.finditer(r"(?<![A-Za-z0-9_$.])E\(", src):
        args = _call_args(src, m.end() - 1)
        if args is None or len(args) < 3:
            continue                                      # 2-arg E(tag, class) never touches innerHTML
        found.append((src.count("\n", 0, m.start()) + 1, args[2]))
    return found


def test_the_innerhtml_helper_is_still_the_thing_this_gate_guards():
    """Pin the premise: `E` assigns innerHTML and `ET` assigns textContent. If someone makes E() safe by
    construction this gate is measuring nothing, and the failure should say so rather than pass silently."""
    html = open(INDEX, encoding="utf-8").read()
    assert "const E = (t, c, h, tid) =>" in html and "e.innerHTML=h" in html
    assert "const ET = (t, c, text, tid) =>" in html and "e.textContent=text" in html


def test_no_record_or_external_value_reaches_innerhtml():
    """The gate itself: no `E(` call site paints a `rec.*` field, an API error, or a refusal/dependency string.
    Guards the search-card XSS — a Galaxy-published `description` of `<img src=x onerror=…>` executing in the
    operator's session on search alone."""
    src = _strip_js(open(INDEX, encoding="utf-8").read())
    offenders = [(line, arg.strip(), tok)
                 for line, arg in _innerhtml_args(src)
                 for tok in FORBIDDEN if tok in arg]
    assert not offenders, "externally-authored value(s) reaching innerHTML — use ET():\n" + "\n".join(
        "  index.html:%d  contains %r  ->  %s" % (line, tok, arg) for line, arg, tok in offenders)


def test_the_scanner_actually_catches_a_planted_sink():
    """A gate that cannot fail is not a gate. Plant each forbidden token in a synthetic E() call and prove the
    scanner reports it — and that the same expression via ET() is clean."""
    for tok in FORBIDDEN:
        bad = "x.appendChild(E('div','meta', %sfoo, 'result-meta'));" % tok
        assert [a for _, a in _innerhtml_args(_strip_js(bad)) if tok in a], "scanner missed %r" % tok
        good = "x.appendChild(ET('div','meta', %sfoo, 'result-meta'));" % tok
        assert not _innerhtml_args(_strip_js(good)), "ET() must not be scanned as an innerHTML sink"


def test_the_scanner_ignores_prose_and_strings():
    """`E(` inside a comment or a string literal is not a call site. Without this the helper's own doc comment
    (`// E(tag, class, html, testid)`) and any `'http://…'` would produce noise or a crash."""
    assert not _innerhtml_args(_strip_js("// E(tag, class, html, testid) — the doc comment\n"))
    assert not _innerhtml_args(_strip_js("const u = 'E(rec.description, x, y)';\n"))
    assert _innerhtml_args(_strip_js("E('a','b', 'literal', 'tid');\n")), "real call sites must still be seen"


def test_record_painting_testids_are_built_with_et():
    """Belt to the gate's braces: the four elements that carry externally-authored bytes are named and pinned to
    ET( by testid, so a rewrite cannot quietly move one back to E() with a differently-shaped expression."""
    html = open(INDEX, encoding="utf-8").read()
    for tid, what in MUST_USE_ET.items():
        assert re.search(r"ET\([^\n]*'%s'" % re.escape(tid), html), \
            "%s (%s) must be painted with ET(), not E()" % (tid, what)


def test_security_headers_are_declared():
    """The defence-in-depth layer ships and stays: object-src/base-uri/frame-ancestors plus nosniff. NOT
    script-src — index.html carries a large inline <script>, so asserting it here would pin a header that breaks
    the page; relocating that script is a named follow-up."""
    app_src = open(os.path.join(ROOT, "gui", "app.py"), encoding="utf-8").read()
    assert "@app.after_request" in app_src
    m = re.search(r'"Content-Security-Policy",\s*\n?\s*"([^"]*)"', app_src)
    assert m, "no Content-Security-Policy header value found in gui/app.py"
    policy = m.group(1)          # assert on the POLICY, not the file — prose about script-src is not a directive
    for directive in ("object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'"):
        assert directive in policy, "missing CSP directive: %s (policy is %r)" % (directive, policy)
    assert "X-Content-Type-Options" in app_src
    assert "script-src" not in policy, "script-src cannot ship while index.html has an inline <script>"
