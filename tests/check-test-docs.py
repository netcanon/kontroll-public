#!/usr/bin/env python3
"""Fail if any test function lacks a docstring (docs/testing-standards.md §2 — the rule is
machine-enforced, not aspirational). Run by tests/validate.{sh,ps1}; also useful standalone:
`python3 tests/check-test-docs.py`. Exit 0 = all documented, 1 = some undocumented (lists them).
"""
import ast
import glob
import sys

missing = []
for f in sorted(glob.glob("tests/**/test_*.py", recursive=True)):
    tree = ast.parse(open(f, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_") and not ast.get_docstring(node):
            missing.append("%s:%d  %s" % (f, node.lineno, node.name))

if missing:
    print("undocumented tests (docs/testing-standards.md §2 — add a docstring saying what it verifies + why):")
    print("  " + "\n  ".join(missing))
    sys.exit(1)
print("all test functions carry a docstring")
