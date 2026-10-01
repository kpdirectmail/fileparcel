#!/usr/bin/env python3
"""Keep failure-phrased text out of PASS lines.

fp.record() prints its `detail` on PASS *and* on FAIL, so a call site that
passes a literal like "still down" as the positional detail produces
"[PASS] server is back after the restore -- still down", which reads as a
failure. The smoke log is the artefact DESIGN §20.1 is written from, so a
reader scanning it can record the opposite of what happened.

Failure-phrased text belongs in the `fail_detail=` keyword, which is printed
only when the check fails. This scan fails the run when a check()/record()
call passes a non-empty string *constant* as the positional detail. A
computed detail (an f-string, "%d %s" % (...), a variable, a slice) describes
what was observed and is fine, and so is an always-FAIL marker written as
check(name, False, "why this was skipped") -- there the detail can only ever
be printed on a FAIL line.
"""
import ast
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FUNCS = {"check", "record"}
DETAIL_ARG = 2  # check(name, cond, detail) / record(name, ok, detail)


def offenders(path):
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        if name not in FUNCS or len(node.args) <= DETAIL_ARG:
            continue
        detail = node.args[DETAIL_ARG]
        if not (isinstance(detail, ast.Constant) and isinstance(detail.value, str) and detail.value):
            continue
        cond = node.args[1]
        if isinstance(cond, ast.Constant) and cond.value is False:
            continue  # always-FAIL marker: the detail can only print on a FAIL
        yield node.lineno, detail.value


def main():
    bad = []
    for path in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        for lineno, text in offenders(path):
            bad.append((os.path.basename(path), lineno, text))
    for path, lineno, text in bad:
        print("%s:%d: literal detail %r is printed on PASS too; "
              "pass it as fail_detail=" % (path, lineno, text[:70]), file=sys.stderr)
    if bad:
        print("%d call site(s) would print failure-phrased text on a PASS line" % len(bad), file=sys.stderr)
        return 1
    print("detail lint: %d files clean" % len(glob.glob(os.path.join(HERE, "*.py"))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
