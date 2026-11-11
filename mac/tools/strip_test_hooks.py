#!/usr/bin/env python3
"""strip_test_hooks.py <script>... - remove what exists only for the tests from the scripts the app carries.

A script may hold regions that only the tests use (options that stand in for what it would measure on the Mac, a
looser rule for who may own a file). In the source each is marked:

    # test-hook-begin
    ...lines only the tests need...
    # test-hook-end
    # ship: <the line the carried copy has in their place, if any>

This rewrites each file given, in place: the regions go, and each "# ship: " line becomes the line it names. build.sh
runs it on the copies inside the app, before their hashes are taken; the sources are never changed. A marker with no
partner stops the build."""
import os
import sys

BEGIN, END, SHIP = "# test-hook-begin", "# test-hook-end", "# ship: "


def strip(text, name="script"):
    out, inside = [], False
    for ln in text.split("\n"):
        s = ln.strip()
        if s == BEGIN:
            if inside:
                raise ValueError(f"{name}: a test region starts inside another")
            inside = True
        elif s == END:
            if not inside:
                raise ValueError(f"{name}: a test region ends that never started")
            inside = False
        elif not inside:
            out.append(ln[:len(ln) - len(ln.lstrip())] + s[len(SHIP):] if s.startswith(SHIP) else ln)
    if inside:
        raise ValueError(f"{name}: a test region never ends")
    return "\n".join(out)


def main(paths):
    for p in paths:
        with open(p) as fh:
            text = fh.read()
        try:
            new = strip(text, os.path.basename(p))
        except ValueError as e:
            print(f"STOP: {e}")
            return 1
        if new != text:
            mode = os.stat(p).st_mode
            tmp = p + ".tmp"
            with open(tmp, "w") as fh:
                fh.write(new)
            os.chmod(tmp, mode)
            os.replace(tmp, p)
            print(f"test regions removed: {os.path.basename(p)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
