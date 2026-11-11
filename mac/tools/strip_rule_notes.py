#!/usr/bin/env python3
"""strip_rule_notes.py <file.json>:<key>... - remove a key, at every depth, from a JSON file the app carries.

The rule files keep, beside each rule, a note of where it came from ("source" in efi_rules.json, "evidence" in
nullmoth-rules.json): reports, dates, counts. No code reads those notes; they are for whoever maintains the rules.
build.sh removes them from the copies inside the app, in place, before the hashes are taken. The sources keep them."""
import json
import os
import sys


def strip(value, key):
    if isinstance(value, dict):
        return {k: strip(v, key) for k, v in value.items() if k != key}
    if isinstance(value, list):
        return [strip(v, key) for v in value]
    return value


def main(args):
    for a in args:
        path, _, key = a.rpartition(":")
        if not path or not key:
            print("usage: strip_rule_notes.py <file.json>:<key>...")
            return 2
        with open(path) as fh:
            data = json.load(fh)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(strip(data, key), fh, indent=1, sort_keys=False)
            fh.write("\n")
        os.replace(tmp, path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
