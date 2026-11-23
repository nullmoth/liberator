#!/usr/bin/env python3
"""The Golden Gate script reads plist values through pex(): on macOS 15, `plutil -extract KEY raw` for a missing key
prints its error message on STDOUT, and a reader that captured the output took the message as the value (every kit
entry without an executable or a comment then failed the text check: "a kit entry has a field 1401 will not write").
These arms run the script's own pex() line, and the old kv() from the last release as the control, under a plutil
that answers the way macOS 15's does."""
import os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "Resources", "nullmoth-golden-gate.sh")
fails = 0


def arm(name, ok, detail=""):
    global fails
    fails += not ok
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f" ({detail})"))


with tempfile.TemporaryDirectory() as t:
    fake = os.path.join(t, "bin"); os.makedirs(fake)
    with open(os.path.join(fake, "plutil"), "w") as fh:
        fh.write('#!/bin/bash\nout=$(/usr/bin/plutil "$@" 2>/dev/null); rc=$?\n'
                 'if [ $rc -ne 0 ] && [ "$1" = "-extract" ]; then echo "Could not extract value, error: No value at that key path or invalid key path: $2"; exit 1; fi\n'
                 '[ -n "$out" ] && printf \'%s\\n\' "$out"; exit $rc\n')
    os.chmod(os.path.join(fake, "plutil"), 0o755)
    man = os.path.join(t, "m.plist")
    with open(man, "w") as fh:
        fh.write('<?xml version="1.0"?><plist version="1.0"><dict><key>kexts</key><array><dict>'
                 '<key>name</key><string>Lilu.kext</string></dict></array></dict></plist>')
    env = dict(os.environ, PATH=fake + ":" + os.environ["PATH"])
    src = open(SCRIPT).read()
    pex = re.search(r'^pex\(\) \{.*\}$', src, re.M)
    arm("the script defines pex() on one line", pex is not None)
    old = subprocess.run(["git", "-C", HERE, "show", "HEAD~0:mac/Resources/nullmoth-golden-gate.sh"], capture_output=True, text=True).stdout
    oldkv = re.search(r'^kv\(\) \{ plutil -extract .*\}', old, re.M)

    def run(defs, call):
        return subprocess.run(["/bin/bash", "-c", defs + "\n" + call], capture_output=True, text=True, env=env)

    if pex:
        r = run(pex.group(0), f'v=$(pex kexts.0.executable "{man}"); echo "[$v] rc=$?"')
        arm("pex: a missing key reads as empty under macOS 15's plutil", r.stdout.strip() == "[] rc=1", r.stdout + r.stderr)
        r = run(pex.group(0), f'echo "[$(pex kexts.0.name "{man}")]"')
        arm("pex: a present key still reads its value", r.stdout.strip() == "[Lilu.kext]", r.stdout + r.stderr)
    if oldkv and "pex" not in oldkv.group(0):
        r = run(f'KIT={t}; MANIFEST=m.plist\n' + oldkv.group(0), 'echo "[$(kv kexts.0.executable)]"')
        arm("control: the released kv() takes macOS 15's error text as the value", "Could not extract" in r.stdout, r.stdout)
    else:
        print("note: HEAD already has the fixed reader; control skipped")

print(f"{'all arms passed' if not fails else str(fails) + ' FAILED'}")
sys.exit(1 if fails else 0)
