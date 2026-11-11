#!/usr/bin/env python3
"""The scripts the app carries hold nothing that exists only for the tests.

nullmoth-golden-gate.sh has options that stand in for what it would measure on the Mac, and accepts files owned by
the user running it when that user is not root. Both exist so the suite can run it against fixtures; neither may be
in the app. build.sh removes the marked regions from the copies in the bundle (tools/strip_test_hooks.py). Here the
same removal is made on a copy and the copy is run: every stand-in option is refused as unknown, the rest of the
script is the source line for line, and a kit owned by the running user is refused while the source accepts it."""
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(ROOT / "tools"))
import strip_test_hooks  # noqa: E402
from p1401 import v3_macos27  # noqa: E402
from test_v3_macos27 import Fixture  # noqa: E402

fails = 0
HOOKS = ["--macos-major", "--gpu-id", "--disk-free-gb", "--device-id", "--diskutil", "--tools", "--kc-work", "--step-log", "--cpu-vendor", "--laptop"]


def arm(name, ok, detail=""):
    global fails
    fails += not ok
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f" ({str(detail).strip()[-500:]})"))


def run(script, *args):
    env = {k: v for k, v in os.environ.items() if k != v3_macos27.KIT_ENV}
    r = subprocess.run(["/bin/bash", str(script), *args], capture_output=True, text=True, timeout=120, env=env)
    return r.returncode, r.stdout + r.stderr


source = (ROOT / "Resources/nullmoth-golden-gate.sh").read_text()
carried = strip_test_hooks.strip(source)
arm("the source has test regions and the carried copy has none of their markers",
    source.count("# test-hook-begin") == source.count("# test-hook-end") == 3 and "test-hook" not in carried and "# ship: " not in carried)
arm("no stand-in option is left in the carried copy", not [h for h in HOOKS if h in carried], [h for h in HOOKS if h in carried])
arm("control: every one of them is in the source", all(h in source for h in HOOKS))
# line for line: the carried copy is the source without the lines inside the regions, plus the one "ship" line
kept, inside = [], False
for ln in source.split("\n"):
    if ln.strip() == "# test-hook-begin":
        inside = True
    elif ln.strip() == "# test-hook-end":
        inside = False
    elif not inside:
        kept.append(ln)
diff = [(a, b) for a, b in zip(kept, carried.split("\n")) if a != b]
arm("the carried copy is the source line for line outside the regions; the only changed line is the file-owner rule",
    len(kept) == len(carried.split("\n")) and diff == [("# ship: ME=0", "ME=0")], diff[:3])
with tempfile.TemporaryDirectory() as td:
    script = pathlib.Path(td) / "nullmoth-golden-gate.sh"
    script.write_text(carried)
    arm("the carried copy parses", subprocess.run(["/bin/bash", "-n", str(script)]).returncode == 0)
    for res in ("nvidia_gsp_ids.json",):
        (pathlib.Path(td) / res).write_bytes((ROOT / "Resources" / res).read_bytes())
    fx = Fixture(os.path.join(td, "fx"))
    with open(os.path.join(fx.efi, ".1401-build"), "w") as fh:
        fh.write("built by 1401\n")
    for h in HOOKS:
        rc, out = run(script, "preflight", "--root", fx.efi, "--kit", fx.kit_path, h, "x")
        arm(f"the carried copy refuses {h} as an unknown option", rc == 2 and f"STOP unknown option {h}" in out, out)
    rc, out = run(ROOT / "Resources/nullmoth-golden-gate.sh", "preflight", "--root", fx.efi, "--kit", fx.kit_path, "--macos-major", "26")
    arm("control: the source takes the same option", "unknown option" not in out, out)
    rc, out = run(script, "status", "--root", fx.efi)
    arm("the carried copy still runs a step that needs no stand-in (status)", rc == 0 and "Golden Gate state: none" in out, out)
    rc, out = run(script, "stage", "--root", fx.efi, "--kit", fx.kit_path)
    rc2, out2 = run(ROOT / "Resources/nullmoth-golden-gate.sh", "stage", "--root", fx.efi, "--kit", fx.kit_path, "--gpu-id", "2D05", "--device-id", "0BDA-8922")
    arm("the carried copy refuses a kit that is not root's (here: the user running the test); control: the source accepts the same kit",
        (os.getuid() == 0 or (rc == 1 and "is not trusted" in out)) and rc2 == 0, out + out2)
# the maintainers' notes beside each rule are not carried either, and the rules themselves are untouched
import json  # noqa: E402
import strip_rule_notes  # noqa: E402
for name, key in (("../p1401/efi_rules.json", "source"), ("Resources/nullmoth-rules.json", "evidence")):
    data = json.loads((ROOT / name).read_text())
    carried_rules = strip_rule_notes.strip(data, key)

    def without(v):
        return {k: without(x) for k, x in v.items() if k != key} if isinstance(v, dict) else [without(x) for x in v] if isinstance(v, list) else v
    text = json.dumps(carried_rules)
    arm(f"{os.path.basename(name)}: the carried copy has no \"{key}\" note and is otherwise the same data (control: the source has them)",
        f'"{key}"' not in text and f'"{key}"' in json.dumps(data) and carried_rules == without(data))
code = "".join((ROOT / "Sources" / f).read_text() for f in os.listdir(ROOT / "Sources") if f.endswith(".swift")) + (ROOT / "Resources/app.js").read_text()
arm("no code of the app reads those notes", '"evidence"' not in code
    and all('"source"' not in (ROOT / "Sources" / f).read_text() for f in ("EfiRules.swift", "EfiCheck.swift", "profile.swift")))
# and the app's own checker decides every recorded case the same from the carried copy of the rules
with tempfile.TemporaryDirectory() as td:
    carried_path = pathlib.Path(td) / "efi_rules.json"
    carried_path.write_text(json.dumps(strip_rule_notes.strip(json.loads((ROOT / "../p1401/efi_rules.json").read_text()), "source")))
    exe = pathlib.Path(td) / "efi_rules_test"
    c = subprocess.run(["xcrun", "swiftc", "-Onone", str(ROOT / "Sources/EfiRules.swift"), str(ROOT / "tests/efi_rules/main.swift"), "-o", str(exe)],
                       capture_output=True, text=True, timeout=600)
    r = subprocess.run([str(exe), str(carried_path), str(ROOT / "tests/efi_rules/vectors.json")], capture_output=True, text=True, timeout=120) if c.returncode == 0 else None
    r0 = subprocess.run([str(exe), str(ROOT / "../p1401/efi_rules.json"), str(ROOT / "tests/efi_rules/vectors.json")], capture_output=True, text=True, timeout=120) if c.returncode == 0 else None
    arm("the app's EFI checker decides every recorded case the same from the rules without their notes (control: the source file gives the same output)",
        r is not None and r.returncode == 0 and r0.returncode == 0 and r.stdout == r0.stdout, (r.stdout[-300:] if r else c.stderr[-300:]))
build = (ROOT / "build.sh").read_text()
arm("the build removes the notes from both rule files after copying them and before the hashes are taken",
    build.index('cp ../p1401/efi_rules.json') < build.index("tools/strip_rule_notes.py") < build.index("BundleHashes.swift")
    and '"$APP/Contents/Resources/efi_rules.json:source" "$APP/Contents/Resources/nullmoth-rules.json:evidence"' in build)
arm("the build removes the test regions from the copies in the app before their hashes are taken, and stops if a marker is left",
    0 < build.index('cp Resources/* "$APP/Contents/Resources/"') < build.index("tools/strip_test_hooks.py") < build.index("BundleHashes.swift")
    and "a test region marker is left in a script the app carries" in build)
print("FAILED" if fails else "all passed")
sys.exit(1 if fails else 0)
