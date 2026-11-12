#!/usr/bin/env python3
"""Prepare for Golden Gate on the Mac (nullmoth-golden-gate.sh): offered only with a v3 kit, makes the same macOS 27
startup files as 1401's builder, and every step leaves the way back.

The script is run for real against a synthetic startup partition (the fixture of tests/test_v3_macos27.py). Each guard
is shown in both directions: refusing with the partition unchanged, and working when its condition holds. The same
partition is also handed between the script and p1401/golden_gate.py mid-way, since either may finish what the other
started."""
import hashlib
import json
import os
import pathlib
import plistlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "tests"))
from p1401 import golden_gate as gg, v3_macos27  # noqa: E402
from test_v3_macos27 import Fixture  # noqa: E402

SCRIPT = str(ROOT / "Resources/nullmoth-golden-gate.sh")
TOOLS = tempfile.mkdtemp(prefix="gg-tools-")
READY = ["--macos-major", "26", "--gpu-id", "2D05", "--disk-free-gb", "110", "--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS]
fails = 0


def arm(name, ok, detail=""):
    global fails
    fails += not ok
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f" ({str(detail).strip()[-600:]})"))


class Vols(str):
    """A folder standing in for mounted volumes. As an argument to run() it becomes the options that point the script
    at this folder's record of the macOS 27 volumes and at the diskutil stand-in that knows where they are mounted."""
    args = ()


def stand_in_tools(root, missing=(), broken=()):
    """The system tools preflight probes, as stand-ins: each exists and answers the way the probe asks."""
    answers = {"usr/bin/bspatch": "", "usr/bin/aea": "", "usr/bin/hdiutil": "", "usr/bin/shasum": "", "usr/bin/curl": "",
               "usr/sbin/pkgutil": 'echo "Could not open product archive: $2"; exit 1',    # as the real one answers the probe
               "usr/sbin/diskutil": '[ "$1 $2" = "apfs addVolume" ] && echo "Usage: diskutil apfs addVolume <c> <fs> <name> [-groupWith <g>]"',
               "usr/bin/plutil": 'exec /usr/bin/plutil "$@"'}
    for rel, body in answers.items():
        if rel in missing:
            continue
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            # a pkgutil from before the option says so; the other two just answer something else
            old = 'echo "pkgutil: unrecognized option \\`--expand-full\'" >&2; exit 1' if rel == "usr/sbin/pkgutil" else "echo nothing"
            fh.write("#!/bin/bash\n" + (old if rel in broken else body) + "\n")
        os.chmod(path, 0o755)
    return root


stand_in_tools(TOOLS)
DISKUTIL_STUB = """#!/bin/bash
# stands in for: diskutil info -plist <volume identifier, device or />
d=$(dirname "$0")
# and for: diskutil mount <volume identifier>, on a stand-in volume that can be mounted
if [ "$1" = mount ] && [ -f "$d/$2.mounted.plist" ]; then cp "$d/$2.mounted.plist" "$d/$2.plist"; exit 0; fi
# and for: diskutil enableOwnership <volume identifier>; it works only on a stand-in volume that allows it
if [ "$1" = enableOwnership ]; then echo "owners $2" >> "$d/disk-calls.log"; [ -f "$d/$2.owned.plist" ] && cp "$d/$2.owned.plist" "$d/$2.plist"; exit 0; fi
# and for the two calls that take a volume away; each is written down
if [ "$1 $2" = "unmount force" ]; then echo "unmount $3" >> "$d/disk-calls.log"; exit 0; fi
# and for: diskutil unmount <volume identifier>, the gentle one a reporting step uses to put back what it mounted
if [ "$1" = unmount ]; then echo "release $2" >> "$d/disk-calls.log"; [ -f "$d/$2.unmounted.plist" ] && cp "$d/$2.unmounted.plist" "$d/$2.plist"; exit 0; fi
if [ "$1 $2" = "apfs deleteVolume" ]; then echo "delete $3" >> "$d/disk-calls.log"; [ ! -e "$d/refuse-delete" ] || exit 1; rm -f "$d/$3.plist"; exit 0; fi
[ "$1 $2" = "info -plist" ] || exit 1
key=$3; [ "$key" = / ] && key=root
[ -f "$d/$key.plist" ] && cat "$d/$key.plist" || exit 1
"""


def run(step, root, kit="", *more):
    flat, i, more = [], 0, list(more)
    while i < len(more):                       # a Vols, with or without the old option name before it, becomes its options
        if more[i] == "--volumes" and i + 1 < len(more) and isinstance(more[i + 1], Vols):
            flat += more[i + 1].args
            i += 2
        elif isinstance(more[i], Vols):
            flat += more[i].args
            i += 1
        else:
            flat.append(more[i])
            i += 1
    args = ["/bin/bash", SCRIPT, step, "--root", root] + (["--kit", kit] if kit else []) + flat
    env = {k: v for k, v in os.environ.items() if k != v3_macos27.KIT_ENV}
    r = subprocess.run(args, capture_output=True, text=True, timeout=300, env=env)
    return r.returncode, r.stdout + r.stderr


def tree(root, parsed=False):
    """Every file under root. parsed=True compares property lists by content, since two writers format them differently."""
    out = {}
    for base, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(base, f)
            with open(p, "rb") as fh:
                data = fh.read()
            if parsed and f.endswith(".plist"):
                out[os.path.relpath(p, root)] = plistlib.loads(data)
            elif parsed and f == gg.STATE:
                out[os.path.relpath(p, root)] = json.loads(data)["state"]
            else:
                out[os.path.relpath(p, root)] = hashlib.sha256(data).hexdigest()
    return out


def fresh(td, name):
    fx = Fixture(os.path.join(td, name))
    with open(os.path.join(fx.efi, ".1401-build"), "w") as fh:
        fh.write("built by 1401\n")
    return fx


arm("the script parses", subprocess.run(["/bin/bash", "-n", SCRIPT]).returncode == 0)

with tempfile.TemporaryDirectory() as td:
    # 1. the switch: no kit, or a kit that fails its checks, and nothing is offered or changed
    fx = fresh(td, "switch")
    before = tree(fx.efi)
    for step in ("preflight", "stage", "activate", "installer", "finish"):
        rc, out = run(step, fx.efi, "", "--confirm", *READY)
        arm(f"no kit: {step} stops as not offered", rc == 1 and "not offered" in out and "RESULT stop" in out, out)
    broken = os.path.join(td, "broken-kit")
    shutil.copytree(fx.kit_path, broken)
    m = json.load(open(os.path.join(broken, v3_macos27.MANIFEST)))
    m["boot_args"] = [a for a in m["boot_args"] if a != "-v"]
    json.dump(m, open(os.path.join(broken, v3_macos27.MANIFEST), "w"))
    rc, out = run("stage", fx.efi, broken)
    arm("a kit without -v is not an offer", rc == 1 and "not offered" in out, out)
    arm("nothing on the partition changed", tree(fx.efi) == before)

    # 2. preflight names what fails, and passes a ready Mac
    rc, out = run("preflight", fx.efi, fx.kit_path, *READY)
    arm("preflight passes a ready Mac", rc == 0 and "FAIL" not in out and "RESULT ok" in out, out)
    PC = ["--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS]
    for name, args, word in (("macOS 14", ["--macos-major", "14", "--gpu-id", "2D05", "--disk-free-gb", "110"] + PC, "FAIL this Mac runs macOS 14"),
                             ("macOS 27", ["--macos-major", "27", "--gpu-id", "2D05", "--disk-free-gb", "110"] + PC, "FAIL this Mac runs macOS 27"),
                             ("a card the driver does not take", ["--macos-major", "26", "--gpu-id", "1C03", "--disk-free-gb", "110"] + PC, "FAIL no NVIDIA card the driver takes was found"),
                             ("a full disk", ["--macos-major", "26", "--gpu-id", "2D05", "--disk-free-gb", "59"] + PC, "FAIL room for macOS 27")):
        rc, out = run("preflight", fx.efi, fx.kit_path, *args)
        arm(f"preflight refuses {name} and names it", rc == 1 and word in out and out.count("FAIL ") == 1, out)

    # 2a2. the startup partition is small. A refusal says which partition is meant; old OpenCore start-up logs are
    # the one thing staging removes to make room, and the three newest stay.
    esp = fresh(td, "esp-room")
    logs = ["opencore-2026-11-%02d-101010.txt" % d for d in range(1, 8)]
    for n in logs:
        with open(os.path.join(esp.efi, n), "wb") as fh:
            fh.write(b"x" * 300000)
    with open(os.path.join(esp.efi, "opencore-notes.txt"), "w") as fh:
        fh.write("mine")
    rc, out = run("preflight", esp.efi, esp.kit_path, *READY, "--esp-free-kb", "1")
    arm("too little room on the startup partition is refused, and the refusal says it is the EFI partition and not the disk",
        rc == 1 and "FAIL room on the startup partition: 0 MB free" in out and "small EFI partition OpenCore starts from" in out
        and "not the disk macOS is on" in out and "NOTE to make room on the startup partition" in out, out)
    need_kb = int(subprocess.run(["du", "-sk", os.path.join(esp.efi, "EFI", "OC")], capture_output=True, text=True).stdout.split()[0]) + \
        int(subprocess.run(["du", "-sk", os.path.join(esp.kit_path, "Kexts")], capture_output=True, text=True).stdout.split()[0]) + 8192
    short = str(need_kb - 600)
    rc, out = run("preflight", esp.efi, esp.kit_path, *READY, "--esp-free-kb", short)
    arm("room that old OpenCore start-up logs would give is counted, and the check says staging removes them",
        rc == 0 and "staging removes old OpenCore start-up logs there" in out and all(os.path.exists(os.path.join(esp.efi, n)) for n in logs), out)
    rc, out = run("stage", esp.efi, esp.kit_path, "--esp-free-kb", short)
    left = sorted(n for n in os.listdir(esp.efi) if n.startswith("opencore-"))
    arm("staging then removes all but the three newest logs, keeps a file that only looks like one, and says what it did",
        rc == 0 and left == logs[-3:] + ["opencore-notes.txt"] and "NOTE removed old OpenCore start-up logs" in out, out + repr(left))
    esp2 = fresh(td, "esp-room-plenty")
    for n in logs:
        with open(os.path.join(esp2.efi, n), "wb") as fh:
            fh.write(b"x" * 300000)
    rc, out = run("stage", esp2.efi, esp2.kit_path)
    arm("control: with room to spare staging removes no log", rc == 0 and sorted(n for n in os.listdir(esp2.efi) if n.startswith("opencore-")) == logs and "removed old" not in out, out)
    esp3 = fresh(td, "esp-room-none")
    b3 = tree(esp3.efi)
    rc, out = run("stage", esp3.efi, esp3.kit_path, "--esp-free-kb", "1")
    arm("staging with no room and nothing to remove stops, names the EFI partition, and changes nothing",
        rc == 1 and "small EFI partition OpenCore starts from" in out and tree(esp3.efi) == b3, out)

    # 2b. different PCs. Every PC the driver runs on under macOS 26 may try macOS 27; what has not been started yet
    # is said, with the way back and how a failure reaches us. Only a card the driver does not take is refused.
    def pc(card, cpu="GenuineIntel", laptop="no"):
        return ["--macos-major", "26", "--gpu-id", card, "--disk-free-gb", "110", "--cpu-vendor", cpu, "--laptop", laptop, "--tools", TOOLS]

    SEND = "start macOS 26 from the 1401 USB stick and press Send logs there"
    before = tree(fx.efi)
    rc, out = run("preflight", fx.efi, fx.kit_path, *pc("2D05"))
    arm("a passing preflight says plainly that macOS 27 has run on one PC so far and how to get back",
        rc == 0 and "NOTE macOS 27 has been started on one desktop PC so far. On a different board or processor generation it is untried" in out
        and "the 1401 USB stick still starts macOS 26" in out, out)
    arm("PC 1 (RTX 5060, Intel desktop, the card it has run on): passes with no extra notice",
        rc == 0 and "OK NVIDIA card NVIDIA GeForce RTX 5060 (2D05) is one the driver takes" in out and "has not been run on" not in out and SEND not in out, out)
    rc, out = run("preflight", fx.efi, fx.kit_path, *pc("2484"))
    arm("PC 2 (RTX 3070, Intel desktop): passes, and is told macOS 27 has not been run on this card, that it is a beta, and how a failure reaches us",
        rc == 0 and "FAIL" not in out and "OK NVIDIA card NVIDIA GeForce RTX 3070 (2484) is one the driver takes" in out
        and "NOTE macOS 27 has not been run on NVIDIA GeForce RTX 3070 yet (so far: NVIDIA GeForce RTX 5060 (2D05)). This is a beta: it may not start. "
        "If macOS 27 does not reach its desktop, " + SEND in out and tree(fx.efi) == before, out)
    rc, out = run("preflight", fx.efi, fx.kit_path, *pc("1B80"))
    arm("PC 3 (GTX 1080, a card the driver does not take): refused, saying what was found, and nothing else is promised",
        rc == 1 and "FAIL no NVIDIA card the driver takes was found (found: 1B80)" in out and "offered only" not in out
        and out.count("FAIL ") == 1 and tree(fx.efi) == before, out)
    rc, out = run("preflight", fx.efi, fx.kit_path, *pc("2D05", "GenuineIntel", "yes"))
    arm("a laptop passes and is told that a laptop is untried", rc == 0 and "FAIL" not in out
        and "NOTE macOS 27 with this kit has not been started on a laptop yet; its built-in screen and its switch between two graphics chips are untried. If macOS 27 does not reach its desktop, " + SEND in out, out)
    rc, out = run("preflight", fx.efi, fx.kit_path, *pc("2484", "AuthenticAMD"))
    arm("an AMD desktop with an untried card passes and is told both",
        rc == 0 and "FAIL" not in out and "has not been run on NVIDIA GeForce RTX 3070 yet" in out
        and "macOS 27 with this kit has not been started on a PC with an AMD processor yet" in out and out.count(SEND) == 1, out)
    # the tried cards are data for the wording only: a kit that names the RTX 3070 as tried drops the notice, and a
    # kit that names none falls back to the cards this app records
    wide = os.path.join(td, "kit-wide")
    shutil.copytree(fx.kit_path, wide)
    mw = json.load(open(os.path.join(wide, v3_macos27.MANIFEST)))
    mw["gpu_ids"] = ["2D05", "2484"]
    json.dump(mw, open(os.path.join(wide, v3_macos27.MANIFEST), "w"))
    rc, out = run("preflight", fx.efi, wide, *pc("2484"))
    arm("control: with a kit that names the RTX 3070 as tried, the same PC passes without the notice", rc == 0 and "has not been run on" not in out, out)
    none = os.path.join(td, "kit-nolist")
    shutil.copytree(fx.kit_path, none)
    mn = json.load(open(os.path.join(none, v3_macos27.MANIFEST)))
    arm("the kit tool writes the tried cards into the kit", mn.get("gpu_ids") == ["2D05"], mn.get("gpu_ids"))
    del mn["gpu_ids"]
    json.dump(mn, open(os.path.join(none, v3_macos27.MANIFEST), "w"))
    rc, out = run("preflight", fx.efi, none, *pc("2484"))
    rc2, out2 = run("preflight", fx.efi, none, *pc("2D05"))
    arm("a kit that names no cards still accepts every card the driver takes, and words the notice from this app's own record",
        rc == 0 and "(so far: NVIDIA GeForce RTX 5060 (2D05))" in out and rc2 == 0 and "has not been run on" not in out2, out + out2)

    # 2c. graphics other than NVIDIA. Three paths: the NVIDIA driver, Apple's own AMD and Intel drivers (real Macs,
    # and the Radeon cards Apple shipped), 1401's AMD and Intel test drivers. A path is offered only when the kit
    # says it carries macOS 27 graphics for it; a kit that says nothing is an NVIDIA kit.
    def mac(displays, apple=(), card=None):
        a = ["--macos-major", "26", "--disk-free-gb", "110", "--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS]
        a += ["--gpu-id", card] if card else ["--apple-id", "0000:0000"]
        for d in displays:
            a += ["--display", d]
        for i in apple:
            a += ["--apple-id", i]
        return a

    def kit_with(name, paths):
        k = os.path.join(td, name)
        shutil.copytree(fx.kit_path, k)
        m = json.load(open(os.path.join(k, v3_macos27.MANIFEST)))
        m["graphics"] = paths
        json.dump(m, open(os.path.join(k, v3_macos27.MANIFEST), "w"))
        return k

    allk, applek = kit_with("kit-all", ["nvidia", "apple", "test"]), kit_with("kit-apple", ["nvidia", "apple"])
    POLARIS, UHD630, XE, RX7600 = "1002:67DF", "8086:3E92", "8086:9A49", "1002:7480"
    APPLE = (POLARIS, UHD630, "1002:7340")
    rc, out = run("preflight", fx.efi, fx.kit_path, *mac([POLARIS], APPLE))
    arm("today's kit (names no graphics paths) still refuses a Mac on Apple's AMD driver, and says what it found and what the kit carries",
        rc == 1 and out.count("FAIL ") == 1 and "FAIL this Mac has AMD graphics (1002:67DF), which Apple's own driver in this macOS runs; "
        "this kit has no macOS 27 graphics for it yet (it carries: nvidia)" in out and tree(fx.efi) == before, out)
    rc, out = run("preflight", fx.efi, applek, *mac([POLARIS], APPLE))
    arm("a kit that carries Apple's drivers accepts a Mac with a Radeon Apple shipped, on the apple path, and says it is untried",
        rc == 0 and "FAIL" not in out and "OK this Mac has AMD graphics (1002:67DF), which Apple's own driver in this macOS runs, and this kit carries macOS 27 graphics for it" in out
        and "NOTE graphics path: apple" in out and "macOS 27 has not been started on AMD graphics with this kit yet" in out and out.count(SEND) == 1, out)
    rc, out = run("preflight", fx.efi, applek, *mac([UHD630], APPLE))
    arm("the same kit accepts a Mac whose only graphics are Intel's on Apple's driver", rc == 0 and "Intel graphics (8086:3E92), which Apple's own driver" in out and "NOTE graphics path: apple" in out, out)
    rc, out = run("preflight", fx.efi, applek, *mac([XE], APPLE))
    arm("that kit refuses Intel graphics only a test driver runs, naming the test path", rc == 1 and out.count("FAIL ") == 1
        and "Intel graphics (8086:9A49), which 1401's test driver runs; this kit has no macOS 27 graphics for it yet (it carries: nvidia, apple)" in out, out)
    rc, out = run("preflight", fx.efi, allk, *mac([XE], APPLE))
    arm("a kit that carries the test drivers accepts Intel processor graphics on the test path", rc == 0 and "NOTE graphics path: test" in out and "FAIL" not in out, out)
    rc, out = run("preflight", fx.efi, allk, *mac([RX7600], APPLE))
    arm("and an AMD card Apple never shipped, on the test path", rc == 0 and "AMD graphics (1002:7480), which 1401's test driver runs" in out and "NOTE graphics path: test" in out, out)
    rc, out = run("preflight", fx.efi, allk, *mac([XE, POLARIS], APPLE))
    arm("with both kinds present, the chip on Apple's own driver is the one chosen", rc == 0 and "NOTE graphics path: apple" in out and "1002:67DF" in out, out)
    rc, out = run("preflight", fx.efi, allk, *mac([XE, POLARIS], APPLE, card="2D05"))
    arm("an NVIDIA card the driver takes still wins over both", rc == 0 and "NOTE graphics path: nvidia" in out and "OK NVIDIA card NVIDIA GeForce RTX 5060 (2D05)" in out and "test driver" not in out, out)
    rc, out = run("preflight", fx.efi, allk, *mac(["1234:1111"], APPLE))
    arm("a display device from no maker we have a driver for is refused, and named", rc == 1 and "FAIL no NVIDIA card the driver takes was found (found: none; other graphics: 1234:1111)" in out, out)
    rc, out = run("preflight", fx.efi, allk, *mac([], APPLE))
    arm("no graphics at all is refused", rc == 1 and "FAIL no NVIDIA card the driver takes was found (found: none)" in out, out)
    rc, out = run("preflight", fx.efi, fx.kit_path, "--macos-major", "26", "--gpu-id", "2D05", "--disk-free-gb", "91", "--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS)
    rc2, out2 = run("preflight", fx.efi, fx.kit_path, "--macos-major", "26", "--gpu-id", "2D05", "--disk-free-gb", "92", "--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS)
    arm("room is one number, from the kit scripts' own figures: 92 GB passes, 91 GB is refused",
        rc == 1 and "FAIL room for macOS 27: 91 GB free, 92 GB needed" in out and rc2 == 0, out + out2)
    # A second try with the downloads kept: what is already downloaded is not needed again. The first real second try
    # was refused with 88 GB free for the 102 GB a first try needed then, while 26 GB of that was already on the disk.
    lay = os.path.join(td, "lay-kept"); os.makedirs(lay); os.chmod(lay, 0o700)
    with open(os.path.join(lay, "UniversalMac_27.2_26B123_Restore.ipsw"), "wb") as fh:
        fh.truncate(26 * 1024 ** 3)
    with open(os.path.join(lay, "notes.txt"), "wb") as fh:
        fh.truncate(40 * 1024 ** 3)                      # not a download: counts for nothing
    kept = ["--macos-major", "26", "--gpu-id", "2D05", "--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS, "--lay-work", lay]
    rc, out = run("preflight", fx.efi, fx.kit_path, *kept, "--disk-free-gb", "66")
    rc2, out2 = run("preflight", fx.efi, fx.kit_path, *kept, "--disk-free-gb", "65")
    arm("with the restore image kept from an earlier run, the room it takes is not asked for again: 66 GB is enough, 65 is not",
        rc == 0 and "66 GB needed (26 GB is already downloaded)" in out and rc2 == 1 and "FAIL room for macOS 27: 65 GB free, 66 GB needed" in out2, out + out2)
    os.symlink(os.path.join(lay, "notes.txt"), os.path.join(lay, "Kernel_Debug_Kit_27.2_build_26B123.dmg"))
    rc, out = run("preflight", fx.efi, fx.kit_path, *kept, "--disk-free-gb", "66")
    arm("a link in that folder is not counted as a download", rc == 0 and "66 GB needed (26 GB is already downloaded)" in out, out)
    rc, out = run("preflight", fx.efi, fx.kit_path, "--macos-major", "15", "--gpu-id", "2D05", "--disk-free-gb", "110", "--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS)
    arm("Golden Gate starts from macOS 15 as well as 26", rc == 0 and "OK this Mac runs macOS 15; Golden Gate starts from macOS 15 or 26" in out, out)
    # what the later steps need from the running macOS is probed before anything is staged; a miss is said in one
    # fixed sentence that names the way out, and no version number is refused by itself
    SYSMSG = "cannot prepare macOS 27. Update to macOS 26.7.1, then run Golden Gate again. Reason: "
    for rel in ("usr/bin/bspatch", "usr/bin/aea", "usr/bin/hdiutil", "usr/sbin/pkgutil", "usr/sbin/diskutil", "usr/bin/plutil", "usr/bin/shasum", "usr/bin/curl"):
        tdir = stand_in_tools(os.path.join(td, "tools-no-" + os.path.basename(rel)), missing=(rel,))
        rc, out = run("preflight", fx.efi, fx.kit_path, *[tdir if a == TOOLS else a for a in READY])
        arm(f"a macOS without {os.path.basename(rel)}: the check stops with the fixed sentence and the reason, and nothing is changed",
            rc == 1 and "STOP This Mac's macOS " in out and SYSMSG + f"the system tool {os.path.basename(rel)} is missing. Nothing was changed" in out
            and tree(fx.efi) == before, out)
    for rel, word in (("usr/sbin/pkgutil", "pkgutil on this macOS cannot open a package in full (--expand-full)"),
                      ("usr/sbin/diskutil", "diskutil on this macOS cannot add a volume to a volume group (-groupWith)"),
                      ("usr/bin/plutil", "plutil on this macOS cannot read one value (-extract ... raw)")):
        tdir = stand_in_tools(os.path.join(td, "tools-old-" + os.path.basename(rel)), broken=(rel,))
        rc, out = run("preflight", fx.efi, fx.kit_path, *[tdir if a == TOOLS else a for a in READY])
        arm(f"a macOS whose {os.path.basename(rel)} answers differently: the same sentence, with that reason", rc == 1 and SYSMSG + word in out, out)
    # the model: this card's generation by default, the kit's own when asked (the second attempt if 27 does not start)
    for name, more, model, word in (("by default an RTX 50 PC is staged as the model for its generation", [], "Mac17,15", "NOTE model: Mac17,15"),
                                    ("with --kit-model the same PC keeps the model the kit sets", ["--kit-model"], "Mac15,14", "NOTE model: Mac15,14 (kept from the kit, as asked)")):
        m = fresh(td, "model" + str(len(more)))
        serial0 = plistlib.load(open(os.path.join(m.efi, "EFI", "OC", "config.plist"), "rb"))["PlatformInfo"]["Generic"].get("SystemSerialNumber")
        rc, out = run("stage", m.efi, m.kit_path, "--gpu-id", "2D05", "--device-id", "0BDA-8922", *more)
        g = plistlib.load(open(os.path.join(m.efi, "EFI", gg.STAGED, "config.plist"), "rb"))["PlatformInfo"]["Generic"]
        arm(name + (", and the serial is left as it was" if more else ""),
            rc == 0 and g["SystemProductName"] == model and word in out and (not more or g.get("SystemSerialNumber") == serial0), out + repr(g))
    setup_text = (ROOT / "Resources/nullmoth-setup.sh").read_text()
    # The app's own flow keeps the kit's model (the one that has started macOS 27) unless the card's model is asked
    # for: the model for the card's generation has not started macOS 27 on a real PC yet.
    arm("setup keeps the kit's model by default, hands --kit-model to the stage step only, and takes --card-model to turn it off",
        "--card-model) GGCARDMODEL=1;;" in setup_text and '$([ "$1" = stage ] && [ -z "${GGCARDMODEL:-}" ] && echo --kit-model)' in setup_text
        and '[ -n "${GGKITMODEL:-}" ] && echo --kit-model' not in setup_text)
    os.remove(os.path.join(fx.efi, ".1401-build"))
    rc, out = run("preflight", fx.efi, fx.kit_path, *READY)
    arm("preflight refuses startup files 1401 did not make", rc == 1 and "FAIL the startup files" in out, out)
    rc, out = run("stage", fx.efi, fx.kit_path)
    arm("stage refuses them too", rc == 1 and "not made by 1401" in out, out)
    arm("preflight and the refused stage changed nothing", {k: v for k, v in tree(fx.efi).items()} == {k: v for k, v in before.items() if k != ".1401-build"})

    # 2d. a real Mac. Its OpenCore files are not a 1401 build (OpenCore Legacy Patcher writes them); what marks
    # them as a Mac's is that no kext stands in for Apple's SMC chip. Such a config gives its kexts the limit
    # 27.99.99 as a matter of course, which is not proof that they run on macOS 27: on the first real Mac that let
    # the kernel-patching kexts into the macOS 27 kernel and it never reached its first service.
    def kx(name, mx):
        return {"Arch": "x86_64", "BundlePath": name, "Comment": "", "Enabled": True, "ExecutablePath": "Contents/MacOS/" + name[:-5],
                "MaxKernel": mx, "MinKernel": "", "PlistPath": "Contents/Info.plist"}

    def real_mac(name, smc_on=False):
        m = Fixture(os.path.join(td, name))                    # no .1401-build marker
        cp = os.path.join(m.efi, "EFI", "OC", "config.plist")
        c = plistlib.load(open(cp, "rb"))
        for k in c["Kernel"]["Add"]:
            if k["BundlePath"] == "VirtualSMC.kext":
                k["Enabled"] = smc_on
            if k["BundlePath"] == "AMFIPass.kext":
                k["MaxKernel"] = "27.99.99"                    # a capped kext that already carries the patcher's limit
        c["Kernel"]["Add"] += [kx("RestrictEvents.kext", "27.99.99"), kx("CatalinaIntelI210Ethernet.kext", ""),
                               kx("AppleIntelCPUPowerManagement.kext", ""), kx("OldOnly.kext", "24.99.99")]
        c["PlatformInfo"]["Generic"]["SystemProductName"] = ""  # a patcher config keeps the Mac's own identity
        plistlib.dump(c, open(cp, "wb"))
        return m

    def mac_kit(name, **extra):
        k = os.path.join(td, name)
        shutil.copytree(fx.kit_path, k)
        m = json.load(open(os.path.join(k, v3_macos27.MANIFEST)))
        m.update(extra)
        json.dump(m, open(os.path.join(k, v3_macos27.MANIFEST), "w"))
        return k

    MACARGS = ["--macos-major", "26", "--disk-free-gb", "110", "--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS,
               "--display", "1002:6810", "--apple-id", "1002:6810"]
    mkit = mac_kit("kit-mac", graphics=["nvidia", "apple"], only={"nvidia": ["NetArm2x86IOAPIC.kext"], "pc": ["-vsmcbeta"]},
                   known_27_mac=["CatalinaIntelI210Ethernet.kext", "AppleIntelCPUPowerManagement.kext"])
    mac1 = real_mac("mac1")
    rc, out = run("preflight", mac1.efi, mkit, *MACARGS)
    arm("a real Mac's own OpenCore files are accepted, said to be a Mac's, and said to be untried",
        rc == 0 and "FAIL" not in out and "are a Mac's own OpenCore files (not a 1401 build)" in out
        and "macOS 27 with this kit has not been started on a real Mac yet" in out and "NOTE graphics path: apple" in out, out)
    pcish = real_mac("pcish", smc_on=True)
    rc, out = run("preflight", pcish.efi, mkit, *MACARGS)
    arm("control: the same files with an SMC stand-in enabled are a PC's, and without 1401's mark they are refused",
        rc == 1 and "FAIL the startup files" in out, out)
    rc, out = run("stage", mac1.efi, mkit, *[a for a in MACARGS if a not in ("--disk-free-gb", "110", "--tools", TOOLS)])
    sc = plistlib.load(open(os.path.join(mac1.efi, "EFI", gg.STAGED, "config.plist"), "rb")) if rc == 0 else {"Kernel": {"Add": []}, "NVRAM": {"Add": {}}, "PlatformInfo": {"Generic": {}}}
    lim = {k["BundlePath"]: k.get("MaxKernel", "") for k in sc["Kernel"]["Add"] if k.get("Enabled")}
    args27 = " " + " ".join(v.get("boot-args", "") for v in sc["NVRAM"]["Add"].values() if isinstance(v, dict)) + " "
    arm("staging a real Mac: a limit that only reaches 27 is treated like none, so a kext nobody has run on 27 stops at 26",
        rc == 0 and lim.get("RestrictEvents.kext") == "26.99.99" and "NOTE RestrictEvents.kext was never run on macOS 27" in out, out + repr(lim))
    arm("and a kext the kit caps is capped even when the patcher had written 27.99.99 on it", lim.get("AMFIPass.kext") == "26.99.99", repr(lim))
    arm("the Mac's own hardware kexts the kit names as known on 27 keep loading", lim.get("CatalinaIntelI210Ethernet.kext") == "" and lim.get("AppleIntelCPUPowerManagement.kext") == "", repr(lim))
    arm("a limit below 27 is left exactly as it was", lim.get("OldOnly.kext") == "24.99.99", repr(lim))
    arm("what the kit marks for an NVIDIA machine is left out on other graphics, and the rest of the kit is there",
        "NetArm2x86IOAPIC.kext" not in lim and "A2XACPIPlatform.kext" in lim and "a2x_exec_hook.kext" in lim, repr(sorted(lim)))
    arm("what the kit marks for a PC is left out on a Mac, and the other kit arguments are added", " -vsmcbeta " not in args27 and " -no_compat_check " in args27, args27)
    arm("a real Mac keeps its own model, and is told so", sc["PlatformInfo"]["Generic"].get("SystemProductName") == "" and "NOTE model: this Mac's own (not changed)" in out, out)
    # 2e. kernel patches. A patch list written for macOS 26 ends at 25.99.99, and an AMD PC does not start without
    # it. Only a patch the kit names (its bytes were found in this macOS 27 kernel, in the same functions) is carried;
    # the kit's own patch stands in for one that would hit other code; anything else keeps its limit and is named.
    import kernel_patches_27 as kp27

    def kpatch(comment, find, mx="25.99.99", mn="17.0.0", on=True, **more):
        p = {"Arch": "x86_64", "Base": "", "Comment": comment, "Count": 1, "Enabled": on, "Find": find, "Identifier": "kernel", "Limit": 0,
             "Mask": b"", "MaxKernel": mx, "MinKernel": mn, "Replace": bytes(len(find)), "ReplaceMask": b"", "Skip": 0}
        p.update(more)
        return p

    known = kpatch("known | remove rdmsr", b"\x0f\x32\x90")
    loose = kpatch("loose | first match elsewhere on 27", b"\x48\x00\x0f", Mask=b"\x48\x00\xff", Count=2)
    stranger = kpatch("stranger; `rm -rf` $(x)", b"\xde\xad")
    cored = kpatch("known | cores (user value)", b"\xc1\xe8\x1a", Base="_cpuid_set_info", Replace=b"\xb8\x10\x00")
    old = kpatch("known bytes, ended before 26", b"\x0f\x32\x90", mx="24.99.99")
    off = kpatch("known bytes, switched off", b"\x0f\x32\x90", on=False)
    already = kpatch("already reaches 27", b"\x0f\x30", mx="")
    amd = fresh(td, "amd-pc")
    acp = os.path.join(amd.efi, "EFI", "OC", "config.plist")
    ac = plistlib.load(open(acp, "rb"))
    ac["Kernel"]["Patch"] = [known, loose, stranger, cored, old, off, already]
    plistlib.dump(ac, open(acp, "wb"))
    own27 = {"for": kp27.mark(loose), "patch": {"identifier": "kernel", "base": "", "comment": "NullMoth | exact | macOS 27", "count": 1, "limit": 0,
                                                 "find": "TCsPgg==", "replace": "TCtmkA==", "mask": "", "replace_mask": ""}}
    akit = mac_kit("kit-amd", patches_27=[kp27.mark(known), kp27.mark(dict(cored, Replace=b"\xb8\x08\x00"))], patches_27_own=[own27])
    AMDARGS = ["--macos-major", "26", "--gpu-id", "2D05", "--cpu-vendor", "AuthenticAMD", "--laptop", "no"]
    rc, out = run("stage", amd.efi, akit, *AMDARGS)
    sp = plistlib.load(open(os.path.join(amd.efi, "EFI", gg.STAGED, "config.plist"), "rb"))["Kernel"]["Patch"] if rc == 0 else []
    by = {p["Comment"]: p for p in sp}
    lim = lambda c: by.get(c, {}).get("MaxKernel")  # noqa: E731
    arm("an AMD PC: a kernel patch the kit names is carried to macOS 27", rc == 0 and lim("known | remove rdmsr") == "27.99.99", out + repr(sorted(by)))
    arm("the name ignores what a patch writes: the one holding the user's own core count is carried with it",
        lim("known | cores (user value)") == "27.99.99" and by["known | cores (user value)"]["Replace"] == b"\xb8\x10\x00", repr(by.get("known | cores (user value)")))
    arm("a patch whose first match on macOS 27 is in other code keeps its limit", lim("loose | first match elsewhere on 27") == "25.99.99", repr(lim("loose | first match elsewhere on 27")))
    mine = by.get("NullMoth | exact | macOS 27", {})
    arm("and the kit's own patch for it is added, for the macOS 27 kernel only, with its bytes",
        mine.get("MinKernel") == "27.0.0" and mine.get("MaxKernel") == "27.99.99" and mine.get("Find") == b"\x4c\x2b\x0f\x82"
        and mine.get("Replace") == b"\x4c\x2b\x66\x90" and mine.get("Enabled") is True and mine.get("Count") == 1 and len(sp) == 8, repr(mine))
    arm("a patch the kit does not name keeps its limit and is named in the result, with nothing of its text run",
        lim("stranger; `rm -rf` $(x)") == "25.99.99" and "1 kernel patch(es) of this PC were not checked against macOS 27 and stay off there: stranger" in out, out)
    arm("the result says how many were carried and how many replaced", "NOTE kernel patches for macOS 27: 2 carried as they are" in out and "1 replaced by the kit's own" in out, out)
    arm("a patch that ended before macOS 26, one that is switched off and one that already reaches 27 are left exactly as they were",
        lim("known bytes, ended before 26") == "24.99.99" and lim("known bytes, switched off") == "25.99.99" and by["known bytes, switched off"]["Enabled"] is False
        and lim("already reaches 27") == "", repr({c: lim(c) for c in by}))
    oc = plistlib.load(open(acp, "rb"))["Kernel"]["Patch"]
    arm("the macOS 26 startup files keep every patch as it was", oc == [known, loose, stranger, cored, old, off, already])
    amd2 = fresh(td, "amd-pc-old-kit")
    c2 = plistlib.load(open(os.path.join(amd2.efi, "EFI", "OC", "config.plist"), "rb"))
    c2["Kernel"]["Patch"] = [known]
    plistlib.dump(c2, open(os.path.join(amd2.efi, "EFI", "OC", "config.plist"), "wb"))
    oldkit = mac_kit("kit-no-patch-list")
    om = json.load(open(os.path.join(oldkit, v3_macos27.MANIFEST)))
    for key in ("patches_27", "patches_27_own"):
        om.pop(key, None)
    json.dump(om, open(os.path.join(oldkit, v3_macos27.MANIFEST), "w"))
    rc, out = run("stage", amd2.efi, oldkit, *AMDARGS)
    sp2 = plistlib.load(open(os.path.join(amd2.efi, "EFI", gg.STAGED, "config.plist"), "rb"))["Kernel"]["Patch"] if rc == 0 else [{}]
    arm("control: a kit that names no patches carries none", rc == 0 and sp2[0].get("MaxKernel") == "25.99.99" and "kernel patch" not in out, out)
    badkit = mac_kit("kit-amd-bad", patches_27=[], patches_27_own=[dict(own27, patch=dict(own27["patch"], comment='x","Enabled":false,"y":"'))])
    amd3 = fresh(td, "amd-pc-bad-kit")
    c3 = plistlib.load(open(os.path.join(amd3.efi, "EFI", "OC", "config.plist"), "rb"))
    c3["Kernel"]["Patch"] = [loose]
    plistlib.dump(c3, open(os.path.join(amd3.efi, "EFI", "OC", "config.plist"), "wb"))
    b3 = tree(amd3.efi)
    rc, out = run("stage", amd3.efi, badkit, *AMDARGS)
    arm("a kit patch with text that would break out of its field is refused and nothing is staged",
        rc == 1 and "a kit kernel patch has a field 1401 will not write" in out and tree(amd3.efi) == b3, out)
    pc2 = fresh(td, "pc-after-mac")
    rc, out = run("stage", pc2.efi, mkit, "--gpu-id", "2D05")
    pcc = plistlib.load(open(os.path.join(pc2.efi, "EFI", gg.STAGED, "config.plist"), "rb")) if rc == 0 else {"Kernel": {"Add": []}, "NVRAM": {"Add": {}}, "PlatformInfo": {"Generic": {}}}
    pargs = " " + " ".join(v.get("boot-args", "") for v in pcc["NVRAM"]["Add"].values() if isinstance(v, dict)) + " "
    arm("control: the same kit on an NVIDIA PC stages everything, with the PC's model",
        rc == 0 and any(k["BundlePath"] == "NetArm2x86IOAPIC.kext" and k.get("Enabled") for k in pcc["Kernel"]["Add"])
        and " -vsmcbeta " in pargs and pcc["PlatformInfo"]["Generic"].get("SystemProductName") not in ("", "MacPro7,1"), out)

    # 3. stage makes what the builder makes, and leaves EFI/OC alone
    a, b = fresh(td, "py"), fresh(td, "sh")
    oc_before = tree(os.path.join(b.efi, "EFI", "OC"))
    gg.stage(a.efi, a.kit_path, a.report)
    rc, out = run("stage", b.efi, b.kit_path, "--device-id", "0BDA-8922", "--gpu-id", "0000")
    arm("stage succeeds", rc == 0 and "RESULT ok" in out, out)
    arm("stage left EFI/OC byte for byte", tree(os.path.join(b.efi, "EFI", "OC")) == oc_before)
    pa, sb = (tree(os.path.join(x.efi, "EFI", gg.STAGED), parsed=True) for x in (a, b))
    diff = sorted(k for k in set(pa) | set(sb) if pa.get(k) != sb.get(k))
    arm("the staged files equal the ones 1401's builder makes from the same kit", not diff, diff)
    cfg = sb.get("config.plist", {})
    arm("and match the configuration that booted macOS 27.2",
        bool(cfg) and v3_macos27.diff_reference(cfg, b.ref, b.kit, os.path.join(b.efi, "EFI", gg.STAGED, "Kexts"), b.ref_kexts) == [],
        v3_macos27.diff_reference(cfg, b.ref, b.kit) if cfg else "no config")
    # model identity: the script and the builder give an RTX 50 the same model, and leave an RTX 30 with the kit's
    for did, want in (("2D05", "Mac17,15"), ("2504", "Mac15,14")):
        ia, ib = fresh(td, "idpy" + did), fresh(td, "idsh" + did)
        for x in (ia, ib):                                    # a PC's own serial and UUID, as every real config has
            cp = os.path.join(x.efi, "EFI", "OC", "config.plist"); c0 = plistlib.load(open(cp, "rb"))
            c0["PlatformInfo"]["Generic"].update({"SystemSerialNumber": "C02ABCDEHX87", "SystemUUID": "11111111-2222-3333-4444-555555555555"})
            plistlib.dump(c0, open(cp, "wb"))
        gg.stage(ia.efi, ia.kit_path, {"GPU": {"card": {"Manufacturer": "NVIDIA", "Device Type": "Discrete GPU", "Device ID": "10DE-" + did}}})
        run("stage", ib.efi, ib.kit_path, "--device-id", "none", "--gpu-id", did)
        ca, cb = (plistlib.load(open(os.path.join(x.efi, "EFI", gg.STAGED, "config.plist"), "rb")) for x in (ia, ib))
        arm(f"card {did}: the script and the builder agree, and the model is {want}",
            ca == cb and cb["PlatformInfo"]["Generic"]["SystemProductName"] == want, cb["PlatformInfo"]["Generic"])
        base = plistlib.load(open(os.path.join(ib.efi, "EFI", "OC", "config.plist"), "rb"))["PlatformInfo"]["Generic"]
        was, now = base.get("SystemSerialNumber"), cb["PlatformInfo"]["Generic"].get("SystemSerialNumber")
        if did == "2D05":
            arm(f"card {did}: the model changed, so the serial follows it: a new 10-character serial, the same from the script and the builder",
                bool(was) and now != was and len(now or "") == 10 and set(now) <= set(v3_macos27.SERIAL_ALPHABET)
                and now == ca["PlatformInfo"]["Generic"].get("SystemSerialNumber")
                and now == v3_macos27.serial_for_model(was, base.get("SystemUUID"), want), (was, now))
            run("cancel", ib.efi, ib.kit_path, "--confirm"); run("stage", ib.efi, ib.kit_path, "--device-id", "none", "--gpu-id", did)
            again = plistlib.load(open(os.path.join(ib.efi, "EFI", gg.STAGED, "config.plist"), "rb"))["PlatformInfo"]["Generic"].get("SystemSerialNumber")
            arm(f"card {did}: staging the same PC again gives the same serial, never a third identity", again == now, (now, again))
        else:
            arm(f"card {did}: no model is chosen for this card, so the serial is kept", bool(was) and now == was, (was, now))
    c = fresh(td, "nobt")
    run("stage", c.efi, c.kit_path, "--device-id", "8087-0026", "--gpu-id", "0000")
    arm("without a Realtek adapter the Realtek firmware kext stays out (control: with one it is in)",
        not os.path.isdir(os.path.join(c.efi, "EFI", gg.STAGED, "Kexts", "RealtekBluetoothFirmware.kext"))
        and os.path.isdir(os.path.join(b.efi, "EFI", gg.STAGED, "Kexts", "RealtekBluetoothFirmware.kext")))

    # 4. a stage that cannot finish leaves nothing behind
    d = fresh(td, "bad")
    info = os.path.join(d.efi, "EFI", "OC", "Kexts", "VirtualSMC.kext", "Contents", "Info.plist")
    p = plistlib.load(open(info, "rb"))
    p["IOKitPersonalities"]["VirtualSMC"]["IOProviderClass"] = "SomethingElse"
    plistlib.dump(p, open(info, "wb"))
    before = tree(d.efi)
    rc, out = run("stage", d.efi, d.kit_path, "--device-id", "0BDA-8922")
    arm("a kit that cannot be applied stops the stage", rc == 1 and "EFI/OC is unchanged" in out, out)
    arm("and the partition is as it was", tree(d.efi) == before)

    # 5. activate needs the confirmation; the way back needs no kit; the two tools share one partition
    original = tree(os.path.join(b.efi, "EFI", "OC"))
    staged = tree(os.path.join(b.efi, "EFI", gg.STAGED))
    mid = tree(b.efi)
    rc, out = run("activate", b.efi, b.kit_path)
    arm("activate without the confirmation refuses and changes nothing", rc == 1 and tree(b.efi) == mid, out)
    rc, out = run("activate", b.efi, b.kit_path, "--confirm")
    arm("activate with it makes the staged files the default and keeps macOS 26's",
        rc == 0 and tree(os.path.join(b.efi, "EFI", "OC")) == staged and tree(os.path.join(b.efi, "EFI", gg.KEPT)) == original, out)
    arm("the builder's tool reads the script's state", gg.read_state(b.efi)["state"] == "active")
    gg.rollback(b.efi)
    rc, out = run("status", b.efi)
    arm("the script reads the state the builder's rollback wrote", rc == 0 and "state: staged" in out, out)
    arm("rollback restored macOS 26's startup files exactly", tree(os.path.join(b.efi, "EFI", "OC")) == original)
    run("activate", b.efi, b.kit_path, "--confirm")
    rc, out = run("cancel", b.efi)
    left = tree(b.efi)
    arm("cancel from active, with no kit, puts the partition back as it was",
        rc == 0 and left == {**{os.path.join("EFI", "OC", k): v for k, v in original.items()}, ".1401-build": left.get(".1401-build")}, out)
    rc, out = run("rollback", b.efi)
    arm("rollback with nothing to roll back refuses", rc == 1, out)

    # 5b. a swap stopped between its two renames leaves no EFI/OC; the way back repairs it instead of refusing
    rc, out = run("stage", b.efi, b.kit_path, "--device-id", "0BDA-8922", "--gpu-id", "0000")
    oc_dir = os.path.join(b.efi, "EFI", "OC")
    os.rename(oc_dir, os.path.join(b.efi, "EFI", gg.KEPT))          # activate's first rename, then the run stops
    rc, out = run("cancel", b.efi)
    arm("a swap stopped after its first rename: cancel puts macOS 26's startup files back and removes the rest",
        rc == 0 and tree(oc_dir) == original and not os.path.isdir(os.path.join(b.efi, "EFI", gg.STAGED))
        and not os.path.isdir(os.path.join(b.efi, "EFI", gg.KEPT)), out)

    # 6. a partition that does not match its record is refused
    os.rename(os.path.join(c.efi, "EFI", gg.STAGED), os.path.join(c.efi, "EFI", "moved-by-hand"))
    before = tree(c.efi)
    for step in ("activate", "cancel", "finish"):
        rc, out = run(step, c.efi, c.kit_path, "--confirm", "--macos-major", "26")
        arm(f"{step} refuses a partition that does not match its record", rc == 1 and "Nothing was changed" in out and tree(c.efi) == before, out)

    # 7. finish: only with the macOS 27 files as the default, a staged driver, and from macOS 26
    e = fresh(td, "fin")
    run("stage", e.efi, e.kit_path, "--device-id", "0BDA-8922")
    rc, out = run("finish", e.efi, e.kit_path, "--macos-major", "26")
    arm("finish runs before activation too (the packages go on before the startup files are switched): staged, it gets as far as asking for the packages",
        rc == 1 and "not the default yet" not in out and "not staged yet" not in out and "carries no driver package" in out, out)
    f0 = fresh(td, "fin-none")
    rc, out = run("finish", f0.efi, f0.kit_path, "--macos-major", "26")
    arm("control: with nothing staged finish refuses and says so", rc == 1 and "the macOS 27 startup files are not staged yet (state: none)" in out, out)
    run("activate", e.efi, e.kit_path, "--confirm")
    rc, out = run("finish", e.efi, e.kit_path, "--macos-major", "27")
    arm("finish refuses from macOS 27", rc == 1 and "set up from macOS 15 or 26; this Mac runs macOS 27" in out, out)
    rc, out = run("finish", e.efi, e.kit_path, "--macos-major", "26")
    arm("finish refuses when the kit carries no driver package", rc == 1 and "carries no driver package" in out, out)

    script_text = open(SCRIPT).read()
    # 7a. finish runs the kit's system installer and then its driver installer: both dry runs first, each from the
    # private copy of the kit. The stand-in installers write one line per run to a file on the data volume they are
    # given, and refuse a run when a file named for it is there.
    FAKE = """#!/bin/bash
me=%s; mode=install; pay=; data=; sys=; esp=
while [ $# -gt 0 ]; do case "$1" in --dry-run) mode=dry;; --apply) mode=apply;; --payload) pay=$2; shift;;
  --data) data=$2; shift;; --system) sys=$2; shift;; --esp) esp=$2; shift;; *) echo "unknown $1"; exit 9;; esac; shift; done
[ -f "$pay/$(basename "$0")" ] && [ -d "$sys/System" ] && [ -d "$esp/EFI" ] || exit 8
echo "$me $mode $pay" >> "$data/Library/calls.log"
[ ! -e "$data/Library/refuse-$me-$mode" ]
"""

    def package(kit, key, folder, installer):
        os.makedirs(os.path.join(kit, folder))
        with open(os.path.join(kit, folder, installer), "w") as fh:
            fh.write(FAKE % key)
        edit(kit, lambda m: m.update({key: {"dir": folder, "installer": installer}}))

    def edit(kit, change):
        path = os.path.join(kit, v3_macos27.MANIFEST)
        m = json.load(open(path))
        change(m)
        json.dump(m, open(path, "w"))

    SYS_UUID, DATA_UUID = "11111111-AAAA-4BBB-8CCC-000000000001", "11111111-AAAA-4BBB-8CCC-000000000002"

    def volumes(name, versions=("27.2",), record=True, container="disk1", mounted=True, mountable=False):
        """A folder standing in for mounted volumes: one system volume per version given, each with its data volume.
        Beside it, the record the install step writes (the two identifiers of the first pair) and a diskutil stand-in
        that says where those two are mounted and which container they and the running system are in."""
        vols = os.path.join(td, name)
        for i, ver in enumerate(versions):
            core = os.path.join(vols, f"New{i}", "System", "Library", "CoreServices")
            os.makedirs(core)
            with open(os.path.join(core, "SystemVersion.plist"), "wb") as fh:
                plistlib.dump({"ProductVersion": ver, "ProductBuildVersion": "26B123"}, fh)
            os.makedirs(os.path.join(vols, f"New{i} - Data", "Library"))
        gg_dir = vols + ".gg"
        os.makedirs(gg_dir)
        stub = os.path.join(gg_dir, "diskutil")
        with open(stub, "w") as fh:
            fh.write(DISKUTIL_STUB)
        os.chmod(stub, 0o755)

        def info(key, **fields):
            with open(os.path.join(gg_dir, key + ".plist"), "wb") as fh:
                plistlib.dump(fields, fh)
        info("root", APFSContainerReference="disk1", FilesystemType="apfs", MountPoint="/")
        for uuid, dev, mp in ((SYS_UUID, "disk1s5", os.path.join(vols, "New0")), (DATA_UUID, "disk1s6", os.path.join(vols, "New0 - Data"))):
            fields = dict(APFSContainerReference=container, FilesystemType="apfs", VolumeUUID=uuid, MountPoint=mp if mounted else "")
            info(uuid, **fields)
            info(dev, **fields)
            if mountable:      # what diskutil answers once the volume is mounted
                info(uuid + ".mounted", **dict(fields, MountPoint=mp))
        if record:
            with open(os.path.join(gg_dir, "macos27-volumes"), "w") as fh:
                fh.write(f"system {SYS_UUID}\ndata {DATA_UUID}\n")
        v = Vols(vols)
        v.args = ("--step-log", os.path.join(gg_dir, "steps.log"), "--diskutil", stub)
        v.gg = gg_dir
        return v

    def calls(vols):
        try:
            return [ln.split() for ln in open(os.path.join(vols, "New0 - Data", "Library", "calls.log")).read().splitlines()]
        except OSError:
            return []

    def active(name, system=True, driver=True):
        f = fresh(td, name)
        if driver:
            package(f.kit_path, "driver", "driver", "install-macos27.sh")
        if system:
            package(f.kit_path, "system", "system", "install-system.sh")
        run("stage", f.efi, f.kit_path, "--device-id", "0BDA-8922")
        rc, out = run("activate", f.efi, f.kit_path, "--confirm")
        assert rc == 0, out
        return f

    FIN = ["--macos-major", "26", "--volumes"]
    g = active("fin-both")
    arm("stage records the system package and does not copy it to the startup partition",
        json.load(open(os.path.join(g.efi, "EFI", gg.STATE)))["system"] == "in the kit with its installer install-system.sh"
        and not any("install-system.sh" in p for p in tree(g.efi)), tree(g.efi).keys())
    arm("stage records the driver package too and copies it nowhere: its size is not counted against the partition",
        json.load(open(os.path.join(g.efi, "EFI", gg.STATE)))["driver"] == "in the kit with its installer install-macos27.sh"
        and not os.path.lexists(os.path.join(g.efi, gg.DRIVER)) and not any("install-macos27.sh" in p for p in tree(g.efi))
        and "drv" not in script_text[script_text.index("stage_need_kb() {"):script_text.index("free_kb() {")]
        and 'cp -R "$KIT/$ddir"' not in script_text, tree(g.efi).keys())
    # 7a0. a macOS 27 volume that ignores file owners: switched on before anything is written, or the step stops
    def owners_off(vols, fixable):
        for uuid in (DATA_UUID,):
            p = os.path.join(vols.gg, uuid + ".plist")
            f = plistlib.load(open(p, "rb"))
            if fixable:
                plistlib.dump(dict(f, GlobalPermissionsEnabled=True), open(os.path.join(vols.gg, uuid + ".owned.plist"), "wb"))
            plistlib.dump(dict(f, GlobalPermissionsEnabled=False), open(p, "wb"))

    gown = active("fin-owners")
    vown = volumes("vols-owners-fixed")
    owners_off(vown, True)
    rc, out = run("finish", gown.efi, gown.kit_path, *FIN, vown)
    dc = open(os.path.join(vown.gg, "disk-calls.log")).read() if os.path.exists(os.path.join(vown.gg, "disk-calls.log")) else ""
    arm("a data volume that ignores file owners has them switched on before the installers run, and the result says so",
        rc == 0 and f"owners {DATA_UUID}" in dc and f"owners {SYS_UUID}" not in dc and "file owners were switched off on" in out
        and out.index("file owners were switched off") < out.index("Checking the macOS 27 system install"), out + dc)
    gown2 = active("fin-owners-stuck")
    vown2 = volumes("vols-owners-stuck")
    owners_off(vown2, False)
    b4 = tree(gown2.efi)
    rc, out = run("finish", gown2.efi, gown2.kit_path, *FIN, vown2)
    arm("when owners cannot be switched on the step stops before any installer runs and gives the command",
        rc == 1 and "ignores file owners and that could not be changed" in out and "sudo diskutil enableOwnership" in out
        and calls(vown2) == [] and tree(gown2.efi) == b4, out + repr(calls(vown2)))
    vols = volumes("vols-both")
    before = tree(g.efi)
    rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
    got = calls(vols)
    arm("finish runs system dry run, driver dry run, then each again with --apply, system first",
        rc == 0 and [c[:2] for c in got] == [["system", "dry"], ["driver", "dry"], ["system", "apply"], ["driver", "apply"]]
        and "RESULT ok" in out and tree(g.efi) == before, out + repr(got))
    arm("each installer gets its own package folder as --payload, from the private copy and never from the kit folder or the startup partition",
        len(got) == 4 and [os.path.basename(c[2]) for c in got] == ["system", "driver", "system", "driver"]
        and all(not c[2].startswith(g.kit_path) and not c[2].startswith(g.efi) and not os.path.exists(c[2]) for c in got), got)
    for name, refuse, want, word in (
            ("the system dry run refuses: nothing else is run", "refuse-system-dry", [["system", "dry"]], "system installer refused its dry run. Nothing was changed"),
            ("the driver dry run refuses: neither installer makes a change", "refuse-driver-dry", [["system", "dry"], ["driver", "dry"]],
             "driver installer refused its dry run. Nothing was changed"),
            ("the system installer stops: the driver installer is never run", "refuse-system-apply",
             [["system", "dry"], ["driver", "dry"], ["system", "apply"]], "The driver was not installed")):
        vols = volumes("vols-" + refuse)
        open(os.path.join(vols, "New0 - Data", "Library", refuse), "w").close()
        rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
        arm(f"finish, {name}", rc == 1 and [c[:2] for c in calls(vols)] == want and word in out and "RESULT stop" in out, out + repr(calls(vols)))
    # macOS 27 is found by the record the install step wrote, never by what is mounted: a volume that only says it is
    # macOS 27 (a mounted disk image, a volume someone attached) is not taken, whatever it holds
    for name, kw, word in (
            ("there is no record (macOS 27 was not laid down by this app), though a volume that says 27 is mounted", dict(record=False), "there is no record of its volumes"),
            ("the recorded volumes are in another container than the running system's (a disk image)", dict(container="disk9"), "are not APFS volumes on the disk this macOS runs from"),
            ("the recorded volumes are not mounted", dict(mounted=False), "is not mounted (mount it in Disk Utility)")):
        vols = volumes("vols-rec%d" % len(word), **kw)
        rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
        arm(f"finish refuses when {name}, before any installer is run",
            rc == 1 and word in out and "Nothing was changed" in out and calls(vols) == [], out)
    # The lay-down leaves both volumes unmounted. The first real upgrade stopped here ("not mounted"), and a second
    # run took the finished lay-down for none. finish and the "already laid down" check mount the two recorded volumes.
    vols = volumes("vols-unmounted", mounted=False, mountable=True)
    rc, out = run("laid", g.efi, g.kit_path, vols)
    arm("a finished lay-down whose volumes are unmounted is still found (control: unmountable ones are not, above)",
        rc == 0 and "macOS 27 is already on its own volumes" in out, out)
    vols = volumes("vols-unmounted2", mounted=False, mountable=True)
    rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
    arm("finish mounts the recorded volumes itself and runs all four installers", rc == 0 and len(calls(vols)) == 4, out + repr(calls(vols)))
    vols = volumes("vols-two", versions=("27.2", "27.2"))
    rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
    arm("with a second volume that says macOS 27 mounted beside the recorded one, only the recorded one is used",
        rc == 0 and len(calls(vols)) == 4 and not os.path.exists(os.path.join(vols, "New1 - Data", "Library", "calls.log")), out)
    vols = volumes("vols-notours")
    with open(os.path.join(vols.gg, "macos27-volumes"), "w") as fh:
        fh.write("system ../../etc\ndata x\n")
    rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
    arm("a record that is not two volume identifiers is refused", rc == 1 and "is not one this app wrote" in out and calls(vols) == [], out)
    vols = volumes("vols-old", versions=("26.7",))
    rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
    arm("a recorded volume that does not hold macOS 27 is refused", rc == 1 and "does not hold macOS 27" in out and calls(vols) == [], out)
    # --- preflight on a Mac where macOS 27 is already laid down (an update to a newer release of this app) ---
    # The first such PC was refused "51 GB free, 67 GB needed" for download room it would never use.
    def pre_calls(vols):
        log = os.path.join(vols.gg, "disk-calls.log")
        return [ln.split() for ln in open(log).read().splitlines()] if os.path.exists(log) else []

    pf = fresh(td, "pre-room")
    LOW = ["--macos-major", "26", "--gpu-id", "2D05", "--cpu-vendor", "GenuineIntel", "--laptop", "no", "--tools", TOOLS, "--disk-free-gb", "51"]
    vols = volumes("pre-laid")
    rc, out = run("preflight", pf.efi, pf.kit_path, *LOW, vols)
    arm("with macOS 27 already on its recorded volumes, 51 GB free is not refused for room, and the line says why",
        rc == 0 and "OK room for macOS 27: macOS 27 is already on its own volumes, so no download room is needed (51 GB free)" in out
        and "FAIL" not in out and pre_calls(vols) == [], out + repr(pre_calls(vols)))
    vols = volumes("pre-laid-unmounted", mounted=False, mountable=True)
    for uuid in (SYS_UUID, DATA_UUID):
        shutil.copy(os.path.join(vols.gg, uuid + ".plist"), os.path.join(vols.gg, uuid + ".unmounted.plist"))
    rc, out = run("preflight", pf.efi, pf.kit_path, *LOW, vols)
    arm("with the laid-down volumes unmounted, preflight mounts them to read the version, passes, and unmounts both again",
        rc == 0 and "macOS 27 is already on its own volumes" in out and "FAIL" not in out
        and pre_calls(vols) == [["release", SYS_UUID], ["release", DATA_UUID]]
        and plistlib.load(open(os.path.join(vols.gg, SYS_UUID + ".plist"), "rb"))["MountPoint"] == ""
        and plistlib.load(open(os.path.join(vols.gg, DATA_UUID + ".plist"), "rb"))["MountPoint"] == "", out + repr(pre_calls(vols)))
    vols = volumes("pre-none", record=False)
    rc, out = run("preflight", pf.efi, pf.kit_path, *LOW, vols)
    arm("with no record of laid-down volumes and 51 GB free, preflight still refuses for room (control)",
        rc == 1 and "FAIL room for macOS 27: 51 GB free, 92 GB needed" in out and out.count("FAIL ") == 1, out)
    vols = volumes("pre-old", versions=("26.7",))
    rc, out = run("preflight", pf.efi, pf.kit_path, *LOW, vols)
    arm("with recorded volumes that hold macOS 26, not 27, preflight still refuses for room",
        rc == 1 and "FAIL room for macOS 27: 51 GB free, 92 GB needed" in out and "already on its own volumes" not in out and out.count("FAIL ") == 1, out)
    vols = volumes("pre-unmountable", mounted=False, mountable=False)
    rc, out = run("preflight", pf.efi, pf.kit_path, *LOW, vols)
    arm("when the recorded volumes cannot be mounted to read, it is undecided and preflight falls back to the room refusal",
        rc == 1 and "FAIL room for macOS 27: 51 GB free, 92 GB needed" in out and out.count("FAIL ") == 1, out)
    vols = volumes("pre-roomy")
    rc, out = run("preflight", pf.efi, pf.kit_path, *LOW[:-1], "110", vols)
    arm("with room to spare the volumes are not asked about and the room line is the usual one",
        rc == 0 and "OK room for macOS 27: 110 GB free, 92 GB needed" in out and pre_calls(vols) == [], out)
    # --- Remove macOS 27: the startup files go back and the two recorded volumes are taken away, nothing else ---
    GROUP = DATA_UUID

    def disk_calls(vols):
        try:
            return [ln.split() for ln in open(os.path.join(vols.gg, "disk-calls.log")).read().splitlines()]
        except OSError:
            return []

    def more_info(vols, key, **fields):
        path = os.path.join(vols.gg, key + ".plist")
        with open(path, "rb") as fh:
            d = plistlib.load(fh)
        d.update(fields)
        with open(path, "wb") as fh:
            plistlib.dump(d, fh)

    def removable(name, **kw):
        f = fresh(td, "rm-" + name)
        f.before = tree(f.efi)
        package(f.kit_path, "driver", "driver", "install-macos27.sh")
        package(f.kit_path, "system", "system", "install-system.sh")
        run("stage", f.efi, f.kit_path, "--device-id", "0BDA-8922")
        rc, out = run("activate", f.efi, f.kit_path, "--confirm")
        assert rc == 0, out
        f.active = tree(f.efi)
        vols = volumes("vols-rm-" + name, **kw)
        for u in (SYS_UUID, DATA_UUID):
            more_info(vols, u, APFSVolumeGroupID=GROUP)
        f.pre = os.path.join(td, "preboot-" + name)
        os.makedirs(os.path.join(f.pre, GROUP, "boot"))
        os.makedirs(os.path.join(f.pre, "22222222-AAAA-4BBB-8CCC-000000000009"))
        f.lay = os.path.join(td, "lay-" + name)
        os.makedirs(f.lay, mode=0o700)
        f.opts = ["--macos-major", "26", "--preboot", f.pre, "--lay-work", f.lay, "--kc-work", os.path.join(td, "kc-" + name), vols]
        return f, vols

    BOTH = [["unmount", SYS_UUID], ["delete", SYS_UUID], ["unmount", DATA_UUID], ["delete", DATA_UUID]]
    f, vols = removable("ok")
    rc, out = run("remove", f.efi, "", *f.opts)
    arm("remove without the user's yes changes nothing: startup files, volumes and record are as they were",
        rc == 1 and "only with --confirm" in out and tree(f.efi) == f.active and disk_calls(vols) == []
        and os.path.exists(os.path.join(vols.gg, "macos27-volumes")), out)
    rc, out = run("remove", f.efi, "", "--confirm", *f.opts)
    arm("remove puts the startup partition back as it was before Golden Gate and takes exactly the two recorded volumes away",
        rc == 0 and "RESULT ok" in out and tree(f.efi) == f.before and disk_calls(vols) == BOTH
        and not os.path.exists(os.path.join(vols.gg, "macos27-volumes")), out + repr(disk_calls(vols)))
    arm("remove takes the removed system's Preboot folder and leaves every other one",
        not os.path.exists(os.path.join(f.pre, GROUP)) and os.path.isdir(os.path.join(f.pre, "22222222-AAAA-4BBB-8CCC-000000000009")), os.listdir(f.pre))
    rc, out = run("remove", f.efi, "", "--confirm", *f.opts)
    arm("remove a second time finds nothing to do and removes nothing", rc == 0 and "no volume was removed" in out and disk_calls(vols) == BOTH, out)

    def refused(name, word, prep, **kw):
        f, vols = removable(name, **kw)
        prep(f, vols)
        rc, out = run("remove", f.efi, "", "--confirm", *f.opts)
        arm(f"remove refuses when {name}: no volume is removed and the startup files are not touched",
            rc == 1 and word in out and "Nothing was changed" in out and disk_calls(vols) == [] and tree(f.efi) == f.active
            and os.path.isdir(os.path.join(f.pre, GROUP)), out + repr(disk_calls(vols)))

    refused("a recorded volume is on another disk than the running macOS", "is not an APFS volume on the disk this macOS runs from", lambda f, v: None, container="disk9")
    refused("a recorded volume is in the volume group of the macOS that is running", "belongs to the macOS that is running",
            lambda f, v: more_info(v, "root", APFSVolumeGroupID=GROUP))
    refused("a recorded volume is the one the running macOS started from", "is one of the macOS that is running",
            lambda f, v: more_info(v, "root", VolumeUUID=SYS_UUID.lower()))
    refused("a recorded volume is mounted as part of the running macOS", "is in use by the macOS that is running",
            lambda f, v: more_info(v, DATA_UUID, MountPoint="/System/Volumes/Data"))
    refused("the record is not two volume identifiers", "is not one this app wrote",
            lambda f, v: open(os.path.join(v.gg, "macos27-volumes"), "w").write("system /\ndata disk1s1\n"))
    f, vols = removable("major27")
    rc, out = run("remove", f.efi, "", "--confirm", *[o if o != "26" else "27" for o in f.opts])
    arm("remove is refused on macOS 27 itself", rc == 1 and "this Mac runs macOS 27" in out and disk_calls(vols) == [] and tree(f.efi) == f.active, out)
    f, vols = removable("norecord", record=False)
    rc, out = run("remove", f.efi, "", "--confirm", *f.opts)
    arm("remove with no record of volumes puts the startup files back and removes no volume, whatever is mounted",
        rc == 0 and "no volume was removed" in out and tree(f.efi) == f.before and disk_calls(vols) == [] and os.path.isdir(os.path.join(f.pre, GROUP)), out)
    f, vols = removable("delete-fails")
    open(os.path.join(vols.gg, "refuse-delete"), "w").close()
    rc, out = run("remove", f.efi, "", "--confirm", *f.opts)
    arm("when a volume cannot be removed remove stops there, says so, and keeps the record for the next try",
        rc == 1 and "could not be removed" in out and disk_calls(vols) == BOTH[:2] and os.path.exists(os.path.join(vols.gg, "macos27-volumes")), out)
    f, vols = removable("gone")
    for u in (SYS_UUID, DATA_UUID):
        os.remove(os.path.join(vols.gg, u + ".plist"))
    rc, out = run("remove", f.efi, "", "--confirm", *f.opts)
    arm("recorded volumes that are already gone: the record is removed and nothing is deleted",
        rc == 0 and "already gone" in out and disk_calls(vols) == [] and not os.path.exists(os.path.join(vols.gg, "macos27-volumes")), out)
    f, vols = removable("cutoff", record=False)
    with open(os.path.join(f.lay, "volumes.created"), "w") as fh:
        fh.write(f"name macOS 27\ncontainer disk1\ndata disk1s6 {DATA_UUID}\n")
    rc, out = run("clear-downloads", f.efi, "", "--confirm", *f.opts)
    arm("clearing the downloads is refused while a cut-off lay-down's volumes are still on the disk (its record is in that folder)",
        rc == 1 and "Press Remove macOS 27 first" in out and os.path.exists(os.path.join(f.lay, "volumes.created")), out)
    rc, out = run("remove", f.efi, "", "--confirm", *f.opts)
    arm("a lay-down that was cut off before its record: remove takes the one volume the lay-down wrote down, and that record",
        rc == 0 and disk_calls(vols) == BOTH[2:] and not os.path.exists(os.path.join(f.lay, "volumes.created")) and tree(f.efi) == f.before, out + repr(disk_calls(vols)))

    # --- what is kept downloaded: shown, and cleared only on the user's yes ---
    f, vols = removable("dl")
    kc = f.opts[f.opts.index("--kc-work") + 1]
    os.makedirs(kc, mode=0o700)
    with open(os.path.join(f.lay, "UniversalMac_27.2_26B123_Restore.ipsw"), "wb") as fh:
        fh.write(b"\0" * 2_000_000)
    with open(os.path.join(kc, "BootKernelExtensions.kc"), "wb") as fh:
        fh.write(b"\0" * 1_000_000)
    outside = os.path.join(td, "outside-dl")
    os.makedirs(outside)
    open(os.path.join(outside, "keep"), "w").write("x" * 5000)
    os.symlink(outside, os.path.join(f.lay, "link"))
    rc, out = run("downloads", f.efi, "", *f.opts)
    shown = os.path.join(vols.gg, "downloads")
    arm("downloads says what is kept, writes the figure where the app can read it, follows no link and leaves the step log alone",
        rc == 0 and "kept from an earlier try" in out and open(shown).read() == "bytes 3000000\n" and os.stat(shown).st_mode & 0o777 == 0o644
        and not os.path.exists(os.path.join(vols.gg, "steps.log")), out)
    rc, out = run("clear-downloads", f.efi, "", *f.opts)
    arm("clear-downloads without the user's yes removes nothing", rc == 1 and "only with --confirm" in out and len(os.listdir(f.lay)) == 2 and os.path.isdir(kc), out)
    rc, out = run("clear-downloads", f.efi, "", "--confirm", *f.opts)
    arm("clear-downloads removes both folders, nothing a link in them names, and the figure shown goes to zero",
        rc == 0 and not os.path.exists(f.lay) and not os.path.exists(kc) and os.path.exists(os.path.join(outside, "keep"))
        and open(shown).read() == "bytes 0\n" and tree(f.efi) == f.active and disk_calls(vols) == [], out)
    os.symlink(outside, f.lay)
    rc, out = run("clear-downloads", f.efi, "", "--confirm", *f.opts)
    arm("a link standing where the downloads folder should be is refused and what it names is untouched",
        rc == 1 and "is not a folder of its own" in out and os.path.exists(os.path.join(outside, "keep")), out)
    os.remove(f.lay)
    g = active("fin-nosys", system=False)
    vols = volumes("vols-nosys")
    rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
    arm("finish refuses a kit with a driver package and no system package, and runs neither (control: with both it ran four)",
        rc == 1 and "carries no system package. Nothing was changed" in out and calls(vols) == [], out)
    for name, entry in (("names a folder outside the kit", {"dir": "../system", "installer": "install-system.sh"}),
                        ("names an installer in a sub-folder", {"dir": "system", "installer": "sub/install-system.sh"}),
                        ("names an installer that is not there", {"dir": "system", "installer": "missing.sh"})):
        g = active("fin" + str(abs(hash(name))))
        edit(g.kit_path, lambda m, entry=entry: m.update({"system": entry}))
        vols = volumes("vols" + str(abs(hash(name))))
        rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
        arm(f"finish refuses a kit whose system entry {name}", rc == 1 and "carries no system package" in out and calls(vols) == [], out)
        s = fresh(td, "stg" + str(abs(hash(name))))
        package(s.kit_path, "system", "system", "install-system.sh")
        edit(s.kit_path, lambda m, entry=entry: m.update({"system": entry}))
        before = tree(s.efi)
        rc, out = run("stage", s.efi, s.kit_path, "--device-id", "0BDA-8922")
        arm(f"stage refuses a kit whose system entry {name}, and leaves the partition as it was",
            rc == 1 and "system" in out and "EFI/OC is unchanged" in out and tree(s.efi) == before, out)

    # 7d. the install step lays macOS 27 down with the kit's script: its dry run first, then the real run; the new
    # system starts at Apple's setup unless an account is named. The kernel collections step refuses while the kit
    # has no maker. The stand-ins write the arguments they were given to a file named by the test.
    LAY = """#!/bin/bash
echo "%s $*" >> "$GG_TEST_LOG"
case " $* " in *" --dry-run "*) m=dry;; *" --apply "*) m=apply;; *) m=other;; esac
[ ! -e "$GG_TEST_LOG.system-$m" ] || { echo "SYSTEM: this macOS has no aea that opens the restore image"; exit 3; }
[ ! -e "$GG_TEST_LOG.refuse-$m" ] || exit 1
[ $m != apply ] || echo "OK   macOS 27.2 (26B123) is on 'macOS 27' (disk1s5) with data volume 'macOS 27 - Data' (disk1s6), group 11111111-AAAA-4BBB-8CCC-000000000002"
"""
    MAKER = """#!/bin/bash
echo "maker $*" >> "$GG_TEST_LOG"
[ ! -e "$GG_TEST_LOG.system-maker" ] || { echo "SYSTEM: bspatch on this macOS is not the one the collections are made with"; exit 3; }
case " $* " in *" --apply "*) echo "PLAN kdk-download:40 kdk-unpack:20 collections:40"; echo "PROGRESS kdk-download 50 625000000 1250000000"; echo "PROGRESS collections 100";; esac
case " $* " in *" --apply "*) [ "$1" = --out ] && echo boot > "$2/BootKernelExtensions.kc" && echo sys > "$2/SystemKernelExtensions.kc";; esac
[ ! -e "$GG_TEST_LOG.refuse-maker" ]
"""

    def lay_kit(name, maker=False, laydown=True):
        f = fresh(td, name)
        if laydown:
            os.makedirs(os.path.join(f.kit_path, "laydown"))
            with open(os.path.join(f.kit_path, "laydown", "lay-down-27.sh"), "w") as fh:
                fh.write(LAY % "laydown")
            if maker:
                with open(os.path.join(f.kit_path, "laydown", "make-kernel-collections.sh"), "w") as fh:
                    fh.write(MAKER)
            edit(f.kit_path, lambda m: m.update({"laydown": {"dir": "laydown", "installer": "lay-down-27.sh"}}))
        return f

    LAYVOLS = {}

    def layvols(f):
        """The volumes a fixture's lay-down "makes": there from the start, recorded only by the install step."""
        key = os.path.basename(os.path.dirname(f.efi))
        if key not in LAYVOLS:
            LAYVOLS[key] = volumes("layvols-" + key, record=False)
        return LAYVOLS[key]

    def lay(f, step, *more):
        log = os.path.join(td, "lay.log")
        for p in (log,):
            if os.path.exists(p):
                os.remove(p)
        os.environ["GG_TEST_LOG"] = log
        try:
            rc, out = run(step, "", f.kit_path, "--macos-major", "26", "--kc-work", os.path.join(td, "kc-" + os.path.basename(os.path.dirname(f.efi))), layvols(f), *more)
        finally:
            del os.environ["GG_TEST_LOG"]
        return rc, out, (open(log).read().splitlines() if os.path.exists(log) else [])

    f = lay_kit("lay-a")
    rc, out, got = lay(f, "installer")
    arm("install: the lay-down script's dry run goes first, then its real run; by default the new system gets no account (it starts at Apple's setup)",
        rc == 0 and got == ["laydown --no-user --dry-run", "laydown --no-user --apply"] and "RESULT ok" in out
        and "NOTE this kit cannot make kernel collections" in out, out + repr(got))
    rc, out, got = lay(f, "installer", "--bring-account", "pat")
    arm("install with an account to bring over passes it on", rc == 0 and got == ["laydown --user pat --dry-run", "laydown --user pat --apply"], out + repr(got))
    for size, quota in (("40", "20"), ("256", "236")):
        rc, out, got = lay(f, "installer", "--size-gb", size)
        arm(f"install with a size of {size} GB gives the lay-down a limit of {quota} GB for the data volume (the system's 20 GB taken off)",
            rc == 0 and got == [f"laydown --no-user --data-quota-gb {quota} --dry-run", f"laydown --no-user --data-quota-gb {quota} --apply"], out + repr(got))
    for size in ("39", "5000", "64g", "-1", "6 4"):
        rc, out, got = lay(f, "installer", "--size-gb", size)
        arm(f"install refuses the size {size!r} and runs nothing", rc == 1 and got == [] and "Nothing was changed" in out, out + repr(got))
    rc, out, got = lay(f, "installer", "--bring-account", "a b;c")
    arm("install refuses an account name it will not pass on, and runs nothing", rc == 1 and got == [] and "Nothing was changed" in out, out)
    open(os.path.join(td, "lay.log.refuse-dry"), "w").close()
    rc, out, got = lay(f, "installer")
    os.remove(os.path.join(td, "lay.log.refuse-dry"))
    arm("install: when the dry run refuses, the real run is never made", rc == 1 and got == ["laydown --no-user --dry-run"]
        and "the lay-down step refused its dry run. Nothing was changed" in out, out + repr(got))
    # Preflight on a Mac where macOS 27 is already laid down: the lay-down's dry run refuses on the volumes the
    # lay-down itself made, which stopped the first such PC one line after the room check let it through.
    fl = lay_kit("lay-pre"); prelog = os.path.join(td, "lay-pre.log"); os.environ["GG_TEST_LOG"] = prelog
    vols = volumes("pre-laid-dry")
    rc, out = run("preflight", fl.efi, fl.kit_path, *LOW, vols)
    arm("with macOS 27 already laid down, the lay-down step's dry run is not asked and the check passes",
        rc == 0 and "OK macOS 27 is already laid down, so the lay-down step is not asked" in out and "Asking the lay-down step" not in out
        and not os.path.exists(prelog), out)
    vols = volumes("pre-none-dry", record=False)
    rc, out = run("preflight", fl.efi, fl.kit_path, *LOW[:-1], "110", vols)
    arm("with no macOS 27 laid down, the lay-down step's dry run is still asked (control)",
        rc == 0 and "Asking the lay-down step whether it can run here (dry run)" in out and "is not asked" not in out
        and open(prelog).read().splitlines() == ["laydown --no-user --dry-run"], out)
    os.environ["GG_TEST_LOG"] = os.path.join(td, "lay.log")
    rc, out = run("installer", "", f.kit_path, "--macos-major", "27")
    del os.environ["GG_TEST_LOG"]
    arm("install refuses from macOS 27", rc == 1 and "macOS 27 is laid down from macOS 15 or 26; this Mac runs macOS 27" in out, out)
    f0 = lay_kit("lay-none", laydown=False)
    for step in ("installer", "collections"):
        rc, out, got = lay(f0, step)
        arm(f"{step} refuses a kit with no lay-down step and runs nothing", rc == 1 and "carries no lay-down step. Nothing was changed" in out and got == [], out)
    rc, out, got = lay(f, "collections")
    arm("kernel collections: a kit without the maker is refused cleanly, and nothing is run",
        rc == 1 and "this v3 kit cannot make the Intel kernel collections for macOS 27 yet. Nothing was changed" in out and got == [], out)
    fm = lay_kit("lay-m", maker=True)
    rc, out, got = lay(fm, "collections")
    kc = os.path.join(td, "kc-" + os.path.basename(os.path.dirname(fm.efi)))
    arm("kernel collections: with the maker in the kit, its dry run goes first and then its real run, into a folder made for it; both collections must be there afterwards",
        rc == 0 and got == [f"maker --out {kc} --dry-run", f"maker --out {kc} --apply"] and os.path.isfile(os.path.join(kc, "BootKernelExtensions.kc"))
        and oct(os.stat(kc).st_mode & 0o777) == "0o755", out + repr(got))
    barlines = ["PLAN kdk-download:40 kdk-unpack:20 collections:40", "PROGRESS kdk-download 50 625000000 1250000000", "PROGRESS collections 100"]
    fmlog = open(os.path.join(layvols(fm).gg, "steps.log")).read().splitlines()
    arm("the kit script's plan and progress lines pass through unchanged, in order, to the output and to the step log",
        [l for l in out.splitlines() if l.startswith(("PLAN", "PROGRESS"))] == barlines
        and [l for l in fmlog if l.startswith(("PLAN", "PROGRESS"))] == barlines and "\r" not in out, out)
    fm2 = lay_kit("lay-m2", maker=True)
    rc, out, got = lay(fm2, "installer")
    arm("install refuses while the kit can make the kernel collections and they have not been made, and lays nothing down",
        rc == 1 and got == [] and "the kernel collections have not been made yet: make them first" in out and "Nothing was changed" in out, out)
    open(os.path.join(td, "lay.log.refuse-maker"), "w").close()
    rc, out, got = lay(fm2, "collections")
    os.remove(os.path.join(td, "lay.log.refuse-maker"))
    arm("kernel collections: when the maker's dry run refuses, its real run is never made",
        rc == 1 and len(got) == 1 and got[0].endswith("--dry-run") and "refused its dry run. Nothing was changed" in out, out + repr(got))
    rc, out, got = lay(fm, "installer")
    arm("install then hands the lay-down script the folder with the kernel collections",
        rc == 0 and got == [f"laydown --no-user --kernel-collections {kc} --dry-run", f"laydown --no-user --kernel-collections {kc} --apply"]
        and "kernel collections" not in out.replace("--kernel-collections", ""), out + repr(got))
    # the install step records the two volumes it made; the next step finds macOS 27 through that record
    lv = layvols(f)
    rec = open(os.path.join(lv.gg, "macos27-volumes")).read() if os.path.exists(os.path.join(lv.gg, "macos27-volumes")) else ""
    arm("install records the identifiers of the two volumes the lay-down made, read back through diskutil from its last line",
        rec == f"system {SYS_UUID}\ndata {DATA_UUID}\n", rec)
    copy = os.path.join(lv, "New0 - Data", "Library", "NullMoth", "golden-gate", "laydown.log")
    lay_log = os.path.join(lv.gg, "laydown.log")
    arm("install keeps the lay-down's own lines in laydown.log beside the step log, and a copy on the new data volume",
        os.path.isfile(lay_log) and os.path.isfile(copy) and open(lay_log).read() == open(copy).read() and "is on 'macOS 27' (disk1s5)" in open(copy).read()
        and oct(os.stat(os.path.dirname(copy)).st_mode & 0o777) == "0o755", lay_log)
    # every step's lines also go to the step log, which is kept under 1 MB
    slog = os.path.join(lv.gg, "steps.log")
    text1 = open(slog).read() if os.path.exists(slog) else ""
    arm("a step's lines are also appended to the step log, under a line that names the step and the time",
        "STEP Laying macOS 27 down" in text1 and "OK macOS 27 is on its own volumes" in text1 and text1.startswith("== 20") and " installer\n" in text1, text1[-600:])
    rc, out, got = lay(f, "collections")
    text2 = open(slog).read()
    arm("the next step appends to the same log, and a step that stops leaves its reason there",
        text2.startswith(text1) and "collections\n" in text2[len(text1):] and "STOP this v3 kit cannot make the Intel kernel collections" in text2[len(text1):], text2[len(text1):])
    with open(slog, "w") as fh:
        fh.write("old line\n" * 150000)
    lay(f, "collections")
    arm("the step log is bounded: past 1 MB the older half is dropped before a step writes (control: it was 1.35 MB)",
        600000 > os.path.getsize(slog) > 500000 and "collections" in open(slog).read()[-400:], os.path.getsize(slog))
    # a root write onto the new data volume goes nowhere a link points: each planted link is refused, nothing is
    # written through it, and the lay-down's log stays where it is beside the step log
    outside = os.path.join(td, "outside-target")
    os.makedirs(outside)
    for name, plant in (("Library is a link", lambda d: (os.rmdir(os.path.join(d, "Library")), os.symlink(outside, os.path.join(d, "Library")))),
                        ("NullMoth is a link", lambda d: os.symlink(outside, os.path.join(d, "Library", "NullMoth"))),
                        ("the destination file is a link", lambda d: (os.makedirs(os.path.join(d, "Library", "NullMoth", "golden-gate")),
                                                                     os.symlink(os.path.join(outside, "victim"), os.path.join(d, "Library", "NullMoth", "golden-gate", "laydown.log"))))):
        fl = lay_kit("lay-link" + str(abs(hash(name))))
        plant(os.path.join(layvols(fl), "New0 - Data"))
        rc, out, got = lay(fl, "installer")
        arm(f"the copy onto the new data volume, {name}: nothing is written through the link, and the step says where the log is",
            rc == 0 and os.listdir(outside) == [] and "could not be copied onto the new data volume" in out, out + repr(os.listdir(outside)))
    # the folder with the kernel collections must be root's all the way up, and hold the two files the step recorded
    fk = lay_kit("lay-kc", maker=True)
    kck = os.path.join(td, "kc-" + os.path.basename(os.path.dirname(fk.efi)))
    rc, out, got = lay(fk, "collections")
    sums = os.path.join(layvols(fk).gg, "kernel-collections.sha256")
    arm("the collections step records the checksums of the two files it made", rc == 0 and os.path.isfile(sums) and open(sums).read().count("KernelExtensions.kc") == 2, out)
    with open(os.path.join(kck, "BootKernelExtensions.kc"), "w") as fh:
        fh.write("swapped\n")
    rc, out, got = lay(fk, "installer")
    arm("install refuses collections that are not the recorded ones (one file was swapped since), and lays nothing down",
        rc == 1 and got == [] and "are not the ones the collections step made" in out and "Nothing was changed" in out, out)
    lay(fk, "collections")
    os.chmod(kck, 0o777)
    rc, out, got = lay(fk, "installer")
    os.chmod(kck, 0o755)
    arm("install refuses a collections folder that others can write, and lays nothing down (control: the same folder passes once it is root's alone)",
        rc == 1 and got == [] and "is not one only root can write" in out and lay(fk, "installer")[0] == 0, out)
    fp = lay_kit("lay-planted", maker=True)
    kcp = os.path.join(td, "kc-" + os.path.basename(os.path.dirname(fp.efi)))
    os.makedirs(kcp)
    os.chmod(kcp, 0o777)
    rc, out, got = lay(fp, "collections")
    arm("the collections step refuses a folder someone else made writable for everyone before it ran, and makes nothing in it",
        rc == 1 and got == [] and "is not one only root can write" in out and os.listdir(kcp) == [], out)
    os.chmod(kcp, 0o755)
    # a kit script that stops for a reason tied to the running macOS (exit 3, "SYSTEM: ...") is said in the fixed sentence
    for step, flag, fx_kit in (("installer", "system-dry", lay_kit("lay-sys1")), ("collections", "system-maker", lay_kit("lay-sys2", maker=True))):
        open(os.path.join(td, "lay.log." + flag), "w").close()
        rc, out, got = lay(fx_kit, step)
        os.remove(os.path.join(td, "lay.log." + flag))
        arm(f"{step}: the kit script stops for a reason tied to this macOS (exit 3): the user reads the fixed sentence with the script's reason",
            rc == 1 and "STOP This Mac's macOS " in out and "cannot prepare macOS 27. Update to macOS 26.7.1, then run Golden Gate again. Reason: " in out
            and ("no aea that opens the restore image" in out or "bspatch on this macOS is not the one" in out) and "Nothing was changed" in out, out)
    fo = lay_kit("lay-own")
    open(os.path.join(td, "lay.log.refuse-dry"), "w").close()
    rc, out, got = lay(fo, "installer")
    os.remove(os.path.join(td, "lay.log.refuse-dry"))
    arm("control: a refusal that is not about the running macOS (exit 1) keeps its own words", rc == 1 and "Update to macOS 26.7.1" not in out and "refused its dry run" in out, out)
    rc, out = run("status", f.efi, "", "--step-log", os.path.join(td, "status.log"))
    arm("status writes no step log", rc == 0 and not os.path.exists(os.path.join(td, "status.log")), out)
    appjs_flow = (ROOT / "Resources/app.js").read_text()
    arm("the app shows the newest line of the step log while a step runs, and gives the install step hours",
        'if (event === "ggprogress") $("ggt").textContent = data;' in appjs_flow
        and "limit = GoldenGate.timeLimit(step: extra.count > 1 ? extra[1] : \"\")" in (ROOT / "Sources/main.swift").read_text()
        and "let run = Privileged.run(cmd, timeout: limit)" in (ROOT / "Sources/main.swift").read_text())
    setup_flow = (ROOT / "Resources/nullmoth-setup.sh").read_text()
    main_flow = (ROOT / "Sources/main.swift").read_text()
    page = (ROOT / "Resources/index.html").read_text()
    appjs_flow = (ROOT / "Resources/app.js").read_text()
    arm("the app: the account is brought over unless the box for a new Mac is ticked (unticked as shipped), the user is told which before the run, and setup passes the name on",
        '<input type="checkbox" id="ggnew"> Set up as a new Mac instead' in page and 'id="ggnew" checked' not in page and "ggbring" not in page + appjs_flow
        and 'bringAccount: !$("ggnew").checked' in appjs_flow
        and 'let bring = b["bringAccount"] as? Bool == true' in main_flow and 'if bring { extra += ["--bring-account", NSUserName()] }' in main_flow
        and 'bring ? "\\n\\nmacOS 27 will start with your account brought over." : "\\n\\nmacOS 27 will start at Apple\'s setup like a new Mac."' in main_flow
        and main_flow.index("a.informativeText += bring") < main_flow.index('a.addButton(withTitle: "Prepare for Golden Gate")')
        and 'if step == "installer", b["bringAccount"] as? Bool == true { extra += ["--bring-account", NSUserName()] }' in main_flow
        and '${GGACCOUNT:+--bring-account "$GGACCOUNT"}' in setup_flow)
    hidden_row = page[page.index('<p hidden><button type="button" id="ggkit"'):]
    arm("the page shows one button for the whole move and the way back; the single steps are in the page but not shown",
        page.index('id="ggprep"') < page.index('id="ggcancel"') < page.index('<p hidden>')
        and all(f'id="{b}" disabled' in hidden_row[:hidden_row.index("</p>")] for b in ("ggkit", "ggkitf", "ggkc", "gginst", "ggfin", "ggact"))
        and '[["ggprep", "all"]' in open(ROOT / "Resources/app.js").read()
        and "softwareupdate" not in open(SCRIPT).read())

    # 7c. local: the same installers on macOS 27 itself, against the running system; dry runs only unless confirmed.
    # The stand-in installer for this step takes no volumes and writes its line where LOCALLOG says.
    LOCAL = """#!/bin/bash
me=%s; mode=install; pay=
while [ $# -gt 0 ]; do case "$1" in --dry-run) mode=dry;; --apply) mode=apply;; --payload) pay=$2; shift;; *) echo "unknown $1"; exit 9;; esac; shift; done
[ -f "$pay/$(basename "$0")" ] || exit 8
echo "$me $mode" >> "@LOG@"
[ ! -e "@LOG@.refuse-$me-$mode" ]
"""

    def local_kit(name, system=True):
        f = fresh(td, name)
        log = os.path.join(td, name + ".calls")
        for key, inst in (("driver", "install-macos27.sh"),) + ((("system", "install-system.sh"),) if system else ()):
            os.makedirs(os.path.join(f.kit_path, key))
            with open(os.path.join(f.kit_path, key, inst), "w") as fh:
                fh.write((LOCAL % key).replace("@LOG@", log))
            edit(f.kit_path, lambda m, key=key, inst=inst: m.update({key: {"dir": key, "installer": inst}}))
        return f, log

    def local(f, *more):
        args = ["/bin/bash", SCRIPT, "local", "--kit", f.kit_path] + list(more)
        r = subprocess.run(args, capture_output=True, text=True, timeout=300,
                           env={k: v for k, v in os.environ.items() if k != v3_macos27.KIT_ENV})
        return r.returncode, r.stdout + r.stderr

    def lines(log):
        return open(log).read().split("\n")[:-1] if os.path.exists(log) else []

    f, log = local_kit("local-a")
    before = tree(f.efi)
    rc, out = local(f, "--macos-major", "27")
    arm("local without --confirm makes both dry runs and no real run, with no startup partition named",
        rc == 0 and lines(log) == ["system dry", "driver dry"] and "Nothing was changed" in out and "RESULT ok" in out, out)
    os.remove(log)
    rc, out = local(f, "--macos-major", "27", "--confirm")
    arm("local with --confirm runs system dry run, driver dry run, then each again with --apply, system first",
        rc == 0 and lines(log) == ["system dry", "driver dry", "system apply", "driver apply"] and tree(f.efi) == before, out)
    for major in ("26", "15", "28"):
        os.remove(log) if os.path.exists(log) else None
        rc, out = local(f, "--macos-major", major, "--confirm")
        arm(f"local refuses on macOS {major} and runs no installer (control: it ran four on 27)",
            rc == 1 and "this step runs on macOS 27" in out and lines(log) == [], out)
    for name, refuse, want in (("the system dry run refuses: nothing else is run", "system-dry", ["system dry"]),
                               ("the driver dry run refuses: no real run", "driver-dry", ["system dry", "driver dry"]),
                               ("the system installer stops: the driver installer is never run", "system-apply", ["system dry", "driver dry", "system apply"])):
        os.remove(log) if os.path.exists(log) else None
        open(log + ".refuse-" + refuse, "w").close()
        rc, out = local(f, "--macos-major", "27", "--confirm")
        arm(f"local, {name}", rc == 1 and lines(log) == want and "RESULT stop" in out, out + repr(lines(log)))
        os.remove(log + ".refuse-" + refuse)
    rc, out = run("local", "", "", "--macos-major", "27", "--confirm")
    arm("local without a kit stops as not offered", rc == 1 and "not offered" in out, out)
    f, log = local_kit("local-nosys", system=False)
    rc, out = local(f, "--macos-major", "27", "--confirm")
    arm("local refuses a kit without a system package and runs neither installer", rc == 1 and "carries no system package" in out and lines(log) == [], out)
    setup_src = (ROOT / "Resources/nullmoth-setup.sh").read_text()
    v3i = setup_src.index('if [ -n "${V3I:-}" ]; then')
    arm("setup hands a macOS 27 install to the local step only with a kit, before any disk is looked at or a package opened, and confirms only for apply",
        0 < setup_src.index('[ "$(id -u)" = 0 ] ||') < v3i < setup_src.index("driver_os_ok() {") < setup_src.index('step "Checking the driver package"')
        and '[ -f "${GGKIT:-}/v3-kit.json" ] || { echo "STOP macOS 27 is not offered by this build of 1401. Nothing was changed"' in setup_src[v3i:v3i + 700]
        and 'if [ "$V3I" = apply ]; then /bin/bash "$GGS" local --kit "$GGKIT" --confirm; else /bin/bash "$GGS" local --kit "$GGKIT"; fi\n  exit $?' in setup_src[v3i:v3i + 900]
        and "--pkg" not in setup_src[v3i:v3i + 900] and "$PKG" not in setup_src[v3i:v3i + 900])

    # 7b. the kit is trusted by owner and place only, and what its manifest may change is a fixed list
    for name, loosen in (("the kit folder is writable by others", lambda k: os.chmod(k, 0o757)),
                         ("the kit folder is writable by its group", lambda k: os.chmod(k, 0o775)),
                         ("a folder above the kit is writable by others", lambda k: os.chmod(os.path.dirname(k), 0o777)),
                         ("a file in the kit is writable by others", lambda k: os.chmod(os.path.join(k, v3_macos27.MANIFEST), 0o666)),
                         ("a kext in the kit is writable by its group", lambda k: os.chmod(os.path.join(k, "Kexts", "Lilu.kext", "Contents", "Info.plist"), 0o664))):
        t = fresh(td, "trust" + str(abs(hash(name))))
        before = tree(t.efi)
        rc, out = run("preflight", t.efi, t.kit_path, *READY)
        control = rc == 0
        loosen(t.kit_path)
        for step in ("preflight", "stage", "finish"):
            rc, out = run(step, t.efi, t.kit_path, *READY)
            arm(f"{name}: {step} refuses the kit (control: it was accepted before)",
                control and rc == 1 and "is not trusted" in out and tree(t.efi) == before, out)
    for name, change, word in (
            ("a config key outside the list", lambda m: m["set"].update({"Misc/Security/Vault": "Optional"}), "does not let a kit set: Misc/Security/Vault"),
            ("a kernel quirk", lambda m: m["set"].update({"Kernel/Quirks/DisableIoMapper": True}), "does not let a kit set: Kernel/Quirks/DisableIoMapper"),
            ("a boot argument outside the list", lambda m: m["boot_args"].append("amfi_get_out_of_my_way=1"), "does not let a kit add: amfi_get_out_of_my_way=1")):
        t = fresh(td, "allow" + str(abs(hash(name))))
        edit(t.kit_path, change)
        before = tree(t.efi)
        for step in ("preflight", "stage"):
            rc, out = run(step, t.efi, t.kit_path, *READY)
            arm(f"{name}: {step} refuses the kit and names it", rc == 1 and word in out and tree(t.efi) == before, out)
    # a symbolic link that names anything outside the kit crosses the line between the kit and the rest of the disk:
    # every forward step refuses it, and no installer is run. A link that stays inside the kit is accepted.
    planted = os.path.join(td, "planted-outside.sh")
    with open(planted, "w") as fh:
        fh.write(FAKE % "outside")
    for name, plant in (("a link beside the installer in the system package", lambda k: os.symlink(planted, os.path.join(k, "system", "extra"))),
                        ("the system installer itself is a link", lambda k: (os.remove(os.path.join(k, "system", "install-system.sh")),
                                                                              os.symlink(planted, os.path.join(k, "system", "install-system.sh")))),
                        ("a link that climbs out of the kit by a relative path", lambda k: os.symlink("../../" + os.path.basename(planted), os.path.join(k, "system", "up"))),
                        ("a link that names nothing", lambda k: os.symlink("not-there", os.path.join(k, "driver", "dangling"))),
                        ("a link inside a kext to a full path", lambda k: os.symlink("/etc/hosts", os.path.join(k, "Kexts", "Lilu.kext", "Contents", "hosts")))):
        g = active("link" + str(abs(hash(name))))
        vols = volumes("vols-link" + str(abs(hash(name))))
        rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
        control = rc == 0 and len(calls(vols)) == 4
        vols = volumes("vols-link2" + str(abs(hash(name))))
        plant(g.kit_path)
        before = tree(g.efi)
        for step in ("preflight", "stage", "finish"):
            rc, out = run(step, g.efi, g.kit_path, *READY, "--volumes", vols)
            arm(f"symbolic link in the kit, {name}: {step} refuses the kit and runs nothing (control: finish ran four before)",
                control and rc == 1 and "is not trusted" in out and "no symbolic link in it may name anything outside it" in out
                and calls(vols) == [] and tree(g.efi) == before, out)
    # links that stay inside the kit, as a versioned bundle has: accepted, and finish still runs all four
    g = active("link-inside")
    fw = os.path.join(g.kit_path, "driver", "X.framework")
    os.makedirs(os.path.join(fw, "Versions", "A"))
    open(os.path.join(fw, "Versions", "A", "X"), "w").close()
    os.symlink("A", os.path.join(fw, "Versions", "Current"))
    os.symlink("Versions/Current/X", os.path.join(fw, "X"))
    os.symlink("Info.plist", os.path.join(g.kit_path, "Kexts", "Lilu.kext", "Contents", "Info.short"))
    vols = volumes("vols-link-inside")
    rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
    arm("links that stay inside the kit (a versioned bundle, a short name) are accepted: finish runs all four installers",
        rc == 0 and len(calls(vols)) == 4, out)
    # an installer or a package folder that is itself a link is refused even when it stays inside the kit
    for name, plant, word in (
            ("the system installer is a link to a file inside the kit",
             lambda k: (os.rename(os.path.join(k, "system", "install-system.sh"), os.path.join(k, "system", "real.sh")),
                        os.symlink("real.sh", os.path.join(k, "system", "install-system.sh"))), "carries no system package"),
            ("the driver package folder is a link to a folder inside the kit",
             lambda k: (os.rename(os.path.join(k, "driver"), os.path.join(k, "driver-real")),
                        os.symlink("driver-real", os.path.join(k, "driver"))), "carries no driver package")):
        g = active("linkinst" + str(abs(hash(name))))
        plant(g.kit_path)
        vols = volumes("vols-linkinst" + str(abs(hash(name))))
        rc, out = run("finish", g.efi, g.kit_path, *FIN, vols)
        arm(f"{name}: finish refuses and runs nothing", rc == 1 and word in out and calls(vols) == [], out)
    arm("the script refuses a link as a package folder or installer on its own, apart from the walk of the tree",
        script_text.count('[ ! -L "$PAY/$inst" ]') == 1 and script_text.count('[ ! -L "$SPAY/$sinst" ]') == 1
        and script_text.count('links_inside "$1" || return 1') == 1)
    left = [p for p in os.listdir(tempfile.gettempdir()) if p.startswith("1401-golden-gate")]
    arm("no private copy of a kit is left behind", not left, left)
    script = open(SCRIPT).read()
    arm("as root only root may own the kit: the running user is accepted only because the script has that user's rights",
        'ME=$(id -u)\n# test-hook-end\n# ship: ME=0\nowner_ok() { [ "$1" = 0 ] || [ "$1" = "$ME" ]; }' in script)
    arm("the kit is copied to a private folder and only the copy is used, before anything reads it",
        script.index("chain_trusted \"$KIT\" && tree_trusted \"$KIT\"") < script.index('cp -R "$KIT" "$PRIV/kit"')
        < script.index('KIT="$PRIV/kit"') < script.index("  kit_ok || stop \"$NOT_OFFERED Nothing was changed\"\n  kit_allowed"))
    kit_runs = (script.count('/bin/bash "$PAY/$inst"') + script.count('/bin/bash "$SPAY/$sinst"') + script.count('/bin/bash "$LDIR/$linst"')
                + script.count('run_kit "$LDIR/$linst"') + script.count('run_kit "$KM"') + script.count('run_kit "$LDIR/make-kernel-collections.sh"'))
    arm("every kit script is run from the private copy and never from the startup partition: four runs in finish, four in local, and the lay-down and the collections maker through one helper",
        '"$ROOT/$DRIVER/$inst"' not in script and script.count('/bin/bash "$PAY/$inst"') == 4 and script.count('/bin/bash "$SPAY/$sinst"') == 4
        and script.count('/bin/bash "$LDIR/$linst"') == 1 and script.count('/bin/bash "$@"') == 1 and script.count("/bin/bash ") == 10
        and script.count('SPAY="$KIT/$sdir"') == 1 and script.count('PAY="$KIT/$ddir"') == 1 and script.count('LDIR="$KIT/$d"') == 1 and kit_runs == 14, kit_runs)
    arm("the private copy is checked again right before each of those runs once the step has started changing things",
        script.count('tree_trusted "$KIT" || stop "the private copy of the v3 kit changed') >= 12)
    fin = script[script.index("\nfinish)"):script.index("\nlocal)")]
    order = [fin.index(x) for x in ('"$SPAY/$sinst" --payload "$SPAY" --system "$SYS" --data "$DATA" --esp "$ROOT" --dry-run',
                                    '"$PAY/$inst" --payload "$PAY" --system "$SYS" --data "$DATA" --esp "$ROOT" --dry-run',
                                    '"$SPAY/$sinst" --payload "$SPAY" --system "$SYS" --data "$DATA" --esp "$ROOT" --apply',
                                    '"$PAY/$inst" --payload "$PAY" --system "$SYS" --data "$DATA" --esp "$ROOT" --apply')]
    arm("in the script both dry runs come before either real run, and the system package before the driver", order == sorted(order), order)

arm("the script carries every model the builder has (RTX 50 only so far)",
    {k: v["model"] for k, v in v3_macos27.IDENTITY.items() if v["model"]} == {"RTX 50": "Mac17,15"}
    and "MODEL_RTX50=Mac17,15" in open(SCRIPT).read())
arm("the script's lists of what a kit may set are the builder's",
    f'SET_ALLOWED="{" ".join(v3_macos27.SETTABLE)}"' in open(SCRIPT).read()
    and f'BOOT_ARGS_ALLOWED="{" ".join(v3_macos27.BOOT_ARGS_ALLOWED)}"' in open(SCRIPT).read())

# 8. the switch in the app: hidden and inert unless the app found a kit, and nothing a 2.x user sees names macOS 27
import re
html = (ROOT / "Resources/index.html").read_text()
appjs = (ROOT / "Resources/app.js").read_text()
main = (ROOT / "Sources/main.swift").read_text()
setup = (ROOT / "Resources/nullmoth-setup.sh").read_text()
arm("the card is hidden in the page as shipped and every button on it starts disabled",
    '<div class="pane card" id="ggcard" hidden>' in html
    and all(f'id="{b}" disabled' in html for b in ("ggprep", "gginst", "ggact", "ggfin", "ggcancel")))
arm("the page shows the card only when the app reports a kit, and enables it only on macOS 15 or 26",
    '$("ggcard").hidden = !m.goldenGate;' in appjs and "S.ggReady = !!m.goldenGate && OS_FROM.includes(m.major) && !why;" in appjs
    and re.search(r"^const OS_FROM = \[15, 26\][,;]", appjs, re.M) is not None)   # the two versions live in one named list since the page became Liberator's own
arm("the page script still never names macOS 27", "macOS 27" not in appjs)
_sh = open(SCRIPT).read().splitlines()
_bless = [i for i, ln in enumerate(_sh) if "/usr/sbin/bless " in ln and not ln.lstrip().startswith("#")]
arm("the system's own bless is only ever reached as root with the system's own disk tool, so no test run can start it (one waited for ever)",
    len(_bless) == 2 and all(any('[ "$DISKUTIL" = /usr/sbin/diskutil ] && [ "$(id -u)" = 0 ]' in _sh[j] for j in range(max(0, i - 6), i + 1)) for i in _bless)
    and os.geteuid() != 0, repr(_bless))
osgate = (ROOT / "Sources/OSGate.swift").read_text()
planall = re.findall(r'ggmark "PLAN-ALL ([a-z0-9: -]+)"', setup)
shares = [p.split(":") for p in planall[0].split()] if len(planall) == 1 else []
stage_marks = re.findall(r'ggmark "STAGE ([a-z]+)"', setup)
arm("the one-button run prints one plan whose shares sum to 100, and marks each of its stages and the end, in the plan's order",
    sum(int(w) for _, w in shares) == 100 and stage_marks == [n for n, _ in shares] + ["done"], repr((planall, stage_marks)))
arm("every stage of the plan has words in the app",
    bool(shares) and all(f'"{n}": "' in osgate.split("static let stageWords")[1].split("static let phaseWords")[0] for n, _ in shares))
arm("the lines made by setup go to the step log the app follows, and the kit download's progress goes there too",
    "GGSTEPLOG=/Library/NullMoth/golden-gate/steps.log" in setup and '"PROGRESS "*) ggmark "$l";;' in setup
    and setup.count("| ggkitlines drop; ggkrc=${PIPESTATUS[0]}") == 2 and setup.count("| ggkitlines keep; ggkrc=${PIPESTATUS[0]}") == 2)
arm("the app reads every new line for the bar, sends the bar apart from the text line, and keeps bar lines out of the log on the page",
    "for l in r.lines { bar.take(l, at: now) }" in main and 'self.send("ggbar", ["pct": b.percent, "text": b.text])' in main
    and ".filter { !GoldenGateProgress.isControl($0) }" in main and "!GoldenGateProgress.isControl($0) }) ?? \"\"" in main)
arm("the page has the bar and its line in the card, hidden until the app sends one, and a new run starts it again",
    'id="ggbar" hidden' in html and 'id="ggbart" hidden' in html and html.index('id="ggbar"') > html.index('id="ggcard"')
    and 'if (event === "ggbar") ggBar(data.pct, data.text);' in appjs and appjs.count("ggBar(null); post(") == 2
    and "S.ggPct = Math.max(S.ggPct || 0" in appjs)
arm("the app shows the card only for an installed kit or a build that carries a kit pin, and refuses a step before setup is started",
    '"goldenGate": !GoldenGate.kit().isEmpty || App.goldenGateKitState() != "none",' in main
    and 0 < main.index("if let why = GoldenGate.refusal(step: step, major: OSGate.currentMajor, kit: kit, kitState: App.goldenGateKitState())")
    < main.index('run(mode: "goldengate"'))
one = main.index('a.messageText = "Prepare this Mac for macOS 27 and start from its startup files?"')
single = main.index('a.messageText = "Start this Mac from the macOS 27 startup files?"')
confirms = [i for i in range(len(main)) if main.startswith('extra.append("--confirm")', i)]
rm_q = main.index('a.messageText = "Remove macOS 27 from this Mac?"')
clr_q = main.index('a.messageText = "Clear the Golden Gate downloads?"')
GUARD = "guard a.runModal() == .alertSecondButtonReturn else"
arm("--confirm is passed only after the user's yes: the whole move, removing macOS 27, clearing the downloads, the single switch",
    main.count('"--confirm"') == 4 and len(confirms) == 4 and one < confirms[0] < rm_q < confirms[1] < clr_q < confirms[2] < single < confirms[3]
    and all(GUARD in main[q:c] for q, c in ((one, confirms[0]), (rm_q, confirms[1]), (clr_q, confirms[2]), (single, confirms[3]))))
arm("the question before removing macOS 27 says that everything inside it is erased, that it cannot be undone, and that the running macOS is not touched",
    all(w in main[rm_q:confirms[1]] for w in ("with everything saved inside it", "It cannot be undone", "The macOS you are using now is not touched")))
osgate = (ROOT / "Sources/OSGate.swift").read_text()
page = (ROOT / "Resources/index.html").read_text()
js = (ROOT / "Resources/app.js").read_text()
arm("the app knows the two new steps, needs no kit for them, and the page has a button for each",
    '["cancel", "kit", "all", "remove", "clear-downloads"]' in osgate and 'id="ggrm"' in page and 'id="ggclr"' in page
    and '["ggrm", "remove"], ["ggclr", "clear-downloads"]' in js and 'const GG_NO_KIT = ["ggcancel", "ggrm", "ggclr"];' in js)
arm("the size the page offers reaches the install step only as one of the app's own sizes, and setup passes it to that step alone",
    'static let sizes: Set<Int> = [0, 40, 64, 128, 256, 512]' in osgate and main.count('GoldenGate.sizeArgs(b["sizeGB"])') == 3
    and '$([ "$1" = installer ] && [ -n "${GGSIZE:-}" ] && echo "--size-gb $GGSIZE")' in setup
    and all(f'<option value="{n}"' in page for n in (0, 40, 64, 128, 256, 512)) and 'sizeGB: Number($("ggsize").value) || 0' in js)
arm("setup answers the two download steps without looking for a startup partition, and passes --confirm only when it was given",
    0 < setup.index('case "$GG" in downloads|clear-downloads)') < setup.index('step "Checking the driver package"')
    and '/bin/bash "$GGS" "$GG" ${GGCONFIRM:+--confirm}; exit $?;; esac' in setup)
refuse = setup.index('[ -f "${GGKIT:-}/v3-kit.json" ] || { echo "STOP macOS 27 is not offered by this build of 1401')
arm("setup refuses a forward step without a kit before it looks for the OpenCore partition or opens a package",
    0 < refuse < setup.index('step "Checking the driver package"') < setup.index('if [ -n "$CFG" ]; then C=$CFG;'), refuse)
arm("setup hands Golden Gate to its script only after the partition is found, and skips the driver package path",
    setup.index('if [ -n "${GG:-}" ]; then\n  # Prepare for Golden Gate: the steps live') > setup.index('OCREL=$(ocrel_in "$MP")')
    and '[ -z "${GG:-}" ] && { [ -z "$UPD" ] || [ $INSTALL_THEN_PREPARE = 1 ]; }; then' in setup)

print("FAILED" if fails else "all passed")
sys.exit(1 if fails else 0)
