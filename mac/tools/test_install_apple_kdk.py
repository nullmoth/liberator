#!/usr/bin/env python3
"""install-apple.sh on a Mac whose Tahoe keeps its Intel graphics driver code only in the kernel collection: the driver
folder on disk names a program and holds none, so it links to nothing ("linked, but ... is not in the collection",
real Intel-graphics Macs). The code must come from the Kernel Debug Kit for that Tahoe build: an installed kit, a given
one, or a downloaded image whose package Apple signed. Runs the real script against throwaway volumes with stand-in
kmutil, hdiutil, pkgutil and curl; nothing outside a temporary folder is touched."""
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "..", "kit", "driver_apple", "install-apple.sh")
CFL = "com.apple.driver.AppleIntelCFLGraphicsFramebuffer"
NAME = "AppleIntelCFLGraphicsFramebuffer"
BUILD, VER = "25G241", "26.7.1"
FAILS = []


def arm(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name)
    if not ok:
        FAILS.append(name)
        print("     " + detail.replace("\n", "\n     ")[:3000])


def kext(folder, name, bid, version="24.0.5", exe=None, program=None):
    """exe names the program in Info.plist; program is the file to place as it (None = no program on disk)."""
    c = os.path.join(folder, name + ".kext", "Contents")
    os.makedirs(c, exist_ok=True)
    info = {"CFBundleIdentifier": bid, "CFBundleVersion": version}
    if exe:
        info["CFBundleExecutable"] = exe
    plistlib.dump(info, open(os.path.join(c, "Info.plist"), "wb"))
    if program:
        os.makedirs(os.path.join(c, "MacOS"), exist_ok=True)
        shutil.copy(program, os.path.join(c, "MacOS", exe))


def touch(path, text="x", mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write(text)
    if mode:
        os.chmod(path, mode)


def world(td):
    pay = os.path.join(td, "pkg")
    p = os.path.join(pay, "payload")
    kext(os.path.join(p, "Library", "Extensions"), "NMXAudio", "com.nullmoth.NMXAudio")
    for f in ("usr/local/libexec/nullmoth/audsel", "usr/local/libexec/nullmoth/netup.sh",
              "Library/LaunchDaemons/com.nullmoth.netup.plist", "Library/LaunchAgents/com.nullmoth.audsel.plist"):
        touch(os.path.join(p, f))
    touch(os.path.join(pay, "MANIFEST"), "# no checked files in this stand-in\n")
    sysv, data = os.path.join(td, "sys"), os.path.join(td, "data")
    for f in ("System/Library/KernelCollections/BootKernelExtensions.kc", "System/Library/KernelCollections/SystemKernelExtensions.kc",
              "System/Library/Kernels/kernel"):
        touch(os.path.join(sysv, f))
    os.makedirs(data, exist_ok=True)
    ext = os.path.join(td, "tahoe-ext")
    kext(ext, NAME, CFL, exe=NAME)                      # as on a real Tahoe: names a program, holds none
    bins = os.path.join(td, "bin")
    # kmutil stand-in. create: a driver is in the collection only when its folder in the repository holds the program
    # its Info.plist names (what the real kmutil does with a folder that has none). inspect -A prints the collection.
    touch(os.path.join(bins, "kmutil"), '''#!/bin/bash
if [ "$1" = create ]; then out=""; ids=""; repo=""
  while [ $# -gt 0 ]; do case "$1" in -A) out=$2; shift;; -b) ids="$ids $2"; shift;; --repository) repo=$2; shift;; esac; shift; done
  : > "$out"
  for id in $ids; do for k in "$repo"/*.kext; do
    [ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$k/Contents/Info.plist" 2>/dev/null)" = "$id" ] || continue
    e=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$k/Contents/Info.plist" 2>/dev/null)
    if [ -z "$e" ] || [ -f "$k/Contents/MacOS/$e" ]; then echo "$id" >> "$out"; fi
  done; done; exit 0; fi
if [ "$1" = inspect ]; then while [ $# -gt 0 ]; do [ "$1" = -A ] && cat "$2"; shift; done; exit 0; fi
exit 0
''', 0o755)
    # the opened image: a folder with KernelDebugKit.pkg (a marker file naming the tree pkgutil will "expand")
    tree = os.path.join(td, "kit-tree")
    mnt = os.path.join(td, "mnt")
    touch(os.path.join(mnt, "KernelDebugKit.pkg"), tree)
    touch(os.path.join(bins, "hdiutil"), f'#!/bin/bash\nif [ "$1" = attach ]; then printf "/dev/disk9\\tGUID_partition_scheme\\t\\n/dev/disk9s1\\tApple_HFS\\t{mnt}\\n"; fi\nexit 0\n', 0o755)
    touch(os.path.join(bins, "pkgutil"), '''#!/bin/bash
if [ "$1" = --check-signature ]; then if [ "${KIT_SIGNED:-1}" = 1 ]; then echo "   Status: signed Apple Software"; else echo "   Status: no signature"; fi; exit 0; fi
if [ "$1" = --expand-full ]; then mkdir -p "$3/KDK.pkg" && cp -R "$(cat "$2")" "$3/KDK.pkg/Payload"; exit $?; fi
exit 1
''', 0o755)
    # curl stand-in: writes the "image" when the download is allowed, fails otherwise
    touch(os.path.join(bins, "curl"), '''#!/bin/bash
[ "${NET:-0}" = 1 ] || exit 6
while [ $# -gt 0 ]; do [ "$1" = -o ] && echo image > "$2"; shift; done; exit 0
''', 0o755)
    return pay, sysv, data, ext, bins, tree


def kit(root, version="24.0.5", program="/bin/ls"):
    kext(os.path.join(root, "System", "Library", "Extensions"), NAME, CFL, version=version, exe=NAME, program=program)


def run(td, mode, extra=(), env_extra=None, prep=None):
    pay, sysv, data, ext, bins, tree = world(td)
    installed = os.path.join(td, "KDKs")
    os.makedirs(installed, exist_ok=True)
    if prep:
        prep(td, installed, tree)
    env = dict(os.environ, GG_EFIKIND="mac")
    env.update(env_extra or {})
    a = ["/bin/bash", SCRIPT, "--payload", pay, "--system", sysv, "--data", data, mode, "--model", "Macmini8,1",
         "--kmutil", os.path.join(bins, "kmutil"), "--hdiutil", os.path.join(bins, "hdiutil"),
         "--pkgutil", os.path.join(bins, "pkgutil"), "--curl", os.path.join(bins, "curl"),
         "--tahoe-ext", ext, "--gfx-ids", CFL, "--tahoe-build", BUILD, "--tahoe-version", VER,
         "--kdk-installed", installed] + list(extra)
    r = subprocess.run(a, capture_output=True, text=True, env=env, timeout=120)
    aux = os.path.join(data, "Library", "KernelCollections", "AuxiliaryKernelExtensions.kc")
    return r.returncode, r.stdout + r.stderr, (open(aux).read() if os.path.exists(aux) else None), data


def main():
    with tempfile.TemporaryDirectory() as td:
        n = [0]

        def d():
            n[0] += 1
            return os.path.join(td, str(n[0]))

        rc, out, aux, _ = run(d(), "--apply")
        arm("control: with no kit anywhere and no network the Mac is refused, told which kit to get, and nothing is placed",
            rc == 1 and aux is None and f"Kernel Debug Kit {VER} build {BUILD}" in out and "Nothing was changed" in out, out)

        rc, out, aux, _ = run(d(), "--apply", prep=lambda td_, inst, tree: kit(os.path.join(inst, f"KDK_{VER}_{BUILD}.kdk")))
        arm("an installed kit for this Tahoe build gives the driver its code and the driver is in the collection",
            rc == 0 and aux is not None and CFL in aux and "code from the Kernel Debug Kit" in out, out)

        rc, out, aux, _ = run(d(), "--apply", prep=lambda td_, inst, tree: kit(os.path.join(inst, "KDK_26.6.2_25G82.kdk")))
        arm("an installed kit for ANOTHER build is not taken (and with no network the Mac is refused)", rc == 1 and aux is None, out)

        def given_wrong(td_, inst, tree):
            kit(os.path.join(td_, "given"), version="23.0.1")
        rc, out, aux, _ = run(d(), "--apply", extra=("--kdk", os.path.join(td, str(n[0]), "given")), prep=given_wrong)
        arm("a given kit whose driver is another version is refused by name, nothing placed",
            rc == 1 and aux is None and "for another build" in out, out)

        def given_noprog(td_, inst, tree):
            touch(os.path.join(td_, "notmacho"), "text")
            kit(os.path.join(td_, "given"), program=os.path.join(td_, "notmacho"))
        rc, out, aux, _ = run(d(), "--apply", extra=("--kdk", os.path.join(td, str(n[0]), "given")), prep=given_noprog)
        arm("a kit driver with no Intel program is refused, nothing placed", rc == 1 and aux is None and "no Intel program" in out, out)

        rc, out, aux, data = run(d(), "--apply", env_extra={"NET": "1"}, prep=lambda td_, inst, tree: kit(tree))
        arm("with no kit installed the image is downloaded, its Apple-signed package opened, and the driver links",
            rc == 0 and aux is not None and CFL in aux
            and os.path.exists(os.path.join(data, "Library/NullMoth/golden-gate/apple/kdk", f"Kernel_Debug_Kit_{VER}_build_{BUILD}.dmg")), out)

        rc, out, aux, _ = run(d(), "--apply", env_extra={"NET": "1", "KIT_SIGNED": "0"}, prep=lambda td_, inst, tree: kit(tree))
        arm("a downloaded image whose package Apple did not sign is not used, nothing placed",
            rc == 1 and aux is None and "not signed by Apple" in out, out)

        rc, out, aux, data = run(d(), "--dry-run", env_extra={"NET": "1"})
        arm("a dry run names the drivers without code and the download, and changes nothing",
            rc == 0 and aux is None and "keep their code only in Tahoe's kernel collection" in out and "will be downloaded" in out
            and not os.path.exists(os.path.join(data, "Library")), out)
    print("all passed" if not FAILS else f"{len(FAILS)} failed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
