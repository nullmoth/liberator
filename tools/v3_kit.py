#!/usr/bin/env python3
"""Make a NullMoth v3 kit (macOS 27) from a configuration that has booted macOS 27.2.

    python3 tools/v3_kit.py make <config.plist> <Kexts dir> <out kit dir>
    python3 tools/v3_kit.py diff <built EFI dir> <config.plist> <Kexts dir> <kit dir>
    python3 tools/v3_kit.py package <kit dir> system|driver|laydown <package folder> <installer file name>

make copies the kexts SPEC names out of that EFI and writes v3-kit.json with the MinKernel, MaxKernel and executable
each one booted with, the boot-args SPEC allows, and the values SPEC copies. Only what SPEC names goes into the kit:
the reference machine's own drivers (its fan controller, its GPU) are not part of a macOS 27 build for another PC.
The kit is written outside this repository and is never committed (it holds the macOS 27 kexts).

diff compares a built EFI with the reference, the same check tests/test_v3_macos27.py runs.

package copies a package folder into a made kit as "system" or "driver" and names it and its installer in the
manifest. Golden Gate's finish step runs both installers from macOS 26 against the macOS 27 volumes, the system
package first, and refuses a kit that lacks either (p1401/golden_gate.py system_source).
"""
import json
import os
import plistlib
import shutil
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from p1401 import v3_macos27  # noqa: E402

# name -> how the build uses it. Every PC that takes macOS 27 needs the first group; the rest follow the hardware.
SPEC = [
    {"name": "a2x_exec_hook.kext", "when": "always", "position": "first"},
    {"name": "Lilu.kext", "when": "always", "position": "first"},
    # The NVIDIA kernel driver. On macOS 26 it loads from /Library/Extensions; on 27 the boot loader injects it, before
    # the platform kexts as the reference has it. "optional": a reference without it still makes a kit.
    {"name": "NVRM.kext", "when": "always", "position": "end", "optional": True},
    {"name": "A2XACPIPlatform.kext", "when": "always", "position": "end"},
    {"name": "NetArm2x86IOAPIC.kext", "when": "always", "position": "end"},
    {"name": "AppleRTC.kext", "when": "always", "position": "end"},
    {"name": "efiruntime.kext", "when": "always", "position": "end"},
    {"name": "efinvram.kext", "when": "always", "position": "end"},
    {"names": ["A2XSMBIOS.kext", "smbios.kext"], "when": "always", "position": "end"},
    {"name": "NativeUSBHIDRoute.kext", "when": "always", "position": "end"},
    {"name": "BlueToolFixup.kext", "when": "present", "position": "after-lilu", "needs_lilu": True},
    # Realtek Bluetooth adapters (USB vendor 0BDA): the firmware loader macOS 27.2 needs for them.
    {"name": "RealtekBluetoothFirmware.kext", "when": "ids", "section": "Bluetooth", "ids": ["0BDA-"],
     "position": "end", "needs_lilu": True},
]
# Kexts the macOS 26 build carries that must not load on 27 (the reference stops each at 26.99.99).
CAPS = ["AMFIPass.kext", "AppleALC.kext", "NVMeFix.kext", "RestrictEvents.kext", "WhateverGreen.kext"]
# Kexts a macOS 26 build can carry that were never run on 27 and are not in the reference's macOS 27 set: the Wi-Fi
# stack that replaces Apple's Skywalk, the Intel Bluetooth patcher, the generic Super I/O sensor kext. Each stops at
# macOS 26 unless the PC's own config already gives it an upper limit. Chosen here, not read from the reference: the
# reference's own limits for some of them are lower (24.99.99) and would take them away from a PC's macOS 26.
TAHOE_ONLY = ["IOSkywalkFamily.kext", "IO80211FamilyLegacy.kext", "RTW89Bridge.kext", "RTW89Legacy.kext",
              "RTW89Wifi.kext", "IntelBTPatcher.kext", "SMCSuperIO.kext", "AirportItlwm.kext", "itlwm.kext",
              "AirportBrcmFixup.kext", "IntelBluetoothFirmware.kext", "IntelBluetoothInjector.kext",
              "BrcmPatchRAM3.kext", "BrcmFirmwareData.kext", "BrcmBluetoothInjector.kext"]
TAHOE_MAX = "26.99.99"
# Kexts of a PC's own macOS 26 build that may load on 27 as they are. The first group ran on the reference; the
# Ethernet drivers after it did not, and stay open because a 27 without a network cannot send its logs. Every other
# kext with code in it that the kit does not bring stops at macOS 26: an unknown kext on a new kernel is the likeliest
# reason for a start that hangs, and it then hangs with no log.
KNOWN_27 = ["Lilu.kext", "VirtualSMC.kext", "SMCProcessor.kext", "AppleMCEReporterDisabler.kext", "USBToolBox.kext",
            "RTL812xLucy.kext",
            "LucyRTL8125Ethernet.kext", "IntelMausi.kext", "AppleIGC.kext", "AppleIGB.kext", "IntelLucy.kext",
            "RealtekRTL8111.kext", "AtherosE2200Ethernet.kext"]
# The parts of the identity tables that belong to one machine. They are blanked in the kit and filled from each PC's own
# config when the kit is applied.
PLATFORM_IDS = {"DataHub": ["SystemSerialNumber", "SystemUUID"],
                "PlatformNVRAM": ["MLB", "ROM", "SystemSerialNumber", "SystemUUID"],
                "SMBIOS": ["BoardSerialNumber", "ChassisSerialNumber", "SystemSerialNumber", "SystemUUID"]}
# A Kernel.Block entry that takes Apple's own kext away so an injected one can replace it must stop where the injected
# one stops, or macOS 27 is left with neither.
BLOCK_CAPS = ["com.apple.iokit.IOSkywalkFamily"]
PERSONALITY = [{"name": "VirtualSMC.kext", "from": "AppleACPIPlatformExpert", "to": "IOACPIPlatformExpert"}]
# Copied only when the reference has them; -v is required. Lilu and VirtualSMC refuse an unknown kernel without
# their beta switches.
# The second line was found missing on the first real upgrade (11-10): the reference starts macOS 27.2 with all of
# them, and every 27.2 start that reached the network had the live console (a2x_conlive=1) beside -v. The first four
# are read by the platform kexts the kit brings, the last two by the NVIDIA kernel driver.
BOOT_ARGS = ["-v", "-lilubetaall", "-vsmcbeta", "-no_compat_check",
             "a2x_conlive=1", "a2xbusydump=2", "pci_log=0x201", "pci_log_mode=0x2", "gfxrst=4", "nvrmholdcap=180"]
SET = ["Misc/Security/SecureBootModel", "PlatformInfo/Generic/SystemProductName"]


def _entries(cfg):
    return {e["BundlePath"].split("/")[-1]: e for e in cfg["Kernel"]["Add"] if e.get("Enabled")}


def make(config, kexts, out):
    with open(config, "rb") as fh:
        cfg = plistlib.load(fh)
    have = _entries(cfg)
    if os.path.exists(out) and os.listdir(out):
        sys.exit(f"refusing to write into the nonempty folder {out}")
    # Every bundle the kit will take must be here before anything is written, so a refusal leaves no half kit.
    missing = [n for s in SPEC for n in (s.get("names") or [s["name"]]) if n in have and not os.path.isdir(os.path.join(kexts, n))]
    if missing:
        sys.exit(f"enabled in the reference config but not in {kexts}: {missing}; copy them from the same EFI")
    os.makedirs(os.path.join(out, "Kexts"), exist_ok=True)
    # source_config is the file's name only: a kit is handed to other people and must not carry a path (a user name, a
    # folder layout) from the machine that made it.
    manifest = {"kit": "nullmoth-v3-macos27", "darwin": v3_macos27.DARWIN, "source_config": os.path.basename(config),
                "kexts": [], "caps": [], "personality": [], "boot_args": [], "set": {}}
    for s in SPEC:
        names = s.get("names") or [s["name"]]
        name = next((n for n in names if n in have), None)
        if name is None:
            if s.get("optional"):
                continue
            if s["when"] == "always":
                sys.exit(f"the reference config has none of {names} enabled; it is not a macOS 27 config")
            continue
        e = have[name]
        shutil.copytree(os.path.join(kexts, name), os.path.join(out, "Kexts", name), symlinks=True)
        k = {"name": name, "when": s["when"], "position": s["position"], "executable": e.get("ExecutablePath", ""),
             "min_kernel": e.get("MinKernel", ""), "max_kernel": e.get("MaxKernel", "")}
        for key in ("section", "ids", "needs_lilu"):
            if key in s:
                k[key] = s[key]
        manifest["kexts"].append(k)
    for c in CAPS:
        if c in have and have[c].get("MaxKernel"):
            manifest["caps"].append({"name": c, "max_kernel": have[c]["MaxKernel"]})
    capped = {c["name"] for c in manifest["caps"]}
    manifest["caps"] += [{"name": n, "max_kernel": TAHOE_MAX} for n in TAHOE_ONLY if n not in capped]
    manifest["block_caps"] = [{"identifier": i, "max_kernel": TAHOE_MAX} for i in BLOCK_CAPS]
    manifest["known_27"] = list(KNOWN_27)
    # Kernel patches of a PC's own config that may be carried to macOS 27, and ours that stand in for one that may not:
    # tools/kernel_patches_27.py check wrote the file from the macOS 26 and 27 kernels. A kit without the file carries
    # none, which is what every kit did before.
    plist27 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patches_27.json")
    if os.path.exists(plist27):
        with open(plist27) as fh:
            p27 = json.load(fh)
        manifest["patches_27"] = [r["mark"] for r in p27["carried"]]
        manifest["patches_27_own"] = p27["own"]
        manifest["patches_27_kernel_sha256"] = p27["kernel_27_sha256"]
    nv = cfg["NVRAM"]["Add"].get("7C436110-AB2A-4BBB-A880-FE41995C9F82", {})
    if isinstance(nv.get("csr-active-config"), bytes) and len(nv["csr-active-config"]) == 4:
        manifest["csr_active_config"] = nv["csr-active-config"].hex()
    pi = cfg.get("PlatformInfo") or {}
    if pi.get("Automatic") is False and all(isinstance(pi.get(s), dict) for s in PLATFORM_IDS):
        tables = {}
        for sect, ids in PLATFORM_IDS.items():
            tables[sect] = dict(pi[sect])
            for key in ids:
                if key in tables[sect]:
                    tables[sect][key] = b"" if isinstance(tables[sect][key], bytes) else ""
        with open(os.path.join(out, v3_macos27.PLATFORM), "wb") as fh:
            plistlib.dump(tables, fh)
        manifest["platform"] = v3_macos27.PLATFORM
    # System kexts the reference pulls into the boot collection for macOS 27 so that the injected driver can link.
    manifest["force"] = [
        {"bundle_path": f["BundlePath"], "identifier": f["Identifier"], "executable": f.get("ExecutablePath", ""),
         "plist_path": f.get("PlistPath", "Contents/Info.plist"), "min_kernel": f.get("MinKernel", ""),
         "max_kernel": f.get("MaxKernel", "")}
        for f in (cfg["Kernel"].get("Force") or []) if f.get("Enabled") and f.get("MinKernel")]
    for p in PERSONALITY:
        info = os.path.join(kexts, p["name"], "Contents", "Info.plist")
        with open(info, "rb") as fh:
            pers = plistlib.load(fh).get("IOKitPersonalities") or {}
        if any(isinstance(v, dict) and v.get("IOProviderClass") == p["to"] for v in pers.values()):
            manifest["personality"].append(p)
    args = (cfg["NVRAM"]["Add"].get("7C436110-AB2A-4BBB-A880-FE41995C9F82", {}).get("boot-args") or "").split()
    manifest["boot_args"] = [a for a in BOOT_ARGS if a in args]
    for dotted in SET:
        v = v3_macos27._get_path(cfg, dotted)
        if v is not None:
            manifest["set"][dotted] = v
    # The cards macOS 27 is offered for: the ones this repository records as tried, written into the kit so that the
    # kit says what it has run on. Nothing about the reference machine's own card is read here.
    from p1401 import nullmoth  # noqa: PLC0415
    manifest["gpu_ids"] = sorted(str(i).upper() for i in nullmoth.TABLE["tested"])
    with open(os.path.join(out, v3_macos27.MANIFEST), "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    kit = v3_macos27.load_kit(out)   # the kit must pass the same checks a build applies
    print(f"kit {out}: {[k['name'] for k in kit['kexts']]}, boot-args {kit['boot_args']}, "
          f"personality {[p['name'] for p in kit['personality']]}, caps {[c['name'] for c in kit['caps']]}")
    return kit


def package(kit_path, key, folder, installer):
    """Copies folder into the kit as <key> and names it in the manifest. Refuses, leaving the kit as it was, unless the
    kit loads, the installer is a file directly in the folder, and the kit does not already carry that package."""
    from p1401 import golden_gate  # noqa: PLC0415
    if key not in ("system", "driver", "laydown"):
        sys.exit(f"the package is system, driver or laydown, not {key!r}")
    kit = v3_macos27.load_kit(kit_path)
    if os.sep in installer or installer.startswith(".") or not os.path.isfile(os.path.join(folder, installer)):
        sys.exit(f"{installer!r} is not a file directly in {folder}")
    link = golden_gate.outside_symlink(folder)
    if link:
        sys.exit(f"{folder} holds a symbolic link that names something outside it ({link}); a kit package may not")
    dst = os.path.join(kit_path, key)
    if os.path.lexists(dst) or key in kit:
        sys.exit(f"the kit at {kit_path} already carries a {key} package; make the kit again to replace it")
    shutil.copytree(folder, dst, symlinks=True)
    mpath = os.path.join(kit_path, v3_macos27.MANIFEST)
    with open(mpath) as fh:
        manifest = json.load(fh)
    manifest[key] = {"dir": key, "installer": installer}
    tmp = mpath + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    os.replace(tmp, mpath)
    kit = v3_macos27.load_kit(kit_path)
    kit["_path"] = kit_path
    src, why = golden_gate._package_source(kit, key)
    if not src:
        sys.exit(why)
    print(f"kit {kit_path}: {key} package {key}/{installer}")
    return kit


def diff(efi, config, kexts, kit_path):
    kit = v3_macos27.load_kit(kit_path)
    with open(os.path.join(efi, "EFI", "OC", "config.plist"), "rb") as fh:
        cfg = plistlib.load(fh)
    with open(config, "rb") as fh:
        ref = plistlib.load(fh)
    d = v3_macos27.diff_reference(cfg, ref, kit, os.path.join(efi, "EFI", "OC", "Kexts"), kexts)
    for line in d:
        print("DIFF", line)
    print(f"{len(d)} difference(s)")
    return d


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "make":
        make(*sys.argv[2:])
    elif len(sys.argv) == 6 and sys.argv[1] == "package":
        package(*sys.argv[2:])
    elif len(sys.argv) == 6 and sys.argv[1] == "diff":
        sys.exit(1 if diff(*sys.argv[2:]) else 0)
    else:
        sys.exit(__doc__)
