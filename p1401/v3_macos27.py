"""macOS 27 builds (driver v3 only): turn a finished macOS 26 EFI into one that boots macOS 27.2.

No public 1.x/2.x build offers macOS 27. The parts that make it boot (the platform kexts, the exec hook, the
SMBIOS kext and the macOS 27 builds of Lilu, BlueToolFixup and RealtekBluetoothFirmware) are not in this
repository and are never downloaded. They come from a v3 kit: a local folder holding the kexts plus a
manifest, `v3-kit.json`, written from a configuration that has booted macOS 27.2. Without a kit the version
is not offered at all (require_kit raises MacosNotOffered), so a build of this repository alone cannot make a
macOS 27 EFI.

The upstream engine has no macOS 27 entry, so the engine builds the macOS 26 EFI for the machine first and
apply() then changes only what the kit's manifest names:

  kexts         each entry is added (or its engine copy replaced) from the kit, with its MinKernel/MaxKernel;
                "when": "present" entries are only replaced when the engine already chose that kext for the
                machine (BlueToolFixup, for example); "when": "ids" entries are added when the scan has a device
                whose ID starts with one of "ids" in "section" (the Realtek Bluetooth firmware for 0BDA- adapters)
  caps          kexts the engine added that must not load on 27 get a MaxKernel (AMFIPass stops at 26)
  personality   a kext whose IOKit personality matches on a provider class that macOS 27.2 does not publish
                gets the class the kit names. VirtualSMC matched AppleACPIPlatformExpert; on 27.2 the platform
                expert is A2XACPIPlatformExpert, a subclass of IOACPIPlatformExpert, so VirtualSMC never matched,
                no SMC came up, and the CPU power plugin held the desktop back at boot.
  boot_args     tokens added to boot-args. "-v" is required: without it the boot console is the graphical
                progress screen, and on these PCs that screen stops at the PCI configuration step.
  set           plain config.plist values (key path -> value), for example Misc > Security > SecureBootModel

Anything the manifest asks for that cannot be done stops the build. A half-applied macOS 27 EFI is worse than
none: it boots macOS 26's kexts into 27 and stops somewhere much harder to explain.

The auxiliary kernel collection (the display and audio driver kexts on 27) is not part of the EFI. The v3
driver installer builds it from macOS 26 after macOS 27 is installed; the build result says so.
"""
import json
import os
import plistlib
import re
import shutil

KIT_ENV = "NULLMOTH_V3_KIT"
MANIFEST = "v3-kit.json"
DARWIN = "27"
NAME = "macOS 27"
# What the build reports as its macOS version, in the engine's own "<darwin>.99.99" form.
VERSION = "27.99.99"
LILU = "Lilu.kext"
PLATFORM = "platform.plist"        # the identity tables in a kit, without any machine's own numbers
PLATFORM_SECTIONS = ("DataHub", "PlatformNVRAM", "SMBIOS")
UNKNOWN_MAX = "26.99.99"           # where a kext nobody has run on macOS 27 stops

# Model identity on macOS 27 follows the NVIDIA generation, so the PC presents itself as the Apple silicon class its
# card is closest to: GTX 16 as M1, RTX 20 as M2, RTX 30 as M3, RTX 40 as M4, RTX 50 as M5 (Mac Studio, M5 Ultra).
# "model" is the SystemProductName for that class. TODO: only RTX 50 has one. While a model is None the build keeps
# the SystemProductName the kit sets and records which class the card belongs to; nothing here invents an identifier.
# The Mac app's nullmoth-golden-gate.sh applies kits too and carries the same models (mac/tools/test_golden_gate.py
# compares the two).
IDENTITY = {
    "GTX 16": {"class": "M1", "model": None},
    "RTX 20": {"class": "M2", "model": None},
    "RTX 30": {"class": "M3", "model": None},
    "RTX 40": {"class": "M4", "model": None},
    "RTX 50": {"class": "M5", "model": "Mac17,15"},   # Mac Studio, M5 Ultra
}
_GENERATION = re.compile(r"\b(?:GTX (16)\d\d|RTX ([2-5]0)\d\d)\b")


def gpu_generation(name):
    """ "RTX 50" for "NVIDIA GeForce RTX 5060 Ti", "GTX 16" for a GTX 1660; None for anything else (workstation
    cards have no class here)."""
    m = _GENERATION.search(name or "")
    if not m:
        return None
    return "GTX 16" if m.group(1) else f"RTX {m.group(2)}"


def identity_for(report):
    """(generation, IDENTITY entry) for the newest supported NVIDIA card in a scan report, or (None, None)."""
    from . import nullmoth  # noqa: PLC0415
    found = set()
    for name, gpu in nullmoth.cards(report or {}).items():
        found.add(gpu_generation(nullmoth.TABLE["ids"].get(nullmoth._pid(gpu), "")) or gpu_generation(name))
    for gen in reversed(list(IDENTITY)):
        if gen in found:
            return gen, IDENTITY[gen]
    return None, None


# All a kit's manifest may set in config.plist and all it may add to boot-args. A kit is data from outside this
# repository; these lists are what keeps it from rewriting the rest of the boot configuration.
SETTABLE = ("Misc/Security/SecureBootModel", "PlatformInfo/Generic/SystemProductName")
BOOT_ARGS_ALLOWED = ("-v", "-lilubetaall", "-vsmcbeta", "-no_compat_check",
                     "a2x_conlive=1", "a2xbusydump=2", "pci_log=0x201", "pci_log_mode=0x2", "gfxrst=4", "nvrmholdcap=180")

_KERNEL = re.compile(r"\d{1,2}\.\d{1,2}\.\d{1,2}\Z")
_KEXT = re.compile(r"[A-Za-z0-9_.+-]{1,96}\.kext\Z")
_IDENT = re.compile(r"[A-Za-z0-9_.-]{3,128}\Z")                       # a bundle identifier
_FPATH = re.compile(r"(?!/)(?!.*\.\./)[A-Za-z0-9_./+ -]{1,200}\Z")      # a path below the system root, no "../"


class KitError(RuntimeError):
    """The kit or its manifest cannot make a correct macOS 27 EFI."""


def kit_dir(explicit=""):
    """The kit folder the user pointed at (the CLI option, else the environment), or "" when there is none."""
    return explicit or os.environ.get(KIT_ENV, "")


def not_offered_message():
    return (f"{NAME} is not offered by this build of 1401. It needs the NullMoth v3 kit, which is not public; "
            "pick macOS 26 Tahoe or macOS 15 Sequoia and build again.")


def load_kit(path):
    """Reads and checks the manifest. Every kext it names must be a complete bundle in the kit."""
    if not path or not os.path.isdir(path):
        raise KitError(f"no v3 kit folder at {path!r}")
    mpath = os.path.join(path, MANIFEST)
    try:
        with open(mpath, "rb") as fh:
            m = json.loads(fh.read(1024 * 1024))
    except (OSError, ValueError) as e:
        raise KitError(f"the v3 kit manifest {mpath} could not be read: {e}") from e
    if not isinstance(m, dict) or str(m.get("darwin")) != DARWIN:
        raise KitError(f"the v3 kit at {path} is not a Darwin {DARWIN} kit (darwin={m.get('darwin') if isinstance(m, dict) else None!r})")
    kexts = m.get("kexts")
    if not isinstance(kexts, list) or not kexts:
        raise KitError("the v3 kit manifest names no kexts")
    seen = set()
    for k in kexts:
        name = k.get("name", "") if isinstance(k, dict) else ""
        if not _KEXT.match(name) or name in seen:
            raise KitError(f"bad or repeated kext name in the v3 kit manifest: {name!r}")
        seen.add(name)
        if k.get("when", "always") not in ("always", "present", "ids"):
            raise KitError(f"{name}: 'when' must be always, present or ids")
        if k.get("when") == "ids" and not (isinstance(k.get("ids"), list) and k["ids"] and k.get("section")):
            raise KitError(f"{name}: 'when': 'ids' needs a section and a list of ids")
        if k.get("position", "end") not in ("first", "end", "after-lilu"):
            raise KitError(f"{name}: 'position' must be first, end or after-lilu")
        for key in ("min_kernel", "max_kernel"):
            v = k.get(key, "")
            if v and not _KERNEL.match(v):
                raise KitError(f"{name}: {key} {v!r} is not a kernel version like 27.0.0")
        bundle = os.path.join(path, "Kexts", name)
        exe = k.get("executable", "")
        if not os.path.isfile(os.path.join(bundle, "Contents", "Info.plist")):
            raise KitError(f"the v3 kit has no {name} (expected {bundle}/Contents/Info.plist)")
        if exe and not os.path.isfile(os.path.join(bundle, exe)):
            raise KitError(f"the v3 kit's {name} has no executable {exe}")
    for cap in m.get("caps", []):
        if not _KEXT.match(cap.get("name", "")) or not _KERNEL.match(cap.get("max_kernel", "")):
            raise KitError(f"bad cap in the v3 kit manifest: {cap!r}")
    for cap in m.get("block_caps", []):
        if not _IDENT.match(cap.get("identifier", "")) or not _KERNEL.match(cap.get("max_kernel", "")):
            raise KitError(f"bad block cap in the v3 kit manifest: {cap!r}")
    for f in m.get("force", []):
        if (not isinstance(f, dict) or not _IDENT.match(f.get("identifier", "")) or not _FPATH.match(f.get("bundle_path", ""))
                or not _FPATH.match(f.get("plist_path", "")) or (f.get("executable") and not _FPATH.match(f["executable"]))
                or not _KERNEL.match(f.get("min_kernel", "")) or (f.get("max_kernel") and not _KERNEL.match(f["max_kernel"]))):
            raise KitError(f"bad forced kext in the v3 kit manifest: {f!r}")
    for n in m.get("known_27", []):
        if not isinstance(n, str) or not _KEXT.match(n):
            raise KitError(f"bad kext name in the v3 kit's list of kexts known on macOS 27: {n!r}")
    for n in m.get("try_27", []) + m.get("may_27", []):
        if not isinstance(n, str) or not _KEXT.match(n):
            raise KitError(f"bad kext name in the v3 kit's lists of kexts to try on macOS 27: {n!r}")
    if "csr_active_config" in m and not re.match(r"[0-9a-f]{8}\Z", str(m["csr_active_config"])):
        raise KitError(f"bad system-protection value in the v3 kit manifest: {m['csr_active_config']!r}")
    if "platform" in m:
        if m["platform"] != PLATFORM:
            raise KitError(f"the v3 kit names its identity tables {m['platform']!r}, not {PLATFORM}")
        try:
            with open(os.path.join(path, PLATFORM), "rb") as fh:
                tables = plistlib.load(fh)
        except (OSError, ValueError) as e:
            raise KitError(f"the v3 kit's identity tables could not be read: {e}") from e
        if not isinstance(tables, dict) or any(not isinstance(tables.get(s), dict) for s in PLATFORM_SECTIONS):
            raise KitError("the v3 kit's identity tables do not hold DataHub, PlatformNVRAM and SMBIOS")
        m["_platform"] = tables
    for p in m.get("personality", []):
        if not _KEXT.match(p.get("name", "")) or not p.get("from") or not p.get("to"):
            raise KitError(f"bad personality change in the v3 kit manifest: {p!r}")
    for key in (m.get("set") or {}):
        if key not in SETTABLE:
            raise KitError(f"the v3 kit sets a config key 1401 does not let a kit set: {key}")
    for arg in m.get("boot_args", []):
        if arg not in BOOT_ARGS_ALLOWED:
            raise KitError(f"the v3 kit adds a boot argument 1401 does not let a kit add: {arg}")
    if "-v" not in m.get("boot_args", []):
        raise KitError("the v3 kit's boot-args do not include -v; macOS 27.2 stops at the progress screen without it")
    m["_path"] = os.path.abspath(path)
    return m


def require_kit(explicit=""):
    """The loaded kit for a macOS 27 build. No kit, or a kit that fails its checks, means the version is not offered."""
    from .engine import MacosNotOffered  # noqa: PLC0415 - engine imports this module
    path = kit_dir(explicit)
    if not path:
        raise MacosNotOffered(not_offered_message())
    try:
        return load_kit(path)
    except KitError as e:
        raise MacosNotOffered(f"{not_offered_message()} ({e})") from e


def _entry(k):
    exe = k.get("executable", "")
    return {"Arch": "x86_64", "BundlePath": k["name"], "Comment": k.get("comment", ""), "Enabled": True,
            "ExecutablePath": exe, "MaxKernel": k.get("max_kernel", ""), "MinKernel": k.get("min_kernel", ""),
            "PlistPath": "Contents/Info.plist"}


def _bundle(entry):
    return entry.get("BundlePath", "").split("/")[-1]


def _copy_bundle(src, dst):
    if os.path.lexists(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True)


def _retarget_personality(info_path, old, new):
    """IOProviderClass old -> new in every personality of one Info.plist. Returns how many changed."""
    with open(info_path, "rb") as fh:
        info = plistlib.load(fh)
    n = 0
    for pers in (info.get("IOKitPersonalities") or {}).values():
        if isinstance(pers, dict) and pers.get("IOProviderClass") == old:
            pers["IOProviderClass"] = new
            n += 1
    if n:
        tmp = info_path + ".tmp"
        with open(tmp, "wb") as fh:
            plistlib.dump(info, fh)
        os.replace(tmp, info_path)
    return n


SERIAL_ALPHABET = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"   # no I and no O, as on Apple's own 10-character serials


def serial_for_model(serial, uuid, model):
    """The serial number a PC presents under a new Mac model. A serial names the model it was made for, so a config
    whose model changes while its serial stays describes two different Macs (About This Mac then shows the old one).
    The new serial is worked out from the old serial, the machine's UUID and the new model, so staging the same PC
    again gives the same serial and never a third identity. None when there is nothing of this PC's own to work from:
    two PCs must not end up with the same serial. nullmoth-golden-gate.sh computes the same value."""
    import hashlib  # noqa: PLC0415
    serial, uuid = (serial or "").strip(), (uuid or "").strip()
    if not serial and not uuid:
        return None
    digest = hashlib.sha256(f"{serial}\n{uuid}\n{model}".encode()).digest()
    return "".join(SERIAL_ALPHABET[b % len(SERIAL_ALPHABET)] for b in digest[:10])


def _set_path(cfg, dotted, value):
    keys = dotted.split("/")
    node = cfg
    for key in keys[:-1]:
        if not isinstance(node.get(key), dict):
            raise KitError(f"config.plist has no {'/'.join(keys[:-1])} to set {keys[-1]} in")
        node = node[key]
    node[keys[-1]] = value


_PCI_PATH = re.compile(r"PciRoot\(0x[0-9A-Fa-f]+\)(/Pci\(0x[0-9A-Fa-f]+,0x[0-9A-Fa-f]+\))+")


def builtin_devices(cfg, report):
    """Marks this PC's own storage and network controllers as built-in (DeviceProperties, "built-in" = 01), the way a
    Mac's are. Measured on macOS 27.2 without it: the internal disk reads "External" and the wired port reads
    IOBuiltin = No / IOPrimaryInterface = No. Apple's sign-in check reads the address of the interface that is both,
    so the Apple account cannot sign in, and the eligibility input "external boot drive" stays failed. With the
    property on both paths the same machine read Internal, Yes / Yes, and that input passed.
    Only controllers with a well-formed PCI path from the scan that are not on USB are touched; a value already
    there is kept.
    Returns the list of (section, name, path) it added."""
    added = []
    add = cfg.setdefault("DeviceProperties", {}).setdefault("Add", {})
    for section in ("Storage Controllers", "Network"):
        for name, dev in sorted(((report or {}).get(section) or {}).items()):
            path = (dev or {}).get("PCI Path") or ""
            # the scan names a disk controller's bus "NVMe", "SATA" or "PCI"; a device on USB is never built-in
            if "USB" in str((dev or {}).get("Bus Type") or "").upper() or not _PCI_PATH.fullmatch(path):
                continue
            props = add.setdefault(path, {})
            if "built-in" in props:
                continue
            props["built-in"] = b"\x01"
            added.append((section, name, path))
    return added


def apply(efi_dir, kit, notices, report=None, kit_model=False):
    """Changes the built macOS 26 EFI under efi_dir into a macOS 27 one, as the kit's manifest says. Returns the
    list of changes (for the build log). Raises KitError on anything it cannot do."""
    oc = os.path.join(efi_dir, "EFI", "OC")
    cpath = os.path.join(oc, "config.plist")
    kdir = os.path.join(oc, "Kexts")
    with open(cpath, "rb") as fh:
        cfg = plistlib.load(fh)
    add = cfg["Kernel"]["Add"]
    changes = []
    by_name = {}
    for i, e in enumerate(add):
        by_name.setdefault(_bundle(e), i)

    first, end, after_lilu = [], [], []
    for k in kit["kexts"]:
        name = k["name"]
        src = os.path.join(kit["_path"], "Kexts", name)
        present = name in by_name
        when = k.get("when", "always")
        if when == "present" and not present:
            continue
        if when == "ids" and not present:
            from .community import _ids  # noqa: PLC0415
            have = _ids(report, k["section"])
            if not any(d.startswith(p.upper()) for d in have for p in k["ids"]):
                continue
        _copy_bundle(src, os.path.join(kdir, name))
        if present:
            e = add[by_name[name]]
            e.update({"Enabled": True, "MinKernel": k.get("min_kernel", ""), "MaxKernel": k.get("max_kernel", ""),
                      "ExecutablePath": k.get("executable", e.get("ExecutablePath", ""))})
            changes.append({"v3": "replaced", "kext": name, "min_kernel": e["MinKernel"], "max_kernel": e["MaxKernel"]})
        else:
            {"first": first, "end": end, "after-lilu": after_lilu}[k.get("position", "end")].append(_entry(k))
            changes.append({"v3": "added", "kext": name, "position": k.get("position", "end")})
    if after_lilu:
        li = next((i for i, e in enumerate(add) if _bundle(e) == LILU), None)
        if li is None:
            raise KitError(f"the kit places {[_bundle(e) for e in after_lilu]} after Lilu, and the build has no Lilu")
        add[li + 1:li + 1] = after_lilu
    add[0:0] = first
    add.extend(end)

    # An upper limit the PC's own config already gives is kept: it is never raised.
    for cap in kit.get("caps", []):
        for e in add:
            if _bundle(e) == cap["name"] and not e.get("MaxKernel"):
                e["MaxKernel"] = cap["max_kernel"]
                changes.append({"v3": "capped", "kext": cap["name"], "max_kernel": cap["max_kernel"]})
    for cap in kit.get("block_caps", []):
        for b in cfg["Kernel"].get("Block") or []:
            if b.get("Identifier") == cap["identifier"] and b.get("Enabled") and not b.get("MaxKernel"):
                b["MaxKernel"] = cap["max_kernel"]
                changes.append({"v3": "block capped", "identifier": cap["identifier"], "max_kernel": cap["max_kernel"]})
    forced = cfg["Kernel"].setdefault("Force", []) if kit.get("force") else []
    for f in kit.get("force", []):
        if any(x.get("Identifier") == f["identifier"] and x.get("Enabled") for x in forced):
            continue
        forced.append({"Arch": "x86_64", "BundlePath": f["bundle_path"], "Comment": "macOS 27: in the boot collection for the injected driver",
                       "Enabled": True, "ExecutablePath": f.get("executable", ""), "Identifier": f["identifier"],
                       "MaxKernel": f.get("max_kernel", ""), "MinKernel": f["min_kernel"], "PlistPath": f["plist_path"]})
        changes.append({"v3": "forced", "identifier": f["identifier"], "min_kernel": f["min_kernel"]})

    for p in kit.get("personality", []):
        info = os.path.join(kdir, p["name"], "Contents", "Info.plist")
        if not any(_bundle(e) == p["name"] and e.get("Enabled") for e in add):
            continue   # the machine does not use that kext, so there is nothing to retarget
        if not os.path.isfile(info):
            raise KitError(f"{p['name']} is in the config but its Info.plist is not in the EFI")
        n = _retarget_personality(info, p["from"], p["to"])
        if not n:
            # Neither the old class nor (by a previous run) the new one: the kext changed and the manifest is stale.
            with open(info, "rb") as fh:
                already = any(isinstance(v, dict) and v.get("IOProviderClass") == p["to"]
                              for v in (plistlib.load(fh).get("IOKitPersonalities") or {}).values())
            if not already:
                raise KitError(f"{p['name']} has no personality on {p['from']} to move to {p['to']}")
        changes.append({"v3": "personality", "kext": p["name"], "from": p["from"], "to": p["to"], "count": n})

    nv = cfg["NVRAM"]["Add"].setdefault("7C436110-AB2A-4BBB-A880-FE41995C9F82", {})
    args = (nv.get("boot-args") or "").split()
    # name=value: a value the PC's own config gives that name is replaced, so the name is there once
    for a in kit["boot_args"]:
        if "=" in a:
            args = [t for t in args if t == a or not t.startswith(a.split("=")[0] + "=")]
    added = [a for a in kit["boot_args"] if a not in args]
    nv["boot-args"] = " ".join(args + added)
    if added:
        changes.append({"v3": "boot-args", "added": added})

    for dotted, value in (kit.get("set") or {}).items():
        _set_path(cfg, dotted, value)
        changes.append({"v3": "set", "key": dotted, "value": value if not isinstance(value, bytes) else value.hex()})

    for section, name, path in builtin_devices(cfg, report):
        changes.append({"v3": "built-in", "section": section, "device": name, "path": path})

    # kit_model: keep the model the kit sets (the one its reference configuration started macOS 27 with) instead of
    # the model for this card's generation. It is the second attempt when macOS 27 does not start with that model.
    gen, ident = identity_for(report)
    if gen and kit_model:
        changes.append({"v3": "identity", "generation": gen, "class": ident["class"], "model": "kept from the kit (asked for)"})
    elif gen:
        if ident["model"]:
            generic = (cfg.get("PlatformInfo") or {}).get("Generic") or {}
            if generic.get("SystemProductName") != ident["model"]:
                fresh = serial_for_model(generic.get("SystemSerialNumber"), generic.get("SystemUUID"), ident["model"])
                if fresh:
                    _set_path(cfg, "PlatformInfo/Generic/SystemSerialNumber", fresh)
                    changes.append({"v3": "serial", "why": "the model changed; the serial follows it"})
                else:
                    notices.append("The config has no serial number or UUID of its own, so the serial was left as it is.")
            _set_path(cfg, "PlatformInfo/Generic/SystemProductName", ident["model"])
        changes.append({"v3": "identity", "generation": gen, "class": ident["class"], "model": ident["model"] or "kept from the kit"})

    # A kext of the PC's own build that has code, that the kit neither brings nor knows, and that has no upper limit
    # of its own, stops at macOS 26. The result names each one.
    if kit.get("known_27"):
        keep = set(kit["known_27"]) | set(kit.get("try_27", [])) | {k["name"] for k in kit["kexts"]}
        for e in add:
            if e.get("Enabled") and e.get("ExecutablePath") and not e.get("MaxKernel") and _bundle(e) not in keep:
                e["MaxKernel"] = UNKNOWN_MAX
                changes.append({"v3": "not on 27", "kext": _bundle(e), "max_kernel": UNKNOWN_MAX})
                notices.append(f"{_bundle(e)} was never run on {NAME}: it stays on macOS 26 and does not load on {NAME}.")

    if kit.get("csr_active_config"):
        nv["csr-active-config"] = bytes.fromhex(kit["csr_active_config"])
        changes.append({"v3": "set", "key": "NVRAM csr-active-config", "value": kit["csr_active_config"]})

    # The identity as hand-written tables, with this PC's own numbers. OpenCore's automatic mode needs a model it has
    # data for; it has none for an Apple-silicon model name, and the Mac then starts with no Apple identity at all.
    tables = kit.get("_platform")
    pinfo = cfg.get("PlatformInfo") or {}
    generic = pinfo.get("Generic") or {}
    if tables and generic.get("SystemSerialNumber") and generic.get("SystemUUID"):
        ids = {"SystemSerialNumber": generic["SystemSerialNumber"], "SystemUUID": generic["SystemUUID"],
               "ChassisSerialNumber": generic["SystemSerialNumber"], "MLB": generic.get("MLB", ""),
               "BoardSerialNumber": generic.get("MLB", ""), "ROM": generic.get("ROM", b"")}
        model = generic.get("SystemProductName", "")
        for sect in PLATFORM_SECTIONS:
            t = dict(tables[sect])
            for key in list(t):
                if key in ids:
                    t[key] = ids[key]
            if "SystemProductName" in t:
                t["SystemProductName"] = model
            if sect == "SMBIOS" and "BoardVersion" in t:
                t["BoardVersion"] = model
            pinfo[sect] = t
        pinfo["Automatic"] = False
        changes.append({"v3": "identity tables", "model": model})
    elif tables:
        notices.append("The config has no serial number and UUID of its own, so the identity tables were not written.")

    li = [_bundle(e) for e in add if e.get("Enabled")]
    if LILU in li:
        late = [n for n in li[:li.index(LILU)] if n in {k["name"] for k in kit["kexts"] if k.get("needs_lilu")}]
        if late:
            raise KitError(f"{late} would load before Lilu")

    tmp = cpath + ".tmp"
    with open(tmp, "wb") as fh:
        plistlib.dump(cfg, fh)
    os.replace(tmp, cpath)
    notices.append(f"{NAME}: built from the v3 kit ({len([c for c in changes if c['v3'] in ('added', 'replaced')])} kexts). "
                   "After macOS 27 is installed, run the v3 NVIDIA driver installer from macOS 26: it builds the "
                   "auxiliary kernel collection that holds the display and audio drivers on 27.")
    return changes


def _get_path(cfg, dotted):
    node = cfg
    for key in dotted.split("/"):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _info(kexts_dir, name):
    try:
        with open(os.path.join(kexts_dir, name, "Contents", "Info.plist"), "rb") as fh:
            return plistlib.load(fh)
    except OSError:
        return None


def diff_reference(cfg, ref, kit, efi_kexts=None, ref_kexts=None):
    """What differs between a built macOS 27 config and a reference config that booted macOS 27.2, on everything the
    kit is responsible for. Empty means they agree. With both Kexts folders it also compares the bundle versions and
    the retargeted personalities."""
    out = []

    def enabled(c):
        return {_bundle(e): e for e in c["Kernel"]["Add"] if e.get("Enabled")}

    got, want = enabled(cfg), enabled(ref)
    names = [k["name"] for k in kit["kexts"]]
    for k in kit["kexts"]:
        name = k["name"]
        if name not in want:
            continue   # a "present"/"ids" kext the reference machine has and this one need not, or the reverse
        if name not in got:
            if k.get("when", "always") == "always":
                out.append(f"{name}: in the reference, not in the build")
            continue
        for key in ("MinKernel", "MaxKernel", "ExecutablePath"):
            if (got[name].get(key) or "") != (want[name].get(key) or ""):
                out.append(f"{name}: {key} {got[name].get(key)!r} != reference {want[name].get(key)!r}")
        if efi_kexts and ref_kexts:
            g, w = _info(efi_kexts, name), _info(ref_kexts, name)
            gv, wv = (g or {}).get("CFBundleShortVersionString"), (w or {}).get("CFBundleShortVersionString")
            if gv != wv:
                out.append(f"{name}: version {gv} != reference {wv}")
    order_got = [n for n in (_bundle(e) for e in cfg["Kernel"]["Add"] if e.get("Enabled")) if n in want and n in names]
    order_want = [n for n in (_bundle(e) for e in ref["Kernel"]["Add"] if e.get("Enabled")) if n in order_got]
    if order_got != order_want:
        out.append(f"load order of the kit kexts {order_got} != reference {order_want}")
    for cap in kit.get("caps", []):
        g, w = got.get(cap["name"]), want.get(cap["name"])
        if g and w and (g.get("MaxKernel") or "") != (w.get("MaxKernel") or ""):
            out.append(f"{cap['name']}: MaxKernel {g.get('MaxKernel')!r} != reference {w.get('MaxKernel')!r}")
    nv = "7C436110-AB2A-4BBB-A880-FE41995C9F82"
    gargs = set((cfg["NVRAM"]["Add"].get(nv, {}).get("boot-args") or "").split())
    rargs = set((ref["NVRAM"]["Add"].get(nv, {}).get("boot-args") or "").split())
    for a in kit["boot_args"]:
        if a in rargs and a not in gargs:
            out.append(f"boot-args: {a} is in the reference and not in the build")
        elif a in gargs and a not in rargs:
            out.append(f"boot-args: {a} is in the build and not in the reference")
    if "-v" not in gargs:
        out.append("boot-args: -v missing")
    for dotted in (kit.get("set") or {}):
        if _get_path(cfg, dotted) != _get_path(ref, dotted):
            out.append(f"{dotted}: {_get_path(cfg, dotted)!r} != reference {_get_path(ref, dotted)!r}")
    if efi_kexts and ref_kexts:
        for p in kit.get("personality", []):
            if p["name"] not in got or p["name"] not in want:
                continue

            def classes(d):
                pers = (_info(d, p["name"]) or {}).get("IOKitPersonalities") or {}
                return sorted(v.get("IOProviderClass", "") for v in pers.values() if isinstance(v, dict))
            if classes(efi_kexts) != classes(ref_kexts):
                out.append(f"{p['name']}: provider classes {classes(efi_kexts)} != reference {classes(ref_kexts)}")
    return out
