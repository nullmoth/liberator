"""Prepare for Golden Gate: move a PC that 1401 set up for macOS 26 to macOS 27.2 without losing the way back.

Offered only with a NullMoth v3 kit (v3_macos27.py): with no kit every step here refuses, and a build of this
repository alone offers nothing for macOS 27.

macOS 27 goes on its own volume beside macOS 26. The v3 driver installer runs from macOS 26 against the macOS 27
volumes, so macOS 26 has to keep starting for the whole move. The steps, each one undone by the next one down:

  preflight   nothing is changed. The card is one the macOS 27 driver takes, the Mac runs macOS 26, the startup
              files are a 1401 build, and there is room on the startup partition and on the disk.
  stage       a copy of EFI/OC is made at EFI/OC-27-staged and the kit turns the copy into the macOS 27 startup
              files. The firmware still starts EFI/OC: nothing about how the PC starts has changed. The driver
              package and its installer are copied beside it when the kit carries them.
  activate    only after the user confirms: EFI/OC is kept as EFI/OC-26 and the staged folder becomes EFI/OC.
  rollback    the reverse of activate: macOS 26's own startup files start the PC again.
  cancel      rollback if needed, then the staged folder, the staged driver and the state file are removed.

The state file EFI/golden-gate.json says which of these the partition is in; a partition whose folders do not agree
with it is refused rather than guessed at.
"""
import json
import os
import plistlib
import re
import shutil
import time

from . import v3_macos27

STATE = "golden-gate.json"
STAGED = "OC-27-staged"
KEPT = "OC-26"
DRIVER = "NullMoth-v3"          # where an older 1401 copied the driver package, beside EFI; removed when found
FROM_MAJOR = 26
TARGET = "27.2"
# Chosen by us, not measured: Apple's installer is about 17 GB and a fresh macOS 27 volume needs about as much again
# while it installs. 60 GB leaves room for both and for the first start's caches.
# One number for the room macOS 27 needs on the disk macOS 26 runs from, from the lay-down step's own figures: 45 GB
# for the new volumes and 49 GB of work files while it runs (26 GB downloaded from Apple, 23 GB unpacked). The Mac
# app's script has the same number; the lay-down step checks its container and work folder again before it starts.
FROM_MAJORS = (15, 26)                    # either macOS the driver supports; no point release is refused by its number
MIN_DISK_BYTES = 102 * 1024 ** 3          # and 8 GB of work space for the kernel collections step before that
# Room kept free on the startup partition after the staged copy, for the files OpenCore and macOS write there.
ESP_MARGIN_BYTES = 8 * 1024 ** 2
INSTALLER_NOTE = (f"Next, on the Mac: Install macOS {TARGET.split('.')[0]} in 1401 puts it on its own volumes beside macOS 26 "
                  "(it downloads Apple's restore image from Apple, about 26 GB), then Set up, then the switch of startup files.")


class Refused(RuntimeError):
    """A Golden Gate step that cannot run as asked. Nothing was changed."""


def offered(explicit=""):
    """The loaded kit when Golden Gate is offered here, else None. This is the one switch: no kit, no macOS 27."""
    path = v3_macos27.kit_dir(explicit)
    if not path:
        return None
    try:
        return v3_macos27.load_kit(path)
    except v3_macos27.KitError:
        return None


def _require(explicit=""):
    kit = offered(explicit)
    if kit is None:
        raise Refused(v3_macos27.not_offered_message())
    return kit


def is_1401_efi(efi_root):
    """True when the startup files under efi_root/EFI/OC were made by 1401: the build marker beside EFI, or an entry
    1401's own passes label ("1401 | ...", and the Mac app's "1401: Remove NVIDIA driver" tool)."""
    if os.path.isfile(os.path.join(efi_root, ".1401-build")):
        return True
    try:
        with open(os.path.join(efi_root, "EFI", "OC", "config.plist"), "rb") as fh:
            cfg = plistlib.load(fh)
    except (OSError, ValueError):
        return False
    rows = []
    for section, key in (("Kernel", "Add"), ("Kernel", "Patch"), ("ACPI", "Add"), ("Misc", "Tools")):
        rows += (cfg.get(section) or {}).get(key) or []
    return any(isinstance(r, dict) and re.match(r"1401( \||:)", str(r.get("Comment") or r.get("Name") or "")) for r in rows)


def supported_ids(kit):
    """The NVIDIA device IDs macOS 27 is offered for: every card the driver takes, from the same table the driver
    install for macOS 15 and 26 uses. Returns (ids, source)."""
    from . import nullmoth  # noqa: PLC0415
    return set(nullmoth.TABLE["ids"]), "the driver's list"


def tried_ids(kit):
    """The cards macOS 27 has been started on: the kit's own list when it carries one, else the ones this repository
    records. They decide what a passing check says, never whether it passes."""
    from . import nullmoth  # noqa: PLC0415
    ids = kit.get("gpu_ids")
    return {str(i).upper() for i in (ids if isinstance(ids, list) and ids else nullmoth.TABLE["tested"])}


def card_refusal(cards, ids=None):
    """Why none of these device IDs is accepted, in the words the user reads."""
    return f"no NVIDIA card the driver takes was found (found {', '.join(cards) or 'none'})"


SEND_LOGS = ("If macOS 27 does not reach its desktop, start macOS 26 from the 1401 USB stick and press Send logs there: "
             "1401 reads the macOS 27 volume's logs from macOS 26, and that is how the failure reaches us")


def untried(kit, hit, machine):
    """What about this PC macOS 27 has not been started on yet, as one sentence group, or "". Said, never refused:
    every PC that 1401 builds for and the driver runs on under macOS 26 may try it."""
    from . import nullmoth  # noqa: PLC0415
    parts = []
    tried = tried_ids(kit)
    if hit and hit not in tried:
        so_far = ", ".join(sorted(f"{nullmoth.TABLE['ids'].get(i, 'NVIDIA card')} ({i})" for i in tried)) or "none"
        parts.append(f"macOS 27 has not been run on {nullmoth.TABLE['ids'].get(hit, 'this card')} yet (so far: {so_far}). This is a beta: it may not start")
    if (machine or {}).get("cpu_vendor") == "AMD":
        parts.append("macOS 27 with this kit has not been started on a PC with an AMD processor yet")
    if (machine or {}).get("laptop"):
        parts.append("macOS 27 with this kit has not been started on a laptop yet; its built-in screen and its switch between two graphics chips are untried")
    return (". ".join(parts) + ". " + SEND_LOGS) if parts else ""


def machine_of(report):
    """What preflight needs to know about the PC beyond its cards, from a scan report: the processor's maker and
    whether it is a laptop."""
    cpu = (report or {}).get("CPU") or {}
    text = f"{cpu.get('Manufacturer', '')} {cpu.get('Processor Name', '')}"
    vendor = "AMD" if "AMD" in text else "Intel" if "Intel" in text else ""
    return {"cpu_vendor": vendor, "laptop": ((report or {}).get("Motherboard") or {}).get("Platform") == "Laptop"}


# Kept for callers that name them: an AMD processor and a laptop are no longer refused, only said (see untried()).
# What passing preflight does not say; shown with the checks so that nobody reads "ready" as "tried on a PC like mine".
UNTRIED_NOTE = ("macOS 27 has been started on one desktop PC so far. On a different board or processor generation it is "
                "untried and may not start; cancel puts the startup files back, and the 1401 USB stick still starts macOS 26")
REFUSE_AMD = ("this PC has an AMD processor. macOS 27 with this kit has only ever been started on PCs with an Intel "
              "processor, and the platform files it adds were written for one. This beta does not offer it")
REFUSE_LAPTOP = ("this PC is a laptop. macOS 27 with this kit has only ever been started on desktop PCs; a laptop's "
                 "built-in screen and its switch between two graphics chips have never been tried. This beta does not offer it")


def _tree_bytes(path):
    total = 0
    for base, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(base, f)).st_size
            except OSError:
                pass
    return total


def read_state(efi_root):
    """The recorded state, after repairing a swap that a stopped run left half done (see _heal)."""
    _heal(efi_root)
    return _load_state(efi_root)


def _load_state(efi_root):
    try:
        with open(os.path.join(efi_root, "EFI", STATE), "rb") as fh:
            s = json.loads(fh.read(65536))
    except FileNotFoundError:
        return {"state": "none"}
    except (OSError, ValueError) as e:
        raise Refused(f"the Golden Gate state file on this partition cannot be read ({e}); nothing was changed") from e
    if not isinstance(s, dict) or s.get("state") not in ("staged", "active"):
        raise Refused("the Golden Gate state file on this partition is not one 1401 wrote; nothing was changed")
    return s


def _write_state(efi_root, state):
    path = os.path.join(efi_root, "EFI", STATE)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _folders(efi_root):
    efi = os.path.join(efi_root, "EFI")
    return {n: os.path.isdir(os.path.join(efi, n)) for n in ("OC", STAGED, KEPT)}


def _heal(efi_root):
    """Making the macOS 27 files the default, and putting macOS 26's back, are each two renames. A run stopped between
    them (power, a pulled stick) leaves no EFI/OC at all: the PC cannot start from this partition, and every step
    used to refuse the layout, so nothing here could repair it. With EFI/OC missing and both other folders present,
    macOS 26's files go back as EFI/OC and the record says staged - the state that always starts."""
    efi = os.path.join(efi_root, "EFI")
    have = _folders(efi_root)
    if have["OC"] or not (have[STAGED] and have[KEPT]):
        return False
    os.rename(os.path.join(efi, KEPT), os.path.join(efi, "OC"))
    try:
        state = _load_state(efi_root)
    except Refused:
        state = {"state": "none"}
    if state.get("state") in ("staged", "active"):
        state["state"] = "staged"
        _write_state(efi_root, state)
    return True


def _check_layout(efi_root, state):
    """The folders must be the ones the state names. Anything else was changed by hand or by a stopped run."""
    have = _folders(efi_root)
    want = {"none": {"OC": True, STAGED: False, KEPT: False},
            "staged": {"OC": True, STAGED: True, KEPT: False},
            "active": {"OC": True, STAGED: False, KEPT: True}}[state["state"]]
    if have != want:
        raise Refused(f"the startup partition is not in the state its Golden Gate record says ({state['state']}): "
                      f"folders present {sorted(n for n, v in have.items() if v)}. Nothing was changed")


def preflight(efi_root, macos_major, gpu_ids, disk_free, kit_path="", esp_free=None, machine=None):
    """Every check, pass or fail, as {"check", "ok", "detail"}. Changes nothing. The caller measures what only the
    running system knows (macOS version, cards, free space on the disk macOS 27 will go on)."""
    out = []

    def add(name, ok, detail):
        out.append({"check": name, "ok": bool(ok), "detail": detail})

    kit = offered(kit_path)
    add("offered", kit is not None, "the v3 kit is present" if kit else v3_macos27.not_offered_message())
    if kit is None:
        return out
    add("macos", macos_major in FROM_MAJORS,
        f"this Mac runs macOS {macos_major}" + ("" if macos_major in FROM_MAJORS else "; Golden Gate starts from macOS 15 or 26"))
    ids, source = supported_ids(kit)
    cards = [g.upper() for g in gpu_ids]
    hit = [g for g in cards if g in ids]
    from . import nullmoth  # noqa: PLC0415
    add("gpu", bool(hit), (f"NVIDIA card {nullmoth.TABLE['ids'][hit[0]]} ({hit[0]}) is one the driver takes" if hit else card_refusal(cards)))
    add("untried", True, UNTRIED_NOTE)
    said = untried(kit, hit[0] if hit else "", machine)
    if said:
        add("untried-here", True, said)
    oc = os.path.join(efi_root, "EFI", "OC")
    has_oc = os.path.isfile(os.path.join(oc, "config.plist"))
    add("efi", has_oc and is_1401_efi(efi_root),
        "the startup files are a 1401 build" if has_oc and is_1401_efi(efi_root) else
        ("the startup files here were not made by 1401; build them with 1401 first" if has_oc else
         f"no OpenCore startup files at {oc}"))
    if has_oc:
        need = _tree_bytes(oc) + _tree_bytes(os.path.join(kit["_path"], "Kexts")) + ESP_MARGIN_BYTES
        free = shutil.disk_usage(efi_root).free if esp_free is None else esp_free
        add("efi-space", free >= need,
            f"the startup partition has {free // 2 ** 20} MB free; the macOS 27 copy needs {need // 2 ** 20} MB")
    add("disk-space", disk_free >= MIN_DISK_BYTES,
        f"{disk_free // 2 ** 30} GB free for macOS 27; {MIN_DISK_BYTES // 2 ** 30} GB needed")
    try:
        state = read_state(efi_root)
        if has_oc:
            _check_layout(efi_root, state)
        add("state", True, f"Golden Gate state: {state['state']}")
    except Refused as e:
        add("state", False, str(e))
    return out


def _package_source(kit, key):
    """One of the kit's two packages (key is "driver" or "system"): its folder in the kit and its installer, or
    (None, why). The manifest names each as a plain folder in the kit and a plain file in that folder."""
    d = kit.get(key)
    if not isinstance(d, dict) or not d.get("dir") or not d.get("installer"):
        return None, f"the v3 kit carries no {key} package"
    name, inst = str(d["dir"]), str(d["installer"])
    if os.sep in name or name.startswith(".") or os.sep in inst or inst.startswith("."):
        return None, f"the v3 kit's {key} entry is not a plain folder and file name"
    src = os.path.join(kit["_path"], name)
    if os.path.islink(src) or os.path.islink(os.path.join(src, inst)) or not os.path.isfile(os.path.join(src, inst)):
        return None, f"the v3 kit names a {key} installer that is not there ({name}/{inst})"
    link = outside_symlink(src)
    if link:
        return None, f"the v3 kit's {key} package holds a symbolic link that leaves it ({os.path.relpath(link, kit['_path'])})"
    return (src, inst), ""


def outside_symlink(folder):
    """The first symbolic link in folder that names anything but a file or folder inside it, or "". A package is
    copied and its installer run as root, so a link may only name, by a relative path, something inside the package
    (a bundle's Versions/Current, a library's short name): a full path, a path that climbs out, or a link that names
    nothing would bring in a file from outside that nothing here has checked. The folder itself may not be a link."""
    if os.path.islink(folder):
        return folder
    root = os.path.realpath(folder)
    for base, dirs, files in os.walk(folder):
        for n in sorted(dirs + files):
            p = os.path.join(base, n)
            if not os.path.islink(p):
                continue
            real = os.path.realpath(p)
            if os.path.isabs(os.readlink(p)) or not real.startswith(root + os.sep) or not os.path.exists(real):
                return p
    return ""


def driver_source(kit):
    """The v3 driver folder in the kit and its installer, or (None, why). The kit names them under "driver":
    {"dir": "driver", "installer": "install-macos27.sh"}."""
    return _package_source(kit, "driver")


def system_source(kit):
    """The system package in the kit (the interpreter and routes that let Apple's arm64-only programs run on macOS 27)
    and its installer, or (None, why). The kit names them under "system":
    {"dir": "system", "installer": "install-system.sh"}.

    The finish step (nullmoth-golden-gate.sh, from macOS 26) runs this installer before the driver installer, each
    with --payload <package folder> --system <volume> --data <volume> --esp <startup partition>: both dry runs first
    (--dry-run), then the system installer with --apply, then the driver installer with --apply. Finish refuses a kit without
    either package. Both packages are run from the kit itself; neither is copied to the startup partition."""
    return _package_source(kit, "system")


def stage(efi_root, kit_path="", report=None, min_free=None, kit_model=False):
    """Makes EFI/OC-27-staged from a copy of EFI/OC and the kit. EFI/OC is not touched. Returns the state written."""
    kit = _require(kit_path)
    state = read_state(efi_root)
    if state["state"] != "none":
        raise Refused(f"Golden Gate is already {state['state']} on this partition; cancel it first to stage again")
    _check_layout(efi_root, state)
    if not is_1401_efi(efi_root):
        raise Refused("the startup files here were not made by 1401; nothing was changed")
    efi = os.path.join(efi_root, "EFI")
    need = _tree_bytes(os.path.join(efi, "OC")) + _tree_bytes(os.path.join(kit["_path"], "Kexts")) + ESP_MARGIN_BYTES
    free = shutil.disk_usage(efi_root).free if min_free is None else min_free
    if free < need:
        raise Refused(f"the startup partition has {free // 2 ** 20} MB free and the macOS 27 copy needs {need // 2 ** 20} MB")
    # The kit is applied in a scratch tree shaped like an EFI root, then moved into place in one rename: a stopped
    # run leaves a scratch folder that the next run removes, never a half-made staged folder.
    scratch = os.path.join(efi, ".golden-gate-scratch")
    staged_driver = os.path.join(efi_root, DRIVER)
    if os.path.lexists(scratch):
        shutil.rmtree(scratch)
    notices, driver_note = [], ""
    try:
        shutil.copytree(os.path.join(efi, "OC"), os.path.join(scratch, "EFI", "OC"), symlinks=True)
        changes = v3_macos27.apply(scratch, kit, notices, report, kit_model=kit_model)
        os.rename(os.path.join(scratch, "EFI", "OC"), os.path.join(efi, STAGED))
        src, why = driver_source(kit)
        # Neither package is copied to the startup partition: finish runs both from the kit and never from this
        # partition, and the driver package (several hundred MB) is larger than a startup partition has room for.
        if os.path.lexists(staged_driver):
            shutil.rmtree(staged_driver)
        if src:
            driver_note = f"in the kit with its installer {src[1]}"
        elif "symbolic link" in why:                 # a package that could bring in a file from outside it
            raise OSError(why)
        else:
            driver_note = f"not usable: {why}; finish will refuse until the kit carries a driver package"
        sysrc, swhy = system_source(kit)
        system_note = (f"in the kit with its installer {sysrc[1]}" if sysrc
                       else f"not usable: {swhy}; finish will refuse until the kit carries a system package")
    except (OSError, v3_macos27.KitError, KeyError) as e:
        shutil.rmtree(os.path.join(efi, STAGED), ignore_errors=True)
        shutil.rmtree(staged_driver, ignore_errors=True)
        raise Refused(f"the macOS 27 startup files could not be staged ({e}); EFI/OC is unchanged") from e
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    state = {"state": "staged", "from_major": FROM_MAJOR, "target": TARGET, "staged_at": int(time.time()),
             "kit_kexts": len([c for c in changes if c["v3"] in ("added", "replaced")]),
             "driver": driver_note, "driver_installer": src[1] if src else "", "system": system_note,
             "model": next((c["model"] for c in changes if c["v3"] == "identity"), "kept from the kit")}
    _write_state(efi_root, state)
    return state


def activate(efi_root, confirmed=False, kit_path=""):
    """Makes the staged macOS 27 startup files the ones the firmware starts. macOS 26's are kept as EFI/OC-26."""
    _require(kit_path)
    if not confirmed:
        raise Refused("the macOS 27 startup files become the default only when the user confirms it; nothing was changed")
    state = read_state(efi_root)
    if state["state"] != "staged":
        raise Refused(f"there are no staged macOS 27 startup files to make the default (state: {state['state']})")
    _check_layout(efi_root, state)
    efi = os.path.join(efi_root, "EFI")
    os.rename(os.path.join(efi, "OC"), os.path.join(efi, KEPT))
    try:
        os.rename(os.path.join(efi, STAGED), os.path.join(efi, "OC"))
    except OSError as e:
        os.rename(os.path.join(efi, KEPT), os.path.join(efi, "OC"))
        raise Refused(f"the staged files could not be made the default ({e}); macOS 26's startup files are back") from e
    state.update(state="active", activated_at=int(time.time()))
    _write_state(efi_root, state)
    return state


def rollback(efi_root):
    """macOS 26's own startup files start the PC again; the macOS 27 ones go back to staged. Needs no kit: the way
    back must work on a PC whose kit is gone."""
    state = read_state(efi_root)
    if state["state"] != "active":
        raise Refused(f"macOS 26's startup files are already the default (state: {state['state']})")
    _check_layout(efi_root, state)
    efi = os.path.join(efi_root, "EFI")
    os.rename(os.path.join(efi, "OC"), os.path.join(efi, STAGED))
    try:
        os.rename(os.path.join(efi, KEPT), os.path.join(efi, "OC"))
    except OSError as e:
        os.rename(os.path.join(efi, STAGED), os.path.join(efi, "OC"))
        raise Refused(f"macOS 26's startup files could not be put back ({e}); the partition is as it was") from e
    state.update(state="staged")
    state.pop("activated_at", None)
    _write_state(efi_root, state)
    return state


def cancel(efi_root):
    """Removes everything stage made, after a rollback when the macOS 27 files are the default. Needs no kit."""
    state = read_state(efi_root)
    if state["state"] == "none":
        return state
    if state["state"] == "active":
        rollback(efi_root)
        state = read_state(efi_root)
    _check_layout(efi_root, state)
    shutil.rmtree(os.path.join(efi_root, "EFI", STAGED))
    shutil.rmtree(os.path.join(efi_root, DRIVER), ignore_errors=True)
    os.remove(os.path.join(efi_root, "EFI", STATE))
    return {"state": "none"}


def boot_entry_for_26(efi_root):
    """Not done: a picker entry that starts EFI/OC-26 while the macOS 27 files are the default.

    Whether OpenCore started from EFI/OC-26/OpenCore.efi reads its config from that folder has not been tried on a
    PC, and an entry that starts the wrong config is worse than none. Until it has, the way back is rollback() from
    macOS 26, or the 1401 USB stick, which still starts macOS 26."""
    raise Refused("a macOS 26 entry in the boot picker is not available yet. Keep the 1401 USB stick: it starts "
                  "macOS 26, and Cancel Golden Gate from macOS 26 puts its startup files back.")


def main(argv):
    """python -m p1401 golden-gate <step> <EFI partition root> [options]; prints one JSON object."""
    import argparse  # noqa: PLC0415
    ap = argparse.ArgumentParser(prog="1401 golden-gate")
    ap.add_argument("step", choices=["preflight", "stage", "activate", "rollback", "cancel", "status", "entry26"])
    ap.add_argument("efi_root", help="the folder that holds EFI (the mounted startup partition or the stick)")
    ap.add_argument("--v3-kit", default="")
    ap.add_argument("--macos-major", type=int, default=0)
    ap.add_argument("--gpu-id", action="append", default=[], help="an NVIDIA device ID, four hex digits")
    ap.add_argument("--disk-free-gb", type=float, default=0.0)
    ap.add_argument("--confirm", action="store_true", help="activate: the user confirmed the change of default")
    ap.add_argument("--report", default="", help="the scan's Report.json: its NVIDIA cards and Bluetooth adapter are used")
    ap.add_argument("--kit-model", action="store_true",
                    help="stage: keep the model the kit sets instead of the model for this card's generation")
    ap.add_argument("--plain", action="store_true", help="print sentences instead of JSON")
    a = ap.parse_args(argv)
    try:
        report = None
        if a.report:
            from . import nullmoth  # noqa: PLC0415
            try:
                with open(a.report, "rb") as fh:
                    report = json.loads(fh.read(64 * 1024 * 1024))
            except (OSError, ValueError) as e:
                raise Refused(f"the scan report {a.report} could not be read ({e}); nothing was changed") from e
            a.gpu_id += [nullmoth._pid(g) for g in (report.get("GPU") or {}).values() if isinstance(g, dict) and nullmoth._pid(g)]
            if a.step == "stage":
                ids, source = supported_ids(_require(a.v3_kit))
                if not any(g.upper() in ids for g in a.gpu_id):
                    raise Refused(card_refusal([g.upper() for g in a.gpu_id]) + "; nothing was changed")
        if a.step == "preflight":
            checks = preflight(a.efi_root, a.macos_major, a.gpu_id, int(a.disk_free_gb * 1024 ** 3), a.v3_kit,
                               machine=machine_of(report) if report is not None else None)
            ok = all(c["ok"] for c in checks)
            out = {"ok": ok, "checks": checks, "installer": INSTALLER_NOTE if ok else ""}
        elif a.step == "stage":
            out = {"ok": True, **stage(a.efi_root, a.v3_kit, report, kit_model=a.kit_model), "installer": INSTALLER_NOTE}
        elif a.step == "activate":
            out = {"ok": True, **activate(a.efi_root, a.confirm, a.v3_kit)}
        elif a.step == "rollback":
            out = {"ok": True, **rollback(a.efi_root)}
        elif a.step == "cancel":
            out = {"ok": True, **cancel(a.efi_root)}
        elif a.step == "entry26":
            out = {"ok": True, **(boot_entry_for_26(a.efi_root) or {})}
        else:
            out = {"ok": True, **read_state(a.efi_root)}
    except Refused as e:
        out = {"ok": False, "why": str(e)}
    if a.plain:
        if not out["ok"]:
            print(out["why"])
        else:
            print(f"Golden Gate state: {out.get('state', 'checked')}")
            for c in out.get("checks", []):
                print(("ok: " if c["ok"] else "FAILED: ") + c["detail"])
            if out.get("driver"):
                print("Driver package: " + out["driver"])
            if out.get("system"):
                print("System package: " + out["system"])
            if out.get("model"):
                print("Model: " + out["model"])
            if out.get("installer"):
                print(out["installer"])
    else:
        print(json.dumps(out, indent=1, sort_keys=True))
    return 0 if out["ok"] else 1
