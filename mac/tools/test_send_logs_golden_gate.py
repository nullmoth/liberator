#!/usr/bin/env python3
"""Send logs on macOS 26 carries what is needed when Golden Gate stops at any step.

The move to macOS 27 is made from macOS 26, and macOS 26 is where the user still is when it stops: after a failed
check, a lay-down that stopped, a set-up that stopped, or a first start of macOS 27 that never reached a desktop
(the user comes back through the 1401 USB stick). The collector's Golden Gate sources (nullmoth-setup.sh) read the
step log, the lay-down log, the kit, the record and model on a startup partition, and what macOS 27 wrote on its
own volume. They are run here against fixture folders standing in for this macOS, a startup partition and the
mounted volumes. Nothing personal leaves: a serial is cut to its last 4 characters, a path under the users folder loses the
user's name, and of a crash report only its name and the interpreter's own lines are taken."""
import json
import os
import pathlib
import plistlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "Resources/nullmoth-setup.sh"
fails = 0
SERIAL = "C02ZX9ABCDEF"
HOMEDIR = "/" + "Users" + "/pat"            # a home folder as it would appear in a log; it must never be in what is sent


def arm(name, ok, detail=""):
    global fails
    fails += not ok
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f" ({str(detail).strip()[-700:]})"))


def between(text, start, end):
    i = text.index(start)
    return text[i:text.index(end, i) + len(end)]


src = SRC.read_text()
block = between(src, "# --- macOS 27 sources ---", "# --- end macOS 27 sources ---")
block += between(src, "# --- Golden Gate sources (read from macOS 26) ---", "# --- end Golden Gate sources ---")
bounded = between(src, "bounded() {  # <seconds> <command...>", "  return $rc\n}\n")


def put(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


# diskutil is stood in for by a shell function: it answers "info -plist <identifier>" from files the test writes
DISKUTIL = 'diskutil() { [ "$1 $2" = "info -plist" ] || return 1; local k=$3; [ "$k" = / ] && k=root; cat "$STUB/$k.plist" 2>/dev/null; }\n'
SYS_UUID, DATA_UUID = "11111111-AAAA-4BBB-8CCC-000000000001", "11111111-AAAA-4BBB-8CCC-000000000002"


# The reader every file on the other volume goes through (RuntimeCheck/safe_read.c), built once for this machine.
READER_DIR = tempfile.mkdtemp()
READER = os.path.join(READER_DIR, "nullmoth-safe-read")
subprocess.run(["xcrun", "clang", "-O2", "-Wall", "-Wextra", "-Werror", str(ROOT / "RuntimeCheck/safe_read.c"), "-o", READER], check=True)


def run(call, stub="", reader=READER):
    p = subprocess.run(["/bin/bash", "-c", "set -u\n" + bounded + block + "\n" + DISKUTIL + call], capture_output=True, text=True, timeout=120,
                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "HOME": "/var/empty", "STUB": str(stub),
                            "GG_SAFE_READ_FOR_TESTS": reader})
    return p.stdout + p.stderr


def record(root, stub, sysmp, datamp, container="disk1", write=True):
    """The record the install step writes on this macOS, and what diskutil answers for the two volumes it names."""
    stub.mkdir(parents=True, exist_ok=True)
    for key, fields in (("root", dict(APFSContainerReference="disk1", FilesystemType="apfs", MountPoint="/")),
                        (SYS_UUID, dict(APFSContainerReference=container, FilesystemType="apfs", MountPoint=str(sysmp))),
                        (DATA_UUID, dict(APFSContainerReference=container, FilesystemType="apfs", MountPoint=str(datamp)))):
        with open(stub / (key + ".plist"), "wb") as fh:
            plistlib.dump(fields, fh)
    if write:
        put(root / "Library/NullMoth/golden-gate/macos27-volumes", f"system {SYS_UUID}\ndata {DATA_UUID}\n")


def volume(vols, name, version="27.2", data=True, account=None):
    core = vols / name / "System/Library/CoreServices"
    core.mkdir(parents=True)
    with open(core / "SystemVersion.plist", "wb") as fh:
        plistlib.dump({"ProductVersion": version, "ProductBuildVersion": "26B123"}, fh)
    d = vols / f"{name} - Data"
    if data:
        (d / "private/var/tmp").mkdir(parents=True)
        (d / "private/var/log").mkdir(parents=True)
        (d / "Library").mkdir()
        (d / "Users/Shared").mkdir(parents=True)
        if account:
            (d / "Users" / account).mkdir()
    return d


arm("the script still parses", subprocess.run(["/bin/bash", "-n", str(SRC)]).returncode == 0)
with tempfile.TemporaryDirectory() as td:
    td = pathlib.Path(td)
    # this macOS (26): a kit, a step log, a lay-down log
    r26 = td / "root26"
    put(r26 / "Library/NullMoth/v3-kit/v3-kit.json", json.dumps({"kit": "nullmoth-v3-macos27", "system": {"dir": "system", "installer": "install-system.sh"},
                                                                  "driver": {"dir": "driver", "installer": "install-driver.sh"}}))
    put(r26 / "Library/NullMoth/v3-kit/driver/MANIFEST", "F 755 0 /x\n")
    put(r26 / "Library/NullMoth/golden-gate/steps.log",
        "== 2026-11-10 03:00:00 preflight\nFAIL room for macOS 27: 80 GB free, 94 GB needed\nSTOP 1 check(s) failed. Nothing was changed\n"
        "== 2026-11-10 03:20:00 installer\nSTEP Laying macOS 27 down on its own volumes\nwork folder " + HOMEDIR + "/Downloads/work\n")
    put(r26 / "Library/NullMoth/golden-gate/laydown.log", "STOP the restore image did not verify\n")
    empty = td / "no-volumes"
    empty.mkdir()
    out = run(f'gg_sources "{r26}" | gg_private')
    arm("stopped at the check (prepare): the step log carries the failed check and the reason, under the step's own heading",
        "preflight\nFAIL room for macOS 27: 80 GB free, 94 GB needed\nSTOP 1 check(s) failed" in out and "== Golden Gate step log" in out, out)
    arm("stopped while laying macOS 27 down: the step log's last lines and the lay-down log are both carried",
        "STEP Laying macOS 27 down on its own volumes" in out and "== lay-down log (/Library/NullMoth/golden-gate/laydown.log)\nSTOP the restore image did not verify" in out, out)
    arm("the kit is named by its manifest's hash, with its three packages (one missing says so)",
        "goldengate: kit nullmoth-v3-macos27, manifest md5 " in out and "  system: system/install-system.sh" in out
        and "  laydown: none/none" in out and "driver MANIFEST md5 " in out, out)
    arm("with no macOS 27 laid down by this app it says so instead of staying silent",
        "goldengate: the macOS 27 volumes were not read: no macOS 27 has been laid down by this app on this Mac" in out, out)
    arm("a user's name in a path does not leave: /Users/<name> is cut (control: the log has one)",
        HOMEDIR not in out and "work folder ~/Downloads/work" in out
        and HOMEDIR in (r26 / "Library/NullMoth/golden-gate/steps.log").read_text(), out)
    bare = td / "bare26"
    bare.mkdir()
    out = run(f'gg_sources "{bare}" | gg_private')
    arm("a Mac with no kit and no logs says each is absent", "goldengate: no v3 kit installed" in out and out.count("(not present: nothing on this Mac has written it)") == 2, out)

    # a startup partition: staged, then switched (activate)
    esp = td / "esp"
    cfg = {"PlatformInfo": {"Generic": {"SystemProductName": "MacPro7,1", "SystemSerialNumber": SERIAL}}, "Kernel": {"Add": [{}, {}, {}]}}
    for d, model in (("OC", "MacPro7,1"), ("OC-27-staged", "Mac17,15")):
        (esp / "EFI" / d).mkdir(parents=True)
        c = dict(cfg, PlatformInfo={"Generic": {"SystemProductName": model, "SystemSerialNumber": SERIAL}})
        with open(esp / "EFI" / d / "config.plist", "wb") as fh:
            plistlib.dump(c, fh)
    put(esp / "EFI/golden-gate.json", json.dumps({"state": "staged", "staged_at": 1, "driver": "in the kit with its installer install-driver.sh", "system": "in the kit"}))
    out = run(f'gg_partition "{esp}" disk0s1 | gg_private')
    arm("stopped after staging: the record's state and the model of each set of startup files are carried",
        "goldengate: state staged" in out and "EFI/OC: model MacPro7,1" in out and "EFI/OC-27-staged: model Mac17,15" in out and "kernel entries 3" in out, out)
    arm("the serial number is cut to its last 4 characters (control: the config holds the whole one)",
        SERIAL not in out and "serial ...CDEF" in out and SERIAL.encode() in (esp / "EFI/OC/config.plist").read_bytes(), out)
    os.rename(esp / "EFI/OC", esp / "EFI/OC-26")
    os.rename(esp / "EFI/OC-27-staged", esp / "EFI/OC")
    put(esp / "EFI/golden-gate.json", json.dumps({"state": "active"}))
    out = run(f'gg_partition "{esp}" disk0s1')
    arm("stopped after the switch (activate): state active, the macOS 27 files as the default and macOS 26's kept",
        "goldengate: state active" in out and "EFI/OC: model Mac17,15" in out and "EFI/OC-26: model MacPro7,1" in out, out)
    plain = td / "plain-esp"
    (plain / "EFI/OC").mkdir(parents=True)
    arm("a startup partition Golden Gate never touched adds nothing", run(f'gg_partition "{plain}" disk9s1') == "")

    # macOS 27 on its own volumes, never reached a desktop. It is found by the record the install step wrote.
    vols = td / "Volumes"
    data = volume(vols, "macOS 27")
    volume(vols, "Macintosh HD", version="26.7.1", account="pat")
    stub = td / "stub"
    record(r26, stub, vols / "macOS 27", data)
    put(data / "Library/NullMoth/golden-gate/install.log", "2026-11-10 04:00:00 routes: 366 listed, 0 failed\n")
    put(data / "Library/NullMoth/golden-gate/driver/install.log", "2026-11-10 04:05:00 driver files: 53 listed, 0 already current, 53 placed\n")
    out = run(f'gg_other_volume "{r26}" | gg_private', stub)
    arm("stopped after set-up (finish), before any start: both installers' logs are read off the macOS 27 volume, and the start-up logs say they were never written",
        "routes: 366 listed, 0 failed" in out and "driver files: 53 listed" in out and "(private/var/tmp/nvload.log)\n(not present" in out
        and "goldengate: first-start logs read from the macOS 27 volume (27.2)" in out, out)
    arm("a macOS 27 volume with no account yet (it starts at Apple's setup) is read the same, and says so",
        "accounts on it: none yet (it starts at Apple's setup)" in out and "interpreter: NOT installed" in out, out)
    put(data / "private/var/tmp/nvload.log", "2026-11-10 04:30:00 NOT healthy (WindowServer never held one pid for 30 s in 60 s)\n")
    put(data / "private/var/tmp/ws-gate.log", "framebuffer link: none after 20 s\n")
    put(data / "private/var/tmp/ws-stderr.log", "ordinary\nFATAL: no display pipe\na2x-stop: frame 0 SkyLight +0x99\n")
    put(data / "private/var/log/auxkcload.log", "auxkcload: collection refused: wrong kernel\n")
    put(data / "private/var/tmp/a2x-reports/Setup Assistant.log", "FATAL: scene refused\na2x-stop: frame 0 UIKitMacHelper\nfree text that is not a record line\n")
    put(data / "Library/Logs/DiagnosticReports/WindowServer-2026-11-10-043000.ips",
        '{"procPath":"' + HOMEDIR + '/x","asi":["a2x-stop: frame 3 QuartzCore"],"other":"private detail"}\n')
    put(data / "Library/Logs/DiagnosticReports/Kernel-2026-11-10.panic", "panic(cpu 0): something\n")
    (data / "Users/pat").mkdir()
    (vols / "macOS 27/usr/libexec/a2x").mkdir(parents=True)
    out = run(f'gg_other_volume "{r26}" | gg_private', stub)
    arm("first boot never reached the desktop: logs are read from the other volume (display hand-over, the gates, the window server's output, the collection loader)",
        "NOT healthy (WindowServer never held one pid" in out and "framebuffer link: none after 20 s" in out
        and "auxkcload: collection refused: wrong kernel" in out and "== window server output (private/var/tmp/ws-stderr.log)" in out, out)
    arm("  the interpreter's stop lines and each stop record it left are carried, their own lines only (a record's name may hold a space)",
        "== interpreter stop lines in the window server output\n    FATAL: no display pipe\n    a2x-stop: frame 0 SkyLight +0x99" in out
        and "-- Setup Assistant.log\n    FATAL: scene refused\n    a2x-stop: frame 0 UIKitMacHelper" in out and "free text that is not a record line" not in out
        and "goldengate: interpreter stop records 1" in out, out)
    arm("  crash reports and panics are listed by name with the interpreter's lines, and nothing else of them is taken",
        "WindowServer-2026-11-10-043000.ips\n    a2x-stop: frame 3 QuartzCore" in out and "Kernel-2026-11-10.panic" in out
        and "goldengate: crash reports listed 2" in out and "private detail" not in out and "panic(cpu 0)" not in out, out)
    arm("  what is on the volume is said: accounts, interpreter, collections", "accounts on it: yes" in out and "interpreter: installed" in out
        and "auxiliary collection: MISSING" in out, out)
    arm("  no user name leaves", "pat" not in out, out)

    # the collection runs as root and its output leaves the Mac: nothing on the other volume may point it elsewhere
    secret = td / "secret.txt"
    secret.write_text("TOP SECRET CONTENT\n")
    os.remove(data / "private/var/tmp/nvload.log")
    os.symlink(secret, data / "private/var/tmp/nvload.log")
    out = run(f'gg_other_volume "{r26}"', stub)
    arm("a symbolic link planted where a log is expected is not followed: the file is named as skipped and its target is not read",
        "TOP SECRET" not in out and "== display hand-over at boot (private/var/tmp/nvload.log)\n(skipped: not a regular file inside the volume: private/var/tmp/nvload.log)" in out
        and "framebuffer link: none after 20 s" in out, out)
    os.remove(data / "private/var/tmp/nvload.log")
    # a second name for a file elsewhere (a hard link) is not a symbolic link: the reader must refuse it by itself
    os.link(secret, data / "private/var/tmp/nvload.log")
    out = run(f'gg_other_volume "{r26}"', stub)
    arm("a hard link planted where a log is expected is not read either (control: it is a regular file, not a symbolic link)",
        "TOP SECRET" not in out and "(skipped: not a regular file inside the volume: private/var/tmp/nvload.log)" in out
        and os.path.isfile(data / "private/var/tmp/nvload.log") and not os.path.islink(data / "private/var/tmp/nvload.log"), out)
    os.remove(data / "private/var/tmp/nvload.log")
    put(data / "private/var/tmp/nvload.log", "nvload start\nreal content of the log\n")
    out = run(f'gg_other_volume "{r26}"', stub, reader="/nonexistent/nullmoth-safe-read")
    arm("without its reader nothing on the other volume is read, and it says why (control: with the reader the same log is carried)",
        "real content of the log" not in out and "the macOS 27 volumes were not read: this build of 1401 has no reader for the other volume" in out
        and "real content of the log" in run(f'gg_other_volume "{r26}"', stub), out)
    os.remove(data / "private/var/tmp/nvload.log")
    elsewhere = td / "elsewhere"
    put(elsewhere / "install.log", "TOP SECRET CONTENT\n")
    put(elsewhere / "driver/install.log", "TOP SECRET CONTENT\n")
    import shutil
    shutil.rmtree(data / "Library/NullMoth/golden-gate")
    os.symlink(elsewhere, data / "Library/NullMoth/golden-gate")
    out = run(f'gg_other_volume "{r26}"', stub)
    arm("a symbolic link planted as a parent folder is not followed either",
        "TOP SECRET" not in out and out.count("(skipped: not a regular file inside the volume: Library/NullMoth/golden-gate/") >= 2, out)
    os.remove(data / "Library/NullMoth/golden-gate")
    star = "odd name * [a-z] report.ips"
    put(data / "Library/Logs/DiagnosticReports" / star, '{"asi":["a2x-stop: frame 9 odd"]}\n')
    os.symlink(secret, data / "Library/Logs/DiagnosticReports/linked report.ips")
    out = run(f'cd "{data}/Library/Logs/DiagnosticReports" && gg_other_volume "{r26}"', stub)
    arm("a report whose name holds spaces and wildcard characters is listed as one name and read as one file; a linked report is skipped",
        (star + "\n    a2x-stop: frame 9 odd") in out and "goldengate: crash reports listed 4" in out
        and "linked report.ips\n    (skipped: not a regular file inside the volume: linked report.ips)" in out and "TOP SECRET" not in out, out)

    # a volume that only says it is macOS 27 is never read: not recorded, or recorded but in another container
    image = td / "ImageVolumes"
    idata = volume(image, "macOS 27")
    put(idata / "private/var/tmp/nvload.log", "FROM THE IMAGE\n")
    r_none = td / "root-norecord"
    r_none.mkdir()
    out = run(f'gg_other_volume "{r_none}"', stub)
    arm("a mounted volume carrying a 27.x version file is not read when this app recorded no volumes",
        "FROM THE IMAGE" not in out and "the macOS 27 volumes were not read: no macOS 27 has been laid down by this app" in out, out)
    r_img = td / "root-image"
    stub2 = td / "stub-image"
    record(r_img, stub2, image / "macOS 27", idata, container="disk9")
    out = run(f'gg_other_volume "{r_img}"', stub2)
    arm("recorded identifiers that resolve to a disk image (another container than the running system's) are refused and nothing is read",
        "FROM THE IMAGE" not in out and "are not APFS volumes on the disk this macOS runs from" in out, out)
    r_bad = td / "root-badrecord"
    put(r_bad / "Library/NullMoth/golden-gate/macos27-volumes", "system /etc/passwd\ndata x\n")
    out = run(f'gg_other_volume "{r_bad}"', stub)
    arm("a record that is not two volume identifiers is refused", "is not one this app wrote" in out, out)
    r_old = td / "root-old"
    stub3 = td / "stub-old"
    odata = volume(td / "OldVolumes", "Other", version="26.7.1")
    record(r_old, stub3, td / "OldVolumes/Other", odata)
    out = run(f'gg_other_volume "{r_old}"', stub3)
    arm("a recorded volume that does not hold macOS 27 is not read", "does not hold macOS 27 (it says '26.7.1')" in out, out)
    r_um = td / "root-unmounted"
    stub4 = td / "stub-unmounted"
    record(r_um, stub4, "", "")
    out = run(f'gg_other_volume "{r_um}"', stub4)
    arm("the macOS 27 volumes not mounted: it says so and how to get the logs, never a silent gap",
        "the macOS 27 volumes are not mounted (mount them in Disk Utility and send the logs again)" in out, out)

collect = src[src.index('if [ -n "$COLLECT" ]; then'):]
arm("Send logs runs the Golden Gate sources on macOS 26 once Golden Gate has been started, and each startup partition adds its record",
    'gg_sources "" 2>&1 | gg_private >> "$COLLECT/golden-gate.txt"' in collect
    and 'ggp=$(gg_partition "$mp" "$d" 2>&1 | gg_private)' in collect
    and collect.index('ggp=$(gg_partition') < collect.index('gg_sources "" 2>&1'))
arm("golden-gate.txt is among the first files uploaded, before the file limit can drop it",
    "driver-state.txt macos27-state.txt golden-gate.txt driver-kernel-log.txt" in (ROOT / "Resources/nullmoth-log-capture.sh").read_text())
ggsrc = between(src, "# --- Golden Gate sources (read from macOS 26) ---", "# --- end Golden Gate sources ---")
arm("no source looks among mounted volumes for macOS 27: the only way to it is the recorded identifiers",
    "/Volumes" not in ggsrc and 'for v in "$' not in ggsrc and ggsrc.count("gg_volumes \"$1\"") == 1)
arm("nothing is mounted or changed by these sources", not any(w in between(src, "# --- Golden Gate sources (read from macOS 26) ---", "# --- end Golden Gate sources ---")
                                                             for w in ("diskutil mount", "mount -", " rm ", "mv ", "> \"$")))
print(f"{fails} failed")
sys.exit(1 if fails else 0)
