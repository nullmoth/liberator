"""Prepare for Golden Gate (macOS 26 -> 27): offered only with a v3 kit, and every step leaves a way back.

Each guard is checked in both directions: a step that must refuse is shown refusing AND leaving the partition
byte-for-byte as it was, and the same step is shown working when its condition holds.
"""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tools"))
sys.path.insert(0, os.path.join(HERE, "tests"))
from p1401 import golden_gate as gg, v3_macos27  # noqa: E402
from p1401.__main__ import main as cli  # noqa: E402
from test_v3_macos27 import Fixture, read, write  # noqa: E402

GB = 1024 ** 3
CARD = "2D05"


def put(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def manifest(kit, **changes):
    path = os.path.join(kit, v3_macos27.MANIFEST)
    with open(path) as fh:
        m = json.load(fh)
    m.update(changes)
    put(path, json.dumps(m))


def tree(root):
    """Every file under root with its hash: the partition's whole content, for before/after comparisons."""
    out = {}
    for base, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(base, f)
            with open(p, "rb") as fh:
                out[os.path.relpath(p, root)] = hashlib.sha256(fh.read()).hexdigest()
    return out


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(self.tmp.name)
        self.root = self.fx.efi
        put(os.path.join(self.root, ".1401-build"), "built by 1401\n")
        self.kit = self.fx.kit_path
        self.old = os.environ.pop(v3_macos27.KIT_ENV, None)

    def tearDown(self):
        if self.old is not None:
            os.environ[v3_macos27.KIT_ENV] = self.old
        self.tmp.cleanup()

    def failed(self, checks):
        return sorted(c["check"] for c in checks if not c["ok"])

    def add_driver(self):
        d = os.path.join(self.kit, "driver")
        os.makedirs(d)
        put(os.path.join(d, "install-macos27.sh"), "#!/bin/bash\n")
        manifest(self.kit, driver={"dir": "driver", "installer": "install-macos27.sh"})

    def add_system(self):
        d = os.path.join(self.kit, "system")
        os.makedirs(d)
        put(os.path.join(d, "install-system.sh"), "#!/bin/bash\n")
        manifest(self.kit, system={"dir": "system", "installer": "install-system.sh"})


class Switch(Base):
    def test_without_a_kit_every_step_refuses_and_changes_nothing(self):
        before = tree(self.root)
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 110 * GB)), ["offered"])
        with self.assertRaises(gg.Refused):
            gg.stage(self.root)
        with self.assertRaises(gg.Refused):
            gg.activate(self.root, confirmed=True)
        self.assertEqual(tree(self.root), before)

    def test_the_command_line_refuses_without_a_kit(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli(["golden-gate", "stage", self.root])
        self.assertEqual(rc, 1)
        self.assertIn("not offered", json.loads(buf.getvalue())["why"])

    def test_a_broken_kit_is_not_an_offer(self):
        os.remove(os.path.join(self.kit, v3_macos27.MANIFEST))
        self.assertIsNone(gg.offered(self.kit))


class Preflight(Base):
    def test_a_ready_pc_passes_every_check(self):
        checks = gg.preflight(self.root, 26, [CARD], 110 * GB, self.kit)
        self.assertEqual(self.failed(checks), [], checks)

    def test_each_failure_is_named(self):
        self.assertEqual(self.failed(gg.preflight(self.root, 14, [CARD], 110 * GB, self.kit)), ["macos"])
        self.assertEqual(self.failed(gg.preflight(self.root, 15, [CARD], 110 * GB, self.kit)), [])     # 15 is a macOS the driver supports
        self.assertEqual(self.failed(gg.preflight(self.root, 27, [CARD], 110 * GB, self.kit)), ["macos"])
        self.assertEqual(self.failed(gg.preflight(self.root, 26, ["1C03"], 110 * GB, self.kit)), ["gpu"])
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [], 110 * GB, self.kit)), ["gpu"])
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 59 * GB, self.kit)), ["disk-space"])
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 110 * GB, self.kit, esp_free=1024)), ["efi-space"])

    def test_startup_files_1401_did_not_make_are_refused(self):
        os.remove(os.path.join(self.root, ".1401-build"))
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 110 * GB, self.kit)), ["efi"])
        cfg = read(os.path.join(self.root, "EFI", "OC", "config.plist"))
        cfg["Kernel"]["Add"][0]["Comment"] = "1401 | test entry"
        write(os.path.join(self.root, "EFI", "OC", "config.plist"), cfg)
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 110 * GB, self.kit)), [])

    def test_the_kits_card_list_does_not_decide_who_passes(self):
        manifest(self.kit, gpu_ids=["1C03"])                           # a kit cannot narrow or widen the driver's list
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 110 * GB, self.kit)), [])
        self.assertEqual(self.failed(gg.preflight(self.root, 26, ["1c03"], 110 * GB, self.kit)), ["gpu"])

    def test_preflight_changes_nothing(self):
        before = tree(self.root)
        gg.preflight(self.root, 26, [CARD], 110 * GB, self.kit)
        self.assertEqual(tree(self.root), before)


class Steps(Base):
    def oc(self, name="OC"):
        return os.path.join(self.root, "EFI", name)

    def test_stage_leaves_the_default_startup_files_untouched(self):
        before = tree(self.oc())
        state = gg.stage(self.root, self.kit, self.fx.report)
        self.assertEqual(state["state"], "staged")
        self.assertEqual(tree(self.oc()), before)
        staged = read(os.path.join(self.oc(gg.STAGED), "config.plist"))
        self.assertEqual(v3_macos27.diff_reference(staged, self.fx.ref, self.fx.kit,
                                                   os.path.join(self.oc(gg.STAGED), "Kexts"), self.fx.ref_kexts), [])
        self.assertFalse(os.path.exists(os.path.join(self.root, "EFI", ".golden-gate-scratch")))
        self.assertIn("carries no driver package", state["driver"])
        self.assertIn("finish will refuse", state["driver"])

    def test_stage_records_the_driver_the_kit_carries_and_does_not_copy_it(self):
        self.add_driver()
        os.makedirs(os.path.join(self.root, gg.DRIVER))                # a copy an older 1401 left is removed
        put(os.path.join(self.root, gg.DRIVER, "old.bin"), "old")
        state = gg.stage(self.root, self.kit, self.fx.report)
        self.assertEqual(state["driver"], "in the kit with its installer install-macos27.sh")
        self.assertFalse(os.path.lexists(os.path.join(self.root, gg.DRIVER)))
        self.assertFalse(any("install-macos27.sh" in p for p in tree(self.root)))
        self.assertEqual(state["driver_installer"], "install-macos27.sh")

    def test_stage_records_the_system_package_the_kit_carries_and_does_not_copy_it(self):
        self.add_system()
        state = gg.stage(self.root, self.kit, self.fx.report)
        self.assertEqual(state["system"], "in the kit with its installer install-system.sh")
        self.assertEqual(gg.read_state(self.root)["system"], state["system"])
        self.assertFalse(os.path.exists(os.path.join(self.root, "system")))
        self.assertFalse(any("install-system.sh" in p for p in tree(self.root)))

    def test_stage_says_finish_will_refuse_a_kit_without_a_system_package(self):
        state = gg.stage(self.root, self.kit, self.fx.report)          # control: the fixture kit names none
        self.assertIn("carries no system package", state["system"])
        self.assertIn("finish will refuse", state["system"])

    def test_a_system_entry_is_a_plain_folder_and_file_that_exist(self):
        self.add_system()
        kit = v3_macos27.load_kit(self.kit)
        kit["_path"] = self.kit
        src, why = gg.system_source(kit)                               # control: the good entry is accepted
        self.assertEqual((src, why), ((os.path.join(self.kit, "system"), "install-system.sh"), ""))
        for entry, word in (({"dir": "../system", "installer": "install-system.sh"}, "not a plain folder and file name"),
                            ({"dir": "system", "installer": "sub/install-system.sh"}, "not a plain folder and file name"),
                            ({"dir": ".system", "installer": "install-system.sh"}, "not a plain folder and file name"),
                            ({"dir": "system", "installer": "missing.sh"}, "system installer that is not there"),
                            ({"dir": "system"}, "carries no system package"),
                            ("system/install-system.sh", "carries no system package")):
            src, why = gg.system_source(dict(kit, system=entry))
            self.assertIsNone(src, entry)
            self.assertIn(word, why, entry)

    def test_the_kit_tool_adds_a_package_that_stage_then_records(self):
        import contextlib, io  # noqa: PLC0415, E401
        import v3_kit  # noqa: PLC0415
        src = os.path.join(self.tmp.name, "system-src")
        os.makedirs(os.path.join(src, "a2x"))
        put(os.path.join(src, "install-system.sh"), "#!/bin/bash\n")
        put(os.path.join(src, "a2x", "routes.txt"), "/usr/bin/true\n")
        with open(os.path.join(self.kit, v3_macos27.MANIFEST)) as fh:
            before = fh.read()
        for bad in ("missing.sh", "a2x/routes.txt", ".hidden"):         # refused, and the kit is left as it was
            with self.assertRaises(SystemExit):
                v3_kit.package(self.kit, "system", src, bad)
            self.assertFalse(os.path.exists(os.path.join(self.kit, "system")))
        with self.assertRaises(SystemExit):
            v3_kit.package(self.kit, "other", src, "install-system.sh")
        with open(os.path.join(self.kit, v3_macos27.MANIFEST)) as fh:
            self.assertEqual(fh.read(), before)
        with contextlib.redirect_stdout(io.StringIO()):
            v3_kit.package(self.kit, "system", src, "install-system.sh")
        self.assertTrue(os.path.isfile(os.path.join(self.kit, "system", "a2x", "routes.txt")))
        with self.assertRaises(SystemExit):                             # a second one is refused, not merged
            v3_kit.package(self.kit, "system", src, "install-system.sh")
        state = gg.stage(self.root, self.kit, self.fx.report)
        self.assertEqual(state["system"], "in the kit with its installer install-system.sh")

    def test_a_symbolic_link_that_leaves_a_package_is_refused_by_the_kit_tool_and_by_stage(self):
        import contextlib, io  # noqa: PLC0415, E401
        import v3_kit  # noqa: PLC0415
        outside = os.path.join(self.tmp.name, "outside.sh")
        put(outside, "#!/bin/bash\n")
        for plant in ("install-system.sh", "extra-link", "a2x/deep-link", "a2x-dir-link", "climbs-out", "names-nothing"):
            src = os.path.join(self.tmp.name, "src-" + plant.replace("/", "-"))
            os.makedirs(os.path.join(src, "a2x"))
            if plant != "install-system.sh":
                put(os.path.join(src, "install-system.sh"), "#!/bin/bash\n")
            target = {"a2x-dir-link": self.tmp.name, "climbs-out": "../outside.sh", "names-nothing": "not-there"}.get(plant, outside)
            os.symlink(target, os.path.join(src, plant))
            with self.assertRaises(SystemExit, msg=plant):
                v3_kit.package(self.kit, "system", src, "install-system.sh")
            self.assertFalse(os.path.lexists(os.path.join(self.kit, "system")), plant)
        # control: links that stay inside the package, as a versioned bundle or a library's short name has, are accepted
        good = os.path.join(self.tmp.name, "src-good")
        os.makedirs(os.path.join(good, "X.framework", "Versions", "A"))
        put(os.path.join(good, "install-system.sh"), "#!/bin/bash\n")
        put(os.path.join(good, "X.framework", "Versions", "A", "X"), "x")
        os.symlink("A", os.path.join(good, "X.framework", "Versions", "Current"))
        os.symlink("Versions/Current/X", os.path.join(good, "X.framework", "X"))
        with contextlib.redirect_stdout(io.StringIO()):
            v3_kit.package(self.kit, "system", good, "install-system.sh")
        self.assertTrue(os.path.islink(os.path.join(self.kit, "system", "X.framework", "Versions", "Current")))
        kit = v3_macos27.load_kit(self.kit)
        kit["_path"] = self.kit
        self.assertIsNotNone(gg.system_source(kit)[0])
        os.symlink(outside, os.path.join(self.kit, "system", "planted"))
        src, why = gg.system_source(kit)
        self.assertIsNone(src)
        self.assertIn("holds a symbolic link that leaves it (system/planted)", why)
        self.assertIn("symbolic link", gg.stage(self.root, self.kit, self.fx.report)["system"])

    def test_stage_refuses_a_driver_package_with_a_symbolic_link_that_leaves_it_and_copies_nothing(self):
        self.add_driver()
        os.symlink("/etc/hosts", os.path.join(self.kit, "driver", "planted"))
        before = tree(self.root)
        with self.assertRaises(gg.Refused):
            gg.stage(self.root, self.kit, self.fx.report)
        self.assertEqual(tree(self.root), before)
        self.assertFalse(os.path.lexists(os.path.join(self.root, gg.DRIVER)))
        os.remove(os.path.join(self.kit, "driver", "planted"))         # control: the same package without the link stages
        self.assertEqual(gg.stage(self.root, self.kit, self.fx.report)["driver_installer"], "install-macos27.sh")

    def test_the_kit_tool_makes_the_two_entries_the_finish_step_reads(self):
        # the flow the kit's sample manifest describes: make, then package system and driver from their folders
        import contextlib, io  # noqa: PLC0415, E401
        import v3_kit  # noqa: PLC0415
        for key, inst in (("system", "install-system.sh"), ("driver", "install-driver.sh")):
            src = os.path.join(self.tmp.name, "pkg-" + key)
            os.makedirs(src)
            put(os.path.join(src, inst), "#!/bin/bash\n")
            put(os.path.join(src, "MANIFEST"), "# files\n")
            with contextlib.redirect_stdout(io.StringIO()):
                v3_kit.package(self.kit, key, src, inst)
        with open(os.path.join(self.kit, v3_macos27.MANIFEST)) as fh:
            m = json.load(fh)
        self.assertEqual(m["system"], {"dir": "system", "installer": "install-system.sh"})
        self.assertEqual(m["driver"], {"dir": "driver", "installer": "install-driver.sh"})
        kit = v3_macos27.load_kit(self.kit)                            # the kit still passes the checks a build applies
        kit["_path"] = self.kit
        self.assertEqual(gg.system_source(kit)[0][1], "install-system.sh")
        self.assertEqual(gg.driver_source(kit)[0][1], "install-driver.sh")
        state = gg.stage(self.root, self.kit, self.fx.report)
        self.assertEqual(state["driver_installer"], "install-driver.sh")
        self.assertFalse(os.path.lexists(os.path.join(self.root, gg.DRIVER)))
        self.assertEqual(state["system"], "in the kit with its installer install-system.sh")

    # Different PCs, as scan reports. Every PC the driver runs on under macOS 26 may try macOS 27; what has not been
    # started yet is said. Only a card the driver does not take is refused.
    PC1 = {"Motherboard": {"Name": "B860M", "Platform": "Desktop"}, "CPU": {"Manufacturer": "Intel", "Processor Name": "Intel(R) Core(TM) Ultra 5 225F"},
           "GPU": {"NVIDIA GeForce RTX 5060": {"Manufacturer": "NVIDIA", "Device ID": "10DE-2D05", "Device Type": "Discrete GPU"}},
           "Bluetooth": {"Realtek BT": {"Device ID": "0BDA-8922"}}}
    PC2 = {"Motherboard": {"Name": "B550 AORUS ELITE", "Platform": "Desktop"}, "CPU": {"Manufacturer": "AMD", "Processor Name": "AMD Ryzen 7 5800X"},
           "GPU": {"NVIDIA GeForce RTX 3070": {"Manufacturer": "NVIDIA", "Device ID": "10DE-2484", "Device Type": "Discrete GPU"}},
           "Bluetooth": {"Intel AX200": {"Device ID": "8087-0029"}}}
    PC3 = {"Motherboard": {"Name": "Z390-A", "Platform": "Desktop"}, "CPU": {"Manufacturer": "Intel", "Processor Name": "Intel(R) Core(TM) i7-9700K"},
           "GPU": {"NVIDIA GeForce GTX 1080": {"Manufacturer": "NVIDIA", "Device ID": "10DE-1B80", "Device Type": "Discrete GPU"}}}

    def cli(self, step, report, *more):
        import contextlib, io  # noqa: PLC0415, E401
        path = os.path.join(self.tmp.name, "Report.json")
        put(path, json.dumps(report))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = gg.main([step, self.root, "--v3-kit", self.kit, "--macos-major", "26", "--disk-free-gb", "110", "--report", path, *more])
        return rc, json.loads(buf.getvalue())

    def said(self, out):
        return [c["detail"] for c in out["checks"] if c["check"] == "untried-here"]

    def test_pc1_the_card_it_has_run_on_passes_with_no_extra_notice_and_gets_its_generations_model(self):
        rc, out = self.cli("preflight", self.PC1)
        self.assertEqual((rc, [c["check"] for c in out["checks"] if not c["ok"]]), (0, []))
        self.assertTrue(any(c["check"] == "gpu" and c["detail"] == "NVIDIA card NVIDIA GeForce RTX 5060 (2D05) is one the driver takes" for c in out["checks"]))
        self.assertIn(gg.UNTRIED_NOTE, [c["detail"] for c in out["checks"]])       # passing is not "tried on a PC like this"
        self.assertEqual(self.said(out), [])
        rc, out = self.cli("stage", self.PC1)
        self.assertEqual((rc, out["model"]), (0, "Mac17,15"))
        staged = read(os.path.join(self.root, "EFI", gg.STAGED, "config.plist"))
        self.assertEqual(staged["PlatformInfo"]["Generic"]["SystemProductName"], "Mac17,15")
        self.assertIn("RealtekBluetoothFirmware.kext", [e["BundlePath"] for e in staged["Kernel"]["Add"]])   # from this PC's scan

    def test_pc1_staged_with_the_kits_model_when_asked(self):
        rc, out = self.cli("stage", self.PC1, "--kit-model")
        staged = read(os.path.join(self.root, "EFI", gg.STAGED, "config.plist"))
        self.assertEqual((rc, out["model"]), (0, "kept from the kit (asked for)"))
        self.assertEqual(staged["PlatformInfo"]["Generic"]["SystemProductName"], self.fx.kit["set"]["PlatformInfo/Generic/SystemProductName"])
        self.assertNotEqual(staged["PlatformInfo"]["Generic"]["SystemProductName"], "Mac17,15")

    def test_pc2_an_untried_card_on_an_amd_desktop_passes_is_told_so_and_is_staged_from_its_own_scan(self):
        rc, out = self.cli("preflight", self.PC2)
        self.assertEqual((rc, [c["check"] for c in out["checks"] if not c["ok"]]), (0, []))
        self.assertEqual(self.said(out), [
            "macOS 27 has not been run on NVIDIA GeForce RTX 3070 yet (so far: NVIDIA GeForce RTX 5060 (2D05)). This is a beta: it may not start. "
            "macOS 27 with this kit has not been started on a PC with an AMD processor yet. " + gg.SEND_LOGS])
        self.assertIn("press Send logs there", gg.SEND_LOGS)
        rc, out = self.cli("stage", self.PC2)
        staged = read(os.path.join(self.root, "EFI", gg.STAGED, "config.plist"))
        self.assertEqual((rc, out["model"]), (0, "kept from the kit"))   # no model exists for RTX 30: the kit's is kept
        self.assertEqual(staged["PlatformInfo"]["Generic"]["SystemProductName"], self.fx.kit["set"]["PlatformInfo/Generic/SystemProductName"])
        self.assertNotIn("RealtekBluetoothFirmware.kext", [e["BundlePath"] for e in staged["Kernel"]["Add"]])   # no Realtek adapter here

    def test_pc3_a_card_the_driver_does_not_take_is_refused_saying_what_was_found(self):
        before = tree(self.root)
        rc, out = self.cli("preflight", self.PC3)
        failed = {c["check"]: c["detail"] for c in out["checks"] if not c["ok"]}
        self.assertEqual((rc, failed), (1, {"gpu": "no NVIDIA card the driver takes was found (found 1B80)"}))
        rc, out = self.cli("stage", self.PC3)
        self.assertEqual(rc, 1)
        self.assertIn("no NVIDIA card the driver takes was found", out["why"])
        self.assertEqual(tree(self.root), before)

    def test_a_laptop_passes_and_is_told_and_the_tried_cards_only_word_the_notice(self):
        laptop = dict(self.PC1, Motherboard={"Name": "LEGION", "Platform": "Laptop"})
        rc, out = self.cli("preflight", laptop)
        self.assertEqual((rc, [c for c in out["checks"] if not c["ok"]]), (0, []))
        self.assertEqual(self.said(out), ["macOS 27 with this kit has not been started on a laptop yet; its built-in screen and its switch "
                                          "between two graphics chips are untried. " + gg.SEND_LOGS])
        kit = v3_macos27.load_kit(self.kit)
        self.assertEqual(kit["gpu_ids"], ["2D05"])                     # written by the kit tool: data for the wording
        table = __import__("p1401.nullmoth", fromlist=["TABLE"]).TABLE
        self.assertEqual(gg.supported_ids(kit)[0], set(table["ids"]))   # the driver's own list, not a copy and not the tried cards
        self.assertGreater(len(gg.supported_ids(kit)[0]), 200)
        manifest(self.kit, gpu_ids=["2D05", "2484"])                    # a kit that names the RTX 3070 as tried drops its notice
        intel = dict(self.PC2, CPU={"Manufacturer": "Intel", "Processor Name": "Intel(R) Core(TM) i5-12400F"})
        self.assertEqual(self.said(self.cli("preflight", intel)[1]), [])

    def test_room_is_one_number_taken_from_the_lay_down_step(self):
        self.assertEqual(gg.MIN_DISK_BYTES, 102 * GB)                   # 45 for the volumes + 49 + 8 of work files
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 101 * GB, self.kit)), ["disk-space"])
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 102 * GB, self.kit)), [])

    # What 1401 worked out for a PC on macOS 26 must reach its macOS 27 startup files untouched: the staged files are
    # that PC's own files with only what the kit names changed. Four more PCs, each with the pieces its kind has.
    def own_pc(self, extra_args, patches=(), props=None, more_kexts=(), quirks=None):
        """Gives the fixture's macOS 26 startup files the per-machine pieces a 1401 build has, and returns them."""
        import plistlib  # noqa: PLC0415
        path = os.path.join(self.root, "EFI", "OC", "config.plist")
        cfg = read(path)
        nv = cfg["NVRAM"]["Add"][next(iter(cfg["NVRAM"]["Add"]))]
        nv["boot-args"] = (nv["boot-args"] + " nvfb=1 nvaccel=1 nvfbheads=4 -nvkmsnosmooth amfi_get_out_of_my_way=0x1 amfi=0x80 "
                           "ipc_control_port_options=0 " + extra_args).strip()
        nv["csr-active-config"] = bytes.fromhex("030a0000")
        cfg["Kernel"]["Patch"] = [dict(p) for p in patches]
        cfg["Kernel"]["Quirks"] = dict(quirks or {"ProvideCurrentCpuInfo": True})
        cfg["DeviceProperties"] = {"Add": dict(props or {})}
        cfg["ACPI"] = {"Add": [{"Path": "SSDT-EC.aml", "Enabled": True, "Comment": "1401 | embedded controller"}]}
        cfg["PlatformInfo"]["Generic"].update({"SystemSerialNumber": "F5KZX0ABCDEF", "SystemUUID": "11111111-2222-3333-4444-555555555555", "MLB": "F5K1234567890ABCD"})
        for name in more_kexts:
            d = os.path.join(self.root, "EFI", "OC", "Kexts", name, "Contents")
            os.makedirs(d)
            put(os.path.join(d, "Info.plist"), "<plist/>")
            cfg["Kernel"]["Add"].append({"Arch": "x86_64", "BundlePath": name, "Comment": "1401 | this PC", "Enabled": True,
                                         "ExecutablePath": "", "MaxKernel": "", "MinKernel": "", "PlistPath": "Contents/Info.plist"})
        with open(path, "wb") as fh:
            plistlib.dump(cfg, fh)
        return cfg

    def staged_keeps_the_pcs_own(self, before, staged, kit_model):
        """Everything outside what the kit may touch is the PC's own, value for value."""
        import copy  # noqa: PLC0415
        a, b = copy.deepcopy(before), copy.deepcopy(staged)
        nvk = next(iter(a["NVRAM"]["Add"]))
        args26, args27 = a["NVRAM"]["Add"][nvk].pop("boot-args").split(), b["NVRAM"]["Add"][nvk].pop("boot-args").split()
        self.assertEqual([x for x in args27 if x not in v3_macos27.BOOT_ARGS_ALLOWED], [x for x in args26 if x not in v3_macos27.BOOT_ARGS_ALLOWED])
        self.assertTrue(set(args27) >= set(args26) | {"-v"})               # nothing of the PC's own is dropped
        own26 = {e["BundlePath"]: e for e in a["Kernel"].pop("Add")}
        own27 = {e["BundlePath"]: e for e in b["Kernel"].pop("Add")}
        kit_names = {k["name"] for k in self.fx.kit["kexts"]} | {c["name"] for c in self.fx.kit["caps"]}
        for name, e in own26.items():                                      # a kext the kit does not name is carried as it was
            self.assertIn(name, own27, name)
            if name not in kit_names:
                self.assertEqual(own27[name], e, name)
        for key in ("SystemProductName", "SystemSerialNumber"):
            a["PlatformInfo"]["Generic"].pop(key, None)
            b["PlatformInfo"]["Generic"].pop(key, None)
        a["Misc"]["Security"].pop("SecureBootModel", None)
        b["Misc"]["Security"].pop("SecureBootModel", None)
        self.assertEqual(b, a)                                             # patches, quirks, device properties, ACPI, UUID, MLB, SIP
        self.assertEqual(staged["PlatformInfo"]["Generic"]["SystemProductName"], kit_model)

    def stage_pc(self, report, **own):
        before = self.own_pc(**own)
        rc, out = self.cli("stage", report)
        self.assertEqual(rc, 0, out)
        return before, read(os.path.join(self.root, "EFI", gg.STAGED, "config.plist")), out

    KIT_MODEL = property(lambda self: self.fx.kit["set"]["PlatformInfo/Generic/SystemProductName"])

    def test_an_amd_desktop_keeps_its_kernel_patches_quirks_and_fan_kexts(self):
        amd = {"Motherboard": {"Name": "B550 AORUS ELITE", "Platform": "Desktop"}, "CPU": {"Manufacturer": "AMD", "Processor Name": "AMD Ryzen 7 5800X"},
               "GPU": {"NVIDIA GeForce RTX 3070": {"Manufacturer": "NVIDIA", "Device ID": "10DE-2484", "Device Type": "Discrete GPU"}}}
        patches = [{"Comment": "algrey | Force cpuid_cores_per_package", "Identifier": "kernel", "Find": b"\x01", "Replace": b"\x02", "MinKernel": "20.0.0", "MaxKernel": "25.99.99", "Enabled": True},
                   {"Comment": "1401 | AMD: core count", "Identifier": "kernel", "Find": b"\x03", "Replace": b"\x04", "MinKernel": "", "MaxKernel": "", "Enabled": True}]
        before, staged, out = self.stage_pc(amd, extra_args="npci=0x3000", patches=patches,
                                            more_kexts=("AMDRyzenCPUPowerManagement.kext", "SMCAMDProcessor.kext", "SMCSuperIO.kext"),
                                            quirks={"ProvideCurrentCpuInfo": True, "DummyPowerManagement": True})
        self.staged_keeps_the_pcs_own(before, staged, self.KIT_MODEL)       # no model for RTX 30: the kit's
        self.assertEqual(staged["Kernel"]["Patch"], before["Kernel"]["Patch"])
        self.assertEqual(out["model"], "kept from the kit")

    def test_a_laptop_with_a_switch_keeps_its_guard_arguments_and_device_properties(self):
        mux = {"Motherboard": {"Name": "LEGION 5", "Platform": "Laptop"}, "CPU": {"Manufacturer": "Intel", "Processor Name": "13th Gen Intel(R) Core(TM) i7-13700H"},
               "GPU": {"NVIDIA GeForce RTX 4060 Laptop GPU": {"Manufacturer": "NVIDIA", "Device ID": "10DE-28A0", "Device Type": "Discrete GPU"},
                       "Intel Iris Xe": {"Manufacturer": "Intel", "Device ID": "8086-A7A0", "Device Type": "Integrated GPU"}}}
        props = {"PciRoot(0x0)/Pci(0x2,0x0)": {"AAPL,ig-platform-id": bytes.fromhex("0600a6a0"), "enable-backlight-registers-fix": bytes.fromhex("01000000")}}
        before, staged, out = self.stage_pc(mux, extra_args="gfxrst=4 -igfxblr nvmuxless=0", props=props, more_kexts=("VoodooPS2Controller.kext", "ECEnabler.kext"))
        self.staged_keeps_the_pcs_own(before, staged, self.KIT_MODEL)       # no model for RTX 40
        self.assertIn("gfxrst=4", staged["NVRAM"]["Add"][next(iter(staged["NVRAM"]["Add"]))]["boot-args"].split())
        self.assertEqual(staged["DeviceProperties"], before["DeviceProperties"])

    def test_a_laptop_whose_screen_is_on_the_other_chip_keeps_what_hides_nothing(self):
        muxless = {"Motherboard": {"Name": "ROG Zephyrus", "Platform": "Laptop"}, "CPU": {"Manufacturer": "AMD", "Processor Name": "AMD Ryzen 9 6900HS"},
                   "GPU": {"NVIDIA GeForce RTX 3060 Laptop GPU": {"Manufacturer": "NVIDIA", "Device ID": "10DE-2520", "Device Type": "Discrete GPU"},
                           "AMD Radeon 680M": {"Manufacturer": "AMD", "Device ID": "1002-1681", "Device Type": "Integrated GPU"}}}
        before, staged, out = self.stage_pc(muxless, extra_args="nvmuxless=1 -NRedDPDelay", more_kexts=("NootedRed.kext",))
        self.staged_keeps_the_pcs_own(before, staged, self.KIT_MODEL)
        rc, pre = self.cli("preflight", muxless)
        self.assertEqual(rc, 0)
        said = self.said(pre)[0]
        for part in ("has not been run on NVIDIA GeForce RTX 3060 Laptop GPU yet", "AMD processor", "laptop"):
            self.assertIn(part, said)

    def test_two_more_generations_get_the_kits_model_and_keep_their_own_files(self):
        for name, did in (("NVIDIA GeForce GTX 1660 SUPER", "21C4"), ("NVIDIA GeForce RTX 2070 SUPER", "1E84")):
            with self.subTest(card=name):
                self.tearDown()
                self.setUp()
                pc = {"Motherboard": {"Name": "Z390-A", "Platform": "Desktop"}, "CPU": {"Manufacturer": "Intel", "Processor Name": "Intel(R) Core(TM) i7-9700K"},
                      "GPU": {name: {"Manufacturer": "NVIDIA", "Device ID": "10DE-" + did, "Device Type": "Discrete GPU"}}}
                before, staged, out = self.stage_pc(pc, extra_args="alcid=1", more_kexts=("IntelMausi.kext", "USBMap.kext"))
                self.staged_keeps_the_pcs_own(before, staged, self.KIT_MODEL)
                self.assertEqual(out["model"], "kept from the kit")
                self.assertNotIn("RealtekBluetoothFirmware.kext", [e["BundlePath"] for e in staged["Kernel"]["Add"]])

    def test_the_tried_pc_changes_only_model_and_serial_beyond_the_kit(self):
        before, staged, out = self.stage_pc(self.PC1, extra_args="alcid=11")
        self.staged_keeps_the_pcs_own(before, staged, "Mac17,15")
        self.assertNotEqual(staged["PlatformInfo"]["Generic"]["SystemSerialNumber"], before["PlatformInfo"]["Generic"]["SystemSerialNumber"])
        self.assertEqual(staged["PlatformInfo"]["Generic"]["MLB"], before["PlatformInfo"]["Generic"]["MLB"])

    def test_a_made_kit_carries_no_path_from_the_machine_that_made_it(self):
        with open(os.path.join(self.kit, v3_macos27.MANIFEST)) as fh:
            text = fh.read()
        m = json.loads(text)
        self.assertEqual(m["source_config"], os.path.basename(self.fx.ref_path))
        self.assertTrue(os.path.isabs(self.fx.ref_path))               # control: the tool was given a full path
        for part in (self.tmp.name, os.path.realpath(self.tmp.name), os.path.expanduser("~"), "/Users/", "/private/", "/var/"):
            self.assertNotIn(part, text, part)
        self.add_system()
        self.add_driver()
        with open(os.path.join(self.kit, v3_macos27.MANIFEST)) as fh:
            self.assertNotIn(self.tmp.name, fh.read())

    def test_the_driver_and_system_entries_are_read_apart(self):
        self.add_system()
        kit = v3_macos27.load_kit(self.kit)
        kit["_path"] = self.kit
        self.assertIsNone(gg.driver_source(kit)[0])                    # a system package is not a driver package
        self.assertIn("carries no driver package", gg.driver_source(kit)[1])
        self.assertIsNotNone(gg.system_source(kit)[0])

    def test_a_stage_that_fails_leaves_nothing_behind(self):
        # VirtualSMC with neither provider class: the kit cannot be applied (v3_macos27 stops the build).
        import plistlib  # noqa: PLC0415
        info = os.path.join(self.oc(), "Kexts", "VirtualSMC.kext", "Contents", "Info.plist")
        d = read(info)
        d["IOKitPersonalities"]["VirtualSMC"]["IOProviderClass"] = "SomethingElse"
        with open(info, "wb") as fh:
            plistlib.dump(d, fh)
        before = tree(self.root)
        with self.assertRaises(gg.Refused):
            gg.stage(self.root, self.kit, self.fx.report)
        self.assertEqual(tree(self.root), before)

    def test_activate_needs_the_users_confirmation(self):
        gg.stage(self.root, self.kit, self.fx.report)
        before = tree(self.root)
        with self.assertRaises(gg.Refused):
            gg.activate(self.root, confirmed=False, kit_path=self.kit)
        self.assertEqual(tree(self.root), before)

    def test_activate_then_rollback_restores_macos26_exactly(self):
        original = tree(self.oc())
        gg.stage(self.root, self.kit, self.fx.report)
        staged = tree(self.oc(gg.STAGED))
        self.assertEqual(gg.activate(self.root, confirmed=True, kit_path=self.kit)["state"], "active")
        self.assertEqual(tree(self.oc()), staged)
        self.assertEqual(tree(self.oc(gg.KEPT)), original)
        # The way back works with the kit gone.
        self.assertEqual(gg.rollback(self.root)["state"], "staged")
        self.assertEqual(tree(self.oc()), original)
        self.assertEqual(tree(self.oc(gg.STAGED)), staged)

    def test_cancel_from_active_puts_the_partition_back_as_it_was(self):
        self.add_driver()
        before = tree(self.root)
        gg.stage(self.root, self.kit, self.fx.report)
        gg.activate(self.root, confirmed=True, kit_path=self.kit)
        self.assertEqual(gg.cancel(self.root), {"state": "none"})
        self.assertEqual(tree(self.root), before)

    def test_steps_out_of_order_refuse(self):
        with self.assertRaises(gg.Refused):
            gg.activate(self.root, confirmed=True, kit_path=self.kit)
        with self.assertRaises(gg.Refused):
            gg.rollback(self.root)
        gg.stage(self.root, self.kit, self.fx.report)
        with self.assertRaises(gg.Refused):
            gg.stage(self.root, self.kit, self.fx.report)

    def test_folders_that_disagree_with_the_record_are_refused(self):
        gg.stage(self.root, self.kit, self.fx.report)
        os.rename(self.oc(gg.STAGED), self.oc("moved-by-hand"))
        before = tree(self.root)
        for step in (lambda: gg.activate(self.root, confirmed=True, kit_path=self.kit), lambda: gg.cancel(self.root)):
            with self.assertRaises(gg.Refused):
                step()
        self.assertEqual(tree(self.root), before)
        self.assertEqual(self.failed(gg.preflight(self.root, 26, [CARD], 110 * GB, self.kit)), ["state"])

    def test_a_swap_stopped_between_its_two_renames_is_repaired_to_macos26(self):
        # activate = EFI/OC -> EFI/OC-26, then staged -> EFI/OC. Stopped after the first, the partition has no EFI/OC
        # and the PC cannot start from it; every step used to refuse that layout, so nothing could repair it.
        original = tree(self.oc())
        gg.stage(self.root, self.kit, self.fx.report)
        staged = tree(self.oc(gg.STAGED))
        os.rename(self.oc(), self.oc(gg.KEPT))                      # the run stops here
        self.assertFalse(os.path.isdir(self.oc()))
        self.assertEqual(gg.cancel(self.root)["state"], "none")       # the way back heals it and then cancels
        self.assertEqual(tree(self.oc()), original)
        self.assertFalse(os.path.isdir(self.oc(gg.STAGED)))
        self.assertFalse(os.path.isdir(self.oc(gg.KEPT)))
        # the same stop on the way back (state active, macOS 27 files already set aside)
        gg.stage(self.root, self.kit, self.fx.report)
        gg.activate(self.root, confirmed=True, kit_path=self.kit)
        os.rename(self.oc(), self.oc(gg.STAGED))                     # rollback's first rename, then the run stops
        self.assertEqual(gg._load_state(self.root)["state"], "active")   # the record still says active; there is no EFI/OC
        self.assertEqual(gg.read_state(self.root)["state"], "staged")    # reading the state repairs it: macOS 26's files are the default
        self.assertEqual(tree(self.oc()), original)
        self.assertEqual(gg.activate(self.root, confirmed=True, kit_path=self.kit)["state"], "active")   # and the path forward still works
        self.assertEqual(tree(self.oc(gg.KEPT)), original)
        self.assertEqual(tree(self.oc()), staged)

    def test_the_repair_only_acts_on_that_one_layout(self):
        # a folder moved by hand is still refused and nothing is touched (the guard in the other direction)
        gg.stage(self.root, self.kit, self.fx.report)
        os.rename(self.oc(), self.oc("moved-by-hand"))
        before = tree(self.root)
        with self.assertRaises(gg.Refused):
            gg.cancel(self.root)
        self.assertEqual(tree(self.root), before)

    def test_a_driver_package_larger_than_the_partition_does_not_stop_stage(self):
        # the driver package stays in the kit, so its size is not counted against the startup partition
        self.add_driver()
        put(os.path.join(self.kit, "driver", "payload.bin"), "x" * (3 * 1024 * 1024))
        efi = os.path.join(self.root, "EFI")
        need = gg._tree_bytes(os.path.join(efi, "OC")) + gg._tree_bytes(os.path.join(self.kit, "Kexts")) + gg.ESP_MARGIN_BYTES
        before = tree(self.root)
        with self.assertRaises(gg.Refused):                           # control: too little room for the kexts is still refused
            gg.stage(self.root, self.kit, self.fx.report, min_free=need - 1)
        self.assertEqual(tree(self.root), before)
        state = gg.stage(self.root, self.kit, self.fx.report, min_free=need + 1024 * 1024)   # 1 MB spare, 3 MB package
        self.assertEqual(state["driver_installer"], "install-macos27.sh")
        self.assertFalse(any("payload.bin" in p for p in tree(self.root)))

    def test_a_state_file_1401_did_not_write_is_refused(self):
        put(os.path.join(self.root, "EFI", gg.STATE), '{"state": "whatever"}')
        with self.assertRaises(gg.Refused):
            gg.stage(self.root, self.kit, self.fx.report)

    def test_the_macos26_picker_entry_is_a_stub_that_refuses(self):
        with self.assertRaises(gg.Refused) as c:
            gg.boot_entry_for_26(self.root)
        self.assertIn("USB stick", str(c.exception))

    def test_the_command_line_walks_the_whole_path(self):
        def run(*args):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli(["golden-gate", *args])
            return rc, json.loads(buf.getvalue())
        rc, out = run("preflight", self.root, "--v3-kit", self.kit, "--macos-major", "26", "--gpu-id", CARD, "--disk-free-gb", "110")
        self.assertEqual((rc, out["ok"]), (0, True), out)
        self.assertIn("Install macOS 27", out["installer"])
        self.assertNotIn("softwareupdate", out["installer"])           # Apple's installer does not run on an Intel PC
        self.assertEqual(run("stage", self.root, "--v3-kit", self.kit)[1]["state"], "staged")
        self.assertEqual(run("activate", self.root, "--v3-kit", self.kit)[0], 1)
        self.assertEqual(run("activate", self.root, "--v3-kit", self.kit, "--confirm")[1]["state"], "active")
        self.assertEqual(run("status", self.root)[1]["state"], "active")
        self.assertEqual(run("cancel", self.root)[1]["state"], "none")
        self.assertEqual(run("entry26", self.root)[0], 1)

    def test_stage_from_a_scan_report_checks_the_card_and_follows_the_adapter(self):
        def run(report):
            path = os.path.join(self.tmp.name, "Report.json")
            put(path, json.dumps(report))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli(["golden-gate", "stage", self.root, "--plain", "--v3-kit", self.kit, "--report", path])
            return rc, buf.getvalue()
        gpu = {"Manufacturer": "NVIDIA", "Device Type": "Discrete GPU", "Device ID": "10DE-1C03"}
        before = tree(self.root)
        rc, out = run({"GPU": {"GTX 1060": gpu}, **self.fx.report})
        self.assertEqual(rc, 1)
        self.assertIn("no NVIDIA card", out)
        self.assertEqual(tree(self.root), before)
        rc, out = run({"GPU": {"RTX 5060": dict(gpu, **{"Device ID": "10DE-2D05"})}, **self.fx.report})
        self.assertEqual(rc, 0, out)
        self.assertIn("staged", out)
        self.assertTrue(os.path.isdir(os.path.join(self.oc(gg.STAGED), "Kexts", "RealtekBluetoothFirmware.kext")))


class WindowsButton(unittest.TestCase):
    """The Windows form is not compiled here; these pin the gate in its source."""

    def setUp(self):
        with open(os.path.join(HERE, "windows", "App", "MainForm.cs"), encoding="utf-8") as fh:
            self.form = fh.read()

    def test_the_button_is_shown_only_with_a_kit(self):
        self.assertEqual(self.form.count("goldenGate, bar, log)"), 1)
        self.assertIn('if (V3Kit() != "" && summary.Contains("NVIDIA")) Show(disks, refresh, armApps, goldenGate, bar, log); else',
                      self.form)
        self.assertIn("guide, ocLink, logLink, armApps, goldenGate }) c.Visible = on.Contains(c);", self.form)

    def test_the_handler_does_nothing_without_a_kit_and_only_stages(self):
        at = self.form.index("async void PrepareGoldenGate()")
        body = self.form[at:self.form.index("async void UpdateApp()")]
        self.assertLess(body.index('if (busy || V3Kit() == "") return;'), body.index("Engine.Run("))
        self.assertIn('"p1401 golden-gate stage "', body)
        self.assertNotIn("activate", body.replace('"p1401 golden-gate activate"', ""))


if __name__ == "__main__":
    unittest.main()
