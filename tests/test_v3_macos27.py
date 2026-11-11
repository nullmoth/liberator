"""macOS 27 builds come only from a v3 kit, and the EFI they make matches a configuration that booted macOS 27.2.

Two parts:

1. Always: a synthetic reference (a macOS 27.2 config with its kexts) is turned into a kit with tools/v3_kit.py, a
   synthetic macOS 26 build is turned into a macOS 27 one with v3_macos27.apply(), and the result is compared with the
   reference. Each guard is checked in both directions: the unchanged macOS 26 build must FAIL the comparison, a kit
   without -v must be refused, and with no kit at all the build must refuse macOS 27.

2. With NULLMOTH_V3_REF=<dir>: the same comparison against a real reference. The folder holds `live.plist` (the config
   that booted macOS 27.2), `Kexts/` (its kexts) and `base26.plist` (the macOS 26 config of the same machine). Without
   it this part reports that it did not run; it never counts as passed.
"""
import contextlib
import io
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tools"))
from p1401 import engine, v3_macos27  # noqa: E402
import v3_kit  # noqa: E402

NV = "7C436110-AB2A-4BBB-A880-FE41995C9F82"
# The platform kexts every macOS 27 build carries beside A2XACPIPlatform (tools/v3_kit.py SPEC).
PLATFORM = ["NetArm2x86IOAPIC.kext", "AppleRTC.kext", "efiruntime.kext", "efinvram.kext", "NativeUSBHIDRoute.kext"]


def kext(root, name, version="1.0.0", exe=True, personalities=None):
    b = os.path.join(root, name, "Contents")
    os.makedirs(os.path.join(b, "MacOS"), exist_ok=True)
    stem = name[:-5]
    info = {"CFBundleIdentifier": f"test.{stem}", "CFBundleExecutable": stem, "CFBundleShortVersionString": version,
            "IOKitPersonalities": personalities or {}}
    with open(os.path.join(b, "Info.plist"), "wb") as fh:
        plistlib.dump(info, fh)
    if exe:
        with open(os.path.join(b, "MacOS", stem), "wb") as fh:
            fh.write(b"\xcf\xfa\xed\xfe")
    return {"Arch": "x86_64", "BundlePath": name, "Comment": "", "Enabled": True,
            "ExecutablePath": f"Contents/MacOS/{stem}" if exe else "", "MaxKernel": "", "MinKernel": "",
            "PlistPath": "Contents/Info.plist"}


def smc(provider):
    return {"VirtualSMC": {"IOClass": "VirtualSMC", "IOProviderClass": provider}}


def config(entries, args, sbm="Default", product="MacPro7,1"):
    return {"Kernel": {"Add": entries}, "NVRAM": {"Add": {NV: {"boot-args": args}}},
            "Misc": {"Security": {"SecureBootModel": sbm}},
            "PlatformInfo": {"Generic": {"SystemProductName": product}}}


def write(path, obj):
    with open(path, "wb") as fh:
        plistlib.dump(obj, fh)


def read(path):
    with open(path, "rb") as fh:
        return plistlib.load(fh)


class Fixture:
    """A reference macOS 27.2 EFI, and a macOS 26 build of another PC with a Realtek Bluetooth adapter."""

    def __init__(self, tmp):
        self.ref_kexts = os.path.join(tmp, "ref", "Kexts")
        e = {}
        for name, ver, pers in (("a2x_exec_hook.kext", "1.0", None), ("Lilu.kext", "1.7.3", None),
                                ("BlueToolFixup.kext", "2.7.7", None), ("VirtualSMC.kext", "1.3.7",
                                                                        smc("IOACPIPlatformExpert")),
                                ("A2XACPIPlatform.kext", "1.0.0", None), ("A2XSMBIOS.kext", "1.0.0", None),
                                ("RealtekBluetoothFirmware.kext", "1.0.4", None), ("AMFIPass.kext", "1.4.1", None),
                                ("SMCVendorFan.kext", "1.0", None)) + tuple(
                                    (n, "1.0.0", None) for n in PLATFORM):
            e[name] = kext(self.ref_kexts, name, ver, personalities=pers)
        for n in PLATFORM:
            e[n]["MinKernel"] = "27.0.0"
        e["a2x_exec_hook.kext"]["MinKernel"] = "27.0.0"
        e["Lilu.kext"]["MinKernel"] = "27.0.0"
        e["BlueToolFixup.kext"]["MinKernel"] = "27.0.0"
        e["RealtekBluetoothFirmware.kext"]["MinKernel"] = "27.0.0"
        e["A2XACPIPlatform.kext"]["MinKernel"] = "27.0.0"
        e["A2XSMBIOS.kext"]["MinKernel"] = "27.0.0"
        e["AMFIPass.kext"]["MaxKernel"] = "26.99.99"
        order = ["a2x_exec_hook.kext", "Lilu.kext", "BlueToolFixup.kext", "VirtualSMC.kext", "AMFIPass.kext",
                 "SMCVendorFan.kext", "A2XACPIPlatform.kext"] + PLATFORM[:4] + ["A2XSMBIOS.kext"] + PLATFORM[4:] + [
                 "RealtekBluetoothFirmware.kext"]
        self.ref = config([e[n] for n in order], "-v keepsyms=1 -lilubetaall -vsmcbeta -no_compat_check vendorflag=1",
                          sbm="Disabled", product="Mac15,14")
        self.ref_path = os.path.join(tmp, "ref", "config.plist")
        write(self.ref_path, self.ref)

        self.efi = os.path.join(tmp, "efi")
        self.efi_kexts = os.path.join(self.efi, "EFI", "OC", "Kexts")
        b = [kext(self.efi_kexts, "Lilu.kext", "1.7.1"), kext(self.efi_kexts, "VirtualSMC.kext", "1.3.7",
                                                              personalities=smc("AppleACPIPlatformExpert")),
             kext(self.efi_kexts, "BlueToolFixup.kext", "2.7.1"), kext(self.efi_kexts, "AMFIPass.kext", "1.4.1"),
             kext(self.efi_kexts, "USBToolBox.kext", "1.2.0")]
        write(os.path.join(self.efi, "EFI", "OC", "config.plist"), config(b, "keepsyms=1"))
        self.report = {"Bluetooth": {"Realtek BT": {"Device ID": "0BDA-8922"}}}
        self.kit_path = os.path.join(tmp, "kit")
        with contextlib.redirect_stdout(io.StringIO()):
            self.kit = v3_kit.make(self.ref_path, self.ref_kexts, self.kit_path)

    def built(self):
        return read(os.path.join(self.efi, "EFI", "OC", "config.plist"))


class SyntheticReference(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v3m27-")
        self.f = Fixture(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def diff(self):
        return v3_macos27.diff_reference(self.f.built(), self.f.ref, self.f.kit, self.f.efi_kexts, self.f.ref_kexts)

    def test_the_unchanged_macos26_build_fails_the_comparison(self):
        d = self.diff()
        self.assertTrue(any("A2XACPIPlatform.kext: in the reference" in x for x in d), d)
        self.assertTrue(any("-v" in x for x in d), d)
        self.assertTrue(any("VirtualSMC.kext: provider classes" in x for x in d), d)

    def test_the_built_macos27_efi_matches_the_reference(self):
        notes = []
        changes = v3_macos27.apply(self.f.efi, self.f.kit, notes, self.f.report)
        self.assertEqual(self.diff(), [])
        self.assertTrue(any(c["v3"] == "personality" and c["count"] == 1 for c in changes), changes)
        self.assertTrue(any("auxiliary kernel collection" in n for n in notes), notes)

    def test_the_reference_machines_own_drivers_stay_out(self):
        v3_macos27.apply(self.f.efi, self.f.kit, [], self.f.report)
        names = [e["BundlePath"] for e in self.f.built()["Kernel"]["Add"]]
        self.assertNotIn("SMCVendorFan.kext", names)
        self.assertIn("USBToolBox.kext", names)   # the PC's own kexts are kept
        self.assertNotIn("vendorflag=1", self.f.built()["NVRAM"]["Add"][NV]["boot-args"])

    def test_versions_come_from_the_kit_and_amfipass_stops_at_26(self):
        v3_macos27.apply(self.f.efi, self.f.kit, [], self.f.report)
        e = {x["BundlePath"]: x for x in self.f.built()["Kernel"]["Add"]}
        self.assertEqual(read(os.path.join(self.f.efi_kexts, "BlueToolFixup.kext", "Contents", "Info.plist"))
                         ["CFBundleShortVersionString"], "2.7.7")
        self.assertEqual(e["BlueToolFixup.kext"]["MinKernel"], "27.0.0")
        self.assertEqual(e["Lilu.kext"]["MinKernel"], "27.0.0")
        self.assertEqual(e["AMFIPass.kext"]["MaxKernel"], "26.99.99")

    def test_lilu_loads_before_its_plugins(self):
        v3_macos27.apply(self.f.efi, self.f.kit, [], self.f.report)
        order = [x["BundlePath"] for x in self.f.built()["Kernel"]["Add"]]
        self.assertEqual(order[0], "a2x_exec_hook.kext")
        for p in ("BlueToolFixup.kext", "VirtualSMC.kext", "RealtekBluetoothFirmware.kext"):
            self.assertLess(order.index("Lilu.kext"), order.index(p), order)

    def test_realtek_bluetooth_firmware_follows_the_adapter(self):
        v3_macos27.apply(self.f.efi, self.f.kit, [], {"Bluetooth": {"Intel": {"Device ID": "8087-0033"}}})
        names = [e["BundlePath"] for e in self.f.built()["Kernel"]["Add"]]
        self.assertNotIn("RealtekBluetoothFirmware.kext", names)
        self.assertIn("A2XACPIPlatform.kext", names)

    def test_a_kit_without_v_is_refused(self):
        mpath = os.path.join(self.f.kit_path, v3_macos27.MANIFEST)
        with open(mpath) as fh:
            m = json.load(fh)
        m["boot_args"] = [a for a in m["boot_args"] if a != "-v"]
        with open(mpath, "w") as fh:
            json.dump(m, fh)
        with self.assertRaises(v3_macos27.KitError):
            v3_macos27.load_kit(self.f.kit_path)

    def test_a_kit_missing_a_kext_is_refused(self):
        shutil.rmtree(os.path.join(self.f.kit_path, "Kexts", "A2XSMBIOS.kext"))
        with self.assertRaises(v3_macos27.KitError):
            v3_macos27.load_kit(self.f.kit_path)

    def test_a_virtualsmc_with_neither_class_stops_the_build(self):
        info = os.path.join(self.f.efi_kexts, "VirtualSMC.kext", "Contents", "Info.plist")
        p = read(info); p["IOKitPersonalities"] = smc("SomethingElse"); write(info, p)
        with self.assertRaises(v3_macos27.KitError):
            v3_macos27.apply(self.f.efi, self.f.kit, [], self.f.report)

    def test_the_comparison_catches_a_wrong_min_kernel(self):
        v3_macos27.apply(self.f.efi, self.f.kit, [], self.f.report)
        cfg = self.f.built()
        next(e for e in cfg["Kernel"]["Add"] if e["BundlePath"] == "A2XACPIPlatform.kext")["MinKernel"] = "26.0.0"
        d = v3_macos27.diff_reference(cfg, self.f.ref, self.f.kit)
        self.assertTrue(any("A2XACPIPlatform.kext: MinKernel" in x for x in d), d)


class ModelIdentity(unittest.TestCase):
    def test_each_generation_has_its_class(self):
        for name, gen, cls in (("NVIDIA GeForce GTX 1660 SUPER", "GTX 16", "M1"), ("NVIDIA GeForce RTX 2080 Ti", "RTX 20", "M2"),
                               ("NVIDIA GeForce RTX 3060", "RTX 30", "M3"), ("NVIDIA GeForce RTX 4070 Ti SUPER", "RTX 40", "M4"),
                               ("NVIDIA GeForce RTX 5060", "RTX 50", "M5")):
            self.assertEqual(v3_macos27.gpu_generation(name), gen)
            self.assertEqual(v3_macos27.IDENTITY[gen]["class"], cls)
        for name in ("Quadro RTX 6000", "NVIDIA RTX A4000", "NVIDIA GeForce GTX 1080", "", None):
            self.assertIsNone(v3_macos27.gpu_generation(name))

    def card(self, did):
        return {"GPU": {"card": {"Manufacturer": "NVIDIA", "Device Type": "Discrete GPU", "Device ID": did}}}

    def test_a_serial_follows_its_model_and_two_pcs_never_share_one(self):
        a = v3_macos27.serial_for_model("C02ABCDEHX87", "11111111-2222-3333-4444-555555555555", "Mac17,15")
        self.assertEqual(a, "2412BRAJTG")                      # the value the Mac app's script computes for the same input
        self.assertEqual(len(a), 10)
        self.assertLessEqual(set(a), set(v3_macos27.SERIAL_ALPHABET))
        self.assertEqual(a, v3_macos27.serial_for_model(" C02ABCDEHX87 ", "11111111-2222-3333-4444-555555555555", "Mac17,15"))
        self.assertNotEqual(a, v3_macos27.serial_for_model("C02ABCDEHX88", "11111111-2222-3333-4444-555555555555", "Mac17,15"))
        self.assertNotEqual(a, v3_macos27.serial_for_model("C02ABCDEHX87", "11111111-2222-3333-4444-555555555556", "Mac17,15"))
        self.assertNotEqual(a, v3_macos27.serial_for_model("C02ABCDEHX87", "11111111-2222-3333-4444-555555555555", "Mac17,14"))
        # nothing of the PC's own to work from: no serial is made up, or every such PC would get the same one
        self.assertIsNone(v3_macos27.serial_for_model("", None, "Mac17,15"))

    def test_the_serial_changes_only_when_the_model_does(self):
        def own_identity(fx):
            cp = os.path.join(fx.efi, "EFI", "OC", "config.plist")
            with open(cp, "rb") as f:
                c0 = plistlib.load(f)
            c0["PlatformInfo"]["Generic"].update({"SystemSerialNumber": "C02ABCDEHX87", "SystemUUID": "11111111-2222-3333-4444-555555555555"})
            with open(cp, "wb") as f:
                plistlib.dump(c0, f)
            return dict(c0["PlatformInfo"]["Generic"])
        with tempfile.TemporaryDirectory() as tmp:
            fx = Fixture(tmp)
            before = own_identity(fx)
            changes = v3_macos27.apply(fx.efi, fx.kit, [], self.card("10DE-2D05"))
            after = fx.built()["PlatformInfo"]["Generic"]
            self.assertNotEqual(before.get("SystemProductName"), "Mac17,15")
            self.assertEqual(after["SystemSerialNumber"], "2412BRAJTG")
            self.assertEqual([c for c in changes if c["v3"] == "serial"], [{"v3": "serial", "why": "the model changed; the serial follows it"}])
        with tempfile.TemporaryDirectory() as tmp:       # a config with no serial and no UUID: left alone, and said
            fx = Fixture(tmp); notices = []
            v3_macos27.apply(fx.efi, fx.kit, notices, self.card("10DE-2D05"))
            self.assertNotIn("SystemSerialNumber", fx.built()["PlatformInfo"]["Generic"])
            self.assertTrue(any("serial was left as it is" in n for n in notices), notices)
        with tempfile.TemporaryDirectory() as tmp:
            fx = Fixture(tmp)
            before = own_identity(fx)
            changes = v3_macos27.apply(fx.efi, fx.kit, [], self.card("10DE-2504"))
            self.assertEqual(fx.built()["PlatformInfo"]["Generic"].get("SystemSerialNumber"), before.get("SystemSerialNumber"))
            self.assertEqual([c for c in changes if c["v3"] == "serial"], [])

    def test_the_build_records_the_class_and_sets_a_model_only_when_one_is_chosen(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = Fixture(tmp)
            changes = v3_macos27.apply(fx.efi, fx.kit, [], self.card("10DE-2D05"))
            ident = [c for c in changes if c["v3"] == "identity"]
            self.assertEqual([(c["generation"], c["class"], c["model"]) for c in ident], [("RTX 50", "M5", "Mac17,15")])
            self.assertEqual(fx.built()["PlatformInfo"]["Generic"]["SystemProductName"], "Mac17,15")
        with tempfile.TemporaryDirectory() as tmp:
            fx = Fixture(tmp)
            changes = v3_macos27.apply(fx.efi, fx.kit, [], self.card("10DE-2504"))
            self.assertEqual([c["generation"] for c in changes if c["v3"] == "identity"], ["RTX 30"])
            # No model is chosen for this class yet: the kit's own SystemProductName is what the build has.
            self.assertEqual(fx.built()["PlatformInfo"]["Generic"]["SystemProductName"], "Mac15,14")
        with tempfile.TemporaryDirectory() as tmp:
            fx = Fixture(tmp)
            old = v3_macos27.IDENTITY["RTX 20"]["model"]
            v3_macos27.IDENTITY["RTX 20"]["model"] = "TestModel1,1"
            try:
                v3_macos27.apply(fx.efi, fx.kit, [], self.card("10DE-1E04"))
            finally:
                v3_macos27.IDENTITY["RTX 20"]["model"] = old
            self.assertEqual(fx.built()["PlatformInfo"]["Generic"]["SystemProductName"], "TestModel1,1")

    def test_a_pc_with_no_classed_card_gets_no_identity_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = Fixture(tmp)
            changes = v3_macos27.apply(fx.efi, fx.kit, [], fx.report)
            self.assertEqual([c for c in changes if c["v3"] == "identity"], [])


class KitLimits(unittest.TestCase):
    """A kit may set only the listed config keys and add only the listed boot arguments."""

    def manifest(self, fx, **changes):
        path = os.path.join(fx.kit_path, v3_macos27.MANIFEST)
        with open(path) as fh:
            m = json.load(fh)
        for k, v in changes.items():
            m[k] = v(m[k])
        with open(path, "w") as fh:
            json.dump(m, fh)

    def test_the_kit_tool_writes_only_what_a_kit_may_set(self):
        self.assertLessEqual(set(v3_kit.SET), set(v3_macos27.SETTABLE))
        self.assertLessEqual(set(v3_kit.BOOT_ARGS), set(v3_macos27.BOOT_ARGS_ALLOWED))

    def test_a_config_key_outside_the_list_is_refused_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = Fixture(tmp)
            v3_macos27.load_kit(fx.kit_path)   # control: the kit as made loads
            self.manifest(fx, set=lambda s: dict(s, **{"Misc/Security/Vault": "Optional"}))
            with self.assertRaises(v3_macos27.KitError) as c:
                v3_macos27.load_kit(fx.kit_path)
            self.assertIn("Misc/Security/Vault", str(c.exception))

    def test_a_boot_argument_outside_the_list_is_refused_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            fx = Fixture(tmp)
            self.manifest(fx, boot_args=lambda a: a + ["amfi_get_out_of_my_way=1"])
            with self.assertRaises(v3_macos27.KitError) as c:
                v3_macos27.load_kit(fx.kit_path)
            self.assertIn("amfi_get_out_of_my_way=1", str(c.exception))


class NotOfferedWithoutAKit(unittest.TestCase):
    def test_no_kit_means_macos27_is_not_offered(self):
        old = os.environ.pop(v3_macos27.KIT_ENV, None)
        try:
            tmp = tempfile.mkdtemp(prefix="v3m27-nokit-")
            r = engine.build(os.path.join(tmp, "Report.json"), tmp, os.path.join(tmp, "out"), engine.Policy(macos="27"))
            self.assertFalse(r.ok)
            self.assertIn("MacosNotOffered", r.error)
            self.assertIn("not offered by this build", r.error)
            self.assertFalse(os.path.exists(os.path.join(tmp, "out")))   # nothing was built
        finally:
            if old is not None:
                os.environ[v3_macos27.KIT_ENV] = old
            shutil.rmtree(tmp, ignore_errors=True)

    def test_the_repository_carries_no_kit(self):
        files = subprocess.run(["git", "ls-files"], cwd=HERE, capture_output=True, text=True, check=True).stdout.split()
        self.assertFalse([f for f in files if f.endswith(v3_macos27.MANIFEST)])
        self.assertFalse([f for f in files if any(k in f for k in ("A2XACPIPlatform", "A2XSMBIOS", "a2x_exec_hook"))])


@unittest.skipUnless(os.environ.get("NULLMOTH_V3_REF"), "NOT RUN: set NULLMOTH_V3_REF to a folder with live.plist, "
                     "Kexts/ and base26.plist to compare against a configuration that booted macOS 27.2")
class RealReference(unittest.TestCase):
    def test_the_real_base26_becomes_the_real_live_config(self):
        ref = os.environ["NULLMOTH_V3_REF"]
        tmp = tempfile.mkdtemp(prefix="v3m27-real-")
        try:
            kit = v3_kit.make(os.path.join(ref, "live.plist"), os.path.join(ref, "Kexts"), os.path.join(tmp, "kit"))
            efi = os.path.join(tmp, "efi")
            kd = os.path.join(efi, "EFI", "OC", "Kexts")
            base = read(os.path.join(ref, "base26.plist"))
            os.makedirs(kd)
            for e in base["Kernel"]["Add"]:   # the 26 build's own kexts, as the 26 EFI had them
                src = os.path.join(ref, "Kexts26", e["BundlePath"])
                if not os.path.isdir(src):
                    src = os.path.join(ref, "Kexts", e["BundlePath"])
                if os.path.isdir(src) and not os.path.exists(os.path.join(kd, e["BundlePath"])):
                    shutil.copytree(src, os.path.join(kd, e["BundlePath"]), symlinks=True)
            write(os.path.join(efi, "EFI", "OC", "config.plist"), base)
            vsmc = os.path.join(ref, "VirtualSMC-Info.plist.orig")
            if os.path.isfile(vsmc):   # the 26 EFI's VirtualSMC, before its provider class was changed
                shutil.copy(vsmc, os.path.join(kd, "VirtualSMC.kext", "Contents", "Info.plist"))
            report = {}
            if os.path.isfile(os.path.join(ref, "Report.json")):
                with open(os.path.join(ref, "Report.json")) as fh:
                    report = json.load(fh)
            v3_macos27.apply(efi, kit, [], report)
            d = v3_macos27.diff_reference(read(os.path.join(efi, "EFI", "OC", "config.plist")),
                                          read(os.path.join(ref, "live.plist")), kit, kd, os.path.join(ref, "Kexts"))
            self.assertEqual(d, [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class FirstRealUpgrade(unittest.TestCase):
    """What the first upgrade of a real PC showed the stage step was missing (the reference boots, the staged copy did
    not): the identity as tables with the PC's own numbers, the NVIDIA kernel driver with the system kexts it links
    against, and an upper limit for every kext of the PC's own build that was never run on macOS 27."""

    REF_IDS = {"serial": "REFSERIAL001", "uuid": "11111111-2222-3333-4444-555555555555", "mlb": "REFMLB0000000001",
               "rom": b"\x01\x02\x03\x04\x05\x06"}
    PC_IDS = {"serial": "PCSERIAL0099", "uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", "mlb": "PCMLB00000000099",
              "rom": b"\xaa\xbb\xcc\xdd\xee\xff"}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v3first")
        rk = os.path.join(self.tmp, "ref", "Kexts")
        names = ["a2x_exec_hook.kext", "Lilu.kext", "VirtualSMC.kext", "NVRM.kext", "A2XACPIPlatform.kext"] + PLATFORM[:4] + [
            "A2XSMBIOS.kext"] + PLATFORM[4:]
        e = {n: kext(rk, n, personalities=smc("IOACPIPlatformExpert") if n == "VirtualSMC.kext" else None) for n in names}
        for n in names:
            if n not in ("Lilu.kext", "VirtualSMC.kext"):
                e[n]["MinKernel"] = "27.0.0"
        r = self.REF_IDS
        ref = config([e[n] for n in names], "-v -lilubetaall -vsmcbeta -no_compat_check", sbm="Disabled", product="Mac15,14")
        ref["Kernel"]["Force"] = [{"Arch": "x86_64", "BundlePath": "System/Library/Extensions/IOSurface.kext", "Comment": "",
                                   "Enabled": True, "ExecutablePath": "Contents/MacOS/IOSurface",
                                   "Identifier": "com.apple.iokit.IOSurface", "MaxKernel": "", "MinKernel": "27.0.0",
                                   "PlistPath": "Contents/Info.plist"}]
        ref["NVRAM"]["Add"][NV]["csr-active-config"] = bytes.fromhex("ff0f0000")
        ref["PlatformInfo"].update({
            "Automatic": False,
            "Generic": {"SystemProductName": "Mac15,14", "SystemSerialNumber": r["serial"], "SystemUUID": r["uuid"],
                        "MLB": r["mlb"], "ROM": r["rom"]},
            "DataHub": {"BoardProduct": "Mac-27AD2F918AE68F61", "SystemProductName": "Mac15,14",
                        "SystemSerialNumber": r["serial"], "SystemUUID": r["uuid"]},
            "PlatformNVRAM": {"BID": "Mac-27AD2F918AE68F61", "MLB": r["mlb"], "ROM": r["rom"],
                              "SystemSerialNumber": r["serial"], "SystemUUID": r["uuid"]},
            "SMBIOS": {"BoardProduct": "Mac-27AD2F918AE68F61", "BoardVersion": "Mac15,14", "SystemProductName": "Mac15,14",
                       "BoardSerialNumber": r["mlb"], "ChassisSerialNumber": r["serial"],
                       "SystemSerialNumber": r["serial"], "SystemUUID": r["uuid"]}})
        self.ref_path = os.path.join(self.tmp, "ref", "config.plist")
        write(self.ref_path, ref)
        self.kit_path = os.path.join(self.tmp, "kit")
        with contextlib.redirect_stdout(io.StringIO()):
            self.kit = v3_kit.make(self.ref_path, rk, self.kit_path)

        self.efi = os.path.join(self.tmp, "efi")
        ek = os.path.join(self.efi, "EFI", "OC", "Kexts")
        b = [kext(ek, "Lilu.kext"), kext(ek, "VirtualSMC.kext", personalities=smc("AppleACPIPlatformExpert")),
             kext(ek, "USBToolBox.kext"), kext(ek, "USBPorts.kext", exe=False), kext(ek, "SomeVendorFan.kext"),
             kext(ek, "IOSkywalkFamily.kext"), kext(ek, "IntelBTPatcher.kext"), kext(ek, "IntelMausi.kext")]
        b[6]["MaxKernel"] = "24.99.99"          # the PC's own, tighter limit
        pc = config(b, "keepsyms=1")
        pc["Kernel"]["Block"] = [{"Identifier": "com.apple.iokit.IOSkywalkFamily", "Enabled": True, "MaxKernel": "",
                                  "MinKernel": "23.0.0", "Comment": "", "Arch": "Any", "Strategy": "Exclude"}]
        p = self.PC_IDS
        pc["PlatformInfo"] = {"Automatic": True, "Generic": {"SystemProductName": "MacPro7,1", "SystemSerialNumber": p["serial"],
                                                             "SystemUUID": p["uuid"], "MLB": p["mlb"], "ROM": p["rom"]}}
        self.cpath = os.path.join(self.efi, "EFI", "OC", "config.plist")
        write(self.cpath, pc)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def built(self, **kw):
        notes = []
        changes = v3_macos27.apply(self.efi, self.kit, notes, None, **kw)
        return read(self.cpath), changes, notes

    def test_the_kit_carries_no_number_of_the_reference_machine(self):
        blob = b""
        for base, _d, files in os.walk(self.kit_path):
            for f in files:
                if not base.endswith("MacOS"):
                    with open(os.path.join(base, f), "rb") as fh:
                        blob += fh.read()
        for v in (self.REF_IDS["serial"], self.REF_IDS["uuid"], self.REF_IDS["mlb"]):
            self.assertNotIn(v.encode(), blob)
        tables = read(os.path.join(self.kit_path, v3_macos27.PLATFORM))
        self.assertEqual(tables["PlatformNVRAM"]["ROM"], b"")
        self.assertEqual(tables["SMBIOS"]["BoardProduct"], "Mac-27AD2F918AE68F61")   # what is not a number stays

    def test_the_identity_is_tables_with_this_pcs_own_numbers(self):
        cfg, changes, _ = self.built(kit_model=True)
        pi, p = cfg["PlatformInfo"], self.PC_IDS
        self.assertIs(pi["Automatic"], False)
        self.assertEqual(pi["SMBIOS"]["SystemSerialNumber"], p["serial"])
        self.assertEqual(pi["SMBIOS"]["ChassisSerialNumber"], p["serial"])
        self.assertEqual(pi["SMBIOS"]["BoardSerialNumber"], p["mlb"])
        self.assertEqual(pi["DataHub"]["SystemUUID"], p["uuid"])
        self.assertEqual(pi["PlatformNVRAM"]["ROM"], p["rom"])
        self.assertEqual(pi["PlatformNVRAM"]["BID"], "Mac-27AD2F918AE68F61")
        for sect, key in (("DataHub", "SystemProductName"), ("SMBIOS", "SystemProductName"), ("SMBIOS", "BoardVersion")):
            self.assertEqual(pi[sect][key], pi["Generic"]["SystemProductName"])
        self.assertNotIn(self.REF_IDS["serial"], repr(pi))
        self.assertTrue(any(c["v3"] == "identity tables" for c in changes), changes)

    def test_without_a_serial_of_its_own_the_tables_are_not_written_and_it_says_so(self):
        cfg = read(self.cpath)
        del cfg["PlatformInfo"]["Generic"]["SystemSerialNumber"]
        write(self.cpath, cfg)
        cfg, _, notes = self.built(kit_model=True)
        self.assertNotIn("SMBIOS", cfg["PlatformInfo"])
        self.assertIs(cfg["PlatformInfo"]["Automatic"], True)
        self.assertTrue(any("identity tables were not written" in n for n in notes), notes)

    def test_the_driver_its_forced_kexts_and_the_protection_value_come_from_the_kit(self):
        cfg, _, _ = self.built(kit_model=True)
        e = {x["BundlePath"]: x for x in cfg["Kernel"]["Add"]}
        self.assertEqual(e["NVRM.kext"]["MinKernel"], "27.0.0")
        self.assertLess(list(e).index("NVRM.kext"), list(e).index("A2XACPIPlatform.kext"))
        self.assertEqual([f["Identifier"] for f in cfg["Kernel"]["Force"] if f["Enabled"]], ["com.apple.iokit.IOSurface"])
        self.assertEqual(cfg["Kernel"]["Force"][0]["MinKernel"], "27.0.0")
        self.assertEqual(cfg["NVRAM"]["Add"][NV]["csr-active-config"], bytes.fromhex("ff0f0000"))

    def test_kexts_never_run_on_27_stop_at_26_and_known_ones_do_not(self):
        cfg, changes, notes = self.built(kit_model=True)
        e = {x["BundlePath"]: x for x in cfg["Kernel"]["Add"]}
        self.assertEqual(e["SomeVendorFan.kext"]["MaxKernel"], "26.99.99")      # unknown, has code
        self.assertEqual(e["IOSkywalkFamily.kext"]["MaxKernel"], "26.99.99")    # the replaced Wi-Fi stack
        self.assertEqual(cfg["Kernel"]["Block"][0]["MaxKernel"], "26.99.99")    # and the block that makes room for it
        self.assertEqual(e["IntelBTPatcher.kext"]["MaxKernel"], "24.99.99")     # the PC's own limit is not raised
        for name in ("Lilu.kext", "VirtualSMC.kext", "USBToolBox.kext", "IntelMausi.kext", "USBPorts.kext"):
            self.assertEqual(e[name]["MaxKernel"], "", name)                    # known, or no code in it
        self.assertTrue(any("SomeVendorFan.kext" in n and "does not load" in n for n in notes), notes)
        self.assertFalse(any("USBToolBox.kext" in n for n in notes), notes)

    def test_a_kit_with_a_bad_forced_path_is_refused(self):
        mpath = os.path.join(self.kit_path, v3_macos27.MANIFEST)
        with open(mpath) as fh:
            m = json.load(fh)
        m["force"][0]["bundle_path"] = "../../etc/passwd"
        with open(mpath, "w") as fh:
            json.dump(m, fh)
        with self.assertRaises(v3_macos27.KitError):
            v3_macos27.load_kit(self.kit_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
