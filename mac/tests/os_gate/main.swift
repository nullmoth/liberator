import Foundation
// The 2.x app never installs the driver on macOS 27: the driver it carries is for 15 and 26, and 27 has its own.
// Support (Send logs, the first-login report, the app's own update) stays available on every macOS.
var failed = 0
func check(_ ok: Bool, _ what: String) { if ok { print("ok   " + what) } else { failed += 1; print("FAIL " + what) } }
check(OSGate.driverInstallAllowed(major: 15) && OSGate.driverInstallAllowed(major: 26), "macOS 15 and 26 may install the driver")
for major in [14, 27, 28] {
    check(!OSGate.driverInstallAllowed(major: major), "macOS \(major) may not install the driver")
    for mode in ["install", "tahoe", "dry"] {
        check(OSGate.refusal(mode: mode, major: major) != nil, "setup mode \(mode) is refused on macOS \(major)")
    }
}
for mode in ["install", "tahoe", "dry"] {
    check(OSGate.refusal(mode: mode, major: 26) == nil, "setup mode \(mode) still runs on macOS 26")
}
for mode in ["remove", "usbmap", "verbose", "tahoecancel"] {
    check(OSGate.refusal(mode: mode, major: 27) == nil, "setup mode \(mode) (no driver install) is not refused on macOS 27")
}
check(OSGate.refusal(major: 27).contains("macOS 15") && OSGate.refusal(major: 27).contains("runs macOS 27")
      && !OSGate.refusal(major: 27).contains("27 driver"),
      "the refusal names the macOS this driver is for and the one this Mac runs, and offers nothing else")
// macOS 27 with a v3 kit: the check and the install are allowed and go to the kit; without a kit nothing changes.
let kitDir = "/Library/NullMoth/v3-kit"
check(OSGate.driverInstallAllowed(major: 27, kit: kitDir), "macOS 27 with a kit may install")
check(!OSGate.driverInstallAllowed(major: 27, kit: "") && !OSGate.driverInstallAllowed(major: 27),
      "control: macOS 27 without a kit may not install, and a caller that names no kit is refused")
for mode in ["install", "dry"] {
    check(OSGate.refusal(mode: mode, major: 27, kit: kitDir) == nil, "setup mode \(mode) runs on macOS 27 with a kit")
    check(OSGate.refusal(mode: mode, major: 27, kit: "") != nil, "control: setup mode \(mode) is refused on macOS 27 without a kit")
}
check(OSGate.refusal(mode: "tahoe", major: 27, kit: kitDir) != nil, "the Tahoe step is refused on macOS 27 even with a kit")
for major in [14, 28] {
    check(!OSGate.driverInstallAllowed(major: major, kit: kitDir), "a kit opens macOS 27 only: macOS \(major) may not install with one")
    for mode in ["install", "tahoe", "dry"] {
        check(OSGate.refusal(mode: mode, major: major, kit: kitDir) != nil, "setup mode \(mode) is refused on macOS \(major) with a kit")
    }
}
check(OSGate.kitInstall(major: 27, kit: kitDir) && !OSGate.kitInstall(major: 27, kit: "") && !OSGate.kitInstall(major: 26, kit: kitDir)
      && !OSGate.kitInstall(major: 15, kit: kitDir),
      "an install is the kit's only on macOS 27 with a kit: on 15 and 26 a kit changes nothing about what is installed")
check(OSGate.kitArguments(mode: "dry", kit: kitDir) == ["--v3-install", "dry", "--v3-kit", kitDir]
      && OSGate.kitArguments(mode: "install", kit: kitDir) == ["--v3-install", "apply", "--v3-kit", kitDir]
      && !OSGate.kitArguments(mode: "install", kit: kitDir).contains("--pkg"),
      "a kit install hands setup the kit and never a driver package")
// A long step: its time limit, and the line shown while it runs.
check(GoldenGate.timeLimit(step: "installer") >= 6 * 3600 && GoldenGate.timeLimit(step: "finish") <= 3600 && GoldenGate.timeLimit(step: "finish") >= 30 * 60,
      "laying macOS 27 down may run for hours; every other step is bounded at an hour or less")
let logText = "== start\nSTEP one\nOK   two\n"
let first = GoldenGate.newestLine(of: logText, after: 0)
check(first.line == "OK   two" && first.seen == logText.utf8.count, "the newest line of the step log is the one shown")
check(GoldenGate.newestLine(of: logText, after: first.seen).line.isEmpty, "nothing new in the log: nothing is shown again")
let more = GoldenGate.newestLine(of: logText + "downloading 40%\nRESULT ok\n\n", after: first.seen)
check(more.line == "downloading 40%", "a result line and empty lines are not what is shown")
check(GoldenGate.newestLine(of: "short", after: 500).seen == 5, "a log that was cut down is followed from its new end")
check(GoldenGate.stepLog == "/Library/NullMoth/golden-gate/steps.log", "the step log is in one fixed place")
// The Golden Gate bar: a recorded run drives the percent. Times are seconds; the look happens after each line.
let fullRun: [(Double, String)] = [
    (0, "PLAN-ALL kit:1 check:1 stage:1 collections:12 install:74 setup:10 switch:1"),
    (0, "STAGE kit"), (1, "STEP the archive"), (2, "PROGRESS kit-download 40 24000000 59953380"), (4, "PROGRESS kit-download 100 59953380 59953380"),
    (5, "STAGE check"), (6, "OK   the card is supported"), (8, "STAGE stage"), (9, "STEP Staging the startup files"),
    (10, "STAGE collections"), (11, "PLAN kdk-download:40 kdk-unpack:20 collections:40"),
    (12, "PROGRESS kdk-download 50 625000000 1250000000"), (20, "PROGRESS kdk-download 100 1250000000 1250000000"),
    (21, "PROGRESS kdk-unpack 50 0 0"), (25, "PROGRESS collections 10"), (30, "PROGRESS collections 100"),
    (31, "STAGE install"), (32, "PLAN image-download:55 image-verify:5 image-unpack:10 copy-system:20 dyld-cache:5 data-volume:3 preboot:2"),
    (40, "PROGRESS image-download 25 6400000000 25600000000"), (50, "PROGRESS image-download 100 25600000000 25600000000"),
    (51, "PROGRESS image-verify 50 0 0"), (52, "PROGRESS image-unpack 50 0 0"), (53, "PROGRESS copy-system 50 0 0"),
    (54, "PROGRESS dyld-cache 50 0 0"), (55, "PROGRESS data-volume 50 0 0"), (56, "PROGRESS preboot 100 0 0"),
    (60, "STAGE setup"), (61, "STEP routes"), (500, "OK   routes made"), (5000, "OK   driver placed"),
    (5001, "STAGE switch"), (5002, "OK   this Mac now starts from the new startup files"), (5003, "STAGE done"),
]
var bar = GoldenGateProgress(), seenPercents: [Int] = [], texts: [String: String] = [:], last = (percent: 0, text: "")
check(!bar.active, "before any line of the four kinds there is no bar")
for (t, line) in fullRun {
    bar.take(line, at: t); last = bar.show(at: t); seenPercents.append(last.percent)
    let w = line.split(separator: " ")
    if w[0] == "PROGRESS" || w[0] == "STAGE" { texts[String(w[1])] = last.text }
}
check(bar.active && zip(seenPercents, seenPercents.dropFirst()).allSatisfy { $0 <= $1 }, "a whole run: the percent never goes down")
check(last.percent == 100 && last.text == "100%  Done", "a whole run ends at 100 [\(last.text)]")
check(seenPercents.dropLast().allSatisfy { $0 < 100 }, "nothing before the end of the run shows 100")
for (key, want) in [("kit", "Getting macOS 27 support"), ("check", "Checking this Mac"), ("stage", "Preparing the startup files"),
                    ("collections", "Making the kernel collections"), ("install", "Installing macOS 27"), ("setup", "Setting up macOS 27 for this PC"),
                    ("switch", "Switching to the new startup files"), ("kdk-unpack", "Unpacking the Kernel Debug Kit"),
                    ("image-verify", "Checking the download"), ("image-unpack", "Unpacking macOS 27"), ("copy-system", "Copying macOS 27 to its volume"),
                    ("dyld-cache", "Preparing the system libraries for this PC"), ("data-volume", "Preparing the data volume"), ("preboot", "Preparing the startup volume")] {
    check((texts[key] ?? "").hasSuffix("%  " + want), "the line under the bar for \(key) [\(texts[key] ?? "none")]")
}
for phase in ["kit-download", "kdk-download", "kdk-unpack", "collections", "image-download", "image-verify", "image-unpack", "copy-system", "dyld-cache", "data-volume", "preboot"] {
    check(GoldenGateProgress.phaseWords[phase] != nil, "phase \(phase) has words of its own")
}
var b2 = GoldenGateProgress()
for l in ["PLAN-ALL kit:1 check:1 stage:1 collections:12 install:74 setup:10 switch:1", "STAGE install",
          "PLAN image-download:55 image-verify:5 image-unpack:10 copy-system:20 dyld-cache:5 data-volume:3 preboot:2",
          "PROGRESS image-download 25 6400000000 25600000000"] { b2.take(l, at: 0) }
var s2 = b2.show(at: 0)
check(s2.percent == 25 && s2.text == "25%  Downloading macOS 27 from Apple (6.4 of 25.6 GB)", "a download shows its percent of the whole move and its size [\(s2.text)]")
var b3 = GoldenGateProgress()
b3.take("PROGRESS kit-download 40 24000000 59953380", at: 0)
check(b3.show(at: 0).text == "40%  Downloading macOS 27 support (24 of 60 MB)", "a step run by itself: the bar is its own percent, a small download in MB")
// a resumed run: earlier stages and phases are passed over and count as done
var b4 = GoldenGateProgress()
for l in ["PLAN-ALL kit:1 check:1 stage:1 collections:12 install:74 setup:10 switch:1", "STAGE kit", "STAGE collections"] { b4.take(l, at: 0) }
check(b4.show(at: 0).percent == 3, "a resumed run: stages an earlier run finished count as done")
for l in ["STAGE install", "PLAN image-download:55 image-verify:5 image-unpack:10 copy-system:20 dyld-cache:5 data-volume:3 preboot:2", "PROGRESS copy-system 0 0 0"] { b4.take(l, at: 1) }
s2 = b4.show(at: 1)
check(s2.percent == 15 + Int(74.0 * 0.70) && s2.text.hasSuffix("Copying macOS 27 to its volume"), "a resumed lay-down: phases it passes over count as done [\(s2.text)]")
b4.take("PROGRESS image-download 10 1 10", at: 2)
check(b4.show(at: 2).percent == s2.percent, "control: a line that would move the bar back does not")
b4.take("STAGE check", at: 3)
check(b4.show(at: 3).percent == s2.percent, "control: a stage that is already behind does not move the bar back")
var b5 = GoldenGateProgress()
for l in ["PLAN-ALL kit:1 check:1 stage:1 collections:12 install:74 setup:10 switch:1", "STAGE setup"] { b5.take(l, at: 100) }
let p0 = b5.show(at: 100).percent, p1 = b5.show(at: 100 + 450).percent, p2 = b5.show(at: 100 + 90000).percent
check(p0 == 89 && p1 > p0 && p2 == 98, "setup has no count of its own: its share moves with time and stops short of the next stage [\(p0) \(p1) \(p2)]")
var b6 = GoldenGateProgress()
for l in ["STEP one", "PLAN-ALL kit:x", "PLAN a:0", "PROGRESS", "PROGRESS a b", "STAGE nowhere", "PLANNING is not a plan"] { b6.take(l, at: 0) }
check(!b6.active, "control: ordinary lines and malformed ones start no bar")
check(GoldenGateProgress.isControl("PROGRESS a 1") && GoldenGateProgress.isControl("PLAN a:1") && GoldenGateProgress.isControl("PLAN-ALL a:1")
      && GoldenGateProgress.isControl("STAGE a") && !GoldenGateProgress.isControl("STEP a") && !GoldenGateProgress.isControl("OK   PROGRESS"),
      "the four kinds of bar lines are told from text lines")
let mixed = "STEP one\nPROGRESS a 5 1 2\nPLAN a:100\nSTAGE x\n"
check(GoldenGate.newestLine(of: mixed, after: 0).line == "STEP one", "a bar line is never the newest line shown as text")
let cut = GoldenGate.addedLines(of: "STEP one\nPROGRESS a 5", after: 0)
check(cut.lines == ["STEP one"] && cut.seen == 9, "a line still being written is not read until it is whole")
let whole = GoldenGate.addedLines(of: "STEP one\nPROGRESS a 5 1 2\n", after: cut.seen)
check(whole.lines == ["PROGRESS a 5 1 2"] && whole.seen == 26, "and is then read once, whole")
check(GoldenGate.addedLines(of: "short\n", after: 500).seen == 6, "a log that was cut down is followed from its new end")
// Prepare for Golden Gate: offered only with a v3 kit, only from macOS 26.
var asked: [String] = []
let noKit = GoldenGate.kit(exists: { asked.append($0); return false })
let kit = GoldenGate.kit(exists: { $0 == "/Library/NullMoth/v3-kit/v3-kit.json" })
check(noKit.isEmpty, "no kit manifest in the fixed place: Golden Gate is not offered")
check(asked == ["/Library/NullMoth/v3-kit/v3-kit.json"], "the kit is looked for in one fixed place only")
check(kit == "/Library/NullMoth/v3-kit", "a kit manifest in the fixed place: Golden Gate is offered")
for step in ["prepare", "activate", "installer", "collections", "finish"] {
    check(GoldenGate.refusal(step: step, major: 26, kit: "") != nil, "Golden Gate \(step) is refused without a kit")
    check(GoldenGate.refusal(step: step, major: 26, kit: kit) == nil, "Golden Gate \(step) runs on macOS 26 with a kit")
    check(GoldenGate.refusal(step: step, major: 15, kit: kit) == nil, "Golden Gate \(step) runs on macOS 15 with a kit")
    for major in [14, 27] {
        check(GoldenGate.refusal(step: step, major: major, kit: kit) != nil, "Golden Gate \(step) is refused on macOS \(major)")
    }
}
check(GoldenGate.refusal(step: "cancel", major: 26, kit: "") == nil, "Golden Gate cancel needs no kit")
check(GoldenGate.refusal(step: "cancel", major: 27, kit: kit) != nil, "Golden Gate cancel is refused on macOS 27")
check(GoldenGate.refusal(step: "anything", major: 26, kit: kit) != nil, "an unknown Golden Gate step is refused")
// The kit this build accepts is named by its pin; where the Mac stands with it decides which buttons may run.
let sha = String(repeating: "ab", count: 32)
let pin = "name nullmoth-v3-kit-3.0.0-beta.1.tar.gz\ntag v3.0.0-beta.1\nsize 180000000\nsha256 \(sha)\n"
check(GoldenGate.pinValue(pin, "sha256") == sha && GoldenGate.pinValue(pin, "size") == "180000000" && GoldenGate.pinValue(pin, "none") == "", "the pin's values are read by name")
check(GoldenGate.kitState(pin: nil, record: sha, installed: true) == "none", "a build with no pin offers no macOS 27, whatever is installed")
check(GoldenGate.kitState(pin: "name x\nsha256 short\n", record: nil, installed: false) == "none", "a pin without a whole checksum is no pin")
check(GoldenGate.kitState(pin: pin, record: nil, installed: false) == "absent", "a pin and no kit: the kit is to be fetched")
check(GoldenGate.kitState(pin: pin, record: sha + "\n", installed: true) == "current", "a kit from this build's archive is current")
check(GoldenGate.kitState(pin: pin, record: String(repeating: "cd", count: 32), installed: true) == "other", "a kit from another archive is not this build's")
check(GoldenGate.kitState(pin: pin, record: nil, installed: true) == "other", "a kit with no record of its archive is not this build's")
check(GoldenGate.refusal(step: "kit", major: 26, kit: "", kitState: "absent") == nil && GoldenGate.refusal(step: "kit", major: 15, kit: "", kitState: "absent") == nil, "getting the kit needs no kit, from macOS 15 or 26")
check(GoldenGate.refusal(step: "kit", major: 26, kit: "", kitState: "none") != nil, "getting the kit is refused by a build with no pin")
check(GoldenGate.refusal(step: "kit", major: 27, kit: "", kitState: "absent") != nil, "getting the kit is refused on macOS 27")
for step in ["prepare", "collections", "installer", "finish", "activate"] {
    check(GoldenGate.refusal(step: step, major: 26, kit: kit, kitState: "other") != nil, "Golden Gate \(step) is refused with another build's kit")
    check(GoldenGate.refusal(step: step, major: 26, kit: "", kitState: "absent") != nil, "Golden Gate \(step) is refused before the kit is fetched")
}
check(GoldenGate.refusal(step: "cancel", major: 26, kit: kit, kitState: "other") == nil, "cancel runs whatever kit is installed")
for step in ["remove", "clear-downloads"] {
    check(GoldenGate.refusal(step: step, major: 26, kit: "", kitState: "none") == nil, "Golden Gate \(step) needs no kit")
    check(GoldenGate.refusal(step: step, major: 27, kit: kit) != nil, "Golden Gate \(step) is refused on macOS 27")
}
check(GoldenGate.keptMB(record: "bytes 26843545600\n") == 26843, "the kept downloads are read from the script's record")
check(GoldenGate.keptMB(record: "bytes 5\n") == 1, "a few kept bytes still show as kept")
for bad in [nil, "", "bytes 0\n", "bytes -4\n", "bytes x\n", "26843545600\n", "bytes 99999999999999999999999\n"] as [String?] {
    check(GoldenGate.keptMB(record: bad) == 0, "a record that is not a size (\(bad ?? "none")) shows nothing kept")
}
check(GoldenGate.sizeArgs(64) == ["--gg-size", "64"], "a size the page offers is passed on")
for bad in [0, 41, -64, 99999, "64", "64; rm", nil] as [Any?] {
    check(GoldenGate.sizeArgs(bad).isEmpty, "a size the app does not offer (\(String(describing: bad))) is not passed on")
}
print("\(failed) failed"); exit(failed == 0 ? 0 : 1)
