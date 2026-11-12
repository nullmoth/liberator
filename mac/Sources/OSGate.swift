// 1401
// Copyright (c) 2026 NullMoth Systems. SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation

// Which macOS this app may install the driver on: 15 and 26 only. On any other macOS every driver install, driver
// download, driver update offer and Tahoe step is refused here, in setup (driver_os_ok), and by the kexts themselves;
// Send logs, the first-login report and the app's own updates are unaffected.
//
// One exception, and only on a Mac that has a NullMoth v3 kit (GoldenGate.kit(), which no public build carries or
// installs): on the kit's macOS an install is allowed, and it is the kit's own installers that run. The package this
// app carries is never installed there, a driver release is never offered or downloaded there, and the Tahoe step
// stays refused. Without a kit that macOS is refused like any other.
enum OSGate {
    static let driverMajors: Set<Int> = [15, 26]
    /// The macOS a v3 kit installs on.
    static let kitMajor = 27

    static var currentMajor: Int { ProcessInfo.processInfo.operatingSystemVersion.majorVersion }

    /// With no kit given this is the rule for the package the app carries and for driver releases: 15 and 26 only.
    static func driverInstallAllowed(major: Int, kit: String = "") -> Bool {
        driverMajors.contains(major) || kitInstall(major: major, kit: kit)
    }

    /// True when an install on this macOS is the kit's: setup is then handed the kit and never a driver package.
    static func kitInstall(major: Int, kit: String) -> Bool { major == kitMajor && !kit.isEmpty }

    /// The setup modes that install, update or prepare the driver; each is refused outside driverMajors.
    static let installModes: Set<String> = ["dry", "install", "tahoe"]
    /// The install modes a kit install has: the check and the install. Preparing for Tahoe is not one of them.
    static let kitModes: Set<String> = ["dry", "install"]

    /// Why this setup mode may not run on this macOS, or nil when it may.
    static func refusal(mode: String, major: Int, kit: String = "") -> String? {
        guard installModes.contains(mode), !driverMajors.contains(major) else { return nil }
        if kitInstall(major: major, kit: kit) && kitModes.contains(mode) { return nil }
        return refusal(major: major)
    }

    /// What setup is given for a kit install: the kit and whether to install or only check. Never --pkg.
    static func kitArguments(mode: String, kit: String) -> [String] {
        ["--v3-install", mode == "install" ? "apply" : "dry", "--v3-kit", kit]
    }

    static func refusal(major: Int) -> String {
        "The driver is built for macOS 15 Sequoia and macOS 26 Tahoe; this Mac runs macOS \(major)."
    }
}

// Prepare for Golden Gate: the move from macOS 26 to macOS 27.2 (nullmoth-golden-gate.sh). Offered only when a
// NullMoth v3 kit is installed on this Mac at kitPath; no public build carries or installs one, so on every other
// Mac the card stays hidden and every step is refused here before setup is started. The place is fixed and only an
// administrator can write there: setup runs the kit's installer as root, so where the kit is read from is never
// taken from the environment or from the page. The root script checks the kit's owner and permissions itself.
enum GoldenGate {
    static let kitPath = "/Library/NullMoth/v3-kit"
    /// Golden Gate starts from either macOS the driver supports. No point release is refused by its number: a step
    /// that cannot do its job on the running system says so itself.
    static let fromMajors: Set<Int> = [15, 26]
    /// The log every Golden Gate step appends its lines to (nullmoth-golden-gate.sh). The app shows its newest line
    /// while a step runs: laying macOS 27 down takes a long time and prints as it goes.
    static let stepLog = "/Library/NullMoth/golden-gate/steps.log"
    /// How long a step may run. Laying macOS 27 down downloads about 26 GB from Apple and unpacks it; every other
    /// step is done in minutes.
    static func timeLimit(step: String) -> TimeInterval { step == "all" ? 10 * 3600 : step == "installer" ? 8 * 3600 : 60 * 60 }
    /// The newest line of the step log that was added after it held `seen` bytes, with the new size.
    static func newestLine(of text: String, after seen: Int) -> (line: String, seen: Int) {
        let bytes = Array(text.utf8)
        guard bytes.count > seen else { return ("", bytes.count < seen ? bytes.count : seen) }
        let added = String(decoding: bytes[seen...], as: UTF8.self)
        let line = added.split(separator: "\n").last(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty && !$0.hasPrefix("RESULT ") && !GoldenGateProgress.isControl(String($0)) }).map(String.init) ?? ""
        return (line, bytes.count)
    }
    /// Every whole line the step log gained after it held `seen` bytes, with the size up to the last line end: a
    /// line that is still being written is read on the next look, whole.
    static func addedLines(of text: String, after seen: Int) -> (lines: [String], seen: Int) {
        let bytes = Array(text.utf8)
        guard bytes.count > seen else { return ([], bytes.count < seen ? bytes.count : seen) }
        guard let end = bytes[seen...].lastIndex(of: 10) else { return ([], seen) }
        let added = String(decoding: bytes[seen...end], as: UTF8.self)
        return (added.split(separator: "\n").map(String.init), end + 1)
    }
    /// The page's buttons. "prepare" is every check and then the staged copy; nothing else changes how the Mac starts
    /// except "activate", which the app asks the user to confirm.
    static let forwardSteps: Set<String> = ["prepare", "activate", "installer", "collections", "finish"]
    /// "all" is the page's one button: the kit, then every forward step in order, in one run of setup.
    /// "remove" takes a macOS 27 this app laid down away again (startup files back first); "clear-downloads" removes
    /// what is kept downloaded between tries. Like cancel they need no kit, and the app asks before either.
    /// "drivers-off" turns off, for macOS 27 only, every driver of this PC that is on there without having been
    /// proven there: the way back into macOS 27 after a start that did not reach the desktop. "drivers-on" takes
    /// that back. Both need the kit (it says which drivers those are) and both are asked about first.
    static let steps: Set<String> = forwardSteps.union(["cancel", "kit", "all", "remove", "clear-downloads"]).union(["drivers-off", "drivers-on"])
    /// Where the script writes how much is kept downloaded ("bytes N"). The folders themselves are root's alone, so
    /// this figure is all the app can read; it is shown and nothing is decided from it.
    /// The sizes the page offers for macOS 27, in GB; 0 is no limit. Anything else from the page is not passed on.
    static let sizes: Set<Int> = [0, 40, 64, 128, 256, 512]
    static func sizeArgs(_ gb: Any?) -> [String] {
        guard let n = gb as? Int, n > 0, sizes.contains(n) else { return [] }
        return ["--gg-size", String(n)]
    }
    static let downloadsRecord = "/Library/NullMoth/golden-gate/downloads"
    static func keptMB(record: String?) -> Int {
        guard let line = record?.split(separator: "\n").first, line.hasPrefix("bytes "),
              let n = Int(line.dropFirst(6)), n > 0 else { return 0 }
        return max(1, n / 1_000_000)
    }
    /// Where the kit step records the checksum of the archive the installed kit came from (nullmoth-v3-kit.sh).
    static let kitRecord = kitPath + ".archive-sha256"
    /// One value of the pin this build carries (lines "name …", "tag …", "size …", "sha256 …"), or "".
    static func pinValue(_ pin: String, _ key: String) -> String {
        for line in pin.split(separator: "\n") where line.hasPrefix(key + " ") { return String(line.dropFirst(key.count + 1)).trimmingCharacters(in: .whitespaces) }
        return ""
    }
    /// Where this Mac stands with the kit: "none" when this build offers no macOS 27 (it carries no pin), "absent"
    /// when no kit is installed, "current" when the installed kit came from this build's archive, "other" otherwise.
    static func kitState(pin: String?, record: String?, installed: Bool) -> String {
        guard let pin = pin else { return "none" }
        let want = pinValue(pin, "sha256")
        guard want.count == 64 else { return "none" }
        guard installed else { return "absent" }
        return (record ?? "").trimmingCharacters(in: .whitespacesAndNewlines) == want ? "current" : "other"
    }

    /// The kit folder, or "" when Golden Gate is not offered on this Mac.
    static func kit(exists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) -> String {
        exists(kitPath + "/v3-kit.json") ? kitPath : ""
    }

    /// Why this step may not run, or nil when it may. Cancel needs no kit (the way back must outlive the kit), but
    /// like every step it runs from macOS 15 or 26: macOS 27 cannot open the startup partition.
    static func refusal(step: String, major: Int, kit: String, kitState: String = "current") -> String? {
        guard steps.contains(step) else { return "Unknown Golden Gate step." }
        if (step == "kit" || step == "all") && kitState == "none" { return "macOS 27 is not offered by this build of 1401." }
        if forwardSteps.contains(step) && !kit.isEmpty && kitState != "current" { return "Get macOS 27 support first: the kit on this Mac is not the one this build of 1401 uses." }
        if forwardSteps.contains(step) && kit.isEmpty { return "macOS 27 is not offered by this build of 1401." }
        if (step == "drivers-off" || step == "drivers-on") && kit.isEmpty { return "Get macOS 27 support first: it says which drivers these are." }
        if !fromMajors.contains(major) { return "Golden Gate runs from macOS 15 or 26; this Mac runs macOS \(major)." }
        return nil
    }
}

/// One bar for the whole move. The scripts print four kinds of lines that are never shown as text:
///   PLAN-ALL kit:1 check:1 ...        the stages of the one-button run and the share of the bar each has
///   STAGE <name>                      a stage begins (every stage before it is finished, done now or by an earlier run)
///   PLAN <phase>:<weight> ...         the phases of the kit script that is running and the share of its stage each has
///   PROGRESS <phase> <percent> [<done bytes> <total bytes>]
/// Overall percent = the finished stages + the current stage's share x how far it is inside. The value shown never
/// goes down.
struct GoldenGateProgress {
    static let stageWords: [String: String] = [
        "kit": "Getting macOS 27 support", "check": "Checking this Mac", "stage": "Preparing the startup files",
        "collections": "Making the kernel collections", "install": "Installing macOS 27",
        "setup": "Setting up macOS 27 for this PC", "switch": "Switching to the new startup files", "done": "Done",
    ]
    static let phaseWords: [String: String] = [
        "kit-download": "Downloading macOS 27 support",
        "kdk-download": "Downloading Apple's Kernel Debug Kit", "kdk-unpack": "Unpacking the Kernel Debug Kit",
        "collections": "Making the kernel collections",
        "image-download": "Downloading macOS 27 from Apple", "image-verify": "Checking the download",
        "image-unpack": "Unpacking macOS 27", "copy-system": "Copying macOS 27 to its volume",
        "dyld-cache": "Preparing the system libraries for this PC", "data-volume": "Preparing the data volume",
        "preboot": "Preparing the startup volume",
    ]
    /// The setup stage (the kit's two installers) prints no count of its own, so inside its share the bar moves by
    /// elapsed time: toward nine tenths of the share over this many seconds, and the rest when the next stage begins.
    static let setupSeconds: TimeInterval = 15 * 60

    private var stages: [(name: String, weight: Int)] = []
    private var stage = -1
    private var stageBegan: TimeInterval = 0
    private var plan: [(name: String, weight: Int)] = []
    private var phase = ""
    private var phasePercent = 0.0
    private var bytes: (done: Int64, total: Int64) = (0, 0)
    private var finished = false
    private var shown = 0
    /// True once a line of the four kinds was seen: only then is there a bar to show.
    private(set) var active = false

    static func isControl(_ line: String) -> Bool {
        line.hasPrefix("PROGRESS ") || line.hasPrefix("PLAN ") || line.hasPrefix("PLAN-ALL ") || line.hasPrefix("STAGE ")
    }
    private static func pairs(_ words: ArraySlice<Substring>) -> [(name: String, weight: Int)] {
        var out: [(name: String, weight: Int)] = []
        for w in words {
            let p = w.split(separator: ":")
            guard p.count == 2, let n = Int(p[1]), n > 0 else { return [] }
            out.append((String(p[0]), n))
        }
        return out
    }
    mutating func take(_ line: String, at now: TimeInterval) {
        guard GoldenGateProgress.isControl(line) else { return }
        let w = line.split(separator: " ", omittingEmptySubsequences: true)
        guard w.count >= 2 else { return }
        switch w[0] {
        case "PLAN-ALL":
            let p = GoldenGateProgress.pairs(w[1...])
            if !p.isEmpty { stages = p; stage = -1; active = true }
        case "STAGE":
            if w[1] == "done" { finished = true; active = true; return }
            guard let i = stages.firstIndex(where: { $0.name == w[1] }), i >= stage else { return }
            stage = i; stageBegan = now; plan = []; phase = ""; phasePercent = 0; bytes = (0, 0); active = true
        case "PLAN":
            let p = GoldenGateProgress.pairs(w[1...])
            if !p.isEmpty { plan = p; phase = ""; phasePercent = 0; bytes = (0, 0); active = true }
        default:
            guard w.count >= 3, let pct = Double(w[2]) else { return }
            phase = String(w[1]); phasePercent = min(100, max(0, pct)); active = true
            bytes = w.count >= 5 ? (Int64(w[3]) ?? 0, Int64(w[4]) ?? 0) : (0, 0)
        }
    }
    /// How far the current stage is inside, 0...1.
    private func inside(at now: TimeInterval) -> Double {
        if !phase.isEmpty {
            if plan.isEmpty { return phasePercent / 100 }
            guard let i = plan.firstIndex(where: { $0.name == phase }) else { return 0 }
            let total = Double(plan.reduce(0) { $0 + $1.weight })
            let before = Double(plan[..<i].reduce(0) { $0 + $1.weight })
            return (before + Double(plan[i].weight) * phasePercent / 100) / total
        }
        if stage >= 0, stages[stage].name == "setup" {
            return min(0.9, max(0, now - stageBegan) / GoldenGateProgress.setupSeconds * 0.9)
        }
        return 0
    }
    /// The percent and the line under the bar. Mutating only to remember the highest percent shown.
    mutating func show(at now: TimeInterval) -> (percent: Int, text: String) {
        var value: Double
        if finished { value = 100 }
        else if stages.isEmpty { value = inside(at: now) * 100 }
        else if stage < 0 { value = 0 }
        else {
            let total = Double(stages.reduce(0) { $0 + $1.weight })
            let before = Double(stages[..<stage].reduce(0) { $0 + $1.weight })
            value = (before + Double(stages[stage].weight) * inside(at: now)) / total * 100
        }
        if !finished { value = min(value, 99) }
        shown = max(shown, Int(value))
        var words = finished ? GoldenGateProgress.stageWords["done"]!
            : !phase.isEmpty ? (GoldenGateProgress.phaseWords[phase] ?? "Working")
            : stage >= 0 ? (GoldenGateProgress.stageWords[stages[stage].name] ?? "Working") : "Starting"
        if !finished, phase.hasSuffix("-download"), bytes.total > 0 {
            let gb = bytes.total >= 1_000_000_000
            let unit = gb ? 1e9 : 1e6, f = gb ? "%.1f" : "%.0f"
            words += " (" + String(format: f, Double(min(bytes.done, bytes.total)) / unit) + " of " + String(format: f, Double(bytes.total) / unit) + (gb ? " GB)" : " MB)")
        }
        return (shown, "\(shown)%  \(words)")
    }
}
