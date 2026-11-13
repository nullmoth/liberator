#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
OUT=${1:-build}; APP=$OUT/Liberator.app
[ -f Resources/NullMothSafe.efi ] || { echo "STOP: Resources/NullMothSafe.efi missing (build efi-safe first)"; exit 1; }
SDK=$(xcrun --sdk macosx --show-sdk-path)
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
# The EFI checker reads the same rule file 1401 for Windows builds from; it ships only when it decides every case the
# Python checker decided the same way (tests/efi_rules, cases from tools/efi_rules_vectors.py).
T=$(mktemp -d)
xcrun swiftc -O -target x86_64-apple-macos15.0 -sdk "$SDK" Sources/EfiRules.swift tests/efi_rules/main.swift -o "$T/efi_rules_test"
RUN=(); [ "$(uname -m)" = arm64 ] && RUN=(arch -x86_64)
"${RUN[@]}" "$T/efi_rules_test" ../p1401/efi_rules.json tests/efi_rules/vectors.json || { echo "STOP: the Mac EFI checker disagrees with 1401's"; exit 1; }
xcrun swiftc -O -target x86_64-apple-macos15.0 -sdk "$SDK" Sources/TitleBar.swift tests/title_bar/main.swift -o "$T/title_bar_test"
"${RUN[@]}" "$T/title_bar_test" || { echo "STOP: the window cannot be dragged by its title bar"; exit 1; }
xcrun swiftc -O -target x86_64-apple-macos15.0 -sdk "$SDK" Sources/Mirror.swift tests/mirror/main.swift -o "$T/mirror_test"
"${RUN[@]}" "$T/mirror_test" || { echo "STOP: the download mirror maps an address it must refuse"; exit 1; }
xcrun swiftc -O -target x86_64-apple-macos15.0 -sdk "$SDK" Sources/OSGate.swift tests/os_gate/main.swift -o "$T/os_gate_test"
"${RUN[@]}" "$T/os_gate_test" || { echo "STOP: the app would install the driver on a macOS it is not built for"; exit 1; }
rm -rf "$T"
cp Resources/* "$APP/Contents/Resources/"
# What exists only for the tests is removed from the copies the app carries (the sources keep it): the options that
# stand in for what a script would measure on the Mac, and the looser file-owner rule the tests run under.
python3 tools/strip_test_hooks.py "$APP"/Contents/Resources/*.sh || { echo "STOP: a test region in a script is not closed"; exit 1; }
if grep -l 'test-hook-\|^[[:space:]]*# ship: ' "$APP"/Contents/Resources/*.sh; then echo "STOP: a test region marker is left in a script the app carries"; exit 1; fi
cp ../p1401/efi_rules.json "$APP/Contents/Resources/"
# The maintainers' notes of where each rule came from are not part of the app (no code reads them).
python3 tools/strip_rule_notes.py "$APP/Contents/Resources/efi_rules.json:source" "$APP/Contents/Resources/nullmoth-rules.json:evidence" || { echo "STOP: a rule file could not be rewritten"; exit 1; }
xcrun clang -O2 -Wall -Wextra -Werror -target x86_64-apple-macos15.0 -isysroot "$SDK" RuntimeCheck/main.c -o "$APP/Contents/Resources/nullmoth-runtime-check"
codesign --force --runtime-version 15.0.0 --options runtime,library -s - "$APP/Contents/Resources/nullmoth-runtime-check"
xcrun clang -O2 -Wall -Wextra -Werror -target x86_64-apple-macos15.0 -isysroot "$SDK" RuntimeCheck/log_watch.c -o "$APP/Contents/Resources/nullmoth-log-watch"
codesign --force --runtime-version 15.0.0 --options runtime,library -s - "$APP/Contents/Resources/nullmoth-log-watch"
# The reader the log collector uses for files on another volume: every part of the path opened without following a link.
xcrun clang -O2 -Wall -Wextra -Werror -target x86_64-apple-macos15.0 -isysroot "$SDK" RuntimeCheck/safe_read.c -o "$APP/Contents/Resources/nullmoth-safe-read"
codesign --force --runtime-version 15.0.0 --options runtime,library -s - "$APP/Contents/Resources/nullmoth-safe-read"
# Plain ad-hoc, deliberately without the hardened runtime: it has to load the NVIDIA Metal plugin, which is ad-hoc signed
# and which library validation refuses (see RuntimeCheck/metal_devices.m).
xcrun clang -fobjc-arc -O2 -Wall -Wextra -Werror -target x86_64-apple-macos15.0 -isysroot "$SDK" RuntimeCheck/metal_devices.m \
  -framework Foundation -framework Metal -o "$APP/Contents/Resources/nullmoth-metal-devices"
codesign --force -s - "$APP/Contents/Resources/nullmoth-metal-devices"
# "Microphone and camera": asks tccd for the grant through Apple's TCC framework, which takes a private entitlement
# the hardened app cannot carry (RuntimeCheck/tcc_grant.m)
xcrun clang -fobjc-arc -O2 -Wall -Wextra -Werror -target x86_64-apple-macos15.0 -isysroot "$SDK" RuntimeCheck/tcc_grant.m \
  -framework Foundation -o "$APP/Contents/Resources/nullmoth-tcc-grant"
codesign --force -s - --entitlements RuntimeCheck/tcc_grant.entitlements "$APP/Contents/Resources/nullmoth-tcc-grant"
# "Map my GPU": the same separate-process reason as nullmoth-metal-devices (RuntimeCheck/gpumap.m)
xcrun clang -fobjc-arc -O2 -Wall -Wextra -Werror -target x86_64-apple-macos15.0 -isysroot "$SDK" RuntimeCheck/gpumap.m \
  -framework Foundation -framework Metal -o "$APP/Contents/Resources/nullmoth-gpumap"
codesign --force -s - "$APP/Contents/Resources/nullmoth-gpumap"
chmod 755 "$APP/Contents/Resources/nullmoth-runtime-check.sh"
chmod 755 "$APP/Contents/Resources/nullmoth-setup.sh"
chmod 755 "$APP/Contents/Resources/nullmoth-golden-gate.sh"
chmod 755 "$APP/Contents/Resources/nullmoth-v3-kit.sh"
# macOS 27 is offered only by a build that is given the pin of its v3 kit (tools/pack_v3_kit.sh writes it): the name,
# release tag, size and SHA-256 of the one archive this build accepts. Without V3_KIT_PIN the app carries none.
rm -f "$APP/Contents/Resources/v3-kit.pin"
if [ -n "${V3_KIT_PIN:-}" ]; then
  [ "$(grep -c -E '^(name|tag|size|sha256) [A-Za-z0-9._-]+$' "$V3_KIT_PIN")" = 4 ] || { echo "STOP: V3_KIT_PIN is not a kit pin (name, tag, size, sha256)"; exit 1; }
  cp "$V3_KIT_PIN" "$APP/Contents/Resources/v3-kit.pin"; chmod 644 "$APP/Contents/Resources/v3-kit.pin"
fi
# setup runs the installers only when they are executable ([ -x ]); a source file that lost its mode made every app
# install stop with "the audited installer is missing from the app" (1.15 review), so the bundle sets it here
chmod 755 "$APP/Contents/Resources/nullmoth-uninstall.sh"
xcrun clang -fobjc-arc -O1 -Wno-deprecated-declarations -target x86_64-apple-macos15.0 -isysroot "$SDK" \
  -ffile-prefix-map="$(pwd)/DiagnosticsNative=/src/diagnostics" -fdebug-prefix-map="$(pwd)/DiagnosticsNative=/src/diagnostics" \
  DiagnosticsNative/preflight.m DiagnosticsNative/authority/NDSecurityState.m DiagnosticsNative/authority/NDAuthorityPolicy.m \
  DiagnosticsNative/authority/NDCaptureRight.m DiagnosticsNative/module/NDNativeDiagnostics.m DiagnosticsNative/module/NDBoundedProcess.m \
  DiagnosticsNative/module/NDTracePolicy.c -framework Foundation -framework Security -framework IOKit \
  -o "$APP/Contents/Resources/nullmoth-diagnostics-preflight"
strip -S "$APP/Contents/Resources/nullmoth-diagnostics-preflight"
codesign --force --runtime-version 15.0.0 --options runtime,library -s - "$APP/Contents/Resources/nullmoth-diagnostics-preflight"
IS=$(mktemp -d)/m.iconset; mkdir -p "$IS"
for s in 16 32 128 256 512; do
  sips -z $s $s Resources/moth-mark.jpg --setProperty format png --out "$IS/icon_${s}x${s}.png" >/dev/null
  sips -z $((s*2)) $((s*2)) Resources/moth-mark.jpg --setProperty format png --out "$IS/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$IS" -o "$APP/Contents/Resources/Liberator.icns"
cat > "$APP/Contents/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleExecutable</key><string>Liberator</string>
<key>CFBundleIconFile</key><string>Liberator</string>
<key>CFBundleIdentifier</key><string>com.nullmoth.liberator</string>
<key>CFBundleName</key><string>Liberator</string>
<key>CFBundleDisplayName</key><string>Liberator</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.2.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>15.0</string>
<key>NSHumanReadableCopyright</key><string>© 2026 NullMoth Systems</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSRemovableVolumesUsageDescription</key><string>Liberator reads the OpenCore settings on your USB stick or disk to install the driver there.</string>
<key>NSAppleEventsUsageDescription</key><string>Liberator asks macOS for your password to install the driver, and to restart when you click Restart.</string>
</dict></plist>
PL
# The hash of every resource is compiled into the app, so the root shell can check its private copy of the scripts
# (Privileged.bundleScript). This is the last step that may change a resource: helpers are signed above, and the app's
# own signature below does not touch them.
HASHES=$(mktemp -d)/BundleHashes.swift
{
  echo 'enum BundleHashes {'; echo '    static let table: [String: String] = ['
  for f in "$APP"/Contents/Resources/*; do
    n=$(basename "$f")
    [ -f "$f" ] || { echo "STOP: $n in Resources is not a plain file" >&2; exit 1; }
    case $n in *[!A-Za-z0-9._-]*) echo "STOP: the name $n cannot go on a root command line" >&2; exit 1 ;; esac
    printf '        "%s": "%s",\n' "$n" "$(shasum -a 256 "$f" | cut -d' ' -f1)"
  done
  echo '    ]'; echo '}'
} > "$HASHES"
xcrun swiftc -O -target x86_64-apple-macos15.0 -sdk "$SDK" -framework WebKit -framework Metal -framework IOKit \
  Sources/main.swift Sources/TesterLane.swift Sources/ArmApps.swift Sources/ReachedDesktop.swift Sources/profile.swift Sources/redaction.swift Sources/actions.swift Sources/diagnostics.swift Sources/HardwareMap.swift Sources/HardwareMapWorker.swift Sources/NativePeripheralFacts.swift Sources/SavedReports.swift Sources/ReportQueue.swift Sources/Privileged.swift Sources/ReleaseSignature.swift Sources/UpdateChannel.swift Sources/Mirror.swift Sources/EfiRules.swift Sources/EfiCheck.swift Sources/TitleBar.swift Sources/OSGate.swift "$HASHES" -o "$APP/Contents/MacOS/Liberator"
# --options runtime,library: library validation, so only code signed by the
# same identity loads into the bundle. Was a bare ad-hoc signature, which let
# any dropped-in library load into the process that asks for the password.
# The helper binaries above were already signed this way.
# The hardened runtime blocks Apple Events the app sends itself (Restart asks System Events) unless the signature
# carries this entitlement. The Metal device list runs in nullmoth-metal-devices for the same reason the app is hardened.
ENT=$(mktemp -d)/Liberator.entitlements
cat > "$ENT" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.security.automation.apple-events</key><true/>
</dict></plist>
PL
codesign --force --runtime-version 15.0.0 --options runtime,library --entitlements "$ENT" -s - "$APP"
echo "built $APP ($(du -sh "$APP" | cut -f1))"
