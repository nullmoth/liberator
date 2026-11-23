#!/bin/bash
# install-apple.sh - macOS 27.2 on a real Intel Mac (2013 and later), run from Tahoe on the same Mac (Golden Gate's
# finish step does that). macOS 27 for Intel has no graphics drivers; this Mac's Tahoe has the ones it runs on. This
# package works the same way on every Mac:
#  1. reads which graphics drivers the running Tahoe has loaded (AMD, Intel or NVIDIA), copies those kernel drivers
#     into a private folder and the same vendors' user-space bundles onto the macOS 27 system volume. They are read
#     from this Mac and never shipped.
#  2. on AMD graphics, adds one load command to macOS 27's copy of libAMDIL902 (Tahoe's shader compiler) so it loads
#     amdil_rtfix.dylib, which lets it compile macOS 27's shaders. Only the exact 18,187,216-byte build is changed.
#  3. links the auxiliary kernel collection (those graphics drivers + NMXAudio, the audio driver) against the laid-down
#     macOS 27.2 boot and system collections. kmutil must run here: macOS 27's own refuses this pair.
#  4. installs three helpers on macOS 27: RenderBox on its CPU renderer (this GPU has no framebuffer fetch), the
#     internal speakers as the default output, and a DHCP request for wired ports that come up without an address.
#
#   sudo bash install-apple.sh --payload <this folder> --system "/Volumes/<name>" --data "/Volumes/<name> - Data"
#        [--esp <partition>] [--kdk <folder or .dmg>] [--dry-run | --apply | --uninstall]
#
# Intel graphics: Tahoe keeps the code of Apple's Intel graphics drivers only inside its kernel collection - the
# driver folders in /System/Library/Extensions hold an Info.plist and no program, and a folder like that links to
# nothing. For those drivers the code is taken from Apple's Kernel Debug Kit for this Mac's own Tahoe build, which
# holds the same drivers (same version) as files: an installed kit (/Library/Developer/KDKs), one given with --kdk, or
# the kit's disk image, downloaded once (about 1.2 GB) and accepted only when its package is signed by Apple.
#
# No mode word is a dry run. Code 0 done or clean dry run, 1 refused or failed, 2 unknown option.
# A file it adds is listed in added.list under <data>/Library/NullMoth/golden-gate/apple; a file it replaces is kept
# first under .../apple/orig/<path>. --uninstall removes the added files and puts the kept ones back.
set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
HERE=$(cd "$(dirname "$0")" && pwd)
PAYLOAD=$HERE; SYS=""; DATA=""; MODE="--dry-run"; KDK=""
KDK_URL_BASE="https://github.com/dortania/KdkSupportPkg/releases/download"   # <build>/Kernel_Debug_Kit_<version>_build_<build>.dmg
KDK_NEED_GB=9                          # chosen: the image (1.2 GB) plus its opened package (5.5 GB) plus room to work
TBUILD=""; TVER=""                     # this Tahoe's build and version (read below when a kit is needed)
KDK_INSTALLED=/Library/Developer/KDKs  # where installed kits live
PKGUTIL=/usr/sbin/pkgutil; HDIUTIL=/usr/bin/hdiutil; CURL=/usr/bin/curl
# test-hook-begin
KMUTIL=/usr/bin/kmutil
TAHOE_EXT=""                           # one folder holding Tahoe's AMD drivers and bundles, in place of the search
MODEL=""                               # the Mac's model, in place of reading it
GFXIDS=""                              # graphics driver bundle IDs, in place of reading what Tahoe has loaded
# test-hook-end
while [ $# -gt 0 ]; do case "$1" in
  --payload) PAYLOAD=${2:-}; shift;; --system) SYS=${2:-}; shift;; --data) DATA=${2:-}; shift;; --esp) shift;;
  --dry-run|--apply|--uninstall) MODE=$1;; --kdk) KDK=${2:-}; shift;;
  # test-hook-begin
  --kmutil) KMUTIL=${2:-}; shift;; --tahoe-ext) TAHOE_EXT=${2:-}; shift;; --model) MODEL=${2:-}; shift;; --gfx-ids) GFXIDS=${2:-}; shift;;
  --tahoe-build) TBUILD=${2:-}; shift;; --tahoe-version) TVER=${2:-}; shift;; --kdk-installed) KDK_INSTALLED=${2:-}; shift;;
  --pkgutil) PKGUTIL=${2:-}; shift;; --hdiutil) HDIUTIL=${2:-}; shift;; --curl) CURL=${2:-}; shift;;
  # test-hook-end
  *) echo "STOP unknown option $1"; exit 2;; esac; shift; done
say() { echo "  $*"; }
die() { echo "STOP $*"; exit 1; }

[ -n "$SYS" ] && [ -d "$SYS/System/Library" ] || die "--system must name the mounted macOS 27 system volume"
[ -n "$DATA" ] && [ -d "$DATA" ] || die "--data must name the mounted macOS 27 data volume"
STATE="$DATA/Library/NullMoth/golden-gate/apple"; ADDED="$STATE/added.list"; KEPT="$STATE/orig"
AUX="$DATA/Library/KernelCollections/AuxiliaryKernelExtensions.kc"
BOOTKC="$SYS/System/Library/KernelCollections/BootKernelExtensions.kc"
SYSKC="$SYS/System/Library/KernelCollections/SystemKernelExtensions.kc"
KERNEL="$SYS/System/Library/Kernels/kernel"
P="$PAYLOAD/payload"; MAN="$PAYLOAD/MANIFEST"
IL=System/Library/Extensions/AMDShared.bundle/Contents/PlugIns/libAMDIL902.dylib
IL_SIZE=18187216
HOOK=/usr/local/lib/nullmoth/amdil_rtfix.dylib

rel() { case "$1" in "$SYS"/*) echo "S:${1#"$SYS"}";; *) echo "D:${1#"$DATA"}";; esac; }
abs() { case "$1" in S:*) echo "$SYS${1#S:}";; D:*) echo "$DATA${1#D:}";; esac; }

if [ "$MODE" = --uninstall ]; then
  echo "STEP removing the Mac Pro package"
  [ -f "$ADDED" ] || { say "nothing was installed by this package"; exit 0; }
  # The system volume is mounted read-only after a restart, exactly as for an install: make it writable first. Without
  # this every removal and every put-back on it failed, and the backup was then deleted anyway.
  if mount | grep -F " on $SYS (" | grep -q 'read-only'; then
    /sbin/mount -uw "$SYS" 2>/dev/null
    mount | grep -F " on $SYS (" | grep -q 'read-only' && die "the macOS 27 system volume is read-only and could not be made writable. Nothing was changed"
  fi
  while IFS= read -r r; do [ -n "$r" ] && rm -rf "$(abs "$r")"; done < "$ADDED"
  bad=0
  if [ -d "$KEPT" ]; then
    while IFS= read -r f; do f=${f#./}; t=$(abs "${f%%/*}:/${f#*/}")
      { mkdir -p "${t%/*}" && cp -pR "$KEPT/$f" "$t"; } || { say "could not put back $t"; bad=1; }
    done < <(cd "$KEPT" && find . -type f -o -type l)
  fi
  # The kept originals are the only copy: they are deleted only when every one of them went back.
  [ "$bad" = 0 ] || die "some files could not be put back; the originals are still kept in $KEPT"
  rm -rf "$STATE"; say "removed; restart to finish"; exit 0
fi

echo "STEP checking this Mac and the package"
# Golden Gate says whether the startup files are a real Mac's own (GG_EFIKIND=mac); a PC on AMD graphics is not served
# by this package. --model stands in for a test.
GIVEN=$MODEL; [ -n "$MODEL" ] || MODEL=$(sysctl -n hw.model 2>/dev/null)
# A PC (GG_EFIKIND=pc) whose Tahoe runs its built-in graphics on Apple's driver gets that driver alone: the kit's own
# PC path already covers the rest of a PC, so nothing else of its Tahoe is carried, and the Mac-only helpers stay off.
PC=0
if [ "${GG_EFIKIND:-}" = pc ]; then PC=1; say "a PC: only the graphics drivers its Tahoe runs on are carried"
elif [ "${GG_EFIKIND:-}" != mac ] && [ -z "$GIVEN" ]; then
  die "this package is for real Macs and PCs on Apple's graphics driver, and Golden Gate did not say which this is. Nothing was changed"; fi
[ $PC = 1 ] || case "$MODEL" in *Mac*|Mac-*) say "a real Mac: $MODEL";; *) die "this package is for real Macs; this machine reads as '$MODEL'. Nothing was changed";; esac
# Model class: what sits behind the keyboard, trackpad and audio (see MODELS.md), reported so a log shows it.
# The model comes from the firmware's own board data first: a boot loader may show another model name to macOS.
T2=0; SPI=0; REAL=$MODEL
if [ -z "$GIVEN" ]; then
  b=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | sed -n 's/.*"target-type" = <"\([^"]*\)">.*/\1/p;s/.*"board-id" = <"\([^"]*\)">.*/\1/p' | head -1)
  [ -n "$b" ] && say "board data: $b"
fi
case "$MODEL" in
  MacBookAir8,*|MacBookAir9,*|MacBookPro15,*|MacBookPro16,*|Macmini8,*|iMac20,*|iMacPro1,1|MacPro7,1) T2=1;;
  MacBook8,1|MacBook9,1|MacBook10,1|MacBookPro12,1|MacBookPro13,*|MacBookPro14,*) SPI=1;;
esac
if [ "$GIVEN" = "" ] && [ "$T2" = 0 ]; then   # a spoofed model name must not hide a T2: look for its bridge on the PCI bus
  ioreg -rxc IOPCIDevice 2>/dev/null | grep -qiE '"vendor-id" = <6b100000>' &&
    ioreg -rxc IOPCIDevice 2>/dev/null | grep -qiE '"device-id" = <(01|02|03)180000>' && T2=1
fi
# T1 and T2 Macs are not refused: their own Tahoe already runs the drivers for what sits behind the T1/T2 chip or the SPI
# bus (Apple's own on a Tahoe-supported Mac, the patcher's on an older one), and those are carried over below like every
# other driver. Said here so a report shows which class the Mac is in.
[ "$T2" = 1 ] && say "$REAL has an Apple T2 chip: its storage, keyboard, trackpad and speaker drivers come from its own Tahoe"
[ "$SPI" = 1 ] && say "$REAL has its keyboard and trackpad on an SPI bus: those drivers come from its own Tahoe"
[ -f "$MAN" ] || die "the package has no MANIFEST. Nothing was changed"
while read -r kind mode sum path; do
  case "$kind" in F) [ "$(md5 -q "$P$path" 2>/dev/null)" = "$sum" ] || die "$path does not match the package's MANIFEST. Nothing was changed";; esac
done < <(grep -v '^#' "$MAN")
say "package files match MANIFEST"
# The whole Mac, the way the PC side maps a PC: every driver this Mac's Tahoe has loaded that macOS 27's own
# collections do not carry (graphics, Wi-Fi, Bluetooth, audio, USB, Thunderbolt, sensors) is carried over and linked
# for macOS 27. Apple's copies are in /System/Library/Extensions; a root patch may have put some in /Library/Extensions.
# A kext OpenCore injected has no folder on disk and is left out (OpenCore injects it into macOS 27 as well).
DIRS=${TAHOE_EXT:-/System/Library/Extensions /Library/Extensions}
for f in "$KERNEL" "$BOOTKC" "$SYSKC"; do [ -f "$f" ] || die "the macOS 27 volume has no ${f##*/}: lay down macOS 27 and its kernel collections first"; done
if [ -z "$GFXIDS" ]; then
  in27=$("$KMUTIL" inspect -B "$BOOTKC" -S "$SYSKC" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^com\./) print $i}' | sort -u)
  GFXIDS=$(kmutil showloaded --list-only 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /^com\./) print $i}' | sort -u |
    grep -vxF -f <(printf '%s\n' "$in27" com.nullmoth.NMXAudio) | grep -v '^com\.apple\.kpi\.' | tr '\n' ' ')
fi
# macOS 27 on Intel starts through the kit's own platform layer, which OpenCore injects: A2XACPIPlatform (the platform
# expert), NetArm2x86IOAPIC (the interrupt controller), AppleRTC, efiruntime, efinvram and smbios. Tahoe's Apple drivers
# for those same roles are never carried: linked beside the kit's, two drivers claim the platform expert, the interrupt
# controller and the timers, and macOS 27 froze at start with no panic and no network (Mac Pro 6,1). NullMoth's own
# drivers come from the kit, never from Tahoe: a test graphics driver loaded on Tahoe would claim the card.
PLATFORM_OWNED="com.apple.driver.AppleACPIPlatform com.apple.driver.AppleAPIC com.apple.driver.AppleHPET
 com.apple.driver.AppleRTC com.apple.driver.AppleEFIRuntime com.apple.driver.AppleSMBIOS com.apple.driver.AppleACPIEC
 com.apple.driver.AppleACPIButtons com.apple.driver.AppleLPC com.apple.driver.ApplePlatformEnabler
 com.apple.driver.AppleIntelMCEReporter com.apple.Dont_Steal_Mac_OS_X com.apple.driver.pmtelemetry"
kept=""; left=""
for id in $GFXIDS; do
  case " $(echo $PLATFORM_OWNED) " in *" $id "*) left="$left $id"; continue;; esac
  case "$id" in com.nullmoth.*) left="$left $id"; continue;; esac
  kept="$kept $id"
done
GFXIDS=${kept# }
[ -n "$left" ] && say "left to the kit's own start-up drivers:$left"
kext_of() {   # the folder of the kext with bundle ID $1, in DIRS (top level and one plug-in level)
  local d k; for d in $DIRS; do for k in "$d"/*.kext "$d"/*.kext/Contents/PlugIns/*.kext; do [ -d "$k" ] || continue
    [ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$k/Contents/Info.plist" 2>/dev/null)" = "$1" ] && { echo "$k"; return 0; }
  done; done; return 1; }
# KEXTPATHS is one path per LINE: Apple's own kexts have spaces in their names ("Dont Steal Mac OS X.kext"), and a
# space-joined list split them ("could not copy Dont", Beta 4/5, real Macs).
NL='
'
VENDORS=""; KEXTPATHS=""; CARRY=""
is_gfx() { case "$1" in *Graphics*|*Framebuffer*|*AMD*|*ATI*|*Radeon*|*Accelerat*|*GPU*|*Display*|*MCCS*|*nvidia*|*NVDA*|*GeForce*) return 0;; esac; return 1; }
for id in $GFXIDS; do [ $PC = 1 ] && ! is_gfx "$id" && continue
  k=$(kext_of "$id") || continue; KEXTPATHS="$KEXTPATHS$k$NL"; CARRY="$CARRY $id"
  case "$id" in *AMD*) VENDORS="$VENDORS AMD";; *AppleIntel*Graphics*|*AppleIntel*Framebuffer*) VENDORS="$VENDORS AppleIntel";; *nvidia*|*NVDA*|*GeForce*) VENDORS="$VENDORS GeForce NVDA";; esac; done
[ -n "$CARRY" ] || die "found no driver of this machine's Tahoe to carry over. Nothing was changed"
# Drivers whose folder names a program and holds none: their code is only in Tahoe's kernel collection.
pb() { /usr/libexec/PlistBuddy -c "Print :$2" "$1/Contents/Info.plist" 2>/dev/null; }
needs_code() { local e; e=$(pb "$1" CFBundleExecutable) || return 1; [ -n "$e" ] && [ ! -f "$1/Contents/MacOS/$e" ]; }
NOCODE=""; NOCODE_N=0
while IFS= read -r k; do [ -n "$k" ] || continue; needs_code "$k" && { NOCODE="$NOCODE$k$NL"; NOCODE_N=$((NOCODE_N + 1)); }; done <<< "$KEXTPATHS"
KDK_KIND=""; KDK_DMG=""; KDK_URL=""
if [ "$NOCODE_N" -gt 0 ]; then
  [ -n "$TBUILD" ] || TBUILD=$(sw_vers -buildVersion 2>/dev/null)
  [ -n "$TVER" ] || TVER=$(sw_vers -productVersion 2>/dev/null)
  [ -n "$TBUILD" ] && [ -n "$TVER" ] || die "could not read this Tahoe's version and build, needed to find its Kernel Debug Kit. Nothing was changed"
  say "$NOCODE_N of these drivers keep their code only in Tahoe's kernel collection: $(while IFS= read -r k; do [ -n "$k" ] && printf '%s ' "${k##*/}"; done <<< "$NOCODE")"
  KDK_DMG="$STATE/kdk/Kernel_Debug_Kit_${TVER}_build_${TBUILD}.dmg"
  KDK_URL="$KDK_URL_BASE/$TBUILD/Kernel_Debug_Kit_${TVER}_build_${TBUILD}.dmg"
  if [ -n "$KDK" ]; then
    if [ -d "$KDK/System/Library/Extensions" ]; then KDK_KIND=folder
    elif [ -f "$KDK" ]; then KDK_KIND=image; KDK_DMG=$KDK
    else die "--kdk: $KDK is neither a Kernel Debug Kit folder nor its disk image. Nothing was changed"; fi
  else
    for d in "$KDK_INSTALLED"/KDK_*_"$TBUILD".kdk; do [ -d "$d/System/Library/Extensions" ] && { KDK=$d; KDK_KIND=folder; break; }; done
    if [ -z "$KDK_KIND" ]; then if [ -s "$KDK_DMG" ]; then KDK_KIND=image; else KDK_KIND=download; fi; fi
  fi
  case "$KDK_KIND" in
    folder) say "their code comes from the Kernel Debug Kit at $KDK";;
    image) say "their code comes from the Kernel Debug Kit image $KDK_DMG (its package must be signed by Apple)";;
    download) say "their code comes from Apple's Kernel Debug Kit for macOS $TVER ($TBUILD): about 1.2 GB will be downloaded from $KDK_URL";;
  esac
fi
BUNDLES=""; for d in $DIRS; do for v in $(echo $VENDORS | tr ' ' '\n' | sort -u); do for b in "$d"/$v*.bundle; do [ -d "$b" ] && BUNDLES="$BUNDLES $b"; done; done; done
say "this Mac's Tahoe: $(echo $CARRY | wc -w | tr -d ' ') drivers that macOS 27 lacks, $(echo $BUNDLES | wc -w | tr -d ' ') graphics bundles"
# Graphics bundles that name a program and hold none (their code is in Tahoe's shared library cache) are named, so a
# report shows them: they are copied as they are.
for b in $BUNDLES; do needs_code "$b" && say "note: ${b##*/} holds no program of its own on this Tahoe"; done
[ "$MODE" = --apply ] || { echo "dry run finished; nothing was changed. Run again with --apply to install."; exit 0; }

WORK=$(mktemp -d /private/var/tmp/gg-apple.XXXXXX) || die "no private work folder"
trap 'rm -rf "$WORK"' EXIT
echo "STEP linking the auxiliary kernel collection"
mkdir "$WORK/repo"
while IFS= read -r k; do [ -n "$k" ] || continue; cp -RX "$k" "$WORK/repo/" || die "could not copy ${k##*/}"; done <<< "$KEXTPATHS"
cp -RX "$P/Library/Extensions/NMXAudio.kext" "$WORK/repo/" || die "could not copy NMXAudio.kext"
if [ "$NOCODE_N" -gt 0 ]; then
  echo "STEP getting the code of $NOCODE_N drivers from the Kernel Debug Kit"
  KROOT=""; KDEV=""
  if [ "$KDK_KIND" = folder ]; then KROOT=$KDK
  else
    free=$(df -g "$WORK" 2>/dev/null | awk 'NR==2 {print $4}')
    [ -n "$free" ] && [ "$free" -ge "$KDK_NEED_GB" ] || die "${free:-an unknown number of} GB are free where the Kernel Debug Kit would be opened; $KDK_NEED_GB GB are needed. Nothing was changed"
    if [ "$KDK_KIND" = download ]; then
      mkdir -p "${KDK_DMG%/*}" || die "could not make ${KDK_DMG%/*}. Nothing was changed"
      "$CURL" -sS -f -L -C - --proto =https --proto-redir =https -o "$KDK_DMG.part" --connect-timeout 30 --retry 20 --retry-delay 5 \
        --retry-all-errors --speed-limit 1024 --speed-time 120 "$KDK_URL" ||
        die "the Kernel Debug Kit for macOS $TVER ($TBUILD) could not be downloaded from $KDK_URL. Get 'Kernel Debug Kit $TVER build $TBUILD' from Apple's developer downloads, install it, and run this again (a started download is kept and continued). Nothing was changed"
      mv -f "$KDK_DMG.part" "$KDK_DMG" || die "could not keep the downloaded kit. Nothing was changed"
    fi
    out=$("$HDIUTIL" attach -readonly -nobrowse -noautoopen -mountrandom "$WORK" "$KDK_DMG" 2>&1) || die "could not open the Kernel Debug Kit image $KDK_DMG (delete it to download it again). Nothing was changed"
    KDEV=$(printf '%s\n' "$out" | awk '$1 ~ /^\/dev\/disk[0-9]+$/ {print $1; exit}')
    kmp=$(printf '%s\n' "$out" | awk -F'\t' '$NF ~ /^\// {print $NF; exit}')
    trap '[ -n "$KDEV" ] && "$HDIUTIL" detach "$KDEV" -quiet 2>/dev/null; rm -rf "$WORK"' EXIT
    [ -f "$kmp/KernelDebugKit.pkg" ] || die "the image holds no KernelDebugKit.pkg. Nothing was changed"
    # The image came from outside: only a package Apple signed is opened.
    # pkgutil must succeed, and its own status line (the first one, whole) must say Apple signed it: a name inside
    # a certificate cannot stand in for that line.
    sig=$("$PKGUTIL" --check-signature "$kmp/KernelDebugKit.pkg" 2>/dev/null) &&
      [ "$(printf '%s\n' "$sig" | awk '/^ *Status:/ {sub(/^ */, ""); sub(/ *$/, ""); print; exit}')" = "Status: signed Apple Software" ] ||
      die "the Kernel Debug Kit package in $KDK_DMG is not signed by Apple; it is not used (delete the image to download it again). Nothing was changed"
    "$PKGUTIL" --expand-full "$kmp/KernelDebugKit.pkg" "$WORK/kdk" >/dev/null 2>&1 || die "could not open the Kernel Debug Kit's package. Nothing was changed"
    "$HDIUTIL" detach "$KDEV" -quiet 2>/dev/null && KDEV=""
    KROOT="$WORK/kdk/KDK.pkg/Payload"
  fi
  [ -d "$KROOT/System/Library/Extensions" ] || die "the Kernel Debug Kit holds no System/Library/Extensions. Nothing was changed"
  while IFS= read -r k; do [ -n "$k" ] || continue
    id=$(pb "$k" CFBundleIdentifier); ver=$(pb "$k" CFBundleVersion); exe=$(pb "$k" CFBundleExecutable); found=""
    for c in "$KROOT/System/Library/Extensions/${k##*/}" "$KROOT"/System/Library/Extensions/*.kext/Contents/PlugIns/"${k##*/}"; do
      [ -d "$c" ] && [ "$(pb "$c" CFBundleIdentifier)" = "$id" ] && { found=$c; break; }; done
    [ -n "$found" ] || die "the Kernel Debug Kit has no ${k##*/} ($id). Nothing was changed"
    [ "$(pb "$found" CFBundleVersion)" = "$ver" ] ||
      die "the Kernel Debug Kit's ${k##*/} is version $(pb "$found" CFBundleVersion) and this Tahoe's is $ver: the kit is for another build. Nothing was changed"
    [ -f "$found/Contents/MacOS/$exe" ] && lipo -archs "$found/Contents/MacOS/$exe" 2>/dev/null | grep -qw x86_64 ||
      die "the Kernel Debug Kit's ${k##*/} holds no Intel program. Nothing was changed"
    rm -rf "$WORK/repo/${k##*/}" && cp -RX "$found" "$WORK/repo/" || die "could not copy ${k##*/} from the Kernel Debug Kit. Nothing was changed"
    say "${k##*/} $ver: code from the Kernel Debug Kit"
  done <<< "$NOCODE"
  rm -rf "$WORK/kdk"
fi
chown -R root:wheel "$WORK/repo"; chmod -R go-w "$WORK/repo"
IDS="com.nullmoth.NMXAudio $CARRY"
# A Tahoe driver that needs something macOS 27 does not have cannot link. kmutil names it ("Could not use 'id'"); it is
# left out, said so, and the rest are linked again. The audio driver and at least one other must remain.
for try in 1 2 3 4 5 6 7 8 9 10 11 12; do
  args=""; for id in $IDS; do args="$args -b $id"; done
  rm -f "$WORK/aux.kc"
  # shellcheck disable=SC2086
  "$KMUTIL" create -n aux -a x86_64 --allow-missing-kdk --build 26B123 -z --no-authentication --kernel "$KERNEL" \
    -B "$BOOTKC" -S "$SYSKC" --repository "$WORK/repo" -x $args -A "$WORK/aux.kc" > "$WORK/kmutil.log" 2>&1 && [ -f "$WORK/aux.kc" ] && break
  bad=$(grep -oE "Could not use '[^']+'|Unable to resolve dependencies: '[^']+'" "$WORK/kmutil.log" | sed -E "s/.*'([^']+)'/\1/" | sort -u)
  [ -n "$bad" ] || { grep -v '^$' "$WORK/kmutil.log" | tail -12; die "the drivers did not link against the macOS 27.2 collections. Nothing was changed"; }
  for b in $bad; do [ "$b" = com.nullmoth.NMXAudio ] && die "the audio driver did not link. Nothing was changed"; say "left out (does not link on macOS 27): $b"; done
  # kmutil may name a driver that is not on the list: one a listed driver needs, or one kept inside a listed
  # driver's bundle. The listed drivers that need it or hold it are the ones to leave out.
  drop=""
  for b in $bad; do
    case " $IDS " in *" $b "*) drop="$drop $b"; continue;; esac
    while IFS= read -r pl; do [ -n "$pl" ] || continue
      top=${pl#"$WORK/repo/"}; top="$WORK/repo/${top%%/*}"
      for cand in "${pl%/Contents/Info.plist}" "$top"; do
        cid=$(pb "$cand" CFBundleIdentifier)
        case " $IDS " in *" $cid "*) case " $drop " in *" $cid "*) ;; *) drop="$drop $cid"; say "left out (needs $b): $cid";; esac;; esac
      done
    done <<< "$(grep -rlF --include=Info.plist "<key>$b</key>" "$WORK/repo" 2>/dev/null; grep -rlF --include=Info.plist "<string>$b</string>" "$WORK/repo" 2>/dev/null)"
  done
  [ -n "$drop" ] || { grep -v '^$' "$WORK/kmutil.log" | tail -12; die "the drivers did not link against the macOS 27.2 collections. Nothing was changed"; }
  for b in $drop; do [ "$b" = com.nullmoth.NMXAudio ] && die "the audio driver did not link. Nothing was changed"; done
  IDS=$(printf '%s\n' $IDS | grep -vxF -f <(printf '%s\n' $drop) | tr '\n' ' ')
done
[ -f "$WORK/aux.kc" ] || die "kmutil wrote no collection. Nothing was changed"
inside=$("$KMUTIL" inspect -A "$WORK/aux.kc" -B "$BOOTKC" -S "$SYSKC" 2>/dev/null)
[ -n "$inside" ] || die "the new collection could not be read back. Nothing was changed"
# The linker can leave a listed driver out without an error. The audio driver must be there; any other is said and
# left out, and the graphics check below decides whether what remains can show a picture.
kept=""
for id in $IDS; do
  if printf '%s\n' "$inside" | grep -qF "$id"; then kept="$kept $id"
  elif [ "$id" = com.nullmoth.NMXAudio ]; then die "linked, but $id is not in the collection. Nothing was changed"
  else say "left out (the linker did not place it): $id"; fi
done
IDS=${kept# }
# A Mac whose graphics driver was left out above would start macOS 27 with no display. Refuse rather than place it.
printf '%s\n' $IDS | grep -qE 'Framebuffer|Graphics|AMDFramebuffer|AMD7000Controller|AMDRadeonX|NVDA|GeForce' ||
  die "none of this Mac's graphics drivers links against macOS 27.2 (left out above), so it would start with no display. Nothing was changed"
say "linked: $(stat -f %z "$WORK/aux.kc") bytes, $(echo $IDS | wc -w | tr -d ' ') extensions"

HOOKIT=0; src=""
for d in $DIRS; do [ -f "$d/$IL" ] && src="$d/$IL" && break; [ -f "$d/AMDShared.bundle/Contents/PlugIns/libAMDIL902.dylib" ] && src="$d/AMDShared.bundle/Contents/PlugIns/libAMDIL902.dylib" && break; done
if [ -n "$src" ] && [ "$(stat -f %z "$src")" = "$IL_SIZE" ]; then
  echo "STEP preparing the shader compiler"
  python3 "$PAYLOAD/addlc.py" "$src" "$WORK/libAMDIL902.dylib" "$HOOK" >/dev/null || die "could not add the shader hook. Nothing was changed"
  codesign -f -s - "$WORK/libAMDIL902.dylib" >/dev/null 2>&1 || die "could not sign the patched shader compiler. Nothing was changed"
  HOOKIT=1
elif [ -n "$src" ]; then say "this Tahoe's AMD shader compiler is another build; it is copied unchanged"; fi

echo "STEP placing"
if mount | grep -F " on $SYS (" | grep -q 'read-only'; then
  /sbin/mount -uw "$SYS" 2>/dev/null
  mount | grep -F " on $SYS (" | grep -q 'read-only' && die "the macOS 27 system volume is read-only and could not be made writable"
fi
mkdir -p "$STATE" "$KEPT" || die "could not make $STATE"; touch "$ADDED"
keep() { local r k; [ -e "$1" ] || [ -L "$1" ] || return 0; r=$(rel "$1"); k="$KEPT/${r%%:*}${r#*:}"
  [ -e "$k" ] && return 0; grep -qxF "$r" "$ADDED" && return 0; mkdir -p "${k%/*}" && mv "$1" "$k" || die "could not keep $1"; }
put() {   # $1 = source (file or folder), $2 = destination, $3 = mode for a file
  keep "$2"; mkdir -p "${2%/*}" || die "could not make ${2%/*}"; rm -rf "$2.gg-new"
  if [ -d "$1" ]; then cp -RX "$1" "$2.gg-new" && chown -R root:wheel "$2.gg-new"; chmod -R go-w "$2.gg-new"
  else cp -X "$1" "$2.gg-new" && chown root:wheel "$2.gg-new"; chmod "$3" "$2.gg-new"; fi
  rm -rf "$2" && mv -f "$2.gg-new" "$2" || die "could not place $2"
  grep -qxF "$(rel "$2")" "$ADDED" || rel "$2" >> "$ADDED"; }
for b in $BUNDLES; do put "$b" "$SYS/System/Library/Extensions/${b##*/}" 755; done
if [ "$HOOKIT" = 1 ]; then put "$WORK/libAMDIL902.dylib" "$SYS/$IL" 755; put "$P$HOOK" "$DATA$HOOK" 755; fi
put "$P/Library/Extensions/NMXAudio.kext" "$DATA/Library/Extensions/NMXAudio.kext" 755
# the speaker choice and the wired-port address request are a Mac's: a PC keeps its own outputs and network setup
for f in usr/local/libexec/nullmoth/audsel usr/local/libexec/nullmoth/netup.sh; do
  [ $PC = 1 ] && continue; put "$P/$f" "$DATA/$f" 755; done
for f in "$P"/Library/LaunchDaemons/*.plist "$P"/Library/LaunchAgents/*.plist; do
  [ $PC = 1 ] && case "${f##*/}" in com.nullmoth.audsel.plist|com.nullmoth.netup.plist) continue;; esac
  put "$f" "$DATA${f#"$P"}" 644; done
put "$WORK/aux.kc" "$AUX" 644
say "installed; restart into macOS 27 to finish"
