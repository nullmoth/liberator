#!/bin/bash
# Prepare for Golden Gate: move a Mac that 1401 set up for macOS 26 to macOS 27.2, keeping the way back.
#
# Offered only with a NullMoth v3 kit (a local folder with v3-kit.json and the macOS 27 kexts). Without one every
# step stops before reading or changing anything, and no public build of 1401 carries a kit.
#
# The steps are the ones p1401/golden_gate.py defines, with the same folders and the same state file, so a
# partition staged by either can be finished, rolled back or cancelled by the other:
#   preflight  changes nothing: macOS 26, a card the macOS 27 driver takes, startup files made by 1401, room on the
#              startup partition and on the disk
#   stage      EFI/OC is copied to EFI/OC-27-staged and the kit turns the copy into the macOS 27 startup files;
#              the firmware still starts EFI/OC. The kit's two packages are checked and recorded, not copied:
#              finish runs them from the kit, and a driver package does not fit a startup partition
#   activate   with --confirm only: EFI/OC is kept as EFI/OC-26 and the staged folder becomes EFI/OC
#   rollback   the reverse of activate
#   cancel     rollback if needed, then everything stage made is removed
#   installer  lays macOS 27 down on its own volumes beside macOS 26 with the kit's lay-down script: its dry run,
#              then the real run (it downloads Apple's restore image from Apple, about 26 GB). The new system
#              starts at Apple's Setup Assistant unless --bring-account names an account to carry over
#   collections makes the Intel kernel collections for macOS 27 with the kit's maker (its dry run, then the real
#              run); refuses while the kit has none. It comes before installer, which hands them to the lay-down
#   finish     from macOS 26, after macOS 27 is laid down and before its first start: runs the kit's system
#              installer and then its v3 driver installer against the macOS 27 volumes, both dry runs first
#   local      on macOS 27 itself, for a newer kit or a repair: the kit's system installer and then its driver
#              installer against the macOS that is running. Dry runs only, unless --confirm is given
#   status     prints the state
#
# The kit is trusted only by where it is and who owns it, never by what it says about itself: this script runs as
# root, copies the kit's kexts into the startup files and runs the kit's installers. So the kit folder, every
# file in it and every folder above it must belong to root and be writable by root alone. The kit is then copied to
# a private folder, checked again there, and only that copy is read, copied from or run. What the manifest may put
# in the config is limited to the keys and boot arguments listed below; anything else is refused by name.
#
# usage: nullmoth-golden-gate.sh <step> --root <mounted startup partition> --kit <v3 kit> [--confirm] [--kit-model]
# --kit-model (stage): keep the model the kit sets instead of the model for this card's generation; the second attempt
# when macOS 27 does not start with that model.
# test-hook-begin
# In this source only, and removed from the copy the app carries (build.sh, tools/strip_test_hooks.py): options
# that replace what the script would measure on this Mac, so the tests can stand in for another PC.
#        [--macos-major N] [--gpu-id XXXX]... [--disk-free-gb N] [--device-id VVVV-PPPP]...
#        [--volumes DIR] [--cpu-vendor NAME] [--laptop yes|no]
# --diskutil: a stand-in for diskutil. --tools: a folder of stand-ins for the system tools the check probes.
# --kc-work: where the kernel collections go. --step-log: the step log (its folder also holds the records).
# test-hook-end
#
# What finish runs, from the private copy of the kit. The manifest names two packages, each a plain folder in the
# kit and a plain file in that folder:
#   "system": {"dir": ..., "installer": ...}   the interpreter and routes for Apple's arm64-only programs
#   "driver": {"dir": ..., "installer": ...}   the v3 NVIDIA driver
# Every run gets --payload <package folder> --system <volume> --data <volume> --esp <startup partition>. The dry
# runs add --dry-run and the real runs add --apply: an installer changes nothing unless it is told to. Order: system
# dry run, driver dry run, system, driver. A dry run must not need the other package installed. Finish refuses when
# either package is missing.
# The local step runs the same four in the same order with --payload alone: an installer given no --system and
# --data works on the macOS it is started from, and macOS 27 cannot open the startup partition.
set -u
umask 022
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PB=/usr/libexec/PlistBuddy
HERE=$(cd "$(dirname "$0")" && pwd)
STAGED=OC-27-staged; KEPT=OC-26; RENEWED=OC-27-old; CHOICES=golden-gate-drivers.txt; DRVLOG=golden-gate-drivers.log; DRIVER=NullMoth-v3; STATE=golden-gate.json; MANIFEST=v3-kit.json
FROM_MAJOR=26; TARGET=27.2
# One number for the room macOS 27 needs on the disk this macOS runs from, from the kit scripts' own figures: 35 GB
# for the new volumes, and 49 GB of work files while it runs (26 GB downloaded from Apple, 23 GB unpacked), which are
# removed afterwards. The lay-down script checks the container and its work folder again, exactly, before it starts.
# The kernel collections step needs 8 GB of work space of its own before that.
MIN_DISK_GB=92
# Where the kernel collections are made, and where the install step looks for them.
KCWORK="/Library/Application Support/1401/golden-gate/kernel-collections"
# Where the kit's lay-down keeps what it downloads (Apple's restore image, the Kernel Debug Kit) between runs.
LAYWORK="/Library/Application Support/1401/golden-gate/laydown"
DOWNLOAD_GB=27        # the most the downloads can take off the room that is still needed
PREBOOT=/System/Volumes/Preboot   # where the running macOS has its Preboot volume mounted
SIZE_GB=""            # the size the user chose for macOS 27 (--size-gb); empty = no limit
SYSTEM_GB=20          # chosen by us: the macOS 27.2 system volume measured 19 GB used on the first lay-downs
SIZE_MIN_GB=40        # chosen by us: the system plus 20 GB for an account, apps and updates
ESP_MARGIN_KB=8192    # kept free on the startup partition after the staged copy
NV=7C436110-AB2A-4BBB-A880-FE41995C9F82
# All a kit's manifest may set in config.plist, and all it may add to boot-args (p1401/v3_macos27.py has the same lists).
SET_ALLOWED="Misc/Security/SecureBootModel PlatformInfo/Generic/SystemProductName"
BOOT_ARGS_ALLOWED="-v -lilubetaall -vsmcbeta -no_compat_check a2x_conlive=1 a2xbusydump=2 pci_log=0x201 pci_log_mode=0x2 gfxrst=4 nvrmholdcap=180"
# The model each NVIDIA generation presents as on macOS 27 (p1401/v3_macos27.py IDENTITY); generations without a
# model keep what the kit sets.
MODEL_RTX50=Mac17,15

STEP=${1:-}; [ $# -gt 0 ] && shift
ROOT=""; KIT=""; CONFIRM=0; DRVOFF=""; DRVON=""; MAJOR=""; GPUS=""; GPUS_GIVEN=0; DISK_GB=""; DEVIDS=""; DEVIDS_GIVEN=0; ESPFREE=""
DISPLAYS=""; DISPLAYS_GIVEN=0; APPLEIDS=""; APPLEIDS_GIVEN=0
DISKUTIL=/usr/sbin/diskutil; TOOLS=""
KITMODEL=0; CPUV=""; LAPTOP=""; ACCOUNT=""
# Every step's lines also go to one log on this macOS: a step that stopped can be read afterwards, Send logs takes
# it, and the app shows its last line while a long step runs. Kept under 1 MB: past that the older half is dropped.
STEPLOG=/Library/NullMoth/golden-gate/steps.log
while [ $# -gt 0 ]; do case "$1" in
  --root) ROOT=${2:-}; shift;; --kit) KIT=${2:-}; shift;; --confirm) CONFIRM=1;; --kit-model) KITMODEL=1;;
  --bring-account) ACCOUNT=${2:-}; shift;; --size-gb) SIZE_GB=${2:-}; shift;;
  --off) DRVOFF=${2:-}; shift;; --on) DRVON=${2:-}; shift;;
  # test-hook-begin
  --macos-major) MAJOR=${2:-}; shift;; --gpu-id) GPUS="$GPUS ${2:-}"; GPUS_GIVEN=1; shift;;
  --disk-free-gb) DISK_GB=${2:-}; shift;; --esp-free-kb) ESPFREE=${2:-}; shift;; --device-id) DEVIDS="$DEVIDS ${2:-}"; DEVIDS_GIVEN=1; shift;;
  --diskutil) DISKUTIL=${2:-}; shift;; --tools) TOOLS=${2:-}; shift;; --kc-work) KCWORK=${2:-}; shift;; --lay-work) LAYWORK=${2:-}; shift;; --preboot) PREBOOT=${2:-}; shift;; --step-log) STEPLOG=${2:-}; shift;;
  --cpu-vendor) CPUV=${2:-}; shift;; --laptop) LAPTOP=${2:-}; shift;;
  --display) DISPLAYS="$DISPLAYS ${2:-}"; DISPLAYS_GIVEN=1; shift;; --apple-id) APPLEIDS="$APPLEIDS ${2:-}"; APPLEIDS_GIVEN=1; shift;;
  # test-hook-end
  *) echo "STOP unknown option $1"; echo "RESULT stop"; exit 2;; esac; shift; done
step() { echo "STEP $*"; }; ok() { echo "OK $*"; }; note() { echo "NOTE $*"; }
step_log() {     # from here on everything this step prints is also appended to the step log; without the right to write it, nothing changes
  # Root writes the folder and the log; everyone may read them: the app, running as the user, follows the log to
  # show its progress bar. The setup that starts this runs with a umask that would leave both owner-only.
  mkdir -p "$(dirname "$STEPLOG")" 2>/dev/null && touch "$STEPLOG" 2>/dev/null || return 0
  chmod 755 "$(dirname "$STEPLOG")" 2>/dev/null; chmod 644 "$STEPLOG" 2>/dev/null
  if [ "$(stat -f %z "$STEPLOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then tail -c 524288 "$STEPLOG" > "$STEPLOG.tmp" 2>/dev/null && mv -f "$STEPLOG.tmp" "$STEPLOG"; fi
  echo "== $(date '+%F %T') $STEP" >> "$STEPLOG" 2>/dev/null || return 0
  exec > >(tee -a "$STEPLOG") 2>&1
}
case "$STEP" in status|downloads|'') ;; *) step_log;; esac
PRIV=""
trap '[ -z "$PRIV" ] || rm -rf "$PRIV"; case "$STEP" in installer|collections|downloads|clear-downloads|remove) type dl_record >/dev/null 2>&1 && dl_record;; esac' EXIT
stop() { echo "STOP $*"; echo "RESULT stop"; exit 1; }
# The only owner a trusted file may have: root.
# test-hook-begin
# In this source only: when the script is itself not running as root it has no rights to lend, and the user running
# it is accepted too. That is how the tests run it. The copy the app carries accepts root alone.
ME=$(id -u)
# test-hook-end
# ship: ME=0
owner_ok() { [ "$1" = 0 ] || [ "$1" = "$ME" ]; }
tree_trusted() {   # every file and folder under $1 belongs to a trusted owner and is writable by its owner only
  [ -d "$1" ] && [ ! -L "$1" ] || return 1
  links_inside "$1" || return 1
  [ -z "$(find "$1" ! -user 0 ! -user "$ME" -print 2>/dev/null | head -n 1)" ] || return 1
  [ -z "$(find "$1" ! -type l \( -perm -020 -o -perm -002 \) -print 2>/dev/null | head -n 1)" ] || return 1
}
# A symbolic link is trusted by where it sits; what it names is checked only when that is inside the tree too. So a
# link in a kit may only name, by a relative path, something inside the kit (a bundle's Versions/Current, a library's
# short name). A link with a full path, one that climbs out of the kit, or one that names nothing would let a file
# outside the kit be copied, read or run as root, and is refused. A package's installer is never a link at all.
links_inside() {
  local root l t d b
  root=$(cd "$1" 2>/dev/null && pwd -P) || return 1
  while IFS= read -r l; do [ -n "$l" ] || continue
    t=$(readlink "$l") || return 1
    case "$t" in ''|/*) return 1;; esac
    b=$(basename "$t"); case "$b" in .|..) return 1;; esac
    d=$(cd "$(dirname "$l")" 2>/dev/null && cd "$(dirname "$t")" 2>/dev/null && pwd -P) || return 1
    case "$d/" in "$root"/*) ;; *) return 1;; esac
    [ -e "$d/$b" ] || return 1
  done < <(find "$1" -type l -print 2>/dev/null)
  return 0
}
chain_trusted() {  # $1 and every folder above it, up to /
  local d; d=$(cd "$1" 2>/dev/null && pwd -P) || return 1
  while :; do
    owner_ok "$(stat -f %u "$d" 2>/dev/null)" || return 1
    case "$(stat -f %Lp "$d" 2>/dev/null)" in ''|*[2367]|*[2367]?) return 1;; esac
    [ "$d" = / ] && break; d=$(dirname "$d"); done
}
upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

NOT_OFFERED="macOS 27 is not offered by this build of 1401. It needs the NullMoth v3 kit, which is not public."
kv() { plutil -extract "$1" raw -o - "$KIT/$MANIFEST" 2>/dev/null; }      # one value of the kit's manifest
khas() { plutil -extract "$1" raw -o - "$KIT/$MANIFEST" >/dev/null 2>&1; }
kit_ok() {
  [ -n "$KIT" ] && [ -f "$KIT/$MANIFEST" ] && [ "$(kv darwin)" = 27 ] || return 1
  local n i name
  n=$(kv kexts) || return 1
  case "$n" in ''|*[!0-9]*|0) return 1;; esac
  i=0; while [ "$i" -lt "$n" ]; do
    name=$(kv kexts.$i.name)
    printf '%s' "$name" | grep -Eq '^[A-Za-z0-9_.+-]{1,96}\.kext$' || return 1
    [ -f "$KIT/Kexts/$name/Contents/Info.plist" ] || return 1
    i=$((i + 1)); done
  # -v is required: without it macOS 27.2 stops at the graphical progress screen on these PCs
  n=$(kv boot_args) || return 1; i=0; local seen=0
  case "$n" in ''|*[!0-9]*) return 1;; esac
  while [ "$i" -lt "$n" ]; do [ "$(kv boot_args.$i)" = "-v" ] && seen=1; i=$((i + 1)); done
  [ $seen = 1 ]
}

case "$STEP" in preflight|stage|activate|rollback|cancel|installer|collections|finish|local|status|laid|kit-current|refresh|drivers|downloads|clear-downloads|remove) ;;
  *) echo "STOP the step must be preflight, stage, activate, rollback, cancel, installer, collections, finish, local, status, laid, kit-current, refresh, drivers, downloads, clear-downloads or remove"; echo "RESULT stop"; exit 2;; esac
# The way back (rollback, cancel) and status need no kit: they must work on a Mac whose kit is gone.
kit_allowed() {  # stops, naming it, on a config key or boot argument the manifest may not set
  local key a n i
  if khas set; then
    while IFS= read -r key; do [ -n "$key" ] || continue
      case " $SET_ALLOWED " in *" $key "*) ;; *) stop "the v3 kit sets a config key 1401 does not let a kit set: $key. Nothing was changed";; esac
    done <<EOF
$(kv set)
EOF
  fi
  n=$(kv boot_args); i=0
  while [ "$i" -lt "$n" ]; do a=$(kv boot_args.$i)
    case " $BOOT_ARGS_ALLOWED " in *" $a "*) ;; *) stop "the v3 kit adds a boot argument 1401 does not let a kit add: $a. Nothing was changed";; esac
    i=$((i + 1)); done
}
use_kit() {      # trust the kit by owner and place, then work only from a private copy of it
  [ -n "$KIT" ] && [ -f "$KIT/$MANIFEST" ] || stop "$NOT_OFFERED Nothing was changed"
  chain_trusted "$KIT" && tree_trusted "$KIT" \
    || stop "the v3 kit at $KIT is not trusted: it, everything in it and every folder above it must belong to root and be writable by root only, and no symbolic link in it may name anything outside it. Nothing was changed"
  PRIV=$(mktemp -d -t 1401-golden-gate) || stop "could not make a private folder for the kit. Nothing was changed"
  cp -R "$KIT" "$PRIV/kit" || stop "could not copy the kit. Nothing was changed"
  KIT="$PRIV/kit"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit did not come out as it must. Nothing was changed"
  kit_ok || stop "$NOT_OFFERED Nothing was changed"
  kit_allowed
}
case "$STEP" in rollback|cancel|status|laid|downloads|clear-downloads|remove) ;; *) use_kit;; esac
[ "$STEP" = installer ] || [ "$STEP" = collections ] || [ "$STEP" = local ] || [ "$STEP" = laid ] || [ "$STEP" = downloads ] || [ "$STEP" = clear-downloads ] || { [ -n "$ROOT" ] && [ -d "$ROOT/EFI" ] || stop "no EFI folder at ${ROOT:-<none>}. Nothing was changed"; }
EFI="$ROOT/EFI"; C="$EFI/OC/config.plist"

read_state() {   # prints none, staged or active; fails on a state file 1401 did not write
  [ -e "$EFI/$STATE" ] || { echo none; return 0; }
  local s; s=$(plutil -extract state raw -o - "$EFI/$STATE" 2>/dev/null) || return 1
  case "$s" in staged|active) echo "$s";; *) return 1;; esac
}
layout_ok() {    # the folders must be the ones the state names
  local oc=0 st=0 kp=0
  [ -d "$EFI/OC" ] && oc=1; [ -d "$EFI/$STAGED" ] && st=1; [ -d "$EFI/$KEPT" ] && kp=1
  case "$1" in none) [ "$oc$st$kp" = 100 ];; staged) [ "$oc$st$kp" = 110 ];; active) [ "$oc$st$kp" = 101 ];; *) return 1;; esac
}
# What names a kit for the startup files: its manifest and every file of its Kexts folder, since those are what the
# startup files are made from. The manifest alone is not enough: a kit can carry a newer build of a kext under the
# same name with the same manifest, and the startup files would then never be made again.
kit_id() {
  { md5 -q "$KIT/$MANIFEST" 2>/dev/null || return 1
    (cd "$KIT/Kexts" 2>/dev/null && find . -type f | LC_ALL=C sort | while IFS= read -r f; do printf '%s %s\n' "$(md5 -q "$f")" "$f"; done)
  } | md5 -q
}
write_state() {  # $1 = state, $2 = driver note, $3 = driver installer, $4 = system package note
  # kit_md5 names the kit the startup files were staged from (its manifest's checksum). The stage step sets it; every
  # later write carries the recorded value on. A record without it was written by a release that did not keep it,
  # and is read as "another kit": that is how a newer release knows the startup files must be made again.
  local tmp="$EFI/$STATE.tmp" km="${STATE_KIT:-}"
  [ -n "$km" ] || km=$(plutil -extract kit_md5 raw -o - "$EFI/$STATE" 2>/dev/null)
  case "$km" in *[!0-9a-f]*) km="";; esac
  printf '{\n "state": "%s",\n "from_major": %s,\n "target": "%s",\n "staged_at": %s,\n "driver": "%s",\n "driver_installer": "%s",\n "system": "%s",\n "kit_md5": "%s"\n}\n' \
    "$1" "$FROM_MAJOR" "$TARGET" "$(date +%s)" "$2" "$3" "${4:-}" "$km" > "$tmp" && mv -f "$tmp" "$EFI/$STATE"
}
heal() {         # a swap stopped between its two renames leaves no EFI/OC: put macOS 26's files back (golden_gate.py _heal)
  # the refresh step's swap, stopped between its two renames: the startup files it had set aside go back
  if [ ! -d "$EFI/OC" ] && [ -d "$EFI/$RENEWED" ] && [ -d "$EFI/$KEPT" ]; then
    mv "$EFI/$RENEWED" "$EFI/OC" || stop "EFI/OC is missing and the macOS 27 startup files could not be put back from EFI/$RENEWED"
    note "a stopped run had left no EFI/OC; the macOS 27 startup files it had set aside are back as the default"
    return 0
  fi
  [ ! -d "$EFI/OC" ] && [ -d "$EFI/$STAGED" ] && [ -d "$EFI/$KEPT" ] || return 0
  mv "$EFI/$KEPT" "$EFI/OC" || stop "EFI/OC is missing and macOS 26's startup files could not be put back from EFI/$KEPT"
  note "a stopped run had left no EFI/OC; macOS 26's startup files are back as the default"
  if [ -e "$EFI/$STATE" ]; then
    write_state staged "$(plutil -extract driver raw -o - "$EFI/$STATE" 2>/dev/null)" "$(plutil -extract driver_installer raw -o - "$EFI/$STATE" 2>/dev/null)" "$(plutil -extract system raw -o - "$EFI/$STATE" 2>/dev/null)" \
      || stop "macOS 26's startup files are back, but the record could not be updated"
  fi
}
state_or_stop() {
  heal
  ST=$(read_state) || stop "the Golden Gate state file on this partition is not one 1401 wrote. Nothing was changed"
  layout_ok "$ST" || stop "the startup partition is not in the state its Golden Gate record says ($ST). Nothing was changed"
}
is_1401_efi() {
  [ -f "$ROOT/.1401-build" ] && return 0
  [ -f "$C" ] || return 1
  plutil -convert xml1 -o - "$C" 2>/dev/null | grep -Eq '<string>1401( \||:)'
}
# A real Mac starts macOS 26 from OpenCore files 1401 did not build (OpenCore Legacy Patcher writes them). What tells
# a real Mac from a PC, in the files themselves: a PC cannot start macOS without a kext that stands in for Apple's
# SMC chip, and a Mac has the chip, so its config loads none. The config must still be a whole OpenCore config.
is_mac_efi() {
  [ -f "$C" ] || return 1
  plutil -extract Kernel.Add raw -o - "$C" >/dev/null 2>&1 || return 1
  plutil -extract PlatformInfo raw -o - "$C" >/dev/null 2>&1 || return 1
  ! plutil -convert xml1 -o - "$C" 2>/dev/null | awk '
      /<key>BundlePath<\/key>/ { getline; b = $0 } /<key>Enabled<\/key>/ { getline; if ($0 ~ /<true\/>/ && b ~ /(VirtualSMC|FakeSMC)\.kext<\/string>/) f = 1 }
      /<\/dict>/ { b = "" } END { exit !f }'
}
startup_ok() {   # sets EFIKIND to 1401 or mac
  if is_1401_efi; then EFIKIND=1401; return 0; fi
  if is_mac_efi; then EFIKIND=mac; return 0; fi
  return 1
}
nvidia_ids() {   # device IDs of the NVIDIA cards on the PCI bus, upper-case
  ioreg -c IOPCIDevice -r -d 1 -l -w 0 2>/dev/null | awk '
    function flush() { if (v == "de100000" && d != "") print toupper(substr(d, 3, 2) substr(d, 1, 2)); v = ""; d = "" }
    /\+-o / { flush() }
    /"vendor-id" = </ { s = $0; sub(/.*</, "", s); sub(/>.*/, "", s); v = s }
    /"device-id" = </ { s = $0; sub(/.*</, "", s); sub(/>.*/, "", s); d = s }
    END { flush() }'
}
# Graphics other than NVIDIA. macOS 27 has no Intel-side graphics drivers of its own, so each chip needs a package
# in the kit, and there are two kinds: chips Apple's own drivers in this macOS run (every real Intel Mac that starts
# macOS 26 without added drivers, and the Radeon cards Apple shipped), and chips 1401's test drivers run on a PC
# (other Radeon cards, AMD and Intel processor graphics). Which chips Apple's drivers take is read from this
# macOS's own drivers, never from a list kept here: a list would go stale with the next macOS update.
display_ids() {  # VVVV:DDDD of every display-class PCI device (class 03), upper-case
  ioreg -r -c IOPCIDevice -l -w0 2>/dev/null | LC_ALL=C awk -F'<|>' '
    function out() { if (c == "03" && v != "" && d != "") print toupper(v ":" d) }
    /\+-o / { out(); c = ""; v = ""; d = "" }
    /"vendor-id" =/ { v = substr($2, 3, 2) substr($2, 1, 2) } /"device-id" =/ { d = substr($2, 3, 2) substr($2, 1, 2) }
    /"class-code" =/ { c = substr($2, 5, 2) }
    END { out() }' | sort -u
}
apple_graphics_ids() {  # VVVV:DDDD of every AMD and Intel chip a graphics driver of this macOS matches
  local k
  for k in /System/Library/Extensions/AMD*.kext /System/Library/Extensions/AppleIntel*Graphics*.kext; do
    [ -f "$k/Contents/Info.plist" ] && plutil -p "$k/Contents/Info.plist" 2>/dev/null
  done | grep -oE '0x[0-9A-Fa-f]{4}(1002|8086)' | awk '{ print toupper(substr($0, 7, 4) ":" substr($0, 3, 4)) }' | sort -u
}
kit_carries() {  # $1 = nvidia, apple or test: does this kit carry macOS 27 graphics for that path
  local n i; n=$(kv graphics) || n=""
  case "$n" in ''|*[!0-9]*) [ "$1" = nvidia ]; return;; esac   # a kit that names none is an NVIDIA kit
  i=0; while [ "$i" -lt "$n" ]; do [ "$(kv graphics.$i)" = "$1" ] && return 0; i=$((i + 1)); done; return 1
}
kit_paths() { local n i out=""; n=$(kv graphics) || n=""; case "$n" in ''|*[!0-9]*) echo nvidia; return;; esac
  i=0; while [ "$i" -lt "$n" ]; do out="$out, $(kv graphics.$i)"; i=$((i + 1)); done; printf '%s' "${out#, }"; }
chip_maker() { case "${1%%:*}" in 1002) echo AMD;; 8086) echo Intel;; 10DE) echo NVIDIA;; *) echo "${1%%:*}";; esac; }
bluetooth_ids() {  # VVVV-PPPP of USB devices in the wireless-controller class (224), which Bluetooth adapters use
  ioreg -p IOUSB -l -w 0 2>/dev/null | awk '
    function flush() { if (c == 224 && v != "") printf "%04X-%04X\n", v, p; v = ""; p = 0; c = -1 }
    /\+-o / { flush() }
    /"idVendor" = / { v = $NF + 0 } /"idProduct" = / { p = $NF + 0 } /"bDeviceClass" = / { c = $NF + 0 }
    END { flush() }'
}
# macOS 27 is offered for every card the driver takes: the same list the driver install for macOS 15 and 26 uses
# (nvidia_gsp_ids.json beside this script). The cards macOS 27 has actually been started on are fewer; they decide
# only what a passing check says, never whether it passes.
card_supported() {  # $1 = device ID
  local id; id=$(upper "$1")
  printf '%s' "$id" | grep -Eq '^[0-9A-F]{4}$' || return 1
  plutil -extract "ids.$id" raw -o - "$HERE/nvidia_gsp_ids.json" >/dev/null 2>&1
}
card_tried() {      # $1 = device ID: the kit's own list when it carries one, else the cards this app records as tried
  local id n i; id=$(upper "$1")
  if n=$(kv gpu_ids) && [ -n "$n" ] && [ "$n" != 0 ]; then
    i=0; while [ "$i" -lt "$n" ]; do [ "$(upper "$(kv gpu_ids.$i)")" = "$id" ] && return 0; i=$((i + 1)); done; return 1
  fi
  n=$(plutil -extract tested raw -o - "$HERE/nvidia_gsp_ids.json" 2>/dev/null) || return 1
  case "$n" in ''|*[!0-9]*) return 1;; esac
  i=0; while [ "$i" -lt "$n" ]; do [ "$(upper "$(plutil -extract "tested.$i" raw -o - "$HERE/nvidia_gsp_ids.json" 2>/dev/null)")" = "$id" ] && return 0; i=$((i + 1)); done
  return 1
}
card_name() { printf '%s' "$1" | grep -Eq '^[0-9A-F]{4}$' && plutil -extract "ids.$1" raw -o - "$HERE/nvidia_gsp_ids.json" 2>/dev/null; }
cards_tried() {    # the cards macOS 27 has been started on, by name
  local n i id out=""
  if n=$(kv gpu_ids) && [ -n "$n" ] && [ "$n" != 0 ]; then
    i=0; while [ "$i" -lt "$n" ]; do id=$(upper "$(kv gpu_ids.$i)"); out="$out, $(card_name "$id" || echo "NVIDIA card") ($id)"; i=$((i + 1)); done
  else
    n=$(plutil -extract tested raw -o - "$HERE/nvidia_gsp_ids.json" 2>/dev/null); i=0
    while [ "$i" -lt "${n:-0}" ]; do id=$(upper "$(plutil -extract "tested.$i" raw -o - "$HERE/nvidia_gsp_ids.json" 2>/dev/null)"); out="$out, $(card_name "$id" || echo "NVIDIA card") ($id)"; i=$((i + 1)); done
  fi
  printf '%s' "${out#, }"
}
stage_need_kb() {  # the copy of EFI/OC and the kit's kexts. The packages stay in the kit and need no room here.
  echo $(( $(du -sk "$EFI/OC" | awk '{print $1}') + $(du -sk "$KIT/Kexts" | awk '{print $1}') + ESP_MARGIN_KB ))
}
free_kb() { df -k "$1" 2>/dev/null | awk 'NR==2 {print $4}'; }
# Room on the startup partition. It is a small partition (100 or 200 MB on most PCs), and what users read as "disk
# space" in the first reports was this. OpenCore writes a start-up log there on every start when its logging is on,
# a quarter of a megabyte each; one test machine held 182 of them. Those are the one thing there that is safe to
# remove without asking: the three newest are kept for a report, the rest go when staging needs the room.
esp_free_kb() { case "$ESPFREE" in ''|*[!0-9]*) free_kb "$ROOT";; *) echo "$ESPFREE";; esac; }   # --esp-free-kb: a test's stand-in
esp_old_logs() {   # every OpenCore start-up log but the three newest; the names carry the date, so they sort by age
  local all n
  all=$(ls -1 "$ROOT" 2>/dev/null | grep -E '^opencore-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}\.txt$' | sort)
  n=$(printf '%s\n' "$all" | grep -c .); [ "$n" -gt 3 ] || return 0
  printf '%s\n' "$all" | head -n $((n - 3))
}
esp_old_logs_kb() { local f t=0; while IFS= read -r f; do [ -n "$f" ] && [ -f "$ROOT/$f" ] && [ ! -L "$ROOT/$f" ] && t=$((t + $(du -k "$ROOT/$f" | awk '{print $1}'))); done <<EOT
$(esp_old_logs)
EOT
  echo "$t"; }
esp_remove_old_logs() { local f; while IFS= read -r f; do [ -n "$f" ] && [ -f "$ROOT/$f" ] && [ ! -L "$ROOT/$f" ] && rm -f "$ROOT/$f"; done <<EOT
$(esp_old_logs)
EOT
}
laydown_or_stop() {    # the kit's lay-down script, in its private copy: LDIR/linst
  local d; d=$(kv laydown.dir); linst=$(kv laydown.installer)
  case "$d" in ''|*/*|.*) stop "the v3 kit carries no lay-down step. Nothing was changed";; esac
  case "$linst" in ''|*/*|.*) stop "the v3 kit carries no lay-down step. Nothing was changed";; esac
  LDIR="$KIT/$d"
  [ -d "$LDIR" ] && [ ! -L "$LDIR" ] && [ -f "$LDIR/$linst" ] && [ ! -L "$LDIR/$linst" ] || stop "the v3 kit carries no lay-down step. Nothing was changed"
}
# Golden Gate starts from either macOS the driver supports: 15 or 26. No point release of them is refused by its
# number; a step that cannot do its job on the running system says so through system_stop.
from_ok() { [ -n "$MAJOR" ] || { MAJOR=$(sw_vers -productVersion 2>/dev/null); MAJOR=${MAJOR%%.*}; }; case "$MAJOR" in 15|26) return 0;; esac; return 1; }
from_26_or_stop() {    # $1 = what is being done
  from_ok || stop "$1 from macOS 15 or 26; this Mac runs macOS ${MAJOR:-?}. Nothing was changed"
}
# What the user reads when the running macOS cannot do a step's job: a system tool is missing or answers differently,
# or a kit script refused for a reason tied to the running system (it exits 3 and prints the reason after "SYSTEM: ").
os_version() { local v; v=$(sw_vers -productVersion 2>/dev/null); echo "${v:-${MAJOR:-?}}"; }
system_stop() {
  # A Mac that is already on 26.7.1 is not told to update to it: there the reason is ours to look at.
  if [ "$(os_version)" = 26.7.1 ]; then stop "This Mac's macOS 26.7.1 cannot prepare macOS 27. Reason: $1. Press Send logs so we can look at it. Nothing was changed"; fi
  stop "This Mac's macOS $(os_version) cannot prepare macOS 27. Update to macOS 26.7.1, then run Golden Gate again. Reason: $1. Nothing was changed"
}
# run_kit <script> <args...>: runs a kit script, showing its lines; RC is its exit code and SYSWHY its "SYSTEM: " reason
run_kit() {
  local t="$PRIV/last-run.txt"
  /bin/bash "$@" 2>&1 | tee "$t"; RC=${PIPESTATUS[0]}
  SYSWHY=$(sed -n 's/^SYSTEM: //p' "$t" 2>/dev/null | tail -n 1); rm -f "$t"
  [ "$RC" != 3 ] || [ -n "$SYSWHY" ] || SYSWHY="a step of the kit cannot run on this macOS"
}
# system_probe: sets WHY and fails when the running macOS lacks something the later steps need. Nothing is changed.
system_probe() {
  local t p
  for t in usr/bin/bspatch usr/bin/aea usr/bin/hdiutil usr/sbin/pkgutil usr/sbin/diskutil usr/bin/plutil usr/bin/shasum usr/bin/curl; do
    p="${TOOLS:+$TOOLS}/$t"; [ -x "$p" ] || { WHY="the system tool ${t##*/} is missing"; return 1; }
  done
  # pkgutil does not list --expand-full in its usage text, so the option is tried: on a package that is not there a
  # pkgutil that knows the option says it could not open the package, and one that does not says the option is unknown.
  if "${TOOLS:+$TOOLS}/usr/sbin/pkgutil" --expand-full /nonexistent-package /nonexistent-folder 2>&1 | grep -q -i -E 'unrecognized option|illegal option|invalid option'; then
    WHY="pkgutil on this macOS cannot open a package in full (--expand-full)"; return 1
  fi
  "${TOOLS:+$TOOLS}/usr/sbin/diskutil" apfs addVolume 2>&1 | grep -qE -- '-group(With|\[With\])' || { WHY="diskutil on this macOS cannot add a volume to a volume group (-groupWith)"; return 1; }
  [ "$(printf '{"a":"b"}' | "${TOOLS:+$TOOLS}/usr/bin/plutil" -extract a raw -o - - 2>/dev/null)" = b ] || { WHY="plutil on this macOS cannot read one value (-extract ... raw)"; return 1; }
  return 0
}
# --- the macOS 27 this app laid down: found by what was recorded, never by looking at what is mounted ---
# A volume that merely says it is macOS 27 (a mounted disk image, a volume someone attached) must never be handed to
# the installers, read, or written to as root. When the install step lays macOS 27 down it records the two new
# volumes' identifiers; every later step asks diskutil where those two are, and takes them only when both are APFS
# volumes in the same container as the running system and both are mounted. Anything else is a refusal with WHY set.
GGDIR="${STEPLOG%/*}"                       # the records are kept beside the step log, in a folder only root can write
# What is kept between tries so that a second try does not download again: Apple's restore image and the Kernel Debug
# Kit in the lay-down's folder, and the kernel collections made from the kit. Both folders belong to root and nobody
# else can write them; every kept file is checked against its known checksum again before it is used (the lay-down
# and the collections maker do that), so a kept file saves the download and nothing else.
dl_bytes() {     # the bytes of the plain files in the two folders; links are never followed
  local d s t=0
  for d in "$LAYWORK" "$KCWORK"; do
    [ -d "$d" ] && [ ! -L "$d" ] || continue
    while IFS= read -r s; do case "$s" in ''|*[!0-9]*) ;; *) t=$((t + s));; esac; done <<EOF
$(find "$d" -type f -exec stat -f %z {} + 2>/dev/null)
EOF
  done
  echo "$t"
}
# The app's page runs as the user and cannot look into those folders, so the figure it shows is written beside the
# step log, readable by everyone. It is only ever shown; nothing is decided from it.
dl_record() {
  [ -d "$GGDIR" ] || mkdir -p "$GGDIR" 2>/dev/null || return 0
  printf 'bytes %s\n' "$(dl_bytes)" > "$GGDIR/downloads.tmp" 2>/dev/null && chmod 644 "$GGDIR/downloads.tmp" 2>/dev/null \
    && mv -f "$GGDIR/downloads.tmp" "$GGDIR/downloads" 2>/dev/null
  return 0
}
gb1() { awk -v b="$1" 'BEGIN { printf "%.1f", b / 1073741824 }'; }     # bytes as GB with one decimal
vfield() { printf '%s' "$1" | plutil -extract "$2" raw -o - - 2>/dev/null; }
mac27_volumes() {
  local rec="$GGDIR/macos27-volumes" su du here si di
  SYS=""; DATA=""; WHY=""; SYSID=""; DATAID=""
  chain_trusted "$GGDIR" || { WHY="the folder of Golden Gate's records ($GGDIR) is not one only root can write"; return 1; }
  [ -f "$rec" ] && [ ! -L "$rec" ] || { WHY="no macOS 27 has been laid down by this app on this Mac (there is no record of its volumes)"; return 1; }
  su=$(sed -n 's/^system //p' "$rec" | head -n 1); du=$(sed -n 's/^data //p' "$rec" | head -n 1)
  printf '%s\n%s\n' "$su" "$du" | grep -Ev '^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$' >/dev/null && { WHY="the record of the macOS 27 volumes is not one this app wrote"; return 1; }
  here=$(vfield "$("$DISKUTIL" info -plist / 2>/dev/null)" APFSContainerReference)
  [ -n "$here" ] || { WHY="the disk this macOS runs from could not be read"; return 1; }
  si=$("$DISKUTIL" info -plist "$su" 2>/dev/null); di=$("$DISKUTIL" info -plist "$du" 2>/dev/null)
  [ -n "$si" ] && [ -n "$di" ] || { WHY="the macOS 27 volumes this app laid down are no longer on this Mac"; return 1; }
  [ "$(vfield "$si" FilesystemType)" = apfs ] && [ "$(vfield "$di" FilesystemType)" = apfs ] \
    && [ "$(vfield "$si" APFSContainerReference)" = "$here" ] && [ "$(vfield "$di" APFSContainerReference)" = "$here" ] \
    || { WHY="the recorded macOS 27 volumes are not APFS volumes on the disk this macOS runs from"; return 1; }
  SYS=$(vfield "$si" MountPoint); DATA=$(vfield "$di" MountPoint); SYSID=$su; DATAID=$du
  # The lay-down step leaves both volumes unmounted. A step that works on them (asked with "mount") mounts the two
  # recorded volumes itself; a step that only reports does not change what is mounted.
  if [ "${1:-}" = mount ] && { [ -z "$SYS" ] || [ -z "$DATA" ]; }; then
    [ -n "$SYS" ] || "$DISKUTIL" mount "$su" >/dev/null 2>&1
    [ -n "$DATA" ] || "$DISKUTIL" mount "$du" >/dev/null 2>&1
    si=$("$DISKUTIL" info -plist "$su" 2>/dev/null); di=$("$DISKUTIL" info -plist "$du" 2>/dev/null)
    SYS=$(vfield "$si" MountPoint); DATA=$(vfield "$di" MountPoint)
  fi
  [ -n "$SYS" ] && [ -d "$SYS/System/Library/CoreServices" ] || { WHY="the macOS 27 volume is not mounted (mount it in Disk Utility)"; SYS=""; DATA=""; return 1; }
  [ -n "$DATA" ] && [ -d "$DATA" ] && [ "$DATA" != "$SYS" ] || { WHY="the macOS 27 data volume is not mounted (mount it in Disk Utility)"; SYS=""; DATA=""; return 1; }
  return 0
}
# mac27_laid_down: yes when the volumes this app recorded are there and hold macOS 27, the same test the "laid" step
# makes. It is asked from preflight, which only reports, so a volume it had to mount to read the version is unmounted
# again afterwards and the Mac is left as it was found.
mac27_laid_down() {
  local pre_s="" pre_d="" ver id
  if ! mac27_volumes; then
    [ -n "$SYSID" ] && [ -n "$DATAID" ] || return 1
    pre_s=$(vfield "$("$DISKUTIL" info -plist "$SYSID" 2>/dev/null)" MountPoint)
    pre_d=$(vfield "$("$DISKUTIL" info -plist "$DATAID" 2>/dev/null)" MountPoint)
    if mac27_volumes mount; then
      ver=$(plutil -extract ProductVersion raw -o - "$SYS/System/Library/CoreServices/SystemVersion.plist" 2>/dev/null)
    fi
    for id in $([ -n "$pre_s" ] || echo "$SYSID") $([ -n "$pre_d" ] || echo "$DATAID"); do
      "$DISKUTIL" unmount "$id" >/dev/null 2>&1
    done
  else
    ver=$(plutil -extract ProductVersion raw -o - "$SYS/System/Library/CoreServices/SystemVersion.plist" 2>/dev/null)
  fi
  case "$ver" in 27.*) return 0;; esac
  return 1
}
# The two macOS 27 volumes must keep file owners. A volume can be mounted with owners ignored (macOS does that to a
# volume it treats as external, and remembers the choice per volume): every file then reads back as owner 99, the
# change of owner reports success and does nothing, and the kernel refuses a shared cache that is not root's. The
# first PC this happened on stopped in the middle of the system package. So owners are switched on here, before
# anything is written, and the answer is read back.
owners_or_stop() {
  local id name
  for id in "$SYSID" "$DATAID"; do
    [ "$(vfield "$("$DISKUTIL" info -plist "$id" 2>/dev/null)" GlobalPermissionsEnabled)" = false ] || continue
    name=$(vfield "$("$DISKUTIL" info -plist "$id" 2>/dev/null)" MountPoint)
    "$DISKUTIL" enableOwnership "$id" >/dev/null 2>&1
    [ "$(vfield "$("$DISKUTIL" info -plist "$id" 2>/dev/null)" GlobalPermissionsEnabled)" != false ] \
      || stop "the macOS 27 volume at $name ignores file owners and that could not be changed. In Terminal run: sudo diskutil enableOwnership \"$name\" - then run this step again. Nothing was changed"
    note "file owners were switched off on $name; they are on now"
  done
}
# put_on_data <file> <path below the data volume>: a root write onto the new data volume. No part of the path may be
# a symbolic link (a link there would send the write anywhere), folders are made root-owned 0755, and the file is
# written under a fresh name in its folder and renamed into place.
put_on_data() {
  local src=$1 rel=$2 dir cur part tmp
  [ -n "$DATA" ] && [ -d "$DATA" ] && [ ! -L "$DATA" ] || return 1
  dir=${rel%/*}; cur=$DATA
  local IFS=/
  for part in $dir; do [ -n "$part" ] || continue
    cur="$cur/$part"
    [ ! -L "$cur" ] || return 1
    if [ ! -e "$cur" ]; then mkdir "$cur" && chmod 755 "$cur" || return 1; fi
    [ -d "$cur" ] || return 1
  done
  unset IFS
  [ ! -L "$DATA/$rel" ] || return 1
  tmp=$(mktemp "$cur/.gg.XXXXXX") || return 1
  cat "$src" > "$tmp" && chmod 644 "$tmp" && mv -f "$tmp" "$DATA/$rel" || { rm -f "$tmp"; return 1; }
}
# kc_folder_trusted: the folder the kernel collections are kept in belongs to root all the way up, and holds no link
kc_folder_trusted() { [ -d "$KCWORK" ] && [ ! -L "$KCWORK" ] && chain_trusted "$KCWORK" && tree_trusted "$KCWORK"; }
kc_sums() { ( cd "$KCWORK" 2>/dev/null && shasum -a 256 BootKernelExtensions.kc SystemKernelExtensions.kc 2>/dev/null ); }
packages_or_stop() {   # the kit's two packages, in its private copy: PAY/inst the driver's, SPAY/sinst the system's
  # the graphics package follows the graphics this machine starts on: the NVIDIA driver's, or the one the kit
  # carries for Apple's own AMD and Intel drivers (driver_apple) or for the test drivers (driver_test)
  dkey=driver; stage_path
  case "$GFX" in apple|test) khas "driver_$GFX.dir" || stop "the v3 kit carries no macOS 27 graphics package for this Mac's graphics ($GFX). Nothing was changed"; dkey="driver_$GFX";; esac
  ddir=$(kv $dkey.dir); inst=$(kv $dkey.installer)
  case "$ddir" in ''|*/*|.*) stop "the v3 kit carries no driver package. Nothing was changed";; esac
  case "$inst" in ''|*/*|.*) stop "the v3 kit carries no driver package. Nothing was changed";; esac
  PAY="$KIT/$ddir"
  [ -d "$PAY" ] && [ ! -L "$PAY" ] && [ -f "$PAY/$inst" ] && [ ! -L "$PAY/$inst" ] || stop "the v3 kit carries no driver package. Nothing was changed"
  sdir=$(kv system.dir); sinst=$(kv system.installer)
  case "$sdir" in ''|*/*|.*) stop "the v3 kit carries no system package. Nothing was changed";; esac
  case "$sinst" in ''|*/*|.*) stop "the v3 kit carries no system package. Nothing was changed";; esac
  SPAY="$KIT/$sdir"
  [ -d "$SPAY" ] && [ ! -L "$SPAY" ] && [ -f "$SPAY/$sinst" ] && [ ! -L "$SPAY/$sinst" ] || stop "the v3 kit carries no system package. Nothing was changed"
}

# ---- the kit applied to one OC folder: the same changes, in the same order, as p1401/v3_macos27.py apply() ----
WHY=""
bad() { WHY=$*; return 1; }
cget() { plutil -extract "$1" raw -o - "$AC" 2>/dev/null; }
bundle_at() { local b; b=$(cget "Kernel.Add.$1.BundlePath") || return 1; echo "${b##*/}"; }
# The name of one kernel patch of the config being written: a digest of what OpenCore matches on. The kit's maker
# computes the same digest (tools/kernel_patches_27.py mark): the fields joined with '|', data as base64, numbers in
# decimal, an absent field empty. What the patch writes is not part of it: one patch carries the user's own core count.
patch_mark() {
  local k out=""
  for k in Identifier Base Find Mask Count Limit Skip; do out="$out$(cget "Kernel.Patch.$1.$k")|"; done
  out=$(printf '%s' "$out" | shasum -a 256 2>/dev/null | cut -c1-64)
  printf '%s' "$out" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s' "$out"
}
# One of the kit's own macOS 27 patches ($1 = its index in patches_27_own), added at the end of the patch list. It is
# bounded to kernel 27, so macOS 26 starts exactly as before.
add_own_patch() {
  local k="patches_27_own.$1.patch" at ident base comment count limit f
  ident=$(kv "$k.identifier"); base=$(kv "$k.base"); comment=$(kv "$k.comment"); count=$(kv "$k.count"); limit=$(kv "$k.limit")
  safe "$ident" && safe "$base" && safe "$comment" && [ -n "$ident" ] || { bad "a kit kernel patch has a field 1401 will not write"; return 1; }
  case "$count$limit" in ''|*[!0-9]*) bad "a kit kernel patch has a count that is not a number"; return 1;; esac
  for f in find replace mask replace_mask; do
    case "$(kv "$k.$f")" in *[!A-Za-z0-9+/=]*) bad "a kit kernel patch has bytes that are not base64"; return 1;; esac
  done
  [ -n "$(kv "$k.find")" ] && [ -n "$(kv "$k.replace")" ] || { bad "a kit kernel patch has nothing to find or to write"; return 1; }
  at=$(cget Kernel.Patch)
  plutil -insert "Kernel.Patch.$at" -json "{\"Arch\":\"x86_64\",\"Base\":\"$base\",\"Comment\":\"$comment\",\"Count\":$count,\"Enabled\":true,\"Identifier\":\"$ident\",\"Limit\":$limit,\"MaxKernel\":\"27.99.99\",\"MinKernel\":\"27.0.0\",\"Skip\":0}" "$AC" \
    || { bad "could not add the kit's kernel patch"; return 1; }
  plutil -insert "Kernel.Patch.$at.Find" -data "$(kv "$k.find")" "$AC" && plutil -insert "Kernel.Patch.$at.Replace" -data "$(kv "$k.replace")" "$AC" \
    && plutil -insert "Kernel.Patch.$at.Mask" -data "$(kv "$k.mask")" "$AC" && plutil -insert "Kernel.Patch.$at.ReplaceMask" -data "$(kv "$k.replace_mask")" "$AC" \
    || { bad "could not write the kit's kernel patch bytes"; return 1; }
}
index_of() {     # first Kernel.Add index whose bundle is $1
  local n i; n=$(cget Kernel.Add); i=0
  while [ "$i" -lt "$n" ]; do [ "$(bundle_at "$i")" = "$1" ] && { echo "$i"; return 0; }; i=$((i + 1)); done; return 1
}
safe() { [ -z "$1" ] || printf '%s' "$1" | grep -Eq "^[A-Za-z0-9 _./|:+-]+\$"; }   # what may go into an entry's text fields
entry_json() {   # $1 = kit kext index
  local name exe min max com
  name=$(kv kexts.$1.name); exe=$(kv kexts.$1.executable); min=$(kv kexts.$1.min_kernel); max=$(kv kexts.$1.max_kernel); com=$(kv kexts.$1.comment)
  safe "$exe" && safe "$min" && safe "$max" && safe "$com" || return 1
  printf '{"Arch":"x86_64","BundlePath":"%s","Comment":"%s","Enabled":true,"ExecutablePath":"%s","MaxKernel":"%s","MinKernel":"%s","PlistPath":"Contents/Info.plist"}' \
    "$name" "$com" "$exe" "$max" "$min"
}
sets() { plutil -replace "$1" -string "$2" "$AC" 2>/dev/null || plutil -insert "$1" -string "$2" "$AC"; }
# Which graphics this machine starts macOS 27 on, for staging: nvidia, apple, test, or empty when none is known
# (an empty answer stages as an NVIDIA PC does, which is what every kit before these paths did).
stage_path() {
  local g d; GFX=""
  [ $GPUS_GIVEN = 1 ] || GPUS=$(nvidia_ids)
  for g in $GPUS; do card_supported "$(upper "$g")" && { GFX=nvidia; return 0; }; done
  if [ $DISPLAYS_GIVEN = 0 ] && [ $GPUS_GIVEN = 0 ]; then DISPLAYS=$(display_ids); fi
  if [ $APPLEIDS_GIVEN = 0 ] && [ $GPUS_GIVEN = 0 ]; then APPLEIDS=$(apple_graphics_ids); fi
  for d in $DISPLAYS; do d=$(upper "$d")
    case "$d" in 1002:*|8086:*) ;; *) continue;; esac
    if printf '%s\n' $APPLEIDS | tr '[:lower:]' '[:upper:]' | grep -qx "$d"; then GFX=apple; return 0; fi
    [ -n "$GFX" ] || GFX=test
  done
}
in_kit_list() {  # $1 = manifest key of a list of strings, $2 = the string
  local n i; n=$(kv "$1") || return 1
  case "$n" in ''|*[!0-9]*) return 1;; esac
  i=0; while [ "$i" -lt "$n" ]; do [ "$(kv "$1.$i")" = "$2" ] && return 0; i=$((i + 1)); done; return 1
}
# A kit kext or boot argument the kit marks for another kind of machine is left out: the NVIDIA kernel driver and its
# arguments on a machine that starts on other graphics, and what only a PC needs (its SMC stand-in's argument) on a Mac.
not_for_this() {
  case "$GFX" in apple|test) in_kit_list only.nvidia "$1" && return 0;; esac
  [ "$EFIKIND" = mac ] && in_kit_list only.pc "$1" && return 0
  return 1
}
# A kext's upper kernel limit lets it load on macOS 27 when it is empty or names kernel 27 or later. A config made
# by OpenCore Legacy Patcher gives its kexts the limit 27.99.99 as a matter of course, which says nothing about
# whether they were ever run on macOS 27: on the first real Mac this let six kernel-patching kexts into the macOS 27
# kernel, and it never reached its first service. So a limit that reaches 27 is treated like no limit at all.
reaches_27() { case "${1%%.*}" in '') return 0;; *[!0-9]*) return 1;; esac; [ "${1%%.*}" -ge 27 ]; }
NOT27=""; NOTABLES=0     # what apply_kit reports: kexts kept off macOS 27, and identity tables it could not write
PATCH_ON=0; PATCH_OWN=0; PATCH_OFF=0; PATCH_OFF_NAMES=""   # kernel patches: carried to 27, replaced by the kit's own, left at 26
kit_brings() { local n j; n=$(kv kexts) || return 1; j=0; while [ "$j" -lt "$n" ]; do [ "$(kv kexts.$j.name)" = "$1" ] && return 0; j=$((j + 1)); done; return 1; }
choice_of() { [ -f "$EFI/$CHOICES" ] && [ ! -L "$EFI/$CHOICES" ] && awk -F'\t' -v k="$1" '$2 == k { v = $1 } END { print v }' "$EFI/$CHOICES"; }
# What the user chose for single drivers on this partition, applied to the config at $AC. It comes after every rule
# of the kit and wins: "off" stops a driver at macOS 26 (never one the kit itself brings); "on" lets a driver the kit
# holds back by default but allows to be tried (may_27) load on macOS 27. A driver with no choice goes back to the
# kit's default, so taking a choice away is the same as never having made it. Fills TRY27 (not proven on macOS 27
# and on), OFF27 and ON27 (the choices that took effect) for the step's notes.
TRY27=""; OFF27=""; ON27=""
apply_choices() {
  local n i name verb mx
  TRY27=""; OFF27=""; ON27=""
  n=$(cget Kernel.Add) || n=0; i=0
  while [ "$i" -lt "$n" ]; do
    name=$(bundle_at "$i")
    if [ "$(cget "Kernel.Add.$i.Enabled")" = true ] && [ -n "$(cget "Kernel.Add.$i.ExecutablePath")" ] && ! kit_brings "$name"; then
      verb=$(choice_of "$name"); mx=$(cget "Kernel.Add.$i.MaxKernel")
      if [ "$verb" = off ]; then
        if reaches_27 "$mx"; then sets "Kernel.Add.$i.MaxKernel" 26.99.99 || { bad "could not turn $name off"; return 1; }; fi
        OFF27="$OFF27 $name"
      elif [ "$verb" = on ] && in_kit_list may_27 "$name"; then
        if [ "$mx" = 26.99.99 ]; then sets "Kernel.Add.$i.MaxKernel" "" || { bad "could not turn $name on"; return 1; }; fi
        ON27="$ON27 $name"
      elif in_kit_list try_27 "$name" && [ "$mx" = 26.99.99 ]; then
        sets "Kernel.Add.$i.MaxKernel" "" || { bad "could not turn $name back on"; return 1; }
      elif in_kit_list may_27 "$name" && reaches_27 "$mx"; then
        sets "Kernel.Add.$i.MaxKernel" 26.99.99 || { bad "could not hold $name back"; return 1; }
      fi
      if in_kit_list try_27 "$name" && reaches_27 "$(cget "Kernel.Add.$i.MaxKernel")"; then TRY27="$TRY27 $name"; fi
    fi
    i=$((i + 1)); done
  return 0
}
drv_log() {   # one dated line in the drivers log on the startup partition; the newest 200 lines are kept
  local f="$EFI/$DRVLOG"
  [ ! -L "$f" ] || return 0
  printf '%s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$f" 2>/dev/null && tail -n 200 "$f" > "$f.tmp" 2>/dev/null && mv -f "$f.tmp" "$f"
}
apply_kit() {    # $1 = the OC folder to change
  local oc=$1 n i name when pos idx have p m li j key type val parent args a added s0 u0 hex fresh k b
  AC="$oc/config.plist"; local kd="$oc/Kexts"
  local first="" end="" after=""
  n=$(kv kexts); i=0
  while [ "$i" -lt "$n" ]; do
    name=$(kv kexts.$i.name); when=$(kv kexts.$i.when); [ -n "$when" ] || when=always
    pos=$(kv kexts.$i.position); [ -n "$pos" ] || pos=end
    if not_for_this "$name"; then i=$((i + 1)); continue; fi
    idx=$(index_of "$name") || idx=""
    if [ "$when" = present ] && [ -z "$idx" ]; then i=$((i + 1)); continue; fi
    if [ "$when" = ids ] && [ -z "$idx" ]; then
      [ "$(kv kexts.$i.section)" = Bluetooth ] || { bad "$name follows a device list this Mac cannot check ($(kv kexts.$i.section))"; return 1; }
      [ $DEVIDS_GIVEN = 1 ] || DEVIDS=$(bluetooth_ids)
      have=0; m=$(kv kexts.$i.ids); j=0
      while [ "$j" -lt "$m" ]; do p=$(upper "$(kv kexts.$i.ids.$j)")
        for a in $DEVIDS; do case "$(upper "$a")" in "$p"*) have=1;; esac; done; j=$((j + 1)); done
      [ $have = 1 ] || { i=$((i + 1)); continue; }
    fi
    rm -rf "$kd/$name"; cp -R "$KIT/Kexts/$name" "$kd/$name" || { bad "could not copy $name"; return 1; }
    if [ -n "$idx" ]; then
      plutil -replace "Kernel.Add.$idx.Enabled" -bool true "$AC" || { bad "could not change $name"; return 1; }
      safe "$(kv kexts.$i.min_kernel)" && safe "$(kv kexts.$i.max_kernel)" && safe "$(kv kexts.$i.executable)" || { bad "$name has a field 1401 will not write"; return 1; }
      sets "Kernel.Add.$idx.MinKernel" "$(kv kexts.$i.min_kernel)"; sets "Kernel.Add.$idx.MaxKernel" "$(kv kexts.$i.max_kernel)"
      khas kexts.$i.executable && sets "Kernel.Add.$idx.ExecutablePath" "$(kv kexts.$i.executable)"
    else
      case "$pos" in first) first="$first $i";; end) end="$end $i";; after-lilu) after="$after $i";; *) bad "$name: unknown position $pos"; return 1;; esac
    fi
    i=$((i + 1)); done
  if [ -n "$after" ]; then
    li=$(index_of Lilu.kext) || { bad "the kit places kexts after Lilu, and these startup files have no Lilu"; return 1; }
    j=1; for i in $after; do p=$(entry_json "$i") || { bad "a kit entry has a field 1401 will not write"; return 1; }
      plutil -insert "Kernel.Add.$((li + j))" -json "$p" "$AC" || { bad "could not add an entry after Lilu"; return 1; }; j=$((j + 1)); done
  fi
  j=0; for i in $first; do p=$(entry_json "$i") || { bad "a kit entry has a field 1401 will not write"; return 1; }
    plutil -insert "Kernel.Add.$j" -json "$p" "$AC" || { bad "could not add an entry first"; return 1; }; j=$((j + 1)); done
  for i in $end; do p=$(entry_json "$i") || { bad "a kit entry has a field 1401 will not write"; return 1; }
    plutil -insert "Kernel.Add.$(cget Kernel.Add)" -json "$p" "$AC" || { bad "could not add an entry last"; return 1; }; done

  # kexts the macOS 26 startup files carry that must not load on 27
  m=$(kv caps); [ -n "$m" ] || m=0; j=0
  while [ "$j" -lt "$m" ]; do name=$(kv caps.$j.name); val=$(kv caps.$j.max_kernel)
    printf '%s' "$val" | grep -Eq '^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$' || { bad "bad cap for $name"; return 1; }
    n=$(cget Kernel.Add); i=0
    # an upper limit the PC's own config already gives is kept: it is never raised
    while [ "$i" -lt "$n" ]; do [ "$(bundle_at "$i")" = "$name" ] && reaches_27 "$(cget "Kernel.Add.$i.MaxKernel")" && sets "Kernel.Add.$i.MaxKernel" "$val"; i=$((i + 1)); done
    j=$((j + 1)); done

  # a block that takes Apple's own kext away for an injected one stops where the injected one stops
  m=$(kv block_caps); [ -n "$m" ] || m=0; j=0
  while [ "$j" -lt "$m" ]; do name=$(kv block_caps.$j.identifier); val=$(kv block_caps.$j.max_kernel)
    printf '%s' "$val" | grep -Eq '^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$' || { bad "bad block cap for $name"; return 1; }
    n=$(cget Kernel.Block); [ -n "$n" ] || n=0; i=0
    while [ "$i" -lt "$n" ]; do
      [ "$(cget "Kernel.Block.$i.Identifier")" = "$name" ] && [ "$(cget "Kernel.Block.$i.Enabled")" = true ] && reaches_27 "$(cget "Kernel.Block.$i.MaxKernel")" && sets "Kernel.Block.$i.MaxKernel" "$val"
      i=$((i + 1)); done
    j=$((j + 1)); done

  # Kernel patches. A patch list is bounded by kernel version, and one written for macOS 26 ends at 25.99.99, so the
  # macOS 27 kernel would start without it: on a PC with an AMD processor that is a stop before the first line.
  # Raising every limit is not the answer either. One patch of the usual AMD list matches loosely, and in the macOS 27
  # kernel its first match is in other code. So a patch is carried to macOS 27 only when the kit names it: the kit's
  # maker found its bytes in this macOS 27 kernel, in the same functions as in macOS 26. Where the kit holds its own
  # patch for one that cannot be carried, that one is added for macOS 27. Any other patch keeps its limit and is named.
  n=$(cget Kernel.Patch); case "$n" in ''|*[!0-9]*) n=0;; esac
  if [ "$n" -gt 0 ] && khas patches_27; then
    local marks=" " owns=" " mk mx mn nown pcount o key val
    m=$(kv patches_27); case "$m" in ''|*[!0-9]*) m=0;; esac
    j=0; while [ "$j" -lt "$m" ]; do marks="$marks$(kv patches_27.$j) "; j=$((j + 1)); done
    nown=$(kv patches_27_own) || nown=0; case "$nown" in ''|*[!0-9]*) nown=0;; esac
    j=0; while [ "$j" -lt "$nown" ]; do owns="$owns$(kv patches_27_own.$j.for):$j "; j=$((j + 1)); done
    pcount=$n; i=0
    while [ "$i" -lt "$pcount" ]; do
      mx=$(cget "Kernel.Patch.$i.MaxKernel"); mn=$(cget "Kernel.Patch.$i.MinKernel")
      # only a patch that is on, applies to macOS 26 (kernel 25) and ends before 27 is a question at all
      if [ "$(cget "Kernel.Patch.$i.Enabled")" = true ] && [ -n "$mx" ] && ! reaches_27 "$mx" \
         && printf '%s' "${mx%%.*}" | grep -Eq '^[0-9]+$' && [ "${mx%%.*}" -ge 25 ] \
         && { [ -z "$mn" ] || { printf '%s' "${mn%%.*}" | grep -Eq '^[0-9]+$' && [ "${mn%%.*}" -le 25 ]; }; }; then
        mk=$(patch_mark "$i") || { bad "could not read kernel patch $i"; return 1; }
        case "$marks" in *" $mk "*)
          sets "Kernel.Patch.$i.MaxKernel" 27.99.99 || { bad "could not carry kernel patch $i"; return 1; }
          PATCH_ON=$((PATCH_ON + 1));;
        *) case "$owns" in *" $mk:"*)
            o=${owns#* $mk:}; o=${o%% *}
            add_own_patch "$o" || return 1
            PATCH_OWN=$((PATCH_OWN + 1));;
          *) PATCH_OFF=$((PATCH_OFF + 1))
            val=$(cget "Kernel.Patch.$i.Comment" | tr -c 'A-Za-z0-9 _.,|:+()/-' ' ' | cut -c1-90)
            PATCH_OFF_NAMES="$PATCH_OFF_NAMES${PATCH_OFF_NAMES:+; }${val:-patch $i}";; esac;; esac
      fi
      i=$((i + 1)); done
  fi

  # system kexts the injected NVIDIA driver links against: in the boot collection on macOS 27
  m=$(kv force); [ -n "$m" ] || m=0; j=0
  while [ "$j" -lt "$m" ]; do
    local fid fbp fex fpl fmin fmax
    fid=$(kv force.$j.identifier); fbp=$(kv force.$j.bundle_path); fex=$(kv force.$j.executable); fpl=$(kv force.$j.plist_path)
    fmin=$(kv force.$j.min_kernel); fmax=$(kv force.$j.max_kernel)
    safe "$fid" && safe "$fbp" && safe "$fex" && safe "$fpl" && [ -n "$fid" ] && [ -n "$fbp" ] && [ -n "$fpl" ] || { bad "a forced kext has a field 1401 will not write"; return 1; }
    case "$fbp$fex$fpl" in *..*) bad "a forced kext names a path with '..'"; return 1;; esac
    case "$fbp" in /*) bad "a forced kext names an absolute path"; return 1;; esac
    printf '%s' "$fmin" | grep -Eq '^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$' || { bad "bad kernel range for the forced kext $fid"; return 1; }
    [ -z "$fmax" ] || printf '%s' "$fmax" | grep -Eq '^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$' || { bad "bad kernel range for the forced kext $fid"; return 1; }
    [ "$(plutil -type Kernel.Force "$AC" 2>/dev/null)" = array ] || plutil -insert Kernel.Force -json '[]' "$AC" || { bad "the config has no Kernel section to force kexts in"; return 1; }
    n=$(cget Kernel.Force); [ -n "$n" ] || n=0; i=0; have=0
    while [ "$i" -lt "$n" ]; do [ "$(cget "Kernel.Force.$i.Identifier")" = "$fid" ] && [ "$(cget "Kernel.Force.$i.Enabled")" = true ] && have=1; i=$((i + 1)); done
    if [ $have = 0 ]; then
      p=$(printf '{"Arch":"x86_64","BundlePath":"%s","Comment":"macOS 27: in the boot collection for the injected driver","Enabled":true,"ExecutablePath":"%s","Identifier":"%s","MaxKernel":"%s","MinKernel":"%s","PlistPath":"%s"}' "$fbp" "$fex" "$fid" "$fmax" "$fmin" "$fpl")
      plutil -insert "Kernel.Force.$n" -json "$p" "$AC" || { bad "could not add the forced kext $fid"; return 1; }
    fi
    j=$((j + 1)); done

  # a kext whose personality matches on a provider class macOS 27.2 does not publish moves to the class the kit names
  m=$(kv personality); [ -n "$m" ] || m=0; j=0
  while [ "$j" -lt "$m" ]; do
    name=$(kv personality.$j.name); local from to info changed=0 already=0
    from=$(kv personality.$j.from); to=$(kv personality.$j.to); info="$kd/$name/Contents/Info.plist"
    idx=$(index_of "$name") || idx=""
    if [ -n "$idx" ] && [ "$(cget "Kernel.Add.$idx.Enabled")" = true ]; then
      [ -f "$info" ] || { bad "$name is in the config but its Info.plist is not in the startup files"; return 1; }
      safe "$to" || { bad "$name: a provider class 1401 will not write"; return 1; }
      while IFS= read -r key; do [ -n "$key" ] || continue
        val=$($PB -c "Print :IOKitPersonalities:$key:IOProviderClass" "$info" 2>/dev/null) || continue
        if [ "$val" = "$from" ]; then $PB -c "Set :IOKitPersonalities:$key:IOProviderClass $to" "$info" || { bad "could not change $name"; return 1; }; changed=1
        elif [ "$val" = "$to" ]; then already=1; fi
      done <<EOF
$(plutil -extract IOKitPersonalities raw -o - "$info" 2>/dev/null)
EOF
      [ $changed = 1 ] || [ $already = 1 ] || { bad "$name has no personality on $from to move to $to"; return 1; }
    fi
    j=$((j + 1)); done

  args=$(cget "NVRAM.Add.$NV.boot-args"); added=""
  m=$(kv boot_args); j=0
  while [ "$j" -lt "$m" ]; do a=$(kv boot_args.$j)
    if not_for_this "$a"; then j=$((j + 1)); continue; fi
    case " $BOOT_ARGS_ALLOWED " in *" $a "*) ;; *) bad "a boot argument 1401 will not write"; return 1;; esac
    # name=value: a value the PC's own config gives that name is replaced, so the name is there once
    case "$a" in *=*) local kept="" t; for t in $args; do case "$t" in "${a%%=*}="*) [ "$t" = "$a" ] && kept="$kept $t";; *) kept="$kept $t";; esac; done; args=${kept# };; esac
    case " $args $added " in *" $a "*) ;; *) added="$added $a";; esac; j=$((j + 1)); done
  args="$args$added"; args=${args# }
  plutil -extract "NVRAM.Add.$NV" raw -o - "$AC" >/dev/null 2>&1 || plutil -insert "NVRAM.Add.$NV" -json '{}' "$AC" || { bad "the config has no NVRAM section to set boot-args in"; return 1; }
  sets "NVRAM.Add.$NV.boot-args" "$args" || { bad "could not set boot-args"; return 1; }

  if khas set; then
    while IFS= read -r key; do [ -n "$key" ] || continue
      # a real Mac keeps the model its own firmware gives it: the kit's model is the identity a PC is given
      if [ "$EFIKIND" = mac ] && [ "$key" = PlatformInfo/Generic/SystemProductName ]; then continue; fi
      p=$(printf '%s' "$key" | tr / .); parent=${p%.*}
      [ "$(plutil -type "$parent" "$AC" 2>/dev/null)" = dictionary ] || { bad "the config has no $(printf '%s' "$parent" | tr . /) to set ${p##*.} in"; return 1; }
      type=$(plutil -type "set.$key" "$KIT/$MANIFEST" 2>/dev/null); val=$(kv "set.$key")
      case "$type" in
        string) sets "$p" "$val";;
        bool|integer) plutil -replace "$p" "-$type" "$val" "$AC" 2>/dev/null || plutil -insert "$p" "-$type" "$val" "$AC";;
        *) bad "the kit sets $key to a kind of value 1401 will not write here ($type)"; return 1;;
      esac || { bad "could not set $key"; return 1; }
    done <<EOF
$(kv set)
EOF
  fi

  # model identity follows the newest NVIDIA generation that has a model (the same rule as the builder's). With
  # --kit-model the model the kit sets is kept: the one its reference configuration started macOS 27 with.
  [ $GPUS_GIVEN = 1 ] || { GPUS=$(nvidia_ids); GPUS_GIVEN=1; }
  [ $KITMODEL = 0 ] || GPUS=""
  for a in $GPUS; do a=$(upper "$a")
    printf '%s' "$a" | grep -Eq '^[0-9A-F]{4}$' || continue
    val=$(plutil -extract "ids.$a" raw -o - "$HERE/nvidia_gsp_ids.json" 2>/dev/null) || continue
    if printf '%s' "$val" | grep -Eq '(^| )RTX 50[0-9][0-9]( |$)'; then
      # A serial names the model it was made for: when the model changes the serial follows it, worked out from this
      # PC's old serial, its UUID and the new model so that staging again gives the same one (p1401/v3_macos27.py
      # serial_for_model computes the same value). With neither a serial nor a UUID it is left as it is.
      if [ "$(cget PlatformInfo.Generic.SystemProductName)" != "$MODEL_RTX50" ]; then
        s0=$(cget PlatformInfo.Generic.SystemSerialNumber | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'); u0=$(cget PlatformInfo.Generic.SystemUUID | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        if [ -n "$s0" ] || [ -n "$u0" ]; then
          hex=$(printf '%s\n%s\n%s' "$s0" "$u0" "$MODEL_RTX50" | /usr/bin/shasum -a 256 | cut -c1-20); fresh=""; k=1
          while [ $k -le 19 ]; do b=$((16#$(printf '%s' "$hex" | cut -c$k-$((k + 1))))); fresh="$fresh$(printf '%s' 0123456789ABCDEFGHJKLMNPQRSTUVWXYZ | cut -c$((b % 34 + 1)))"; k=$((k + 2)); done
          [ ${#fresh} = 10 ] || { bad "could not work out the serial for the new model"; return 1; }
          sets PlatformInfo.Generic.SystemSerialNumber "$fresh" || { bad "could not set the serial"; return 1; }
        fi
      fi
      sets PlatformInfo.Generic.SystemProductName "$MODEL_RTX50" || { bad "could not set the model"; return 1; }
      break
    fi
  done

  # a kext of the PC's own build that has code, that the kit neither brings nor knows, and that has no upper limit of
  # its own, stops at macOS 26; the result names each one
  m=$(kv known_27); [ -n "$m" ] || m=0
  if [ "$m" -gt 0 ]; then
    local keep=" " exe
    j=0; while [ "$j" -lt "$m" ]; do keep="$keep$(kv known_27.$j) "; j=$((j + 1)); done
    n=$(kv kexts); j=0; while [ "$j" -lt "$n" ]; do keep="$keep$(kv kexts.$j.name) "; j=$((j + 1)); done
    # a Mac's own hardware kexts the kit names as known to load on macOS 27 (its Ethernet, its processor's power management)
    if [ "$EFIKIND" = mac ]; then n=$(kv known_27_mac) || n=0; case "$n" in ''|*[!0-9]*) n=0;; esac
      j=0; while [ "$j" -lt "$n" ]; do keep="$keep$(kv known_27_mac.$j) "; j=$((j + 1)); done; fi
    # drivers that link against the macOS 27 kernel but have not been proven there are kept on as well (try_27):
    # a laptop without its keyboard, trackpad and battery drivers cannot be used on macOS 27 at all
    n=$(kv try_27) || n=0; case "$n" in ''|*[!0-9]*) n=0;; esac
    j=0; while [ "$j" -lt "$n" ]; do keep="$keep$(kv try_27.$j) "; j=$((j + 1)); done
    n=$(cget Kernel.Add); i=0
    while [ "$i" -lt "$n" ]; do
      name=$(bundle_at "$i"); exe=$(cget "Kernel.Add.$i.ExecutablePath")
      if [ "$(cget "Kernel.Add.$i.Enabled")" = true ] && [ -n "$exe" ] && reaches_27 "$(cget "Kernel.Add.$i.MaxKernel")"; then
        case "$keep" in *" $name "*) ;; *)
          sets "Kernel.Add.$i.MaxKernel" 26.99.99 || { bad "could not limit $name"; return 1; }
          NOT27="$NOT27 $name";; esac
      fi
      i=$((i + 1)); done
  fi

  apply_choices || return 1

  # the system-protection value the reference configuration runs macOS 27 with
  if khas csr_active_config; then
    val=$(kv csr_active_config)
    printf '%s' "$val" | grep -Eq '^[0-9a-f]{8}$' || { bad "bad system-protection value in the kit"; return 1; }
    b=$(printf '%s' "$val" | xxd -r -p | base64) || { bad "could not encode the system-protection value"; return 1; }
    plutil -replace "NVRAM.Add.$NV.csr-active-config" -data "$b" "$AC" 2>/dev/null || plutil -insert "NVRAM.Add.$NV.csr-active-config" -data "$b" "$AC" || { bad "could not set the system-protection value"; return 1; }
  fi

  # The identity as hand-written tables, with this PC's own numbers. OpenCore's automatic mode needs a model it has
  # data for; it has none for an Apple-silicon model name, and the Mac then starts with no Apple identity at all.
  if khas platform; then
    local pf sect xml ser uid mlb rom mdl
    pf=$(kv platform); [ "$pf" = platform.plist ] && [ -f "$KIT/$pf" ] && [ ! -L "$KIT/$pf" ] || { bad "the kit's identity tables are missing"; return 1; }
    ser=$(cget PlatformInfo.Generic.SystemSerialNumber); uid=$(cget PlatformInfo.Generic.SystemUUID)
    mlb=$(cget PlatformInfo.Generic.MLB); rom=$(cget PlatformInfo.Generic.ROM); mdl=$(cget PlatformInfo.Generic.SystemProductName)
    if [ -n "$ser" ] && [ -n "$uid" ]; then
      # a model name has a comma in it ("Mac15,14"), which the general filter does not allow
      safe "$ser" && safe "$uid" && safe "$mlb" && printf '%s' "$mdl" | grep -Eq '^[A-Za-z0-9,]{1,32}$' || { bad "this PC's identity has a value 1401 will not write"; return 1; }
      for sect in DataHub PlatformNVRAM SMBIOS; do
        xml=$(plutil -extract "$sect" xml1 -o - "$KIT/$pf" 2>/dev/null) || { bad "the kit's identity tables have no $sect"; return 1; }
        plutil -replace "PlatformInfo.$sect" -xml "$xml" "$AC" 2>/dev/null || plutil -insert "PlatformInfo.$sect" -xml "$xml" "$AC" || { bad "could not write the $sect table"; return 1; }
      done
      for key in DataHub.SystemSerialNumber PlatformNVRAM.SystemSerialNumber SMBIOS.SystemSerialNumber SMBIOS.ChassisSerialNumber; do
        plutil -extract "PlatformInfo.$key" raw -o - "$AC" >/dev/null 2>&1 && { sets "PlatformInfo.$key" "$ser" || { bad "could not write the serial"; return 1; }; }
      done
      for key in DataHub.SystemUUID PlatformNVRAM.SystemUUID SMBIOS.SystemUUID; do
        plutil -extract "PlatformInfo.$key" raw -o - "$AC" >/dev/null 2>&1 && { sets "PlatformInfo.$key" "$uid" || { bad "could not write the UUID"; return 1; }; }
      done
      for key in PlatformNVRAM.MLB SMBIOS.BoardSerialNumber; do
        plutil -extract "PlatformInfo.$key" raw -o - "$AC" >/dev/null 2>&1 && { sets "PlatformInfo.$key" "$mlb" || { bad "could not write the board serial"; return 1; }; }
      done
      if plutil -extract PlatformInfo.PlatformNVRAM.ROM raw -o - "$AC" >/dev/null 2>&1 && [ -n "$rom" ]; then
        plutil -replace PlatformInfo.PlatformNVRAM.ROM -data "$rom" "$AC" || { bad "could not write the ROM value"; return 1; }
      fi
      for key in DataHub.SystemProductName SMBIOS.SystemProductName SMBIOS.BoardVersion; do
        plutil -extract "PlatformInfo.$key" raw -o - "$AC" >/dev/null 2>&1 && { sets "PlatformInfo.$key" "$mdl" || { bad "could not write the model"; return 1; }; }
      done
      plutil -replace PlatformInfo.Automatic -bool false "$AC" || { bad "could not switch the identity to the tables"; return 1; }
    else
      NOTABLES=1
    fi
  fi

  # nothing that needs Lilu may load before it
  li=$(index_of Lilu.kext) || li=""
  if [ -n "$li" ] && [ "$(cget "Kernel.Add.$li.Enabled")" = true ]; then
    n=$(kv kexts); i=0
    while [ "$i" -lt "$n" ]; do
      if [ "$(kv kexts.$i.needs_lilu)" = true ]; then
        idx=$(index_of "$(kv kexts.$i.name)") || idx=""
        [ -z "$idx" ] || [ "$idx" -gt "$li" ] || [ "$(cget "Kernel.Add.$idx.Enabled")" != true ] || { bad "$(kv kexts.$i.name) would load before Lilu"; return 1; }
      fi
      i=$((i + 1)); done
  fi
  plutil -lint "$AC" >/dev/null || { bad "the changed config is not a valid property list"; return 1; }
}

case "$STEP" in
status)
  ST=$(read_state) || stop "the Golden Gate state file on this partition is not one 1401 wrote"
  ok "Golden Gate state: $ST"; echo "RESULT ok"; exit 0;;

preflight)
  step "Checking this Mac for macOS 27"
  fails=0; check() { if [ "$1" = 0 ]; then ok "$2"; else echo "FAIL $2"; fails=$((fails + 1)); fi; }
  [ -n "$MAJOR" ] || { MAJOR=$(sw_vers -productVersion 2>/dev/null); MAJOR=${MAJOR%%.*}; }
  from_ok; check $? "this Mac runs macOS ${MAJOR:-?}; Golden Gate starts from macOS 15 or 26"
  [ $GPUS_GIVEN = 1 ] || GPUS=$(nvidia_ids)
  hit=""; for g in $GPUS; do g=$(upper "$g"); card_supported "$g" && { hit=$g; break; }; done
  UNTRIED=""; ESPHELP=""
  GFX=""
  if [ -n "$hit" ]; then check 0 "NVIDIA card $(card_name "$hit") ($hit) is one the driver takes"
    card_tried "$hit" || UNTRIED="macOS 27 has not been run on $(card_name "$hit") yet (so far: $(cards_tried)). This is a beta: it may not start"
    GFX=nvidia
  else
    # No NVIDIA card the driver takes: an AMD or Intel chip may still be one macOS 27 can be offered for. A chip on
    # Apple's own driver is preferred over one on a test driver (a Mac with both starts on Apple's).
    GFX=""; CHIP=""
    if [ $DISPLAYS_GIVEN = 0 ] && [ $GPUS_GIVEN = 0 ]; then DISPLAYS=$(display_ids); fi
    if [ $APPLEIDS_GIVEN = 0 ] && [ $GPUS_GIVEN = 0 ]; then APPLEIDS=$(apple_graphics_ids); fi
    for d in $DISPLAYS; do d=$(upper "$d")
      case "$d" in 1002:*|8086:*) ;; *) continue;; esac
      if printf '%s\n' $APPLEIDS | tr '[:lower:]' '[:upper:]' | grep -qx "$d"; then GFX=apple; CHIP=$d; break; fi
      [ -n "$GFX" ] || { GFX=test; CHIP=$d; }
    done
    case "$GFX" in
      apple) what="$(chip_maker "$CHIP") graphics ($CHIP), which Apple's own driver in this macOS runs";;
      test)  what="$(chip_maker "$CHIP") graphics ($CHIP), which 1401's test driver runs";;
    esac
    if [ -z "$GFX" ]; then check 1 "no NVIDIA card the driver takes was found (found:${GPUS:- none}${DISPLAYS:+; other graphics:$DISPLAYS})"
    elif kit_carries "$GFX"; then check 0 "this Mac has $what, and this kit carries macOS 27 graphics for it"
      UNTRIED="macOS 27 has not been started on $(chip_maker "$CHIP") graphics with this kit yet. This is a beta: it may not start"
    else check 1 "this Mac has $what; this kit has no macOS 27 graphics for it yet (it carries: $(kit_paths)). No NVIDIA card the driver takes was found (found:${GPUS:- none})"
    fi
  fi
  [ -z "$GFX" ] || note "graphics path: $GFX"
  # A kind of PC macOS 27 has not been started on yet is said, not refused: every PC that 1401 builds for and the
  # driver runs on under macOS 26 may try it.
  [ -n "$CPUV" ] || CPUV=$(sysctl -n machdep.cpu.vendor 2>/dev/null)
  case "$CPUV" in *AMD*) UNTRIED="${UNTRIED:+$UNTRIED. }macOS 27 with this kit has not been started on a PC with an AMD processor yet";; esac
  [ -n "$LAPTOP" ] || { if ioreg -rc AppleSmartBattery 2>/dev/null | grep -q '"BatteryInstalled" = Yes'; then LAPTOP=yes; else LAPTOP=no; fi; }
  [ "$LAPTOP" != yes ] || UNTRIED="${UNTRIED:+$UNTRIED. }macOS 27 with this kit has not been started on a laptop yet; its built-in screen and its switch between two graphics chips are untried"
  EFIKIND=""
  if [ -f "$C" ] && startup_ok; then
    if [ "$EFIKIND" = mac ]; then check 0 "the startup files at $EFI/OC are a Mac's own OpenCore files (not a 1401 build)"
      UNTRIED="${UNTRIED:+$UNTRIED. }macOS 27 with this kit has not been started on a real Mac yet"
    else check 0 "the startup files at $EFI/OC are a 1401 build"; fi
  else check 1 "the startup files at $EFI/OC are a 1401 build"; fi
  if [ -f "$C" ]; then
    need=$(stage_need_kb); free=$(esp_free_kb); gain=$(esp_old_logs_kb)
    if [ -n "$free" ] && [ "$free" -ge "$need" ]; then check 0 "room on the startup partition: $(( free / 1024 )) MB free, $((need / 1024)) MB needed"
    elif [ -n "$free" ] && [ $((free + gain)) -ge "$need" ]; then
      check 0 "room on the startup partition: $(( free / 1024 )) MB free, $((need / 1024)) MB needed; staging removes old OpenCore start-up logs there ($((gain / 1024)) MB) to make the room"
    else
      check 1 "room on the startup partition: $(( ${free:-0} / 1024 )) MB free, $((need / 1024)) MB needed. This is the small EFI partition OpenCore starts from ($ROOT), not the disk macOS is on"
      ESPHELP="to make room on the startup partition: remove what you do not need from $ROOT (old copies of the EFI folder, another boot loader's files), or put OpenCore on an EFI partition of 200 MB or more. A second macOS 27 copy of EFI/OC is kept beside the macOS 26 one, which is why it needs $((need / 1024)) MB"
    fi
  fi
  [ -n "$DISK_GB" ] || DISK_GB=$(( $(free_kb /System/Volumes/Data) / 1048576 ))
  # What an earlier run already downloaded is on the disk now and is not downloaded again, so its size comes off the
  # room that is still needed. Without this a second try with the downloads kept was refused for the very space the
  # downloads were using. Only plain files in the lay-down's own root-only folder count, and never more than the
  # downloads can be.
  have_gb=0
  if [ -d "$LAYWORK" ] && [ ! -L "$LAYWORK" ] && chain_trusted "$LAYWORK"; then
    have_kb=0
    for f in "$LAYWORK"/UniversalMac_*_Restore.ipsw "$LAYWORK"/Kernel_Debug_Kit_*.dmg; do
      [ -f "$f" ] && [ ! -L "$f" ] || continue
      have_kb=$((have_kb + $(stat -f %z "$f" 2>/dev/null || echo 0) / 1024))
    done
    have_gb=$((have_kb / 1048576)); [ "$have_gb" -le "$DOWNLOAD_GB" ] || have_gb=$DOWNLOAD_GB
  fi
  need_gb=$((MIN_DISK_GB - have_gb))
  # The room is for downloading macOS 27 and laying it down. On a Mac where this app already laid it down (an update
  # to a newer release of this app) neither happens again, and the first such PC was refused for room it did not
  # need. The volumes are asked about only when the room is short, and only a yes from mac27_laid_down skips the
  # room check: anything it cannot decide falls back to the room check as before.
  room=1; [ "${DISK_GB%%.*}" -ge "$need_gb" ] 2>/dev/null && room=0
  if [ $room != 0 ] && mac27_laid_down; then
    check 0 "room for macOS 27: macOS 27 is already on its own volumes, so no download room is needed (${DISK_GB} GB free)"
  else
    check $room "room for macOS 27: ${DISK_GB} GB free, $need_gb GB needed$([ "$have_gb" = 0 ] || echo " ($have_gb GB is already downloaded)")"
  fi
  if ST=$(read_state) && layout_ok "$ST"; then check 0 "Golden Gate state: $ST"; else check 1 "the startup partition matches its Golden Gate record"; fi
  [ -z "$ESPHELP" ] || note "$ESPHELP"
  [ $fails = 0 ] || stop "$fails check(s) failed. Nothing was changed"
  # What the later steps need from this macOS is asked for now, before anything is staged: the system tools, and
  # then the two kit scripts' own dry runs. A failure that is the running system's is said in one fixed sentence.
  system_probe || system_stop "$WHY"
  ok "this macOS has the system tools the later steps use"
  if [ "$(kv laydown.dir)" != "" ]; then
    laydown_or_stop
    # The lay-down runs once per Mac. Where macOS 27 is already on its volumes (an update to a newer release of this
    # app) it is not run again, and its dry run refuses there for the very volumes it made: the first such PC was
    # stopped by that. So the dry run is asked only where the lay-down will really run.
    if mac27_laid_down; then
      ok "macOS 27 is already laid down, so the lay-down step is not asked"
    else
      step "Asking the lay-down step whether it can run here (dry run)"
      run_kit "$LDIR/$linst" --no-user --dry-run
      [ "$RC" != 3 ] || system_stop "$SYSWHY"
      [ "$RC" = 0 ] || stop "the lay-down step refused its dry run; see its lines above. Nothing was changed"
    fi
    if [ -f "$LDIR/make-kernel-collections.sh" ] && [ ! -L "$LDIR/make-kernel-collections.sh" ]; then
      { [ -d "$KCWORK" ] || { mkdir -p "$KCWORK" 2>/dev/null && chmod 755 "$KCWORK"; }; } && kc_folder_trusted || stop "the folder for the kernel collections ($KCWORK) is not one only root can write. Nothing was changed"
      step "Asking the kernel collections step whether it can run here (dry run)"
      run_kit "$LDIR/make-kernel-collections.sh" --out "$KCWORK" --dry-run
      [ "$RC" != 3 ] || system_stop "$SYSWHY"
      [ "$RC" = 0 ] || stop "the kernel collections step refused its dry run; see its lines above. Nothing was changed"
    fi
  fi
  # What passing does not say. macOS 27 with this kit has been started on one desktop PC so far, so on another
  # board or another processor generation it is untried, and so is the model the PC is given for its card.
  note "macOS 27 has been started on one desktop PC so far. On a different board or processor generation it is untried and may not start; Cancel Golden Gate puts the startup files back, and the 1401 USB stick still starts macOS 26"
  [ -z "$UNTRIED" ] || note "$UNTRIED. If macOS 27 does not reach its desktop, start macOS 26 from the 1401 USB stick and press Send logs there: 1401 reads the macOS 27 volume's logs from macOS 26, and that is how the failure reaches us"
  ok "this Mac is ready for Golden Gate"; echo "RESULT ok"; exit 0;;

stage)
  step "Staging the macOS 27 startup files beside the macOS 26 ones"
  state_or_stop
  [ "$ST" = none ] || stop "Golden Gate is already $ST on this partition; cancel it first to stage again"
  startup_ok || stop "the startup files here were not made by 1401. Nothing was changed"
  need=$(stage_need_kb); free=$(esp_free_kb)
  if [ -n "$free" ] && [ "$free" -lt "$need" ]; then
    gain=$(esp_old_logs_kb)
    if [ "$gain" -gt 0 ] && [ $((free + gain)) -ge "$need" ]; then
      esp_remove_old_logs; note "removed old OpenCore start-up logs from the startup partition ($((gain / 1024)) MB); the three newest are kept"
      case "$ESPFREE" in ''|*[!0-9]*) free=$(free_kb "$ROOT");; *) free=$((free + gain));; esac
    fi
  fi
  [ -n "$free" ] && [ "$free" -ge "$need" ] || stop "the startup partition (the small EFI partition OpenCore starts from, $ROOT - not the disk macOS is on) has $(( ${free:-0} / 1024 )) MB free and the macOS 27 copy needs $((need / 1024)) MB. Nothing was changed"
  # the copy is changed in a scratch folder and moved into place in one rename, so a stopped run leaves no half-made folder
  SCR="$EFI/.golden-gate-scratch"; rm -rf "$SCR"
  undo() { rm -rf "$SCR" "$EFI/$STAGED" "$ROOT/$DRIVER"; }
  mkdir "$SCR" && cp -R "$EFI/OC" "$SCR/OC" || { undo; stop "could not copy the startup files. EFI/OC is unchanged"; }
  stage_path
  apply_kit "$SCR/OC" || { undo; stop "the macOS 27 startup files could not be staged ($WHY). EFI/OC is unchanged"; }
  mv "$SCR/OC" "$EFI/$STAGED" || { undo; stop "could not place the staged folder. EFI/OC is unchanged"; }
  rm -rf "$SCR"
  # Neither package is copied to the startup partition: finish runs both from the private copy of the kit and never
  # from this partition, and the driver package (several hundred MB) is larger than a startup partition has room for.
  # An older 1401 left a copy at NullMoth-v3; it is removed.
  rm -rf "$ROOT/$DRIVER"
  DNOTE="not in the kit: finish will refuse until the kit carries a driver package"; DINST=""
  ddir=$(kv driver.dir); dinst=$(kv driver.installer)
  if [ -n "$ddir" ] && [ -n "$dinst" ]; then
    case "$ddir" in */*|.*) undo; stop "the v3 kit's driver entry is not a plain folder and file name. EFI/OC is unchanged";; esac
    case "$dinst" in */*|.*) undo; stop "the v3 kit's driver entry is not a plain folder and file name. EFI/OC is unchanged";; esac
    safe "$ddir" && safe "$dinst" || { undo; stop "the v3 kit's driver entry is not a plain folder and file name. EFI/OC is unchanged"; }
    [ ! -L "$KIT/$ddir" ] && [ -f "$KIT/$ddir/$dinst" ] && [ ! -L "$KIT/$ddir/$dinst" ] || { undo; stop "the v3 kit names a driver installer that is not there. EFI/OC is unchanged"; }
    DNOTE="in the kit with its installer $dinst"; DINST=$dinst
  fi
  SNOTE="not in the kit: finish will refuse until the kit carries a system package"
  sdir=$(kv system.dir); sinst=$(kv system.installer)
  if [ -n "$sdir" ] && [ -n "$sinst" ]; then
    case "$sdir" in */*|.*) undo; stop "the v3 kit's system entry is not a plain folder and file name. EFI/OC is unchanged";; esac
    case "$sinst" in */*|.*) undo; stop "the v3 kit's system entry is not a plain folder and file name. EFI/OC is unchanged";; esac
    safe "$sdir" && safe "$sinst" || { undo; stop "the v3 kit's system entry is not a plain folder and file name. EFI/OC is unchanged"; }
    [ ! -L "$KIT/$sdir" ] && [ -f "$KIT/$sdir/$sinst" ] && [ ! -L "$KIT/$sdir/$sinst" ] || { undo; stop "the v3 kit names a system installer that is not there. EFI/OC is unchanged"; }
    SNOTE="in the kit with its installer $sinst"
  fi
  STATE_KIT=$(kit_id)
  write_state staged "$DNOTE" "$DINST" "$SNOTE" || { undo; stop "could not record the state. EFI/OC is unchanged"; }
  ok "macOS 27 startup files staged at EFI/$STAGED; this Mac still starts from EFI/OC"
  if [ "$EFIKIND" = mac ]; then note "model: this Mac's own (not changed)"
  else note "model: $(plutil -extract PlatformInfo.Generic.SystemProductName raw -o - "$EFI/$STAGED/config.plist" 2>/dev/null)$([ $KITMODEL = 0 ] || echo ' (kept from the kit, as asked)')"; fi
  [ -z "$GFX" ] || note "graphics path: $GFX"
  for k in $NOT27; do note "$k was never run on macOS 27: it stays on macOS 26 and does not load on macOS 27"; done
  [ -z "$TRY27" ] || note "not proven on macOS 27 yet, and on:$TRY27. If macOS 27 does not reach its desktop, start macOS 26 and turn them off there (Drivers on macOS 27), then send the logs"
  [ -z "$OFF27" ] || note "off on macOS 27 by your choice:$OFF27"
  [ -z "$ON27" ] || note "on for macOS 27 by your choice:$ON27"
  [ $((PATCH_ON + PATCH_OWN)) = 0 ] || note "kernel patches for macOS 27: $PATCH_ON carried as they are (checked against this macOS 27 kernel)$([ $PATCH_OWN = 0 ] || echo ", $PATCH_OWN replaced by the kit's own")"
  [ $PATCH_OFF = 0 ] || note "$PATCH_OFF kernel patch(es) of this PC were not checked against macOS 27 and stay off there: $PATCH_OFF_NAMES"
  [ $NOTABLES = 0 ] || [ "$EFIKIND" = mac ] || note "this PC's config has no serial number and UUID of its own, so the Mac identity tables were not written"
  note "driver package: $DNOTE"
  note "system package: $SNOTE"
  note "next: get macOS 27 from Apple, then make the staged files the default when you are ready"
  echo "RESULT ok"; exit 0;;

activate)
  [ $CONFIRM = 1 ] || stop "the macOS 27 startup files become the default only when you confirm it. Nothing was changed"
  state_or_stop
  [ "$ST" = staged ] || stop "there are no staged macOS 27 startup files to make the default (state: $ST)"
  step "Making the macOS 27 startup files the default"
  mv "$EFI/OC" "$EFI/$KEPT" || stop "could not set macOS 26's startup files aside. Nothing was changed"
  mv "$EFI/$STAGED" "$EFI/OC" || { mv "$EFI/$KEPT" "$EFI/OC"; stop "the staged files could not be made the default; macOS 26's startup files are back"; }
  write_state active "$(plutil -extract driver raw -o - "$EFI/$STATE" 2>/dev/null)" "$(plutil -extract driver_installer raw -o - "$EFI/$STATE" 2>/dev/null)" "$(plutil -extract system raw -o - "$EFI/$STATE" 2>/dev/null)" \
    || { mv "$EFI/OC" "$EFI/$STAGED"; mv "$EFI/$KEPT" "$EFI/OC"; stop "could not record the change; macOS 26's startup files are back"; }
  ok "this Mac now starts from the macOS 27 startup files; macOS 26's are kept at EFI/$KEPT"
  # The boot picker starts the startup disk by itself after a few seconds. Until this step set it, that was still
  # the macOS this runs on, which gets no picture from the macOS 27 startup files: on the first install made this
  # way the picker started the wrong system twice. The system volume is named by device: on a macOS 27 volume the
  # form that names a mounted folder fails (it wants a file an Apple silicon system does not carry). Only with the
  # system's own disk tool and as root, never in a test run: a test once ran the system's own bless on the machine
  # it was run on, where it can wait for ever.
  if [ "$DISKUTIL" = /usr/sbin/diskutil ] && [ "$(id -u)" = 0 ]; then
    sdu=$(sed -n 's/^system //p' "$GGDIR/macos27-volumes" 2>/dev/null | head -n 1); sdd=""
    case "$sdu" in ????????-????-????-????-????????????) sdd=$("$DISKUTIL" info "$sdu" 2>/dev/null | awk -F': *' '/Device Identifier/ {print $2; exit}');; esac
    case "$sdd" in
      disk[0-9]*s[0-9]*)
        if /usr/sbin/bless --device "/dev/$sdd" --setBoot >/dev/null 2>&1; then ok "the boot picker now starts macOS 27 by itself"
        else note "the boot picker's own choice could not be set: choose the macOS 27 volume in it and hold Control while pressing Return, which keeps the choice"; fi;;
      *) note "the macOS 27 volume was not found to make it the boot picker's own choice: choose it in the picker and hold Control while pressing Return, which keeps the choice";;
    esac
  fi
  note "keep the 1401 USB stick: it still starts macOS 26. Cancel Golden Gate from macOS 26 puts everything back"
  echo "RESULT ok"; exit 0;;

downloads)
  b=$(dl_bytes)
  if [ "$b" = 0 ]; then ok "nothing is kept from an earlier try"; else ok "kept from an earlier try: $(gb1 "$b") GB of downloads (they are checked again before they are used)"; fi
  echo "RESULT ok"; exit 0;;

clear-downloads)
  [ $CONFIRM = 1 ] || stop "clearing the downloads is done only with --confirm. Nothing was changed"
  # The lay-down's folder also holds its record of the volumes of a macOS 27 it has not finished. Without it they
  # could no longer be told from anyone else's, so that system is removed first.
  if [ -f "$LAYWORK/volumes.created" ] && [ ! -e "$LAYWORK/volumes.complete" ]; then
    stop "an unfinished macOS 27 from an earlier try is still on this disk. Press Remove macOS 27 first, then clear the downloads. Nothing was removed"
  fi
  step "Removing what Golden Gate keeps downloaded"
  b=$(dl_bytes)
  for d in "$LAYWORK" "$KCWORK"; do
    [ -e "$d" ] || [ -L "$d" ] || continue
    [ -d "$d" ] && [ ! -L "$d" ] || stop "$d is not a folder of its own. Nothing was removed"
    chain_trusted "$(dirname "$d")" || stop "the folder above $d is not one only root can write. Nothing was removed"
    # an image from an interrupted try can still be open below it; removing under an open image is never tried
    if mount | grep -F " on $d/" >/dev/null 2>&1; then stop "an image below $d is still open. Restart this Mac and try again. Nothing was removed"; fi
  done
  for d in "$LAYWORK" "$KCWORK"; do
    [ -d "$d" ] || continue
    rm -rf "$d" || stop "could not remove $d"
  done
  rm -f "$GGDIR/kernel-collections.sha256"
  ok "removed $(gb1 "$b") GB. The next Prepare for Golden Gate downloads what it needs again"
  echo "RESULT ok"; exit 0;;

rollback|cancel|remove)
  # Going back also gives the boot picker its old choice: the macOS this runs on. Left on macOS 27 it would start
  # that system from startup files that are no longer the macOS 27 ones. Best effort, and never in a test run.
  # A removal that has not been confirmed changes nothing at all, this included.
  if [ "$DISKUTIL" = /usr/sbin/diskutil ] && [ "$(id -u)" = 0 ] && { [ "$STEP" != remove ] || [ $CONFIRM = 1 ]; }; then /usr/sbin/bless --mount / --setBoot >/dev/null 2>&1 || true; fi
  if [ "$STEP" = remove ]; then
    [ $CONFIRM = 1 ] || stop "removing macOS 27 is done only with --confirm. Nothing was changed"
    from_ok || stop "macOS 27 is removed from macOS 15 or 26; this Mac runs macOS $MAJOR. Nothing was changed"
    # The macOS 27 this app laid down is found by the record the install step wrote and by nothing else. Both volumes
    # are checked here, before the startup files or either volume is touched, and a volume of the macOS that is
    # running can never be one of them.
    # A lay-down that was cut off has not reached that record yet; the lay-down's own record of the volumes it
    # made (in its work folder, written as it makes them) names them then, and can hold one volume only.
    rec="$GGDIR/macos27-volumes"; lrec="$LAYWORK/volumes.created"; grp=""; found=""; su=""; du=""
    uuid_ok() { printf '%s\n' "$1" | grep -Eq '^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$'; }
    if [ -f "$rec" ] && [ ! -L "$rec" ]; then
      chain_trusted "$GGDIR" || stop "the folder of Golden Gate's records ($GGDIR) is not one only root can write. Nothing was changed"
      su=$(sed -n 's/^system //p' "$rec" | head -n 1); du=$(sed -n 's/^data //p' "$rec" | head -n 1)
      uuid_ok "$su" && uuid_ok "$du" && [ "$su" != "$du" ] || stop "the record of the macOS 27 volumes is not one this app wrote. Nothing was changed"
    elif [ -f "$lrec" ] && [ ! -L "$lrec" ] && [ -d "$LAYWORK" ] && [ ! -L "$LAYWORK" ]; then
      chain_trusted "$LAYWORK" || stop "the folder of the lay-down ($LAYWORK) is not one only root can write. Nothing was changed"
      su=$(awk '$1 == "system" {print $3; exit}' "$lrec"); du=$(awk '$1 == "data" {print $3; exit}' "$lrec")
      { [ -n "$su" ] || [ -n "$du" ]; } && { [ -z "$su" ] || uuid_ok "$su"; } && { [ -z "$du" ] || uuid_ok "$du"; } && [ "$su" != "$du" ] \
        || stop "the lay-down's record of its volumes is not one this app wrote. Nothing was changed"
      rec=$lrec
    else rec=""; fi
    if [ -n "$rec" ]; then
      ri=$("$DISKUTIL" info -plist / 2>/dev/null)
      here=$(vfield "$ri" APFSContainerReference); rootu=$(vfield "$ri" VolumeUUID); rootg=$(vfield "$ri" APFSVolumeGroupID)
      [ -n "$here" ] || stop "the disk this macOS runs from could not be read. Nothing was changed"
      datau=$(vfield "$("$DISKUTIL" info -plist /System/Volumes/Data 2>/dev/null)" VolumeUUID)
      for u in $su $du; do
        vi=$("$DISKUTIL" info -plist "$u" 2>/dev/null) || vi=""
        [ -n "$vi" ] || continue
        [ "$(vfield "$vi" FilesystemType)" = apfs ] && [ "$(vfield "$vi" APFSContainerReference)" = "$here" ] \
          || stop "a recorded macOS 27 volume is not an APFS volume on the disk this macOS runs from. Nothing was changed"
        g=$(vfield "$vi" APFSVolumeGroupID)
        case "$(upper "$u")" in "$(upper "${rootu:-x}")"|"$(upper "${datau:-x}")") stop "a recorded volume is one of the macOS that is running. Nothing was changed";; esac
        [ -z "$rootg" ] || [ "$(upper "$g")" != "$(upper "$rootg")" ] || stop "a recorded volume belongs to the macOS that is running. Nothing was changed"
        case "$(vfield "$vi" MountPoint)" in /|/System/Volumes/*) stop "a recorded volume is in use by the macOS that is running. Nothing was changed";; esac
        [ -n "$grp" ] || grp=$g
        found="$found $u"
      done
    fi
  fi
  state_or_stop
  if [ "$ST" = active ]; then
    step "Putting macOS 26's startup files back"
    mv "$EFI/OC" "$EFI/$STAGED" || stop "could not set the macOS 27 startup files aside. Nothing was changed"
    mv "$EFI/$KEPT" "$EFI/OC" || { mv "$EFI/$STAGED" "$EFI/OC"; stop "macOS 26's startup files could not be put back; the partition is as it was"; }
    write_state staged "$(plutil -extract driver raw -o - "$EFI/$STATE" 2>/dev/null)" "$(plutil -extract driver_installer raw -o - "$EFI/$STATE" 2>/dev/null)" "$(plutil -extract system raw -o - "$EFI/$STATE" 2>/dev/null)" \
      || note "macOS 26's startup files are back, but the record could not be updated; run Cancel again"
    ok "this Mac starts from macOS 26's startup files again"; ST=staged
  elif [ "$STEP" = rollback ]; then
    stop "macOS 26's startup files are already the default (state: $ST)"
  fi
  if [ "$STEP" != rollback ] && [ "$ST" = staged ]; then
    step "Removing the staged macOS 27 files"
    rm -rf "$EFI/$STAGED" "$ROOT/$DRIVER" && rm -f "$EFI/$STATE" || stop "could not remove the staged files"
    ok "Golden Gate cancelled: the startup partition is as it was"
  elif [ "$STEP" != rollback ]; then ok "Golden Gate was not started on this partition - nothing to cancel"; fi
  [ "$STEP" = remove ] || { echo "RESULT ok"; exit 0; }
  # Removing macOS 27 also takes the driver choices and their log off the startup partition: they are about a
  # macOS 27 that is no longer there. Cancel keeps them, because an update cancels and stages again.
  rm -f "$EFI/$CHOICES" "$EFI/$DRVLOG" "$EFI/$CHOICES.old" 2>/dev/null

  # remove: with the startup files back, the macOS 27 this app laid down goes too (checked above, before any change)
  if [ -z "$rec" ]; then
    ok "no macOS 27 laid down by this app is recorded on this Mac: no volume was removed"
    echo "RESULT ok"; exit 0
  fi
  step "Removing the macOS 27 volumes"
  for u in $found; do
    # unmounted first and the disk settled, so that nothing of the volume is still in use when it goes
    "$DISKUTIL" unmount force "$u" >/dev/null 2>&1
    sync
    "$DISKUTIL" apfs deleteVolume "$u" >/dev/null 2>&1 || stop "volume $u could not be removed. The startup files are back as they were; restart this Mac and try again"
  done
  # the folder Preboot holds for that volume group, never the running system's
  case "$grp" in ????????-????-????-????-????????????)
    if [ "$(upper "$grp")" != "$(upper "${rootg:-x}")" ] && [ -d "$PREBOOT/$grp" ] && [ ! -L "$PREBOOT/$grp" ]; then rm -rf "$PREBOOT/$grp" || note "the Preboot folder of the removed system could not be removed; it is unused"; fi;; esac
  rm -f "$GGDIR/macos27-volumes" "$LAYWORK/volumes.created" "$LAYWORK/volumes.complete"
  if [ -n "$found" ]; then ok "macOS 27 and its volumes are removed. The macOS you use now was not touched"
  else ok "the recorded macOS 27 volumes were already gone; their record is removed"; fi
  [ "$(dl_bytes)" = 0 ] || note "the downloads are kept ($(gb1 "$(dl_bytes)") GB); Clear downloads removes them"
  echo "RESULT ok"; exit 0;;

kit-current)
  # Whether the macOS 27 startup files on this partition were staged from the kit given. The one-button run asks
  # this on a Mac that is already staged or active: after an update of the app the kit is a newer one, and without
  # this question the startup files of the older kit stayed in place for good while only the packages were renewed.
  state_or_stop
  [ "$ST" != none ] || { note "no macOS 27 startup files are staged on this partition"; echo "RESULT stop"; exit 1; }
  have=$(plutil -extract kit_md5 raw -o - "$EFI/$STATE" 2>/dev/null); want=$(kit_id)
  if [ -n "$want" ] && [ "$have" = "$want" ]; then ok "the macOS 27 startup files were staged from this kit"; echo "RESULT ok"; exit 0; fi
  note "the macOS 27 startup files were staged from another kit"; echo "RESULT stop"; exit 1;;

refresh)
  # The macOS 27 startup files, made again from this kit on a Mac that already starts from them. It is what an update
  # of the app run on macOS 27 itself needs: the packages are renewed by the local step, and without this the older
  # kit's startup files (its platform driver, its kernel patches) stayed for good. The new set is built the way the
  # stage step builds it, from the macOS 26 files kept at EFI/OC-26, in a scratch folder; the set in use is replaced
  # by two renames only after the new one is complete, and goes back if the second rename or the record fails.
  [ $CONFIRM = 1 ] || stop "the macOS 27 startup files are renewed only when you confirm it. Nothing was changed"
  state_or_stop
  [ "$ST" = active ] || stop "this Mac does not start from the macOS 27 startup files (state: $ST), so there is nothing to renew. Nothing was changed"
  have=$(plutil -extract kit_md5 raw -o - "$EFI/$STATE" 2>/dev/null); want=$(kit_id)
  if [ -n "$want" ] && [ "$have" = "$want" ]; then ok "the macOS 27 startup files are already this kit's"; echo "RESULT ok"; exit 0; fi
  step "Making the macOS 27 startup files again from this kit"
  C="$EFI/$KEPT/config.plist"
  startup_ok || stop "the macOS 26 startup files kept at EFI/$KEPT were not made by 1401. Nothing was changed"
  need=$(stage_need_kb); free=$(esp_free_kb)
  if [ -n "$free" ] && [ "$free" -lt "$need" ]; then
    gain=$(esp_old_logs_kb)
    if [ "$gain" -gt 0 ] && [ $((free + gain)) -ge "$need" ]; then
      esp_remove_old_logs; note "removed old OpenCore start-up logs from the startup partition ($((gain / 1024)) MB); the three newest are kept"
      case "$ESPFREE" in ''|*[!0-9]*) free=$(free_kb "$ROOT");; *) free=$((free + gain));; esac
    fi
  fi
  [ -n "$free" ] && [ "$free" -ge "$need" ] || stop "the startup partition (the small EFI partition OpenCore starts from, $ROOT - not the disk macOS is on) has $(( ${free:-0} / 1024 )) MB free and the new macOS 27 copy needs $((need / 1024)) MB. Nothing was changed"
  SCR="$EFI/.golden-gate-scratch"; rm -rf "$SCR" "$EFI/$RENEWED"
  mkdir "$SCR" && cp -R "$EFI/$KEPT" "$SCR/OC" || { rm -rf "$SCR"; stop "could not copy the startup files. EFI/OC is unchanged"; }
  stage_path
  # Which graphics path a PC takes is read from the macOS that is running. For an NVIDIA card it is the card alone
  # that decides, so macOS 27 gives the answer macOS 26 gave. For the other paths it is not known to, so from
  # macOS 27 they are refused, never guessed.
  [ "$GFX" = nvidia ] || from_ok || { rm -rf "$SCR"; stop "on this PC's graphics the startup files are renewed from macOS 26: start macOS 26 and update there. Nothing was changed"; }
  apply_kit "$SCR/OC" || { rm -rf "$SCR"; stop "the macOS 27 startup files could not be made again ($WHY). EFI/OC is unchanged"; }
  mv "$EFI/OC" "$EFI/$RENEWED" || { rm -rf "$SCR"; stop "could not set the startup files in use aside. Nothing was changed"; }
  mv "$SCR/OC" "$EFI/OC" || { mv "$EFI/$RENEWED" "$EFI/OC"; rm -rf "$SCR"; stop "the new startup files could not be put in place; the ones in use are back"; }
  STATE_KIT=$want
  write_state active "$(plutil -extract driver raw -o - "$EFI/$STATE" 2>/dev/null)" "$(plutil -extract driver_installer raw -o - "$EFI/$STATE" 2>/dev/null)" "$(plutil -extract system raw -o - "$EFI/$STATE" 2>/dev/null)" \
    || { rm -rf "$EFI/OC"; mv "$EFI/$RENEWED" "$EFI/OC"; rm -rf "$SCR"; stop "could not record the change; the startup files in use are back"; }
  rm -rf "$EFI/$RENEWED" "$SCR"
  ok "the macOS 27 startup files are now this kit's; macOS 26's are still kept at EFI/$KEPT. Restart to use them"
  [ $((PATCH_ON + PATCH_OWN)) = 0 ] || note "kernel patches for macOS 27: $PATCH_ON carried as they are$([ $PATCH_OWN = 0 ] || echo ", $PATCH_OWN replaced by the kit's own")"
  echo "RESULT ok"; exit 0;;

drivers)
  # The drivers of this PC's own build on macOS 27: which are on, which are off, and the user's own choices. Without
  # an option it lists. --off NAME stops one driver at macOS 26; --off unproven does that for every driver that is on
  # without having been proven on macOS 27 (the way back into macOS 27 after a start that did not reach the
  # desktop); --on NAME takes a choice back, or turns on a driver the kit only allows to be tried. The choice is
  # kept on the startup partition, so staging again or renewing the startup files keeps it, and every change is
  # written to a log there that the log collector sends.
  state_or_stop
  [ "$ST" != none ] || stop "there are no macOS 27 startup files on this partition yet. Nothing was changed"
  if [ "$ST" = active ]; then T=OC; else T=$STAGED; fi
  AC="$EFI/$T/config.plist"; [ -f "$AC" ] || stop "the macOS 27 startup files have no config. Nothing was changed"
  if [ -z "$DRVOFF" ] && [ -z "$DRVON" ]; then
    n=$(cget Kernel.Add) || n=0; i=0
    while [ "$i" -lt "$n" ]; do
      name=$(bundle_at "$i")
      if [ "$(cget "Kernel.Add.$i.Enabled")" = true ] && [ -n "$(cget "Kernel.Add.$i.ExecutablePath")" ] && ! kit_brings "$name"; then
        if reaches_27 "$(cget "Kernel.Add.$i.MaxKernel")"; then on=on; else on=off; fi
        verb=$(choice_of "$name")
        if in_kit_list try_27 "$name"; then kind="not proven on macOS 27"
        elif in_kit_list may_27 "$name"; then kind="held back, may be tried"
        elif in_kit_list known_27 "$name"; then kind="known on macOS 27"
        else kind="never run on macOS 27"; fi
        echo "DRIVER $name|$on|$kind|${verb:+your choice: $verb}"
      fi
      i=$((i + 1)); done
    echo "RESULT ok"; exit 0
  fi
  [ $CONFIRM = 1 ] || stop "a driver is turned on or off only when you confirm it. Nothing was changed"
  [ -z "$DRVOFF" ] || [ -z "$DRVON" ] || stop "turn drivers on or off, not both at once. Nothing was changed"
  want="$DRVOFF$DRVON"; safe "$want" || stop "that is not a driver's name. Nothing was changed"
  names=""
  if [ "$DRVOFF" = unproven ]; then
    n=$(cget Kernel.Add) || n=0; i=0
    while [ "$i" -lt "$n" ]; do
      name=$(bundle_at "$i")
      if [ "$(cget "Kernel.Add.$i.Enabled")" = true ] && [ -n "$(cget "Kernel.Add.$i.ExecutablePath")" ] && ! kit_brings "$name" \
         && reaches_27 "$(cget "Kernel.Add.$i.MaxKernel")" && { in_kit_list try_27 "$name" || in_kit_list may_27 "$name"; }; then names="$names$name
"; fi
      i=$((i + 1)); done
    [ -n "$names" ] || { ok "no driver is on for macOS 27 without having been proven there"; echo "RESULT ok"; exit 0; }
  else
    index_of "$want" >/dev/null || stop "this PC's startup files have no driver named $want. Nothing was changed"
    ! kit_brings "$want" || stop "$want is part of macOS 27 support itself and cannot be turned off here. Nothing was changed"
    if [ -n "$DRVON" ] && [ -z "$(choice_of "$want")" ] && ! in_kit_list may_27 "$want"; then
      stop "$want is not a driver that may be turned on for macOS 27: it was never run there, or it needs something macOS 27 does not have. Nothing was changed"; fi
    names="$want
"
  fi
  # the choices file is written first as a copy, then the config as a copy; both go into place only when both are whole
  CF="$EFI/$CHOICES"; [ ! -L "$CF" ] || stop "the record of driver choices is a link. Nothing was changed"
  { [ ! -f "$CF" ] || cat "$CF"; } > "$CF.new" || stop "the record of driver choices could not be written. Nothing was changed"
  while IFS= read -r nm; do [ -n "$nm" ] || continue
    awk -F'\t' -v k="$nm" '$2 != k' "$CF.new" > "$CF.new2" && mv -f "$CF.new2" "$CF.new" || { rm -f "$CF.new" "$CF.new2"; stop "the record of driver choices could not be written. Nothing was changed"; }
    if [ -n "$DRVOFF" ]; then printf 'off\t%s\n' "$nm" >> "$CF.new"
    elif in_kit_list may_27 "$nm"; then printf 'on\t%s\n' "$nm" >> "$CF.new"; fi
  done <<EOT
$names
EOT
  LIVE=$AC; cp "$LIVE" "$LIVE.new" || { rm -f "$CF.new"; stop "the config could not be copied. Nothing was changed"; }
  OLDCF="$EFI/$CHOICES.old"; rm -f "$OLDCF"; [ ! -f "$CF" ] || cp "$CF" "$OLDCF"
  mv -f "$CF.new" "$CF" || { rm -f "$LIVE.new" "$CF.new"; stop "the record of driver choices could not be put in place. Nothing was changed"; }
  AC="$LIVE.new"
  if apply_choices && plutil -lint "$AC" >/dev/null 2>&1 && mv -f "$AC" "$LIVE"; then rm -f "$OLDCF"
  else rm -f "$LIVE.new"; if [ -f "$OLDCF" ]; then mv -f "$OLDCF" "$CF"; else rm -f "$CF"; fi
    stop "the config could not be changed ($WHY); the choices are as they were. Nothing was changed"; fi
  while IFS= read -r nm; do [ -n "$nm" ] || continue
    if [ -n "$DRVOFF" ]; then ok "$nm is off for macOS 27 (it still loads on macOS 26)"; drv_log "off $nm (macOS 27 startup files: $ST)"
    else ok "$nm is on for macOS 27"; drv_log "on $nm (macOS 27 startup files: $ST)"; fi
  done <<EOT
$names
EOT
  note "restart into macOS 27 to use this. To report a driver that stopped macOS 27, press Send logs from macOS 26: the report carries this record and what macOS 27 left behind"
  echo "RESULT ok"; exit 0;;

laid)
  # Whether the volumes the install step recorded are there and hold macOS 27. The one-button run asks this so that
  # a second run does not lay macOS 27 down again. The install step leaves both volumes unmounted, so they are
  # mounted here to be read: without that a finished lay-down looked like none, and the second run stopped on it.
  if mac27_volumes mount; then
    case "$(plutil -extract ProductVersion raw -o - "$SYS/System/Library/CoreServices/SystemVersion.plist" 2>/dev/null)" in
      27.*) ok "macOS 27 is already on its own volumes"; echo "RESULT ok"; exit 0;; esac
  fi
  note "macOS 27 is not laid down yet"; echo "RESULT stop"; exit 1;;

installer)
  # macOS 27 goes on its own volumes beside macOS 26, laid down by the kit's script from Apple's restore image (Apple's
  # installer does not run on an Intel PC). The script's own dry run goes first; a refusal there changes nothing.
  # By default the new system has no account and starts at Apple's Setup Assistant, like a new Mac.
  from_26_or_stop "macOS 27 is laid down"
  laydown_or_stop
  [ -z "$ACCOUNT" ] || printf '%s\n' "$ACCOUNT" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' || stop "the account to bring over has a name this step will not pass on. Nothing was changed"
  if [ -n "$ACCOUNT" ]; then set -- --user "$ACCOUNT"; else set -- --no-user; fi
  # The size the user chose for macOS 27, when they chose one: the system itself is a fixed SYSTEM_GB, and the rest is
  # the most its data volume may grow to. Without a choice it shares the disk's free space with this macOS.
  if [ -n "${SIZE_GB:-}" ]; then
    printf '%s' "$SIZE_GB" | grep -Eq '^[0-9]{2,4}$' && [ "$SIZE_GB" -ge "$SIZE_MIN_GB" ] && [ "$SIZE_GB" -le 4096 ] \
      || stop "the size for macOS 27 must be a whole number of GB, $SIZE_MIN_GB or more. Nothing was changed"
    set -- "$@" --data-quota-gb $((SIZE_GB - SYSTEM_GB))
  fi
  if [ -f "$KCWORK/BootKernelExtensions.kc" ] && [ -f "$KCWORK/SystemKernelExtensions.kc" ]; then
    # only the two files the collections step made, in a folder nobody but root could have written since
    kc_folder_trusted || stop "the folder with the kernel collections ($KCWORK) is not one only root can write. Nothing was changed"
    [ ! -L "$KCWORK/BootKernelExtensions.kc" ] && [ ! -L "$KCWORK/SystemKernelExtensions.kc" ] && [ -f "$GGDIR/kernel-collections.sha256" ] && [ ! -L "$GGDIR/kernel-collections.sha256" ] \
      && [ "$(kc_sums)" = "$(cat "$GGDIR/kernel-collections.sha256")" ] \
      || stop "the kernel collections in $KCWORK are not the ones the collections step made (their checksums are not the recorded ones): make them again. Nothing was changed"
    set -- "$@" --kernel-collections "$KCWORK"
  elif [ -f "$LDIR/make-kernel-collections.sh" ]; then stop "the kernel collections have not been made yet: make them first (the step before this one); macOS 27 cannot start without them. Nothing was changed"
  else note "this kit cannot make kernel collections: macOS 27 will be laid down complete except for them, and cannot start until they are placed"; fi
  step "Checking that macOS 27 can be laid down (dry run)"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  run_kit "$LDIR/$linst" "$@" --dry-run
  [ "$RC" != 3 ] || system_stop "$SYSWHY"
  [ "$RC" = 0 ] || stop "the lay-down step refused its dry run. Nothing was changed"
  step "Laying macOS 27 down on its own volumes (downloads Apple's restore image, about 26 GB)"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  # The real run's lines are also kept on their own, beside the step log (the newest run only, its last 1 MB), and
  # a copy goes onto the new data volume, so that what laid a system down can be read from either side.
  LAYLOG="$GGDIR/laydown.log"; [ -w "$GGDIR" ] || stop "the folder for Golden Gate's records ($GGDIR) cannot be written. Nothing was changed"
  LAYOUT="$PRIV/laydown-run.txt"
  /bin/bash "$LDIR/$linst" "$@" --apply 2>&1 | tee "$LAYOUT"; rc=${PIPESTATUS[0]}
  if [ "$LAYLOG" != /dev/null ]; then tail -c 1048576 "$LAYOUT" > "$LAYLOG.cap" 2>/dev/null && mv -f "$LAYLOG.cap" "$LAYLOG"; fi
  [ "$rc" != 3 ] || system_stop "$(sed -n 's/^SYSTEM: //p' "$LAYOUT" | tail -n 1)"
  [ "$rc" = 0 ] || stop "the lay-down step stopped; see its lines above. This macOS and its volumes are untouched"
  # The two volumes it made are recorded by their identifiers: the lay-down's last line names their devices, and
  # diskutil gives each device's volume identifier. Every later step finds macOS 27 through this record alone.
  sv=$(sed -n "s/^OK  *macOS .* is on '.*' (\\(disk[0-9]*s[0-9]*\\)) with data volume '.*' (\\(disk[0-9]*s[0-9]*\\)), group .*/\\1/p" "$LAYOUT" | tail -n 1)
  dv=$(sed -n "s/^OK  *macOS .* is on '.*' (\\(disk[0-9]*s[0-9]*\\)) with data volume '.*' (\\(disk[0-9]*s[0-9]*\\)), group .*/\\2/p" "$LAYOUT" | tail -n 1)
  su=$(vfield "$("$DISKUTIL" info -plist "${sv:-none}" 2>/dev/null)" VolumeUUID); du=$(vfield "$("$DISKUTIL" info -plist "${dv:-none}" 2>/dev/null)" VolumeUUID)
  [ -n "$su" ] && [ -n "$du" ] || stop "macOS 27 was laid down, but its two volumes could not be read back from the lay-down's last line; the later steps cannot find it. Send the logs"
  printf 'system %s\ndata %s\n' "$su" "$du" > "$GGDIR/macos27-volumes.new" && mv -f "$GGDIR/macos27-volumes.new" "$GGDIR/macos27-volumes" \
    || stop "macOS 27 was laid down, but the record of its volumes could not be written in $GGDIR"
  # a copy of the lay-down's lines goes onto the new data volume, written as carefully as anything root puts there
  if mac27_volumes mount && [ "$LAYLOG" != /dev/null ]; then put_on_data "$LAYLOG" Library/NullMoth/golden-gate/laydown.log || note "the lay-down's log could not be copied onto the new data volume; it is in $LAYLOG"; fi
  ok "macOS 27 is on its own volumes. Next: Set up macOS 27 (the system package and the driver), before its first start"
  echo "RESULT ok"; exit 0;;

collections)
  # The Intel kernel collections for macOS 27, made by the kit's maker (Apple ships none): its dry run, then its
  # real run, into a folder only root can write. Both files must be there afterwards; the install step hands the
  # folder to the lay-down. A kit without the maker stops here.
  from_26_or_stop "the kernel collections are made"
  laydown_or_stop
  KM="$LDIR/make-kernel-collections.sh"
  [ -f "$KM" ] && [ ! -L "$KM" ] || stop "this v3 kit cannot make the Intel kernel collections for macOS 27 yet. Nothing was changed"
  # The folder is one only root can write, all the way up: what is left in it is handed to the lay-down as the
  # kernel macOS 27 starts from. A folder someone else made or could write is refused, never used.
  # (made here when it is not there; one that is already there is judged as it is, never adjusted to pass)
  [ -d "$KCWORK" ] || { mkdir -p "$KCWORK" 2>/dev/null && chmod 755 "$KCWORK"; } || stop "could not make the folder for the kernel collections ($KCWORK). Nothing was changed"
  kc_folder_trusted || stop "the folder for the kernel collections ($KCWORK) is not one only root can write. Nothing was changed"
  step "Checking that the kernel collections can be made (dry run)"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  run_kit "$KM" --out "$KCWORK" --dry-run
  [ "$RC" != 3 ] || system_stop "$SYSWHY"
  [ "$RC" = 0 ] || stop "the kernel collections maker refused its dry run. Nothing was changed"
  step "Making the Intel kernel collections for macOS 27"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  run_kit "$KM" --out "$KCWORK" --apply
  [ "$RC" != 3 ] || system_stop "$SYSWHY"
  [ "$RC" = 0 ] || stop "the kernel collections could not be made; see the lines above"
  [ -f "$KCWORK/BootKernelExtensions.kc" ] && [ ! -L "$KCWORK/BootKernelExtensions.kc" ] && [ -f "$KCWORK/SystemKernelExtensions.kc" ] && [ ! -L "$KCWORK/SystemKernelExtensions.kc" ] \
    || stop "the maker finished without leaving both kernel collections in $KCWORK"
  # their checksums are recorded now and asked for again by the install step, so that it hands over these two files
  # and nothing put there since (the maker itself only finishes on the two known collections)
  kc_folder_trusted && kc_sums > "$GGDIR/kernel-collections.sha256.new" && [ -s "$GGDIR/kernel-collections.sha256.new" ] \
    && mv -f "$GGDIR/kernel-collections.sha256.new" "$GGDIR/kernel-collections.sha256" || stop "the kernel collections were made, but their checksums could not be recorded in $GGDIR"
  ok "the kernel collections are in $KCWORK"
  echo "RESULT ok"; exit 0;;

finish)
  # Hands over to the kit's system installer and then its v3 driver installer, which run from macOS 26 against the
  # macOS 27 volumes. Both dry runs go first and a refusal in either stops before anything is changed.
  state_or_stop
  # Staged is enough: the packages go on before the startup files are switched, so that macOS 27 never starts bare.
  [ "$ST" = staged ] || [ "$ST" = active ] || stop "the macOS 27 startup files are not staged yet (state: $ST). Nothing was changed"
  from_26_or_stop "the macOS 27 driver is set up"
  # The installers and their payloads are run from the private copy of the trusted kit. The copy on the startup
  # partition is never run: that partition has no owners or permissions, so anything on it could have been changed.
  packages_or_stop
  mac27_volumes mount || stop "$WHY. Nothing was changed"
  case "$(plutil -extract ProductVersion raw -o - "$SYS/System/Library/CoreServices/SystemVersion.plist" 2>/dev/null)" in 27.*) ;;
    *) stop "the volume this app laid down does not hold macOS 27. Nothing was changed";; esac
  [ -d "$DATA/Library" ] && [ ! -L "$DATA/Library" ] || stop "the macOS 27 data volume ($DATA) has no Library folder of its own. Nothing was changed"
  owners_or_stop
  step "Checking the macOS 27 system install (dry run)"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  /bin/bash "$SPAY/$sinst" --payload "$SPAY" --system "$SYS" --data "$DATA" --esp "$ROOT" --dry-run || stop "the v3 system installer refused its dry run. Nothing was changed"
  step "Checking the macOS 27 driver install (dry run)"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  /bin/bash "$PAY/$inst" --payload "$PAY" --system "$SYS" --data "$DATA" --esp "$ROOT" --dry-run || stop "the v3 driver installer refused its dry run. Nothing was changed"
  step "Installing the macOS 27 system package"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  /bin/bash "$SPAY/$sinst" --payload "$SPAY" --system "$SYS" --data "$DATA" --esp "$ROOT" --apply || stop "the v3 system installer stopped; see its lines above. The driver was not installed"
  step "Installing the macOS 27 driver"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. The system package is installed; the driver is not"
  /bin/bash "$PAY/$inst" --payload "$PAY" --system "$SYS" --data "$DATA" --esp "$ROOT" --apply || stop "the v3 driver installer stopped; see its lines above"
  # Which kit set it up is left on the new system, for the log collector there: the kit's name and its manifest's checksum.
  KR=$(mktemp -t 1401-kit-record) || KR=""
  if [ -n "$KR" ]; then
    printf 'kit %s, manifest md5 %s\n' "$(plutil -extract kit raw -o - "$KIT/$MANIFEST" 2>/dev/null)" "$(md5 -q "$KIT/$MANIFEST" 2>/dev/null)" > "$KR"
    put_on_data "$KR" Library/NullMoth/golden-gate/kit.txt || note "the kit's name could not be recorded on the new data volume"
    rm -f "$KR"
  fi
  ok "the macOS 27 system package and driver are set up. Restart and choose macOS 27"
  echo "RESULT ok"; exit 0;;

local)
  # The same two installers on macOS 27 itself, against the macOS that is running. Nothing on the startup partition
  # is read or changed. Without --confirm only the two dry runs are made.
  [ -n "$MAJOR" ] || { MAJOR=$(sw_vers -productVersion 2>/dev/null); MAJOR=${MAJOR%%.*}; }
  [ "$MAJOR" = "${TARGET%%.*}" ] || stop "this step runs on macOS ${TARGET%%.*}; this Mac runs macOS ${MAJOR:-?}. Nothing was changed"
  packages_or_stop
  step "Checking the macOS 27 system install (dry run)"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  /bin/bash "$SPAY/$sinst" --payload "$SPAY" --dry-run || stop "the v3 system installer refused its dry run. Nothing was changed"
  step "Checking the macOS 27 driver install (dry run)"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  /bin/bash "$PAY/$inst" --payload "$PAY" --dry-run || stop "the v3 driver installer refused its dry run. Nothing was changed"
  [ $CONFIRM = 1 ] || { ok "both installers passed their dry runs. Nothing was changed"; echo "RESULT ok"; exit 0; }
  step "Installing the macOS 27 system package"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. Nothing was changed"
  /bin/bash "$SPAY/$sinst" --payload "$SPAY" --apply || stop "the v3 system installer stopped; see its lines above. The driver was not installed"
  step "Installing the macOS 27 driver"
  tree_trusted "$KIT" || stop "the private copy of the v3 kit changed. The system package is installed; the driver is not"
  /bin/bash "$PAY/$inst" --payload "$PAY" --apply || stop "the v3 driver installer stopped; see its lines above"
  ok "the macOS 27 system package and driver are set up. Restart to finish"
  echo "RESULT ok"; exit 0;;
esac
