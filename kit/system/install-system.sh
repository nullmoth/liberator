#!/bin/bash
# Installs the macOS 27 system package: the interpreter for Apple silicon programs and the start-up scripts.
# Apple's programs stay Apple's; the kernel's exec hook sends them to the interpreter. Dry run unless --apply is given; --uninstall puts everything back.
# usage: install-system.sh [--system <volume> --data <volume>] [--dry-run | --apply | --uninstall]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
MODE=dry; SYS=""; DATA=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply|--uninstall) MODE=$1;;
    --dry-run|dry) MODE=dry;;
    --system) SYS=${2:-}; shift;;
    --data) DATA=${2:-}; shift;;
    --payload|--esp) shift;;                 # given by Golden Gate to every installer it runs; not used here
    *) echo "STOP: usage: install-system.sh [--system <volume> --data <volume>] [--dry-run | --apply | --uninstall]"; exit 1;;
  esac
  shift
done
SYS=${SYS%/}; DATA=${DATA%/}
if [ -n "$SYS" ] || [ -n "$DATA" ]; then
  [ -n "$SYS" ] && [ -n "$DATA" ] || { echo "STOP: --system and --data are given together"; exit 1; }
  [ -f "$SYS/System/Library/CoreServices/SystemVersion.plist" ] || { echo "STOP: $SYS is not a macOS system volume"; exit 1; }
  [ -d "$DATA/Library" ] || { echo "STOP: $DATA is not a macOS data volume"; exit 1; }
fi
r() { case "$1" in /Library|/usr/local|/private/var|/Users|/Library/*|/usr/local/*|/private/var/*|/Users/*) printf '%s' "$DATA$1";; *) printf '%s' "$SYS$1";; esac; }
STATE=$(r /Library/NullMoth/golden-gate)
ORIG=$STATE/orig
LOG=$STATE/install.log
PB=/usr/libexec/PlistBuddy
say() { echo "$*"; [ -d "$STATE" ] && echo "$(date '+%F %T') $*" >> "$LOG"; }
die() { say "STOP: $*"; exit 1; }
run() { if [ "$MODE" = "--apply" ]; then "$@"; else echo "  would run: $*"; fi; }
# A file this install replaces is kept, never deleted: when what is in place differs from what is placed, the copy in
# place goes to a dated folder under /Library/NullMoth/backups first (the originals above are the files from before the
# first install, for uninstall; these are the ones each later install replaced). The folder is named at the end.
RUNBK=$(r /Library/NullMoth/backups)/system-$(date +%Y%m%d-%H%M%S); RUNBK_USED=0
backup_current() { local dst=$1 src=$2 rel; [ -f "$dst" ] && [ ! -L "$dst" ] || return 0; cmp -s "$dst" "$src" && return 0
  rel=${dst#"$SYS"}; rel=${rel#"$DATA"}; mkdir -p "$RUNBK$(dirname "$rel")" && cp -p "$dst" "$RUNBK$rel" && RUNBK_USED=1; }
place() { local mode=$1 src=$2 dst=$3
  if [ "$MODE" != "--apply" ]; then echo "  would place: $dst"; return 0; fi
  backup_current "$dst" "$src" || die "could not keep a copy of $dst before replacing it"
  cp "$src" "$dst.ggnew" && chown root:wheel "$dst.ggnew" && chmod "$mode" "$dst.ggnew" && mv -f "$dst.ggnew" "$dst" || { rm -f "$dst.ggnew"; die "could not place $dst"; }; }
add() { local mode=$1 src=$2 lf=$3 d p todo="" x left
  d=$(r "$lf")
  [ -f "$src" ] || die "kit has no ${src#"$HERE"/}"
  if [ -f "$d" ] && [ ! -L "$d" ] && [ "$(md5 -q "$d")" = "$(md5 -q "$src")" ] && [ "$(stat -f '%u:%g %Lp' "$d")" = "0:0 $mode" ]; then
    echo "  already in place: $lf"; return 0
  fi
  if [ "$MODE" != "--apply" ]; then echo "  would place: $d"; return 0; fi
  p=${lf%/*}
  while [ -n "$p" ] && [ ! -d "$(r "$p")" ]; do todo="$p
$todo"; p=${p%/*}; done
  while IFS= read -r x; do [ -n "$x" ] || continue
    mkdir "$(r "$x")" && chown root:wheel "$(r "$x")" && chmod 755 "$(r "$x")" && echo "$x" >> "$STATE/added-dirs.list" || die "could not make the folder $x"
  done <<EOF
$todo
EOF
  if [ -e "$d" ] || [ -L "$d" ]; then
    if [ ! -e "$ORIG$lf" ]; then mkdir -p "$(dirname "$ORIG$lf")" && cp -p "$d" "$ORIG$lf" || die "could not keep the original of $lf"; fi
  elif ! grep -Fxq -- "$lf" "$STATE/added.list" 2>/dev/null; then echo "$lf" >> "$STATE/added.list"; fi
  backup_current "$d" "$src" || die "could not keep a copy of $lf before replacing it"
  rm -f "$d.ggnew"
  cp -X "$src" "$d.ggnew" && chown root:wheel "$d.ggnew" && chmod "$mode" "$d.ggnew" && mv -f "$d.ggnew" "$d" || { rm -f "$d.ggnew"; die "could not place $lf"; }
  /usr/bin/xattr -c "$d" 2>/dev/null
  [ "$(md5 -q "$d")" = "$(md5 -q "$src")" ] || die "$lf does not read back as the kit's file"
  [ "$(stat -f '%u:%g %Lp' "$d")" = "0:0 $mode" ] || die "$lf reads back with owner $(stat -f '%u:%g' "$d") and mode $(stat -f '%Lp' "$d"), not root:wheel $mode; does the volume ignore ownership?"
  left=$(/usr/bin/xattr "$d" 2>/dev/null | tr '\n' ' ')
  say "placed $lf$([ -z "$left" ] || echo " (it still carries: $left)")"
}

[ "$(id -u)" = 0 ] || die "run with sudo"
if [ "$(stat -f %z "$LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then tail -c 524288 "$LOG" > "$LOG.cap" 2>/dev/null && mv -f "$LOG.cap" "$LOG"; fi
[ "$(/usr/sbin/sysctl -n hw.cputype 2>/dev/null)" = 7 ] || die "this installs on an Intel machine"
if [ -n "$SYS" ]; then BUILD=$(/usr/bin/plutil -extract ProductBuildVersion raw -o - "$SYS/System/Library/CoreServices/SystemVersion.plist" 2>/dev/null)
else BUILD=$(sw_vers -buildVersion); fi
KITBUILD=$(sed -n 's/^BuildVersion:[[:space:]]*//p' "$HERE/BUILT-ON.txt")
[ -n "$KITBUILD" ] || die "the kit has no BUILT-ON.txt"
[ "$BUILD" = "$KITBUILD" ] || die "this kit is for macOS build $KITBUILD and ${SYS:-this machine} has ${BUILD:-no readable build}; the route list would not match"

if [ "$MODE" = "--uninstall" ]; then
  [ -d "$ORIG" ] || die "nothing to uninstall: $ORIG does not exist"
  n=0
  while IFS= read -r b; do
    f=$(r "${b#"$ORIG"}")
    cp -p "$b" "$f.ggrestore" && mv -f "$f.ggrestore" "$f" && n=$((n+1))
  done < <(find "$ORIG" -type f)
  for f in /Library/LaunchDaemons/com.nullmoth.a2xarm.plist /Library/LaunchDaemons/com.nullmoth.bringup.auxload.plist \
           /Library/LaunchDaemons/com.nullmoth.keepdisplayawake.boot.plist /Library/LaunchDaemons/com.nullmoth.startreport.plist; do
    [ -f "$(r "$f")" ] && { [ -z "$SYS" ] && launchctl bootout system "$f" 2>/dev/null; rm -f "$(r "$f")"; }
  done
  rm -rf "$(r /usr/libexec/a2x)" "$(r /Library/NullMoth/bringup)" "$(r /usr/local/libexec/a2x-keepalive.sh)" "$(r /usr/local/lib/arm2x86)"
  if [ -f "$STATE/added.list" ]; then
    while IFS= read -r p; do [ -n "$p" ] || continue; [ -e "$ORIG$p" ] || rm -f "$(r "$p")"; done < "$STATE/added.list"
    rm -f "$STATE/added.list"
  fi
  if [ -f "$STATE/added-dirs.list" ]; then
    /usr/bin/tail -r "$STATE/added-dirs.list" | while IFS= read -r p; do [ -n "$p" ] && rmdir "$(r "$p")" 2>/dev/null; done
    rm -f "$STATE/added-dirs.list"
  fi
  say "restored $n programs and removed the interpreter; restart to finish"
  exit 0
fi

echo "== 1. the kit is intact"
bad=0
while read -r sum path; do
  [ -f "$HERE/$path" ] || { echo "  missing $path"; bad=$((bad+1)); continue; }
  [ "$(md5 -q "$HERE/$path")" = "$sum" ] || { echo "  changed $path"; bad=$((bad+1)); }
done < "$HERE/MD5SUMS"
[ "$bad" = 0 ] || die "$bad kit files are missing or changed"
for t in /usr/bin/codesign /usr/bin/plutil "$PB"; do [ -x "$t" ] || die "$t is missing on this system"; done
echo "  ok"

SYSMNT=${SYS:-/}
if mount | grep -F " on $SYSMNT (" | grep -q 'read-only'; then
  if [ "$MODE" = "--apply" ]; then /sbin/mount -uw "$SYSMNT" 2>/dev/null; mount | grep -F " on $SYSMNT (" | grep -q 'read-only' && die "the system volume is read-only and could not be made writable"; say "system volume remounted writable"
  else echo "  the system volume is read-only: --apply will remount it writable"; fi
fi
[ "$MODE" = "--apply" ] && { mkdir -p "$ORIG" || die "cannot create $STATE"; chmod 755 "$STATE"; }

echo "== 2. the interpreter in /usr/libexec/a2x"
SIGNED=$(mktemp /tmp/gg-host.XXXXXX)
cp "$HERE/a2x/a2xhost-mac.unsigned" "$SIGNED" || die "copy"
/usr/bin/codesign -f -s - -i .a2xhost-mac --entitlements "$HERE/a2x/a2xhost-standalone.entitlements.plist" "$SIGNED" >/dev/null 2>&1 || die "could not sign the interpreter"
/usr/bin/codesign --verify --strict "$SIGNED" || die "the signed interpreter does not verify"
run mkdir -p "$(r /usr/libexec/a2x)"
for f in a2xhost-cat a2xpre.dylib; do place 755 "$HERE/a2x/$f" "$(r "/usr/libexec/a2x/$f")"; done
place 755 "$SIGNED" "$(r /usr/libexec/a2x/a2xhost-mac)"
# The exec hook starts /usr/libexec/a2x/a2xhost for every Apple silicon program. It is the interpreter itself: it runs
# xpcproxy without a second exec, so a service keeps the identity launchd gave it, and starts every other program
# through a2xhost-mac or a2xhost-cat.
place 755 "$SIGNED" "$(r /usr/libexec/a2x/a2xhost)"
# Every other program goes through the small launcher, which starts the right interpreter at once: a process the
# system manages (a widget extension) is suspended a few milliseconds after it starts unless it has moved on by then.
place 755 "$HERE/a2x/a2xlaunch" "$(r /usr/libexec/a2x/a2xlaunch)"
# The Apple board name Software Update reports for this machine. Liberator names it for the kind of machine
# (A2X_BOARD); without that the kit's own default, a Mac Studio's, is used.
BOARDSRC="$HERE/a2x/board"
case "${A2X_BOARD:-}" in
  "") ;;
  *[!A-Za-z0-9-]*) die "the board name '$A2X_BOARD' is not a board name";;
  *) BOARDSRC=$(mktemp /tmp/gg-board.XXXXXX) && printf '%s' "$A2X_BOARD" > "$BOARDSRC" || die "could not write the board name";;
esac
if [ -f "$BOARDSRC" ]; then
  run mkdir -p "$(r /Library/NullMoth/a2x)"
  place 644 "$BOARDSRC" "$(r /Library/NullMoth/a2x/board)"
fi
[ "$BOARDSRC" = "$HERE/a2x/board" ] || rm -f "$BOARDSRC"
place 755 "$HERE/a2x/a2xroute" "$(r /usr/libexec/a2x/a2xroute)"
place 755 "$HERE/a2x/mkroute.sh" "$(r /usr/libexec/a2x/mkroute.sh)"
place 755 "$HERE/a2x/a2xhost-mac.unsigned" "$(r /usr/libexec/a2x/a2xhost-mac.unsigned)"
place 755 "$HERE/a2x/a2xhost-cat.unsigned" "$(r /usr/libexec/a2x/a2xhost-cat.unsigned)"
run mkdir -p "$(r /usr/local/lib/arm2x86)"
place 755 "$HERE/a2x/libc++.1.0.dylib" "$(r /usr/local/lib/arm2x86/libc++.1.0.dylib)"

place 755 "$HERE/a2x/libcsfill.dylib" "$(r /usr/libexec/a2x/libcsfill.dylib)"
for cs_job in /System/Library/LaunchAgents/com.apple.corespotlightd.plist /System/Library/LaunchAgents/com.apple.managedcorespotlightd.plist; do
cs_f=$(r "$cs_job")
if [ ! -f "$cs_f" ]; then echo "  no $cs_job on this system; skipped"
elif [ "$("$PB" -c "Print :EnvironmentVariables:DYLD_INSERT_LIBRARIES" "$cs_f" 2>/dev/null)" = /usr/libexec/a2x/libcsfill.dylib ]; then echo "  already loads the library: $cs_job"
elif "$PB" -c "Print :EnvironmentVariables:DYLD_INSERT_LIBRARIES" "$cs_f" >/dev/null 2>&1; then die "$cs_job already inserts another library; not touched"
elif [ "$MODE" != "--apply" ]; then echo "  would edit: $cs_job"
else
  cs_t=$(mktemp /tmp/gg-job.XXXXXX) && cp "$cs_f" "$cs_t" || die "copy of $cs_job"
  "$PB" -c "Print :EnvironmentVariables" "$cs_t" >/dev/null 2>&1 || "$PB" -c "Add :EnvironmentVariables dict" "$cs_t" >/dev/null || die "could not edit $cs_job"
  "$PB" -c "Add :EnvironmentVariables:DYLD_INSERT_LIBRARIES string /usr/libexec/a2x/libcsfill.dylib" "$cs_t" >/dev/null || die "could not edit $cs_job"
  /usr/bin/plutil -lint "$cs_t" >/dev/null || die "the edited $cs_job does not parse; not installed"
  cs_b="$ORIG$cs_job"; if [ ! -f "$cs_b" ]; then mkdir -p "$(dirname "$cs_b")" && cp -p "$cs_f" "$cs_b" || die "could not keep the original of $cs_job"; fi
  place 644 "$cs_t" "$cs_f"; rm -f "$cs_t"; say "edited $cs_job"
fi
done

echo "== 3. boot-time bring-up"
run mkdir -p "$(r /Library/NullMoth/bringup)" "$(r /usr/local/libexec)" "$(r /Library/LaunchDaemons)"
# Interpreter stop reports: any process adds one, nothing but root reads, replaces or deletes. Root-owned, sticky,
# write+search for everyone (1733) - never the world-writable 1777 an earlier build left behind.
# /var/tmp is writable by everyone: a link or a file someone else put at this name is refused, never followed.
RD="$(r /private/var/tmp/a2x-reports)"
[ -L "$RD" ] && die "a2x-reports is a link; remove $RD and run again"
[ -e "$RD" ] && [ ! -d "$RD" ] && die "a2x-reports is not a folder; remove $RD and run again"
[ -d "$RD" ] && [ "$(stat -f %u "$RD")" != 0 ] && die "a2x-reports is not owned by root; remove $RD and run again"
run mkdir -p "$RD"
run chown -h root:wheel "$RD"
run chmod -h 1733 "$RD"
if [ "$MODE" = "--apply" ]; then
  [ "$(stat -f '%u:%g %Sp' "$(r /private/var/tmp/a2x-reports)")" = "0:0 drwx-wx-wt" ] || die "a2x-reports is not root:wheel 1733"
  # Set the mode on an open descriptor, never by path: open without following links, then check the same
  # file (regular, one link) and fchmod it. A path check followed by chmod can be raced in a shared folder.
  /usr/bin/perl -e 'use Fcntl; for (@ARGV) { sysopen(my $f, $_, O_RDONLY|O_NOFOLLOW|O_NONBLOCK) or next; my @s = stat($f); chmod(0600, $f) if -f _ && $s[3] == 1; close $f }' "$(r /private/var/tmp/a2x-reports)"/*.log
fi
for f in nvload.sh ws-gate.sh lw-gate.sh cryptex-place.sh start-report.sh nvgo wsready; do
  [ -f "$HERE/bringup/$f" ] || die "kit has no bringup/$f"
  place 755 "$HERE/bringup/$f" "$(r "/Library/NullMoth/bringup/$f")"
done
[ -f "$HERE/libexec/a2x-keepalive.sh" ] || die "kit has no libexec/a2x-keepalive.sh"
place 755 "$HERE/libexec/a2x-keepalive.sh" "$(r /usr/local/libexec/a2x-keepalive.sh)"
[ -f "$HERE/libexec/a2x-userapps.sh" ] || die "kit has no libexec/a2x-userapps.sh"
place 755 "$HERE/libexec/a2x-userapps.sh" "$(r /usr/local/libexec/a2x-userapps.sh)"
for p in com.nullmoth.a2xarm.plist com.nullmoth.a2xuserapps.plist com.nullmoth.bringup.auxload.plist com.nullmoth.keepdisplayawake.boot.plist com.nullmoth.startreport.plist; do
  [ -f "$HERE/daemons/$p" ] || die "kit has no $p"
  /usr/bin/plutil -lint "$HERE/daemons/$p" >/dev/null || die "$p does not parse"
  place 644 "$HERE/daemons/$p" "$(r "/Library/LaunchDaemons/$p")"
done

echo "== 3b. Apple's own macOS updates are not downloaded or installed by themselves"
# The kernel collections and the system patches of this package are made for one build ($KITBUILD). A newer macOS 27 build
# installed over it would start without them, so Apple's update is checked for but never taken without the owner asking
# (see docs/UPDATES.md). Security data and configuration data updates stay on.
[ -f "$HERE/hold/com.apple.SoftwareUpdate.plist" ] || die "kit has no hold/com.apple.SoftwareUpdate.plist"
/usr/bin/plutil -lint "$HERE/hold/com.apple.SoftwareUpdate.plist" >/dev/null || die "hold/com.apple.SoftwareUpdate.plist does not parse"
add 644 "$HERE/hold/com.apple.SoftwareUpdate.plist" /Library/Preferences/com.apple.SoftwareUpdate.plist

echo "== 3a. two files macOS 27 needs on an Intel PC and does not have"
add 644 "$HERE/driverkit/dyld_shared_cache_x86_64" /System/DriverKit/System/Library/dyld/dyld_shared_cache_x86_64
CHG="$HERE/lib/charging-init.dylib"
[ -f "$CHG" ] || die "kit has no lib/charging-init.dylib"
chgsum=$(/usr/bin/shasum -a 256 "$CHG" | awk '{print $1}')
[ ${#chgsum} = 64 ] || die "could not take the checksum of lib/charging-init.dylib"
[ "$(sed -n 's/^CHG_SHA=//p' "$HERE/libexec/a2x-keepalive.sh")" = "$chgsum" ] || die "libexec/a2x-keepalive.sh names another checksum than lib/charging-init.dylib has ($chgsum); the start-up script would not use it"
add 755 "$CHG" /usr/local/lib/nullmoth/charging-init.dylib
if [ "$MODE" = "--apply" ]; then
  d=$(r /usr/local/lib/nullmoth)
  chown root:wheel "$d" && chmod 755 "$d" && [ "$(stat -f '%u:%g %Lp' "$d")" = "0:0 755" ] || die "/usr/local/lib/nullmoth is not root:wheel 755"
fi

echo "== 3b. the window server and the login window start through the gates"
gate_job() {  # <job path> <Apple's program> <gate script> <ws|lw>
  local lf=$1 apple=$2 gate=$3 kind=$4 f t cur b
  f=$(r "$lf"); [ -f "$f" ] || die "$lf is missing on this system"
  cur=$("$PB" -c "Print :ProgramArguments:0" "$f" 2>/dev/null)
  if [ "$cur" = "$gate" ]; then echo "  already through its gate: $lf"; return 0; fi
  [ "$cur" = "$apple" ] || die "$lf starts $cur, which is neither Apple's program nor the gate; not touched"
  if [ "$MODE" != "--apply" ]; then echo "  would edit: $lf"; return 0; fi
  t=$(mktemp /tmp/gg-job.XXXXXX) && cp "$f" "$t" || die "copy of $lf"
  "$PB" -c "Set :ProgramArguments:0 $gate" "$t" >/dev/null || die "could not edit $lf"
  if [ "$kind" = ws ]; then
    for k in StandardErrorPath StandardOutPath; do
      "$PB" -c "Add :$k string /var/log/nullmoth-ws-stderr.log" "$t" >/dev/null 2>&1 || "$PB" -c "Set :$k /var/log/nullmoth-ws-stderr.log" "$t" >/dev/null || die "could not edit $lf"
    done
  else
    "$PB" -c "Set :Program $gate" "$t" >/dev/null || die "could not edit $lf"
  fi
  /usr/bin/plutil -lint "$t" >/dev/null || die "the edited $lf does not parse; not installed"
  [ "$("$PB" -c "Print :ProgramArguments:0" "$t")" = "$gate" ] || die "the edit of $lf did not take; not installed"
  b="$ORIG$lf"
  if [ ! -f "$b" ]; then mkdir -p "$(dirname "$b")" && cp -p "$f" "$b" || die "could not keep the original of $lf"; fi
  place 644 "$t" "$f"; rm -f "$t"
  say "edited $lf"
}
gate_job /System/Library/LaunchDaemons/com.apple.WindowServer.plist /System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer /Library/NullMoth/bringup/ws-gate.sh ws
gate_job /System/Library/LaunchDaemons/com.apple.loginwindow.plist /System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow /Library/NullMoth/bringup/lw-gate.sh lw

echo "== 4. stock: Apple's programs stay Apple's"
# Earlier kits replaced Apple's arm64-only programs with routes. The kernel's exec hook now runs them unmodified from
# the first boot task on, so each Apple program kept in the originals folder goes back, after the file in place is
# backed up. Only Mach-O files on the system volume are put back: the launchd jobs below stay edited (the window
# server and login window gates, the spotlight helpers' library) and files on the data volume are this kit's own.
KEEP_EDITED=" /System/Library/LaunchDaemons/com.apple.WindowServer.plist /System/Library/LaunchDaemons/com.apple.loginwindow.plist /System/Library/LaunchAgents/com.apple.corespotlightd.plist /System/Library/LaunchAgents/com.apple.managedcorespotlightd.plist "
# Two programs need their own entitlements on the process, which only a route carries; they are handled in 4b.
KEEP_ROUTED="/System/Library/CoreServices/talagentd /System/Library/CoreServices/diagnostics_agent /System/Library/CoreServices/NotificationCenter.app/Contents/MacOS/NotificationCenter"
rwant=0; rsame=0; rdone=0; rfail=0
if [ -d "$ORIG" ]; then
  while IFS= read -r -d '' o; do
    lf=${o#"$ORIG"}
    case "$KEEP_EDITED" in *" $lf "*) continue;; esac
    case " $KEEP_ROUTED " in *" $lf "*) continue;; esac
    case "$lf" in /Library/*|/usr/local/*|/private/var/*|/Users/*) continue;; esac
    /usr/bin/file -b "$o" | /usr/bin/grep -q 'Mach-O' || continue
    f=$(r "$lf"); rwant=$((rwant+1))
    if [ -f "$f" ] && cmp -s "$o" "$f"; then rsame=$((rsame+1)); continue; fi
    if [ "$MODE" != "--apply" ]; then rdone=$((rdone+1)); continue; fi
    backup_current "$f" "$o" || { rfail=$((rfail+1)); echo "  could not keep a copy of $lf"; continue; }
    cp -p "$o" "$f.ggstock" && mv -f "$f.ggstock" "$f" && cmp -s "$o" "$f" && rdone=$((rdone+1)) \
      || { rm -f "$f.ggstock"; rfail=$((rfail+1)); echo "  could not put back $lf"; }
  done < <(find "$ORIG" -type f -print0)
fi
rm -f "$SIGNED" "$SIGNED.r"
say "stock: $rwant Apple programs kept from earlier installs, $rsame already Apple's, $rdone $([ "$MODE" = "--apply" ] && echo 'put back' || echo 'to put back'), $rfail failed"
[ "$rfail" = 0 ] || die "$rfail Apple programs could not be put back; the files in place are unchanged or backed up"

echo "== 4b. programs that keep a route"
# Without talagentd the menu bar shows no Apple menu and no application menus; without its route NotificationCenter is
# ended by the system about once a minute. Apple's file is kept in the originals folder first and put back in place,
# and the route is built from it there: a program inside an app bundle must be signed from inside the bundle, or the
# signature is bound to an Info.plist that is not there and the program is refused at start.
kdone=0; kfail=0
for lf in $KEEP_ROUTED; do
  f=$(r "$lf"); o="$ORIG$lf"
  [ -f "$f" ] || { echo "  not on this system: $lf"; continue; }
  if [ "$MODE" != "--apply" ]; then echo "  would route $lf"; continue; fi
  if [ ! -f "$o" ]; then
    if /usr/bin/file -b "$f" | /usr/bin/grep -q 'x86_64'; then kfail=$((kfail+1)); echo "  $lf is not Apple's file and no original is kept"; continue; fi
    mkdir -p "$(dirname "$o")" && cp -p "$f" "$o" || { kfail=$((kfail+1)); echo "  could not keep Apple's $lf"; continue; }
  fi
  cmp -s "$o" "$f" || { cp -p "$o" "$f.ggapple" && mv -f "$f.ggapple" "$f"; } || { rm -f "$f.ggapple"; kfail=$((kfail+1)); echo "  could not put Apple's $lf in place"; continue; }
  if /bin/bash "$HERE/a2x/mkroute.sh" "$HERE/a2x/a2xhost-mac.unsigned" "$f" "$f.ggroute" \
     && chown root:wheel "$f.ggroute" && chmod 755 "$f.ggroute" && mv -f "$f.ggroute" "$f"; then kdone=$((kdone+1))
  else rm -f "$f.ggroute"; kfail=$((kfail+1)); echo "  could not route $lf"; fi
done
say "routes kept: $kdone made, $kfail failed"
[ "$kfail" = 0 ] || die "$kfail programs that need a route could not be routed"

echo "== 5. not done by this script"
echo "  the exec-hook kernel extension and the NVIDIA kernel extensions load through the boot loader (1401 builds that)"
echo "  the NVIDIA driver bundle and its settings come from the driver package"
[ "$MODE" = "--apply" ] && [ "$RUNBK_USED" = 1 ] && say "BACKUP the files this install replaced are kept in ${RUNBK#"$DATA"}"
[ "$MODE" = "--apply" ] && say "installed; restart to finish" || echo "dry run finished; nothing was changed. Run again with --apply to install."

