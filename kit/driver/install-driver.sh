#!/bin/bash
# Installs the NVIDIA driver for macOS 27 from this package. Dry run unless --apply is given; --uninstall puts
# everything back.
# usage: install-driver.sh [--payload <this folder>] [--system <volume> --data <volume>] [--dry-run | --apply | --uninstall]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
MODE=dry; SYS=""; DATA=""; PKG=""; FILES=""; MAN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply|--uninstall) MODE=$1;;
    --dry-run|dry) MODE=dry;;
    --system) SYS=${2:-}; shift;;
    --data) DATA=${2:-}; shift;;
    --payload) PKG=${2:-}; shift;;
    --esp) shift;;                           # given by Golden Gate to every installer it runs; not used here
    *) echo "STOP: usage: install-driver.sh [--payload <folder>] [--system <volume> --data <volume>] [--dry-run | --apply | --uninstall]"; exit 1;;
  esac
  shift
done
SYS=${SYS%/}; DATA=${DATA%/}
PKG=${PKG:-$HERE}; PKG=${PKG%/}; FILES=${FILES:-$PKG/payload}; FILES=${FILES%/}; MAN=${MAN:-$PKG/MANIFEST}
if [ -n "$SYS" ] || [ -n "$DATA" ]; then
  [ -n "$SYS" ] && [ -n "$DATA" ] || { echo "STOP: --system and --data are given together"; exit 1; }
  [ -f "$SYS/System/Library/CoreServices/SystemVersion.plist" ] || { echo "STOP: $SYS is not a macOS system volume"; exit 1; }
  [ -d "$DATA/Library" ] || { echo "STOP: $DATA is not a macOS data volume"; exit 1; }
fi
r() { case "$1" in /Library|/usr/local|/private/var|/Users|/Library/*|/usr/local/*|/private/var/*|/Users/*) printf '%s' "$DATA$1";; *) printf '%s' "$SYS$1";; esac; }
STATE=$(r /Library/NullMoth/golden-gate/driver)
ORIG=$STATE/orig; ADDED=$STATE/added.list; DIRS=$STATE/added-dirs.list; LOG=$STATE/install.log
SHARED=/Library/GPUBundles/NVIDIAShared.bundle; AIROPT=/Library/GPUBundles/nvmtl/air-opt
say() { echo "$*"; if [ "$MODE" != dry ] && [ -d "$STATE" ]; then echo "$(date '+%F %T') $*" >> "$LOG"; fi; }
die() { say "STOP: $*"; exit 1; }
sum() { /sbin/md5 -q "$1" 2>/dev/null; }
# Every file an install replaces is kept, never deleted: the copy that was in place goes to a dated folder under
# /Library/NullMoth/backups, which the installer names at the end. (The originals kept above are the files from before
# the first install, for uninstall; these are the ones each later install replaced.)
RUNBK=$(r /Library/NullMoth/backups)/driver-$(date +%Y%m%d-%H%M%S); RUNBK_USED=0
backup_current() { local d; d=$(r "$1"); [ -e "$d" ] || [ -L "$d" ] || return 0
  mkdir -p "$RUNBK$(dirname "$1")" && cp -pP "$d" "$RUNBK$1" && RUNBK_USED=1; }
# The NVIDIA auxiliary kernel collection is linked against one boot kernel collection and is refused at start by any
# other. On the macOS that is running, a collection that matches the boot collection it started from is never
# replaced by one that does not: that turns the desktop off at the next start (no NVIDIA driver, no window server).
kc_bootid() { LC_ALL=C grep -a -A2 '<key>_BootKCID</key>' "$1" 2>/dev/null | sed -n 3p | tr -d ' \t' | base64 -D 2>/dev/null | xxd -p | tr a-f A-F; }
booted_kcid() { /usr/sbin/sysctl -n kern.kernelcacheuuid 2>/dev/null | tr -d '-' | tr a-f A-F; }
AUXKC=/Library/KernelCollections/AuxiliaryKernelExtensions.kc
excluded() { case "$1" in "$SHARED"|"$SHARED"/*|"$AIROPT"|*/.NVMTLDriver.*|*/aircache/*|*/spvcache/*) return 0;; esac; return 1; }

[ "$(id -u)" = 0 ] || die "run with sudo"
if [ "$(stat -f %z "$LOG" 2>/dev/null || echo 0)" -gt 1048576 ]; then tail -c 524288 "$LOG" > "$LOG.cap" 2>/dev/null && mv -f "$LOG.cap" "$LOG"; fi
[ "$(/usr/sbin/sysctl -n hw.cputype 2>/dev/null)" = 7 ] || die "this installs on an Intel machine"
if [ -n "$SYS" ]; then BUILD=$(/usr/bin/plutil -extract ProductBuildVersion raw -o - "$SYS/System/Library/CoreServices/SystemVersion.plist" 2>/dev/null)
else BUILD=$(sw_vers -buildVersion); fi
KITBUILD=$(sed -n 's/^BuildVersion:[[:space:]]*//p' "$PKG/BUILT-ON.txt" 2>/dev/null)
[ -n "$KITBUILD" ] || die "the driver package has no BUILT-ON.txt"
[ "$BUILD" = "$KITBUILD" ] || die "this driver is for macOS build $KITBUILD and ${SYS:-this machine} has ${BUILD:-no readable build}; its kernel collection would not load"
[ -f "$MAN" ] || die "the driver package has no MANIFEST ($MAN)"

walk() { local fn=$1 line kind rest a b path
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue;; esac
    kind=${line%% *}; rest=${line#* }; a=""; b=""
    case "$kind" in
      F) a=${rest%% *}; rest=${rest#* }; b=${rest%% *}; path=${rest#* }
           case "$a" in [0-7][0-7][0-7]) ;; *) die "MANIFEST: bad mode in: $line";; esac
           case "$b" in *[!0-9a-f]*|'') die "MANIFEST: bad checksum in: $line";; esac; [ ${#b} = 32 ] || die "MANIFEST: bad checksum in: $line";;
      L) a=${rest%% *}; path=${rest#* }
         case "$a" in ''|*/*|.|..) die "MANIFEST: a link may only name a file beside it: $line";; esac;;
      E) a=${rest%% *}; path=${rest#* }
         case "$a" in [0-7][0-7][0-7]) ;; *) die "MANIFEST: bad mode in: $line";; esac;;
      *) die "MANIFEST: unknown entry: $line";;
    esac
    case "$path" in /*) ;; *) die "MANIFEST: not a full path: $line";; esac
    case "$path" in */../*|*/..|*/./*|*//*|*/) die "MANIFEST: not a plain path: $line";; esac
    excluded "$path" && die "MANIFEST names a file that is never installed: $path"
    "$fn" "$kind" "$a" "$b" "$path"
  done < "$MAN"
}

if [ "$MODE" = "--uninstall" ]; then
  [ -d "$STATE" ] || die "nothing to uninstall: $STATE does not exist"
  restored=0; removed=0; failed=0
  undo() { local path=$4 d; d=$(r "$4")
    if [ -f "$ADDED" ] && grep -Fxq -- "$path" "$ADDED"; then
      if [ -e "$d" ] || [ -L "$d" ]; then rm -f "$d" && removed=$((removed+1)) || failed=$((failed+1)); fi
    elif [ -e "$ORIG$path" ] || [ -L "$ORIG$path" ]; then
      rm -f "$d.ggrestore"; cp -pP "$ORIG$path" "$d.ggrestore" && mv -fh "$d.ggrestore" "$d" && restored=$((restored+1)) || { rm -f "$d.ggrestore"; failed=$((failed+1)); }
    fi; }
  walk undo
  [ "$failed" = 0 ] || die "$failed files could not be put back; the kept originals are still in $ORIG"
  for n in "$SHARED" "$AIROPT"; do
    if [ -e "$ORIG$n" ]; then
      [ ! -e "$(r "$n")" ] || die "$n is installed and the kept one is still in $ORIG; move one of them away and run --uninstall again"
      mv "$ORIG$n" "$(r "$n")" || die "could not put $n back"; restored=$((restored+1))
    fi
  done
  if [ -f "$DIRS" ]; then /usr/bin/tail -r "$DIRS" | while IFS= read -r p; do [ -n "$p" ] && rmdir "$(r "$p")" 2>/dev/null; done; fi
  rm -rf "$STATE"
  echo "restored $restored files and removed $removed that the driver added; restart to finish"
  exit 0
fi

echo "== 1. the driver files match MANIFEST"
[ -d "$FILES" ] || die "the driver files folder is not there: $FILES"
LIST=$(mktemp /tmp/gg-driver.XXXXXX) || die "no temporary file"; trap 'rm -f "$LIST"' EXIT
bad=0; nfile=0; nlink=0
verify() { local kind=$1 want=$3 path=$4 f="$FILES$4"
  printf '%s\n' "$path" >> "$LIST"
  case "$kind" in
    L) nlink=$((nlink+1)); return 0;;
    E) return 0;;
  esac
  if [ -L "$f" ] || [ ! -f "$f" ]; then echo "  missing $path"; bad=$((bad+1)); return 0; fi
  [ "$(sum "$f")" = "$want" ] || { echo "  changed $path"; bad=$((bad+1)); return 0; }
  nfile=$((nfile+1)); }
walk verify
[ "$(sort "$LIST" | uniq -d | wc -l | tr -d ' ')" = 0 ] || die "MANIFEST names a path twice"
left=0; extra=0
while IFS= read -r f; do p=${f#"$FILES"}
  if excluded "$p"; then left=$((left+1)); continue; fi
  grep -Fxq -- "$p" "$LIST" || { echo "  not in MANIFEST: $p"; extra=$((extra+1)); }
done < <(find "$FILES" \( -type f -o -type l \) -print)
[ "$bad" = 0 ] || die "$bad driver files are missing or changed"
[ "$extra" = 0 ] || die "$extra files in the files folder are not in MANIFEST"
FWDIR=$(sed -n 's|^\(/Library/NullMoth/nvfw/nvidia/[^/]*\)/[^/]*$|\1|p' "$LIST" | sort -u)
[ -n "$FWDIR" ] || die "MANIFEST installs no card firmware under /Library/NullMoth/nvfw/nvidia; the driver could not start the card"
[ "$(printf '%s\n' "$FWDIR" | wc -l | tr -d ' ')" = 1 ] || die "MANIFEST installs card firmware of more than one version"
for n in gsp_ga10x.bin gsp_tu10x.bin ucodes_ga10x.bin ucodes_tu10x.bin; do
  grep -Fxq -- "$FWDIR/$n" "$LIST" || die "MANIFEST does not install the firmware file $FWDIR/$n"
done
NVRM="$PKG/../Kexts/NVRM.kext/Contents/MacOS/NVRM"
if [ -f "$NVRM" ]; then
  LC_ALL=C grep -a -q -F -- "$FWDIR/gsp_" "$NVRM" || die "the kit's NVRM does not read its firmware from $FWDIR; this package and that NVRM are not of one version"
  fwnote="the kit's NVRM reads it from there"
else fwnote="no NVRM beside this package to compare with"; fi
echo "  firmware: ${FWDIR##*/} ($fwnote)"
echo "  ok: $nfile files, $nlink links$([ "$left" = 0 ] || echo "; $left files in the folder are never installed (NVIDIAShared.bundle, air-opt, hidden work folders, caches)")"

SYSMNT=${SYS:-/}
if mount | grep -F " on $SYSMNT (" | grep -q 'read-only'; then
  if [ "$MODE" = "--apply" ]; then /sbin/mount -uw "$SYSMNT" 2>/dev/null; mount | grep -F " on $SYSMNT (" | grep -q 'read-only' && die "the system volume is read-only and could not be made writable"; say "system volume remounted writable"
  else echo "  the system volume is read-only: --apply will remount it writable"; fi
fi
if [ "$MODE" = "--apply" ]; then mkdir -p "$ORIG" || die "cannot create $STATE"; chmod 755 "$STATE" "$ORIG"; touch "$ADDED" "$DIRS"; fi

parents() { local p=${1%/*} todo="" d
  while [ -n "$p" ] && [ ! -d "$(r "$p")" ]; do todo="$p
$todo"; p=${p%/*}; done
  while IFS= read -r d; do [ -n "$d" ] || continue
    mkdir "$(r "$d")" && chown root:wheel "$(r "$d")" && chmod 755 "$(r "$d")" && echo "$d" >> "$DIRS" || return 1
  done <<EOF
$todo
EOF
}
keep() { local d; d=$(r "$1")
  if [ -e "$ORIG$1" ] || [ -L "$ORIG$1" ]; then return 0; fi
  grep -Fxq -- "$1" "$ADDED" && return 0
  if [ -e "$d" ] || [ -L "$d" ]; then mkdir -p "$(dirname "$ORIG$1")" && cp -pP "$d" "$ORIG$1"; else echo "$1" >> "$ADDED"; fi; }

echo "== 1b. the kernel collections"
# A Mac already on macOS 27 has the boot and system kernel collections an earlier kit made. When they are exactly the
# previous kit's (checked by checksum), this kit's are made from them here with bspatch and the two small deltas in
# kc/, checked against their pins, and placed in the Preboot volume and on the system volume; the ones that were in
# place are kept in the backup folder first. Collections that are not a kit's (made on this Mac) are left as they are.
# The NVIDIA auxiliary collection below is matched against the boot collection the next start will use.
KC_OLD_BOOT=4a49bffb32594d0d9287de38540dec71b6f679dbd3c3a06fb315077b624f9873; KC_NEW_BOOT=e8aadd4736a06f34b403ee256e419d673ba8d8b412e44c0fdb7df7f87acd55ca
KC_OLD_SYS=a1b532710fd64a90cb1a505f3b594f02fab9070c2a36274e98a051bb375a8301; KC_NEW_SYS=262c64047e9058e923a2a62e9d2361667a310ad3d7ca220595ad76269ad76434
KC_NEW_BOOTID=5CEE5ECFB3A482133CF6FA40BD3384EB; TARGET_BOOTID=""
sha256() { /usr/bin/shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }
if [ -z "$SYS" ]; then
  G=$(diskutil info / 2>/dev/null | awk -F': *' '/APFS Volume Group/{print $2}')
  PBK=/System/Volumes/Preboot/$G/boot/System/Library/KernelCollections; SKC=/System/Library/KernelCollections
  if [ -n "$G" ] && [ -f "$PBK/BootKernelExtensions.kc" ]; then
    cb=$(sha256 "$PBK/BootKernelExtensions.kc"); cs=$(sha256 "$PBK/SystemKernelExtensions.kc")
    if [ "$cb" = "$KC_NEW_BOOT" ]; then TARGET_BOOTID=$KC_NEW_BOOTID; say "kernel collections: already this kit's"
    elif [ "$cb" = "$KC_OLD_BOOT" ] && [ "$cs" = "$KC_OLD_SYS" ]; then
      TARGET_BOOTID=$KC_NEW_BOOTID
      if [ "$MODE" != "--apply" ]; then echo "  would make this kit's boot and system kernel collections and place them"
      else
        KT=$(mktemp -d /private/var/tmp/nmkc.XXXXXX) || die "could not make a folder for the kernel collections"
        bspatch "$PBK/BootKernelExtensions.kc" "$KT/boot.kc" "$PKG/kc/boot-update.delta" && [ "$(sha256 "$KT/boot.kc")" = "$KC_NEW_BOOT" ] \
          && bspatch "$PBK/SystemKernelExtensions.kc" "$KT/sys.kc" "$PKG/kc/system-update.delta" && [ "$(sha256 "$KT/sys.kc")" = "$KC_NEW_SYS" ] \
          || { rm -rf "$KT"; die "this kit's kernel collections could not be made from the ones in place; nothing was changed"; }
        mount | grep -q ' on / (.*read-only' && { /sbin/mount -uw / 2>/dev/null || { rm -rf "$KT"; die "the system volume could not be made writable; nothing was changed"; }; }
        mkdir -p "$RUNBK/preboot" "$RUNBK/system" && cp -p "$PBK/BootKernelExtensions.kc" "$PBK/SystemKernelExtensions.kc" "$RUNBK/preboot/" \
          && { [ ! -f "$SKC/BootKernelExtensions.kc" ] || cp -p "$SKC/BootKernelExtensions.kc" "$SKC/SystemKernelExtensions.kc" "$RUNBK/system/"; } && RUNBK_USED=1 \
          || { rm -rf "$KT"; die "could not keep the kernel collections in place; nothing was changed"; }
        kcput() { cp "$1" "$2.nmnew" && cmp -s "$1" "$2.nmnew" && mv -f "$2.nmnew" "$2" || { rm -f "$2.nmnew"; return 1; }; }
        kcput "$KT/boot.kc" "$PBK/BootKernelExtensions.kc" && kcput "$KT/sys.kc" "$PBK/SystemKernelExtensions.kc" \
          && { [ ! -f "$SKC/BootKernelExtensions.kc" ] || { kcput "$KT/boot.kc" "$SKC/BootKernelExtensions.kc" && kcput "$KT/sys.kc" "$SKC/SystemKernelExtensions.kc"; }; } \
          || { cp -p "$RUNBK/preboot/"*.kc "$PBK/" 2>/dev/null; [ -f "$RUNBK/system/BootKernelExtensions.kc" ] && cp -p "$RUNBK/system/"*.kc "$SKC/" 2>/dev/null; rm -rf "$KT"; die "the kernel collections could not be placed; the ones that were in place are back"; }
        rm -rf "$KT"; say "kernel collections: this kit's are placed (the previous ones are kept in $RUNBK)"
      fi
    else say "kernel collections: this Mac's are not a kit's (made on this Mac); left as they are"; fi
  fi
fi
echo "== 2. the driver's files"
want=0; have=0; made=0; nsys=0; ndata=0
put() { local kind=$1 a=$2 md=$3 path=$4 d src; d=$(r "$4"); src="$FILES$4"
  want=$((want+1))
  [ -d "$d" ] && [ ! -L "$d" ] && die "$path is a folder on the macOS being set up; nothing was placed there"
  case "$kind" in
    F) if [ -f "$d" ] && [ ! -L "$d" ] && [ "$(sum "$d")" = "$md" ] && [ "$(stat -f '%Lp %u:%g' "$d")" = "$a 0:0" ]; then have=$((have+1)); return 0; fi;;
    L) if [ -L "$d" ] && [ "$(readlink "$d")" = "$a" ]; then have=$((have+1)); return 0; fi;;
    E) if [ -e "$d" ]; then have=$((have+1)); return 0; fi;;
  esac
  made=$((made+1)); case "$path" in /Library/*) ndata=$((ndata+1));; *) nsys=$((nsys+1));; esac
  if [ "$path" = "$AUXKC" ] && [ -z "$SYS" ] && [ -f "$d" ]; then
    bk=${TARGET_BOOTID:-$(booted_kcid)}
    if [ -n "$bk" ] && [ "$(kc_bootid "$d")" = "$bk" ] && [ "$(kc_bootid "$src")" != "$bk" ]; then
      say "  kept: $d - the one in place matches the boot kernel collection this Mac started from and the kit's does not"
      made=$((made-1)); ndata=$((ndata-1)); have=$((have+1)); return 0
    fi
  fi
  if [ "$MODE" != "--apply" ]; then echo "  would place: $d"; return 0; fi
  parents "$path" || die "could not make the folder for $path"
  backup_current "$path" || die "could not keep a copy of $path before replacing it; nothing was placed there"
  keep "$path" || die "could not keep the original of $path; nothing was placed there"
  rm -f "$d.ggnew"
  # A file made immutable (schg/uchg, done to the aux collection so macOS 27 does not delete it at start-up) cannot be
  # replaced; the lock is lifted for the swap and put back on the new file.
  lock=""
  if [ "$kind" = F ] && [ -f "$d" ] && [ ! -L "$d" ]; then
    case ",$(ls -lO "$d" | awk '{print $5}')," in *,schg,*) lock=schg;; esac
    case ",$(ls -lO "$d" | awk '{print $5}')," in *,uchg,*) lock=${lock:+$lock,}uchg;; esac
    [ -z "$lock" ] || chflags noschg,nouchg "$d" || die "could not unlock $path to replace it; nothing was placed there"
  fi
  case "$kind" in
    F) cp "$src" "$d.ggnew" && chown root:wheel "$d.ggnew" && chmod "$a" "$d.ggnew" && mv -fh "$d.ggnew" "$d" || { rm -f "$d.ggnew"; [ -z "$lock" ] || chflags "$lock" "$d"; die "could not place $path"; }
       [ -z "$lock" ] || chflags "$lock" "$d" || die "placed $path but could not lock it again ($lock)";;
    L) ln -s "$a" "$d.ggnew" && chown -h root:wheel "$d.ggnew" && mv -fh "$d.ggnew" "$d" || { rm -f "$d.ggnew"; die "could not place the link $path"; };;
    E) : > "$d.ggnew" && chown root:wheel "$d.ggnew" && chmod "$a" "$d.ggnew" && mv -fh "$d.ggnew" "$d" || { rm -f "$d.ggnew"; die "could not make $path"; };;
  esac; }
walk put
say "driver files: $want listed, $have already current, $made $([ "$MODE" = "--apply" ] && echo placed || echo 'to place') ($nsys on the system volume, $ndata on the data volume)"
[ "$MODE" = "--apply" ] && [ "$RUNBK_USED" = 1 ] && say "BACKUP the files this install replaced are kept in $RUNBK"

echo "== 3. NVIDIAShared.bundle and nvmtl/air-opt are not part of this driver"
for n in "$SHARED" "$AIROPT"; do
  if [ -e "$(r "$n")" ]; then
    if [ "$MODE" != "--apply" ]; then echo "  would move the installed $n to the kept originals"
    elif [ -e "$ORIG$n" ]; then say "  $n is installed and one is already kept; the installed one is left alone"
    else mkdir -p "$(dirname "$ORIG$n")" && mv "$(r "$n")" "$ORIG$n" || die "could not move $n to the kept originals"
      say "  moved the installed $n to the kept originals"; fi
  else echo "  not installed: $n"; fi
done

echo "== 3b. saved icon images"
# Icons drawn by an earlier driver stay in two caches and keep showing after an update (seen with Safari, Maps and
# FaceTime in the Dock). The system rebuilds both on demand, so they are removed whenever driver files were placed.
if [ "$MODE" = "--apply" ] && [ "$made" -gt 0 ]; then
  rm -rf "$DATA/Library/Caches/com.apple.iconservices.store"
  find "$DATA/private/var/folders" -maxdepth 4 -name com.apple.dock.iconcache -type f -delete 2>/dev/null
  say "  removed the saved icon images (rebuilt at the next start)"
else echo "  nothing to do"; fi

echo "== 4. not done by this script"
echo "  NVRM.kext is injected by the boot loader (1401 builds that); the interpreter and routes come from install-system.sh"
echo "  the auxiliary kernel collection is placed as built, not rebuilt: it is only known to load on the machine it was built on"
if [ "$MODE" = "--apply" ]; then say "installed; restart to finish"; else echo "dry run finished; nothing was changed. Run again with --apply to install."; fi

