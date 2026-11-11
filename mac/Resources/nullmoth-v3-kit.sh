#!/bin/bash
# nullmoth-v3-kit.sh - get the NullMoth v3 kit (the macOS 27 parts) onto this Mac, where Golden Gate reads it.
#
# The kit is one archive. This build of 1401 knows exactly one: its name, size and SHA-256 are in v3-kit.pin beside
# this script, written when the app was built. Any other archive is refused, wherever it came from.
#
#   nullmoth-v3-kit.sh status            says whether the kit is installed and whether it is this build's kit
#   nullmoth-v3-kit.sh get               downloads the archive, checks it, installs the kit
#   nullmoth-v3-kit.sh get --file FILE   the same from an archive that is already on this Mac (it is checked the same)
#   nullmoth-v3-kit.sh remove            removes the installed kit (Cancel Golden Gate does not need the kit)
#
# The kit ends up in /Library/NullMoth/v3-kit, owned by root and writable by root alone: Golden Gate runs the kit's
# installers as root and accepts a kit only from there. Nothing else on the Mac is changed.
set -u
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
HERE=$(cd "$(dirname "$0")" && pwd)
PIN="$HERE/v3-kit.pin"
DEST=/Library/NullMoth/v3-kit
BASES="https://github.com/nullmoth/nvidia-macos-driver/releases/download https://nullmothsystems.com/download/v3"
NEED_ROOT=1
PROTO='=https'

say()  { echo "$*"; }
step() { echo "STEP $*"; }
ok()   { echo "OK   $*"; }
stop() { echo "STOP $*"; [ -n "${WORK:-}" ] && rm -rf "$WORK"; echo "RESULT stop"; exit 1; }

CMD=${1:-}; [ $# -gt 0 ] && shift
FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --file) FILE=${2:-}; [ -n "$FILE" ] || stop "--file needs a path"; shift;;
    # test-hook-begin
    --dest) DEST=${2:?}; NEED_ROOT=0; shift;;
    --pin) PIN=${2:?}; shift;;
    --bases) BASES=${2:?}; shift;;
    --protocol) PROTO=${2:?}; shift;;
    # test-hook-end
    *) echo "STOP unknown option $1"; echo "RESULT stop"; exit 2;;
  esac
  shift
done

# The pin: four lines, "name", "tag", "size", "sha256". Without it this build offers no macOS 27.
read_pin() {
  [ -f "$PIN" ] || stop "macOS 27 is not offered by this build of 1401. Nothing was changed"
  KNAME=$(sed -n 's/^name //p' "$PIN"); KTAG=$(sed -n 's/^tag //p' "$PIN")
  KSIZE=$(sed -n 's/^size //p' "$PIN"); KSHA=$(sed -n 's/^sha256 //p' "$PIN")
  case "$KNAME" in ""|*/*|*[!A-Za-z0-9._-]*) stop "this build's kit record is damaged (name). Nothing was changed";; esac
  case "$KTAG" in ""|*/*|*[!A-Za-z0-9._-]*) stop "this build's kit record is damaged (tag). Nothing was changed";; esac
  case "$KSIZE" in ""|*[!0-9]*) stop "this build's kit record is damaged (size). Nothing was changed";; esac
  [ ${#KSHA} = 64 ] || stop "this build's kit record is damaged (checksum). Nothing was changed"
  case "$KSHA" in *[!0-9a-f]*) stop "this build's kit record is damaged (checksum). Nothing was changed";; esac
}

# What is installed: the checksum of the archive it came from is kept in a file beside the kit folder, not in it.
installed_sha() { [ -f "$DEST/v3-kit.json" ] && [ -f "$DEST.archive-sha256" ] && [ ! -L "$DEST.archive-sha256" ] && head -c 64 "$DEST.archive-sha256"; }

case "$CMD" in
status)
  read_pin
  if [ ! -f "$DEST/v3-kit.json" ]; then say "kit: not installed"; echo "RESULT absent"; exit 0; fi
  if [ "$(installed_sha)" = "$KSHA" ]; then say "kit: installed, the one this build of 1401 uses ($KNAME)"; echo "RESULT current"; exit 0; fi
  say "kit: installed, but not the one this build of 1401 uses"; echo "RESULT other"; exit 0;;
remove)
  [ "$NEED_ROOT" = 0 ] || [ "$(id -u)" = 0 ] || stop "this must run as root. Nothing was changed"
  [ -L "$DEST" ] && stop "$DEST is a link, not a folder; not touched"
  [ -e "$DEST" ] || { say "kit: not installed"; echo "RESULT ok"; exit 0; }
  rm -rf "$DEST" || stop "could not remove $DEST"
  rm -f "$DEST.archive-sha256"
  ok "the kit is removed"; echo "RESULT ok"; exit 0;;
get) ;;
*) echo "usage: nullmoth-v3-kit.sh status | get [--file FILE] | remove"; echo "RESULT stop"; exit 2;;
esac

read_pin
[ "$NEED_ROOT" = 0 ] || [ "$(id -u)" = 0 ] || stop "this must run as root. Nothing was changed"
for t in curl shasum tar stat mktemp; do command -v "$t" >/dev/null 2>&1 || stop "this macOS has no $t. Nothing was changed"; done

step "the kit this build of 1401 uses: $KNAME"
if [ "$(installed_sha)" = "$KSHA" ]; then ok "already installed"; echo "RESULT ok"; exit 0; fi

# Everything is done in a new folder that only root can open, on the same volume as the destination, so the last
# step is one rename. The folder above the destination must be a real folder owned by root.
PARENT=$(dirname "$DEST")
[ -L "$PARENT" ] && stop "$PARENT is a link, not a folder. Nothing was changed"
mkdir -p "$PARENT" || stop "could not make $PARENT. Nothing was changed"
if [ "$NEED_ROOT" = 1 ]; then
  [ "$(stat -f '%u' "$PARENT")" = 0 ] || stop "$PARENT does not belong to root. Nothing was changed"
  case "$(stat -f '%Lp' "$PARENT")" in *[2367][0-7]|*[2367]) stop "$PARENT can be written by others than root. Nothing was changed";; esac
fi
need_kb=$(( (KSIZE / 1024) * 4 + 102400 ))
free_kb=$(df -k "$PARENT" | awk 'NR==2 {print $4}')
[ "${free_kb:-0}" -ge "$need_kb" ] || stop "not enough room for the kit: $(( need_kb / 1024 )) MB needed. Nothing was changed"
WORK=$(mktemp -d "$PARENT/.v3-kit.XXXXXXXX") || stop "could not make a work folder. Nothing was changed"
chmod 700 "$WORK"
A="$WORK/archive"

step "the archive"
if [ -n "$FILE" ]; then
  [ -f "$FILE" ] || stop "$FILE is not a file. Nothing was changed"
  cat "$FILE" > "$A" || stop "could not read $FILE. Nothing was changed"
  ok "taken from $FILE"
else
  got=0
  for b in $BASES; do
    case "$b" in *github.com*) u="$b/$KTAG/$KNAME";; *) u="$b/$KNAME";; esac
    say "NOTE downloading $u"
    # curl runs silent (its own meter is not for a window); how far it is comes from the size of the file so far,
    # as "PROGRESS kit-download <percent> <bytes so far> <bytes in all>" lines, which 1401 draws as a bar.
    curl -f -L -sS --proto "$PROTO" --proto-redir "$PROTO" --connect-timeout 30 --retry 5 --retry-delay 5 \
         --max-filesize "$KSIZE" -o "$A" "$u" &
    cpid=$!
    while kill -0 "$cpid" 2>/dev/null; do
      sleep 1
      sz=$(stat -f '%z' "$A" 2>/dev/null || echo 0); [ "$sz" -le "$KSIZE" ] || sz=$KSIZE
      [ "$KSIZE" -gt 0 ] && echo "PROGRESS kit-download $(( sz * 100 / KSIZE )) $sz $KSIZE"
    done
    if wait "$cpid"; then echo "PROGRESS kit-download 100 $KSIZE $KSIZE"; got=1; break; fi
    rm -f "$A"
  done
  [ "$got" = 1 ] || stop "the kit could not be downloaded. Check the internet connection and try again. Nothing was changed"
fi
sz=$(stat -f '%z' "$A")
[ "$sz" = "$KSIZE" ] || stop "the archive is $sz bytes, the kit is $KSIZE: this is not the kit this build of 1401 uses. Nothing was changed"
sum=$(shasum -a 256 "$A" | awk '{print $1}')
[ "$sum" = "$KSHA" ] || stop "the archive's checksum does not match: this is not the kit this build of 1401 uses. Nothing was changed"
ok "size and SHA-256 match"

step "what the archive holds"
# Only plain files and folders under v3-kit/ are accepted: no links, no devices, no path that leaves the folder.
L="$WORK/list"
tar -tvzf "$A" > "$L" 2>/dev/null || stop "the archive cannot be read. Nothing was changed"
bad=$(awk '{ t=substr($1,1,1); if (t != "-" && t != "d") print }' "$L" | head -n 1)
[ -z "$bad" ] || stop "the archive holds something that is neither a file nor a folder. Nothing was changed"
N="$WORK/names"
tar -tzf "$A" > "$N" 2>/dev/null || stop "the archive cannot be read. Nothing was changed"
bad=$(grep -v -E '^v3-kit(/|$)' "$N" | head -n 1); [ -z "$bad" ] || stop "the archive holds a path outside v3-kit. Nothing was changed"
bad=$(grep -E '(^|/)\.\.(/|$)' "$N" | head -n 1); [ -z "$bad" ] || stop "the archive holds a path that leaves its folder. Nothing was changed"
grep -q -x 'v3-kit/v3-kit.json' "$N" || stop "the archive holds no v3-kit/v3-kit.json. Nothing was changed"
ok "$(grep -c -v '/$' "$N") files, all inside v3-kit"

step "install"
mkdir "$WORK/x" || stop "could not unpack. Nothing was changed"
tar -xzf "$A" -C "$WORK/x" --no-same-owner --no-same-permissions 2>/dev/null || stop "the archive did not unpack. Nothing was changed"
K="$WORK/x/v3-kit"
[ -d "$K" ] && [ ! -L "$K" ] && [ -f "$K/v3-kit.json" ] || stop "the unpacked kit is not complete. Nothing was changed"
[ -z "$(find "$K" -type l -print | head -n 1)" ] || stop "the unpacked kit holds a link. Nothing was changed"
if [ "$NEED_ROOT" = 1 ]; then chown -R root:wheel "$K" || stop "could not set the kit's owner. Nothing was changed"; fi
chmod -R go-w "$K" || stop "could not set the kit's permissions. Nothing was changed"
find "$K" -type d -exec chmod 755 {} + ; find "$K" -type f ! -perm -100 -exec chmod 644 {} + ; find "$K" -type f -perm -100 -exec chmod 755 {} +
[ -L "$DEST" ] && stop "$DEST is a link, not a folder. Nothing was changed"
if [ -e "$DEST" ]; then mv "$DEST" "$WORK/old" || stop "could not set the old kit aside. Nothing was changed"; fi
if ! mv "$K" "$DEST"; then
  [ -e "$WORK/old" ] && mv "$WORK/old" "$DEST"
  stop "could not put the kit in place; the previous kit is back"
fi
rm -f "$DEST.archive-sha256"; printf '%s\n' "$KSHA" > "$DEST.archive-sha256"; chmod 644 "$DEST.archive-sha256"
rm -rf "$WORK"; WORK=""
ok "the kit is in $DEST"
echo "RESULT ok"
