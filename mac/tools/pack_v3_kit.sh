#!/bin/bash
# pack_v3_kit.sh <kit folder> <tag> <out folder> - makes the one archive of a v3 kit and the pin the app is built with.
# The archive holds the folder as v3-kit/, plain files and folders only, in sorted order with fixed owner and times,
# so the same kit always gives the same archive. Prints the pin (name, tag, size, sha256) and writes it as v3-kit.pin.
set -eu
KIT=${1:?kit folder}; TAG=${2:?release tag, e.g. v3.0.0-beta.1}; OUT=${3:?out folder}
[ -f "$KIT/v3-kit.json" ] || { echo "STOP $KIT holds no v3-kit.json"; exit 1; }
[ -z "$(find "$KIT" -type l -print | head -n 1)" ] || { echo "STOP the kit holds a link"; exit 1; }
case "$TAG" in *[!A-Za-z0-9._-]*) echo "STOP the tag may hold letters, digits, dot, dash and underscore only"; exit 1;; esac
mkdir -p "$OUT"; W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
mkdir "$W/v3-kit"; (cd "$KIT" && tar -cf - .) | (cd "$W/v3-kit" && tar -xf -)
find "$W/v3-kit" -name .DS_Store -delete; find "$W/v3-kit" -exec touch -h -t 202601010000 {} +
NAME="nullmoth-v3-kit-${TAG#v}.tar.gz"
(cd "$W" && find v3-kit -print | LC_ALL=C sort > "$W/order" && COPYFILE_DISABLE=1 tar --no-recursion --uid 0 --gid 0 --uname root --gname wheel --no-xattrs --no-mac-metadata -cf - -T "$W/order") | gzip -n -9 > "$OUT/$NAME"
SIZE=$(stat -f '%z' "$OUT/$NAME"); SHA=$(shasum -a 256 "$OUT/$NAME" | awk '{print $1}')
printf 'name %s\ntag %s\nsize %s\nsha256 %s\n' "$NAME" "$TAG" "$SIZE" "$SHA" | tee "$OUT/v3-kit.pin"
