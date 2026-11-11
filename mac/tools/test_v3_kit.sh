#!/bin/bash
# test_v3_kit.sh <kit folder> - arms for nullmoth-v3-kit.sh and pack_v3_kit.sh. Runs without root, in a temp folder,
# through the script's test options (--dest, --pin, --bases); nothing under /Library is read or written.
set -u
KIT=${1:?a v3 kit folder}; HERE=$(cd "$(dirname "$0")" && pwd); S="$HERE/../Resources/nullmoth-v3-kit.sh"
T=$(mktemp -d); trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
pass=0; fail=0
arm() { if [ "$2" = "$3" ]; then pass=$((pass+1)); echo "ok   $1"; else fail=$((fail+1)); echo "FAIL $1"; echo "     got:  $2"; echo "     want: $3"; fi; }
last() { printf '%s\n' "$1" | tail -n 1; }
has() { printf '%s\n' "$1" | grep -q -- "$2" && echo yes || echo no; }

bash "$HERE/pack_v3_kit.sh" "$KIT" v3.0.0-test.1 "$T/a" > "$T/pin1.txt" || { echo "FAIL pack"; exit 1; }
bash "$HERE/pack_v3_kit.sh" "$KIT" v3.0.0-test.1 "$T/b" > /dev/null
AR="$T/a/nullmoth-v3-kit-3.0.0-test.1.tar.gz"; PIN="$T/a/v3-kit.pin"
arm "the same kit packs to the same archive twice" "$(shasum -a 256 < "$AR")" "$(shasum -a 256 < "$T/b/nullmoth-v3-kit-3.0.0-test.1.tar.gz")"
arm "the archive holds only files and folders" "$(tar -tvzf "$AR" | awk '{print substr($1,1,1)}' | sort -u | tr -d '\n')" "-d"
arm "the archive names no user and no time of ours" "$(tar -tvzf "$AR" | awk '{print $3"/"$4}' | sort -u | tr -d '\n')" "root/wheel"
run() { bash "$S" "$@" --pin "$PIN" --bases "https://127.0.0.1:9/none" 2>&1; }
D="$T/lib/v3-kit"

o=$(run status --dest "$D"); arm "status before: not installed" "$(last "$o")" "RESULT absent"
o=$(run get --dest "$D"); arm "no file and an address that does not answer: refused, nothing made" "$(last "$o") $(ls "$T/lib" 2>/dev/null | wc -l | tr -d ' ')" "RESULT stop 0"
o=$(run get --dest "$D" --file "$AR"); arm "the pinned archive installs" "$(last "$o")" "RESULT ok"
arm "the installed kit equals the source kit, file for file" "$(cd "$D" && find . -type f -exec shasum -a 256 {} + | LC_ALL=C sort | shasum | cut -c1-40)" "$(cd "$KIT" && find . -type f ! -name .DS_Store -exec shasum -a 256 {} + | LC_ALL=C sort | shasum | cut -c1-40)"
arm "nothing in the installed kit can be written by group or others, and no work folder is left" "$(find "$D" -perm +022 | wc -l | tr -d ' ') $(ls -A "$T/lib" | grep -c '^\.v3-kit\.')" "0 0"
o=$(run status --dest "$D"); arm "status after: this build's kit" "$(last "$o")" "RESULT current"
o=$(run get --dest "$D" --file /nonexistent); arm "a second get does nothing, even with a bad file" "$(has "$o" 'already installed') $(last "$o")" "yes RESULT ok"

# the download: silent curl, PROGRESS lines made from the size of the file, nothing that rewrites a line
o=$(bash "$S" get --dest "$T/libdl/v3-kit" --pin "$PIN" --bases "file://$T/a" --protocol '=file' 2>&1)
arm "a download installs the kit and ends its progress at 100 with the pinned size" "$(last "$o") $(printf '%s\n' "$o" | grep '^PROGRESS ' | tail -n 1)" "RESULT ok PROGRESS kit-download 100 $(stat -f '%z' "$AR") $(stat -f '%z' "$AR")"
arm "every progress line is 'PROGRESS kit-download <percent> <bytes> <bytes>', and the output holds no carriage return" "$(printf '%s\n' "$o" | grep '^PROGRESS ' | grep -c -v -E '^PROGRESS kit-download [0-9]{1,3} [0-9]+ [0-9]+$') $(printf '%s' "$o" | tr -d -c '\r' | wc -c | tr -d ' ')" "0 0"
arm "the shipped script takes only https" "$(grep -c "^PROTO='=https'$" "$S") $(grep -c -- '--proto "\$PROTO" --proto-redir "\$PROTO"' "$S")" "1 1"

# refusals: each leaves the installed kit as it was
before=$(cd "$D" && find . -type f -exec shasum {} + | LC_ALL=C sort | shasum)
printf 'x' >> "$T/grown.tgz"; cat "$AR" "$T/grown.tgz" > "$T/longer.tgz"
head -c 100000 "$AR" > "$T/short.tgz"
python3 - "$AR" "$T/flip.tgz" <<'PY'
import sys
b=bytearray(open(sys.argv[1],'rb').read()); b[len(b)//2]^=1; open(sys.argv[2],'wb').write(b)
PY
D2="$T/lib2/v3-kit"
for c in longer short flip; do
  o=$(run get --dest "$D2" --file "$T/$c.tgz")
  arm "refused, nothing installed: archive '$c' than the pinned one" "$(last "$o") $(ls -A "$T/lib2" 2>/dev/null | wc -l | tr -d ' ')" "RESULT stop 0"
done
# archives that match a pin of their own but hold what a kit may not
mk() { # <name> <builder commands run inside a folder>
  rm -rf "$T/m"; mkdir -p "$T/m/v3-kit"; echo '{}' > "$T/m/v3-kit/v3-kit.json"; ( cd "$T/m" && eval "$2" )
  ( cd "$T/m" && COPYFILE_DISABLE=1 tar -czf "$T/$1.tgz" $3 )
  printf 'name %s\ntag t\nsize %s\nsha256 %s\n' "$1.tgz" "$(stat -f '%z' "$T/$1.tgz")" "$(shasum -a 256 "$T/$1.tgz" | awk '{print $1}')" > "$T/$1.pin"
}
mk link 'ln -s /etc/hosts v3-kit/hosts' v3-kit
mk outside 'echo x > other' 'v3-kit other'
mk nomanifest 'rm v3-kit/v3-kit.json; echo x > v3-kit/a' v3-kit
for c in link outside nomanifest; do
  o=$(bash "$S" get --dest "$T/lib3/v3-kit" --pin "$T/$c.pin" --bases https://127.0.0.1:9/none --file "$T/$c.tgz" 2>&1)
  arm "refused, nothing installed: an archive with '$c'" "$(last "$o") $(ls -A "$T/lib3" 2>/dev/null | wc -l | tr -d ' ')" "RESULT stop 0"
done
python3 - "$T/dotdot.tgz" <<'PY'
import tarfile,io,sys
t=tarfile.open(sys.argv[1],'w:gz')
for n,d in (('v3-kit/v3-kit.json',b'{}'),('v3-kit/../escaped',b'x')):
    i=tarfile.TarInfo(n); i.size=len(d); t.addfile(i,io.BytesIO(d))
t.close()
PY
printf 'name dotdot.tgz\ntag t\nsize %s\nsha256 %s\n' "$(stat -f '%z' "$T/dotdot.tgz")" "$(shasum -a 256 "$T/dotdot.tgz" | awk '{print $1}')" > "$T/dotdot.pin"
o=$(bash "$S" get --dest "$T/lib4/v3-kit" --pin "$T/dotdot.pin" --bases https://127.0.0.1:9/none --file "$T/dotdot.tgz" 2>&1)
arm "refused, nothing installed, nothing escaped: a path with '..'" "$(last "$o") $(ls -A "$T/lib4" 2>/dev/null | wc -l | tr -d ' ') $(ls "$T/escaped" 2>/dev/null | wc -l | tr -d ' ')" "RESULT stop 0 0"
o=$(bash "$S" get --dest "$T/lib5/v3-kit" --pin "$T/none.pin" --bases https://127.0.0.1:9/none --file "$AR" 2>&1)
arm "no pin: macOS 27 is not offered" "$(has "$o" 'not offered by this build') $(last "$o")" "yes RESULT stop"
printf 'name ../x\ntag t\nsize 1\nsha256 %064d\n' 0 > "$T/badname.pin"
o=$(bash "$S" get --dest "$T/lib5/v3-kit" --pin "$T/badname.pin" --bases https://127.0.0.1:9/none 2>&1)
arm "a pin whose name holds a path is refused" "$(last "$o")" "RESULT stop"
arm "after every refusal the installed kit is unchanged" "$(cd "$D" && find . -type f -exec shasum {} + | LC_ALL=C sort | shasum)" "$before"
ln -s "$T/a" "$T/lib6"; o=$(run get --dest "$T/lib6/v3-kit" --file "$AR")
arm "a destination whose folder is a link is refused" "$(last "$o") $(ls "$T/a" | grep -c v3-kit$)" "RESULT stop 0"
o=$(bash "$S" get --pin "$PIN" --file "$AR" 2>&1); arm "without the test options and without root: refused" "$(last "$o")" "RESULT stop"
o=$(run remove --dest "$D"); arm "remove takes the kit and its record away" "$(last "$o") $(ls -A "$T/lib" | wc -l | tr -d ' ')" "RESULT ok 0"
echo "$pass passed, $fail failed"; [ "$fail" = 0 ]
