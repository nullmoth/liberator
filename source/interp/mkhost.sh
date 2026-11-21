#!/bin/bash
# mkhost.sh — build the generic arm64 host.  NOT a per-app build: this binary is fixed and takes any arm64
#    Mach-O as an argument. It is the thing the OS would install.
#  -no_pie + image_base 0x400000000: a macOS executable defaults to 0x100000000, which is exactly where the
#    GUEST wants its __TEXT — the host must live out of the guest's way or every mapping fails on the first
#    segment. The per-app host has carried this flag since 10-10; the generic one needs it for the same reason.
#  -stack_size 60 MB: the interpreter's frames are far wider than the arm64 frames they stand in for.
set -u
D=$(cd "$(dirname "$0")" && pwd)
O=${1:?output path}
X=${ARM2X86_LLVM:-/opt/homebrew/Cellar/llvm/22.1.8/bin}
SDK=${HOST_SDK:-$(xcrun --show-sdk-path)}
# 27.2 build: HOST_SDK = the 27.2 SDK, HOST_LD_DIR = the 27.2 linker (reads arm64e.x1 stubs), HOST_MACABI=27.2 so the host
# carries Apple's own Catalyst stamp (UIKitSystem on 27.2 = MACCATALYST minos 27.2 sdk 27.2): frameworks gate behaviour on the
# running main executable's SDK, and that is this slice. Unset = the old 18.0 build.
MA=${HOST_MACABI:-18.0}
LDF=${HOST_LD_DIR:+-B$HOST_LD_DIR -fuse-ld=$HOST_LD_DIR/ld}
python3 "$D/mksigtable.py" "$D/sig_table.h" || exit 2
"$X/llc" -filetype=obj -mtriple=x86_64-apple-ios${MA}-macabi "$D/native_door.ll" -o "$D/native_door.o" || exit 2
"$X/llc" -filetype=obj -mtriple=x86_64-apple-ios${MA}-macabi "$D/eh_guard.ll" -o "$D/eh_guard.o" || exit 2
#  GENERATE THE GENERATED FILES, NEVER TRUST A CHECKED-IN COPY. rf_table.h and cb_slots.s are both
#    generated, and both were COMMITTED — so every build used whatever was last written by hand. That is
#    drift this project has already paid for: the symbol→bridge routing table lives in TWO sources
#    (xlat2.py AND xlat.py), and reading only one left objc_msgSend bound natively, which surfaced as an
#    "unrecognized selector" nowhere near the cause. Regenerating here makes a stale table impossible.
#  A GENERATOR THAT CANNOT RUN FAILS THE BUILD. Skipping it would leave yesterday's answer in place and
#    build green against it, which is strictly worse than not building at all.
python3 "$D/mkrftable.py" || { echo "mkhost: mkrftable.py failed — REFUSING to build against a stale rf_table.h" >&2; exit 2; }
python3 "$D/mkcbslots.py" || { echo "mkhost: mkcbslots.py failed — REFUSING to build against a stale cb_slots.s" >&2; exit 2; }
"$X/clang" -target x86_64-apple-ios${MA}-macabi -c "$D/cb_slots.s" -o "$D/cb_slots.o" || exit 2
"$X/clang" -target x86_64-apple-ios${MA}-macabi -c "$D/swift_door.s" -o "$D/swift_door.o" || exit 2
"$X/clang" -target x86_64-apple-ios${MA}-macabi -isysroot "$SDK" $LDF -O2 -w -DA2X_SLOTS=1 -include "$D/a2x_flavour.h" ${A2X_BUILD_ID:+-DA2X_BUILD_ID="\"$A2X_BUILD_ID\""} ${A2X_SHIP:+-DA2X_SHIP=1 -ffile-prefix-map="$D"=. -Wl,-x} \
  -Wl,-headerpad,0x2000 -Wl,-no_pie -Wl,-image_base,0x400000000 -Wl,-stack_size,0x3C00000 \
  -Wl,-segaddr,__ARMRSV,0x100000000 \
  -Wl,-sectcreate,__TEXT,__info_plist,"$D/infoplist_reserve.bin" \
  -o "$O" \
  ${A2XPRE:+"$A2XPRE"} \
  "$D/host.c" "$D/unwfix.c" "$D/machofix.c" "$D/a64_all.c" "$D/a64slot.c" "$D/a64_eh.c" "$D/vararg.c" \
  "$D/compat_roundeven.c" \
  "$D/host_doors.c" "$D/cb_host.c" "$D/tlv.c" "$D/sig_door.c" "$D/gss_abi.c" "$D/audit_abi.c" "$D/sig_guest.c" "$D/exc_front.c" "$D/spawn_arch.c" "$D/ws_quartz.c" "$D/sl_display.c" "$D/swift_xi.c" "$D/ls_gate.c" "$D/guest_sections.c" "$D/guest_infoplist.c" "$D/cb_slots.o" "$D/swift_door.o" "$D/objc_bridge.c" "$D/swift_vlb.c" "$D/cxx_bridge.cpp" \
  -lffi -lobjc -lc++ -framework Foundation \
  "$D/native_door.o" "$D/eh_guard.o" || exit 3
echo "host: $O"
