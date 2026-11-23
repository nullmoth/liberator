#!/bin/bash
# build-kext.sh - build A2XACPIPlatform.kext (ACPICA + OS layer + platform expert) for the macOS 27 x86_64 kernel.
# Needs libacpica.a from build-acpica.sh. Output: out/A2XACPIPlatform.kext. Exit != 0 on any failure.
set -euo pipefail
A=$(cd "$(dirname "$0")" && pwd); cd "$A"
# Kernel headers: the 26.5 SDK with IOKit/pci replaced by 27's (27 IOPCIBridge/IOPCIDevice override getWorkLoop;
# the 27 SDK alone does not compile: its IOPM.h dropped the IOPMDriverAssertion typedefs RootDomain.h uses).
K=${SDK27_KERNEL_HEADERS:?set SDK27_KERNEL_HEADERS (see README)}
CXX=(xcrun clang++ -arch x86_64 -mkernel -fapple-kext -nostdinc -std=gnu++17 -O2 -DKERNEL -DACPI_XNU_KERNEL
     -I"$K" -I"$A/acpica/source/include" -Wall -Wno-unused-parameter -Wno-extern-c-compat -Wno-macro-redefined)
CC=(xcrun clang -arch x86_64 -mkernel -nostdinc -O2 -DKERNEL -I"$K")

[ -f libacpica.a ] || { echo "libacpica.a missing: run build-acpica.sh"; exit 1; }
mkdir -p kobj out
# confollow.h arms (incl. negative controls: the old policies must fail them) gate the build.
xcrun clang -O1 -Wall -Iport port/confollow_selftest.c -o kobj/confollow_selftest
kobj/confollow_selftest > kobj/confollow_selftest.log || { cat kobj/confollow_selftest.log; echo "confollow selftest FAILED"; exit 1; }
tail -1 kobj/confollow_selftest.log
"${CXX[@]}" -c port/osxnu.cpp  -o kobj/osxnu.o
"${CXX[@]}" -c port/expert.cpp -o kobj/expert.o
"${CXX[@]}" -c port/events.cpp -o kobj/events.o
"${CXX[@]}" -c port/cpuint.cpp -o kobj/cpuint.o
"${CXX[@]}" -c port/pcibridge.cpp -o kobj/pcibridge.o
"${CXX[@]}" -c port/buttons.cpp -o kobj/buttons.o
"${CXX[@]}" -c port/crumb.cpp -o kobj/crumb.o
"${CXX[@]}" -c port/devprops.cpp -o kobj/devprops.o
"${CXX[@]}" -c port/vtdmap.cpp -o kobj/vtdmap.o
"${CXX[@]}" -c port/xhciroute.cpp -o kobj/xhciroute.o
# The private IOCPU / IOCPUInterruptController declarations must match the kernel slots it calls.
"${CXX[@]}" -include IOKit/IOPlatformExpert.h -c port/vtcheck.cpp -o kobj/vtcheck.o
VT=$(xcrun llvm-objdump -d kobj/vtcheck.o)
for want in "a2x_vt_cpunum 0x8a0" "a2x_vt_handle 0x888" "a2x_vt_regctl 0x900"; do
    set -- $want
    echo "$VT" | awk -v f="<_$1>:" '$0 ~ f {on=1; next} /^$/ {on=0} on' | grep -qE "[[:space:]*]$2\(%" \
        || { echo "vtable slot mismatch: $1 is not $2"; exit 1; }
done
cat > kobj/info.c <<'EOF'
#include <mach/mach_types.h>
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
__attribute__((visibility("default"))) KMOD_EXPLICIT_DECL(net.arm2x86.platform.ACPIPlatform, "1.0.0", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = 0;
__private_extern__ kmod_stop_func_t *_antimain = 0;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
EOF
"${CC[@]}" -c kobj/info.c -o kobj/info.o

B=out/A2XACPIPlatform.kext
rm -rf "$B"; mkdir -p "$B/Contents/MacOS"
xcrun clang++ -arch x86_64 -Xlinker -kext -nostdlib -Xlinker -export_dynamic \
    kobj/info.o kobj/expert.o kobj/events.o kobj/cpuint.o kobj/pcibridge.o kobj/buttons.o kobj/crumb.o kobj/devprops.o kobj/vtdmap.o kobj/xhciroute.o kobj/osxnu.o -Wl,-force_load,libacpica.a -lkmodc++ -lkmod -lcc_kext \
    -o "$B/Contents/MacOS/A2XACPIPlatform"
cp port/Info.plist "$B/Contents/Info.plist"
plutil -lint "$B/Contents/Info.plist" >/dev/null
codesign -f -s - "$B" 2>/dev/null
echo "built $B $(stat -f %z "$B/Contents/MacOS/A2XACPIPlatform") bytes"
