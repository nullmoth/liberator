#!/bin/bash
# mkpre.sh <out dylib> <install name> [-DA2XPRE_CAT_BUILD]
set -u
D=$(cd "$(dirname "$0")" && pwd); X=${ARM2X86_LLVM:-/opt/homebrew/Cellar/llvm/22.1.8/bin}; SDK=${HOST_SDK:-$(xcrun --show-sdk-path)}; MA=${HOST_MACABI:-18.0}; LDF=${HOST_LD_DIR:+-B$HOST_LD_DIR -fuse-ld=$HOST_LD_DIR/ld}
"$X/clang" -target x86_64-apple-ios${MA}-macabi -isysroot "$SDK" $LDF -O2 -w -include "$D/a2x_flavour.h" ${A2X_BUILD_ID:+-DA2X_BUILD_ID="\"$A2X_BUILD_ID\""} ${A2X_SHIP:+-DA2X_SHIP=1 -ffile-prefix-map="$D"=. -Wl,-x} -dynamiclib ${3:-} -o "$1" "$D/a2xpre.c" -install_name "$2" || exit 2
echo "pre: $1"
