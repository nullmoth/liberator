# Makefile - arm2x86 OS-level exec hook.
#
#  UNTESTED. Nothing here has been run. `make` has never been invoked in
# this directory, so even the flag spellings are unverified.
#
#  THE KEXT MUST BE BUILT FOR x86_64 ON A MACHINE WITH A FULL TOOLCHAIN.
# The target is Intel macOS 27; building it on the arm64 laptop needs
# -arch x86_64 and the macOS 27 SDK.
#
# Two products, deliberately separate:
#   selftest  - the decision logic, in userspace, the only thing with arms
#   kext      - the thing that touches a live kernel
#
#  RUN THE SELFTEST FIRST AND EVERY TIME. It is the only check in this
# directory that does not need a disposable VM.

SDK      ?= $(shell xcrun --sdk macosx --show-sdk-path)
KINC      = $(SDK)/System/Library/Frameworks/Kernel.framework/Headers
CC       ?= clang
BUNDLE    = a2x_exec_hook.kext

# ---------------------------------------------------------------- selftest
#  -fno-builtin so the byte loops in the logic stay byte loops; the kernel
# build must not turn them into a libc memcpy that is not linkable there.
selftest: a2x_hook_logic.c a2x_hook_logic.h
	$(CC) -DA2X_SELFTEST -Wall -Wextra -Wno-unused-function \
	    -fno-builtin -O1 -o a2x_logic_selftest a2x_hook_logic.c
	./a2x_logic_selftest --selftest

# -------------------------------------------------------------------- kext
#  -mno-red-zone and -fno-builtin are not optional for kernel code.
#  -mno-sse keeps the logic out of vector registers in the exec path; the
# byte loops give the compiler no reason to vectorize, and this removes the
# question entirely.
KCFLAGS = -arch x86_64 -isysroot $(SDK) -I$(KINC) -I. \
	  -DKERNEL -DKERNEL_PRIVATE -DAPPLE -D__APPLE__ \
	  -mkernel -fno-builtin -fno-common -mno-red-zone -mno-sse \
	  -fno-stack-protector -Wall -Wextra -O2 \
	  -std=gnu11 -target x86_64-apple-macos27.0

OBJS = a2x_hook_kext.o a2x_hook_logic.o a2x_hook_tramp.o a2x_adopt.o a2x_split.o a2x_ident.o

KCXXFLAGS = -arch x86_64 -isysroot $(SDK) -I$(KINC) -I. \
	  -DKERNEL -DKERNEL_PRIVATE -DAPPLE -D__APPLE__ \
	  -mkernel -fno-builtin -fno-common -mno-red-zone -mno-sse \
	  -fno-stack-protector -fno-rtti -fno-exceptions -Wall -Wextra -O2 \
	  -std=gnu++17 -target x86_64-apple-macos27.0

a2x_ident.o: a2x_ident.cpp
	$(CXX) $(KCXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(KCFLAGS) -c $< -o $@

a2x_hook_tramp.o: a2x_hook_tramp.s
	$(CC) -arch x86_64 -isysroot $(SDK) -c $< -o $@

kext: $(OBJS) Info.plist
	mkdir -p $(BUNDLE)/Contents/MacOS
	cp Info.plist $(BUNDLE)/Contents/Info.plist
	$(CC) -arch x86_64 -isysroot $(SDK) -Xlinker -kext -nostdlib \
	    -lkmod -lcc_kext \
	    -Xlinker -e -Xlinker _a2x_hook_start \
	    -o $(BUNDLE)/Contents/MacOS/a2x_exec_hook $(OBJS)
	@echo " UNSIGNED. install_os_exec_hook.sh signs and stages it."

clean:
	rm -rf $(OBJS) a2x_logic_selftest $(BUNDLE)

.PHONY: selftest kext clean
