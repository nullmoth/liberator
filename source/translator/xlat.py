#!/usr/bin/env python3
"""xlat.py — ladder rung 1 (Layers 1+2+3-C): ANY plain-arm64 Mach-O executable -> a native x86_64 executable.

    python3 xlat.py <arm64-exe> <outdir> [cpu]          (cpu: llc -mcpu, default x86-64-v3)

 Nothing here names a program. R34 (compression_tool) proved the pipeline with a HAND table of imports, a hand stub range
   and a hand-written main; this derives all three from the binary and the SDK:
   - code      : llvm-objdump __text + dyld_info -function_starts -> split_fns (the one splitter) -> arm2x86.build()
   - imports   : __stubs decoded (adrp x16 / ldr x16,[x16,#o] / br x16) -> GOT slot -> dyld_info bind symbol ->
                 sigdb.json (clang's own declarations) -> a bind with the TRUE argument kinds and return type
   - variadics : Apple arm64 passes every variadic argument on the stack; a SysV va_list whose overflow area IS the arm64
                 stack reads them exactly (R34). printf-family binds go to a generated thunk calling the v-variant;
                 open/openat/fcntl/ioctl read their one optional int tail the same way.
   - data      : every GOT slot gets the NATIVE address of its symbol at boot (dlsym) — ___stdoutp, ___stack_chk_guard ...
   - entry     : LC_MAIN entryoff -> x_fn_<addr>(argc, argv, envp, apple)
 An import with no declaration, or one sigdb refused ('x': struct by value, long double, block, _Float16), is left UNBOUND:
   reaching it aborts BY NAME. Guessing its registers would run with garbage arguments and look like it works.
 The arm64 image keeps its own addresses: a zerofill __ARMRSV segment pinned at the image's vm base reserves the range at
   exec, before dyld allocates (R34). Its size is the image's vm size — computed, not a constant."""
import json, os, re, struct, subprocess, sys
import split_fns
from arm2x86 import build

S = os.path.dirname(os.path.abspath(__file__))
LLVM = os.environ.get('ARM2X86_LLVM', '/opt/homebrew/Cellar/llvm@22/22.1.8/bin')   #  10-03: the mini's 22.1.8 lives at Cellar/llvm/
OBJDUMP = 'xcrun'
VTAB = {'printf': 'vprintf', 'fprintf': 'vfprintf', 'sprintf': 'vsprintf', 'snprintf': 'vsnprintf', 'asprintf': 'vasprintf',
        'dprintf': 'vdprintf', 'scanf': 'vscanf', 'fscanf': 'vfscanf', 'sscanf': 'vsscanf', 'syslog': 'vsyslog',
        'err': 'verr', 'errx': 'verrx', 'warn': 'vwarn', 'warnx': 'vwarnx', 'fwprintf': 'vfwprintf', 'swprintf': 'vswprintf',
        'wprintf': 'vwprintf', 'NSLog': 'NSLogv', 'CFStringCreateWithFormat': 'CFStringCreateWithFormatAndArguments',
        #  10-05 the FORTIFIED forms (clang emits them for sprintf/snprintf under _FORTIFY_SOURCE) were missing: Cyberpunk's
        #    4 __sprintf_chk sites went to the x0-x7 adapter, and native code read the arm64 STACK varargs from x86 registers
        '__sprintf_chk': '__vsprintf_chk', '__snprintf_chk': '__vsnprintf_chk',
        #  10-10 THE SAME BUG AGAIN, AND IT COST A BOOT. A variadic native with no v-form here is called through the
        #    plain adapter, so the callee reads varargs from x86 registers while the arm64 caller left them on ITS stack.
        #    macOS 27's opendirectoryd died in _platform_strlen on 0xffffffff00000000, called from __vfprintf — asl_log,
        #    which sigdb marks va=1 but VTAB could not map. Every pair below was PROBED with dlsym in a real x86_64
        #    process before being added; the ones whose v-form does not exist (asl_log_message, malloc_printf) are
        #    deliberately absent rather than guessed.
        #  CFStringAppendFormat cost a second round: the first probe for its v-form linked only libSystem, so the
        #    CoreFoundation symbols "did not exist" — a fact about the probe, not about the system. Re-probed with
        #    CoreFoundation linked, both are present. opendirectoryd died SIGTRAP inside
        #    __CFSTRING_IS_CALLING_OUT_TO_AN_OBJECT_FORMAT_ARGUMENT_WITH_LOCALE__ reading varargs from x86 registers.
        'CFStringAppendFormat': 'CFStringAppendFormatAndArguments',
        'CFStringCreateStringWithValidatedFormat': 'CFStringCreateStringWithValidatedFormatAndArguments',
        'asl_log': 'asl_vlog', 'errc': 'verrc', 'warnc': 'vwarnc',
        'fwscanf': 'vfwscanf', 'swscanf': 'vswscanf', 'wscanf': 'vwscanf',
        'xpc_string_create_with_format': 'xpc_string_create_with_format_and_arguments',
        'dispatch_debug': 'dispatch_debugv',
        # the locale-suffixed family: every one verified present
        'printf_l': 'vprintf_l', 'fprintf_l': 'vfprintf_l', 'sprintf_l': 'vsprintf_l', 'snprintf_l': 'vsnprintf_l',
        'asprintf_l': 'vasprintf_l', 'dprintf_l': 'vdprintf_l', 'scanf_l': 'vscanf_l', 'sscanf_l': 'vsscanf_l',
        'fscanf_l': 'vfscanf_l', 'wprintf_l': 'vwprintf_l', 'fwprintf_l': 'vfwprintf_l', 'swprintf_l': 'vswprintf_l',
        'wscanf_l': 'vwscanf_l', 'fwscanf_l': 'vfwscanf_l', 'swscanf_l': 'vswscanf_l'}
VPROTO = {'__vsprintf_chk': 'extern int __vsprintf_chk(char *, int, size_t, const char *, va_list);',     # declared only
          '__vsnprintf_chk': 'extern int __vsnprintf_chk(char *, size_t, int, size_t, const char *, va_list);'}   # when fortified
INTTAIL = {'openat', 'fcntl', 'ioctl'}   # 'open' is handled by XARGCB (traced); one owner only          # one optional int-sized variadic argument
#  10-10 a DATA export of a translated bundle is not a function and cannot be wrapped: it must resolve to its
#    address INSIDE the mapped guest image (proxy.bundle exports _proxy_module, an 8-byte __common pointer the
#    module fills in at init, plus two __TEXT,__const version symbols). An absolute assembler symbol does that.
#     Anything the host later CALLS through such a pointer is still a raw arm64 address — that is a separate rung.
#  10-10 A CALLBACK BEHIND A BY-VALUE STRUCT. sigdb types such a struct as 'x' and the whole import is then left
#    unbound, so its callback argument never reaches __arm2x86_cb and native code jumps into raw arm64 bytes
#    (opendirectoryd -> CFArrayApplyFunction -> SIGBUS at a guest address, 10-10). A struct of integer fields that is
#    16 bytes or less occupies ceil(size/8) consecutive INTEGER registers on arm64 AND on x86-64, so the thunk can take
#    those registers as plain words and rebuild the struct. sizeof is asserted at compile time, never assumed here:
#    CFRange measured at 16 bytes = 2 registers, so the applier lands in x3 (not x2, which is half the range — that
#    off-by-one is exactly why reading sigdb's C-argument index as a register index would also have been wrong).
#    The entry is (register count, return kind, body). The register count is the arm64 x-register footprint of the
#    whole argument list, which is what the IR hands over; the return kind is sigdb's own code ('i64') when the callee returns a value in
#    x0 ('void' otherwise) — dispatch_block_create hands back a block the program goes on to use, so losing its
#    return value would be its own silent bug.
XARGCB = {
    'CFArrayApplyFunction': (5, 'void', r'''
void @T@(unsigned long a0, unsigned long r1, unsigned long r2, unsigned long a3, unsigned long a4) {
    _Static_assert(sizeof(CFRange) == 16, "CFRange must occupy exactly two integer registers");
    unsigned long w[2] = { r1, r2 }; CFRange rg; memcpy(&rg, w, sizeof rg);
    CFArrayApplyFunction((CFArrayRef)a0, rg, (CFArrayApplierFunction)__arm2x86_cb(a3), (void *)a4);
}'''),
    'CFArraySortValues': (5, 'void', r'''
void @T@(unsigned long a0, unsigned long r1, unsigned long r2, unsigned long a3, unsigned long a4) {
    _Static_assert(sizeof(CFRange) == 16, "CFRange must occupy exactly two integer registers");
    unsigned long w[2] = { r1, r2 }; CFRange rg; memcpy(&rg, w, sizeof rg);
    CFArraySortValues((CFMutableArrayRef)a0, rg, (CFComparatorFunction)__arm2x86_cb(a3), (void *)a4);
}'''),
    'CFArrayBSearchValues': (6, 'i64', r'''
unsigned long @T@(unsigned long a0, unsigned long r1, unsigned long r2, unsigned long a3, unsigned long a4, unsigned long a5) {
    _Static_assert(sizeof(CFRange) == 16, "CFRange must occupy exactly two integer registers");
    unsigned long w[2] = { r1, r2 }; CFRange rg; memcpy(&rg, w, sizeof rg);
    return (unsigned long)CFArrayBSearchValues((CFArrayRef)a0, rg, (const void *)a3, (CFComparatorFunction)__arm2x86_cb(a4), (void *)a5);
}'''),
    #  the dispatch_block_* family: every argument is a scalar, but dispatch_block_flags_t is an enum sigdb types as
    #    'x', which left the whole import unbound and its BLOCK (not a function pointer — __arm2x86_blk, not
    #    __arm2x86_cb) unwrapped. Signatures read from the SDK's dispatch/block.h, not recalled.
    #  10-10 DIAGNOSTIC: the whole os_log stream of a translated daemon, without logd. Every Apple daemon says
    #    what went wrong through os_log, and on a bench with no logd that output goes nowhere — opendirectoryd dies
    #    with "Failed to open /Search" and not one line of why. _os_log_impl's 4th argument is the format string;
    #    printing it (unsubstituted) names the failing step. sigdb types arg 2 as 'x' (os_log_type_t), so without a
    #    hand-written thunk this import is unbound anyway. Gated on ARM2X86_TRACE_OSLOG; always calls through.
    '_os_log_impl': (6, 'void', r'''
void @T@(unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4, unsigned long a5) {
    /* the umbrella already declares _os_log_impl with its real prototype — do not redeclare it */
    if (a3 && getenv("ARM2X86_TRACE_OSLOG")) {
        fprintf(stderr, "[oslog:%lu] %s", a2, (const char *)a3);
        /* the format alone is not enough: every interesting value is a %{public}@ or %{public}s. Decode the
           argument buffer Apple passes alongside it — [flags][nargs] then per argument [descriptor][size][value].
           The low nibble of the descriptor is the type: 2 = C string, 4 = ObjC/CF object, anything else scalar. */
        const uint8_t *b = (const uint8_t *)a4; uint32_t n = (uint32_t)a5;
        if (b && n >= 2) {
            uint8_t nargs = b[1]; const uint8_t *p = b + 2;
            for (uint8_t i = 0; i < nargs && (uint32_t)(p - b) + 2 <= n; i++) {
                uint8_t type = *p++ & 0x0f, sz = *p++;
                if ((uint32_t)(p - b) + sz > n) break;
                /* NEVER dereference a pointer out of this buffer. The layout is Apple-private and this parse is
                   approximate: treating an argument as a char* walked strlen into unmapped memory, killed
                   opendirectoryd inside __vfprintf, wrote binary garbage into the log, and cut its own output from
                   1278 lines to 182. A scalar is copied out by value and is safe; a pointer is printed AS a value. */
                if (type == 2 && sz == 8) { fprintf(stderr, " | str@%p", *(void *const *)p); }
                else if (type == 4 && sz == 8) {
                    /* do NOT CFCopyDescription here. It allocates, takes locks and can run arbitrary -description
                       code; called from inside the logging path during early init it crashed opendirectoryd in
                       __vfprintf and cut its own log from 1278 lines to 182 — the diagnostic destroyed the
                       measurement. The pointer is enough to correlate; print it and touch nothing. */
                    fprintf(stderr, " | obj@%p", *(void *const *)p);
                } else if (sz && sz <= 8) { unsigned long long v = 0; memcpy(&v, p, sz); fprintf(stderr, " | %llu", v); }
                p += sz;
            }
        }
        fprintf(stderr, "\n");
    }
    _os_log_impl((void *)a0, (os_log_t)a1, (os_log_type_t)a2, (const char *)a3, (uint8_t *)a4, (uint32_t)a5);
}'''),
    #  10-10 DIAGNOSTIC: why a plug-in bundle would not load. opendirectoryd loads its OpenDirectory modules
    #    with CFBundleLoadExecutableAndReturnError and only logs "no session modules available" — the CFError, which
    #    names the bundle and the missing symbol, is thrown away. This prints both and then behaves exactly as before
    #    (the caller still owns the error when it asked for one). Gated on ARM2X86_TRACE_BUNDLE.
    #  10-10 DIAGNOSTIC: which open() fails and why. opendirectoryd reported only
    #    "Failed to write configuration ... errno 5" (EIO) with no path for the actual syscall; this prints the
    #    path and errno of every FAILING open. Successes are silent, so the cost is nil. ARM2X86_TRACE_OPEN.
    # Apple ARM64 passes the optional mode on the guest stack; only O_CREAT consumes it.
    'open': (3, 'i64', r'''
unsigned long @T@(unsigned long a0, unsigned long a1, unsigned long a2) {
    mode_t mode = 0;
    if (a1 & O_CREAT) memcpy(&mode, (const void *)__arm_sp, sizeof(mode));
    int fd = open((const char *)a0, (int)a1, mode);
    if (fd < 0 && getenv("ARM2X86_TRACE_OPEN"))
        fprintf(stderr, "[open] FAILED errno=%d flags=0x%lx %s\n", errno, a1, a0 ? (const char *)a0 : "(null)");
    return (unsigned long)(long)fd;
}'''),
    #  10-10 preflight runs BEFORE the load, and a failure there means no load is ever attempted — so the
    #    CFBundleLoadExecutableAndReturnError thunk below never sees it and the module silently does not exist.
    #    opendirectoryd then says only "no session modules available". Same gate, same call-through.
    'CFBundlePreflightExecutable': (2, 'i64', r'''
unsigned long @T@(unsigned long a0, unsigned long a1) {
    CFErrorRef err = NULL;
    Boolean ok = CFBundlePreflightExecutable((CFBundleRef)a0, &err);
    if (getenv("ARM2X86_TRACE_BUNDLE")) {
        char path[1024] = "?";
        CFURLRef u = CFBundleCopyBundleURL((CFBundleRef)a0);
        if (u) { CFURLGetFileSystemRepresentation(u, true, (UInt8 *)path, sizeof path); CFRelease(u); }
        if (ok) fprintf(stderr, "[preflight] OK     %s\n", path);
        else {
            char desc[2048] = "(no CFError returned)";
            if (err) { CFStringRef d = CFErrorCopyDescription(err);
                       if (d) { CFStringGetCString(d, desc, sizeof desc, kCFStringEncodingUTF8); CFRelease(d); } }
            fprintf(stderr, "[preflight] FAILED %s : %s\n", path, desc);
        }
    }
    if (a1) *(CFErrorRef *)a1 = err; else if (err) CFRelease(err);
    return (unsigned long)ok;
}'''),
    'CFBundleLoadExecutableAndReturnError': (2, 'i64', r'''
unsigned long @T@(unsigned long a0, unsigned long a1) {
    CFErrorRef err = NULL;
    Boolean ok = CFBundleLoadExecutableAndReturnError((CFBundleRef)a0, &err);
    if (getenv("ARM2X86_TRACE_BUNDLE")) {
        char path[1024] = "?";
        CFURLRef u = CFBundleCopyBundleURL((CFBundleRef)a0);
        if (u) { CFURLGetFileSystemRepresentation(u, true, (UInt8 *)path, sizeof path); CFRelease(u); }
        if (ok) fprintf(stderr, "[bundle] LOADED %s\n", path);
        else {
            char desc[2048] = "(no CFError returned)";
            if (err) { CFStringRef d = CFErrorCopyDescription(err);
                       if (d) { CFStringGetCString(d, desc, sizeof desc, kCFStringEncodingUTF8); CFRelease(d); } }
            fprintf(stderr, "[bundle] FAILED %s : %s\n", path, desc);
        }
    }
    if (a1) *(CFErrorRef *)a1 = err; else if (err) CFRelease(err);
    return (unsigned long)ok;
}'''),
    #  10-10 DIAGNOSTIC, and the only way to read a panic string from inside a translated daemon. od_panic()
    #    formats its message, hands it to reboot_np, then executes `brk #0x1`; nothing else ever prints it. Gated on
    #    ARM2X86_TRACE_PANIC so a normal run is silent, and it always calls through.
    'reboot_np': (2, 'i64', r'''
extern int reboot_np(int, const char *);
unsigned long @T@(unsigned long a0, unsigned long a1) {
    if (getenv("ARM2X86_TRACE_PANIC"))
        fprintf(stderr, "[xlat2] reboot_np(howto=0x%lx) message: %s\n", a0, a1 ? (const char *)a1 : "(null)");
    return (unsigned long)reboot_np((int)a0, (const char *)a1);
}'''),
    'dispatch_block_create': (2, 'i64', r'''
unsigned long @T@(unsigned long a0, unsigned long a1) {
    return (unsigned long)dispatch_block_create((dispatch_block_flags_t)a0, (dispatch_block_t)__arm2x86_blk((void *)a1));
}'''),
    'dispatch_block_perform': (2, 'void', r'''
void @T@(unsigned long a0, unsigned long a1) {
    dispatch_block_perform((dispatch_block_flags_t)a0, (dispatch_block_t)__arm2x86_blk((void *)a1));
}'''),
    #  10-10 A STRUCT **OF** CALLBACKS, PASSED BY POINTER. Nothing in the signature says "callback": the argument is
    #    a plain const pointer, so sigdb types it cleanly, the import binds, and the bridge never sees the two arm64
    #    function pointers sitting INSIDE the struct. rb_tree_init stores that pointer and the first insertion calls
    #    through it — measured on macOS 27's opendirectoryd: SIGBUS executing __rbt_compare_type_key at 0x10002afac,
    #    a guest address, with the ops table at 0x1000933d0 reached only as a rebased data pointer.
    #     rb_tree_init KEEPS the pointer rather than copying the struct, so the wrapped copy must outlive the call
    #    and is deliberately never freed: one 32-byte allocation per tree, said out loud instead of hidden.
    #  10-10 _os_object_alloc TAKES A CLASS, and nothing was mapping it. It is absent from sigdb (a private
    #    runtime entry point with no public header) so it went through the generic adapter, which handed the
    #    native runtime the RAW GUEST class pointer. Every os_object was then created with isa = the guest class,
    #    whose method IMPs are raw arm64 addresses — and the first release on a dispatch queue jumped straight
    #    into them. Measured on macOS 27's opendirectoryd: SIGBUS executing 0x100003724,
    #    -[OS_od_object dealloc], from _dispatch_block_async_invoke2.
    #     The `objc_`/`class_`/`object_` prefix rule above cannot catch this one: the name starts with _os_.
    '_os_object_alloc': (2, 'i64', r'''
extern void *_os_object_alloc(const void *, unsigned long);
unsigned long @T@(unsigned long a0, unsigned long a1) {
    return (unsigned long)_os_object_alloc((const void *)__arm2x86_mapcls(a0), (unsigned long)a1);
}'''),
    #  10-11 A 32-BYTE STRUCT BY VALUE, AND THE TWO ABIs DISAGREE ABOUT WHERE IT LIVES. arm64 copies an
    #    audit_token_t to the caller's stack and passes a POINTER to it in x0 (read off a real call site in
    #    opendirectoryd: `stp q0,q1,[sp,#0x20]` then `add x0, sp, #0x20`), with the 7 output pointers in x1-x7
    #    and the 9th argument on the stack. x86-64 SysV classifies those 32 bytes MEMORY and passes them ON THE
    #    STACK, moving every pointer argument along. The generic x0-x7 adapter cannot express that, so the
    #    callee read garbage: SIGSEGV in audit_token_to_au32+0x58 on 0x2000000116. It is also absent from sigdb,
    #    which is why it reached the adapter at all. The 9th argument comes off the arm64 stack (rung 6 sizes).
    'audit_token_to_au32': (9, 'void', r'''
#include <bsm/libbsm.h>
void @T@(unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4,
         unsigned long a5, unsigned long a6, unsigned long a7, unsigned long a8) {
    audit_token_t tok; memcpy(&tok, (const void *)a0, sizeof tok);
    audit_token_to_au32(tok, (uid_t *)a1, (uid_t *)a2, (gid_t *)a3, (uid_t *)a4,
                        (gid_t *)a5, (pid_t *)a6, (au_asid_t *)a7, (au_tid_t *)a8);
}'''),
    #  10-22 THE SAME 32-BYTE audit_token_t, IN LaunchServices. MenuBarAgent identifies every app that connects to its menu
    #    server with `_LSCopyLSASNForAuditToken(-2, token)` — arm64 `mov w0, #-2 / sub x1, x29, #0xa0`, a POINTER — and the
    #    generic adapter passed that pointer where x86-64 expects the token's 32 bytes ON THE STACK. LaunchServices read
    #    garbage, returned nil, and the menu bar logged 'Cannot identify app for connection from pid' for every app, so no
    #    app ever owned the menu bar. Also absent from sigdb (SPI), which is why it reached the adapter.
    '_LSCopyLSASNForAuditToken': (2, 'i64', r'''
#include <mach/message.h>
extern const void *_LSCopyLSASNForAuditToken(int, audit_token_t);
unsigned long @T@(unsigned long a0, unsigned long a1) {
    audit_token_t tok; memcpy(&tok, (const void *)a1, sizeof tok);
    return (unsigned long)_LSCopyLSASNForAuditToken((int)a0, tok);
}'''),
    #  10-22 THE WHOLE DESKTOP HUNG ON THIS ONE SPI. `SLSManagedDisplayGetCurrentSpace(cid, displayUUID)` does not
    #    ask WindowServer: it asks the WindowManagement *client bridge* (`SLSWMBridgeDelegate()`), a per-process cache.
    #    In a translated agent that delegate is registered but never populated, so the call returns 0 -> the display's
    #    Optional<SpaceID> is nil -> MenuBarAgent builds ZERO MenuBar entries and hands WindowServer an empty array
    #    (_swiftEmptyArrayStorage), WindowManager takes its wallpaper assertion with `space: ` empty, and no app window
    #    is ever placed: measured as a black screen with only the Dock.
    #     MEASURED, same process, same arguments: the WindowServer-client variant returns the RIGHT space (1) while
    #    this one returns 0, and a NATIVE x86 probe (which finds no delegate and falls back) also returns 1.
    #    So route it to the server, which is the authority for the answer.
    #     10-22 THIS ENTRY IS INERT AND KEPT ONLY AS THE RECORD OF A DEAD END: `nm -u` shows NEITHER MenuBarAgent
    #    NOR WindowManager imports this symbol (0 of 21 _SLS imports in MenuBarAgent), so the call is native->native
    #    INSIDE SkyLight and no bind of ours can ever intercept it. The rebuild proved it: byte-identical binary,
    #    md5 6bcd8bf0 before and after. A bridge can only ever catch a symbol the GUEST image imports.
    'SLSManagedDisplayGetCurrentSpace': (2, 'i64', r'''
extern unsigned long long SLSWindowServerClientManagedDisplayGetCurrentSpace(int, const void *);
unsigned long @T@(unsigned long a0, unsigned long a1) {
    return (unsigned long)SLSWindowServerClientManagedDisplayGetCurrentSpace((int)a0, (const void *)a1);
}'''),
    'rb_tree_init': (2, 'void', r'''
#include <sys/rbtree.h>
void @T@(unsigned long a0, unsigned long a1) {
    _Static_assert(sizeof(rb_tree_ops_t) == 32, "rb_tree_ops_t is not the 4-field layout this thunk copies");
    rb_tree_ops_t *o = (rb_tree_ops_t *)malloc(sizeof *o);
    if (!o) { fprintf(stderr, "FATAL: rb_tree_init ops copy\n"); abort(); }
    memcpy(o, (const void *)a1, sizeof *o);
    o->rbto_compare_nodes = (__typeof__(o->rbto_compare_nodes))__arm2x86_cb((unsigned long)o->rbto_compare_nodes);
    o->rbto_compare_key   = (__typeof__(o->rbto_compare_key))__arm2x86_cb((unsigned long)o->rbto_compare_key);
    rb_tree_init((rb_tree_t *)a0, o);
}'''),
    'dispatch_block_create_with_qos_class': (4, 'i64', r'''
unsigned long @T@(unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3) {
    return (unsigned long)dispatch_block_create_with_qos_class((dispatch_block_flags_t)a0, (dispatch_qos_class_t)a1,
                                                               (int)a2, (dispatch_block_t)__arm2x86_blk((void *)a3));
}'''),
}


#  rung 2 THE CALLBACK BRIDGE. Native code (qsort, pthread, GCD, atexit ...) calls a pointer it was given as x86 code.
#    Each distinct arm64 function handed to an import gets ONE slot of a static trampoline pool:
#      slot i:  movl $i, %r11d ; jmp ___arm2x86_cb_common
#    The common entry keeps the native caller's argument registers (rdi..r9, xmm0..7), gives the THREAD an arm64 stack if
#    it has none (a pthread or GCD worker is a thread translated code has never run on), and calls the IR door
#    __arm2x86_cb_door(a0..a5, q0..q7, t). The door returns { i64, <2 x i64> } = rax + xmm0 — exactly where the native
#    caller reads an int or a double result — so the common entry returns without touching either.
#  Limits said out loud: integer arguments 7+ of a callback are not forwarded (x6/x7 = 0); a struct-by-value callback
#    argument is not supported. The pool has CB_SLOTS distinct functions; exhausting it aborts BY NAME.
#  10-18 WAS 2048. Cyberpunk on studio aborted 3 s in with "callback trampoline pool exhausted": since the 10-11
#    native adapter swaps every exact guest function start passed to a native function POINTER, a big program hands
#    over thousands of distinct functions. 131072 slots = 2 MB of stubs, generated by the assembler (.rept), not as text.
CB_SLOTS = 1 << 17
CB_ASM = ('.text\n.p2align 4\n.globl ___arm2x86_cb_slots\n___arm2x86_cb_slots:\n'
          + f'.set ___arm2x86_cbi, 0\n.rept {CB_SLOTS}\n  movl $___arm2x86_cbi, %r11d\n  jmp ___arm2x86_cb_common\n  .p2align 4\n'
            '  .set ___arm2x86_cbi, ___arm2x86_cbi+1\n.endr\n'   # slot i = movl $i (verified with llvm-mc 22, 10-18)
          + '.p2align 4\n.globl ___arm2x86_cb_common\n___arm2x86_cb_common:\n'
          #  10-03 CFI: a C++ exception thrown by an arm64 callback (a qsort comparator) unwinds THROUGH this frame;
          #    without unwind info libunwind stops here and std::terminate runs.
          '  .cfi_startproc\n  pushq %rbp\n  .cfi_def_cfa_offset 16\n  .cfi_offset %rbp, -16\n  movq %rsp, %rbp\n'
          '  .cfi_def_cfa_register %rbp\n  subq $208, %rsp\n'
          #  10-20 rax is a SWIFT caller's indirect-result pointer (arm64 x8); cb_prepare clobbers it, so it is kept at
          #    176(%rsp) and handed to the door as its 8th integer argument. r12 (swifterror) and r13 (self) are
          #    callee-saved in C, so they reach the door untouched.
          '  movq %rax, 176(%rsp)\n'
          #  10-21 r14 is the SWIFT ASYNC CONTEXT of a native async caller (arm64 x22): kept at 184(%rsp) and handed to
          #    the door as its 9th integer argument, for the same reason as rax above.
          '  movq %r14, 184(%rsp)\n'
          '  movq %rdi, 0(%rsp)\n  movq %rsi, 8(%rsp)\n  movq %rdx, 16(%rsp)\n  movq %rcx, 24(%rsp)\n  movq %r8, 32(%rsp)\n  movq %r9, 40(%rsp)\n'
          + ''.join(f'  movdqu %xmm{i}, {48 + 16 * i}(%rsp)\n' for i in range(8)) +
          #  10-11 a0 is already saved at 0(%rsp) above; hand it to cb_prepare so a trace can name the
          #    object the callback was entered with (the block pointer, for a block invoke).
          '  movl %r11d, %edi\n  movq 0(%rsp), %rsi\n  movq 184(%rsp), %rdx\n  movq %rbp, %rcx\n  callq ___arm2x86_cb_prepare\n  movq %rax, %r10\n  movq %rdx, 192(%rsp)\n'
          '  movq 0(%rsp), %rdi\n  movq 8(%rsp), %rsi\n  movq 16(%rsp), %rdx\n  movq 24(%rsp), %rcx\n  movq 32(%rsp), %r8\n  movq 40(%rsp), %r9\n'
          + ''.join(f'  movdqu {48 + 16 * i}(%rsp), %xmm{i}\n' for i in range(8)) +
          '  movq 176(%rsp), %rax\n  movq 184(%rsp), %r11\n  subq $32, %rsp\n  movq %r10, 0(%rsp)\n  movq %rax, 8(%rsp)\n'
          '  movq %r11, 16(%rsp)\n  callq ___arm2x86_cb_door\n'
          #  10-21 A SWIFT ASYNC ENTRY IS swifttailcc: CALLEE-POP. LLVM's swifttailcc passes its stack arguments (none, here) in
          #    an area rounded to 8 mod 16, so the callee returns with `retq $8` and its caller re-reserves the 8 bytes after the
          #    call (the native adapter's `subq $8, %rsp` after `call swifttailcc`, llc 22.1.8, checked). A native async function
          #    that tail-jumps here ends the whole chain in OUR `ret`: a plain retq left the runtime's frame 8 bytes off and it
          #    returned into a heap pointer (asyncmx, fault address = rip = 0x6000…). cb_prepare says which slots are async
          #    entries (a marked function, or a forwarder to one); every other callback still returns with a plain retq.
          #    (the flag lives at 192(%rsp) of the 208-byte frame = -16(%rbp); rsp itself is 32 lower after the door call)
          '  movq -16(%rbp), %r11\n  testq %r11, %r11\n  jnz 1f\n  movq %rbp, %rsp\n  popq %rbp\n  retq\n1:\n'
          # Drain pending async calls after the guest frames return. The drain holds
          # one depth guard so resumed callbacks hand their next call back to its loop.
          '  leaq -208(%rbp), %rsp\n  movq %rax, 0(%rsp)\n  movq %rdx, 8(%rsp)\n  movq %rcx, 16(%rsp)\n  movq %r8, 24(%rsp)\n'
          '  movdqu %xmm0, 32(%rsp)\n  movdqu %xmm1, 48(%rsp)\n  movdqu %xmm2, 64(%rsp)\n  movdqu %xmm3, 80(%rsp)\n'
          '  callq ___arm2x86_cb_finish\n'
          '  movq 0(%rsp), %rax\n  movq 8(%rsp), %rdx\n  movq 16(%rsp), %rcx\n  movq 24(%rsp), %r8\n'
          '  movdqu 32(%rsp), %xmm0\n  movdqu 48(%rsp), %xmm1\n  movdqu 64(%rsp), %xmm2\n  movdqu 80(%rsp), %xmm3\n'
          '  movq %rbp, %rsp\n  popq %rbp\n  retq $8\n'
          '  .cfi_endproc\n')
# The record carries target, six integers, eight floating-point words, self,
# context, valid, x6/x7, sixteen guest stack words, and swifterror. Rebuild rsp
# from rbp after the call: swifttailcc callees pop their own argument area.
CB_ASYNC_ASM = ('.text\n.p2align 4\n.globl ___arm2x86_async_call\n___arm2x86_async_call:\n'
                '  .cfi_startproc\n  pushq %rbp\n  .cfi_def_cfa_offset 16\n  .cfi_offset %rbp, -16\n  movq %rsp, %rbp\n'
                '  .cfi_def_cfa_register %rbp\n  pushq %rbx\n  pushq %r12\n  pushq %r13\n  pushq %r14\n  pushq %r15\n  subq $152, %rsp\n'
                '  movq %rdi, %r10\n  movq 144(%r10), %r11\n  movq %r11, 0(%rsp)\n  movq 152(%r10), %r11\n  movq %r11, 8(%rsp)\n'
                '  movq 16(%r10), %rsi\n  movq 24(%r10), %rdx\n  movq 32(%r10), %rcx\n  movq 40(%r10), %r8\n  movq 48(%r10), %r9\n'
                + ''.join(f'  movq {160 + 8 * i}(%r10), %r11\n  movq %r11, {16 + 8 * i}(%rsp)\n' for i in range(16))
                + ''.join(f'  movq {56 + 8 * i}(%r10), %xmm{i}\n' for i in range(8)) +
                '  movq 288(%r10), %r12\n  movq 120(%r10), %r13\n  movq 128(%r10), %r14\n  movq 8(%r10), %rdi\n  movq 0(%r10), %r11\n  callq *%r11\n'
                '  leaq -40(%rbp), %rsp\n  popq %r15\n  popq %r14\n  popq %r13\n  popq %r12\n  popq %rbx\n  popq %rbp\n  retq\n'
                '  .cfi_endproc\n')
CB_C = r"""
#include <pthread.h>
extern unsigned long __arm_text_base, __arm_text_size;
extern char __arm2x86_cb_slots[];
__asm__(""" + '"' + (CB_ASM + CB_ASYNC_ASM).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n"\n"') + '"' + r""");
static unsigned long cb_fn[""" + str(CB_SLOTS) + r"""]; static unsigned cb_n;
/* 10-21 1 = the guest function behind this slot is entered with the swifttailcc convention (see cb_is_async) */
static unsigned char cb_async[""" + str(CB_SLOTS) + r"""];
/* 10-21 IS THIS GUEST FUNCTION A SWIFT ASYNC ENTRY (swifttailcc: context in r14 = x22, callee-pop)? xlat2 lists them
   (abi_scan.async_entries: the functions that READ x22 on entry, plus pure forwarders to one) as a sorted table. A single-image
   build has no table (weak): nothing is async there, as before.  NOT "the function opens with `orr x29, x29, #0x1000...`":
   a frameless async function or resume point has no frame marker. */
extern const unsigned long __arm2x86_async_entries[] __attribute__((weak_import));
extern const unsigned long __arm2x86_async_entries_n __attribute__((weak_import));
static int cb_is_async(unsigned long fn) {
    if (!&__arm2x86_async_entries || !&__arm2x86_async_entries_n) return 0;
    unsigned long lo = 0, hi = __arm2x86_async_entries_n;
    while (lo < hi) { unsigned long mid = lo + (hi - lo) / 2; if (__arm2x86_async_entries[mid] < fn) lo = mid + 1; else hi = mid; }
    return lo < __arm2x86_async_entries_n && __arm2x86_async_entries[lo] == fn;
}
/* 10-18 fn -> slot by open addressing (2x the pool, linear probe); WAS a linear scan under the lock, O(n) per call. */
static unsigned cb_tab[2 * """ + str(CB_SLOTS) + r"""];   /* slot index + 1; 0 = empty */
static pthread_mutex_t cb_mu = PTHREAD_MUTEX_INITIALIZER;
unsigned long __arm2x86_mapcls(unsigned long a);
void *__arm2x86_blk(void *b);
unsigned long __arm2x86_cb(unsigned long fn) {
    if (!fn || fn < __arm_text_base || fn >= __arm_text_base + __arm_text_size) return fn;   /* NULL or native: pass through */
    pthread_mutex_lock(&cb_mu);
    const unsigned long mask = 2UL * """ + str(CB_SLOTS) + r""" - 1;
    unsigned long h = ((fn >> 2) * 0x9E3779B97F4A7C15UL) >> 20 & mask;
    while (cb_tab[h] && cb_fn[cb_tab[h] - 1] != fn) h = (h + 1) & mask;
    unsigned i;
    if (cb_tab[h]) i = cb_tab[h] - 1;
    else {
        if (cb_n == """ + str(CB_SLOTS) + r""") { fprintf(stderr, "FATAL: callback trampoline pool exhausted (%u)\n", cb_n); abort(); }
        i = cb_n; cb_fn[cb_n++] = fn; cb_async[i] = (unsigned char)cb_is_async(fn); cb_tab[h] = i + 1;
    }
    pthread_mutex_unlock(&cb_mu);
    return (unsigned long)(__arm2x86_cb_slots + 16UL * i);
}
#define CB_STACK (8UL << 20)
static pthread_key_t cb_key; static pthread_once_t cb_once = PTHREAD_ONCE_INIT;
struct cb_stk { void *base; size_t len; };
static void cb_free(void *p) { struct cb_stk *k = p; __arm_sp = 0; munmap(k->base, k->len); free(k); }
static void cb_key_make(void) { pthread_key_create(&cb_key, cb_free); }
void __arm2x86_ensure_stack(void) {
    if (!__arm_sp) {   /* a native thread entering translated code for the first time: give it an arm64 stack */
        /* 10-03: as big as the thread's OWN stack (the program may have asked pthread_attr_setstacksize for more), >= 8 MB */
        size_t len = pthread_get_stacksize_np(pthread_self()); if (len < CB_STACK) len = CB_STACK;
        len = (len + 0x3FFFUL) & ~0x3FFFUL;
        void *s = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (s == MAP_FAILED || mprotect(s, (size_t)sysconf(_SC_PAGESIZE), PROT_NONE) != 0) { perror("[xlat] callback stack"); abort(); }
        struct cb_stk *k = malloc(sizeof *k); if (!k) abort(); k->base = s; k->len = len;
        pthread_once(&cb_once, cb_key_make); pthread_setspecific(cb_key, k);
        __arm_sp = ((unsigned long)s + len) & ~15UL;
    }
}
/* Async callbacks return a pending call to one iterative native caller. Keeping
   its guard active while native code resumes the guest bounds host stack use,
   including calls whose stack arguments are set up in outlined fragments. */
__thread long __arm2x86_async_depth;
__thread unsigned long __arm2x86_async_pend[37];
extern void __arm2x86_async_call(const unsigned long *rec);
void __arm2x86_async_run(const unsigned long *rec) {
    unsigned long next[37];
    if (!rec) {
        if (!__arm2x86_async_pend[17]) return;
        rec = __arm2x86_async_pend;
    }
    memcpy(next, rec, sizeof next);
    __arm2x86_async_depth++;
    for (;;) {
        __arm2x86_async_pend[17] = 0;
        __arm2x86_async_call(next);
        if (!__arm2x86_async_pend[17]) break;
        memcpy(next, __arm2x86_async_pend, sizeof next);
    }
    __arm2x86_async_depth--;
}
void __arm2x86_cb_finish(void) {
    if (--__arm2x86_async_depth == 0) __arm2x86_async_run(NULL);
}
struct cb_prep { unsigned long fn, async; };
struct cb_prep __arm2x86_cb_prepare(unsigned idx, unsigned long a0, unsigned long r14, unsigned long rbp_) {
    __arm2x86_ensure_stack();
    /* 10-11 DIAGNOSTIC: which trampoline native code entered, and with what first argument. For a block
       invoke a0 is the block pointer, so a garbage a0 here says the caller handed us the wrong object rather
       than the translated body being wrong. getenv is cached: this runs on every callback. */
    static int tr = -1;
    if (tr < 0) tr = getenv("ARM2X86_TRACE_CB") ? 1 : 0;
    if (tr) fprintf(stderr, "[cb %x] slot %u -> guest 0x%lx  a0=0x%lx  r14(async ctx)=0x%lx  async=%d  entry rsp=0x%lx ret=0x%lx\n", (unsigned)(((unsigned long)pthread_self() >> 12) & 0xfff), idx, cb_fn[idx], a0, r14, cb_async[idx], rbp_ + 8, *(unsigned long *)(rbp_ + 8));
    if (cb_async[idx]) __arm2x86_async_depth++;   /* popped by cb_finish in the door's epilogue */
    return (struct cb_prep){ cb_fn[idx], cb_async[idx] };   /* rax = the guest function, rdx = 1 for a swifttailcc entry */
}
"""
#  10-20 THE DOOR IS swiftcc, BECAUSE NATIVE SWIFT CALLS TRANSLATED SWIFT THROUGH IT. macOS 27's ArgumentParser calls a
#    command's witnesses (`configuration`, `run()`) through the trampoline with self in r13, the error in r12 and an
#    indirect result in rax; a C door dropped all three, the translated witness forwarded garbage self back into native
#    Swift and eslogger died at fault 0x10, xprotect at a null initializeWithCopy destination. Mapping both ways:
#    rax (8th int, from cb_common) -> x8, r13 -> x20, r12 -> x21 into @__arm_xr (every lifted prologue loads them),
#    and back x1-x3 -> rdx/rcx/r8, v1-v3 -> xmm1-3, x21 -> r12 (llc 22.1.8, checked: swiftself = r13, swifterror = r12
#    in AND out, 7th/8th ints on the stack, returns rax/rdx/rcx/r8 + xmm0-3).
#  A C CALLER IS UNCHANGED: rax/xmm0 are where it reads its result, rdx/rcx/r8/xmm1-3 are caller-saved, r13 is never
#    written, and r12 comes back as the x21 the lifted callee was handed — which an on-contract callee preserves.
#  10-21 BOTH DOORS SAVE AND RESTORE @__arm_xr, BECAUSE A CALLBACK IS REENTRANCY. @__arm_xr is ONE thread-local
#    register file, and an OFF-CONTRACT guest function publishes XR_FULL_OUT (x1-x29 + v1-v31 + nzcv) into it on every
#    return. So a native->guest callback that happens INSIDE a guest->native call overwrites the file the outer guest
#    frame is still waiting to read back, and the outer frame continues with the callback's registers.
#     MEASURED in macOS 27's WindowManager: `-[AppDelegate init]` reaches fn_1001a3d34, which does `mov x19, x20`
#       (x20 = the object swift_allocObject just returned, traced as 0x6000023740c0 — correct) and then stores through
#       x19 at `stp x26, x25, [x19, #0x10]`. Between the two there are five calls; x19 came back as 0x7ffc474d8868,
#       which dladdr names `block_descriptor+0x108` in Gestures.framework's READ-ONLY __DATA_CONST, so the store was
#       SIGBUS (signal 10) at 0x7ffc474d8878 — and WindowManager is what Finder's first NSWindow waits on, so this is
#       what kept the desktop off the screen.
#  10-21 THE DOOR CARRIES THE SWIFT ASYNC CONTEXT TOO: native async code calls (or tail-jumps to) a translated async
#    function with the context in r14, which is arm64 x22. cb_common keeps r14 at 184(%rsp) and passes it as the door's 9th
#    integer argument; the door stores it to the x22 slot.  WAS dropped: the Dock's `for await` crashed in a resume
#    function that read [x22] off whatever the slot last held (asyncmx baseline on macpro27: SIGSEGV at fault address 0x10 inside the
#    translated async-main code, fn_100001364, reading through an x22 it never received).
#     imp_handler already applies this exact rule to __arm2x86_rf ("reentrancy"); @__arm_xr was simply never included.
#       The save is 768 bytes of stack and one memcpy pair per callback, and it CANNOT lose anything: a callback is a
#       fresh ABI boundary whose inputs the door sets explicitly (x8/x20/x21), and its outputs are read out of the file
#       BEFORE the restore.
#  10-22 AND THEY SAVE AND RESTORE @__arm_sp. Inside a callback every internal call publishes the callee's LOWERED sp, and an
#    on-contract function never republishes it on return, so the callback left @__arm_sp pointing into its own dead frame. An
#    OFF-contract guest caller reloads sp from @__arm_sp after a full-file call (abi_ret's 10-21 rule), took that stale sp, and
#    its epilogue `ldp x20, x19, [sp]` read x19 out of the dead callback frame. MenuBarAgent: fn_1002378d0's saved-x19 slot
#    held the right value (dtrace, unchanged across all 7 calls) yet its caller got x19 = $s2os6LoggerVWV and SIGBUSed storing
#    through it into read-only libswiftos. A callback must hand native code back the sp it was entered with.
_CB_RET = '{ i64, i64, i64, i64, <2 x i64>, <2 x i64>, <2 x i64>, <2 x i64> }'
CB_IR = ('\ndefine swiftcc ' + _CB_RET + ' @__arm2x86_cb_door('
         + ', '.join([f'i64 %a{i}' for i in range(6)] + [f'<2 x i64> %q{i}' for i in range(8)]
                     + ['i64 %t', 'i64 %x8', 'i64 %x22', 'ptr swiftself %self', 'ptr swifterror %err']) + ') {\n'
         '  %xrsav = alloca [96 x i64], align 16\n'
         '  %spsav = load i64, ptr @__arm_sp\n'
         '  %f = call ptr @__arm2x86_lookup(i64 %t)\n'
         '  call void @llvm.memcpy.p0.p0.i64(ptr align 16 %xrsav, ptr align 16 @__arm_xr, i64 768, i1 false)\n'
         '  %gx8 = getelementptr inbounds i8, ptr @__arm_xr, i64 64\n  store i64 %x8, ptr %gx8\n'
         '  %selfi = ptrtoint ptr %self to i64\n'
         '  %gx20 = getelementptr inbounds i8, ptr @__arm_xr, i64 160\n  store i64 %selfi, ptr %gx20\n'
         #  10-21 r14 (cb_common's 9th argument) is the SWIFT ASYNC CONTEXT of a native async caller = arm64 x22
         '  %gx22 = getelementptr inbounds i8, ptr @__arm_xr, i64 176\n  store i64 %x22, ptr %gx22\n'
         '  %errin = load ptr, ptr %err\n  %errini = ptrtoint ptr %errin to i64\n'
         '  %gx21 = getelementptr inbounds i8, ptr @__arm_xr, i64 168\n  store i64 %errini, ptr %gx21\n'
         '  %r = call { i64, <2 x i64> } %f(' + ', '.join([f'i64 %a{i}' for i in range(6)] + ['i64 0', 'i64 0'] + [f'<2 x i64> %q{i}' for i in range(8)]) + ')\n'
         '  %errouti = load i64, ptr %gx21\n  %errout = inttoptr i64 %errouti to ptr\n  store ptr %errout, ptr %err\n'
         '  %r0 = extractvalue { i64, <2 x i64> } %r, 0\n  %rv0 = extractvalue { i64, <2 x i64> } %r, 1\n'
         '  %o0 = insertvalue ' + _CB_RET + ' poison, i64 %r0, 0\n'
         + ''.join(f'  %gox{i} = getelementptr inbounds i8, ptr @__arm_xr, i64 {8 * i}\n  %rx{i} = load i64, ptr %gox{i}\n'
                   f'  %o{i} = insertvalue ' + _CB_RET + f' %o{i - 1}, i64 %rx{i}, {i}\n' for i in (1, 2, 3))
         + '  %o4 = insertvalue ' + _CB_RET + ' %o3, <2 x i64> %rv0, 4\n'
         + ''.join(f'  %gov{j} = getelementptr inbounds i8, ptr @__arm_xr, i64 {256 + 16 * j}\n  %rvx{j} = load <2 x i64>, ptr %gov{j}, align 16\n'
                   f'  %o{4 + j} = insertvalue ' + _CB_RET + f' %o{3 + j}, <2 x i64> %rvx{j}, {4 + j}\n' for j in (1, 2, 3))
         + '  call void @llvm.memcpy.p0.p0.i64(ptr align 16 @__arm_xr, ptr align 16 %xrsav, i64 768, i1 false)\n'
         + '  store i64 %spsav, ptr @__arm_sp\n'
         + '  ret ' + _CB_RET + ' %o7\n}\n'
         #  rung 3b the door a libffi-closure IMP enters translated code through: the register file in, x0/v0 out
         '\ndefine void @__arm2x86_call_rf(i64 %t) {\n  %xrsav = alloca [96 x i64], align 16\n  %spsav = load i64, ptr @__arm_sp\n'
         '  %f = call ptr @__arm2x86_lookup(i64 %t)\n'
         '  call void @llvm.memcpy.p0.p0.i64(ptr align 16 %xrsav, ptr align 16 @__arm_xr, i64 768, i1 false)\n'
         + ''.join(f'  %gx{i} = getelementptr inbounds i8, ptr @__arm2x86_rf, i64 {8 * i}\n  %x{i} = load i64, ptr %gx{i}\n' for i in range(8))
         + ''.join(f'  %gv{j} = getelementptr inbounds i8, ptr @__arm2x86_rf, i64 {80 + 16 * j}\n  %v{j} = load <2 x i64>, ptr %gv{j}, align 16\n' for j in range(8))
         #  10-03 x8 (the sret buffer) goes in through @__arm_xr; x1 and v1-v3 come back from it (pairs, HFA up to 4)
         + '  %gx8 = getelementptr inbounds i8, ptr @__arm2x86_rf, i64 64\n  %x8 = load i64, ptr %gx8\n'
           '  %xr8 = getelementptr inbounds i8, ptr @__arm_xr, i64 64\n  store i64 %x8, ptr %xr8\n'
         + '  %r = call { i64, <2 x i64> } %f(' + ', '.join([f'i64 %x{i}' for i in range(8)] + [f'<2 x i64> %v{j}' for j in range(8)]) + ')\n'
         '  %rx = extractvalue { i64, <2 x i64> } %r, 0\n  store i64 %rx, ptr @__arm2x86_rf\n'
         '  %rv = extractvalue { i64, <2 x i64> } %r, 1\n  store <2 x i64> %rv, ptr %gv0, align 16\n'
         '  %xr1 = getelementptr inbounds i8, ptr @__arm_xr, i64 8\n  %rx1 = load i64, ptr %xr1\n  store i64 %rx1, ptr %gx1\n'
         + ''.join(f'  %xrv{j} = getelementptr inbounds i8, ptr @__arm_xr, i64 {256 + 16 * j}\n  %rv{j} = load <2 x i64>, ptr %xrv{j}, align 16\n'
                   f'  store <2 x i64> %rv{j}, ptr %gv{j}, align 16\n' for j in (1, 2, 3))
         + '  call void @llvm.memcpy.p0.p0.i64(ptr align 16 @__arm_xr, ptr align 16 %xrsav, i64 768, i1 false)\n'
         + '  store i64 %spsav, ptr @__arm_sp\n'
         + '  ret void\n}\n')


def sh(*a):
    return subprocess.run(list(a), capture_output=True, text=True, check=True).stdout


def make_binds(stub_slot, slot_sym, objc_stub_sel, sig):
    """ rung 6: the import -> bind table, shared by xlat (one image) and xlat2 (a whole program). Unchanged body."""
    binds, thunks, unbound = {}, [], []
    RF = {'objc_msgSend': '__arm2x86_objc_msgSend', 'objc_msgSendSuper2': '__arm2x86_objc_msgSendSuper2'}
    #  rung 4: what the program asks about the machine answers like an Apple Silicon Mac (identity.c, mkidentity.py)
    IDF = {'sysctlbyname', 'sysctl', 'sysctlnametomib', 'uname', 'getpagesize', 'sysconf', 'mmap', 'munmap', 'mprotect', 'madvise',
           'thread_policy_set'}   #  10-05 page + affinity parity (identity.c)
    for st_, sref in objc_stub_sel.items():
        binds[st_] = {'sym': '__arm2x86_objc_msgSend', 'argc': 0, 'args': '', 'ret': 'void', 'rf': 1, 'va': 1, 'selref': sref}
    for stub, slot in sorted(stub_slot.items()):
        sym = slot_sym.get(slot)
        if not sym: unbound.append(f'0x{stub:x}:no-bind'); continue
        c = sym[1:] if sym.startswith('_') else sym
        if c in RF:   #  rung 3: a message send has no fixed signature — the whole register file goes to the bridge
            binds[stub] = {'sym': RF[c], 'argc': 0, 'args': '', 'ret': 'void', 'rf': 1, 'va': 1}; continue
        if c in XARGCB:   #  10-10 a callback behind an argument sigdb cannot type — see XARGCB
            n_, ret_, body_ = XARGCB[c]
            tn = f'__arm2x86_fpx_{c}'
            thunks.append(body_.replace('@T@', tn))
            binds[stub] = {'sym': tn, 'argc': n_, 'args': 'i' * n_, 'ret': ret_, 'cache': sym,
                           'cret': 'void' if ret_ == 'void' else 'unsigned long', 'sizes': [8] * n_}
            continue
        s = sig.get(c)
        if not s or s['ret'] == 'x' or 'x' in s['args']:
            #  10-10 AN UNTYPEABLE ARGUMENT PLUS A CALLBACK ARGUMENT IS A GUARANTEED CRASH, AND IT WAS SILENT.
            #    'x' (struct by value, long double, block, _Float16) leaves the import unbound, so its call goes through
            #    the generic x0-x7 adapter — which passes the arm64 function pointer STRAIGHT THROUGH instead of
            #    swapping it for a trampoline. Native code then jumps into raw arm64 bytes. Measured: macOS 27's
            #    opendirectoryd handed ___fixup_schema4 to CFArrayApplyFunction (args 'ixii', the 'x' is a 16-byte
            #    CFRange) and died SIGBUS executing 0x10005b40c, a guest address. Say it out loud; never swallow it.
            if s and (s.get('fnp') or s.get('blk')):
                unbound.append(f'{sym}:CALLBACK-UNWRAPPED(untypeable arg in "{s["args"]}")')
            else:
                unbound.append(sym)
            continue
        b = {'sym': f'__arm2x86_id_{c}' if c in IDF else c, 'argc': s['argc'], 'args': s['args'], 'ret': s['ret'], 'cache': sym,
             'cret': s.get('cret'),   #  10-05 a bool/char/short return is narrowed + extended (arm2x86.NARROW_RET)
             'sizes': s.get('sizes'),   #  rung 6: natural sizes, for arguments past x7/v7 (read off the arm64 stack)
             'valist': [i for i, t in enumerate(s.get('ctypes') or []) if '__va_list_tag' in (t or '')]}   #  10-03 see va_conv
        if c == '__cxa_atexit':   #  rung 6: unbounded, NOT through the 2,048-slot pool (objc_bridge.c __arm2x86_cxa_atexit)
            b.update({'sym': '__arm2x86_cxa_atexit', 'va': 1}); binds[stub] = b; continue
        if s['va']:
            names = [f'a{i}' for i in range(s['argc'])]
            proto = ', '.join(f'{t} {n}' for t, n in zip(s['ctypes'], names)) or 'void'
            call = ', '.join(names)
            if c in VTAB:
                body = f'va_list ap; arm_va(ap); {"" if s["cret"] == "void" else "return "}{VTAB[c]}({call}, ap);'
                if VTAB[c] in VPROTO: thunks.append(VPROTO[VTAB[c]])
            elif c in INTTAIL:
                body = f'return {c}({call}, *(unsigned long *)__arm_sp);'
            else:
                unbound.append(sym + '(variadic, no v-variant)'); continue
            tn = f'__arm2x86_va_{c}'
            thunks.append(f'{s["cret"]} {tn}({proto}) {{ {body} }}')
            b.update({'sym': tn, 'va': 1})
        elif c.startswith(('objc_', 'class_', 'object_')) and s['argc'] and 'd' not in s['args'] and 'f' not in s['args']:
            #  rung 3b: the runtime's C entry points get every pointer argument class-mapped (an ARM class address
            #    -> the native class); anything else passes through untouched.
            names = [f'a{i}' for i in range(s['argc'])]
            proto = ', '.join(f'unsigned long {n}' for n in names)
            call = ', '.join(f'({t})__arm2x86_mapcls({n})' for t, n in zip(s['ctypes'], names))
            tn = f'__arm2x86_oc_{c}'
            #  10-17 objc_retainBlock copies the block INSIDE libobjc, where no override can see it, so the block's
            #    invoke and copy/dispose helpers are wrapped first (objc_bridge.c). Measured: SIGBUS in the arm64
            #    ___copy_helper_block_e8_32r from native _Block_copy, slice/objc1.m.
            callee = '__arm2x86_objc_retainBlock' if c == 'objc_retainBlock' else c
            if callee != c: thunks.append(f'extern {s["cret"]} {callee}({", ".join(s["ctypes"]) or "void"});')
            if s.get('abi'):   # a runtime ABI function no public header declares: its prototype comes from sigdb
                thunks.append(f'extern {s["cret"]} {c}({", ".join(s["ctypes"]) or "void"});')
            thunks.append(f'{s["cret"]} {tn}({proto}) {{ {"" if s["cret"] == "void" else "return "}{callee}({call}); }}')
            b['sym'] = tn
        elif s.get('fnp') or s.get('blk'):
            #  rung 2: native code will CALL these parameters — swap each arm64 function address for a trampoline.
            names = [f'a{i}' for i in range(s['argc'])]
            #  a function-pointer declarator puts the NAME inside the parens; the thunk never uses the arm64 value's type,
            #    so those parameters are plain unsigned long and get their real type only in the cast at the call.
            cbp = set(s['fnp']) | set(s.get('blk', []))
            proto = ', '.join(('unsigned long' if i in cbp else t) + f' {n}' for i, (t, n) in enumerate(zip(s['ctypes'], names)))
            call = ', '.join(f'({s["ctypes"][i]})__arm2x86_cb((unsigned long){n})' if i in s['fnp'] else
                             f'({s["ctypes"][i]})__arm2x86_blk((void *){n})' if i in s.get('blk', []) else n
                             for i, n in enumerate(names))
            tn = f'__arm2x86_fp_{c}'
            if s.get('abi'):   #  rung 6: an ABI function no public header declares (__cxa_atexit, _tlv_atexit)
                thunks.append(f'extern {s["cret"]} {c}({", ".join(s["ctypes"]) or "void"});')
            cc = {'pthread_create': '__arm2x86_pthread_create'}.get(c, c)   #  10-03 shim: altstack + stack scaling
            if cc != c: thunks.append(f'extern {s["cret"]} {cc}({", ".join(s["ctypes"])});')
            thunks.append(f'{s["cret"]} {tn}({proto}) {{ {"" if s["cret"] == "void" else "return "}{cc}({call}); }}')
            b['sym'] = tn
        #  rung 2: EVERY import call publishes the arm64 sp. Any native call can run a callback registered earlier
        #    (exit() runs atexit handlers, qsort runs the comparator); a callback entering translated code with a STALE
        #    @__arm_sp would build its frame on top of its caller's live one. One TLS store per import call.
        b['va'] = 1
        binds[stub] = b
    #  10-10 SAY THE DANGEROUS ONES OUT LOUD. An import whose callback could not be wrapped will make native code
    #    jump into raw arm64 bytes the first time it is invoked — a SIGBUS at a guest address, with nothing in the log
    #    to connect it to this import. It went unprinted once and cost a boot (opendirectoryd, CFArrayApplyFunction).
    cbu = sorted({u.split(':')[0] for u in unbound if 'CALLBACK-UNWRAPPED' in u})
    if cbu:
        print(f' callbacks NOT wrapped ({len(cbu)}): native code will jump into arm64 bytes if these are called — '
              + ', '.join(cbu))
    #  rung 6 (10-03, l6 ruler): one thunk per STUB — two images importing printf defined __arm2x86_va_printf twice
    #    and the link refused. Same symbol, same text: keep the first, in order.
    return binds, list(dict.fromkeys(thunks)), unbound


def main(exe, out, cpu='x86-64-v3'):
    os.makedirs(out, exist_ok=True)
    exe = os.path.abspath(exe)
    assert 'arm64' in sh('file', exe), f'{exe} is not an arm64 Mach-O'
    sig = json.load(open(os.path.join(S, 'sigdb.json')))

    # --- load commands: entry, segments --------------------------------------------------------------------------------
    lc = sh('otool', '-l', exe)
    entryoff = int(re.search(r'cmd LC_MAIN\s+cmdsize \d+\s+entryoff (\d+)', lc).group(1))
    segs = [(m.group(1), int(m.group(2), 16), int(m.group(3), 16))
            for m in re.finditer(r'segname (\S+)\s+vmaddr (0x[0-9a-f]+)\s+vmsize (0x[0-9a-f]+)', lc)]
    text = [s for s in segs if s[0] == '__TEXT'][0]
    entry = text[1] + entryoff
    lo = min(s[1] for s in segs if s[0] not in ('__PAGEZERO', '__LINKEDIT'))
    hi = max(s[1] + s[2] for s in segs if s[0] != '__PAGEZERO')
    rsv = (hi - lo + 0xFFFFF) & ~0xFFFFF
    print(f'image {os.path.basename(exe)}: vm 0x{lo:x}..0x{hi:x} (reserve {rsv >> 20} MB), entry 0x{entry:x}')

    # --- code ----------------------------------------------------------------------------------------------------------
    dis = os.path.join(out, 'full.txt'); starts = os.path.join(out, 'starts.txt')
    open(dis, 'w').write(sh('xcrun', 'llvm-objdump', '-d', '--no-show-raw-insn', '--section=__text', exe))
    st = re.findall(r'^0x([0-9a-fA-F]+)', sh('xcrun', 'dyld_info', '-function_starts', exe), re.M)
    open(starts, 'w').write(''.join(f'{int(a, 16):016x}\n' for a in st))
    fsegs, rep = split_fns.split(dis, starts); print(rep)

    # --- stubs -> GOT slot -----------------------------------------------------------------------------------------------
    stub_slot, cur = {}, None
    for ln in sh('xcrun', 'llvm-objdump', '-d', '--no-show-raw-insn', '--section=__stubs', exe).splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+(\w+)\s+(.*)', ln)
        if not m: continue
        a, op, rest = int(m.group(1), 16), m.group(2), m.group(3)
        if op == 'adrp':
            cur = [a, int(re.search(r'0x([0-9a-f]+)', rest).group(1), 16)]
        elif op == 'ldr' and cur:
            off = re.search(r'#(0x[0-9a-f]+|\d+)\]', rest)
            stub_slot[cur[0]] = cur[1] + (int(off.group(1), 0) if off else 0); cur = None
    # --- __objc_stubs: `adrp x1,P ; ldr x1,[x1,#o] ; (adrp x16,Q ; ldr x16,[x16,#o2] ; br x16 | b objc_msgSend)` ----
    #     rung 3: modern clang emits each message send as a call to one of these. Each becomes a FULL-REGISTER bind
    #    to the ObjC bridge that loads x1 from its selector reference first.
    objc_stub_sel, cur = {}, None
    try:
        ods = sh('xcrun', 'llvm-objdump', '-d', '--no-show-raw-insn', '--section=__objc_stubs', exe)
    except subprocess.CalledProcessError:
        ods = ''
    for ln in ods.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+(\w+)\s+(.*)', ln)
        if not m: continue
        a, op, rest = int(m.group(1), 16), m.group(2), m.group(3)
        if op == 'adrp' and rest.startswith('x1,'):
            cur = [a, int(re.search(r'0x([0-9a-f]+)', rest).group(1), 16)]
        elif op == 'ldr' and rest.startswith('x1,') and cur:
            off = re.search(r'#(0x[0-9a-f]+|\d+)\]', rest)
            objc_stub_sel[cur[0]] = cur[1] + (int(off.group(1), 0) if off else 0); cur = None
    # --- fixups ---------------------------------------------------------------------------------------------------------
    fx = sh('xcrun', 'dyld_info', '-fixups', exe)
    slot_sym, recs, nrows = {}, [], 0
    for ln in fx.splitlines():
        m = re.match(r'\s+\S+\s+\S+\s+0x([0-9A-Fa-f]+)\s+(rebase|auth-rebase|bind|auth-bind|weak-bind)\s+(\S+)', ln)
        if not m: continue
        nrows += 1
        a, kind, t = int(m.group(1), 16), m.group(2), m.group(3)
        if 'rebase' in kind: recs.append((a, int(t, 16)))
        else:
            slot_sym[a] = t.split('/', 1)[1]; recs.append((a, 0))   #  0, never raw chained bits; main.c writes the native
    assert len(recs) == nrows, 'unparsed fixup rows'
    fxp = os.path.join(out, 'fixups.bin')
    with open(fxp + '.tmp', 'wb') as f:
        f.write(struct.pack('<Q', len(recs)))
        for a, v in recs: f.write(struct.pack('<QQ', a, v))
    os.replace(fxp + '.tmp', fxp)

    # --- binds ----------------------------------------------------------------------------------------------------------
    binds, thunks, unbound = make_binds(stub_slot, slot_sym, objc_stub_sel, sig)
    print(f'stubs {len(stub_slot)}  bound {len(binds)}  variadic thunks {len(thunks)}  unbound {unbound}')

    # --- lift -----------------------------------------------------------------------------------------------------------
    fd = os.path.join(out, 'fn'); os.makedirs(fd, exist_ok=True)
    specs = []
    for name, ls in fsegs:
        a0 = int(re.match(r'^\s*([0-9a-f]+):', ls[0]).group(1), 16)
        p = os.path.join(fd, f'{a0:x}.txt'); open(p, 'w').write('\n'.join(ls) + '\n'); specs.append((p, None, 0))
    mod = build(specs, binds)
    assert f'@x_fn_{entry:x}(' in mod, f'no x_fn door for the entry 0x{entry:x}'
    ll = os.path.join(out, 'all.ll'); open(ll + '.tmp', 'w').write(mod); os.replace(ll + '.tmp', ll)
    print(f'lifted {len(specs)} functions -> {ll} ({len(mod)} bytes)')

    # --- host main ------------------------------------------------------------------------------------------------------
    #  rung 4: the page-size DATA imports point at identity.c's 16 KB values, not the kernel's 4 KB ones
    IDD = {'vm_page_size', 'vm_page_mask', 'vm_page_shift'}
    slots = ',\n'.join(f'  {{0x{a:x}UL, "{("__arm2x86_id_" if s.lstrip("_") in IDD and s.startswith("_") else "") + (s[1:] if s.startswith("_") else s)}"}}'
                       for a, s in sorted(slot_sym.items()))
    sm = re.search(r'sectname __objc_selrefs\s+segname \S+\s+addr (0x[0-9a-f]+)\s+size (0x[0-9a-f]+)', lc)
    selrefs = (int(sm.group(1), 16), int(sm.group(2), 16)) if sm else (0, 0)
    osec = {}
    for nm in ('__objc_classlist', '__objc_catlist', '__objc_classrefs', '__objc_superrefs'):
        mm = re.search(rf'sectname {nm}\s+segname \S+\s+addr (0x[0-9a-f]+)\s+size (0x[0-9a-f]+)', lc)
        osec[nm] = (int(mm.group(1), 16), int(mm.group(2), 16)) if mm else (0, 0)
    umbrella = open(os.path.join(S, 'sigdb_umbrella.c')).read()   # the SAME declarations sigdb read, so every thunk compiles
    mainc = f'''/* generated by xlat.py for {os.path.basename(exe)} — do not edit */
{umbrella}
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <err.h>
#include <wchar.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
extern __thread unsigned long __arm_sp;
__attribute__((section("__ARMRSV,__rsv,zerofill"), used)) static char arm2x86_rsv[0x{rsv:x}UL];
char *const __arm2x86_rsv_base = arm2x86_rsv;
const unsigned long __arm2x86_rsv_len = sizeof arm2x86_rsv;
static void arm_va(va_list ap) {{ ap[0].gp_offset = 48; ap[0].fp_offset = 176; ap[0].overflow_arg_area = (void *)__arm_sp; ap[0].reg_save_area = NULL; }}
{CB_C}
{chr(10).join(thunks)}
static const struct {{ unsigned long slot; const char *sym; }} kSlots[] = {{
{slots}
}};
extern unsigned long x_fn_{entry:x}(unsigned long, unsigned long, unsigned long, unsigned long,
                                    unsigned long, unsigned long, unsigned long, unsigned long);
unsigned long __arm2x86_cb_unwrap(unsigned long t) {{
    unsigned long b = (unsigned long)__arm2x86_cb_slots;
    return (t >= b && t < b + 16UL * {CB_SLOTS} && (t - b) / 16 < cb_n) ? cb_fn[(t - b) / 16] : t;
}}
#include <objc/runtime.h>
int main(int argc, char **argv, char **envp, char **apple) {{
    unsigned long ps = (unsigned long)sysconf(_SC_PAGESIZE);
    for (unsigned i = 0; i < sizeof kSlots / sizeof kSlots[0]; i++) {{
        void *p = dlsym(RTLD_DEFAULT, kSlots[i].sym);
        if (!p) {{ fprintf(stderr, "[xlat] import %s has no native definition — its slot stays 0\\n", kSlots[i].sym); continue; }}
        void *pg = (void *)(kSlots[i].slot & ~(ps - 1));
        if (mprotect(pg, ps, PROT_READ | PROT_WRITE) != 0) {{ perror("[xlat] mprotect GOT"); return 120; }}
        *(void **)kSlots[i].slot = p;
    }}
    /* rung 3: __objc_selrefs hold raw C-string pointers until dyld uniques them — dyld never saw this image, so we
       do it: every reference becomes the runtime's registered SEL, or the native runtime matches nothing. */
    for (unsigned long p = 0x{selrefs[0]:x}UL; p < 0x{selrefs[0]:x}UL + 0x{selrefs[1]:x}UL; p += 8) {{
        void *pg = (void *)(p & ~(ps - 1)); mprotect(pg, ps, PROT_READ | PROT_WRITE);
        *(SEL *)p = sel_registerName(*(const char **)p);
    }}
    {{ void __arm2x86_objc_register(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long,
                                    unsigned long, unsigned long);
       /* rung 3b: the image's own classes and categories, rebuilt in the native runtime, references patched */
       __arm2x86_objc_register(0x{osec['__objc_classlist'][0]:x}UL, 0x{osec['__objc_classlist'][1] // 8:x}UL,
                               0x{osec['__objc_catlist'][0]:x}UL, 0x{osec['__objc_catlist'][1] // 8:x}UL,
                               0x{osec['__objc_classrefs'][0]:x}UL, 0x{osec['__objc_classrefs'][1] // 8:x}UL,
                               0x{osec['__objc_superrefs'][0]:x}UL, 0x{osec['__objc_superrefs'][1] // 8:x}UL); }}
    unsigned long rc = x_fn_{entry:x}((unsigned long)argc, (unsigned long)argv, (unsigned long)envp, (unsigned long)apple, 0, 0, 0, 0);
    exit((int)rc);
}}
'''
    #  L1 self-contained: the fixups ride inside the host; a constructor that runs BEFORE the loader's (priority 101)
    #    points ARM_IMAGE at this file's own arm64 slice. Finder gives a program no environment, so nothing may need one.
    blob = ', '.join([f'0x{len(recs):x}ULL'] + [f'0x{a:x}ULL, 0x{v:x}ULL' for a, v in recs])
    mainc += f'''
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach/machine.h>
#include <libkern/OSByteOrder.h>
static const unsigned long long kFix[] = {{ {blob} }};
const unsigned long long *const __arm2x86_fixups_blob = kFix;
__attribute__((constructor(101))) static void xlat_self(void) {{
    if (getenv("ARM_IMAGE")) return;                       /* an explicit image (testing) wins */
    char p[4096]; uint32_t n = sizeof p; if (_NSGetExecutablePath(p, &n) != 0) return;
    char rp[4096]; if (!realpath(p, rp)) return;
    int fd = open(rp, O_RDONLY); if (fd < 0) return;
    struct fat_header fh; unsigned long long off = 0;
    if (pread(fd, &fh, sizeof fh, 0) == sizeof fh && OSSwapBigToHostInt32(fh.magic) == FAT_MAGIC) {{
        uint32_t na = OSSwapBigToHostInt32(fh.nfat_arch);
        for (uint32_t i = 0; i < na; i++) {{ struct fat_arch fa;
            if (pread(fd, &fa, sizeof fa, sizeof fh + i * sizeof fa) != sizeof fa) break;
            if ((cpu_type_t)OSSwapBigToHostInt32((uint32_t)fa.cputype) == CPU_TYPE_ARM64) {{ off = OSSwapBigToHostInt32(fa.offset); break; }} }}
    }}
    close(fd);
    if (!off) {{ fprintf(stderr, "[xlat] %s has no arm64 slice — nothing to run\\n", rp); return; }}
    char v[4200]; snprintf(v, sizeof v, "%s@%llu", rp, off); setenv("ARM_IMAGE", v, 1); setenv("ARM_FIXUPS", "@embedded", 1);
}}
'''
    mp = os.path.join(out, 'main.c'); open(mp, 'w').write(mainc)
    with open(ll, 'a') as f: f.write(CB_IR)   #  the IR door native trampolines enter translated code through

    # --- compile + link -------------------------------------------------------------------------------------------------
    base = os.path.join(out, 'all')
    for args in (([f'{LLVM}/llvm-as', f'{base}.ll', '-o', f'{base}.bc'],),
                 ([f'{LLVM}/opt', '-O2', f'{base}.bc', '-o', f'{base}_opt.bc'],),
                 ([f'{LLVM}/llc', '-mtriple=x86_64-apple-macosx', f'-mcpu={cpu}', '-mattr=+aes,+pclmul', '-filetype=obj',
                   f'{base}_opt.bc', '-o', f'{base}.o'],)):
        subprocess.run(args[0], check=True)
    xe = os.path.join(out, os.path.basename(exe) + '.x86')
    #  rung 5: a framework the program links but this list lacked (MetalFX) left its classes' slots 0 and every message
    #    to them answered nil/NO. Link EVERY framework the arm64 image names in its load commands.
    linkfw = []
    for fw in re.findall(r'name /System/Library/Frameworks/(\w+)\.framework/\S+ \(offset', lc):
        if fw not in linkfw: linkfw += ['-framework', fw]
    subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=15.0', '-O1', '-w', '-Wl,-no_pie',
                    '-Wl,-image_base,0x400000000', f'-Wl,-segaddr,__ARMRSV,0x{lo:x}', '-x', 'objective-c', mp, '-x', 'none', os.path.join(S, 'shim_comp.c'), os.path.join(S, 'identity.c'),
                    os.path.join(S, 'objc_bridge.c'), f'{base}.o', '-lffi', '-lobjc', '-framework', 'Foundation', '-framework', 'AppKit', '-framework', 'Metal', '-framework', 'MetalKit',
                    '-framework', 'QuartzCore', '-framework', 'CoreGraphics', '-framework', 'IOKit', '-framework', 'GameController',
                    '-framework', 'AudioToolbox', '-framework', 'CoreAudio', '-framework', 'CoreVideo', '-framework', 'CoreText',
                    '-framework', 'ImageIO', '-framework', 'Security', '-framework', 'SystemConfiguration', '-framework', 'Carbon',
                    '-framework', 'AVFAudio'] + linkfw + ['-o', xe], check=True)
    uni = os.path.join(out, os.path.basename(exe))
    subprocess.run(['lipo', '-create', xe, exe, '-output', uni + '.tmp'], check=True); os.replace(uni + '.tmp', uni)
    subprocess.run(['codesign', '-f', '-s', '-', uni], check=True, capture_output=True)
    print(f'wrote {uni}  (universal: x86_64 = translation, arm64 = the original, untouched)')


if __name__ == '__main__':
    main(*sys.argv[1:])
