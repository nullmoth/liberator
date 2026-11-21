// host.c — run an arm64 Mach-O on x86_64 with NO build step for it.
// // THIS IS THE SHAPE THE GOAL NEEDS. The per-app pipeline translates one binary on a build machine and
// bakes its import bindings into a host built for it alone — which is why every app cost its own build.
// Here nothing is generated: the app is mapped at its own addresses, its fixups are read at load time
// (machofix.c, validated against dyld on 75 real binaries), imports are dlsym'd straight to the real x86
// frameworks, and execution is the certified interpreter (all 2,224 instruction forms identical to an M4).
// One fixed binary, any arm64 program.
// It refuses loudly rather than half-running: a segment that will not map where it must, a missing import,
// an unimplemented instruction and a branch to nowhere each stop with the address and the reason.
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
extern int *_NSGetArgc(void);
extern char ***_NSGetArgv(void);
#include <sys/mman.h>
#include <sys/stat.h>
#include <sched.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>   /* r13m: mach_vm_remap for shared code pages */
#include <uuid/uuid.h>
#include <stdbool.h>   /* _NSGetExecutablePath: bundle mode asks where WE are */

/* THE SUFFIX THAT MAKES THIS HOST AN APP. The launch hook renames an app bundle's own arm64
      executable to <name>.a2x64 and puts this host at <name>, so the kernel — which refuses to exec an
      arm64 slice on Intel at all (ml_grade_binary has no CPU_TYPE_ARM64 case, EBADARCH) — execs us
      instead, and we interpret the file beside us. */
#define A2X_GUEST_EXT ".a2x64"
#include "a64i.h"
#include "rf_table.h"
#include <objc/runtime.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <pthread.h>
#include <sched.h>
#include <stddef.h>

/* ── the state the interpreter and the native door read ── */
unsigned long __arm_text_base, __arm_text_size;
__thread unsigned long __arm_sp;
__thread unsigned long __arm_xr[96];
unsigned long __arm_tsd_off;

FILE *a2x_errf(void) { return stderr; }

/* ──  THE LOAD STAGE, PUBLISHED FOR THE FAULT HANDLER ───────────────────────────────────────────────────
       FIVE macOS 27 APPS DIE WITH `guest pc 0x0 (insn 0x00000000), faulting address 0x20` (FindMy, Maps,
         Reminders, Shortcuts, and Notes before the universal trampoline). A zero guest pc means the
         interpreter's per-step publish never happened on that thread, so the fault is in the host's own load
         and registration work — and the report named no part of it, which left five apps diagnosed as one
         guess. One store per stage, exactly the idiom a64_cur_pc already uses, makes the next single run name
         the stage, the image and the record instead.
       0x20 IS NOT AN ARBITRARY ADDRESS. libobjc's objc_class::data() reads `bits` at +0x20, and this tree's
         own RO(c) macro (objc_bridge.c) reads the same word — so a Nil Class handed to the runtime faults at
         EXACTLY 0x20. objc_bridge.c already records that shape once, measured: a Shortcuts category on an
         unrealized Swift class died in prepareMethodLists at fault 0x20. The stage below says which record
         was being handed over; audit_image() below says which records could not survive being handed over. */
enum {
    ST_START = 0, ST_EXE_LOAD, ST_DEP_SCAN, ST_DEP_LOAD, ST_DLOPEN, ST_FSTART_SORT, ST_FIXUPS,
    ST_AUDIT, ST_SELREFS, ST_OBJC_PROTO, ST_OBJC_CLASS, ST_SWIFT, ST_TLV, ST_STACK, ST_ENTRY, ST_GUEST,
    ST_N
};
static const char *const g_stage_name[ST_N] = {
    "start", "load-executable", "scan-dependencies", "load-dependency", "dlopen-system-framework",
    "sort-function-starts", "apply-fixups", "audit-objc-sections", "register-selectors",
    "register-objc-protocols", "register-objc-classes", "register-swift-metadata",
    "register-thread-locals", "build-guest-stack", "enter-guest", "guest-running"
};
/* volatile, one store each, no lock: the handler only ever reads the LAST published value. A lock taken in
      a signal handler is how a crash becomes a hang, and this has to survive being read mid-update. */
static volatile int g_stage;
static volatile int g_stage_img = -1;
static volatile unsigned long g_stage_idx;
static const char *volatile g_stage_what = "";   /* STATIC STORAGE ONLY — the handler prints it unchanged */
static volatile unsigned long g_stage_thread;
static int g_stage_live = -1;

static void stage(int s, int img, unsigned long idx, const char *what) {
    g_stage = s; g_stage_img = img; g_stage_idx = idx; g_stage_what = what ? what : "";
    g_stage_thread = (unsigned long)(uintptr_t)pthread_self();
    if (g_stage_live < 0)
        g_stage_live = (A2X_DBGENV("ARM2X86_HOST_STAGE") || A2X_DBGENV("ARM2X86_HOST_TRACE")) ? 1 : 0;
    /* LIVE PRINTING IS NOT OPTIONAL FOR THE abort() CASE: objc_bridge's die2() and libobjc's own
          _objc_fatal end the process without a signal, so they never reach the fault handler. Without a live
          line the stage dies with the process and the run says nothing. */
    if (g_stage_live > 0)
        fprintf(stderr, "[stage] %-24s image %d index %lu %s\n",
                g_stage_name[s < 0 || s >= ST_N ? 0 : s], img, idx, g_stage_what);
}
/* THE INDEX ALONE, for a loop tight enough that a live line per element would be a flood — Maps has
      32,736 selector references. The stage name has already been printed; the handler reads the index. */
static inline void stage_idx(unsigned long idx) { g_stage_idx = idx; }
/* A STAGE STRING MUST OUTLIVE THE FRAME THAT SET IT: the fault handler prints g_stage_what long after the
      caller returned, so a path built in a local buffer is copied here first. */
static char g_stage_path[1024];

/* THE GUEST'S ADDRESS RANGE IS RESERVED AT LINK TIME, NOT CLAIMED AT RUN TIME. MAP_FIXED replaces
      whatever is already there SILENTLY, and by the time main() has opened a file and dlopened a framework
      the allocator may already own pages at 0x100000000 — the host then mapped the guest over its own memory
      and died before the first instruction, with nothing in the log to say why. A zerofill segment placed by
      the linker exists before any code runs, so the range cannot be taken in the first place; the per-app
      host has carried exactly this reservation since 10-10. 2 GB is address space, not memory: it costs
      nothing until touched, and no single app image comes near it. */
#define A2X_GUEST_BASE 0x100000000UL
#define A2X_GUEST_LEN  0x80000000UL
__attribute__((section("__ARMRSV,__rsv,zerofill"), used)) static char a2x_rsv[A2X_GUEST_LEN];

/* Guest code pages are sealed PROT_NONE after load, and the interpreter fetches from a read-only alias.
   A native call into a guest function is an instruction-fetch fault, and on this VM that fault costs 3-24 ms
   when the page is readable (200-fault loop, native x86 control: RW page 3.4 and 9.3 ms, R page 14.7 and 23.9 ms
   per fault) but 2.7 us when the page is PROT_NONE or unmapped. Calculator makes 1,735 such calls to start,
   so a readable page costs it about 100 s before the run loop, and the 12 s sweep reads that as no window.
   a2x_pg_sealed has one byte per 4 KiB guest page: 1 = the page is PROT_NONE here and its bytes live at
   page + a2x_alias_delta. Anything that touches a sealed page by data access (a literal pool in __text, a
   host peek, a store) takes a fault that unseals just that page and retries, so correctness never depends on
   the seal; only the speed of native->guest calls into that one page does. */
#define A2X_ALIAS_BASE 0x200000000UL
#define A2X_PG_SHIFT   12
unsigned char *a2x_pg_sealed;
unsigned long a2x_alias_delta;
/* 11-02 r13m 1 = this sealed page's original was RELEASED at seal time (it reads as zeros); its only bytes are
      in the alias, which shares the original's physical pages. The first unseal copies them back. */
static unsigned char *a2x_pg_disc;
static inline const void *a2x_code_view(unsigned long a) {
    if (a2x_pg_sealed && a >= A2X_GUEST_BASE && a < A2X_GUEST_BASE + A2X_GUEST_LEN
        && a2x_pg_sealed[(a - A2X_GUEST_BASE) >> A2X_PG_SHIFT] == 1)   /* B23b: 2 = unsealed code page, read live */
        return (const void *)(uintptr_t)(a + a2x_alias_delta);
    return (const void *)(uintptr_t)a;
}
extern const void *(*a2x_block_probe_view)(unsigned long);

/* The return address of the guest call that is being handed to Intel code; set by the interpreter loop just before
   the hand-over. 0 when it is not known. */
__thread unsigned long a2x_native_lr;

/* One call site's stack-argument layout: n arguments at offs[] of sizes[] bytes, then plain 8-byte words from
   tail on. plain = 1 means the caller's layout already is one 8-byte place per argument. */
/* 32 = the width of the hand-over's stack window (native_door.ll); chosen by us, one call met so far has 22 */
#define A2X_STK_ARGS 32
struct a2x_stk_layout { unsigned long lr; int plain, n; unsigned short offs[A2X_STK_ARGS]; unsigned char sizes[A2X_STK_ARGS]; unsigned tail; };
#define A2X_STK_SITES 1024
static struct a2x_stk_layout *a2x_stk_site[A2X_STK_SITES];

/* Reads the stores to the stack that precede the call at lr - 4 and works out how the caller laid its stack
   arguments out. Walks back at most 128 instructions and stops at an earlier call, a return, a jump, or a change
   of the stack pointer, since offsets before any of those mean something else. */
static struct a2x_stk_layout *a2x_stk_scan(unsigned long lr) {
    struct a2x_stk_layout *L = calloc(1, sizeof *L);
    if (!L) return 0;
    L->lr = lr; L->plain = 1;
    if (lr < 8 || (lr & 3) || lr - 4 < __arm_text_base || lr - __arm_text_base > __arm_text_size) return L;
    uint32_t call; memcpy(&call, a2x_code_view(lr - 4), 4);
    if ((call & 0xfc000000u) != 0x94000000u && (call & 0xfffff000u) != 0xd63f0000u) return L;   /* not a call: leave as is */
    struct { int off, size; } st[64]; int ns = 0;
    for (unsigned k = 2; k <= 129; k++) {
        unsigned long a = lr - 4UL * k;
        if (a < __arm_text_base) break;
        uint32_t i; memcpy(&i, a2x_code_view(a), 4);
        if ((i & 0xfc000000u) == 0x94000000u || (i & 0xfffff000u) == 0xd63f0000u || (i & 0xfffffc1fu) == 0xd65f0000u
            || (i & 0xfc000000u) == 0x14000000u || (i & 0xff8003ffu) == 0xd10003ffu || (i & 0xff8003ffu) == 0x910003ffu) break;
        int off = -1, size = 0, two = 0;
        if (((i >> 5) & 31) != 31) continue;                              /* base register is not the stack pointer */
        uint32_t top = i & 0xffc00000u;
        if (top == 0x39000000u) { size = 1; off = (int)((i >> 10) & 0xfff); }
        else if (top == 0x79000000u) { size = 2; off = (int)((i >> 10) & 0xfff) * 2; }
        else if (top == 0xb9000000u || top == 0xbd000000u) { size = 4; off = (int)((i >> 10) & 0xfff) * 4; }
        else if (top == 0xf9000000u || top == 0xfd000000u) { size = 8; off = (int)((i >> 10) & 0xfff) * 8; }
        else if (top == 0xa9000000u || top == 0x6d000000u) { size = 8; two = 1; off = ((int)((i >> 15) & 0x7f) << 25 >> 25) * 8; }
        else if (top == 0x29000000u) { size = 4; two = 1; off = ((int)((i >> 15) & 0x7f) << 25 >> 25) * 4; }
        else if ((i & 0x3fe00c00u) == 0x38000000u) { size = 1 << (i >> 30); off = (int)((i >> 12) & 0x1ff) << 23 >> 23; }
        else continue;
        for (int t = 0; t <= two; t++) {
            int o = off + t * size, seen = 0;
            if (o < 0 || o > 1024) continue;
            for (int j = 0; j < ns; j++) if (st[j].off == o) seen = 1;   /* the store nearest the call wins */
            if (!seen && ns < 64) { st[ns].off = o; st[ns].size = size; ns++; }
        }
    }
    /* the arguments are the run of stores that starts at offset 0 with no gap but the padding a size asks for */
    int expect = 0, narrow = 0;
    while (L->n < A2X_STK_ARGS) {
        int best = -1;
        for (int j = 0; j < ns; j++) {
            int al = (expect + st[j].size - 1) & ~(st[j].size - 1);
            /* the NEXT argument is the one lowest on the stack: after a byte at 0 comes the byte at 1, not the
               8-byte word at 8, which also sits at its own aligned place */
            if (st[j].off == al && (best < 0 || st[j].off < st[best].off)) best = j;
        }
        if (best < 0) break;
        L->offs[L->n] = (unsigned short)st[best].off; L->sizes[L->n] = (unsigned char)st[best].size; L->n++;
        if (st[best].size < 8) narrow = 1;
        expect = st[best].off + st[best].size;
    }
    L->tail = (unsigned)((expect + 7) & ~7);
    L->plain = !narrow;
    return L;
}

/* the callee's stack arguments: AAPCS64 puts the 9th argument onward on the arm stack, and SysV expects
      them on ours, so the door copies a bounded window across. 16 words covers every signature we have met;
      a function wanting more would read our frame, which is why the count is fixed and documented. */
void __arm2x86_stack_args_n(unsigned long asp, unsigned long *out, int W) {
    if (!asp) { memset(out, 0, (size_t)W * sizeof *out); return; }
    unsigned long lr = a2x_native_lr;
    if (lr) {
        unsigned h = (unsigned)((lr >> 2) * 0x9E3779B97F4A7C15UL >> 54) & (A2X_STK_SITES - 1);
        struct a2x_stk_layout *L = __atomic_load_n(&a2x_stk_site[h], __ATOMIC_ACQUIRE);
        if (!L || L->lr != lr) {
            L = a2x_stk_scan(lr);                      /* an earlier record for another call site in this slot is left to leak: it may be in use */
            if (L) __atomic_store_n(&a2x_stk_site[h], L, __ATOMIC_RELEASE);
        }
        if (L && !L->plain) {
            int n = 0;
            for (; n < L->n && n < W; n++) {
                unsigned long v = 0;
                memcpy(&v, (const void *)(uintptr_t)(asp + L->offs[n]), L->sizes[n]);
                out[n] = v;
            }
            if (n < W) memcpy(out + n, (const void *)(uintptr_t)(asp + L->tail), (size_t)(W - n) * sizeof *out);
            return;
        }
    }
    memcpy(out, (const void *)(uintptr_t)asp, (size_t)W * sizeof *out);
}
/* the 16-word entry, for callers that own a 16-word buffer */
void __arm2x86_stack_args(unsigned long asp, unsigned long *out) { __arm2x86_stack_args_n(asp, out, 16); }
/* For the Swift door: 1 and W re-laid words in out when the caller at lr packed its stack arguments by size,
   0 (out untouched) when its layout already is one 8-byte place per argument or is not known. */
int a2x_stk_relay(unsigned long lr, unsigned long asp, unsigned long *out, int W) {
    if (!asp || !lr) return 0;
    unsigned h = (unsigned)((lr >> 2) * 0x9E3779B97F4A7C15UL >> 54) & (A2X_STK_SITES - 1);
    struct a2x_stk_layout *L = __atomic_load_n(&a2x_stk_site[h], __ATOMIC_ACQUIRE);
    if (!L || L->lr != lr) {
        L = a2x_stk_scan(lr);
        if (L) __atomic_store_n(&a2x_stk_site[h], L, __ATOMIC_RELEASE);
    }
    if (!L || L->plain) return 0;
    int n = 0;
    for (; n < L->n && n < W; n++) {
        unsigned long v = 0;
        memcpy(&v, (const void *)(uintptr_t)(asp + L->offs[n]), L->sizes[n]);
        out[n] = v;
    }
    if (n < W) memcpy(out + n, (const void *)(uintptr_t)(asp + L->tail), (size_t)(W - n) * sizeof *out);
    return 1;
}

/* WHICH ARGUMENTS ARE FUNCTION POINTERS. An arm64 function pointer handed to native code must become a
      trampoline, or native code jumps into arm64 bytes — measured exactly that way: qsort was handed the
      guest comparator at 0x100000af8 and called it, for a SIGBUS whose faulting address was the comparator
      itself.
    "ANY VALUE INSIDE __TEXT" IS THE WRONG RULE and would be worse than doing nothing: __cstring lives in
      __TEXT too, so every string constant passed to native code would be replaced by a trampoline address.
      The test has to be an EXACT function start, and LC_FUNCTION_STARTS is precisely that list — every
      function in the image including the static ones, which a symbol table can miss. */
/* 65,536 WAS NOT ENOUGH AND THE OVERFLOW WAS SILENT. Measured on macOS 27: Maps' executable
      alone has 80,734 LC_FUNCTION_STARTS entries, so 15,198 of its functions were invisible to
      is_function_start() — which means the universal trampoline could NOT recover a native->guest
      call into any of them and __arm2x86_cbarg could not wrap one as a callback. The truncation
      printed nothing; the resulting crash looked like a translation bug in a random function.
    The count is now reported when it is exceeded, because a cap that silently drops data is a
      measurement that lies. 262,144 entries is 2 MB of BSS against a host that already reserves 2 GB. */
/* 4,194,304: a browser engine has well over a million functions, and one that is dropped here is called as Intel code */
#define FSTARTS_MAX (1 << 22)
static unsigned long g_fstart[FSTARTS_MAX];
static unsigned g_nfstart;
static unsigned long g_fstart_dropped;

static int fstart_cmp(const void *a, const void *b) {
    unsigned long x = *(const unsigned long *)a, y = *(const unsigned long *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}
static int is_function_start(unsigned long a);
/* Code sections of images that came without a function-start list. Entries are written before the count is
   published and never change afterwards, so the reader (which may be the fault handler) takes no lock. */
#define NOFS_MAX 256
static struct { unsigned long lo, hi; } g_nofs[NOFS_MAX];
static unsigned g_nnofs;
static unsigned long g_ld_code_lo, g_ld_code_hi;      /* the image being loaded: its code section, if seen */
static int g_ld_fs_seen;                               /* ...and whether it carried the list */
/* THE READER NEVER SEES AN ARRAY BEING SORTED. is_function_start is called from the fault handler with no lock, so a
      late guest load builds the merged, sorted array BESIDE the live one and publishes it with one pointer store. Until
      the first publish (startup sorts g_fstart in place, before any guest runs) the reader uses g_fstart directly. */
struct fsnap { unsigned n; unsigned long a[]; };
static struct fsnap *volatile g_fsnap;
static int g_fs_late;                                  /* 1 while a late load collects starts into g_fnew */
static unsigned long *g_fnew; static unsigned g_nfnew;
static int is_function_start(unsigned long a) {
    for (unsigned i = 0, nn = __atomic_load_n(&g_nnofs, __ATOMIC_ACQUIRE); i < nn; i++)
        if (a >= g_nofs[i].lo && a < g_nofs[i].hi) return !(a & 3);
    struct fsnap *s = __atomic_load_n(&g_fsnap, __ATOMIC_ACQUIRE);
    const unsigned long *v = s ? s->a : g_fstart;
    unsigned n = s ? s->n : g_nfstart;
    unsigned lo = 0, hi = n;
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        if (v[mid] < a) lo = mid + 1; else hi = mid;
    }
    return lo < n && v[lo] == a;
}
#if A2X_SLOTS
/* [lo, hi) = the function holding a: the last start <= a and the next start. -1 = an image with no list. */
int a2x_func_bounds(uint64_t a, uint64_t *flo, uint64_t *fhi) {
    for (unsigned i = 0, nn = __atomic_load_n(&g_nnofs, __ATOMIC_ACQUIRE); i < nn; i++)
        if (a >= g_nofs[i].lo && a < g_nofs[i].hi) return -1;
    struct fsnap *sn = __atomic_load_n(&g_fsnap, __ATOMIC_ACQUIRE);
    const unsigned long *v = sn ? sn->a : g_fstart;
    unsigned n = sn ? sn->n : g_nfstart;
    unsigned lo = 0, hi = n;
    while (lo < hi) { unsigned mid = (lo + hi) / 2; if (v[mid] <= a) lo = mid + 1; else hi = mid; }
    if (!lo) return -1;
    *flo = v[lo - 1];
    *fhi = lo < n ? v[lo] : v[lo - 1] + 0x100000;      /* the last function: the caller clips to its image */
    return 0;
}
#endif

extern unsigned long __arm2x86_cb(unsigned long fn);

/* THE SWIFT METADATA PROBE IS GONE, and so is the descriptor+36 patch it measured. It worked — it
      moved Tips past the completion function — but it was ONE data structure's function pointer, and the
      sweep over all 65 apps showed the same fault arriving from dispatch_once blocks, job continuations and
      SwiftUI glue as well. recover_guest_call() below handles every one of them without knowing any layout,
      so the measured offset is kept as a FINDING in the memory note, not as code. */

unsigned long __arm2x86_cbarg(unsigned long v) {
    /* __arm2x86_cb returns anything outside the main image's text unchanged, so testing that range FIRST
       gives the same answer and spares the binary search over up to 262,144 function starts. The fixed-shape
       door calls this for all eight integer registers of EVERY native call, and nearly all of them are small
       integers, heap or stack pointers. */
    if (!v || v < __arm_text_base || v - __arm_text_base >= __arm_text_size || !is_function_start(v)) return v;
    return __arm2x86_cb(v);
}

/* svc: the host runs no syscalls on the guest's behalf yet — report rather than guess at one */
unsigned long __arm2x86_svc(unsigned long x16, unsigned long *a, unsigned long c, unsigned long addr) {
    (void)a; (void)c;
    fprintf(stderr, "[host] svc %lu at 0x%lx is not implemented by the host\n", x16, addr);
    a2x_stop("a direct system call is not supported", ""); abort();
}

extern int __arm2x86_interp_run(unsigned long target, unsigned long *xs, unsigned char *vs);

/* ── Mach-O ── */
struct mh64 { uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved; };
struct lc { uint32_t cmd, cmdsize; };
struct seg64 {
    uint32_t cmd, cmdsize; char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
};
struct entry_point { uint32_t cmd, cmdsize; uint64_t entryoff, stacksize; };
struct dylib_cmd { uint32_t cmd, cmdsize, name_off, ts, cur, compat; };
struct linkedit { uint32_t cmd, cmdsize, dataoff, datasize; };

#define LC_SEGMENT_64_   0x19
#define LC_MAIN_         0x80000028
#define LC_LOAD_DYLIB_   0x0c
#define LC_LOAD_WEAK_    0x80000018
#define LC_REEXPORT_     0x8000001f
#define LC_SYMTAB_       0x02
#define LC_FUNCTION_STARTS_ 0x26
/* THE GUEST'S PLATFORM, read only so the host can SAY what it is. PLATFORM_MACCATALYST = 6, and a Catalyst
      app's frameworks live under /System/iOSSupport — which dyld will not load into a process whose own
      platform is macOS. a2xhost is a plain macOS binary, so those dependencies can fail to load and every
      import from them resolves to 0. MEASURED: FindMy and Maps are PLATFORM_MACCATALYST and name 15 and 32
      /System/iOSSupport dependencies; 235 of FindMy's 353 and 1,834 of Maps' 2,709 class records take their
      superclass from a bind, so a framework that does not load is a NULL superclass pointer per class. */
#define LC_BUILD_VERSION_   0x32
#define PLATFORM_MACCATALYST_ 6
struct build_version { uint32_t cmd, cmdsize, platform, minos, sdk, ntools; };

struct a64_fixup { uint64_t at, target; const char *symbol; int lib_ordinal, weak, is_bind; };
static int a2x_sysdylib_guest_path(const char *nm, char *out, size_t n);   /* 11-02 1102h, defined after exe_arm64_only */
int a64_walk_fixups_slide(const uint8_t *file, size_t flen, uint64_t slide,
                          void (*cb)(const struct a64_fixup *, void *), void *ctx);

/* ── the guest images: the executable plus every arm64 dylib it ships inside its own bundle ──
    An app's own frameworks are GUESTS too (Books ships 14, Podcasts 15). A system path resolves to the
      real x86 framework through dlopen, but a bundle-relative one is arm64 and must be mapped, rebased and
      fixed up exactly like the executable — otherwise its imports stay unresolved and the first call into it
      lands on zero. */
struct symtab_cmd { uint32_t cmd, cmdsize, symoff, nsyms, stroff, strsize; };
struct nlist64 { uint32_t n_strx; uint8_t n_type, n_sect; uint16_t n_desc; uint64_t n_value; };
#define N_EXT_  0x01
#define N_TYPE_ 0x0e
#define N_SECT_ 0x0e

#define IMAGES_MAX 1024   /* was 64: one media player alone ships over 300 plug-in libraries */
/* THE ObjC SECTIONS, FOUND AT LOAD TIME. xlat2 reads these on the build machine and emits a per-image
      registration call; the host walks the section headers instead — the same data, without the build step.
      Addresses are slid, so they point into the mapped image. */
struct objc_secs { uint64_t classlist, nclass, catlist, ncat, protolist, nproto,
                            catlist2, ncat2,   /* categories on Swift classes reached through a class stub */
                            protorefs, nprotoref, classrefs, nclassref, superrefs, nsuperref,
                            selrefs, nselref,
                            /* Swift metadata and thread-locals, same idea: sections the runtime must be told
                               about because this host maps the image instead of dyld */
                            sw_proto, nsw_proto, sw_types, nsw_types, sw_protos, nsw_protos,
                            tvars, ntvars, tdata, tdata_size, tbss, tbss_size,
                            /* static initializers: __init_offsets (32-bit offsets from the header) and __mod_init_func (pointers) */
                            initoff, ninitoff, modinit, nmodinit,
                            /* byte ranges: __objc_const, __objc_data, __objc_classname (class_ro_t sweep, objc_bridge.c) */
                            rconst_a, rconst_n, rdata_a, rdata_n, cname_a, cname_n; };
struct section64 {
    char sectname[16], segname[16];
    uint64_t addr, size;
    uint32_t offset, align, reloff, nreloc, flags, r1, r2, r3;
};

struct image {
    const uint8_t *file;        /* the arm64 slice */
    size_t flen;
    uint64_t slide;             /* where it actually went; 0 for the executable */
    uint64_t text_vmaddr, vmend;
    uint64_t code_a[16], code_e[16];   /* __TEXT sections holding instructions (S_ATTR_PURE|SOME_INSTRUCTIONS) */
    unsigned ncode;
    /* vmlo/vmend bracket what this host ACTUALLY mapped for the image. guest_mapped() below is
          the only honest answer to "is this pointer one of ours", and every list the ObjC and Swift
          registration dereferences is checked against it before the runtime ever sees it. */
    uint64_t vmlo;
    uint32_t platform;          /* LC_BUILD_VERSION; 6 = Mac Catalyst, which changes where its deps live */
    const struct nlist64 *syms;
    uint32_t nsyms, strsize;
    const char *strs;
    const uint8_t *trie;        /* the export trie (LC_DYLD_EXPORTS_TRIE / LC_DYLD_INFO), bounds-checked at load */
    uint32_t trie_size;
    struct objc_secs objc;
    char path[1024];
};
static struct image g_img[IMAGES_MAX];
static unsigned g_nimg;
/* 11-04 the exception walker (a64_eh.c) reads a guest image's __unwind_info and LSDAs from its file bytes */
int a2x_guest_image_at(uint64_t pc, const uint8_t **file, uint64_t *flen, uint64_t *slide) {
    for (unsigned i = 0; i < g_nimg; i++)
        if (pc >= g_img[i].vmlo && pc < g_img[i].vmend) {
            *file = g_img[i].file; *flen = g_img[i].flen; *slide = g_img[i].slide; return 1;
        }
    return 0;
}

/* IS THIS ADDRESS INSIDE SOMETHING WE MAPPED? The guest's whole range is reserved at link time, so
      "inside the reservation" is not the same question — a pointer can be in the reservation and in
      no image at all, which is precisely what an unapplied fixup leaves behind. */
static int guest_mapped(uint64_t a, uint64_t len) {
    if (!a || !len) return 0;
    for (unsigned i = 0; i < g_nimg; i++)
        if (a >= g_img[i].vmlo && a + len <= g_img[i].vmend) return 1;
    return 0;
}

/* 10-27 THE SYMBOL TABLE IS NOT THE EXPORT LIST. A stripped framework keeps its exported names only in the
      export trie, so a lookup that reads LC_SYMTAB alone says "missing" for symbols the image defines: Podcasts
      bound 4981 imports to 0 this way — 3485 of ShelfKit's own, 396 of PodcastsPlayback's, 300 of
      PodcastsAppEntities' — and died in the Swift runtime on "Failed to look up symbolic reference ... missing
      weak symbol" at a ShowEntity type descriptor. This walks the trie for one name. Every offset is checked
      against the trie's size, and a cycle cannot run for ever because each step consumes at least one byte of
      the label or moves to a strictly later node (bounded by the node count below anyway). */
static int trie_uleb(const uint8_t *t, uint32_t n, uint32_t *pos, uint64_t *out) {
    uint64_t v = 0; unsigned sh = 0;
    while (*pos < n) {
        uint8_t b = t[(*pos)++];
        if (sh < 64) v |= (uint64_t)(b & 0x7f) << sh;
        sh += 7;
        if (!(b & 0x80)) { *out = v; return 1; }
    }
    return 0;
}
static int trie_find(const struct image *im, const char *name, uint64_t *off) {
    const uint8_t *t = im->trie; uint32_t n = im->trie_size, node = 0;
    if (!t || !n) return 0;
    for (unsigned guard = 0; guard < 4096; guard++) {
        uint32_t pos = node; uint64_t tsz;
        if (!trie_uleb(t, n, &pos, &tsz)) return 0;
        uint32_t after = pos + (uint32_t)tsz;
        if (tsz > n || after > n) return 0;
        if (!*name && tsz) {
            uint64_t flags, val;
            if (!trie_uleb(t, n, &pos, &flags)) return 0;
            if (flags & 0x08) return 0;                 /* re-export: another image's symbol, not ours */
            if (flags & 0x03) return 0;                 /* thread-local or absolute: the value is not an image offset */
            if (!trie_uleb(t, n, &pos, &val)) return 0;
            if (flags & 0x10) return 0;                 /* stub-and-resolver: the address is a resolver, not data */
            *off = val; return 1;
        }
        pos = after;
        if (pos >= n) return 0;
        unsigned nchild = t[pos++], k;
        uint32_t next = 0; int hit = 0;
        for (k = 0; k < nchild; k++) {
            uint32_t lab = pos;
            while (pos < n && t[pos]) pos++;
            if (pos >= n) return 0;
            size_t ll = pos - lab;
            pos++;
            uint64_t child;
            if (!trie_uleb(t, n, &pos, &child)) return 0;
            if (!hit && !strncmp((const char *)t + lab, name, ll)) {
                if (child >= n) return 0;
                next = (uint32_t)child; name += ll; hit = 1;
            }
        }
        if (!hit) return 0;
        node = next;
    }
    return 0;
}

/* EXPORTS COME FROM LC_SYMTAB first: an external symbol defined in a section is exactly what another
      image's bind needs, and the symbol table says so directly. The export trie is the second source
      (see trie_find) for the images whose table was stripped. */
/* 10-28 AN EXPORT INDEX, BUILT ONCE PER IMAGE. guest_lookup WAS a linear scan of every symbol of every image,
      once per bind: measured on Freeform, 96 of 112 main-thread samples in apply/strcmp/dlsym, still binding when the
      12 s window test gave up. The index gives the old answer exactly — image order, the first definition wins, the
      symbol table before the export trie — and extends itself when an image is added after it was built. */
struct gx { const char *name; uint64_t addr; };
static struct gx *g_gx;
static size_t g_gxcap, g_gxn;
static unsigned g_gxnimg;
static uint64_t gx_hash(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) { h ^= (unsigned char)*s++; h *= 1099511628211ULL; }
    return h;
}
static struct gx *gx_slot(struct gx *t, size_t cap, const char *name) {
    size_t m = cap - 1, i = (size_t)gx_hash(name) & m;
    while (t[i].name && strcmp(t[i].name, name)) i = (i + 1) & m;
    return &t[i];
}
static void gx_put(const char *name, uint64_t addr) {
    if ((g_gxn + 1) * 2 > g_gxcap) {
        size_t nc = g_gxcap ? g_gxcap * 2 : 1u << 16;
        struct gx *nt = calloc(nc, sizeof *nt);
        if (!nt) return;                                /* the trie fallback below still answers */
        for (size_t i = 0; i < g_gxcap; i++) if (g_gx[i].name) *gx_slot(nt, nc, g_gx[i].name) = g_gx[i];
        free(g_gx); g_gx = nt; g_gxcap = nc;
    }
    struct gx *e = gx_slot(g_gx, g_gxcap, name);
    if (e->name) return;                                /* first definition wins, as the scan did */
    e->name = name; e->addr = addr; g_gxn++;
}
static void gx_sync(void) {
    for (; g_gxnimg < g_nimg; g_gxnimg++) {
        const struct image *im = &g_img[g_gxnimg];
        for (uint32_t k = 0; k < im->nsyms; k++) {
            const struct nlist64 *n = &im->syms[k];
            if (!(n->n_type & N_EXT_)) continue;
            if ((n->n_type & N_TYPE_) != N_SECT_) continue;
            if (!n->n_value) continue;
            /* n_strx IS AN INDEX INTO A TABLE WHOSE SIZE WE NOW KNOW. Unbounded, strcmp() reads
                  past the mapped file and compares whatever is there as a symbol name. */
            if (!im->strs || n->n_strx >= im->strsize) continue;
            gx_put(im->strs + n->n_strx, n->n_value + im->slide);
        }
    }
}

/* A handle names one image. A prior image exporting the same symbol must
   neither supply that address nor hide the requested image's own definition. */
static uint64_t guest_image_lookup(unsigned idx, const char *name) {
    if (idx >= g_nimg || !name) return 0;
    const struct image *im = &g_img[idx];
    for (uint32_t k = 0; k < im->nsyms; k++) {
        const struct nlist64 *n = &im->syms[k];
        if (!(n->n_type & N_EXT_) || (n->n_type & N_TYPE_) != N_SECT_ || !n->n_value) continue;
        if (!im->strs || n->n_strx >= im->strsize) continue;
        const char *sym = im->strs + n->n_strx;
        if (!memchr(sym, 0, im->strsize - n->n_strx) || strcmp(sym, name)) continue;
        uint64_t addr = n->n_value + im->slide;
        if (addr >= im->vmlo && addr < im->vmend) return addr;
    }
    uint64_t off;
    if (trie_find(im, name, &off)) {
        uint64_t addr = im->text_vmaddr + im->slide + off;
        if (addr >= im->vmlo && addr < im->vmend) return addr;
    }
    return 0;
}

static uint64_t guest_lookup(const char *name) {
    gx_sync();
    if (g_gxcap) {
        const struct gx *e = gx_slot(g_gx, g_gxcap, name);
        if (e->name) return e->addr;
    }
    for (unsigned i = 0; i < g_nimg; i++) {
        uint64_t off;
        if (trie_find(&g_img[i], name, &off)) return g_img[i].text_vmaddr + off + g_img[i].slide;
    }
    return 0;
}

/* ONE MISSING IMPORT WAS NAMED; THE REST WERE A COUNT. For the pre-guest fault that is the wrong way
      round: the slot an unresolved bind leaves at 0 may be a class record's metaclass or superclass
      pointer, and that is the 0x20 shape. Keep the first MISSING_MAX names, and count the class ones
      separately so one line of the log answers "did a class pointer stay NULL". */
#define MISSING_MAX 32
struct ctx {
    uint64_t text;              /* the image's __TEXT vmaddr — the slide is zero, we map where it asks */
    unsigned long nrebase, nbind, nmissing;
    const char *first_missing;
    const char *missing[MISSING_MAX];
    unsigned long nmissing_cls;
    unsigned cur;               /* the image being bound: its lib ordinals name ITS load commands */
    void *dlh[253];             /* per-image cache: ordinal -> native handle (0 = none) */
    unsigned char dlh_done[253];
    unsigned long n2lvl;        /* binds where the named library's answer differed from the flat one */
};

/* WHO ARE WE CALLING. The interpreter needs the callee's NAME at the moment it leaves the images, because
      the variadic ABI differs between the two architectures and only the symbol says whether that applies.
      Recorded here at bind time: the host is the only place that knows which address got which symbol. */
#define NAMES_MAX 65536   /* Weather alone binds 23970 imports; past the cap a callee loses its name and takes the wrong door */
static unsigned g_nnames;

/* 10-31 ADDRESS-KEYED HASHES, NOT LINEAR SCANS. Both lookups below walked their whole table: a64_native_name up
      to 65,536 entries (Weather binds 23,970) on every door-cache fill — and an UNNAMED target (a vtable slot, a
      witness) is a full miss — and remember() did the same walk per bind, O(n^2) at load (~288M compares for 24k).
    Same answers as the arrays they replace: an address keeps the FIRST name it was given, nothing is ever removed,
      and the counts g_nnames / g_nrf (which a64_names_gen() publishes) move exactly when the arrays used to grow.
    Readers take no lock: a slot's value is written before its key is published with RELEASE, and a reader that
      sees the key with ACQUIRE sees the value. Writers (binds) are serialised by g_namesm.
   Open addressing at <= 50% load (NAMES_MAX entries in 2x slots), linear probe, key 0 = empty (address 0 is never
   bound: a missing import is not remembered). */
#define NAMES_HN (2 * NAMES_MAX)
static unsigned long g_nh_key[NAMES_HN];
static const char *g_nh_val[NAMES_HN];
#define RF_MAX 512
#define RF_HN 1024
static unsigned long g_rh_key[RF_HN];
static unsigned g_nrf;
static pthread_mutex_t g_namesm = PTHREAD_MUTEX_INITIALIZER;
static inline unsigned a2x_ahash(unsigned long a, unsigned mask) {
    return (unsigned)(((a >> 2) * 0x9E3779B97F4A7C15UL) >> 32) & mask;
}

const char *a64_native_name(unsigned long addr) {
    if (!addr) return 0;
    for (unsigned h = a2x_ahash(addr, NAMES_HN - 1);; h = (h + 1) & (NAMES_HN - 1)) {
        unsigned long k = __atomic_load_n(&g_nh_key[h], __ATOMIC_ACQUIRE);
        if (!k) return 0;
        if (k == addr) return g_nh_val[h];
    }
}
/* WHICH NATIVE ADDRESSES ARE BRIDGE WRAPPERS. The interpreter asks at the moment it leaves the images:
      a wrapper is entered through the register file, everything else through the variadic door. */
int a64_is_rf_callee(unsigned long addr) {
    if (!addr) return 0;
    for (unsigned h = a2x_ahash(addr, RF_HN - 1);; h = (h + 1) & (RF_HN - 1)) {
        unsigned long k = __atomic_load_n(&g_rh_key[h], __ATOMIC_ACQUIRE);
        if (!k) return 0;
        if (k == addr) return 1;
    }
}
/* A VERSION OF EVERYTHING THE TWO LOOKUPS ABOVE READ. Both tables only ever grow, and an address keeps the
      first name it was given, so a verdict about an address stays true until this number changes. The
      interpreter's per-target door cache keys on it, which is what lets a NEGATIVE verdict (an unnamed
      target: a vtable slot, a witness) be cached too. */
unsigned a64_names_gen(void) { return __atomic_load_n(&g_nnames, __ATOMIC_ACQUIRE) + __atomic_load_n(&g_nrf, __ATOMIC_ACQUIRE) + 1; }
static void rf_mark(unsigned long addr) {
    if (!addr) return;
    pthread_mutex_lock(&g_namesm);
    unsigned h = a2x_ahash(addr, RF_HN - 1);
    while (g_rh_key[h] && g_rh_key[h] != addr) h = (h + 1) & (RF_HN - 1);
    if (!g_rh_key[h] && g_nrf < RF_MAX) {
        __atomic_store_n(&g_rh_key[h], addr, __ATOMIC_RELEASE);
        __atomic_store_n(&g_nrf, g_nrf + 1, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&g_namesm);
}

/* WHAT DID WE BIND, AND TO WHAT. ARM2X86_TRACE_BINDS=1 lists every import with the address it resolved
      to. A guess about which symbol an app imports is how the Swift probe came back silent: the interception
      was keyed on a name the binary never mentions. */
static void trace_bind(const char *sym, unsigned long addr, const char *how) {
    static int tr = -1;
    if (tr < 0) tr = A2X_DBGENV("ARM2X86_TRACE_BINDS") ? 1 : 0;
    if (tr) fprintf(stderr, "[bind] %-56s -> 0x%lx (%s)\n", sym ? sym : "(null)", addr, how);
}

static int remember(unsigned long addr, const char *name) {
    if (!addr || !name) return 0;
    /* TEST-ONLY MISS ARM (10-31): ARM2X86_TEST_FORGET=<symbol> leaves that one symbol out of the table, so the gate
          can prove a missing hash entry is VISIBLE (the callee loses its door). Read once; unset, nothing changes. */
    static const char *forget; static int fr;
    if (!fr) { forget = A2X_DBGENV("ARM2X86_TEST_FORGET"); fr = 1; }
    if (forget && name && !strcmp(forget, name[0] == '_' && forget[0] != '_' ? name + 1 : name)) return 0;
    int added = 0;
    pthread_mutex_lock(&g_namesm);
    if (g_nnames < NAMES_MAX) {
        unsigned h = a2x_ahash(addr, NAMES_HN - 1);
        while (g_nh_key[h] && g_nh_key[h] != addr) h = (h + 1) & (NAMES_HN - 1);
        if (!g_nh_key[h]) {                       /* an address keeps the first name it was given */
            g_nh_val[h] = name;
            __atomic_store_n(&g_nh_key[h], addr, __ATOMIC_RELEASE);
            __atomic_store_n(&g_nnames, g_nnames + 1, __ATOMIC_RELEASE);
            added = 1;
        }
    }
    pthread_mutex_unlock(&g_namesm);
    return added;   /* a caller frees a name that was not kept */
}

/* The program's C++ library is a guest image when the vendored arm64 libc++ was found: Apple arm64 lays std::string out as
   {data, size, cap|bit63} / {chars, size in byte 23}, the native x86-64 libc++ as {cap|1, size, data} / {size*2, chars}, so any
   libc++ member bound natively reads and writes a guest string at the wrong offsets. */
static int g_libcxx_guest;

static void *a2x_late_wrapper(const char *nm);
/* 11-01 the install name of image c->cur's ordinal-th dylib command (1-based, every dylib-loading kind, in order),
      opened with RTLD_NOLOAD: the dependency scan already loaded it, and a bind must never load something new. */
static const uint8_t *slice_arm64(const uint8_t *f, size_t flen, size_t *out);
static void *a2x_twolevel_sym(struct ctx *c, int ord, const char *nm) {
    if (c->cur >= g_nimg || ord < 1 || ord > 252) return 0;
    if (!c->dlh_done[ord - 1]) {
        c->dlh_done[ord - 1] = 1;
        const struct image *im = &g_img[c->cur];
        size_t fl = 0;                                   /* im->file is the WHOLE file (fat): take the arm64 slice */
        const uint8_t *f = im->file ? slice_arm64(im->file, im->flen, &fl) : 0;
        if (!f || fl < sizeof(struct mh64)) return 0;
        const struct mh64 *mh = (const struct mh64 *)f;
        if ((size_t)mh->sizeofcmds > fl - sizeof *mh) return 0;
        const uint8_t *end = f + sizeof *mh + mh->sizeofcmds;
        const struct lc *l = (const struct lc *)(f + sizeof *mh);
        int n = 0;
        for (uint32_t k = 0; k < mh->ncmds; k++) {
            if ((const uint8_t *)l + sizeof *l > end || l->cmdsize < sizeof *l || (const uint8_t *)l + l->cmdsize > end) break;
            if (l->cmd == LC_LOAD_DYLIB_ || l->cmd == LC_LOAD_WEAK_ || l->cmd == LC_REEXPORT_
                || l->cmd == 0x80000023u /* LC_LOAD_UPWARD_DYLIB */ || l->cmd == 0x20u /* LC_LAZY_LOAD_DYLIB */) {
                if (++n == ord) {
                    const struct dylib_cmd *d = (const struct dylib_cmd *)l;
                    if (d->cmdsize >= sizeof *d && d->name_off >= sizeof *d && d->name_off < d->cmdsize
                        && memchr((const char *)l + d->name_off, 0, d->cmdsize - d->name_off)) {
                        const char *in = (const char *)l + d->name_off;
                        if (in[0] == '/') c->dlh[ord - 1] = dlopen(in, RTLD_LAZY | RTLD_NOLOAD);
                        if (A2X_DBGENV("ARM2X86_TRACE_BINDS"))
                            fprintf(stderr, "[bind-lib] image %u ordinal %d = %s -> handle %p%s\n", c->cur, ord, in,
                                    c->dlh[ord - 1], c->dlh[ord - 1] ? "" : " (NOT loaded: flat path)");
                    }
                    break;
                }
            }
            l = (const struct lc *)((const uint8_t *)l + l->cmdsize);
        }
    }
    return c->dlh[ord - 1] ? dlsym(c->dlh[ord - 1], nm) : 0;
}

/* the flat answer is deliberate when it comes from a DYLD_INSERT_LIBRARIES image or from the host executable itself */
static int a2x_flat_is_deliberate(const char *fn) {
    static char self[4096]; static int have = -1;
    if (have < 0) { uint32_t sz = sizeof self; have = _NSGetExecutablePath(self, &sz) == 0; }
    if (have && !strcmp(fn, self)) return 1;
    const char *ins = getenv("DYLD_INSERT_LIBRARIES");
    if (ins && *ins) {
        size_t L = strlen(fn);
        for (const char *p = ins; *p; ) {
            const char *q = strchr(p, ':'); size_t m = q ? (size_t)(q - p) : strlen(p);
            if (m == L && !strncmp(p, fn, m)) return 1;
            if (!q) break;
            p = q + 1;
        }
    }
    return strstr(fn, "/a2x") != 0;                  /* our own interposers live under /usr/libexec/a2x */
}

static void apply(const struct a64_fixup *f, void *vc) {
    struct ctx *c = vc;
    uint64_t *slot = (uint64_t *)(uintptr_t)f->at;
    if (!f->is_bind) { *slot = f->target; c->nrebase++; return; }
    /* AN IMPORT IS dlsym + STORE, and that is the whole reason no per-app build is needed: the interpreter
          reads this slot and the native door calls whatever address is in it. */

    /* SOME SYMBOLS MUST NOT BE CALLED NATIVELY AT ALL. objc_alloc takes a GUEST class the native
          runtime has never heard of, objc_msgSend has to find a guest method, swift_once takes a guest
          function pointer — so those bind to the bridge's wrapper instead, and the call goes through the
          register file rather than the variadic door. Without this, objc said exactly what you would
          expect: "Attempt to use unknown class 0x1000080b0", the guest's own class structure handed
          straight to the runtime. The table is generated from xlat2.py (interp/mkrftable.py). */
    /* The rf_table bridges for libc++ (to_string, stringbuf::str, operator+, filesystem::path) call the NATIVE function and
       return a native-layout std::string. With the guest libc++ mapped, the guest definition is the right one. */
    if (g_libcxx_guest && f->symbol && strstr(f->symbol, "St3__1")) {
        uint64_t gl = guest_lookup(f->symbol);
        if (gl) { *slot = gl + f->target; c->nbind++; return; }
    }
    /* arm64-only entry points of classes whose x86 twin has a different layout (swift_vlb.c) */
    {
        extern void (*a2x_arm_only_handler(const char *))(void);
        void (*h)(void) = a2x_arm_only_handler(f->symbol);
        if (h) {
            *slot = (uint64_t)(uintptr_t)h;
            rf_mark((unsigned long)(uintptr_t)h);
            remember((unsigned long)(uintptr_t)h, f->symbol);
            c->nbind++;
            return;
        }
    }
    for (unsigned k = 0; k < A64_RF_TABLE_N; k++) {
        if (strcmp(A64_RF_TABLE[k].sym, f->symbol)) continue;
        *slot = (uint64_t)(uintptr_t)A64_RF_TABLE[k].fn;
        rf_mark((unsigned long)(uintptr_t)A64_RF_TABLE[k].fn);
        remember((unsigned long)(uintptr_t)A64_RF_TABLE[k].fn, f->symbol);
        c->nbind++;
        return;
    }

    /* A GUEST EXPORT WINS OVER A NATIVE ONE. The app's own framework defines the symbol its executable
          imports, and resolving that to some same-named native function instead would call the wrong code. */
    uint64_t g = guest_lookup(f->symbol);
    if (g) { *slot = g + f->target; c->nbind++; return; }
    const char *nm = f->symbol;
    if (nm && nm[0] == '_') nm++;                       /* dlsym takes the C name */
    /* 11-05 r14s a native C++ function taking std::string gets the guest's arm64-layout strings converted (cxx_bridge.cpp) */
    if (g_libcxx_guest && f->symbol && !strncmp(f->symbol, "__Z", 3) && strstr(f->symbol, "basic_string")) {
        extern void (*a2x_strb_bind(const char *, void *))(void);
        void *nat_ = dlsym(RTLD_DEFAULT, nm);
        void (*h_)(void) = nat_ ? a2x_strb_bind(f->symbol, nat_) : 0;
        if (h_) {
            *slot = (uint64_t)(uintptr_t)h_;
            rf_mark((unsigned long)(uintptr_t)h_);
            remember((unsigned long)(uintptr_t)h_, f->symbol);
            c->nbind++;
            return;
        }
    }
    void *a = a2x_late_wrapper(nm);                     /* 10-28 late-load aware CFBundle/dlopen/dlsym */
    /* x86-64 plain stat/fstat/readdir/... ARE THE LEGACY 32-BIT-INODE LAYOUTS. The arm64 program was built against the
          64-bit-inode structs, so a plain dlsym handed it st_size at the wrong offset: Music read ColumnWidths.plist
          as 0 bytes, got no columnWidths, and quit with -192. The $INODE64 entry point is the one with the arm64 layout. */
    {
        static const char *const ino64[] = { "stat", "lstat", "fstat", "fstatat", "statfs", "fstatfs", "getfsstat", "getmntinfo",
            "readdir", "readdir_r", "opendir", "scandir", "seekdir", "telldir", "rewinddir", "fts_open", "fts_read",
            "fts_children", "fts_close", "fts_set", "glob", "ftw", "nftw", "alphasort",
            /* 11-01 fdopendir was missing: its legacy DIR read by readdir$INODE64 dropped the first character of
                  every name (logd's timesync scan -> EEXIST -> exit 1 x651 -> launchd never left on-demand mode). */
            "fdopendir", "fts_open_b", "glob_b", "scandir_b", "getmntinfo_r_np", "statx_np", "lstatx_np",
            "fstatx_np", 0 };
        for (int k = 0; ino64[k]; k++) if (!strcmp(nm, ino64[k])) {
            char alt[64]; snprintf(alt, sizeof alt, "%s$INODE64", nm);
            a = dlsym(RTLD_DEFAULT, alt);
            break;
        }
    }
    /* 11-01 TWO-LEVEL NAMESPACE. An import names its library by ordinal; dyld looks only there (and in what that
          library re-exports or depends on). The flat walk below took the FIRST loaded image with the name, and the
          stock-27 sshd got EVP_MD_CTX_new from libcrypto.46 but EVP_DigestInit_ex/Update from another library that
          exports the same names: digest_update asserted ctx != NULL and sshd never started.
        An inserted library (our interposers) or the host itself answering the flat lookup is DELIBERATE and wins.
        Ordinals 0 (self), 0xfd-0xff (weak / flat / main executable) and a library with no native handle keep the
          old flat path exactly. */
    if (!a && nm && f->lib_ordinal >= 1 && f->lib_ordinal <= 252) {
        void *t = a2x_twolevel_sym(c, f->lib_ordinal, nm);
        if (t) {
            void *flat = dlsym(RTLD_DEFAULT, nm);
            Dl_info di;
            if (flat && flat != t && dladdr(flat, &di) && di.dli_fname && a2x_flat_is_deliberate(di.dli_fname)) t = flat;
            else if (flat && flat != t) {
                c->n2lvl++;
                if (A2X_DBGENV("ARM2X86_TRACE_BINDS"))
                    fprintf(stderr, "[bind-2lvl] %s: named library 0x%lx, flat walk would have taken 0x%lx\n",
                            nm, (unsigned long)(uintptr_t)t, (unsigned long)(uintptr_t)flat);
            }
            a = t;
        }
    }
    /* 10-28 dlsym(RTLD_DEFAULT) walks every loaded image, and the same import (objc_msgSend, swift_retain) is
          bound once per guest image that uses it. A found answer cannot change while binding, so it is kept; a
          miss is NOT kept, because a later dlopen can supply it. */
    if (!a) {
        static struct gx *nt; static size_t ncap, nn;
        if (!nt) { ncap = 1u << 16; nt = calloc(ncap, sizeof *nt); }
        struct gx *e = nt ? gx_slot(nt, ncap, nm) : 0;
        if (e && e->name) a = (void *)(uintptr_t)e->addr;
        else {
            a = dlsym(RTLD_DEFAULT, nm);
            if (a && e && (nn + 1) * 2 <= ncap) { e->name = strdup(nm); e->addr = (uint64_t)(uintptr_t)a; nn++; }
        }
    }
    /* 10-27 ASK THE ObjC RUNTIME WHEN dlsym COMES BACK EMPTY. A framework in the dyld shared cache may
          omit its _OBJC_CLASS_$_ symbols from the export trie — dyld's ObjC optimisation makes them
          unnecessary, because the runtime finds a class by NAME — and then dlsym cannot see a class that is
          loaded and working. Measured on Photos: 16867 imports bound, 349 missing, and the host's own audit
          line says 138 of those are _OBJC_CLASS_$_ / _OBJC_METACLASS_$_ — with NO dlopen failure anywhere in
          the run, i.e. every one of those frameworks was loaded and answering.
        Each unresolved one leaves a NULL isa or superclass in a class record, and libobjc reads
          class->bits at +0x20 on it: the exact 0x20 fault that FindMy and Reminders still die on.
        This is what libobjc itself does when it fixes up an image's classrefs, so it is the same answer
          by the same route — not a substitute for it. */
    if (!a && f->symbol) {
        const char *cn = 0; int want_meta = 0;
        if (!strncmp(f->symbol, "_OBJC_CLASS_$_", 14))          cn = f->symbol + 14;
        else if (!strncmp(f->symbol, "_OBJC_METACLASS_$_", 18)) { cn = f->symbol + 18; want_meta = 1; }
        if (cn && *cn) {
            Class c = objc_getClass(cn);
            if (c) {
                a = want_meta ? (void *)object_getClass((id)c) : (void *)c;
                static unsigned long nbyname;
                nbyname++;
                if (nbyname <= 4 || !(nbyname % 64))
                    fprintf(stderr, "[host] %s was not in any export trie but the ObjC runtime has it "
                                    "(%lu resolved by name so far)\n", f->symbol, nbyname);
            }
        }
    }
    if (!a) {
        c->nmissing++;
        if (!c->first_missing) c->first_missing = f->symbol;
        if (c->nmissing <= MISSING_MAX) c->missing[c->nmissing - 1] = f->symbol;
        /* A MISSING CLASS IMPORT IS THE MOST LIKELY SOURCE OF THE 0x20 FAULT. The slot left at 0
              is a class record's metaclass (isa, +0) or superclass (+8) pointer, and libobjc reads
              class->bits at +0x20 — so the registration stage then hands the runtime a Nil Class and
              it faults at EXACTLY 0x20, with no guest pc because nothing has been interpreted yet.
              Counted apart from every other missing symbol so the log answers that in one line. */
        if (f->symbol && (!strncmp(f->symbol, "_OBJC_CLASS_$_", 14)
                          || !strncmp(f->symbol, "_OBJC_METACLASS_$_", 18)))
            c->nmissing_cls++;
        /* left as 0 deliberately: reaching it traps at a named address instead of running wild */
        /* ARM2X86_TRACE_BINDS also names the SLOT of every unresolved import, so a runtime message that
           cites a guest address ("pointer at 0x... is likely a reference to a missing weak symbol") maps
           straight to a symbol. */
        if (A2X_DBGENV("ARM2X86_TRACE_BINDS"))
            fprintf(stderr, "[bind-missing] slot 0x%lx  %s\n", (unsigned long)(uintptr_t)slot, f->symbol ? f->symbol : "(null)");
        { extern void a2x_missing_slot_note(unsigned long, const char *);      /* C1 11-06: a call through it is named */
          a2x_missing_slot_note((unsigned long)(uintptr_t)slot, f->symbol); }
        *slot = 0;
        return;
    }
    *slot = (uint64_t)(uintptr_t)a + f->target;         /* target carries the addend */
    remember((unsigned long)(uintptr_t)a, f->symbol);
    trace_bind(f->symbol, (unsigned long)(uintptr_t)a, "native");
    c->nbind++;
}

#define CPU_TYPE_ARM64_ 0x0100000c
static const uint8_t *slice_arm64(const uint8_t *f, size_t flen, size_t *out) {
    *out = 0;
    /* A FILE SHORTER THAN A MACH-O HEADER WAS READ AS ONE: magic came out of four bytes nobody had
          checked were there. */
    if (flen < sizeof(struct mh64)) return 0;
    uint32_t magic;
    memcpy(&magic, f, 4);
    if (magic != 0xbebafeca) {
        /* A THIN x86_64 MACH-O HAS THE SAME 0xfeedfacf MAGIC AS AN arm64 ONE, and the caller only
              ever checked the magic. Without a cputype test the host maps an x86_64 binary and
              interprets its bytes as arm64 instructions — nonsense from the first step, with nothing
              in the log to say the file was never ours to run. */
        uint32_t ct;
        memcpy(&ct, f + 4, 4);
        if (ct != CPU_TYPE_ARM64_) return 0;
        *out = flen;
        return f;
    }
    uint32_t n;
    memcpy(&n, f + 4, 4);
    n = __builtin_bswap32(n);
    /* THE FAT HEADER'S OWN ARRAY WAS UNBOUNDED: nfat_arch is a file field, and 20 bytes per entry
          past the end of a short file is a read of whatever follows it. */
    const uint8_t *fb = 0; size_t fbz = 0;      /* first arm64-type slice: the fallback when no arm64e exists */
    for (uint32_t k = 0; k < n && (size_t)8 + 20 * ((size_t)k + 1) <= flen; k++) {
        const uint8_t *fa = f + 8 + 20 * (size_t)k;
        uint32_t ct, off, sz;
        memcpy(&ct, fa, 4); memcpy(&off, fa + 8, 4); memcpy(&sz, fa + 12, 4);
        ct = __builtin_bswap32(ct); off = __builtin_bswap32(off); sz = __builtin_bswap32(sz);
        /* a slice header can name an extent past the end of the file it sits in */
        /* r13v 11-03: Apple ships arm64 AND arm64e in one fat (same cputype). An arm64e process on Apple silicon
              runs the arm64e slice; the first arm64-type entry may be the non-PAC arm64 one. Prefer subtype 2. */
        uint32_t cs; memcpy(&cs, fa + 4, 4); cs = __builtin_bswap32(cs);
        if (ct == CPU_TYPE_ARM64_ && sz >= sizeof(struct mh64) && (size_t)off + sz <= flen) {
            if ((cs & 0xff) == 2) { *out = sz; return f + off; }
            if (!fb) { fb = f + off; fbz = sz; }
        }
    }
    if (fb) { *out = fbz; return fb; }
    return 0;
}

/* A SECTION MUST LIE INSIDE THE SEGMENT THAT DECLARES IT, AND A LIST SECTION'S SIZE MUST BE A WHOLE
      NUMBER OF ENTRIES. Both were trusted: `sc->addr + slide` was recorded without ever asking whether that
      address is in the range this host just mapped, and `sc->size / 8` silently drops a partial entry. The
      Swift records are the dangerous case — host_doors.c hands libswiftCore a BYTE RANGE and the runtime
      walks it to the end, so a size that is not a multiple of 4 makes it read a record that is partly
      whatever follows the section.
    Reported BY NAME and left out, never dereferenced: a list we cannot trust is better absent than
      registered, and an absent one is visible in the counts the trace already prints. */
static int sect_ok(const char *path, const struct section64 *sc, const struct seg64 *sg, unsigned ent) {
    char sn[17];
    memcpy(sn, sc->sectname, 16);
    sn[16] = 0;
    if (sc->addr < sg->vmaddr || sc->addr + sc->size > sg->vmaddr + sg->vmsize) {
        fprintf(stderr, "[host] %s: section %s at 0x%llx + 0x%llx lies outside its own segment %s "
                        "(0x%llx + 0x%llx) — NOT recorded\n", path, sn,
                (unsigned long long)sc->addr, (unsigned long long)sc->size, sg->segname,
                (unsigned long long)sg->vmaddr, (unsigned long long)sg->vmsize);
        return 0;
    }
    if (ent && (sc->size % ent)) {
        fprintf(stderr, "[host] %s: section %s is %llu bytes, not a whole number of %u-byte entries — "
                        "NOT recorded\n", path, sn, (unsigned long long)sc->size, ent);
        return 0;
    }
    return 1;
}

/* map one guest image at `slide` and record what the binder needs from it. Returns 0 on success. */
static int load_guest(const char *path, uint64_t slide, int trace, uint64_t *entry_out) {
    if (g_nimg >= IMAGES_MAX) { fprintf(stderr, "[host] too many guest images\n"); return 1; }
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "[host] cannot open %s\n", path); return 1; }
    struct stat st;
    if (fstat(fd, &st)) { close(fd); return 1; }
    /* 10-28 READ, never mmap(fd). A file mapping is validated against whatever signature the kernel holds
          for that vnode (an earlier adopt, an exec of the fat file), and under the union-entitled host an
          invalid page is fatal: a never-adopted copy lived, the same bytes on an adopted vnode died in 1 s.
          Anonymous memory has no signature to fail. Lifetime is unchanged: im->file is never unmapped. */
    /* 11-02 r13m READ ONLY THE arm64 SLICE, INTO PAGE-ALIGNED MEMORY. Every installed route is a fat file whose
          x86_64 slice is this host (3.5 MB, already mapped as the executable), and the whole file was read into malloc,
          so every interpreted process paid it again as dirty memory.
        R12, 63 min: 738 jetsam high-watermark kills (findmylocateagent 354, wifip2pd 341, both at 15 MB).
          Every reader of im->file goes through slice_arm64(), which returns a thin arm64 file as itself, so keeping
          the slice alone changes no reader. Page alignment lets __TEXT share these pages instead of copying them. */
    uint8_t hdr_[4096];
    ssize_t hn_ = pread(fd, hdr_, sizeof hdr_, 0);
    off_t soff = 0;
    size_t ssz = (size_t)st.st_size;
    if (hn_ >= 8) {
        uint32_t mg_; memcpy(&mg_, hdr_, 4);
        if (mg_ == 0xbebafeca) {          /* the same rule as slice_arm64: the arm64e entry, else the first arm64 entry that fits */
            uint32_t na_; memcpy(&na_, hdr_ + 4, 4); na_ = __builtin_bswap32(na_);
            int found_ = 0;
            for (uint32_t k = 0; k < na_ && (size_t)8 + 20 * ((size_t)k + 1) <= (size_t)hn_; k++) {
                const uint8_t *fa_ = hdr_ + 8 + 20 * (size_t)k;
                uint32_t ct_, o_, z_;
                memcpy(&ct_, fa_, 4); memcpy(&o_, fa_ + 8, 4); memcpy(&z_, fa_ + 12, 4);
                ct_ = __builtin_bswap32(ct_); o_ = __builtin_bswap32(o_); z_ = __builtin_bswap32(z_);
                uint32_t cs_; memcpy(&cs_, fa_ + 4, 4); cs_ = __builtin_bswap32(cs_);   /* r13v: arm64e first */
                if (ct_ == CPU_TYPE_ARM64_ && z_ >= sizeof(struct mh64) && (size_t)o_ + z_ <= (size_t)st.st_size) {
                    if ((cs_ & 0xff) == 2) { soff = (off_t)o_; ssz = z_; found_ = 1; break; }
                    if (!found_) { soff = (off_t)o_; ssz = z_; found_ = 1; }
                }
            }
            if (!found_) { close(fd); fprintf(stderr, "[host] %s has no arm64 slice\n", path); return 1; }
        }
    }
    size_t wlen = (ssz + 0xfffUL) & ~0xfffUL;
    uint8_t *whole = wlen ? mmap(0, wlen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) : 0;
    if (whole == MAP_FAILED) whole = 0;
    size_t got = 0;
    while (whole && got < ssz) {
        ssize_t r = pread(fd, whole + got, ssz - got, soff + (off_t)got);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    if (!whole || got != ssz) {
        fprintf(stderr, "[host] cannot read %s (%zu of %zu slice bytes at offset %lld)\n", path, got, ssz, (long long)soff);
        if (whole) munmap(whole, wlen);
        return 1;
    }
    size_t flen = 0;
    const uint8_t *file = slice_arm64(whole, ssz, &flen);
    if (!file) { fprintf(stderr, "[host] %s has no arm64 slice\n", path); return 1; }
    const struct mh64 *mh = (const struct mh64 *)file;
    if (mh->magic != 0xfeedfacf) { fprintf(stderr, "[host] %s is not a 64-bit Mach-O\n", path); return 1; }

    struct image *im = &g_img[g_nimg];
    memset(im, 0, sizeof *im);
    im->vmlo = (uint64_t)-1;        /* lowered by each mapped segment; vmlo > vmend means nothing yet */
    im->file = whole; im->flen = ssz; im->slide = slide;   /* r13m: the arm64 slice only */
    snprintf(im->path, sizeof im->path, "%s", path);

    long ps = sysconf(_SC_PAGESIZE);
    int have_text = 0;
    /* BOUND EVERY MACH-O WALK — the rule, and this one had no bound at all. ncmds and cmdsize are
          file fields: a zero cmdsize spins forever, an unaligned one desynchronises every command
          after it, and a command that runs past sizeofcmds reads whatever follows in the file AS a
          load command. A chance 16-byte match in that garbage sets objc.classlist to a pointer that
          is not a class list, which the registration stage then dereferences. */
    if ((size_t)mh->sizeofcmds > flen - sizeof *mh) {
        fprintf(stderr, "[host] %s: %u bytes of load commands do not fit in the %zu-byte slice\n",
                path, mh->sizeofcmds, flen);
        return 1;
    }
    const uint8_t *lc_end = file + sizeof *mh + mh->sizeofcmds;
    const struct lc *c = (const struct lc *)(file + sizeof *mh);
    for (uint32_t k = 0; k < mh->ncmds; k++) {
        if ((const uint8_t *)c + sizeof *c > lc_end) {
            fprintf(stderr, "[host] %s: load command %u starts past the end of the command area\n",
                    path, k);
            return 1;
        }
        if (c->cmdsize < sizeof *c || (c->cmdsize & 3)
            || (const uint8_t *)c + c->cmdsize > lc_end) {
            fprintf(stderr, "[host] %s: load command %u (cmd 0x%x) has a bad size %u\n",
                    path, k, c->cmd, c->cmdsize);
            return 1;
        }
        if (c->cmd == LC_SEGMENT_64_) {
            const struct seg64 *sg = (const struct seg64 *)c;
            if (!sg->vmsize || (!sg->initprot && !sg->maxprot && !sg->filesize)) {
                c = (const struct lc *)((const uint8_t *)c + c->cmdsize);
                continue;                               /* __PAGEZERO: the null guard, never a mapping */
            }
            /* A SEGMENT'S FILE EXTENT IS A FILE OFFSET AND WAS NEVER CHECKED: the memcpy below
                  copies filesize bytes out of the slice into a mapping sized from vmsize, so
                  filesize > vmsize writes past the mapping and fileoff + filesize > flen reads past
                  the file. Neither is representable in a well-formed image. */
            if (sg->cmdsize < sizeof *sg || sg->filesize > sg->vmsize
                || (size_t)sg->fileoff + sg->filesize > flen) {
                fprintf(stderr, "[host] %s %s: file 0x%llx + 0x%llx / vm 0x%llx does not fit the "
                                "%zu-byte slice\n", path, sg->segname,
                        (unsigned long long)sg->fileoff, (unsigned long long)sg->filesize,
                        (unsigned long long)sg->vmsize, flen);
                return 1;
            }
            if (!have_text && !strcmp(sg->segname, "__TEXT")) { im->text_vmaddr = sg->vmaddr; have_text = 1; }
            uint64_t want = sg->vmaddr + slide;
            uint64_t lo = want & ~(uint64_t)(ps - 1);
            uint64_t slack = want - lo;
            size_t len = (size_t)((slack + sg->vmsize + ps - 1) & ~(uint64_t)(ps - 1));
            if (lo < A2X_GUEST_BASE || lo + len > A2X_GUEST_BASE + A2X_GUEST_LEN) {
                fprintf(stderr, "[host] %s %s wants 0x%llx + %zu, outside the reserved range\n",
                        path, sg->segname, (unsigned long long)lo, len);
                return 1;
            }
            /* THE RESERVATION KEEPS THE ALLOCATOR OUT; IT DOES NOT KEEP ONE GUEST OFF ANOTHER.
                  MAP_FIXED replaces whatever is there SILENTLY — the finding that cost the host its
                  own memory before the first instruction — and the slide for each dependency is
                  derived from the LAST image's end alone, not from all of them, while the first
                  dependency's slide is the fixed 0x140000000 whatever the executable's extent was.
                  An overlap would leave the earlier image's fixups applied to bytes that no longer
                  exist, which is a crash with a plausible address far from its cause. */
            for (unsigned j = 0; j < g_nimg; j++)
                if (lo < g_img[j].vmend && lo + len > g_img[j].vmlo) {
                    fprintf(stderr, "[host] %s %s at 0x%llx + %zu would overlap %s "
                                    "(0x%llx..0x%llx) — refusing to map over it\n",
                            path, sg->segname, (unsigned long long)lo, len, g_img[j].path,
                            (unsigned long long)g_img[j].vmlo, (unsigned long long)g_img[j].vmend);
                    return 1;
                }
            /* 11-02 r13m __TEXT SHARES THE SLICE BUFFER'S PAGES instead of a copy: code is never fixed up, so the
                  two copies were byte-identical and both dirty (wifip2pd: 7.5 MB twice). Only a segment of whole pages,
                  at a page-aligned file offset, fully backed by the file; anything else keeps the copy below. */
            int shared_ = 0;
            if (!strcmp(sg->segname, "__TEXT") && !slack && sg->filesize == sg->vmsize
                && !(sg->vmsize & (uint64_t)(ps - 1)) && !(sg->fileoff & (uint64_t)(ps - 1))
                && !(((uintptr_t)file + (uintptr_t)sg->fileoff) & (uintptr_t)(ps - 1)) && !A2X_DBGENV("ARM2X86_NO_TEXTSHARE")) {
                mach_vm_address_t t_ = lo; vm_prot_t cu_ = 0, mx_ = 0;
                kern_return_t kr_ = mach_vm_remap(mach_task_self(), &t_, len, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                                                  mach_task_self(), (mach_vm_address_t)(uintptr_t)(file + sg->fileoff),
                                                  FALSE, &cu_, &mx_, VM_INHERIT_COPY);
                if (kr_ == KERN_SUCCESS && t_ == lo && (cu_ & VM_PROT_READ)) shared_ = 1;
                else fprintf(stderr, "[host] %s __TEXT page share failed (kr %d): copying it\n", path, (int)kr_);
            }
            if (!shared_) {
            void *p = mmap((void *)(uintptr_t)lo, len, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
            if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != lo) {
                fprintf(stderr, "[host] cannot map %s %s at 0x%llx\n", path, sg->segname,
                        (unsigned long long)lo);
                return 1;
            }
            if (sg->filesize) memcpy((void *)(uintptr_t)want, file + sg->fileoff, (size_t)sg->filesize);
            }
            if (lo < im->vmlo) im->vmlo = lo;
            if (want + sg->vmsize > im->vmend) im->vmend = want + sg->vmsize;
            /* the arm text range spans EVERY guest image: the interpreter asks "is this arm64 code?" and a
                  framework's function is just as much arm64 as the executable's. */
            if (!strcmp(sg->segname, "__TEXT")) {
                unsigned long tlo = (unsigned long)want, thi = tlo + (unsigned long)sg->vmsize;
                /* where this image's code section lies, for an image that turns out to have no function-start list */
                if ((uint64_t)sg->cmdsize >= sizeof *sg + (uint64_t)sg->nsects * sizeof(struct section64)) {
                    const struct section64 *sc = (const struct section64 *)(sg + 1);
                    for (uint32_t si = 0; si < sg->nsects; si++, sc++)
                        if (!strncmp(sc->sectname, "__text", 16) && sc->addr >= sg->vmaddr && sc->size <= sg->vmsize) {
                            g_ld_code_lo = (unsigned long)(want + (sc->addr - sg->vmaddr));
                            g_ld_code_hi = g_ld_code_lo + (unsigned long)sc->size;
#if A2X_SLOTS
                            { extern void a2x_slots_note(unsigned long, unsigned long); a2x_slots_note(g_ld_code_lo, g_ld_code_hi); }
#endif
                        }
                }
                if (!__arm_text_base) { __arm_text_base = tlo; __arm_text_size = thi - tlo; }
                else {
                    unsigned long end = __arm_text_base + __arm_text_size;
                    if (tlo < __arm_text_base) __arm_text_base = tlo;
                    if (thi > end) end = thi;
                    __arm_text_size = end - __arm_text_base;
                }
            }
            /* the __objc_* lists are sections of this segment; record where they landed */
            /* THE SECTION HEADERS MUST FIT INSIDE THE SEGMENT'S OWN LOAD COMMAND. nsects is a file
                  field and the walk below ran nsects * 80 bytes from the command's start, so past its
                  end it reads the NEXT load command as section headers — and a chance 16-byte match
                  there sets classlist/selrefs to an address that is not a list at all. */
            if (sg->nsects
                && (uint64_t)sg->cmdsize < sizeof *sg + (uint64_t)sg->nsects * sizeof(struct section64)) {
                fprintf(stderr, "[host] %s %s claims %u section(s) but its load command is only %u "
                                "bytes — NO sections recorded for it\n",
                        path, sg->segname, sg->nsects, sg->cmdsize);
            } else {
                const struct section64 *sc = (const struct section64 *)((const uint8_t *)sg + sizeof *sg);
                for (uint32_t t = 0; t < sg->nsects; t++, sc++) {
                    uint64_t a_ = sc->addr + slide, n_ = sc->size / 8;
                    if (!strcmp(sg->segname, "__TEXT") && (sc->flags & 0x80000400u) && im->ncode < 16 && sc->size) {
                        im->code_a[im->ncode] = a_; im->code_e[im->ncode] = a_ + sc->size; im->ncode++;
                    }
                    if (!memcmp(sc->sectname, "__objc_classlist", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.classlist = a_; im->objc.nclass = n_; } }
                    else if (!memcmp(sc->sectname, "__objc_catlist\0\0", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.catlist = a_; im->objc.ncat = n_; } }
                    else if (!memcmp(sc->sectname, "__objc_catlist2\0", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.catlist2 = a_; im->objc.ncat2 = n_; } }
                    else if (!memcmp(sc->sectname, "__objc_protolist", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.protolist = a_; im->objc.nproto = n_; } }
                    else if (!memcmp(sc->sectname, "__objc_protorefs", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.protorefs = a_; im->objc.nprotoref = n_; } }
                    /* THE LAST FOUR ARGUMENTS ARE classrefs AND superrefs, not protorefs and selrefs.
                          Guessed wrong first: the bridge rebuilds each guest class with the native runtime,
                          so the slots that POINT at classes have to be repointed — and objc said exactly
                          that, "Attempt to use unknown class 0x1000080b0", which is a classref slot. */
                    else if (!memcmp(sc->sectname, "__objc_classrefs", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.classrefs = a_; im->objc.nclassref = n_; } }
                    else if (!memcmp(sc->sectname, "__objc_superrefs", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.superrefs = a_; im->objc.nsuperref = n_; } }
                    else if (!memcmp(sc->sectname, "__objc_selrefs\0\0", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.selrefs = a_; im->objc.nselref = n_; } }
                    /* Swift and TLV sizes are BYTE sizes, not element counts, unlike the lists above */
                    /* 4-BYTE RELATIVE POINTERS, AND THE RUNTIME IS HANDED A BYTE RANGE IT WALKS TO
                          THE END (host_doors.c) — so a size that is not a multiple of 4 makes
                          libswiftCore read a record that is partly whatever follows the section. */
                    else if (!memcmp(sc->sectname, "__swift5_proto\0\0", 16)) { if (sect_ok(path, sc, sg, 4)) { im->objc.sw_proto = a_; im->objc.nsw_proto = sc->size; } }
                    else if (!memcmp(sc->sectname, "__swift5_types\0\0", 16)) { if (sect_ok(path, sc, sg, 4)) { im->objc.sw_types = a_; im->objc.nsw_types = sc->size; } }
                    else if (!memcmp(sc->sectname, "__swift5_protos", 15) && sc->sectname[15] == 0) { if (sect_ok(path, sc, sg, 4)) { im->objc.sw_protos = a_; im->objc.nsw_protos = sc->size; } }
                    else if (!memcmp(sc->sectname, "__thread_vars\0\0\0", 16)) { if (sect_ok(path, sc, sg, 24)) { im->objc.tvars = a_; im->objc.ntvars = sc->size / 24; } }
                    else if (!memcmp(sc->sectname, "__thread_data\0\0\0", 16)) { if (sect_ok(path, sc, sg, 0)) { im->objc.tdata = a_; im->objc.tdata_size = sc->size; } }
                    else if (!memcmp(sc->sectname, "__init_offsets\0\0", 16)) { if (sect_ok(path, sc, sg, 4)) { im->objc.initoff = a_; im->objc.ninitoff = sc->size / 4; } }
                    else if (!memcmp(sc->sectname, "__mod_init_func\0", 16)) { if (sect_ok(path, sc, sg, 8)) { im->objc.modinit = a_; im->objc.nmodinit = n_; } }
                    else if (!memcmp(sc->sectname, "__objc_const\0\0\0\0", 16)) { if (sect_ok(path, sc, sg, 0)) { im->objc.rconst_a = a_; im->objc.rconst_n = sc->size; } }
                    else if (!memcmp(sc->sectname, "__objc_data\0\0\0\0\0", 16)) { if (sect_ok(path, sc, sg, 0)) { im->objc.rdata_a = a_; im->objc.rdata_n = sc->size; } }
                    else if (!memcmp(sc->sectname, "__objc_classname", 16)) { if (sect_ok(path, sc, sg, 0)) { im->objc.cname_a = a_; im->objc.cname_n = sc->size; } }
                    else if (!memcmp(sc->sectname, "__thread_bss\0\0\0\0", 16)) { if (sect_ok(path, sc, sg, 0)) { im->objc.tbss = a_; im->objc.tbss_size = sc->size; } }
                }
            }
            if (trace) fprintf(stderr, "[host] mapped %-14s %-12s 0x%llx + 0x%llx\n",
                               strrchr(path, '/') ? strrchr(path, '/') + 1 : path, sg->segname,
                               (unsigned long long)want, (unsigned long long)sg->vmsize);
        } else if (c->cmd == LC_MAIN_ && entry_out) {
            *entry_out = ((const struct entry_point *)c)->entryoff;
        } else if (c->cmd == LC_FUNCTION_STARTS_) {
            /* ULEB128 deltas from the image's __TEXT base — the loader format's own function list */
            const struct linkedit *le = (const struct linkedit *)c;
            /* A LINKEDIT EXTENT IS A FILE OFFSET AND NOTHING ELSE CHECKS IT. Unbounded, the ULEB
                  walk below reads past the mapped file and invents function starts out of whatever is
                  there — and a wrong entry in that list is the one thing that must never be wrong:
                  the fault handler recovers a native->guest call ONLY at an exact function start. */
            if ((size_t)le->dataoff + le->datasize > flen) {
                fprintf(stderr, "[host] %s: LC_FUNCTION_STARTS at 0x%x + %u is past the end of the "
                                "%zu-byte slice — NO function starts recorded for this image, so no "
                                "native->guest call into it can be recovered\n",
                        path, le->dataoff, le->datasize, flen);
                c = (const struct lc *)((const uint8_t *)c + c->cmdsize);
                continue;
            }
            const uint8_t *p = file + le->dataoff, *end = p + le->datasize;
            uint64_t addr = im->text_vmaddr + slide;
            if (le->datasize) g_ld_fs_seen = 1;
            while (p < end) {
                uint64_t delta = 0;
                unsigned sh = 0;
                while (p < end) {
                    uint8_t byte = *p++;
                    delta |= (uint64_t)(byte & 0x7f) << sh;
                    sh += 7;
                    if (!(byte & 0x80)) break;
                }
                if (!delta) break;                      /* a zero delta ends the list */
                addr += delta;
                if (g_fs_late) { if (g_nfnew < FSTARTS_MAX) g_fnew[g_nfnew++] = (unsigned long)addr; }
                else if (g_nfstart < FSTARTS_MAX) g_fstart[g_nfstart++] = (unsigned long)addr;
                else g_fstart_dropped++;      /* reported in main; never silent again */
            }
        } else if (c->cmd == LC_SYMTAB_) {
            const struct symtab_cmd *sy = (const struct symtab_cmd *)c;
            /* THE SYMBOL AND STRING TABLES ARE FILE OFFSETS, TRUSTED UNTIL NOW. guest_lookup()
                  walks nsyms entries and indexes the string table by n_strx, so a table that runs
                  past the slice reads unmapped file bytes and compares them as a symbol name — and a
                  chance match would resolve another guest's import to a meaningless address. */
            if ((uint64_t)sy->symoff + (uint64_t)sy->nsyms * sizeof(struct nlist64) > flen
                || (uint64_t)sy->stroff + sy->strsize > flen) {
                fprintf(stderr, "[host] %s: LC_SYMTAB is outside the %zu-byte slice (symoff 0x%x "
                                "nsyms %u stroff 0x%x strsize %u) — this image exports nothing to the "
                                "other guests\n",
                        path, flen, sy->symoff, sy->nsyms, sy->stroff, sy->strsize);
            } else {
                im->syms = (const struct nlist64 *)(file + sy->symoff);
                im->nsyms = sy->nsyms;
                im->strs = (const char *)(file + sy->stroff);
                im->strsize = sy->strsize;
            }
        } else if (c->cmd == 0x80000033 || c->cmd == 0x22 || c->cmd == 0x80000022) {
            /* LC_DYLD_EXPORTS_TRIE: {cmd, cmdsize, dataoff, datasize}; LC_DYLD_INFO[_ONLY]: export_off/size at +40/+44 */
            uint32_t eo = 0, es = 0;
            if (c->cmd == 0x80000033 && c->cmdsize >= 16) {
                eo = ((const uint32_t *)c)[2]; es = ((const uint32_t *)c)[3];
            } else if (c->cmd != 0x80000033 && c->cmdsize >= 48) {
                eo = ((const uint32_t *)c)[10]; es = ((const uint32_t *)c)[11];
            }
            if (es && (uint64_t)eo + es <= flen) { im->trie = file + eo; im->trie_size = es; }
        } else if (c->cmd == LC_BUILD_VERSION_) {
            if (c->cmdsize >= sizeof(struct build_version))
                im->platform = ((const struct build_version *)c)->platform;
        }
        c = (const struct lc *)((const uint8_t *)c + c->cmdsize);
    }
    if (!have_text) { fprintf(stderr, "[host] %s has no __TEXT\n", path); return 1; }
    if (!g_ld_fs_seen && g_ld_code_hi > g_ld_code_lo) {
        unsigned nn = g_nnofs;
        if (nn < NOFS_MAX) {
            g_nofs[nn].lo = g_ld_code_lo; g_nofs[nn].hi = g_ld_code_hi;
            __atomic_store_n(&g_nnofs, nn + 1, __ATOMIC_RELEASE);
            fprintf(stderr, "[host] %s has no function-start list: every 4-aligned address in its code section "
                            "(0x%lx..0x%lx) counts as a function\n", path, g_ld_code_lo, g_ld_code_hi);
        } else fprintf(stderr, "[host] %s has no function-start list and the table for such images is full: "
                               "its functions will not be recognised when handed to a system call\n", path);
    }
    g_ld_code_lo = g_ld_code_hi = 0; g_ld_fs_seen = 0;
    g_nimg++;
    return 0;
}

/* resolve an install name the way dyld does, but only for the forms a bundle uses */
/* 10-27 @rpath AND @executable_path WERE RESOLVED AGAINST THE IMAGE THAT NAMED THEM, NOT THE PROGRAM. A
      framework nested in the app (Podcasts' PodcastsSiriDonation, Books' BooksUI) asks for
      @rpath/PodcastsAppEntities.framework/..., which the program's rpath (@executable_path/../Frameworks)
      finds beside it — but the old rule built <that framework's own dir>/../Frameworks/..., which does not
      exist, so the dependency was dropped and every import from it stayed 0: Podcasts 4981 missing and a
      Swift "Failed to look up symbolic reference ... missing weak symbol" abort; Books 5433 missing.
    dyld tries every rpath in order, so this does too: the main executable's Frameworks first (it is also the
      spelling the first-level loads already use, which keeps the `already` check by path honest), then the
      loader's own @loader_path/Frameworks and ../Frameworks. The first candidate that exists wins; if none
      does the first is returned so the caller's "does not exist" line still names a path. */
/* The run paths (LC_RPATH) an image file declares, read from the file itself: its arm64 slice when the file holds
   several. Fills out[] in the order declared and returns how many; 0 when the file cannot be read or declares
   none. Bounded: at most 4 MB of load commands, at most `max` paths, each cut to 1023 bytes. */
static int a2x_file_rpaths(const char *path, char out[][1024], int max) {
    int fd = open(path, O_RDONLY), n = 0;
    if (fd < 0) return 0;
    unsigned char h[4096];
    off_t base = 0;
    if (pread(fd, h, sizeof h, 0) < 32) { close(fd); return 0; }
    uint32_t magic = (uint32_t)h[0] << 24 | (uint32_t)h[1] << 16 | (uint32_t)h[2] << 8 | h[3];
    if (magic == 0xcafebabe || magic == 0xcafebabf) {          /* several slices: big-endian table */
        uint32_t na = (uint32_t)h[4] << 24 | (uint32_t)h[5] << 16 | (uint32_t)h[6] << 8 | h[7];
        size_t step = magic == 0xcafebabe ? 20 : 32;
        int found = 0;
        for (uint32_t i = 0; i < na && 8 + (i + 1) * step <= sizeof h; i++) {
            const unsigned char *e = h + 8 + i * step;
            uint32_t cpu = (uint32_t)e[0] << 24 | (uint32_t)e[1] << 16 | (uint32_t)e[2] << 8 | e[3];
            if (cpu != 0x0100000c) continue;
            if (step == 20) base = (off_t)((uint32_t)e[8] << 24 | (uint32_t)e[9] << 16 | (uint32_t)e[10] << 8 | e[11]);
            else { uint64_t o = 0; for (int k = 0; k < 8; k++) o = o << 8 | e[8 + k]; base = (off_t)o; }
            found = 1; break;
        }
        if (!found || pread(fd, h, 32, base) < 32) { close(fd); return 0; }
    }
    uint32_t m; memcpy(&m, h, 4);
    if (m != 0xfeedfacf) { close(fd); return 0; }
    uint32_t ncmds, sizeofcmds; memcpy(&ncmds, h + 16, 4); memcpy(&sizeofcmds, h + 20, 4);
    if (!sizeofcmds || sizeofcmds > (4u << 20)) { close(fd); return 0; }
    unsigned char *lc = malloc(sizeofcmds);
    if (!lc) { close(fd); return 0; }
    if (pread(fd, lc, sizeofcmds, base + 32) == (ssize_t)sizeofcmds) {
        uint32_t off = 0;
        for (uint32_t i = 0; i < ncmds && off + 8 <= sizeofcmds && n < max; i++) {
            uint32_t cmd, size; memcpy(&cmd, lc + off, 4); memcpy(&size, lc + off + 4, 4);
            if (size < 8 || off + size > sizeofcmds) break;
            if (cmd == 0x8000001c && size >= 12) {             /* LC_RPATH: the path's offset, then the path */
                uint32_t po; memcpy(&po, lc + off + 8, 4);
                if (po < size) {
                    size_t len = strnlen((const char *)lc + off + po, size - po);
                    if (len > 1023) len = 1023;
                    memcpy(out[n], lc + off + po, len); out[n][len] = 0; n++;
                }
            }
            off += size;
        }
    }
    free(lc); close(fd);
    return n;
}

/* One declared run path, made into a folder: @loader_path is the folder of the image that declares it,
   @executable_path the main program's folder, anything else is taken as written. */
static void a2x_expand_rpath(const char *rp, const char *decl_dir, const char *main_dir, char *out, size_t outsz) {
    if (!strncmp(rp, "@loader_path", 12)) snprintf(out, outsz, "%s%s", decl_dir, rp + 12);
    else if (!strncmp(rp, "@executable_path", 16)) snprintf(out, outsz, "%s%s", main_dir, rp + 16);
    else snprintf(out, outsz, "%s", rp);
}

static int bundle_relative(const char *dep, const char *exe_path, const char *main_path, char *out, size_t outsz) {
    const char *rest = 0;
    if (!strncmp(dep, "@executable_path/", 17)) rest = dep + 17;
    else if (!strncmp(dep, "@loader_path/", 13)) rest = dep + 13;
    else if (!strncmp(dep, "@rpath/", 7)) rest = dep + 7;
    else return 0;
    /* @rpath in an app bundle is @executable_path/../Frameworks, so both forms land in the same place */
    char dir[1024];
    snprintf(dir, sizeof dir, "%s", exe_path);
    char *sl = strrchr(dir, '/');
    if (!sl) return 0;
    *sl = 0;
    char mdir[1024];
    snprintf(mdir, sizeof mdir, "%s", main_path ? main_path : exe_path);
    char *msl = strrchr(mdir, '/');
    if (msl) *msl = 0;
    if (!strncmp(dep, "@rpath/", 7)) {
        /* what the images declare comes first: the asking image's run paths, then the main program's */
        {
            static char rps[16][1024];
            const char *files[2] = { exe_path, main_path && strcmp(main_path, exe_path) ? main_path : 0 };
            const char *dirs[2] = { dir, mdir };
            struct stat rst;
            for (int f = 0; f < 2; f++) {
                if (!files[f]) continue;
                int nrp = a2x_file_rpaths(files[f], rps, 16);
                for (int k = 0; k < nrp; k++) {
                    char folder[2048], full[3200];
                    a2x_expand_rpath(rps[k], dirs[f], mdir, folder, sizeof folder);
                    snprintf(full, sizeof full, "%s/%s", folder, rest);
                    if (!stat(full, &rst)) { snprintf(out, outsz, "%s", full); return 1; }
                }
            }
        }
        char cand[3][1100];
        snprintf(cand[0], sizeof cand[0], "%s/../Frameworks/%s", mdir, rest);
        snprintf(cand[1], sizeof cand[1], "%s/Frameworks/%s", dir, rest);
        snprintf(cand[2], sizeof cand[2], "%s/../Frameworks/%s", dir, rest);
        struct stat st;
        int pick = 0;
        for (int k = 0; k < 3; k++) if (!stat(cand[k], &st)) { pick = k; break; }
        snprintf(out, outsz, "%s", cand[pick]);
    }
    else if (!strncmp(dep, "@executable_path/", 17)) snprintf(out, outsz, "%s/%s", mdir, rest);
    else snprintf(out, outsz, "%s/%s", dir, rest);
    return 1;
}


/* THE PRE-REGISTRATION AUDIT — WHAT WE ARE ABOUT TO HAND libobjc, CHECKED BEFORE WE HAND IT OVER.
    __arm2x86_objc_register() and __arm2x86_objc_protocols() take a bare (address, count) pair and
      dereference every entry. ONE slot whose fixup did not land is an unnamed SIGSEGV in native code with no
      guest pc to report — which is exactly the five-app shape this file is instrumented for. libobjc reads
      class->bits at +0x20, so a NULL class record or a NULL metaclass pointer faults at EXACTLY 0x20.
    This changes NOTHING about what is registered: it names every record that cannot be valid and counts the
      rest, so one run says which image and which index. ARM2X86_HOST_AUDIT=strict makes the host refuse
      instead, for the case where a named refusal beats a crash; the default is unchanged for every app that
      already works.
    A NON-GUEST isa OR superclass IS NOT A DEFECT — a guest class may legitimately inherit from a native
      one, and dlsym resolves _OBJC_METACLASS_$_NSObject into libobjc. Only a NULL one is reported. */
#define AUDIT_SHOW 16
static unsigned long audit_image(const struct image *im, int trace) {
    const struct objc_secs *o = &im->objc;
    const char *base = strrchr(im->path, '/') ? strrchr(im->path, '/') + 1 : im->path;
    unsigned long bad = 0, shown = 0, nullsup = 0;

    for (uint64_t k = 0; k < o->nclass; k++) {
        const char *why = 0;
        uint64_t c = 0;
        if (!guest_mapped(o->classlist + 8 * k, 8)) why = "the __objc_classlist slot itself is not inside any mapped guest image";
        else {
            c = ((const uint64_t *)(uintptr_t)o->classlist)[k];
            if (!c) why = "the list entry is NULL — libobjc reads class->bits at +0x20, so this record faults at EXACTLY 0x20";
            else if (c & 7) why = "the list entry is not 8-byte aligned, so it is not a class record";
            else if (!guest_mapped(c, 0x40)) why = "the class record is not inside any mapped guest image";
            else if (!((const uint64_t *)(uintptr_t)c)[0])
                why = "its metaclass pointer (isa, +0) is NULL — RO(isa) and libobjc both read +0x20 off it, "
                      "which is EXACTLY the measured faulting address";
        }
        /* A NULL SUPERCLASS SLOT HERE IS AN UNRESOLVED IMPORT, NOT A ROOT CLASS, AND IT IS THE 0x20
              PRECONDITION. MEASURED in the file for all five of the apps that fault this way: the +8 slot of
              a class record carries a BIND, not a rebase, for most of their classes — FindMy 235 of 353,
              Maps 1834 of 2709, Shortcuts 60 of 60, Notes 248 of 383, Reminders 280 of 338 — and the symbol
              is _OBJC_CLASS_$_NSObject, _OBJC_CLASS_$_UIView or _OBJC_CLASS_$__TtCs12_SwiftObject in the
              overwhelming majority. So a 0 in this slot means dlsym did not resolve that symbol. For a Swift
              class the bridge keeps the guest record and lets libobjc realize it later, and realization reads
              supercls->data() — `bits` at +0x20 — on a Nil superclass. Genuine root classes are a handful
              (NSObject, NSProxy) and a translated program normally defines none, so this count is a finding
              every time it is not zero.
            Counted, not added to `bad`: the bridge already prints one line per class, and Maps would print
              a wall. One line with a number is the diagnosis. */
        if (!why && !((const uint64_t *)(uintptr_t)c)[1]) nullsup++;
        if (!why) continue;
        bad++;
        if (shown++ < AUDIT_SHOW)
            fprintf(stderr, "[host] AUDIT %s __objc_classlist[%llu] = 0x%llx: %s\n",
                    base, (unsigned long long)k, (unsigned long long)c, why);
    }
    if (nullsup)
        fprintf(stderr, "[host] AUDIT %s: %lu of %llu class record(s) have a NULL superclass slot (+8). In "
                        "this image's file that slot carries a BIND for most classes, so a NULL is an import "
                        "dlsym did not resolve — libobjc's realization then reads supercls->data() at +0x20, "
                        "which is the measured faulting address. The missing-import list above names them.\n",
                base, nullsup, (unsigned long long)o->nclass);
    /* a category's target class is read at cat+8 before anything checks it (objc_bridge: mapcls(*(ct+8))) */
    for (uint64_t k = 0; k < o->ncat; k++) {
        const char *why = 0;
        uint64_t ct = 0;
        if (!guest_mapped(o->catlist + 8 * k, 8)) why = "the __objc_catlist slot itself is not inside any mapped guest image";
        else {
            ct = ((const uint64_t *)(uintptr_t)o->catlist)[k];
            if (!ct) why = "the list entry is NULL — the registration reads cat->cls at +8 off it";
            else if (!guest_mapped(ct, 0x28)) why = "the category record is not inside any mapped guest image";
        }
        if (!why) continue;
        bad++;
        if (shown++ < AUDIT_SHOW)
            fprintf(stderr, "[host] AUDIT %s __objc_catlist[%llu] = 0x%llx: %s\n",
                    base, (unsigned long long)k, (unsigned long long)ct, why);
    }
    /* a2x_map_protocol() guards a NULL entry itself, so only an UNMAPPED one is reported here */
    for (uint64_t k = 0; k < o->nproto; k++) {
        const char *why = 0;
        uint64_t p = 0;
        if (!guest_mapped(o->protolist + 8 * k, 8)) why = "the __objc_protolist slot itself is not inside any mapped guest image";
        else {
            p = ((const uint64_t *)(uintptr_t)o->protolist)[k];
            if (p && !guest_mapped(p, 0x38))
                why = "the protocol record is not inside any mapped guest image — its name is read at +8";
        }
        if (!why) continue;
        bad++;
        if (shown++ < AUDIT_SHOW)
            fprintf(stderr, "[host] AUDIT %s __objc_protolist[%llu] = 0x%llx: %s\n",
                    base, (unsigned long long)k, (unsigned long long)p, why);
    }
    if (bad)
        fprintf(stderr, "[host] AUDIT %s: %lu record(s) cannot be dereferenced safely%s\n",
                base, bad, shown > AUDIT_SHOW ? " (the first 16 are named above)" : "");
    else if (trace)
        fprintf(stderr, "[host] AUDIT %s: %llu class, %llu category, %llu protocol record(s) — all mapped, "
                        "aligned and non-NULL\n", base, (unsigned long long)o->nclass,
                (unsigned long long)o->ncat, (unsigned long long)o->nproto);
    return bad;
}

/* A FAULT IN INTERPRETED CODE MUST NAME THE GUEST INSTRUCTION. Without this the process dies with a bus
      error and an x86 pc inside the interpreter, which tells you nothing about which guest address did it —
      and the first callback test lost an hour to exactly that. */
extern __thread unsigned long a64_cur_pc;
extern __thread unsigned int a64_cur_insn;
extern __thread const a64 *a64_cur_state;
/* 10-31 WHERE THE GUEST IS, FOR A REPORT. The decode-cache path of the run loop does not store pc and insn to TLS
      on every instruction: it publishes its register file (a64_cur_state) and writes a64_cur_pc/a64_cur_insn only when
      control leaves for native code (the call site) or a syscall. So: if the published state's pc is guest text, the
      fault is INSIDE that instruction (an exec changes pc only for a branch, and a branch touches no memory) and the
      word is read back through the code view; otherwise the thread is in native code and the call site is the answer,
      which is what the per-step store used to leave there. The uncached path still stores per step: same answer. */
static unsigned long a2x_report_pc(unsigned *insn) {
    const a64 *st = a64_cur_state;
    if (st && __arm_text_base && st->pc >= __arm_text_base && st->pc < __arm_text_base + __arm_text_size) {
        unsigned w = 0; memcpy(&w, a2x_code_view(st->pc), 4);
        if (insn) *insn = w;
        return st->pc;
    }
    /* the cached path leaves a64_cur_insn 0 at a native call (one TLS store saved per call): read the word back */
    if (insn) {
        unsigned w = a64_cur_insn;
        if (!w && a64_cur_pc && __arm_text_base && a64_cur_pc >= __arm_text_base && a64_cur_pc < __arm_text_base + __arm_text_size)
            memcpy(&w, a2x_code_view(a64_cur_pc), 4);
        *insn = w;
    }
    return a64_cur_pc;
}
/* THE UNIVERSAL TRAMPOLINE — NATIVE CODE CALLING GUEST CODE, WITHOUT KNOWING WHERE THE POINTER CAME FROM.
      MEASURED 10-26 over all 65 macOS 27 system apps: 25 of the 29 crashes were the SAME INSTRUCTION,
      `braa x16, x17` (0xd71f0a11) — the guest tail-jumps through an arm64e auth stub into a framework, and
      the framework then CALLS a guest function pointer it read out of guest data: a Swift metadata
      completion function, a dispatch_once block, a job continuation, SwiftUI's glue. Those pointers never
      pass through a register on our side, so __arm2x86_cbarg cannot wrap them, and patching each data
      structure in turn is exactly the app-by-app road this host exists to replace.
    Guest pages carry no PROT_EXEC, so every such call ALREADY faults on the instruction fetch, with
      si_addr == rip == the guest function. That fault IS the trampoline: map the native argument registers
      onto arm64's, interpret the function, leave the result where the native caller will read it, and resume
      at the return address the caller pushed. One mechanism, every data structure, no layout knowledge.
    ONLY AT AN EXACT FUNCTION START (LC_FUNCTION_STARTS) AND ONLY WHEN rip == si_addr. A fault in the
      middle of a guest function, or a data fault that merely lands on a function's first byte, is a REAL
      bug: recovering there would resume a half-executed frame and turn a crash into silent corruption.
    SIX INTEGER ARGUMENTS, exactly like the callback door: the 7th onward sit on the NATIVE stack while
      arm64 expects them in x6/x7, and a fault carries no signature to say how many there are. Said out loud
      because a 7-argument callback would silently see zero rather than fail. */
extern void __arm2x86_ensure_stack(void);
extern __thread unsigned long __arm_sp;
extern int __arm2x86_interp_run(unsigned long target, unsigned long *xs, unsigned char *vs);
extern int a2x_tramp_sret_probe(unsigned long rsi, unsigned long rdx, unsigned long imp, unsigned long *info);
extern void a2x_tramp_sret_store(const unsigned long *info, void *buf, const unsigned char *vs);
static int g_trace_tramp = -1;
static unsigned long g_tramp_n;

/* 10-29 "THE CALLER'S RETURN SITE STARTS WITH `sub $8,%rsp`" DOES NOT MAKE THE CALLEE ASYNC.
      recover_guest_call popped one EXTRA word whenever the instruction after the native call site was
      48 83 ec 08, on the theory that the runtime emits it to rebalance a swiftasync callee's `retq $8`. Ordinary
      native code emits the same bytes for plain alignment of the next call's stack arguments. Measured on Font Book:
      guest 0x100094908 (`pacibsp; sub sp,sp,#0x50` — a plain function) returned into SwiftUI at 48 83 ec 08 44 8b 55 18,
      rsp came back 8 high, and the next call chain ran misaligned until `movaps 0x10(%rbp)` in
      LockingConcurrentMap::getOrInsert took a #GP (trapno 13, rbp ending in 8) — the "ret then fault at 0" report.
    The call site is only half the evidence. The callee must itself be async: its first instructions touch the async
      context through x22 (the continuation load of a swift_task_switch thunk, or any ldr/str/ldp/stp based on x22)
      before anything has written x22. A function that overwrites x22 first is using it as an ordinary callee-saved
      register. Scans at most 16 instructions and stops at the first branch or return. */
#include "outlined_async.h"
static int a2x_async_guest_word(unsigned long pc, unsigned int *word) {
    if (pc & 3) return 0;
    for (unsigned i = 0; i < g_nimg; i++)
        for (unsigned k = 0; k < g_img[i].ncode; k++)
            if (pc >= g_img[i].code_a[k] && pc < g_img[i].code_e[k]
                && g_img[i].code_e[k] - pc >= 4) {
                *word = *(const unsigned int *)a2x_code_view(pc);
                return 1;
            }
    return 0;
}
static int a2x_callee_uses_async_ctx(unsigned long tgt) {
    if (a2x_outlined_async(tgt, a2x_async_guest_word, 0)) return 1;
    int w22 = 0;                                        /* x22 written earlier in the window: a later read is not the context */
    for (int i = 0; i < 16; i++) {
        unsigned int ins;
        if (tgt > ~0UL - 4UL * i || !a2x_async_guest_word(tgt + 4UL * i, &ins)) return 0;
        unsigned int rn = (ins >> 5) & 0x1f, rd = ins & 0x1f;
        if (rn == 22 && ((ins & 0x3b000000u) == 0x39000000u || (ins & 0x3a000000u) == 0x28000000u)) return 1;
        /* 10-30 `mov x1, x22` IS A READ OF THE ASYNC CONTEXT TOO. It is orr xd, xzr, x22 (Rm, not Rn), so the
              load/store test above never sees it. App Store 0x1003b17e4 — `mov x1,x22; ldr x2,[x1,#8]!; ...; braa x2,x16`,
              an await-resume thunk — was judged "not async", took no extra pop, and swift_job_runImpl returned to a
              stack address (SIGBUS, rip = rsp+0x68). x19-x28 are callee-saved, so a read before any write is the
              incoming swiftasync argument by definition. */
        if ((ins & 0xffe0ffe0u) == 0xaa0003e0u && ((ins >> 16) & 0x1f) == 22 && !w22) return 1;
        if (rd == 22 || ((ins & 0x3a000000u) == 0x28000000u && ((ins >> 10) & 0x1f) == 22)) w22 = 1;
        if (rd == 22) { unsigned int g = (ins >> 24) & 0x1f; if (g == 0x0a || g == 0x0b || g == 0x11 || g == 0x12) return 0; }
        if ((ins & 0xfc000000u) == 0x14000000u || (ins & 0xfc000000u) == 0x94000000u
            || (ins & 0xfffffc1fu) == 0xd65f0000u || (ins & 0xfffffc1fu) == 0xd61f0000u) return 0;
    }
    return 0;
}
/* The callback door's half of the rule in recover_guest_call. The caller has already seen the rebalancing sub at the
   return site. A C call site can also be followed by that sub, so the callee or the site must confirm it: an async
   prologue, a callee that reads its context, or a return site inside the Swift concurrency runtime, whose indirect
   calls to a job's resume function are always swiftasync. */
int a2x_cb_async_return(unsigned long tgt, unsigned long ret) {
    unsigned int ip[2] = {0, 0};
    a2x_async_guest_word(tgt, &ip[0]);
    if (tgt <= ~0UL - 4) a2x_async_guest_word(tgt + 4, &ip[1]);
    int why = 0;
    if (ip[0] == 0xb24403bdu || (ip[0] == 0xd503237fu && ip[1] == 0xb24403bdu)) why = 1;
    else if (a2x_callee_uses_async_ctx(tgt)) why = 2;
    else {
        Dl_info d;
        if (dladdr((void *)(uintptr_t)ret, &d) && d.dli_fname && strstr(d.dli_fname, "libswift_Concurrency")) why = 3;
    }
    /* a mechanism that cannot be seen working cannot be told from one that never fired: first three per process */
    static int shown;
    if (why && shown < 3) { shown++; fprintf(a2x_errf(), "[cb] async return: guest 0x%lx back to 0x%lx (reason %d)\n", tgt, ret, why); }
    return why != 0;
}
/* The Swift Concurrency runtime resumes a task with `callq *0x38(%r15)` (Job::ResumeTask) and rebalances with
   `subq $8,%rsp` at the return site. ResumeTask is the runtime`s own non_future_adapter / future_adapter /
   task_*_resume_adapter, which loads the closure`s entry from the AsyncContext prefix and TAIL-JUMPS to it
   (jmpq *%rax with [rsp] = that return site). The target is a guest async function whose first instructions
   need not read x22 (a closure body that spills other registers first), so the callee test below can say "not
   async" and rsp ends 8 low. The caller is the proof: a call through a 0x38 displacement, in libswift_Concurrency. */
static int a2x_ret_is_task_resume(unsigned long ret) {
    const unsigned char *rp = (const unsigned char *)(uintptr_t)ret;
    if (!(rp[-1] == 0x38 && rp[-3] == 0xff && (rp[-2] & 0xf8) == 0x50)) return 0;
    Dl_info di;
    return dladdr((const void *)(uintptr_t)ret, &di) && di.dli_fname && strstr(di.dli_fname, "libswift_Concurrency");
}
static int recover_guest_call(void *uc_, unsigned long tgt) {
    ucontext_t *u = (ucontext_t *)uc_;
    if (!u || !u->uc_mcontext) return 0;
    _STRUCT_X86_THREAD_STATE64 *ss = &u->uc_mcontext->__ss;
    if ((unsigned long)ss->__rip != tgt) return 0;      /* a data fault, not an attempt to execute */

    /* the caller's `call` pushed a return address; a tail `jmp` left its own caller's there. Both resume by
       popping exactly one word, so one path serves either. */
    unsigned long ret = 0;
    memcpy(&ret, (const void *)(uintptr_t)ss->__rsp, 8);
    if (!ret) return 0;

    unsigned long xs[32];
    memset(xs, 0, sizeof xs);
    _Alignas(16) unsigned char vs[32 * 16];
    memset(vs, 0, sizeof vs);
    xs[0] = ss->__rdi; xs[1] = ss->__rsi; xs[2] = ss->__rdx;
    xs[3] = ss->__rcx; xs[4] = ss->__r8;  xs[5] = ss->__r9;
    xs[8] = ss->__rax;                                  /* a Swift indirect result arrives in arm64 x8 */
    /* The 7th and 8th integer arguments: arm64 takes them in x6/x7, x86-64 (C and swiftcc) puts them on the
       stack just above the return address. A Swift protocol-extension thunk receives its witness table that
       way (`mov x19, x7` at entry); with x7 left at zero the native callee copied from a NULL witness. A
       callee with fewer arguments never reads x6/x7, and the two words above a return address are always mapped. */
    {
        const unsigned long *sa = (const unsigned long *)(uintptr_t)(ss->__rsp + 8);
        xs[6] = sa[0]; xs[7] = sa[1];
    }
    /* 10-27 THE SWIFT SELF/ERROR/ASYNC REGISTERS, CARRIED IN ONLY — AND THAT IS WHAT MAKES IT SAFE.
          swiftcc keeps self, error and the async context in x20/x21/x22 on arm64 and in r13/r12/r14 on
          x86-64, so a native Swift caller entering a guest Swift function left all three at ZERO. Measured
          here 10-27 on Maps: a worker thread entered a guest function whose FIRST instruction is
          `ldp x21, x23, [x20, #16]` (insn 0xa9415e95) and took SIGSEGV at faulting address 0x10 — x20 was 0.
          Same shape as the Tips swift_getWitnessTable gap recorded below.
        THE 10-26 ATTEMPT WENT THE OTHER WAY TOO AND THAT IS WHY IT LOST GROUND (65-app sweep 37 good/24
          crashing -> 33 good/26 crashing): it also wrote the guest's x20/x21/x22 BACK into r13/r12/r14 on the
          way out. Those three are callee-saved under SysV, so for every callback that is NOT swiftcc — nearly
          all of them — the native caller's own saved registers came back corrupted. The write-back is the
          part that was wrong, not the read.
        WHY READING THEM IS SOUND RATHER THAN A GUESS, and why no signature is needed: x19-x28 are
          CALLEE-SAVED on arm64. A correct arm64 function therefore never reads x20/x21/x22 before it has
          written them — the sole exception being a swiftcc entry, for which those registers ARE incoming
          arguments. So seeding them can only change the behaviour of a function that is swiftcc by
          definition; a C callee spills them, restores them, and never looks at what arrived. Nothing is
          written back, so the native caller's r12/r13/r14 are left exactly as they were.
        VERIFY BY ABSENCE when judging this: the thing that must NOT appear is a NEW crash in an app that
          ran before. The gate is the whole app sweep, not the one app this was measured on. */
    /* 10-28 A MEMORY-RETURN METHOD IMP: rdi is the result buffer, so everything shifts down one register
          (see a2x_tramp_sret_probe). Proven against the runtime's own method table, never guessed. */
    unsigned long sinfo[3] = {0, 0, 0};
    int is_sret = a2x_tramp_sret_probe(ss->__rsi, ss->__rdx, tgt, sinfo);
    /* A small C++ value the method writes through x8 while this caller reads rax:rdx: give it a buffer of our own
       and hand the two words back in the registers afterwards. */
    static const unsigned char cxx_mark[16] = { 0xA5, 0xC3, 0x5E, 0x11, 0xD0, 0x6B, 0x47, 0x92, 0xA5, 0xC3, 0x5E, 0x11, 0xD0, 0x6B, 0x47, 0x92 };
    unsigned long cxx_buf[2]; int cxx_small = is_sret && sinfo[0] == 3;
    if (cxx_small) { is_sret = 0; memcpy(cxx_buf, cxx_mark, 16); xs[8] = (unsigned long)(uintptr_t)cxx_buf; }
    if (is_sret) {
        const unsigned long *sa2 = (const unsigned long *)(uintptr_t)(ss->__rsp + 8);
        xs[0] = ss->__rsi; xs[1] = ss->__rdx; xs[2] = ss->__rcx; xs[3] = ss->__r8; xs[4] = ss->__r9;
        xs[5] = sa2[0]; xs[6] = sa2[1]; xs[7] = sa2[2];
        xs[8] = ss->__rdi;                              /* AAPCS64: x8 = result buffer (an HFA ignores it) */
    }
    xs[20] = ss->__r13;                                 /* swiftself  : x20 <- r13 */
    xs[21] = ss->__r12;                                 /* swifterror : x21 <- r12 */
    xs[22] = ss->__r14;                                 /* swiftasync : x22 <- r14 */
    _STRUCT_X86_FLOAT_STATE64 *fs = &u->uc_mcontext->__fs;
    memcpy(vs +  0, &fs->__fpu_xmm0, 16); memcpy(vs +  16, &fs->__fpu_xmm1, 16);
    memcpy(vs + 32, &fs->__fpu_xmm2, 16); memcpy(vs +  48, &fs->__fpu_xmm3, 16);
    memcpy(vs + 64, &fs->__fpu_xmm4, 16); memcpy(vs +  80, &fs->__fpu_xmm5, 16);
    memcpy(vs + 96, &fs->__fpu_xmm6, 16); memcpy(vs + 112, &fs->__fpu_xmm7, 16);
    {   /* 11-05 r14i: a by-value struct wider than 16 bytes: see a2x_tramp_byval */
        extern int a2x_tramp_byval(unsigned long, int, const unsigned long *, const unsigned long *, const unsigned char *, unsigned long *, unsigned char *);
        const unsigned long gp_[6] = { ss->__rdi, ss->__rsi, ss->__rdx, ss->__rcx, ss->__r8, ss->__r9 };
        unsigned char xm_[128]; memcpy(xm_, vs, sizeof xm_);
        a2x_tramp_byval(tgt, is_sret, gp_, (const unsigned long *)(uintptr_t)(ss->__rsp + 8), xm_, xs, vs);
    }
    __arm2x86_ensure_stack();
    /* 10-30 THE 9TH INTEGER ARGUMENT AND BEYOND. x86 passes args 7.. on the stack (words 0,1 became x6/x7 above); arm64
          passes args 9.. at [sp], [sp+8], ... on entry. Leaving the arm stack untouched handed a guest method with ten
          integer arguments zeros for the last two. App Store: a guest override of a 10-argument AppStoreKit method read
          its two stack arguments (ldp x8,x9,[x29,#0x10]), passed them on to the native super implementation, and that
          dereferenced 0+8 (swift door -> mov 8(%rax),%rax, rax 0). The count is unknown without a signature, so a fixed
          window of 8 words is copied: the words above a call site are the caller own own frame and always mapped, a callee
          with fewer arguments never reads them, and nothing is written back. */
    unsigned long asp = (__arm_sp - 64) & ~15UL;
    {
        const unsigned long *sa = (const unsigned long *)(uintptr_t)(ss->__rsp + 8);
        for (int k = 0; k < 8; k++) ((unsigned long *)(uintptr_t)asp)[k] = sa[2 + k];
    }
    xs[31] = asp;

    unsigned long a2x_sp0 = __arm_sp;   /* restored below: see cb_host.c, 11-01 */
    int a2x_rr = __arm2x86_interp_run(tgt, xs, vs);
    __arm_sp = a2x_sp0;
    if (a2x_rr) return 0;    /* could not run it: report the fault as before */
    /* r15a: what the guest popped of its incoming stack arguments (swifttailcc is callee-pop on both sides) */
    unsigned long a2x_gpop = xs[31] - asp;
    if (a2x_gpop > 64 || (a2x_gpop & 7)) {
        fprintf(a2x_errf(), "[tramp] 0x%lx: guest sp moved by %ld on return, ignored\n", tgt, (long)a2x_gpop);
        a2x_gpop = 0;
    }

    /* the whole return, not its first word: Swift returns a two-word pair in rax:rdx (key-path argument
       layout functions return (size, alignmentMask)), and an AAPCS64 composite comes back in x0-x3 / v0-v3.
       rdx, rcx, r8 and xmm1-3 are caller-saved, so writing them cannot disturb a caller that expected one word. */
    ss->__rax = xs[0]; ss->__rdx = xs[1]; ss->__rcx = xs[2]; ss->__r8 = xs[3];
    if (cxx_small && (memcmp(cxx_buf, cxx_mark, 16) != 0 || xs[0] == (unsigned long)(uintptr_t)cxx_buf)) { extern void a2x_tramp_result_via_x8(void); ss->__rax = cxx_buf[0]; ss->__rdx = cxx_buf[1]; a2x_tramp_result_via_x8(); }
    if (is_sret) { a2x_tramp_sret_store(sinfo, (void *)(uintptr_t)ss->__rdi, vs); ss->__rax = ss->__rdi; }   /* x86 returns the buffer in rax */
    memcpy(&fs->__fpu_xmm0, vs, 16);      memcpy(&fs->__fpu_xmm1, vs + 16, 16);
    memcpy(&fs->__fpu_xmm2, vs + 32, 16); memcpy(&fs->__fpu_xmm3, vs + 48, 16);
    ss->__rsp += 8;
    int a2x_async = 0;   /* set below; read after the block by the swifterror hand-back */
    /* A swiftasync callee returns with retq $8: the x86-64 async convention has the caller leave one extra word
       above the return address and the callee pop it. A guest async function (its prologue sets the async-frame
       bit, orr x29, x29, #0x1000000000000000) is called that way by the Swift runtime, so returning with a plain
       pop left rsp 8 low and every later pop in the runtime frame one slot off, ending in a ret to a stack
       address. */
    {
        unsigned int ip[2] = {0, 0};
        a2x_async_guest_word(tgt, &ip[0]);
        if (tgt <= ~0UL - 4) a2x_async_guest_word(tgt + 4, &ip[1]);
        /* The prologue test misses an async function that never sets the frame bit: a thunk that only loads the
           continuation and tail-calls swift_task_switch (ldr x1,[x22,#n]; ...; b swift_task_switch) is called
           by the runtime like any other, and the runtime then emits sub $8,%rsp at the return site (48 83 ec 08)
           to rebalance the word the callee was meant to pop. Without the extra pop rsp ended 8 low and the
           caller's epilogue returned to a stack address (ProcessOutOfLineJob::process, swift_job_run). */
        const unsigned char *rp = (const unsigned char *)(uintptr_t)ret;
        int asyncsite = rp[0] == 0x48 && rp[1] == 0x83 && rp[2] == 0xec && rp[3] == 0x08;
        int taskresume = asyncsite && a2x_ret_is_task_resume(ret);
        if (g_trace_tramp > 0)
            fprintf(a2x_errf(), "[tramp] 0x%lx ret=0x%lx site=%d task_resume=%d\n", tgt, ret, asyncsite, taskresume);
        if (asyncsite && !taskresume && ip[0] != 0xb24403bdu && !(ip[0] == 0xd503237fu && ip[1] == 0xb24403bdu)
            && !a2x_callee_uses_async_ctx(tgt)) {
            if (g_trace_tramp > 0) fprintf(a2x_errf(), "[tramp] 0x%lx returns into `sub $8,%%rsp` but is not async: no extra pop\n", tgt);
            asyncsite = 0;
        }
        /* 11-05 r15a A SWIFTTAILCC CALLEE POPS ITS WHOLE ARGUMENT AREA, not just the async word. x86-64 puts
              integer args 7.. on the stack (arm64: 9..), so an arm64 callee that popped N bytes of stack arguments
              had N + 16 on x86, and the caller sized the area so that it plus the return address is 16-aligned.
              N = 0 gives the 8 this line always popped. sharingd: N = 16 -> 0x28; popping 8 left rsp 0x20 low and
              the job runner returned to 0 (exit 139 every launch). */
        a2x_async = asyncsite || ip[0] == 0xb24403bdu || (ip[0] == 0xd503237fu && ip[1] == 0xb24403bdu);
        if (a2x_async) {
            unsigned long argb = a2x_gpop ? a2x_gpop + 16 : 0;
            unsigned long area = ((argb + 8 + 15) & ~15UL) - 8;
            ss->__rsp += area;
            static int shown_pop;
            if (a2x_gpop && shown_pop < 3) { shown_pop++;
                fprintf(a2x_errf(), "[tramp] async 0x%lx popped %lu guest stack bytes: x86 area 0x%lx\n", tgt, a2x_gpop, area); }
        } else if (a2x_gpop) {
            fprintf(a2x_errf(), "[tramp] 0x%lx popped %lu guest stack bytes at a non-async site: left to the caller\n", tgt, a2x_gpop);
        }
    }
    /* THE ERROR A GUEST SWIFT FUNCTION THROWS. swiftcc returns the thrown error in x21 on arm64 and in r12 on
       x86-64; the caller zeroes the register before the call and tests it afterwards. x21 was carried in but never
       back, so a guest function that threw looked like one that returned normally and the native caller went on to
       read a result the callee never wrote. Reminders: RemindersUICore calls the application's witness for
       TTRMonitorableDataView.fetchData(from:userInteractive:) (xorl %r12d,%r12d; callq *0x18(%r15); testq %r12,%r12);
       the witness skips its store when x21 is set (cbnz x21), and the caller then wrapped an unwritten buffer in
       Result.success and retained stack garbage on a worker thread.
       Only a register that went in as zero is written, and only with a non-zero value: for every callee that is not
       a throwing Swift function x21 is callee-saved and comes back as it went in, so nothing changes for them. An
       async callee is left alone: it returns through the task runtime, not to this caller. */
    if (!a2x_async && ss->__r12 == 0 && xs[21] != 0) {
        if (g_trace_tramp > 0) fprintf(a2x_errf(), "[tramp] 0x%lx threw: x21 0x%lx handed back in r12\n", tgt, xs[21]);
        ss->__r12 = xs[21];
    }
    ss->__rip = ret;
    g_tramp_n++;
    /* SUCCESS MUST NOT BE SILENT — a recovered call leaves no trace of its own, and a mechanism that
          cannot be seen working cannot be told from one that never fired. */
    if (g_trace_tramp > 0) {
        char b[160];
        int k = snprintf(b, sizeof b, "[tramp] native -> guest 0x%lx (call %lu), back to 0x%lx\n",
                         tgt, g_tramp_n, ret);
        ssize_t ig = write(2, b, (size_t)k); (void)ig;
    }
    return 1;
}

/* THE OS REPORTS ITS OWN FAILURES. When this host was started by launchd or the kernel exec
      redirect, fd 2 is /dev/null and every report below - the fault handler, the bridge's named
      aborts, the load stages - vanished. Point fd 2 at /var/tmp/a2x-reports/<program>.log instead.
    Only when fd 2 IS /dev/null: compared by device number against a fresh open of /dev/null, so a
      terminal, a pipe or a redirect chosen by the caller is never touched.
    The directory is 1777 because hosted programs run as many users; the file is truncated per
      start so a crash loop overwrites one file instead of creating thousands.
    Stage printing is switched on for these runs: it is ~20 lines, and without it a death inside
      libobjc's own _objc_fatal (no signal, so no fault handler) would say nothing at all. */
/* C1 11-06 A CALL THROUGH A MISSING IMPORT WAS A BARE SIGSEGV AT pc 0.
      27.2 ships daemons for Apple-silicon-only hardware whose frameworks the x86_64 (Rosetta) cache does not carry AT
      ALL — m6 27.2 dyld_shared_cache_x86_64.map: CoreRepairCore 0, CentauriController 0, SPINANDClient 0 images. The
      binder leaves those slots 0 (below), the arm64e stub does `adrp/add x17 = slot; ldr x16,[x17]; braa x16,x17`, and
      the daemon died SIGSEGV with "native rip 0": corerepaird+0x20e4 (a stub), centaurid, IOMFB_bics_daemon, all exit
      139 on the box. Every one is a corpse, and a KeepAlive daemon crash-looping is what fills the kernel corpse cap.
    x17 IS the slot at that braa, so the slot names the symbol: when the interpreter is asked to call native 0 and x17
      is a slot this binder left empty, the report names the import and the process exits 69 (EX_UNAVAILABLE) — what a
      daemon whose hardware is absent tells launchd — instead of crashing. A NULL call NOT through a recorded slot is
      untouched and still faults exactly as it would on real hardware.
    The symbol is copied: f->symbol points into the guest file's LINKEDIT buffer, which need not outlive binding. */
#define A2X_MISS_CAP 8192
static struct { unsigned long slot; char *sym; } a2x_miss[A2X_MISS_CAP];
static unsigned a2x_miss_n;
static int a2x_miss_lk;
void a2x_missing_slot_note(unsigned long slot, const char *sym) {
    while (__atomic_exchange_n(&a2x_miss_lk, 1, __ATOMIC_ACQUIRE)) sched_yield();
    unsigned n = a2x_miss_n;
    if (n < A2X_MISS_CAP) {
        a2x_miss[n].slot = slot;
        a2x_miss[n].sym = sym ? strdup(sym) : 0;
        __atomic_store_n(&a2x_miss_n, n + 1, __ATOMIC_RELEASE);   /* the entry is whole before a reader can count it */
    }
    __atomic_store_n(&a2x_miss_lk, 0, __ATOMIC_RELEASE);
}
/* returns only when `slot` is not one the binder left empty */
void a2x_missing_import_called(unsigned long slot, unsigned long site) {
    unsigned n = __atomic_load_n(&a2x_miss_n, __ATOMIC_ACQUIRE);
    for (unsigned k = 0; k < n; k++) {
        if (a2x_miss[k].slot != slot) continue;
        extern void a2x_stop_import(const char *, unsigned long);
        a2x_stop_import(a2x_miss[k].sym ? a2x_miss[k].sym : "(unnamed)", site);
        _exit(69);
    }
}

#define A2X_REPORT_DIR "/var/tmp/a2x-reports"
static void a2x_report_to_file(const char *gpath, int argc, char **argv) {
    struct stat es, ns;
    /* 11-01 fd 2 CLOSED counts as nowhere too: WindowServer crash-looped (exit 139 x9) with no report file. */
    if (getpid() == 1) return;
    int same;
    if (fstat(2, &es) != 0) same = 1;
    else {
        int nfd = open("/dev/null", O_RDONLY);
        if (nfd < 0) return;
        same = fstat(nfd, &ns) == 0 && S_ISCHR(es.st_mode) && es.st_rdev == ns.st_rdev;
        close(nfd);
    }
    if (!same) return;
    /* Any process may add a report, none may read, replace or delete another's: sticky and write+search only (01733).
       The installer makes the folder root-owned with the same mode; this covers a run before that. */
    if (mkdir(A2X_REPORT_DIR, 01733) == 0) chmod(A2X_REPORT_DIR, 01733);
    const char *base = gpath ? strrchr(gpath, '/') : 0;
    base = base ? base + 1 : (gpath ? gpath : "unknown");
    char path[1024];
    /* A program run by a user other than root writes <name>.<uid>.log, so one account's file never blocks another's. */
    if (geteuid()) snprintf(path, sizeof path, A2X_REPORT_DIR "/%s.%u.log", base, (unsigned)geteuid());
    else snprintf(path, sizeof path, A2X_REPORT_DIR "/%s.log", base);
    /* The folder is shared and writable: never follow a link someone left there, and only reuse a plain file of ours. */
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    struct stat fs;
    if (fstat(fd, &fs) != 0 || !S_ISREG(fs.st_mode) || fs.st_nlink != 1 || fs.st_uid != geteuid()) { close(fd); return; }
    ftruncate(fd, 0);
    if (fd != 2) { dup2(fd, 2); close(fd); }
}

/* 11-01 AT PID 1 THERE IS NO STDERR. Stock 27 launchd under the host died "initproc exited ... exit 139" with
      an empty serial log: fault() wrote its whole report to fd 2, which the kernel never opens for init.
      At PID 1 the report goes to /dev/console (the serial log); everywhere else it stays fd 2. */
/* 11-01 RE-SEAL AFTER ONE INSTRUCTION. The unseal below used to be permanent: one data read of a code page
      (a literal pool, a host peek) left it readable, and every later native->guest call into it paid the 3-24 ms
      readable-page fault instead of 2.7 us.  t18: remoted 217,895 of them on ONE page (0x100001000) in ~10 min,
      launchd ~11,800 — remoted spent its life in the kernel. Now the page is RW for the one faulting instruction
      (x86 trap flag), then copied into the alias (a store stays visible) and sealed PROT_NONE again.
   States in a2x_pg_sealed: 1 sealed, 2 open for one instruction (a data fault that sees 2 just retries — the B29
      race shape), 0 open for good. A page re-sealed 64 times stays open (a hot literal loop must not pay 2 faults per
      load forever) and says so once. The trap is PROBED at install: no SIGTRAP back = re-seal off, old behaviour. */
static int a2x_reseal_on;
static unsigned char *a2x_pg_count;
/* 11-05 r14q ONE THREAD'S TRAP RE-SEALED EVERY THREAD'S PAGE. a2x_reseal_now() sealed all pending pages on any
      thread's single-step trap, including a page another thread had just opened and not yet read. Eight threads reading
      one page (searchpartyuseragent's crash printers, dladdr on the main header 0x100000000) each re-sealed the others'
      page before it was used: 57 min at 645% CPU, 97% of it system time, none reached _exit. Now each thread holds a
      reference on the pages it opened and drops only its own on its trap; a page is sealed when the last one leaves. */
static unsigned short *a2x_pg_ref;
static __thread unsigned long t_rs_pg[4];
static __thread int t_rs_n;
static unsigned long a2x_reseal_pend[64];
static volatile int a2x_trap_probe;
/* Signal handlers on different threads must serialize protection changes and
   alias refreshes. Otherwise one thread makes the alias read-only during the
   other thread's copy (the previously fixed B32p failure). */
static int a2x_reseal_lk;
/* 11-05 r14h: a fault taken while holding this lock re-enters the handler on the same thread. Measured: MenuBarAgent spun
   at 295% CPU for 4.6 hours, three threads in sched_yield under _sigtramp. The owner proceeds and says so once. */
static int g_errfd;
static volatile unsigned long a2x_reseal_own;
static int a2x_reseal_depth;
static void a2x_reseal_lock(void) {
    unsigned long me = (unsigned long)pthread_self();
    if (__atomic_load_n(&a2x_reseal_own, __ATOMIC_ACQUIRE) == me) {
        a2x_reseal_depth++;
        return;
    }
    while (__atomic_exchange_n(&a2x_reseal_lk, 1, __ATOMIC_ACQUIRE)) sched_yield();
    __atomic_store_n(&a2x_reseal_own, me, __ATOMIC_RELEASE);
}
static void a2x_reseal_unlock(void) {
    if (a2x_reseal_depth) { a2x_reseal_depth--; return; }
    __atomic_store_n(&a2x_reseal_own, 0UL, __ATOMIC_RELEASE);
    __atomic_store_n(&a2x_reseal_lk, 0, __ATOMIC_RELEASE);
}
static int a2x_reseal_open(unsigned long pg) {
    for (int i = 0; i < 64; i++)
        if (__sync_bool_compare_and_swap(&a2x_reseal_pend[i], 0UL, pg)) return 1;
    return 0;
}
static void a2x_reseal_now(void) {
    for (int i = 0; i < 64; i++) {
        unsigned long pg = a2x_reseal_pend[i];
        if (!pg || !__sync_bool_compare_and_swap(&a2x_reseal_pend[i], pg, 0UL)) continue;
        unsigned char *st = &a2x_pg_sealed[(pg - A2X_GUEST_BASE) >> A2X_PG_SHIFT];
        a2x_reseal_lock();
        if (__atomic_load_n(st, __ATOMIC_ACQUIRE) == 2) {
            unsigned long al = pg + a2x_alias_delta;
            if (mprotect((void *)al, 0x1000, PROT_READ | PROT_WRITE) == 0) {
                /* the decode cache keys on a64_code_gen: changed bytes must orphan it */
                if (memcmp((void *)al, (const void *)pg, 0x1000)) { extern unsigned a64_code_gen; __atomic_add_fetch(&a64_code_gen, 1, __ATOMIC_RELEASE); }
                memcpy((void *)al, (const void *)pg, 0x1000);
                if (mprotect((void *)al, 0x1000, PROT_READ) == 0) {
                    __atomic_store_n(st, 1, __ATOMIC_RELEASE);
                    if (mprotect((void *)pg, 0x1000, PROT_NONE))
                        __atomic_store_n(st, 0, __ATOMIC_RELEASE);
                }
            }
        }
        a2x_reseal_unlock();
    }
}
/* r14q: the copy-and-seal of reseal_now for one page; the caller holds the lock and saw state 2 */
static void a2x_reseal_page_locked(unsigned long pg) {
    unsigned char *st = &a2x_pg_sealed[(pg - A2X_GUEST_BASE) >> A2X_PG_SHIFT];
    unsigned long al = pg + a2x_alias_delta;
    if (mprotect((void *)al, 0x1000, PROT_READ | PROT_WRITE)) return;
    if (memcmp((void *)al, (const void *)pg, 0x1000)) { extern unsigned a64_code_gen; __atomic_add_fetch(&a64_code_gen, 1, __ATOMIC_RELEASE); }
    memcpy((void *)al, (const void *)pg, 0x1000);
    if (mprotect((void *)al, 0x1000, PROT_READ)) return;
    __atomic_store_n(st, 1, __ATOMIC_RELEASE);
    if (mprotect((void *)pg, 0x1000, PROT_NONE)) __atomic_store_n(st, 0, __ATOMIC_RELEASE);
}
/* r14q: this thread will read page pg for one instruction; the caller holds the lock. 0 = no table or no slot (old path) */
static int a2x_join_open(unsigned long pg, void *uc) {
    if (!a2x_pg_ref || !uc) return 0;
    unsigned long ix = (pg - A2X_GUEST_BASE) >> A2X_PG_SHIFT;
    int have = 0;
    for (int i = 0; i < t_rs_n; i++) if (t_rs_pg[i] == pg) have = 1;
    if (!have) {
        if (t_rs_n >= 4 || a2x_pg_ref[ix] == 0xffff) return 0;
        a2x_pg_ref[ix]++; t_rs_pg[t_rs_n++] = pg;
    }
    ((ucontext_t *)uc)->uc_mcontext->__ss.__rflags |= 0x100ULL;
    return 1;
}
/* r14q: on this thread's trap, drop its own references; the last one out seals */
static void a2x_release_own(void) {
    for (int i = 0; i < t_rs_n; i++) {
        unsigned long pg = t_rs_pg[i], ix = (pg - A2X_GUEST_BASE) >> A2X_PG_SHIFT;
        a2x_reseal_lock();
        if (a2x_pg_ref[ix] && --a2x_pg_ref[ix] == 0 && __atomic_load_n(&a2x_pg_sealed[ix], __ATOMIC_ACQUIRE) == 2)
            a2x_reseal_page_locked(pg);
        a2x_reseal_unlock();
    }
    t_rs_n = 0;
}
static void a2x_trap(int sig, siginfo_t *si, void *uc) {
    (void)si;
    if (uc) ((ucontext_t *)uc)->uc_mcontext->__ss.__rflags &= ~0x100ULL;
    if (a2x_trap_probe == 1) { a2x_trap_probe = 2; return; }
    if (a2x_reseal_on) { if (t_rs_n) a2x_release_own(); a2x_reseal_now(); return; }
    signal(sig, SIG_DFL);
    raise(sig);
}

static int g_errfd = 2;
static __thread int g_fault_depth, g_lowstack_said;
static const struct mach_header_64 *guest_mh(unsigned i);
static void a2x_report_swift_types(unsigned long rsp, unsigned long hi) {
    /* 11-05 r14l: a fault inside native SwiftUI shows only addresses. Names every struct, enum and optional metadata pointer in the
       first 600 stack words, plus the words of each pointer that a metadata word sits beside. The process is already dying, so a
       runtime call is acceptable; every read goes through vm_read_overwrite so a stale word cannot fault here. */
    typedef struct { const char *p; size_t n; } tn_t;
    void *swh = dlopen("/usr/lib/swift/libswiftCore.dylib", RTLD_NOW);
    tn_t (*nm)(const void *, int) = swh ? (tn_t (*)(const void *, int))dlsym(swh, "swift_getTypeName") : 0;
    if (!nm) { static const char m[] = "[host]   type report: no swift_getTypeName\n"; ssize_t ig = write(g_errfd, m, sizeof m - 1); (void)ig; return; }
    unsigned long seen[32]; int ns = 0, nscan = 0, nread = 0, pf[2];
    if (pipe(pf)) return;
    for (int k = 0; k < 600 && rsp + (unsigned long)(k + 1) * 8 <= hi && ns < 32; k++) {
        unsigned long w = ((unsigned long *)(uintptr_t)rsp)[k], kind = 0;
        nscan++;
        if (w < 0x100000000ul || (w & 7)) continue;
        if (write(pf[1], (const void *)(uintptr_t)(w - 8), 16) != 16) continue;   /* EFAULT on an unmapped word, no signal */
        unsigned long two[2];
        if (read(pf[0], two, 16) != 16) continue;
        nread++;
        kind = two[1];
        if (kind != 0x200 && kind != 0x201 && kind != 0x202) continue;
        int dup = 0; for (int j = 0; j < ns; j++) if (seen[j] == w) dup = 1;
        if (dup) continue;
        seen[ns++] = w;
        if (!two[0]) continue;
        tn_t t = nm((const void *)(uintptr_t)w, 1);
        char b[420];
        int n = snprintf(b, sizeof b, "[host]   type stack[%d] %#lx kind %#lx %.*s\n", k, w, kind, (int)(t.n > 360 ? 360 : t.n), t.p);
        ssize_t ig = write(g_errfd, b, (size_t)(n < (int)sizeof b ? n : (int)sizeof b - 1)); (void)ig;
    }
    { char b[96]; int n = snprintf(b, sizeof b, "[host]   type report: scanned %d read %d named %d\n", nscan, nread, ns);
      ssize_t ig = write(g_errfd, b, (size_t)(n < (int)sizeof b ? n : (int)sizeof b - 1)); (void)ig; }
    close(pf[0]); close(pf[1]);
}
static void fault_lowstack_check(int sig, unsigned long fa, void *uc) {
    if (!uc || g_lowstack_said) return;
    unsigned long rsp = (unsigned long)((ucontext_t *)uc)->uc_mcontext->__ss.__rsp;
    unsigned long hi = (unsigned long)(uintptr_t)pthread_get_stackaddr_np(pthread_self());
    unsigned long sz = (unsigned long)pthread_get_stacksize_np(pthread_self());
    if (!hi || !sz || rsp > hi || rsp < hi - sz) return;            /* already on some other stack: say nothing */
    unsigned long left = rsp - (hi - sz);
    if (left >= (96u << 10)) return;
    g_lowstack_said = 1;
}
/* AN ALIGNED SSE OPERAND AT AN ADDRESS THAT IS NOT 16-BYTE ALIGNED. Apple's x86_64 system code on macOS 27 only ever
   runs under Rosetta, which does not raise the alignment fault a real Intel processor does, so it carries latent ones:
   VectorKit keeps its camera view at 16n+8 and reads it with `movapd 0x328(%r14), %xmm2`, `mulpd 0x338(%rsi), %xmm0`
   and the like; every application that shows a map died there with a general-protection fault (Weather, Find My;
   measured 11-09). Complete the instruction the way it completes there and continue:
 a store (movaps/movapd/movdqa to memory, movntps/pd, movntdq) is done here as a plain 16-byte copy;
 anything else reads its operand: the 16 bytes are copied to an aligned slot on a per-thread page and the thread
     resumes at a copy of the instruction whose memory operand is that slot, followed by a jump back.
   Only for trap 13, only legacy-SSE encodings (0F, 0F 38, 0F 3A maps), only when the operand really is misaligned, and
   never for guest addresses. Anything it does not recognise is left to fault as before. */
static unsigned long a2x_sse_fixups;
static __thread unsigned char *a2x_sse_page;
static int a2x_sse_align_fixup(void *uc_) {
    ucontext_t *u = (ucontext_t *)uc_;
    if (!u || !u->uc_mcontext) return 0;
    _STRUCT_MCONTEXT64 *mc = u->uc_mcontext;
    if (mc->__es.__trapno != 13) return 0;
    _STRUCT_X86_THREAD_STATE64 *ss = &mc->__ss;
    unsigned long rip = (unsigned long)ss->__rip;
    if (rip >= A2X_GUEST_BASE && rip < A2X_GUEST_BASE + A2X_GUEST_LEN) return 0;
    const unsigned char *ip = (const unsigned char *)(uintptr_t)rip;
    unsigned long *g[16] = { (unsigned long *)&ss->__rax, (unsigned long *)&ss->__rcx, (unsigned long *)&ss->__rdx, (unsigned long *)&ss->__rbx,
                             (unsigned long *)&ss->__rsp, (unsigned long *)&ss->__rbp, (unsigned long *)&ss->__rsi, (unsigned long *)&ss->__rdi,
                             (unsigned long *)&ss->__r8,  (unsigned long *)&ss->__r9,  (unsigned long *)&ss->__r10, (unsigned long *)&ss->__r11,
                             (unsigned long *)&ss->__r12, (unsigned long *)&ss->__r13, (unsigned long *)&ss->__r14, (unsigned long *)&ss->__r15 };
    unsigned i = 0, p66 = 0, rex = 0, npre = 0;
    while (ip[i] == 0x66 || ip[i] == 0xf2 || ip[i] == 0xf3) { if (ip[i] == 0x66) p66 = 1; i++; if (++npre > 3) return 0; }
    unsigned rexat = i;
    if ((ip[i] & 0xf0) == 0x40) rex = ip[i++];
    unsigned opat = i;
    if (ip[i++] != 0x0f) return 0;
    unsigned op = ip[i++], map = 1, imm = 0;
    if (op == 0x38) { map = 2; op = ip[i++]; }
    else if (op == 0x3a) { map = 3; op = ip[i++]; imm = 1; }
    else if (op == 0x70 || op == 0x71 || op == 0x72 || op == 0x73 || op == 0xc2 || op == 0xc4 || op == 0xc5 || op == 0xc6) imm = 1;
    unsigned opend = i;
    unsigned modrm = ip[i++], mod = modrm >> 6, reg = ((modrm >> 3) & 7) | ((rex & 4) ? 8u : 0u), rm = modrm & 7;
    if (mod == 3) return 0;                                   /* register to register never faults this way */
    unsigned long ea = 0; int riprel = 0;
    if (rm == 4) {
        unsigned sib = ip[i++], idx = ((sib >> 3) & 7) | ((rex & 2) ? 8u : 0u), base = (sib & 7) | ((rex & 1) ? 8u : 0u);
        if (idx != 4) ea += *g[idx] << (sib >> 6);
        if ((sib & 7) == 5 && mod == 0) { int d; memcpy(&d, ip + i, 4); i += 4; ea += (unsigned long)(long)d; }
        else ea += *g[base];
    } else if (rm == 5 && mod == 0) { int d; memcpy(&d, ip + i, 4); i += 4; ea = (unsigned long)(long)d; riprel = 1; }
    else ea += *g[rm | ((rex & 1) ? 8u : 0u)];
    if (mod == 1) ea += (unsigned long)(long)(signed char)ip[i++];
    else if (mod == 2) { int d; memcpy(&d, ip + i, 4); i += 4; ea += (unsigned long)(long)d; }
    unsigned char immb = imm ? ip[i++] : 0;
    if (riprel) ea += rip + i;
    if (!(ea & 15)) return 0;                                 /* aligned: this fault is something else */
    /* A general-protection fault is also what an address outside the canonical range gives, aligned or not. That is
       a wild pointer in the faulting code, not an alignment fault: completing it here would read the same address
       inside the signal handler and fault again, without end. Leave it to be reported. */
    if ((unsigned long)((long)(ea << 16) >> 16) != ea) return 0;
    int store = map == 1 && (op == 0x29 || op == 0x2b || (p66 && (op == 0x7f || op == 0xe7)));
    if (store) {
        memcpy((void *)(uintptr_t)ea, (unsigned char *)&mc->__fs.__fpu_xmm0 + 16 * reg, 16);
        ss->__rip = rip + i;
    } else {
        unsigned char *pg = a2x_sse_page;
        if (!pg) {
            pg = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
            if (pg == MAP_FAILED) pg = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
            if (pg == MAP_FAILED) return 0;
            a2x_sse_page = pg;
        }
        unsigned char *slot = pg + 64, *c = pg; unsigned n = 0;
        memcpy(slot, (const void *)(uintptr_t)ea, 16);
        for (unsigned k = 0; k < rexat; k++) c[n++] = ip[k];                    /* 66 / F2 / F3 */
        if (rex & 0x0c) c[n++] = (unsigned char)(0x40 | (rex & 0x0c));          /* keep W and R; the operand has no base or index now */
        for (unsigned k = opat; k < opend; k++) c[n++] = ip[k];                 /* 0F [38|3A] opcode */
        c[n++] = (unsigned char)((modrm & 0x38) | 0x05);                        /* mod 00, rm 101: rip-relative */
        unsigned after = n + 4 + imm;
        int d = (int)((long)(slot - (c + after))); memcpy(c + n, &d, 4); n += 4;
        if (imm) c[n++] = immb;
        c[n++] = 0xff; c[n++] = 0x25; c[n++] = 0; c[n++] = 0; c[n++] = 0; c[n++] = 0;   /* jmp *0(%rip) */
        unsigned long back = rip + i; memcpy(c + n, &back, 8);
        ss->__rip = (unsigned long)(uintptr_t)c;
    }
    return 1;
}
/* THE STOP RECORD. What the interpreter leaves behind when it stops a program: always on, in both flavours, no
   switch, at most 4 KB, written once. It exists so that a report from a user's log can be diagnosed without
   asking them to turn anything on. Every line has a fixed prefix so a script can read it:
     FATAL: <reason> [<detail>]                 the reason line (the log collector looks for this prefix)
     a2x-stop: build a2x <id> macos <build> pid <n>
     a2x-stop: program <path of the program being run>
     a2x-stop: signal <name> fault <address>    only when a signal stopped it
     a2x-stop: guest pc <image>+<offset> lr <image>+<offset>
     a2x-stop: objc selector <name> class <name>   only for a stop in the Objective-C bridge
     a2x-stop: import <symbol> wanted-by <image>   only for a call through an import this OS does not have
     a2x-stop: frame <n> native|guest <image>+<offset> [<function>+<offset>]    at most 16
     a2x-stop: end
   Places are an image's file name and an offset into it; there are no registers and no memory. The first four
   native frames also carry the function the system's own lookup names for that address (a system library's
   function, cut to 96 bytes; never one of the interpreter's own): what stopped a system program is told apart
   by it, and the start-up scripts read it.
   Every word of another stack is read with vm_read_overwrite, so a bad frame pointer ends the list instead of
   faulting inside the report. */
#include <stdarg.h>
#include <sys/sysctl.h>
#ifndef A2X_BUILD_ID
#define A2X_BUILD_ID "dev"
#endif
extern unsigned int mach_task_self_;
extern int vm_read_overwrite(unsigned int, unsigned long, unsigned long, unsigned long, unsigned long *);
static int stop_rd(unsigned long a, unsigned long *v) {
    unsigned long got = 0;
    return a && !(a & 7) && vm_read_overwrite(mach_task_self_, a, 8, (unsigned long)v, &got) == 0 && got == 8;
}
static int g_stop_written;
static __thread const char *g_stop_sel, *g_stop_cls;
static const char *g_stop_import; static unsigned long g_stop_import_site;
struct stop_buf { char b[4096]; int n; };
static void stop_add(struct stop_buf *s, const char *fmt, ...) {
    int room = (int)sizeof s->b - s->n;
    if (room <= 1) return;
    va_list ap; va_start(ap, fmt);
    int k = vsnprintf(s->b + s->n, (size_t)room, fmt, ap);
    va_end(ap);
    if (k > 0) s->n += k < room ? k : room - 1;
}
static const char *stop_base(const char *p) { const char *b = p ? strrchr(p, '/') : 0; return b ? b + 1 : (p ? p : "?"); }
static void stop_where(char *out, size_t n, unsigned long a) {
    for (unsigned i = 0; i < g_nimg; i++)
        if (g_img[i].vmlo <= g_img[i].vmend && a >= g_img[i].vmlo && a < g_img[i].vmend) {
            snprintf(out, n, "%s+0x%lx", stop_base(g_img[i].path), a - (unsigned long)(uintptr_t)guest_mh(i)); return; }
    Dl_info di;
    if (a && dladdr((const void *)(uintptr_t)a, &di) && di.dli_fname) {
        snprintf(out, n, "%s+0x%lx", stop_base(di.dli_fname), a - (unsigned long)(uintptr_t)di.dli_fbase); return; }
    snprintf(out, n, "0x%lx", a);
}
/* " <function>+0x<offset>" for a native address, or nothing. Uses the same lookup stop_where already makes. */
static void stop_sym(char *out, size_t n, unsigned long a) {
    Dl_info di, me; out[0] = 0;
    if (!a || !dladdr((const void *)(uintptr_t)a, &di) || !di.dli_sname || !di.dli_saddr) return;
    if (dladdr((const void *)&g_stop_written, &me) && me.dli_fbase == di.dli_fbase) return;
    snprintf(out, n, " %.96s+0x%lx", di.dli_sname, a - (unsigned long)(uintptr_t)di.dli_saddr);
}
void a2x_stop_record(const char *reason, const char *detail, int sig, const void *fa, void *uc) {
    if (__sync_lock_test_and_set(&g_stop_written, 1)) return;
    static struct stop_buf s; s.n = 0;
    char w[320], w2[320];
    stop_add(&s, "FATAL: %s%s%.400s\n", reason ? reason : "stop", detail && *detail ? " " : "", detail ? detail : "");
    char osb[32] = "?"; size_t ol = sizeof osb - 1;
    if (sysctlbyname("kern.osversion", osb, &ol, 0, 0) != 0) { osb[0] = '?'; osb[1] = 0; }
    stop_add(&s, "a2x-stop: build a2x " A2X_BUILD_ID " macos %s pid %d\n", osb, (int)getpid());
    stop_add(&s, "a2x-stop: program %s\n", g_nimg ? g_img[0].path : "?");
    if (sig) stop_add(&s, "a2x-stop: signal %s fault 0x%lx\n", reason ? reason : "?", (unsigned long)(uintptr_t)fa);
    unsigned insn = 0; unsigned long pc = a2x_report_pc(&insn);
    const a64 *g = a64_cur_state;
    if (pc || g) {
        stop_where(w, sizeof w, pc);
        if (g) stop_where(w2, sizeof w2, g->x[30] & 0x0000ffffffffffffUL); else { w2[0] = '-'; w2[1] = 0; }
        stop_add(&s, "a2x-stop: guest pc %s lr %s\n", w, w2);
    }
    if (g_stop_sel) stop_add(&s, "a2x-stop: objc selector %.200s class %.200s\n", g_stop_sel, g_stop_cls ? g_stop_cls : "?");
    if (g_stop_import) { stop_where(w, sizeof w, g_stop_import_site);
        const char *plus = strrchr(w, '+'); int wl = plus ? (int)(plus - w) : (int)strlen(w);
        stop_add(&s, "a2x-stop: import %.200s wanted-by %.*s\n", g_stop_import, wl, w); }
    int f = 0;
    unsigned long ip = 0, bp = 0;
    if (uc) { _STRUCT_MCONTEXT64 *mc = ((ucontext_t *)uc)->uc_mcontext; ip = (unsigned long)mc->__ss.__rip; bp = (unsigned long)mc->__ss.__rbp; }
    else { bp = (unsigned long)(uintptr_t)__builtin_frame_address(0); ip = (unsigned long)(uintptr_t)__builtin_return_address(0); }
    for (int k = 0; k < 8 && ip; k++) {
        stop_where(w, sizeof w, ip);
        w2[0] = 0; if (k < 4) stop_sym(w2, sizeof w2, ip);
        stop_add(&s, "a2x-stop: frame %d native %s%s\n", f++, w, w2);
        unsigned long nb = 0, ra = 0;
        if (!stop_rd(bp, &nb) || !stop_rd(bp + 8, &ra) || nb <= bp) break;
        ip = ra; bp = nb;
    }
    if (g) {
        unsigned long fp = g->x[29];
        for (int k = 0; k < 8; k++) {
            unsigned long nfp = 0, lr = 0;
            if (!stop_rd(fp, &nfp) || !stop_rd(fp + 8, &lr)) break;
            lr &= 0x0000ffffffffffffUL; if (!lr) break;
            stop_where(w, sizeof w, lr); stop_add(&s, "a2x-stop: frame %d guest %s\n", f++, w);
            if (nfp <= fp) break;
            fp = nfp;
        }
    }
    stop_add(&s, "a2x-stop: end\n");
    ssize_t ig = write(g_errfd, s.b, (size_t)s.n); (void)ig;
}
void a2x_stop_import(const char *sym, unsigned long site) {
    g_stop_import = sym; g_stop_import_site = site;
    a2x_stop_record("missing import", sym, 0, 0, 0);
}
/* for the other sources: a named stop that is not a signal, and the Objective-C send it happened in */
void a2x_stop(const char *reason, const char *detail) { a2x_stop_record(reason, detail, 0, 0, 0); }
void a2x_stop_objc(const char *sel, const char *cls) { g_stop_sel = sel; g_stop_cls = cls; }

static void fault(int sig, siginfo_t *si, void *uc) {
    /* a native caller entering guest code is not a crash: it is a call that needs the interpreter */
    unsigned long fa = si ? (unsigned long)(uintptr_t)si->si_addr : 0;
    { extern void a2x_exc_front_tick(void); a2x_exc_front_tick(); }   /* exc_front.c: the host's port ahead of a program's exception handler */
    if (a2x_sse_align_fixup(uc)) return;
    fault_lowstack_check(sig, fa, uc);   /* 11-02 1102g diag (patch_lowstack.py) */
    if (g_trace_tramp > 0 && uc) { /* wsigbus diag: every fault, recovered or not */
        _STRUCT_MCONTEXT64 *mc = ((ucontext_t *)uc)->uc_mcontext;
        char tb[256];
        int tn = snprintf(tb, sizeof tb, "[fault] uc %p sig %d si_addr 0x%lx code %d rip 0x%llx rsp 0x%llx trapno %u err 0x%x fvaddr 0x%llx\n",
                          uc, sig, fa, si ? si->si_code : -1, mc->__ss.__rip, mc->__ss.__rsp,
                          (unsigned)mc->__es.__trapno, (unsigned)mc->__es.__err, (unsigned long long)mc->__es.__faultvaddr);
        ssize_t ig2 = write(g_errfd, tb, (size_t)tn); (void)ig2;
    }
    if (a2x_pg_sealed && fa >= A2X_GUEST_BASE && fa < A2X_GUEST_BASE + A2X_GUEST_LEN
        && a2x_pg_sealed[(fa - A2X_GUEST_BASE) >> A2X_PG_SHIFT] == 2 && uc
        && (unsigned long)((ucontext_t *)uc)->uc_mcontext->__ss.__rip == fa) {
        /* B23b A NATIVE CALL INTO A CODE PAGE THAT A DATA ACCESS UNSEALED: seal it again, then recover the call.
              Left readable, every call into it is a 3-24 ms fetch fault (MenuBarAgent 10-30: 21% of ~1,000 calls/s,
              13 pages, err 0x15). This one call pays it; the next is 2.7 us. The alias is refreshed first because
              the page was writable while unsealed; mark 1 before dropping the page so a reader sees the copy. */
        /* B32p TWO THREADS RE-SEALING ONE PAGE AT ONCE. Each opened the alias RW, copied, and made it R again, so the
              first to finish made the alias read-only under the second's memcpy: SIGSEGV writing 0x2000e3020 (dest +0x20,
              rdx 0xfe0 left), an address no arm recovers. Bare metal 10-30 15:2x, WallpaperAgent exit 139 on 3 of 4
              starts, page 0x1000e3 (the B29 jump-table page). One re-seal at a time; the flag is read again under the
              lock because the page may already be sealed, and then the retried call simply faults back here as 1. */
        /* 11-05 r14h: this arm had its own static lock of the same name, so it could seal a page during the other arm's copy */
        a2x_reseal_lock();
        if (a2x_pg_sealed[(fa - A2X_GUEST_BASE) >> A2X_PG_SHIFT] == 2
            && !(a2x_pg_ref && a2x_pg_ref[(fa - A2X_GUEST_BASE) >> A2X_PG_SHIFT])) {   /* r14q */
            unsigned long pg_ = fa & ~0xfffUL;
            void *al_ = (void *)(pg_ + a2x_alias_delta);
            if (!mprotect(al_, 0x1000, PROT_READ | PROT_WRITE)) {
                /* 10-31 the one place guest code bytes can change under a decode cache: the page was writable while
                      unsealed. Only a refresh that CHANGES bytes starts a new epoch — a plain re-seal happens hundreds of
                      times a second (MenuBarAgent) and would empty every thread's cache each time for nothing. */
                if (memcmp(al_, (const void *)pg_, 0x1000)) { extern unsigned a64_code_gen; __atomic_add_fetch(&a64_code_gen, 1, __ATOMIC_RELEASE); }
                memcpy(al_, (const void *)pg_, 0x1000);
                mprotect(al_, 0x1000, PROT_READ);
                a2x_pg_sealed[(fa - A2X_GUEST_BASE) >> A2X_PG_SHIFT] = 1;
                if (mprotect((void *)pg_, 0x1000, PROT_NONE)) a2x_pg_sealed[(fa - A2X_GUEST_BASE) >> A2X_PG_SHIFT] = 2;
            }
        }
        a2x_reseal_unlock();
    }
    /* B29 A DATA ACCESS THAT LOST THE RACE TO ANOTHER THREAD'S UNSEAL. The fault is taken while the page is
          PROT_NONE; by the time this handler reads the flag another thread has unsealed it (2), so neither the
          seal-again arm (rip == fa only) nor the unseal arm (== 1 only) matched and a plain retry was reported as a
          crash. Bare metal 10-30: WallpaperAgent SIGBUS at guest pc 0x1000e38b4 (ldr w16, [x17, x16, lsl #2], a
          jump table in __text), faulting address 0x1000e3950, intermittent (alive on some launches, 248 runs).
          Opening the page again is idempotent, and a page another thread re-seals in between faults back here as 1. */
    if (a2x_pg_sealed && fa >= A2X_GUEST_BASE && fa < A2X_GUEST_BASE + A2X_GUEST_LEN
        && a2x_pg_sealed[(fa - A2X_GUEST_BASE) >> A2X_PG_SHIFT] == 2 && uc
        && (unsigned long)((ucontext_t *)uc)->uc_mcontext->__ss.__rip != fa) {
        /* r14q: under the lock, and holding a reference, so the page cannot be sealed before this read runs */
        int ok_ = 0;
        a2x_reseal_lock();
        unsigned char st_ = a2x_pg_sealed[(fa - A2X_GUEST_BASE) >> A2X_PG_SHIFT];
        if ((st_ == 2 || st_ == 0) && !mprotect((void *)(fa & ~0xfffUL), 0x1000, PROT_READ | PROT_WRITE)) {
            ok_ = 1;
            if (st_ == 2 && a2x_reseal_on) a2x_join_open(fa & ~0xfffUL, uc);
        }
        a2x_reseal_unlock();
        if (ok_) return;
    }
    if (a2x_pg_sealed && fa >= A2X_GUEST_BASE && fa < A2X_GUEST_BASE + A2X_GUEST_LEN
        && a2x_pg_sealed[(fa - A2X_GUEST_BASE) >> A2X_PG_SHIFT] == 1) {
        unsigned long rip_ = uc ? (unsigned long)((ucontext_t *)uc)->uc_mcontext->__ss.__rip : 0;
        if (rip_ != fa) {
            /* a data access to bytes inside a sealed code page: open that one page for one instruction */
            unsigned long pg = fa & ~0xfffUL;
            unsigned char *st = &a2x_pg_sealed[(pg - A2X_GUEST_BASE) >> A2X_PG_SHIFT];
            a2x_reseal_lock();
            if (mprotect((void *)pg, 0x1000, PROT_READ | PROT_WRITE)) {
                a2x_reseal_unlock();
                goto a2x_unseal_failed;
            }
            /* 11-02 r13m a RELEASED original reads as zeros: its bytes are in the alias (shared at seal time) */
            if (a2x_pg_disc && a2x_pg_disc[(pg - A2X_GUEST_BASE) >> A2X_PG_SHIFT]) {
                memcpy((void *)pg, (const void *)(pg + a2x_alias_delta), 0x1000);
                a2x_pg_disc[(pg - A2X_GUEST_BASE) >> A2X_PG_SHIFT] = 0;
            }
            /* Even a queued fault for an already-open page must reopen it under
               the same lock: a concurrent trap may have sealed it meanwhile. */
            unsigned char *cnt = a2x_pg_count ? &a2x_pg_count[(pg - A2X_GUEST_BASE) >> A2X_PG_SHIFT] : 0;
            if (a2x_reseal_on && cnt && (a2x_pg_ref ? a2x_join_open(pg, uc) : a2x_reseal_open(pg))) {   /* 11-01: no cap — an open code page costs an exec fault per call */
                if (*cnt < 255) (*cnt)++;
                __atomic_store_n(st, 2, __ATOMIC_RELEASE);
                a2x_reseal_unlock();
                ((ucontext_t *)uc)->uc_mcontext->__ss.__rflags |= 0x100ULL;   /* trap after this one instruction */
                return;
            }
            __atomic_store_n(st, 0, __ATOMIC_RELEASE);
            a2x_reseal_unlock();
            if (cnt && *cnt == 64) {
                *cnt = 65;
            }
            return;
        }
    }
a2x_unseal_failed:
    if (fa >= __arm_text_base && fa < __arm_text_base + __arm_text_size
        && is_function_start(fa)) { g_fault_depth++; int ok_ = recover_guest_call(uc, fa); g_fault_depth--; if (ok_) return; }
    /* A native caller can reach guest text with si_addr == 0: the kernel then reports the signal with a
       syscall-style exception state (trapno 133, err 0x20000b8) instead of a page fault, so there is no
       fault address to compare. The native rip is the authority: guest pages are never executable and the
       interpreter runs from host text, so rip inside guest __TEXT at an exact function start can only be
       a native call or jump INTO a guest function. Measured on Weather, SIGBUS at rip 0x10019087c. */
    if (uc && fa == 0) {
        unsigned long rip = (unsigned long)((ucontext_t *)uc)->uc_mcontext->__ss.__rip;
        if (rip >= __arm_text_base && rip < __arm_text_base + __arm_text_size
            && is_function_start(rip)) { g_fault_depth++; int ok_ = recover_guest_call(uc, rip); g_fault_depth--; if (ok_) return; }
    }
    (void)uc;
    const char *nm = sig == SIGSEGV ? "SIGSEGV" : sig == SIGBUS ? "SIGBUS" : sig == SIGABRT ? "SIGABRT" : "SIGILL";
    a2x_stop_record(nm, 0, sig, si ? si->si_addr : 0, uc);
#if A2X_SHIP
    _exit(139);
#endif
    /* snprintf RETURNS THE LENGTH IT WOULD HAVE WRITTEN, NOT WHAT IT WROTE, and the stage lines below
          carry a full image path (up to 1024 bytes) — so write(g_errfd, b, n) would read PAST THE BUFFER on a deep
          path and print whatever is on the stack after it. Every line this handler adds clamps n; the buffer
          is 1024 so a real path fits in the first place. */
    char b[1024];
    unsigned a2x_rinsn = 0;
    unsigned long a2x_rpc = a2x_report_pc(&a2x_rinsn);
    const char *gip_ = "?"; unsigned long goff_ = a2x_rpc;
    for (unsigned i_ = 0; i_ < g_nimg; i_++)
        if (g_img[i_].vmlo <= g_img[i_].vmend && a2x_rpc >= g_img[i_].vmlo && a2x_rpc < g_img[i_].vmend) {
            gip_ = g_img[i_].path; goff_ = a2x_rpc - (unsigned long)(uintptr_t)guest_mh(i_); break; }
    int n = snprintf(b, sizeof b,
                     "\n[host] %s at guest pc 0x%lx (insn 0x%08x), faulting address %p | pid %d %s | pc in %s+0x%lx\n",
                     nm, a2x_rpc, a2x_rinsn, si ? si->si_addr : 0, (int)getpid(), g_nimg ? g_img[0].path : "?", gip_, goff_);
    ssize_t ignored = write(g_errfd, b, (size_t)n);
    /* 11-01 t28 THE GUEST CALLER FIRST. The native diagnostics below can fault themselves; the guest lr and
          argument registers are the diagnosis of a bad native call, so they print before anything risky. */
    if (a64_cur_state) { const a64 *g0 = a64_cur_state;
        n = snprintf(b, sizeof b, "[host]   guest lr %#lx fp %#lx sp %#lx x0 %#lx x1 %#lx x2 %#lx x8 %#lx x19 %#lx x20 %#lx x21 %#lx\n",
                     g0->x[30], g0->x[29], g0->sp, g0->x[0], g0->x[1], g0->x[2], g0->x[8], g0->x[19], g0->x[20], g0->x[21]);
        if (n > (int)sizeof b - 1) n = (int)sizeof b - 1;
        ignored = write(g_errfd, b, (size_t)n); }
    /* 10-27 WHICH SIDE FAULTED. si_addr alone cannot tell "the interpreter touched a bad guest
          address" from "we handed control to native code and IT faulted": si_addr equalling a native
          callee's own entry reads as an instruction-fetch fault, and a probe proved those pages are
          real x86 code (push rbp; mov rbp,rsp), so the two readings disagree. The NATIVE rip settles it,
          with the bytes AT rip so the instruction that faulted is named rather than guessed. */
    if (uc) {
        _STRUCT_X86_THREAD_STATE64 *fss = &((ucontext_t *)uc)->uc_mcontext->__ss;
        /* r14r: rdi_ was uninitialized when dladdr failed (rip 0), so dli_fname was stack garbage (0x7230) and this
              snprintf crashed inside the crash report: sharingd's 1,773 pc-0 reports ended here and hid the real fault. */
        Dl_info rdi_ = {0};
        int rok_ = dladdr((void *)(uintptr_t)fss->__rip, &rdi_);
        const char *rsym = rok_ && rdi_.dli_sname ? rdi_.dli_sname : "?";
        const char *rimg = rok_ && rdi_.dli_fname ? rdi_.dli_fname : "?";
        n = snprintf(b, sizeof b, "[host]   native rip %016llx (%s in %s)  rsp %016llx\n",
                     fss->__rip, rsym, rimg, fss->__rsp);
        ignored = write(g_errfd, b, (size_t)n);
        { /* wsigbus diag: exception state, bytes at rip, [rsp], page protection of rip */
            _STRUCT_MCONTEXT64 *mc = ((ucontext_t *)uc)->uc_mcontext;
            n = snprintf(b, sizeof b, "[host]   exc trapno %u err 0x%x faultvaddr 0x%llx si_code %d\n",
                         (unsigned)mc->__es.__trapno, (unsigned)mc->__es.__err,
                         (unsigned long long)mc->__es.__faultvaddr, si ? si->si_code : -1);
            ignored = write(g_errfd, b, (size_t)n);
            unsigned long ra = 0; memcpy(&ra, (const void *)(uintptr_t)fss->__rsp, 8);
            n = snprintf(b, sizeof b, "[host]   [rsp]=0x%lx rip_is_fstart=%d rip_in_text=%d\n", ra,
                         is_function_start((unsigned long)fss->__rip),
                         (unsigned long)fss->__rip >= __arm_text_base && (unsigned long)fss->__rip < __arm_text_base + __arm_text_size);
            ignored = write(g_errfd, b, (size_t)n);
            { /* wsigbus diag: who is on the native stack */
                unsigned long cand[42]; int nc = 0; cand[nc++] = ra;
                unsigned long *bp = (unsigned long *)(uintptr_t)fss->__rbp;
                /* 10-29 the old floor (bp > 0x7ff000000000) held for the MAIN thread only, so every worker-thread
                      fault (dispatch / pthread stacks at 0x7000.. or 0x1xxxxxxxx..) printed frame0 and nothing more:
                      Games, TV and App Store crash on workers and their callers were never named. Walk the chain
                      while it is 8-aligned, climbs, and stays inside THIS thread's stack [rsp, stack top) — the
                      handler runs on the faulting thread, so pthread_self() is that thread. */
                unsigned long lo = (unsigned long)fss->__rsp;
                unsigned long hi = (unsigned long)(uintptr_t)pthread_get_stackaddr_np(pthread_self());
                for (int k = 0; k < 40 && bp && ((unsigned long)bp & 7) == 0 && (unsigned long)bp >= lo
                                && (unsigned long)bp + 16 <= hi; k++) {
                    cand[nc++] = bp[1];
                    unsigned long *nb = (unsigned long *)(uintptr_t)bp[0];
                    if ((unsigned long)nb <= (unsigned long)bp) break;
                    bp = nb;
                }
                for (int k = 0; k < nc; k++) {
                    Dl_info di = {0}; const char *sn = "?", *im = "?";
                    if (dladdr((void *)(uintptr_t)cand[k], &di)) { sn = di.dli_sname ? di.dli_sname : "?"; im = di.dli_fname ? di.dli_fname : "?"; }
                    n = snprintf(b, sizeof b, "[host]   frame%d 0x%lx %s+0x%lx (%s)\n", k, cand[k], sn,
                                 di.dli_saddr ? cand[k] - (unsigned long)di.dli_saddr : 0UL, im);
                    ignored = write(g_errfd, b, (size_t)n);
                }
                n = snprintf(b, sizeof b, "[host]   rax %llx rbx %llx rbp %llx r8 %llx r9 %llx r10 %llx r11 %llx r15 %llx rflags %llx\n",
                             fss->__rax, fss->__rbx, fss->__rbp, fss->__r8, fss->__r9, fss->__r10, fss->__r11, fss->__r15, fss->__rflags);
                ignored = write(g_errfd, b, (size_t)n);
            }
            { unsigned long *sw = (unsigned long *)(uintptr_t)fss->__rsp;
              /* 96 words, clamped to this thread's stack top (a worker's frames are deeper than 24 words) */
              unsigned long swhi = (unsigned long)(uintptr_t)pthread_get_stackaddr_np(pthread_self());
              for (int k = 0; k < 96 && (unsigned long)(sw + k + 1) <= swhi; k++) { Dl_info di; unsigned long w = sw[k];
                if (dladdr((void *)(uintptr_t)w, &di) && di.dli_sname) {
                    n = snprintf(b, sizeof b, "[host]   stack[%d] 0x%lx %s+0x%lx (%s)\n", k, w, di.dli_sname, w - (unsigned long)di.dli_saddr, di.dli_fname ? di.dli_fname : "?");
                    ignored = write(g_errfd, b, (size_t)n); } } }
            a2x_report_swift_types((unsigned long)fss->__rsp, (unsigned long)(uintptr_t)pthread_get_stackaddr_np(pthread_self()));
            /* r15a: never dereference rip in the handler - at rip 0 the report itself faulted (nested fault) */
            unsigned char ip[8] = {0}; vm_size_t ipgot = 0;
            if (vm_read_overwrite(mach_task_self(), (vm_address_t)fss->__rip, sizeof ip, (vm_address_t)ip, &ipgot) || ipgot != sizeof ip)
                n = snprintf(b, sizeof b, "[host]   bytes@rip unreadable (rip 0x%llx)\n", (unsigned long long)fss->__rip);
            else
            n = snprintf(b, sizeof b, "[host]   bytes@rip %02x %02x %02x %02x %02x %02x %02x %02x\n",
                         ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
            ignored = write(g_errfd, b, (size_t)n);
        }
        n = snprintf(b, sizeof b, "[host]   rdi %016llx rsi %016llx rdx %016llx rcx %016llx r12 %016llx r13 %016llx r14 %016llx\n",
                     fss->__rdi, fss->__rsi, fss->__rdx, fss->__rcx, fss->__r12, fss->__r13, fss->__r14);
        ignored = write(g_errfd, b, (size_t)n);
    }
    /* WHICH STAGE OF THE LOAD. Five macOS 27 apps die here with pc 0x0 at faulting address 0x20 —
          in the host's own work, with nothing interpreted yet — and the line above cannot tell
          mapping from fixups from registration. The stage, the image and the record index are the
          whole diagnosis, exactly as the dladdr lines below are for a native callee.
        0x20 is libobjc's objc_class::data() offset (`bits`), so a Nil Class faults at EXACTLY 0x20.
        write() and snprintf() ONLY — and pthread_self(), which on Darwin is a leaf read of the
          thread's own TSD with no lock, strictly tamer than the dladdr() already called below. */
    unsigned long me = (unsigned long)(uintptr_t)pthread_self();
    int sg_ = g_stage;
    if (sg_ < 0 || sg_ >= ST_N) sg_ = 0;
    n = snprintf(b, sizeof b, "[host] load stage: %s  image %d  index %lu  %s\n",
                 g_stage_name[sg_], g_stage_img, g_stage_idx, g_stage_what);
    if (n > (int)sizeof b - 1) n = (int)sizeof b - 1;
    ignored = write(g_errfd, b, (size_t)n);
    if (g_stage_img >= 0 && (unsigned)g_stage_img < g_nimg) {
        n = snprintf(b, sizeof b, "[host]   image %d is %s\n", g_stage_img, g_img[g_stage_img].path);
        if (n > (int)sizeof b - 1) n = (int)sizeof b - 1;
        ignored = write(g_errfd, b, (size_t)n);
    }
    /* A ZERO GUEST pc DOES NOT ALWAYS MEAN "BEFORE THE GUEST RAN". a64_cur_pc is per-thread, so a
          framework's own worker thread — one the guest has never run on — reports 0 at any point in
          the run. Say which thread faulted and which published the stage, or the two cases read the
          same and the next hour goes to the wrong one. */
    n = snprintf(b, sizeof b, "[host] faulting thread %#lx; the stage was published by thread %#lx%s\n",
                 me, g_stage_thread,
                 me == g_stage_thread ? ""
                     : " — A DIFFERENT THREAD, so guest pc 0 may only mean this thread never interpreted");
    if (n > (int)sizeof b - 1) n = (int)sizeof b - 1;
    ignored = write(g_errfd, b, (size_t)n);
    const a64 *st = a64_cur_state;
    if (st) {
        for (int k = 0; k < 32; k += 4) {
            n = snprintf(b, sizeof b, "  x%-2d %016lx  x%-2d %016lx  x%-2d %016lx  x%-2d %016lx\n",
                         k, st->x[k], k + 1, k < 30 ? st->x[k + 1] : 0,
                         k + 2, k + 2 < 31 ? st->x[k + 2] : 0, k + 3, k + 3 < 31 ? st->x[k + 3] : 0);
            if (k + 3 < 31) ignored = write(g_errfd, b, (size_t)n);
        }
        n = snprintf(b, sizeof b, "  sp %016lx  lr %016lx\n", st->sp, st->x[30]);
        ignored = write(g_errfd, b, (size_t)n);
        /* NAME THE NATIVE CALLEE. A fault on `br x16` is almost always a native call, and the symbol is
              the whole diagnosis — without it the report is a hex address and a guess. */
        Dl_info di;
        if (st->x[16] && dladdr((const void *)(uintptr_t)st->x[16], &di) && di.dli_sname) {
            n = snprintf(b, sizeof b, "  x16 -> %s  (%s)\n", di.dli_sname,
                         di.dli_fname ? di.dli_fname : "?");
            ignored = write(g_errfd, b, (size_t)n);
        }
        if (st->x[30] && dladdr((const void *)(uintptr_t)st->x[30], &di) && di.dli_sname) {
            n = snprintf(b, sizeof b, "  lr  -> %s\n", di.dli_sname);
            ignored = write(g_errfd, b, (size_t)n);
        }
    }
    (void)ignored;
    _exit(139);
}
/* 10-29 ARM2X86_STACKDUMP=1: `kill -USR2 <pid>` makes the MAIN thread say where it is — guest pc, the native
      function it is inside (x16 of the last guest call), the guest frame chain (x29) and the native backtrace.
    `sample` cannot see this: the guest runs inside the exec fault's signal frame, so a WORKING Dock showed 40/56 main
      samples ending in _sigtramp. 21 NOWINDOW apps were one undifferentiated "alive" bucket.
    Every guest word is read with vm_read_overwrite, never dereferenced: a bad x29 must not become a fault here. */
extern unsigned int mach_task_self_;
extern int vm_read_overwrite(unsigned int, unsigned long, unsigned long, unsigned long, unsigned long *);
#include <execinfo.h>
static pthread_t g_dump_main; static int g_dump_main_set;
static int dump_rd(unsigned long a, unsigned long *v) {
    unsigned long got = 0;
    return a && !(a & 7) && vm_read_overwrite(mach_task_self_, a, 8, (unsigned long)v, &got) == 0 && got == 8;
}
static int dump_name(char *b, size_t bs, unsigned long a) {
    for (unsigned i = 0; i < g_nimg; i++)
        if (a >= g_img[i].vmlo && a < g_img[i].vmend) {
            const char *nm = strrchr(g_img[i].path, '/');
            return snprintf(b, bs, "%s+%#lx", nm ? nm + 1 : g_img[i].path, (unsigned long)(a - g_img[i].slide));
        }
    Dl_info di;
    if (dladdr((const void *)(uintptr_t)a, &di) && di.dli_sname)
        return snprintf(b, bs, "%s+%#lx", di.dli_sname, a - (unsigned long)di.dli_saddr);
    return snprintf(b, bs, "%#lx", a);
}
static void stackdump(int sig, siginfo_t *si, void *uc) {
    (void)si; (void)uc;
    if (g_dump_main_set && !pthread_main_np()) { pthread_kill(g_dump_main, sig); return; }
    char b[600], nm[300]; int n; ssize_t ig;
    dump_name(nm, sizeof nm, a2x_report_pc(0));
    n = snprintf(b, sizeof b, "[stack] guest pc %s\n", nm); ig = write(2, b, (size_t)n);
    const a64 *st = a64_cur_state;
    if (st) {
        Dl_info di;
        if (st->x[16] && dladdr((const void *)(uintptr_t)st->x[16], &di) && di.dli_sname) {
            n = snprintf(b, sizeof b, "[stack] in native %s\n", di.dli_sname); ig = write(2, b, (size_t)n); }
        dump_name(nm, sizeof nm, st->x[30] & 0x7fffffffffffUL);
        n = snprintf(b, sizeof b, "[stack] g lr %s\n", nm); ig = write(2, b, (size_t)n);
        unsigned long fp = st->x[29], nfp, lr;
        for (int k = 0; k < 24 && dump_rd(fp, &nfp) && dump_rd(fp + 8, &lr) && lr; k++) {
            dump_name(nm, sizeof nm, lr & 0x7fffffffffffUL);
            n = snprintf(b, sizeof b, "[stack] g%-2d %s\n", k, nm); ig = write(2, b, (size_t)n);
            if (nfp <= fp) break;
            fp = nfp;
        }
    }
    void *bt[28]; int nb = backtrace(bt, 28);
    for (int k = 1; k < nb; k++) {
        dump_name(nm, sizeof nm, (unsigned long)bt[k]);
        n = snprintf(b, sizeof b, "[stack] n%-2d %s\n", k, nm); ig = write(2, b, (size_t)n);
    }
    (void)ig;
}
/* B32s THE macOS 27 KERNEL REFUSES SOME sigreturns WITH EPERM, AND _sigtramp ANSWERS WITH ud2.
      Bare metal 10-30: WindowManager crash-looped 1,397 times (exit 139 -> SIGILL at _sigtramp+0x33). Measured with an
      errno-reporting trampoline: __sigreturn returned -1 errno 1 (EPERM) on the main thread and a worker in the same
      instant, every launch, after ~405 good returns; the token was intact (r12 at the crash = r12 at handler entry, and
      uctx ^ token matched the delivery). The published xnu sigreturn has no EPERM path at all (EINVAL only), so this is a
      27 kernel check that switches on per process. The state handed back was ordinary: cs 0x2b, canonical rip/rsp, mxcsr 0x1fa0.
    The fix is our own trampoline with _sigtramp's contract (rdi catcher, esi infostyle, edx sig, rcx siginfo, r8 uctx,
      r9 token). It calls __sigreturn exactly as before; only when the kernel refuses with EPERM does it restore the
      interrupted context itself: ymm0-15 (low + high halves), mxcsr, the x87 control word, all sixteen GPRs and rflags,
      then returns to rip. Nothing is written in the interrupted code's red zone (the three scratch words sit 128 bytes
      below its rsp). The signal mask needs no restore: SA_NODEFER with an empty sa_mask means the handler ran under the
      interrupted mask. A different failure, or a non-AVX context, still traps as _sigtramp would. */
struct a2x_ksigaction {
    void (*sa_sigaction_)(int, siginfo_t *, void *);
    void (*sa_tramp)(void *, int, int, siginfo_t *, void *, unsigned long);
    sigset_t sa_mask_;
    int sa_flags_;
};
extern int __sigaction(int, struct a2x_ksigaction *, struct sigaction *);
extern int __sigreturn(void *, int, unsigned long);
static volatile unsigned long g_uresume_n;
static __attribute__((noreturn, noinline)) void a2x_uc_resume(_STRUCT_MCONTEXT_AVX64 *mc) {
    __asm__ volatile(
        "vmovdqu %c[x0]+0(%%rdi), %%xmm0\n\t"
        "vinsertf128 $1, %c[h0]+0(%%rdi), %%ymm0, %%ymm0\n\t"
        "vmovdqu %c[x0]+16(%%rdi), %%xmm1\n\t"
        "vinsertf128 $1, %c[h0]+16(%%rdi), %%ymm1, %%ymm1\n\t"
        "vmovdqu %c[x0]+32(%%rdi), %%xmm2\n\t"
        "vinsertf128 $1, %c[h0]+32(%%rdi), %%ymm2, %%ymm2\n\t"
        "vmovdqu %c[x0]+48(%%rdi), %%xmm3\n\t"
        "vinsertf128 $1, %c[h0]+48(%%rdi), %%ymm3, %%ymm3\n\t"
        "vmovdqu %c[x0]+64(%%rdi), %%xmm4\n\t"
        "vinsertf128 $1, %c[h0]+64(%%rdi), %%ymm4, %%ymm4\n\t"
        "vmovdqu %c[x0]+80(%%rdi), %%xmm5\n\t"
        "vinsertf128 $1, %c[h0]+80(%%rdi), %%ymm5, %%ymm5\n\t"
        "vmovdqu %c[x0]+96(%%rdi), %%xmm6\n\t"
        "vinsertf128 $1, %c[h0]+96(%%rdi), %%ymm6, %%ymm6\n\t"
        "vmovdqu %c[x0]+112(%%rdi), %%xmm7\n\t"
        "vinsertf128 $1, %c[h0]+112(%%rdi), %%ymm7, %%ymm7\n\t"
        "vmovdqu %c[x0]+128(%%rdi), %%xmm8\n\t"
        "vinsertf128 $1, %c[h0]+128(%%rdi), %%ymm8, %%ymm8\n\t"
        "vmovdqu %c[x0]+144(%%rdi), %%xmm9\n\t"
        "vinsertf128 $1, %c[h0]+144(%%rdi), %%ymm9, %%ymm9\n\t"
        "vmovdqu %c[x0]+160(%%rdi), %%xmm10\n\t"
        "vinsertf128 $1, %c[h0]+160(%%rdi), %%ymm10, %%ymm10\n\t"
        "vmovdqu %c[x0]+176(%%rdi), %%xmm11\n\t"
        "vinsertf128 $1, %c[h0]+176(%%rdi), %%ymm11, %%ymm11\n\t"
        "vmovdqu %c[x0]+192(%%rdi), %%xmm12\n\t"
        "vinsertf128 $1, %c[h0]+192(%%rdi), %%ymm12, %%ymm12\n\t"
        "vmovdqu %c[x0]+208(%%rdi), %%xmm13\n\t"
        "vinsertf128 $1, %c[h0]+208(%%rdi), %%ymm13, %%ymm13\n\t"
        "vmovdqu %c[x0]+224(%%rdi), %%xmm14\n\t"
        "vinsertf128 $1, %c[h0]+224(%%rdi), %%ymm14, %%ymm14\n\t"
        "vmovdqu %c[x0]+240(%%rdi), %%xmm15\n\t"
        "vinsertf128 $1, %c[h0]+240(%%rdi), %%ymm15, %%ymm15\n\t"
        "ldmxcsr %c[mx](%%rdi)\n\t"
        "fldcw %c[cw](%%rdi)\n\t"
        "movq %c[rsp_](%%rdi), %%rax\n\t"
        "leaq -152(%%rax), %%rax\n\t"
        "movq %c[rip_](%%rdi), %%rcx\n\t"
        "movq %%rcx, 16(%%rax)\n\t"
        "movq %c[rfl_](%%rdi), %%rcx\n\t"
        "movq %%rcx, 8(%%rax)\n\t"
        "movq %c[rdi_](%%rdi), %%rcx\n\t"
        "movq %%rcx, 0(%%rax)\n\t"
        "movq %%rax, %%rsp\n\t"
        "movq %c[rax](%%rdi), %%rax\n\t"
        "movq %c[rbx](%%rdi), %%rbx\n\t"
        "movq %c[rcx](%%rdi), %%rcx\n\t"
        "movq %c[rdx](%%rdi), %%rdx\n\t"
        "movq %c[rsi](%%rdi), %%rsi\n\t"
        "movq %c[rbp](%%rdi), %%rbp\n\t"
        "movq %c[r8](%%rdi), %%r8\n\t"
        "movq %c[r9](%%rdi), %%r9\n\t"
        "movq %c[r10](%%rdi), %%r10\n\t"
        "movq %c[r11](%%rdi), %%r11\n\t"
        "movq %c[r12](%%rdi), %%r12\n\t"
        "movq %c[r13](%%rdi), %%r13\n\t"
        "movq %c[r14](%%rdi), %%r14\n\t"
        "movq %c[r15](%%rdi), %%r15\n\t"
        "popq %%rdi\n\t"
        "popfq\n\t"
        "retq $128\n\t"
        :
        : "D"(mc),
          [x0] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __fs.__fpu_xmm0)),
          [h0] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __fs.__fpu_ymmh0)),
          [mx] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __fs.__fpu_mxcsr)),
          [cw] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __fs.__fpu_fcw)),
          [rsp_] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rsp)),
          [rip_] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rip)),
          [rfl_] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rflags)),
          [rdi_] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rdi)),
          [rax] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rax)),
          [rbx] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rbx)),
          [rcx] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rcx)),
          [rdx] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rdx)),
          [rsi] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rsi)),
          [rbp] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__rbp)),
          [r8] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__r8)),
          [r9] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__r9)),
          [r10] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__r10)),
          [r11] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__r11)),
          [r12] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__r12)),
          [r13] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__r13)),
          [r14] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__r14)),
          [r15] "i"(offsetof(_STRUCT_MCONTEXT_AVX64, __ss.__r15))
        : "memory");
    __builtin_unreachable();
}
static void a2x_sigtramp(void *catcher, int style, int sig, siginfo_t *si, void *uc, unsigned long tok) {
    ((void (*)(int, siginfo_t *, void *))catcher)(sig, si, uc);
    int r = __sigreturn(uc, style, tok);
    int e = errno;
    ucontext_t *u = (ucontext_t *)uc;
    if (r == -1 && e == EPERM && u && u->uc_mcontext && u->uc_mcsize == sizeof(_STRUCT_MCONTEXT_AVX64)) {
        unsigned long k = __atomic_add_fetch(&g_uresume_n, 1, __ATOMIC_RELAXED);
        if (k <= 3 || g_trace_tramp > 0) {   /* success must not be silent, but a crash loop must not fill the report */
            char b[160];
            int n = snprintf(b, sizeof b, "[sigret] kernel refused sigreturn (EPERM), resumed in user space: sig %d rip 0x%llx (%lu)\n",
                             sig, ((_STRUCT_MCONTEXT_AVX64 *)u->uc_mcontext)->__ss.__rip, k);
            if (n > (int)sizeof b - 1) n = (int)sizeof b - 1;
            ssize_t ig = write(2, b, (size_t)n); (void)ig;
        }
        a2x_uc_resume((_STRUCT_MCONTEXT_AVX64 *)u->uc_mcontext);
    }
    char b[200];
    int n = snprintf(b, sizeof b, "[sigret] FAILED r=%d errno %d sig %d style %d uc %p mcsize %lu\n",
                     r, e, sig, style, uc, u ? (unsigned long)u->uc_mcsize : 0UL);
    if (n > (int)sizeof b - 1) n = (int)sizeof b - 1;
    ssize_t ig = write(2, b, (size_t)n); (void)ig;
    a2x_stop("returning from a signal handler failed", ""); __builtin_trap();
}
static void install_fault_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = fault;
    /* SA_NODEFER: a recovered call runs guest code INSIDE the handler, and that guest code may itself
          call back out into another guest function. Without it the second fault kills the process. */
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    g_trace_tramp = A2X_DBGENV("ARM2X86_TRACE_TRAMP") ? 1 : 0;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    sigaction(SIGILL, &sa, 0);
    /* 11-02: abort() is the WindowServer death on the stock-27 bench; without this the host says nothing */
    sigaction(SIGABRT, &sa, 0);
    /* the re-seal is only trusted if a single-step trap really comes back to us in THIS process */
    if (!A2X_DBGENV("ARM2X86_NO_RESEAL")) {
        struct sigaction st_;
        memset(&st_, 0, sizeof st_);
        st_.sa_sigaction = a2x_trap;
        st_.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(SIGTRAP, &st_, 0);
        a2x_trap_probe = 1;
        __asm__ volatile("pushfq\n\torq $0x100, (%%rsp)\n\tpopfq\n\tnop\n\tnop" ::: "memory", "cc");
        if (a2x_trap_probe == 2) a2x_reseal_on = 1;
        else {
            fprintf(stderr, "[host] re-seal OFF: single-step probe got no SIGTRAP (state %d)\\n", a2x_trap_probe);
            struct sigaction dfl; memset(&dfl, 0, sizeof dfl); dfl.sa_handler = SIG_DFL; sigaction(SIGTRAP, &dfl, 0);
        }
        a2x_trap_probe = 0;
    }
    if (A2X_DBGENV("ARM2X86_STACKDUMP")) {
        if (pthread_main_np()) { g_dump_main = pthread_self(); g_dump_main_set = 1; }
        struct sigaction sd; memset(&sd, 0, sizeof sd); sd.sa_sigaction = stackdump; sd.sa_flags = SA_SIGINFO | SA_RESTART;
        sigaction(SIGUSR2, &sd, 0);
    }
}

/* ── dependency walk, factored out of main so a late load runs the SAME code the executable's dependents do ── */
#include "aot_dependency.h"
static int a2x_aot_dependency(const char *path, uint64_t *preferred) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) || st.st_size < 8 || (uint64_t)st.st_size > SIZE_MAX) { close(fd); return 0; }
    size_t n = (size_t)st.st_size;
    uint8_t *p = malloc(n);
    size_t got = 0;
    while (p && got < n) {
        ssize_t nr = read(fd, p + got, n - got);
        if (nr < 0 && errno == EINTR) continue;
        if (nr <= 0) break;
        got += (size_t)nr;
    }
    close(fd);
    if (!p || got != n) { free(p); return 0; }
    int yes = a2x_aot_dependency_bytes(p, n);
    if (yes) {
        size_t an = 0;
        const uint8_t *arm = slice_arm64(p, n, &an);
        yes = 0;
        if (arm && an >= sizeof(struct mh64)) {
            const struct mh64 *mh = (const struct mh64 *)arm;
            size_t at = sizeof *mh;
            if (mh->sizeofcmds <= an - at) {
                size_t end = at + mh->sizeofcmds;
                for (uint32_t i = 0; i < mh->ncmds && end - at >= sizeof(struct lc); i++) {
                    const struct lc *lc = (const struct lc *)(arm + at);
                    if (lc->cmdsize < sizeof *lc || lc->cmdsize > end - at) break;
                    if (lc->cmd == LC_SEGMENT_64_ && lc->cmdsize >= sizeof(struct seg64)) {
                        const struct seg64 *seg = (const struct seg64 *)lc;
                        if (!memcmp(seg->segname, "__TEXT\0", 7)) { *preferred = seg->vmaddr; yes = 1; break; }
                    }
                    at += lc->cmdsize;
                }
            }
        }
    }
    free(p);
    return yes;
}

static int scan_deps(unsigned from, uint64_t *next_slide, int trace, unsigned long *ndlfail,
                     unsigned long *nhardfail, int *want_libcxx) {
    for (unsigned i = from; i < g_nimg; i++) {
        const struct image *im = &g_img[i];
        const struct mh64 *mh;
        size_t fl = 0;
        const uint8_t *f = slice_arm64(im->file, im->flen, &fl);
        mh = (const struct mh64 *)f;
        char exe_path[1024];
        snprintf(exe_path, sizeof exe_path, "%s", im->path);
        stage(ST_DEP_SCAN, (int)i, 0, im->path);
        /* BOUND THIS WALK TOO — it is the same unbounded ncmds/cmdsize loop load_guest had, over the
              same file, and a desynchronised command here builds a dependency path out of garbage. */
        if (!f || (size_t)mh->sizeofcmds > fl - sizeof *mh) {
            fprintf(stderr, "[host] %s: load commands do not fit its slice on the second pass\n",
                    im->path);
            return 3;
        }
        const uint8_t *lc_end = f + sizeof *mh + mh->sizeofcmds;
        const struct lc *c = (const struct lc *)(f + sizeof *mh);
        for (uint32_t k = 0; k < mh->ncmds; k++) {
            if ((const uint8_t *)c + sizeof *c > lc_end || c->cmdsize < sizeof *c
                || (c->cmdsize & 3) || (const uint8_t *)c + c->cmdsize > lc_end) break;
            if (c->cmd == LC_LOAD_DYLIB_ || c->cmd == LC_LOAD_WEAK_ || c->cmd == LC_REEXPORT_) {
                const struct dylib_cmd *d = (const struct dylib_cmd *)c;
                /* name_off IS AN OFFSET INSIDE THIS COMMAND, and the install name must be
                      NUL-terminated inside it. Past its end the "path" is whatever follows in the
                      file, and bundle_relative() would build a path out of it and stat() that. */
                if (d->cmdsize < sizeof *d || d->name_off < sizeof *d || d->name_off >= d->cmdsize
                    || !memchr((const char *)c + d->name_off, 0, d->cmdsize - d->name_off)) {
                    fprintf(stderr, "[host] %s: dependency %u has an unterminated install name "
                                    "(name_off %u, cmdsize %u) — skipped\n",
                            im->path, k, d->name_off, d->cmdsize);
                    c = (const struct lc *)((const uint8_t *)c + c->cmdsize);
                    continue;
                }
                const char *nm = (const char *)c + d->name_off;
                char rp[1024];
                if (bundle_relative(nm, exe_path, g_img[0].path, rp, sizeof rp)) {
                    struct stat ds;
                    int already = 0;
                    for (unsigned j = 0; j < g_nimg; j++) if (!strcmp(g_img[j].path, rp)) already = 1;
                    /* A BUNDLE-RELATIVE DEPENDENCY THAT IS NOT IN THE BUNDLE IS DROPPED ENTIRELY: it
                          is not loaded as a guest and, because the name does not start with '/', it is
                          not dlopen'd either. Every bind to it then resolves to 0 and only the import
                          count says anything. Measured shape: FindMy's one @rpath dependency,
                          FindMyAppCore.framework, which IS in the bundle — so a stat() miss here means
                          the path rule is wrong, not that the framework is absent. Say it. */
                    if (!already && stat(rp, &ds)) {
                        fprintf(stderr, "[host] %s: %s resolved to %s, which does not exist — NOT "
                                        "loaded and NOT dlopen'd, so every import from it stays 0\n",
                                im->path, nm, rp);
                    }
                    if (!already && !stat(rp, &ds)) {
                        snprintf(g_stage_path, sizeof g_stage_path, "%s", rp);
                        stage(ST_DEP_LOAD, (int)g_nimg, 0, g_stage_path);
                        if (load_guest(rp, (*next_slide), trace, 0)) return 3;
                        /* one slide per image, rounded well clear of the last one's end */
                        (*next_slide) = (g_img[g_nimg - 1].vmend + 0xffffffUL) & ~0xffffffUL;
                        (*next_slide) -= 0;
                    }
                } else if (nm[0] == '/') {
                    uint64_t preferred = 0;
                    if (a2x_aot_dependency(nm, &preferred)) {
                        int already = 0;
                        for (unsigned j = 0; j < g_nimg; j++)
                            if (!strcmp(g_img[j].path, nm)) already = 1;
                        if (!already) {
                            fprintf(stderr, "[host] translated dependency: loading original ARM slice %s\n", nm);
                            stage(ST_DEP_LOAD, (int)g_nimg, 0, nm);
                            /* The retained ARM slice may already have a nonzero preferred base. */
                            if (load_guest(nm, *next_slide - preferred, trace, 0)) return 3;
                            *next_slide = (g_img[g_nimg - 1].vmend + 0xffffffUL) & ~0xffffffUL;
                        }
                        c = (const struct lc *)((const uint8_t *)c + c->cmdsize);
                        continue;
                    }
                    if (!strcmp(nm, "/usr/lib/libc++.1.dylib")) (*want_libcxx) = 1;
                    stage(ST_DLOPEN, (int)i, k, nm);
                    /* A FAILED dlopen WAS SILENT UNLESS ARM2X86_HOST_TRACE HAPPENED TO BE SET. Every
                          import from a framework that did not load then resolves to 0, and the only trace of
                          it was one number in the missing count — which is how 235 NULL superclass pointers
                          could present as a single anonymous SIGSEGV with no guest pc. A dependency we
                          cannot load is said out loud, every run.
                        A weak dependency is ALLOWED to be absent, so it is counted but only printed under
                          trace; a non-weak one is a fact about this run either way. */
                    char gp_[1024];
                    void *dh_ = dlopen(nm, RTLD_LAZY | RTLD_GLOBAL);
                    const char *de_ = dh_ ? 0 : dlerror();   /* read before anything else can reset it */
                    if (!dh_ && a2x_sysdylib_guest_path(nm, gp_, sizeof gp_)) {
                        /* 11-02 1102h no x86_64 slice anywhere: the file is guest code, exactly like a bundle framework */
                        int already = 0;
                        for (unsigned j = 0; j < g_nimg; j++) if (!strcmp(g_img[j].path, gp_)) already = 1;
                        if (!already) {
                            fprintf(stderr, "[host] %s: system dylib %s has no x86_64 slice — loaded as a guest image from %s\n",
                                    im->path, nm, gp_);
                            snprintf(g_stage_path, sizeof g_stage_path, "%s", gp_);
                            stage(ST_DEP_LOAD, (int)g_nimg, 0, g_stage_path);
                            if (load_guest(gp_, (*next_slide), trace, 0)) return 3;
                            (*next_slide) = (g_img[g_nimg - 1].vmend + 0xffffffUL) & ~0xffffffUL;
                        }
                    } else if (!dh_) {
                        const char *e = de_;
                        int weak = (c->cmd == LC_LOAD_WEAK_);
                        (*ndlfail)++;
                        if (!weak) (*nhardfail)++;
                        if (!weak || trace)
                            fprintf(stderr, "[host] dlopen %s%s FAILED: %s\n", weak ? "(weak) " : "", nm,
                                    e ? e : "(no reason given)");
                    }
                }
            }
            c = (const struct lc *)((const uint8_t *)c + c->cmdsize);
        }
    }
    return 0;
}

/* ── steps 3-4 of startup (fixups, audit, ObjC/Swift/TLV registration) for images [first, g_nimg) ──
   Startup runs it with first = 0. A late guest load runs it with the index of the first image it added. */
/* Seal the code sections of images [first, g_nimg): copy to the alias, mark, then drop the original to
   PROT_NONE. Only pages that lie wholly inside a run of code sections are sealed, so the Mach-O header page
   and any page shared with cstrings, method names or unwind info stay readable. Call it after fixups. */
static void a2x_seal_code(unsigned first) {
    if (A2X_DBGENV("ARM2X86_NO_SEAL")) return;
    if (!a2x_alias_delta) {
        void *w = mmap((void *)A2X_ALIAS_BASE, A2X_GUEST_LEN, PROT_NONE,
                       MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
        if (w == MAP_FAILED) {
            fprintf(stderr, "[host] code seal OFF: no address space for the alias window (errno %d)\n", errno);
            return;
        }
        void *t = mmap(0, A2X_GUEST_LEN >> A2X_PG_SHIFT, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (t == MAP_FAILED) { munmap(w, A2X_GUEST_LEN); fprintf(stderr, "[host] code seal OFF: no page table\n"); return; }
        a2x_pg_sealed = t;
        void *tc = mmap(0, A2X_GUEST_LEN >> A2X_PG_SHIFT, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        a2x_pg_count = tc == MAP_FAILED ? 0 : tc;      /* no counter table = permanent unseal, as before */
        void *td = mmap(0, A2X_GUEST_LEN >> A2X_PG_SHIFT, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        a2x_pg_disc = td == MAP_FAILED ? 0 : td;       /* r13m: no table = originals are kept (the old copy) */
        void *tr = mmap(0, (A2X_GUEST_LEN >> A2X_PG_SHIFT) * sizeof(unsigned short), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        a2x_pg_ref = tr == MAP_FAILED ? 0 : tr;        /* r14q: no table = the old global pending slots */
        a2x_alias_delta = A2X_ALIAS_BASE - A2X_GUEST_BASE;
    }
    unsigned long npg = 0;
    for (unsigned i = first; i < g_nimg; i++) {
        struct image *im = &g_img[i];
        for (unsigned k = 0; k < im->ncode; k++) {
            uint64_t a = im->code_a[k], e = im->code_e[k];
            while (k + 1 < im->ncode && im->code_a[k + 1] <= e + 64) { if (im->code_e[k + 1] > e) e = im->code_e[k + 1]; k++; }
            /* 11-01 OUTWARD: a partial page is code too. Inward rounding left remoted with zero sealed pages. */
            /* 11-01 t22: HIGH edge inward — __cstring can share it and the kernel's copyin cannot fault-retry */
            unsigned long lo = (unsigned long)(a & ~0xfffUL), hi = (unsigned long)(e & ~0xfffUL);
            if (hi <= lo || lo < A2X_GUEST_BASE || hi > A2X_GUEST_BASE + A2X_GUEST_LEN) continue;
            unsigned long al = lo + a2x_alias_delta, len = hi - lo;
            /* 11-02 r13m THE ALIAS SHARES THE ORIGINAL'S PAGES (it was a memcpy: every sealed page dirty twice), then
                  the original is replaced by untouched PROT_NONE memory, so the code lives once. The alias holds the
                  very pages the original had, so there is no equality question. A data access that unseals a released
                  page copies it back from the alias first (fault(), a2x_pg_disc). ARM2X86_NO_SEALSHARE=1 = the copy. */
            int shared = 0;
            if (a2x_pg_disc && !A2X_DBGENV("ARM2X86_NO_SEALSHARE")) {
                mach_vm_address_t t = al; vm_prot_t cu = 0, mx = 0;
                if (mach_vm_remap(mach_task_self(), &t, len, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, mach_task_self(),
                                  (mach_vm_address_t)lo, FALSE, &cu, &mx, VM_INHERIT_COPY) == KERN_SUCCESS && t == al
                    && (cu & VM_PROT_READ))
                    shared = 1;
            }
            if (!shared) {
                if (mprotect((void *)al, len, PROT_READ | PROT_WRITE)) continue;
                memcpy((void *)al, (const void *)lo, len);
            }
            mprotect((void *)al, len, PROT_READ);
            unsigned char *pg = a2x_pg_sealed + ((lo - A2X_GUEST_BASE) >> A2X_PG_SHIFT);
            memset(pg, 1, len >> A2X_PG_SHIFT);                 /* mark first: a reader that sees 1 reads the finished copy */
            if (mprotect((void *)lo, len, PROT_NONE)) { memset(pg, 0, len >> A2X_PG_SHIFT); continue; }
            if (shared) {
                /* mark first: an unseal that races the release copies the (identical) alias bytes back */
                unsigned char *dz = a2x_pg_disc + ((lo - A2X_GUEST_BASE) >> A2X_PG_SHIFT);
                memset(dz, 1, len >> A2X_PG_SHIFT);
                void *r = mmap((void *)lo, len, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
                if (r != (void *)lo) memset(dz, 0, len >> A2X_PG_SHIFT);
            }
            npg += len >> A2X_PG_SHIFT;
        }
    }
    /* pid/ppid/path: a boot with no ssh is read from the serial console alone (11-01 xpcproxy loop) */
    /* 11-05: every exec printed this to the console; at serial speed that is milliseconds per process */
    if (A2X_DBGENV("ARM2X86_HOST_TRACE")) fprintf(stderr, "[host] sealed %lu code page(s) PROT_NONE (images %u..%u) pid %d ppid %d %s\n", npg, first,
            g_nimg ? g_nimg - 1 : 0, (int)getpid(), (int)getppid(), g_nimg ? g_img[0].path : "?");
    if (A2X_DBGENV("ARM2X86_FOOTPRINT")) {      /* r13m diag: phys_footprint right after sealing (the jetsam number) */
        task_vm_info_data_t vi; mach_msg_type_number_t vc = TASK_VM_INFO_COUNT;
        if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vi, &vc) == KERN_SUCCESS)
            fprintf(stderr, "[host] footprint %.2f MB after sealing (peak %.2f MB) pid %d\n",
                    vi.phys_footprint / 1048576.0, vi.ledger_phys_footprint_peak / 1048576.0, (int)getpid());
    }
}

static int finish_images(unsigned first, uint64_t text, int trace) {
    /* 10-31 new guest code: every decode cache starts a new epoch (fixups below rewrite bytes of these images) */
    { extern unsigned a64_code_gen; __atomic_add_fetch(&a64_code_gen, 1, __ATOMIC_RELEASE); }
    /* ── 3. fixups for every image, now that all exports are known ── */
    struct ctx cx;
    memset(&cx, 0, sizeof cx);
    cx.text = text;
    for (unsigned i = first; i < g_nimg; i++) {
        stage(ST_FIXUPS, (int)i, 0, g_img[i].path);
        cx.cur = i; memset(cx.dlh, 0, sizeof cx.dlh); memset(cx.dlh_done, 0, sizeof cx.dlh_done);
        int rc = a64_walk_fixups_slide(g_img[i].file, g_img[i].flen, g_img[i].slide, apply, &cx);
        if (rc && rc != -2) {       /* -2 is a classic image with LC_DYLD_INFO instead of chained fixups */
            fprintf(stderr, "[host] fixups failed for %s rc=%d\n", g_img[i].path, rc);
            return 5;
        }
    }
    if (trace || cx.nmissing)
        fprintf(stderr, "[host] %u image(s): %lu rebases, %lu imports bound, %lu missing%s%s\n",
                g_nimg, cx.nrebase, cx.nbind, cx.nmissing,
                cx.first_missing ? ", first: " : "", cx.first_missing ? cx.first_missing : "");
    /* AN UNRESOLVED CLASS IMPORT IS THE 0x20 CANDIDATE AND IT USED TO BE ONE NUMBER IN A TOTAL.
          The slot stays 0, the registration below hands libobjc a Nil Class, and libobjc reads
          class->bits at +0x20. Named here, every one of them, before the stage that dereferences it. */
    if (cx.nmissing_cls)
        fprintf(stderr, "[host] %lu of those missing imports are _OBJC_CLASS_$_ / _OBJC_METACLASS_$_ "
                        "symbols — each leaves a NULL class pointer in a class record, and libobjc "
                        "reads class->bits at +0x20, which is the measured faulting address\n",
                cx.nmissing_cls);
    for (unsigned long k = 0; k < cx.nmissing && k < MISSING_MAX; k++)
        fprintf(stderr, "[host]   missing import: %s\n", cx.missing[k] ? cx.missing[k] : "(null)");
    if (cx.nmissing > MISSING_MAX)
        fprintf(stderr, "[host]   ... and %lu more (first %d named)\n",
                cx.nmissing - MISSING_MAX, MISSING_MAX);

    /* ── 3b. the audit: every record the registration below will dereference, checked first ── */
    unsigned long nbadrec = 0;
    for (unsigned i = first; i < g_nimg; i++) {
        stage(ST_AUDIT, (int)i, 0, g_img[i].path);
        nbadrec += audit_image(&g_img[i], trace);
    }
    if (nbadrec) {
        const char *strict = A2X_DBGENV("ARM2X86_HOST_AUDIT");
        fprintf(stderr, "[host] %lu ObjC record(s) across %u image(s) cannot be dereferenced safely%s\n",
                nbadrec, g_nimg,
                (strict && !strcmp(strict, "strict")) ? ""
                    : " — registering anyway; ARM2X86_HOST_AUDIT=strict refuses instead");
        if (strict && !strcmp(strict, "strict")) return 8;
    }

    /* ── 4. ObjC: publish every guest class, category, protocol and selector to the native runtime ──
        AFTER FIXUPS, NEVER BEFORE. A class structure is full of bound pointers — its metaclass, its method
          lists, its superclass — so registering it unfixed hands the runtime addresses of nothing.
        Protocols first: a conforming class needs its protocols already registered. */
    extern void __arm2x86_objc_protocols(unsigned long, unsigned long, unsigned long, unsigned long);
    extern void __arm2x86_objc_register(unsigned long, unsigned long, unsigned long, unsigned long,
                                        unsigned long, unsigned long, unsigned long, unsigned long);
    extern void __arm2x86_objc_ro_sweep(unsigned long, unsigned long, unsigned long, unsigned long,
                                        unsigned long, unsigned long);
    /* SELECTOR REFERENCES MUST BECOME REAL SELECTORS. Each __objc_selrefs slot holds a pointer to the
          guest's own method-name STRING, and the native runtime needs a registered SEL — the two are not
          interchangeable even though both are pointers. Left raw, class_getInstanceMethod finds nothing and
          the bridge reports "no method / type encoding for selector length" on a plain native NSString whose
          isa was perfectly correct. The per-app runtime resolves these at translate time; the host does it
          here, which is the same work without the build.
        Registered from the STRING the slot points at, after fixups have made that pointer valid. */
    unsigned long nsel = 0, nbadsel = 0;
    for (unsigned i = first; i < g_nimg; i++) {
        const struct objc_secs *o = &g_img[i].objc;
        if (!o->selrefs) continue;
        stage(ST_SELREFS, (int)i, 0, g_img[i].path);
        uint64_t *sl = (uint64_t *)(uintptr_t)o->selrefs;
        for (uint64_t k = 0; k < o->nselref; k++) {
            stage_idx((unsigned long)k);
            const char *nm = (const char *)(uintptr_t)sl[k];
            if (!nm) continue;
            /* A SELREF SLOT HOLDS A POINTER TO THE GUEST'S OWN METHOD-NAME STRING, so it must point
                  INSIDE a mapped guest image. Anything else is a slot whose fixup did not land, and
                  sel_registerName() would read a C string from an address that is not ours — for as
                  long as it takes to find a zero byte. Named and skipped. */
            if (!guest_mapped((uint64_t)(uintptr_t)nm, 1)) {
                if (nbadsel < 8)
                    fprintf(stderr, "[host] %s __objc_selrefs[%llu] = 0x%llx is not inside any mapped "
                                    "guest image — not registered\n",
                            g_img[i].path, (unsigned long long)k, (unsigned long long)(uintptr_t)nm);
                nbadsel++;
                continue;
            }
            sl[k] = (uint64_t)(uintptr_t)sel_registerName(nm);
            nsel++;
        }
    }
    if (nbadsel)
        fprintf(stderr, "[host] %lu selector reference(s) were not registered (first 8 named above) — "
                        "class_getInstanceMethod will find nothing for each of them\n", nbadsel);

    unsigned long nobjc = 0, nref = 0;
    for (unsigned i = first; i < g_nimg; i++) {
        const struct objc_secs *o = &g_img[i].objc;
        if (o->protolist || o->protorefs) {
            stage(ST_OBJC_PROTO, (int)i, 0, g_img[i].path);
            __arm2x86_objc_protocols(o->protolist, o->nproto, o->protorefs, o->nprotoref);
        }
    }
    /* FRAMEWORKS FIRST, THE EXECUTABLE LAST — REGISTRATION ORDER IS A DEPENDENCY ORDER.
          MEASURED 10-26 on Books: 17 of its classes name superclasses that are GUEST RECORDS inside its own
          embedded frameworks (0x1473d69e8, 0x14535a9f8, 0x14a0415a0 — all in the 0x140000000 framework
          range), and this loop ran image 0, the executable, FIRST. So every one of those superclasses did
          not exist yet, registration reported "its superclass is the guest record ..., which no image has
          registered" and gave up, and libobjc then read class->bits at +0x20 on a half-built class:
          SIGSEGV at exactly 0x20 with guest pc 0, because no guest instruction had run yet.
        g_img is in LOAD order (0 = the executable, 1.. = the frameworks it pulled in), and a framework
          cannot depend on the executable that loads it — so DESCENDING index is the dependency order.
        This does NOT fix a mutual dependency between two frameworks, and that is not claimed: it would
          need a fixpoint across all images. Named here so the next failure of this shape is not read as
          this one already being handled. */
    for (unsigned k = g_nimg; k-- > first;) {
        const unsigned i = k;
        const struct objc_secs *o = &g_img[i].objc;
        /* MEASURED on macOS 27: __objc_classrefs is ABSENT from all five of the apps that fault here
              (FindMy, Maps, Reminders, Shortcuts, Notes) and from every working one checked beside
              them — so this guard rests on classlist/catlist alone, and an image carrying ONLY
              __objc_superrefs would be skipped with its super sends left pointing at guest records.
              Said out loud rather than silently skipped. */
        /* an image whose only ObjC content is stub-class categories still has those to hand over */
        if (!o->classlist && !o->catlist && !o->classrefs && o->ncat2) {
            extern void __arm2x86_objc_register_stubcats(unsigned long, unsigned long);
            __arm2x86_objc_register_stubcats(o->catlist2, o->ncat2);
        }
        if (!o->classlist && !o->catlist && !o->classrefs) {
            if (o->nsuperref)
                fprintf(stderr, "[host] %s has %llu __objc_superrefs but no class list — its super "
                                "sends are NOT rewritten\n",
                        g_img[i].path, (unsigned long long)o->nsuperref);
            continue;
        }
        stage(ST_OBJC_CLASS, (int)i, 0, g_img[i].path);
        __arm2x86_objc_register(o->classlist, o->nclass, o->catlist, o->ncat,
                                o->classrefs, o->nclassref, o->superrefs, o->nsuperref);
        if (o->ncat2) {
            extern void __arm2x86_objc_register_stubcats(unsigned long, unsigned long);
            __arm2x86_objc_register_stubcats(o->catlist2, o->ncat2);
        }
        /* 10-30 fill the memory-return IMP table from EVERY class_ro_t the image owns (see objc_bridge.c) */
        __arm2x86_objc_ro_sweep(o->cname_a, o->cname_n, o->rconst_a, o->rconst_n, o->rdata_a, o->rdata_n);
        nobjc += o->nclass; nref += o->nclassref;
    }
    if (trace) fprintf(stderr, "[host] ObjC: %lu guest class(es), %lu class ref(s), %lu selector(s) registered\n",
                       nobjc, nref, nsel);

    /* ── Swift metadata and thread-locals, for the same reason: dyld never saw these images ── */
    extern void __arm2x86_swift_register(unsigned long, unsigned long, unsigned long, unsigned long,
                                          unsigned long, unsigned long);
    extern void __arm2x86_tlv_register(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
    for (unsigned i = first; i < g_nimg; i++) {
        const struct objc_secs *o = &g_img[i].objc;
        if (o->nsw_proto || o->nsw_types || o->nsw_protos) {
            stage(ST_SWIFT, (int)i, 0, g_img[i].path);
            __arm2x86_swift_register(o->sw_proto, o->nsw_proto, o->sw_types, o->nsw_types,
                                     o->sw_protos, o->nsw_protos);
            if (trace) fprintf(stderr, "[host] Swift: %llu conformance / %llu type / %llu protocol record(s)\n",
                               (unsigned long long)(o->nsw_proto / 4), (unsigned long long)(o->nsw_types / 4),
                               (unsigned long long)(o->nsw_protos / 4));
        }
        if (o->ntvars) {
            /* the template is __thread_data followed by __thread_bss; the total size covers both, and
                  __thread_bss has no file content so only the data part is copied from. */
            uint64_t lo = o->tdata ? o->tdata : o->tbss;
            uint64_t hi = o->tbss ? o->tbss + o->tbss_size : o->tdata + o->tdata_size;
            /* __thread_vars WITH NO TEMPLATE: tlv.c then calloc()s a ONE-byte block and
                  __arm2x86_tlv_get() returns block + 16 + offset out of it — a heap write past the end
                  on the first access to any thread_local, far from here and with nothing to connect
                  the two. A descriptor section without its data is not registerable; say so. */
            if (!lo || hi <= lo) {
                fprintf(stderr, "[host] %s has %llu thread-local variable(s) but no "
                                "__thread_data/__thread_bss template — NOT registered\n",
                        g_img[i].path, (unsigned long long)o->ntvars);
            } else {
            stage(ST_TLV, (int)i, 0, g_img[i].path);
            __arm2x86_tlv_register(o->tvars, o->ntvars, lo, o->tdata_size, hi - lo);
            if (trace) fprintf(stderr, "[host] thread-locals: %llu variable(s)\n",
                               (unsigned long long)o->ntvars);
            }
        }
    }
    return 0;
}

/* ── __init_offsets / __mod_init_func of images [first, g_nimg). Startup: first = 0 on the main thread, whose guest
   stack step 5 made. A late load reaches it on ANY thread, so the thread gets an arm64 stack the way the native->guest
   callback door gives one (cb_host.c): __arm2x86_ensure_stack(), then xs[31] = __arm_sp. On the main thread it is a no-op. */
extern void __arm2x86_ensure_stack(void);
static void run_static_inits(unsigned first, int gargc, char **gargv, char **envp, int trace) {
    __arm2x86_ensure_stack();
    if (!A2X_DBGENV("ARM2X86_NO_INITS")) {
        char **apple = envp; while (apple && *apple) apple++;
        if (apple) apple++;
        for (unsigned ii = g_nimg; ii-- > first;) {
            const struct image *im = &g_img[ii];
            unsigned long list[1024]; unsigned nl = 0;
            for (uint64_t k = 0; k < im->objc.ninitoff && nl < 1024; k++) {
                uint32_t off; memcpy(&off, (const void *)(uintptr_t)(im->objc.initoff + k * 4), 4);
                list[nl++] = im->text_vmaddr + im->slide + off;
            }
            for (uint64_t k = 0; k < im->objc.nmodinit && nl < 1024; k++) {
                unsigned long f; memcpy(&f, (const void *)(uintptr_t)(im->objc.modinit + k * 8), 8);
                f &= 0x0000ffffffffffffUL;                      /* an arm64e pointer may still carry its signature */
                if (f) list[nl++] = f;
            }
            if (im->objc.ninitoff + im->objc.nmodinit > 1024)
                fprintf(stderr, "[host] %s has %llu static initializers; only the first 1024 run\n", im->path,
                        (unsigned long long)(im->objc.ninitoff + im->objc.nmodinit));
            if (trace && nl) fprintf(stderr, "[host] %u static initializer(s) in %s\n", nl, im->path);
            for (unsigned k = 0; k < nl; k++) {
                unsigned long ixs[32]; memset(ixs, 0, sizeof ixs);
                _Alignas(16) unsigned char ivs[32 * 16]; memset(ivs, 0, sizeof ivs);
                ixs[0] = (unsigned long)gargc; ixs[1] = (unsigned long)(uintptr_t)gargv;
                ixs[2] = (unsigned long)(uintptr_t)envp; ixs[3] = (unsigned long)(uintptr_t)apple;
                ixs[31] = __arm_sp;
                install_fault_handler();
                unsigned long a2x_sp0 = __arm_sp;   /* restored below: see cb_host.c, 11-01 */
                int ir = __arm2x86_interp_run(list[k], ixs, ivs);
                __arm_sp = a2x_sp0;
                if (ir) fprintf(stderr, "[host] static initializer 0x%lx in %s did not complete (reason %d)\n", list[k], im->path, ir);
            }
        }
    }
}

/* ═══ LATE GUEST LOAD (10-28) ═══════════════════════════════════════════════════════════════════════════════════
   Startup maps the executable and its dependents. A bundle or dylib the app opens LATER (FaceTime's
   FaceTimeMacHelper.bundle, ColorSync's .csutil plug-ins) is arm64e-only, so the native loader refuses it: NSBundle
   fails with Cocoa 3585 BEFORE it calls dlopen (CFBundle checks the executable's architectures itself), and a plain
   dlopen says "incompatible architecture". Both are routed here, to the same load_guest / finish_images /
   run_static_inits that startup uses. ARM2X86_NO_LATE=1 turns every hook off. */
#include <objc/message.h>
#include <limits.h>
static int g_hargc; static char **g_hargv, **g_henvp;
static pthread_mutex_t g_late_mu; static pthread_once_t g_late_once = PTHREAD_ONCE_INIT;
static void late_mu_init(void) {
    pthread_mutexattr_t at; pthread_mutexattr_init(&at);
    pthread_mutexattr_settype(&at, PTHREAD_MUTEX_RECURSIVE);   /* an initializer may open another bundle */
    pthread_mutex_init(&g_late_mu, &at);
}
static unsigned be32(const uint8_t *p) { return (unsigned)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
/* 1 when the file has an arm64 slice and no x86_64 slice (the only files the native loader cannot take) */
static int exe_arm64_only(const char *path) {
    if (!path || !path[0]) return 0;
    uint8_t h[4096];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = pread(fd, h, sizeof h, 0);
    close(fd);
    if (n < 32) return 0;
    uint32_t mg; memcpy(&mg, h, 4);
    int a64 = 0, x86 = 0;
    if (mg == 0xfeedfacf) {
        uint32_t ct; memcpy(&ct, h + 4, 4);
        a64 = ct == 0x0100000c; x86 = ct == 0x01000007;
    } else if (h[0] == 0xca && h[1] == 0xfe && h[2] == 0xba && (h[3] == 0xbe || h[3] == 0xbf)) {
        unsigned na = be32(h + 4), sz = h[3] == 0xbf ? 32 : 20;
        for (unsigned i = 0; i < na && 8 + (i + 1) * sz <= (size_t)n; i++) {
            unsigned ct = be32(h + 8 + i * sz);
            if (ct == 0x0100000c) a64 = 1;
            if (ct == 0x01000007) x86 = 1;
        }
    }
    return a64 && !x86;
}
/* Maps the vendored arm64 libc++ as a guest image. 0 = mapped, or left native with the reason printed; 1 = the load failed. */
static int map_guest_libcxx(uint64_t *next_slide, int trace) {
    if (g_libcxx_guest || A2X_DBGENV("ARM2X86_NO_GUEST_LIBCXX")) return 0;
    const char *lp = A2X_DBGENV("ARM2X86_GUEST_LIBCXX");
    if (!lp) lp = "/usr/local/lib/arm2x86/libc++.1.0.dylib";
    struct stat ls;
    if (stat(lp, &ls)) {
        fprintf(stderr, "[host] guest libc++ %s not found — libc++ stays NATIVE and std::string crossing it is "
                        "in the wrong layout\n", lp);
        return 0;
    }
    stage(ST_DEP_LOAD, (int)g_nimg, 0, lp);
    if (load_guest(lp, *next_slide, trace, 0)) return 1;
    *next_slide = (g_img[g_nimg - 1].vmend + 0xffffffUL) & ~0xffffffUL;
    g_libcxx_guest = 1;
    if (trace) fprintf(stderr, "[host] guest libc++ %s mapped as image %u\n", lp, g_nimg - 1);
    return 0;
}
static int late_find(const char *path) {
    char rp[PATH_MAX];
    const char *r = realpath(path, rp) ? rp : path;
    for (unsigned j = 0; j < g_nimg; j++) if (!strcmp(g_img[j].path, path) || !strcmp(g_img[j].path, r)) return (int)j;
    return -1;
}
/* 1 = the image is mapped (already, or now); 0 = it could not be */
int a2x_late_guest_load(const char *path) {
    pthread_once(&g_late_once, late_mu_init);
    pthread_mutex_lock(&g_late_mu);
    int idx = late_find(path);
    if (idx >= 0) { pthread_mutex_unlock(&g_late_mu); return 1; }
    int trace = A2X_DBGENV("ARM2X86_HOST_TRACE") != 0, ok = 0;
    char rp[PATH_MAX];
    const char *use = realpath(path, rp) ? rp : path;
    if (g_nimg >= IMAGES_MAX) { fprintf(stderr, "[host] late load of %s: too many guest images\n", use); goto out; }
    unsigned n0 = g_nimg; int cxx0 = g_libcxx_guest;
    uint64_t ns = (g_img[g_nimg - 1].vmend + 0xffffffUL) & ~0xffffffUL;
    g_fnew = malloc(FSTARTS_MAX * sizeof *g_fnew); g_nfnew = 0;
    if (!g_fnew) goto out;
    g_fs_late = 1;
    int rc = load_guest(use, ns, trace, 0);
    if (!rc) {
        ns = (g_img[g_nimg - 1].vmend + 0xffffffUL) & ~0xffffffUL;
        unsigned long ndl = 0, nhard = 0; int wl = 0;
        rc = scan_deps(n0, &ns, trace, &ndl, &nhard, &wl);
        /* A program that does not link libc++ itself can still open one that does: strings opens libLTO for a bitcode
           file. Mapped here, before the new images bind, their libc++ imports resolve to the guest definitions instead
           of the native x86 ones, whose std::string layout differs (SIGSEGV in basic_string::__grow_by_and_replace). */
        if (!rc && wl && !cxx0) rc = map_guest_libcxx(&ns, trace) ? 3 : 0;
    }
    g_fs_late = 0;
    if (rc) { fprintf(stderr, "[host] late load of %s failed (rc %d)\n", use, rc); g_nimg = n0; g_libcxx_guest = cxx0; free(g_fnew); g_fnew = 0; goto out; }
    /* the merged, sorted start list is built beside the live one and published with one store (see is_function_start) */
    qsort(g_fnew, g_nfnew, sizeof *g_fnew, fstart_cmp);
    {
        struct fsnap *old = __atomic_load_n(&g_fsnap, __ATOMIC_ACQUIRE);
        const unsigned long *ov = old ? old->a : g_fstart; unsigned on = old ? old->n : g_nfstart;
        struct fsnap *ns2 = malloc(sizeof *ns2 + (size_t)(on + g_nfnew) * sizeof(unsigned long));
        if (!ns2) { fprintf(stderr, "[host] late load: no memory for the function-start list\n"); g_nimg = n0; goto out; }
        unsigned a = 0, b = 0, o = 0;
        while (a < on || b < g_nfnew) ns2->a[o++] = (b >= g_nfnew || (a < on && ov[a] <= g_fnew[b])) ? ov[a++] : g_fnew[b++];
        ns2->n = o;
        __atomic_store_n(&g_fsnap, ns2, __ATOMIC_RELEASE);        /* the old one is leaked: a reader may still hold it */
    }
    free(g_fnew); g_fnew = 0;
    install_fault_handler();
    fprintf(stderr, "[host] late guest image %s (images %u..%u)\n", use, n0, g_nimg - 1);
    rc = finish_images(n0, g_img[0].text_vmaddr, trace);
    if (rc) { fprintf(stderr, "[host] late load of %s: registration failed (rc %d)\n", use, rc); goto out; }
    a2x_seal_code(n0);
    run_static_inits(n0, g_hargc, g_hargv, g_henvp, trace);
    ok = 1;
out:
    pthread_mutex_unlock(&g_late_mu);
    return ok;
}

/* ── NSBundle ── */
static IMP o_loadErr, o_load, o_isLoaded, o_principal, o_preflight;
static const char *nsb_exe(id b) {
    id p = ((id (*)(id, SEL))objc_msgSend)(b, sel_registerName("executablePath"));
    return p ? ((const char *(*)(id, SEL))objc_msgSend)(p, sel_registerName("UTF8String")) : 0;
}
/* 11-02 1102h where an arm64-only SYSTEM dylib really lives: the install name itself, or the same path inside the OS
      cryptex (dyld searches /System/Volumes/Preboot/Cryptexes/OS first for /usr/lib and /System/Library names). */
static int a2x_sysdylib_guest_path(const char *nm, char *out, size_t n) {
    if (!nm || nm[0] != '/') return 0;
    static const char *const pre[] = { "", "/System/Volumes/Preboot/Cryptexes/OS", "/System/Cryptexes/OS", 0 };
    for (int k = 0; pre[k]; k++) {
        if ((size_t)snprintf(out, n, "%s%s", pre[k], nm) >= n) continue;
        if (exe_arm64_only(out)) return 1;
    }
    return 0;
}
static const char *nsb_guest_exe(id b) { const char *e = nsb_exe(b); return exe_arm64_only(e) ? e : 0; }
static signed char h_loadErr(id self, SEL c, id *err) {
    const char *e = nsb_guest_exe(self);
    if (e && a2x_late_guest_load(e)) { if (err) *err = 0; return 1; }
    return ((signed char (*)(id, SEL, id *))o_loadErr)(self, c, err);
}
static signed char h_load(id self, SEL c) {
    const char *e = nsb_guest_exe(self);
    if (e && a2x_late_guest_load(e)) return 1;
    return ((signed char (*)(id, SEL))o_load)(self, c);
}
static signed char h_preflight(id self, SEL c, id *err) {
    const char *e = nsb_guest_exe(self);
    if (e) { if (err) *err = 0; return 1; }
    return ((signed char (*)(id, SEL, id *))o_preflight)(self, c, err);
}
static signed char h_isLoaded(id self, SEL c) {
    const char *e = nsb_guest_exe(self);
    if (e) return late_find(e) >= 0;
    return ((signed char (*)(id, SEL))o_isLoaded)(self, c);
}
static id h_principal(id self, SEL c) {
    const char *e = nsb_guest_exe(self);
    if (!e || !a2x_late_guest_load(e)) return ((id (*)(id, SEL))o_principal)(self, c);
    id v = ((id (*)(id, SEL))o_principal)(self, c);
    if (v) return v;
    id key = ((id (*)(id, SEL, const char *))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), "NSPrincipalClass");
    id nm = ((id (*)(id, SEL, id))objc_msgSend)(self, sel_registerName("objectForInfoDictionaryKey:"), key);
    if (nm) {
        const char *u = ((const char *(*)(id, SEL))objc_msgSend)(nm, sel_registerName("UTF8String"));
        Class k = u ? objc_getClass(u) : 0;
        if (k) return (id)k;
    }
    int j = late_find(e);                                      /* the bundle's first class */
    if (j >= 0 && g_img[j].objc.nclass && g_img[j].objc.classlist) {
        uint64_t p; memcpy(&p, (const void *)(uintptr_t)g_img[j].objc.classlist, 8);
        return (id)(uintptr_t)(p & 0x0000ffffffffffffUL);
    }
    return 0;
}
/* +[NSBundle bundleForClass:] FOR A GUEST CLASS. Foundation answers it from class_getImageName, i.e. from the
   dyld image that contains the class. A guest class lives in this host's a2x_rsv reservation, so the "image" is
   the host binary, which is in no bundle: the lookup falls back to mainBundle (right for the app's own classes,
   wrong for every guest framework, Swift package resource bundle and Bundle(for:) in a guest dylib). Answer from
   the guest image table instead: the bundle that owns the image's file. ARM2X86_TRACE_BUNDLE=1 logs every
   answer so the box can tell a wrong bundle from a right bundle that lacks the resource. */
static id (*o_bfc)(id, SEL, Class);
static int img_of(uint64_t a) {
    for (unsigned i = 0; i < g_nimg; i++) if (a >= g_img[i].vmlo && a < g_img[i].vmend) return (int)i;
    return -1;
}
static int bundle_dir_of(const char *exe, char *out, size_t n) {
    const char *m = strstr(exe, ".framework/");              /* Foo.framework/Versions/A/Foo -> Foo.framework */
    if (m) { size_t l = (size_t)(m - exe) + 10; if (l >= n) return 0; memcpy(out, exe, l); out[l] = 0; return 1; }
    m = strstr(exe, "/Contents/MacOS/");                     /* Foo.app/Contents/MacOS/Foo -> Foo.app */
    if (m) { size_t l = (size_t)(m - exe); if (l >= n) return 0; memcpy(out, exe, l); out[l] = 0; return 1; }
    return 0;
}
/* +[NSBundle bundleWithIdentifier:] FOR A GUEST FRAMEWORK. CoreFoundation answers from the bundles it already knows
   plus the ones it discovers from dyld's image list. A guest framework is not a dyld image, so until something has
   made an NSBundle for its directory the identifier is unknown and the answer is nil. Books: EngagementCollector
   asks Bundle(identifier: "com.apple.EngagementCollector") for BooksMessages.momd and stops with "LocalStorage
   unable to load model". On a miss, make the bundle of each guest image's directory and compare identifiers; making
   it registers it, so later lookups (CFBundleGetBundleWithIdentifier included) find it on their own. */
static id (*o_bwi)(id, SEL, id);
static int bundle_dir_of(const char *exe, char *out, size_t n);
static id h_bundleWithIdentifier(id self, SEL c, id ident) {
    id r = o_bwi(self, c, ident);
    if (r || !ident) return r;
    for (unsigned i = 0; i < g_nimg; i++) {
        char dir[PATH_MAX];
        if (!bundle_dir_of(g_img[i].path, dir, sizeof dir)) continue;
        id s = ((id (*)(id, SEL, const char *))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), dir);
        id b = s ? ((id (*)(id, SEL, id))objc_msgSend)((id)objc_getClass("NSBundle"), sel_registerName("bundleWithPath:"), s) : 0;
        id bi = b ? ((id (*)(id, SEL))objc_msgSend)(b, sel_registerName("bundleIdentifier")) : 0;
        if (bi && ((BOOL (*)(id, SEL, id))objc_msgSend)(bi, sel_registerName("isEqual:"), ident)) {
            if (A2X_DBGENV("ARM2X86_TRACE_BUNDLE")) fprintf(stderr, "[bundle] identifier lookup answered from guest image %u: %s\n", i, dir);
            return b;
        }
    }
    return r;
}
static id h_bundleForClass(id self, SEL c, Class cls) {
    static int tr = -1; if (tr < 0) tr = A2X_DBGENV("ARM2X86_TRACE_BUNDLE") ? 1 : 0;
    int i = cls ? img_of((uint64_t)(uintptr_t)cls) : -1;
    /* A class whose record lies inside a guest image is answered from that image below, whatever Foundation says.
       Foundation is therefore not asked about it first: such a class need not be known to the native runtime
       (Reminders passes one of its own Swift classes from native RemindersUICore code), and Foundation asking the
       runtime about an unknown class ends the program ("no class for metaclass"). It is still asked when the
       image yields no bundle folder, exactly as before. */
    int in_guest = i >= 0;
    id r = in_guest ? 0 : o_bfc(self, c, cls);
    /* A plain ObjC guest class is registered as a separately allocated class, so its address is in no guest image
       and the lookup above misses; the answer then fell back to the main bundle. Books asks
       [NSBundle bundleForClass:[BRCConfigurationManager class]] for BooksDefaults.json, which exists only in
       BookCore.framework, got the application bundle, read no data and raised in NSJSONSerialization. Ask the
       class map for the guest record the class stands for and use that address. */
    if (i < 0 && cls) {
        extern unsigned long __arm2x86_twin_guest_addr(void *);
        unsigned long g = __arm2x86_twin_guest_addr((void *)cls);
        if (g) i = img_of((uint64_t)g);
    }
    char dir[PATH_MAX];
    id mine = 0;
    if (i >= 0 && bundle_dir_of(g_img[i].path, dir, sizeof dir)) {
        id s = ((id (*)(id, SEL, const char *))objc_msgSend)((id)objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), dir);
        mine = ((id (*)(id, SEL, id))objc_msgSend)((id)objc_getClass("NSBundle"), sel_registerName("bundleWithPath:"), s);
    }
    if (tr) {
        const char *nm = cls ? class_getName(cls) : "(nil)";
        const char *img = cls ? class_getImageName(cls) : 0;
        id p1 = r ? ((id (*)(id, SEL))objc_msgSend)(r, sel_registerName("bundlePath")) : 0;
        id p2 = mine ? ((id (*)(id, SEL))objc_msgSend)(mine, sel_registerName("bundlePath")) : 0;
        const char *u1 = p1 ? ((const char *(*)(id, SEL))objc_msgSend)(p1, sel_registerName("UTF8String")) : "(nil)";
        const char *u2 = p2 ? ((const char *(*)(id, SEL))objc_msgSend)(p2, sel_registerName("UTF8String")) : "(none)";
        fprintf(stderr, "[bundle] class %s guest_img=%d img_name=%s foundation=%s guest=%s\n",
                nm, i, img ? img : "(null)", u1, u2);
    }
    if (!mine && in_guest) r = o_bfc(self, c, cls);
    return mine ? mine : r;
}
/* ARM2X86_TRACE_COLOR=1: log every +[UIColor colorNamed:inBundle:compatibleWithTraitCollection:], the call that
   UIColor(resource:) force-unwraps. Name, bundle path and whether the answer was nil say which of "empty
   ColorResource", "wrong bundle" and "right bundle, colour absent" a trap is. */
static id (*o_cnib)(id, SEL, id, id, id);
static const char *u8of(id s) { return s ? ((const char *(*)(id, SEL))objc_msgSend)(s, sel_registerName("UTF8String")) : 0; }
static id h_colorNamed(id self, SEL c, id name, id bundle, id traits) {
    id r = o_cnib(self, c, name, bundle, traits);
    id bp = bundle ? ((id (*)(id, SEL))objc_msgSend)(bundle, sel_registerName("bundlePath")) : 0;
    const char *n = u8of(name), *b = u8of(bp);
    fprintf(stderr, "[color] name=%s bundle=%s -> %s\n", n ? n : "(nil)", b ? b : "(nil bundle)", r ? "found" : "NIL");
    return r;
}
/* -[NSBundle classNamed:] FOR A GUEST BUNDLE. Foundation loads the bundle, looks the name up, and keeps the class only
   when class_getImageName says it came from the bundle's own file. A guest class lives in this host's reservation, so
   that test never passes and the answer is nil. A Catalyst application asks its AppKit plug-in for its window and
   application providers this way and asserts on the answer (Weather: AppKitWindowProvider, trap 28 ms after its
   window is made). Answer with the class of that name when it belongs to the bundle's guest image. */
static IMP o_classNamed;
static id h_classNamed(id self, SEL c, id name) {
    const char *e = nsb_guest_exe(self);
    if (!e || !a2x_late_guest_load(e)) return ((id (*)(id, SEL, id))o_classNamed)(self, c, name);
    const char *u = u8of(name);
    int j = late_find(e);
    /* the bundle image's own class list is the authority (principalClass above reads the same list): a class is this
       bundle's when it is listed there under that name, plain or module-qualified ("AppKitPlugin.Name") */
    if (u && j >= 0 && g_img[j].objc.nclass && g_img[j].objc.classlist) {
        size_t ul = strlen(u);
        for (unsigned long n = 0; n < g_img[j].objc.nclass; n++) {
            uint64_t q; memcpy(&q, (const void *)(uintptr_t)(g_img[j].objc.classlist + 8 * n), 8);
            Class k = (Class)(uintptr_t)(q & 0x0000ffffffffffffUL);
            const char *cn = k ? class_getName(k) : 0; if (!cn) continue;
            size_t cl = strlen(cn);
            if (!strcmp(cn, u) || (cl > ul && cn[cl - ul - 1] == '.' && !strcmp(cn + cl - ul, u))) return (id)k;
        }
    }
    id r = ((id (*)(id, SEL, id))o_classNamed)(self, c, name);
    if (!r) fprintf(stderr, "[host] -[NSBundle classNamed:%s] in guest bundle %s: not in its %lu-entry class list (image %d)\n",
                    u ? u : "(nil)", e, j >= 0 ? (unsigned long)g_img[j].objc.nclass : 0UL, j);
    return r;
}
static void late_install_hooks(void) {
    if (A2X_DBGENV("ARM2X86_TRACE_COLOR")) {
        Class uc = objc_getClass("UIColor");
        Method mc = uc ? class_getClassMethod(uc, sel_registerName("colorNamed:inBundle:compatibleWithTraitCollection:")) : 0;
        if (mc) o_cnib = (id (*)(id, SEL, id, id, id))method_setImplementation(mc, (IMP)h_colorNamed);
        else fprintf(stderr, "[host] trace color: +[UIColor colorNamed:inBundle:compatibleWithTraitCollection:] not found\n");
    }
    if (A2X_DBGENV("ARM2X86_NO_LATE")) return;
    Class k = objc_getClass("NSBundle");
    if (!k) return;
    {
        Method mb = class_getClassMethod(k, sel_registerName("bundleForClass:"));
        if (mb) o_bfc = (id (*)(id, SEL, Class))method_setImplementation(mb, (IMP)h_bundleForClass);
        else fprintf(stderr, "[host] late hooks: +[NSBundle bundleForClass:] not found\n");
        Method mi = class_getClassMethod(k, sel_registerName("bundleWithIdentifier:"));
        if (mi) o_bwi = (id (*)(id, SEL, id))method_setImplementation(mi, (IMP)h_bundleWithIdentifier);
        else fprintf(stderr, "[host] late hooks: +[NSBundle bundleWithIdentifier:] not found\n");
    }
    struct { const char *s; IMP n; IMP *o; } t[] = {
        { "loadAndReturnError:", (IMP)h_loadErr, &o_loadErr }, { "load", (IMP)h_load, &o_load },
        { "preflightAndReturnError:", (IMP)h_preflight, &o_preflight }, { "isLoaded", (IMP)h_isLoaded, &o_isLoaded },
        { "principalClass", (IMP)h_principal, &o_principal }, { "classNamed:", (IMP)h_classNamed, &o_classNamed } };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) {
        Method m = class_getInstanceMethod(k, sel_registerName(t[i].s));
        if (!m) { fprintf(stderr, "[host] late hooks: -[NSBundle %s] not found\n", t[i].s); continue; }
        *t[i].o = method_setImplementation(m, t[i].n);
    }
}

/* ── CFBundle / dlopen / dlsym, bound in place of the native entry points for GUEST imports ── */
extern const void *CFBundleCopyExecutableURL(const void *);
extern const void *CFURLCopyFileSystemPath(const void *, long);
extern const void *CFURLCopyAbsoluteURL(const void *);
extern int CFStringGetCString(const void *, char *, long, uint32_t);
extern void CFRelease(const void *);
static int cfb_guest_exe(const void *b, char *out, size_t n) {
    if (!b) return 0;
    /* 11-05 r14p: the first CFBundleCopyExecutableURL on a fresh bundle is relative to the bundle, and its file system path is the bare
       name; later calls are absolute (measured: "IOHIDEventServicePlugin", then the full path). The bare name opened nothing, so
       every plug-in's first arm64-only check said no. WindowServer's first HID service failed with 0xe00002c7 and only the second
       worked: one boot lost the mouse, another the keyboard, by enumeration order alone. */
    const void *rel_ = CFBundleCopyExecutableURL(b);
    if (!rel_) return 0;
    const void *u = CFURLCopyAbsoluteURL(rel_);
    CFRelease(rel_);
    if (!u) return 0;
    const void *s = CFURLCopyFileSystemPath(u, 0);
    int ok = s && CFStringGetCString(s, out, (long)n, 0x08000100) && exe_arm64_only(out);
    if (s) CFRelease(s);
    CFRelease(u);
    return ok;
}
#define A2X_HTAG 0x00A2D00000000000UL
static void *real_fn(const char *n) { return dlsym(RTLD_DEFAULT, n); }
static unsigned char w_CFBundleLoadExecutable(const void *b) {
    char p[PATH_MAX];
    if (cfb_guest_exe(b, p, sizeof p) && a2x_late_guest_load(p)) return 1;
    return ((unsigned char (*)(const void *))real_fn("CFBundleLoadExecutable"))(b);
}
static unsigned char w_CFBundleLoadExecutableAndReturnError(const void *b, void **err) {
    char p[PATH_MAX];
    if (cfb_guest_exe(b, p, sizeof p) && a2x_late_guest_load(p)) { if (err) *err = 0; return 1; }
    return ((unsigned char (*)(const void *, void **))real_fn("CFBundleLoadExecutableAndReturnError"))(b, err);
}
static unsigned char w_CFBundlePreflightExecutable(const void *b, void **err) {
    char p[PATH_MAX];
    if (cfb_guest_exe(b, p, sizeof p)) { if (err) *err = 0; return 1; }
    return ((unsigned char (*)(const void *, void **))real_fn("CFBundlePreflightExecutable"))(b, err);
}
static unsigned char w_CFBundleIsExecutableLoaded(const void *b) {
    char p[PATH_MAX];
    if (cfb_guest_exe(b, p, sizeof p)) return late_find(p) >= 0;
    return ((unsigned char (*)(const void *))real_fn("CFBundleIsExecutableLoaded"))(b);
}
static uint64_t late_sym(int idx, const char *name) {
    if (idx < 0 || (unsigned)idx >= g_nimg || !name) return 0;
    char u[1024];
    int n = snprintf(u, sizeof u, "_%s", name);
    if (n < 0 || (size_t)n >= sizeof u) return 0;
    return guest_image_lookup((unsigned)idx, u);
}
static void *w_CFBundleGetFunctionPointerForName(const void *b, const void *name) {
    char p[PATH_MAX], n[1024];
    if (cfb_guest_exe(b, p, sizeof p) && name && CFStringGetCString(name, n, sizeof n, 0x08000100)) {
        int j = late_find(p);
        if (j >= 0) return (void *)(uintptr_t)late_sym(j, n);
    }
    return ((void *(*)(const void *, const void *))real_fn("CFBundleGetFunctionPointerForName"))(b, name);
}
/* 11-04 NATIVE IOKit opens every HID service and session through ObjC plug-ins that 27 ships arm64e-only
      (/System/Library/HIDPlugins). IOHIDService asks CFBundleGetDataPointerForName(bundle, "OBJC_CLASS_$_Name"); the native
      dlopen answers "missing compatible architecture", so WindowServer held 0 services: USB reports reached the kernel
      and stopped (real 27: 176 IOHIDEventServiceUserClient, all WindowServer). a2x_late_wrapper only rebinds GUEST imports, so
      IOKit's own slot is redirected to the existing late loader. The class handed back is the runtime's registered copy. */
static void *(*g_real_getdata)(const void *, const void *);
static void *n_CFBundleGetDataPointerForName(const void *b, const void *name) {
    char p[PATH_MAX], n[1024];
    if (cfb_guest_exe(b, p, sizeof p) && name && CFStringGetCString(name, n, sizeof n, 0x08000100)) {
        if (!a2x_late_guest_load(p)) { fprintf(stderr, "[host] native bundle load FAILED %s\n", p); return 0; }
        if (!strncmp(n, "OBJC_CLASS_$_", 13)) {
            Class c = objc_getClass(n + 13);
            fprintf(stderr, "[host] native bundle class %s -> %p (%s)\n", n + 13, (void *)c, p);
            return (void *)c;
        }
        int j = late_find(p);
        return j >= 0 ? (void *)(uintptr_t)late_sym(j, n) : 0;
    }
    return g_real_getdata(b, name);
}
/* 11-05 r14j: THE OTHER HALF OF THE HID PLUG-IN ROUTE. n_CFBundleGetDataPointerForName serves plug-ins with an NSPrincipalClass.
      The nine at the top of /System/Library/HIDPlugins use CFPlugInFactories instead (IOHIDNXEventTranslatorSessionFilter,
      IOHIDKeyboardFilter, IOHIDPointerScrollFilter and more) and 27 ships them arm64e-only, so native CFPlugInInstanceCreate
      returned NULL and they never ran. Measured: wrangler ActivityTickles 0, HIDIdleTime = uptime, IOPMUserIsActive No, System
      Capabilities 9. loginwindow then refused to unlock (IOPMUserIsActive 0 -> _wakeForIncomingMessage), SecurityAgent saw 0
      displays, and the panel squeezed into the corner. One IOPMAssertionDeclareUserActivity by hand cured all of it, and that call
      is in the session filter. Native load is tried first; only a failed load of an arm64-only bundle comes here. The factory is
      named by the bundle's own plist and returns Apple's COM object; its function table holds raw guest addresses, which native
      callers reach through recover_guest_call like any raw guest IMP. */
#define A2X_PF_MAX 96
static struct { const void *uuid, *bundle; } g_pf[A2X_PF_MAX];
static unsigned g_npf;
static pthread_mutex_t g_pf_mu = PTHREAD_MUTEX_INITIALIZER;
static const void *(*g_real_pifind)(const void *, const void *);
static void *(*g_real_piinst)(const void *, const void *, const void *);
static const void *n_CFPlugInFindFactories(const void *type, const void *plugin) {
    const void *r = g_real_pifind(type, plugin);
    const void *(*getb)(const void *) = (const void *(*)(const void *))real_fn("CFPlugInGetBundle");
    long (*cnt)(const void *) = (long (*)(const void *))real_fn("CFArrayGetCount");
    const void *(*at)(const void *, long) = (const void *(*)(const void *, long))real_fn("CFArrayGetValueAtIndex");
    const void *(*keep)(const void *) = (const void *(*)(const void *))real_fn("CFRetain");
    const void *b = plugin && getb ? getb(plugin) : 0;
    if (!r || !b || !cnt || !at || !keep) return r;
    long n = cnt(r);
    pthread_mutex_lock(&g_pf_mu);
    for (long i = 0; i < n; i++) {
        const void *u = at(r, i); unsigned k;
        for (k = 0; k < g_npf; k++) if (g_pf[k].uuid == u) break;   /* CFUUIDs are interned */
        if (k == g_npf && g_npf < A2X_PF_MAX) { g_pf[g_npf].uuid = keep(u); g_pf[g_npf].bundle = keep(b); g_npf++; }
    }
    pthread_mutex_unlock(&g_pf_mu);
    return r;
}
static void *n_CFPlugInInstanceCreate(const void *alloc, const void *factory, const void *type) {
    void *o = g_real_piinst(alloc, factory, type);
    if (o) return o;
    const void *b = 0;
    pthread_mutex_lock(&g_pf_mu);
    for (unsigned k = 0; k < g_npf; k++) if (g_pf[k].uuid == factory) { b = g_pf[k].bundle; break; }
    pthread_mutex_unlock(&g_pf_mu);
    char p[PATH_MAX], fn[256];
    if (!b || !cfb_guest_exe(b, p, sizeof p)) return 0;
    if (!a2x_late_guest_load(p)) { fprintf(stderr, "[host] COM plug-in load FAILED %s\n", p); return 0; }
    const void *(*info)(const void *) = (const void *(*)(const void *))real_fn("CFBundleGetInfoDictionary");
    const void *(*get)(const void *, const void *) = (const void *(*)(const void *, const void *))real_fn("CFDictionaryGetValue");
    const void *(*ustr)(const void *, const void *) = (const void *(*)(const void *, const void *))real_fn("CFUUIDCreateString");
    const void *(*mks)(const void *, const char *, unsigned) = (const void *(*)(const void *, const char *, unsigned))real_fn("CFStringCreateWithCString");
    unsigned char (*cstr)(const void *, char *, long, unsigned) = (unsigned char (*)(const void *, char *, long, unsigned))real_fn("CFStringGetCString");
    void (*rel)(const void *) = (void (*)(const void *))real_fn("CFRelease");
    if (!info || !get || !ustr || !mks || !cstr || !rel) { fprintf(stderr, "[host] COM plug-in: CF symbols missing\n"); return 0; }
    const void *key = mks(0, "CFPlugInFactories", 0x08000100), *us = ustr(0, factory);
    const void *d = info(b), *facs = d && key ? get(d, key) : 0, *name = facs && us ? get(facs, us) : 0;
    int have = name && cstr(name, fn, sizeof fn, 0x08000100);
    if (key) rel(key);
    if (us) rel(us);
    if (!have) { fprintf(stderr, "[host] COM plug-in: no factory name in %s\n", p); return 0; }
    int j = late_find(p);
    uint64_t g = j >= 0 ? late_sym(j, fn) : 0;
    if (!g) { fprintf(stderr, "[host] COM plug-in: factory %s not found in %s\n", fn, p); return 0; }
    o = ((void *(*)(const void *, const void *))(uintptr_t)g)(alloc, type);
    fprintf(stderr, "[host] COM plug-in %s -> %p (%s)\n", fn, o, p);
    return o;
}
static void a2x_route_native_cfbundle(void) {
    static const char suffix[] = "/IOKit.framework/Versions/A/IOKit";
    g_real_getdata = (void *(*)(const void *, const void *))dlsym(RTLD_DEFAULT, "CFBundleGetDataPointerForName");
    g_real_pifind = (const void *(*)(const void *, const void *))dlsym(RTLD_DEFAULT, "CFPlugInFindFactoriesForPlugInTypeInPlugIn");
    g_real_piinst = (void *(*)(const void *, const void *, const void *))dlsym(RTLD_DEFAULT, "CFPlugInInstanceCreate");
    if (!g_real_getdata || !dlopen("/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit", RTLD_LAZY)) {
        fprintf(stderr, "[host] native bundle route: CoreFoundation symbol or IOKit missing\n"); return;
    }
    unsigned hits = 0, found = 0;
    for (uint32_t i = 0, ni = _dyld_image_count(); i < ni && !found; i++) {
        const char *nm = _dyld_get_image_name(i); size_t ln = nm ? strlen(nm) : 0;
        if (ln < sizeof suffix - 1 || strcmp(nm + ln - (sizeof suffix - 1), suffix)) continue;
        found = 1;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct load_command *lc = (const struct load_command *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++, lc = (const struct load_command *)((const char *)lc + lc->cmdsize)) {
            if (lc->cmd != LC_SEGMENT_64) continue;
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__TEXT")) continue;
            const struct section_64 *sc = (const struct section_64 *)(sg + 1);
            for (uint32_t k = 0; k < sg->nsects; k++, sc++) {
                /* 11-04 measured in the guest: IOKit's stub is `jmp *[rip+d]` and the slot lies OUTSIDE IOKit (the shared
                      cache coalesces pointers cache-wide; IOKit's __got is section type 0). The slot therefore comes from the stub. */
                if ((sc->flags & SECTION_TYPE) != S_SYMBOL_STUBS) continue;
                const unsigned char *t = (const unsigned char *)(uintptr_t)(sc->addr + (uint64_t)slide);
                for (uint64_t o = 0; o + 6 <= sc->size; o++) {
                    if (t[o] != 0xff || t[o + 1] != 0x25) continue;
                    int32_t d; memcpy(&d, t + o + 2, 4);
                    void **slot = (void **)(uintptr_t)(t + o + 6 + d);
                    void *cur = 0; vm_size_t got = 0;
                    if (vm_read_overwrite(mach_task_self(), (vm_address_t)slot, sizeof cur, (vm_address_t)&cur, &got) || got != sizeof cur) continue;
                    void *rep_ = cur == (void *)g_real_getdata ? (void *)n_CFBundleGetDataPointerForName
                               : g_real_pifind && cur == (void *)g_real_pifind ? (void *)n_CFPlugInFindFactories
                               : g_real_piinst && cur == (void *)g_real_piinst ? (void *)n_CFPlugInInstanceCreate : (void *)0;
                    if (!rep_) continue;
                    vm_address_t pg = (vm_address_t)slot & ~(vm_address_t)(vm_page_size - 1);
                    kern_return_t kr = vm_protect(mach_task_self(), pg, vm_page_size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                    if (kr) { fprintf(stderr, "[host] native bundle route: vm_protect %d\n", kr); continue; }
                    *slot = rep_; hits++;
                    vm_protect(mach_task_self(), pg, vm_page_size, 0, VM_PROT_READ);
                    if (A2X_DBGENV("ARM2X86_HOST_TRACE")) fprintf(stderr, "[host] native bundle route: slot %p redirected\n", (void *)slot);
                }
            }
        }
    }
    if (!hits) fprintf(stderr, "[host] native bundle route: 0 slots in IOKit (image found %u); HID plug-ins stay unloadable\n", found);
}
/* 11-05 r14y NATIVE dlopen OF AN arm64e-ONLY IMAGE. 27.2 ships SkyLight's Resources/CursorAsset as arm64e + arm64e.x1
      (no x86_64): a code-less dylib whose one export `_cursors` (__DATA_CONST, 816 B) points into 8 MB of cursor art. Native
      SkyLight in WindowServer dlopens it, dyld answers "incompatible architecture", the builtin-cursor registry comes up
      empty: "Unknown builtin cursor com.apple.coregraphics.Arrow" every ~10 s and a black box where the pointer is.
      a2x_ndlopen / a2x_ndlsym sit in SkyLight's dlopen/dlsym slots. Only an absolute path to an arm64-only file is
      taken (the same late guest loader every other route uses) and answered with a tagged handle; only a tagged handle
      is taken by dlsym. Everything else TAIL-JUMPS to dyld with the caller's return address intact - a C wrapper calling
      dlopen would make dyld resolve @rpath/@loader_path/RTLD_NEXT against the host instead of the caller. */
__attribute__((used)) void *a2x_real_dlopen_p, *a2x_real_dlsym_p;
__attribute__((used)) void *a2x_ndlopen_want(const char *p, int fl, const void *ret) {
    if (!p || p[0] != '/' || (fl & RTLD_NOLOAD)) return 0;
    /* r14z: the slot is shared by every image in the x86 cache; only SkyLight's own calls are ours. IOKit and CFBundle keep
       dyld's answer, so their arm64-only plug-ins still reach the r14j CFBundle/COM route instead of a raw guest handle. */
    Dl_info ci;
    if (!ret || !dladdr(ret, &ci) || !ci.dli_fname || !strstr(ci.dli_fname, "/SkyLight.framework/")) return 0;
    if (!exe_arm64_only(p)) return 0;
    if (!a2x_late_guest_load(p)) { fprintf(stderr, "[host] native dlopen: guest load FAILED %s\n", p); return 0; }
    int j = late_find(p);
    if (j < 0) return 0;
    fprintf(stderr, "[host] native dlopen %s -> guest image %d\n", p, j);
    return (void *)(A2X_HTAG | (unsigned long)j);
}
__attribute__((used)) void *a2x_ndlsym_tag(void *h, const char *n) {
    void *r = (void *)(uintptr_t)late_sym((int)((unsigned long)h & 0xffff), n);
    if (!r) fprintf(stderr, "[host] native dlsym %s: not in guest image %lu\n", n ? n : "(null)", (unsigned long)h & 0xffff);
    return r;
}
extern void a2x_ndlopen(void), a2x_ndlsym(void);
__asm__(".text\n"
        ".p2align 4\n"
        "_a2x_ndlopen:\n"
        "    movq (%rsp), %rdx\n"                                   /* r14z: the caller's return address */
        "    pushq %rdi\n    pushq %rsi\n    subq $8, %rsp\n"      /* entry rsp = 8 mod 16 -> 0 mod 16 at the call */
        "    call _a2x_ndlopen_want\n"
        "    addq $8, %rsp\n    popq %rsi\n    popq %rdi\n"
        "    testq %rax, %rax\n    jz 1f\n    ret\n"
        "1:  jmpq *_a2x_real_dlopen_p(%rip)\n"
        ".p2align 4\n"
        "_a2x_ndlsym:\n"
        "    movabsq $0xfffffff000000000, %rax\n    andq %rdi, %rax\n"
        "    movabsq $0x00A2D00000000000, %r11\n    cmpq %r11, %rax\n    jne 2f\n"
        "    jmp _a2x_ndlsym_tag\n"
        "2:  jmpq *_a2x_real_dlsym_p(%rip)\n");
_Static_assert(A2X_HTAG == 0x00A2D00000000000UL, "a2x_ndlsym's tag compare is written out in the asm");
static void a2x_route_native_dl(void) {
    static const char suffix[] = "/SkyLight.framework/Versions/A/SkyLight";
    a2x_real_dlopen_p = dlsym(RTLD_DEFAULT, "dlopen");
    a2x_real_dlsym_p = dlsym(RTLD_DEFAULT, "dlsym");
    if (!a2x_real_dlopen_p || !a2x_real_dlsym_p) { fprintf(stderr, "[host] native dl route: dlopen/dlsym not found\n"); return; }
    unsigned hits = 0, found = 0;
    for (uint32_t i = 0, ni = _dyld_image_count(); i < ni && !found; i++) {
        const char *nm = _dyld_get_image_name(i); size_t ln = nm ? strlen(nm) : 0;
        if (ln < sizeof suffix - 1 || strcmp(nm + ln - (sizeof suffix - 1), suffix)) continue;
        found = 1;
        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct load_command *lc = (const struct load_command *)(mh + 1);
        for (uint32_t c = 0; c < mh->ncmds; c++, lc = (const struct load_command *)((const char *)lc + lc->cmdsize)) {
            if (lc->cmd != LC_SEGMENT_64) continue;
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__TEXT")) continue;
            const struct section_64 *sc = (const struct section_64 *)(sg + 1);
            for (uint32_t k = 0; k < sg->nsects; k++, sc++) {
                if ((sc->flags & SECTION_TYPE) != S_SYMBOL_STUBS) continue;   /* same stub walk as the IOKit route */
                const unsigned char *t = (const unsigned char *)(uintptr_t)(sc->addr + (uint64_t)slide);
                for (uint64_t o = 0; o + 6 <= sc->size; o++) {
                    if (t[o] != 0xff || t[o + 1] != 0x25) continue;
                    int32_t d; memcpy(&d, t + o + 2, 4);
                    void **slot = (void **)(uintptr_t)(t + o + 6 + d);
                    void *cur = 0; vm_size_t got = 0;
                    if (vm_read_overwrite(mach_task_self(), (vm_address_t)slot, sizeof cur, (vm_address_t)&cur, &got) || got != sizeof cur) continue;
                    void *rep_ = cur == a2x_real_dlopen_p ? (void *)a2x_ndlopen : cur == a2x_real_dlsym_p ? (void *)a2x_ndlsym : (void *)0;
                    if (!rep_) continue;
                    vm_address_t pg = (vm_address_t)slot & ~(vm_address_t)(vm_page_size - 1);
                    kern_return_t kr = vm_protect(mach_task_self(), pg, vm_page_size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                    if (kr) { fprintf(stderr, "[host] native dl route: vm_protect %d\n", kr); continue; }
                    *slot = rep_; hits++;
                    vm_protect(mach_task_self(), pg, vm_page_size, 0, VM_PROT_READ);
                }
            }
        }
    }
    if (A2X_DBGENV("ARM2X86_HOST_TRACE") || (found && !hits))
        fprintf(stderr, "[host] native dl route: SkyLight %s, %u dlopen/dlsym slots redirected\n", found ? "found" : "not loaded", hits);
}
static void *w_dlopen(const char *p, int fl) {
    if (fl & RTLD_NOLOAD) {   /* 1102j: a presence query never loads (review finding 2) */
        int j = p ? late_find(p) : -1; char ga_[1024];
        if (j < 0 && p && a2x_sysdylib_guest_path(p, ga_, sizeof ga_)) j = late_find(ga_);
        if (j >= 0) return (void *)(A2X_HTAG | (unsigned long)j);
        return dlopen(p, fl);
    }
    if (p && p[0] == '/' && exe_arm64_only(p) && a2x_late_guest_load(p)) return (void *)(A2X_HTAG | (unsigned long)late_find(p));
    void *h_ = dlopen(p, fl);
    char gp_[1024];   /* 11-02 1102h an arm64-only system dylib in the OS cryptex is a guest too */
    if (!h_ && p && a2x_sysdylib_guest_path(p, gp_, sizeof gp_) && a2x_late_guest_load(gp_)) return (void *)(A2X_HTAG | (unsigned long)late_find(gp_));
    return h_;
}
static void *w_dlsym(void *h, const char *n) {
    if (((unsigned long)h & 0xfffffff000000000UL) == A2X_HTAG) return (void *)(uintptr_t)late_sym((int)((unsigned long)h & 0xffff), n);
    void *p = dlsym(h, n);
    if (p && n) {
        size_t len = strlen(n);
        if (len <= SIZE_MAX - 2) {
            char *name = malloc(len + 2);
            if (name) {
                name[0] = '_'; memcpy(name + 1, n, len + 1);
                if (!remember((unsigned long)(uintptr_t)p, name)) free(name);
            }
        }
    }
    return p;
}
/* Guest lazy-binding metadata belongs to the guest loader. Native dyld
   cannot process authenticated ARM pointer chains in an x86 process. */
#define A2X_LAZY_LOAD_IMPL
#include "lazy_load.h"
static pthread_mutex_t g_lazy_bind_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_native_lazy_once = PTHREAD_ONCE_INIT;
static void (*g_native_lazy)(uint32_t *,const void *);
static void a2x_native_lazy_init(void) {
    void *h=dlopen("/usr/lib/system/libdyld.dylib",RTLD_NOLOAD|RTLD_FIRST);
    if(h)g_native_lazy=dlsym(h,"_dyld_lazy_load");
}
struct a2x_lazy_active { const void *mh; const void *flag; struct a2x_lazy_active *previous; };
static __thread struct a2x_lazy_active *g_lazy_active;
static void a2x_lazy_fail(const char *why, int code) {
    fprintf(stderr, "[host] lazy binding refused: %s (%d)\n", why, code);
    a2x_stop("lazy binding refused:", why); abort();
}
static void w_dyld_lazy_load(uint32_t *flag, const void *mh) {
    int index = -1;
    for (unsigned i = 0; i < g_nimg; i++)
        if ((uintptr_t)mh == g_img[i].text_vmaddr + g_img[i].slide) { index = (int)i; break; }
    if (index < 0) {
        pthread_once(&g_native_lazy_once,a2x_native_lazy_init);
        if (!g_native_lazy) a2x_lazy_fail("native lazy loader unavailable", -1);
        g_native_lazy(flag,mh); return;
    }
    struct image *im = &g_img[index]; size_t length = 0;
    const uint8_t *file = slice_arm64(im->file,im->flen,&length);
    struct a2x_lazy_info info;
    int rc = file ? a2x_lazy_parse(file,length,im->slide,(uintptr_t)flag,&info) : -1;
    if (rc) a2x_lazy_fail("invalid guest metadata",rc);
    uint32_t loaded = __atomic_load_n(flag,__ATOMIC_ACQUIRE);
    if (loaded == 1) { a2x_lazy_dispose(&info); return; }
    if (loaded) a2x_lazy_fail("invalid guest loaded flag",-2);
    for (struct a2x_lazy_active *a=g_lazy_active;a;a=a->previous)
        if (a->mh==mh && a->flag==flag) a2x_lazy_fail("recursive lazy dependency",-3);
    struct a2x_lazy_active active={mh,flag,g_lazy_active};g_lazy_active=&active;
    char relative[PATH_MAX]; const char *path=info.path;
    if (bundle_relative(path,im->path,g_img[0].path,relative,sizeof relative)) path=relative;
    /* Loading and symbol resolution can execute initializers. Neither happens
       under the publication lock, and no guest pointer is changed yet. */
    void *handle=w_dlopen(path,RTLD_NOW|RTLD_FIRST);
    if (!handle && !info.weak) a2x_lazy_fail("required library unavailable",-4);
    uint64_t *values=calloc(info.count?info.count:1,sizeof *values);
    if (!values) a2x_lazy_fail("binding allocation",-5);
    for (size_t i=0;i<info.count;i++) {
        const char *name=info.bindings[i].symbol;
        if (name[0]=='_') name++;
        if (handle) values[i]=(uintptr_t)w_dlsym(handle,name);
        if (!values[i] && !info.weak) a2x_lazy_fail("required symbol unavailable",-6);
    }
    pthread_mutex_lock(&g_lazy_bind_mu);
    loaded=__atomic_load_n(flag,__ATOMIC_ACQUIRE);
    if (!loaded) {
        for (size_t i=0;i<info.count;i++)
            memcpy((void *)(uintptr_t)info.bindings[i].at,values+i,sizeof *values);
        __atomic_store_n(flag,1,__ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&g_lazy_bind_mu);
    if (loaded>1) a2x_lazy_fail("loaded flag changed unexpectedly",-7);
    if (A2X_DBGENV("ARM2X86_HOST_TRACE"))
        fprintf(stderr,"[host] guest lazy library %s: %zu bindings, flag %p\n",path,info.count,(void*)flag);
    free(values);a2x_lazy_dispose(&info);g_lazy_active=active.previous;
}
int a2x_native_loader_call(unsigned long target,unsigned long *xs) {
    pthread_once(&g_native_lazy_once,a2x_native_lazy_init);
    if(!g_native_lazy || target!=(uintptr_t)g_native_lazy)return 0;
    w_dyld_lazy_load((uint32_t *)(uintptr_t)xs[0],(const void *)(uintptr_t)xs[1]);
    xs[0]=0;return 1;
}
static int w_dlclose(void *h) {
    if (((unsigned long)h & 0xfffffff000000000UL) == A2X_HTAG) return 0;
    return dlclose(h);
}
/* 11-01 THE MAIN EXECUTABLE IS THE GUEST, NOT THIS HOST. Stock 27 launchd (arm64e, run with the host as its x86 slice)
      panicked PID 1: "launchd built improperly: no __TEXT,__config" - it reads its own section through
      getsectiondata(_NSGetMachExecuteHeader(), ...), and the native answer was the host's x86 header. Every program
      that inspects itself this way (sections, UUID) needs the guest's header: g_img[0] mapped at text_vmaddr+slide. */
#include <mach-o/ldsyms.h>
extern const struct mach_header *_NSGetMachExecuteHeader(void);         /* crt_externs.h */
extern bool _dyld_get_image_uuid(const struct mach_header *mh, uuid_t uuid);   /* dyld private, exported */
static const struct mach_header_64 *guest_mh(unsigned i) {
    return i < g_nimg ? (const struct mach_header_64 *)(uintptr_t)(g_img[i].text_vmaddr + g_img[i].slide) : 0;
}
static const struct mach_header_64 *w_NSGetMachExecuteHeader(void) {
    return g_nimg ? guest_mh(0) : (const struct mach_header_64 *)_NSGetMachExecuteHeader();
}
/* The image list a guest program is shown: its own images 0..g_nimg-1, then the native images from native index 1 on
   (native index 0 is this interpreter, which the program must not take for itself). */
static uint32_t w_dyld_image_count(void) {
    uint32_t n = _dyld_image_count();
    return g_nimg ? g_nimg + (n ? n - 1 : 0) : n;
}
static const struct mach_header *w_dyld_get_image_header(uint32_t i) {
    if (!g_nimg) return _dyld_get_image_header(i);
    return i < g_nimg ? (const struct mach_header *)guest_mh(i) : _dyld_get_image_header(i - g_nimg + 1);
}
static const char *w_dyld_get_image_name(uint32_t i) {
    if (!g_nimg) return _dyld_get_image_name(i);
    return i < g_nimg ? g_img[i].path : _dyld_get_image_name(i - g_nimg + 1);
}
static intptr_t w_dyld_get_image_vmaddr_slide(uint32_t i) {
    if (!g_nimg) return _dyld_get_image_vmaddr_slide(i);
    return i < g_nimg ? (intptr_t)g_img[i].slide : _dyld_get_image_vmaddr_slide(i - g_nimg + 1);
}
static int w_NSGetExecutablePath(char *buf, uint32_t *size) {
    if (!g_nimg || !g_img[0].path || !size) return _NSGetExecutablePath(buf, size);
    size_t need = strlen(g_img[0].path) + 1;
    if (!buf || *size < need) { *size = (uint32_t)need; return -1; }
    memcpy(buf, g_img[0].path, need);
    return 0;
}
static bool w_dyld_get_image_uuid(const struct mach_header *mh, uuid_t out) {
    for (unsigned i = 0; i < g_nimg; i++) {
        if ((const void *)mh != (const void *)guest_mh(i)) continue;
        const struct mach_header_64 *h = guest_mh(i);
        const uint8_t *lc = (const uint8_t *)(h + 1);
        for (uint32_t k = 0; k < h->ncmds; k++) {
            const struct load_command *c = (const struct load_command *)lc;
            if (c->cmd == LC_UUID) { memcpy(out, ((const struct uuid_command *)c)->uuid, 16); return true; }
            lc += c->cmdsize;
        }
        return false;
    }
    return _dyld_get_image_uuid(mh, out);
}
/* 11-01 dladdr ON A GUEST ADDRESS. Stock 27 launchd takes _NSGetMachExecuteHeader(), passes it to dladdr(), and
      only then calls getsectiondata(__TEXT,__config). Native dyld has never heard of a guest image, so dladdr said 0
      and launchd aborted "built improperly: no __TEXT,__config" (exit 134 off the VM, PID-1 panic in it). A guest
      address answers with the guest image's path and header; everything else stays native. Symbol name is left
      NULL (dladdr allows it) - callers that need it are the ones a later row will name. */
static int w_dladdr(const void *a, Dl_info *info) {
    uint64_t x = (uint64_t)(uintptr_t)a;
    for (unsigned i = 0; i < g_nimg; i++) {
        if (g_img[i].vmlo > g_img[i].vmend || x < g_img[i].vmlo || x >= g_img[i].vmend) continue;
        info->dli_fname = g_img[i].path;
        info->dli_fbase = (void *)guest_mh(i);
        info->dli_sname = 0;
        info->dli_saddr = 0;
        return 1;
    }
    return dladdr(a, info);
}
/* 11-01 HOW A LAUNCHD CHILD ENDS, ON THE CONSOLE. Stock 27 xpcproxy ran ~5/s with no exec and no crash report,
      and launchd stops console logging after early boot - so the end of a process was invisible with no ssh.
      Children of PID 1 (and PID 1) print their exit/abort reason to stderr (the console for them); nothing else
      changes - every wrapper then calls the real function. */
static int exit_diag_on(void) { return getpid() == 1 || getppid() == 1; }
static const char *exit_diag_path(void) { return g_nimg ? g_img[0].path : "?"; }
static void w_exit_diag(int c) {
    exit(c);
}
static void w__exit_diag(int c) {
    if (exit_diag_on()) fprintf(stderr, "[host] _exit(%d) pid %d %s\n", c, (int)getpid(), exit_diag_path());
    _exit(c);
}
extern void abort_with_reason(uint32_t, uint64_t, const char *, uint64_t) __attribute__((noreturn));
extern void abort_with_payload(uint32_t, uint64_t, void *, uint32_t, const char *, uint64_t) __attribute__((noreturn));
static void w_abort_with_reason_diag(uint32_t ns, uint64_t code, const char *msg, uint64_t fl) {
    if (exit_diag_on()) fprintf(stderr, "[host] abort_with_reason ns %u code 0x%llx '%s' pid %d %s\n", ns,
                                (unsigned long long)code, msg ? msg : "", (int)getpid(), exit_diag_path());
    a2x_stop("the program aborted:", msg ? msg : "(no reason given)");     /* the program's own words belong in the record */
    abort_with_reason(ns, code, msg, fl);
}
static void w_abort_with_payload_diag(uint32_t ns, uint64_t code, void *p, uint32_t sz, const char *msg, uint64_t fl) {
    if (exit_diag_on()) fprintf(stderr, "[host] abort_with_payload ns %u code 0x%llx '%s' pid %d %s\n", ns,
                                (unsigned long long)code, msg ? msg : "", (int)getpid(), exit_diag_path());
    a2x_stop("the program aborted:", msg ? msg : "(no reason given)");
    abort_with_payload(ns, code, p, sz, msg, fl);
}
static void w_abort_diag(void) {
    if (exit_diag_on()) fprintf(stderr, "[host] abort() pid %d %s\n", (int)getpid(), exit_diag_path());
    abort();
}
#include <bsm/audit.h>
/* Set when this program asked for a sandbox of its own and the call succeeded. abi_sbx.c reads it: only such a
 * program is told it is sandboxed when it asks about itself. */
int a2x_sbx_entered;
static int w_sandbox_init(const char *profile, uint64_t flags, char **err) {
    static int (*f)(const char *, uint64_t, char **); if (!f) f = (int (*)(const char *, uint64_t, char **))dlsym(RTLD_DEFAULT, "sandbox_init");
    int r = f ? f(profile, flags, err) : -1; if (r == 0) a2x_sbx_entered = 1; return r;
}
static int w_sandbox_init_with_parameters(const char *profile, uint64_t flags, const char *const params[], char **err) {
    static int (*f)(const char *, uint64_t, const char *const[], char **); if (!f) f = (int (*)(const char *, uint64_t, const char *const[], char **))dlsym(RTLD_DEFAULT, "sandbox_init_with_parameters");
    int r = f ? f(profile, flags, params, err) : -1; if (r == 0) a2x_sbx_entered = 1; return r;
}
static int w_sandbox_init_with_extensions(const char *profile, uint64_t flags, const char *const exts[], char **err) {
    static int (*f)(const char *, uint64_t, const char *const[], char **); if (!f) f = (int (*)(const char *, uint64_t, const char *const[], char **))dlsym(RTLD_DEFAULT, "sandbox_init_with_extensions");
    int r = f ? f(profile, flags, exts, err) : -1; if (r == 0) a2x_sbx_entered = 1; return r;
}
static int w_sandbox_apply(void *profile) {
    static int (*f)(void *); if (!f) f = (int (*)(void *))dlsym(RTLD_DEFAULT, "sandbox_apply");
    int r = f ? f(profile) : -1; if (r == 0) a2x_sbx_entered = 1; return r;
}
static int w_setaudit_addr_keepbs(const struct auditinfo_addr *ai, int len) {
    mach_port_t before = MACH_PORT_NULL, after = MACH_PORT_NULL;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &before);
    mach_port_t gbefore = bootstrap_port;
    int r = setaudit_addr(ai, len);
    int e = errno;
    task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &after);
    int restored = 0;
    if (r == 0 && MACH_PORT_VALID(before) && !MACH_PORT_VALID(after)) {
        task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, before);
        restored = 1;
    }
    if (MACH_PORT_VALID(gbefore) && !MACH_PORT_VALID(bootstrap_port)) { bootstrap_port = gbefore; restored |= 2; }
    errno = e;
    return r;
}
static void *a2x_late_wrapper(const char *nm) {
    if (!nm || A2X_DBGENV("ARM2X86_NO_LATE")) return 0;
    static const struct { const char *n; void *f; } t[] = {
        { "_NSGetMachExecuteHeader", (void *)w_NSGetMachExecuteHeader },
        { "_dyld_get_image_header", (void *)w_dyld_get_image_header },
        { "_dyld_image_count", (void *)w_dyld_image_count },
        { "_dyld_get_image_name", (void *)w_dyld_get_image_name },
        { "_dyld_get_image_vmaddr_slide", (void *)w_dyld_get_image_vmaddr_slide },
        { "_NSGetExecutablePath", (void *)w_NSGetExecutablePath },
        { "_dyld_get_image_uuid", (void *)w_dyld_get_image_uuid },
        { "dladdr", (void *)w_dladdr },
        { "setaudit_addr", (void *)w_setaudit_addr_keepbs },
        { "sandbox_init", (void *)w_sandbox_init },
        { "sandbox_init_with_parameters", (void *)w_sandbox_init_with_parameters },
        { "sandbox_init_with_extensions", (void *)w_sandbox_init_with_extensions },
        { "sandbox_apply", (void *)w_sandbox_apply },
        { "exit", (void *)w_exit_diag }, { "_exit", (void *)w__exit_diag }, { "abort", (void *)w_abort_diag },
        { "abort_with_reason", (void *)w_abort_with_reason_diag },
        { "abort_with_payload", (void *)w_abort_with_payload_diag },
        { "CFBundleLoadExecutable", (void *)w_CFBundleLoadExecutable },
        { "CFBundleLoadExecutableAndReturnError", (void *)w_CFBundleLoadExecutableAndReturnError },
        { "CFBundlePreflightExecutable", (void *)w_CFBundlePreflightExecutable },
        { "CFBundleIsExecutableLoaded", (void *)w_CFBundleIsExecutableLoaded },
        { "CFBundleGetFunctionPointerForName", (void *)w_CFBundleGetFunctionPointerForName },
        { "dlopen", (void *)w_dlopen }, { "dlsym", (void *)w_dlsym }, { "dlclose", (void *)w_dlclose } };
    for (unsigned i = 0; i < sizeof t / sizeof t[0]; i++) if (!strcmp(nm, t[i].n)) return t[i].f;
    /* 11-01 GSS-API: the x86_64 GSS headers are #pragma pack(2) (gss_OID_desc 12 bytes, elements @+4; arm64 16,
          @+8). The stock-27 sshd-auth died in native gss_test_oid_set_member reading a guest OID 4 bytes early.
          gss_abi.c keeps every OID/set the guest sees in arm64 layout. ARM2X86_NO_GSSABI=1 turns it off. */
    /* 11-01 a guest signal handler is a guest FUNCTION: sigaction/signal install a native entry for it
          (sig_guest.c). The raw arm64 address left sshd's listener spinning on its own sigchld_handler. */
    /* 11-01 a guest spawn arch preference gains x86_64/any (spawn_arch.c): launchd's arm64-only list made
          xpcproxy's posix_spawn of every host-fat daemon fail with EBADARCH on the x86 kernel. */
    { extern void *a2x_spawnarch_wrapper(const char *); void *w = a2x_spawnarch_wrapper(nm); if (w) return w; }
    { extern void *a2x_sig_wrapper(const char *); void *w = a2x_sig_wrapper(nm); if (w) return w; }
    extern void *a2x_gss_wrapper(const char *);
    { void *g = a2x_gss_wrapper(nm); if (g) return g; }
    /* 11-01 audit_token_t BY VALUE: 32 bytes = a pointer in an x register on arm64, 32 bytes on the x86 stack.
          launchd's sandbox_check_by_audit_token denied every privileged lookup (error 159) -> configd died -> no
          en0, no ssh. audit_abi.c dereferences the guest pointer and calls native by value. ARM2X86_NO_AUDITABI=1 off. */
    extern void *a2x_audit_wrapper(const char *);
    return a2x_audit_wrapper(nm);
}

/* ═══ ADOPT THE GUEST'S CODE SIGNATURE (10-28) ══════════════════════════════════════════════════════════════════
    THE PROBLEM. The process image is this host, so its code signature is the host's - ad-hoc, no entitlements.
      Measured: `codesign -d --entitlements - +<pid>` on a running app prints only Executable=a2xhost-mac, while the
      app's own binary carries 10-30 keys. Both halves of every entitlement check read that same signature, so the
      app is answered "no" about itself (SecTask) and daemons are answered "no" about it (csops_audittoken).
      Measured consequences: Journal, Stocks and Freeform trap inside CloudKit; Screenshot loses its connection.
    THE FIX, IN TWO HALVES THAT MUST BOTH HAPPEN.
      1. Register the guest's signature blob against the guest's vnode, with fcntl(F_ADDFILESIGS_RETURN). This is
         dyld's own call for exactly this purpose: fs_file_start is the slice's start in the file and fs_blob_start
         is LC_CODE_SIGNATURE's dataoff, an offset relative to that slice.
      2. Ask the kernel hook to point this process's p_textvp/p_textoff at the guest, which is where
         csproc_get_blob and cs_entitlements_blob_get both read from (measured in the 26A5425a kernel at
         0xffffff80007b42d0 and 0xffffff80007b4f60). The kext refuses unless the caller is really running an
         a2x host, so this cannot be used by anything else.
    IT RUNS IN main, WHICH IS AFTER libsystem_secinit. That is deliberate, not an oversight: secinit's
      registration already sees the host's signature today and the app works, so leaving that untouched is the
      additive change. A host signed with a full entitlement set instead made secinit fail with "registration
      request failed (0x10)" and SIGILL - measured 10-28, and the reason this route was chosen over signing.
    EVERY FAILURE IS REPORTED AND NONE IS FATAL. Without the kext's sysctl (an older kext, or the hook not
      installed) the app runs exactly as it did before. ARM2X86_NO_ADOPT=1 turns it off.                       */
#include <sys/sysctl.h>
#include <errno.h>              /* strerror(errno): every adopt failure names itself */
#ifndef F_ADDFILESIGS_RETURN
#define F_ADDFILESIGS_RETURN 97
typedef struct fsignatures { off_t fs_file_start; void *fs_blob_start; size_t fs_blob_size; } fsignatures_t;
#endif
#ifndef F_ADDSIGS
#define F_ADDSIGS 59           /* takes the blob from OUR memory; F_ADDFILESIGS* read it from the file */
#endif
#define A2X_CSMAGIC_EMBEDDED  0xfade0cc0u
#define A2X_CSMAGIC_CODEDIR   0xfade0c02u
/* CodeDirectory FIELD OFFSETS — PAID FOR 10-28. pageSize is at +39, NOT +36. The first attempt used
      +36 and silently overwrote hashSize (32 for SHA-256) with 12, which is why the kernel kept objecting
      to "page shift: 14": the shift byte was never touched. The trace that printed `shift=32` is what
      exposed it — 32 is not a shift, it is a hash length. Layout, from the top of the struct:
        +0 magic  +4 length  +8 version  +12 flags  +16 hashOffset  +20 identOffset
        +24 nSpecialSlots  +28 nCodeSlots  +32 codeLimit  +36 hashSize  +37 hashType  +38 platform
        +39 pageSize  +40 spare2                                                                      */
#define A2X_CD_NCODESLOTS_OFF 28
#define A2X_CD_CODELIMIT_OFF  32
#define A2X_CD_HASHSIZE_OFF   36
#define A2X_CD_HASHTYPE_OFF   37
#define A2X_CD_PAGESIZE_OFF   39
#define A2X_LC_CODE_SIGNATURE 0x1d

#include <CommonCrypto/CommonDigest.h>   /* B24: the original cdhash (libcommonCrypto is inside libSystem) */
static unsigned a2x_be32(const uint8_t *p) {
    return (unsigned)p[0] << 24 | (unsigned)p[1] << 16 | (unsigned)p[2] << 8 | p[3];
}
static uint64_t a2x_be64(const uint8_t *p) { return (uint64_t)a2x_be32(p) << 32 | a2x_be32(p + 4); }

/* The arm64 slice's offset in the file, or -1 if there is no arm64 slice. 0 for a thin arm64 file. */
static long long a2x_arm64_slice_off(const uint8_t *m, size_t sz) {
    uint32_t mg;
    if (sz < 8) return -1;
    memcpy(&mg, m, 4);
    if (mg == 0xfeedfacfu) {
        uint32_t ct; memcpy(&ct, m + 4, 4);
        return ct == 0x0100000cu ? 0 : -1;
    }
    if (!(m[0] == 0xca && m[1] == 0xfe && m[2] == 0xba && (m[3] == 0xbe || m[3] == 0xbf))) return -1;
    int w64 = m[3] == 0xbf;
    unsigned na = a2x_be32(m + 4), st = w64 ? 32u : 20u;
    for (unsigned i = 0; i < na; i++) {
        const uint8_t *a = m + 8 + (size_t)i * st;
        if ((size_t)(a - m) + st > sz) break;
        if (a2x_be32(a) != 0x0100000cu) continue;
        return w64 ? (long long)a2x_be64(a + 8) : (long long)a2x_be32(a + 8);
    }
    return -1;
}


/* 10-29 READ the guest file, never mmap(fd). The adopt half (a2x_adopt_signature) registers the app's signature
      with codeLimit cut to 4K-page slots, and the kernel keeps it on the vnode until it is recycled. A file mapping of
      that app is then validated against the cut blob: every page past ~100 KB is "Invalid" and the union-entitled host
      is SIGKILLed (CS_KILL). Measured b14: TextEdit rc=137 on every launch after its first adopt, adopt on OR off. */
static void *a2x_readall(int fd, size_t len) {
    uint8_t *b = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (b == MAP_FAILED) return MAP_FAILED;
    for (size_t o = 0; o < len; ) {
        ssize_t r = pread(fd, b + o, len - o, (off_t)o);
        if (r <= 0) { munmap(b, len); return MAP_FAILED; }
        o += (size_t)r;
    }
    return b;
}
/* 11-19 READ ONLY WHAT ADOPT LOOKS AT: the fat header and the bytes from the arm64 slice to the end of the file,
      at their own offsets in a file-sized anonymous buffer (pages never read stay untouched and cost nothing).
      Every route is fat and its x86_64 slice is this host (3.4 MB): a2x_readall copied all of it on every launch,
      3.5 MB and 1.2 ms of a 12 ms true-route launch (dtrace, 100 launches, 27.2 PC). Adopt reads only the fat
      header (a2x_arm64_slice_off) and m + soff .. end (a2x_split_blob), so those bytes are identical. */
static void *a2x_read_armpart(int fd, size_t len) {
    uint8_t *b = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (b == MAP_FAILED) return MAP_FAILED;
    size_t hl = len < 4096 ? len : 4096;
    for (size_t o = 0; o < hl; ) {
        ssize_t r = pread(fd, b + o, hl - o, (off_t)o);
        if (r <= 0) { munmap(b, len); return MAP_FAILED; }
        o += (size_t)r;
    }
    long long so = a2x_arm64_slice_off(b, len);
    size_t from = so > 0 && (size_t)so < len ? (size_t)so : hl;   /* thin file or no arm64 entry: read it all, as before */
    for (size_t o = from; o < len; ) {
        ssize_t r = pread(fd, b + o, len - o, (off_t)o);
        if (r <= 0) { munmap(b, len); return MAP_FAILED; }
        o += (size_t)r;
    }
    return b;
}

/* 10-30 B36 A DAEMON'S JETSAM LIMIT IS SIZED FOR ITS NATIVE FOOTPRINT, NOT FOR THE INTERPRETER UNDER IT.
      modelmanagerd: limit 15 MB (active and inactive), 3,143 runs, every one ended JETSAM_REASON_MEMORY_PERPROCESSLIMIT.
      Measured interpreted footprints: rapportd 16 MB phys (44 MB RSS), WiFiAgent 82 MB RSS, identityservicesd 180 MB RSS.
      So the host adds its own overhead to whatever limit launchd gave the job, once, before the guest runs. The host
      carries com.apple.private.memorystatus (union entitlements), which is what lets a process set its own limit.
   128 MB is chosen, not from nature: it covers the measured overhead of every daemon above with room to spare.
   A job with no limit (-1 / 0) is left alone. A failure is reported and the guest runs as before. */
struct a2x_memlimit { int32_t act; uint32_t act_attr; int32_t inact; uint32_t inact_attr; };
extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
static void a2x_jetsam_raise(void) {
    struct a2x_memlimit m = {0, 0, 0, 0};
    if (memorystatus_control(8 /* GET_MEMLIMIT_PROPERTIES */, getpid(), 0, &m, sizeof m) != 0) {
        fprintf(stderr, "[host] jetsam: read limit: %s\n", strerror(errno)); return; }
    int32_t a0 = m.act, i0 = m.inact;
    if (m.act > 0) m.act += 128;
    if (m.inact > 0) m.inact += 128;
    if (m.act == a0 && m.inact == i0) return;
    if (memorystatus_control(7 /* SET_MEMLIMIT_PROPERTIES */, getpid(), 0, &m, sizeof m) != 0) {
        fprintf(stderr, "[host] jetsam: raise %d/%d MB: %s\n", a0, i0, strerror(errno)); return; }
    if (A2X_DBGENV("ARM2X86_HOST_TRACE")) fprintf(stderr, "[host] jetsam: limit %d/%d -> %d/%d MB\n", a0, i0, m.act, m.inact);
}

/* 11-05 r14u THE APP SANDBOX, APPLIED THE WAY APPLE APPLIES IT. On real 27 (ruler: the M6, 27.2 26B123) the kernel gives
      an app its own signature at exec; dyld maps its images; libSystem's initializer calls libsystem_secinit's
      _libsecinit_initializer, which reads the process's entitlements (com.apple.security.app-sandbox), registers with
      secinitd over xpc_pipe, receives the compiled profile + container, sets it with __sandbox_ms("Sandbox",
      SET_USERLAND_PROFILE), consumes the container extension and sets HOME / CFFIXED_USER_HOME / TMPDIR.
    Under us that initializer ran while the process still carried the HOST's signature (adopt comes later, in main), so it
      found no app-sandbox entitlement and no guest was ever sandboxed. Measured 11-05: every sandboxed extension then died
      in libxpc _xpc_objc_main+0xf2, "XPC service requested sandbox, but is not sandboxed!" (WeatherWidget-class on the M6
      runs sandboxed with ~/Library/Containers/<id>.)
    The order is Apple's: images mapped first (dyld does that before libSystem initializes), then secinit, then the first guest
      instruction. The code is Apple's: we call the same exported initializer again, now that the kernel reports the guest's
      signature (its state block is re-read on every call: _libsecinit_appsandbox_check copies the entitlements afresh).
      Skipped when the process is already sandboxed (a route: its own signature was in place at exec, secinit already ran)
      or does not ask for the sandbox. A secinitd refusal aborts the process inside Apple's code, exactly as on real 27. */
/* 11-05 r14v THE IDENTITY secinitd CHECKS. secinitd (27.2) takes the caller's cdhash from the kernel and the file's
      from disk and refuses on any difference: "cdhash mismatch: file:///System/Library/CoreServices/WallpaperAgent.app/,
      {52441e63...}, {039ba56d...}", MacOS error -67034, "registration request failed: (0x10, 0x3)", then libsecinit's
      _libsecinit_appsandbox.cold.6 formats that reason and executes ud2 (bytes read from the live guest, 11-05).
      A fat whose x86_64 slice is this host runs under its OWN signature, so the two agree and Apple's flow completes.
      An adopted guest (an untouched arm64e app routed by the exec hook) runs under its signature with each
      CodeDirectory lowered to 4K pages, so the kernel's cdhash is the rewritten one and can never agree.
    Substituting the original hash in the kernel (a2xa.adopt_cdfix) is NOT the fix: ISSUES "no hash substitution".
      Until the kernel carries the guest's real identity, an adopted guest is left exactly as before r14u
      (unsandboxed, alive) and says so once, instead of being killed by a refusal it cannot pass.               */
static unsigned char a2x_guest_cd[20];  /* the app file's own cdhash, kept by a2x_adopt_signature on success */
static int a2x_guest_cd_have;
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define A2X_CS_OPS_CDHASH 5

static void a2x_secinit_as_guest(int trace) {
    int (*sbc)(pid_t, const char *, int) = (int (*)(pid_t, const char *, int))dlsym(RTLD_DEFAULT, "sandbox_check");
    void *(*cpe)(const char *) = (void *(*)(const char *))dlsym(RTLD_DEFAULT, "xpc_copy_entitlement_for_self");
    int (*xbv)(void *) = (int (*)(void *))dlsym(RTLD_DEFAULT, "xpc_bool_get_value");
    void (*xrel)(void *) = (void (*)(void *))dlsym(RTLD_DEFAULT, "xpc_release");
    void (*init)(void) = (void (*)(void))dlsym(RTLD_DEFAULT, "_libsecinit_initializer");
    if (!sbc || !cpe || !xbv || !xrel || !init) {
        fprintf(stderr, "[host] secinit: missing %s - guest sandbox NOT applied\n",
                !sbc ? "sandbox_check" : !cpe ? "xpc_copy_entitlement_for_self" : !init ? "_libsecinit_initializer" : "xpc_bool");
        return;
    }
    if (sbc(getpid(), NULL, 0) > 0) { if (trace) fprintf(stderr, "[host] secinit: already sandboxed at exec\n"); return; }
    void *v = cpe("com.apple.security.app-sandbox");
    int want = v && xbv(v);
    if (v) xrel(v);
    if (!want) return;
    if (a2x_guest_cd_have) {   /* r14v: adopted guest - secinitd compares this with the file's cdhash */
        unsigned char k[20] = {0};
        int r = csops(getpid(), A2X_CS_OPS_CDHASH, k, sizeof k);
        if (r != 0 || memcmp(k, a2x_guest_cd, sizeof k) != 0) {
            fprintf(stderr, "[host] secinit: running cdhash %02x%02x%02x%02x is not the app's %02x%02x%02x%02x%s (adopted,"
                    " 4K-rewritten CodeDirectory) - secinitd would refuse; App Sandbox NOT applied\n",
                    k[0], k[1], k[2], k[3], a2x_guest_cd[0], a2x_guest_cd[1], a2x_guest_cd[2], a2x_guest_cd[3],
                    r ? " (csops failed)" : "");
            return;
        }
    }
    init();
    int now = sbc(getpid(), NULL, 0);
    if (now <= 0 || trace)
        fprintf(stderr, "[host] secinit: app-sandbox requested; after Apple's initializer sandbox_check = %d, HOME=%s\n",
                now, A2X_DBGENV("HOME") ? A2X_DBGENV("HOME") : "(unset)");
}

/* 11-05 r14w APPLE'S SIGNATURE AS SIGNED. Ruler (M6, 27.2): a running app's kernel cdhash IS its file's cdhash.
      The kernel here validates pages at 4K and Apple signs arm64e at 16K, so the superblob goes in untouched and a
      4K CodeDirectory derived from Apple's primary one is appended after it (outside its index). The kext
      (a2x_split.c) checks every 16K page of the file against Apple's hashes and every 4K hash against the same
      bytes before it uses that directory for page validation; cdhash, CMS, team id and entitlements stay Apple's.
      Only when a2xa.split_gate says the kernel's policy is live; a refusal falls back to the 4K rewrite below. */
static void a2x_split_digest(unsigned ht, const void *p, size_t n, unsigned char out[CC_SHA384_DIGEST_LENGTH]) {
    if (ht == 4) CC_SHA384(p, (CC_LONG)n, out);
    else if (ht == 1) CC_SHA1(p, (CC_LONG)n, out);
    else CC_SHA256(p, (CC_LONG)n, out);
}
static uint8_t *a2x_split_blob(const uint8_t *sl, size_t slen, const uint8_t *sbk, uint32_t sbsz,
                               uint32_t *outlen, unsigned char cd20[20]) {
    if (sbsz < 12 || a2x_be32(sbk) != A2X_CSMAGIC_EMBEDDED) return 0;
    uint32_t sblen = a2x_be32(sbk + 4), count = a2x_be32(sbk + 8);
    if (sblen > sbsz || sblen < 12 || 12 + (uint64_t)count * 8 > sblen) return 0;   /* split8: may end unaligned */
    const uint8_t *cd = 0; int best = 0;
    for (uint32_t i = 0; i < count; i++) {          /* the kernel's choice: SHA-384 > SHA-256 > SHA-256/20 > SHA-1 */
        const uint8_t *e = sbk + 12 + (size_t)i * 8;
        uint32_t type = a2x_be32(e), off = a2x_be32(e + 4);
        if (!(type == 0 || (type >= 0x1000 && type < 0x1005)) || (uint64_t)off + 44 > sblen) continue;
        const uint8_t *b = sbk + off;
        if (a2x_be32(b) != A2X_CSMAGIC_CODEDIR || (uint64_t)off + a2x_be32(b + 4) > sblen) continue;
        unsigned ht = b[37];
        int rank = ht == 4 ? 4 : ht == 2 ? 3 : ht == 3 ? 2 : ht == 1 ? 1 : 0;
        if (rank > best) { best = rank; cd = b; }
    }
    if (!cd) return 0;
    uint32_t cdlen = a2x_be32(cd + 4), ver = a2x_be32(cd + 8), hoff = a2x_be32(cd + 16);
    uint32_t n16 = a2x_be32(cd + 28), climit = a2x_be32(cd + 32);
    unsigned hsz = cd[36], ht = cd[37];
    if (cd[39] != 14 || hsz == 0 || hsz > CC_SHA384_DIGEST_LENGTH) return 0;
    if (ver >= 0x20100 && cdlen >= 48 && a2x_be32(cd + 44)) return 0;                      /* scatter */
    if (ver >= 0x20300 && cdlen >= 0x40 && (a2x_be32(cd + 0x38) | a2x_be32(cd + 0x3c))) return 0;  /* codeLimit64 */
    if ((uint64_t)hoff + (uint64_t)n16 * hsz != cdlen || climit == 0 || climit > slen) return 0;
    uint32_t n4 = (climit + 4095u) >> 12, dlen = hoff + n4 * hsz, doff = (sblen + 7u) & ~7u;   /* split8 */
    uint8_t *out = calloc(1, (size_t)doff + dlen);   /* the gap after Apple's bytes stays zero: the kext checks it */
    if (!out) return 0;
    memcpy(out, sbk, sblen);                        /* Apple's superblob, byte for byte */
    uint8_t *d = out + doff;
    memcpy(d, cd, hoff);                            /* header, identifier, team id, special slots: Apple's */
    d[4] = (uint8_t)(dlen >> 24); d[5] = (uint8_t)(dlen >> 16); d[6] = (uint8_t)(dlen >> 8); d[7] = (uint8_t)dlen;
    d[28] = (uint8_t)(n4 >> 24); d[29] = (uint8_t)(n4 >> 16); d[30] = (uint8_t)(n4 >> 8); d[31] = (uint8_t)n4;
    d[39] = 12;
    unsigned char dg[CC_SHA384_DIGEST_LENGTH];
    for (uint32_t i = 0; i < n4; i++) {
        uint32_t o = i << 12, l = climit - o < 4096 ? climit - o : 4096;
        a2x_split_digest(ht, sl + o, l, dg);
        memcpy(d + hoff + (size_t)i * hsz, dg, hsz);
    }
    a2x_split_digest(ht, cd, cdlen, dg);            /* Apple's cdhash: what the kernel will now report */
    memcpy(cd20, dg, 20);
    *outlen = doff + dlen;
    return out;
}

#define ADOPT_LOG(t) do { } while (0)
static void a2x_adopt_signature(const char *guest) {
    if (!guest || !guest[0] || A2X_DBGENV("ARM2X86_NO_ADOPT")) { ADOPT_LOG("R1"); return; }
    /* 10-29 gated on the KERNEL's switch, not ours: with a2xa.adopt_enable 0 (the boot default) or the node
          absent, nothing is registered on the app's vnode at all, so landing this host changes nothing until the
          switch is flipped in the VM — an A/B with no rebuild and no reboot. */
    { int en = 0; size_t el = sizeof en;
      if (sysctlbyname("a2xa.adopt_enable", &en, &el, 0, 0) != 0 || !en) { ADOPT_LOG("R2"); return; } }
    int trace = A2X_DBGENV("ARM2X86_HOST_TRACE") != 0;

    int fd = open(guest, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "[host] adopt: open %s: %s\n", guest, strerror(errno)); { ADOPT_LOG("R3"); return; } }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 32) {
        fprintf(stderr, "[host] adopt: %s is not readable as a Mach-O\n", guest);
        close(fd); { ADOPT_LOG("R4"); return; }
    }
    uint8_t *m = a2x_read_armpart(fd, (size_t)st.st_size);
    if (m == MAP_FAILED) { fprintf(stderr, "[host] adopt: read %s: %s\n", guest, strerror(errno)); close(fd); { ADOPT_LOG("R5"); return; } }

    long long soff = a2x_arm64_slice_off(m, (size_t)st.st_size);
    uint32_t cs_off = 0, cs_size = 0;
    if (soff >= 0 && (size_t)soff + 32 <= (size_t)st.st_size) {
        const uint8_t *h = m + soff;
        uint32_t ncmds, szcmds;
        memcpy(&ncmds, h + 16, 4);
        memcpy(&szcmds, h + 20, 4);
        const uint8_t *lc = h + 32, *end = lc + szcmds;
        if (end <= m + st.st_size) {
            for (uint32_t i = 0; i < ncmds && lc + 8 <= end; i++) {
                uint32_t cmd, len;
                memcpy(&cmd, lc, 4);
                memcpy(&len, lc + 4, 4);
                if (len < 8 || lc + len > end) break;
                if (cmd == A2X_LC_CODE_SIGNATURE && len >= 16) {
                    memcpy(&cs_off, lc + 8, 4);
                    memcpy(&cs_size, lc + 12, 4);
                    break;
                }
                lc += len;
            }
        }
    }
    /* Copy the signature out while the file is still mapped: what gets registered is a MODIFIED copy,
          so the bytes have to live somewhere we own. cs_size is only ever set when soff >= 0. */
    uint8_t *blob = 0;
    if (cs_size && (size_t)soff + cs_off + cs_size <= (size_t)st.st_size) {
        blob = malloc(cs_size);
        if (blob) memcpy(blob, m + soff + cs_off, cs_size);
    }
    uint8_t *split = 0; uint32_t splitlen = 0; unsigned char splitcd[20];   /* r14w */
    { int sg = 0; size_t sgl = sizeof sg;
      if (blob && sysctlbyname("a2xa.split_gate", &sg, &sgl, 0, 0) == 0 && sg)
          split = a2x_split_blob(m + soff, (size_t)st.st_size - (size_t)soff, blob, cs_size, &splitlen, splitcd); }
    munmap(m, (size_t)st.st_size);

    if (soff < 0) { fprintf(stderr, "[host] adopt: %s has no arm64 slice\n", guest); close(fd); { ADOPT_LOG("R6"); return; } }
    /* No signature is a fact worth printing: it means this app will keep answering "no entitlements"
          about itself, and that is the thing being fixed, so a silence here would hide the miss. */
    if (!cs_size) { fprintf(stderr, "[host] adopt: %s has no LC_CODE_SIGNATURE - entitlements stay empty\n", guest); close(fd); { ADOPT_LOG("R7"); return; } }
    if (split) {   /* r14w: Apple's signature as signed + the kernel-verified 4K directory */
        fsignatures_t sfs;
        sfs.fs_file_start = (off_t)soff;
        sfs.fs_blob_start = split;
        sfs.fs_blob_size = (size_t)splitlen;
        int sr = fcntl(fd, F_ADDSIGS, &sfs), se = errno;
        free(split);
        if (sr == 0 || se == EEXIST) {
            char sarg[4200];
            int sn = snprintf(sarg, sizeof sarg, "%s:%lld", guest, soff);
            int arc_ = (sn > 0 && (size_t)sn < sizeof sarg) ? sysctlbyname("a2xa.adopt", 0, 0, sarg, (size_t)sn + 1) : -2; int aer_ = errno;
            errno = aer_;
            if (arc_ == 0) {
                memcpy(a2x_guest_cd, splitcd, sizeof a2x_guest_cd); a2x_guest_cd_have = 1;
                if (trace) fprintf(stderr, "[host] adopt: Apple's signature as signed, cdhash %02x%02x%02x%02x, 4K pages kernel-verified\n",
                                   splitcd[0], splitcd[1], splitcd[2], splitcd[3]);
            } else if (trace || errno != EINVAL) {
                fprintf(stderr, "[host] adopt: a2xa.adopt=%s: %s\n", sarg, strerror(errno));
            }
            free(blob); close(fd); { ADOPT_LOG("R8"); return; }
        }
        fprintf(stderr, "[host] adopt: the kernel refused Apple's signature for %s (%s) - 4K-rewritten registration instead\n",
                guest, strerror(se));
    }

    /* THE 16K PAGE SHIFT IS THE WALL, AND THE KERNEL SAID SO ITSELF (measured 10-28, log stream):
             "disallowing unsupported code signature page shift: 14"
             "unable to create a validated cs_blob object: 85"      (85 = EBADEXEC)
          Apple signs arm64e binaries with 16K code-signature pages (shift 14); this x86_64 kernel accepts
          only 4K (shift 12). So F_ADDFILESIGS_RETURN - dyld's own call, and the first thing tried here -
          can NEVER register an arm64e app's signature as it stands. The refusal is structural and happens
          before a single byte is hashed, so it is not something a different offset or size would fix.
        WHY LOWERING THE SHIFT IS SOUND HERE, AND EXACTLY WHERE IT STOPS BEING SOUND. pageSize describes
          the CODE-PAGE hashes only. Entitlements live in a special slot whose hash is taken over the
          entitlement blob itself, so the shift cannot change the entitlement answer - which is the only
          thing being asked for. The code-page hashes do become wrong, and they are never consulted,
          because this VM boots with cs_enforcement_disable=1 (verified in nvram boot-args) and so validates
          no page.  ON A KERNEL THAT ENFORCES PAGE VALIDATION THIS WOULD BE WRONG AND WOULD KILL THE
          PROCESS. That boot-arg is the whole guard, which is why this is a VM-only mechanism and must not
          be carried to the bare-metal box without re-deciding it.
        Both CodeDirectories are patched: Apple ships two (SHA-1 and SHA-256) and which one this kernel
          picks is not ours to choose, so leaving either at 14 risks the same refusal. */
    if (!blob) { fprintf(stderr, "[host] adopt: could not read %s's signature\n", guest); close(fd); { ADOPT_LOG("R9"); return; } }
    unsigned npatched = 0, ncd = 0;
    /* B24 THE ORIGINAL CDHASH, taken before any byte is lowered. The kernel's choice among the CodeDirectories
          is by hash type (SHA-384 > SHA-256 > SHA-256-truncated > SHA-1), and securityd makes the same choice on
          the file; the cdhash is that directory's digest in its own hash type, cut to 20 bytes. */
    unsigned char cdorig[CC_SHA384_DIGEST_LENGTH];
    int cdrank = 0;
    if (cs_size >= 12 && a2x_be32(blob) == A2X_CSMAGIC_EMBEDDED) {
        unsigned count = a2x_be32(blob + 8);
        for (unsigned i = 0; i < count; i++) {
            const uint8_t *e = blob + 12 + (size_t)i * 8;
            if ((size_t)(e - blob) + 8 > cs_size) break;
            uint32_t boff = a2x_be32(e + 4);
            if ((size_t)boff + A2X_CD_PAGESIZE_OFF + 1 > cs_size) continue;
            uint8_t *b = blob + boff;
            if (trace) fprintf(stderr, "[host] adopt: slot type=0x%x off=%u magic=0x%x\n",
                               a2x_be32(e), boff, a2x_be32(b));
            if (a2x_be32(b) != A2X_CSMAGIC_CODEDIR) continue;
            ncd++;
            unsigned nslots = a2x_be32(b + A2X_CD_NCODESLOTS_OFF);
            unsigned climit = a2x_be32(b + A2X_CD_CODELIMIT_OFF);
            if (trace) fprintf(stderr, "[host] adopt: cd at +%u shift=%u hashSize=%u hashType=%u nslots=%u codeLimit=%u\n",
                               boff, b[A2X_CD_PAGESIZE_OFF], b[A2X_CD_HASHSIZE_OFF],
                               b[A2X_CD_HASHTYPE_OFF], nslots, climit);
            {   unsigned cdlen = a2x_be32(b + 4), ht = b[A2X_CD_HASHTYPE_OFF];
                int rank = ht == 4 ? 4 : ht == 2 ? 3 : ht == 3 ? 2 : ht == 1 ? 1 : 0;
                if (rank > cdrank && (size_t)boff + cdlen <= cs_size && cdlen >= 44) {
                    if (ht == 4) CC_SHA384(b, cdlen, cdorig);
                    else if (ht == 1) CC_SHA1(b, cdlen, cdorig);
                    else CC_SHA256(b, cdlen, cdorig);
                    cdrank = rank;
                }
            }
            if (b[A2X_CD_PAGESIZE_OFF] > 12) {
                b[A2X_CD_PAGESIZE_OFF] = 12;
                /* nCodeSlots DESCRIBES THE SAME BYTES AT A NEW PAGE SIZE, so it can no longer cover the
                      whole image: 24 slots reached 24x16K, and at 4K they reach 24x4K. Growing the slot
                      array would mean growing the blob and moving every index offset after it; shortening
                      codeLimit instead keeps the blob byte-for-byte the same size and internally consistent
                      for any bounds check the kernel makes. It is sound ONLY because this VM boots
                      cs_enforcement_disable=1 and validates no code page - the shortened range is never
                      hashed. The entitlement answer is untouched either way: entitlements live in special
                      slots BEFORE hashOffset, hashed over the entitlement blob, not over code pages.
                    On a kernel that enforces page validation this is wrong and must be re-decided. */
                unsigned reach = nslots << 12;
                if (climit > reach) {
                    b[A2X_CD_CODELIMIT_OFF + 0] = (uint8_t)(reach >> 24);
                    b[A2X_CD_CODELIMIT_OFF + 1] = (uint8_t)(reach >> 16);
                    b[A2X_CD_CODELIMIT_OFF + 2] = (uint8_t)(reach >> 8);
                    b[A2X_CD_CODELIMIT_OFF + 3] = (uint8_t)reach;
                    if (trace) fprintf(stderr, "[host] adopt: codeLimit %u -> %u (%u slots x 4K)\n",
                                       climit, reach, nslots);
                }
                npatched++;
            }
        }
    }
    /* No CodeDirectory found means the SuperBlob was not the shape expected - report it rather than
          registering something unexamined. An empty result is a fact about the parse. */
    if (!ncd) { fprintf(stderr, "[host] adopt: no CodeDirectory in %s's signature (%u bytes) - not registering\n",
                        guest, cs_size); free(blob); close(fd); { ADOPT_LOG("R10"); return; } }

    fsignatures_t fs;
    fs.fs_file_start = (off_t)soff;
    fs.fs_blob_start = blob;                             /* F_ADDSIGS reads our memory, not the file */
    fs.fs_blob_size = (size_t)cs_size;
    if (fcntl(fd, F_ADDSIGS, &fs) == -1 && errno != EEXIST && !(cdrank && errno == EALREADY)) {
        fprintf(stderr, "[host] adopt: F_ADDSIGS on %s (%u/%u CodeDirectories lowered to 4K pages): %s\n",
                guest, npatched, ncd, strerror(errno));
        free(blob); close(fd); { ADOPT_LOG("R11"); return; }
    }
    free(blob);
    close(fd);

    int cdorig_rank = cdrank;   /* r14v: kept for the secinit identity check, before the cdfix switch clears it */
    char arg[4200];
    /* Only when the kernel says it takes the prefix: a kext without B24 reads "cd=..." as a path that does
          not start with '/' and refuses the whole adopt. The switch reads 0 at boot, so both halves start off. */
    { int cf = 0; size_t cl = sizeof cf;
      if (sysctlbyname("a2xa.adopt_cdfix", &cf, &cl, 0, 0) != 0 || !cf) cdrank = 0; }
    char cdhex[41] = "";
    for (int i = 0; cdrank && i < 20; i++) snprintf(cdhex + 2 * i, 3, "%02x", cdorig[i]);
    int n = cdrank ? snprintf(arg, sizeof arg, "cd=%s;%s:%lld", cdhex, guest, soff)
                   : snprintf(arg, sizeof arg, "%s:%lld", guest, soff);
    if (n <= 0 || (size_t)n >= sizeof arg) { fprintf(stderr, "[host] adopt: path too long\n"); { ADOPT_LOG("R12"); return; } }
    if (sysctlbyname("a2xa.adopt", 0, 0, arg, (size_t)n + 1) != 0) {
        /* ENOENT = this kernel has no adopt-capable hook loaded. Expected before the kext lands, so it is a
           trace line, not a warning on every launch. Anything else is a real refusal and is printed. */
        if (errno == ENOENT) {
            if (trace) fprintf(stderr, "[host] adopt: a2xa.adopt absent (adopt kext not loaded) - entitlements stay the host's\n");
        } else {
            /* 11-05: EINVAL is the kernel declining a route, whose signature is already its own (a2xa.adopt_refused_off): normal, not news */
            if (trace || errno != EINVAL) fprintf(stderr, "[host] adopt: a2xa.adopt=%s: %s\n", arg, strerror(errno));
        }
        { ADOPT_LOG("R14"); return; }
    }
    if (trace) fprintf(stderr, "[host] adopt: entitlements now %s (slice +0x%llx, blob %u bytes)\n",
                       guest, (unsigned long long)soff, cs_size);
    if (cdorig_rank) { memcpy(a2x_guest_cd, cdorig, sizeof a2x_guest_cd); a2x_guest_cd_have = 1; }  /* r14v */
}

#include <mach/mach.h>
#include <servers/bootstrap.h>
extern void *xpc_pipe_create_from_port(mach_port_t port, uint64_t flags);
/* 11-01 LIBXPC TAKES ITS ROLE FROM THE MAIN EXECUTABLE'S SECTIONS, and the main executable is this host.
      _libxpc_initializer runs getsectbyname("__TEXT", "__launchd" / "__xpcproxy" / "__launchctl") before a line
      of ours runs; the identical code is in 27's arm64e libxpc (0x18054B76C..) and the x86 one, same offsets.
    So a guest xpcproxy was initialised as a PLAIN process: task_get_special_port(bootstrap) = NULL (launchd
      hands xpcproxy its port through mach_ports_register, not as the bootstrap port) -> flags |= 2, globals
      byte 4 = 1 -> xpcproxy's inlined libxpc check returns 141 -> exit(66) for every job; no daemon ever ran.
   This replays libxpc's own xpcproxy branch on the already-initialised globals (slot 1, 0xd8 bytes):
   byte 1 = role, +0x08 flags, +0x10/+0x14 the looked-up ports, +0x18 the bootstrap pipe, byte 4 = null bootstrap. */
static void xpc_role_from_guest(int trace) {
    const struct mach_header_64 *mh = (const void *)(uintptr_t)g_img[0].text_vmaddr;
    if (!getsectbynamefromheader_64(mh, "__TEXT", "__xpcproxy")) return;
    /* by dlsym: the xpc-diag block declares the same table with its own anonymous struct type */
    struct { long once; unsigned char *ptr; } *_os_alloc_once_table = dlsym(RTLD_DEFAULT, "_os_alloc_once_table");
    if (!_os_alloc_once_table || _os_alloc_once_table[1].once != -1 || !_os_alloc_once_table[1].ptr) {
        fprintf(stderr, "[host] xpc-role: xpcproxy guest but libxpc globals are not initialised; left as is\n");
        return;
    }
    unsigned char *g = _os_alloc_once_table[1].ptr;
    if (g[0] || g[1]) return;                       /* libxpc already found a role: trust it */
    mach_port_t *ports = 0;
    mach_msg_type_number_t n = 0;
    kern_return_t kr = mach_ports_lookup(mach_task_self(), &ports, &n);
    mach_port_t p = (!kr && n) ? ports[0] : MACH_PORT_NULL;
    mach_port_t p2 = (!kr && n > 1) ? ports[1] : MACH_PORT_NULL;
    if (!kr && n) vm_deallocate(mach_task_self(), (vm_address_t)ports, n * sizeof *ports);
    if (!MACH_PORT_VALID(p)) {
        fprintf(stderr, "[host] xpc-role: xpcproxy guest but mach_ports_lookup kr=%d n=%u port=0x%x; left as a plain process\n",
                kr, n, p);
        return;
    }
    uint64_t *flags = (uint64_t *)(void *)(g + 0x08);
    *flags &= ~2ULL;                                /* the null-bootstrap mark the plain-process path set */
    g[4] = 0;
    g[1] = 1;
    *(mach_port_t *)(void *)(g + 0x10) = p;
    if (n > 1) *(mach_port_t *)(void *)(g + 0x14) = p2;
    { mach_port_t tb = MACH_PORT_NULL;               /* no task bootstrap port: the registered port is the bootstrap */
      if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &tb) != KERN_SUCCESS || !MACH_PORT_VALID(tb)) g[9] |= 1;
      else mach_port_deallocate(mach_task_self(), tb); }
    if (g[9] & 1) {                                 /* flags 0x100: the port is also the bootstrap port */
        bootstrap_port = p;
        mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, 1);
    }
    mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_SEND, 1);   /* _xpc_create_bootstrap_pipe's retain */
    void *pipe = xpc_pipe_create_from_port(p, 4);
    if (!pipe) {
        fprintf(stderr, "[host] xpc-role: xpc_pipe_create_from_port(0x%x) = NULL; globals now xpcproxy without a pipe\n", p);
        return;
    }
    *(void **)(void *)(g + 0x18) = pipe;            /* the plain-path pipe (from a NULL port) is left, not released */
    char b[24];
    snprintf(b, sizeof b, "0x%llx", (unsigned long long)(*flags & 0x82));
    setenv("XPC_FLAGS", b, 1);
    if (trace || exit_diag_on())
        fprintf(stderr, "[host] xpc-role: xpcproxy, port 0x%x (+0x%x), flags 0x%llx\n", p, p2, (unsigned long long)*flags);
}

/* 11-01 THE ARM64 USER COMMPAGE. arm64 code reads _COMM_PAGE_* with a plain load from 0xFFFFF4000+off
      (xnu cpu_capabilities.h, _COMM_PAGE64_BASE_ADDRESS); x86's commpage is elsewhere, so that address was
      unmapped and the first read was a SIGSEGV: 27 xpcproxy reads _COMM_PAGE_DEV_FIRM (+0x84) right after setsid,
      119 crashes in boot 14, no daemon ran.
    Ruler: the M4 mini's real page, dumped from a user process 11-01 — the whole 16 KB is zero except
      +0x24/+0x25 (user page shift 32/64) and +0x37 (kernel page shift), all 0x0e. Same bytes here, except the
      shifts are 12: this box has 4 KB pages, and every native answer the guest gets (vm_page_size) says so. */
/* 11-01 THE ARM64 MAIN COMMPAGE, 0xFFFFFC000 (xnu-12377 arm/cpu_capabilities.h _COMM_PAGE64_BASE_ADDRESS; the page
      above is _COMM_PAGE64_RO_ADDRESS).  It was unmapped: stock 27 logd read +0x104 (ATM_DIAGNOSTIC_CONFIG) and mds
      +0x30 (MEMORY_PRESSURE) and both died in t18. Ruler: the M4's live page ("commpage 64-bit", version 3).
   Every field that describes THIS machine is copied from its own x86 commpage (0x7fffffe00000, i386/cpu_capabilities.h
      offsets), once, at start: a snapshot, so MEMORY_PRESSURE and KDEBUG_ENABLE do not follow later changes.
   Left 0 on purpose: CPU_CAPABILITIES (no arm feature is promised to guest code that picks paths from it), CPUFAMILY,
      USER_TIMEBASE and APPROX_TIME_SUPPORTED (0 = guest code takes the syscall fallbacks; the timebase is not arm's),
      the timeofday blocks, DEV_FIRM. Page shifts are 12, as on the RO page. */
static void map_arm64_commpage_main(int trace) {
    const uintptr_t base = 0xFFFFFC000ULL;
    const size_t len = 0x4000;
    void *p = mmap((void *)base, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED || (uintptr_t)p != base) {
        fprintf(stderr, "[host] commpage: could not map the main page 0x%lx (got %p); inlined reads will fault\n",
                (unsigned long)base, p);
        if (p != MAP_FAILED) munmap(p, len);
        return;
    }
    unsigned char *c = p;
    const unsigned char *x = (const unsigned char *)0x7fffffe00000ULL;    /* this machine's live x86 commpage */
    memcpy(c, "commpage 64-bit", 16);
    *(uint16_t *)(void *)(c + 0x1e) = 3;                                  /* _COMM_PAGE_VERSION, the M4's */
    c[0x22] = x[0x22];                                                    /* NCPUS */
    c[0x24] = 12; c[0x25] = 12; c[0x37] = 12;                             /* user 32/64 and kernel page shift */
    memcpy(c + 0x26, x + 0x26, 2);                                        /* CACHE_LINESIZE */
    c[0x2f] = 1;                                                          /* CPU_CLUSTERS: one */
    *(uint32_t *)(void *)(c + 0x30) = 0;      /* CPG_TABLE: 0 measured on 26A5425a (mds compares it against 50) */
    memcpy(c + 0x34, x + 0x34, 3);                                        /* ACTIVE/PHYSICAL/LOGICAL CPUS */
    memcpy(c + 0x38, x + 0x38, 8);                                        /* MEMORY_SIZE */
    memcpy(c + 0xa0, x + 0xc8, 8);                                        /* BOOTTIME_USEC     x86 +0xc8 */
    memcpy(c + 0x100, x + 0x44, 4);                                       /* KDEBUG_ENABLE     x86 +0x44 */
    *(uint32_t *)(void *)(c + 0x104) = 1;     /* CPG_TABLE: 0x00000001 on an M1, an M4 and 26A5425a; NOT x86's ATM word */
    memcpy(c + 0x160, x + 0x100, 8);                                      /* DYLD_FLAGS        x86 +0x100 */
    if (mprotect(p, len, PROT_READ))
        fprintf(stderr, "[host] commpage: main page mprotect read-only failed (%s); left writable\n", strerror(errno));
    if (trace) fprintf(stderr, "[host] commpage: arm64 main page at 0x%lx, atm 0x%x, ncpus %u\n", (unsigned long)base,
                       *(uint32_t *)(void *)(c + 0x104), c[0x22]);
}

static void map_arm64_commpage(int trace) {
    const uintptr_t base = 0xFFFFF4000ULL;
    const size_t len = 0x4000;
    void *p = mmap((void *)base, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED || (uintptr_t)p != base) {
        fprintf(stderr, "[host] commpage: could not map 0x%lx (got %p); inlined _COMM_PAGE reads will fault\n",
                (unsigned long)base, p);
        if (p != MAP_FAILED) munmap(p, len);
        return;
    }
    unsigned char *c = p;
    c[0x24] = 12;   /* _COMM_PAGE_USER_PAGE_SHIFT_32 */
    c[0x25] = 12;   /* _COMM_PAGE_USER_PAGE_SHIFT_64 */
    c[0x37] = 12;   /* _COMM_PAGE_KERNEL_PAGE_SHIFT */
    if (mprotect(p, len, PROT_READ))
        fprintf(stderr, "[host] commpage: mprotect read-only failed (%s); left writable\n", strerror(errno));
    if (trace) fprintf(stderr, "[host] commpage: arm64 page at 0x%lx\n", (unsigned long)base);
    map_arm64_commpage_main(trace);
}

static void a2x_early_bootstrap(void) {
    if (getppid() != 1) return;
    mach_port_t tb = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &tb) == KERN_SUCCESS && MACH_PORT_VALID(tb)) {
        mach_port_deallocate(mach_task_self(), tb);
        return;
    }
    mach_port_t *rp = 0; mach_msg_type_number_t rn = 0;
    if (mach_ports_lookup(mach_task_self(), &rp, &rn) != KERN_SUCCESS || !rn) return;
    mach_port_t r0 = rp[0];
    for (mach_msg_type_number_t i = 1; i < rn; i++) if (MACH_PORT_VALID(rp[i])) mach_port_deallocate(mach_task_self(), rp[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)rp, rn * sizeof *rp);
    if (!MACH_PORT_VALID(r0)) return;
    /* A launchd child normally inherits the system bootstrap port of launchd; registered port 0 is the job domain
       port, which answers plain lookups but refuses privileged ones (0x44e), and the opendirectoryd module of libinfo
       looks up privileged. Its parent is the bootstrap the child would have inherited. */
    mach_port_t bs = r0, par = MACH_PORT_NULL;
    if (bootstrap_parent(r0, &par) == KERN_SUCCESS && MACH_PORT_VALID(par)) bs = par;
    if (task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, bs) == KERN_SUCCESS) bootstrap_port = bs;
}
/* The exec hook's interpreter is /usr/libexec/a2x/a2xhost. When this host is installed there, it receives
 * [a2xhost, guest, args...]. It shifts argv to the guest's own [guest, args...], sets CFProcessPath and A2X_GUEST
 * as the launcher did, and runs the guest in this process. A Catalyst guest needs the Catalyst host, which is
 * the only case that still execs. Any other install name leaves argv untouched. */
static int a2x_one_exec(int *argcp, char ***argvp) {
    char **argv = *argvp;
    char self[4096]; uint32_t sz = sizeof self;
    if (*argcp < 2 || getenv("A2X_GUEST") || _NSGetExecutablePath(self, &sz) != 0) return 0;
    const char *base = strrchr(self, '/'); base = base ? base + 1 : self;
    if (strcmp(base, "a2xhost") != 0) return 0;
    const char *guest = argv[1];
    int fd = open(guest, O_RDONLY); struct stat st; int cat = 0;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        if (fd >= 0) close(fd);
        fprintf(stderr, "a2xhost: cannot read the guest %s: %s\n", guest, strerror(errno)); _exit(3);
    }
    void *m = mmap(0, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0); close(fd);
    if (m == MAP_FAILED) { fprintf(stderr, "a2xhost: cannot map the guest %s\n", guest); _exit(3); }
    cat = memmem(m, (size_t)st.st_size, "/System/iOSSupport", 18) != 0; munmap(m, (size_t)st.st_size);
    if (setenv("CFProcessPath", guest, 1) != 0 || setenv("A2X_GUEST", guest, 1) != 0) {
        fprintf(stderr, "a2xhost: setenv failed: %s\n", strerror(errno)); _exit(4);
    }
    /* Only xpcproxy runs in this process: launchd answers its privileged lookups by the identity it spawned,
     * and an exec changes that identity. Every other guest goes to its host by exec, as the launcher did. */
    if (cat || strcmp(guest, "/usr/libexec/xpcproxy") != 0) {
        const char *h = cat ? "/usr/libexec/a2x/a2xhost-cat" : "/usr/libexec/a2x/a2xhost-mac";
        execv(h, argv + 1);
        fprintf(stderr, "a2xhost: execv %s failed: %s\n", h, strerror(errno)); _exit(5); }
    /* The vector is advanced, never moved: the environment must stay right after argv's terminator. */
    int n = *argcp;
    *argcp = n - 1; *argvp = argv + 1;
    *_NSGetArgc() = n - 1; *_NSGetArgv() = argv + 1;
    return 1;
}

int main(int argc, char **argv, char **envp) {
    a2x_early_bootstrap();
    a2x_one_exec(&argc, &argv);
    a2x_block_probe_view = a2x_code_view;
    if (getpid() == 1) { int c = open("/dev/console", O_WRONLY | O_NOCTTY | O_CLOEXEC);
        if (c >= 0) { int h = fcntl(c, F_DUPFD_CLOEXEC, 200); if (h >= 0) { close(c); c = h; } g_errfd = c; } }
    /* 11-01 t27 A LAUNCHD CHILD WITH stderr = /dev/null REPORTS ON THE CONSOLE. logd/configd ran 444x with no
          host line: their fd 2 is /dev/null, so 'never ran' and 'ran and died' looked the same. */
    if (getppid() == 1) { struct stat e2, dn;
        if (!fstat(2, &e2) && !stat("/dev/null", &dn) && e2.st_rdev == dn.st_rdev && S_ISCHR(e2.st_mode)) {
            int c = open("/dev/console", O_WRONLY | O_NOCTTY); if (c >= 0) { dup2(c, 2); if (c != 2) close(c); } } }
    /* TWO WAYS IN, AND THE MODE IS A FACT ON DISK — NEVER A GUESS ABOUT argv[1].
          CLI mode is `a2xhost <binary> [args]`, which is how every gate and sweep runs.
          BUNDLE mode is this host installed AS an app's CFBundleExecutable: the kernel then execs us with
          THE APP'S OWN arguments, so argv[1] is whatever the app was given — and for
          `open -a Foo.app report.pdf` that is a DOCUMENT. Treating it as the guest would interpret the PDF.
        SO THE TEST IS THE EXISTENCE OF <own path>.a2x64, which the installer creates and nothing else
          does. A heuristic like "argv[1] exists and is arm64" would be right nearly always, and the rare
          case is exactly the bug that survives a whole sweep.
        One exec, not two. A stub that re-exec'd this host would make a SECOND pass through secinit, and
          the 10-21 measurement says that is what kills a sandboxed app: of five bundles swapped this way,
          the two that died were exactly the two with app-sandbox = 1 (SIGILL, rc=132, a 0-byte errfile). */
    g_hargc = argc - 1; g_hargv = argv + 1; g_henvp = envp;
    a2x_route_native_cfbundle();
    a2x_route_native_dl();   /* r14y */
    static char selfpath[4096], bguest[4160];
    uint32_t selfsz = (uint32_t)sizeof selfpath;
    const char *gpath = 0;
    int gargc = argc - 1;                       /* CLI: the guest's argv starts after the binary path */
    char **gargv = argv + 1;
    /* DISPATCHED MODE (10-28): a2xdispatch passes the app's own argv verbatim and the guest path in
       A2X_GUEST, so Foundation's argv snapshot (taken before main) is the app's, not [host, app]. Unset
       at once so a process this app spawns cannot inherit it; the dispatcher sets it fresh each exec. */
    static char eguest[4096];
    const char *envg = getenv("A2X_GUEST");
    if (envg && envg[0]) {
        snprintf(eguest, sizeof eguest, "%s", envg);
        unsetenv("A2X_GUEST");
        gpath = eguest;
        gargc = argc;
        gargv = argv;
    }
    if (_NSGetExecutablePath(selfpath, &selfsz) == 0) {
        struct stat gst;
        snprintf(bguest, sizeof bguest, "%s%s", selfpath, A2X_GUEST_EXT);
        if (!gpath && stat(bguest, &gst) == 0 && S_ISREG(gst.st_mode)) {
            gpath = bguest;
            gargc = argc;                       /* bundle: the app's argv VERBATIM, argv[0] included */
            gargv = argv;
        }
    }
    if (!gpath) {
        /* SELF-HOSTED MODE: we ARE the x86_64 slice of a fat app binary. The kernel picked us out
              of the app's own executable, so argv[0] is the app's path and there is no argument. The
              guest is the arm64 slice of that very file, which slice_arm64() already finds.
            The test is the FILE, never argv: only a fat file carries an arm64 slice (is_arm below), and
              argv[1] is passed to the guest untouched, so a DOCUMENT is never interpreted. WAS "argc < 2",
              which made every component launchd starts with an argument open that argument as its guest:
              UIKitSystem (system_app_start) exited 3 and respawned 861 times, and the 12 Catalyst apps
              waited forever for its application-initialization reply (10-28).
            This is the whole reason the app keeps its own identity: the process image is the app's
              executable, so CoreFoundation builds the right main bundle with no CFProcessPath needed,
              and a crash report is filed against the app rather than against the interpreter. */
        if (selfpath[0]) {
            size_t sl = 0;
            long sfd = open(selfpath, O_RDONLY);
            if (sfd >= 0) {
                struct stat sst;
                if (fstat((int)sfd, &sst) == 0 && sst.st_size > 0) {
                    void *sm = mmap(0, (size_t)sst.st_size, PROT_READ, MAP_PRIVATE, (int)sfd, 0);
                    if (sm != MAP_FAILED) {
                        const uint8_t *as = slice_arm64((const uint8_t *)sm, (size_t)sst.st_size, &sl);
                        /* slice_arm64 returns the file itself when there is no fat header, so a thin
                           x86_64 host must NOT be mistaken for its own guest. */
                        int is_arm = as && sl >= 4 && as != (const uint8_t *)sm;
                        munmap(sm, (size_t)sst.st_size);
                        if (is_arm) {
                            gpath = selfpath;
                            gargc = argc;
                            gargv = argv;
                        }
                    }
                }
                close((int)sfd);
            }
        }
        if (!gpath) {
            if (argc < 2) { fprintf(stderr, "usage: %s <arm64 binary> [args...]\n", argv[0]); return 2; }
            gpath = argv[1];
        }
    }
    a2x_report_to_file(gpath, argc, argv);
    /* 11-09 a guest under the standalone host had getprogname() = "a2xhost-mac": +[AOSUtilities isDaemon] read 0 in
          com.apple.iCloudHelper, which then forwarded every request to itself and deadlocked (the 27.2 sign-in
          hang).
       The name is the guest's argv[0], not its file name - that is what crt0 gives a program on a real Mac, and
          launchd starts some programs under another name (talagentd as "talagent").
          (An earlier note here blamed basename(gpath) for talagentd dying 75 ms after every start. Measured later:
          that crash was the route's missing embedded Info.plist, see a2xroute --plist; this line was not the cause.) */
    { const char *a0_ = (gargc > 0 && gargv[0] && gargv[0][0]) ? gargv[0] : gpath;
      const char *pn_ = strrchr(a0_, '/'); setprogname(pn_ ? pn_ + 1 : a0_); }
    /* 11-01 WindowServer: QuartzCore prepare_one_filter calls 0 through SkyLight's 14-entry table (10-28).
          ws_quartz.c turns that one call into `false`; armed only for a WindowServer guest. */
    { extern void a2x_wsquartz_arm(const char *); a2x_wsquartz_arm(gpath); }
    /* 11-02 r13s SkyLight display-state decode fix moved OUT of the dyld cache into the host (sl_display.c, NO26 #3) */
    { extern void a2x_sldisplay_arm(const char *); a2x_sldisplay_arm(gpath); }
    /* 11-05 r14m: native Optional witnesses read arm64 nested-none words correctly (swift_xi.c) */
    { extern void a2x_swiftxi_arm(void); a2x_swiftxi_arm(); }
    { extern void a2x_lsgate_arm(const char *); a2x_lsgate_arm(gpath); }   /* 11-02 1102i ls_gate.c */
    /* 10-29 CALLED AGAIN, behind a2xa.adopt_enable: the kernel reports the HOST as every app's executable
          (proc_pidpath, the audit-token path, csops identity), so FuseBoard finds no bundle for a Catalyst app
          (no scene, 14 apps) and bird crashes on an unlinked host. The adopt half of the exec-hook kext swaps
          p_textvp to the app once its signature is registered. Wall 1 below is answered by load_guest reading
          into anonymous memory (no guest file mapping for a cut signature to invalidate). */
    a2x_jetsam_raise();
    a2x_adopt_signature(gpath);
    /* 10-28 a2x_adopt_signature() was NOT CALLED from here until 10-29. It registered a copy of the app's signature with
          codeLimit cut to nCodeSlots << 12 (this kernel takes only 4K pages; Apple signs 16K), so every guest
          page past ~100 KB became an "Invalid Page". An unentitled host shrugs that off; the union-entitled
          host gets CS_KILL from the kernel and was SIGKILLed (Code Signature Invalid) at main+2950, measured on
          revisiond: adopt on -> rc=137 in 1 s, adopt off -> alive. Its reader (the a2x.adopt kext) cannot load
          on 26A5425a, so it bought nothing. Entitlements now come from the host's own union signature. */
    install_fault_handler();
    int trace = A2X_DBGENV("ARM2X86_HOST_TRACE") != 0;
    stage(ST_START, -1, 0, "");
    map_arm64_commpage(trace);   /* before any guest code */

    /* ── 1. the executable, at the base it asks for ── */
    uint64_t entryoff = 0;
    stage(ST_EXE_LOAD, 0, 0, gpath);
    if (load_guest(gpath, 0, trace, &entryoff)) return 3;
    if (!entryoff) { fprintf(stderr, "[host] no LC_MAIN entry point\n"); return 4; }
    { extern void a2x_guest_infoplist(const uint8_t *, size_t); size_t gfl = 0;
      const uint8_t *gf = g_img[0].file ? slice_arm64(g_img[0].file, g_img[0].flen, &gfl) : 0;
      if (gf) a2x_guest_infoplist(gf, gfl);
      extern void a2x_guest_sections(const uint8_t *, size_t);
      if (gf) a2x_guest_sections(gf, gfl);
      extern void a2x_guest_text_entry(const uint8_t *, size_t, uint64_t);   /* 11-05 r14t: extensions' Swift @main */
      if (gf) a2x_guest_text_entry(gf, gfl, g_img[0].slide); }
    uint64_t text = g_img[0].text_vmaddr;
    /* entryoff IS TRUSTED ALL THE WAY TO THE FIRST INTERPRETED INSTRUCTION. Outside the mapping it
          is an interpreted read of unmapped memory whose reported guest pc is the entry itself. */
    if (text + entryoff < g_img[0].vmlo || text + entryoff >= g_img[0].vmend) {
        fprintf(stderr, "[host] LC_MAIN entry 0x%llx is outside the mapped image (0x%llx..0x%llx)\n",
                (unsigned long long)(text + entryoff), (unsigned long long)g_img[0].vmlo,
                (unsigned long long)g_img[0].vmend);
        return 4;
    }

    /* ── 2. its dependencies: a system path is the real x86 framework, a bundle path is another guest ──
        GUESTS ARE LOADED BEFORE ANYTHING IS BOUND. A bind in the executable may name a symbol its own
          framework exports, so every guest has to be mapped and its symbol table known before resolution
          starts; binding as we go would miss exports that are not loaded yet. */
    /* A MAC CATALYST GUEST'S FRAMEWORKS LIVE UNDER /System/iOSSupport AND dyld REFUSES TO LOAD THEM INTO
          A PROCESS WHOSE OWN PLATFORM IS macOS. a2xhost is a plain macOS binary. The install names already
          carry the full /System/iOSSupport/... path, so this is not a path problem — it is a platform one, and
          the dlopen below is where it shows. MEASURED: FindMy and Maps are PLATFORM_MACCATALYST with 15 and 32
          iOSSupport dependencies; Reminders, Shortcuts and Notes are plain macOS, so this accounts for at most
          two of the five apps that fault before the guest runs. Reported, never worked around here. */
    if (g_img[0].platform == PLATFORM_MACCATALYST_)
        fprintf(stderr, "[host] %s is PLATFORM_MACCATALYST — its dependencies live under /System/iOSSupport "
                        "and this host's own platform is macOS, so dyld may refuse them; read the dlopen "
                        "failures and the missing-import list below before anything else\n", g_img[0].path);
    uint64_t next_slide = 0x140000000UL;
    unsigned long ndlfail = 0, nhardfail = 0;
    int want_libcxx = 0;
    {
        int drc = scan_deps(0, &next_slide, trace, &ndlfail, &nhardfail, &want_libcxx);
        if (drc) return drc;
    }

    /* The guest libc++ is loaded after everything else: initializers run last-loaded first, and its locale and
       iostream state must exist before any other image's initializer touches a stream. libc++abi and libunwind stay native
       (the exception runtime, and layout-identical), which is why its re-exports are not guest definitions. */
    if (want_libcxx && map_guest_libcxx(&next_slide, trace)) return 3;

    /* the function-start list is searched by every callback argument, so sort it once */
    if (ndlfail)
        fprintf(stderr, "[host] %lu dependency framework(s) did not load, %lu of them NOT weak — every import "
                        "from one of those resolves to 0, including the _OBJC_CLASS_$_ superclass of any class "
                        "that inherits from it\n", ndlfail, nhardfail);

    stage(ST_FSTART_SORT, -1, g_nfstart, "");
    /* A dlopened system library can install its own SIGSEGV/SIGBUS handler from an initializer (the crash reporter
          in libLaunchServicesSupport does, every time it loads), which replaces ours. Activity Monitor then died on
          the first native-to-guest call, a plain SIGBUS at the function start that recover_guest_call exists to take.
          Install ours again once the dlopens are done and again as the guest starts. */
    install_fault_handler();
    qsort(g_fstart, g_nfstart, sizeof g_fstart[0], fstart_cmp);
    /* MEASURED: Maps' executable has 80,734 function starts. At the old cap of 65,536 it lost
          15,198 of them with no message, and every native->guest call into one of those was an
          unrecoverable fault reported against the callee rather than against the cap. */
    if (g_fstart_dropped)
        fprintf(stderr, "[host] %lu function start(s) DROPPED — FSTARTS_MAX is %d and this program has "
                        "%lu; no native->guest call into a dropped function can be recovered\n",
                g_fstart_dropped, FSTARTS_MAX, (unsigned long)g_nfstart + g_fstart_dropped);
    if (trace) fprintf(stderr, "[host] %u guest function start(s)\n", g_nfstart);

    { int frc = finish_images(0, text, trace); if (frc) return frc; }
    a2x_seal_code(0);

    /* ── 5. the guest stack ── */
    stage(ST_STACK, -1, 0, "");
    size_t stksz = 8u << 20;
    void *stk = mmap(0, stksz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stk == MAP_FAILED) { perror("mmap stack"); return 6; }
    __arm_sp = ((unsigned long)(uintptr_t)stk + stksz - 4096) & ~15UL;
    /* 11-01 WAS `__arm_tsd_off = 0`: %gs:0 is pthread_self, the TSD array (tsd[0] == self, tsd[3] == the mach
          thread port) lies inside the pthread struct. The guest read struct fields as TSD slots: logd's lock owner
          (TSD[3]) was garbage -> __ulock_wait EOWNERDEAD -> libtrace brk -> panic. Measured, not assumed. */
    {
        unsigned long gself = 0, gport = 0;
        __asm__ volatile("movq %%gs:0, %0" : "=r"(gself));
        __asm__ volatile("movq %%gs:0x18, %0" : "=r"(gport));
        __arm_tsd_off = ~0UL;
        for (unsigned long o = 0; o < 2048; o += 8) {
            const unsigned long *w = (const unsigned long *)(gself + o);
            if (w[0] == gself && w[3] == gport) { __arm_tsd_off = o; break; }
        }
        if (__arm_tsd_off == ~0UL) { fprintf(stderr, "[host] TSD array not found in pthread_self %#lx\n", gself); return 6; }
        if (trace) fprintf(stderr, "[host] TSD array at pthread_self + %#lx\n", __arm_tsd_off);
    }

    /* ── 6. run main(argc, argv, envp) ── */
    unsigned long xs[32];
    memset(xs, 0, sizeof xs);
    _Alignas(16) unsigned char vs[32 * 16];
    memset(vs, 0, sizeof vs);
    xs[0] = (unsigned long)gargc;
    xs[1] = (unsigned long)(uintptr_t)gargv;
    xs[2] = (unsigned long)(uintptr_t)envp;
    xs[31] = __arm_sp;

    /* STATIC INITIALIZERS. dyld runs every image's __init_offsets / __mod_init_func before main, and this host
          maps the images itself, so nothing did: a C++ global such as a std::map stayed all zeroes (begin_node
          NULL instead of &end_node) and the first insert into it read through NULL, faulting inside the
          interpreter's own memmove. Dependencies first, the program last. ARM2X86_NO_INITS=1 turns it off. */
    a2x_secinit_as_guest(trace);  /* r14u: Apple's secinit as the guest, after the images, before any guest code */
    xpc_role_from_guest(trace);   /* before any guest code, initialisers included */
    run_static_inits(0, gargc, gargv, envp, trace);

    late_install_hooks();
    stage(ST_ENTRY, 0, 0, gpath);
    if (trace) fprintf(stderr, "[host] entry 0x%llx\n", (unsigned long long)(text + entryoff));
    stage(ST_GUEST, 0, 0, gpath);
    install_fault_handler();
    int r = __arm2x86_interp_run(text + entryoff, xs, vs);
    if (r) { fprintf(stderr, "[host] the program did not complete (reason %d above)\n", r); return 7; }
    if (trace) fprintf(stderr, "[host] main returned %ld\n", (long)xs[0]);
    return (int)xs[0];
}
