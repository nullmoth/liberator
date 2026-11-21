// cb_host.c — the callback pool's C half: hand native code a callable address for a guest function, and
// bring the call back into the interpreter.
// // WITHOUT THIS, NATIVE CODE JUMPS INTO arm64 BYTES. Every block, every delegate, every comparator handed
// to a framework is an arm64 function pointer that native code will CALL, so each one needs a distinct
// x86 address that leads home. The stubs are generated (interp/cb_slots.s); this decides which guest
// function each slot stands for and what happens when one is entered.
// The door is plain C because SysV puts the arguments exactly where the stub leaves them: the first six
// integers in registers, eight doubles in xmm0-7, and the three the stub pushes (the resolved guest
// function, x8, the async context) as stack arguments. A struct of {long, double} comes back in rax and
// xmm0 — exactly where the native caller reads an integer or a double result.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>

extern unsigned long __arm_text_base, __arm_text_size;
extern __thread unsigned long __arm_sp;
extern void __arm2x86_ensure_stack(void);
extern int __arm2x86_interp_run(unsigned long target, unsigned long *xs, unsigned char *vs);

#define CB_SLOTS (1 << 17)
extern char __arm2x86_cb_slots[];

static unsigned long cb_fn[CB_SLOTS];
static unsigned cb_tab[2 * CB_SLOTS];          /* slot index + 1; 0 = empty */
static unsigned cb_n;
static pthread_mutex_t cb_mu = PTHREAD_MUTEX_INITIALIZER;

/* ONE SLOT PER GUEST FUNCTION, not per hand-over: the same block passed twice must come back as the same
      native pointer, because frameworks compare callback pointers for identity (and a pool that grew on
      every hand-over would exhaust itself immediately). */
unsigned long __arm2x86_cb(unsigned long fn) {
    /* NULL, or a native address already: nothing to wrap */
    if (!fn || !__arm_text_base || fn < __arm_text_base || fn >= __arm_text_base + __arm_text_size) return fn;
    const unsigned long mask = 2UL * CB_SLOTS - 1;
    const unsigned long h0 = ((fn >> 2) * 0x9E3779B97F4A7C15UL) >> 20 & mask;
    /* 10-31 THE HIT TAKES NO LOCK. Every block an ObjC send hands to native code comes through here, and it took
          a process-wide mutex even when the slot already existed, serialising every thread that passes blocks.
          A slot is published in this order under the lock: cb_fn[i] first, then cb_tab[h] = i + 1 with RELEASE; a
          reader that sees cb_tab[h] with ACQUIRE therefore sees cb_fn[i]. Entries are never removed or moved, so a
          probe that finds fn is final; one that reaches an empty slot falls through to the locked path, which
          probes again before inserting (so two racing first hand-overs still get ONE slot — identity holds). */
    for (unsigned long h = h0;; h = (h + 1) & mask) {
        unsigned t = __atomic_load_n(&cb_tab[h], __ATOMIC_ACQUIRE);
        if (!t) break;
        if (cb_fn[t - 1] == fn) return (unsigned long)(uintptr_t)(__arm2x86_cb_slots + 16UL * (t - 1));
    }
    pthread_mutex_lock(&cb_mu);
    unsigned long h = h0;
    while (cb_tab[h] && cb_fn[cb_tab[h] - 1] != fn) h = (h + 1) & mask;
    unsigned i;
    if (cb_tab[h]) i = cb_tab[h] - 1;
    else {
        if (cb_n == CB_SLOTS) {
            /* ABORT BY NAME rather than reuse a slot: reusing one would send a later callback to the
                  wrong guest function, which is silent corruption instead of a stop. */
            fprintf(stderr, "FATAL: callback trampoline pool exhausted (%u slots)\n", cb_n);
            a2x_stop("the callback pool is full", ""); abort();
        }
        i = cb_n;
        cb_fn[cb_n++] = fn;
        __atomic_store_n(&cb_tab[h], i + 1, __ATOMIC_RELEASE);   /* publish AFTER cb_fn[i] is written */
    }
    pthread_mutex_unlock(&cb_mu);
    return (unsigned long)(uintptr_t)(__arm2x86_cb_slots + 16UL * i);
}

/* the stub asks which guest function its index stands for, and the thread gets an arm64 stack if it has none
   — a GCD worker or an AppKit thread is a thread the guest has never run on */
struct cb_prep { unsigned long fn, async; };
/* The native caller's 7th and 8th integer arguments, read by the prepare step from the caller's own frame (just above
   its return address) and handed to the door on the same thread before any guest code can run and re-enter. */
static __thread unsigned long cb_arg78[2];
struct cb_prep __arm2x86_cb_prepare(unsigned idx, unsigned long a0, unsigned long r14, unsigned long rbp_) {
    __arm2x86_ensure_stack();
    static int tr = -1;
    if (tr < 0) tr = A2X_DBGENV("ARM2X86_TRACE_CB") ? 1 : 0;
    if (tr)
        fprintf(stderr, "[cb] slot %u -> guest 0x%lx  a0=0x%lx  r14=0x%lx\n",
                idx, idx < CB_SLOTS ? cb_fn[idx] : 0UL, a0, r14);
    if (idx >= CB_SLOTS || !cb_fn[idx]) {
        fprintf(stderr, "FATAL: callback slot %u was entered but stands for nothing\n", idx);
        a2x_stop("a callback slot that stands for nothing was entered", ""); abort();
    }
    /* A swiftasync callee returns with retq $8, and the runtime rebalances at the return site with sub $8,%rsp
       (48 83 ec 08). This door used to return with a plain retq, so a job resumed through a slot left rsp 8 low and
       swift_job_run's caller popped every saved register one slot off, ending in a ret to a stack address: Setup
       Assistant died this way about 5 minutes after every start. Same rule as recover_guest_call in host.c. */
    extern int a2x_cb_async_return(unsigned long tgt, unsigned long ret);
    unsigned long ret = *(unsigned long *)(rbp_ + 8);
    /* x86-64 passes integer arguments 7 and 8 on the stack, just above the return address; arm64 wants them in x6 and
       x7. The stub has no signature, so both words are always copied: a callee with fewer arguments never reads x6/x7
       as arguments, and the words are the caller's own frame, always readable. */
    cb_arg78[0] = *(unsigned long *)(rbp_ + 16);
    cb_arg78[1] = *(unsigned long *)(rbp_ + 24);
    const unsigned char *rp = (const unsigned char *)(uintptr_t)ret;
    int async = rp[0] == 0x48 && rp[1] == 0x83 && rp[2] == 0xec && rp[3] == 0x08 && a2x_cb_async_return(cb_fn[idx], ret);
    return (struct cb_prep){ cb_fn[idx], (unsigned long)async };
}

/* THE RETURN MUST LAND IN rax AND xmm0. A struct of exactly one integer and one double is returned in
      those two registers under SysV, which is where the native caller looks for either kind of result —
      so the stub needs no epilogue of its own to move anything. */
struct cb_ret { unsigned long x0; double d0; };

struct cb_ret __arm2x86_cb_door(unsigned long a0, unsigned long a1, unsigned long a2,
                                unsigned long a3, unsigned long a4, unsigned long a5,
                                double d0, double d1, double d2, double d3,
                                double d4, double d5, double d6, double d7,
                                unsigned long target, unsigned long x8, unsigned long asyncctx,
                                unsigned long swiftself, unsigned long swifterr) {
    unsigned long xs[32];
    memset(xs, 0, sizeof xs);
    _Alignas(16) unsigned char vs[32 * 16];
    memset(vs, 0, sizeof vs);

    /* x86-64 passes the 7th and 8th integer arguments on the stack while arm64 expects them in x6/x7. They used to
          be dropped (zeros), and Spotlight's mds asserted on every start: its query callback takes (..., count, oids)
          as arguments 6 and 7 and saw count 17 with a NULL list ("oidIx == oidCount", MDSDiskStore+OpenClose.m).
          The prepare step reads both words from the caller's frame. A 9th argument onward would go on the arm64
          stack and is still not carried. */
    xs[0] = a0; xs[1] = a1; xs[2] = a2; xs[3] = a3; xs[4] = a4; xs[5] = a5;
    xs[6] = cb_arg78[0]; xs[7] = cb_arg78[1];
    xs[8] = x8;                                   /* a Swift indirect result arrives in arm64 x8 */
    /* Swift self, error and async context arrive in r13, r12 and r14 and are x20, x21 and x22 on arm64. A native
       runtime resuming a suspended async function (swift_task_switch, a job) calls it through this door with the
       context in r14; leaving x22 zero made the resume function fault on its first [x22, #n] load. They are only
       read, never written back: x19-x28 are callee-saved on arm64, so a non-Swift callee never reads them before
       writing them, and the native caller keeps its own r12-r14. Same rule as recover_guest_call in host.c. */
    xs[20] = swiftself; xs[21] = swifterr; xs[22] = asyncctx;
    memcpy(vs + 0 * 16, &d0, 8); memcpy(vs + 1 * 16, &d1, 8);
    memcpy(vs + 2 * 16, &d2, 8); memcpy(vs + 3 * 16, &d3, 8);
    memcpy(vs + 4 * 16, &d4, 8); memcpy(vs + 5 * 16, &d5, 8);
    memcpy(vs + 6 * 16, &d6, 8); memcpy(vs + 7 * 16, &d7, 8);
    __arm2x86_ensure_stack();
    xs[31] = __arm_sp;

    /* 11-01 RESTORE THE PUBLISHED SP. The guest's native calls leave __arm_sp at their call site, inside a frame
          that is gone once the guest returns; without the restore every later entry on this thread starts lower,
          and stock 27 launchd walked off its 8 MB guest stack after ~4 min (SIGSEGV just below the stack, panic). */
    unsigned long a2x_sp0 = __arm_sp;
    int rc = __arm2x86_interp_run(target, xs, vs);
    __arm_sp = a2x_sp0;
    if (rc) {
        fprintf(stderr, "[host] a callback into guest code at 0x%lx did not complete (reason %d above)\n",
                target, rc);
        a2x_stop("a callback into the program did not complete", ""); abort();
    }
    struct cb_ret r;
    r.x0 = xs[0];
    memcpy(&r.d0, vs, 8);
    return r;
}

/* A TRAMPOLINE A 32-BIT RELATIVE POINTER CAN REACH. Swift's type descriptor stores its metadata
      completion function as a RELATIVE pointer, so patching it to one of the linked stubs above is
      impossible: those live in the host at 0x4xxxxxxxx, roughly 12 GB from the guest image, and a rel32
      spans 2 GB. This pool is allocated INSIDE the guest's reserved range instead, so the patched offset
      fits, and each stub jumps to the common entry ABSOLUTELY rather than by rel32 for the same reason.
    Each stub is 32 bytes and the index is its own, exactly like the linked pool: the two must agree on
      what a slot means, because both feed __arm2x86_cb_common. */
extern void __arm2x86_cb_common(void);

#define NEAR_SLOTS 4096
#define NEAR_STUB  32
static unsigned char *g_near;
static unsigned g_near_n;
static unsigned long g_near_fn[NEAR_SLOTS];

unsigned long __arm2x86_cb_near(unsigned long fn, unsigned long want_base, unsigned long want_len) {
    if (!fn) return 0;
    pthread_mutex_lock(&cb_mu);
    for (unsigned k = 0; k < g_near_n; k++)
        if (g_near_fn[k] == fn) { unsigned long r = (unsigned long)(uintptr_t)(g_near + (size_t)k * NEAR_STUB);
                                  pthread_mutex_unlock(&cb_mu); return r; }
    if (!g_near) {
        /* NOT AT THE FAR END OF THE RESERVATION. 2 GB away is right at the rel32 limit and leaves no room
              for an image mapped low; just past the main image is comfortably in range for everything.
            AND NOT PROT_EXEC AT mmap TIME: macOS refuses write+execute anonymous memory without the JIT
              entitlement, so the first attempt failed and every Swift app reported "cannot reach a
              trampoline". Write the stubs, THEN make the page executable — W^X, which needs no entitlement. */
        unsigned long at = want_base + 0x20000000UL;
        (void)want_len;
        void *p = mmap((void *)(uintptr_t)at, (size_t)NEAR_SLOTS * NEAR_STUB,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (p == MAP_FAILED || (unsigned long)(uintptr_t)p != at) {
            fprintf(stderr, "[host] cannot place the in-range callback pool at 0x%lx\n", at);
            pthread_mutex_unlock(&cb_mu);
            return fn;
        }
        g_near = (unsigned char *)p;
    }
    if (g_near_n == NEAR_SLOTS) {
        fprintf(stderr, "FATAL: the in-range callback pool is full (%u)\n", g_near_n);
        a2x_stop("the in-range callback pool is full", ""); abort();
    }
    unsigned i = g_near_n++;
    g_near_fn[i] = fn;
    unsigned char *st = g_near + (size_t)i * NEAR_STUB;
    /* movl $i, %r11d ; movabsq $cb_common, %rax ; jmpq *%rax */
    st[0] = 0x41; st[1] = 0xbb; memcpy(st + 2, &i, 4);
    st[6] = 0x48; st[7] = 0xb8;
    unsigned long common = (unsigned long)(uintptr_t)&__arm2x86_cb_common;
    memcpy(st + 8, &common, 8);
    st[16] = 0xff; st[17] = 0xe0;
    /* the whole pool goes executable once the stub is written; re-protecting per stub is harmless */
    mprotect(g_near, (size_t)NEAR_SLOTS * NEAR_STUB, PROT_READ | PROT_EXEC);
    /* the slot must mean the same thing to cb_prepare as a linked stub's does */
    pthread_mutex_unlock(&cb_mu);
    unsigned long linked = __arm2x86_cb(fn);        /* registers fn and gives it its canonical index */
    pthread_mutex_lock(&cb_mu);
    unsigned idx = (unsigned)(((unsigned long)linked - (unsigned long)(uintptr_t)__arm2x86_cb_slots) / 16UL);
    mprotect(g_near, (size_t)NEAR_SLOTS * NEAR_STUB, PROT_READ | PROT_WRITE);
    memcpy(st + 2, &idx, 4);
    mprotect(g_near, (size_t)NEAR_SLOTS * NEAR_STUB, PROT_READ | PROT_EXEC);
    pthread_mutex_unlock(&cb_mu);
    return (unsigned long)(uintptr_t)st;
}
