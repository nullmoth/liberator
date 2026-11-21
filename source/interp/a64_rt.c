// a64_rt.c — the interpreter's runtime entry: what a lookup miss falls through to.
// // RUNG 1 OF UNIVERSAL-27-PLAN.md, LANDED. Before this, a dispatch to an address with no translated
// function aborted the process ("__arm2x86_dispatch: no entry for 0x…"), so a single function abi_scan
// missed, or a jump into the middle of one, killed the app. Now that address is EXECUTED: a64_step runs
// the arm64 in place, over an explicit register file, until the frame returns.
// The arm64 images are mapped at their own vmaddrs (shim_comp.c maps every segment MAP_FIXED), so reading
// the instruction at an arm64 address is a plain load — no decoding of the image is needed here.
// IT REFUSES RATHER THAN IMPROVISES. Leaving the translated images, an unimplemented encoding, a trap, or
// running past the instruction budget all return a reason code, and the caller reports that instead of
// pretending the call happened. The whole value of the rung is that "we could not do this" stays
// distinguishable from "we did it wrong".
#include "a64i.h"
#include "a64_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <execinfo.h>
#include <pthread.h>

extern unsigned long __arm_text_base, __arm_text_size;
extern unsigned char *a2x_pg_sealed;     /* host.c: 1 byte per 4 KiB guest page, 1 = sealed PROT_NONE */
extern unsigned long a2x_alias_delta;
/* one instruction word at pc, through the read-only alias when the page is sealed (B23b: 2 = unsealed, read live) */
static inline uint32_t a64_fetch(unsigned long pc) {
    unsigned long f = pc;
    if (a2x_pg_sealed && f - 0x100000000UL < 0x80000000UL && a2x_pg_sealed[(f - 0x100000000UL) >> 12] == 1) f += a2x_alias_delta;
    uint32_t w; memcpy(&w, (const void *)(uintptr_t)f, 4); return w;
}
extern __thread unsigned long __arm_sp;
extern __thread unsigned long __arm_xr[96];
extern unsigned long __arm_tsd_off;
extern unsigned long __arm2x86_svc(unsigned long x16, unsigned long *a, unsigned long c, unsigned long addr);
extern FILE *a2x_errf(void);
/* 11-04 native C++ exceptions reach the guest's catch blocks (a64_eh.c, eh_guard.ll) */
extern int __arm2x86_eh_guard(void *fn, unsigned long *out, unsigned long a, unsigned long b, unsigned long c,
                              unsigned long d, unsigned long e);
extern void a2x_eh_push(const a64 *); extern void a2x_eh_pop(const a64 *);
extern int a2x_eh_land(a64 *, void *); extern int a2x_eh_is_resume(unsigned long); extern int a2x_eh_resume(a64 *);
extern void a2x_eh_fatal(void *);
extern int __arm2x86_sig_door(const char *, unsigned long, unsigned long *, unsigned char *, unsigned long);

/* WHERE THE INTERPRETER IS RIGHT NOW. A fault inside interpreted code arrives as a SIGSEGV or SIGBUS with
      an x86 pc inside the interpreter, which says nothing about WHICH guest instruction did it — and lldb
      cannot attach over ssh here. One store per step buys a crash report that names the guest address. */
__thread unsigned long a64_cur_pc;
__thread uint32_t a64_cur_insn;
__thread const a64 *a64_cur_state;      /* the registers a crash report needs to name a cause */


/* x30 AT ENTRY IS A SENTINEL, NOT A REAL ADDRESS: a `ret` to it is how the interpreter knows the frame it
      was asked to run has finished. It is deliberately a non-canonical value so that branching to it by
      accident faults loudly instead of executing something. */
/* THE OUTERMOST RETURN ADDRESS, AND IT MUST SURVIVE AN arm64e AUT CHECK.
      We enter the guest with x30 = this value so a `ret` to it means "the frame we were asked to run has
      returned".  BUT THE OLD VALUE 0xdead5a2c0000beef MADE EVERY arm64e APP TRAP IN ITS OWN ENTRY
      FUNCTION. Measured on Chess, 121 steps in, at 0x1000020dc:

          autibsp                      ; authenticate LR with the B key
          eor  x16, x30, x30, lsl #1   ; fold bit 62 against bit 61
          tbz  x16, #0x3e, ok          ; equal -> LR is a clean pointer
          brk  #0xc471                 ; unequal -> authentication failed, trap

      That is the standard arm64e authentication-failure check: a failed AUT poisons the high bits, and the
      eor/tbz pair catches it. 0xde = 1101 1110, so bit 62 = 1 and bit 61 = 0 — they DISAGREE, and the
      guest trapped on our sentinel believing its own return address had been tampered with. It exits as
      "the program did not complete", which is the whole rc=7 class of the 65-app sweep.
    SO THE SENTINEL MUST LOOK LIKE A CLEAN POINTER: bits 63..48 zero, which makes bits 61 and 62 equal
      and the check pass. It still must never be a real address — 0xdead5a2cbeef is ~244 TB, far above both
      the guest reservation (0x100000000..0x180000000) and anything mapped, so a stray jump to it faults
      loudly instead of executing. Keep the top 16 bits zero in any future value. */
#define A64_RET_SENTINEL 0x0000dead5a2cbeefULL

/* a sane ceiling.  Not a timeout: a bound that REPORTS. An interpreted loop that never exits would
   otherwise hang the app with no line in the log saying where. */
#define A64_MAX_STEPS 400000000ULL

/* 10-26 OVERRIDABLE ONLY SO THE REFUSAL CAN BE PROVEN IN THE NEGATIVE DIRECTION. A guard that no test
   can make fire has not been measured, and 400,000,000 steps is not reachable in a certifier run — the old
   negative arm forced a function that calls native code and asserted RT_LEFT_IMAGE, which stopped firing the
   moment the interpreter could make native calls (interp/host_facts.c), i.e. it tested a missing capability
   rather than the refusal path. With ARM2X86_INTERP_MAX_STEPS=<decimal> a known-good function refuses by
   name after that many instructions. Unset, the ceiling is exactly what it was. */
static unsigned long long a64_max_steps(void) {
    static unsigned long long v;
    if (!v) {
        const char *e = A2X_DBGENV("ARM2X86_INTERP_MAX_STEPS");
        unsigned long long n = e ? strtoull(e, 0, 10) : 0;
        /* No ceiling unless one is asked for. A thread is one entry here, so a fixed ceiling stopped every program
           that worked for long enough on one thread; the value kept above is only what the ceiling used to be.
           ~0 stands for "none" so that the answer is still worked out once. */
        v = n ? n : ~0ULL;
    }
    return v;
}

/* 10-27 x6/x7 ARGUMENT LIVENESS, BY SHADOW COMPARE. arm64 has eight integer argument registers and
      x86-64 has six, so arm64's 7th and 8th register arguments belong in the first two stack slots of an
      x86 call — but only when they ARE arguments. A stack argument also appears when the FLOAT pool runs
      out, and then inserting them shifts every stack argument by two slots. Measured 10-27, 3 runs per app
      per host, deterministic both ways: always-insert gives Image Playground 3/3 and Automator 1/3; never-
      insert gives Automator 3/3 and Image Playground 0/3.
    x0-x7 are CALLER-SAVED on arm64, so a value in x6 the guest has not written since the last call
      boundary cannot be an argument to this call. That is the discriminator, and it needs no signature.
    DO NOT IMPLEMENT THIS BY POISONING THE REGISTERS. Tried 10-27: Automator 3/3 -> 0/3, Console 2/3 ->
      0/3. A sentinel in a register the guest can still read is a change to the program, not a measurement
      of it. These shadows are invisible to the guest. */
static inline void a64_mark_argregs(unsigned long *s6, unsigned long *s7, a64 *st) {
    *s6 = st->x[6]; *s7 = st->x[7];
    /* THE VALUE SHADOW ABOVE MISREADS A REWRITE OF THE SAME VALUE AS "NEVER WRITTEN". MEASURED 10-27 on
          Calculator: the guest keeps one witness table in x6 and re-copies it before every call, so at
          SwiftUI.PickerOption.init the shadow equalled x6, nint came out 6, the 7th argument was dropped and
          the callee compared a NULL witness table in swift::MetadataCacheKey::areWitnessTablesEqual.
        The write flag is exact: wz/wsp set it, this clears it at every call boundary. */
    st->argw = 0;
}

enum { RT_OK = 0, RT_LEFT_IMAGE = 1, RT_UNIMPL = 2, RT_TRAP = 3, RT_BUDGET = 4 };

#if A2X_SLOTS
/* FIXED SLOTS (a64slot.c). Every guest code section the loader maps is noted here; the first time execution reaches
   one it is converted whole (one 32-byte x86 slot per arm64 instruction) and from then on the loop enters the slots
   and only takes back what they hand it: an instruction they leave before (SLOT_EXIT, s.pc names it and the
   interpreter runs exactly that one), or an event an instruction run by their helper raised (SLOT_EVENT, handled by
   the same switch as an event from a64_step). Native calls, svc, brk and every branch out of the converted code
   come back here, so the native-call door, exceptions and callbacks are the interpreter's own code, unchanged.
   ARM2X86_SLOTS=1 turns it on; ARM2X86_SLOTS_OPT=N picks the options (default 7 = in place, sp in rsp, no
   zero-extend). Off = the old loop, one predicted branch per instruction. */
#include "a64slot.h"
#include <pthread.h>
static int a2x_slots_on = -1;
/* the crash reporter's annotation record (CrashReporterClient's layout, version 5): `message` shows in the report */
struct a2x_crashinfo { uint64_t version, message, signature, backtrace, message2, thread, dialog_mode, abort_cause; };
__attribute__((section("__DATA,__crash_info"), used)) struct a2x_crashinfo a2x_crash_info = {5, 0, 0, 0, 0, 0, 0, 0};
#define A2X_SLOT_RANGES 512
static struct { unsigned long lo, hi; int state; } a2x_sr[A2X_SLOT_RANGES];   /* state 0 noted, 1 converted, 2 refused */
static int a2x_nsr;
static pthread_mutex_t a2x_slots_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned long a2x_sl_lo = ~0ul, a2x_sl_hi;     /* the span of every noted code section (a2x_slots_try) */
static int a2x_sl_dead;                               /* the code area was refused: slots off for this process */
void a2x_slots_note(unsigned long lo, unsigned long hi) {
    pthread_mutex_lock(&a2x_slots_mu);
    if (a2x_nsr < A2X_SLOT_RANGES && hi > lo && !(lo & 3)) {
        a2x_sr[a2x_nsr].lo = lo; a2x_sr[a2x_nsr].hi = hi & ~3ul; a2x_sr[a2x_nsr].state = 0;
        __atomic_store_n(&a2x_nsr, a2x_nsr + 1, __ATOMIC_RELEASE);
        if (lo < a2x_sl_lo) a2x_sl_lo = lo;
        if ((hi & ~3ul) > a2x_sl_hi) a2x_sl_hi = hi & ~3ul;
    }
    pthread_mutex_unlock(&a2x_slots_mu);
}
static void a2x_slots_init(void) {
    const char *e = getenv("ARM2X86_SLOTS");
    /* ON BY DEFAULT: the whole system runs on slots. The kill switch is a file on the writable volume (the system
          volume is sealed read-only at every start on 27, and a launchd child gets no environment of ours):
          /Library/NullMoth/a2x/slots holds words, read in order, the last that applies wins:
            off  every program off on  every program on -<name>  this program off +<name>  this program on
          ARM2X86_SLOTS=0/1 in the environment overrides the file (tests). A file that cannot be read = on. */
    int on = 1, file_learn = -1, file_opt = -1;
    if (e) on = atoi(e) > 0;
    else {
        FILE *f = fopen("/Library/NullMoth/a2x/slots", "r");
        char w[160];
        const char *me = getprogname();
        if (f) {
            while (fscanf(f, "%159s", w) == 1) {
                if (!strcmp(w, "off")) on = 0;
                else if (!strcmp(w, "on")) on = 1;
                else if (me && (w[0] == '-' || w[0] == '+') && !strcmp(w + 1, me)) on = w[0] == '+';
                else {
                    /* options, for every program (learn=0, opt=N) or one (<name>:learn=0, <name>:opt=N) */
                    char *c = strchr(w, ':'), *kv = w;
                    if (c) { *c = 0; if (!me || strcmp(w, me)) continue; kv = c + 1; }
                    if (!strncmp(kv, "learn=", 6)) file_learn = atoi(kv + 6);
                    else if (!strncmp(kv, "opt=", 4)) file_opt = atoi(kv + 4) & 7;
                }
            }
            fclose(f);
        }
    }
    const char *o = getenv("ARM2X86_SLOTS_OPT");
    /* default 13 = OPT_INPLACE | OPT_NOZX | OPT_RET: guest calls and returns ride the CPU's return predictor (OPT_RSP,
       which keeps guest sp in rsp, cannot be combined with it and measured ~0 gain) */
    slot_opt = o ? (atoi(o) & 7) : file_opt >= 0 ? file_opt : 7;
    /* learning (a64slot.c): on with the slots unless ARM2X86_SLOTS_LEARN=0; ARM2X86_SLOTS_HOT=N = the back-edge count */
    { extern int a2x_func_bounds(uint64_t, uint64_t *, uint64_t *);
      const char *le = getenv("ARM2X86_SLOTS_LEARN"), *ht = getenv("ARM2X86_SLOTS_HOT");
      slot_learn = le ? atoi(le) > 0 : file_learn >= 0 ? file_learn > 0 : 1;
      if (slot_learn) slot_func_bounds = a2x_func_bounds;
      if (ht && atoi(ht) > 0) slot_hot_threshold = atoi(ht); }
    if (on) fprintf(a2x_errf(), "[slots] on, options %d, %d code sections noted\n", slot_opt, a2x_nsr);
    slot_census = getenv("ARM2X86_SLOTS_CENSUS") != 0;
    __atomic_store_n(&a2x_slots_on, on, __ATOMIC_RELEASE);
}
/* MEASURED 11-16 on 27: with every image refused, asking the slots on each interpreter step cost 25% (awk 7.7 s ->
      9.9 s). The interpreter runs only what the slots hand back, and most of that is outside every converted image
      (import stubs, code nobody noted), so the common answer must cost one load and two compares: the span of every
      noted code section (nothing outside it can ever be converted), and the switch a refusal throws. A refusal means
      the code area itself could not be had (no entitlement for writable+executable memory), so it switches the
      slots off for the whole process instead of being asked again on every step. */
static uint64_t a2x_slots_try(a64 *s) {
    unsigned long pc = s->pc;
    if (a2x_sl_dead || pc - a2x_sl_lo >= a2x_sl_hi - a2x_sl_lo) return SLOT_NONE;
    uint64_t r = slot_run(s);
    if (r != SLOT_NONE) return r;
    int n = __atomic_load_n(&a2x_nsr, __ATOMIC_ACQUIRE), hit = -1;
    for (int i = 0; i < n; i++) if (pc - a2x_sr[i].lo < a2x_sr[i].hi - a2x_sr[i].lo) { hit = i; break; }
    if (hit < 0 || __atomic_load_n(&a2x_sr[hit].state, __ATOMIC_ACQUIRE)) return SLOT_NONE;
    pthread_mutex_lock(&a2x_slots_mu);
    if (!a2x_sr[hit].state) {
        int rc = slot_image_add(a2x_sr[hit].lo, a2x_sr[hit].hi - a2x_sr[hit].lo);
        fprintf(a2x_errf(), "[slots] converted 0x%lx-0x%lx (%lu instructions): %s\n", a2x_sr[hit].lo, a2x_sr[hit].hi,
                (a2x_sr[hit].hi - a2x_sr[hit].lo) / 4, rc ? "REFUSED" : "ok");
        if (rc == -1) __atomic_store_n(&a2x_sl_dead, 1, __ATOMIC_RELEASE);   /* no code area: off for this process */
        if (!rc && getenv("ARM2X86_SLOTS_SKILLALL"))
            fprintf(a2x_errf(), "[slots] learned every function: %d\n", slot_learn_all(a2x_sr[hit].lo, a2x_sr[hit].hi - a2x_sr[hit].lo));
        __atomic_store_n(&a2x_sr[hit].state, rc ? 2 : 1, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&a2x_slots_mu);
    return slot_run(s);
}
static void a2x_slots_report(void) {
    struct slot_stats t; slot_stats_get(&t);
    fprintf(a2x_errf(), "[slots] runs %llu helper %llu lookups %llu | slots: template %llu helper %llu exit %llu overflow %llu\n",
            (unsigned long long)t.runs, (unsigned long long)t.helper, (unsigned long long)t.ilookup,
            (unsigned long long)t.k_template, (unsigned long long)t.k_helper, (unsigned long long)t.k_exit,
            (unsigned long long)t.overflow);
    { struct slot_learnst L; slot_learn_stats(&L);
      fprintf(a2x_errf(), "[slots] learning: hot %llu skills %llu failed %llu no-bounds %llu too-big %llu labels patched %llu\n",
              (unsigned long long)L.hot, (unsigned long long)L.skills, (unsigned long long)L.failed,
              (unsigned long long)L.nobounds, (unsigned long long)L.toobig, (unsigned long long)L.patched); }
    if (slot_census) slot_census_dump(a2x_errf(), 40);
}
#endif

static inline int in_arm_text(unsigned long a) {
    return __arm_text_base && a >= __arm_text_base && a < __arm_text_base + __arm_text_size;
}

/* THE DOOR CACHE. Everything the native-call path decides from the CALLEE ALONE (its name, whether it is
      a register-file bridge or the stack probe, which of the argument fixups can apply, whether the typed door
      can take it, whether it is swiftcc) is a pure function of the target address. It used to be re-derived on
      every call: a linear scan of up to 65,536 bound names, one over the bridge table, and ~100 strcmps against
      the fixup tables. MEASURED (strlen, 3.0e5 calls): 34% of samples in a64_variadic_fixup's strcmp chain, 18% in
      sig_door's, before any argument was touched.
    The verdict depends on the host's name tables, which only grow; an entry carries the table generation it was
      computed at and is recomputed when that moves, so an UNNAMED target (a vtable slot, a witness) is cached
      too and still becomes named if a later bind names it. Generation 0 means "cannot cache" (a translated
      image): the descriptor is then rebuilt on every call, which is the old behaviour. */
extern const char *a64_native_name(unsigned long addr);
extern int a64_is_rf_callee(unsigned long addr);
extern unsigned a64_names_gen(void);
extern unsigned a64_door_flags(const char *name);
extern int a2x_c_vtail_nfixed(const void *fn);
extern int a64_native_is_sret(const char *name);
extern int __arm2x86_sig_applies(const char *name);
struct a64_door {
    unsigned long tgt; unsigned gen;
    const char *nm;
    unsigned char chk, rf, swift, sigok, flags;      /* flags: 1 va_list 2 CFGregorianDate 4 variadic */
    signed char vnf;                                  /* fixed int args of a prologue-detected C variadic, -1 none */
    unsigned char sret;                               /* takes an indirect result: x8 goes to rdi (vararg.c) */
};
#define DOOR_N 8192
static struct a64_door g_door[DOOR_N];
static unsigned g_doorseq[DOOR_N];                    /* seqlock: odd while a writer is in the slot */
static pthread_mutex_t g_doorm = PTHREAD_MUTEX_INITIALIZER;

/* The error a swiftcc callee hands back in r12 is only meaningful when the callee has a swifterror parameter, and a
   caller that reaches one always zeroes x21 first. Everywhere else x21 is an ordinary callee-saved guest register
   the callee must preserve, so the guest value is put back (same rule as the C door in xlat2's native adapter: "the
   slot is put back as it came in"). A thrown error is a heap box, never an address on the native stack; that is
   what a callee which did not preserve r12 (an async suspend/resume point, a coroutine switch) leaves behind.
   ARM2X86_TRACE_X21=1 prints every call whose r12 came back different, with the verdict. */
/* 11-05 r14k: the large stack a deep chain moves to; see __arm2x86_interp_run. Read by the swifterror test below. */
static __thread unsigned long a2x_bs_lo, a2x_bs_hi, a2x_th_lo;
static int a64_on_native_stack(unsigned long a) {
    if (a2x_bs_lo && a >= a2x_bs_lo && a < a2x_bs_hi) return 1;
    pthread_t me = pthread_self();
    unsigned long hi = (unsigned long)pthread_get_stackaddr_np(me), lo = hi - (unsigned long)pthread_get_stacksize_np(me);
    return a >= lo && a < hi;
}
static unsigned long a64_swifterr_out(const char *nm, unsigned long tgt, unsigned long in, unsigned long out) {
    static int tr = -1;
    if (tr < 0) tr = A2X_DBGENV("ARM2X86_TRACE_X21") ? 1 : 0;
    if (out == in) return out;
    int keep = (in == 0) && !a64_on_native_stack(out);
    if (tr) fprintf(a2x_errf(), "[x21] %s 0x%lx in=%lx r12out=%lx -> %s\n", nm ? nm : "(unnamed)", tgt, in, out,
                    keep ? "error kept" : "restored");
    return keep ? out : in;
}

static int door_swift(const char *nm) {
    if (!nm) {
        static int unn = -1;
        if (unn < 0) unn = A2X_DBGENV("ARM2X86_UNNAMED_C") ? 0 : 1;
        return unn;
    }
    if (nm[0] == '$' ? nm[1] == 's' : (nm[0] == '_' && nm[1] == '$' && nm[2] == 's')) return 1;
    const char *b = nm[0] == '_' && nm[1] == 's' && nm[2] == 'w' ? nm + 1 : nm;
    return !strncmp(b, "swift_getAtKeyPath", 18) || !strncmp(b, "swift_setAt", 11)
        || !strncmp(b, "swift_modifyAt", 14)
        || !strcmp(b, "swift_task_switch")
        || !strcmp(b, "swift_continuation_await")
        || !strncmp(b, "swift_task_future_wait", 22)
        || !strncmp(b, "swift_asyncLet_get", 18) || !strncmp(b, "swift_asyncLet_wait", 19)
        || !strncmp(b, "swift_asyncLet_consume", 22) || !strcmp(b, "swift_asyncLet_finish")
        || !strncmp(b, "swift_taskGroup_wait_next", 25);
}

static void door_fill(unsigned long tgt, unsigned gen, struct a64_door *d) {
    const char *nm = a64_native_name(tgt);
    d->tgt = tgt; d->gen = gen; d->nm = nm;
    d->chk = nm && (!strcmp(nm, "__chkstk_darwin") || !strcmp(nm, "___chkstk_darwin"));
    d->rf = a64_is_rf_callee(tgt) ? 1 : 0;
    d->flags = nm ? (unsigned char)a64_door_flags(nm) : 0;
    /* an rf callee (CGRectInset and the other by-value geometry) never reaches the sig door; asking would only print
       a false "sigdb cannot type" refusal for a call a register-file handler already places correctly */
    d->sigok = (nm && !d->rf) ? (unsigned char)__arm2x86_sig_applies(nm) : 0;
    d->swift = door_swift(nm) ? 1 : 0;
    /* a C variadic no name rule covers: its nfixed comes from its own prologue (vtail.h, B34) */
    d->sret = (nm && !d->rf && !d->swift && a64_native_is_sret(nm)) ? 1 : 0;
    d->vnf = (nm && !d->sret && !d->rf && !d->swift && !d->chk && !(d->flags & 7)) ? (signed char)a2x_c_vtail_nfixed((const void *)tgt) : -1;
}

static void door_get(unsigned long tgt, struct a64_door *out) {
    unsigned gen = a64_names_gen();
    if (!gen) { door_fill(tgt, 0, out); return; }
    unsigned h = (unsigned)(((tgt >> 2) * 0x9E3779B97F4A7C15UL) >> 51) & (DOOR_N - 1);
    unsigned s1 = __atomic_load_n(&g_doorseq[h], __ATOMIC_ACQUIRE);
    if (!(s1 & 1)) {
        memcpy(out, &g_door[h], sizeof *out);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if (__atomic_load_n(&g_doorseq[h], __ATOMIC_RELAXED) == s1 && out->tgt == tgt && out->gen == gen) return;
    }
    door_fill(tgt, gen, out);
    if (pthread_mutex_trylock(&g_doorm)) return;      /* contended: use the answer, skip the install */
    unsigned s0 = g_doorseq[h];
    __atomic_store_n(&g_doorseq[h], s0 + 1, __ATOMIC_RELAXED);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    memcpy(&g_door[h], out, sizeof *out);
    __atomic_store_n(&g_doorseq[h], s0 + 2, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_doorm);
}

/* xs: x0..x30 then sp (32 slots). vs: v0..v31 (32 x 16 bytes). Both are the IR entry's own allocas. */
/* 11-05 r14k: A DEEP NATIVE-TO-GUEST CHAIN OVERFLOWED A WORKER STACK AND THE PROCESS VANISHED WITH NO REPORT.
      A native call into a guest function nests a signal frame and an interpreter run on the caller's own stack, about 7 KB per
      level against what the same arm64 frames would cost. Worker threads have 512 KB. Measured: WallpaperAgent logged LOW-STACK
      91,784 bytes left at fault depth 60 and launchd restarted it at once with no fault block (no stack left to report on); the
      session stayed without wallpaper until the replacement ran. A thread with under 256 KB left continues on a 64 MiB mapping,
      touched lazily, with a guard page, kept per thread. rbp links the two stacks, so unwinding and frame walks cross it through
      the frame below. The swifterror test counts the mapping as the native stack. A failed map runs where it is, as before. */
#include <sys/mman.h>
#define A2X_BS_LEN (64ul << 20)
#define A2X_BS_MARGIN (256ul << 10)
__asm__(".text\n.p2align 4\n_a2x_call_on_stack:\n"
        ".cfi_startproc\n"
        "pushq %rbp\n.cfi_def_cfa_offset 16\n.cfi_offset %rbp, -16\n"
        "movq %rsp, %rbp\n.cfi_def_cfa_register %rbp\n"
        "movq %r8, %rsp\n"
        "movq %rdi, %rax\nmovq %rsi, %rdi\nmovq %rdx, %rsi\nmovq %rcx, %rdx\n"
        "callq *%rax\n"
        "movq %rbp, %rsp\npopq %rbp\n.cfi_def_cfa %rsp, 8\nretq\n"
        ".cfi_endproc\n");
extern int a2x_call_on_stack(int (*)(unsigned long, unsigned long *, unsigned char *), unsigned long, unsigned long *, unsigned char *, unsigned long) __asm__("_a2x_call_on_stack");
static int a2x_interp_run_here(unsigned long target, unsigned long *xs, unsigned char *vs);
static pthread_key_t a2x_bs_key;
static pthread_once_t a2x_bs_once = PTHREAD_ONCE_INIT;
static void a2x_bs_free(void *p) {
    unsigned long here = (unsigned long)__builtin_frame_address(0), lo = (unsigned long)p;
    if (here >= lo && here < lo + A2X_BS_LEN) return;   /* pthread_exit from a guest on this stack: it dies with the thread's address space use */
    munmap(p, A2X_BS_LEN);
}
static void a2x_bs_key_make(void) { (void)pthread_key_create(&a2x_bs_key, a2x_bs_free); }
/* C6 11-06 A GUEST brk / udf IS THE PROGRAM'S OWN ASSERT, AND IT MUST DIE THE WAY IT DIES ON arm64.
      The interpreter returned RT_TRAP and every caller made up its own ending: the main entry exited 7 (watchdogd's
      os_crash, offline), the callback slot and the ObjC method door called abort() (134), and a native->guest call
      recovered in the fault handler fell back to reporting the ORIGINAL native fault — mds on the 27.2 box: "SIGBUS at
      guest pc 0x0, faulting address 0x100014ff8 ... A DIFFERENT THREAD", read as a missing libxpc trampoline, when the
      block had run 124 instructions and reached MDSAssert's brk #1 at 0x100015194 (listener got "Connection invalid").
    arm64 truth, measured natively on the mini (c6/xl oracle): brk -> SIGTRAP (rc 133); udf is SIGILL (132). One
      line names the guest pc, insn and registers; then the signal goes to its default action, as on the real chip.
    HLT (also A64_BRK in the decoder) keeps the old RT_TRAP path. */
#include <signal.h>
static void a64_guest_trap_die(unsigned long pc, unsigned insn, unsigned long lr, unsigned long x0,
                               unsigned long x1, unsigned long x16) {
    int is_brk = (insn & 0xffe0001fu) == 0xd4200000u;
    int is_udf = (insn >> 16) == 0;
    if (!is_brk && !is_udf) return;
    int sg = is_brk ? SIGTRAP : SIGILL;
    fprintf(a2x_errf(), "[host] GUEST TRAP %s at guest pc 0x%lx (insn 0x%08x) lr 0x%lx x0 0x%lx x1 0x%lx x16 0x%lx — "
            "the program's own assert; dying %s as arm64 does\n", is_brk ? "brk" : "udf", pc, insn, lr, x0, x1, x16,
            is_brk ? "SIGTRAP" : "SIGILL");
    fflush(a2x_errf());
#if A2X_SLOTS
    /* the crash report's "Application Specific Information": the guest pc and the last functions learning compiled.
          A launchd job's stderr is /dev/null and a sandboxed one cannot write /tmp, so the report itself carries it. */
    { static char cm[1024]; int k = snprintf(cm, sizeof cm, "a2x GUEST TRAP %s pc 0x%lx insn 0x%08x lr 0x%lx x0 0x%lx | slots %s opt %d learn %d | learned %u:",
                                            is_brk ? "brk" : "udf", pc, insn, lr, x0, a2x_slots_on > 0 ? "on" : "off", slot_opt, slot_learn, slot_learned_n);
      for (unsigned i = 0; i < 16 && i < slot_learned_n && k < (int)sizeof cm - 24; i++)
          k += snprintf(cm + k, sizeof cm - k, " 0x%llx", (unsigned long long)slot_learned_ring[(slot_learned_n - 1 - i) & 15]);
      a2x_crash_info.message = (uint64_t)(uintptr_t)cm; }
    /* a launchd job's stderr is /dev/null: the trap would leave no guest pc anywhere. One small file per death. */
    { char fn[256]; snprintf(fn, sizeof fn, "/tmp/a2x-stop-%s.%d.txt", getprogname(), (int)getpid());
      FILE *tf = fopen(fn, "w");
      if (tf) { struct slot_stats t; slot_stats_get(&t);
                fprintf(tf, "GUEST TRAP %s at guest pc 0x%lx (insn 0x%08x) lr 0x%lx x0 0x%lx x1 0x%lx x16 0x%lx slots %s opt %d learn %d runs %llu\n",
                        is_brk ? "brk" : "udf", pc, insn, lr, x0, x1, x16, a2x_slots_on > 0 ? "on" : "off", slot_opt, slot_learn,
                        (unsigned long long)t.runs);
                fclose(tf); } }
#endif
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigaction(sg, &sa, 0);
    sigset_t m; sigemptyset(&m); sigaddset(&m, sg);
    pthread_sigmask(SIG_UNBLOCK, &m, 0);
    raise(sg);
    _exit(128 + sg);                       /* not reached: the default action ends the process */
}

int __arm2x86_interp_run(unsigned long target, unsigned long *xs, unsigned char *vs) {
    unsigned long here = (unsigned long)__builtin_frame_address(0);
    if (!a2x_th_lo) {
        pthread_t me = pthread_self();
        a2x_th_lo = (unsigned long)pthread_get_stackaddr_np(me) - (unsigned long)pthread_get_stacksize_np(me);
    }
    if (here < a2x_th_lo || here - a2x_th_lo >= A2X_BS_MARGIN || (a2x_bs_lo && here >= a2x_bs_lo && here < a2x_bs_hi))
        return a2x_interp_run_here(target, xs, vs);
    if (!a2x_bs_lo) {
        void *m = mmap(0, A2X_BS_LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (m == MAP_FAILED) return a2x_interp_run_here(target, xs, vs);
        (void)mprotect(m, 0x4000, PROT_NONE);
        pthread_once(&a2x_bs_once, a2x_bs_key_make);
        (void)pthread_setspecific(a2x_bs_key, m);
        a2x_bs_lo = (unsigned long)m; a2x_bs_hi = a2x_bs_lo + A2X_BS_LEN;
    }
    return a2x_call_on_stack(a2x_interp_run_here, target, xs, vs, (a2x_bs_hi - 64) & ~15ul);
}
static int a2x_interp_run_here(unsigned long target, unsigned long *xs, unsigned char *vs) {
    /* Native callbacks can re-enter while an enclosing bridge is still
       preparing a call. Keep its argument state separate from this entry. */
    extern __thread unsigned char __arm2x86_rf[208];
    extern __thread unsigned long __arm2x86_rfall[31];
    _Alignas(16) unsigned char enclosing_rf[208];
    unsigned long enclosing_rfall[31];
    memcpy(enclosing_rf, __arm2x86_rf, sizeof enclosing_rf);
    memcpy(enclosing_rfall, __arm2x86_rfall, sizeof enclosing_rfall);
    a64 s;
    memset(&s, 0, sizeof s);
    memcpy(s.x, xs, 31 * sizeof(unsigned long));
    s.sp = xs[31];
    memcpy(s.v, vs, sizeof s.v);
    s.pc = target;
    s.x[30] = A64_RET_SENTINEL;
    /* a crash report must never name a frame that has returned: restore the enclosing run's state on exit */
    const a64 *prev_state = a64_cur_state;
    unsigned long prev_pc = a64_cur_pc;
    uint32_t prev_insn = a64_cur_insn;
    /* recover_guest_call() can hand over x0..x5 and x8; the 7th and 8th integer arguments of a native
          caller sit on ITS stack, so they are unknown here and start as "not written for any call". */
    unsigned long a64_s6 = s.x[6], a64_s7 = s.x[7];
    /* A function entered from native code holds its own incoming arguments in x6 and x7, exactly as one entered by a
       guest call does (there the caller's writes left both flags set). The flags started clear here, so a function that
       forwards its seventh argument untouched - a protocol-witness thunk that tail-calls back into native code - had it
       dropped: Weather's thunk for SwiftUI.DynamicProperty._makeProperty lost the witness table in x6 and the callee
       compared a null one (swift::MetadataCacheKey::areWitnessTablesEqual, fault at 0). The first call boundary clears
       them as before. */
    s.argw = 3;

    /* the thread pointer the way the lifter reports it: %gs:0 plus the measured TSD offset */
    unsigned long self = 0;
    __asm__ volatile("movq %%gs:0, %0" : "=r"(self));
    s.tsd = self + __arm_tsd_off;

    /* THE NATIVE CALL IS WHAT MAKES THIS AN OS FEATURE RATHER THAN A PER-APP TRICK. An interpreted
          program spends most of its life calling the real x86 frameworks; refusing at that boundary meant
          only self-contained functions could run. The door is IR (xlat2.py @__arm2x86_interp_native) for the
          same ABI reason the native adapter is: the proven call is variadic and returns four registers. */
    extern void *const __arm2x86_interp_native_p;
    void (*ncall)(unsigned long, unsigned long *, unsigned char *, unsigned long) =
        (void (*)(unsigned long, unsigned long *, unsigned char *, unsigned long))__arm2x86_interp_native_p;

    int rc = RT_OK;
    unsigned long long steps = 0;
    unsigned long long ncalls = 0;
    unsigned long fault_at = 0;
    uint32_t fault_insn = 0;

    /* the two environment switches are read ONCE per entry, not once per instruction */
    const unsigned long long maxsteps = a64_max_steps();
    static long long tsteps = -1;
    if (tsteps < 0) {
        const char *e = A2X_DBGENV("ARM2X86_INTERP_STEPS"); tsteps = e ? atoll(e) : 0;
        /* a launchd child gets no env of ours: "/usr/libexec/a2x/steps" = "N progname" traces that one */
        FILE *sf = (!e && getppid() == 1) ? fopen("/usr/libexec/a2x/steps", "r") : NULL;
        if (sf) { long long n = 0; char nm[64] = "";
                  if (fscanf(sf, "%lld %63s", &n, nm) == 2 && !strcmp(nm, getprogname())) tsteps = n;
                  fclose(sf); }
    }
    const long long tsteps_l = tsteps;
    /* 10-31 THE DECODE CACHE (a64_cache.c). A hit skips the text-range check, the seal lookup, the fetch, the
          op0 table and the group's decode: one index, one compare, one call into the same exec a64_step would run.
 an entry exists only for a pc that passed the text check when it was filled, and the text only grows;
 a fault inside a cached instruction still names it exactly: s.pc is that instruction's address until its
            exec returns, and host.c a2x_report_pc() reads the published state (no per-instruction TLS store here);
 a64_cur_pc/insn are written where control leaves for native code or a syscall, as the call site;
 after every return from native code (repub) the state is re-published and the epoch re-read, so a code
            change made while we were out (a late image load, a guest IC IVAU) orphans every older entry.
        ARM2X86_NO_ICACHE=1 runs the old path (the A/B switch and the kill switch), and so does the step trace. */
    /* 11-01 ARM2X86_INTERP_WATCH="pc,pc,..." (or /usr/libexec/a2x/watch = "progname pc pc ...", for a
          launchd child) prints x0/x1/errno each time one of those guest pcs is about to run — put the pc just
          after a `bl` to read what the call returned. Up to 16 pcs, 64 lines a process; off = one branch. */
    static int nwatch = -1;
    static unsigned long wpc[16];
    static int whits;
    if (nwatch < 0) {
        nwatch = 0;
        char wb[512] = "";
        const char *e = A2X_DBGENV("ARM2X86_INTERP_WATCH");
        if (e) snprintf(wb, sizeof wb, "%s", e);
        else if (getppid() == 1) {
            FILE *wf = fopen("/usr/libexec/a2x/watch", "r");
            char nm[64] = "";
            if (wf) {
                if (fscanf(wf, "%63s", nm) == 1 && !strcmp(nm, getprogname()) && !fgets(wb, sizeof wb, wf)) wb[0] = 0;
                fclose(wf);
            }
        }
        char *sv = NULL;
        for (char *t = strtok_r(wb, ", \n", &sv); t && nwatch < 16; t = strtok_r(NULL, ", \n", &sv))
            wpc[nwatch++] = strtoul(t, NULL, 16);
        if (nwatch) fprintf(a2x_errf(), "[watch] %d pc(s) armed in %s\n", nwatch, getprogname());
    }
    static int noic = -1;
    if (noic < 0) noic = A2X_DBGENV("ARM2X86_NO_ICACHE") ? 1 : 0;
    struct a64_ce *const ct = (noic || tsteps_l > 0 || nwatch) ? 0 : a64c_table();
    uint64_t epk = ct ? a64c_epoch(&s.cgen) : 0;
    int repub = 0;
    if (ct) a64_cur_state = &s;
#if A2X_SLOTS
    static pthread_once_t slots_once = PTHREAD_ONCE_INIT;
    pthread_once(&slots_once, a2x_slots_init);
    static int slots_rep = -1;
    if (slots_rep < 0) { slots_rep = getenv("ARM2X86_SLOTS_STATS") ? 1 : 0; if (slots_rep) atexit(a2x_slots_report); }
    const int slots = a2x_slots_on > 0 && tsteps_l <= 0 && !nwatch;   /* the step trace and the watch see every instruction */
    unsigned long slot_skip = 1;                                      /* the pc the interpreter must run next (never a real pc) */
#endif
    for (;;) {
        if (++steps > maxsteps) { rc = RT_BUDGET; fault_at = s.pc; break; }
        uint32_t insn = 0;
        int ev;
        unsigned long ipc = s.pc;
#if A2X_SLOTS
        if (slots && ipc != slot_skip) {
            uint64_t sr = a2x_slots_try(&s);
            if (sr != SLOT_NONE) {
                /* the slots mark x6/x7 writes in two plain bytes; argw is the interpreter's record of the same thing */
                s.argw |= (uint8_t)(s.argwx[0] | (s.argwx[1] << 1));
                s.argwx[0] = s.argwx[1] = 0;
                if (sr == SLOT_EXIT) { slot_skip = s.pc; continue; }
                ipc = slot_ev_pc; ev = (int)(sr & 0xff);
                goto slot_ev;
            }
        }
#endif
        if (ct) {
            if (__builtin_expect(repub, 0)) {
                /* MEASURED 10-31: re-reading the epoch through a64c_epoch() (a call and two TLS reads) after EVERY
                      native return cost msg +18%, strlen +13% under Rosetta. The generation is one global load; the
                      epoch only needs re-reading when it moved (a nested run moves this thread's epoch only then). */
                a64_cur_state = &s;
                if (__atomic_load_n(&a64_code_gen, __ATOMIC_ACQUIRE) != s.cgen) epk = a64c_epoch(&s.cgen);
                repub = 0;
            }
            struct a64_ce *e = &ct[(ipc >> 2) & (A64C_N - 1)];
            if (__builtin_expect(e->key != (ipc | epk), 0)) {
                if (!in_arm_text(ipc)) { rc = RT_LEFT_IMAGE; fault_at = ipc; break; }
                insn = a64_fetch(ipc);
                a64c_fill(e, ipc | epk, insn);
            }
            ev = e->x(&s, &e->d);
        } else {
            if (!in_arm_text(s.pc)) { rc = RT_LEFT_IMAGE; fault_at = s.pc; break; }   /* only reachable at entry */
            insn = a64_fetch(s.pc);
            a64_cur_pc = s.pc; a64_cur_insn = insn; a64_cur_state = &s;
            /* ARM2X86_INTERP_STEPS=N prints the first N instructions with the registers a fault would name.
                  A SIGSEGV inside interpreted code kills the process with no line of ours in the log, and lldb
                  cannot attach over ssh here — so the trace is the instrument. */
            if ((long long)steps <= tsteps_l)
                fprintf(a2x_errf(), "[step %4llu] 0x%lx  %08x  x0=%lx x1=%lx x16=%lx sp=%lx lr=%lx\n",
                        steps, s.pc, insn, s.x[0], s.x[1], s.x[16], s.sp, s.x[30]);
            if (nwatch && whits < 400)
                for (int wi = 0; wi < nwatch; wi++)
                    if (wpc[wi] == s.pc) {
                        whits++;
                        fprintf(a2x_errf(), "[watch] 0x%lx  x0=%lx x1=%lx x2=%lx x3=%lx x4=%lx x5=%lx x6=%lx x7=%lx x19=%lx x25=%lx errno=%d lr=%lx\n",
                                s.pc, s.x[0], s.x[1], s.x[2], s.x[3], s.x[4], s.x[5], s.x[6], s.x[7], s.x[19], s.x[25], errno, s.x[30]);
                        break;
                    }
            ev = a64_step(&s, insn);
        }
#if A2X_SLOTS
    slot_ev:
#endif
        switch (ev) {
        case A64_NEXT:
            s.pc += 4;
            continue;
        case A64_CODECHG:                   /* a generic entry saw the code generation move: new epoch, then on */
            s.pc += 4;
            epk = a64c_epoch(&s.cgen);
            continue;
        case A64_JUMP:
        case A64_CALL:
            /* A typed closure called by guest code already has AAPCS64 arguments. */
            if (!in_arm_text(s.pc)) {
                extern unsigned long __arm2x86_objc_imp_target(unsigned long);
                unsigned long guest = __arm2x86_objc_imp_target(s.pc);
                if (guest && in_arm_text(guest)) s.pc = guest;
            }
            if (!in_arm_text(s.pc)) {
                /* THE TARGET IS NATIVE. A `bl` into native code returns here and carries on; a `b` or
                      `br x16` is a TAIL call — an import stub is exactly that — so its result is this
                      frame's result and we return to whatever x30 held. */
                /* C1 11-06 native target 0 through an import stub: x17 holds the slot (arm64e stub shape). host.c
                      names it and exits 69 if the binder left that slot empty; otherwise this returns and the call faults
                      as before. */
                if (!s.pc) { extern void a2x_missing_import_called(unsigned long, unsigned long); a2x_missing_import_called(s.x[17], ipc); }
                if (!ncall) { rc = RT_LEFT_IMAGE; fault_at = s.pc; goto done; }
                a64_cur_pc = ipc; a64_cur_insn = 0;   /* the call site; the report reads its word back (host.c) */
                repub = 1;
                unsigned long xs2[32];
                memcpy(xs2, s.x, 31 * sizeof(unsigned long));
                xs2[31] = s.sp;
                unsigned long tgt = s.pc;
                /* A VARIADIC CALLEE NEEDS ITS ARGUMENTS MOVED, not just handed over: arm64 put them on
                      the stack and x86 reads them from registers (vararg.c). The host names the symbol at
                      this address; without a name nothing is re-marshalled. */
                extern const char *a64_native_name(unsigned long addr);
                extern int a64_variadic_fixup(const char *name, const a64 *st,
                                              unsigned long *xsp, unsigned char *vsp);
                struct a64_door dd;
                door_get(tgt, &dd);
                const char *nm = dd.nm;
                /* a guest cleanup pad ends in _Unwind_Resume: the next guest landing pad, not libunwind */
                if (a2x_eh_is_resume(tgt) && a2x_eh_resume(&s)) { ncalls++; continue; }
                /* The ARM stack probe takes its byte count in x9 and preserves
                   the argument registers. Calling the Intel helper through the
                   C adapter corrupts arguments before the function saves them.
                   Probe the guest stack directly and preserve the ARM state. */
                if (dd.chk) {
                    if (s.x[9] > s.sp) {
                        rc = RT_TRAP; fault_at = s.pc; goto done;
                    }
                    unsigned long low = s.sp - s.x[9];
                    for (unsigned long p = s.sp; p > low;) {
                        p -= p - low > 4096 ? 4096 : p - low;
                        (void)*(volatile const unsigned char *)(uintptr_t)p;
                    }
                    ncalls++;
                    s.pc = s.x[30];
                    if (s.pc == A64_RET_SENTINEL) goto done;
                    continue;
                }
                /* A BRIDGE WRAPPER IS ENTERED THROUGH THE REGISTER FILE, not as a C function: it takes no
                      arguments and returns nothing, reading x0..x8 and v0..v7 out of __arm2x86_rf and
                      writing its result back there. That is how objc_msgSend and friends reach guest code. */
                extern __thread unsigned char __arm2x86_rf[208];
                extern void *a2x_native_imp_plan(unsigned long, unsigned long);
                extern void a2x_call_native_imp(unsigned long, void *);
                void *imp_plan = a2x_native_imp_plan(tgt, s.x[1]);
                if (imp_plan || dd.rf) {
                    unsigned long *rf = (unsigned long *)__arm2x86_rf;
                    for (int k = 0; k <= 8; k++) rf[k] = s.x[k];
                    /* 10-27 THE SIDE CHANNEL: all 31 integer registers, not the 9 the 208-byte register
                          file can hold. The register-specialised retain/release helpers (_objc_retain_x19,
                          _swift_release_x28, ...) take their object in a CALLEE-SAVED register, which x0..x8
                          cannot express at all — the per-app lifter moves it for them and the interpreter
                          has no lifter. Strictly additive: __arm2x86_rf and the read-back below are untouched,
                          so every existing wrapper behaves exactly as before. */
                    extern __thread unsigned long __arm2x86_rfall[31];
                    memcpy(__arm2x86_rfall, s.x, 31 * sizeof(unsigned long));
                    for (int j = 0; j < 8; j++) memcpy(__arm2x86_rf + 80 + 16 * j, s.v[j], 16);
                    __arm_sp = s.sp;
                    unsigned long rfeo = 0;
                    a2x_eh_push(&s);
                    int rfth = imp_plan ? __arm2x86_eh_guard((void *)a2x_call_native_imp, &rfeo, tgt, (unsigned long)imp_plan, 0, 0, 0)
                                        : __arm2x86_eh_guard((void *)(uintptr_t)tgt, &rfeo, 0, 0, 0, 0, 0);
                    a2x_eh_pop(&s);
                    if (rfth) { if (!a2x_eh_land(&s, (void *)rfeo)) a2x_eh_fatal((void *)rfeo); ncalls++; continue; }
                    /* READ BACK THE WHOLE RETURN, NOT A QUARTER OF IT. AAPCS64 returns a composite
                          either in the PAIR x0:x1 (up to 16 bytes) or as an HFA in v0-v3 — and this read
                          back only x0 and v0, so three quarters of every struct return was whatever the
                          caller's registers already held.
                        MEASURED 10-26: NSInsetRect({11,22,33,44}, 1, 2) came back 12 22 33 44. The x WAS
                          inset correctly, which is the tell — the handler ran and was right, and then y, w
                          and h arrived as the guest's own untouched input. Seen from the other end, every
                          objc_msgSend returning NSRect/CGRect/CGSize/NSRange loses its last three fields:
                          -[NSWindow frame], -[NSView bounds], -[NSScreen visibleFrame]. A frame whose width
                          and height are whatever v2/v3 last held is a 0x0 WINDOW, which is exactly what
                          Chess's three windows measured.
                        The per-app bind has always done this correctly (arm2x86.py:1323-1328 reloads x1 and
                          v0-v3). This was the HOST failing to match its own certified reference, so the fix
                          is to copy that path register for register rather than invent one. */
                    s.x[0] = rf[0];
                    s.x[1] = rf[1];
                    for (int j = 0; j < 4; j++) memcpy(s.v[j], __arm2x86_rf + 80 + 16 * j, 16);
                    a64_mark_argregs(&a64_s6, &a64_s7, &s);   /* the wrapper was a call */
                    s.pc = s.x[30];
                    if (s.pc == A64_RET_SENTINEL) goto done;
                    ncalls++;
                    continue;
                }
                /* a va_list argument becomes an x86 va_list over the same slots, for every door below */
                struct a64_x86va { unsigned g, f; void *o, *r; } va_x86;
                extern int a64_valist_fixup(const char *, unsigned long *, struct a64_x86va *);
                if (dd.flags & 1) a64_valist_fixup(nm, xs2, &va_x86);
                extern int a2x_native_loader_call(unsigned long,unsigned long *);
                if(a2x_native_loader_call(tgt,xs2)) {
                    ncalls++;s.x[0]=xs2[0];
                    a64_mark_argregs(&a64_s6,&a64_s7,&s);s.pc=s.x[30];
                    if(s.pc==A64_RET_SENTINEL)goto done;
                    continue;
                }
                extern int a64_cfgreg_door(const char *, unsigned long, unsigned long *, unsigned char *);
                if ((dd.flags & 2) && a64_cfgreg_door(nm, tgt, xs2, (unsigned char *)s.v)) {
                    ncalls++;
                    s.x[0] = xs2[0]; s.x[1] = xs2[1];
                    a64_mark_argregs(&a64_s6, &a64_s7, &s);
                    s.pc = s.x[30];
                    if (s.pc == A64_RET_SENTINEL) goto done;
                    continue;
                }
                /* Resolve known C signatures before the untyped native call. */
                __arm_sp = s.sp;
                int sigr = 0;
                if (dd.sigok) {
                    unsigned long sigeo = 0;
                    a2x_eh_push(&s);
                    int sigth = __arm2x86_eh_guard((void *)__arm2x86_sig_door, &sigeo, (unsigned long)nm, tgt,
                                                   (unsigned long)xs2, (unsigned long)s.v, s.sp);
                    a2x_eh_pop(&s);
                    if (sigth) { if (!a2x_eh_land(&s, (void *)sigeo)) a2x_eh_fatal((void *)sigeo); ncalls++; continue; }
                    sigr = (int)sigeo;
                }
                if (sigr) {
                    ncalls++;
                    s.x[0] = xs2[0];
                    a64_mark_argregs(&a64_s6, &a64_s7, &s);
                    s.pc = s.x[30];
                    if (s.pc == A64_RET_SENTINEL) goto done;
                    continue;
                }
                /* A NATIVE SWIFT FUNCTION NEEDS THE OTHER DOOR. swiftcc keeps `self` in arm64 x20 but in
                      x86 r13, the error in x21 but r12, the async context in x22 but r14 — so the C door,
                      which carries only x0-x7/v0-v7, hands a Swift method garbage for `self`. Measured
                      10-26: every remaining crash with a nameable callee was a $s-mangled symbol.
                    The TEST IS THE MANGLING, which is exact rather than heuristic: Swift 5 mangles every
                      swiftcc symbol as `$s...` (`_$s...` in the symbol table), and nothing else does. A
                      C-convention helper that merely lives in a Swift library — __swift_memcpy40_8,
                      __swift_closure_destructor — is not mangled, and correctly takes the C door. */
                extern void __arm2x86_swift_door(unsigned long, unsigned long *, unsigned char *,
                                                 unsigned long, unsigned long);
                /* the mangling / key-path / swiftasync tests are a function of the name: door_swift() */
                int swiftcall = dd.swift;
                if (!nm) {
                    /* A callee with no recorded name was not bound by symbol: it is a pointer the guest loaded from
                       metadata (a class vtable slot, a protocol witness); door_swift() sends it to the Swift door. */
                    static int tun = -1;
                    if (tun < 0) tun = A2X_DBGENV("ARM2X86_TRACE_UNNAMED") ? 1 : 0;
                    if (tun) fprintf(a2x_errf(), "[unnamed] native 0x%lx from 0x%lx x20=%lx x8=%lx -> %s door\n", tgt, s.pc - 0, s.x[20], s.x[8], swiftcall ? "swift" : "C");
                }
                if (swiftcall) {
                    /* 8 = x7 was written for this call, 7 = x6 was, 6 = neither */
                    unsigned long nint = (s.argw & 2) ? 8 : ((s.argw & 1) ? 7 : 6); (void)a64_s6; (void)a64_s7;
                    /* ARM2X86_TRACE_SWIFTDOOR=<text>: log every named native Swift call whose mangled name contains
                       <text> (empty = all), with the register count this door chose and the first stack words. The
                       count is inferred from which of x6/x7 the guest wrote, so a wrong count shows here as an
                       argument that sits one or two slots away from where the callee reads it. */
                    { static const char *tsd; static int tsdi;
                      if (!tsdi) { tsd = A2X_DBGENV("ARM2X86_TRACE_SWIFTDOOR"); tsdi = 1; }
                      if (tsd && nm && (!*tsd || strstr(nm, tsd))) {
                          const unsigned long *sw = (const unsigned long *)s.sp;
                          fprintf(a2x_errf(), "[swiftdoor] %s nint=%lu pc=0x%lx x0-7=%lx %lx %lx %lx %lx %lx %lx %lx x8=%lx x20=%lx "
                                  "sp0-3=%lx %lx %lx %lx\n", nm, nint, (unsigned long)s.pc, xs2[0], xs2[1], xs2[2], xs2[3], xs2[4],
                                  xs2[5], xs2[6], xs2[7], xs2[8], xs2[20], sw[0], sw[1], sw[2], sw[3]);
                      } }
                    extern int a2x_swift_stack_prepare(const char *, unsigned long, const unsigned long *,
                                                       const unsigned char *, unsigned long, unsigned char *);
                    _Alignas(16) unsigned char native_stack[512];
                    extern int a2x_stk_relay(unsigned long, unsigned long, unsigned long *, int);
                    if (nm && a2x_swift_stack_prepare(nm, tgt, xs2, (unsigned char *)s.v, s.sp, native_stack))
                        __arm2x86_swift_door(tgt, xs2, (unsigned char *)s.v, (unsigned long)native_stack, 6);
                    /* the signature could not be sized: the caller's own stores say how it packed the arguments */
                    else if (a2x_stk_relay(s.x[30], s.sp, (unsigned long *)(void *)native_stack, 64))
                        __arm2x86_swift_door(tgt, xs2, (unsigned char *)s.v, (unsigned long)native_stack, nint);
                    else
                        __arm2x86_swift_door(tgt, xs2, (unsigned char *)s.v, s.sp, nint);
                    s.x[21] = a64_swifterr_out(nm, tgt, s.x[21], xs2[21]);   /* the error swiftcc returns in x21 */
                    s.x[2] = xs2[2]; s.x[3] = xs2[3];   /* the 3rd and 4th return registers (rcx, r8) */
                } else {
                    extern __thread const unsigned long *a64_va_ovf;
                    extern int __arm2x86_sig_is_fixed(const char *);
                    a64_va_ovf = 0;
                    int fixed = (dd.flags & 4) ? a64_variadic_fixup(nm, &s, xs2, (unsigned char *)s.v) : 0;
                    unsigned long call_sp = a64_va_ovf ? (unsigned long)(uintptr_t)a64_va_ovf : s.sp;
                    a64_va_ovf = 0;
                    /* Private C variadics have no SDK name rule. Their exact
                       compiler register-save run identifies the fixed GP count. */
                    if (dd.vnf >= 0 && !fixed && !__arm2x86_sig_is_fixed(nm)) {
                        int nf = dd.vnf;   /* read once per target by door_fill, not on every call */
                        if (nf <= 5) {
                            const unsigned long *tail = (const unsigned long *)(uintptr_t)s.sp;
                            for (int j = nf; j < 8; j++) xs2[j] = tail[j - nf];
                            call_sp = s.sp + (8 - nf) * sizeof(unsigned long);
                        }
                    }
                    /* 11-01 x8 becomes rdi and every integer argument moves up one register */
                    if (dd.sret) { for (int j = 7; j > 0; j--) xs2[j] = xs2[j - 1]; xs2[0] = s.x[8]; }
                    __arm_sp = call_sp;
                    unsigned long nceo = 0;
                    a2x_eh_push(&s);
                    { extern __thread unsigned long a2x_native_lr; a2x_native_lr = s.x[30]; }   /* the call site, for the stack arguments' layout */
                    int ncth = __arm2x86_eh_guard((void *)ncall, &nceo, tgt, (unsigned long)xs2, (unsigned long)s.v, call_sp, 0);
                    a2x_eh_pop(&s);
                    if (ncth) { if (!a2x_eh_land(&s, (void *)nceo)) a2x_eh_fatal((void *)nceo); ncalls++; continue; }
                    extern int a64_native_return_is_u8(const char *);
                    if (a64_native_return_is_u8(nm)) xs2[0] &= 0xff;
                }
                ncalls++;
                s.x[0] = xs2[0]; s.x[1] = xs2[1];
                if (dd.flags & 8) s.x[0] &= 0xff;   /* an 8-bit return: bits 8..63 of rax are undefined (vararg.c) */
                a64_mark_argregs(&a64_s6, &a64_s7, &s);
                if (ev == A64_CALL) { s.pc = s.x[30]; }
                else {
                    s.pc = s.x[30];
                    if (s.pc == A64_RET_SENTINEL) goto done;
                }
                if (s.pc == A64_RET_SENTINEL) goto done;
                continue;
            }
            continue;                       /* a64_step already set pc (and x30 for a call) */
        case A64_RET:
            /* THE ONE EXIT THAT MEANS SUCCESS: the frame we were asked to run has returned. A `ret` to
                  anything else is a return deeper inside the interpreted code and simply continues. */
            if (s.pc == A64_RET_SENTINEL) goto done;
            continue;
        case A64_SVC: {
            a64_cur_pc = ipc; a64_cur_insn = 0; repub = 1;
            unsigned long a[9];
            for (int k = 0; k < 9; k++) a[k] = s.x[k];
            unsigned long r = __arm2x86_svc(s.x[16], a, 0, s.pc - 4);
            s.x[0] = a[0]; s.x[1] = a[1];
            (void)r;
            continue;
        }
        case A64_BRK:
            a64_guest_trap_die(ipc, a64_fetch(ipc), s.x[30], s.x[0], s.x[1], s.x[16]);   /* C6: returns for HLT only */
            rc = RT_TRAP; fault_at = s.pc; fault_insn = a64_fetch(ipc);
            goto done;
        default:
            rc = RT_UNIMPL; fault_at = s.pc; fault_insn = a64_fetch(ipc);
            goto done;
        }
    }
done:
    memcpy(__arm2x86_rf, enclosing_rf, sizeof enclosing_rf);
    memcpy(__arm2x86_rfall, enclosing_rfall, sizeof enclosing_rfall);
    a64_cur_state = prev_state; a64_cur_pc = prev_pc; a64_cur_insn = prev_insn;
    if (rc == RT_OK) {
        memcpy(xs, s.x, 31 * sizeof(unsigned long));
        xs[31] = s.sp;
        memcpy(vs, s.v, sizeof s.v);
        /* SUCCESS USED TO BE SILENT, and that made the first A/B of this rung unfalsifiable: a run that
              never engaged the interpreter and a run that engaged it and got the right answer looked
              exactly alike. Under the trace, every completed entry says so and how many instructions it
              took. Off by default — see the RenderBox note in shim_comp.c for why a working path stays
              quiet unless asked. */
        static int tr = -1;
        if (tr < 0) tr = A2X_DBGENV("ARM2X86_TRACE_INTERP") ? 1 : 0;
        if (tr) fprintf(a2x_errf(), "[xlat2] interp: ran 0x%lx to completion in %llu instructions, "
                        "%llu native calls\n", target, steps, ncalls);
        return RT_OK;
    }

    /* every refusal names itself, with the instruction and the address, the way the dispatch abort does */
    const char *why = rc == RT_LEFT_IMAGE ? "branched out of the translated images"
                    : rc == RT_UNIMPL ? "instruction not implemented by the interpreter"
                    : rc == RT_TRAP ? "trap (brk/udf)"
                    : "ran past the instruction budget";
    fprintf(a2x_errf(), "[xlat2] interp: %s at 0x%lx", why, fault_at);
    if (fault_insn) fprintf(a2x_errf(), " (insn 0x%08x)", fault_insn);
    fprintf(a2x_errf(), ", entered at 0x%lx after %llu steps\n", target, steps);
    return rc;
}

/* the address the IR entry picks up, published by __arm2x86_lookup on a miss */
__thread unsigned long __arm2x86_interp_target;

/* THE PROOF SWITCH. A miss is by definition an address the build could not translate, so the fallback
      cannot be exercised on a program that works — which would leave it shipped and unproven. With
      ARM2X86_INTERP_FORCE=<hex> the lookup sends that ONE address to the interpreter even though a perfectly
      good translation exists, so the same binary can be run both ways and its output compared. A difference
      is then the interpreter's, with nothing else changed. */
unsigned long __arm2x86_interp_force(void) {
    static unsigned long v = 1;          /* 1 = unread; no real arm64 entry is at 1 */
    if (v == 1) {
        const char *e = A2X_DBGENV("ARM2X86_INTERP_FORCE");
        v = e ? strtoul(e, 0, 16) : 0;
    }
    return v;
}

/* Off by default for now: ARM2X86_INTERP=1 turns the rung on. The fallback changes what a missing
      translation DOES, so it goes in behind a switch and gets proven app by app before it becomes the
      default — a silent behaviour change on every miss is not something to ship untested. */
int __arm2x86_interp_enabled(void) {
    static int v = -1;
    if (v < 0) { const char *e = A2X_DBGENV("ARM2X86_INTERP"); v = (e && e[0] == '1') ? 1 : 0; }
    return v;
}

/* THE REFUSAL PATH ABORTS WITH A BACKTRACE, exactly as the dispatch miss did before the interpreter
      existed. a2x_errf() already carries the reason, the instruction and the address; this adds WHICH
      translated function handed us the target, which is the one thing the interpreter cannot know. */
void __arm2x86_interp_failed(unsigned long target) {
    fprintf(a2x_errf(), "__arm2x86_interp: refused 0x%lx\n  called from (innermost first):\n", target);
    void *bt[24];
    int n = backtrace(bt, 24);
    backtrace_symbols_fd(bt, n < 8 ? n : 8, 2);
    a2x_stop("a call into the interpreter was refused", ""); abort();
}
