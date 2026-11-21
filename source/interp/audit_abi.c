/* audit_abi.c — audit_token_t passed BY VALUE across the arm64 / x86_64 boundary.
   reuses: host.c a2x_late_wrapper (the name -> host function table every bind consults first; gss_abi.c answers its
     misses first, this file answers what gss leaves); vararg.c's VFIX table moves the variadic tail of
     sandbox_check_by_audit_token off the arm stack into x3..x5 before the C door calls the wrapper below.
   new-because: 11-01 offline ruler (studio, probe sbp.c): native x86 sandbox_check_by_audit_token("mach-lookup", 2|3)
     = 0 and audit_token_to_pid = our pid; the same arm64e probe under host 1101ai = -1, -1 and pid 0. audit_token_t is
     32 bytes: Apple arm64 passes a >16-byte struct as a POINTER in an x register, x86_64 passes it as 32 bytes on the
     stack. The generic adapter handed native code the pointer in rdi, so native read the token from the arm stack.
     In the guest: launchd's privileged mach-lookup check failed for every caller -> "denied lookup ... error = 159:
     Sandbox restriction" -> configd's SCDynamicStoreCreate NULL -> configd crash -> en0 no address -> no ssh.
     sigdb (header-based) has neither libbsm nor the private libsandbox prototypes, so abi_gen never generated these.

   Wrapped (each calls the native function with *token by value):
     sandbox_check_by_audit_token(token, op, type, ...)   variadic: up to 3 tail words, from x3..x5 (VFIX)
     audit_token_to_{pid,euid,egid,ruid,rgid,auid,asid,pidversion}(token)
     audit_token_to_au32(token, 8 out pointers)            9 args: the door hands x6, x7, sp[0] as stack args 7..9
    NOT covered — named so nobody assumes they are: sandbox_extension_issue_*_to_process* and any other private API
      taking audit_token_t by value; add them here with a ruler line when an import list shows one.
   ARM2X86_NO_AUDITABI=1 turns the layer off (binds go native exactly as before); ARM2X86_TRACE_AUDIT=1 traces it.
   Selftest (studio, real x86 libraries): clang -arch x86_64 -DAUDIT_ABI_SELFTEST audit_abi.c -o aut && ./aut
*/
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

typedef struct { unsigned int v[8]; } a_tok;      /* audit_token_t: 32 bytes on both architectures */
_Static_assert(sizeof(a_tok) == 32, "audit_token_t");

static int atr(void) { static int t = -1; if (t < 0) t = A2X_DBGENV("ARM2X86_TRACE_AUDIT") != 0; return t; }

/* native symbol: libsystem_sandbox is in libSystem (RTLD_DEFAULT); libbsm is its own image, loaded on first need. */
static void *asym(const char *n) {
    void *p = dlsym(RTLD_DEFAULT, n);
    if (p) return p;
    static void *hb; static int tried;
    if (!tried) { hb = dlopen("/usr/lib/libbsm.0.dylib", RTLD_LAZY | RTLD_LOCAL); tried = 1; }
    p = hb ? dlsym(hb, n) : 0;
    if (!p) fprintf(stderr, "[host] audit_abi: native %s not found: %s\n", n, dlerror());
    return p;
}

/* ---- sandbox_check_by_audit_token ---- */
typedef int (*sbcheck_fn)(a_tok, const char *, int, ...);
static int w_sandbox_check_by_audit_token(const a_tok *t, const char *op, int type,
                                          unsigned long v0, unsigned long v1, unsigned long v2) {
    static sbcheck_fn f;
    if (!f) f = (sbcheck_fn)asym("sandbox_check_by_audit_token");
    if (!f || !t) { errno = EINVAL; return -1; }
    int r = f(*t, op, type, v0, v1, v2);
    if (atr()) fprintf(stderr, "[host] audit_abi: sandbox_check_by_audit_token(pid %u, %s, %#x, %#lx) = %d\n",
                       t->v[5], op ? op : "(null)", type, v0, r);
    return r;
}

/* ---- audit_token_to_<field>(audit_token_t) -> 32-bit scalar ---- */
typedef unsigned int (*a2u_fn)(a_tok);
#define A2U(NAME)                                                                       \
    static unsigned int w_##NAME(const a_tok *t) {                                      \
        static a2u_fn f;                                                                \
        if (!f) f = (a2u_fn)asym(#NAME);                                                \
        if (!f || !t) return (unsigned int)-1;                                          \
        unsigned int r = f(*t);                                                         \
        if (atr()) fprintf(stderr, "[host] audit_abi: " #NAME " = %u\n", r);            \
        return r;                                                                       \
    }
A2U(audit_token_to_pid)
A2U(audit_token_to_euid)
A2U(audit_token_to_egid)
A2U(audit_token_to_ruid)
A2U(audit_token_to_rgid)
A2U(audit_token_to_auid)
A2U(audit_token_to_asid)
A2U(audit_token_to_pidversion)

/* ---- audit_token_to_au32(token, auid*, euid*, egid*, ruid*, rgid*, pid*, asid*, tid*) ---- */
typedef void (*au32_fn)(a_tok, void *, void *, void *, void *, void *, void *, void *, void *);
static void w_audit_token_to_au32(const a_tok *t, void *auid, void *euid, void *egid, void *ruid, void *rgid,
                                  void *pid, void *asid, void *tid) {
    static au32_fn f;
    if (!f) f = (au32_fn)asym("audit_token_to_au32");
    if (!f || !t) return;
    f(*t, auid, euid, egid, ruid, rgid, pid, asid, tid);
    if (atr()) fprintf(stderr, "[host] audit_abi: audit_token_to_au32(pid %u)\n", t->v[5]);
}

/* 11-01 THE BY-VALUE TOKEN CLASS, measured, not guessed. A name is here only when BOTH halves agree:
      x86_64 (studio, lldb): the non-variadic function reads its CALLER'S stack at 0x10..0x2f(%rbp) — a 32-byte
        MEMORY-class argument (pid at 0x24, pidversion at 0x2c);
      arm64e (laptop = real 27, lldb): incoming x<k> is dereferenced at token offsets (+0x14/+0x1c) — the pointer
        Apple arm64 passes for a >16-byte struct.
   k = the token's argument index(es). Every other argument keeps its order and goes to the x86 integer registers;
   the token(s) go to the stack, in order. Controls: audit_token_to_* (known by value) and SecTaskCreateWithAuditToken
   (abi_gen's header-typed wrapper, k=1) were classified the same way by the same scan.
    sandbox_check_network killed launchd on the 11-01 proof boot (native read guest x3 as the sockaddr).
    NOT here: names already wrapped above (sandbox_check_by_audit_token is variadic, VFIX owns its tail),
      SecTaskCreateWithAuditToken (rf_table binds it first), and anything taking `const audit_token_t *`
      (csops_audittoken, proc_*_audittoken, SecCodeCreateWithAuditToken: x86 reads them from a register). */
struct tokgen { const char *n; signed char k0, k1; char ret; };   /* ret 'b' = bool in al only: narrow */
static const struct tokgen g_tok[] = {
    { "sandbox_check_network", 0, -1, 'l' },
    { "sandbox_check_finder_automation_for_path", 0, -1, 'l' },
    { "sandbox_check_message_filter_integer", 0, -1, 'l' },
    { "sandbox_check_message_filter_string", 0, -1, 'l' },
    { "sandbox_enable_state_flag", 1, -1, 'l' },
    { "sandbox_check_process_signal_target", 0, 2, 'l' },   /* two tokens: x86 reads 0x24/0x2c AND 0x44/0x4c(%rbp) */
    { "sandbox_check_self_signal_target", 1, -1, 'l' },
    { "sandbox_container_path_for_audit_token", 0, -1, 'l' },
    { "sandbox_extension_issue_file_to_process", 3, -1, 'l' },
    { "sandbox_extension_issue_generic_to_process", 2, -1, 'l' },
    { "sandbox_extension_issue_iokit_registry_entry_class_to_process", 3, -1, 'l' },
    { "sandbox_extension_issue_mach_to_process", 3, -1, 'l' },
    { "sandbox_extension_issue_related_file_to_process", 5, -1, 'l' },
    { "sandbox_proc_getcontainer", 0, -1, 'l' },
    { "sandbox_proc_getprofilename", 0, -1, 'l' },
    { "sandbox_query_user_intent_for_process_with_audit_token", 0, -1, 'l' },
    { "sandbox_reference_retain_by_audit_token", 0, -1, 'l' },
    { "sandbox_set_container_path_for_audit_token", 0, -1, 'l' },
    { "container_audit_token_copy_codesign_hash", 0, -1, 'l' },
    { "container_audit_token_copy_codesign_identifier", 0, -1, 'l' },
    { "container_audit_token_copy_codesign_team_identifier", 0, -1, 'l' },
    { "container_audit_token_copy_entitlement", 0, -1, 'l' },
    { "container_audit_token_copy_executable_name", 0, -1, 'l' },
    { "container_audit_token_get_codesign_status", 0, -1, 'l' },
    { "container_audit_token_get_egid", 0, -1, 'l' },
    { "container_audit_token_get_euid", 0, -1, 'l' },
    { "container_audit_token_get_pid", 0, -1, 'l' },
    { "container_audit_token_get_platform", 0, -1, 'l' },
    { "container_audit_token_is_valid", 0, -1, 'b' },        /* x86: setne %al; ret */
    { "container_client_create_from_audit_token", 0, -1, 'l' },
    { "AuthorizationCreateWithAuditToken", 0, -1, 'l' },
};
#define NTOK (int)(sizeof g_tok / sizeof g_tok[0])
typedef long (*tok1_fn)(long, long, long, long, long, long, a_tok);
typedef long (*tok2_fn)(long, long, long, long, long, long, a_tok, a_tok);
static long a2x_tokgen(int i, const long *a) {
    static void *fp[64];
    const struct tokgen *d = &g_tok[i];
    if (!fp[i]) fp[i] = asym(d->n);
    const a_tok *t0 = (const a_tok *)a[(int)d->k0], *t1 = d->k1 >= 0 ? (const a_tok *)a[(int)d->k1] : 0;
    if (!fp[i] || !t0 || (d->k1 >= 0 && !t1)) {
        fprintf(stderr, "[host] audit_abi: %s %s — returning -1/EINVAL\n", d->n, fp[i] ? "NULL token" : "not found");
        errno = EINVAL; return -1;
    }
    long o[6] = {0}; int n = 0;                      /* the other arguments, in order, into the 6 x86 int registers */
    for (int j = 0; j < 8 && n < 6; j++) if (j != d->k0 && j != d->k1) o[n++] = a[j];
    long r = d->k1 >= 0 ? ((tok2_fn)fp[i])(o[0], o[1], o[2], o[3], o[4], o[5], *t0, *t1)
                        : ((tok1_fn)fp[i])(o[0], o[1], o[2], o[3], o[4], o[5], *t0);
    if (d->ret == 'b') r = (unsigned char)r;
    if (atr()) fprintf(stderr, "[host] audit_abi: %s(pid %u, k=%d) = %ld\n", d->n, t0->v[5], d->k0, r);
    return r;
}
#define TG(I) static long tg_##I(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) { \
        long a[8] = {a0, a1, a2, a3, a4, a5, a6, a7}; return a2x_tokgen(I, a); }
TG(0) TG(1) TG(2) TG(3) TG(4) TG(5) TG(6) TG(7) TG(8) TG(9) TG(10) TG(11) TG(12) TG(13) TG(14) TG(15)
TG(16) TG(17) TG(18) TG(19) TG(20) TG(21) TG(22) TG(23) TG(24) TG(25) TG(26) TG(27) TG(28) TG(29) TG(30)
static void *const g_tg[] = { tg_0, tg_1, tg_2, tg_3, tg_4, tg_5, tg_6, tg_7, tg_8, tg_9, tg_10, tg_11, tg_12, tg_13,
    tg_14, tg_15, tg_16, tg_17, tg_18, tg_19, tg_20, tg_21, tg_22, tg_23, tg_24, tg_25, tg_26, tg_27, tg_28, tg_29, tg_30 };
_Static_assert(sizeof g_tg / sizeof g_tg[0] == sizeof g_tok / sizeof g_tok[0], "one thunk per g_tok row");

static const struct { const char *n; void *f; } g_fn[] = {
    { "sandbox_check_by_audit_token", (void *)w_sandbox_check_by_audit_token },
    { "audit_token_to_pid", (void *)w_audit_token_to_pid },
    { "audit_token_to_euid", (void *)w_audit_token_to_euid },
    { "audit_token_to_egid", (void *)w_audit_token_to_egid },
    { "audit_token_to_ruid", (void *)w_audit_token_to_ruid },
    { "audit_token_to_rgid", (void *)w_audit_token_to_rgid },
    { "audit_token_to_auid", (void *)w_audit_token_to_auid },
    { "audit_token_to_asid", (void *)w_audit_token_to_asid },
    { "audit_token_to_pidversion", (void *)w_audit_token_to_pidversion },
    { "audit_token_to_au32", (void *)w_audit_token_to_au32 },
};

/* host.c a2x_late_wrapper's miss path: a by-value audit_token_t function -> its pointer-taking wrapper; else 0. */
void *a2x_audit_wrapper(const char *nm) {
    if (!nm || A2X_DBGENV("ARM2X86_NO_AUDITABI")) return 0;
    for (unsigned i = 0; i < sizeof g_fn / sizeof g_fn[0]; i++)
        if (!strcmp(nm, g_fn[i].n)) return g_fn[i].f;
    for (int i = 0; i < NTOK; i++)
        if (!strcmp(nm, g_tok[i].n)) return g_tg[i];
    return 0;
}

#ifdef AUDIT_ABI_SELFTEST
#include <mach/mach.h>
#include <sys/wait.h>
#include <signal.h>
static int fails;
static void arm(int ok, const char *name, const char *got) {
    printf("%s  %s  [%s]\n", ok ? "ok  " : "FAIL", name, got);
    if (!ok) fails++;
}
int main(void) {
    a_tok t; mach_msg_type_number_t n = 8;
    if (task_info(mach_task_self(), 15 /* TASK_AUDIT_TOKEN */, (task_info_t)&t, &n) != KERN_SUCCESS) {
        printf("FAIL  task_info(TASK_AUDIT_TOKEN) — cannot run (UNKNOWN, not clean)\n"); return 2;
    }
    char b[160];
    unsigned (*pidf)(const a_tok *) = a2x_audit_wrapper("audit_token_to_pid");
    unsigned (*euidf)(const a_tok *) = a2x_audit_wrapper("audit_token_to_euid");
    snprintf(b, sizeof b, "wrapper pid %u, getpid %d", pidf ? pidf(&t) : 0, getpid());
    arm(pidf && pidf(&t) == (unsigned)getpid(), " audit_token_to_pid through the wrapper is this process's pid", b);
    snprintf(b, sizeof b, "wrapper euid %u, geteuid %u", euidf ? euidf(&t) : 0, geteuid());
    arm(euidf && euidf(&t) == geteuid(), " audit_token_to_euid through the wrapper is geteuid()", b);
    unsigned au[8] = {~0u, ~0u, ~0u, ~0u, ~0u, ~0u, ~0u, ~0u}; unsigned tid[2];
    void (*au32)(const a_tok *, void *, void *, void *, void *, void *, void *, void *, void *) =
        a2x_audit_wrapper("audit_token_to_au32");
    if (au32) au32(&t, &au[0], &au[1], &au[2], &au[3], &au[4], &au[5], &au[6], tid);
    snprintf(b, sizeof b, "euid %u egid %u pid %u (getpid %d)", au[1], au[2], au[5], getpid());
    arm(au32 && au[5] == (unsigned)getpid() && au[1] == geteuid() && au[2] == getegid(),
        " audit_token_to_au32 fills all 8 outs (the 9th argument rides the stack)", b);
    int (*sbw)(const a_tok *, const char *, int, unsigned long, unsigned long, unsigned long) =
        a2x_audit_wrapper("sandbox_check_by_audit_token");
    sbcheck_fn sbn = (sbcheck_fn)dlsym(RTLD_DEFAULT, "sandbox_check_by_audit_token");
    for (int ty = 2; ty <= 3; ty++) {
        const char *svc = "com.apple.SystemConfiguration.configd";
        int w = sbw ? sbw(&t, "mach-lookup", ty, (unsigned long)svc, 0, 0) : -9;
        int nv = sbn ? sbn(t, "mach-lookup", ty, svc) : -9;
        snprintf(b, sizeof b, "type %d: wrapper %d, native %d", ty, w, nv);
        arm(sbn && w == nv && w == 0, " sandbox_check_by_audit_token wrapper == native == 0 (unsandboxed)", b);
    }
    /* 11-01 the by-value table, against native called BY VALUE through its real x86 prototype */
    {
        int pid = getpid();
        long (*gp)(const a_tok *) = a2x_audit_wrapper("container_audit_token_get_pid");
        snprintf(b, sizeof b, "wrapper %ld getpid %d", gp ? gp(&t) : -9, pid);
        arm(gp && gp(&t) == pid, " container_audit_token_get_pid(token BY VALUE, k=0) through the table == getpid", b);
        long (*iv)(const a_tok *) = a2x_audit_wrapper("container_audit_token_is_valid");
        snprintf(b, sizeof b, "wrapper %ld", iv ? iv(&t) : -9);
        arm(iv && iv(&t) == 1, " container_audit_token_is_valid(self) == 1, narrowed to the bool in al", b);
        struct { unsigned char len, fam; unsigned short port; unsigned int addr; char z[8]; } sa = {16, 2, 0x5000, 0x0100007f, {0}};
        long (*nw)(const a_tok *, long, const char *, long, void *) = a2x_audit_wrapper("sandbox_check_network");
        long (*nn)(a_tok, long, const char *, int, void *) = dlsym(RTLD_DEFAULT, "sandbox_check_network");
        errno = 0; long w = nw ? (int)nw(&t, 0, "network-outbound", 0, &sa) : -9; int we = errno;
        errno = 0; long v = nn ? (int)nn(t, 0, "network-outbound", 0, &sa) : -9; int ve = errno;
        snprintf(b, sizeof b, "wrapper %ld/errno %d, native-by-value %ld/errno %d", w, we, v, ve);
        arm(nw && nn && w == v && we == ve, " sandbox_check_network (launchd's crash, 11-01) wrapper == native, same errno", b);
        long (*st)(const a_tok *, int, const a_tok *) = a2x_audit_wrapper("sandbox_check_process_signal_target");
        long (*sn)(a_tok, int, a_tok) = dlsym(RTLD_DEFAULT, "sandbox_check_process_signal_target");
        long w2 = st ? st(&t, 15, &t) : -9, v2 = sn ? sn(t, 15, t) : -9;
        snprintf(b, sizeof b, "wrapper %ld native %ld", w2, v2);
        arm(st && sn && w2 == v2, " TWO tokens (k=0,2): sandbox_check_process_signal_target wrapper == native", b);
        /* the failure direction: the old path (the guest pointer handed straight to native) must NOT equal native */
        pid_t c = fork();
        if (c == 0) { long (*raw)(long, long, long, long, long) = (void *)nn;
                      long r = raw((long)&t, (long)"network-outbound", (long)"network-outbound", 0x19, (long)&sa); _exit(r == v ? 0 : 3); }
        int stt = 0; waitpid(c, &stt, 0);
        snprintf(b, sizeof b, "old path: %s %d", WIFSIGNALED(stt) ? "signal" : "exit", WIFSIGNALED(stt) ? WTERMSIG(stt) : WEXITSTATUS(stt));
        arm(WIFSIGNALED(stt) && WTERMSIG(stt) == SIGSEGV, " the OLD path (launchd's x0..x4 straight to native: x3=0x19 read as the sockaddr) faults", b);
        long (*nul)(const a_tok *, long, const char *, long, void *) = nw;
        errno = 0; long z = nul ? nul(0, 0, "network-outbound", 0, &sa) : -9;
        snprintf(b, sizeof b, "ret %ld errno %d", z, errno);
        arm(z == -1 && errno == EINVAL, " a NULL token pointer returns -1/EINVAL instead of faulting", b);
    }
    snprintf(b, sizeof b, "malloc %p, open %p", a2x_audit_wrapper("malloc"), a2x_audit_wrapper("open"));
    arm(!a2x_audit_wrapper("malloc") && !a2x_audit_wrapper("open"), " an unrelated name is NOT wrapped", b);
    setenv("ARM2X86_NO_AUDITABI", "1", 1);
    void *off = a2x_audit_wrapper("audit_token_to_pid");
    unsetenv("ARM2X86_NO_AUDITABI");
    arm(!off && a2x_audit_wrapper("audit_token_to_pid"), " ARM2X86_NO_AUDITABI=1 turns the layer off, only while set",
        off ? "still wrapped" : "off, then back");
    printf("%d failed\n", fails);
    return fails != 0;
}
#endif
