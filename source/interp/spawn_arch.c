/* spawn_arch.c — a guest's spawn ARCH PREFERENCE always ends in x86_64: on Intel the x86_64 slice of a host fat IS the
   interpreter that runs its arm64e slice.
   reuses: host.c a2x_late_wrapper (posix_spawnattr_setarchpref_np / setbinpref_np binds land here, like sig_guest.c).
   new-because: 11-01 t23 boot: across 22 serial logs of the stock-27 bench, xpcproxy NEVER exec'd one host-fat daemon
     (logd, configd, diskarbitrationd, sshd...: 0 host lines in ~10,000 xpcproxy launches) — no network, no ssh.
     xpcproxy calls posix_spawnattr_setarchpref_np(psattr, xb_count, xb_cpu_types, xb_cpu_subtypes) with launchd's arm64
     list. Measured on studio's x86 kernel, posix_spawn of the sshd host fat: pref arm64/arm64e -> 86 Bad CPU type,
     arm64/any -> 86, arm64e then x86_64 -> ok, x86_64 -> ok, no pref -> ok.
    The guest's own entries stay first and in order (an arm64 kernel would honour them); x86_64/ANY is appended when the
     list has no x86_64 entry. A list already at the kernel's 4 slots gets its LAST slot replaced.
    Nothing is lost: a thin arm64e target was EBADARCH before and is EBADARCH now; a native fat picks its Apple x86_64
     slice exactly as with no preference.
   ARM2X86_NO_SPAWNARCH=1 turns it off; ARM2X86_TRACE_SPAWNARCH=1 traces each rewrite.
*/
#include <mach/machine.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NPREF 4   /* xnu NBINPREFS: posix_spawnattr holds at most 4 entries */

static int trace_(void) { static int t = -1; if (t < 0) t = A2X_DBGENV("ARM2X86_TRACE_SPAWNARCH") != 0 || getppid() == 1; return t; }   /* t24: xpcproxy always traces */

/* copy the guest list (at most NPREF), then make sure x86_64/ANY is in it; returns the new count */
static size_t widen(size_t n, const cpu_type_t *ct, const cpu_subtype_t *st, cpu_type_t *oct, cpu_subtype_t *ost) {
    size_t k = n < NPREF ? n : NPREF, i;
    int has = 0;
    for (i = 0; i < k; i++) {
        oct[i] = ct ? ct[i] : 0;
        ost[i] = st ? st[i] : CPU_SUBTYPE_ANY;
        if (oct[i] == CPU_TYPE_X86_64) has = 1;
    }
    if (!has) {
        if (k == NPREF) k--;          /* full: the last guest entry gives way */
        oct[k] = CPU_TYPE_X86_64; ost[k] = CPU_SUBTYPE_ANY; k++;
    }
    if (trace_()) {
        fprintf(stderr, "[spawn-arch] guest %zu pref(s):", n);
        for (i = 0; i < (n < NPREF ? n : NPREF); i++) fprintf(stderr, " %#x/%#x", ct ? ct[i] : 0, st ? st[i] : -1);
        fprintf(stderr, "%s\n", has ? " (has x86_64, unchanged)" : " -> + x86_64/any");
    }
    return k;
}

static int w_setarchpref(posix_spawnattr_t *a, size_t n, cpu_type_t *ct, cpu_subtype_t *st, size_t *ocount) {
    cpu_type_t oct[NPREF]; cpu_subtype_t ost[NPREF];
    if (n == 0) return posix_spawnattr_setarchpref_np(a, n, ct, st, ocount);
    size_t k = widen(n, ct, st, oct, ost), got = 0;
    int r = posix_spawnattr_setarchpref_np(a, k, oct, ost, &got);
    if (ocount) *ocount = got < n ? got : n;   /* the guest asked to set n; report how many of ITS entries took */
    return r;
}

static int w_setbinpref(posix_spawnattr_t *a, size_t n, cpu_type_t *ct, size_t *ocount) {
    cpu_type_t oct[NPREF]; cpu_subtype_t ost[NPREF];
    if (n == 0) return posix_spawnattr_setbinpref_np(a, n, ct, ocount);
    size_t k = widen(n, ct, NULL, oct, ost), got = 0;
    int r = posix_spawnattr_setbinpref_np(a, k, oct, &got);
    if (ocount) *ocount = got < n ? got : n;
    return r;
}

/* A failed spawn says why, on the console. Children of PID 1 (xpcproxy) and PID 1 print path, errno and spawn flags
   when posix_spawn/posix_spawnp fails; success with POSIX_SPAWN_SETEXEC never returns, so a working exec prints
   nothing. Behaviour is unchanged: the real call's result is returned as is. */
#include <unistd.h>
static int spawn_diag_on(void) { return getpid() == 1 || getppid() == 1; }
static void spawn_diag(const char *fn, const char *path, const posix_spawnattr_t *a, int r) {
    short fl = 0;
    if (a) posix_spawnattr_getflags(a, &fl);
    fprintf(stderr, "[host] %s(%s) -> %d pid %d flags %#x\n", fn, path ? path : "(null)", r, (int)getpid(), fl);
}

/* Spawn attributes the guest sets (sandbox profile and container, launch constraint, pointer-auth keys, security
   transition shims, address limit, shared region config) are carried to the native spawn: each setter forwards to the
   real function with every argument. Before, six of them and the launch constraint returned 0 without being applied,
   so every child launched through a rewritten spawn ran without the profile or constraint its parent asked for, with
   no sign of it.
   A setter the running system does not export is the one case that cannot be carried; it is logged (once per name)
   and answers 0, because the guest cannot act on the difference either.
   ARM2X86_SPAWNATTR_SKIP=<name>[,<name>...] (or "all") drops named setters again, for bisecting a child that dies
   after exec; every skip is logged. */
#include <dlfcn.h>
typedef long (*a2x_f6)(long, long, long, long, long, long);
static const char *const sa_tab[] = {
    "sandbox_spawnattrs_setprofilename", "sandbox_spawnattrs_setcontainer",
    "posix_spawnattr_disable_ptr_auth_a_keys_np", "posix_spawnattr_set_use_sec_transition_shims_np",
    "posix_spawnattr_set_max_addr_np", "posix_spawnattr_set_shared_region_config_np",
    "posix_spawnattr_set_subsystem_root_path_np", "posix_spawnattr_set_launch_type_np",
    "posix_spawnattr_set_platform_np", "posix_spawnattr_setmacpolicyinfo_np",
    "posix_spawnattr_set_use_sanitizers_np", "posix_spawnattr_setflags",
    "responsibility_spawnattrs_setdisclaim", "sandbox_spawnattrs_init",
};
#define SA_N (int)(sizeof sa_tab / sizeof sa_tab[0])
static char sa_missing[SA_N + 1];
static int sa_skipped(const char *nm) {
    const char *e = A2X_DBGENV("ARM2X86_SPAWNATTR_SKIP");
    if (!e || !*e) return 0;
    if (!strcmp(e, "all")) return 1;
    size_t n = strlen(nm);
    for (const char *p = e; *p; ) {
        const char *q = strchr(p, ',');
        size_t l = q ? (size_t)(q - p) : strlen(p);
        if (l == n && !strncmp(p, nm, n)) return 1;
        if (!q) break;
        p = q + 1;
    }
    return 0;
}
static long sa_call(int i, long a, long b, long c, long d, long e, long f) {
    const char *nm = sa_tab[i];
    int skip = sa_skipped(nm);
    if (spawn_diag_on()) fprintf(stderr, "[host] sa %s(%#lx, %#lx, %#lx)%s pid %d\n", nm, a, b, c,
                                 skip ? " skip (ARM2X86_SPAWNATTR_SKIP)" : "", (int)getpid());
    if (skip) return 0;
    /* Every child is an x86_64 process to the kernel, routed programs included (their Intel half is this host). The
       pointer-auth keys, security transition shims, address limit and shared-region config describe an arm64 process,
       so they are not carried: forwarding them made launchd's spawns of plain Intel programs fail with EX_CONFIG
       (caffeinate and bash jobs, 12 retries, measured on 27.2). */
    if (i >= 2 && i <= 5) return 0;
    /* The sandbox profile and container are not carried either, yet. Carrying them made launchd itself read as
       sandboxed on 27.2: the Sandbox stand-in records a spawn-time profile against the process that spawns (PID 1),
       and every process launchd started afterwards inherited it ("log: Cannot run while sandboxed" from a launchd
       job, measured). The stand-in must attach a spawn-time profile to the child before this can be turned on. */
    if (i <= 1) return 0;
    a2x_f6 fn = (a2x_f6)dlsym(RTLD_DEFAULT, nm);
    if (!fn) {
        if (!sa_missing[i]) { sa_missing[i] = 1; fprintf(stderr, "[spawn-arch] %s not exported here: not carried\n", nm); }
        return 0;
    }
    return fn(a, b, c, d, e, f);
}
#define SA_W(i) static long sa_w##i(long a, long b, long c, long d, long e, long f) { return sa_call(i, a, b, c, d, e, f); }
SA_W(0) SA_W(1) SA_W(2) SA_W(3) SA_W(4) SA_W(5) SA_W(6) SA_W(7) SA_W(8) SA_W(9) SA_W(10) SA_W(11) SA_W(12) SA_W(13)
static void *const sa_fns[] = { sa_w0, sa_w1, sa_w2, sa_w3, sa_w4, sa_w5, sa_w6, sa_w7, sa_w8, sa_w9, sa_w10, sa_w11,
                                sa_w12, sa_w13 };
_Static_assert(sizeof sa_fns / sizeof sa_fns[0] == sizeof sa_tab / sizeof sa_tab[0], "sa table");

/* The launch constraint is carried the same way (four arguments). */
static int w_amfi_lc(posix_spawnattr_t *a, int which, const void *data, size_t len) {
    static const char nm[] = "amfi_launch_constraint_set_spawnattr";
    static char missing;
    if (spawn_diag_on()) fprintf(stderr, "[host] launch constraint %d (%zu B) pid %d\n", which, len, (int)getpid());
    if (sa_skipped(nm)) return 0;
    /* Not carried: the kernel checks a launch constraint against the executable it starts, and a routed program's
       executable is this host, signed ad hoc, which Apple's constraints reject - every routed child would be refused. */
    if (1) return 0;
    int (*fn)(posix_spawnattr_t *, int, const void *, size_t) = (int (*)(posix_spawnattr_t *, int, const void *, size_t))dlsym(RTLD_DEFAULT, nm);
    if (!fn) { if (!missing) { missing = 1; fprintf(stderr, "[spawn-arch] %s not exported here: not carried\n", nm); } return 0; }
    return fn(a, which, data, len);
}
static int w_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa,
                         const posix_spawnattr_t *a, char *const argv[], char *const envp[]) {
    if (spawn_diag_on()) fprintf(stderr, "[host] spawn %s pid %d\n", path ? path : "(null)", (int)getpid());
    int r = posix_spawn(pid, path, fa, a, argv, envp);
    if (r && spawn_diag_on()) spawn_diag("posix_spawn", path, a, r);
    return r;
}
static int w_posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *fa,
                          const posix_spawnattr_t *a, char *const argv[], char *const envp[]) {
    if (spawn_diag_on()) fprintf(stderr, "[host] spawn %s pid %d\n", file ? file : "(null)", (int)getpid());
    int r = posix_spawnp(pid, file, fa, a, argv, envp);
    if (r && spawn_diag_on()) spawn_diag("posix_spawnp", file, a, r);
    return r;
}

/* host.c a2x_late_wrapper: the two arch-preference setters + the two spawns -> the wrappers above; anything else -> 0 */
void *a2x_spawnarch_wrapper(const char *nm) {
    if (!nm || A2X_DBGENV("ARM2X86_NO_SPAWNARCH")) return 0;
    if (!strcmp(nm, "amfi_launch_constraint_set_spawnattr")) return (void *)w_amfi_lc;
    /* Only the six setters that were always answered here are taken; the others bind natively, as before. Wrapping and
       forwarding them as well left processes marked sandboxed by the Sandbox stand-in on 27.2 ("log: Cannot run
       while sandboxed" from a plain shell and from a launchd job, measured), which the stand-in has to handle first. */
    for (int i = 0; i < 6; i++) if (!strcmp(nm, sa_tab[i])) return sa_fns[i];
    if (nm[0] != 'p') return 0;
    if (!strcmp(nm, "posix_spawnattr_setarchpref_np")) return (void *)w_setarchpref;
    if (!strcmp(nm, "posix_spawnattr_setbinpref_np")) return (void *)w_setbinpref;
    if (!strcmp(nm, "posix_spawn")) return (void *)w_posix_spawn;
    if (!strcmp(nm, "posix_spawnp")) return (void *)w_posix_spawnp;
    return 0;
}
