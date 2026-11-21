/* * a2x_hook_kext.c - the one install that makes every arm64 binary on an
 * Intel macOS 27 box reach the host, with no per-app anything.
 *
 *  UNTESTED. This has never been compiled, signed, staged or loaded. Every
 * sentence about behaviour on a machine is a prediction. The arms in TEST.md
 * are what would make any of it a fact.
 *
 *  WHAT IT DOES, IN ONE SENTENCE: retargets one conditional branch inside
 * the kernel's Mach-O image activator so that an arm64 executable, instead of
 * failing with EBADARCH, is re-exec'd through the kernel's own interpreter
 * path with /usr/libexec/a2x/a2xhost as the interpreter.
 *
 *  THE SAFETY ARGUMENT, which is the reason this shape was chosen over
 * patching the grader:
 *
 *   1. The hook sits on an ERROR path. grade_binary() still returns 0 for
 *      arm64; every gate Apple ships is untouched. A binary that execs
 *      successfully today never executes one instruction of this kext.
 *   2. Nothing is patched at load. Arming requires a sysctl write, so a
 *      reboot ALWAYS comes back with an unpatched kernel.  That is the
 *      primary recovery path and it needs no tools, no Recovery and no
 *      typing: power-cycle the box.
 *   3. A dead-man disarms the hook if userspace stops saying it is alive.
 *       The failure this guards against is "nothing can exec any more",
 *      and a machine in that state is exactly a machine that CANNOT write
 *      the keepalive - so the guard fires precisely when it is needed.
 *   4. Arming verifies 36 bytes of kernel text against values measured from
 *      a named kernel UUID and refuses on any mismatch, including "could not
 *      read".
 *
 *  WHAT IT COSTS, named here because it is not visible from the code:
 * after the redirect the process image is a2xhost, so the process's code
 * identity, entitlements and sandbox container are a2xhost's and NOT the
 * app's. Already measured in this project: of five Apple system apps given
 * x86_64 executables on 10-21, the two that died were the two with
 * com.apple.security.app-sandbox. The kernel route does not fix that, it
 * inherits it.
 */

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>          /* vn_rdwr - the slide anchor */
#include <sys/imgact.h>         /* struct image_params, a public KPI header */
#include <libkern/libkern.h>
#include <kern/thread_call.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>  /* PE_parse_boot_argn - the boot-arm switch */
#include <stddef.h>

#include "a2x_hook_logic.h"
#include "a2x_hook_sites.h"

/* *  THE OFFSETS IN a2x_hook_logic.h ARE CHECKED HERE, AT BUILD TIME,
 * AGAINST THE REAL SDK HEADER. The logic file uses raw offsets so it can be
 * tested in userspace; this is what stops those offsets from silently drifting
 * away from the struct the kernel actually compiled. A header change breaks
 * the build instead of corrupting an exec.
 */
_Static_assert(A2X_IP_USER_FNAME == offsetof(struct image_params, ip_user_fname), "ip_user_fname");
_Static_assert(A2X_IP_SEG == offsetof(struct image_params, ip_seg), "ip_seg");
_Static_assert(A2X_IP_ORIGCPUTYPE == offsetof(struct image_params, ip_origcputype), "ip_origcputype");
_Static_assert(A2X_IP_ORIGCPUSUBTYPE == offsetof(struct image_params, ip_origcpusubtype), "ip_origcpusubtype");
_Static_assert(A2X_IP_VDATA == offsetof(struct image_params, ip_vdata), "ip_vdata");
_Static_assert(A2X_IP_FLAGS == offsetof(struct image_params, ip_flags), "ip_flags");
_Static_assert(A2X_IP_STRINGS == offsetof(struct image_params, ip_strings), "ip_strings");
_Static_assert(A2X_IP_STRENDP == offsetof(struct image_params, ip_strendp), "ip_strendp");
_Static_assert(A2X_IP_ARGSPACE == offsetof(struct image_params, ip_argspace), "ip_argspace");
_Static_assert(A2X_IP_STRSPACE == offsetof(struct image_params, ip_strspace), "ip_strspace");
_Static_assert(A2X_IP_ARCH_OFFSET == offsetof(struct image_params, ip_arch_offset), "ip_arch_offset");
_Static_assert(A2X_IP_ARCH_SIZE == offsetof(struct image_params, ip_arch_size), "ip_arch_size");
_Static_assert(A2X_IP_INTERP_BUFFER == offsetof(struct image_params, ip_interp_buffer), "ip_interp_buffer");
_Static_assert(A2X_IP_INTERP_SUGID_FD == offsetof(struct image_params, ip_interp_sugid_fd), "ip_interp_sugid_fd");
_Static_assert(A2X_IMG_SHSIZE == IMG_SHSIZE, "IMG_SHSIZE");
_Static_assert(A2X_IMGPF_INTERPRET == IMGPF_INTERPRET, "IMGPF_INTERPRET");
_Static_assert(sizeof(A2X_EXECUTABLE_KEY) - 1 == A2X_EXECUTABLE_KEY_LEN, "key len");

/* From a2x_hook_tramp.s */
extern void a2x_tramp(void);
extern kern_return_t a2x_adopt_start(kmod_info_t *, void *);
extern int a2x_ident_start(void);          /* a2x_ident.cpp: the board name for Software Update */
extern void a2x_split_start(void *xd), a2x_split_arm(void), a2x_split_disarm(void);  /* a2x_split.c */
extern kern_return_t a2x_adopt_stop(kmod_info_t *, void *);
extern uint64_t a2x_resume_ok;
extern uint64_t a2x_resume_bad;
extern uintptr_t __stack_chk_guard;

/* ---------------------------------------------------------------- state */

static uint64_t a2x_slide;              /* runtime - on-disk, kernel __text */
static int      a2x_verified;           /* bytes matched; safe to arm */
static int      a2x_armed;              /* branch is retargeted right now */
/* fat path (11-03): the trampoline grades an arm64e slice only while this is 1; set with a2x_armed. */
int             a2x_fat_gate;
uint64_t        a2x_fat_graded_count;
static int      a2x_fat_installed;
extern void a2x_fattramp(void);
extern uint64_t a2x_fat_resume_native, a2x_fat_resume_graded, a2x_fat_resume_skip;
static uint32_t a2x_deadman_secs = 120; /* 0 = no dead-man (refused below) */
static uint64_t a2x_deadman_fired;
static thread_call_t a2x_deadman_call;

#define A2X_LOG(fmt, ...) printf("a2x-exec-hook: " fmt "\n", ##__VA_ARGS__)

static void *
a2x_rt(uint64_t vmaddr)
{
	return (void *)(uintptr_t)(vmaddr + a2x_slide);
}

/* ------------------------------------------------------- text writing */

/* *  Kernel __text is mapped read-only. On x86-64 a supervisor write to a
 * read-only page is permitted while CR0.WP is clear, which is the only
 * mechanism available to a kext here - there is no exported interface for
 * remapping kernel text. Interrupts are off across the window so this CPU
 * cannot be preempted with WP clear.
 *
 *  OTHER CPUs ARE NOT STOPPED. There is no stop-the-world primitive in the
 * KPI (mp_rendezvous_no_intrs is not exported), so the design keeps the only
 * live-code write down to a single 4-byte ALIGNED store, which cannot tear.
 * The thunk, which is 13 bytes and cannot be written atomically, is written
 * while nothing branches to it yet - ordering is the safety property, see
 * a2x_arm().
 */
static void
a2x_write_bytes(volatile uint8_t *dst, const uint8_t *src, size_t len)
{
	uint64_t flags;
	uint64_t cr0;

	__asm__ volatile ("pushfq; popq %0; cli" : "=r" (flags) :: "memory");
	__asm__ volatile ("movq %%cr0, %0" : "=r" (cr0));
	__asm__ volatile ("movq %0, %%cr0" :: "r" (cr0 & ~(uint64_t)0x10000) : "memory");

	for (size_t i = 0; i < len; i++) {
		dst[i] = src[i];
	}

	__asm__ volatile ("movq %0, %%cr0" :: "r" (cr0) : "memory");
	if (flags & 0x200) {    /* restore IF only if it was set */
		__asm__ volatile ("sti" ::: "memory");
	}
}

/* One aligned 32-bit store: the live-code patch. */
static void
a2x_write_disp32(volatile uint32_t *dst, uint32_t val)
{
	uint64_t flags;
	uint64_t cr0;

	__asm__ volatile ("pushfq; popq %0; cli" : "=r" (flags) :: "memory");
	__asm__ volatile ("movq %%cr0, %0" : "=r" (cr0));
	__asm__ volatile ("movq %0, %%cr0" :: "r" (cr0 & ~(uint64_t)0x10000) : "memory");

	*dst = val;             /* aligned, single store, atomic on x86-64 */
	__asm__ volatile ("mfence" ::: "memory");

	__asm__ volatile ("movq %0, %%cr0" :: "r" (cr0) : "memory");
	if (flags & 0x200) {
		__asm__ volatile ("sti" ::: "memory");
	}
}

/* ---------------------------------------------------------- verifying */

struct a2x_check {
	const char *what;
	uint64_t vmaddr;
	const uint8_t *want;
	size_t len;
};

static int
a2x_verify(void)
{
	static const uint8_t gate[]  = A2X_BYTES_GATE;
	static const uint8_t jne[]   = A2X_BYTES_SITE_JNE;
	static const uint8_t bad[]   = A2X_BYTES_RESUME_BAD;
	static const uint8_t thunk[] = A2X_BYTES_THUNK;
	static const uint8_t fsite[] = A2X_BYTES_FAT_SITE;
	static const uint8_t fnat[]  = A2X_BYTES_FAT_NATIVE;
	static const uint8_t fgrd[]  = A2X_BYTES_FAT_GRADED;
	static const uint8_t fskp[]  = A2X_BYTES_FAT_SKIP;
	static const uint8_t fslab[] = A2X_BYTES_FAT_SLAB;

	const struct a2x_check checks[] = {
		{ "grade gate",  A2X_VMADDR_GATE,       gate,  sizeof(gate) },
		{ "jne site",    A2X_VMADDR_SITE_JNE,   jne,   sizeof(jne) },
		{ "resume_bad",  A2X_VMADDR_RESUME_BAD, bad,   sizeof(bad) },
		{ "thunk slab",  A2X_VMADDR_THUNK,      thunk, sizeof(thunk) },
		{ "fat site",    A2X_VMADDR_FAT_SITE,   fsite, sizeof(fsite) },
		{ "fat native",  A2X_VMADDR_FAT_NATIVE, fnat,  sizeof(fnat) },
		{ "fat graded",  A2X_VMADDR_FAT_GRADED, fgrd,  sizeof(fgrd) },
		{ "fat skip",    A2X_VMADDR_FAT_SKIP,   fskp,  sizeof(fskp) },
		{ "fat slab",    A2X_VMADDR_FAT_SLAB,   fslab, sizeof(fslab) },
	};

	a2x_slide = (uint64_t)(uintptr_t)&vn_rdwr - A2X_VMADDR_ANCHOR;
	A2X_LOG("anchor vn_rdwr runtime %p on-disk 0x%llx slide 0x%llx",
	    (void *)&vn_rdwr, (unsigned long long)A2X_VMADDR_ANCHOR,
	    (unsigned long long)a2x_slide);

	for (size_t c = 0; c < sizeof(checks) / sizeof(checks[0]); c++) {
		const uint8_t *got = (const uint8_t *)a2x_rt(checks[c].vmaddr);

		for (size_t i = 0; i < checks[c].len; i++) {
			if (got[i] != checks[c].want[i]) {
				/* Fail loud and name the byte. A mismatch means
				 * this is not the kernel the sites were measured
				 * from, and arming would retarget a branch into
				 * the middle of an unknown instruction. */
				A2X_LOG("REFUSING: %s at %p byte %zu is 0x%02x, "
				    "expected 0x%02x - this is not kernel %s",
				    checks[c].what, (void *)got, i, got[i],
				    checks[c].want[i], A2X_SITE_UUID_STR);
				a2x_verified = 0;
				return 0;
			}
		}
		A2X_LOG("verified %s (%zu bytes) at %p",
		    checks[c].what, checks[c].len, (void *)got);
	}

	/* The collection linker relocates the cookie reference independently of
	 * kernel text. Check the instruction and its resolved target. */
	{
		const uint8_t *p = a2x_rt(A2X_VMADDR_RESUME_OK);
		int32_t displacement;
		memcpy(&displacement, p + 3, sizeof(displacement));
		uintptr_t target = (uintptr_t)(p + 7) + (intptr_t)displacement;
		if (p[0] != 0x48 || p[1] != 0x8d || p[2] != 0x05 ||
		    target != (uintptr_t)&__stack_chk_guard) {
			A2X_LOG("REFUSING: resume epilogue does not reference the resolved stack cookie");
			a2x_verified = 0;
			return 0;
		}
		A2X_LOG("verified resume epilogue and resolved stack cookie");
	}

	/* * Cross-check the branch we are about to retarget actually goes
	 * where the site table says it does. If the displacement means
	 * something else, the register facts the trampoline relies on are not
	 * this kernel's facts either.
	 */
	{
		uint32_t disp = *(const uint32_t *)a2x_rt(A2X_VMADDR_SITE_DISP);
		uint64_t target = A2X_VMADDR_SITE_JNE + 6 + disp;

		if (disp != A2X_ORIG_DISP || target != A2X_VMADDR_RESUME_BAD) {
			A2X_LOG("REFUSING: jne displacement 0x%x targets 0x%llx, "
			    "expected 0x%x -> 0x%llx", disp,
			    (unsigned long long)target, A2X_ORIG_DISP,
			    (unsigned long long)A2X_VMADDR_RESUME_BAD);
			a2x_verified = 0;
			return 0;
		}
	}

	a2x_verified = 1;
	A2X_LOG("site table matches kernel %s (%s); NOT armed",
	    A2X_SITE_UUID_STR, A2X_SITE_KERNVERS);
	return 1;
}

/* ------------------------------------------------------------- arming */

static void a2x_deadman_arm(void);

static int
a2x_arm(void)
{
	uint8_t thunk[A2X_THUNK_LEN];
	uint64_t tramp = (uint64_t)(uintptr_t)&a2x_tramp;
	int64_t disp;

	if (a2x_armed) {
		return 0;
	}
	if (!a2x_verified) {
		A2X_LOG("refusing to arm: verification did not pass");
		return EPERM;
	}

	/* Step 1: tell the trampoline where to go back to. It jumps through
	 * these slots, so they must be non-zero BEFORE anything can reach it. */
	a2x_resume_ok = (uint64_t)(uintptr_t)a2x_rt(A2X_VMADDR_RESUME_OK);
	a2x_resume_bad = (uint64_t)(uintptr_t)a2x_rt(A2X_VMADDR_RESUME_BAD);

	/* Step 2: write the far-jump thunk into the dead _grade_binary body.
	 * Safe to write non-atomically because no branch targets it yet. */
	thunk[0] = 0x50;                        /* pushq %rax */
	thunk[1] = 0x48; thunk[2] = 0xb8;       /* movabs $tramp, %rax */
	for (int i = 0; i < 8; i++) {
		thunk[3 + i] = (uint8_t)((tramp >> (8 * i)) & 0xff);
	}
	thunk[11] = 0xff; thunk[12] = 0xe0;     /* jmpq *%rax */
	_Static_assert(A2X_THUNK_LEN == 13, "thunk length");
	_Static_assert(A2X_THUNK_LEN <= A2X_THUNK_ROOM, "thunk does not fit");
	a2x_write_bytes((volatile uint8_t *)a2x_rt(A2X_VMADDR_THUNK),
	    thunk, sizeof(thunk));

	/* Step 3: retarget the branch. ONE aligned 32-bit store, and the
	 * instant it lands the hook is live on every CPU. */
	disp = (int64_t)A2X_VMADDR_THUNK - (int64_t)(A2X_VMADDR_SITE_JNE + 6);
	if (disp > 0x7fffffffLL || disp < -0x80000000LL) {
		A2X_LOG("refusing to arm: thunk displacement 0x%llx out of rel32",
		    (unsigned long long)disp);
		return ERANGE;
	}
	a2x_write_disp32((volatile uint32_t *)a2x_rt(A2X_VMADDR_SITE_DISP),
	    (uint32_t)(int32_t)disp);

	a2x_armed = 1;
	a2x_hook_enabled = 1;
	a2x_fat_gate = a2x_fat_installed;
	a2x_split_arm();        /* userspace time: the a2x-split MAC policy lands after AMFI */
	a2x_deadman_arm();
	A2X_LOG("ARMED: arm64 exec -> %s (dead-man %u s)",
	    A2X_HOST_PATH, a2x_deadman_secs);
	return 0;
}

static void
a2x_disarm(const char *why)
{
	static const uint8_t thunk[] = A2X_BYTES_THUNK;

	a2x_fat_gate = 0;               /* first: fat arm64e slices stop being chosen */
	a2x_split_disarm();
	if (!a2x_armed) {
		a2x_hook_enabled = 0;
		return;
	}

	/* Reverse order of arming: the branch first, so by the time the
	 * thunk bytes change nothing can be entering them. */
	a2x_write_disp32((volatile uint32_t *)a2x_rt(A2X_VMADDR_SITE_DISP),
	    A2X_ORIG_DISP);
	a2x_hook_enabled = 0;
	a2x_write_bytes((volatile uint8_t *)a2x_rt(A2X_VMADDR_THUNK),
	    thunk, sizeof(thunk));

	a2x_armed = 0;
	A2X_LOG("DISARMED (%s): seen=%llu claimed=%llu", why,
	    a2x_hook_stats.seen, a2x_hook_stats.claimed);
}

/* ------------------------------------------------------------ fat path */

/* *  Installed once, at load, right after a2x_verify() passed: the slab and the 11-byte site cannot be written
 * atomically, and at kext load no user exec exists, so nothing can be inside the fat loop. Until a2x_fat_gate is
 * set by arming, the trampoline does exactly what the 11 original bytes did.
 */
static void
a2x_fat_install(void)
{
	uint8_t slab[13], site[A2X_FAT_SITE_LEN];
	uint64_t tramp = (uint64_t)(uintptr_t)&a2x_fattramp;
	int64_t disp = (int64_t)A2X_VMADDR_FAT_SLAB - (int64_t)(A2X_VMADDR_FAT_SITE + 5);

	if (!a2x_verified || a2x_fat_installed) {
		return;
	}
	if (disp > 0x7fffffffLL || disp < -0x80000000LL) {
		A2X_LOG("fat path NOT installed: slab displacement out of rel32");
		return;
	}
	a2x_fat_resume_native = (uint64_t)(uintptr_t)a2x_rt(A2X_VMADDR_FAT_NATIVE);
	a2x_fat_resume_graded = (uint64_t)(uintptr_t)a2x_rt(A2X_VMADDR_FAT_GRADED);
	a2x_fat_resume_skip   = (uint64_t)(uintptr_t)a2x_rt(A2X_VMADDR_FAT_SKIP);

	slab[0] = 0x50;                         /* pushq %rax */
	slab[1] = 0x48; slab[2] = 0xb8;         /* movabs $a2x_fattramp, %rax */
	for (int i = 0; i < 8; i++) {
		slab[3 + i] = (uint8_t)((tramp >> (8 * i)) & 0xff);
	}
	slab[11] = 0xff; slab[12] = 0xe0;       /* jmpq *%rax */
	a2x_write_bytes((volatile uint8_t *)a2x_rt(A2X_VMADDR_FAT_SLAB), slab, sizeof(slab));

	site[0] = 0xe9;                         /* jmp rel32 -> slab */
	for (int i = 0; i < 4; i++) {
		site[1 + i] = (uint8_t)(((uint32_t)(int32_t)disp >> (8 * i)) & 0xff);
	}
	for (int i = 5; i < A2X_FAT_SITE_LEN; i++) {
		site[i] = 0x90;
	}
	a2x_write_bytes((volatile uint8_t *)a2x_rt(A2X_VMADDR_FAT_SITE), site, sizeof(site));
	a2x_fat_installed = 1;
	A2X_LOG("fat path installed (arm64e slice graded only while armed)");
}

/* ----------------------------------------------------------- dead-man */

/* *  WHY THIS EXISTS: an exec hook that mis-grades can leave a machine
 * unable to launch anything at all - including the shell you would repair it
 * from. The guard is deliberately built so that the broken state cannot feed
 * it: disarming happens unless userspace keeps saying "I am still able to run
 * programs". No heartbeat, no hook.
 */
static void
a2x_deadman_fire(void *a __unused, void *b __unused)
{
	a2x_deadman_fired++;
	a2x_disarm("dead-man: no keepalive");
}

static void
a2x_deadman_arm(void)
{
	uint64_t deadline;

	if (a2x_deadman_call == NULL) {
		return;         /* allocation failed at load; see a2x_start */
	}
	clock_interval_to_deadline(a2x_deadman_secs, NSEC_PER_SEC, &deadline);
	thread_call_enter_delayed(a2x_deadman_call, deadline);
}

/* ------------------------------------------------------------ sysctls */

SYSCTL_NODE(, OID_AUTO, a2x, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "arm64 exec hook");

static int
a2x_sysctl_enable(struct sysctl_oid *oidp __unused, void *arg1 __unused,
    int arg2 __unused, struct sysctl_req *req)
{
	int val = a2x_armed;
	int error;

	error = sysctl_io_number(req, val, sizeof(val), &val, NULL);
	if (error || req->newptr == 0) {
		return error;
	}
	if (val) {
		return a2x_arm();
	}
	a2x_disarm("sysctl");
	return 0;
}

static int
a2x_sysctl_keepalive(struct sysctl_oid *oidp __unused, void *arg1 __unused,
    int arg2 __unused, struct sysctl_req *req)
{
	int val = 0;
	int error = sysctl_io_number(req, a2x_armed, sizeof(val), &val, NULL);

	if (error || req->newptr == 0) {
		return error;
	}
	if (a2x_armed) {
		a2x_deadman_arm();      /* re-arm; this is the heartbeat */
	}
	return 0;
}

/* NO CTLFLAG_ANYBODY on either of these. Arming the exec path is a root
 * operation, and a keepalive any process could write would let an unprivileged
 * program hold the dead-man open. */
SYSCTL_PROC(_a2x, OID_AUTO, exec_hook_enable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, a2x_sysctl_enable, "I", "1 arms the hook, 0 disarms it");
SYSCTL_PROC(_a2x, OID_AUTO, exec_hook_keepalive,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, a2x_sysctl_keepalive, "I", "write to re-arm the dead-man");
SYSCTL_INT(_a2x, OID_AUTO, exec_hook_verified, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_verified, 0, "site table matched this kernel");
SYSCTL_UINT(_a2x, OID_AUTO, exec_hook_deadman_secs, CTLFLAG_RW | CTLFLAG_LOCKED,
    &a2x_deadman_secs, 0, "dead-man timeout in seconds");
SYSCTL_QUAD(_a2x, OID_AUTO, exec_hook_deadman_fired, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_deadman_fired, "times the dead-man disarmed the hook");
SYSCTL_QUAD(_a2x, OID_AUTO, exec_seen, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_hook_stats.seen, "execs the gate handed us");
SYSCTL_QUAD(_a2x, OID_AUTO, exec_claimed, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_hook_stats.claimed, "execs redirected to the host");
SYSCTL_QUAD(_a2x, OID_AUTO, exec_not_mach, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_hook_stats.not_mach, "not a 64-bit Mach-O executable");
SYSCTL_QUAD(_a2x, OID_AUTO, exec_not_arm64, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_hook_stats.not_arm64, "a Mach-O, but not CPU_TYPE_ARM64");
SYSCTL_QUAD(_a2x, OID_AUTO, exec_no_fname, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_hook_stats.no_fname, "no path to hand the host");
SYSCTL_QUAD(_a2x, OID_AUTO, exec_fat_graded, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_fat_graded_count, "fat arm64e slices graded by the fat path");
SYSCTL_INT(_a2x, OID_AUTO, exec_fat_installed, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_fat_installed, 0, "fat path patched in");

static struct sysctl_oid *a2x_oids[] = {
	&sysctl__a2x_exec_hook_enable, &sysctl__a2x_exec_hook_keepalive,
	&sysctl__a2x_exec_hook_verified, &sysctl__a2x_exec_hook_deadman_secs,
	&sysctl__a2x_exec_hook_deadman_fired, &sysctl__a2x_exec_seen,
	&sysctl__a2x_exec_claimed, &sysctl__a2x_exec_not_mach,
	&sysctl__a2x_exec_not_arm64, &sysctl__a2x_exec_no_fname,
	&sysctl__a2x_exec_fat_graded, &sysctl__a2x_exec_fat_installed,
};

/* ------------------------------------------------------- load/unload */

/* ---------------------------------------------------------- boot arm */

/* * Arming from a daemon leaves a window: launchd runs its boot tasks (cc_fips_test and others) before any
 * LaunchDaemon starts, and with Apple's own arm64-only files in place those fail with "Bad CPU type" and
 * launchd panics on purpose. With boot-arg a2xbootarm=1 the hook arms itself as soon as the kernel's
 * code-signing policies are in place.
 *
 * Order matters: the split-signature MAC policy must be registered after AMFI's, so this waits until the
 * sandbox stand-in publishes security.mac.sandbox.sentinel, which happens after AMFI registers. If that
 * never appears (a configuration without it), it arms anyway after 30 s and says so.
 *
 * The dead-man still applies, with a boot-length window; the keepalive daemon takes it over when it runs.
 */
extern int a2x_adopt_enable;
#define A2X_BOOTARM_DEADMAN_SECS 900
#define A2X_BOOTARM_POLL_MS      10
#define A2X_BOOTARM_MAX_POLLS    3000            /* 30 s */
static thread_call_t a2x_bootarm_call;
static uint32_t a2x_bootarm_polls;
static int a2x_bootarm_result = -1;              /* -1 = not attempted */

static void
a2x_bootarm_fire(void *a __unused, void *b __unused)
{
	size_t len = 0;
	int have = (sysctlbyname("security.mac.sandbox.sentinel", NULL, &len, NULL, 0) == 0);
	uint64_t deadline;

	if (!have && ++a2x_bootarm_polls < A2X_BOOTARM_MAX_POLLS) {
		clock_interval_to_deadline(A2X_BOOTARM_POLL_MS, NSEC_PER_MSEC, &deadline);
		thread_call_enter_delayed(a2x_bootarm_call, deadline);
		return;
	}
	a2x_adopt_enable = 1;
	if (a2x_deadman_secs < A2X_BOOTARM_DEADMAN_SECS) {
		a2x_deadman_secs = A2X_BOOTARM_DEADMAN_SECS;
	}
	a2x_bootarm_result = a2x_arm();
	A2X_LOG("boot-arm: %s after %u polls, arm=%d",
	    have ? "code-signing policies ready" : "TIMED OUT waiting for the sandbox sentinel",
	    a2x_bootarm_polls, a2x_bootarm_result);
}

SYSCTL_INT(_a2x, OID_AUTO, exec_hook_bootarm_result, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_bootarm_result, 0, "boot-arm outcome: -1 not tried, 0 armed, else errno");

kern_return_t
a2x_hook_start(kmod_info_t *ki __unused, void *d __unused)
{
	sysctl_register_oid(&sysctl__a2x);
	(void)a2x_adopt_start(NULL, NULL);
	(void)a2x_ident_start();
	for (size_t i = 0; i < sizeof(a2x_oids) / sizeof(a2x_oids[0]); i++) {
		sysctl_register_oid(a2x_oids[i]);
	}

	a2x_deadman_call = thread_call_allocate(a2x_deadman_fire, NULL);
	if (a2x_deadman_call == NULL) {
		/* No dead-man means no arming. A guard that cannot run must
		 * block, not be skipped. */
		A2X_LOG("dead-man allocation failed - the hook cannot be armed");
	}

	/* *  Verification only. NOTHING is patched here, so a machine that
	 * boots with this kext loaded boots exactly as it did without it, and a
	 * reboot is always a complete recovery.
	 */
	(void)a2x_verify();
	a2x_fat_install();
	a2x_split_start(d);     /* after the fat path: Apple's 16K signatures (a2x_split.c) */
	A2X_LOG("loaded, verified=%d, armed=0; "
	    "arm with: sysctl -w a2x.exec_hook_enable=1", a2x_verified);

	sysctl_register_oid(&sysctl__a2x_exec_hook_bootarm_result);
	int bootarm = 0;
	if (PE_parse_boot_argn("a2xbootarm", &bootarm, sizeof(bootarm)) && bootarm && a2x_verified &&
	    a2x_deadman_call != NULL) {
		a2x_bootarm_call = thread_call_allocate(a2x_bootarm_fire, NULL);
		if (a2x_bootarm_call != NULL) {
			thread_call_enter(a2x_bootarm_call);
			A2X_LOG("boot-arm requested (a2xbootarm=1): waiting for the code-signing policies");
		}
	}
	return KERN_SUCCESS;
}

kern_return_t
a2x_hook_stop(kmod_info_t *ki __unused, void *d __unused)
{
	/* *  Refuse to unload while armed. Unloading would free the trampoline
	 * the kernel's own branch is pointing at, and the next arm64 exec
	 * would jump into freed memory. Disarm first, then unload.
	 */
	if (a2x_fat_installed) {
		A2X_LOG("refusing to unload: the fat path jumps into this kext");
		return KERN_FAILURE;
	}
	if (a2x_armed) {
		A2X_LOG("refusing to unload while ARMED - "
		    "sysctl -w a2x.exec_hook_enable=0 first");
		return KERN_FAILURE;
	}

	if (a2x_deadman_call != NULL) {
		thread_call_cancel(a2x_deadman_call);
		thread_call_free(a2x_deadman_call);
		a2x_deadman_call = NULL;
	}
	for (size_t i = 0; i < sizeof(a2x_oids) / sizeof(a2x_oids[0]); i++) {
		sysctl_unregister_oid(a2x_oids[i]);
	}
	if (a2x_bootarm_call != NULL) {
		thread_call_cancel(a2x_bootarm_call);
		thread_call_free(a2x_bootarm_call);
		a2x_bootarm_call = NULL;
	}
	sysctl_unregister_oid(&sysctl__a2x_exec_hook_bootarm_result);
	(void)a2x_adopt_stop(NULL, NULL);
	sysctl_unregister_oid(&sysctl__a2x);
	A2X_LOG("unloaded");
	return KERN_SUCCESS;
}

KMOD_EXPLICIT_DECL(net.arm2x86.exechook, "0.1", a2x_hook_start, a2x_hook_stop)
