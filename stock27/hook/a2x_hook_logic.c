/* * a2x_hook_logic.c - turn a refused arm64 exec into the kernel's own
 * interpreter exec, pointed at the host.
 *
 *  UNTESTED ON A MACHINE. The selftest at the bottom is the only part of
 * this directory that has any check at all behind it, and it proves the
 * mutation, not the exec.
 *
 *  THE MECHANISM, AND WHY IT IS NOT A TRANSLATOR LOADER
 * ---------------------------------------------------------
 * Apple's own answer to "foreign binary" is load_rosetta() in
 * bsd/kern/mach_loader.c:3353: it loads a NATIVE translator image for a
 * FOREIGN main binary, replaces the load result's entry point, and passes the
 * dyld load address plus two file descriptors on the new stack
 * (kern_exec.c:2013). Mirroring that means inventing kernel code: a grade
 * exemption, a cputype exemption in parse_machfile (mach_loader.c:1121), and
 * a whole second parse_machfile at depth 2.
 *
 * The kernel already has a second, much older mechanism for "this file is not
 * code I can run; run THAT binary and hand it this file": the interpreter
 * path. exec_shell_imgact() (kern_exec.c:603) sets IMGPF_INTERPRET, writes
 * the interpreter into imgp->ip_interp_buffer, re-saves the exec path, and
 * returns -3. exec_activate_image() (kern_exec.c:2468) then drops the vnode,
 * re-does namei() on the saved path and runs the activators again - and
 * exec_extract_strings() (kern_exec.c:6073) builds argv as
 *
 *      [ interp_buffer tokens... , ip_user_fname , original argv[1..] ]
 *
 * discarding the original argv[0]. That is exactly `a2xhost <guest> <args>`,
 * which is the host's existing CLI form - argv[1] is the guest, and
 * host.c:700 hands argc-1/argv+1 to the guest so the guest's own argv[0] is
 * its path, which is what bundle_relative() in host.c:413 needs to resolve
 * @executable_path.
 *
 *  So the whole OS-level hook is: when the Mach-O activator is about to
 * return EBADARCH for an arm64 image, hand it back as an interpreter exec
 * instead. No grader change, no loader change, no new stack layout, no fd
 * passing, no entry-point substitution.
 *
 *  AND THAT IS THE SAFETY PROPERTY: we only ever run on the error path.
 * grade_binary() keeps returning 0 for arm64 and every other gate stays
 * exactly as Apple shipped it. A binary that launches on this machine today
 * never reaches a single instruction of this file - WindowServer, launchd,
 * kextd and every x86_64 program are untouched by construction, not by care.
 */

#ifdef A2X_SELFTEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define A2X_NCARGS      (1024 * 1024)   /* NCARGS = ARG_MAX, sys/param.h:99 */
#define A2X_PAGE_SIZE   4096
#else
#include <sys/param.h>                  /* NCARGS */
#include <sys/systm.h>
#include <mach/machine.h>
#define A2X_NCARGS      NCARGS
#define A2X_PAGE_SIZE   PAGE_SIZE
#endif

#include "a2x_hook_logic.h"

volatile int a2x_hook_enabled = 0;      /* off until a sysctl says otherwise */
struct a2x_hook_stats a2x_hook_stats;

/* Field accessors. Deliberately ugly so every access names its offset. */
#define IPU64(p, off)   (*(volatile uint64_t *)((char *)(p) + (off)))
#define IPI32(p, off)   (*(volatile int32_t  *)((char *)(p) + (off)))
#define IPPTR(p, off)   (*(char **)((char *)(p) + (off)))
#define IPFIELD(p, off) ((char *)(p) + (off))

static void
a2x_memcpy(char *dst, const char *src, unsigned long n)
{
	while (n--) {
		*dst++ = *src++;
	}
}

static void
a2x_memset0(char *dst, unsigned long n)
{
	while (n--) {
		*dst++ = '\0';
	}
}

static unsigned long
a2x_strlen(const char *s)
{
	const char *p = s;
	while (*p) {
		p++;
	}
	return (unsigned long)(p - s);
}

/* * a2x_save_path - the body of exec_save_path() (kern_exec.c:513) for a
 * kernel-space path, inlined here because that function is static and this
 * code cannot call it.
 *
 *  The length accounting must match the original exactly. copystr() reports
 * bytes copied INCLUDING the NUL, the original then adds strlen(key) and
 * advances ip_strendp/ip_strspace by the total. A short count leaves
 * ip_strendp inside the path and exec_extract_strings() then writes argv[0]
 * over the path the relookup is about to read.
 */
static int
a2x_streq(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

static void
a2x_save_path(void *imgp, const char *path)
{
	char *strings = IPPTR(imgp, A2X_IP_STRINGS);
	unsigned long plen = a2x_strlen(path) + 1;      /* + NUL, as copystr */
	unsigned long total = A2X_EXECUTABLE_KEY_LEN + plen;

	/* ip_strings comes out of a cache; the original obliterates the old
	 * path first (kern_exec.c:521) or a longer previous path's tail
	 * survives after ours. */
	a2x_memset0(strings, A2X_EXECUTABLE_KEY_LEN + 1024 /* MAXPATHLEN */);

	a2x_memcpy(strings, A2X_EXECUTABLE_KEY, A2X_EXECUTABLE_KEY_LEN);
	a2x_memcpy(strings + A2X_EXECUTABLE_KEY_LEN, path, plen);

	IPPTR(imgp, A2X_IP_STRENDP) = strings + total;
	IPI32(imgp, A2X_IP_STRSPACE) -= (int32_t)total;
}

/* exec_reset_save_path(), kern_exec.c:572 - verbatim. */
static void
a2x_reset_save_path(void *imgp)
{
	IPPTR(imgp, A2X_IP_STRENDP) = IPPTR(imgp, A2X_IP_STRINGS);
	IPI32(imgp, A2X_IP_ARGSPACE) = A2X_NCARGS;
	IPI32(imgp, A2X_IP_STRSPACE) = A2X_NCARGS + A2X_PAGE_SIZE;
}

int
a2x_exec_decide(void *imgp)
{
	const char *vdata;
	uint32_t magic, filetype;
	int32_t cputype;
	char *interp;
	unsigned long hlen;
	const char *host = A2X_LAUNCH_PATH;
	const char *saved;

	a2x_hook_stats.seen++;

	if (!a2x_hook_enabled) {
		a2x_hook_stats.disabled++;
		return A2X_NOT_OURS;
	}

	/* Never redirect a redirect. exec_shell_imgact() guards itself the
	 * same way (kern_exec.c:616). Without this, a host that somehow graded
	 * 0 itself would loop until EAI_ITERLIMIT and report EBADEXEC. */
	if (IPI32(imgp, A2X_IP_FLAGS) & A2X_IMGPF_INTERPRET) {
		a2x_hook_stats.already++;
		return A2X_NOT_OURS;
	}

	/* *  The guest path we hand the host is imgp->ip_user_fname, the path as
	 * the caller passed it to execve/posix_spawn - that is what
	 * exec_extract_strings() inserts as the interpreter's first argument.
	 * If there is no such path (a spawn that only had a descriptor) we have
	 * nothing to name, so leave the kernel's EBADARCH alone rather than
	 * exec the host with a wrong or empty guest.
	 */
	if (IPU64(imgp, A2X_IP_USER_FNAME) == 0) {
		a2x_hook_stats.no_fname++;
		return A2X_NOT_OURS;
	}

	vdata = IPPTR(imgp, A2X_IP_VDATA);
	if (vdata == NULL) {
		a2x_hook_stats.not_mach++;
		return A2X_NOT_OURS;
	}

	/* ip_vdata already holds the first page of the image - and for a fat
	 * file, exec_fat_imgact() re-read it at the chosen slice's offset
	 * (kern_exec.c:849). So the header below is the real header either way
	 * and this costs no I/O. */
	magic    = *(const uint32_t *)(const void *)(vdata + 0);
	cputype  = *(const int32_t  *)(const void *)(vdata + 4);
	filetype = *(const uint32_t *)(const void *)(vdata + 12);

	/* 64-bit, host-endian, MH_EXECUTE only. A byte-swapped header
	 * (MH_CIGAM_64) is refused by exec_mach_imgact with EBADARCH before the
	 * grade gate and must stay refused; a dylib or bundle is not something
	 * the host can be given as argv[1]. */
	if (magic != A2X_MH_MAGIC_64) {
		a2x_hook_stats.not_mach++;
		return A2X_NOT_OURS;
	}
	if (filetype != A2X_MH_EXECUTE) {
		a2x_hook_stats.not_mach++;
		return A2X_NOT_OURS;
	}

	/* CPU_TYPE_ARM64 only. arm64_32 and 32-bit arm are different
	 * instruction sets and the host does not interpret them; claiming them
	 * would turn a clean EBADARCH into a confusing host failure. arm64e
	 * shares CPU_TYPE_ARM64 and is accepted here - whether the host can
	 * run signed-pointer code is the host's problem to report, not ours to
	 * pre-judge. */
	if (cputype != A2X_CPU_TYPE_ARM64) {
		a2x_hook_stats.not_arm64++;
		return A2X_NOT_OURS;
	}

	/* ---- claimed: rewrite imgp into the kernel's interpreter form ---- */

	/* The path being executed was saved at ip_strings behind the key by the kernel before this pass. */
	saved = IPPTR(imgp, A2X_IP_STRINGS);
	if (saved != NULL && a2x_streq(saved + A2X_EXECUTABLE_KEY_LEN, A2X_XPCPROXY_PATH))
		host = A2X_HOST_PATH;

	hlen = a2x_strlen(host);
	if (hlen + 1 > A2X_IMG_SHSIZE) {
		/* Unreachable with the compiled-in path, but a check that cannot
		 * run must not report clean. */
		a2x_hook_stats.not_mach++;
		return A2X_NOT_OURS;
	}

	IPI32(imgp, A2X_IP_FLAGS) |= A2X_IMGPF_INTERPRET;
	IPI32(imgp, A2X_IP_INTERP_SUGID_FD) = -1;

	interp = IPFIELD(imgp, A2X_IP_INTERP_BUFFER);
	a2x_memset0(interp, A2X_IMG_SHSIZE);
	a2x_memcpy(interp, host, hlen + 1);

	a2x_reset_save_path(imgp);
	a2x_save_path(imgp, host);

	/* *  THE TRAP THAT WOULD HAVE LOOKED LIKE "THE HOOK DOES NOTHING".
	 * exec_mach_imgact() set imgp->ip_origcputype to the arm64 header's
	 * cputype on this pass (kern_exec.c:1371). On the NEXT pass - the host -
	 * the very first thing it does with a non-zero ip_origcputype is
	 *   if (ip_origcputype != mach_header->cputype) { error = EBADARCH; }
	 * (kern_exec.c:1365). The host is x86_64, so without this reset the
	 * redirect fails with the same EBADARCH the redirect exists to avoid,
	 * and every symptom - the shell message, the errno, the log line - is
	 * identical to not having installed the hook at all.
	 *
	 *  ip_arch_offset/ip_arch_size are the slice window inside a FAT
	 * guest. Left set, load_machfile() reads the host at the guest's slice
	 * offset. Zero means "the whole file", which is what a thin host is.
	 */
	IPI32(imgp, A2X_IP_ORIGCPUTYPE) = 0;
	IPI32(imgp, A2X_IP_ORIGCPUSUBTYPE) = 0;
	IPU64(imgp, A2X_IP_ARCH_OFFSET) = 0;
	IPU64(imgp, A2X_IP_ARCH_SIZE) = 0;

	a2x_hook_stats.claimed++;
	return A2X_CLAIMED;
}

/* ===================================================================== */
#ifdef A2X_SELFTEST
/* * Build (on a machine with a compiler - NOT run by anything in this
 * directory):
 *   cc -DA2X_SELFTEST -Wall -Wextra -o a2x_logic_selftest a2x_hook_logic.c
 *   ./a2x_logic_selftest --selftest
 *
 *  Arms are named sentences. Every negative arm must FIRE - a run where the
 * negatives all "pass" because the hook claimed nothing at all is caught by
 * A1, which requires a claim.
 */

#define IMGP_SZ 0x400           /* > offsetof(ip_interp_sugid_fd) + 8 */

static int fails;
static int arms;

static void
arm(const char *name, int ok)
{
	arms++;
	if (!ok) {
		fails++;
	}
	printf("%s %s\n", ok ? "ok  " : "FAIL", name);
}

struct fake {
	char imgp[IMGP_SZ];
	char page[4096];
	char strings[8192];
};

static struct fake *
mk(uint32_t magic, int32_t cputype, uint32_t filetype)
{
	struct fake *f = calloc(1, sizeof(*f));
	memset(f->imgp, 0, IMGP_SZ);
	*(uint32_t *)(void *)(f->page + 0) = magic;
	*(int32_t *)(void *)(f->page + 4) = cputype;
	*(uint32_t *)(void *)(f->page + 12) = filetype;
	IPU64(f->imgp, A2X_IP_USER_FNAME) = 0xdead0000ull;  /* non-zero path */
	IPPTR(f->imgp, A2X_IP_VDATA) = f->page;
	IPPTR(f->imgp, A2X_IP_STRINGS) = f->strings;
	IPPTR(f->imgp, A2X_IP_STRENDP) = f->strings + 777;  /* junk to reset */
	IPI32(f->imgp, A2X_IP_STRSPACE) = 12;               /* junk to reset */
	IPI32(f->imgp, A2X_IP_ARGSPACE) = 13;               /* junk to reset */
	/* as exec_mach_imgact left them before the grade gate */
	IPI32(f->imgp, A2X_IP_ORIGCPUTYPE) = cputype;
	IPI32(f->imgp, A2X_IP_ORIGCPUSUBTYPE) = 2;
	IPU64(f->imgp, A2X_IP_ARCH_OFFSET) = 0x4000;
	IPU64(f->imgp, A2X_IP_ARCH_SIZE) = 0x9000;
	return f;
}

int
main(int argc, char **argv)
{
	struct fake *f;
	int r;

	(void)argc; (void)argv;
	a2x_hook_enabled = 1;

	/* ---------- positive arms ---------- */

	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	r = a2x_exec_decide(f->imgp);
	arm("A1 a thin arm64 MH_EXECUTE is claimed", r == A2X_CLAIMED);
	arm("A2 the interpreter buffer names the host, NUL terminated",
	    strcmp(IPFIELD(f->imgp, A2X_IP_INTERP_BUFFER), A2X_LAUNCH_PATH) == 0);
	arm("A3 IMGPF_INTERPRET is set, so the kernel relooks up the host",
	    (IPI32(f->imgp, A2X_IP_FLAGS) & A2X_IMGPF_INTERPRET) != 0);
	arm("A4 the sugid fd is -1, so argv gets the path and not /dev/fd/N",
	    IPI32(f->imgp, A2X_IP_INTERP_SUGID_FD) == -1);
	arm("A5 the relookup reads the host at ip_strings+strlen(key)",
	    strcmp(f->strings + A2X_EXECUTABLE_KEY_LEN, A2X_LAUNCH_PATH) == 0);
	arm("A6 the EXECUTABLE_KEY prefix is intact for the applev entry",
	    memcmp(f->strings, A2X_EXECUTABLE_KEY, A2X_EXECUTABLE_KEY_LEN) == 0);
	arm("A7 ip_strendp lands past the saved path, not inside it",
	    IPPTR(f->imgp, A2X_IP_STRENDP) ==
	    f->strings + A2X_EXECUTABLE_KEY_LEN + strlen(A2X_LAUNCH_PATH) + 1);
	arm("A8 argspace/strspace are reset to the kernel's own values",
	    IPI32(f->imgp, A2X_IP_ARGSPACE) == A2X_NCARGS &&
	    IPI32(f->imgp, A2X_IP_STRSPACE) ==
	    (int32_t)(A2X_NCARGS + A2X_PAGE_SIZE -
	    (A2X_EXECUTABLE_KEY_LEN + strlen(A2X_LAUNCH_PATH) + 1)));

	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	strcpy(f->strings, A2X_EXECUTABLE_KEY A2X_XPCPROXY_PATH);
	r = a2x_exec_decide(f->imgp);
	arm("X1 xpcproxy is handed to the interpreter itself, not the launcher",
	    r == A2X_CLAIMED && strcmp(IPFIELD(f->imgp, A2X_IP_INTERP_BUFFER), A2X_HOST_PATH) == 0 &&
	    strcmp(f->strings + A2X_EXECUTABLE_KEY_LEN, A2X_HOST_PATH) == 0);
	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	strcpy(f->strings, A2X_EXECUTABLE_KEY A2X_XPCPROXY_PATH "2");
	r = a2x_exec_decide(f->imgp);
	arm("X2 a path that only begins like xpcproxy goes to the launcher",
	    r == A2X_CLAIMED && strcmp(IPFIELD(f->imgp, A2X_IP_INTERP_BUFFER), A2X_LAUNCH_PATH) == 0);
	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	strcpy(f->strings, A2X_EXECUTABLE_KEY "/System/Applications/Weather.app/Contents/PlugIns/WeatherWidget.appex/Contents/MacOS/WeatherWidget");
	r = a2x_exec_decide(f->imgp);
	arm("X3 a widget extension goes to the launcher",
	    r == A2X_CLAIMED && strcmp(IPFIELD(f->imgp, A2X_IP_INTERP_BUFFER), A2X_LAUNCH_PATH) == 0);
	/* the trap: without these the host pass returns EBADARCH */
	arm("A9 ip_origcputype is zeroed, or the host pass returns EBADARCH",
	    IPI32(f->imgp, A2X_IP_ORIGCPUTYPE) == 0 &&
	    IPI32(f->imgp, A2X_IP_ORIGCPUSUBTYPE) == 0);
	arm("A10 ip_arch_offset/size are zeroed, or the host is read at the "
	    "guest's slice offset",
	    IPU64(f->imgp, A2X_IP_ARCH_OFFSET) == 0 &&
	    IPU64(f->imgp, A2X_IP_ARCH_SIZE) == 0);
	free(f);

	/* ---------- negative arms: each of these MUST fire ---------- */

	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_X86_64, A2X_MH_EXECUTE);
	r = a2x_exec_decide(f->imgp);
	arm("N1 an x86_64 executable is NOT claimed", r == A2X_NOT_OURS);
	arm("N2 a refused image is left completely untouched",
	    (IPI32(f->imgp, A2X_IP_FLAGS) & A2X_IMGPF_INTERPRET) == 0 &&
	    IPI32(f->imgp, A2X_IP_ORIGCPUTYPE) == A2X_CPU_TYPE_X86_64 &&
	    IPU64(f->imgp, A2X_IP_ARCH_OFFSET) == 0x4000);
	free(f);

	f = mk(A2X_MH_CIGAM_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	arm("N3 a byte-swapped Mach-O header is NOT claimed",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(A2X_MH_MAGIC, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	arm("N4 a 32-bit Mach-O header is NOT claimed",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(A2X_FAT_MAGIC, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	arm("N5 a fat header is NOT claimed (the slice is, one pass later)",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(0x23212f62u /* '#!/b' */, 0, 0);
	arm("N6 a #! script is NOT claimed - the kernel's own activator owns it",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(0x00000000u, 0, 0);
	arm("N7 a non-Mach-O file of zeroes is NOT claimed",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, 0x6 /* MH_DYLIB */);
	arm("N8 an arm64 dylib is NOT claimed",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64_32, A2X_MH_EXECUTE);
	arm("N9 arm64_32 is NOT claimed",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM, A2X_MH_EXECUTE);
	arm("N10 32-bit arm is NOT claimed",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	IPI32(f->imgp, A2X_IP_FLAGS) |= A2X_IMGPF_INTERPRET;
	arm("N11 an image already being interpreted is NOT claimed twice",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	IPU64(f->imgp, A2X_IP_USER_FNAME) = 0;
	arm("N12 an exec with no path to hand the host is NOT claimed",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);

	/* ---------- the kill switch, measured in both directions ---------- */
	a2x_hook_enabled = 0;
	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	arm("K1 with the hook disabled the SAME image is NOT claimed",
	    a2x_exec_decide(f->imgp) == A2X_NOT_OURS);
	free(f);
	a2x_hook_enabled = 1;
	f = mk(A2X_MH_MAGIC_64, A2X_CPU_TYPE_ARM64, A2X_MH_EXECUTE);
	arm("K2 re-enabling claims it again, so K1 measured the switch and "
	    "not the image",
	    a2x_exec_decide(f->imgp) == A2X_CLAIMED);
	free(f);

	/* Every call must land in exactly one counter. A path that returns
	 * without counting is a path nobody can see from a sysctl, and the
	 * negative arms in TEST.md are all read off these counters. */
	arm("S1 every call is accounted for in exactly one counter",
	    a2x_hook_stats.seen ==
	    a2x_hook_stats.claimed + a2x_hook_stats.not_mach +
	    a2x_hook_stats.not_arm64 + a2x_hook_stats.no_fname +
	    a2x_hook_stats.already + a2x_hook_stats.disabled);
	arm("S2 the 17 decide() calls above were all seen",
	    a2x_hook_stats.seen == 17);

	printf("\n%d arms, %d failed\n", arms, fails);
	printf("seen=%llu claimed=%llu not_mach=%llu not_arm64=%llu "
	    "no_fname=%llu already=%llu disabled=%llu\n",
	    a2x_hook_stats.seen, a2x_hook_stats.claimed,
	    a2x_hook_stats.not_mach, a2x_hook_stats.not_arm64,
	    a2x_hook_stats.no_fname, a2x_hook_stats.already,
	    a2x_hook_stats.disabled);
	return fails ? 1 : 0;
}
#endif /* A2X_SELFTEST */
