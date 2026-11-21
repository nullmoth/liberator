/* * a2x_split.c - an arm64e guest keeps APPLE'S OWN code signature on the x86_64 kernel.
 *
 *  THE RULER (11-05, M6 mini, real 27.2 26B123): a running app's kernel cdhash IS its file's cdhash
 *    (WallpaperAgent 077f4990.. both; MenuBarAgent a3918aa9.. both). secinitd, securityd and every
 *    SecCode check rely on that: in the VM a mismatch made secinitd refuse ("cdhash mismatch", -67034,
 *    "registration request failed: (0x10, 0x3)") and libsecinit trapped.
 *
 *  WHY THE HOST COULD NOT JUST REGISTER APPLE'S BLOB. Apple signs arm64e with 16K code pages (shift 14).
 *    This kernel's CodeDirectory validator (static, 0x...8486a0) accepts shift 12 only, and its page
 *    validator panics on a 4K fault at an offset that is not a multiple of the signature's page size
 *    ("offset not aligned to cshash boundary", ubc_subr.c:0x1717). So the host lowered the shift, which
 *    changed the directory and therefore the cdhash: the identity was no longer Apple's.
 *
 *  APPLE'S OWN PATTERN, RUN THE OTHER WAY. ubc_cs_blob_add already converts a SMALLER-page signature up
 *    to the kernel page ("Attempting to convert Code Directory for %lu -> %lu page shift"): it keeps the
 *    original cdhash for identity and validates pages with a derived directory. It only goes up (shift
 *    <= 11). This file goes down, at an Apple-provided extension point:
 *    - the host registers Apple's superblob UNTOUCHED, followed by a derived 4K CodeDirectory that is
 *      byte-identical to Apple's primary one except length, nCodeSlots, pageSize and the code hashes;
 *    - the validator accepts shift 14 only while this policy is live (a2x_cdvtramp);
 *    - mpo_vnode_check_signature (slot 304) receives the blob with Apple's cdhash already computed and
 *      AMFI already consulted, BEFORE it is linked to the vnode. Here the kernel reads the file, checks
 *      every 16K page against Apple's hashes and every 4K hash against the same bytes, and only then
 *      points csb_cd at the derived directory and sets the shift to 12. cdhash, CMS, team id and
 *      entitlements stay Apple's; page validation stays real (4K, against Apple-verified content).
 *    -  any blob with shift > 12 that cannot be derived is REFUSED, so a 16K geometry can never reach
 *      the page validator. Nothing is substituted: no hash is ever written into the kernel.
 *
 * Field offsets: struct cs_blob from the 27.2 KDK DWARF (kernel.dSYM 33da3da2). zalloc_ro_mut and
 * csblob_get_cdhash are reached by address + slide and both prologues are checked byte for byte first.
 * Boot-arg a2xsplit=0 installs nothing.
 */
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/kauth.h>
#include <kern/locks.h>
#include <pexpert/pexpert.h>
#include "a2x_hook_sites.h"

#define A2X_CSB_RO_ADDR      0x10
#define A2X_CSB_BASE_OFFSET  0x28
#define A2X_CSB_START        0x30
#define A2X_CSB_END          0x38
#define A2X_CSB_MEM_SIZE     0x40
#define A2X_CSB_MEM_OFFSET   0x48
#define A2X_CSB_MEM_KADDR    0x50
#define A2X_CSB_HASHTYPE     0xa0
#define A2X_CSB_PAGESHIFT    0xa8
#define A2X_CSB_FIRSTLEVEL   0xac
#define A2X_CSB_CD           0xb0
#define A2X_ZONE_ID_CS_BLOB  8          /* ubc_cs_blob_add: zalloc_ro(edi=8, ...), 27.2 verified */
#define A2X_CSH_SIZE         0x08       /* struct cs_hash: cs_size (slot size), cs_digest_size, init/update/final */
#define A2X_CSH_DIGEST       0x10
#define A2X_CSH_INIT         0x18
#define A2X_CSH_UPDATE       0x20
#define A2X_CSH_FINAL        0x28
#define A2X_CS_CTX_BYTES     0xd0       /* union cs_hash_union */
#define A2X_MPO_SLOTS        335        /* 27.2 mac_policy_ops = 0xa78 bytes */
#define A2X_MPO_VNODE_CHECK_SIGNATURE 304   /* +0x980: mac_vnode_check_signature calls [ops+0x980] */

#define A2X_VMADDR_CDV_SITE  0xffffff80008486b6ull  /* cmpl $0xc,%eax ; jne 0x...84870c */
#define A2X_VMADDR_CDV_OK    0xffffff80008486bbull  /* movzbl 0x25(%rdi),%eax: next check (hash type) */
#define A2X_VMADDR_CDV_BAD   0xffffff800084870cull  /* leaq "disallowing unsupported code signature page shift" */
#define A2X_VMADDR_CDV_SLAB  0xffffff80008843d0ull  /* dead _grade_binary + 0x30, after the fat slab's 13 */
#define A2X_VMADDR_ROMUT_272 0xffffff80002f7800ull  /* nm: t _zalloc_ro_mut (27.2) */
#define A2X_VMADDR_CDH_272   0xffffff80007b8530ull  /* nm: T _csblob_get_cdhash (27.2): lea 0x58(%rdi) */

struct mac_policy_conf {
	const char *mpc_name;
	const char *mpc_fullname;
	char const * const *mpc_labelnames;
	unsigned int mpc_labelname_count;
	const void *mpc_ops;
	int mpc_loadtime_flags;
	int *mpc_field_off;
	int mpc_runtime_flags;
	void *mpc_list;
	void *mpc_data;
};
typedef unsigned int mac_policy_handle_t;
extern int mac_policy_register(struct mac_policy_conf *mpc, mac_policy_handle_t *handlep, void *xd);

extern void a2x_cdvtramp(void);
extern uint64_t a2x_cdv_resume_ok, a2x_cdv_resume_bad, a2x_cdv_allowed;
extern uint32_t a2x_split_gate;

int a2x_split_enable = 1;
static int a2x_split_installed, a2x_split_registered;
static uint64_t a2x_split_seen, a2x_split_derived, a2x_split_refused, a2x_split_last_reason;
static void *a2x_split_xd;
static lck_mtx_t *a2x_split_mtx;
static uint8_t a2x_split_buf[16384] __attribute__((aligned(64)));
static void (*a2x_split_romut)(uint16_t, void *, vm_offset_t, const void *, vm_size_t);

static const void *a2x_split_ops[A2X_MPO_SLOTS];
static struct mac_policy_conf a2x_split_conf = {
	.mpc_name = "a2x-split",
	.mpc_fullname = "a2x: Apple signature of an arm64e guest, validated in 4K pages",
	.mpc_ops = a2x_split_ops,
};
static mac_policy_handle_t a2x_split_handle;

#define A2X_SLOG(fmt, ...) printf("a2x-split: " fmt "\n", ##__VA_ARGS__)

static uint32_t
a2x_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static int
a2x_same(const uint8_t *a, const uint8_t *b, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (a[i] != b[i]) {
			return 0;
		}
	}
	return 1;
}

static void
a2x_split_hash(const uint8_t *ht, const void *data, size_t len, uint8_t out[64])
{
	uint64_t ctx[A2X_CS_CTX_BYTES / 8 + 2];
	void (*init)(void *) = *(void (* const *)(void *))(ht + A2X_CSH_INIT);
	void (*update)(void *, const void *, size_t) = *(void (* const *)(void *, const void *, size_t))(ht + A2X_CSH_UPDATE);
	void (*final)(void *, void *) = *(void (* const *)(void *, void *))(ht + A2X_CSH_FINAL);

	init(ctx);                  /* the kernel's own calling order: init(ctx) update(ctx,d,n) final(digest,ctx) */
	update(ctx, data, len);
	final(out, ctx);
}

/* Returns 0 after the blob has been rewritten to the derived 4K geometry, else a reason number (refused). */
static int
a2x_split_derive(vnode_t vp, uint8_t *b)
{
	const uint8_t *cd = *(const uint8_t * const *)(b + A2X_CSB_CD);
	const uint8_t *ht = *(const uint8_t * const *)(b + A2X_CSB_HASHTYPE);
	const uint8_t *kaddr = *(const uint8_t * const *)(b + A2X_CSB_MEM_KADDR);
	uint64_t msize = *(const uint64_t *)(b + A2X_CSB_MEM_SIZE);
	uint64_t moff = *(const uint64_t *)(b + A2X_CSB_MEM_OFFSET);
	off_t base = *(const off_t *)(b + A2X_CSB_BASE_OFFSET);
	uint8_t *ro = *(uint8_t * const *)(b + A2X_CSB_RO_ADDR);
	uint8_t dig[64];

	if (cd == NULL || ht == NULL || kaddr == NULL || ro == NULL || a2x_split_romut == NULL) {
		return 1;
	}
	if (*(const uint64_t *)(b + A2X_CSB_START) != 0 || *(const uint32_t *)(b + A2X_CSB_FIRSTLEVEL) != 0) {
		return 2;
	}
	const uint8_t *sb = kaddr + moff;
	if (msize < 12 || a2x_be32(sb) != 0xfade0cc0u) {
		return 3;
	}
	uint32_t sblen = a2x_be32(sb + 4);
	if (sblen < 12 || sblen > msize) {   /* split8: Apple superblobs end unaligned (WallpaperAgent 14555) */
		return 4;
	}
	if (cd < sb || cd + 44 > sb + sblen) {
		return 5;               /* the primary CodeDirectory must be Apple's, inside Apple's superblob */
	}
	uint32_t cdlen = a2x_be32(cd + 4), ver = a2x_be32(cd + 8), hoff = a2x_be32(cd + 16);
	uint32_t nspec = a2x_be32(cd + 24), n16 = a2x_be32(cd + 28), climit = a2x_be32(cd + 32);
	uint8_t hsz = cd[36], htype = cd[37], pshift = cd[39];
	if (cd + cdlen > sb + sblen || pshift != 14) {
		return 6;
	}
	if (ver >= 0x20100 && cdlen >= 48 && a2x_be32(cd + 44) != 0) {
		return 7;               /* scatter: not used by Apple binaries; refuse rather than guess */
	}
	if (ver >= 0x20300 && cdlen >= 0x40 && (a2x_be32(cd + 0x38) | a2x_be32(cd + 0x3c)) != 0) {
		return 8;               /* codeLimit64 */
	}
	if (climit == 0 || n16 != (climit + 16383u) >> 14) {
		return 9;
	}
	if ((uint64_t)hoff + (uint64_t)n16 * hsz != cdlen || hoff < 44 || (uint64_t)nspec * hsz > hoff) {
		return 10;
	}
	if (ht[0] != htype || *(const uint64_t *)(ht + A2X_CSH_SIZE) != hsz ||
	    *(const uint64_t *)(ht + A2X_CSH_DIGEST) > sizeof(dig) || hsz == 0) {
		return 11;
	}
	/* the derived directory sits right after Apple's superblob, outside its index: anything that reads
	 * the signature by slot (codesign, csops CS_OPS_BLOB) still finds Apple's directories only */
	uint64_t doff = ((uint64_t)sblen + 7u) & ~(uint64_t)7u;   /* split8: next 8-byte boundary, the gap is zeros */
	if (doff + 44 > msize) {
		return 12;
	}
	for (uint64_t i = sblen; i < doff; i++) {
		if (sb[i] != 0) {
			return 19;   /* nothing may hide between Apple's bytes and ours */
		}
	}
	const uint8_t *d = sb + doff;
	uint32_t n4 = (climit + 4095u) >> 12;
	if (a2x_be32(d) != 0xfade0c02u) {
		return 12;
	}
	uint32_t dlen = a2x_be32(d + 4);
	if (doff + dlen > msize || (uint64_t)dlen != (uint64_t)hoff + (uint64_t)n4 * hsz) {
		return 13;
	}
	for (uint32_t i = 8; i < hoff; i++) {
		if ((i >= 28 && i < 32) || i == 39) {
			continue;
		}
		if (d[i] != cd[i]) {
			return 14;      /* header, identifier, team id, special slots: byte-identical to Apple's */
		}
	}
	if (a2x_be32(d + 28) != n4 || d[39] != 12) {
		return 15;
	}

	lck_mtx_lock(a2x_split_mtx);
	for (uint32_t i = 0; i < n16; i++) {
		uint64_t o = (uint64_t)i << 14;
		uint32_t len = (climit - o) < 16384 ? (uint32_t)(climit - o) : 16384;
		int resid = 0;

		if (vn_rdwr(UIO_READ, vp, (caddr_t)a2x_split_buf, (int)len, base + (off_t)o, UIO_SYSSPACE,
		    IO_NODELOCKED, vfs_context_ucred(vfs_context_current()), &resid, current_proc()) != 0 || resid != 0) {
			lck_mtx_unlock(a2x_split_mtx);
			return 16;
		}
		a2x_split_hash(ht, a2x_split_buf, len, dig);
		if (!a2x_same(dig, cd + hoff + (uint64_t)i * hsz, hsz)) {
			lck_mtx_unlock(a2x_split_mtx);
			return 17;      /* the file is not what Apple signed */
		}
		for (uint32_t j = 0; j < 4; j++) {
			uint64_t o4 = o + ((uint64_t)j << 12);
			if (o4 >= climit) {
				break;
			}
			uint32_t l4 = (climit - o4) < 4096 ? (uint32_t)(climit - o4) : 4096;
			a2x_split_hash(ht, a2x_split_buf + ((size_t)j << 12), l4, dig);
			if (!a2x_same(dig, d + hoff + ((uint64_t)i * 4 + j) * hsz, hsz)) {
				lck_mtx_unlock(a2x_split_mtx);
				return 18;  /* a 4K hash that does not describe Apple-verified bytes */
			}
		}
	}
	lck_mtx_unlock(a2x_split_mtx);

	const uint8_t *dcd = d;
	uint32_t twelve = 12;
	uint64_t end = ((uint64_t)climit + 4095u) & ~(uint64_t)4095u;
	/* the stack copy the rest of ubc_cs_blob_add reads (its up-converter reads the shift at +0xa8) ... */
	*(const uint8_t **)(b + A2X_CSB_CD) = dcd;
	*(uint32_t *)(b + A2X_CSB_PAGESHIFT) = twelve;
	*(uint64_t *)(b + A2X_CSB_END) = end;
	/* ... and the read-only element it was already copied into */
	a2x_split_romut(A2X_ZONE_ID_CS_BLOB, ro, A2X_CSB_CD, &dcd, sizeof(dcd));
	a2x_split_romut(A2X_ZONE_ID_CS_BLOB, ro, A2X_CSB_PAGESHIFT, &twelve, sizeof(twelve));
	a2x_split_romut(A2X_ZONE_ID_CS_BLOB, ro, A2X_CSB_END, &end, sizeof(end));
	return 0;
}

static int
a2x_split_vnode_check_signature(vnode_t vp, void *label __unused, int cputype __unused, void *blob,
    unsigned int *cs_flags __unused, unsigned int *signer_type __unused, int flags __unused,
    unsigned int platform __unused, char **fatal_desc __unused, size_t *fatal_len __unused)
{
	uint8_t *b = blob;

	if (b == NULL || *(const uint32_t *)(b + A2X_CSB_PAGESHIFT) <= 12) {
		return 0;               /* every native signature: one load, one compare */
	}
	a2x_split_seen++;
	int r = a2x_split_derive(vp, b);
	if (r != 0) {
		a2x_split_refused++;
		a2x_split_last_reason = (uint64_t)r;
		if (a2x_split_refused <= 20) {
			A2X_SLOG("REFUSED a 16K signature (reason %d) - it is not linked to the vnode", r);
		}
		return EBADEXEC;
	}
	a2x_split_derived++;
	return 0;
}

SYSCTL_DECL(_a2xa);
SYSCTL_INT(_a2xa, OID_AUTO, split_enable, CTLFLAG_RW | CTLFLAG_LOCKED, &a2x_split_enable, 0,
    "1: Apple's 16K signature registered as-is, validated through a kernel-verified 4K directory");
SYSCTL_INT(_a2xa, OID_AUTO, split_installed, CTLFLAG_RD | CTLFLAG_LOCKED, &a2x_split_installed, 0, "validator site installed");
SYSCTL_INT(_a2xa, OID_AUTO, split_registered, CTLFLAG_RD | CTLFLAG_LOCKED, &a2x_split_registered, 0, "MAC policy registered");
SYSCTL_UINT(_a2xa, OID_AUTO, split_gate, CTLFLAG_RD | CTLFLAG_LOCKED, &a2x_split_gate, 0, "validator accepts shift 14");
SYSCTL_QUAD(_a2xa, OID_AUTO, split_seen, CTLFLAG_RD | CTLFLAG_LOCKED, &a2x_split_seen, "16K signatures seen");
SYSCTL_QUAD(_a2xa, OID_AUTO, split_derived, CTLFLAG_RD | CTLFLAG_LOCKED, &a2x_split_derived, "verified and linked with 4K pages");
SYSCTL_QUAD(_a2xa, OID_AUTO, split_refused, CTLFLAG_RD | CTLFLAG_LOCKED, &a2x_split_refused, "refused");
SYSCTL_QUAD(_a2xa, OID_AUTO, split_last_reason, CTLFLAG_RD | CTLFLAG_LOCKED, &a2x_split_last_reason, "last refusal reason");
SYSCTL_QUAD(_a2xa, OID_AUTO, split_cdv_allowed, CTLFLAG_RD | CTLFLAG_LOCKED, &a2x_cdv_allowed, "validator passes at shift 14");

static struct sysctl_oid *a2x_split_oids[] = {
	&sysctl__a2xa_split_enable, &sysctl__a2xa_split_installed, &sysctl__a2xa_split_registered,
	&sysctl__a2xa_split_gate, &sysctl__a2xa_split_seen, &sysctl__a2xa_split_derived,
	&sysctl__a2xa_split_refused, &sysctl__a2xa_split_last_reason, &sysctl__a2xa_split_cdv_allowed,
};

static void
a2x_split_wbytes(volatile uint8_t *dst, const uint8_t *src, size_t len)
{
	uint64_t fl, cr0;

	__asm__ volatile ("pushfq; popq %0; cli" : "=r" (fl) :: "memory");
	__asm__ volatile ("movq %%cr0, %0" : "=r" (cr0));
	__asm__ volatile ("movq %0, %%cr0" :: "r" (cr0 & ~(uint64_t)0x10000) : "memory");
	for (size_t i = 0; i < len; i++) {
		dst[i] = src[i];
	}
	__asm__ volatile ("movq %0, %%cr0" :: "r" (cr0) : "memory");
	if (fl & 0x200) {
		__asm__ volatile ("sti" ::: "memory");
	}
}

/* Called from the hook kext's start, after its own site table verified and the fat path installed. */
void
a2x_split_start(void *xd)
{
	static const uint8_t site[] = { 0x83, 0xf8, 0x0c, 0x75, 0x51 };
	static const uint8_t ok[] = { 0x0f, 0xb6, 0x47, 0x25 };
	static const uint8_t bad[] = { 0x48, 0x8d, 0x3d };
	static const uint8_t slab0[] = { 0x94, 0xc1, 0x01, 0xc9, 0x83, 0xfe, 0x08, 0xb8, 0x03, 0x00, 0x00, 0x00, 0x0f };
	static const uint8_t romut[] = { 0x55, 0x48, 0x89, 0xe5, 0x83, 0xff, 0x0e, 0x75, 0x30 };
	static const uint8_t cdh[] = { 0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x47, 0x58, 0x5d, 0xc3 };
	int arg = 1;

	a2x_split_xd = xd;
	for (size_t i = 0; i < sizeof(a2x_split_oids) / sizeof(a2x_split_oids[0]); i++) {
		sysctl_register_oid(a2x_split_oids[i]);
	}
	if (PE_parse_boot_argn("a2xsplit", &arg, sizeof(arg)) && arg == 0) {
		a2x_split_enable = 0;
		A2X_SLOG("OFF (boot-arg a2xsplit=0): validator untouched, guests keep the 4K-rewritten path");
		return;
	}
	uint64_t slide = (uint64_t)(uintptr_t)&vn_rdwr - A2X_VMADDR_ANCHOR;
	const struct { const char *what; uint64_t a; const uint8_t *w; size_t n; } chk[] = {
		{ "cd validator site", A2X_VMADDR_CDV_SITE, site, sizeof(site) },
		{ "cd validator ok", A2X_VMADDR_CDV_OK, ok, sizeof(ok) },
		{ "cd validator bad", A2X_VMADDR_CDV_BAD, bad, sizeof(bad) },
		{ "cd validator slab", A2X_VMADDR_CDV_SLAB, slab0, sizeof(slab0) },
		{ "zalloc_ro_mut", A2X_VMADDR_ROMUT_272, romut, sizeof(romut) },
		{ "csblob_get_cdhash", A2X_VMADDR_CDH_272, cdh, sizeof(cdh) },
	};
	for (size_t c = 0; c < sizeof(chk) / sizeof(chk[0]); c++) {
		const uint8_t *got = (const uint8_t *)(uintptr_t)(chk[c].a + slide);
		if (!a2x_same(got, chk[c].w, chk[c].n)) {
			A2X_SLOG("REFUSING to install: %s at %p does not match 27.2 26B123 - nothing written", chk[c].what, (const void *)got);
			a2x_split_enable = 0;
			return;
		}
	}
	a2x_split_romut = (void (*)(uint16_t, void *, vm_offset_t, const void *, vm_size_t))(uintptr_t)(A2X_VMADDR_ROMUT_272 + slide);
	a2x_split_mtx = lck_mtx_alloc_init(lck_grp_alloc_init("a2x-split", LCK_GRP_ATTR_NULL), LCK_ATTR_NULL);
	if (a2x_split_mtx == NULL) {
		A2X_SLOG("no lock - not installed");
		a2x_split_enable = 0;
		return;
	}
	a2x_cdv_resume_ok = A2X_VMADDR_CDV_OK + slide;      /* the trampoline jumps through these: set first */
	a2x_cdv_resume_bad = A2X_VMADDR_CDV_BAD + slide;

	uint8_t slab[13], s5[5];
	uint64_t tramp = (uint64_t)(uintptr_t)&a2x_cdvtramp;
	int64_t disp = (int64_t)A2X_VMADDR_CDV_SLAB - (int64_t)(A2X_VMADDR_CDV_SITE + 5);
	slab[0] = 0x50;                                     /* pushq %rax */
	slab[1] = 0x48; slab[2] = 0xb8;                     /* movabs $a2x_cdvtramp, %rax */
	for (int i = 0; i < 8; i++) {
		slab[3 + i] = (uint8_t)((tramp >> (8 * i)) & 0xff);
	}
	slab[11] = 0xff; slab[12] = 0xe0;                   /* jmpq *%rax */
	a2x_split_wbytes((volatile uint8_t *)(uintptr_t)(A2X_VMADDR_CDV_SLAB + slide), slab, sizeof(slab));
	s5[0] = 0xe9;                                       /* jmp rel32 -> slab (exactly the 5 replaced bytes) */
	for (int i = 0; i < 4; i++) {
		s5[1 + i] = (uint8_t)(((uint32_t)(int32_t)disp >> (8 * i)) & 0xff);
	}
	a2x_split_wbytes((volatile uint8_t *)(uintptr_t)(A2X_VMADDR_CDV_SITE + slide), s5, sizeof(s5));
	a2x_split_installed = 1;
	A2X_SLOG("validator site installed (shift 14 accepted only while the policy is live); policy registers at arm");
}

/* Called from a2x_arm: userspace time, so this policy comes after AMFI in the MAC list. */
void
a2x_split_arm(void)
{
	if (!a2x_split_installed || !a2x_split_enable) {
		return;
	}
	if (!a2x_split_registered) {
		a2x_split_ops[A2X_MPO_VNODE_CHECK_SIGNATURE] = (const void *)a2x_split_vnode_check_signature;
		int r = mac_policy_register(&a2x_split_conf, &a2x_split_handle, a2x_split_xd);
		A2X_SLOG("mac_policy_register(\"a2x-split\") = %d", r);
		if (r != 0) {
			return;
		}
		a2x_split_registered = 1;
	}
	a2x_split_gate = 1;
}

void
a2x_split_disarm(void)
{
	a2x_split_gate = 0;     /* the validator refuses shift 14 again; the policy keeps refusing what it cannot derive */
}
