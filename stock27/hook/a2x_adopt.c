/* * a2x_adopt.c - the interpreted process adopts the GUEST's code signature, so
 * its entitlements are the app's and not the host interpreter's.
 *
 *  UNTESTED ON A LIVE KERNEL at the time of writing. Every sentence about
 * behaviour on a machine is a prediction until the arms below are run.
 *
 *  THE PROBLEM, MEASURED 10-28 ON THE VM. An app launched through the exec
 * hook runs as /usr/libexec/a2x/a2xhost-{mac,cat}, so the process image is the
 * host and its code signature is the host's - ad-hoc, no entitlements:
 *
 *   codesign -d --entitlements - +<pid of a running TextEdit>
 *       -> Executable=/usr/libexec/a2x/a2xhost-mac      (and no entitlement dict)
 *   codesign -d --entitlements - /System/Applications/TextEdit.app/...
 *       -> TextEdit's keys
 *
 * Both halves of an entitlement check read the same place, so both are wrong:
 *   - the process asking about itself (SecTask -> csops CS_OPS_ENTITLEMENTS_BLOB)
 *   - a daemon asking about its client by audit token (csops_audittoken)
 * Measured consequences: Journal, Stocks and Freeform trap in CloudKit (3/3
 * runs each), and Screenshot dies with "Underlying connection interrupted".
 * A host copy signed with the guest's own non-security keys removed both, which
 * is what proves the cause - but a copy per entitlement set is a per-app
 * artefact, and there are none of those here.
 *
 *  WHAT THE KERNEL ACTUALLY READS, from the 26A5425a kernel's own
 * disassembly (not from headers - there is no KDK on the build machine):
 *
 *   _csproc_get_blob        ffffff80007b42d0
 *     ffffff80007b4300  movq 0x5d8(%rbx), %rdi      ; proc->p_textvp
 *     ffffff80007b4307  movq 0x5e0(%rbx), %rcx      ; proc->p_textoff
 *     ffffff80007b430e  movl $-1, %esi / %edx       ; cputype/subtype = any
 *     ffffff80007b431e  jmp  _ubc_cs_blob_get
 *   _cs_entitlements_blob_get   ffffff80007b4f60
 *     ffffff80007b4f7c  testl $0x20000000, %eax     ; CS_SIGNED, else no blob
 *     ffffff80007b4f83  movq 0x5d8(%r12), %rdi      ; the same two fields
 *     ffffff80007b4fb0  callq _ubc_cs_blob_get
 *     ffffff80007b4fcb  jmp  _csblob_get_entitlements
 *   and _csops calls _csproc_get_blob at ffffff80007f2c60 and ffffff80007f2dc6.
 *
 * So ONE pair of fields decides every entitlement answer about a process, and
 * pointing them at the guest's vnode is the whole fix. It also makes
 * proc_pidpath report the app, which is why a crash report then names the app.
 *
 *  WHY THIS IS A SYSCTL AND NOT A SECOND CODE PATCH. The first design put a
 * second trampoline on the exec setter so the swap happened inside exec. It is
 * not needed: p_textvp is written once at exec and read later, so the host can
 * do the swap on ITSELF, from an ordinary syscall, where blocking and
 * allocation are legal. That removes a second patched call site, the
 * imgp-keyed pending table, and every refcount question about an exec that
 * fails after the hook ran.  It also removes the need to call
 * ubc_cs_blob_add from the kext: the host registers the guest's signature with
 * fcntl(F_ADDFILESIGS_RETURN), which is dyld's own public route, so every
 * kernel function this file calls is a KPI.
 *
 *  THE SEQUENCE IS THE KERNEL'S OWN, copied from the setter at
 * ffffff80007db330 so the reference counting cannot disagree with it:
 *     ffffff80007db34e  movq 0x5d8(%rdi), %rax      ; save the old vnode
 *     ffffff80007db367  callq _vnode_ref_ext        ; (vp, 0, 0) == vnode_ref
 *     ffffff80007db36f  leaq 0x50(%r14), %r13       ;  proc + 0x50 IS the
 *     ffffff80007db376  callq _lck_mtx_lock         ;    proc mutex - measured
 *     ffffff80007db38b  movq %r15, 0x5d8(%r14)      ; store under the lock
 *     ffffff80007db392  movq %rbx, 0x5e0(%r14)
 *     ffffff80007db3a0  callq _lck_mtx_unlock
 *     ffffff80007db3aa  (release the old vnode, outside the lock)
 * Ledger: vnode_ref(guest) +1, vnode_rele(host) -1, and proc exit's existing
 * vnode_rele(p_textvp) now releases the guest. Balanced, with no leak and no
 * double release.
 *
 *  THE OFFSET IS NOT TRUSTED - IT IS PROVEN ON EVERY CALL. Before it writes
 * anything, this reads proc+0x5d8 and requires it to equal the vnode of the
 * host binary the caller is actually running. A wrong offset would have to
 * hold, by coincidence, a pointer equal to that vnode. The same check is the
 * authorization check: only a process whose image IS an a2x host can adopt.
 *
 *  RESIDUAL, SAID OUT LOUD: an interpreted process can name any arm64 Mach-O
 * as its guest, so it can adopt that binary's entitlements. On this VM that
 * crosses no boundary - it boots with amfi_get_out_of_my_way=1 and
 * cs_enforcement_disable=1, so entitlements are already not a privilege
 * barrier here. To close it, record the claimed guest path per-proc in
 * a2x_exec_decide and require a match. NOT done; this is the note that says
 * why, rather than a silence that looks like the question was never asked.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/kernel_types.h>
#include <kern/locks.h>
#include <libkern/libkern.h>

#include "a2x_hook_logic.h"

/* The a2x node itself is created by SYSCTL_NODE in a2x_hook_kext.c, so this
 * translation unit only has a forward reference to its children list. Without
 * this the build fails with "use of undeclared identifier
 * sysctl__a2x_children" once per sysctl below - measured, 8 of them. */
/* ITS OWN NODE, AND ITS OWN KEXT — MEASURED 10-28. The exec hook already owns the `a2x` node, and
      it lives in a kernel COLLECTION: `kmutil showloaded` reported the same UUID, index and address
      before and after a reboot, and `kmutil unload` answered "kext is in use or retained". So the hook
      cannot be unloaded or replaced without rebuilding that collection, and a second bundle carrying
      the same identifier can never load. Rebuilding the collection on this OpenCore + spoofed-SMBIOS
      install risks the BOOT, which is not a trade worth making for a module that patches nothing.
    So this ships separately. It touches no kernel bytes - it only needs somewhere to publish its
      sysctls - which is exactly what makes a second kext the cheap answer: it loads beside the hook,
      unloads on its own, and its failure costs nothing but the entitlement answer. */
SYSCTL_NODE(, OID_AUTO, a2xa, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "arm2x86 signature adoption");

/* Measured on kernel 87EC2AC1-6A19-371D-BACC-E859DAF34B14 (26A5425a,
 * xnu-13432.1.9~3/RELEASE_X86_64); see the disassembly in the header comment.
 * struct proc is opaque to a kext, so these are byte offsets and every one of
 * them is checked against the live process before use. */
#define A2X_OFF_PROC_TEXTVP     0x5d8   /* vnode_t  p_textvp  */
#define A2X_OFF_PROC_TEXTOFF    0x5e0   /* off_t    p_textoff */
#define A2X_OFF_PROC_MLOCK      0x50    /* the proc mutex     */
#define A2X_OFF_PROC_COMM       0x5fc   /* char p_comm[17]: proc_best_name, 26B123: lea 0x5fc(%rdi) */
#define A2X_OFF_PROC_NAME       0x60d   /* char p_name[33]: proc_best_name, 26B123: cmpb $0,0x60d(%rdi) */
#define A2X_MAXCOMLEN           16

/* The short process name. exec sets p_comm from the file it ran, which for an interpreted program is the host, so
 * ps, launchctl procinfo "comm name", sysctl KERN_PROC and everything else that reads p_comm saw "a2xhost-mac".
 * p_name already holds the guest's own name, so once the guest's signature is in place the short name is cut from
 * it, as exec does: the first 16 bytes, always terminated. */
static void a2x_comm_from_name(proc_t p) {
	char *comm = (char *)p + A2X_OFF_PROC_COMM;
	const char *name = (const char *)p + A2X_OFF_PROC_NAME;
	if (name[0] == 0) return;
	lck_mtx_lock((lck_mtx_t *)((char *)p + A2X_OFF_PROC_MLOCK));
	int i = 0;
	for (; i < A2X_MAXCOMLEN && name[i]; i++) comm[i] = name[i];
	comm[i] = 0;
	lck_mtx_unlock((lck_mtx_t *)((char *)p + A2X_OFF_PROC_MLOCK));
}

/* The three binaries a claimed exec can be running. a2xhost is the
 * dispatcher; it execs one of the other two, so a process that has already
 * reached the interpreter is -mac or -cat. All three are accepted because the
 * dispatcher could, in principle, adopt before exec'ing. */
static const char *const a2x_host_paths[] = {
	"/usr/libexec/a2x/a2xhost-mac",
	"/usr/libexec/a2x/a2xhost-cat",
	"/usr/libexec/a2x/a2xhost",
};

int a2x_adopt_enable = 0;               /* default OFF; a reboot comes back off */

struct a2x_adopt_stats {
	uint64_t adopted;       /* p_textvp now names the guest */
	uint64_t refused_off;   /* p_textvp was not a host binary: offset or caller wrong */
	uint64_t refused_arg;   /* unusable path or offset from userspace */
	uint64_t refused_look;  /* the guest path did not resolve */
	uint64_t refused_macho; /* not an arm64 Mach-O at that offset */
	uint64_t refused_noblob;/* no code signature registered at (guest, offset) */
	uint64_t disabled;      /* adopt_enable was 0 */
	uint64_t adopted_fat;   /* FAT routes: p_textoff moved to the file's own arm64 slice */
	uint64_t refused_fat;   /* FAT route refused: not root-owned or group/other-writable */
	uint64_t cdfixed;       /* blob cdhash set to the app's original */
	uint64_t cdfix_refused; /* kernel bytes did not match 26A5425a: nothing written */
};
static struct a2x_adopt_stats a2x_adopt_stats;

/* ubc_cs_blob_get: exported T symbol in 26A5425a (nm, ffffff8000846060). It is
 * the exact lookup csproc_get_blob / cs_entitlements_blob_get make, with
 * cputype/subtype -1 (any) and offset = p_textoff. */
extern void *ubc_cs_blob_get(vnode_t vp, int cputype, int cpusubtype, off_t offset);

/* B24 THE ORIGINAL CDHASH. The host lowers each CodeDirectory's page size to 4K before F_ADDSIGS, so the
 * kernel stores the cdhash of the REWRITTEN directory. securityd computes the cdhash from the file on disk,
 * sees a mismatch, and retries forever ("cdhash mismatch", -67034): measured 10-30, securityd 499 s CPU since
 * boot in the VM against 16 min in 21.7 days on the laptop. The host sends the original cdhash and this
 * writes it into the blob. Page hashes are untouched and still describe the rewritten directory.
 *  The cs_blob lives in a READ-ONLY zone; a plain store faults. The kernel's own writer is
 *    zalloc_ro_mut(ZONE_ID_CS_BLOB=8, elem, offset, src, size) (ubc_cs_blob_add, 26A5425a). Neither it nor
 *    csblob_get_cdhash is exported, so both are reached by address + slide, and BOTH are checked byte for
 *    byte first. Any mismatch (another kernel build) writes nothing and counts cdfix_refused.
 *  Default OFF (a2xa.adopt_cdfix=0): a wrong zone id panics, and a reboot must come back safe. */
#include "a2x_hook_sites.h"             /* A2X_VMADDR_ANCHOR: the vn_rdwr slide anchor */
#define A2X_VMADDR_ZALLOC_RO_MUT  0xffffff80002f77b0ull  /* nm: t _zalloc_ro_mut */
#define A2X_VMADDR_CSBLOB_CDHASH  0xffffff80007b43a0ull  /* nm: t _csblob_get_cdhash */
#define A2X_ZONE_ID_CS_BLOB       8      /* ubc_cs_blob_add: zalloc_ro(edi=8, ...) */
#define A2X_CSBLOB_CDHASH_OFF     0x58   /* csblob_get_cdhash: lea 0x58(%rdi),%rax */
#define A2X_CDHASH_LEN            20
int a2x_adopt_cdfix = 0;

static int
a2x_bytes_are(const uint8_t *p, const uint8_t *want, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (p[i] != want[i]) {
			return 0;
		}
	}
	return 1;
}

static void
a2x_cdfix(void *blob, const uint8_t cd[A2X_CDHASH_LEN])
{
	/* push rbp; mov rbp,rsp; cmp edi,0xe; jne +0x30 */
	static const uint8_t mut_pro[] = { 0x55, 0x48, 0x89, 0xe5, 0x83, 0xff, 0x0e, 0x75, 0x30 };
	/* push rbp; mov rbp,rsp; lea rax,[rdi+0x58]; pop rbp; ret */
	static const uint8_t cdh_pro[] = { 0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x47, 0x58, 0x5d, 0xc3 };
	uint64_t slide = (uint64_t)(uintptr_t)&vn_rdwr - A2X_VMADDR_ANCHOR;
	const uint8_t *mut = (const uint8_t *)(uintptr_t)(A2X_VMADDR_ZALLOC_RO_MUT + slide);
	const uint8_t *cdh = (const uint8_t *)(uintptr_t)(A2X_VMADDR_CSBLOB_CDHASH + slide);

	if (!a2x_bytes_are(mut, mut_pro, sizeof mut_pro) || !a2x_bytes_are(cdh, cdh_pro, sizeof cdh_pro)) {
		a2x_adopt_stats.cdfix_refused++;
		return;
	}
	const uint8_t *cur = (const uint8_t *)blob + A2X_CSBLOB_CDHASH_OFF;
	if (a2x_bytes_are(cur, cd, A2X_CDHASH_LEN)) {
		a2x_adopt_stats.cdfixed++;      /* an earlier launch already set it */
		return;
	}
	void (*ro_mut)(uint16_t, void *, vm_offset_t, const void *, vm_size_t) =
	    (void (*)(uint16_t, void *, vm_offset_t, const void *, vm_size_t))(uintptr_t)mut;
	ro_mut(A2X_ZONE_ID_CS_BLOB, blob, A2X_CSBLOB_CDHASH_OFF, cd, A2X_CDHASH_LEN);
	a2x_adopt_stats.cdfixed++;
}

static int
a2x_hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

/* *  Is this process running one of the host binaries, and if so what is its
 * text vnode? Returns the vnode p_textvp currently holds on success, with
 * NOTHING referenced: the comparison vnode is looked up and put back here, and
 * the returned pointer is only ever used as the argument to the final
 * vnode_rele, by which time it is still held by p_textvp.
 *
 *  A check that cannot run must refuse, never pass: every failure path here
 * returns NULL and the caller writes nothing.
 */
/* *  A FAT route may take the signature of its OWN file's arm64 slice. The file is the one the process is already
 * running, so the only thing that changes is which slice's signature the kernel reports.  Only for files root owns
 * and nobody else can write: otherwise anyone could staple Apple's arm64e slice next to their own x86_64 code and
 * read as Apple.
 */
static int
a2x_fat_file_ok(vnode_t vp)
{
	struct vnode_attr va;
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	VATTR_WANTED(&va, va_mode);
	if (vnode_getattr(vp, &va, vfs_context_current()) != 0) {
		return 0;
	}
	if (!VATTR_IS_SUPPORTED(&va, va_uid) || !VATTR_IS_SUPPORTED(&va, va_mode)) {
		return 0;
	}
	/* S_IWGRP/S_IWOTH are not declared by these kernel headers; the POSIX values are fixed by the standard. */
	const mode_t a2x_w_group_other = 0020 | 0002;
	return va.va_uid == 0 && (va.va_mode & a2x_w_group_other) == 0;
}

static vnode_t
a2x_proc_host_textvp(proc_t p)
{
	vnode_t cur = *(vnode_t *)((char *)p + A2X_OFF_PROC_TEXTVP);

	if (cur == NULL) {
		return NULL;
	}
	for (size_t i = 0; i < sizeof(a2x_host_paths) / sizeof(a2x_host_paths[0]); i++) {
		vnode_t hv = NULLVP;

		if (vnode_lookup(a2x_host_paths[i], 0, &hv, vfs_context_current()) != 0) {
			continue;               /* that host is not installed; try the next */
		}
		/* vnode identity is the pointer: one vnode per file while it is in
		 * core, and p_textvp holds a usecount on it, so it cannot have been
		 * reclaimed and re-used for another file under us. */
		int same = (hv == cur);
		vnode_put(hv);              /* drop the lookup's iocount at once */
		if (same) {
			return cur;
		}
	}
	return NULL;
}

/* *  Read the Mach-O header at the given offset and require a 64-bit arm64
 * image. This is the one place the kext looks inside the guest, and it is a
 * cheap refusal for a path or offset that does not describe what the caller
 * claims. Runs in a syscall context, so vn_rdwr may block.
 */
static int
a2x_guest_is_arm64(vnode_t gvp, off_t off)
{
	uint32_t hdr[2] = { 0, 0 };
	int resid = 0;

	/* current_proc() rather than vfs_context_proc(): one fewer KPI to be
	 * wrong about, and it is the same process either way - this only ever runs
	 * in the calling host's own syscall context. */
	if (vn_rdwr(UIO_READ, gvp, (caddr_t)hdr, (int)sizeof(hdr), off,
	    UIO_SYSSPACE, IO_NODELOCKED, vfs_context_ucred(vfs_context_current()),
	    &resid, current_proc()) != 0) {
		return 0;
	}
	if (resid != 0) {
		return 0;
	}
	if (hdr[0] != A2X_MH_MAGIC_64) {
		return 0;
	}
	return hdr[1] == (uint32_t)A2X_CPU_TYPE_ARM64;
}

/* * a2x.adopt - the host writes "<guest path>:<slice offset>" and the calling
 * process's text vnode becomes the guest's.
 *
 *  The pair of stores is NOT made atomic, and does not need to be: a reader
 * that catches it half-done asks ubc_cs_blob_get for a blob at an offset that
 * has none, gets NULL, and sees a process with no entitlements - which is
 * exactly what every reader saw before this file existed. The window is two
 * instructions wide and degrades to the old behaviour, so there is nothing to
 * serialize against.
 */
static int
a2x_sysctl_adopt(struct sysctl_oid *oidp __unused, void *arg1 __unused,
    int arg2 __unused, struct sysctl_req *req)
{
	char buf[MAXPATHLEN + 32];
	char *colon = NULL;
	off_t off = 0;
	vnode_t gvp = NULLVP, oldvp = NULLVP;
	proc_t p = current_proc();
	size_t len;
	int error;

	if (req->newptr == 0) {
		return 0;                       /* a read says nothing; the counters do */
	}
	if (!a2x_adopt_enable) {
		a2x_adopt_stats.disabled++;
		return EPERM;
	}
	len = req->newlen;
	if (len == 0 || len >= sizeof(buf)) {
		a2x_adopt_stats.refused_arg++;
		return EINVAL;
	}
	error = SYSCTL_IN(req, buf, len);
	if (error) {
		return error;
	}
	buf[len] = '\0';

	/* B24 optional "cd=<40 lowercase hex>;" prefix: the guest's original cdhash. A path always starts
	 * with '/', so the prefix cannot be mistaken for one. Malformed = refused, never half-parsed. */
	uint8_t cdorig[A2X_CDHASH_LEN];
	int have_cd = 0;
	if (len > 3 && buf[0] == 'c' && buf[1] == 'd' && buf[2] == '=') {
		if (len < 3 + 2 * A2X_CDHASH_LEN + 2 || buf[3 + 2 * A2X_CDHASH_LEN] != ';') {
			a2x_adopt_stats.refused_arg++;
			return EINVAL;
		}
		for (int i = 0; i < A2X_CDHASH_LEN; i++) {
			int hi = a2x_hexval(buf[3 + 2 * i]), lo = a2x_hexval(buf[4 + 2 * i]);
			if (hi < 0 || lo < 0) {
				a2x_adopt_stats.refused_arg++;
				return EINVAL;
			}
			cdorig[i] = (uint8_t)(hi << 4 | lo);
		}
		size_t skip = 3 + 2 * A2X_CDHASH_LEN + 1;
		for (size_t i = skip; i <= len; i++) {  /* byte loop: -fno-builtin, and includes the NUL */
			buf[i - skip] = buf[i];
		}
		len -= skip;
		have_cd = 1;
	}

	/* "<path>:<decimal offset>"; the offset is the arm64 slice's start in a fat
	 * file, 0 for a thin one, and must be the same number the host passed to
	 * fcntl(F_ADDFILESIGS_RETURN) or the blob will not be found. */
	/* The scan is by hand, not strrchr: the kernel's string set is not the
	 * same as libc's, and the build must not depend on which of them this SDK
	 * happens to declare. Last colon wins, so a path may contain one. */
	for (size_t i = len; i > 0; i--) {
		if (buf[i - 1] == ':') {
			colon = &buf[i - 1];
			break;
		}
	}
	if (colon == NULL || colon == buf) {
		a2x_adopt_stats.refused_arg++;
		return EINVAL;
	}
	*colon = '\0';
	for (const char *d = colon + 1; *d != '\0'; d++) {
		if (*d < '0' || *d > '9') {
			a2x_adopt_stats.refused_arg++;
			return EINVAL;
		}
		off = off * 10 + (*d - '0');
		if (off > (off_t)1 << 40) {         /* nothing legitimate is this far in */
			a2x_adopt_stats.refused_arg++;
			return EINVAL;
		}
	}
	if (buf[0] != '/') {
		a2x_adopt_stats.refused_arg++;
		return EINVAL;
	}

	/* THE OFFSET CHECK AND THE PERMISSION CHECK ARE THE SAME CHECK, and it
	 * comes before any write: unless this process is running an a2x host, and
	 * p_textvp is where this kernel keeps that fact, nothing happens. */
	oldvp = a2x_proc_host_textvp(p);
	vnode_t fatvp = NULLVP;         /* set: not a standalone host; may be a FAT route (decided after the lookup) */
	if (oldvp == NULLVP) {
		fatvp = *(vnode_t *)((char *)p + A2X_OFF_PROC_TEXTVP);
		if (fatvp == NULLVP) {
			a2x_adopt_stats.refused_off++;
			return EINVAL;
		}
	}
	if (vnode_lookup(buf, 0, &gvp, vfs_context_current()) != 0) {
		a2x_adopt_stats.refused_look++;
		return ENOENT;
	}
	if (!a2x_guest_is_arm64(gvp, off)) {
		vnode_put(gvp);
		a2x_adopt_stats.refused_macho++;
		return EINVAL;
	}
	/* NEVER SWAP TO A VNODE THAT HAS NO SIGNATURE AT THIS OFFSET. Every reader
	 * (csproc_get_blob, cs_entitlements_blob_get, csops) would get NULL and the
	 * process would read as unsigned with no entitlements - worse than the host's
	 * own blob. The host must have registered the guest's signature (F_ADDSIGS)
	 * BEFORE writing here; this checks that it did, with the kernel's own lookup,
	 * while the lookup's iocount on the guest vnode is still held. */
	void *gblob = ubc_cs_blob_get(gvp, -1, -1, off);
	if (gblob == NULL) {
		vnode_put(gvp);
		a2x_adopt_stats.refused_noblob++;
		return ENOENT;
	}
	if (fatvp != NULLVP) {
		/* The guest must BE the running file; anything else from a non-host is refused exactly as before. */
		if (gvp != fatvp) {
			vnode_put(gvp);
			a2x_adopt_stats.refused_off++;
			return EINVAL;
		}
		if (!a2x_fat_file_ok(gvp)) {
			vnode_put(gvp);
			a2x_adopt_stats.refused_fat++;
			return EPERM;
		}
		lck_mtx_lock((lck_mtx_t *)((char *)p + A2X_OFF_PROC_MLOCK));
		int still = (*(vnode_t *)((char *)p + A2X_OFF_PROC_TEXTVP) == gvp);
		if (still) {
			*(off_t *)((char *)p + A2X_OFF_PROC_TEXTOFF) = off;
		}
		lck_mtx_unlock((lck_mtx_t *)((char *)p + A2X_OFF_PROC_MLOCK));
		vnode_put(gvp);             /* p_textvp keeps its own reference; nothing else was taken */
		if (!still) {
			a2x_adopt_stats.refused_off++;
			return EAGAIN;
		}
		a2x_adopt_stats.adopted_fat++;
		a2x_comm_from_name(p);
		return 0;
	}
	/* B24: while the lookup's iocount still holds the vnode, and so the blob */
	if (have_cd && a2x_adopt_cdfix) {
		a2x_cdfix(gblob, cdorig);
	}
	/* Take the persistent reference p_textvp is going to hold, then give the
	 * lookup's iocount back. vnode_ref is vnode_ref_ext(vp, 0, 0), which is
	 * exactly what the kernel's own setter calls. */
	if (vnode_ref(gvp) != 0) {
		vnode_put(gvp);
		a2x_adopt_stats.refused_look++;
		return EIO;
	}
	vnode_put(gvp);

	/* RE-READ p_textvp UNDER THE LOCK AND REFUSE IF IT MOVED. The host check
	 * above ran unlocked, so in principle another thread of this process could
	 * have exec'd in between, and then the vnode_rele below would release a
	 * reference this process no longer owns - a refcount underflow, which is a
	 * panic later and somewhere else. Re-checking makes the whole class
	 * impossible for the price of one load. */
	lck_mtx_lock((lck_mtx_t *)((char *)p + A2X_OFF_PROC_MLOCK));
	vnode_t now = *(vnode_t *)((char *)p + A2X_OFF_PROC_TEXTVP);
	if (now == oldvp) {
		*(vnode_t *)((char *)p + A2X_OFF_PROC_TEXTVP) = gvp;
		*(off_t *)((char *)p + A2X_OFF_PROC_TEXTOFF) = off;
	}
	lck_mtx_unlock((lck_mtx_t *)((char *)p + A2X_OFF_PROC_MLOCK));
	if (now != oldvp) {
		vnode_rele(gvp);                /* give back the ref nobody took up */
		a2x_adopt_stats.refused_off++;
		return EAGAIN;
	}

	/* Outside the lock, as the kernel does: hand back the reference exec took
	 * on the host binary. p_textvp no longer names it, and proc exit will
	 * release the guest instead. */
	vnode_rele(oldvp);

	a2x_adopt_stats.adopted++;
	a2x_comm_from_name(p);
	return 0;
}

/* CTLFLAG_ANYBODY because the host runs as the app's own uid, never root.
 * It is not a hole on its own: the write only ever changes the CALLING
 * process, and only when that process's image is an a2x host. The gate that
 * makes the feature available at all - a2x.adopt_enable - stays root-only. */
SYSCTL_PROC(_a2xa, OID_AUTO, adopt,
    CTLTYPE_STRING | CTLFLAG_WR | CTLFLAG_ANYBODY | CTLFLAG_LOCKED,
    0, 0, a2x_sysctl_adopt, "A",
    "write \"<guest path>:<slice offset>\" to adopt the guest's code signature");
SYSCTL_INT(_a2xa, OID_AUTO, adopt_enable, CTLFLAG_RW | CTLFLAG_LOCKED,
    &a2x_adopt_enable, 0, "1 allows a host process to adopt its guest's signature");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_adopted, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.adopted, "processes whose text vnode is now the guest");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_adopted_fat, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.adopted_fat, "FAT routes now reporting their own file's arm64 signature");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_refused_fat, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.refused_fat, "FAT route refused: file not root-owned or writable by others");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_refused_off, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.refused_off, "caller was not running an a2x host (or the offset is wrong)");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_refused_arg, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.refused_arg, "unusable path or offset");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_refused_look, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.refused_look, "the guest path did not resolve");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_refused_macho, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.refused_macho, "not an arm64 Mach-O at that offset");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_refused_noblob, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.refused_noblob, "guest has no registered signature at that offset");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_disabled, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.disabled, "writes refused because adopt_enable was 0");
SYSCTL_INT(_a2xa, OID_AUTO, adopt_cdfix, CTLFLAG_RW | CTLFLAG_LOCKED,
    &a2x_adopt_cdfix, 0, "1 sets the adopted blob's cdhash to the app's original (B24)");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_cdfixed, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.cdfixed, "blobs whose cdhash is the app's original");
SYSCTL_QUAD(_a2xa, OID_AUTO, adopt_cdfix_refused, CTLFLAG_RD | CTLFLAG_LOCKED,
    &a2x_adopt_stats.cdfix_refused, "kernel bytes did not match: cdhash left as registered");

struct sysctl_oid *a2x_adopt_oids[] = {
	&sysctl__a2xa_adopt, &sysctl__a2xa_adopt_enable,
	&sysctl__a2xa_adopt_adopted, &sysctl__a2xa_adopt_refused_off,
	&sysctl__a2xa_adopt_refused_arg, &sysctl__a2xa_adopt_refused_look,
	&sysctl__a2xa_adopt_refused_macho, &sysctl__a2xa_adopt_refused_noblob,
	&sysctl__a2xa_adopt_disabled,
	&sysctl__a2xa_adopt_cdfix, &sysctl__a2xa_adopt_cdfixed, &sysctl__a2xa_adopt_cdfix_refused,
};
const size_t a2x_adopt_noids = sizeof(a2x_adopt_oids) / sizeof(a2x_adopt_oids[0]);


/* ─── load / unload ──────────────────────────────────────────────────────────────────────────────
    REGISTER THE NODE BEFORE ITS CHILDREN. A child oid points at the node's children list, so
      registering a child first puts it on a list the kernel has not been told about and the name
      never resolves - which looks exactly like "the module did not load".
    adopt_enable defaults to 0, so a load changes nothing until it is turned on deliberately. */
kern_return_t a2x_adopt_start(kmod_info_t *ki __unused, void *d __unused);
kern_return_t a2x_adopt_stop(kmod_info_t *ki __unused, void *d __unused);

kern_return_t
a2x_adopt_start(kmod_info_t *ki __unused, void *d __unused)
{
	sysctl_register_oid(&sysctl__a2xa);
	for (size_t i = 0; i < a2x_adopt_noids; i++) {
		sysctl_register_oid(a2x_adopt_oids[i]);
	}
	printf("a2x-adopt: loaded, %u oids under a2xa, adopt_enable=%d\n",
	       (unsigned)a2x_adopt_noids, a2x_adopt_enable);
	return KERN_SUCCESS;
}

kern_return_t
a2x_adopt_stop(kmod_info_t *ki __unused, void *d __unused)
{
	for (size_t i = 0; i < a2x_adopt_noids; i++) {
		sysctl_unregister_oid(a2x_adopt_oids[i]);
	}
	sysctl_unregister_oid(&sysctl__a2xa);
	printf("a2x-adopt: unloaded\n");
	return KERN_SUCCESS;
}

/* merged into net.arm2x86.exechook: its start/stop call these; no KMOD decl of its own */
