/* * a2x_ident.cpp - the Apple board identity of this machine.
 *
 * Apple silicon Macs carry their board name in the device tree root as "target-type" (J775d) and
 * "target-sub-type" (J775dAP). Software Update asks Apple for updates by that name; with none, Apple offers
 * nothing. The name is given by the boot argument a2xtarget=<board>AP and published here once, at start.
 * Without the argument nothing is changed.
 */
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOLib.h>
#include <pexpert/pexpert.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <i386/cpuid.h>

extern "C" int a2x_ident_start(void);

/* hw.target: the kernel answers it from a platform call that an Intel platform expert leaves empty, and the
 * system's own identity library reads the board name from this sysctl. The answer becomes the published name. */
static char a2x_target_name[32];

static int
a2x_hw_target(__unused struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	if (req->newptr != USER_ADDR_NULL)
		return EPERM;
	return SYSCTL_OUT(req, a2x_target_name, strlen(a2x_target_name) + 1);
}

/* The kernel's own hw.target entry is constant data. An entry registered later under the same name is found
 * first by a lookup by name, which is how the identity library asks. The hw node is found by walking the root
 * list (entries added at run time, then, behind the anchor entry, the kernel's own), because its list is not a
 * symbol a driver can link against. */
#define A2X_OID_ANCHOR ((int)0x80000000)

static struct sysctl_oid a2x_hw_target_oid = {
	.oid_parent = NULL,
	.oid_link = { NULL },
	.oid_number = OID_AUTO,
	.oid_kind = (int)(CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_KERN | CTLFLAG_OID2),
	.oid_arg1 = NULL,
	.oid_arg2 = 0,
	.oid_name = "target",
	.oid_handler = a2x_hw_target,
	.oid_fmt = "A",
	.oid_descr = "board name",
	.oid_version = SYSCTL_OID_VERSION,
	.oid_refcnt = 0,
};

static struct sysctl_oid *
a2x_find_oid(struct sysctl_oid_list *list, const char *name)
{
	struct sysctl_oid *o = SLIST_FIRST(list), *rest = NULL;
	int n = 0;

	for (int pass = 0; pass < 2; pass++) {
		for (; o && n < 4096; o = SLIST_NEXT(o, oid_link), n++) {
			if (o->oid_number == A2X_OID_ANCHOR) {
				rest = o->oid_arg1 ? *(struct sysctl_oid **)o->oid_arg1 : NULL;
				continue;
			}
			if (o->oid_name && strcmp(o->oid_name, name) == 0)
				return o;
		}
		o = rest; rest = NULL;
	}
	return NULL;
}

static struct sysctl_oid_list *
a2x_find_hw(void)
{
	struct sysctl_oid *o = a2x_find_oid(&sysctl__children, "hw");

	return (o && (o->oid_kind & CTLTYPE) == CTLTYPE_NODE) ? (struct sysctl_oid_list *)o->oid_arg1 : NULL;
}

/* Test rigs only (boot argument a2xnovmm=1): a virtual machine tells Apple's update service it is one, and the
 * service then asks for updates under a name Apple has none for. With the argument, kern.hv_vmm_present reads 0
 * so a virtual test machine asks the way real hardware does. Real hardware never needs it. */
static void
a2x_hide_vmm(void)
{
	unsigned int on = 0;

	if (!PE_parse_boot_argn("a2xnovmm", &on, sizeof on) || on != 1)
		return;
	/* The kernel answers from its cached processor features. Start-up timing was settled with the hypervisor
	 * visible; only the cached bit is cleared, afterwards. */
	i386_cpu_info_t *ci = cpuid_info();
	if (ci && (ci->cpuid_features & CPUID_FEATURE_VMM)) {
		ci->cpuid_features &= ~CPUID_FEATURE_VMM;
		IOLog("a2x-ident: test rig, hypervisor flag hidden\n");
	} else {
		IOLog("a2x-ident: a2xnovmm given, no hypervisor flag\n");
	}
}

static int
a2x_take_hw_target(void)
{
	struct sysctl_oid_list *hw = a2x_find_hw();

	if (!hw)
		return 0;
	a2x_hw_target_oid.oid_parent = hw;
	sysctl_register_oid(&a2x_hw_target_oid);
	return 1;
}

/* a2x.board_id: the board name Software Update reports for this machine. On an Intel kernel the update service
 * reads it from the "board-id" property of the platform device, which the firmware tables fill with the name the
 * boot loader was given. Root writes the Apple board name here once the system is up, so the drivers that chose
 * their settings from the firmware's name at start keep them. Reading returns the name last written, or nothing. */
extern "C" { extern struct sysctl_oid_list sysctl__a2x_children; }
static char a2x_board_name[16];

static int
a2x_board_id(struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	char t[16];
	int e;

	(void)oidp;
	if (req->newptr == USER_ADDR_NULL)
		return SYSCTL_OUT(req, a2x_board_name, strlen(a2x_board_name) + 1);
	if (req->newlen < 3 || req->newlen >= sizeof t)
		return EINVAL;
	memset(t, 0, sizeof t);
	e = SYSCTL_IN(req, t, req->newlen);
	if (e)
		return e;
	t[sizeof t - 1] = 0;
	size_t n = strlen(t);
	if (n < 3 || n > 15)
		return EINVAL;
	for (size_t i = 0; i < n; i++) {
		char c = t[i];
		if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-'))
			return EINVAL;
	}
	IORegistryEntry *root = IORegistryEntry::fromPath("/", gIODTPlane);
	if (!root)
		return ENOENT;
	root->setProperty("board-id", (void *)t, (unsigned int)(n + 1));
	root->release();
	strlcpy(a2x_board_name, t, sizeof a2x_board_name);
	IOLog("a2x-ident: board-id set to %s\n", t);
	return 0;
}

static struct sysctl_oid a2x_board_id_oid = {
	.oid_parent = &sysctl__a2x_children,
	.oid_link = { NULL },
	.oid_number = OID_AUTO,
	.oid_kind = (int)(CTLTYPE_STRING | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_OID2),
	.oid_arg1 = NULL,
	.oid_arg2 = 0,
	.oid_name = "board_id",
	.oid_handler = a2x_board_id,
	.oid_fmt = "A",
	.oid_descr = "board name reported to Software Update",
	.oid_version = SYSCTL_OID_VERSION,
	.oid_refcnt = 0,
};

extern "C" int
a2x_ident_start(void)
{
	char t[32];

	sysctl_register_oid(&a2x_board_id_oid);
	a2x_hide_vmm();
	memset(t, 0, sizeof t);
	if (!PE_parse_boot_argn("a2xtarget", t, sizeof t) || t[0] == 0)
		return 0;
	t[sizeof t - 1] = 0;
	size_t n = strlen(t);
	/* board names are short and plain: letters and digits only */
	if (n < 3 || n > 15) { IOLog("a2x-ident: a2xtarget ignored (length)\n"); return -1; }
	for (size_t i = 0; i < n; i++) {
		char c = t[i];
		if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
			IOLog("a2x-ident: a2xtarget ignored (character)\n"); return -1;
		}
	}
	IORegistryEntry *root = IORegistryEntry::fromPath("/", gIODTPlane);
	if (!root) { IOLog("a2x-ident: no device tree root\n"); return -1; }
	root->setProperty("target-sub-type", (void *)t, (unsigned int)(n + 1));
	strlcpy(a2x_target_name, t, sizeof a2x_target_name);
	int took = a2x_take_hw_target();
	if (t[n - 2] == 'A' && t[n - 1] == 'P') { t[n - 2] = 0; n -= 2; }
	root->setProperty("target-type", (void *)t, (unsigned int)(n + 1));
	root->release();
	IOLog("a2x-ident: board %s, hw.target %s\n", t, took ? "answered" : "not found");
	return 1;
}
