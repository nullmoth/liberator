/* * a2x_hook_logic.h - the OS-level exec redirect decision, with no kernel
 * knowledge in it.
 *
 *  UNTESTED. Nothing in this directory has been built, loaded or run.
 *
 *  WHY THIS FILE IS SEPARATE FROM THE KEXT: this is the only part of the
 * hook that can be verified without a machine. It takes a pointer to a
 * kernel `struct image_params` and decides "is this an arm64 executable that
 * should be handed to the host interpreter", then performs the mutation that
 * turns the kernel's own interpreter path on. It touches no kernel function,
 * allocates nothing, blocks nothing, and can therefore be compiled and run in
 * userspace against a synthetic image_params (see --selftest).
 *
 *  THE FIELD OFFSETS ARE THE INTERFACE. The logic reads imgp through byte
 * offsets rather than the struct, so the selftest needs no kernel headers.
 * The kext translation unit static-asserts every one of these against
 * offsetof() on the real <sys/imgact.h>, so a header change fails the BUILD
 * rather than corrupting an exec.
 *
 * Measured on macOS 27.0 (26A5425a), x86_64 kernel xnu-13432.1.9~3
 * RELEASE_X86_64, UUID 87EC2AC1-6A19-371D-BACC-E859DAF34B14:
 *   - offsets hand-derived from the SDK's own
 *     Kernel.framework/Headers/sys/imgact.h
 *   - two of them appear verbatim in the shipping kernel's disassembly of the
 *     grade gate: `movq 0x90(%rbx), %rdx` / `movq 0x98(%rbx), %rcx` are
 *     imgp->ip_arch_offset / ip_arch_size being passed to
 *     validate_potential_simulator_binary, and `movq (%rbx), %rsi` /
 *     `movl 0x18(%rbx), %edx` are ip_user_fname / ip_seg. Independent
 *     witnesses that this layout is the layout this kernel compiled.
 */

#ifndef A2X_HOOK_LOGIC_H
#define A2X_HOOK_LOGIC_H

#include <stdint.h>

/* Offsets into struct image_params, x86_64 LP64. */
#define A2X_IP_USER_FNAME       0x00    /* user_addr_t  */
#define A2X_IP_SEG              0x18    /* int          */
#define A2X_IP_ORIGCPUTYPE      0x38    /* cpu_type_t   */
#define A2X_IP_ORIGCPUSUBTYPE   0x3c    /* cpu_subtype_t */
#define A2X_IP_VDATA            0x40    /* char *       */
#define A2X_IP_FLAGS            0x48    /* int          */
#define A2X_IP_STRINGS          0x70    /* char *       */
#define A2X_IP_STRENDP          0x78    /* char *       */
#define A2X_IP_ARGSPACE         0x88    /* int          */
#define A2X_IP_STRSPACE         0x8c    /* int          */
#define A2X_IP_ARCH_OFFSET      0x90    /* user_size_t  */
#define A2X_IP_ARCH_SIZE        0x98    /* user_size_t  */
#define A2X_IP_INTERP_BUFFER    0xa0    /* char[IMG_SHSIZE] */
#define A2X_IP_INTERP_SUGID_FD  0x2a0   /* int          */

/* From <sys/imgact.h> - IMG_SHSIZE is the interpreter line budget. */
#define A2X_IMG_SHSIZE          512
#define A2X_IMGPF_INTERPRET     0x00000001

/* *  EXECUTABLE_KEY is kern_exec.c:476 - "executable_path=". exec_save_path()
 * writes the key at imgp->ip_strings and the path at
 * ip_strings + strlen(key), and hands *that* address back to
 * exec_activate_image as `excpath`. The -3 relookup does
 *   NDINIT(ndp, LOOKUP, ..., CAST_USER_ADDR_T(excpath), ...)
 * with the excpath pointer it captured BEFORE the activator ran, so the only
 * way to redirect the relookup is to rewrite the bytes at that exact address.
 *  Get the key length wrong and the kernel re-looks-up the ORIGINAL path,
 * which re-enters the hook, which hits EAI_ITERLIMIT (3) and returns
 * EBADEXEC - a different error that looks like a different bug.
 */
#define A2X_EXECUTABLE_KEY      "executable_path="
#define A2X_EXECUTABLE_KEY_LEN  16      /* strlen, no NUL */

/* Mach-O constants (mach-o/loader.h, machine.h) - spelled out so the
 * selftest needs no SDK headers either. */
#define A2X_MH_MAGIC_64         0xfeedfacfu
#define A2X_MH_CIGAM_64         0xcffaedfeu
#define A2X_MH_MAGIC            0xfeedfaceu
#define A2X_MH_CIGAM            0xcefaedfeu
#define A2X_FAT_MAGIC           0xcafebabeu
#define A2X_MH_EXECUTE          0x2u
#define A2X_CPU_TYPE_ARM64      0x0100000c
#define A2X_CPU_TYPE_ARM64_32   0x0200000c
#define A2X_CPU_TYPE_ARM        0x0000000c
#define A2X_CPU_TYPE_X86_64     0x01000007

/* * The host that does the interpreting.  ONE fixed x86_64 binary for every
 * app; this string is the whole "registration" the OS needs.
 *
 *  IT MUST BE A THIN x86_64 MACH-O, NOT A FAT ONE. Measured reason:
 * kern_exec.c:339 `#define EAI_ITERLIMIT 3` bounds the activator loop, and
 * `if (++itercount > EAI_ITERLIMIT)` returns EBADEXEC. A fat arm64 guest
 * already spends pass 1 (fat) and pass 2 (mach-o -> our -3); the host is
 * pass 3. A fat host would need pass 3 (its fat header) and pass 4 (its
 * mach-o) and the exec fails with EBADEXEC on exactly the binaries a fat
 * guest covers.
 */
#define A2X_HOST_PATH           "/usr/libexec/a2x/a2xhost"
/* * Two entry programs. xpcproxy is handed to the interpreter itself, which runs it without a second exec so the
 * service keeps the identity launchd gave it. Every other program is handed to the small launcher, which execs
 * the right interpreter within a millisecond: a process the system manages (a widget extension) is suspended a
 * few milliseconds after it starts unless it has already been replaced by then, and the interpreter's own
 * start-up takes longer than that.
 */
#define A2X_LAUNCH_PATH         "/usr/libexec/a2x/a2xlaunch"
#define A2X_XPCPROXY_PATH       "/usr/libexec/xpcproxy"

/* Return values of a2x_exec_decide(). */
#define A2X_NOT_OURS            0       /* leave the kernel's error alone */
#define A2X_CLAIMED             1       /* imgp rewritten; caller returns -3 */

/* * a2x_exec_decide - called from the patched grade gate with the live imgp.
 *
 * Returns A2X_CLAIMED after rewriting imgp into the kernel's interpreter
 * form, or A2X_NOT_OURS having touched nothing.
 *
 *  Runs in the exec path on the calling thread with the process in
 * transition. It must not block, allocate, take a lock or touch a vnode.
 */
int a2x_exec_decide(void *imgp);

/* The kill switch the kext's sysctl drives. 0 = claim nothing. */
extern volatile int a2x_hook_enabled;

/* Counters, for the sysctls that TEST.md reads. Monotonic, never reset. */
struct a2x_hook_stats {
	uint64_t seen;          /* times the gate called us */
	uint64_t claimed;       /* redirected to the host */
	uint64_t not_mach;      /* not a 64-bit Mach-O executable */
	uint64_t not_arm64;     /* a Mach-O, but not CPU_TYPE_ARM64 */
	uint64_t no_fname;      /* no ip_user_fname to hand the host */
	uint64_t already;       /* IMGPF_INTERPRET already set */
	uint64_t disabled;      /* hook off */
};
extern struct a2x_hook_stats a2x_hook_stats;

#endif /* A2X_HOOK_LOGIC_H */
