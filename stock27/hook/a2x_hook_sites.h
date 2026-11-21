/* * a2x_hook_sites.h - the measured patch site, pinned to ONE kernel.
 *
 *  UNTESTED. These numbers were read out of a kernel binary; nothing has
 * been patched with them.
 *
 *  EVERY NUMBER BELOW WAS MEASURED, not derived from source line numbers.
 * The kernel they came from:
 *
 *   file     /System/Library/Kernels/kernel   (Mach-O 64-bit executable x86_64,
 *                                              21,115,728 bytes)
 *   version  Darwin Kernel Version 27.0.0: Tue Aug 11 22:02:19 PDT 2026;
 *            root:xnu-13432.1.9~3/RELEASE_X86_64
 *   build    26A5425a   (macOS 27.0)
 *   LC_UUID  87EC2AC1-6A19-371D-BACC-E859DAF34B14
 *
 *  WHY THE SITE IS AN INLINED COMPARE AND NOT A FUNCTION
 * ---------------------------------------------------------
 * The obvious hook - patch ml_grade_binary() or grade_binary() so arm64
 * grades non-zero - PROVABLY DOES NOTHING on this kernel. Measured:
 *
 *   nm  /System/Library/Kernels/kernel | grep _grade_binary
 *       -> ffffff800087ff70 T _grade_binary          (a real, global symbol)
 *   otool -tV ... | grep -c 'callq.*0xffffff800087ff70'
 *       -> 0                                         (ZERO callers, kernel-wide)
 *
 * LTO inlined grade_binary into every caller and left the standalone body
 * behind as dead code. The copy that actually decides an exec lives inside
 * exec_mach_imgact, which is static and has no symbol. Patching the symbol
 * would report success and change nothing - the exec path never calls it.
 *
 *  HOW THE SITE WAS FOUND, with one hit and no guessing
 * ------------------------------------------------------
 * exec_mach_imgact contains an `#if __x86_64__` branch that logs
 * "Unsupported 32-bit executable: \"%s\"" (kern_exec.c:1427). That cstring
 * exists once in the kernel (__TEXT,__os_log at 0xffffff8000b7df20) and
 * EXACTLY ONE instruction in 2,342,528 disassembled instructions references
 * it: a leaq at 0xffffff80007d1e04. Walking back from there gives the whole
 * gate, and the inlined grade is unmistakable:
 *
 *   ffffff80007d1d5b  cmpl $0x7, %edi            ; CPU_TYPE_I386
 *   ffffff80007d1d5e  je   0xffffff80007d1d9d
 *   ffffff80007d1d60  cmpl $0x1000007, %edi      ; CPU_TYPE_X86_64
 *   ffffff80007d1d66  jne  0xffffff80007d1e1f    ; <-- THE SITE
 *   ...
 *   ffffff80007d1da4  movq 0x90(%rbx), %rdx      ; imgp->ip_arch_offset
 *   ffffff80007d1dab  movq 0x98(%rbx), %rcx      ; imgp->ip_arch_size
 *   ffffff80007d1db5  callq _validate_potential_simulator_binary
 *   ffffff80007d1e17  movl $0x56, %r12d          ; EBADARCH (86) - log path
 *   ffffff80007d1e1f  movl $0x56, %r12d          ; EBADARCH - every other path
 *   ffffff80007d1e25  leaq ___stack_chk_guard(%rip), %rax   ; the epilogue
 *
 *  Two register facts fall out of that listing and the hook depends on both:
 *   %rbx  == imgp   (the 0x90/0x98/0x00/0x18 loads are its fields)
 *   %r12d == error  (the EBADARCH stores, and `movl %r12d,%eax` in the
 *                    epilogue is the function's return value)
 *
 *  THE PATCH IS ONE ALIGNED 4-BYTE STORE
 * -----------------------------------------
 * The site is `jne rel32` = 0f 85 b3 00 00 00. Its displacement field is at
 * 0xffffff80007d1d68, which is 4-byte ALIGNED. So the hook does not rewrite
 * an instruction at all - it retargets a branch by storing one aligned
 * 32-bit word, which is a single atomic store on x86-64. The instruction
 * stays a `jne`, taken under exactly the condition we want ("the cputype is
 * neither i386 nor x86_64"), and it simply lands somewhere else.
 *
 *  A multi-byte rewrite here would be the real hazard: another core can be
 * executing these bytes while we write them, and there is no stop-the-world
 * primitive available to a kext (mp_rendezvous_no_intrs is not a KPI). One
 * aligned word is the smallest possible exposure.  UNCONFIRMED: whether a
 * concurrent core can still mis-speculate the old target - Intel's rules for
 * cross-modifying code ask for a serializing operation on every core, which
 * we cannot force. See ROUTES.md §"what is still unconfirmed".
 *
 *  REACH: a rel32 from the site reaches +/-2 GB, but the kext's own text is
 * at an address we do not control. So the branch is retargeted to a 13-byte
 * far-jump thunk written into the dead body of _grade_binary - 0xae204 bytes
 * away, in the same __text section, so the distance is fixed by the build and
 * cannot go out of range. _grade_binary has zero callers (measured above), is
 * 0x70 bytes to the next symbol, and is restored byte-for-byte on unpatch.
 */

#ifndef A2X_HOOK_SITES_H
#define A2X_HOOK_SITES_H

#include <stdint.h>

#define A2X_SITE_UUID_STR  "037E7B86-0AC8-3C67-AFB8-7C2C86435E9A"   /* 27.2 26B123 */
#define A2X_SITE_KERNVERS   "xnu-13432.41.4~25/RELEASE_X86_64"

/* The anchor: a real KPI symbol in the kernel's __text that the kext links
 * against, so slide = (uintptr_t)&vn_rdwr - A2X_VMADDR_ANCHOR. Any kernel
 * __text address then rebases by the same slide, because a kernel collection
 * relocates the kernel image as a unit.  UNCONFIRMED that the booted
 * collection preserves intra-__text deltas; the kext therefore proves it by
 * comparing the bytes it finds against A2X_BYTES_* before writing anything,
 * and refuses if they differ. */
#define A2X_VMADDR_ANCHOR       0xffffff80004bca20ull   /* nm: T _vn_rdwr */

#define A2X_VMADDR_GATE         0xffffff80007d5eebull   /* inlined grade */
#define A2X_VMADDR_SITE_JNE     0xffffff80007d5ef6ull   /* jne rel32 */
#define A2X_VMADDR_SITE_DISP    0xffffff80007d5ef8ull   /* its rel32, 4-aligned */
#define A2X_VMADDR_RESUME_BAD   0xffffff80007d5fafull   /* movl $0x56,%r12d */
#define A2X_VMADDR_RESUME_OK    0xffffff80007d5fb5ull   /* epilogue */
#define A2X_VMADDR_THUNK        0xffffff80008843a0ull   /* dead _grade_binary */
#define A2X_THUNK_ROOM          0x61                    /* to the next symbol */

/* The original rel32 at A2X_VMADDR_SITE_DISP. Unpatch restores this. */
#define A2X_ORIG_DISP           0x000000b3

/* * Expected bytes.  Every one of these is checked before any write and the
 * kext REFUSES TO ARM on a single mismatch. A check that cannot run must
 * block, never report clean - so "could not read" is also a refusal.
 */
#define A2X_BYTES_GATE \
	{ 0x83, 0xff, 0x07, 0x74, 0x3d, 0x81, 0xff, 0x07, 0x00, 0x00, 0x01, \
	  0x0f, 0x85, 0xb3, 0x00, 0x00, 0x00 }                  /* 17 bytes */
#define A2X_BYTES_SITE_JNE \
	{ 0x0f, 0x85, 0xb3, 0x00, 0x00, 0x00 }                  /* 6 bytes */
#define A2X_BYTES_RESUME_BAD \
	{ 0x41, 0xbc, 0x56, 0x00, 0x00, 0x00 }                  /* 6 bytes */
#define A2X_BYTES_RESUME_OK \
	{ 0x48, 0x8d, 0x05, 0x84, 0x80, 0x6c, 0x00 }            /* 7 bytes */
#define A2X_BYTES_THUNK \
	{ 0x83, 0xff, 0x07, 0x74, 0x3c, 0x55, 0x48, 0x89, 0xe5, \
	  0x81, 0xff, 0x07, 0x00, 0x00, 0x01, 0x75 }            /* 16 bytes */

/* * The thunk we write over _grade_binary:
 *   50                      pushq %rax          ;  so the thunk clobbers
 *   48 b8 <imm64>           movabs $tramp,%rax  ;   nothing at all; the
 *   ff e0                   jmpq  *%rax         ;   trampoline pops it back
 * 13 bytes, in 0x61 of room.
 */
#define A2X_THUNK_LEN           13

/* *  11-03 27.2: THE FAT PATH. _fatfile_getbestarch's inner loop (static, 0x...880940) drops a slice whose cputype
 * family is not the host's at this 11-byte filter, before grading. Replaced by a jmp to the second slab; see
 * a2x_fattramp in a2x_hook_tramp.s. Resume points are the three places the original code goes next.
 */
#define A2X_VMADDR_FAT_SITE     0xffffff80008809e6ull   /* mov r13d,r12d; xor r10d,r12d; test ecx,r12d; jne */
#define A2X_VMADDR_FAT_NATIVE   0xffffff80008809f1ull   /* original fall-through: movl 4(%rdi),%ebx */
#define A2X_VMADDR_FAT_GRADED   0xffffff80008809beull   /* cmpl %edx,%r13d: keep the best grade */
#define A2X_VMADDR_FAT_SKIP     0xffffff80008809d0ull   /* decq %r11: next fat_arch */
#define A2X_VMADDR_FAT_SLAB     0xffffff80008843c0ull   /* dead _grade_binary + 0x20, 13 of the 0x41 left */
#define A2X_FAT_SITE_LEN        11
#define A2X_BYTES_FAT_SITE \
	{ 0x45, 0x89, 0xec, 0x45, 0x31, 0xd4, 0x41, 0x85, 0xcc, 0x75, 0xdf }
#define A2X_BYTES_FAT_NATIVE    { 0x8b, 0x5f, 0x04, 0x21, 0xf3 }
#define A2X_BYTES_FAT_GRADED    { 0x41, 0x39, 0xd5 }
#define A2X_BYTES_FAT_SKIP      { 0x49, 0xff, 0xcb }
#define A2X_BYTES_FAT_SLAB \
	{ 0x83, 0xf8, 0x04, 0x74, 0x2c, 0x83, 0xf8, 0x08, 0x75, 0x33, 0x31, 0xc9, 0x83, 0xfe, 0x03, 0x0f }

#endif /* A2X_HOOK_SITES_H */
