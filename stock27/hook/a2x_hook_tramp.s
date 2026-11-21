/* * a2x_hook_tramp.s - the branch target of the patched grade gate.
 *
 *  UNTESTED. Never assembled, never executed.
 *
 *  WHAT REACHES HERE: the retargeted `jne` inside exec_mach_imgact, by way
 * of a 13-byte far-jump thunk written over the dead body of _grade_binary.
 * The thunk did `pushq %rax` before `movabs/jmp *%rax`, so the first thing
 * this does is pop it back - after which EVERY general register holds exactly
 * what it held at the original `jne`.
 *
 *  THIS IS A BRANCH TARGET, NOT A FUNCTION. There is no return address on
 * the stack and `ret` must never be executed here. The only ways out are the
 * two indirect jumps at the bottom, back into exec_mach_imgact.
 *
 *  The two register facts this depends on, both read from the disassembly
 * of kernel 87EC2AC1-6A19-371D-BACC-E859DAF34B14 (see a2x_hook_sites.h):
 *     %rbx  == imgp
 *     %r12d == the `error` variable that the epilogue returns
 *  They are properties of ONE compilation. The kext verifies 17 bytes of
 * the gate before it arms, which is what pins the register allocation: the
 * instructions that prove %rbx and %r12d are inside the window it checks.
 *
 *  CALLEE-SAVED REGISTERS ARE LIVE. %rbx, %rbp, %r12, %r13, %r14 and %r15
 * all belong to exec_mach_imgact's frame, so none of them may be used as
 * scratch - which is why the stack alignment below is done through %rax and a
 * saved copy on the stack instead of the usual "stash rsp in a callee-saved
 * register" idiom.
 */

	.text
	.align	4, 0x90
	.globl	_a2x_tramp
_a2x_tramp:
	popq	%rax			/* undo the thunk's push */

	/* Save every register the C ABI lets a callee clobber. */
	pushq	%r11
	pushq	%r10
	pushq	%r9
	pushq	%r8
	pushq	%rdi
	pushq	%rsi
	pushq	%rdx
	pushq	%rcx
	pushq	%rax			/* 9 pushes, 72 bytes */

	/* The incoming alignment is whatever the compiler left; the C ABI
	 * wants %rsp 16-byte aligned at the call. Force it, keeping the old
	 * %rsp in a stack slot because no register is free to hold it. */
	movq	%rsp, %rax
	andq	$-16, %rsp
	pushq	%rax			/* slot 0: old %rsp */
	pushq	%rax			/* slot 1: pad, keeps %rsp 16-aligned */

	movq	%rbx, %rdi		/* imgp */
	callq	_a2x_exec_decide	/* 1 = claimed, 0 = not ours */

	testl	%eax, %eax
	/* Everything from here to the jz must leave the flags alone.
	 * `movq mem,%rsp` and `popq` do not write flags; that is the only
	 * reason the test can be done before the restores. */
	movq	8(%rsp), %rsp		/* back to the unaligned %rsp */
	popq	%rax
	popq	%rcx
	popq	%rdx
	popq	%rsi
	popq	%rdi
	popq	%r8
	popq	%r9
	popq	%r10
	popq	%r11

	jz	La2x_not_ours

	/* Claimed: imgp now describes an interpreter exec. Return -3, the
	 * value exec_activate_image reads as "interpreter: relookup"
	 * (kern_exec.c:2468), through the same variable the original
	 * `movl $0x56, %r12d` used. */
	movl	$-3, %r12d
	jmpq	*_a2x_resume_ok(%rip)

La2x_not_ours:
	/* Not ours: jump to the instruction the original `jne` targeted, so
	 * the kernel's own EBADARCH store runs and the behaviour is bit-for-bit
	 * what it was before the patch. */
	jmpq	*_a2x_resume_bad(%rip)

/* *  11-03: the fat-path trampoline. Reached from the 11-byte site in _fatfile_getbestarch's loop by way of the
 * second slab (pushq %rax; movabs; jmp *%rax). Live registers there: %r13d = this slice's cputype (host order),
 * %r10d = the wanted cputype, %ecx = the family mask, %rdi = this fat_arch (big-endian), %edx = best grade so far.
 * %r12d is scratch (the original sequence writes it too). Exits only by the three indirect jumps.
 */
	.text
	.align	4, 0x90
	.globl	_a2x_fattramp
_a2x_fattramp:
	popq	%rax			/* undo the slab's push */
	movl	%r13d, %r12d		/* the original 11 bytes, replayed */
	xorl	%r10d, %r12d
	testl	%ecx, %r12d
	jne	1f
	jmpq	*_a2x_fat_resume_native(%rip)
1:	cmpl	$0x0100000c, %r13d	/* CPU_TYPE_ARM64 */
	jne	2f
	cmpl	$0, _a2x_fat_gate(%rip)	/* only while the hook is armed */
	je	2f
	movl	4(%rdi), %r12d		/* cpusubtype, big-endian */
	bswapl	%r12d
	andl	$0x00ffffff, %r12d	/* capability bits off */
	cmpl	$2, %r12d		/* CPU_SUBTYPE_ARM64E */
	jne	2f
	lock incq _a2x_fat_graded_count(%rip)
	movl	$1, %r13d		/* grade 1: any x86_64 slice (2/3) still wins */
	jmpq	*_a2x_fat_resume_graded(%rip)
2:	jmpq	*_a2x_fat_resume_skip(%rip)

/* * Filled in by the kext when it arms, from the site table plus the measured
 * slide.  Both are zero until then; the kext never retargets the branch
 * before it has written these, because a jump through a NULL slot panics.
 */
	.data
	.align	3
	.globl	_a2x_resume_ok
_a2x_resume_ok:
	.quad	0
	.globl	_a2x_resume_bad
_a2x_resume_bad:
	.quad	0
	.globl	_a2x_fat_resume_native
_a2x_fat_resume_native:
	.quad	0
	.globl	_a2x_fat_resume_graded
_a2x_fat_resume_graded:
	.quad	0
	.globl	_a2x_fat_resume_skip
_a2x_fat_resume_skip:
	.quad	0

/* * 11-05 27.2: THE CODE-DIRECTORY PAGE SIZE (a2x_split.c). cs_validate_codedirectory accepts pageSize 12 only;
 * its 5 bytes (cmpl $0xc,%eax; jne bad) are replaced by a jmp to the slab, which jumps here. Shift 14 passes
 * only while the a2x-split policy is live - that policy refuses any 16K blob it cannot verify and re-derive.
 */
	.text
	.align	4, 0x90
	.globl	_a2x_cdvtramp
_a2x_cdvtramp:
	popq	%rax			/* undo the slab's push: %eax is cd->pageSize again */
	cmpl	$0xc, %eax		/* the original 5 bytes, replayed */
	je	1f
	cmpl	$0xe, %eax
	jne	2f
	cmpl	$0, _a2x_split_gate(%rip)
	je	2f
	lock incq _a2x_cdv_allowed(%rip)
1:	jmpq	*_a2x_cdv_resume_ok(%rip)
2:	jmpq	*_a2x_cdv_resume_bad(%rip)

	.data
	.align	3
	.globl	_a2x_cdv_resume_ok
_a2x_cdv_resume_ok:
	.quad	0
	.globl	_a2x_cdv_resume_bad
_a2x_cdv_resume_bad:
	.quad	0
	.globl	_a2x_cdv_allowed
_a2x_cdv_allowed:
	.quad	0
	.globl	_a2x_split_gate
_a2x_split_gate:
	.long	0
