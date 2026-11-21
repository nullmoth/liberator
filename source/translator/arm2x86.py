#!/usr/bin/env python3
"""arm2x86.py — AArch64 -> LLVM IR -> x86_64, for function bodies pulled from the dyld shared cache.

 THE SHAPE: LLVM's MC disassembler is the front half (it already reads arm64e Mach-O),
   LLVM's x86_64 backend is the back half. This file is the ONLY part that is ours: the
   per-instruction semantics. Registers become allocas; mem2reg + regalloc map 31 ARM GPRs
   onto 16 x86 registers for free. That is the standard lifter shape and the least code.

 NEVER emit a silent fallthrough for an instruction we do not implement. An unimplemented
   op that "does nothing" returns a PLAUSIBLE WRONG NUMBER, which is the one failure mode
   this whole project cannot survive. Unknown -> abort loudly, named, at runtime.
"""
import re, sys

M64 = (1 << 64) - 1
#  R12 THE WHOLE AAPCS64 SIGNATURE. x0-x7 in the i64s, v0-v7 in the vectors, and
#    the return is x0 AND v0 because ARM returns floats and vectors in v0.
ABI_RET = '{ i64, <2 x i64> }'

#  R14 A BIND'S ARGUMENT KINDS. 'i' = integer (x0, x1, ...), 'd' = double
#    (d0, d1, ...), 'f' = float. The two sequences are INDEPENDENT on both ABIs, which is
#    the whole reason a count alone cannot describe a bind.
BIND_TY = {'i': 'i64', 'd': 'double', 'f': 'float'}


#  10-05 A NATIVE RETURN NARROWER THAN 32 BITS. Apple arm64 callees extend bool/char/short results to 32 bits and
#    arm64 callers rely on it (`cbz w0` after os_unfair_lock_trylock). x86-64 only defines the low 8/16 bits: measured on
#    studio, os_unfair_lock_trylock on a BUSY lock returns rax=0x100 — `cbz w0` read "acquired" and Red's resource cache
#    (0x103fe5a1c) entered a critical section another thread held. Every such bind is narrowed to its C width, then
#    extended exactly as the arm64 callee would have (zero for bool/unsigned, sign for signed).
NARROW_RET = {'bool': (8, 0), '_Bool': (8, 0), 'Boolean': (8, 0), 'BOOL': (8, 0), 'unsigned char': (8, 0), 'uint8_t': (8, 0),
              'UInt8': (8, 0), 'char': (8, 1), 'signed char': (8, 1), 'int8_t': (8, 1), 'SInt8': (8, 1),
              'unsigned short': (16, 0), 'uint16_t': (16, 0), 'UInt16': (16, 0), 'unichar': (16, 0), 'UniChar': (16, 0),
              'short': (16, 1), 'int16_t': (16, 1), 'SInt16': (16, 1)}
def narrow_ret(b):
    c = (b.get('cret') or '').replace('const ', '').strip()
    return NARROW_RET.get(c) if b.get('ret') == 'i32' else None


def bind_kinds(b):
    """The kinds string for a bind, defaulting to all-integer so nothing existing moves."""
    k = b.get('args') or 'i' * b['argc']
    #  A DISAGREEMENT HERE IS A WRONG-REGISTER READ, so it blocks rather than picking one.
    if len(k) != b['argc']:
        raise NotImplementedError(f'{b["sym"]}: args {k!r} disagrees with argc {b["argc"]}')
    bad = [c for c in k if c not in BIND_TY]
    if bad:
        raise NotImplementedError(f'{b["sym"]}: unknown argument kind(s) {bad} in {k!r}')
    return k


def bind_is_fp(b):
    """True when this bind touches the vector file in either direction."""
    return b['ret'] in ('double', 'float') or any(c != 'i' for c in bind_kinds(b))


def bind_thunk(sym, ret, kinds):
    """ R14 THE INDIRECT ENTRY FOR A FLOATING-POINT BIND.

     The dispatch map calls every entry with the lifted signature. A bare
       `double(double)` in that table is called through the wrong one: it links, and it
       reads its argument from rdi. This thunk has the lifted signature, pulls the FP
       arguments out of q0.. and the integer ones out of a0.., and packs the result back
       into {x0, v0} the way a lifted function does."""
    ps = ', '.join([f'i64 %a{i}' for i in range(8)] + [f'<2 x i64> %q{i}' for i in range(8)])
    pre, call, ni, nf, nstk, sp = [], [], 0, 0, 0, False
    for c in kinds:
        if c == 'i':
            #  10-23 THE NINTH INTEGER ARGUMENT IS ON THE STACK, NOT IN A REGISTER. This thunk has the
            #    LIFTED signature, which declares %a0..%a7 only, so `%a{ni}` past 7 named a value that does
            #    not exist and the whole module died in the verifier: macOS 27's diskimages-helper calls
            #    CFUserNotificationDisplayAlert (double + TEN pointers) and the build stopped with
            #    "use of undefined value '%a8'". AAPCS64 puts integer arguments 9.. at [sp], [sp+8], ...
            if ni >= 8:
                if not sp:
                    pre.append('  %bsp = load i64, ptr @__arm_sp')
                    pre.append('  %bspp = inttoptr i64 %bsp to ptr')
                    sp = True
                pre.append(f'  %bs{nstk}p = getelementptr i64, ptr %bspp, i64 {nstk}')
                pre.append(f'  %bs{nstk} = load i64, ptr %bs{nstk}p')
                call.append(f'i64 %bs{nstk}'); nstk += 1
            else:
                call.append(f'i64 %a{ni}')
            ni += 1
        else:
            #  A FLOATING-POINT ARGUMENT PAST v7 WOULD INTERLEAVE WITH THE INTEGER STACK SLOTS ABOVE, so the
            #    offsets stop being sequential. Nothing in the system needs it yet; block rather than guess,
            #    exactly like bind_kinds() does when args and argc disagree.
            if nf >= 8:
                raise NotImplementedError(f'{sym}: floating-point argument {nf} passes on the stack (past v7)')
            ty, lanes = BIND_TY[c], (2 if c == 'd' else 4)
            pre.append(f'  %fb{nf} = bitcast <2 x i64> %q{nf} to <{lanes} x {ty}>')
            pre.append(f'  %fa{nf} = extractelement <{lanes} x {ty}> %fb{nf}, i32 0')
            call.append(f'{ty} %fa{nf}'); nf += 1
    out = [f'define internal {ABI_RET} @__arm2x86_bindthunk_{sym}({ps}) {{'] + pre
    #  x0 and v0 are BOTH caller-saved on AAPCS64, so the half the callee did not set
    #    gets a deterministic zero. Passing our own stale value back would be the
    #    stale-but-plausible failure that hides itself.
    x0, q0 = 'i64 0', '<2 x i64> zeroinitializer'
    argl = ', '.join(call)
    if ret == 'void':
        out.append(f'  call void @{sym}({argl})')
        if sym == 'bzero':
            # Darwin ARM64 bzero preserves its destination in x0, even though
            # the C declaration is void. Tail callers can return that register.
            x0 = 'i64 %a0'
    else:
        out.append(f'  %r = call {ret} @{sym}({argl})')
        if ret == 'i32':
            out.append('  %rz = zext i32 %r to i64'); x0 = 'i64 %rz'
        elif ret in ('double', 'float'):
            lanes = 2 if ret == 'double' else 4
            out.append(f'  %ri = insertelement <{lanes} x {ret}> zeroinitializer, '
                       f'{ret} %r, i32 0')
            out.append(f'  %rq = bitcast <{lanes} x {ret}> %ri to <2 x i64>')
            q0 = '<2 x i64> %rq'
        else:
            x0 = 'i64 %r'
    out.append(f'  %p0 = insertvalue {ABI_RET} undef, {x0}, 0')
    out.append(f'  %p1 = insertvalue {ABI_RET} %p0, {q0}, 1')
    out.append(f'  ret {ABI_RET} %p1')
    out.append('}')
    return '\n'.join(out)

ABI_PARAMS = ', '.join(['i64 %%a%d' % i for i in range(8)]
                      + ['<2 x i64> %%q%d' % i for i in range(8)])
ABI_DECL = ', '.join(['i64'] * 8 + ['<2 x i64>'] * 8)
M32 = 0xFFFFFFFF

# ── parsing ──────────────────────────────────────────────────────────────────
def imm(tok):
    """ SHIFT AMOUNTS ARE DECIMAL, DATA IMMEDIATES ARE HEX. `lsr #15` is fifteen, not 21.
       Getting this backwards is silent and produces a plausible wrong answer."""
    t = tok.lstrip('#')
    neg = t.startswith('-')
    if neg: t = t[1:]
    v = int(t, 16) if t.lower().startswith('0x') else int(t, 10)
    return (-v if neg else v) & M64

def split_ops(s):
    """Split on ', ' but never inside [] — `ldr x9, [x8, x9, lsl #3]` is 2 operands."""
    out, cur, d = [], '', 0
    for ch in s:
        if ch == '[': d += 1
        elif ch == ']': d -= 1
        if ch == ',' and d == 0:
            out.append(cur.strip()); cur = ''
        else:
            cur += ch
    if cur.strip(): out.append(cur.strip())
    return out

#  R20 THE RAW WORD IS CARRIED NOW. llvm-objdump prints four space-separated byte
#    pairs before the mnemonic unless --no-show-raw-insn is passed, and the AMX family
#    prints as `<unknown>` with NO operands — so without the word there is literally
#    nothing to lift. This regex accepts BOTH forms, so every caller that still passes
#    --no-show-raw-insn keeps working unchanged.
#  THE FORMAT WAS CHECKED AGAINST REAL OUTPUT, NOT ASSUMED. This first said objdump
#    printed four space-separated byte pairs; it prints ONE assembled 8-hex word
#    (`1917d7b08: 00201080 <unknown>`), already in instruction order and needing no
#    byte swap. The wrong regex would have matched nothing, the AMX arm would never have
#    fired, and every selftest written around the wrong shape would still have passed.
#  The raw group is exactly 8 hex digits, which no AArch64 mnemonic can be, so a
#    raw-less line cannot have its mnemonic eaten by the group.
INSN = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})?\s*(\S+)\s*(.*)$')
AMX_PREFIX_MASK, AMX_PREFIX = 0xFFFFF000, 0x00201000


#  R37 APPLE'S OBJDUMP DROPS THE ARRANGEMENT ON THESE BY-ELEMENT FORMS. It prints
#    `sdot v0, v1, v2[0]` for BOTH `sdot v0.2s, v1.8b, v2.4b[0]` and the .4s form; the
#    only record of which one ran is the Q bit (bit 30) of the raw word. Measured on
#    r37/k.o: 0f82e020 (Q=0) and 4fa2e020 (Q=1) disassemble to the same text.
#  WITHOUT RAW BYTES THE SHAPE IS UNKNOWABLE, so the mnemonic stays bare and the
#    instruction aborts as unrouted. Guessing .4s would be silently wrong on every .2s.
BYELEM_Q = {m: ('2s', '4s') for m in ('sdot', 'udot', 'usdot', 'sudot', 'fmlal', 'fmlal2',
                                     'fmlsl', 'fmlsl2', 'bfdot')}


def parse(text):
    insns = []
    for line in text.splitlines():
        line = line.split(';')[0].rstrip()          # drop `; =-65521` comments
        m = INSN.match(line)
        if not m: continue
        addr, raw, mn, rest = int(m.group(1), 16), m.group(2), m.group(3), m.group(4)
        if raw and mn == '<unknown>':
            w = int(raw, 16)                        # already in instruction order
            if (w & AMX_PREFIX_MASK) == AMX_PREFIX:
                #  ONLY the AMX prefix is reclassified. Every other undecodable word
                #    stays `<unknown>`, because R19 needs it in that bucket to recognise
                #    jump-table payload — and a data word must never become an
                #    instruction. Measured split: 398,691 AMX / 186,577 payload.
                insns.append((addr, 'amx', [f'#{(w >> 5) & 0x1F}', f'#{w & 0x1F}']))
                continue
        if raw and mn in BYELEM_Q and '[' in rest:
            mn = f'{mn}.{BYELEM_Q[mn][(int(raw, 16) >> 30) & 1]}'
        insns.append((addr, mn, split_ops(rest)))
    return insns

#  R20 op -> (state global suffix, register count, is_load). MEASURED, see patch_r20.py.
AMX_LDST = {0: ('x', 8, True),  2: ('x', 8, False),
            1: ('y', 8, True),  3: ('y', 8, False),
            4: ('z', 64, True), 5: ('z', 64, False)}
#  BITS 56..63 ARE THE INDEX; EVERYTHING ELSE IS THE ADDRESS, BIT 32 INCLUDED.
#    This used to clear bit 32, citing a measurement that bit 32 "is not load-multiple" —
#    a different claim from "is not an address bit", and the weaker one cannot support the
#    stronger. The original probe could not have found the difference: macOS arm64 user
#    space begins at 0x100000000, so every real pointer already has bit 32 set and OR-ing
#    it in is a no-op that reads exactly like "ignored". Measured in BOTH directions on
#    2026-09-22: a buffer at 0x7543004000 loads correctly as given, and the SAME address
#    with bit 32 cleared takes a Bus error. Masking it off corrupts every AMX transfer
#    whose buffer sits above 4 GB, which on this OS is every buffer.
AMX_ADDR_MASK = 0x00FFFFFFFFFFFFFF

# ── emitter ──────────────────────────────────────────────────────────────────
VARR = {'16b': (16, 8), '8b': (8, 8), '8h': (8, 16), '4h': (4, 16),
        '4s': (4, 32), '2s': (2, 32), '2d': (2, 64), '1d': (1, 64),
        # scalar forms: Apple writes `mov.d v0, v1` / `fcvt.s` — one lane, full width
        'b': (1, 8), 'h': (1, 16), 's': (1, 32), 'd': (1, 64), 'q': (16, 8),
        #  `.1q` is the DESTINATION shape of pmull: one 128-bit lane.
        '1q': (1, 128)}
""" THE ARRANGEMENT IS DATA, NOT AN OPCODE. Apple's disassembly folds the vector shape
   into the mnemonic (`fsub.2d`, `dup.4s`) and that is why a naive count reads 1,087
   distinct NEON 'mnemonics'. Measured on libsystem_m + AccelerateGPU: 219 suffixed forms
   collapse to 102 base ops x 12 arrangements, and 25 base ops cover 90% of NEON volume."""

#  NOT arrangements — these are CONDITION CODES on b.eq / csel.lt and they also contain
#    a '.'. Treating them as vector shapes made a first pass count 22 branch mnemonics as
#    NEON. The suffix alone does not tell you what an instruction is.
CONDS = {'eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl', 'vs', 'vc',
         'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'}

#  THE ARRANGEMENT IS NOT ALWAYS ON THE MNEMONIC. Apple writes `movi.2d v0, #0` but also
#    `movi d0, #0x000000ffffffff` and `shl d6, d5, #0x20` — same instruction class, shape
#    carried by the REGISTER instead. Measured 2026-09-22: 3 of libz's last 5 blocked
#    functions were this one parsing gap, not a missing operation.
VEC_BARE = {'movi', 'mvni', 'mov', 'shl', 'ushr', 'sshr', 'add', 'sub', 'mul',
            'and', 'orr', 'eor', 'not', 'mvn', 'neg', 'abs', 'dup', 'ext',
            'bsl', 'bit', 'bif', 'umin', 'umax', 'smin', 'smax', 'addv', 'addp',
            'fadd', 'fsub', 'fmul', 'fdiv', 'fneg', 'fabs', 'fsqrt', 'fmla', 'fmls',
            'cmeq', 'cmgt', 'cmge', 'cmhi', 'cmhs', 'rev64', 'rev32', 'rev16',
            #  R17-b THE SCALAR SPELLINGS. `sqadd s0, s0, s1` is the SAME
            #    instruction as `sqadd.4s` with one lane, and every one of these
            #    already had a working vector arm — they were in the gap list purely
            #    because a bare `s0` operand never reached neon(). Routing, not
            #    semantics, which is R9's finding wearing its last disguise.
            'sqadd', 'sqsub', 'uqadd', 'uqsub', 'sshl', 'ushl', 'srshr', 'urshr',
            'sqshl', 'uqshl', 'sqshlu', 'srshl', 'urshl', 'sqrshl', 'uqrshl',
            'sqabs', 'sqneg', 'usqadd', 'suqadd', 'uaba', 'saba',
            'fcmgt', 'fcmge', 'fcmeq', 'fcmlt', 'fcmle', 'facgt', 'facge',
            'frecpe', 'frsqrte', 'frecps', 'frsqrts', 'fcvtxn', 'sha1h',
            'fmax', 'fmin', 'fmaxnm', 'fminnm', 'fabd'}
VREG = re.compile(r'^[qdshb]\d+$')
#  DISPATCH ON THE OPERAND, NOT THE MNEMONIC. `mov.s` is a vector move, a lane read,
#    or a lane insert depending only on which register class its tokens name.
GPRT = re.compile(r'^([wx]\d+|wzr|xzr)$')
#  THE LSE ATOMIC FAMILY IS A GRAMMAR, NOT A LIST. `ld<op>{a}{l}{b|h}` — ordering
#    suffix BEFORE size suffix — so one regex covers 80 mnemonics. Measured in the
#    2026-09-22 cache sweep: the acquire/release + atomic families were 76.5% of all
#    whole-function translation failures, `stlr` alone 69.5%.
LSE = re.compile(r'^(ld|st)(add|clr|set|eor|smax|smin|umax|umin)(a?l?)(b|h)?$')
SWP = re.compile(r'^swp(a?l?)(b|h)?$')

#  R17-a VECTOR LENGTH IS A CONSTANT HERE, AND 128 BITS IS THE ONLY HONEST CHOICE.
#    x86-64 has no scalable vector register at all, so the translated process has to
#    present SOME length. 128 is the architectural minimum and therefore the one value
#    every conforming VL-agnostic program must already handle. Fixing it makes rdvl /
#    cntb / incw / addvl exactly computable — and those appear overwhelmingly in the
#    RUNTIME DISPATCH at the top of a function, the code that asks how wide the machine
#    is and then picks a path. Answering it lets the whole non-SVE path translate.
#  WHAT WOULD FALSIFY IT: code that REQUIRES VL > 128 — a kernel that indexes past
#    lane 15, or one that assumes a predicate wider than 16 bits. No conforming SVE
#    program may do that, so such a failure indicts the program, not this constant.
#    It is still a constant chosen by us, not read off silicon, and it says so.
#  R18-c READ OFF AN M4, NOT CHOSEN: rdsvl#1=64, rdvl#1=64, cntb=64, cnth=32,
#    cntw=16, cntd=8 — all exactly SVL/elsize at a 512-bit streaming vector length.
#  THIS WAS 128 AND ALL THREE USES WERE WRONG BY 4x. `cntb` returned 16 for a machine
#    that returns 64 (a silently truncated loop, which its own comment warned about), and
#    `addvl sp, sp, #-2` reserved 32 bytes for 128 bytes of vectors — stack corruption.
#  THERE IS ONLY ONE LENGTH TO MODEL. rdvl and cntb SIGILL outside streaming mode on
#    Apple silicon (measured), because Apple ships FEAT_SME and no FEAT_SVE at all — so
#    any occurrence of either in a real image is already streaming code, running at SVL.
VL_BITS = 512
VL_BYTES = VL_BITS // 8          # rdvl/addvl step, and cntb at pattern ALL
PL_BYTES = VL_BYTES // 8         # predicate length: one bit per byte of VL

#  R17-a THE UNPRIVILEGED / NON-TEMPORAL / ORDERED-LIMITED SPELLINGS. Every one of
#    these differs from the name it maps to ONLY in a hint or a privilege level that a
#    translated userland thread does not have. Expressed as a table because a regex over
#    mnemonics is how `cbhs` becomes `cb` + `hs` + a silent wrong branch.
#  NOT a place for "close enough". `ldnp` really is `ldp` (non-temporal is a cache
#    hint); `ldapur` is NOT `ldur` and is handled as a real acquire load below.
ALIAS = {
    # non-temporal and unprivileged pairs — the hint has no x86-64 expression
    'stnp': 'stp', 'ldnp': 'ldp', 'sttp': 'stp', 'ldtp': 'ldp',
    'sttnp': 'stp', 'ldtnp': 'ldp',
    # unprivileged single access: EL0 already, so the check is a tautology
    'sttr': 'stur', 'sttrb': 'sturb', 'sttrh': 'sturh',
    'ldtr': 'ldur', 'ldtrb': 'ldurb', 'ldtrh': 'ldurh',
    'ldtrsw': 'ldursw', 'ldtrsb': 'ldursb', 'ldtrsh': 'ldursh',
    # LoadLOAcquire / StoreLORelease: ordering within a LIMITED ORDERED REGION. x86-64
    # has no LORegions, so the whole address space is one region and the limited form
    # is the full one. Mapping to the STRONGER ldar/stlr is the safe direction.
    'ldlar': 'ldar', 'ldlarb': 'ldarb', 'ldlarh': 'ldarh',
    'stllr': 'stlr', 'stllrb': 'stlrb', 'stllrh': 'stlrh',
    # unprivileged compare-and-swap and unprivileged exclusives
    'cast': 'cas', 'casat': 'casa', 'caslt': 'casl', 'casalt': 'casal',
    'castb': 'casb', 'casth': 'cash',
    #  R37 ldraa/ldrab AUTHENTICATE then load. pac*/aut* lower to no-ops here (the
    #    translated process never signs a pointer — pc_rt.c), so the authenticated
    #    address IS the register, and the offset and `!` writeback are ldr's own.
    #    Checked on silicon: r37 ldraa/ldraa_wb/ldrab, M1 Pro == M4 == Xeon.
    'ldraa': 'ldr', 'ldrab': 'ldr',
    'ldtxr': 'ldxr', 'ldatxr': 'ldaxr', 'sttxr': 'stxr', 'stltxr': 'stlxr',
    'ldtxrb': 'ldxrb', 'ldtxrh': 'ldxrh', 'sttxrb': 'stxrb', 'sttxrh': 'stxrh',
}
# the unprivileged LSE atomics: ldt<op><order> is ld<op><order>
for _o in ('add', 'clr', 'set', 'eor', 'smax', 'smin', 'umax', 'umin'):
    for _ord in ('', 'a', 'l', 'al'):
        for _sz in ('', 'b', 'h'):
            ALIAS[f'ldt{_o}{_ord}{_sz}'] = f'ld{_o}{_ord}{_sz}'
            ALIAS[f'stt{_o}{_ord}{_sz}'] = f'st{_o}{_ord}{_sz}'
del _o, _ord, _sz

#  R17-a HINTS. Every one is a scheduling or power request with no data effect. On a
#    translated thread they are genuinely nothing: `yield` asks a hyperthread to back off,
#    `wfe`/`wfi` wait for an event that only an interrupt controller we do not model can
#    send, `sb`/`csdb` fence SPECULATION, which x86-64 expresses with different barriers
#    and which affects no architectural state.
#  `sev`/`sevl` SET the event register that a `wfe` elsewhere would wait on. Both sides
#    are no-ops here, so the PAIR stays consistent; a lone modelled `wfe` would hang.
#  R17-c MTE — AND THE WHOLE MODEL IS "EVERY TAG IS ZERO".
#  NOT BECAUSE TAGS ARE UNINTERESTING, BUT BECAUSE x86-64 HAS NO TBI. ARM ignores the
#    top byte of a pointer on every access, so a tagged pointer dereferences fine there.
#    On x86-64 bits 59:56 are part of the address: propagating a tag would send the very
#    next load to a canonical-form fault. So the tag field is held at zero everywhere,
#    which is exactly the architecturally legal state of a machine without FEAT_MTE.
#  WHAT THIS COSTS, SAID OUT LOUD: a program that deliberately probes MTE — writes a
#    mismatched tag and expects a fault — sees no fault, and every tag comparison reads
#    equal. That is a real behavioural difference, not a rounding error. It is confined to
#    code that tests the allocator; ordinary tagged allocation keeps working because the
#    data half of STG/STZG (the zeroing) is implemented for real below.
MTE_TAGMASK = ~(0xF << 56) & ((1 << 64) - 1)
MTE_STORE = {'stg': (16, False), 'stzg': (16, True),
             'st2g': (32, False), 'stz2g': (32, True)}
CRC32 = re.compile(r'^crc32(c?)([bhwx])$')
#  a granule zeroing goes to an inttoptr TEMP; a register write goes to a named alloca
_GRANULE_Z = re.compile(r'store <2 x i64> zeroinitializer, ptr %t\d+')
CRC32_POLY = {'': 0xEDB88320, 'c': 0x82F63B78}
CRC32_BITS = {'b': 8, 'h': 16, 'w': 32, 'x': 64}
CSSC = {'umin': 'ult', 'umax': 'ugt', 'smin': 'slt', 'smax': 'sgt'}
AESMAP = {'aese': 'aesenclast', 'aesd': 'aesdeclast'}
#  R37 op codes shared with neon_rt.c's enum — ORDER IS THE CONTRACT.
R37_SHA = {m: i for i, m in enumerate(('sha1c', 'sha1p', 'sha1m', 'sha1su0', 'sha1su1',
    'sha256h', 'sha256h2', 'sha256su0', 'sha256su1', 'sha512h', 'sha512h2',
    'sha512su0', 'sha512su1'))}
HINT_NOP = frozenset(('yield', 'wfe', 'wfi', 'sev', 'sevl', 'sb', 'esb', 'dgh',
                      'csdb', 'hint', 'ssbb', 'pssbb', 'xaflag', 'axflag', 'bti'))

#  R17-a DATA CACHE MAINTENANCE. x86-64's caches are coherent and self-managing, so
#    every clean/invalidate operation is genuinely a no-op — EXCEPT the zeroing ones.
DC_NOP = frozenset(('cvac', 'cvau', 'cvap', 'cvadp', 'civac', 'ivac', 'isw', 'csw',
                    'cisw', 'cigvac', 'cgvac', 'cgvap', 'cgvadp', 'igvac',
                    'cigdvac', 'cgdvac', 'cgdvap', 'cgdvadp', 'igdvac'))
DC_ZERO = frozenset(('zva', 'gzva', 'gva'))     # gva zeroes TAGS only — see the handler

CNTVL = re.compile(r'^(cnt|inc|dec)([bhwd])$')
#  THE ORDER OF THE ALTERNATION MATTERS AND THE GROUPS MUST BE WHOLE. `cbhs` is an
#    unsigned-higher-or-same on the FULL register, `cbhhs` is the halfword one. Writing
#    this as cb(b|h)?(..) and letting each group be a complete token is what keeps the two
#    apart; matching `h` then `s` would turn every cbhs into a halfword compare.
CMPBR = re.compile(r'^cb(b|h)?(eq|ne|gt|ge|lt|le|hi|hs|lo|ls)$')
# signed conditions compare sign-extended values, unsigned ones zero-extended
CMPBR_PRED = {'eq': 'eq', 'ne': 'ne', 'gt': 'sgt', 'ge': 'sge', 'lt': 'slt',
              'le': 'sle', 'hi': 'ugt', 'hs': 'uge', 'lo': 'ult', 'ls': 'ule'}

CAS = re.compile(r'^cas(a?l?)(b|h)?$')
AORD = {'': 'monotonic', 'a': 'acquire', 'l': 'release', 'al': 'acq_rel'}
#  10-05 THE GUEST MEMORY MODEL. An arm64 plain ldr/str is single-copy atomic and coherent per address — defined under
#    races, and every lock-free structure in a program relies on that (Red's job queue, its allocator's cross-thread
#    free queue, refcounts). A plain LLVM load/store is NOT: per llvm.org/docs/Atomics.html a racing NotAtomic load is
#    `undef`, and the optimizer may re-read a load, split or narrow a store, or store a value that would not be stored.
#    Lifting guest plain accesses as NotAtomic made Cyberpunk's lock-free code undefined: -O2 broke it only under
#    multithreaded timing (blocks reissued from a live cross-thread free queue, measured 10-05) while every
#    single-threaded certifier stayed green. `monotonic` is exactly ARM's plain-access guarantee and lowers to the same
#    x86 mov. ARM2X86_PLAIN_ORDER=notatomic restores the old lifting for an A/B only.
import os as _os
PLAIN_ORDER = _os.environ.get('ARM2X86_PLAIN_ORDER', 'monotonic')
def gload(width, pt):
    if PLAIN_ORDER == 'notatomic': return f'load i{width}, ptr {pt}'
    return f'load atomic i{width}, ptr {pt} {PLAIN_ORDER}, align {width // 8}'
def gstore(width, v, pt):
    if PLAIN_ORDER == 'notatomic': return f'store i{width} {v}, ptr {pt}'
    return f'store atomic i{width} {v}, ptr {pt} {PLAIN_ORDER}, align {width // 8}'
FTY = {'d': 'double', 's': 'float', 'h': 'half'}
FBITS = {'half': 16, 'float': 32, 'double': 64}
#  SCALAR FP INTRINSIC SUFFIX. The vector path has self._sfx (llvm.floor.v2f64); the
#    scalar path needs the plain form (llvm.floor.f64). They are DIFFERENT symbols and a
#    missing declare is a hard verify error, not a warning.
SFX1 = {'half': 'f16', 'float': 'f32', 'double': 'f64'}
#  ARM'S SEVEN ROUNDING MODES, AND THE TWO THAT ARE EASY TO GET WRONG:
#      frintm = floor            frintp = ceil            frintz = truncate
#      frinta = nearest, ties AWAY from zero   -> llvm.round
#      frintn = nearest, ties to EVEN          -> llvm.roundeven
#      frinti = nearest in the CURRENT FPCR mode -> llvm.nearbyint
#      frintx = frinti but also raises Inexact   -> llvm.rint
#  THE VECTOR TABLE HAD frintn->nearbyint AND frinti->rint. Under the default FPCR
#    (round-to-nearest-even) nearbyint and roundeven agree on every input, so the bug is
#    invisible on a default-mode machine and only appears once something sets a rounding
#    mode — the exact shape of a test that passes while measuring nothing.
FRINTS = {'frintm': 'floor', 'frintp': 'ceil', 'frintz': 'trunc',
          'frinta': 'round', 'frintn': 'roundeven',
          'frinti': 'nearbyint', 'frintx': 'rint'}
#  ARM HAS TWO MIN/MAX FAMILIES AND THEY DIFFER ONLY ON NaN:
#      FMAX/FMIN     propagate NaN            -> llvm.maximum / llvm.minimum
#      FMAXNM/FMINNM IEEE-754 maxNum/minNum, return the NUMBER -> llvm.maxnum / minnum
#  llvm.maxnum IS THE *NM* SEMANTICS. Mapping plain fmax onto it is a NaN-only bug:
#    every comparison on ordinary data agrees, which is why it shipped.
FMINMAX = {'fmax': 'maximum', 'fmin': 'minimum',
           'fmaxnm': 'maxnum', 'fminnm': 'minnum'}
#  EIGHT CONVERT-WITH-ROUNDING MNEMONICS, ONE SHAPE: round in the named mode, THEN
#    convert to an integer. The letter pair is (mode, signedness).
FCVTR = re.compile(r'^fcvt([amnpz])([su])$')
FCVTRND = {'a': 'round', 'm': 'floor', 'n': 'roundeven', 'p': 'ceil', 'z': 'trunc'}
#  R8 — THE TWO-ARRANGEMENT FORMS. llvm-objdump CANNOT use Apple's `mn.arr` shorthand
#    when destination and source have DIFFERENT shapes, so these arrive as a bare mnemonic
#    with the arrangement written on each register: `fcvtl v0.2d, v0.2s`.
#  MEASURED 2026-09-22: 40 of the 170 functions R7 still failed were exactly this, and
#    they are a ROUTING gap, not a semantics one — the dispatch never saw them, because it
#    keys on a dot in the MNEMONIC. An arm that is never reached looks identical to an arm
#    that does not exist.
VARRREG = re.compile(r'^v(\d+)\.(\d+[bhsd]|[bhsd])$', re.I)
#    narrowing/widening pairs: the WIDE arrangement -> the narrow one beside it
NARROW_SRC = {'2d': '2s', '4s': '4h', '8h': '8b'}
#  R9 the 64-bit half of a 128-bit arrangement — what every `2` form operates on.
HALF = {'16b': '8b', '8h': '4h', '4s': '2s', '2d': '1d'}
#  R9 SVE/SME register files. x86-64 has no scalable vector and no matrix tile, so
#    these abort — but they must abort as NotImplementedError (an architectural limit)
#    and NOT as a ValueError out of imm() (which reads as translator breakage).
#  `pn8` IS AN SME2 PREDICATE-AS-COUNTER and `\bp\d+\b` does not match it. Measured
#    2026-09-22 on the instance ruler: ptrue/whilelt with a pn operand were reported as
#    translator gaps. A limit misfiled as a gap is the same lie as a gap misfiled as a
#    limit — both make the remaining work the wrong size.
SVEREG = re.compile(r'\b[zp]n?\d+\b|\bza\d*\b', re.I)
#  R18-f a ZA TILE OPERAND: za, za0, za1h.b[w12, 0]. Anchored, because the loose
#    substring test it replaced also matched the word 'za' in `smstart za`.
ZATOK = re.compile(r'^za\d*(?:[hv]\b|\.|\[|$)', re.I)

# ── R22 SME2 OPERAND GRAMMAR ───────────────────────────────────────────────
#  A ZA ARRAY-VECTOR GROUP: `za.s[w8, 0, vgx4]`. split_ops tracks [] depth, so this
#    arrives as ONE token; the brace lists beside it do not, which is what sme_join is for.
ZA_GROUP = re.compile(r'^za\.([bhsd])\[\s*([wx]\d+|[wx]zr)\s*,\s*'
                      r'(#?-?(?:0x)?[0-9a-f]+)\s*(?:,\s*vgx(\d+)\s*)?\]$', re.I)
#  A TILE SLICE: `za0h.b[w12, 0]` or a RANGE `za0h.b[w12, 0:3]`. 'h' is horizontal
#    (a row of the tile), 'v' is vertical — measured as the exact TRANSPOSE, element i of
#    za<T>v.<t>[Wv,k] being (tile row i)[lane k].
ZA_SLICE = re.compile(r'^za(\d*)([hv])\.([bhsd])\[\s*([wx]\d+|[wx]zr)\s*,\s*'
                      r'(#?-?(?:0x)?[0-9a-f]+)\s*(?::\s*(#?-?(?:0x)?[0-9a-f]+)\s*)?\]$',
                      re.I)
ZA_TILE = re.compile(r'^za(\d+)\.([bhsd])$', re.I)


def simm(tok):
    """ imm() MASKS TO 2^64, so a negative `mul vl` offset comes back as ~1.8e19
       and the address arithmetic runs off the end of the world instead of one vector
       backwards. Every SME immediate goes through here."""
    v = imm(tok)
    return v - (1 << 64) if v >= (1 << 63) else v
#  `[x9]`, `[x9, #0x4, mul vl]` — the immediate is HEX in objdump's output (`#0x4`),
#    which int(s, 0) reads and int(s, 10) would silently refuse. It scales by SVL, once,
#    NOT by the number of vectors in the list (measured: ld1w x4 at #4 starts at chunk 4).
SME_ADDR_VL = 'mul vl'
# the SME2 while<cc> family -> (is the comparison signed, does the count include equality,
# are the operands swapped). whilegt/whilege count DOWN from the first operand.
SME_WHILE = {'whilelt': (True, False, False), 'whilele': (True, True, False),
             'whilelo': (False, False, False), 'whilels': (False, True, False),
             'whilegt': (True, False, True), 'whilege': (True, True, True),
             'whilehi': (False, False, True), 'whilehs': (False, True, True)}
# multi-vector element-wise, by element kind
SME_MV_FP = {'fadd': 'fadd', 'fsub': 'fsub', 'fmul': 'fmul'}
SME_MV_FPI = {'fmax': 'maxnum', 'fmin': 'minnum'}
SME_MV_INT = {'add': 'add', 'sub': 'sub', 'mul': 'mul', 'and': 'and', 'orr': 'or',
              'eor': 'xor'}
SME_MV_INTI = {'smax': 'smax', 'smin': 'smin', 'umax': 'umax', 'umin': 'umin'}

#  R18 APPLE'S STREAMING VECTOR LENGTH, MEASURED (rdsvl on an M4), NOT ASSUMED.
#    64 bytes = 512 bits. Every z register, every predicate and the ZA tile are sized
#    from this one number, so if a future part ships a different SVL exactly one
#    constant moves - and the selftest arm below asserts the shapes track it.
SVL_B = VL_BYTES        #  R18-c one constant, not two that can drift


def _sve_sfx(n, el):
    """<16 x float> -> v16f32, for an llvm intrinsic name."""
    k = {'half': 'f16', 'float': 'f32', 'double': 'f64',
         'i8': 'i8', 'i16': 'i16', 'i32': 'i32', 'i64': 'i64'}[el]
    return f'v{n}{k}'


def _fpbits_literal(k, el):
    """ AN SVE FP IMMEDIATE IS A VALUE, NOT A BIT PATTERN, and LLVM wants it spelled as
       a hex double. Emitting the raw integer would build a denormal out of an integer."""
    import struct as _st
    d = float(k)
    return '0x%016X' % _st.unpack('<Q', _st.pack('<d', d))[0]

SVL_BITS = SVL_B * 8
# element suffix -> (bits, llvm int type, llvm fp type or None)
SVE_EL = {'b': (8, 'i8', None), 'h': (16, 'i16', 'half'),
          's': (32, 'i32', 'float'), 'd': (64, 'i64', 'double'),
          'q': (128, 'i128', None)}
# the SVE mnemonics that are plain element-wise arithmetic, and their LLVM opcode.
SVE_FP2 = {'fadd': 'fadd', 'fsub': 'fsub', 'fmul': 'fmul', 'fdiv': 'fdiv'}
#  R18-k asr/lsr/lsl LEFT THIS TABLE. They lowered to a plain LLVM shift, which is
#    POISON when the amount reaches the element width - and an M4 says SVE SATURATES
#    there (asr -> all sign bits, lsr/lsl -> zero) rather than wrapping like the scalar
#    forms do. They have their own arm below.
SVE_INT2 = {'add': 'add', 'sub': 'sub', 'mul': 'mul', 'and': 'and', 'orr': 'or',
            'eor': 'xor'}
SVE_SHIFT = {'asr': 'ashr', 'lsr': 'lshr', 'lsl': 'shl'}
#  R18-h THE INTRINSIC IS llvm.sqrt, NOT llvm.fsqrt. `fsqrt` there made llvm-as
#    reject the module outright: unknown intrinsic 'llvm.fsqrt.v8f64'.
SVE_FP1 = {'fneg': 'fneg', 'fabs': 'fabs', 'fsqrt': 'sqrt'}
#  REVERSED-OPERAND FORMS ARE NOT THE SAME INSTRUCTION. `fdivr z0, p0/m, z0, z1`
#    computes z1/z0, not z0/z1. Treating fdivr as fdiv returns a plausible number.
SVE_REV = {'fdivr': 'fdiv', 'subr': 'sub', 'fsubr': 'fsub'}
#  R18-i (source kind, destination kind): 'f' float, 's' signed int, 'u' unsigned int.
SVE_CVT = {'fcvt': ('f', 'f'), 'fcvtzs': ('f', 's'), 'fcvtzu': ('f', 'u'),
           'scvtf': ('s', 'f'), 'ucvtf': ('u', 'f')}
SVE_FN = {16: 'f16', 32: 'f32', 64: 'f64'}
SVE_PTRUE_PAT = {'b': (1 << 64) - 1, 'h': 0x5555555555555555,
                 's': 0x1111111111111111, 'd': 0x0101010101010101}


# ── R19 JUMP-TABLE PAYLOAD IS DATA, NOT INSTRUCTIONS ───────────────────────
JT_MEM = re.compile(r'^\[x(\d+), x(\d+), lsl #2\]$')
JT_REG = re.compile(r'^x(\d+)$')
JT_HEX = re.compile(r'^(0x[0-9a-f]+)')
JT_IMM = re.compile(r'^#(0x[0-9a-f]+|\d+)$')


def _jt_base(insns, i, dest):
    """Resolve the TABLE BASE the `br` at index i indexes through, or None.

     EVERY OPERAND IS RESOLVED FROM ITS OWN POSITION IN PROGRAM ORDER. A first
       version scanned back from the `br` for whatever last wrote the table register
       and found `adr x17, <pc>` — the PC base — because the real sequence REUSES x17
       for both, writing the PC base AFTER the load. It reported base == pc on all 782
       JavaScriptCore sites and found zero tables. A register's value is only defined
       at a point, and a backward scan must start from the USE, not from the end.
    """
    lo = max(0, i - 12)
    k_add = b_reg = off_reg = None
    for k in range(i - 1, lo - 1, -1):
        a, mn, ops = insns[k]
        if (mn == 'add' and len(ops) == 3 and ops[0] == 'x%d' % dest
                and JT_REG.match(ops[1]) and JT_REG.match(ops[2])):
            k_add, b_reg, off_reg = k, ops[1], ops[2]
            break
        if mn in ('b', 'ret', 'retab', 'retaa'):
            return None
    if k_add is None:
        return None
    k_ld = t_reg = None
    for k in range(k_add - 1, lo - 1, -1):
        a, mn, ops = insns[k]
        if mn == 'ldrsw' and len(ops) == 2 and ops[0] in (b_reg, off_reg):
            mm = JT_MEM.match(ops[1])
            if mm:
                k_ld, t_reg = k, 'x' + mm.group(1)
                break
    if k_ld is None:
        return None
    pend = None
    for k in range(k_ld - 1, lo - 1, -1):
        a, mn, ops = insns[k]
        if (mn == 'add' and pend is None and len(ops) == 3
                and ops[0] == t_reg and ops[1] == t_reg and JT_IMM.match(ops[2])):
            pend = int(JT_IMM.match(ops[2]).group(1), 0)
            continue
        if mn in ('adrp', 'adr') and len(ops) >= 2 and ops[0] == t_reg:
            mh = JT_HEX.match(ops[1])
            if mh:
                return int(mh.group(1), 16) + (pend or 0)
            return None
    return None


def jump_table_data(insns):
    """Addresses inside `insns` that are jump-table PAYLOAD rather than code.

    Returns a set. Empty when nothing is recognised, which leaves every existing
    behaviour exactly as it was.
    """
    noni = {a for a, mn, _ in insns if mn in ('udf', '<unknown>')}
    if not noni:
        return set()
    bases = set()
    for i, (a, mn, ops) in enumerate(insns):
        if mn != 'br' or len(ops) != 1:
            continue
        mr = JT_REG.match(ops[0])
        if not mr:
            continue
        t = _jt_base(insns, i, int(mr.group(1)))
        #  THE GUARD: a base is only believed when it POINTS AT UNDECODABLE WORDS.
        #    If the dispatch indexes real code, nothing is reclassified.
        if t is not None and t in noni:
            bases.add(t)
    if not bases:
        return set()
    order = sorted(bases)
    data = set()
    for k, T in enumerate(order):
        stop = order[k + 1] if k + 1 < len(order) else (1 << 63)
        x = T
        while x < stop and x in noni:
            data.add(x)
            x += 4
    return data


class Lifter:
    def __init__(self, insns, name, known=(), binds=None):
        #  `known` = entry addresses of every function in THIS translation unit. A `bl`
        #    into the set becomes a real call; a `bl` out of it aborts loudly.
        #  R5 `binds` = cross-image call targets that exist NATIVELY on x86-64.
        #    addr -> {sym, argc, ret, cache}. These are LINKED, not translated: libz's
        #    `bl 0x1980f46f0` is a dyld shared-cache auth stub whose GOT entry resolves to
        #    _platform_memmove, and x86-64 already has memmove. Translating libc would be
        #    work we never have to do.
        #  R19 the payload comes out BEFORE the label pass and before lift(), so a
        #    data word can neither abort as an unknown mnemonic nor become a block that
        #    R11's switch can branch into.
        self.jt_data = jump_table_data(insns)
        if self.jt_data and len(self.jt_data) < len(insns):
            insns = [t for t in insns if t[0] not in self.jt_data]
        #  rung 6 (10-03): WAS set(known) — a COPY of the whole program's function set per function. On Cyberpunk that is a
        #    450,000-entry set copied 447,510 times (~75 CPU-minutes); the lift itself is ~6. Membership only is ever asked.
        self.insns, self.name = insns, name
        self.known = known if isinstance(known, (set, frozenset)) else set(known)
        self.binds = dict(binds or {})
        self.used_binds = {}
        self.n, self.body = 0, []
        self.lo = insns[0][0]
        self.hi = insns[-1][0]
        self.labels = {self.lo}
        #  10-21 SWIFT ASYNC: every swifttailcc function (and every resume point) of arm64 Swift code opens with
        #    `orr x29, x29, #0x1000000000000000` — the extended-frame marker, bit 60 of the frame pointer — and clears it
        #    again (`and x29, x29, #0xefff...`) just before its final tail transfer. Nothing else emits it, so it says exactly
        #    "x22 is an async context here and the last transfer is an async tail call" (see native_hint).
        #     ...but a FRAMELESS async function (`leaf`: str x0,[x22,#0x10] / b swift_task_switch) or resume point has no frame, so
        #    no marker: ASYNC_FNS (xlat2) names those from the register they read.
        self.async_fn = self.lo in ASYNC_FNS or any(mn_ == 'orr' and list(ops_) == ['x29', 'x29', '#0x1000000000000000'] for _, mn_, ops_ in insns[:3])
        #  10-03 C++ exceptions: one landing-pad block per (arm64 pad, clause list), shared by every call that uses it
        self.eh = EH.get(self.lo)
        self.eh_sites, self.eh_pads, self.eh_n, self.eh_decls = [], {}, 0, set()
        if self.eh:
            addrs_ = {t_[0] for t_ in insns}
            for st_, en_, lp_, cl_ in self.eh['sites']:
                if not lp_: continue
                if lp_ not in addrs_: raise NotImplementedError(f'landing pad 0x{lp_:x} is outside function 0x{self.lo:x}')
                k_ = (lp_, cl_)
                if k_ not in self.eh_pads: self.eh_pads[k_] = f'EHLP{lp_:x}_{len(self.eh_pads)}'
                self.labels.add(lp_); self.eh_sites.append((st_, en_, self.eh_pads[k_]))
            self.eh_decls.add(f'declare i32 @{self.eh["pers"]}(...)')
        for i, (a, mn, ops) in enumerate(insns):
            t = self.target(mn, ops)
            if t is not None and self.lo <= t <= self.hi:
                self.labels.add(t)
            #  THE FALLTHROUGH SIDE OF A CONDITIONAL BRANCH IS ALSO A BLOCK ENTRY.
            #    WAS: only branch TARGETS became labels, so `b.ne`'s not-taken edge
            #    referenced a block that was never opened -> "use of undefined value".
            #  R17-a AND THE NEW BRANCH FORMS ARE CONDITIONAL TOO. Adding
            #    compare-and-branch to target() above without adding it HERE left its
            #    not-taken edge referencing a block nobody opened — the identical
            #    "use of undefined value" this comment was written for, reintroduced
            #    by the same omission one commit later. `bc.` is spelled out because
            #    this pass runs BEFORE lift() normalises it to `b.`.
            if ((mn.startswith('b.') or mn.startswith('bc.') or CMPBR.match(mn)
                 or mn in ('cbz', 'cbnz', 'tbz', 'tbnz'))
                    and i + 1 < len(insns)):
                self.labels.add(insns[i + 1][0])
        #  R11 A COMPUTED JUMP TABLE LANDS WHERE NOTHING BRANCHES. Measured 2026-09-22 on
        #    a real Xeon: `_zlibDecodeBuffer` does
        #        ldrsw x16, [x17, x16, lsl #2] ; adr x17, 0x1916e4154 ; add x16, x17, x16 ; br x16
        #    and `_lzvn_decode_buffer` does the same with a 16-bit table. The targets are
        #    ADDRESSES INSIDE THE FUNCTION, reached only through that register — so the label
        #    pass above, which walks direct branch operands, never sees them. They arrived at
        #    the global fnmap (which holds function ENTRY points) and aborted: "no entry for
        #    0x1916e4188 in a 575-entry map".
        #  WE DO NOT DECODE THE TABLE. Its base, stride and element width differ per site
        #    (ldrsw/lsl#2 here, ldrsh/lsl#1 there) and a misread table is a silent jump to the
        #    middle of an instruction. Instead the SAFE SUPERSET: in a function that contains
        #    an indirect branch, every instruction address becomes a block entry, and the
        #    branch switches over them. LLVM's simplifycfg folds the blocks that only fall
        #    through, so the cost is compile time, not code.
        self.has_ind = any(m in ('br', 'braa', 'brab', 'braaz', 'brabz') and o
                           and re.fullmatch(r'x\d+', o[0]) for _, m, o in insns)
        if self.has_ind:
            self.labels.update(a for a, _, _ in insns)

    def target(self, mn, ops):
        if not ops: return None
        #  R17-a A BRANCH WHOSE TARGET target() DOES NOT RECOGNISE RETURNS None,
        #    and None is not a label — the compare-and-branch family would have
        #    branched to nowhere rather than aborting. Adding the handler without
        #    adding it here is the same defect shape as R11's jump tables.
        if (mn == 'b' or mn.startswith('b.') or mn.startswith('bc.')
                or CMPBR.match(mn)
                or mn in ('cbz', 'cbnz', 'bl', 'tbz', 'tbnz')):
            m = re.match(r'^(0x[0-9a-f]+)', ops[-1])
            #  rung 6: a stub whose GOT slot resolves INSIDE the translated address space (a call into a translated
            #    library, or a weak-def-coalesce bind to the program's own definition) is a direct call to its target.
            return ALIASES.get(int(m.group(1), 16), int(m.group(1), 16)) if m else None
        return None

    def t(self):
        self.n += 1; return f'%t{self.n}'

    def e(self, s): self.body.append('  ' + s)

    # registers ---------------------------------------------------------------
    def rd(self, r):
        """Read a register.  wN means the LOW 32 BITS, not the whole register."""
        r = r.strip()
        if r in ('xzr', 'wzr'): return '0'
        who = 'rd'
        #  THE MIRROR OF vslot's GUARD, AND IT IS THE SAME BUG CLASS. A q/d/s/h/b
        #    token arriving here names the VECTOR file, and this function would hand back
        #    `%d2` — an alloca that does not exist — without raising. Every one of these
        #    found so far was silent, and coverage read 100% while the IR was invalid.
        #    An accessor that cannot recognise its own operand BLOCKS (engineering.md §3).
        if VREG.match(r):
            raise NotImplementedError(f'{who}: {r!r} is a VECTOR register, not a GPR')
        #  10-03 (rung 6): an operand that is NOT a register name at all — `0x10c010bc8 <dyld_stub_binder+…>`, an
        #    unstripped disassembler annotation — became `ptr %0x10c010bc8`. Anything outside the GPR grammar BLOCKS by name.
        if not GPR.match(r):
            raise NotImplementedError(f'{who}: {r!r} is not a general-purpose register')
        slot = 'sp' if r == 'wsp' else ('x' + r[1:] if r[0] == 'w' else r)
        v = self.t(); self.e(f'{v} = load i64, ptr %{slot}')
        if r[0] == 'w':
            m = self.t(); self.e(f'{m} = and i64 {v}, {M32}'); return m
        return v

    def wr(self, r, val):
        """ A WRITE TO wN ZEROES THE UPPER 32 BITS. Dropping this is silent corruption."""
        r = r.strip()
        if r in ('xzr', 'wzr'): return
        who = 'wr'
        #  THE MIRROR OF vslot's GUARD, AND IT IS THE SAME BUG CLASS. A q/d/s/h/b
        #    token arriving here names the VECTOR file, and this function would hand back
        #    `%d2` — an alloca that does not exist — without raising. Every one of these
        #    found so far was silent, and coverage read 100% while the IR was invalid.
        #    An accessor that cannot recognise its own operand BLOCKS (engineering.md §3).
        if VREG.match(r):
            raise NotImplementedError(f'{who}: {r!r} is a VECTOR register, not a GPR')
        #  10-03 (rung 6): an operand that is NOT a register name at all — `0x10c010bc8 <dyld_stub_binder+…>`, an
        #    unstripped disassembler annotation — became `ptr %0x10c010bc8`. Anything outside the GPR grammar BLOCKS by name.
        if not GPR.match(r):
            raise NotImplementedError(f'{who}: {r!r} is not a general-purpose register')
        slot = 'sp' if r == 'wsp' else ('x' + r[1:] if r[0] == 'w' else r)
        if r[0] == 'w':
            m = self.t(); self.e(f'{m} = and i64 {val}, {M32}'); val = m
        self.e(f'store i64 {val}, ptr %{slot}')

    # ── the vector register file (v0-v31, 128 bits each) ──────────────────────
    def vslot(self, tok):
        """v3 / q3 / d3 / s3 / b3 all name the SAME 128-bit register — slot %v3."""
        r = tok.strip().lstrip('%').split('.')[0]
        #  MEASURED 2026-09-22, AND IT WAS SILENT: `mov.s w0, v5[0]` reached here with
        #    a GPR token. 'w' is not in the strip class, so this returned 'vw0' and the
        #    lifter emitted `load ptr %vw0` — a register that no alloca ever defined.
        #    coverage.py counted that function as TRANSLATED WHOLE because nothing raised.
        #    A name this function cannot recognise is a routing bug upstream; it must
        #    block, never invent a slot. (engineering.md §3: a check that cannot run BLOCKS.)
        if not re.fullmatch(r'[vqdshb]\d+', r):
            raise NotImplementedError(f'vslot: {tok!r} is not a vector register')
        return 'v' + re.sub(r'^[vqdshb]', '', r)

    def vty(self, arr, fp=False):
        """arrangement -> (llvm type, lanes, element type, element bits)"""
        n, eb = VARR[arr]
        el = ({16: 'half', 32: 'float', 64: 'double'}[eb] if fp else f'i{eb}')
        return f'<{n} x {el}>', n, el, eb

    def abi_args(self):
        """ R12 the 16 outgoing argument registers, in AAPCS64 order."""
        return ', '.join([f'i64 {self.rd(f"x{i}")}' for i in range(8)]
                         + [f'<2 x i64> {self.vrd(f"v{i}", "2d")}' for i in range(8)])

    def abi_split(self, r):
        """ R12 unpack a callee's return into x0 and v0.
            v0 MUST be written even when the callee returned an integer: ARM's v0 is
              caller-saved, so leaving OUR v0 in place would let a stale value read back
              as the callee's result. Writing the callee's (possibly garbage) v0 is what
              the hardware does."""
        q = self.t(); self.e(f'{q} = extractvalue {ABI_RET} {r}, 1')
        self.vwr('v0', '2d', q)
        v = self.t(); self.e(f'{v} = extractvalue {ABI_RET} {r}, 0')
        return v

    def carry_at(self, i):
        """ 10-21 MAY THE ASYNC TAIL TRANSFER AT INSTRUCTION i CARRY THE 7th/8th INTEGER ARGUMENT (arm64 x6/x7; x86-64 has six
           integer argument registers, so those two travel on the stack)? A deferred tail call (indirect_tail / NATIVE_ADAPTER_IR)
           has no room for stack words, a nested one does. The arguments of THIS call were set up after the previous call, so
           x6/x7 count if they are mentioned between the previous call (or the function entry) and here.  Not "anywhere in
           the function": -Osize outlines code that uses x6/x7 as scratch all over, every site read as carrying and nested,
           and the 100,000-element stream exhausted a 512 KB worker again."""
        for j in range(i - 1, -1, -1):
            _, mn_, o_ = self.insns[j]
            if mn_ == 'bl' or mn_.startswith('blr'): return False
            if re.search(r'(?<![\w])[xw][67](?![\w])', ', '.join(map(str, o_))): return True
        return False

    def native_hint(self, i=0):
        """ 10-20 tell the native adapter which convention an indirect tail transfer's NATIVE target has. An import stub
           names its callee's by symbol (STUB_CC).  10-21 An async guest function's `br` is an ASYNC tail call whatever it
           reaches (a witness-table or closure entry, a native ResumeParent): hint 3 = swifttailcc with the context in r14.
            Stored only on the dispatch path: __arm2x86_lookup clears it when the target is translated code."""
        #  10-22 AN ASYNC IMPORT STUB STORES 5, NOT 3. Its callee is KNOWN swifttailcc (callee-pop), but its x22 need not be a
        #    context: swift_continuation_await takes the continuation context as an ordinary FIRST argument, and WallpaperAgent
        #    reached it with x22 = a Swift object (isa 0x100218218, refcount 3). The adapter rejected that as a context (right) and
        #    took the plain swiftcc path (wrong): the callee's `retq $8` left the adapter 8 bytes off and it returned into the
        #    guest (dtrace: adapter entry rsp ...ab68, return rsp ...ab78 vs +8 on the other 242 calls). 5 = always the async
        #    path; the x22 check then only decides whether ResumeParent is swapped. A `br`'s 3/4 still need a valid context.
        if self.lo in STUB_CC: self.e(f'store i8 {5 if STUB_CC[self.lo] == 3 else STUB_CC[self.lo]}, ptr @__arm2x86_native_hint')
        elif self.async_fn: self.e(f'store i8 {4 if self.carry_at(i) else 3}, ptr @__arm2x86_native_hint')   # 4: may carry stack words

    def indirect_tail(self, a0, args):
        """ 10-21 THE INDIRECT TAIL TRANSFER (`br xN`). An ordinary function calls the target and returns its result,
           handing its own register file back afterwards (the 10-03 XR_TAIL_KEEP rule: its CALLER reads x19-x28 once it
           returns). An ASYNC function has no such caller — control never comes back to it, a swift async function ends by
           transferring to its ResumeParent — so its transfer is a true `musttail`: a `for await` over elements that are
           already buffered resumes the guest from the native runtime from inside the guest, and with a nested call every
           element cost one more stack frame (asyncmx: 5.4 KB each, a 512 KB GCD worker overflowed at ~95 elements).
            Not under C++ exception handling: an invoke cannot be a tail call."""
        if self.async_fn and not self.eh:
            f = self.t(); self.e(f'{f} = call ptr @__arm2x86_lookup(i64 {a0})')
            r = self.t(); self.e(f'{r} = musttail call {ABI_RET} {f}({args})')
            self.e(f'ret {ABI_RET} {r}')
            return
        r = self.t()
        self.e(f'{r} = call {ABI_RET} @__arm2x86_dispatch(i64 {a0}, {args})')
        if self.lo in NONABI: self.xr_xfer(XR_TAIL_KEEP, True)   #  10-03: hand our file back after the tail call
        self.e(f'ret {ABI_RET} {self.this_ret(r)}')

    def xr_xfer(self, regs, put):
        """ rung 6 move registers between this frame and @__arm_xr (see the declaration in the module head)."""
        self.xr_n = getattr(self, 'xr_n', 0) + 1
        for ln in xr_lines(regs, put, f's{self.xr_n}'): self.e(ln.strip())

    def xr_tail_pub(self, full_if_nonabi=False):
        """ 10-21 A TAIL TRANSFER PUBLISHES WHAT THIS FUNCTION DEFINES. The 10-20 rule (an on-contract caller
           publishes only XR_ABI_IN, because it never received a file) is right about what it must NOT write and
           wrong about what it must: measured on callmx -Oz, all 75 failing sites are on-contract callers that
           DEFINE x9 and tail-call an off-contract callee which loads x9 from @__arm_xr+72 — so the callee read the
           grandparent's x9 and the caller's own value was dropped (300 differing lines at -Oz, 0 at -O1/-O2).
           Publishing the full file brings the 10-20 erasure straight back (the registers a function never wrote
           hold the entry ZERO, not the caller's value), so the set is the MIDDLE one: XR_ABI_IN + every XR_FULL_IN
           register this function actually stores to. Resolved after lifting — the defines are only all known then —
           see xr_tail_resolve.  The matching entry load is what makes a NOT-taken path right too: a function that
           defines x9 on one path and tail-calls on another publishes the value it loaded at entry, i.e. its
           caller's, unchanged. Loading at ENTRY and not at the site is deliberate: nothing has run yet that could
           have overwritten @__arm_xr.  The 10-20 negative control still passes by construction — the Dock thunk
           at 0x100153cb0 writes x4/x5 only, neither is in XR_FULL_IN, so its set stays exactly XR_ABI_IN."""
        self.xr_tail_n = getattr(self, 'xr_tail_n', 0) + 1
        self.e(f';;XRTAIL{self.xr_tail_n}' + ('F' if full_if_nonabi else ''))

    def xr_tail_resolve(self, head, body):
        """ 10-21 fill in the XRTAIL/XRIN markers now that every store in the function is known."""
        import re as _re
        pub = list(XR_ABI_IN)
        if self.lo not in NONABI and any(ln.strip().startswith(';;XRTAIL') for ln in body):
            wrote = set(_re.findall(r', ptr %(x\d+|v\d+|[NZCV])$', '\n'.join(body), _re.M))
            if wrote & set('NZCV'): wrote.add('nzcv')
            pub += [r for r in XR_FULL_IN if r not in pub and r in wrote]
        out = []
        for ln in body:
            s = ln.strip()
            if s.startswith(';;XRTAIL'):
                regs = XR_FULL_IN if (s.endswith('F') and self.lo in NONABI) else pub
                tag = 't' + s[len(';;XRTAIL'):].rstrip('F')
                out += ['  ' + l.strip() for l in xr_lines(regs, True, tag)]
            else:
                out.append(ln)
        i = head.index(XR_IN_MARK)
        head[i:i + 1] = xr_lines(XR_FULL_IN if self.lo in NONABI else pub, False, 'in')
        return head, out

    def abi_ret(self, x0=None):
        """ R12 return x0 AND v0, because AAPCS64 does."""
        #  A NAMED SEAM. It reads as a comment in the .ll (useful in a 25 MB module) and
        #    it is what vloads() slices on: the epilogue's read of %v0 is the ABI's, not the
        #    instruction's, and four arms that count register reads must not see it.
        self.e('; --- R12 epilogue: return x0 and v0 ---')
        self.xr_xfer(XR_FULL_OUT if self.lo in NONABI else XR_ABI_OUT, True)   #  rung 6 the rest of the return
        #  10-21 sp IS AN OUT VALUE OF OFF-CONTRACT CODE. clang outlines a big prologue into a
        #    shared helper that allocates the caller's frame and RETURNS WITH sp STILL LOWERED
        #    (`sub sp, sp, #0xc0` / saves x19-x28 / `ret`, with a matching `add sp, sp, #0xc0` epilogue
        #    helper). XR_FULL_OUT moves x1-x28 + v1-v31 + nzcv and did NOT include sp, so the caller
        #    kept its pre-call sp and every later [sp, #N] was 0xc0 bytes too high -- it wrote into its
        #    CALLER's live frame. Measured in the Dock: 0x1001587c8 is such a helper, and the caller's
        #    `stp x4, x5, [sp]` landed on a weak reference that objc_storeWeak had registered, so
        #    libobjc reported "Weak reference at 0x1038bfda0 contains 0x100400ae0, should contain
        #    0x600002268510" and objc_retain faulted. sp rides @__arm_sp, which already means "the real
        #    ARM sp" -- publish it here and reload it after the call.
        #  10-22 AND EVERY FUNCTION, NOT ONLY OFF-CONTRACT ONES. An off-contract helper that tail-calls an ON-contract
        #    function returns through that function's `ret`; its internal calls had published their LOWERED sp and it never
        #    republished, so the helper's caller reloaded a too-low sp and its [sp, #N] slots moved under live data.
        #    MenuBarAgent (dtrace on swift_cvw_initWithCopy): a MenuBarAgentSettings value at 0x104cb9500 had a second
        #    instance written over it at +0xa0, its String fields read the doubles 0.01/0.001/1.0 and swift_retain died on
        #    0x3f50624dd2f1a9fc. A balanced function's sp here IS its entry sp, so publishing it is always right.
        self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
        v = self.rd('x0') if x0 is None else x0
        q = self.vrd('v0', '2d')
        a = self.t(); self.e(f'{a} = insertvalue {ABI_RET} poison, i64 {v}, 0')
        b = self.t(); self.e(f'{b} = insertvalue {ABI_RET} {a}, <2 x i64> {q}, 1')
        self.e(f'ret {ABI_RET} {b}')

    def vrd(self, tok, arr, fp=False):
        """Read a vector register in the requested arrangement."""
        ty, n, el, eb = self.vty(arr, fp)
        lanes = 128 // eb
        full = f'<{lanes} x {el}>'
        v = self.t(); self.e(f'{v} = load <16 x i8>, ptr %{self.vslot(tok)}')
        c = self.t(); self.e(f'{c} = bitcast <16 x i8> {v} to {full}')
        if n == lanes: return c
        idx = ', '.join(f'i32 {i}' for i in range(n))
        s = self.t()
        self.e(f'{s} = shufflevector {full} {c}, {full} poison, <{n} x i32> <{idx}>')
        return s

    def vwr(self, tok, arr, val, fp=False):
        """ A WRITE TO A 64-BIT ARRANGEMENT ZEROES THE UPPER 64 BITS of the 128-bit
           register — exactly as a write to wN zeroes the upper 32 (see wr()). Leaving the
           old top half in place is silent corruption that only surfaces later, when
           something reads the full q register and finds a ghost."""
        ty, n, el, eb = self.vty(arr, fp)
        lanes = 128 // eb
        full = f'<{lanes} x {el}>'
        if n == lanes:
            w = val
        else:
            idx = ', '.join([f'i32 {i}' for i in range(n)] + [f'i32 {n}'] * (lanes - n))
            w = self.t()
            self.e(f'{w} = shufflevector {ty} {val}, {ty} zeroinitializer, '
                   f'<{lanes} x i32> <{idx}>')
        b = self.t(); self.e(f'{b} = bitcast {full} {w} to <16 x i8>')
        self.e(f'store <16 x i8> {b}, ptr %{self.vslot(tok)}')

    def vrd_hi(self, tok, arr, fp=False):
        """ R9 read the HIGH 64 bits of a register AS `arr` — the widening `2` forms.
           `arr` is the NARROW (64-bit) shape being read, e.g. fcvtl2 v0.2d, v1.4s reads
           v1 as 2s taken from lanes 2,3 of its 4s."""
        ty, n, el, eb = self.vty(arr, fp)
        if n * eb != 64:
            raise NotImplementedError(f'vrd_hi wants a 64-bit arrangement, got {arr!r}')
        farr = {8: '16b', 16: '8h', 32: '4s', 64: '2d'}[eb]
        fty, fn, _, _ = self.vty(farr, fp)
        full = self.vrd(tok, farr, fp)
        idx = ', '.join(f'i32 {i}' for i in range(n, fn))
        r = self.t()
        self.e(f'{r} = shufflevector {fty} {full}, {fty} poison, <{n} x i32> <{idx}>')
        return r

    def vwr_hi(self, tok, arr, val, fp=False):
        """ R9 write the HIGH 64 bits and PRESERVE THE LOW ONES — narrowing `2` forms.
            vwr() zeroes the upper half of the register by design (that is correct for a
              64-bit arrangement). A narrowing `2` is ALWAYS the partner of a non-`2` that
              just wrote the low half, so writing through vwr() here would erase the result
              the previous instruction produced and the checksum would still look sane."""
        ty, n, el, eb = self.vty(arr, fp)
        if n * eb != 64:
            raise NotImplementedError(f'vwr_hi wants a 64-bit arrangement, got {arr!r}')
        farr = {8: '16b', 16: '8h', 32: '4s', 64: '2d'}[eb]
        fty, fn, _, _ = self.vty(farr, fp)
        lo = self.vrd(tok, farr, fp)
        pidx = ', '.join([f'i32 {i}' for i in range(n)] + ['i32 0'] * (fn - n))
        pv = self.t()
        self.e(f'{pv} = shufflevector {ty} {val}, {ty} poison, <{fn} x i32> <{pidx}>')
        midx = ', '.join([f'i32 {i}' for i in range(n)]
                         + [f'i32 {fn + i}' for i in range(n)])
        w = self.t()
        self.e(f'{w} = shufflevector {fty} {lo}, {fty} {pv}, <{fn} x i32> <{midx}>')
        self.vwr(tok, farr, w, fp)

    def opnd(self, tok, shift=None):
        """A register operand, optionally with `lsl/lsr/asr #n` folded in."""
        v = imm(tok) if tok.startswith('#') else self.rd(tok)
        v = str(v)
        #  R13-b THE OPERAND'S OWN WIDTH DECIDES THE SHIFT WIDTH. `w8, asr #31`
        #    must shift in i32 or the sign bit it exists to broadcast is not there.
        w32 = not tok.startswith('#') and tok.strip()[:1] == 'w'
        if shift:
            parts = shift.split()
            kind = parts[0]
            a = imm(parts[1]) if len(parts) > 1 else 0
            m = re.match(r'^(uxt|sxt)([bhwx])$', kind)
            if m:
                #  AN EXTEND WITH NO AMOUNT IS LEGAL AND IT CRASHED THE PARSER.
                bits = {'b': 8, 'h': 16, 'w': 32, 'x': 64}[m.group(2)]
                if bits < 64:
                    tr = self.t(); self.e(f'{tr} = trunc i64 {v} to i{bits}')
                    ex = self.t(); self.e(f'{ex} = {"sext" if m.group(1) == "sxt" else "zext"} i{bits} {tr} to i64')
                    v = ex
                if not a: return v
                o = self.t(); self.e(f'{o} = shl i64 {v}, {a}'); return o
            if kind == 'ror':
                #  R13 `ror #0` made this emit `shl i64 v, 64`, which is POISON.
                #    Same family as the variable-shift bug: a rotate by zero is the value.
                if not a:
                    return v
                if w32:
                    #  R13-b a 32-bit rotate wraps within 32 bits. llvm.fshr takes the
                    #    amount modulo the width, which is ARM's rule.
                    t32 = self.t(); self.e(f'{t32} = trunc i64 {v} to i32')
                    r = self.t()
                    self.e(f'{r} = call i32 @llvm.fshr.i32(i32 {t32}, i32 {t32}, i32 {a & 31})')
                    o = self.t(); self.e(f'{o} = zext i32 {r} to i64'); return o
                hi = self.t(); self.e(f'{hi} = lshr i64 {v}, {a}')
                lo = self.t(); self.e(f'{lo} = shl i64 {v}, {64 - a}')
                o = self.t(); self.e(f'{o} = or i64 {hi}, {lo}'); return o
            op = {'lsl': 'shl', 'lsr': 'lshr', 'asr': 'ashr'}[kind]
            if w32:
                t32 = self.t(); self.e(f'{t32} = trunc i64 {v} to i32')
                r = self.t(); self.e(f'{r} = {op} i32 {t32}, {a & 31}')
                o = self.t(); self.e(f'{o} = zext i32 {r} to i64')
                return o
            o = self.t()
            self.e(f'{o} = {op} i64 {v}, {a}')
            return o
        return v

    def src(self, ops, i):
        """operand i, absorbing a trailing shift OR extend spec if present"""
        nxt = ops[i+1] if len(ops) > i+1 else None
        #  R13-c ror IS a legal shifted operand for the logical instructions and it
        #    was missing from this list, so it fell through and was DROPPED.
        if nxt and re.match(r'^(lsl|lsr|asr|ror) #', nxt):
            return self.opnd(ops[i], nxt)
        m = re.match(r'^(uxt|sxt)([bhwx])(?: #(\d+))?$', nxt) if nxt else None
        if m:
            #  `add x1, x21, w19, uxtw` PARSED CORRECTLY ONLY BY ACCIDENT before this:
            #    rd('w19') masks to 32 bits, which happens to equal uxtw. sxtw did NOT —
            #    it zero-extended, turning a negative index into a +4-billion offset.
            bits = {'b': 8, 'h': 16, 'w': 32, 'x': 64}[m.group(2)]
            v = self.rd(ops[i])
            if bits < 64:
                tr = self.t(); self.e(f'{tr} = trunc i64 {v} to i{bits}')
                ex = self.t(); self.e(f'{ex} = {"sext" if m.group(1) == "sxt" else "zext"} i{bits} {tr} to i64')
                v = ex
            if m.group(3):
                s = self.t(); self.e(f'{s} = shl i64 {v}, {int(m.group(3))}'); v = s
            return v
        #  R13-c AN OPERAND MODIFIER WE DO NOT RECOGNISE MUST ABORT, NOT BE IGNORED.
        #    `ror` was dropped here for the whole life of the translator and nothing ever
        #    said so: the arithmetic simply came out wrong, quietly, in 1,543 places in a
        #    40-image sample. Anything shaped like `<word> #<n>` that reached this line was
        #    being thrown away, so the failure mode was unbounded, not limited to ror.
        if nxt and re.match(r'^[a-z]{2,4} #-?\d', nxt):
            raise NotImplementedError(f'unhandled shifted/extended operand {nxt!r}')
        return self.opnd(ops[i], None)

    # flags -------------------------------------------------------------------
    def setflags(self, w32, A, B, sub_op, pred=None, nzcv=0):
        """ N, Z, C AND V. The flag model held only Z and C until 2026-09-22, which made
           every signed condition (lt/le/gt/ge/mi/vs) unimplementable — measured: 4 libz
           functions failed on `condition le`/`lt` alone.
            V IS NOT 'CARRY FOR SIGNED'. It is the sign overflow of the operation; treating
              it as C inverts every signed compare near INT_MIN/INT_MAX, which is precisely
              the kind of wrong answer that looks right on small test values.
           `pred` (for ccmp/ccmn): when the condition is false the flags take the literal
           nzcv immediate instead of the comparison."""
        wid = M32 if w32 else M64
        sb = 31 if w32 else 63
        am = self.t(); self.e(f'{am} = and i64 {A}, {wid}')
        bm = self.t(); self.e(f'{bm} = and i64 {B}, {wid}')
        raw = self.t(); self.e(f'{raw} = {"sub" if sub_op else "add"} i64 {am}, {bm}')
        res = self.t(); self.e(f'{res} = and i64 {raw}, {wid}')
        z = self.t(); self.e(f'{z} = icmp eq i64 {res}, 0')
        c = self.t()
        if sub_op: self.e(f'{c} = icmp uge i64 {am}, {bm}')
        else:      self.e(f'{c} = icmp ult i64 {res}, {am}')
        ns = self.t(); self.e(f'{ns} = lshr i64 {res}, {sb}')
        n = self.t(); self.e(f'{n} = trunc i64 {ns} to i1')
        xab = self.t(); self.e(f'{xab} = xor i64 {am}, {bm}')
        if not sub_op:
            nx = self.t(); self.e(f'{nx} = xor i64 {xab}, {wid}'); xab = nx
        xar = self.t(); self.e(f'{xar} = xor i64 {am}, {res}')
        va = self.t(); self.e(f'{va} = and i64 {xab}, {xar}')
        vsh = self.t(); self.e(f'{vsh} = lshr i64 {va}, {sb}')
        v = self.t(); self.e(f'{v} = trunc i64 {vsh} to i1')
        for slot, val, bit in (('N', n, 3), ('Z', z, 2), ('C', c, 1), ('V', v, 0)):
            if pred is not None:
                alt = 'true' if (nzcv >> bit) & 1 else 'false'
                s = self.t(); self.e(f'{s} = select i1 {pred}, i1 {val}, i1 {alt}'); val = s
            self.e(f'store i1 {val}, ptr %{slot}')

    def setflags_add(self, w32, A, B):
        """ THE CARRY OUT OF AN ADD IS NOT ALWAYS FALSE. This stored `i1 false` into %C
           unconditionally until 2026-09-22. inflateStateCheck ends `cmn w8,#0x20 ; cset w0,lo`,
           which READS that carry — with a constant false the state check INVERTS and every
           call returns a plausible wrong answer. Carry = the sum wrapped, at the op width."""
        self.setflags(w32, A, B, False)

    def setflags_sub(self, a, b, w32=False):
        self.setflags(w32, a, b, True)

    def setflags_carry(self, w32, an, bn, cin):
        """ R9 NZCV for ADCS/SBCS. Operands arrive ALREADY at the operation width.
            setflags() DERIVES C FROM `res < a`, WHICH IS ONLY VALID FOR A 2-INPUT ADD.
              With carry-in 1 and a+b == all-ones the true carry-out is 1 while `res < a`
              reads 0 — the exact input a multiword add exists to handle. So the sum is
              computed one bit wider, where the carry-out IS bit W and nothing is inferred."""
        W = 32 if w32 else 64
        ity, wty = f'i{W}', f'i{W + 1}'
        za = self.t(); self.e(f'{za} = zext {ity} {an} to {wty}')
        zb = self.t(); self.e(f'{zb} = zext {ity} {bn} to {wty}')
        zc = self.t(); self.e(f'{zc} = zext i1 {cin} to {wty}')
        p = self.t(); self.e(f'{p} = add {wty} {za}, {zb}')
        q = self.t(); self.e(f'{q} = add {wty} {p}, {zc}')
        cs = self.t(); self.e(f'{cs} = lshr {wty} {q}, {W}')
        ct = self.t(); self.e(f'{ct} = trunc {wty} {cs} to i1')
        r = self.t(); self.e(f'{r} = trunc {wty} {q} to {ity}')
        z = self.t(); self.e(f'{z} = icmp eq {ity} {r}, 0')
        nn = self.t(); self.e(f'{nn} = icmp slt {ity} {r}, 0')
        #  signed overflow: the operands agreed in sign and the result disagreed.
        x1 = self.t(); self.e(f'{x1} = xor {ity} {an}, {bn}')
        x2 = self.t(); self.e(f'{x2} = xor {ity} {an}, {r}')
        nx = self.t(); self.e(f'{nx} = xor {ity} {x1}, -1')
        vm = self.t(); self.e(f'{vm} = and {ity} {nx}, {x2}')
        vs = self.t(); self.e(f'{vs} = lshr {ity} {vm}, {W - 1}')
        vt = self.t(); self.e(f'{vt} = trunc {ity} {vs} to i1')
        self.e(f'store i1 {nn}, ptr %N'); self.e(f'store i1 {z}, ptr %Z')
        self.e(f'store i1 {ct}, ptr %C'); self.e(f'store i1 {vt}, ptr %V')

    def fsrd(self, tok):
        # Read a SCALAR fp register -> (ssa value, llvm fp type).
        #  Scalar FP shares the 128-bit vector file, and <1 x ty> is how the rest of
        #    this lifter already spells 'the bottom lane and nothing else'.
        tok = tok.strip(); ft = FTY[tok[0]]
        v = self.vrd(tok, tok[0], True)
        e = self.t(); self.e(f'{e} = extractelement <1 x {ft}> {v}, i64 0')
        return e, ft

    def fswr(self, tok, val, ft):
        #  Goes through vwr so the upper bits of the 128-bit register are ZEROED, which
        #    is what ARM does on a scalar FP write. Storing the lane in place leaves a
        #    ghost for the next reader of the full q register.
        tok = tok.strip()
        iv = self.t()
        self.e(f'{iv} = insertelement <1 x {ft}> poison, {ft} {val}, i64 0')
        self.vwr(tok, tok[0], iv, True)

    def t_round(self, fty, val, fn, sfx):
        """Round a vector in a named mode before converting.  fptosi ALWAYS truncates,
           so without this fcvtms/fcvtps/fcvtas/fcvtns all collapse into fcvtzs — correct
           for z, off by one for the other six on exactly the inputs they exist for."""
        r = self.t()
        self.e(f'{r} = call {fty} @llvm.{fn}.{sfx}({fty} {val})')
        return r

    def satcvt(self, fty, ity, val, signed, sfx_f, sfx_i):
        """ ARM'S FP->INT CONVERSIONS SATURATE; LLVM'S fptosi/fptoui ARE POISON.
           R6 AND R7 BOTH SHIPPED A PLAIN `fptosi` AND EVERY ARM STAYED GREEN, because no
           arm tested the FAILURE direction — out-of-range inputs and NaN never appear in a
           test written with small whole numbers (engineering.md §1). ARM clamps to
           INT_MIN/INT_MAX and maps NaN to 0; llvm.fptosi.sat/fptoui.sat do exactly that and
           are target-neutral, so the x86 backend still picks the instruction.
           This is not a rounding nicety: poison licenses the optimiser to delete the code
           around it, so the wrong answer is not even bounded."""
        op = 'fptosi' if signed else 'fptoui'
        r = self.t()
        self.e(f'{r} = call {ity} @llvm.{op}.sat.{sfx_i}.{sfx_f}({fty} {val})')
        return r

    def fcall(self, fn, ft, *xs):
        args = ', '.join(f'{ft} {x}' for x in xs)
        r = self.t(); self.e(f'{r} = call {ft} @llvm.{fn}.{SFX1[ft]}({args})')
        return r

    def cond(self, cc):
        Z = self.t(); self.e(f'{Z} = load i1, ptr %Z')
        C = self.t(); self.e(f'{C} = load i1, ptr %C')
        N = self.t(); self.e(f'{N} = load i1, ptr %N')
        V = self.t(); self.e(f'{V} = load i1, ptr %V')
        r = self.t()
        if   cc == 'eq': self.e(f'{r} = select i1 {Z}, i1 true, i1 false')
        elif cc == 'ne': self.e(f'{r} = xor i1 {Z}, true')
        elif cc in ('hs', 'cs'): self.e(f'{r} = select i1 {C}, i1 true, i1 false')
        elif cc in ('lo', 'cc'): self.e(f'{r} = xor i1 {C}, true')
        elif cc == 'hi':
            nz = self.t(); self.e(f'{nz} = xor i1 {Z}, true')
            self.e(f'{r} = and i1 {C}, {nz}')
        elif cc == 'ls':
            nc = self.t(); self.e(f'{nc} = xor i1 {C}, true')
            self.e(f'{r} = or i1 {nc}, {Z}')
        elif cc == 'mi': self.e(f'{r} = select i1 {N}, i1 true, i1 false')
        elif cc == 'pl': self.e(f'{r} = xor i1 {N}, true')
        elif cc == 'vs': self.e(f'{r} = select i1 {V}, i1 true, i1 false')
        elif cc == 'vc': self.e(f'{r} = xor i1 {V}, true')
        elif cc == 'ge': self.e(f'{r} = icmp eq i1 {N}, {V}')
        elif cc == 'lt': self.e(f'{r} = icmp ne i1 {N}, {V}')
        elif cc == 'gt':
            ge = self.t(); self.e(f'{ge} = icmp eq i1 {N}, {V}')
            nz = self.t(); self.e(f'{nz} = xor i1 {Z}, true')
            self.e(f'{r} = and i1 {ge}, {nz}')
        elif cc == 'le':
            lt = self.t(); self.e(f'{lt} = icmp ne i1 {N}, {V}')
            self.e(f'{r} = or i1 {lt}, {Z}')
        elif cc in ('al', 'nv'): self.e(f'{r} = or i1 true, false')
        else: raise NotImplementedError(f'condition {cc}')
        return r

    def br(self, c, taken, nxt):
        tl = f'L{taken:x}' if taken in self.labels else None
        if tl is None:  # branch leaves the function
            tl = f'OUT{taken:x}'
        if nxt in self.labels:
            nl = f'L{nxt:x}'
        else:   #  10-03 the NOT-taken path runs off this function's end (37 in Cyberpunk): continue into the next one
            nl = f'FT{nxt:x}'; self.ft_targets.add(nxt)
        self.e(f'br i1 {c}, label %{tl}, label %{nl}')

    def setflags_logic(self, o, w32):
        """ 10-03 (instruction certifier vs the M4: 17 forms of ands/bics/tst differed): a LOGICAL flag-setting op sets ALL
           FOUR flags — N = the result's top bit AT ITS WIDTH (31 for w, 63 for x), Z = result == 0 at that width, C = 0,
           V = 0. It WAS Z only (+ C for two of the three): N and V kept stale values, so b.mi / b.lt / b.ge after a tst
           went the wrong way."""
        v = o
        if w32:
            tr = self.t(); self.e(f'{tr} = trunc i64 {o} to i32')
            z = self.t(); self.e(f'{z} = icmp eq i32 {tr}, 0')
            n = self.t(); self.e(f'{n} = icmp slt i32 {tr}, 0')
        else:
            z = self.t(); self.e(f'{z} = icmp eq i64 {v}, 0')
            n = self.t(); self.e(f'{n} = icmp slt i64 {v}, 0')
        self.e(f'store i1 {n}, ptr %N'); self.e(f'store i1 {z}, ptr %Z')
        self.e('store i1 false, ptr %C'); self.e('store i1 false, ptr %V')

    def emit_call(self, tgt):
        """ AAPCS64: args x0-x7, return x0. Emitting a real LLVM call hands the ENTIRE
           ABI translation (ARM x0-x7 -> SysV rdi/rsi/rdx/rcx/r8/r9 + stack) to the x86_64
           backend for free. That boundary is the whole project and it costs us nothing.
            PUBLISH THE STACK POINTER FIRST. The callee reads @__arm_sp at entry, not our
              %sp alloca — without this store it builds its frame on top of ours.
            R12 x0 AND v0 ARE CARRIED BACK, and v0-v7 go OUT. Before R12 only x0-x7
              travelled, and a callee taking a `double`/vector argument read a zeroed v0 —
              see the module docstring of patch_r12.py for the 4 oracle arms that cost.
            STILL LOST: a 128-bit integer return in the x0:x1 PAIR. No callee in this
              closure returns one; a future one must be caught here, not discovered in a
              wrong answer."""
        self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
        full = tgt in NONABI
        self.xr_xfer(XR_FULL_IN if full else XR_ABI_IN, True)   #  rung 6 x8 out (sret); the whole file to outlined code
        r = self.t()
        self.e(f'{r} = call {ABI_RET} @fn_{tgt:x}({self.abi_args()})')
        self.xr_xfer(XR_FULL_OUT if full else XR_ABI_OUT, False)   #  rung 6 x1 + v1-v3 back (pairs, HFA)
        if full:   #  10-21 and sp, which an outlined prologue leaves lowered for us (see abi_ret)
            sp_ = self.t(); self.e(f'{sp_} = load i64, ptr @__arm_sp'); self.wr('sp', sp_)
        return self.abi_split(r)

    def emit_bind(self, tgt):
        """ R5 THE CROSS-IMAGE CALL. Emit a direct call to the native symbol and let
           the system linker resolve it. This is the whole trick: 44 of libz's 140
           functions reach outside the image, and every one of those targets is ordinary
           libc that x86-64 already has.
            ARITY IS PART OF THE BIND — we pass the callee's TRUE argument count, not
              x0-x7. Declaring i64(i64 x8) would make every bind variadic-shaped and would
              stop LLVM from matching the real symbol's signature at link time.
            A 32-BIT RETURN IS ZEXT'd, NOT READ AS i64. Apple's arm64 ABI leaves the top
              half of x0 undefined for an `int` return, so ARM code always reads w0; SysV
              says the same about rax/eax. `call i32` + zext is the faithful model —
              `call i64` would hand the lifted code 32 bits of garbage that happens to
              read correct on this machine today.
            10-21 PUBLISH @__arm_sp ON EVERY NATIVE CALL. This used to publish only for
              an `rf` or `va` bind, reasoning that "a native callee builds its frame on the
              REAL x86 stack, so publishing would be a lie that only matters the day
              something reads it". That day came. A native callee that calls BACK into guest
              code -- a function pointer, a block, an ObjC IMP, a Swift value witness, or the
              lazy trampoline -- enters through a door that reads @__arm_sp to place the
              callback's ARM frame. With the publish skipped, @__arm_sp still held the sp of
              some SHALLOWER frame, so the callback built its frame ON TOP of locals that
              were still live and overwrote them.
              Measured in the Dock: `WeakIdentitySet<__C.WorkspacesObserver>.Identity` sat at
              0x1038bfda0 (its caller's sp) with a weak ref to the WindowDragController that
              objc_storeWeak had registered; by the time swift_cvw_initWithCopy read it the
              slot held 0x100400ae0, the address of a __DATA global, and libobjc said so
              itself -- "Weak reference at 0x1038bfda0 contains 0x100400ae0, should contain
              0x600002754630" -- then objc_retain faulted at +0x20. 8/8 runs, deterministic.
              The stack in that crash is the shape to remember: msg_send -> ffi_call_unix64 ->
              ffi_closure_unix64 -> imp_handler -> guest code, i.e. a native round trip.
              One store per native call is the whole cost."""
        b = self.binds[tgt]
        self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
        if b.get('rf'):
            #  L3 THE FULL-REGISTER BIND. objc_msgSend has no fixed signature: its arguments are whatever the
            #    METHOD declares, known only at run time from the method's type encoding. So the whole arm64 argument
            #    state goes to the bridge: x0..x8 (x8 = the indirect-result pointer for a large struct return) and
            #    v0..v7 into the thread-local @__arm2x86_rf (x at +8*i, v at +80+16*j —  16-ALIGNED: at +72 LLVM's
            #    vmovaps faulted, b108 objc1 03:31), sp published for stack
            #    arguments. The bridge writes the result back the arm64 way and we reload every return register:
            #    x0, x1 (16-byte structs) and v0..v3 (an HFA such as CGRect). Nothing about the callee is guessed here.
            self.used_binds[b['sym']] = ('void', '')
            if b.get('selref'):   #  an __objc_stubs entry: `adrp/ldr x1, selref` then objc_msgSend — load the SEL first
                sp_ = self.t(); self.e(f'{sp_} = inttoptr i64 {b["selref"]} to ptr')
                sv = self.t(); self.e(f'{sv} = load i64, ptr {sp_}'); self.wr('x1', sv)
            self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
            for i in range(9):
                g = self.t(); self.e(f'{g} = getelementptr inbounds i8, ptr @__arm2x86_rf, i64 {8 * i}')
                self.e(f'store i64 {self.rd(f"x{i}")}, ptr {g}')
            if b.get('xin') is not None:
                #  10-25 THE ARGUMENT IS IN xN, NOT x0 (libobjc's arm64-only objc_retain_xN / objc_release_xN).
                #    The register file holds x0..x8 only, so a handler reading x19 read the v-register area: the
                #    rrx2 oracle printed x0 != object and a release that never happened for x19/x23/x28.
                xr = b['xin']; self.e(f'store i64 {self.rd(f"x{xr}")}, ptr @__arm2x86_rf')
            for j in range(8):
                v = self.t(); self.e(f'{v} = load <16 x i8>, ptr %v{j}')
                g = self.t(); self.e(f'{g} = getelementptr inbounds i8, ptr @__arm2x86_rf, i64 {80 + 16 * j}')
                self.e(f'store <16 x i8> {v}, ptr {g}, align 16')
            self.e(f'call void @{b["sym"]}()')
            x1p = self.t(); self.e(f'{x1p} = getelementptr inbounds i8, ptr @__arm2x86_rf, i64 8')
            x1 = self.t(); self.e(f'{x1} = load i64, ptr {x1p}'); self.wr('x1', x1)
            for j in range(4):
                g = self.t(); self.e(f'{g} = getelementptr inbounds i8, ptr @__arm2x86_rf, i64 {80 + 16 * j}')
                v = self.t(); self.e(f'{v} = load <16 x i8>, ptr {g}, align 16')
                self.e(f'store <16 x i8> {v}, ptr %v{j}')
            x0 = self.t(); self.e(f'{x0} = load i64, ptr @__arm2x86_rf')
            return x0
        kinds = bind_kinds(b)
        self.used_binds[b['sym']] = (b['ret'], kinds)
        #  R34 A VARIADIC CALLEE READS ITS TAIL OFF THE ARM STACK. Apple's arm64 ABI puts
        #    EVERY variadic argument in an 8-byte stack slot; SysV puts them in registers + AL.
        #    A `va` bind is a named C thunk (fprintf, open) that rebuilds a SysV va_list whose
        #    overflow area IS the ARM stack, so it needs the caller's sp at the bl — published
        #    here and ONLY here.  Binding fprintf plain would read garbage registers and still
        #    print something that looks like output.
        if b.get('va'):
            self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
        #  R14 TWO INDEPENDENT SEQUENCES. An integer argument consumes the next x
        #    register, a floating-point one the next v register — they do not share a
        #    counter on either ABI. Reading x0 for a `double` argument was the bug.
        _a, ni, nf = [], 0, 0
        #  rung 6 (10-03 review): an integer argument past x7 (or a float past v7) WAS read from x8, x9 ... — whatever those
        #    registers held. AAPCS64-Darwin passes it on the STACK, packed at its natural alignment; the bind reads it there
        #    with the size sigdb took from clang's own type. A stack argument of unknown size BLOCKS by name.
        sizes, so = b.get('sizes') or [], [0]
        def from_stack(k, idx):
            if idx >= len(sizes) or not sizes[idx]:
                raise NotImplementedError(f"{b['sym']}: stack argument {idx} has no known size")
            sz = sizes[idx]; off = (so[0] + sz - 1) // sz * sz; so[0] = off + sz
            ad = self.t(); self.e(f'{ad} = add i64 {self.rd("sp")}, {off}')
            pt = self.t(); self.e(f'{pt} = inttoptr i64 {ad} to ptr')
            if k == 'i':
                ity = {1: 'i8', 2: 'i16', 4: 'i32', 8: 'i64'}[sz]
                v = self.t(); self.e(f'{v} = load {ity}, ptr {pt}, align 1')
                if sz < 8:
                    w = self.t(); self.e(f'{w} = zext {ity} {v} to i64'); v = w
                return f'i64 {v}'
            ty = BIND_TY[k]; v = self.t(); self.e(f'{v} = load {ty}, ptr {pt}, align 1'); return f'{ty} {v}'
        vl_ = set(b.get('valist') or ())
        for idx, c in enumerate(kinds):
            if c == 'i':
                v_ = f'i64 {self.rd(f"x{ni}")}' if ni < 8 else from_stack('i', idx)
                _a.append(self.va_conv(v_) if idx in vl_ else v_); ni += 1
            elif nf >= 8:
                _a.append(from_stack(c, idx)); nf += 1
            else:
                ty, arr = BIND_TY[c], ('2d' if c == 'd' else '4s')
                lanes = 2 if c == 'd' else 4
                vv = self.vrd(f'v{nf}', arr, fp=True)
                el = self.t()
                self.e(f'{el} = extractelement <{lanes} x {ty}> {vv}, i32 0')
                _a.append(f'{ty} {el}'); nf += 1
        args = ', '.join(_a)
        if b['ret'] == 'void':
            # Preserve the observed Darwin ARM64 register contract of bzero.
            # A fresh M4 oracle covers call, tail-call and GOT paths, lengths
            # 0..65536 and every byte alignment. Returning zero here destroyed
            # the allocation pointer of a translated tail caller.
            preserved_x0 = self.rd('x0') if b['sym'] == 'bzero' else None
            self.e(f'call void @{b["sym"]}({args})')
            if preserved_x0 is not None:
                return preserved_x0
            #  AAPCS64 makes x0 caller-saved, so its value after a void call is
            #    unspecified. Write a DETERMINISTIC 0 rather than leaving the old value:
            #    stale-but-plausible is the failure mode that hides itself.
            return '0'
        r = self.t(); self.e(f'{r} = call {b["ret"]} @{b["sym"]}({args})')
        if b['ret'] in ('double', 'float'):
            #  R14 THE RESULT COMES BACK IN v0, NOT x0. vwr zeroes the upper half of
            #    the 128-bit register, which is what a write to d0/s0 does on the hardware.
            #    x0 gets a deterministic 0 for the same reason the void case does.
            ty = b['ret']; lanes = 2 if ty == 'double' else 4
            arr = '2d' if ty == 'double' else '4s'
            iv = self.t()
            self.e(f'{iv} = insertelement <{lanes} x {ty}> zeroinitializer, {ty} {r}, i32 0')
            self.vwr('v0', arr, iv, fp=True)
            return '0'
        nr = narrow_ret(b)
        if nr:
            bits, signed = nr
            n_ = self.t(); self.e(f'{n_} = trunc i32 {r} to i{bits}')
            w_ = self.t(); self.e(f'{w_} = {"sext" if signed else "zext"} i{bits} {n_} to i32'); r = w_
        if b['ret'] == 'i32':
            z = self.t(); self.e(f'{z} = zext i32 {r} to i64'); return z
        return r

    # ── the instruction set ──────────────────────────────────────────────────
    def lift(self):
        out_targets = set()
        self.ft_targets = set()   #  10-03 fall-through past this function's end (see br() and the end of lift())
        if self.insns and self.insns[0][1] == 'udf':
            #  10-03 A 'FUNCTION' THAT STARTS WITH udf IS DATA. Executing udf traps on the real machine, so no code
            #    enters here; Galaxy's 0x10ea11140 (udf #0x1, udf #0x0, ...) is a table whose later words decode as SME
            #    smop4a and stopped the build. It lifts as the trap the hardware would raise, by name.
            self.body.append(f'L{self.lo:x}:')
            self.e(f'call void @__arm2x86_unimplemented(i64 {self.lo})'); self.e('unreachable')
            return out_targets
        term = True
        eh_pend = None   #  10-03 (body index, pad) of a call inside an exception range, converted to `invoke` below
        for i, (a, mn, ops) in enumerate(self.insns):
            nxt = self.insns[i+1][0] if i+1 < len(self.insns) else a + 4   #  10-03: past the end = the next address
            if eh_pend: self.eh_invoke(*eh_pend); eh_pend = None
            if a in self.labels:
                if not term: self.e(f'br label %L{a:x}')
                self.body.append(f'L{a:x}:'); term = False
            if self.lo in TRACE_FNS and not term:
                regs_ = ', '.join(f'i64 {self.rd(r)}' for r in ('x0', 'x1', 'x8', 'x9', 'x19', 'x20', 'x21', 'x22', 'x23', 'x30', 'sp'))
                self.e(f'call void @__arm2x86_trace(i64 {a}, {regs_})')
            term = False
            if self.eh_sites and mn in ('bl', 'blr', 'blraa', 'blrab', 'blraaz', 'blrabz'):
                pad_ = next((p_ for s_, e_, p_ in self.eh_sites if s_ <= a < e_), None)
                if pad_: eh_pend = (len(self.body), pad_)

            #  R17-a NORMALISE THE SPELLING BEFORE ANY ARM READS IT. `bc.hi` and
            #    `b.hi` are the same branch; `stnp` and `stp` are the same store. Rewriting
            #    the mnemonic here means one handler serves both and the alias can never
            #    drift away from the thing it aliases.
            #  IT MUST HAPPEN BEFORE THE SVE TEST BELOW, not after: that test reads `mn`.
            if mn.startswith('bc.'):
                mn = 'b.' + mn[3:]
            else:
                mn = ALIAS.get(mn, mn)

            #  THIS TEST MUST COME FIRST, AND IT DID NOT. `add d5, d5, d6` is a SCALAR
            #    NEON add, but `add` is also a GPR mnemonic, and the GPR arm sat earlier in
            #    this chain — so it won, and VEC_BARE below was never consulted for any of
            #    the overlapping names (add, sub, mul, and, orr, eor, neg, mov...). The
            #    instruction then read `%d5` as a general register. Silent until rd() got
            #    its guard.  THE OPERAND DECIDES THE REGISTER FILE, NEVER THE MNEMONIC,
            #    so the operand has to be looked at before any mnemonic arm runs.
            #  R39 ABSENT-ON-EVERY-OWNED-CHIP OPS ARE NAMED BEFORE THE SVE GATE, which
            #    would otherwise claim them by their z operands and report "not yet modelled",
            #    a gap that invites a lowering nobody can check. See R38_NOFEAT.
            if mn.split('.', 1)[0] in R38_NOFEAT and SVEREG.match(
                    (ops[0] if ops else '').strip().lstrip('{').strip()):
                self.e(f'call void @__arm2x86_nofeature(i64 {a}, '
                       f'i64 {R38_NOFEAT[mn.split(".", 1)[0]]})')
                self.e('unreachable'); term = True
                continue
            #  R9 SVE/SME FIRST, BECAUSE IT WAS CRASHING THE PARSER INSTEAD OF
            #    ABORTING. `ldr p5, [x5, #0x45, mul vl]` raised ValueError out of imm() on
            #    the literal '0x45, mul vl'; the sweep counted that as translator breakage
            #    rather than what it is — a register file x86-64 does not have. An honest
            #    NotImplementedError is the difference between a gap and a bug.
            if any(SVEREG.match(o.strip().lstrip('{').strip()) for o in ops) \
                    or any('mul vl' in o or 'vgx' in o or 'vlx' in o for o in ops) \
                    or any(re.search(r'\bzt0\b', o, re.I) for o in ops) \
                    or SVEREG.match(mn.split('.', 1)[0]):
                #  R18 NO LONGER AN UNCONDITIONAL ABORT. Apple's SVL is FIXED at 512
                #    bits (measured, rdsvl on an M4), so a z register is <16 x float> and
                #    the x86 backend splits it into xmm registers itself. sve() returns
                #    False for anything it does not model, and that still aborts.
                if not self.sve_or_r33(mn, ops, a):
                    raise NotImplementedError(
                        f'SVE/SME {mn} {ops} at {a:x} (not yet modelled)')
                continue
            #  smstart/smstop CARRY NO z OR p OPERAND, so the SVE gate above — which
            #    keys on the operands — never sees them and they fell through to the
            #    unknown-mnemonic abort. They are the two instructions that DEFINE the
            #    mode everything else in that gate runs in; they have to be routed by name.
            if mn.split('.', 1)[0] in ('smstart', 'smstop'):
                self.sve(mn, ops, a)
                continue
            if mn in VEC_BARE and ops and VREG.match(ops[0].strip()):
                self.neon(mn, ops[0].strip()[0], ops, a)      # `add d5, d5, d6`
            elif mn in ('mov', 'movz'):
                self.wr(ops[0], self.opnd(ops[1]) if not ops[1].startswith('#') else str(imm(ops[1])))
            elif mn == 'movk':
                sh = imm(ops[2].split()[1]) if len(ops) > 2 else 0
                cur = self.rd(ops[0]); v = imm(ops[1])
                mask = M64 ^ (0xFFFF << sh)
                c = self.t(); self.e(f'{c} = and i64 {cur}, {mask}')
                o = self.t(); self.e(f'{o} = or i64 {c}, {(v & 0xFFFF) << sh}')
                self.wr(ops[0], o)
            elif mn == 'adrp':
                #  llvm-objdump has ALREADY resolved the page address, so we keep Apple's
                #    ORIGINAL vmaddr verbatim and let the shim mmap the data there. That is
                #    what a loader does; rewriting every reference is what a hack does.
                m = re.match(r'^(0x[0-9a-f]+)', ops[1])
                if not m: raise NotImplementedError(f'adrp operand {ops[1]!r}')
                self.wr(ops[0], str(int(m.group(1), 16)))
            elif mn == 'mvn':
                v = self.src(ops, 1); o = self.t(); self.e(f'{o} = xor i64 {v}, {M64}'); self.wr(ops[0], o)
            elif mn in ('add', 'sub', 'and', 'orr', 'eor', 'adds', 'subs', 'ands'):
                A, B = self.rd(ops[1]), self.src(ops, 2)
                llvm = {'add': 'add', 'adds': 'add', 'sub': 'sub', 'subs': 'sub',
                        'and': 'and', 'ands': 'and', 'orr': 'or', 'eor': 'xor'}[mn]
                o = self.t(); self.e(f'{o} = {llvm} i64 {A}, {B}')
                if mn in ('subs',): self.setflags_sub(A, B, ops[0][0] == 'w')
                elif mn == 'ands':
                    self.setflags_logic(o, ops[0][0] == 'w')
                elif mn == 'adds': self.setflags_add(ops[0][0] == 'w', A, B)
                self.wr(ops[0], o)
            elif mn in ('lsl', 'lsr', 'asr', 'lslv', 'lsrv', 'asrv'):
                #  R13 THE AMOUNT IS MASKED TO THE REGISTER WIDTH, and a 32-bit
                #    shift is performed IN i32 — measured against real silicon, see
                #    patch_r13.py for the table. The old comment here claimed the 32-bit
                #    part was already handled; masking the VALUE is not performing the
                #    shift at that width, and `asr` is where the difference shows.
                #  UNMASKED IS NOT MERELY WRONG, IT IS POISON: LLVM may fold a shift
                #    whose amount is >= the width to anything, so the failure is silent
                #    and depends on the optimization level.
                base = mn[:3]
                w32 = ops[0][0] == 'w'
                A = self.rd(ops[1]); B = self.opnd(ops[2])
                op = {'lsl': 'shl', 'lsr': 'lshr', 'asr': 'ashr'}[base]
                m = self.t(); self.e(f'{m} = and i64 {B}, {31 if w32 else 63}')
                if w32:
                    av = self.t(); self.e(f'{av} = trunc i64 {A} to i32')
                    sv = self.t(); self.e(f'{sv} = trunc i64 {m} to i32')
                    r = self.t(); self.e(f'{r} = {op} i32 {av}, {sv}')
                    o = self.t(); self.e(f'{o} = zext i32 {r} to i64')
                else:
                    o = self.t(); self.e(f'{o} = {op} i64 {A}, {m}')
                self.wr(ops[0], o)
            elif mn == 'cmp':
                A, B = self.rd(ops[0]), self.src(ops, 1); self.setflags_sub(A, B, ops[0][0] == 'w')
            elif mn == 'cmn':
                A, B = self.rd(ops[0]), self.src(ops, 1); self.setflags_add(ops[0][0] == 'w', A, B)
            elif mn in ('ccmp', 'ccmn'):
                #  `ccmp x8, x9, #0, eq` — compare IF the condition holds, else take the
                #    literal nzcv. This is how a compiler chains `a && b` without branching.
                p = self.cond(ops[3])
                A, B = self.rd(ops[0]), self.opnd(ops[1])
                self.setflags(ops[0][0] == 'w', A, B, mn == 'ccmp', pred=p, nzcv=imm(ops[2]))
            elif mn in ('tbz', 'tbnz'):
                v = self.rd(ops[0]); b = imm(ops[1])
                sh = self.t(); self.e(f'{sh} = lshr i64 {v}, {b}')
                bt = self.t(); self.e(f'{bt} = and i64 {sh}, 1')
                c = self.t(); self.e(f'{c} = icmp {"eq" if mn == "tbz" else "ne"} i64 {bt}, 0')
                tgt = self.target(mn, ops)
                if tgt not in self.labels: out_targets.add(tgt)
                self.br(c, tgt, nxt); term = True
            elif mn in ('ubfiz', 'ubfx', 'sbfiz', 'sbfx'):
                #  lsb AND width are both DECIMAL here, and they are not interchangeable.
                v = self.rd(ops[1]); lsb, w = imm(ops[2]), imm(ops[3])
                mask = (1 << w) - 1
                if mn in ('ubfx', 'sbfx'):
                    s = self.t(); self.e(f'{s} = lshr i64 {v}, {lsb}')
                    o = self.t(); self.e(f'{o} = and i64 {s}, {mask}')
                elif mn == 'sbfiz' and w < 64:
                    #  10-03 (certifier vs M4): SBFIZ sign-extends the FIELD (bit w-1), THEN shifts. It shifted first and
                    #    sign-extended at width w, taking the sign from the wrong bit whenever lsb > 0.
                    tr = self.t(); self.e(f'{tr} = trunc i64 {v} to i{w}')
                    ex = self.t(); self.e(f'{ex} = sext i{w} {tr} to i64')
                    o = self.t(); self.e(f'{o} = shl i64 {ex}, {lsb}')
                else:
                    a = self.t(); self.e(f'{a} = and i64 {v}, {mask}')
                    o = self.t(); self.e(f'{o} = shl i64 {a}, {lsb}')
                if mn == 'sbfx' and w < 64:
                    tr = self.t(); self.e(f'{tr} = trunc i64 {o} to i{w}')
                    ex = self.t(); self.e(f'{ex} = sext i{w} {tr} to i64'); o = ex
                self.wr(ops[0], o)
            elif mn in ('csinv', 'csneg', 'csinc'):
                c = self.cond(ops[3]); A, B = self.rd(ops[1]), self.rd(ops[2])
                alt = self.t()
                if   mn == 'csinv': self.e(f'{alt} = xor i64 {B}, {M64}')
                elif mn == 'csneg': self.e(f'{alt} = sub i64 0, {B}')
                else:               self.e(f'{alt} = add i64 {B}, 1')
                o = self.t(); self.e(f'{o} = select i1 {c}, i64 {A}, i64 {alt}'); self.wr(ops[0], o)
            elif mn in ('cinc', 'cinv', 'cneg'):
                c = self.cond(ops[2]); A = self.rd(ops[1])
                alt = self.t()
                if   mn == 'cinc': self.e(f'{alt} = add i64 {A}, 1')
                elif mn == 'cinv': self.e(f'{alt} = xor i64 {A}, {M64}')
                else:              self.e(f'{alt} = sub i64 0, {A}')
                o = self.t(); self.e(f'{o} = select i1 {c}, i64 {alt}, i64 {A}'); self.wr(ops[0], o)
            elif mn in ('mul', 'mneg'):
                A, B = self.rd(ops[1]), self.rd(ops[2])
                o = self.t(); self.e(f'{o} = mul i64 {A}, {B}')
                if mn == 'mneg':
                    g = self.t(); self.e(f'{g} = sub i64 0, {o}'); o = g
                self.wr(ops[0], o)
            elif mn in ('smull', 'umull', 'smnegl', 'umnegl'):
                #  32x32 -> 64. The operands are W registers and the SIGNEDNESS decides
                #    whether 0xFFFFFFFF means -1 or 4294967295.
                sgn = mn[0] == 's'
                o = []
                for r in (ops[1], ops[2]):
                    v = self.rd(r); tr = self.t(); self.e(f'{tr} = trunc i64 {v} to i32')
                    ex = self.t(); self.e(f'{ex} = {"sext" if sgn else "zext"} i32 {tr} to i64'); o.append(ex)
                p = self.t(); self.e(f'{p} = mul i64 {o[0]}, {o[1]}')
                if 'neg' in mn:
                    g = self.t(); self.e(f'{g} = sub i64 0, {p}'); p = g
                self.wr(ops[0], p)
            elif mn == 'smulh':
                A, B = self.rd(ops[1]), self.rd(ops[2])
                a1 = self.t(); self.e(f'{a1} = sext i64 {A} to i128')
                b1 = self.t(); self.e(f'{b1} = sext i64 {B} to i128')
                m = self.t(); self.e(f'{m} = mul i128 {a1}, {b1}')
                s = self.t(); self.e(f'{s} = ashr i128 {m}, 64')
                o = self.t(); self.e(f'{o} = trunc i128 {s} to i64'); self.wr(ops[0], o)
            elif mn in ('sdiv', 'udiv'):
                #  ARM DIVIDE BY ZERO YIELDS 0. x86 RAISES #DE and kills the process.
                #    A bare sdiv here turns a defined ARM result into a crash.
                A, B = self.rd(ops[1]), self.rd(ops[2])
                w32 = ops[0][0] == 'w'
                ty = 'i32' if w32 else 'i64'
                if w32:
                    ta = self.t(); self.e(f'{ta} = trunc i64 {A} to i32'); A = ta
                    tb = self.t(); self.e(f'{tb} = trunc i64 {B} to i32'); B = tb
                nz = self.t(); self.e(f'{nz} = icmp eq {ty} {B}, 0')
                safe = self.t(); self.e(f'{safe} = select i1 {nz}, {ty} 1, {ty} {B}')
                q = self.t(); self.e(f'{q} = {"sdiv" if mn == "sdiv" else "udiv"} {ty} {A}, {safe}')
                z = self.t(); self.e(f'{z} = select i1 {nz}, {ty} 0, {ty} {q}')
                if w32:
                    ex = self.t(); self.e(f'{ex} = zext i32 {z} to i64'); z = ex
                self.wr(ops[0], z)
            elif mn in ('neg', 'negs'):
                B = self.src(ops, 1)
                o = self.t(); self.e(f'{o} = sub i64 0, {B}')
                if mn == 'negs': self.setflags_sub('0', B, ops[0][0] == 'w')
                self.wr(ops[0], o)
            elif mn == 'adr':
                m = re.match(r'^(0x[0-9a-f]+)', ops[1])
                if not m: raise NotImplementedError(f'adr operand {ops[1]!r}')
                self.wr(ops[0], str(int(m.group(1), 16)))
            elif mn in ('orn', 'bic', 'eon', 'bics'):
                A, B = self.rd(ops[1]), self.src(ops, 2)
                nb = self.t(); self.e(f'{nb} = xor i64 {B}, {M64}')
                llvm = {'orn': 'or', 'bic': 'and', 'bics': 'and', 'eon': 'xor'}[mn]
                o = self.t(); self.e(f'{o} = {llvm} i64 {A}, {nb}')
                if mn == 'bics':
                    self.setflags_logic(o, ops[0][0] == 'w')
                self.wr(ops[0], o)
            elif re.match(r'^(sxt|uxt)[bhw]$', mn):
                bits = {'b': 8, 'h': 16, 'w': 32}[mn[3]]
                v = self.rd(ops[1])
                tr = self.t(); self.e(f'{tr} = trunc i64 {v} to i{bits}')
                ex = self.t(); self.e(f'{ex} = {"sext" if mn[0] == "s" else "zext"} i{bits} {tr} to i64')
                self.wr(ops[0], ex)
            elif mn in ('rev', 'rev16', 'rev32', 'rbit', 'clz', 'cls'):
                w32 = ops[0][0] == 'w'
                ty = 'i32' if w32 else 'i64'
                v = self.rd(ops[1])
                if w32:
                    tr = self.t(); self.e(f'{tr} = trunc i64 {v} to i32'); v = tr
                o = self.t()
                if   mn == 'rev':   self.e(f'{o} = call {ty} @llvm.bswap.{ty}({ty} {v})')
                elif mn == 'rbit':  self.e(f'{o} = call {ty} @llvm.bitreverse.{ty}({ty} {v})')
                elif mn == 'clz':   self.e(f'{o} = call {ty} @llvm.ctlz.{ty}({ty} {v}, i1 false)')
                elif mn == 'rev16':
                    #  byte-swap WITHIN each halfword, not across the register
                    hi = self.t(); self.e(f'{hi} = lshr {ty} {v}, 8')
                    hm = self.t(); self.e(f'{hm} = and {ty} {hi}, {0x00FF00FF if w32 else 0x00FF00FF00FF00FF}')
                    lo = self.t(); self.e(f'{lo} = shl {ty} {v}, 8')
                    lm = self.t(); self.e(f'{lm} = and {ty} {lo}, {0xFF00FF00 if w32 else 0xFF00FF00FF00FF00}')
                    self.e(f'{o} = or {ty} {hm}, {lm}')
                elif mn == 'cls':
                    #  COUNT LEADING SIGN BITS = CLZ(x ^ (x >>a 1)) - 1. Same identity as
                    #    the vector form; verified on 0, -1, 0x40000000 and 0x80000000.
                    a1 = self.t(); self.e(f'{a1} = ashr {ty} {v}, 1')
                    a2 = self.t(); self.e(f'{a2} = xor {ty} {v}, {a1}')
                    a3 = self.t()
                    self.e(f'{a3} = call {ty} @llvm.ctlz.{ty}({ty} {a2}, i1 false)')
                    self.e(f'{o} = sub {ty} {a3}, 1')
                elif mn == 'rev32':
                    #  BYTE-SWAP WITHIN EACH 32-BIT WORD. bswap64 reverses all eight
                    #    bytes; rotating that by 32 puts each word back in its own half.
                    #  THERE IS NO 32-BIT ENCODING — `rev32 w0, w1` would be `rev`.
                    if w32:
                        raise NotImplementedError(f'rev32 on a w register at {a:x}')
                    b = self.t(); self.e(f'{b} = call i64 @llvm.bswap.i64(i64 {v})')
                    hi = self.t(); self.e(f'{hi} = shl i64 {b}, 32')
                    lo = self.t(); self.e(f'{lo} = lshr i64 {b}, 32')
                    self.e(f'{o} = or i64 {hi}, {lo}')
                else:
                    raise NotImplementedError(f'{mn} at {a:x}')
                if w32:
                    ex = self.t(); self.e(f'{ex} = zext i32 {o} to i64'); o = ex
                self.wr(ops[0], o)
            elif mn in ('ror', 'rorv'):
                #  R9 THIS ROTATED IN 64 BITS FOR EVERY WIDTH, AND IT WAS SILENT.
                #    `ror w0, w1, #8` wrapped bits into 56..63, and wr() masks a wN write
                #    to 32 bits — so the wrapped bits were DISCARDED and a 32-bit rotate
                #    executed as a plain `lsr`. Every SHA-256 and BLAKE round is `ror w`;
                #    the checksum comes out wrong with no crash and no warning.
                #  AND THE REGISTER-AMOUNT FORM (`ror x10, x10, x1`) raised ValueError
                #    out of imm(), which killed the whole function rather than one insn.
                #  llvm.fshr(x, x, n) IS a rotate and is DEFINED for n >= width (it takes
                #    n modulo the width), which is exactly ARM's rule.
                w32 = ops[0].strip()[0] in 'wW'
                bw = 32 if w32 else 64
                ity = f'i{bw}'
                A = self.rd(ops[1])
                t3 = ops[2].strip()
                if t3.startswith('#'):
                    amt = str(imm(t3) % bw)
                else:
                    amt = self.rd(t3)
                    if w32:
                        tr = self.t(); self.e(f'{tr} = trunc i64 {amt} to i32'); amt = tr
                if w32:
                    ta = self.t(); self.e(f'{ta} = trunc i64 {A} to i32'); A = ta
                o = self.t()
                self.e(f'{o} = call {ity} @llvm.fshr.{ity}({ity} {A}, {ity} {A}, {ity} {amt})')
                if w32:
                    zz = self.t(); self.e(f'{zz} = zext i32 {o} to i64'); o = zz
                self.wr(ops[0], o)
            elif mn in ('cset', 'csetm'):
                c = self.cond(ops[1])
                v = self.t(); self.e(f'{v} = select i1 {c}, i64 {1 if mn == "cset" else M64}, i64 0')
                self.wr(ops[0], v)
            elif mn == 'tst':
                A, B = self.rd(ops[0]), self.src(ops, 1)
                t = self.t(); self.e(f'{t} = and i64 {A}, {B}')
                self.setflags_logic(t, ops[0][0] == 'w')
            elif mn == 'csel':
                c = self.cond(ops[3]); A, B = self.rd(ops[1]), self.rd(ops[2])
                o = self.t(); self.e(f'{o} = select i1 {c}, i64 {A}, i64 {B}'); self.wr(ops[0], o)
            elif mn == 'umulh':
                A, B = self.rd(ops[1]), self.rd(ops[2])
                a1 = self.t(); self.e(f'{a1} = zext i64 {A} to i128')
                b1 = self.t(); self.e(f'{b1} = zext i64 {B} to i128')
                m  = self.t(); self.e(f'{m} = mul i128 {a1}, {b1}')
                s  = self.t(); self.e(f'{s} = lshr i128 {m}, 64')
                o  = self.t(); self.e(f'{o} = trunc i128 {s} to i64'); self.wr(ops[0], o)
            elif mn == 'msub':      # d = a - n*m
                N, Mu, Ac = self.rd(ops[1]), self.rd(ops[2]), self.rd(ops[3])
                p = self.t(); self.e(f'{p} = mul i64 {N}, {Mu}')
                o = self.t(); self.e(f'{o} = sub i64 {Ac}, {p}'); self.wr(ops[0], o)
            elif mn == 'madd':
                N, Mu, Ac = self.rd(ops[1]), self.rd(ops[2]), self.rd(ops[3])
                p = self.t(); self.e(f'{p} = mul i64 {N}, {Mu}')
                o = self.t(); self.e(f'{o} = add i64 {Ac}, {p}'); self.wr(ops[0], o)
            elif mn in ('prfm', 'prfum'):
                #  R9 THE SINGLE BIGGEST BLOCKER IN THE SWEEP — 83 whole functions.
                #    A prefetch is a HINT: getting the locality wrong costs cycles, but
                #    ABORTING cost us the entire function it appeared in.
                #  It still has to compute its address, because the address expression can
                #    be a writeback form, and dropping a writeback IS a wrong answer.
                tgt = ops[1].strip()
                if not tgt.startswith('['):
                    raise NotImplementedError(f'{mn} literal form at {a:x}')
                hint = ops[0].strip().lower()
                hm = re.match(r'^p(ld|li|st)(l1|l2|l3|slc)(keep|strm)$', hint)
                if not hm:
                    raise NotImplementedError(f'{mn} {hint} at {a:x}')
                kind, lvl, pol = hm.groups()
                rw = 1 if kind == 'st' else 0
                loc = 0 if pol == 'strm' else {'l1': 3, 'l2': 2, 'l3': 1, 'slc': 0}[lvl]
                cty = 0 if kind == 'li' else 1        # 0 = instruction cache, 1 = data
                pre = tgt.endswith('!')
                parts = split_ops(tgt.rstrip('!').strip('[]'))
                addr = self.rd(parts[0])
                if len(parts) > 1:
                    off = self.opnd(parts[1], parts[2] if len(parts) > 2 else None)
                    p = self.t(); self.e(f'{p} = add i64 {addr}, {off}'); ea = p
                else:
                    ea = addr
                pp = self.t(); self.e(f'{pp} = inttoptr i64 {ea} to ptr')
                self.e(f'call void @llvm.prefetch.p0(ptr {pp}, i32 {rw}, i32 {loc}, i32 {cty})')
                if pre:
                    self.wr(parts[0], ea)
            elif mn in ('ldrb', 'ldrh', 'ldr', 'ldur', 'ldurb', 'ldurh',
                        'ldrsw', 'ldrsb', 'ldrsh', 'ldursw', 'ldursb', 'ldursh'):
                #  ldur/stur are the UNSCALED forms — identical semantics, signed offset.
                #    The ldrs* forms SIGN-extend;  zero-extending them silently turns a
                #    negative index into a 4-billion-entry offset.
                signed = mn in ('ldrsw', 'ldrsb', 'ldrsh', 'ldursw', 'ldursb', 'ldursh')
                #  MEASURED 2026-09-22, AND IT WAS COMPLETELY SILENT. `ldr d0, [x1]`
                #    took this GPR path: the width rule is `64 if ops[0][0] == 'x' else 32`,
                #    so it loaded THIRTY-TWO bits, then stored them to `%d0` — a register no
                #    alloca ever defined. `str d0` was the same bug in reverse, writing 32
                #    bits of the wrong register file to memory. 53 instructions in libz
                #    alone; not one of them raised, and coverage read 100%.
                #  THE REGISTER CLASS IS PART OF THE OPCODE. q/d/s/h/b name the vector
                #    file at 128/64/32/16/8 bits, and a 64-bit-or-narrower load zeroes the
                #    rest of the 128-bit register exactly as wN zeroes the top of xN.
                vec = bool(VREG.match(ops[0].strip()))
                width = {'ldrb': 8, 'ldrsb': 8, 'ldurb': 8, 'ldursb': 8,
                         'ldrh': 16, 'ldrsh': 16, 'ldurh': 16, 'ldursh': 16,
                         'ldrsw': 32, 'ldursw': 32,
                         'ldr': 64 if ops[0][0] == 'x' else 32,
                         'ldur': 64 if ops[0][0] == 'x' else 32}[mn]
                #  THE PRE-INDEX FORM `ldr x8, [x9, #0x2]!` BROKE THE PARSER: strip('[]')
                #    cannot remove the ']' while '!' is the last character, so the offset
                #    parsed as the literal '0x2]!'. The str handler always rstrip'd '!';
                #    the ldr handler never did. Four libz functions died on it.
                pre = ops[1].endswith('!')
                if re.fullmatch(r'0x[0-9a-f]+', ops[1].strip()):
                    #  10-03 LDR (LITERAL): a PC-relative constant in the code pages, already resolved to its ADDRESS by
                    #    the disassembler. The image is mapped at its own addresses, so this is a plain load.
                    #  WAS read as a register name and refused — libsteam_api, Bink and Galaxy, 4 shards.
                    ea = str(int(ops[1].strip(), 16)); pre = False
                else:
                    parts = split_ops(ops[1].rstrip('!').strip('[]'))
                    base = parts[0]
                    addr = self.rd(base)
                    if len(parts) > 1:                    # [xn, #imm] or [xn, xm, lsl #k]
                        off = self.opnd(parts[1], parts[2] if len(parts) > 2 else None)
                        p = self.t(); self.e(f'{p} = add i64 {addr}, {off}'); ea = p
                    else: ea = addr
                if pre: self.wr(base, ea)             # writeback BEFORE the access
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                if vec:
                    va = ops[0].strip()[0]
                    vt, _, _, _ = self.vty(va)
                    ld = self.t(); self.e(f'{ld} = load {vt}, ptr {pt}, align 1')
                    self.vwr(ops[0], va, ld)
                else:
                    ld = self.t(); self.e(f'{ld} = {gload(width, pt)}')
                    if width < 64:
                        z = self.t()
                        self.e(f'{z} = {"sext" if signed else "zext"} i{width} {ld} to i64')
                        ld = z
                    self.wr(ops[0], ld)
                if len(ops) > 2 and ops[2].startswith('#'):   # post-index writeback
                    o = self.t(); self.e(f'{o} = add i64 {addr}, {imm(ops[2])}'); self.wr(base, o)
            elif mn in ('stp', 'ldp', 'ldpsw'):
                #  THREE addressing forms and they are NOT interchangeable:
                #    [sp, #-0x30]!  pre-index  — sp updated BEFORE the access
                #    [sp, #0x10]    offset     — sp unchanged
                #    [sp], #0x30    post-index — sp updated AFTER the access
                #     Confusing pre- and post-index corrupts the frame silently.
                #  `stp q0, q1, [x8, #0x10]` STRIDED BY 8 and read the GPR file — it
                #    wrote the second register over the first half of the first one's slot
                #    and lost 16 bytes per pair. The stride is the REGISTER WIDTH.
                vecp = bool(VREG.match(ops[0].strip()))
                #  AND A `w` PAIR STRIDES BY 4 AND TOUCHES 4 BYTES. Measured 2026-09-22:
                #    `ldp w8, w2, [x21, #0x40]` in _inflateGetDictionary strode by 8, so w2
                #    got the low half of state->window instead of state->wnext and the
                #    second memmove ran off a garbage pointer — a SEGFAULT, which is the
                #    lucky outcome. The unlucky one is `stp w,w`: an i64 store writes 8
                #    bytes where ARM writes 4, silently overwriting the NEXT field. The
                #    rule in the comment above ("the stride is the REGISTER WIDTH") was
                #    written for the vector case and never applied to the GPR case.
                #  ldpsw LOADS TWO 32-BIT WORDS AND SIGN-EXTENDS EACH TO 64.
                #  ITS DESTINATIONS ARE NAMED xN, so the `w` test below cannot see it —
                #    the stride and access width follow the MNEMONIC, not the register
                #    letter. Treating it as a plain ldp strides by 8 and reads 16 bytes
                #    where ARM reads 8: the identical 32-bit-pair bug that sat under
                #    3,051 green arms on 2026-09-22, wearing a different name.
                sw = mn == 'ldpsw'
                w32 = sw or (not vecp and ops[0].strip()[0] in 'wW')
                stride = ({'q': 16, 'd': 8, 's': 4, 'h': 2, 'b': 1}[ops[0].strip()[0]]
                          if vecp else (4 if w32 else 8))
                memtok = ops[2]
                pre = memtok.endswith('!')
                parts = split_ops(memtok.rstrip('!').strip('[]'))
                base = parts[0]
                disp = imm(parts[1]) if len(parts) > 1 else 0
                post = imm(ops[3]) if len(ops) > 3 and ops[3].startswith('#') else None
                b = self.rd(base)
                if pre:
                    ea = self.t(); self.e(f'{ea} = add i64 {b}, {disp}'); self.wr(base, ea)
                elif disp:
                    ea = self.t(); self.e(f'{ea} = add i64 {b}, {disp}')
                else:
                    ea = b
                for k, rt in enumerate((ops[0], ops[1])):
                    if k:
                        a = self.t(); self.e(f'{a} = add i64 {ea}, {stride}')
                    else:
                        a = ea
                    pt = self.t(); self.e(f'{pt} = inttoptr i64 {a} to ptr')
                    if vecp:
                        va = rt.strip()[0]
                        vt, _, _, _ = self.vty(va)
                        if mn == 'stp':
                            self.e(f'store {vt} {self.vrd(rt, va)}, ptr {pt}, align 1')
                        else:
                            v = self.t()
                            self.e(f'{v} = load {vt}, ptr {pt}, align 1')
                            self.vwr(rt, va, v)
                    elif mn == 'stp':
                        v = self.rd(rt)
                        if w32:
                            t32 = self.t(); self.e(f'{t32} = trunc i64 {v} to i32')
                            self.e(gstore(32, t32, pt))
                        else:
                            self.e(gstore(64, v, pt))
                    elif w32:
                        v = self.t(); self.e(f'{v} = {gload(32, pt)}')
                        z = self.t()
                        #  SEXT FOR ldpsw, ZEXT FOR ldp w-pairs. Zero-extending a
                        #    negative ldpsw index turns -1 into 4294967295 and the
                        #    resulting address is wrong by 16 GB, not by a sign.
                        self.e(f'{z} = {"sext" if sw else "zext"} i32 {v} to i64')
                        self.wr(rt, z)
                    else:
                        v = self.t(); self.e(f'{v} = {gload(64, pt)}'); self.wr(rt, v)
                if post is not None:
                    o = self.t(); self.e(f'{o} = add i64 {b}, {post}'); self.wr(base, o)
            elif mn in ('str', 'strb', 'strh', 'stur', 'sturb', 'sturh'):
                vec = bool(VREG.match(ops[0].strip()))   # see the ldr note above
                width = {'strb': 8, 'sturb': 8, 'strh': 16, 'sturh': 16,
                         'str': 64 if ops[0][0] == 'x' else 32,
                         'stur': 64 if ops[0][0] == 'x' else 32}[mn]
                parts = split_ops(ops[1].rstrip('!').strip('[]'))
                base = parts[0]; b = self.rd(base)
                off = self.opnd(parts[1], parts[2] if len(parts) > 2 else None) if len(parts) > 1 else '0'
                if ops[1].endswith('!'):
                    ea = self.t(); self.e(f'{ea} = add i64 {b}, {off}'); self.wr(base, ea)
                elif off != '0':
                    ea = self.t(); self.e(f'{ea} = add i64 {b}, {off}')
                else:
                    ea = b
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                if vec:
                    va = ops[0].strip()[0]
                    vt, _, _, _ = self.vty(va)
                    self.e(f'store {vt} {self.vrd(ops[0], va)}, ptr {pt}, align 1')
                else:
                    v = self.rd(ops[0])
                    if width < 64:
                        tv = self.t(); self.e(f'{tv} = trunc i64 {v} to i{width}'); v = tv
                    self.e(gstore(width, v, pt))
                if len(ops) > 2 and ops[2].startswith('#'):
                    o = self.t(); self.e(f'{o} = add i64 {b}, {imm(ops[2])}'); self.wr(base, o)
            elif mn in ('cbz', 'cbnz'):
                v = self.rd(ops[0]); c = self.t()
                self.e(f'{c} = icmp {"eq" if mn == "cbz" else "ne"} i64 {v}, 0')
                tgt = self.target(mn, ops)
                if tgt not in self.labels: out_targets.add(tgt)
                self.br(c, tgt, nxt); term = True
            elif mn.startswith('b.'):
                c = self.cond(mn[2:]); tgt = self.target(mn, ops)
                if tgt not in self.labels: out_targets.add(tgt)
                self.br(c, tgt, nxt); term = True
            elif mn == 'b':
                tgt = self.target(mn, ops)
                if tgt in self.labels: self.e(f'br label %L{tgt:x}')
                elif tgt in self.known:
                    #  A TAIL CALL. `_adler32` is literally `mov w2, w2 ; b _adler32_z`.
                    self.tail_call(tgt, self.carry_at(i))
                elif tgt in self.binds:
                    #  R5 a tail branch straight out of the image, e.g. `b _memmove`.
                    r = self.emit_bind(tgt); self.abi_ret(r)
                else:
                    out_targets.add(tgt); self.e(f'br label %OUT{tgt:x}')
                term = True
            elif mn == 'bl' and self.target(mn, ops) in NOOP_CALLS:
                pass   #  10-03 ___chkstk_darwin: see NOOP_CALLS — registers, flags and memory untouched, as on the hardware
            elif mn == 'bl':
                tgt = self.target(mn, ops)
                if tgt in self.known:
                    self.wr('x0', self.emit_call(tgt))
                elif tgt in self.binds:
                    #  R5 THE CROSS-IMAGE CALL, linked instead of translated.
                    self.wr('x0', self.emit_bind(tgt))
                else:
                    #  The callee is NOT translated and NOT bound. Abort loudly. Skipping
                    #    the call would return a plausible wrong answer, the one failure
                    #    mode that must never happen.  snprintf/vsnprintf land here ON
                    #    PURPOSE: AAPCS64 passes variadic args on the ARM stack and SysV
                    #    passes them in registers + AL, so a naive bind would read garbage
                    #    and still print something that looks like output.
                    self.e(f'call void @__arm2x86_unimplemented(i64 {tgt})')
            elif mn in ('br', 'braa', 'brab', 'braaz', 'brabz'):
                #  An indirect TAIL branch, and it is TWO different things wearing one
                #    mnemonic: a jump table landing INSIDE this function, and a tail call
                #    landing in another one. R11 separates them by asking where the address
                #    is, at run time, rather than guessing at translation time.
                a0 = self.rd(ops[0])
                args = self.abi_args()
                if self.has_ind and re.fullmatch(r'x\d+', ops[0] if ops else ''):
                    #  THE LOCAL CASES COME FIRST AND THE GLOBAL DISPATCH IS THE DEFAULT, not
                    #    the other way round. An address inside this function is a block; an
                    #    address outside it is a tail call; an address that is neither reaches
                    #    __arm2x86_dispatch and ABORTS by name. No silent third behaviour.
                    ind = f'IND{a:x}'
                    cases = ' '.join(f'i64 {t}, label %L{t:x}' for t in sorted(self.labels))
                    self.e(f'switch i64 {a0}, label %{ind} [ {cases} ]')
                    self.body.append(f'{ind}:')
                    self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
                    self.xr_tail_pub()   #  rung 6 x8 + what we define; the tail callee's x1/v1-v3 pass straight to our caller
                    self.native_hint(i)
                    self.indirect_tail(a0, args); term = True
                else:
                    self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
                    self.xr_tail_pub()   #  rung 6 x8 + what we define; the tail callee's x1/v1-v3 pass straight to our caller
                    self.native_hint(i)
                    self.indirect_tail(a0, args); term = True
            elif (mn == 'blr' and ops == ['x16'] or mn in ('blraa', 'blrab') and ops == ['x16', 'x17']) and self.got_call_slot(i) in NOOP_CALLS:
                pass   #  10-03 `blr x16` through the ___chkstk_darwin GOT slot: see NOOP_CALLS
            elif mn in ('blr', 'blraa', 'blrab', 'blraaz', 'blrabz'):
                #  THE INDIRECT CALL — this is how objc_msgSend dispatches, and it is the
                #    mechanism R5 turns on. The PAC variants authenticate the target first;
                #    on x86_64 there are no signature bits, so the address passes through.
                #  UNEXERCISED BY R2: libz contains ZERO blraa (measured, 0 of 12,373).
                #    It is implemented and it is NOT proven. Do not report it as proven.
                a0 = self.rd(ops[0])
                args = self.abi_args()
                self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
                self.xr_xfer(XR_ABI_IN, True)   #  rung 6 x8 (sret) to the callee
                r = self.t()
                self.e(f'{r} = call {ABI_RET} @__arm2x86_dispatch(i64 {a0}, {args})')
                self.xr_xfer(XR_ABI_OUT, False)   #  rung 6 x1 + v1-v3 back.  10-20: a NATIVE target through the
                #    adapter now writes them too (C: rdx/xmm1; Swift: rdx/rcx/r8/xmm1-3 + the swifterror r12 -> x21). A native
                #    C function returning a struct through a hidden pointer is still not carried (cxx_bridge handles the known ones)
                self.wr('x0', self.abi_split(r))
            elif mn in ('ret', 'retab', 'retaa'):
                self.abi_ret(); term = True
            elif mn in ('pacibsp', 'autibsp', 'paciasp', 'autiasp', 'nop'):
                pass          #  x86_64 has no PAC to enforce; the sign/auth pair is a no-op here
            elif mn == 'bti':
                #  BTI is a LANDING PAD: it marks an address as a legal indirect-branch
                #    target for ARM's Branch Target Identification, and it is architecturally
                #    a NOP whenever BTI is not enabled. It carries no data and writes no
                #    register. `bti c` / `bti j` / `bti jc` differ only in WHICH kind of
                #    indirect branch may land there.
                #  It is NOT security we are dropping: x86-64's equivalent is CET's
                #    ENDBR64, which the LLVM x86 backend emits itself when the module asks
                #    for it. Open-coding an ARM landing pad into the x86 stream would be a
                #    second, unenforced marker that looks like protection and is not.
                pass
            elif re.match(r'^(pac|aut)[id][ab]1716(15)?$', mn):
                #  R16 THE FIXED-REGISTER FORMS. `pacia1716` is not a spelling of
                #    `pacia x17, x16` — it takes NO OPERANDS AT ALL. The pointer is X17 and
                #    the modifier is X16, both implicit in the encoding. They live in PLT and
                #    stub sequences, which is why 3,792 of them sit in the cache.
                #  ops[0] DOES NOT EXIST here, so the general register form below raised
                #    IndexError and ABORTED the function. 20 functions in libcompression died
                #    on pacia1716 alone — a missing mnemonic costs whole functions, not one
                #    instruction. Identity on the value, destination still written.
                self.wr('x17', self.rd('x17'))
            elif mn == 'pacga':
                #  R16 PACGA IS THE ONE PAC INSTRUCTION THAT IS NOT IDENTITY. It is a
                #    generic MAC over two registers: Xd[63:32] = code(Xn, Xm), Xd[31:0] = 0.
                #    Nothing ever strips it — code computes the code twice and COMPARES, so
                #    what has to survive translation is the FUNCTION, not the value.
                #  The real value is keyed by a per-process secret that no correct program
                #    can predict or persist, so ANY deterministic mix with the same equality
                #    behaviour is a faithful lowering: same inputs -> same code, different
                #    inputs -> different code. This is splitmix64's finaliser over
                #    (Xn * golden) ^ Xm, keeping the top 32 bits where the architecture puts
                #    them. It is the one instruction whose value is DELIBERATELY allowed to
                #    differ from the hardware's, so it can never be checked by a value
                #    differential — only by an equality-structure one.
                #  DO NOT lower this to a constant or to zero. Two different pointers would
                #    then produce the same code and a comparison meant to FAIL would PASS,
                #    which is the failure mode that turns a check into decoration.
                _n, _m = self.rd(ops[1]), self.rd(ops[2])
                _a = self.t(); self.e(f'{_a} = mul i64 {_n}, -7046029254386353131')
                _b = self.t(); self.e(f'{_b} = xor i64 {_a}, {_m}')
                _c = self.t(); self.e(f'{_c} = lshr i64 {_b}, 30')
                _d = self.t(); self.e(f'{_d} = xor i64 {_b}, {_c}')
                _e = self.t(); self.e(f'{_e} = mul i64 {_d}, -4658895280553007687')
                _f = self.t(); self.e(f'{_f} = lshr i64 {_e}, 27')
                _g = self.t(); self.e(f'{_g} = xor i64 {_e}, {_f}')
                _h = self.t(); self.e(f'{_h} = mul i64 {_g}, -7723592293110705685')
                _i = self.t(); self.e(f'{_i} = lshr i64 {_h}, 31')
                _j = self.t(); self.e(f'{_j} = xor i64 {_h}, {_i}')
                _k = self.t(); self.e(f'{_k} = shl i64 {_j}, 32')
                self.wr(ops[0], _k)
            elif re.match(r'^(pac|aut)[id](a|b|za|zb|zab)$', mn) or mn in ('xpaci', 'xpacd', 'xpaclri'):
                #  The REGISTER forms carry a value: `autda x8, x9` authenticates the pointer
                #    in x8. x86_64 has no signature bits, so sign/auth/strip are all IDENTITY
                #    on the value — but the destination must still be WRITTEN.
                #  These are 3.1% of executed volume and falling through would leave the
                #    destination holding a stale register. Identity, explicitly.
                self.wr(ops[0], self.rd(ops[0]))
            elif mn == 'amx':
                #  R20 APPLE'S AMX COPROCESSOR, 398,691 instructions in the cache.
                #    Operands arrive from parse() as ['#op', '#operand'] carved out of
                #    the raw word; `operand` is a GPR NUMBER for the transfer ops and an
                #    IMMEDIATE for op17, which is why parse() stays semantics-free and
                #    the split happens here.
                aop, aopnd = int(ops[0][1:]), int(ops[1][1:])
                if aop == 17:
                    if aopnd == 0:
                        #  ENABLE ZEROES ALL THREE FILES — measured (amx_state.c): load
                        #    X0, disable, enable, store X0 reads back ZEROS. Modelling
                        #    enable as a no-op would hand a guest the previous kernel's
                        #    tile, and every arm of a numeric selftest would still pass.
                        for gg, sz in (('x', 512), ('y', 512), ('z', 4096)):
                            self.e('call void @llvm.memset.p0.i64(ptr '
                                   f'@__arm2x86_amx_{gg}, i8 0, i64 {sz}, i1 false)')
                    elif aopnd != 1:
                        #  op17 with any operand but 0 or 1 SIGILLs on real silicon.
                        self.e(f'call void @__arm2x86_trap(i64 {a})')
                    # operand 1 is DISABLE: no architectural state change to model, since
                    # the next enable is what clears the files.
                elif aop in AMX_LDST:
                    gg, cnt, is_ld = AMX_LDST[aop]
                    gpr = self.rd(f'x{aopnd}')
                    ad = self.t(); self.e(f'{ad} = and i64 {gpr}, {AMX_ADDR_MASK}')
                    mp = self.t(); self.e(f'{mp} = inttoptr i64 {ad} to ptr')
                    sh = self.t(); self.e(f'{sh} = lshr i64 {gpr}, 56')
                    ix = self.t(); self.e(f'{ix} = and i64 {sh}, {cnt - 1}')
                    off = self.t(); self.e(f'{off} = mul i64 {ix}, 64')
                    rp = self.t()
                    self.e(f'{rp} = getelementptr i8, ptr @__arm2x86_amx_{gg}, i64 {off}')
                    dst, srcp = (rp, mp) if is_ld else (mp, rp)
                    self.e(f'call void @llvm.memcpy.p0.p0.i64(ptr {dst}, ptr {srcp}, '
                           'i64 64, i1 false)')
                else:
                    #  R21 THE COMPUTE OPS GO TO THE RUNTIME, WITH THE GPR'S VALUE.
                    #    ops 6, 7 (Z interleaved) and 8..16, 18..22. op12/op13 are measured
                    #    and implemented in amx_rt.c (200/200 against silicon); the rest
                    #    abort there naming the operand and the unknown bits.
                    #  THE OPERAND IS A REGISTER NUMBER, NOT AN IMMEDIATE, so this cannot
                    #    be a static special-case. Reading the GPR is the whole point of
                    #    the call — an unlowered op must never become a no-op, which would
                    #    let a BLAS kernel return the zeros it was initialised with and
                    #    read exactly like a working translation.
                    gpr = self.rd(f'x{aopnd}')
                    self.e(f'call void @__arm2x86_amx_op(i64 {aop}, i64 {gpr}, '
                           f'i64 {a})')
            elif mn in ('brk', 'udf'):
                #  A trap is NOT a nop. Reaching one means the original code decided the
                #    state was impossible; continuing past it invents an answer.
                #  AND A TRAP IS NOT A TRANSLATION GAP — it gets its OWN symbol.
                #    Measured 2026-09-22: `__arm2x86_unimplemented` was emitted for BOTH,
                #    so the coverage number counted 5 correctly-translated functions as
                #    untranslated. Four of them carry Apple's standard PAC epilogue
                #    (`autibsp; eor x16,x30,x30,lsl#1; tbz x16,#62,ok; brk #0xc471`) where
                #    the brk is the authentication-failure path and is meant to be there.
                #    One number covering two different facts is one number that is wrong
                #    about at least one of them.
                self.e(f'call void @__arm2x86_trap(i64 {a})')
                self.e('unreachable'); term = True
            elif mn == 'svc':
                #  R39 A SUPERVISOR CALL IS A REAL x86 SYSCALL, NOT A GAP (715 sites in the
                #    macOS 27 cache, nearly all libsystem_kernel stubs). READ OFF SILICON
                #    2026-09-23, libsystem_kernel's own stubs on both machines (r39/*_stubs.txt):
                #      arm64 `mov x16,#4; svc #0x80; b.lo ok`   x86 `mov $0x2000004,%eax; syscall; jae ok`
                #      arm64 `mov x16,#-28; svc #0x80`          x86 `mov $0x100001c,%eax; syscall`
                #    so x16>0 is BSD (class 2), x16<0 is a Mach trap (class 1, number negated),
                #    and CARRY SET MEANS ERROR on both. The class split and every refusal live
                #    in sysreg_rt.c, where the number is finally known (x16 is a register).
                #  NOT A NOP AND NOT A STUB RETURN: an svc that "returns 0" makes write()
                #    report success for bytes that never reached the file.
                #  x0-x8 GO BY POINTER and only x0/x1/C come back — the runtime writes x1 only
                #    where the kernel did (BSD success), so an error leaves x1 as it was.
                for i in range(9):
                    p = self.t()
                    self.e(f'{p} = getelementptr [9 x i64], ptr %svcargs, i64 0, i64 {i}')
                    self.e(f'store i64 {self.rd(f"x{i}")}, ptr {p}')
                c0 = self.t(); self.e(f'{c0} = load i1, ptr %C')
                c1 = self.t(); self.e(f'{c1} = zext i1 {c0} to i64')
                cn = self.t()
                self.e(f'{cn} = call i64 @__arm2x86_svc(i64 {self.rd("x16")}, ptr %svcargs, '
                       f'i64 {c1}, i64 {a})')
                for i in (0, 1):
                    p = self.t()
                    self.e(f'{p} = getelementptr [9 x i64], ptr %svcargs, i64 0, i64 {i}')
                    v = self.t(); self.e(f'{v} = load i64, ptr {p}')
                    self.wr(f'x{i}', v)
                cb = self.t(); self.e(f'{cb} = trunc i64 {cn} to i1')
                self.e(f'store i1 {cb}, ptr %C')
            elif mn in ('umaddl', 'umsubl', 'smaddl', 'smsubl'):
                #  32x32 -> 64 multiply-accumulate. NOT a vector op despite the company
                #    it keeps.  The multiply happens in 64 bits on ALREADY-EXTENDED
                #    32-bit halves; multiplying the raw x-registers would fold in whatever
                #    garbage sits in the upper halves.
                ext = 'zext' if mn[0] == 'u' else 'sext'
                xa = self.t(); self.e(f'{xa} = trunc i64 {self.rd(ops[1])} to i32')
                xb = self.t(); self.e(f'{xb} = trunc i64 {self.rd(ops[2])} to i32')
                ea = self.t(); self.e(f'{ea} = {ext} i32 {xa} to i64')
                eb_ = self.t(); self.e(f'{eb_} = {ext} i32 {xb} to i64')
                p = self.t(); self.e(f'{p} = mul i64 {ea}, {eb_}')
                acc = self.rd(ops[3])
                o = self.t()
                self.e(f'{o} = {"sub" if "sub" in mn else "add"} i64 {acc}, {p}')
                self.wr(ops[0], o)
            elif mn in ('fcvtxn', 'fcvtxn2') and ops and ops[0].strip().startswith('v'):
                #  R37 `fcvtxn v0.2s, v1.2d` carries its shape on the REGISTERS, so the
                #    dotted route below never sees it. Round to odd lives in neon_rt.c.
                self.e(f'call void @__arm2x86_rt_fcvtxn(ptr %{self.vslot(ops[0])}, '
                       f'ptr %{self.vslot(ops[1])}, i64 {2 if mn == "fcvtxn2" else 1})')
            elif mn == 'faddp.2h':
                #  R37 `2h` is not a VARR shape (it exists only as this pairwise source),
                #    so the dotted route below cannot carry it.
                self.e(f'call void @__arm2x86_rt_faddp_h(ptr %{self.vslot(ops[0])}, '
                       f'ptr %{self.vslot(ops[1])})')
            elif '.' in mn and mn.split('.', 1)[1] in VARR \
                    and mn.split('.', 1)[1] not in CONDS:
                b_, ar_ = mn.split('.', 1)
                self.neon(b_, ar_, ops, a)
            elif mn == 'fmov' and len(ops) == 2:
                #  fmov IS A BIT MOVE, NOT A CONVERSION. `fmov x0, d0` copies v0's raw
                #    low 64 bits into x0 — no rounding, no float semantics.
                #  Lowering it as a conversion changes the VALUE, and that is exactly
                #    the bug that survives every test written with small whole numbers.
                d, sb = ops[0].strip(), ops[1].strip()
                dv, sv = bool(VREG.match(d)), bool(VREG.match(sb))
                if dv and sv:
                    self.vwr(d, d[0], self.vrd(sb, sb[0], False), False)
                elif dv and GPRT.match(sb):
                    #  10-25 THE WIDTH IS THE V REGISTER'S, AND `h` IS 16. Chess's `fmov w0, h0` (after
                    #    `fcvt h0, s0`) was lowered as a 32-bit lane of an <8 x i16> view, and the module
                    #    verifier refused it ('<1 x i16>' but expected '<1 x i32>'). fmov Hd, Wn takes the
                    #    low 16 bits; fmov Wn, Hd zero-extends them.
                    w = {'d': 64, 's': 32, 'h': 16}[d[0]]
                    g = self.rd(sb)
                    if w == 64:
                        x = g
                    else:
                        x = self.t(); self.e(f'{x} = trunc i64 {g} to i{w}')
                    vv = self.t()
                    self.e(f'{vv} = insertelement <1 x i{w}> poison, i{w} {x}, i64 0')
                    self.vwr(d, d[0], vv, False)
                elif sv and GPRT.match(d):
                    w = {'d': 64, 's': 32, 'h': 16}[sb[0]]
                    e0 = self.t()
                    self.e(f'{e0} = extractelement <1 x i{w}> '
                           f'{self.vrd(sb, sb[0], False)}, i64 0')
                    if w != 64:
                        z = self.t(); self.e(f'{z} = zext i{w} {e0} to i64'); e0 = z
                    self.wr(d, e0)
                elif dv and sb.startswith('#'):
                    #  `fmov d0, #1.00000000` — objdump has ALREADY decoded the 8-bit
                    #    encoded immediate, so this is a VALUE. Every ARM FP immediate is
                    #    a small dyadic rational, hence exact in half/float/double alike.
                    _ft = FTY[d[0]]
                    _iv = self.t()
                    self.e(f'{_iv} = insertelement <1 x {_ft}> poison, '
                           f'{_ft} {float(sb[1:]):.8e}, i64 0')
                    self.vwr(d, d[0], _iv, True)
                else:
                    raise NotImplementedError(f'fmov {ops} at {a:x}')
            elif mn in HINT_NOP:
                pass                      # see HINT_NOP — a hint with no data effect
            elif mn == 'dc':
                #  R17-a DC IS 7,106 INSTRUCTIONS, THE SECOND-LARGEST GAP FAMILY, and
                #    almost all of it is cache maintenance that x86-64 does in hardware.
                #  BUT `dc zva` IS A 64-BYTE MEMSET WEARING A CACHE-OP NAME. Treating the
                #    whole mnemonic as a hint would leave a caller's freshly "zeroed" buffer
                #    holding whatever was there before — stale data that reads as a
                #    use-after-free and that no zero-check would catch, because the caller
                #    never checks something it just zeroed.
                op = ops[0].strip().lower()
                if op in DC_NOP:
                    pass
                elif op in DC_ZERO:
                    #  THE BLOCK IS ALIGNED DOWN, NOT THE ADDRESS AS GIVEN. DC ZVA zeroes
                    #    the whole naturally-aligned block containing the address; using the
                    #    raw address would zero 64 bytes starting mid-block and leave the
                    #    first bytes of the real block untouched.
                    #  64 bytes is DCZID_EL0's block size on this machine's silicon, read
                    #    from the CTR/DCZID pair (log2 words = 4 -> 16 words -> 64 bytes).
                    #  `gva` SETS ALLOCATION TAGS ONLY and leaves data alone — under the
                    #    MTE model (see R17-c) memory carries no separate tag, so it is the
                    #    one member of this set that really is a no-op.
                    if op != 'gva':
                        ea0 = self.rd(ops[1])
                        al = self.t(); self.e(f'{al} = and i64 {ea0}, -64')
                        for _k in range(0, 64, 8):
                            aa = al
                            if _k:
                                aa = self.t(); self.e(f'{aa} = add i64 {al}, {_k}')
                            pp = self.t(); self.e(f'{pp} = inttoptr i64 {aa} to ptr')
                            self.e(f'store i64 0, ptr {pp}, align 8')
                else:
                    #  AN UNRECOGNISED CACHE OPERATION ABORTS. The house rule: a check
                    #    that cannot run BLOCKS. Silently ignoring an unknown `dc` is how a
                    #    zeroing variant we have not met yet becomes a data-corruption bug.
                    raise NotImplementedError(f'dc {op} at {a:x}')
            elif mn in ('ic', 'tlbi'):
                #  INSTRUCTION CACHE AND TLB MAINTENANCE. x86-64's instruction cache is
                #    coherent with the data cache by architecture, so `ic ivau` is nothing.
                #    `tlbi` is EL1-only; a userland image containing one is kernel code, and
                #    the address translation it invalidates is Layer 2's problem, not ours.
                pass
            elif mn in ('rdvl', 'rdsvl'):
                #  R17-a READ VECTOR LENGTH. `rdvl xd, #imm` is xd = imm * (VL/8).
                #    rdsvl reads the STREAMING vector length; we present the same 128 bits
                #    for both, so a program cannot observe a mode change we do not implement.
                self.wr(ops[0], str(imm(ops[1]) * VL_BYTES))
            elif mn in ('addvl', 'addsvl', 'addpl', 'addspl'):
                #  THE SVE STACK STRIDE. `addvl sp, sp, #-0x2` reserves two vectors of
                #    spill space; at a fixed VL that is an ordinary constant `sub`.
                step = PL_BYTES if mn.endswith('pl') else VL_BYTES
                b_ = self.rd(ops[1])
                o = self.t(); self.e(f'{o} = add i64 {b_}, {imm(ops[2]) * step}')
                self.wr(ops[0], o)
            elif CNTVL.match(mn):
                #  ELEMENT COUNTS AT A FIXED VL: cntb 16, cnth 8, cntw 4, cntd 2.
                #  THE PATTERN OPERAND CHANGES THE COUNT — `cntw x0, vl4` is 4 regardless
                #    of VL, and `pow2` rounds down. Only the default (ALL) is computed here;
                #    anything else aborts rather than returning the ALL count, because a
                #    wrong loop trip count is a silently truncated loop.
                g = CNTVL.match(mn)
                per = {'b': VL_BYTES, 'h': VL_BYTES // 2,
                       'w': VL_BYTES // 4, 'd': VL_BYTES // 8}[g.group(2)]
                mul = 1
                for tk in ops[1:]:
                    tk = tk.strip().lower()
                    if tk == 'all':
                        continue
                    if tk.startswith('mul '):
                        mul = imm(tk.split()[1]); continue
                    raise NotImplementedError(f'{mn} pattern {tk!r} at {a:x}')
                amt = per * mul
                if g.group(1) == 'cnt':
                    self.wr(ops[0], str(amt))
                else:
                    b_ = self.rd(ops[0])
                    o = self.t()
                    self.e(f'{o} = add i64 {b_}, {amt if g.group(1) == "inc" else -amt}')
                    self.wr(ops[0], o)
            elif CMPBR.match(mn):
                #  R17-a FEAT_CMPBR — COMPARE AND BRANCH WITHOUT TOUCHING NZCV. The
                #    whole point of the instruction is that it leaves the flags alone, so
                #    lowering it as `subs` + `b.cc` would clobber a live condition.
                #  THE COMPARE WIDTH IS IN THE MNEMONIC, NOT IN THE REGISTERS. `cbbhi w25,
                #    w15, L` compares BYTES and `cbhhi` HALFWORDS, while both spell their
                #    operands `w`. Comparing the full register would take the branch on the
                #    high bits of a value the program never asked about.
                g = CMPBR.match(mn)
                wid = {'b': 8, 'h': 16}.get(g.group(1) or '',
                                            64 if ops[0].strip()[0] in 'xX' else 32)
                ity = f'i{wid}'
                x = self.rd(ops[0])
                if ops[1].strip().startswith('#'):
                    y = str(imm(ops[1]) & ((1 << wid) - 1))
                    if int(y) >= (1 << (wid - 1)): y = str(int(y) - (1 << wid))
                else:
                    y = self.rd(ops[1])
                    if wid < 64:
                        ty_ = self.t(); self.e(f'{ty_} = trunc i64 {y} to {ity}'); y = ty_
                if wid < 64:
                    tx = self.t(); self.e(f'{tx} = trunc i64 {x} to {ity}'); x = tx
                c = self.t()
                self.e(f'{c} = icmp {CMPBR_PRED[g.group(2)]} {ity} {x}, {y}')
                tgt = self.target(mn, ops)
                if tgt is None: raise NotImplementedError(f'{mn} target {ops} at {a:x}')
                if tgt not in self.labels: out_targets.add(tgt)
                self.br(c, tgt, nxt); term = True
            elif mn in ('ldapur', 'ldapurb', 'ldapurh', 'ldapursw', 'ldapursb', 'ldapursh',
                        'stlur', 'stlurb', 'stlurh'):
                #  R17-a ORDERED ACCESS WITH AN UNSCALED OFFSET. ldar/stlr are always
                #    `[xn]`; these carry a signed 9-bit displacement, which is why they could
                #    not just reuse the existing arm.
                #  x86-64 is TSO, so acquire and release cost no instruction — but they are
                #    emitted as `load atomic acquire` / `store atomic release` anyway, because
                #    the ordering that matters is LLVM's: a plain load may be sunk past a
                #    later store by the optimiser long before the backend sees it.
                st = mn.startswith('stlur')
                sgn = 's' in mn[6:] if not st else False
                width = ({'ldapurb': 8, 'ldapursb': 8, 'ldapurh': 16, 'ldapursh': 16,
                          'ldapursw': 32, 'stlurb': 8, 'stlurh': 16}
                         .get(mn, 64 if ops[0].strip()[0] in 'xX' else 32))
                vec = bool(VREG.match(ops[0].strip()))
                if vec:
                    width = {'q': 128, 'd': 64, 's': 32, 'h': 16, 'b': 8}[ops[0].strip()[0]]
                parts = split_ops(ops[1].strip('[]'))
                b_ = self.rd(parts[0])
                if len(parts) > 1 and imm(parts[1]):
                    ea = self.t(); self.e(f'{ea} = add i64 {b_}, {imm(parts[1])}')
                else:
                    ea = b_
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                if st:
                    v = (self.vrd(ops[0], ops[0].strip()[0]) if vec else self.rd(ops[0]))
                    if vec:
                        vt, _, _, _ = self.vty(ops[0].strip()[0])
                        #  A VECTOR STORE CANNOT BE `store atomic` IN LLVM — the type is
                        #    not integral. On x86-64 a plain store already has release
                        #    ordering; the fence supplies what the optimiser needs.
                        self.e('fence release')
                        self.e(f'store {vt} {v}, ptr {pt}, align 1')
                    else:
                        if width < 64:
                            tv = self.t(); self.e(f'{tv} = trunc i64 {v} to i{width}'); v = tv
                        self.e(f'store atomic i{width} {v}, ptr {pt} release, '
                               f'align {max(1, width // 8)}')
                elif vec:
                    vt, _, _, _ = self.vty(ops[0].strip()[0])
                    ld = self.t(); self.e(f'{ld} = load {vt}, ptr {pt}, align 1')
                    self.e('fence acquire')
                    self.vwr(ops[0], ops[0].strip()[0], ld)
                else:
                    ld = self.t()
                    self.e(f'{ld} = load atomic i{width}, ptr {pt} acquire, '
                           f'align {max(1, width // 8)}')
                    if width < 64:
                        z = self.t()
                        self.e(f'{z} = {"sext" if sgn else "zext"} i{width} {ld} to i64')
                        ld = z
                    self.wr(ops[0], ld)
            elif mn in ('irg', 'addg', 'subg', 'gmi', 'ldg'):
                #  R17-c THE MTE ADDRESS OPS, ALL FIVE, UNDER THE ZERO-TAG MODEL.
                #      irg  Xd, Xn{, Xm}   -> Xd = Xn, tag cleared   (a "random" tag of 0)
                #      addg Xd, Xn, #o, #t -> Xd = Xn + o, tag cleared
                #      subg Xd, Xn, #o, #t -> Xd = Xn - o, tag cleared
                #      gmi  Xd, Xn, Xm     -> Xd = Xm | (1 << tag(Xn)) = Xm | 1
                #      ldg  Xt, [Xn]       -> Xt with its tag replaced by memory's tag = 0
                #  `ldg x10, [x10]` NAMES THE SAME REGISTER TWICE. The value is read
                #    before the write, which the SSA form makes automatic — but only
                #    because this arm does not touch memory at all. Under the zero-tag
                #    model LDG's answer does not depend on what is stored there.
                if mn == 'gmi':
                    o = self.t(); self.e(f'{o} = or i64 {self.rd(ops[2])}, 1')
                else:
                    src = self.rd(ops[0] if mn == 'ldg' else ops[1])
                    if mn in ('addg', 'subg'):
                        t1 = self.t()
                        self.e(f'{t1} = {"add" if mn == "addg" else "sub"} '
                               f'i64 {src}, {imm(ops[2])}')
                        src = t1
                    o = self.t(); self.e(f'{o} = and i64 {src}, {MTE_TAGMASK}')
                self.wr(ops[0], o)
            elif mn in MTE_STORE:
                #  R17-c STG/ST2G STORE A TAG (a no-op here) BUT STZG/STZ2G ALSO ZERO
                #    THE GRANULE, and that half is real data the caller depends on.
                #  THE ADDRESS WRITEBACK IS REAL IN EVERY FORM. `stg x9, [x9], #0x10` is
                #    the bump in an allocator loop; dropping it turns the loop into an
                #    infinite one writing the same granule.
                nby, zero = MTE_STORE[mn]
                mem = ops[1].strip()
                post = len(ops) > 2 and ops[2].strip().startswith('#')
                pre = mem.endswith('!')
                parts = split_ops(mem.rstrip('!').strip('[]'))
                bse = parts[0]
                b_ = self.rd(bse)
                off = imm(parts[1]) if len(parts) > 1 else 0
                if post:
                    ea, wb = b_, imm(ops[2])
                else:
                    if off:
                        p = self.t(); self.e(f'{p} = add i64 {b_}, {off}'); ea = p
                    else:
                        ea = b_
                    wb = 0
                if zero:
                    pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                    for k in range(0, nby, 16):
                        q = pt
                        if k:
                            q = self.t()
                            self.e(f'{q} = getelementptr i8, ptr {pt}, i64 {k}')
                        #  align 16: the tag granule IS 16 bytes and the instruction
                        #    faults on ARM too if the address is not granule-aligned.
                        self.e(f'store <2 x i64> zeroinitializer, ptr {q}, align 16')
                if post:
                    n_ = self.t(); self.e(f'{n_} = add i64 {b_}, {wb}'); self.wr(bse, n_)
                elif pre:
                    self.wr(bse, ea)
            elif mn == 'fjcvtzs':
                #  R17-c MEASURED ON THIS LAPTOP'S SILICON OVER 33 VALUES. FJCVTZS is
                #    JavaScript's ToInt32: truncate toward zero, then take the result
                #    MODULO 2^32 — it does NOT saturate.
                #  HARDWARE, NOT MEMORY: -2147483649.0 -> +2147483647 (wrap), not
                #    -2147483648 (saturate). 4294967295.0 -> -1. 1e18 -> -1486618624.
                #    A saturating lowering is right for every small test value.
                #  AND THE Z FLAG IS NOT `sitofp(result) == x`. On -0.0 the hardware sets
                #    Z=0 while that predicate says Z=1, because IEEE oeq holds between
                #    +0.0 and -0.0. -0.0 is the value a JS engine hits most.
                sv = self.vrd(ops[1], 'd', False)
                u = self.t(); self.e(f'{u} = extractelement <1 x i64> {sv}, i64 0')
                ex = self.t(); self.e(f'{ex} = lshr i64 {u}, 52')
                ex2 = self.t(); self.e(f'{ex2} = and i64 {ex}, 2047')
                mf = self.t(); self.e(f'{mf} = and i64 {u}, 4503599627370495')
                mh = self.t(); self.e(f'{mh} = or i64 {mf}, 4503599627370496')
                sh = self.t(); self.e(f'{sh} = sub i64 {ex2}, 1075')
                # left shift when sh >= 0, right shift when sh < 0
                nsh = self.t(); self.e(f'{nsh} = sub i64 0, {sh}')
                lft = self.t(); self.e(f'{lft} = icmp sgt i64 {sh}, -1')
                #  BOTH SHIFTS ARE CLAMPED TO 63. LLVM makes a shift >= bitwidth POISON,
                #    and sh runs to +972 for 1e300 and to -1075 for a subnormal. The
                #    clamped answer is the right one anyway: >= 64 left is 0 mod 2^32, and
                #    >= 64 right is 0 for a 53-bit mantissa.
                cl = self.t(); self.e(f'{cl} = call i64 @llvm.umin.i64(i64 {sh}, i64 63)')
                cr = self.t(); self.e(f'{cr} = call i64 @llvm.umin.i64(i64 {nsh}, i64 63)')
                ls = self.t(); self.e(f'{ls} = shl i64 {mh}, {cl}')
                rs = self.t(); self.e(f'{rs} = lshr i64 {mh}, {cr}')
                mag = self.t()
                self.e(f'{mag} = select i1 {lft}, i64 {ls}, i64 {rs}')
                m32 = self.t(); self.e(f'{m32} = trunc i64 {mag} to i32')
                ng = self.t(); self.e(f'{ng} = sub i32 0, {m32}')
                sgn = self.t(); self.e(f'{sgn} = icmp slt i64 {u}, 0')
                v0 = self.t(); self.e(f'{v0} = select i1 {sgn}, i32 {ng}, i32 {m32}')
                # exp == 0x7FF (Inf/NaN) and exp < 1023 (|x| < 1) both give 0
                inf = self.t(); self.e(f'{inf} = icmp eq i64 {ex2}, 2047')
                sml = self.t(); self.e(f'{sml} = icmp ult i64 {ex2}, 1023')
                bad = self.t(); self.e(f'{bad} = or i1 {inf}, {sml}')
                res = self.t(); self.e(f'{res} = select i1 {bad}, i32 0, i32 {v0}')
                z64 = self.t(); self.e(f'{z64} = zext i32 {res} to i64')
                self.wr(ops[0], z64)
                bk = self.t(); self.e(f'{bk} = bitcast i64 {u} to double')
                rb = self.t(); self.e(f'{rb} = sitofp i32 {res} to double')
                eq = self.t(); self.e(f'{eq} = fcmp oeq double {rb}, {bk}')
                mz = self.t()
                self.e(f'{mz} = icmp ne i64 {u}, -9223372036854775808')  # not -0.0
                zf = self.t(); self.e(f'{zf} = and i1 {eq}, {mz}')
                self.e(f'store i1 {zf}, ptr %Z')
                #  N, C and V read 0 in all 33 measured rows.
                self.e('store i1 false, ptr %N')
                self.e('store i1 false, ptr %C')
                self.e('store i1 false, ptr %V')
            elif mn in CSSC and len(ops) == 3 and not VREG.match(ops[0].strip()):
                #  R17-c FEAT_CSSC gives the GPR min/max forms. 572 instructions.
                #  THE W FORM MUST BE COMPUTED IN i32. `umax w8, w1, #0x1` on the full
                #    64-bit register would compare bits the program never set, and the
                #    unsigned comparison is exactly where that shows: a wN value whose
                #    upper half holds stale bits compares larger than anything.
                w32 = ops[0].strip()[0] in 'wW'
                ity = 'i32' if w32 else 'i64'
                x = self.rd(ops[1])
                if ops[2].strip().startswith('#'):
                    #  THE CONSTANT MUST LAND IN LLVM'S SIGNED RANGE FOR ITS TYPE.
                    #    icmp compares bit patterns, so the right move is to take the
                    #    immediate modulo the width and re-centre it -- not to branch on
                    #    whether the mnemonic is the signed one, which is how an unsigned
                    #    0xFF becomes an out-of-range i8 constant llvm-as rejects.
                    w = 32 if w32 else 64
                    iv_ = imm(ops[2]) & ((1 << w) - 1)
                    if iv_ >= (1 << (w - 1)): iv_ -= (1 << w)
                    y = str(iv_)
                else:
                    y = self.rd(ops[2])
                    if w32:
                        ty_ = self.t(); self.e(f'{ty_} = trunc i64 {y} to i32'); y = ty_
                if w32:
                    tx = self.t(); self.e(f'{tx} = trunc i64 {x} to i32'); x = tx
                c = self.t(); self.e(f'{c} = icmp {CSSC[mn]} {ity} {x}, {y}')
                r = self.t(); self.e(f'{r} = select i1 {c}, {ity} {x}, {ity} {y}')
                if w32:
                    z = self.t(); self.e(f'{z} = zext i32 {r} to i64'); r = z
                self.wr(ops[0], r)
            elif CRC32.match(mn):
                #  R17-c CRC32C GOES TO THE XEON'S OWN SSE4.2 CRC32 INSTRUCTION. ARM's
                #    CRC32C and x86's CRC32 are the same reflected Castagnoli step with the
                #    same 32-bit accumulator — this is real silicon, not a software model,
                #    exactly as ARM's pmull already becomes x86's pclmulqdq.
                #  THE NON-C FORMS HAVE NO x86 INSTRUCTION. Poly 0xEDB88320 is not
                #    Castagnoli, and feeding them to the same intrinsic would produce a
                #    plausible wrong checksum that no shape check could see. They go to
                #    the bit-loop helper.
                g = CRC32.match(mn)
                bits = CRC32_BITS[g.group(2)]
                acc = self.rd(ops[1])
                a32 = self.t(); self.e(f'{a32} = trunc i64 {acc} to i32')
                val = self.rd(ops[2])
                if g.group(1) == 'c':
                    if bits == 64:
                        aw = self.t(); self.e(f'{aw} = zext i32 {a32} to i64')
                        r64 = self.t()
                        self.e(f'{r64} = call i64 @llvm.x86.sse42.crc32.64.64'
                               f'(i64 {aw}, i64 {val})')
                        r = self.t(); self.e(f'{r} = trunc i64 {r64} to i32')
                    else:
                        v = self.t()
                        self.e(f'{v} = trunc i64 {val} to i{bits}')
                        r = self.t()
                        self.e(f'{r} = call i32 @llvm.x86.sse42.crc32.32.{bits}'
                               f'(i32 {a32}, i{bits} {v})')
                else:
                    mask = (1 << bits) - 1
                    mv = self.t(); self.e(f'{mv} = and i64 {val}, {mask}')
                    r = self.t()
                    self.e(f'{r} = call i32 @__arm2x86_crcstep(i32 {a32}, i64 {mv}, '
                           f'i32 {bits}, i32 {CRC32_POLY[g.group(1)]})')
                z = self.t(); self.e(f'{z} = zext i32 {r} to i64')
                self.wr(ops[0], z)
            elif mn in ('dmb', 'dsb', 'isb'):
                #  A BARRIER IS ORDERING, NOT DATA. x86-64 is TSO, so a fence here costs
                #    nothing unless the backend needs a real one — which is the point of
                #    handing ordering to LLVM instead of picking an x86 instruction.
                self.e('fence seq_cst')
            elif mn in ('ldxr', 'ldaxr', 'ldxrb', 'ldaxrb', 'ldxrh', 'ldaxrh', 'ldxp', 'ldaxp'):
                #  R37 THE EXCLUSIVE MONITOR = A RESERVATION + ONE COMPARE-AND-SWAP.
                #    ldxr records (address, value) in thread-local state (neon_rt.c); stxr
                #    succeeds only if the reservation names ITS address AND memory still holds
                #    what was loaded, decided by one cmpxchg, so a racing writer makes it fail
                #    where real hardware would have lost the reservation.
                #  What it cannot see is ABA (another thread writing the SAME value back).
                #    Every ldxr/stxr retry loop re-reads and recomputes, so that is invisible
                #    to them; it would matter only to code that treats the monitor as a lock.
                #  A torn pair read (ldxp as two loads) is SAFE for the same reason: the
                #    stxp cmpxchg compares both halves and fails, and the loop retries.
                pair = mn.endswith('p')
                width = 8 if mn.endswith('rb') else 16 if mn.endswith('rh') else \
                    (64 if ops[0].strip()[0] == 'x' else 32)
                memtok = ops[2 if pair else 1].strip()
                if ',' in memtok or not memtok.startswith('['):
                    raise NotImplementedError(f'{mn} address form {memtok!r} at {a:x}')
                ea = self.rd(memtok.strip('[]').strip())
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                vals = []
                for k in range(2 if pair else 1):
                    pk = pt
                    if k:
                        pk = self.t(); self.e(f'{pk} = getelementptr i8, ptr {pt}, i64 {width // 8}')
                    ld = self.t()
                    self.e(f'{ld} = load atomic i{width}, ptr {pk} monotonic, align {width // 8}')
                    if width < 64:
                        z = self.t(); self.e(f'{z} = zext i{width} {ld} to i64'); ld = z
                    vals.append(ld)
                if mn.startswith('lda'):
                    self.e('fence acquire')
                self.e(f'store i64 {ea}, ptr @__arm_excl_addr')
                self.e(f'store i64 {vals[0]}, ptr @__arm_excl_lo')
                if pair:
                    self.e(f'store i64 {vals[1]}, ptr @__arm_excl_hi')
                for k, v in enumerate(vals):
                    self.wr(ops[k], v)
            elif mn in ('stxr', 'stlxr', 'stxrb', 'stlxrb', 'stxrh', 'stlxrh', 'stxp', 'stlxp'):
                #  R37 status 0 = stored, 1 = not. EVERY stxr clears the reservation,
                #    success or not, and a miss must not touch memory at all — hence a real
                #    branch, not a select around a store.
                pair = mn.endswith('p')
                width = 8 if mn.endswith('rb') else 16 if mn.endswith('rh') else \
                    (64 if ops[1].strip()[0] == 'x' else 32)
                memtok = ops[3 if pair else 2].strip()
                if ',' in memtok or not memtok.startswith('['):
                    raise NotImplementedError(f'{mn} address form {memtok!r} at {a:x}')
                cw = width * (2 if pair else 1)
                def narrow(v):
                    if width == 64: return v
                    t_ = self.t(); self.e(f'{t_} = trunc i64 {v} to i{width}'); return t_
                def join(lo, hi):
                    zl = self.t(); self.e(f'{zl} = zext i{width} {lo} to i{cw}')
                    zh = self.t(); self.e(f'{zh} = zext i{width} {hi} to i{cw}')
                    sh = self.t(); self.e(f'{sh} = shl i{cw} {zh}, {width}')
                    o_ = self.t(); self.e(f'{o_} = or i{cw} {zl}, {sh}'); return o_
                ea = self.rd(memtok.strip('[]').strip())
                new = narrow(self.rd(ops[1]))
                if pair: new = join(new, narrow(self.rd(ops[2])))
                mon = self.t(); self.e(f'{mon} = load i64, ptr @__arm_excl_addr')
                self.e('store i64 0, ptr @__arm_excl_addr')
                hit = self.t(); self.e(f'{hit} = icmp eq i64 {mon}, {ea}')
                self.wr(ops[0], '1')
                T_, J_ = f'xs{a:x}', f'xj{a:x}'
                self.e(f'br i1 {hit}, label %{T_}, label %{J_}')
                self.body.append(f'{T_}:')
                lo = self.t(); self.e(f'{lo} = load i64, ptr @__arm_excl_lo')
                exp_ = narrow(lo)
                if pair:
                    hi = self.t(); self.e(f'{hi} = load i64, ptr @__arm_excl_hi')
                    exp_ = join(exp_, narrow(hi))
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                pr = self.t()
                self.e(f'{pr} = cmpxchg ptr {pt}, i{cw} {exp_}, i{cw} {new} seq_cst seq_cst, '
                       f'align {cw // 8}')
                ok_ = self.t(); self.e(f'{ok_} = extractvalue {{ i{cw}, i1 }} {pr}, 1')
                st_ = self.t(); self.e(f'{st_} = select i1 {ok_}, i64 0, i64 1')
                self.wr(ops[0], st_)
                self.e(f'br label %{J_}')
                self.body.append(f'{J_}:')
            elif mn == 'clrex':
                self.e('store i64 0, ptr @__arm_excl_addr')
            elif mn in ('ldar', 'ldarb', 'ldarh', 'ldapr', 'ldaprb', 'ldaprh'):
                #  A LOAD-ACQUIRE IS AN ORDINARY LOAD PLUS ORDERING — always `[xn]`, no
                #    offset form exists.  NOT the same as ldxr/ldaxr: those take an
                #    EXCLUSIVE MONITOR reservation that pairs with stxr, and translating
                #    them as plain loads silently destroys the atomicity the caller is
                #    relying on. R37 models them — see the ldxr arm just above.
                width = {'ldarb': 8, 'ldaprb': 8, 'ldarh': 16, 'ldaprh': 16}.get(
                    mn, 64 if ops[0].strip()[0] == 'x' else 32)
                ea = self.rd(ops[1].strip().strip('[]').strip())
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                ld = self.t()
                self.e(f'{ld} = load atomic i{width}, ptr {pt} acquire, align {width // 8}')
                if width < 64:
                    z = self.t(); self.e(f'{z} = zext i{width} {ld} to i64'); ld = z
                self.wr(ops[0], ld)
            elif mn in ('stlr', 'stlrb', 'stlrh'):
                width = {'stlrb': 8, 'stlrh': 16}.get(
                    mn, 64 if ops[0].strip()[0] == 'x' else 32)
                ea = self.rd(ops[1].strip().strip('[]').strip())
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                v = self.rd(ops[0])
                if width < 64:
                    tv = self.t(); self.e(f'{tv} = trunc i64 {v} to i{width}'); v = tv
                self.e(f'store atomic i{width} {v}, ptr {pt} release, align {width // 8}')
            elif LSE.match(mn) or SWP.match(mn):
                m_ = LSE.match(mn)
                if m_: kind, aop, ordr, szc = m_.group(1), m_.group(2), m_.group(3), m_.group(4)
                else:
                    m_ = SWP.match(mn)
                    kind, aop, ordr, szc = 'ld', 'swp', m_.group(1), m_.group(2)
                width = {'b': 8, 'h': 16}.get(szc or '',
                                              64 if ops[0].strip()[0] == 'x' else 32)
                ea = self.rd(ops[-1].strip().strip('[]').strip())
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                sv = self.rd(ops[0])
                if width < 64:
                    tv = self.t(); self.e(f'{tv} = trunc i64 {sv} to i{width}'); sv = tv
                if aop == 'clr':
                    #  LDCLR *CLEARS*: mem &= ~operand. An `and` with the RAW operand is
                    #    the exact inverse of the instruction and looks correct for 0.
                    nv = self.t(); self.e(f'{nv} = xor i{width} {sv}, -1'); sv = nv
                rmw = {'add': 'add', 'clr': 'and', 'set': 'or', 'eor': 'xor',
                       'smax': 'max', 'smin': 'min', 'umax': 'umax', 'umin': 'umin',
                       'swp': 'xchg'}[aop]
                old = self.t()
                self.e(f'{old} = atomicrmw {rmw} ptr {pt}, i{width} {sv} {AORD[ordr or ""]}')
                #  `st<op>` HAS NO DESTINATION — same encoding, result discarded. Writing
                #    ops[1] unconditionally would store into the ADDRESS register.
                if kind == 'ld' and len(ops) > 2:
                    o = old
                    if width < 64:
                        z = self.t(); self.e(f'{z} = zext i{width} {old} to i64'); o = z
                    self.wr(ops[1], o)
            elif CAS.match(mn):
                m_ = CAS.match(mn); ordr, szc = m_.group(1), m_.group(2)
                width = {'b': 8, 'h': 16}.get(szc or '',
                                              64 if ops[0].strip()[0] == 'x' else 32)
                cv, nv = self.rd(ops[0]), self.rd(ops[1])
                ea = self.rd(ops[2].strip().strip('[]').strip())
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                if width < 64:
                    c2 = self.t(); self.e(f'{c2} = trunc i64 {cv} to i{width}'); cv = c2
                    n2 = self.t(); self.e(f'{n2} = trunc i64 {nv} to i{width}'); nv = n2
                #  THE FAILURE ORDERING MAY NOT BE STRONGER THAN THE SUCCESS ORDERING and
                #    may never be release/acq_rel — LLVM rejects the module outright.
                pr = self.t()
                #  10-05 a FAILED casa/casal is still an acquire on arm64; monotonic let the optimizer hoist later loads.
                self.e(f'{pr} = cmpxchg ptr {pt}, i{width} {cv}, i{width} {nv} '
                       f'{AORD[ordr or ""]} {"acquire" if (ordr or "").startswith("a") else "monotonic"}')
                od = self.t(); self.e(f'{od} = extractvalue {{ i{width}, i1 }} {pr}, 0')
                if width < 64:
                    z = self.t(); self.e(f'{z} = zext i{width} {od} to i64'); od = z
                self.wr(ops[0], od)          # CAS returns the OLD value in the compare reg
            elif mn in ('bfi', 'bfxil', 'bfc'):
                #  THE INSERT FORMS MERGE; THE EXTRACT FORMS (ubfx/ubfiz) REPLACE. Lowering
                #    bfi like ubfiz zeroes every neighbouring field in the destination —
                #    silent, and it survives any test whose other fields are already 0.
                w32 = ops[0].strip()[0] in 'wW'
                dw = 32 if w32 else 64
                dst = self.rd(ops[0])
                if mn == 'bfc':
                    lsb, wd = imm(ops[1]), imm(ops[2]); src = '0'
                else:
                    lsb, wd = imm(ops[2]), imm(ops[3]); src = self.rd(ops[1])
                fm = (1 << wd) - 1
                if mn == 'bfxil':
                    sh = self.t(); self.e(f'{sh} = lshr i64 {src}, {lsb}')
                    fv = self.t(); self.e(f'{fv} = and i64 {sh}, {fm}')
                    keep = ((1 << dw) - 1) & ~fm
                else:
                    f0 = self.t(); self.e(f'{f0} = and i64 {src}, {fm}')
                    fv = self.t(); self.e(f'{fv} = shl i64 {f0}, {lsb}')
                    keep = ((1 << dw) - 1) & ~(fm << lsb)
                kv = self.t(); self.e(f'{kv} = and i64 {dst}, {keep}')
                o = self.t(); self.e(f'{o} = or i64 {kv}, {fv}'); self.wr(ops[0], o)
            elif mn in ('fcmp', 'fcmpe'):
                #  THE ARM FP FLAG MAPPING, AND IT IS NOT THE INTEGER ONE:
                #      EQ  -> N0 Z1 C1 V0      LT        -> N1 Z0 C0 V0
                #      GT  -> N0 Z0 C1 V0      UNORDERED -> N0 Z0 C1 V1
                #    so C is `not olt` and V is `uno`.  Reusing setflags() here gets every
                #    NaN comparison wrong in the direction that still looks right on
                #    ordinary numbers.
                a0 = ops[0].strip(); ft = FTY[a0[0]]
                xv = self.vrd(a0, a0[0], True)
                xe = self.t(); self.e(f'{xe} = extractelement <1 x {ft}> {xv}, i64 0')
                b1 = ops[1].strip()
                if b1.startswith('#'):
                    ye = '0.0'                       # ARM allows only #0.0 as the immediate
                else:
                    yv = self.vrd(b1, b1[0], True)
                    ye = self.t(); self.e(f'{ye} = extractelement <1 x {ft}> {yv}, i64 0')
                eq = self.t(); self.e(f'{eq} = fcmp oeq {ft} {xe}, {ye}')
                lt = self.t(); self.e(f'{lt} = fcmp olt {ft} {xe}, {ye}')
                un = self.t(); self.e(f'{un} = fcmp uno {ft} {xe}, {ye}')
                nc = self.t(); self.e(f'{nc} = xor i1 {lt}, true')
                self.e(f'store i1 {lt}, ptr %N'); self.e(f'store i1 {eq}, ptr %Z')
                self.e(f'store i1 {nc}, ptr %C'); self.e(f'store i1 {un}, ptr %V')
            elif mn == 'fcvt':
                d_, s_ = ops[0].strip(), ops[1].strip()
                dt, st = FTY[d_[0]], FTY[s_[0]]
                sv = self.vrd(s_, s_[0], True)
                se = self.t(); self.e(f'{se} = extractelement <1 x {st}> {sv}, i64 0')
                op_ = 'fpext' if FBITS[dt] > FBITS[st] else 'fptrunc'
                r = self.t(); self.e(f'{r} = {op_} {st} {se} to {dt}')
                iv = self.t()
                self.e(f'{iv} = insertelement <1 x {dt}> poison, {dt} {r}, i64 0')
                self.vwr(d_, d_[0], iv, True)
            elif mn in ('scvtf', 'ucvtf') and GPRT.match(ops[1].strip()):
                d_, s_ = ops[0].strip(), ops[1].strip()
                dt = FTY[d_[0]]
                sw = 64 if s_[0] == 'x' else 32
                v = self.rd(s_); tv = v
                if sw == 32:
                    tr = self.t(); self.e(f'{tr} = trunc i64 {v} to i32'); tv = tr
                r = self.t()
                self.e(f'{r} = {"sitofp" if mn == "scvtf" else "uitofp"} i{sw} {tv} to {dt}')
                #  THE FIXED-POINT FORM: `scvtf d0, x0, #8` divides by 2**8 AFTER the
                #    convert.  Dropping the #fbits operand scales the result by 256.
                if len(ops) > 2 and ops[2].strip().startswith('#'):
                    sc = self.t()
                    #  10-23 AN LLVM FLOAT CONSTANT MUST BE EXACT, so %.8e is wrong: 9 significant digits
                    #    turned 2**64 into 1.84467441e+19 and the whole module died in the verifier with
                    #    "floating point constant invalid for type" (macOS 27's parsec-fbf, preflight.ll:1021144).
                    #    A power of two prints exactly with .1f — the same form the sibling fixed-point site uses.
                    self.e(f'{sc} = fdiv {dt} {r}, {float(1 << imm(ops[2])):.1f}'); r = sc
                iv = self.t()
                self.e(f'{iv} = insertelement <1 x {dt}> poison, {dt} {r}, i64 0')
                self.vwr(d_, d_[0], iv, True)
            elif FCVTR.match(mn) and VREG.match(ops[1].strip()):
                #  EIGHT MNEMONICS, ONE SHAPE: round in the named mode, THEN convert.
                #    fcvtas/au ties-away fcvtms/mu floor fcvtns/nu ties-even ·
                #    fcvtps/pu ceil fcvtzs/zu truncate.
                #  REPLACES the R6 arm that handled only fcvtzs/fcvtzu. fptosi ALWAYS
                #    truncates, so emitting it bare turns fcvtms/fcvtps/fcvtas into
                #    fcvtzs — correct for z, off by one for the other six on exactly the
                #    inputs they exist to handle. The old arm is GONE, not beside this.
                #  R8: THREE THINGS THE R7 ARM COULD NOT SEE, all measured in the cache:
                #    (a) `fcvtzs s0, s0` puts the INTEGER in the FP register file — 18 of
                #        the 170 remaining failures. The old guard demanded a GPR dest.
                #    (b) `fcvtzu d31, d31, #0x1` is the FIXED-POINT form: scale by 2^fbits
                #        BEFORE converting. Dropping the third operand is an answer that is
                #        wrong by a factor of two and looks entirely ordinary.
                #    (c) the conversion SATURATES (see satcvt) — it did not before.
                g = FCVTR.match(mn)
                x, ft = self.fsrd(ops[1])
                if len(ops) > 2 and ops[2].strip().startswith('#'):
                    #  the FIXED-POINT form scales by 2^fbits before converting.
                    #    A power of two is exactly representable at every width, so a
                    #    decimal literal is exact here — no hex float needed.
                    fb_ = imm(ops[2])
                    sc = self.t()
                    self.e(f'{sc} = fmul {ft} {x}, {float(2 ** fb_):.1f}')
                    x = sc
                rv = x if g.group(1) == 'z' else self.fcall(FCVTRND[g.group(1)], ft, x)
                d_ = ops[0].strip()
                sgn = g.group(2) == 's'
                sfx_f = {'half': 'f16', 'float': 'f32', 'double': 'f64'}[ft]
                if VREG.match(d_):
                    dw = {'b': 8, 'h': 16, 's': 32, 'd': 64}[d_[0]]
                    r = self.satcvt(ft, f'i{dw}', rv, sgn, sfx_f, f'i{dw}')
                    ivv = self.t()
                    self.e(f'{ivv} = insertelement <1 x i{dw}> poison, i{dw} {r}, i64 0')
                    self.vwr(d_, d_[0], ivv, False)
                else:
                    dw = 64 if d_[0] == 'x' else 32
                    r = self.satcvt(ft, f'i{dw}', rv, sgn, sfx_f, f'i{dw}')
                    if dw < 64:
                        z = self.t(); self.e(f'{z} = zext i32 {r} to i64'); r = z
                    self.wr(d_, r)
            elif mn == 'fcsel':
                d_ = ops[0].strip(); ft = FTY[d_[0]]
                c = self.cond(ops[3].strip())
                A = self.vrd(ops[1].strip(), d_[0], True)
                B = self.vrd(ops[2].strip(), d_[0], True)
                o = self.t()
                self.e(f'{o} = select i1 {c}, <1 x {ft}> {A}, <1 x {ft}> {B}')
                self.vwr(d_, d_[0], o, True)
            elif mn in FRINTS:
                x, ft = self.fsrd(ops[1])
                self.fswr(ops[0], self.fcall(FRINTS[mn], ft, x), ft)
            elif mn in ('fmadd', 'fmsub', 'fnmadd', 'fnmsub'):
                #  ARM NAMES THE ACCUMULATOR LAST: `fmadd d0,d1,d2,d3` is d1*d2 + d3.
                #      fmadd  Rd =  Ra + Rn*Rm      fmsub  Rd =  Ra - Rn*Rm
                #      fnmadd Rd = -Ra - Rn*Rm      fnmsub Rd = -Ra + Rn*Rm
                #  `fnmsub` IS NOT `-(fmsub)`. It negates the ACCUMULATOR only, so
                #    reading the four names as symmetric flips the sign of the product
                #    term and the answer stays finite, plausible, and wrong.
                #  FUSED — ONE rounding. fmul+fadd is two and differs in the last ulp,
                #    which is precisely where libsystem_m is measured.
                n_, ft = self.fsrd(ops[1])
                m_, _ = self.fsrd(ops[2])
                acc, _ = self.fsrd(ops[3])
                if mn in ('fmsub', 'fnmadd'):
                    g = self.t(); self.e(f'{g} = fneg {ft} {n_}'); n_ = g
                if mn in ('fnmadd', 'fnmsub'):
                    g = self.t(); self.e(f'{g} = fneg {ft} {acc}'); acc = g
                #  10-03 ARM NaN rules: addend first, operands as ARM negates them (arm_nan)
                rr = self.arm_nan(self.fcall('fma', ft, n_, m_, acc), [acc, n_, m_], ft, ft, None, (acc, n_, m_))
                self.fswr(ops[0], rr, ft)
            elif mn == 'fnmul':
                a_, ft = self.fsrd(ops[1]); b_, _ = self.fsrd(ops[2])
                p = self.t(); self.e(f'{p} = fmul {ft} {a_}, {b_}')
                p = self.arm_nan(p, [a_, b_], ft, ft, None)   #  10-03 ARM: FPNeg(FPMul) — the chosen NaN is negated too
                g = self.t(); self.e(f'{g} = fneg {ft} {p}')
                self.fswr(ops[0], g, ft)
            elif mn in FMINMAX and VREG.match(ops[0].strip()):
                a_, ft = self.fsrd(ops[1]); b_, _ = self.fsrd(ops[2])
                self.fswr(ops[0], self.fcall(FMINMAX[mn], ft, a_, b_), ft)
            elif mn in ('fccmp', 'fccmpe'):
                #  THE CONDITIONAL COMPARE: if the condition holds, set the flags from
                #    the compare; if it does NOT, load the literal #nzcv instead. That
                #    literal is how ARM chains `a < b && c < d` with no branch.
                #  The flag mapping is fcmp's, NOT setflags' — see the fcmp arm above.
                #    Reusing the integer mapping gets every NaN case wrong in the
                #    direction that still looks right on ordinary numbers.
                p = self.cond(ops[3].strip())
                x, ft = self.fsrd(ops[0])
                b1 = ops[1].strip()
                y = '0.0' if b1.startswith('#') else self.fsrd(b1)[0]
                nz = imm(ops[2])
                eq = self.t(); self.e(f'{eq} = fcmp oeq {ft} {x}, {y}')
                lt = self.t(); self.e(f'{lt} = fcmp olt {ft} {x}, {y}')
                un = self.t(); self.e(f'{un} = fcmp uno {ft} {x}, {y}')
                nc = self.t(); self.e(f'{nc} = xor i1 {lt}, true')
                #  #nzcv IS PACKED N:Z:C:V from bit 3 down to bit 0.
                for nm_, bit, got in (('N', 3, lt), ('Z', 2, eq),
                                      ('C', 1, nc), ('V', 0, un)):
                    lit = 'true' if (nz >> bit) & 1 else 'false'
                    sel = self.t()
                    self.e(f'{sel} = select i1 {p}, i1 {got}, i1 {lit}')
                    self.e(f'store i1 {sel}, ptr %{nm_}')
            elif mn in ('scvtf', 'ucvtf') and VREG.match(ops[1].strip()):
                #  THE SOURCE IS AN INTEGER SITTING IN THE FP FILE (`ucvtf d0, d0`).
                #  Reading it as a double would REINTERPRET the bits instead of
                #    converting them, and 1 would come out as 5e-324.
                d_, s_ = ops[0].strip(), ops[1].strip()
                dt = FTY[d_[0]]; sw = FBITS[FTY[s_[0]]]
                sv = self.vrd(s_, s_[0], False)
                se = self.t(); self.e(f'{se} = extractelement <1 x i{sw}> {sv}, i64 0')
                r = self.t()
                self.e(f'{r} = {"sitofp" if mn == "scvtf" else "uitofp"} '
                       f'i{sw} {se} to {dt}')
                if len(ops) > 2 and ops[2].strip().startswith('#'):
                    sc = self.t()
                    #  10-23 AN LLVM FLOAT CONSTANT MUST BE EXACT, so %.8e is wrong: 9 significant digits
                    #    turned 2**64 into 1.84467441e+19 and the whole module died in the verifier with
                    #    "floating point constant invalid for type" (macOS 27's parsec-fbf, preflight.ll:1021144).
                    #    A power of two prints exactly with .1f — the same form the sibling fixed-point site uses.
                    self.e(f'{sc} = fdiv {dt} {r}, {float(1 << imm(ops[2])):.1f}'); r = sc
                self.fswr(d_, r, dt)
            elif mn in ('ngc', 'ngcs'):
                #  `ngc Rd, Rm` IS `sbc Rd, zr, Rm` — Rd = NOT(Rm) + C.
                #  IT IS NOT `neg` WITH FLAGS. Dropping the carry-in makes it right
                #    exactly when C happens to be 1, which is most of the time in the
                #    multi-word arithmetic sequences where ngc actually appears.
                d_ = ops[0].strip()
                bw = 32 if d_[0] in 'wW' else 64
                mask = (1 << bw) - 1
                v = self.rd(ops[1])
                nb = self.t(); self.e(f'{nb} = xor i64 {v}, {mask}')
                cf = self.t(); self.e(f'{cf} = load i1, ptr %C')
                cz = self.t(); self.e(f'{cz} = zext i1 {cf} to i64')
                sm = self.t(); self.e(f'{sm} = add i64 {nb}, {cz}')
                res = self.t(); self.e(f'{res} = and i64 {sm}, {mask}')
                if mn == 'ngcs':
                    #  C is the carry OUT of the bw-bit add, so it is read from the
                    #    UNMASKED sum. Reading it from res is always 0.
                    sh = self.t(); self.e(f'{sh} = lshr i64 {res}, {bw - 1}')
                    n_ = self.t(); self.e(f'{n_} = trunc i64 {sh} to i1')
                    z_ = self.t(); self.e(f'{z_} = icmp eq i64 {res}, 0')
                    #  10-03 (certifier vs M4): `sm > mask` can never hold in i64 at bw = 64. The carry out of NOT(Rm)+C
                    #    is exactly C && NOT(Rm) == all ones at the width — true for both widths.
                    nbm = self.t(); self.e(f'{nbm} = and i64 {nb}, {mask}')
                    allo = self.t(); self.e(f'{allo} = icmp eq i64 {nbm}, {mask}')
                    c_ = self.t(); self.e(f'{c_} = and i1 {allo}, {cf}')
                    bh = self.t(); self.e(f'{bh} = lshr i64 {nb}, {bw - 1}')
                    b_ = self.t(); self.e(f'{b_} = trunc i64 {bh} to i1')
                    # V: operands 0 and ~Rm agree in sign (both non-negative) and the
                    #    result is negative.
                    nb2 = self.t(); self.e(f'{nb2} = xor i1 {b_}, true')
                    v_ = self.t(); self.e(f'{v_} = and i1 {nb2}, {n_}')
                    self.e(f'store i1 {n_}, ptr %N'); self.e(f'store i1 {z_}, ptr %Z')
                    self.e(f'store i1 {c_}, ptr %C'); self.e(f'store i1 {v_}, ptr %V')
                self.wr(d_, res)
            elif mn == 'mrs':
                #  THE ONLY SYSTEM REGISTER USERLAND READS IS THE THREAD POINTER.
                #    `mrs x0, tpidrro_el0` is how _pthread_getspecific, the stack
                #    protector and the ObjC fast paths find the TSD. On x86-64 macOS the
                #    same base is %gs:0, which LLVM spells as a load from addrspace(256).
                #    So this is a REGISTER RENAME, not an emulation — it lowers to one
                #    `movq %gs:0, %rax`.
                #  EVERY OTHER SYSTEM REGISTER ABORTS. fpcr/fpsr/ctr_el0 have no x86
                #    equivalent, and inventing a value makes a control path take the
                #    wrong branch with nothing in the log to say why.
                sr = ops[1].strip().lower()
                #  R23 TPIDR2_EL0 IS A SECOND, SEPARATE THREAD REGISTER. It is NOT the
                #    TSD base — measured on an M4, the two read different values in the same
                #    thread — so it must not fold into the %gs path. It is the SME lazy-save
                #    pointer, and a thread-local slot reproduces it exactly.
                if sr == 'tpidr2_el0':
                    v = self.t(); self.e(f'{v} = load i64, ptr @__arm_tpidr2')
                    self.wr(ops[0], v)
                elif sr in ('tpidrro_el0', 'tpidr_el0'):
                    #  10-20 %gs:0 is pthread_self, the START of struct _pthread; the arm register is the
                    #    address of the TSD array INSIDE it. Without @__arm_tsd_off (measured at start-up in
                    #    sysreg_rt.c) every inline TSD slot read was early — logd's unfair lock named a dead
                    #    owner and aborted the boot (ulockprobe: port 0x565918a0 vs 0x103).
                    p = self.t(); self.e(f'{p} = inttoptr i64 0 to ptr addrspace(256)')
                    s_ = self.t(); self.e(f'{s_} = load i64, ptr addrspace(256) {p}')
                    o_ = self.t(); self.e(f'{o_} = load i64, ptr @__arm_tsd_off')
                    v = self.t(); self.e(f'{v} = add i64 {s_}, {o_}')
                    self.wr(ops[0], v)
                elif sr == 'nzcv':
                    #  R24 THE FLAGS ARE ALREADY OURS. N/Z/C/V are the %N %Z %C %V
                    #    allocas every compare writes and every b.cc reads, and NZCV is
                    #    just those four at bits 31/30/29/28 — measured, not assumed:
                    #    `cmp x0,x0` reads 0x60000000 (Z,C) and `cmp 1,2` reads 0x80000000.
                    #  ZEXT, NEVER SEXT. An i1 sign-extended is all ones, which would put
                    #    garbage in bits 27..0 of a register the guest may well compare
                    #    against a constant.
                    acc = '0'
                    for nm, sh in (('N', 31), ('Z', 30), ('C', 29), ('V', 28)):
                        b = self.t(); self.e(f'{b} = load i1, ptr %{nm}')
                        w = self.t(); self.e(f'{w} = zext i1 {b} to i64')
                        s = self.t(); self.e(f'{s} = shl i64 {w}, {sh}')
                        nxt = self.t(); self.e(f'{nxt} = or i64 {acc}, {s}')
                        acc = nxt
                    self.wr(ops[0], acc)
                elif sr == 'svcr':
                    #  R24 READ THE STATE smstart/smstop MAINTAINS. Before this patch
                    #    those six spellings tracked no mode at all, so this read had
                    #    nothing to return but an invention.
                    v = self.t(); self.e(f'{v} = load i64, ptr @__arm_svcr')
                    self.wr(ops[0], v)
                elif sr == 's3_6_c15_c1_5':
                    #  R38 the TPRO permission register, a measured per-thread slot.
                    v = self.t(); self.e(f'{v} = load i64, ptr @__arm_sprr')
                    self.wr(ops[0], v)
                elif sr == 'fpcr':
                    #  10-03 the per-thread shadow the write below keeps (the game's 4 reads + 4 writes)
                    v = self.t(); self.e(f'{v} = load i64, ptr @__arm_fpcr')
                    self.wr(ops[0], v)
                elif sr in ('cntpct_el0', 'cntvct_el0'):
                    #  10-03 the generic timer as the M4 runs it: 1 GHz (cntfrq_el0 = 1000000000, measured on the mini).
                    #    Galaxy's clock function is exactly `mrs x0, CNTPCT_EL0; ret`.
                    v = self.t(); self.e(f'{v} = call i64 @__arm2x86_cntpct()')
                    self.wr(ops[0], v)
                elif sr == 'cntfrq_el0':
                    self.wr(ops[0], '1000000000')   #  the M4's measured cntfrq (the M1's is 24 MHz); @__arm2x86_cntpct ticks at it
                elif sr in R38_NOFEAT:
                    self.e(f'call void @__arm2x86_nofeature(i64 {a}, i64 {R38_NOFEAT[sr]})')
                    self.e('unreachable'); term = True
                else:
                    raise NotImplementedError(f'mrs {sr} at {a:x} — no x86 equivalent')
            elif mn in R38_NOFEAT:
                #  R38 macOS 27 adds 223 of these (dyld, libobjc, libpthread, libdyld,
                #    libCoreVMClient); Tahoe 26.5.1 has 0. Every one sits behind
                #    `mrs TINDEX_EL0`, which sits behind the commpage support byte, which is
                #    0 here. Unreachable by construction, so it aborts by name if reached.
                self.e(f'call void @__arm2x86_nofeature(i64 {a}, i64 {R38_NOFEAT[mn]})')
                self.e('unreachable'); term = True
            elif mn == 'msr':
                #  R23 THE WRITE DIRECTION, WHICH HAD NO HANDLER AT ALL. 3,447 of these.
                #  THE OPERAND SPELLING IS UPPERCASE in the disassembly (`msr TPIDR2_EL0,
                #    xzr`) while mrs prints lowercase, so this normalises rather than
                #    trusting either.
                #  EVERY OTHER SYSTEM REGISTER ABORTS. A silent write to a register we do
                #    not model makes the matching read return a stale value, and the fault
                #    would surface as ZA not being saved — arbitrarily far from here.
                sr = ops[0].strip().lower()
                if sr == 'nzcv':
                    #  R24 THE WRITE REALLY REACHES THE FLAGS, MEASURED: on the M4,
                    #    `msr nzcv, 0x40000000` followed by `csetm eq` returns all ones.
                    #    So this must land in the SAME allocas a compare writes, not in a
                    #    shadow word — otherwise the next b.eq reads the old condition and
                    #    the branch goes the wrong way with nothing in the log.
                    #  TRUNC TAKES THE LOW BIT, which is why each field is shifted down
                    #    to bit 0 first rather than masked in place.
                    v = self.rd(ops[1])
                    for nm, sh in (('N', 31), ('Z', 30), ('C', 29), ('V', 28)):
                        t_ = self.t(); self.e(f'{t_} = lshr i64 {v}, {sh}')
                        b = self.t(); self.e(f'{b} = trunc i64 {t_} to i1')
                        self.e(f'store i1 {b}, ptr %{nm}')
                elif sr == 'tpidr2_el0':
                    v = self.rd(ops[1])
                    self.e(f'store i64 {v}, ptr @__arm_tpidr2')
                elif sr == 's3_6_c15_c1_5':
                    #  R38 the write half. libpthread reads it straight back and `brk`s
                    #    on a mismatch, so the round trip is load-bearing, not cosmetic.
                    v = self.rd(ops[1])
                    self.e(f'store i64 {v}, ptr @__arm_sprr')
                elif sr == 'fpcr':
                    #  10-03 kept for the read AND applied: FZ -> MXCSR FTZ+DAZ, RMode -> MXCSR RC (M1: 1e-40f*1 = 0 under FZ).
                    #  DN (default NaN) has no x86 mode: only a NaN's payload bits can differ — the same legal difference
                    #    the shader rulers already accept.
                    v = self.rd(ops[1])
                    self.e(f'store i64 {v}, ptr @__arm_fpcr')
                    self.e(f'call void @__arm2x86_set_fpcr(i64 {v})')
                elif sr in R38_NOFEAT:
                    self.e(f'call void @__arm2x86_nofeature(i64 {a}, i64 {R38_NOFEAT[sr]})')
                    self.e('unreachable'); term = True
                else:
                    raise NotImplementedError(f'msr {sr} at {a:x} — no x86 equivalent')
            elif mn in ('fcvtl', 'fcvtl2', 'fcvtn', 'fcvtn2') and len(ops) == 2 \
                    and VARRREG.match(ops[0].strip()):
                #  R8 THE ROUTING FIX — 40 of the 170. These carry the arrangement on
                #    the REGISTERS because the two ends differ in shape, so the `mn.arr`
                #    dispatch upstream never matched them.
                #  THE `2` FORMS USE THE HIGH HALF of the source (fcvtl2) or write the
                #    HIGH half of the destination (fcvtn2). Treating them as the base form
                #    silently converts the wrong four lanes.
                dm = VARRREG.match(ops[0].strip()); sm = VARRREG.match(ops[1].strip())
                if not sm:
                    raise NotImplementedError(f'{mn} operands {ops} at {a:x}')
                wide = mn.startswith('fcvtl')
                warr = dm.group(2) if wide else sm.group(2)
                narr = sm.group(2) if wide else dm.group(2)
                #  R9 THE `2` FORM PRINTS THE FULL 128-BIT SIDE, so the half it
                #    actually touches is HALF[] of what the operand says:
                #      fcvtl2 v0.2d, v1.4s   reads lanes 2,3 of v1 (a 2s), widens to 2d
                #      fcvtn2 v0.4s, v1.2d   narrows 2d to a 2s and writes lanes 2,3 of v0
                #    Applying HALF to the printed narrow side makes both fall out of the
                #    SAME NARROW_SRC pairing the base forms already use.
                hi2 = mn.endswith('2')
                if hi2:
                    narr = HALF.get(narr, narr)
                if NARROW_SRC.get(warr) != narr:
                    raise NotImplementedError(f'{mn} {warr}<-{narr} at {a:x}')
                wty, wn, wel, _ = self.vty(warr, True)
                nty, nn, nel, _ = self.vty(narr, True)
                if wide:
                    s = (self.vrd_hi(ops[1].strip(), narr, True) if hi2
                         else self.vrd(ops[1].strip(), narr, True))
                    r = self.t(); self.e(f'{r} = fpext {nty} {s} to {wty}')
                    self.vwr(ops[0].strip(), warr, r, True)
                else:
                    s = self.vrd(ops[1].strip(), warr, True)
                    r = self.t(); self.e(f'{r} = fptrunc {wty} {s} to {nty}')
                    if hi2:
                        self.vwr_hi(ops[0].strip(), narr, r, True)
                    else:
                        self.vwr(ops[0].strip(), narr, r, True)
            elif mn == 'fabd' and len(ops) == 3 and VREG.match(ops[0].strip()):
                #  scalar FABD — |a - b|. Three in the cache tail.
                x, ft = self.fsrd(ops[1]); y, _ = self.fsrd(ops[2])
                d = self.t(); self.e(f'{d} = fsub {ft} {x}, {y}')
                r = self.fcall('fabs', ft, d)
                self.fswr(ops[0], r, ft)
            elif mn in ('adc', 'sbc', 'adcs', 'sbcs') and len(ops) == 3:
                #  R8 ADD/SUB WITH CARRY — the 64-bit-arithmetic tail in libsystem_m.
                #  ARM'S BORROW IS INVERTED: for SBC the carry flag means NO borrow, so
                #    the addend is (C - 1), not -C. Getting that backwards is off by one on
                #    exactly the inputs a multiword subtract exists to handle.
                w32 = ops[0].strip()[0] in 'wW'
                bw = 32 if w32 else 64
                ity = f'i{bw}'
                xa, xb = self.rd(ops[1]), self.rd(ops[2])
                if w32:
                    t1 = self.t(); self.e(f'{t1} = trunc i64 {xa} to i32'); xa = t1
                    t2 = self.t(); self.e(f'{t2} = trunc i64 {xb} to i32'); xb = t2
                cf = self.t(); self.e(f'{cf} = load i1, ptr %C')
                cz = self.t(); self.e(f'{cz} = zext i1 {cf} to {ity}')
                if mn.startswith('sbc'):
                    ny = self.t(); self.e(f'{ny} = xor {ity} {xb}, -1'); xb = ny
                s1 = self.t(); self.e(f'{s1} = add {ity} {xa}, {xb}')
                s2 = self.t(); self.e(f'{s2} = add {ity} {s1}, {cz}')
                #  plain ADC/SBC leave NZCV untouched — that is the whole difference
                #    from ADCS/SBCS, which now set them through setflags_carry().
                #  R9 xb IS ALREADY INVERTED for sbcs, which is exactly right: ARM
                #    defines SBCS's flags on a + NOT(b) + C, the same addition it computes.
                if mn.endswith('s'):
                    self.setflags_carry(w32, xa, xb, cf)
                res = s2
                if w32:
                    z = self.t(); self.e(f'{z} = zext i32 {s2} to i64'); res = z
                self.wr(ops[0], res)
            elif mn in ('casp', 'caspa', 'caspl', 'caspal') and len(ops) == 5:
                #  R9 CASP compares an EVEN/ODD REGISTER PAIR against memory as one
                #    128-bit quantity and swaps the second pair in on a match.
                #  CAS ALWAYS WRITES THE OLD MEMORY VALUE BACK INTO ITS COMPARAND, match
                #    or no match. Dropping that write leaves the caller's retry loop
                #    comparing the same stale value forever — a hang, not a wrong number.
                w32 = ops[0].strip()[0] in 'wW'
                if w32:
                    raise NotImplementedError(f'{mn} 32-bit pair form at {a:x}')
                def _pair(lo_t, hi_t):
                    l = self.rd(lo_t); h = self.rd(hi_t)
                    zl = self.t(); self.e(f'{zl} = zext i64 {l} to i128')
                    zh = self.t(); self.e(f'{zh} = zext i64 {h} to i128')
                    sh = self.t(); self.e(f'{sh} = shl i128 {zh}, 64')
                    o = self.t(); self.e(f'{o} = or i128 {zl}, {sh}'); return o
                cmpv = _pair(ops[0], ops[1])
                newv = _pair(ops[2], ops[3])
                addr = self.rd(split_ops(ops[4].strip().strip('[]'))[0])
                pp = self.t(); self.e(f'{pp} = inttoptr i64 {addr} to ptr')
                cx = self.t()
                self.e(f'{cx} = cmpxchg ptr {pp}, i128 {cmpv}, i128 {newv} seq_cst seq_cst')
                old = self.t(); self.e(f'{old} = extractvalue {{ i128, i1 }} {cx}, 0')
                ol = self.t(); self.e(f'{ol} = trunc i128 {old} to i64')
                oh0 = self.t(); self.e(f'{oh0} = lshr i128 {old}, 64')
                oh = self.t(); self.e(f'{oh} = trunc i128 {oh0} to i64')
                self.wr(ops[0], ol); self.wr(ops[1], oh)
            elif mn == 'extr' and len(ops) == 4:
                #  EXTR is a funnel shift: the low bits of a 2N-bit concatenation.
                #  SHIFT 0 IS NOT A NO-OP TO LLVM — `shl i64 x, 64` is POISON, so the
                #    obvious (hi << (64-n)) | (lo >> n) is undefined at n == 0, which is a
                #    legal encoding meaning "return the low register". Special-cased.
                w32 = ops[0].strip()[0] in 'wW'
                bw = 32 if w32 else 64
                ity = f'i{bw}'
                hi, lo, sh = self.rd(ops[1]), self.rd(ops[2]), imm(ops[3])
                if w32:
                    t1 = self.t(); self.e(f'{t1} = trunc i64 {hi} to i32'); hi = t1
                    t2 = self.t(); self.e(f'{t2} = trunc i64 {lo} to i32'); lo = t2
                if sh == 0:
                    res = lo
                else:
                    a1 = self.t(); self.e(f'{a1} = shl {ity} {hi}, {bw - sh}')
                    b1 = self.t(); self.e(f'{b1} = lshr {ity} {lo}, {sh}')
                    res = self.t(); self.e(f'{res} = or {ity} {a1}, {b1}')
                if w32:
                    z = self.t(); self.e(f'{z} = zext i32 {res} to i64'); res = z
                self.wr(ops[0], res)
            else:
                raise NotImplementedError(f'{mn} at {a:x}  (ops={ops})')

        if eh_pend: self.eh_invoke(*eh_pend); eh_pend = None
        #  R12 WAS `ret i64 0`. Falling off the end is already a bug, but returning a
        #    manufactured 0 hides it behind a plausible value; return what the registers
        #    actually hold so the wrongness is the caller's real state.
        if not term:
            la, lmn, _ = self.insns[-1]
            if lmn != 'bl' and la + 4 in self.known:
                #  10-03 RUNNING OFF THE END INTO THE NEXT FUNCTION (81 in Cyberpunk): the function-starts table split one
                #    real function in two. It continues there — abi_scan marks the successor full-file, so every register
                #    goes with it.  WAS a return: the caller got control back halfway through a function.
                self.ft_targets.add(la + 4); self.e(f'br label %FT{la + 4:x}')
            else:
                self.abi_ret()   # after a final `bl`: a noreturn call (35,422 in Cyberpunk: abort, __cxa_throw, ...)
        for t in sorted(self.ft_targets):
            self.body.append(f'FT{t:x}:')
            if t in self.known:
                self.tail_call(t)
            else:
                self.e(f'call void @__arm2x86_unimplemented(i64 {t})'); self.e('unreachable')

        for (lp_, cl_), nm_ in self.eh_pads.items(): self.eh_pad(lp_, cl_, nm_)
        #  EVERY out-of-function target aborts LOUDLY. Never a silent plausible answer.
        for t in sorted(out_targets):
            self.body.append(f'OUT{t:x}:')
            if t in self.known:
                #  10-03 A CONDITIONAL TAIL BRANCH into another function (`b.ls 0x1000b62f0`, Cyberpunk build27: hand-written
                #    decoder code the function-starts table split into fragments; 46 in the program). Taken, it is a tail call —
                #    the same lowering as running off the end (FT).  WAS: the abort below, on an engine job thread.
                self.tail_call(t)
                continue
            self.e(f'call void @__arm2x86_unimplemented(i64 {t})')
            self.e('unreachable')
        return out_targets

    def tail_call(self, t, carry=False):
        """ 10-03 A TAIL TRANSFER REUSES THE FRAME, AS THE HARDWARE'S BRANCH DOES. It WAS call-then-ret: a loop that crosses
           a fragment boundary (Cyberpunk's decoder, 1000b62f0 <-> 1000b6324 via fall-through + `b.ls`) grew one x86 frame per
           iteration and six engine threads overflowed their stacks at once (build30, fault address == rsp). Now `musttail`:
           every fn_ has the same prototype, and the callee's outputs in @__arm_xr ARE ours.  The one exception: an
           OFF-contract caller tail-calling an ON-contract callee must hand its own file back after the call (XR_TAIL_KEEP
           logic) — that keeps the call-then-ret form (it cannot loop: the callee keeps the contract)."""
        #  10-21 DO NOT WIDEN THIS TO `self.lo in NONABI and STUB_CC[t] == 3`. It was tried and it
        #    REGRESSED EVERY OPTIMIZATION LEVEL. The bug it aimed at is real and still open: -Osize hoists
        #    "clear the frame marker + pop the frame + `b` the async stub" into a shared three-instruction
        #    helper (_OUTLINED_FUNCTION_51: `and x29, x29, #0xefff…` / `add sp, sp, #0x20` /
        #    `b <withTaskGroup stub>`) that sets up NO arguments — its CALLER did, before `bl` into it — so
        #    carry_at() correctly finds no x6/x7, the adapter takes async_defer (six integer registers and NO
        #    stack words), and an eight-argument async callee such as
        #    `withTaskGroup(of:returning:isolation:body:)` loses its 7th/8th and calls a garbage `body` closure
        #    (Bus error, rip == fault address == 0x6000020e0160, a malloc-zone address).
        #     BUT "off-contract AND an async stub" also catches ordinary off-contract fragments that DO set up
        #    their own arguments, and forcing those onto async_now changes the nesting protocol. Measured with
        #    that widening in: asyncmx died on the `child task` arm (`await t.value`, an async import) with
        #    SIGILL at -Onone, -O AND -Osize, 2 of 19 arms — against 19/19 rc=0 for the same tree without it.
        #     AND A SECOND ATTEMPT ALSO FAILED, so do not reach for the caller's shape at all. Narrowing it to
        #    the outlined epilogue itself (marker CLEARED by `and x29, x29, #0xefff…`, no argument register
        #    written) fixed -Onone and -O — both back to 19/19 rc=0 — and still broke -Osize, now on the
        #    `buffered stream 0..<100000` arm: SIGILL at 3 of 19 arms, with the shim unable to write a report.
        #     THAT IS THE WHOLE PROBLEM IN ONE SENTENCE: the deep stream's resume and withTaskGroup's call go
        #    through the SAME outlined-epilogue shape, 100,000 times for the stream, so any predicate based on
        #    the caller forces async_now on the one case that must defer to survive (~5.4 KB a resume).
        #     The discriminator has to be the CALLEE's integer arity — whether it really has a 7th/8th integer
        #    argument — not the caller. withTaskGroup(of:returning:isolation:body:) has eight; the stream's
        #    next(isolation:) does not. Until that is available, bug 2 stays OPEN rather than half-fixed.
        if self.async_fn and carry and t in STUB_CC:
            #  10-21 a direct `b stub` into a native async function: the stub names the callee, this names the stack words
            self.e('store i8 1, ptr @__arm2x86_async_carry')
        if self.lo in NONABI and t not in NONABI:
            r = self.emit_call(t); self.abi_ret(r); return
        self.e(f'store i64 {self.rd("sp")}, ptr @__arm_sp')
        #  10-20 AN ON-CONTRACT CALLER MUST NOT PUBLISH THE FULL FILE: it never received one. WAS
        #    `XR_FULL_IN if t in NONABI`, i.e. the callee's status alone decided. A thunk that only takes
        #    x8/x20/x21 (XR_ABI_IN, what an on-contract entry reads) then wrote its OWN x9-x28 and v8-v31
        #    allocas — never initialised, so undef — into @__arm_xr, ERASING the values the real caller left
        #    there for the off-contract callee. On the hardware the thunk touches none of those registers and
        #    they reach the callee untouched, which is exactly what passing only XR_ABI_IN reproduces.
        #    Measured on Dock: `adrp/add x4,x5; b fn_10015351c` at 0x100153cb0 is ON-contract, its tail callee
        #    0x10015351c is OFF-contract and is frame #6 of the crash; the Swift `Identity` the callee should
        #    have filled held the thunk's own (global, metadata) argument pair instead, and copying its weak
        #    field killed the Dock. An on-contract function that really did clobber a callee-saved register
        #    would have been classified off-contract by abi_scan, so passing the caller's values through is
        #    the correct answer in every case that reaches here.
        self.xr_tail_pub(full_if_nonabi=True)   #  10-21 + every XR_FULL_IN register this function defines
        r = self.t(); self.e(f'{r} = musttail call {ABI_RET} @fn_{t:x}({self.abi_args()})')
        self.e(f'ret {ABI_RET} {r}')

    def va_conv(self, arg):
        """ 10-03 A va_list CROSSING INTO NATIVE CODE (Cyberpunk build22: native vsnprintf segfaulted in its first log
           line). arm64's va_list is a pointer to the variadic arguments in 8-byte stack slots; x86-64's is a 24-byte
           {gp_offset, fp_offset, overflow_arg_area, reg_save_area}. Marking every register consumed (gp 48, fp 304)
           makes x86 read every argument from overflow_arg_area in 8-byte slots — which IS the arm64 layout. One slot per
           frame (entry alloca): the native callee is done with it before the next call reuses it."""
        self.vaconv = True
        ap = arg.split()[1]
        self.e('store i32 48, ptr %vaconv')
        g = self.t(); self.e(f'{g} = getelementptr inbounds i8, ptr %vaconv, i64 4'); self.e(f'store i32 304, ptr {g}')
        g = self.t(); self.e(f'{g} = getelementptr inbounds i8, ptr %vaconv, i64 8'); self.e(f'store i64 {ap}, ptr {g}')
        g = self.t(); self.e(f'{g} = getelementptr inbounds i8, ptr %vaconv, i64 16'); self.e(f'store i64 0, ptr {g}')
        p = self.t(); self.e(f'{p} = ptrtoint ptr %vaconv to i64')
        return f'i64 {p}'

    def got_call_slot(self, i):
        """ 10-03 the GOT slot a `blr x16` at insns[i] called through, when the two instructions before it load it:
           `adrp x16, PAGE; ldr x16, [x16, #off]` or the linker-relaxed `ldr x16, <slot>` (literal). Else None."""
        if i < 1: return None
        a1, m1, o1 = self.insns[i - 1]
        #  10-20 THE ARM64e FORM: `adrp x17, PAGE; add x17, x17, #off; ldr x16, [x17]; blraa x16, x17` (the slot address
        #    stays in x17 as the PAC discriminator). macOS 27's mds calls ___chkstk_darwin exactly this way; unmatched, it
        #    went through the native adapter, which hands rdx back in x1, and the path argument in x1 came back as 0 —
        #    strlcpy(NULL) at start-up, so loginwindow sat blocked on mds.legacy.
        if (m1 == 'ldr' and o1 and o1[0] == 'x16' and ', '.join(o1[1:]) == '[x17]' and i >= 3
                and self.insns[i][2][1:2] == ['x17']):
            a2, m2, o2 = self.insns[i - 2]; a3, m3, o3 = self.insns[i - 3]
            ma = re.fullmatch(r'#(0x[0-9a-f]+|\d+)', o2[2]) if m2 == 'add' and o2[:2] == ['x17', 'x17'] and len(o2) == 3 else None
            if ma and m3 == 'adrp' and o3[:1] == ['x17'] and a3 == a2 - 4 and a2 == a1 - 4:
                return int(o3[1], 16) + int(ma.group(1), 0)
            return None
        if m1 != 'ldr' or not o1 or o1[0] != 'x16' or a1 != self.insns[i][0] - 4: return None
        if re.fullmatch(r'0x[0-9a-f]+', o1[1]): return int(o1[1], 16)
        mm = re.fullmatch(r'\[x16, #(0x[0-9a-f]+|\d+)\]', ', '.join(o1[1:]))
        if not mm or i < 2: return None
        a2, m2, o2 = self.insns[i - 2]
        if m2 != 'adrp' or o2[:1] != ['x16'] or a2 != a1 - 4: return None
        return int(o2[1], 16) + int(mm.group(1), 0)

    def this_ret(self, r):
        """ 10-03 see THISRET: a stub for a native ctor/dtor returns the `this` it was given (x0 is untouched by the
           tail dispatch itself, so reading it here reads the caller's x0)."""
        if self.lo not in THISRET: return r
        q = self.t(); self.e(f'{q} = insertvalue {ABI_RET} {r}, i64 {self.rd("x0")}, 0'); return q

    def eh_invoke(self, b0, pad):
        """ 10-03 every call this ONE arm64 call instruction emitted (the callee, the dispatcher, a bind) becomes an
           `invoke` unwinding to `pad`; the code after it continues in a fresh block. @llvm.* intrinsics cannot throw."""
        out = []
        for ln in self.body[b0:]:
            m = re.match(r'^  (%[\w.]+ = )?call (.*)$', ln)
            if m and '@llvm.' not in ln.split('(')[0] and '@__arm2x86_trace(' not in ln:
                if not ln.rstrip().endswith(')'): raise NotImplementedError(f'eh: cannot make an invoke of {ln.strip()[:120]}')
                self.eh_n += 1
                out.append(f'  {m.group(1) or ""}invoke {m.group(2)} to label %EHC{self.eh_n} unwind label %{pad}')
                out.append(f'EHC{self.eh_n}:')
            else:
                out.append(ln)
        self.body[b0:] = out

    def eh_pad(self, lp, cl, nm):
        """ 10-03 the landing pad: the x86 unwinder lands here, and the arm64 pad at `lp` runs with x0 = the exception
           and x1 = the arm64 filter of the clause that matched (llvm.eh.typeid.for maps LLVM's selector back to it)."""
        self.body.append(f'{nm}:')
        cls, cleanup = [], (not cl) or any(f == 0 for f, _ in cl)
        for f, ti in cl:
            if f > 0: cls.append('catch ptr ' + (f'@"{ti}"' if ti else 'null'))
            elif f < 0:   #  10-03 (build19 shard 360): an EMPTY spec, throw(), is `zeroinitializer` — `[]` fails the verifier
                cls.append(f'filter [{len(ti)} x ptr] ' + ('[' + ', '.join(f'ptr @"{x}"' if x else 'ptr null' for x in ti) + ']' if ti else 'zeroinitializer'))
            for x in ((ti,) if f > 0 else ti if f < 0 else ()):
                if x: self.eh_decls.add(f'@"{x}" = external global ptr')
        lpv = self.t()
        self.e(f'{lpv} = landingpad {{ ptr, i32 }}' + (' cleanup' if cleanup else '') + ''.join(' ' + c for c in cls))
        ex = self.t(); self.e(f'{ex} = extractvalue {{ ptr, i32 }} {lpv}, 0')
        sel = self.t(); self.e(f'{sel} = extractvalue {{ ptr, i32 }} {lpv}, 1')
        cur = str(next((f for f, ti in cl if f > 0 and ti is None), 0))   # a catch-all is whatever no typed clause took
        for f, ti in cl:
            if f > 0 and ti:
                self.eh_decls.add('declare i32 @llvm.eh.typeid.for.p0(ptr)')
                tid = self.t(); self.e(f'{tid} = call i32 @llvm.eh.typeid.for.p0(ptr @"{ti}")')
                c = self.t(); self.e(f'{c} = icmp eq i32 {sel}, {tid}')
            elif f < 0:
                c = self.t(); self.e(f'{c} = icmp slt i32 {sel}, 0')
            else:
                continue
            nv = self.t(); self.e(f'{nv} = select i1 {c}, i64 {f}, i64 {cur}'); cur = nv
        xi = self.t(); self.e(f'{xi} = ptrtoint ptr {ex} to i64')
        self.e(f'store i64 {xi}, ptr %x0'); self.e(f'store i64 {cur}, ptr %x1')
        self.e(f'br label %L{lp:x}')

    @staticmethod
    def _sfx(n, el):
        """LLVM intrinsic type suffix: (4,'float') -> v4f32, (16,'i8') -> v16i8"""
        return f'v{n}' + {'float': 'f32', 'double': 'f64', 'half': 'f16'}.get(el, el)

    @staticmethod
    def _splat(el, n, v):
        """A vector constant.  LLVM wants the SIGNED form of an element constant; `i8 255`
           is out of range where `i8 -1` is the same bits and is accepted."""
        if not el.startswith('i'): raise NotImplementedError('fp splat constant')
        eb = int(el[1:]); v &= (1 << eb) - 1
        if v >= (1 << (eb - 1)): v -= (1 << eb)
        return '<' + ', '.join(f'{el} {v}' for _ in range(n)) + '>'

    # ── SVE/SME, at Apple's fixed 512-bit streaming vector length (R18) ───────
    def sve_tok(self, tok):
        """'z0.s' -> ('v0', 's', 32, 'i32', 'float', 16 lanes). Blocks what it cannot read."""
        t = tok.strip().lstrip('{').rstrip('}').strip().lstrip('%')
        if '/' in t:
            t = t.split('/')[0]
        #  R18-g A GOVERNING PREDICATE CARRIES NO WIDTH. `p0/m` is well-formed and
        #    this demanded a '.' on it, blocking every predicated instruction on its own
        #    predicate. Only a p-register may be suffix-less; a z-register without one is
        #    still an operand we cannot assign a lane count to, and still blocks.
        if '.' not in t:
            if t[:1].lower() == 'p' and not t.lower().startswith('pn'):
                return 'p' + t[1:], None, None, None, None, None
            raise NotImplementedError(f'SVE operand {tok!r} has no element suffix')
        name, suf = t.split('.', 1)
        suf = suf.strip()
        #  pn8 IS NOT p8. A predicate-as-counter (SME2) encodes a RANGE, not a lane mask,
        #    and reading it as a mask would silently process the wrong lanes.
        if name.startswith('pn'):
            raise NotImplementedError(f'SVE predicate-as-counter {name} (SME2) unmodelled')
        if suf not in SVE_EL:
            raise NotImplementedError(f'SVE element suffix .{suf} unmodelled')
        eb, ity, fty = SVE_EL[suf]
        if name[0] == 'z':
            slot = 'v' + name[1:]
        elif name[0] == 'p':
            slot = 'p' + name[1:]
        else:
            raise NotImplementedError(f'SVE register {name!r} unmodelled')
        return slot, suf, eb, ity, fty, SVL_BITS // eb

    def zrd(self, tok, fp=False):
        slot, suf, eb, ity, fty, n = self.sve_tok(tok)
        el = fty if fp else ity
        if el is None:
            raise NotImplementedError(f'SVE .{suf} has no floating-point form')
        b = self.t(); self.e(f'{b} = load <{SVL_B} x i8>, ptr %{slot}')
        c = self.t(); self.e(f'{c} = bitcast <{SVL_B} x i8> {b} to <{n} x {el}>')
        return c, f'<{n} x {el}>', n, el

    def zwr(self, tok, val, ty):
        slot = self.sve_tok(tok)[0]
        b = self.t(); self.e(f'{b} = bitcast {ty} {val} to <{SVL_B} x i8>')
        self.e(f'store <{SVL_B} x i8> {b}, ptr %{slot}')

    def pmask(self, tok, n, eb):
        """The governing predicate as <n x i1>.

         A PREDICATE BIT IS PER BYTE, NOT PER ELEMENT. p0 holds SVL/8 = 64 bits and the
           bit governing element i of a .s vector is bit i*4. Reading it as one bit per
           element would enable the wrong lanes and still produce a full-looking vector.
        """
        slot = self.sve_tok(tok)[0]
        w = self.t(); self.e(f'{w} = load i64, ptr %{slot}')
        bits = self.t(); self.e(f'{bits} = bitcast i64 {w} to <{SVL_B} x i1>')
        stride = eb // 8
        if stride == 1 and n == SVL_B:
            return bits
        idx = ', '.join(f'i32 {i * stride}' for i in range(n))
        m = self.t()
        self.e(f'{m} = shufflevector <{SVL_B} x i1> {bits}, <{SVL_B} x i1> poison, '
               f'<{n} x i32> <{idx}>')
        return m

    def sve_splat(self, ty, n, el, val):
        a = self.t(); self.e(f'{a} = insertelement {ty} poison, {el} {val}, i32 0')
        b = self.t()
        self.e(f'{b} = shufflevector {ty} {a}, {ty} poison, '
               f'<{n} x i32> zeroinitializer')
        return b


    # ── R22 SME2 ───────────────────────────────────────────────────────────
    #  EVERY NUMBER BELOW WAS READ OFF AN M4 ON 2026-09-22. Nothing here is recalled
    #    from an architecture manual; the two places where my prediction and the silicon
    #    disagreed are called out at their site, because those are the two facts a
    #    re-derivation would get wrong again.

    @staticmethod
    def sme_join(ops):
        """Regroup a brace list that split_ops fragmented.

         split_ops TRACKS [] AND NOT {}, so `{ z16.s, z20.s, z24.s, z28.s }` arrives as
           four operands while `za.s[w8, 0, vgx4]` arrives as one. Teaching split_ops
           about braces would change the operand count under the NEON list code, which
           was written to re-join the fragments itself and still works. Regroup here.
        """
        out, cur = [], None
        for o in ops:
            if cur is None:
                if o.count('{') > o.count('}'):
                    cur = o
                else:
                    out.append(o)
            else:
                cur += ', ' + o
                if cur.count('{') <= cur.count('}'):
                    out.append(cur); cur = None
        if cur is not None:
            out.append(cur)
        return out

    def sme_list(self, tok):
        """`{ z0.s - z3.s }` or `{ z16.s, z20.s, z24.s, z28.s }` -> slots + element info.

         THE WRITTEN ORDER IS THE GROUP ORDER IN BOTH SPELLINGS — measured. The strided
           spelling is not a different mapping, it is the same four vectors named
           individually because they are not consecutive registers.
        """
        t = tok.strip()
        if not (t.startswith('{') and t.endswith('}')):
            raise NotImplementedError(f'SME2 vector list {tok!r} unparsed')
        inner = t[1:-1].strip()
        if '-' in inner and ',' not in inner:
            lo, hi = [x.strip() for x in inner.split('-')]
            s0, suf, eb, ity, fty, n = self.sve_tok(lo)
            s1 = self.sve_tok(hi)[0]
            if not (s0[0] == 'v' and s1[0] == 'v'):
                raise NotImplementedError(f'SME2 list {tok!r}: not z registers')
            a0, a1 = int(s0[1:]), int(s1[1:])
            if a1 < a0 or a1 - a0 + 1 not in (1, 2, 4):
                raise NotImplementedError(f'SME2 list {tok!r}: length not 1/2/4')
            slots = [f'v{i}' for i in range(a0, a1 + 1)]
        else:
            parts = [x.strip() for x in inner.split(',') if x.strip()]
            info = [self.sve_tok(p) for p in parts]
            if any(i[0][0] != 'v' for i in info):
                raise NotImplementedError(f'SME2 list {tok!r}: not z registers')
            suf, eb, ity, fty, n = info[0][1:]
            if any(i[1] != suf for i in info):
                raise NotImplementedError(f'SME2 list {tok!r}: mixed element widths')
            if len(info) not in (1, 2, 4):
                raise NotImplementedError(f'SME2 list {tok!r}: length not 1/2/4')
            slots = [i[0] for i in info]
        return slots, suf, eb, ity, fty, n

    def sme_ld(self, slot, n, el):
        b = self.t(); self.e(f'{b} = load <{SVL_B} x i8>, ptr %{slot}')
        c = self.t(); self.e(f'{c} = bitcast <{SVL_B} x i8> {b} to <{n} x {el}>')
        return c

    def sme_st(self, slot, val, n, el):
        b = self.t(); self.e(f'{b} = bitcast <{n} x {el}> {val} to <{SVL_B} x i8>')
        self.e(f'store <{SVL_B} x i8> {b}, ptr %{slot}')

    # ── ZA addressing ────────────────────────────────────────────────────────
    def za_rowptr(self, row):
        p = self.t()
        self.e(f'{p} = getelementptr [{SVL_B} x <{SVL_B} x i8>], ptr %za, '
               f'i64 0, i64 {row}')
        return p

    def za_ld(self, row, n, el):
        p = self.za_rowptr(row)
        b = self.t(); self.e(f'{b} = load <{SVL_B} x i8>, ptr {p}')
        c = self.t(); self.e(f'{c} = bitcast <{SVL_B} x i8> {b} to <{n} x {el}>')
        return c

    def za_st(self, row, val, n, el):
        p = self.za_rowptr(row)
        b = self.t(); self.e(f'{b} = bitcast <{n} x {el}> {val} to <{SVL_B} x i8>')
        self.e(f'store <{SVL_B} x i8> {b}, ptr {p}')

    def sme_za_op(self, tok):
        """Parse a ZA operand into a dict, or return None if it is not one."""
        t = tok.strip().lstrip('{').rstrip('}').strip()
        if t.lower() == 'za':
            return {'kind': 'all'}
        m = ZA_TILE.match(t)
        if m:
            return {'kind': 'tile', 'tile': int(m.group(1)),
                    'suf': m.group(2).lower()}
        m = ZA_GROUP.match(t)
        if m:
            return {'kind': 'group', 'suf': m.group(1).lower(), 'w': m.group(2),
                    'imm': simm(m.group(3)), 'vg': int(m.group(4) or 1)}
        m = ZA_SLICE.match(t)
        if m:
            lo = simm(m.group(5))
            hi = simm(m.group(6)) if m.group(6) is not None else lo
            return {'kind': 'slice', 'tile': int(m.group(1) or 0),
                    'vert': m.group(2).lower() == 'v', 'suf': m.group(3).lower(),
                    'w': m.group(4), 'off': lo, 'count': hi - lo + 1}
        return None

    def za_group_rows(self, za):
        """The ZA array vectors a vector group names.

         THE GROUP IS STRIDED BY 64/VG AND I PREDICTED CONSECUTIVE. Measured on an M4:
           vgx2 -> base, base+32; vgx4 -> base, +16, +32, +48. It is independent of the
           element size — za.d vgx4 is stride 16, not 8. A consecutive reading passes any
           test that only reads member 0, which is exactly how R21's Z-row interleave hid.
         Wv AND THE IMMEDIATE ADD INTO ONE SLICE INDEX, then wrap mod 64/VG (measured:
           vgx4 w8=20 lands where w8=4 does).
        """
        vg = za['vg']
        if vg not in (1, 2, 4):
            raise NotImplementedError(f'ZA vector group vgx{vg} unmodelled')
        stride = SVL_B // vg
        w = self.rd(za['w'])
        s = self.t(); self.e(f"{s} = add i64 {w}, {za['imm']}")
        m = self.t(); self.e(f'{m} = and i64 {s}, {stride - 1}')
        rows = [m]
        for g in range(1, vg):
            r = self.t(); self.e(f'{r} = add i64 {m}, {g * stride}')
            rows.append(r)
        return rows

    def za_slice_rows(self, za, count):
        """Horizontal tile slices -> array vectors.

         TILE <T> OF AN esize=E TILE SET HOLDS ROW i AT ARRAY VECTOR T + (E/8)*i, and
           there are E/8 tiles of 64/(E/8) rows each (measured for .b/.h/.s/.d, and
           confirmed independently by `zero {za1.s}` clearing 1, 5, 9, ... 61).
        """
        S = za['eb'] // 8
        rpt = SVL_B // S
        w = self.rd(za['w'])
        rows = []
        if count > 1 and za.get('count', 1) == count:
            #  R33d A MULTI-VECTOR GROUP STARTS ALIGNED (M4): base =
            #    ((w + off) mod rows) & ~(count - 1), then consecutive slices.
            s = self.t(); self.e(f"{s} = add i64 {w}, {za['off']}")
            m = self.t(); self.e(f'{m} = and i64 {s}, {(rpt - 1) & ~(count - 1)}')
            for k in range(count):
                m2 = self.t(); self.e(f'{m2} = add i64 {m}, {k}')
                x = self.t(); self.e(f'{x} = mul i64 {m2}, {S}')
                y = self.t(); self.e(f"{y} = add i64 {x}, {za['tile']}")
                rows.append(y)
            return rows
        for k in range(count):
            s = self.t(); self.e(f"{s} = add i64 {w}, {za['off'] + k}")
            m = self.t(); self.e(f'{m} = and i64 {s}, {rpt - 1}')
            x = self.t(); self.e(f'{x} = mul i64 {m}, {S}')
            y = self.t(); self.e(f"{y} = add i64 {x}, {za['tile']}")
            rows.append(y)
        return rows

    def za_vert(self, za, n, el, val=None):
        """A VERTICAL tile slice is the exact TRANSPOSE of the horizontal one.

         MEASURED: element i of za<T>v.<t>[Wv, k] is (tile row i)[lane k], i.e.
           ZA[T + S*i][k]. Read with `val=None`, written otherwise. n scalar accesses,
           because a transpose of a strided row set is not a vector operation.
        """
        S = za['eb'] // 8
        w = self.rd(za['w'])
        s = self.t(); self.e(f"{s} = add i64 {w}, {za['off']}")
        lane = self.t(); self.e(f'{lane} = and i64 {s}, {n - 1}')
        acc = 'poison'
        for i in range(n):
            p = self.za_rowptr(za['tile'] + S * i)
            ep = self.t()
            self.e(f'{ep} = getelementptr <{n} x {el}>, ptr {p}, i64 0, i64 {lane}')
            if val is None:
                v = self.t(); self.e(f'{v} = load {el}, ptr {ep}')
                nx = self.t()
                self.e(f'{nx} = insertelement <{n} x {el}> {acc}, {el} {v}, i32 {i}')
                acc = nx
            else:
                v = self.t()
                self.e(f'{v} = extractelement <{n} x {el}> {val}, i32 {i}')
                self.e(f'store {el} {v}, ptr {ep}')
        return acc if val is None else None

    # ── predicate-as-counter (pn8..pn15) ─────────────────────────────────────
    def pn_slot(self, tok):
        t = tok.strip().split('/')[0].strip().lstrip('%').lstrip('{').rstrip('}').strip()
        name = t.split('.', 1)[0].split('[', 1)[0]
        if not name.lower().startswith('pn'):
            return None
        return 'p' + name[2:]

    def pn_enc(self, slot, cnt, inv, eb):
        """Store the ARCHITECTURAL 16-bit counter, not a decoded lane count.

         THE ENCODING, MEASURED OVER 15 VALUES x 4 ELEMENT WIDTHS x vlx2/vlx4:
             s      = log2(esize/8)          a marker bit; every bit below it is zero
             count  = (raw & 0x7FFF) >> (s+1)
             inv    = raw >> 15
             active = inv ? capacity - count : count        (always a PREFIX)
           The group WIDTH is not in the counter — the consumer supplies the capacity,
           which is why the same pn8 drives an x2 and an x4 consumer differently.
         L == 0 ENCODES AS RAW 0x0000, with no marker bit at all (measured). The decode
           below reads 0 either way, so this select only matters to a guest that stores
           the predicate and compares the bits — but that is exactly the guest that would
           be impossible to debug, so the raw form is reproduced.
        """
        s = (eb // 8).bit_length() - 1
        sh = self.t(); self.e(f'{sh} = shl i64 {cnt}, {s + 1}')
        mk = self.t(); self.e(f'{mk} = or i64 {sh}, {(1 << s) | (0x8000 if inv else 0)}')
        cl = self.t(); self.e(f'{cl} = and i64 {mk}, 65535')
        if inv:
            self.e(f'store i64 {cl}, ptr %{slot}')
            return
        z = self.t(); self.e(f'{z} = icmp eq i64 {cnt}, 0')
        v = self.t(); self.e(f'{v} = select i1 {z}, i64 0, i64 {cl}')
        self.e(f'store i64 {v}, ptr %{slot}')

    def pn_lanes(self, tok, eb, first, nvec):
        """ R33b the counter -> nvec <n x i1> lane masks at consumer element size eb bits,
           for vectors first .. first+nvec-1 of the 4-vector CounterToPredicate result.
           Measured on the M4 (R33 case 331, 30 random pn values): see patch_r33b.py."""
        slot = self.pn_slot(tok)
        n = SVL_BITS // eb
        raw = self.t(); self.e(f'{raw} = load i64, ptr %{slot}')
        lo4 = self.t(); self.e(f'{lo4} = and i64 {raw}, 15')
        valid = self.t(); self.e(f'{valid} = icmp ne i64 {lo4}, 0')
        #  raw == 0 gives cttz 64, and a shift by 64 is POISON — clamp before any shift.
        s0 = self.t(); self.e(f'{s0} = call i64 @llvm.cttz.i64(i64 {raw}, i1 false)')
        s = self.t(); self.e(f'{s} = select i1 {valid}, i64 {s0}, i64 0')
        s1 = self.t(); self.e(f'{s1} = add i64 {s}, 1')
        sh = self.t(); self.e(f'{sh} = lshr i64 {raw}, {s1}')
        #  count = raw<8:s+1>, a field of 8-s bits. The old decode read raw<14:s+1>.
        wm = self.t(); self.e(f'{wm} = lshr i64 256, {s}')
        wm1 = self.t(); self.e(f'{wm1} = add i64 {wm}, -1')
        cnt = self.t(); self.e(f'{cnt} = and i64 {sh}, {wm1}')
        ps = self.t(); self.e(f'{ps} = shl i64 1, {s}')
        psm = self.t(); self.e(f'{psm} = add i64 {ps}, -1')
        iv = self.t(); self.e(f'{iv} = and i64 {raw}, 32768')
        inv = self.t(); self.e(f'{inv} = icmp ne i64 {iv}, 0')
        vt = f'<{n} x i64>'
        sps = self.sve_splat(vt, n, 'i64', s)
        spm = self.sve_splat(vt, n, 'i64', psm)
        spc = self.sve_splat(vt, n, 'i64', cnt)
        spi = self.sve_splat(f'<{n} x i1>', n, 'i1', inv)
        spv = self.sve_splat(f'<{n} x i1>', n, 'i1', valid)
        out = []
        for g in range(first, first + nvec):
            byt = '<' + ', '.join(f'i64 {(g * n + k) * (eb // 8)}' for k in range(n)) + '>'
            a = self.t(); self.e(f'{a} = and {vt} {byt}, {spm}')
            al = self.t(); self.e(f'{al} = icmp eq {vt} {a}, zeroinitializer')
            el = self.t(); self.e(f'{el} = lshr {vt} {byt}, {sps}')
            lt = self.t(); self.e(f'{lt} = icmp ult {vt} {el}, {spc}')
            ac = self.t(); self.e(f'{ac} = xor <{n} x i1> {lt}, {spi}')
            m1 = self.t(); self.e(f'{m1} = and <{n} x i1> {ac}, {al}')
            m = self.t(); self.e(f'{m} = and <{n} x i1> {m1}, {spv}')
            out.append(m)
        return out

    def pn_dec(self, tok, cap):
        """The counter -> the number of ACTIVE lanes, given the consumer's capacity."""
        slot = self.pn_slot(tok)
        raw = self.t(); self.e(f'{raw} = load i64, ptr %{slot}')
        #  is_zero_poison MUST BE false. raw == 0 is the legal "empty" encoding, and a
        #    poison shift amount here would poison the select that is supposed to rescue it.
        s = self.t(); self.e(f'{s} = call i64 @llvm.cttz.i64(i64 {raw}, i1 false)')
        s1 = self.t(); self.e(f'{s1} = add i64 {s}, 1')
        lo = self.t(); self.e(f'{lo} = and i64 {raw}, 32767')
        c = self.t(); self.e(f'{c} = lshr i64 {lo}, {s1}')
        iv = self.t(); self.e(f'{iv} = and i64 {raw}, 32768')
        isi = self.t(); self.e(f'{isi} = icmp ne i64 {iv}, 0')
        #  R33 AN INVERTED COUNT LARGER THAN THE CAPACITY IS ZERO LANES, NOT cap - c.
        #    The subtraction went negative, and every consumer compares UNSIGNED, so
        #    pn8 = 0xFFFF...(count 16383, invert) enabled EVERY lane. Measured on the M4 in
        #    R33 case `ld1b { z0.b, z8.b }, pn8/z, [x3, x3]`: 0 lanes active on all 30
        #    trials; the translation loaded from 2*x3 and SEGV'd the Xeon.
        comp0 = self.t(); self.e(f'{comp0} = sub i64 {cap}, {c}')
        big = self.t(); self.e(f'{big} = icmp ugt i64 {c}, {cap}')
        comp = self.t(); self.e(f'{comp} = select i1 {big}, i64 0, i64 {comp0}')
        pick = self.t(); self.e(f'{pick} = select i1 {isi}, i64 {comp}, i64 {c}')
        z = self.t(); self.e(f'{z} = icmp eq i64 {raw}, 0')
        out = self.t(); self.e(f'{out} = select i1 {z}, i64 0, i64 {pick}')
        return out

    def sme_prefix(self, ln, n, nvec):
        """A prefix of `ln` active lanes across nvec vectors of n lanes -> nvec masks."""
        out = []
        for g in range(nvec):
            sv = self.sve_splat(f'<{n} x i64>', n, 'i64', ln)
            idx = '<' + ', '.join(f'i64 {g * n + i}' for i in range(n)) + '>'
            m = self.t()
            self.e(f'{m} = icmp ult <{n} x i64> {idx}, {sv}')
            out.append(m)
        return out

    def sme_masks(self, tok, n, eb, nvec):
        """The governing predicate of a multi-vector memory op, as nvec <n x i1> masks.

        Accepts BOTH a predicate-as-counter (pn8/z) and an ordinary predicate (p0/z),
        because the single-vector spellings of these instructions use the latter.
        """
        if self.pn_slot(tok):
            return self.pn_lanes(tok, eb, 0, nvec)
        if nvec != 1:
            raise NotImplementedError(f'SME2 multi-vector under ordinary predicate '
                                      f'{tok!r} unmodelled')
        return [self.pmask(tok, n, eb)]

    def sme_wreg(self, tok, signed):
        """ wN IS 32 BITS AND THE COMPARISON IS 32-BIT. rd() hands back the low 32 bits
           zero-extended; a signed whilelt on them must sign-extend or every negative
           bound reads as a huge positive one and the mask comes out full."""
        v = self.rd(tok)
        if tok.strip().lower().startswith('w'):
            t32 = self.t(); self.e(f'{t32} = trunc i64 {v} to i32')
            r = self.t()
            self.e(f'{r} = {"sext" if signed else "zext"} i32 {t32} to i64')
            return r
        return v

    def sme_addr(self, tok, nvec):
        """`[x9]` or `[x9, #0x4, mul vl]` -> an i64 base.

         THE IMMEDIATE SCALES BY SVL EXACTLY ONCE, not by the list length: measured with
           `ld1w {z0.s-z3.s}, pn8/z, [x9, #4, mul vl]`, which starts at SVL chunk 4 and
           not at chunk 16.
        """
        t = tok.strip()
        if not (t.startswith('[') and t.endswith(']')):
            raise NotImplementedError(f'SME2 address {tok!r} unparsed')
        parts = [p.strip() for p in t[1:-1].split(',')]
        base = self.rd(parts[0])
        if len(parts) == 1:
            return base
        if len(parts) == 3 and parts[2].lower() == SME_ADDR_VL \
                and parts[1].startswith('#'):
            off = simm(parts[1]) * SVL_B
            if off == 0:
                return base
            r = self.t(); self.e(f'{r} = add i64 {base}, {off}')
            return r
        # a register-offset form scales by the ELEMENT size, which is a different
        # addressing mode and is not measured here.
        raise NotImplementedError(f'SME2 address {tok!r} unmodelled')

    # ── the dispatcher ───────────────────────────────────────────────────────
    def sme2(self, mn, ops, a):
        """Return True if this SME2 form is fully lowered, False to let the caller abort.

         FALSE MEANS THE EXISTING GUARDS FIRE. A form this method declines is still a
           named NotImplementedError, never a partial lowering — which is the failure this
           whole file exists to avoid, since a multi-vector op that quietly handles one
           vector returns a register that LOOKS entirely full.
        """
        base = mn.split('.', 1)[0].lower()
        ops = self.sme_join(ops)
        if not ops:
            return False

        # ── zero {za} / zero {za0.s} ─────────────────────────────────────────
        if base == 'zero':
            inner = ', '.join(ops).strip()
            if not (inner.startswith('{') and inner.endswith('}')):
                return False
            items = [x.strip() for x in inner[1:-1].split(',') if x.strip()]
            rows = set()
            for it in items:
                za = self.sme_za_op(it)
                if za is None:
                    return False
                if za['kind'] == 'all':
                    rows |= set(range(SVL_B))
                elif za['kind'] == 'tile':
                    #  MEASURED: `zero {za1.s}` clears 1, 5, 9, ..., 61 — the tile's
                    #    rows are strided by esize/8, not a contiguous block.
                    s = SVE_EL[za['suf']][0] // 8
                    rows |= set(range(za['tile'], SVL_B, s))
                else:
                    return False
            for r in sorted(rows):
                self.e(f'store <{SVL_B} x i8> zeroinitializer, ptr '
                       f'{self.za_rowptr(r)}')
            return True

        # ── ptrue pn<N>.<t> — all lanes, encoded as inv=1 count=0 ────────────
        if base == 'ptrue' and self.pn_slot(ops[0]):
            slot = self.pn_slot(ops[0])
            psuf = ops[0].strip().split('.', 1)[1].strip().lower()
            if psuf not in SVE_EL:
                return False
            eb = SVE_EL[psuf][0]
            self.pn_enc(slot, '0', True, eb)
            return True

        # ── while<cc> ────────────────────────────────────────────────────────
        if base in SME_WHILE:
            signed, incl, swap = SME_WHILE[base]
            dst = ops[0].strip()
            suf = dst.split('.', 1)[1].strip().lower() if '.' in dst else None
            if suf not in SVE_PTRUE_PAT or len(ops) < 3:
                return False
            eb = SVE_EL[suf][0]
            n = SVL_BITS // eb
            va = self.sme_wreg(ops[1], signed)
            vb = self.sme_wreg(ops[2], signed)
            lo, hi = (vb, va) if swap else (va, vb)
            cc = ('sge' if incl else 'sgt') if signed else ('uge' if incl else 'ugt')
            ok = self.t(); self.e(f'{ok} = icmp {cc} i64 {hi}, {lo}')
            d = self.t(); self.e(f'{d} = sub i64 {hi}, {lo}')
            if incl:
                d1 = self.t(); self.e(f'{d1} = add i64 {d}, 1')
                d = d1
            pn = self.pn_slot(dst)
            if pn:
                #  vlx<K> IS THE CAPACITY, AND IT IS NOT IN THE COUNTER. Measured:
                #    the same bound saturates at .b 256, .h 128, .s 64, .d 32 for vlx4.
                vl = 1
                for o in ops[3:]:
                    s = o.strip().lower()
                    if s.startswith('vlx'):
                        vl = int(s[3:])
                cap = n * vl
                sat = self.t(); self.e(f'{sat} = icmp ult i64 {d}, {cap}')
                cl = self.t()
                self.e(f'{cl} = select i1 {sat}, i64 {d}, i64 {cap}')
                ln = self.t(); self.e(f'{ln} = select i1 {ok}, i64 {cl}, i64 0')
                #  whilegt/whilege ENCODE inv=1 WITH count = capacity - active, which
                #    decodes to the same prefix. The bit pattern is reproduced so that a
                #    guest storing the predicate sees what the silicon writes.
                if swap:
                    inv_c = self.t(); self.e(f'{inv_c} = sub i64 {cap}, {ln}')
                    self.pn_enc(pn, inv_c, True, eb)
                else:
                    self.pn_enc(pn, ln, False, eb)
                return True
            # an ordinary predicate: a prefix of `ln` elements, ONE BIT PER BYTE.
            slot = self.sve_tok(dst)[0]
            if not slot.startswith('p'):
                return False
            sat = self.t(); self.e(f'{sat} = icmp ult i64 {d}, {n}')
            cl = self.t(); self.e(f'{cl} = select i1 {sat}, i64 {d}, i64 {n}')
            ln = self.t(); self.e(f'{ln} = select i1 {ok}, i64 {cl}, i64 0')
            #  SHIFTING AN i64 BY 64 IS POISON. A full mask is the common case, so the
            #    shift is done in i128 and truncated rather than special-cased.
            bits = self.t(); self.e(f'{bits} = mul i64 {ln}, {eb // 8}')
            w = self.t(); self.e(f'{w} = zext i64 {bits} to i128')
            sh = self.t(); self.e(f'{sh} = shl i128 1, {w}')
            sb = self.t(); self.e(f'{sb} = add i128 {sh}, -1')
            tr = self.t(); self.e(f'{tr} = trunc i128 {sb} to i64')
            pv = self.t(); self.e(f'{pv} = and i64 {tr}, {SVE_PTRUE_PAT[suf]}')
            self.e(f'store i64 {pv}, ptr %{slot}')
            return True

        # ── pext {pA.t, pB.t}, pn<N>[i]  /  pext pA.t, pn<N>[i] ──────────────
        if base == 'pext':
            src = ops[-1].strip()
            nm = src.split('[', 1)[0]
            if not nm.lower().startswith('pn'):
                return False
            idx = int(src.split('[', 1)[1].rstrip(']').strip()) if '[' in src else 0
            dsts = ops[0]
            if dsts.strip().startswith('{'):
                dl = [x.strip() for x in dsts.strip()[1:-1].split(',') if x.strip()]
                if len(dl) == 2 and '-' in dl[0]:
                    dl = None
            else:
                dl = [dsts.strip()]
            if dl is None:
                return False
            suf = dl[0].split('.', 1)[1].strip().lower()
            eb = SVE_EL[suf][0]
            n = SVL_BITS // eb
            #  R33b part idx of the 4-vector CounterToPredicate result, lane-exact.
            #    The marker may differ from .suf, so the part is not always a prefix.
            for k, (d, mk) in enumerate(zip(dl, self.pn_lanes(src, eb, idx, len(dl)))):
                slot = self.sve_tok(d)[0]
                self.e(f'store i64 {self._r33pack(mk, n, eb)}, ptr %{slot}')
            return True

        # ── ld1<t> / st1<t> / ld1r<t>, multi-vector or single ────────────────
        if base[:3] in ('ld1', 'st1') and len(base) >= 4:
            rep = base.startswith('ld1r')
            w = base[4] if rep else base[3]
            if w not in ('b', 'h', 'w', 'd') or len(base) > (5 if rep else 4):
                return False
            if not ops[0].strip().startswith('{'):
                return False
            # a ZA tile slice load/store wears the same mnemonic — route it first.
            za = self.sme_za_op(ops[0])
            if za is not None:
                return self.sme_za_mem(base, za, ops, a)
            slots, suf, eb, ity, fty, n = self.sme_list(ops[0])
            if {'b': 8, 'h': 16, 'w': 32, 'd': 64}[w] != eb:
                raise NotImplementedError(f'SME2 {mn} {ops}: width {w} vs .{suf}')
            nv = len(slots)
            base_p = self.sme_addr(ops[-1], nv)
            if rep:
                #  REPLICATE: one element is loaded and splatted (measured).
                if nv != 1:
                    return False
                v = self.t(); self.e(f'{v} = load {ity}, ptr {self.iptr(base_p)}')
                sp = self.sve_splat(f'<{n} x {ity}>', n, ity, v)
                self.sme_st(slots[0], sp, n, ity)
                return True
            masks = self.sme_masks(ops[1], n, eb, nv)
            vt = f'<{n} x {ity}>'
            sfx = _sve_sfx(n, ity)
            for g, slot in enumerate(slots):
                p = base_p if g == 0 else None
                if p is None:
                    q = self.t(); self.e(f'{q} = add i64 {base_p}, {g * SVL_B}')
                    p = q
                ip = self.iptr(p)
                if base.startswith('ld1'):
                    #  A MASKED LOAD, NOT A FULL LOAD PLUS A SELECT. The inactive lanes
                    #    of a prefix mask may sit past the end of the mapping — a full
                    #    load there is a fault the hardware does not take.
                    r = self.t()
                    self.e(f'{r} = call {vt} @llvm.masked.load.{sfx}.p0('
                           f'ptr {ip}, i32 1, <{n} x i1> {masks[g]}, {vt} zeroinitializer)')
                    self.sme_st(slot, r, n, ity)
                else:
                    v = self.sme_ld(slot, n, ity)
                    self.e(f'call void @llvm.masked.store.{sfx}.p0({vt} {v}, '
                           f'ptr {ip}, i32 1, <{n} x i1> {masks[g]})')
            return True

        # ── mov / mova, between a vector list and ZA ─────────────────────────
        if base in ('mov', 'mova'):
            d, s = ops[0], (ops[-1] if len(ops) > 1 else None)
            if s is None:
                return False
            zad, zas = self.sme_za_op(d), self.sme_za_op(s)
            if zad is None and zas is None:
                return False
            pred = ops[1] if len(ops) > 2 and '/' in ops[1] else None
            if zas is not None:                      # ZA -> vectors
                return self.sme_za_read(d, zas, pred)
            return self.sme_za_write(zad, s, pred)

        # ── fadd / fsub / fmla / fmls INTO a ZA vector group ─────────────────
        if base in ('fadd', 'fsub', 'fmla', 'fmls', 'add', 'sub'):
            za = self.sme_za_op(ops[0])
            if za is not None and za['kind'] == 'group':
                return self.sme_za_acc(base, za, ops, a)

        # ── fmopa / fmops — the outer product ────────────────────────────────
        if base in ('fmopa', 'fmops'):
            za = self.sme_za_op(ops[0])
            if za is None or za['kind'] != 'tile' or len(ops) != 5:
                return False
            eb, ity, fty = SVE_EL[za['suf']]
            if fty is None:
                return False
            n = SVL_BITS // eb
            S = eb // 8
            zn = self.zrd(ops[3], fp=True)[0]
            zm = self.zrd(ops[4], fp=True)[0]
            rowm = self.pmask(ops[1], n, eb)
            lanem = self.pmask(ops[2], n, eb)
            op = 'fadd' if base == 'fmopa' else 'fsub'
            vt = f'<{n} x {fty}>'
            for i in range(n):
                row = za['tile'] + S * i
                cur = self.za_ld(row, n, fty)
                yi = self.t()
                self.e(f'{yi} = extractelement {vt} {zn}, i32 {i}')
                sp = self.sve_splat(vt, n, fty, yi)
                #  R33d FUSED OUTER PRODUCT, DEFAULT NaN (M4). R22 emitted fmul + fadd,
                #    which its small-integer oracle could not tell apart.
                if op == 'fsub':
                    ng = self.t(); self.e(f'{ng} = fneg {vt} {sp}'); sp = ng
                fm = self.t()
                self.e(f'{fm} = call {vt} @llvm.fma.{_sve_sfx(n, fty)}({vt} {sp}, {vt} {zm}, {vt} {cur})')
                nw = self._r33dn(vt, fm, n, eb)
                s1 = self.t()
                self.e(f'{s1} = select <{n} x i1> {lanem}, {vt} {nw}, {vt} {cur}')
                ri = self.t()
                self.e(f'{ri} = extractelement <{n} x i1> {rowm}, i32 {i}')
                s2 = self.t()
                self.e(f'{s2} = select i1 {ri}, {vt} {s1}, {vt} {cur}')
                self.za_st(row, s2, n, fty)
            return True

        # ── fcvt / fcvtn from a two-vector list ──────────────────────────────
        if base in ('fcvt', 'fcvtn') and len(ops) == 2 \
                and ops[1].strip().startswith('{'):
            slots, suf, eb, ity, fty, n = self.sme_list(ops[1])
            dslot, dsuf, deb, dity, dfty, dn = self.sve_tok(ops[0])
            if len(slots) != 2 or dfty is None or fty is None or dn != 2 * n:
                return False
            a0 = self.sme_ld(slots[0], n, fty)
            a1 = self.sme_ld(slots[1], n, fty)
            c0 = self.t(); self.e(f'{c0} = fptrunc <{n} x {fty}> {a0} to <{n} x {dfty}>')
            c1 = self.t(); self.e(f'{c1} = fptrunc <{n} x {fty}> {a1} to <{n} x {dfty}>')
            if base == 'fcvt':
                #  MEASURED: fcvt CONCATENATES (lanes 0..n-1 from z0, n..2n-1 from z1)
                #    and fcvtn INTERLEAVES (lane 2i from z0, lane 2i+1 from z1). Two
                #    mnemonics one letter apart with completely different layouts.
                idx = list(range(2 * n))
            else:
                idx = []
                for i in range(n):
                    idx += [i, n + i]
            sel = '<' + ', '.join(f'i32 {i}' for i in idx) + '>'
            r = self.t()
            self.e(f'{r} = shufflevector <{n} x {dfty}> {c0}, <{n} x {dfty}> {c1}, '
                   f'<{2 * n} x i32> {sel}')
            self.sme_st(dslot, r, 2 * n, dfty)
            return True

        # ── multi-vector element-wise ────────────────────────────────────────
        if ops[0].strip().startswith('{') and self.sme_za_op(ops[0]) is None:
            return self.sme_mv(base, ops, a)

        # ── single-vector permutes the base SVE arm does not carry ───────────
        return self.sme_perm(base, ops, a)

    def iptr(self, v):
        p = self.t(); self.e(f'{p} = inttoptr i64 {v} to ptr')
        return p

    def sme_za_mem(self, base, za, ops, a):
        """ld1<t>/st1<t> of ONE ZA tile slice: `{za0h.b[w12, 0]}`."""
        if za['kind'] != 'slice' or za['count'] != 1:
            return False
        za['eb'] = SVE_EL[za['suf']][0]
        eb, ity, fty = SVE_EL[za['suf']]
        n = SVL_BITS // eb
        vt = f'<{n} x {ity}>'
        sfx = _sve_sfx(n, ity)
        p = self.iptr(self.sme_addr(ops[-1], 1))
        mask = self.sme_masks(ops[1], n, eb, 1)[0]
        if za['vert']:
            raise NotImplementedError(f'SME2 {base} of a VERTICAL ZA slice at {a:x} '
                                      f'unmodelled (the masked form was not measured)')
        row = self.za_slice_rows(za, 1)[0]
        if base.startswith('ld1'):
            r = self.t()
            self.e(f'{r} = call {vt} @llvm.masked.load.{sfx}.p0(ptr {p}, i32 1, '
                   f'<{n} x i1> {mask}, {vt} zeroinitializer)')
            self.za_st(row, r, n, ity)
        else:
            v = self.za_ld(row, n, ity)
            self.e(f'call void @llvm.masked.store.{sfx}.p0({vt} {v}, ptr {p}, i32 1, '
                   f'<{n} x i1> {mask})')
        return True

    def sme_za_read(self, dst, za, pred):
        """ZA -> a vector list, or one vector (mova)."""
        if dst.strip().startswith('{'):
            slots, suf, eb, ity, fty, n = self.sme_list(dst)
        else:
            s0, suf, eb, ity, fty, n = self.sve_tok(dst)
            slots = [s0]
        za['eb'] = SVE_EL[za['suf']][0]
        if za['eb'] != eb:
            return False
        if za['kind'] == 'group':
            if za['vg'] != len(slots):
                return False
            rows = self.za_group_rows(za)
        elif za['kind'] == 'slice':
            if za['vert']:
                if len(slots) != 1:
                    return False
                v = self.za_vert(za, n, ity)
                self.sme_st(slots[0], self.sme_merge(slots[0], v, pred, n, eb, ity), n, ity)
                return True
            if za['count'] not in (1, len(slots)) or len(slots) not in (1, 2, 4):
                return False
            rows = self.za_slice_rows(za, len(slots))
        else:
            return False
        for slot, row in zip(slots, rows):
            v = self.za_ld(row, n, ity)
            self.sme_st(slot, self.sme_merge(slot, v, pred, n, eb, ity), n, ity)
        return True

    def sme_merge(self, slot, val, pred, n, eb, ity):
        """ `/m` IS A MERGE, NOT A WRITE. mova's predicated form leaves inactive lanes of
           the destination ALONE; overwriting them with zeros is the kind of change that
           only shows up in the lanes nobody printed."""
        if pred is None or '/m' not in pred:
            return val
        m = self.pmask(pred, n, eb)
        old = self.sme_ld(slot, n, ity)
        r = self.t()
        self.e(f'{r} = select <{n} x i1> {m}, <{n} x {ity}> {val}, '
               f'<{n} x {ity}> {old}')
        return r

    def sme_za_write(self, za, src, pred):
        """A vector list (or one vector) -> ZA."""
        if src.strip().startswith('{'):
            slots, suf, eb, ity, fty, n = self.sme_list(src)
        else:
            s0, suf, eb, ity, fty, n = self.sve_tok(src)
            slots = [s0]
        za['eb'] = SVE_EL[za['suf']][0]
        if za['eb'] != eb:
            return False
        if za['kind'] == 'group':
            if za['vg'] != len(slots):
                return False
            rows = self.za_group_rows(za)
        elif za['kind'] == 'slice':
            if za['vert']:
                if len(slots) != 1:
                    return False
                v = self.sme_ld(slots[0], n, ity)
                if pred is not None and '/m' in pred:
                    old = self.za_vert(za, n, ity)
                    m = self.pmask(pred, n, eb)
                    s = self.t()
                    self.e(f'{s} = select <{n} x i1> {m}, <{n} x {ity}> {v}, '
                           f'<{n} x {ity}> {old}')
                    v = s
                self.za_vert(za, n, ity, val=v)
                return True
            if len(slots) not in (1, 2, 4):
                return False
            rows = self.za_slice_rows(za, len(slots))
        else:
            return False
        for slot, row in zip(slots, rows):
            v = self.sme_ld(slot, n, ity)
            if pred is not None and '/m' in pred:
                old = self.za_ld(row, n, ity)
                m = self.pmask(pred, n, eb)
                s = self.t()
                self.e(f'{s} = select <{n} x i1> {m}, <{n} x {ity}> {v}, '
                       f'<{n} x {ity}> {old}')
                v = s
            self.za_st(row, v, n, ity)
        return True

    def sme_za_acc(self, base, za, ops, a):
        """fadd/fsub/fmla/fmls into a ZA vector group.

         MEASURED: these ACCUMULATE into ZA, they do not overwrite it — `fadd` twice
           doubles, and `fmopa` followed by `fmops` with the same operands returns the
           tile to exactly zero. A probe run on a freshly-zeroed ZA cannot tell the two
           apart, which is why it was measured on its own.
        """
        slots, suf, eb, ity, fty, n = self.sme_list(ops[1])
        za['eb'] = SVE_EL[za['suf']][0]
        if za['eb'] != eb or za['vg'] != len(slots):
            return False
        isfp = base[0] == 'f'
        el = fty if isfp else ity
        if el is None:
            return False
        vt = f'<{n} x {el}>'
        rows = self.za_group_rows(za)
        muls = None
        if base in ('fmla', 'fmls'):
            if len(ops) != 3:
                return False
            if ops[2].strip().startswith('{'):
                ms = self.sme_list(ops[2])[0]
                if len(ms) != len(slots):
                    return False
                muls = ms
            else:
                muls = [self.sve_tok(ops[2])[0]] * len(slots)
        elif len(ops) != 2:
            return False
        addop = ('fadd' if isfp else 'add') if base in ('fadd', 'fmla', 'add') \
            else ('fsub' if isfp else 'sub')
        for g, slot in enumerate(slots):
            v = self.sme_ld(slot, n, el)
            cur = self.za_ld(rows[g], n, el)
            if muls is not None and isfp:
                #  R33d fmla/fmls INTO ZA ARE FUSED (M4: 782/782 fused, 706 unfused),
                #    and like every FP op into ZA they return the DEFAULT NaN.
                mv = self.sme_ld(muls[g], n, el)
                if addop == 'fsub':
                    ng = self.t(); self.e(f'{ng} = fneg {vt} {v}'); v = ng
                fm = self.t()
                self.e(f'{fm} = call {vt} @llvm.fma.{_sve_sfx(n, el)}({vt} {v}, {vt} {mv}, {vt} {cur})')
                self.za_st(rows[g], self._r33dn(vt, fm, n, eb), n, el)
                continue
            if muls is not None:
                mv = self.sme_ld(muls[g], n, el)
                p = self.t()
                self.e(f'{p} = mul {vt} {v}, {mv}')
                v = p
            nw = self.t(); self.e(f'{nw} = {addop} {vt} {cur}, {v}')
            if isfp:
                nw = self._r33dn(vt, nw, n, eb)
            self.za_st(rows[g], nw, n, el)
        return True

    def sme_mv(self, base, ops, a):
        """Element-wise and permute forms whose destination is a vector list."""
        slots, suf, eb, ity, fty, n = self.sme_list(ops[0])
        nv = len(slots)
        # ── SME2 zip/uzp: `zip {z0.d - z1.d}, zn.d, zm.d` = zip1 then zip2 ───
        if base in ('zip', 'uzp') and len(ops) == 3 and nv == 2:
            an = self.sme_ld(self.sve_tok(ops[1])[0], n, ity)
            bn = self.sme_ld(self.sve_tok(ops[2])[0], n, ity)
            for k, slot in enumerate(slots):
                idx = self.sme_perm_idx(base + str(k + 1), n)
                sel = '<' + ', '.join(f'i32 {i}' for i in idx) + '>'
                r = self.t()
                self.e(f'{r} = shufflevector <{n} x {ity}> {an}, <{n} x {ity}> {bn}, '
                       f'<{n} x i32> {sel}')
                self.sme_st(slot, r, n, ity)
            return True
        isfp = base in SME_MV_FP or base in SME_MV_FPI
        op = SME_MV_FP.get(base) or SME_MV_INT.get(base)
        fn = SME_MV_FPI.get(base) or SME_MV_INTI.get(base)
        if not op and not fn:
            return False
        el = fty if isfp else ity
        if el is None:
            return False
        vt = f'<{n} x {el}>'
        if len(ops) != 3:
            return False
        lhs = self.sme_list(ops[1])[0]
        if len(lhs) != nv:
            return False
        if ops[2].strip().startswith('{'):
            rhs = self.sme_list(ops[2])[0]
            if len(rhs) != nv:
                return False
        else:
            rhs = [self.sve_tok(ops[2])[0]] * nv
        for g in range(nv):
            x = self.sme_ld(lhs[g], n, el)
            y = self.sme_ld(rhs[g], n, el)
            r = self.t()
            if op:
                self.e(f'{r} = {op} {vt} {x}, {y}')
            else:
                self.e(f'{r} = call {vt} @llvm.{fn}.{_sve_sfx(n, el)}({vt} {x}, {vt} {y})')
            self.sme_st(slots[g], r, n, el)
        return True

    @staticmethod
    def sme_perm_idx(base, n):
        """ THE STANDARD SVE PERMUTES, spelled as LLVM shuffle indices over a 2n
           concatenation. Measured, not recalled — zip1 takes the LOW halves."""
        if base == 'zip1':
            return [x for i in range(n // 2) for x in (i, n + i)]
        if base == 'zip2':
            return [x for i in range(n // 2, n) for x in (i, n + i)]
        if base == 'uzp1':
            return [i for i in range(0, 2 * n, 2)]
        if base == 'uzp2':
            return [i for i in range(1, 2 * n, 2)]
        raise NotImplementedError(f'SVE permute {base} unmodelled')

    def sme_perm(self, base, ops, a):
        """rev / tbl / zip1 / zip2 / uzp1 / uzp2 / ext — single-vector forms."""
        if base in ('zip1', 'zip2', 'uzp1', 'uzp2') and len(ops) == 3:
            dslot, suf, eb, ity, fty, n = self.sve_tok(ops[0])
            an = self.sme_ld(self.sve_tok(ops[1])[0], n, ity)
            bn = self.sme_ld(self.sve_tok(ops[2])[0], n, ity)
            sel = '<' + ', '.join(f'i32 {i}' for i in self.sme_perm_idx(base, n)) + '>'
            r = self.t()
            self.e(f'{r} = shufflevector <{n} x {ity}> {an}, <{n} x {ity}> {bn}, '
                   f'<{n} x i32> {sel}')
            self.sme_st(dslot, r, n, ity)
            return True
        if base == 'rev' and len(ops) == 2:
            #  MEASURED: a FULL-VECTOR element reversal (lane i = src[n-1-i]), not the
            #    byte-reverse-within-element that the scalar `rev` does.
            dslot, suf, eb, ity, fty, n = self.sve_tok(ops[0])
            sslot = self.sve_tok(ops[1])[0]
            v = self.sme_ld(sslot, n, ity)
            sel = '<' + ', '.join(f'i32 {n - 1 - i}' for i in range(n)) + '>'
            r = self.t()
            self.e(f'{r} = shufflevector <{n} x {ity}> {v}, <{n} x {ity}> poison, '
                   f'<{n} x i32> {sel}')
            self.sme_st(dslot, r, n, ity)
            return True
        if base == 'tbl' and len(ops) == 3 and ops[1].strip().startswith('{'):
            tabs, suf, eb, ity, fty, n = self.sme_list(ops[1])
            if len(tabs) != 1:
                return False
            dslot = self.sve_tok(ops[0])[0]
            tv = self.sme_ld(tabs[0], n, ity)
            iv = self.sme_ld(self.sve_tok(ops[2])[0], n, ity)
            #  MEASURED: AN OUT-OF-RANGE INDEX READS ZERO, it does not wrap. A modulo
            #    here would return a plausible element from the wrong lane.
            acc = 'zeroinitializer'
            for i in range(n):
                ix = self.t()
                self.e(f'{ix} = extractelement <{n} x {ity}> {iv}, i32 {i}')
                ok = self.t(); self.e(f'{ok} = icmp ult {ity} {ix}, {n}')
                safe = self.t()
                self.e(f'{safe} = select i1 {ok}, {ity} {ix}, {ity} 0')
                el = self.t()
                self.e(f'{el} = extractelement <{n} x {ity}> {tv}, {ity} {safe}')
                z = self.t(); self.e(f'{z} = select i1 {ok}, {ity} {el}, {ity} 0')
                nx = self.t()
                self.e(f'{nx} = insertelement <{n} x {ity}> {acc}, {ity} {z}, i32 {i}')
                acc = nx
            self.sme_st(dslot, acc, n, ity)
            return True
        if base == 'ext' and len(ops) == 4:
            #  BYTE-GRANULAR AND DESTRUCTIVE: `ext zd.b, zd.b, zm.b, #n` shifts the
            #    concatenation (zd ++ zm) down by n BYTES. The assembler rejects a form
            #    whose first source is not the destination, so the ARM ARM's 4-operand
            #    spelling is really 3 registers.
            dslot, suf, eb, ity, fty, n = self.sve_tok(ops[0])
            if suf != 'b':
                return False
            if self.sve_tok(ops[1])[0] != dslot:
                return False
            k = simm(ops[3])
            if k < 0:
                return False
            if k >= n:
                return False
            mv = self.sme_ld(self.sve_tok(ops[2])[0], n, ity)
            dv = self.sme_ld(dslot, n, ity)
            sel = '<' + ', '.join(f'i32 {k + i}' for i in range(n)) + '>'
            r = self.t()
            self.e(f'{r} = shufflevector <{n} x {ity}> {dv}, <{n} x {ity}> {mv}, '
                   f'<{n} x i32> {sel}')
            self.sme_st(dslot, r, n, ity)
            return True
        return False

    def sve_or_r33(self, mn, ops, a):
        """ R33 the verified arms FIRST, the R33 surface only for what they refuse.
            A refusal can come as False OR as NotImplementedError after some IR was
              already emitted; that IR is truncated so a half-lowered form never survives."""
        mark = len(self.body)
        first = None
        try:
            if self.sve(mn, ops, a):
                return True
        except NotImplementedError as e:
            first = e
        del self.body[mark:]
        try:
            if self.sve_r33(mn, ops, a):
                return True
        except NotImplementedError:
            del self.body[mark:]
            if first is None:
                raise
        del self.body[mark:]
        if first is not None:
            raise first
        return False

    # ══ R33 THE REST OF THE SVE/SME SURFACE, JUDGED BY AN M4 ═══════════════════════════
    #  EVERY FORM HERE IS ONE OF THE 485 GAP SHAPES FOUND IN THE REAL DYLD CACHE (412,362
    #    SVE/SME lines, 60,122 gap instances), and every one of them has a case in the R33
    #    oracle: the same object runs natively on the M4 and translated on the Xeon, and
    #    cmp33.py compares all 10,752 bytes of architectural state per trial. The semantics
    #    written below are HYPOTHESES until that comparison says otherwise — the oracle is
    #    the measurement, this code is the prediction.
    #  EACH HANDLER RETURNS False FOR AN OPERAND FORM IT DOES NOT RECOGNISE, and sve()
    #    then raises "not yet modelled". A handler that half-matched and lowered something
    #    plausible would be this codebase's most expensive recurring bug.
    R33_DN = {16: 0x7E00, 32: 0x7FC00000, 64: 0x7FF8000000000000}
    R33_QB = {16: 0x200, 32: 0x400000, 64: 1 << 51}
    R33_PAT = {'b': (1 << 64) - 1, 'h': 0x5555555555555555, 's': 0x1111111111111111,
               'd': 0x0101010101010101, 'q': 0x0001000100010001}

    def sve_r33(self, mn, ops, a):
        base = mn.split('.', 1)[0].lower()
        h = getattr(self, '_r33_' + base, None)
        if h is None:
            return False
        return bool(h(self.sme_join([o.strip() for o in ops])))

    # ── operand parsing ──────────────────────────────────────────────────────────────
    @staticmethod
    def _r33z(tok):
        """'z5.s' / 'z5' / 'z5.s[3]' / 'z5[3]' -> (slot, suf|None, idx|None), else None."""
        m = re.fullmatch(r'z(\d+)(?:\.([bhsdq]))?(?:\[(\d+)\])?', tok.strip().lower())
        if not m:
            return None
        return 'v' + m.group(1), m.group(2), (int(m.group(3)) if m.group(3) else None)

    @staticmethod
    def _r33p(tok):
        """'p3' / 'p3/m' / 'p3.b' -> (slot, suf|None, mode|None). pn is NOT matched."""
        m = re.fullmatch(r'p(\d+)(?:\.([bhsdq]))?(?:/([mz]))?', tok.strip().lower())
        if not m:
            return None
        return 'p' + m.group(1), m.group(2), m.group(3)

    @staticmethod
    def _r33v(tok):
        """a SIMD scalar 'b3'/'h3'/'s3'/'d3'/'q3' -> ('v3', bits), else None."""
        m = re.fullmatch(r'([bhsdq])(\d+)', tok.strip().lower())
        if not m:
            return None
        return 'v' + m.group(2), {'b': 8, 'h': 16, 's': 32, 'd': 64, 'q': 128}[m.group(1)]

    @staticmethod
    def _r33ty(suf, fp=False):
        eb, ity, fty = SVE_EL[suf]
        n = SVL_BITS // eb
        el = fty if fp else ity
        if el is None:
            raise NotImplementedError(f'R33: .{suf} has no floating-point form')
        return n, el, eb, f'<{n} x {el}>'

    def _r33ld(self, slot, suf, fp=False):
        n, el, eb, ty = self._r33ty(suf, fp)
        return self.sme_ld(slot, n, el), ty, n, el, eb

    def _r33st(self, slot, val, ty):
        b = self.t(); self.e(f'{b} = bitcast {ty} {val} to <{SVL_B} x i8>')
        self.e(f'store <{SVL_B} x i8> {b}, ptr %{slot}')

    def _r33sp(self, ty, n, el, val):
        return self.sve_splat(ty, n, el, val)

    def _r33c(self, ty, n, vals):
        """a constant vector from a python list"""
        el = ty.split(' x ')[1].rstrip('>')
        return '<' + ', '.join(f'{el} {v}' for v in vals) + '>'

    # ── predicates ───────────────────────────────────────────────────────────────────
    def _r33pv(self, slot):
        v = self.t(); self.e(f'{v} = load i64, ptr %{slot}')
        return v

    def _r33mask(self, pv, n, eb):
        """an i64 predicate VALUE -> <n x i1> at element size eb (one bit per byte)."""
        bits = self.t(); self.e(f'{bits} = bitcast i64 {pv} to <{SVL_B} x i1>')
        stride = eb // 8
        if stride == 1:
            return bits
        idx = ', '.join(f'i32 {i * stride}' for i in range(n))
        m = self.t()
        self.e(f'{m} = shufflevector <{SVL_B} x i1> {bits}, <{SVL_B} x i1> poison, '
               f'<{n} x i32> <{idx}>')
        return m

    def _r33pmask(self, tok, n, eb):
        p = self._r33p(tok)
        if not p:
            raise NotImplementedError(f'R33: {tok!r} is not a governing predicate')
        return self._r33mask(self._r33pv(p[0]), n, eb)

    def _r33pack(self, m, n, eb):
        """<n x i1> -> the i64 predicate with element i at bit i*(eb/8), the rest ZERO."""
        stride = eb // 8
        if stride == 1:
            v = self.t(); self.e(f'{v} = bitcast <{SVL_B} x i1> {m} to i64')
            return v
        idx = ', '.join(f'i32 {j // stride if j % stride == 0 else n}' for j in range(SVL_B))
        s = self.t()
        self.e(f'{s} = shufflevector <{n} x i1> {m}, <{n} x i1> zeroinitializer, '
               f'<{SVL_B} x i32> <{idx}>')
        v = self.t(); self.e(f'{v} = bitcast <{SVL_B} x i1> {s} to i64')
        return v

    def _r33ptest(self, g, r):
        """ PredTest: N = first active element true, Z = no active element true,
           C = NOT(last active element true), V = 0. g and r are i64 predicate values."""
        x = self.t(); self.e(f'{x} = and i64 {r}, {g}')
        z = self.t(); self.e(f'{z} = icmp eq i64 {x}, 0')
        ng = self.t(); self.e(f'{ng} = sub i64 0, {g}')
        fb = self.t(); self.e(f'{fb} = and i64 {g}, {ng}')
        nf = self.t(); self.e(f'{nf} = and i64 {r}, {fb}')
        nn = self.t(); self.e(f'{nn} = icmp ne i64 {nf}, 0')
        lz = self.t(); self.e(f'{lz} = call i64 @llvm.ctlz.i64(i64 {g}, i1 false)')
        sh = self.t(); self.e(f'{sh} = sub i64 63, {lz}')
        sm = self.t(); self.e(f'{sm} = and i64 {sh}, 63')
        lb0 = self.t(); self.e(f'{lb0} = shl i64 1, {sm}')
        gz = self.t(); self.e(f'{gz} = icmp eq i64 {g}, 0')
        lb = self.t(); self.e(f'{lb} = select i1 {gz}, i64 0, i64 {lb0}')
        lr = self.t(); self.e(f'{lr} = and i64 {r}, {lb}')
        c = self.t(); self.e(f'{c} = icmp eq i64 {lr}, 0')
        self.e(f'store i1 {nn}, ptr %N'); self.e(f'store i1 {z}, ptr %Z')
        self.e(f'store i1 {c}, ptr %C'); self.e('store i1 false, ptr %V')

    def _r33count(self, pv, suf):
        """active elements of a predicate value at size suf"""
        a = self.t(); self.e(f'{a} = and i64 {pv}, {self.R33_PAT[suf]}')
        c = self.t(); self.e(f'{c} = call i64 @llvm.ctpop.i64(i64 {a})')
        return c

    @staticmethod
    def _r33patcount(pat, n):
        """ptrue / cnt / inc pattern -> element count (a python int)"""
        p = (pat or 'all').strip().lower()
        if p == 'all':
            return n
        if p == 'pow2':
            return 1 << (n.bit_length() - 1)
        if p == 'mul3':
            return n - n % 3
        if p == 'mul4':
            return n - n % 4
        m = re.fullmatch(r'vl(\d+)', p)
        #  ONLY THE ENCODABLE VLn: 1-8, 16, 32, 64, 128, 256. `vl300` is no pattern at all.
        if m and int(m.group(1)) in (1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 128, 256):
            k = int(m.group(1))
            return k if k <= n else 0
        raise NotImplementedError(f'R33: predicate pattern {pat!r} unmodelled')

    # ── addressing and memory ────────────────────────────────────────────────────────
    def _r33addr(self, tok, vl):
        """[xn] | [xn, #imm] (bytes) | [xn, #k, mul vl] (k*vl) | [xn, xm{, lsl #s}]"""
        t = tok.strip()
        if not (t.startswith('[') and t.endswith(']')):
            raise NotImplementedError(f'R33: address {tok!r} unparsed')
        parts = [p.strip().lower() for p in t[1:-1].split(',')]
        base = self.rd(parts[0])
        if len(parts) == 1:
            return base
        if parts[1].startswith('#'):
            k = simm(parts[1])
            if len(parts) == 3 and parts[2] == 'mul vl':
                off = k * vl
            elif len(parts) == 2:
                off = k
            else:
                raise NotImplementedError(f'R33: address {tok!r} unmodelled')
            if off == 0:
                return base
            r = self.t(); self.e(f'{r} = add i64 {base}, {off}')
            return r
        if not re.fullmatch(r'x\d+', parts[1]):
            raise NotImplementedError(f'R33: address index {parts[1]!r} unmodelled')
        ix = self.rd(parts[1])
        if len(parts) == 3:
            m = re.fullmatch(r'lsl #(\d+)', parts[2])
            if not m:
                raise NotImplementedError(f'R33: address {tok!r} unmodelled')
            s = self.t(); self.e(f'{s} = shl i64 {ix}, {int(m.group(1))}')
            ix = s
        elif len(parts) != 2:
            raise NotImplementedError(f'R33: address {tok!r} unmodelled')
        r = self.t(); self.e(f'{r} = add i64 {base}, {ix}')
        return r

    def _r33mload(self, addr, n, ity, mask):
        p = self.iptr(addr)
        r = self.t()
        self.e(f'{r} = call <{n} x {ity}> @llvm.masked.load.v{n}{ity}.p0(ptr {p}, i32 1, '
               f'<{n} x i1> {mask}, <{n} x {ity}> zeroinitializer)')
        return r

    def _r33mstore(self, addr, val, n, ity, mask):
        p = self.iptr(addr)
        self.e(f'call void @llvm.masked.store.v{n}{ity}.p0(<{n} x {ity}> {val}, ptr {p}, '
               f'i32 1, <{n} x i1> {mask})')

    def _r33any(self, m, n):
        """does <n x i1> have any bit set -> i1"""
        b = self.t(); self.e(f'{b} = bitcast <{n} x i1> {m} to i{n}')
        r = self.t(); self.e(f'{r} = icmp ne i{n} {b}, 0')
        return r

    # ── floating point, the ARM way ──────────────────────────────────────────────────
    def _r33fbits(self, ty):
        n = int(ty[1:].split(' x ')[0]); el = ty.split(' x ')[1].rstrip('>')
        eb = {'half': 16, 'float': 32, 'double': 64}[el]
        return n, el, eb, f'<{n} x i{eb}>'

    def _r33nan(self, ty, r, ins):
        """ ARM NaN SELECTION. x86 returns the FIRST SOURCE's NaN and a NEGATIVE default
           NaN for an invalid operation; ARM returns the first SIGNALLING NaN (quieted),
           else the first QUIET NaN, in operand order, and a POSITIVE default NaN.
           `ins` is in ARM's priority order, AFTER any FPNeg (which flips a NaN's sign)."""
        n, el, eb, ity = self._r33fbits(ty)
        qb, dn = self.R33_QB[eb], self.R33_DN[eb]
        isn = self.t(); self.e(f'{isn} = fcmp uno {ty} {r}, {r}')
        rb = self.t(); self.e(f'{rb} = bitcast {ty} {r} to {ity}')
        dnv = self.sve_splat(ity, n, f'i{eb}', str(dn))
        out = self.t(); self.e(f'{out} = select <{n} x i1> {isn}, {ity} {dnv}, {ity} {rb}')
        qv = self.sve_splat(ity, n, f'i{eb}', str(qb))
        info = []
        for x in ins:
            xb = self.t(); self.e(f'{xb} = bitcast {ty} {x} to {ity}')
            xn = self.t(); self.e(f'{xn} = fcmp uno {ty} {x}, {x}')
            qa = self.t(); self.e(f'{qa} = and {ity} {xb}, {qv}')
            iq = self.t(); self.e(f'{iq} = icmp ne {ity} {qa}, zeroinitializer')
            isq = self.t(); self.e(f'{isq} = and <{n} x i1> {xn}, {iq}')
            niq = self.t(); self.e(f'{niq} = xor <{n} x i1> {iq}, '
                                   f'<{", ".join(["i1 true"] * n)}>')
            iss = self.t(); self.e(f'{iss} = and <{n} x i1> {xn}, {niq}')
            qq = self.t(); self.e(f'{qq} = or {ity} {xb}, {qv}')
            info.append((xb, isq, iss, qq))
        for xb, isq, iss, qq in reversed(info):
            o = self.t(); self.e(f'{o} = select <{n} x i1> {isq}, {ity} {xb}, {ity} {out}')
            out = o
        for xb, isq, iss, qq in reversed(info):
            o = self.t(); self.e(f'{o} = select <{n} x i1> {iss}, {ity} {qq}, {ity} {out}')
            out = o
        f = self.t(); self.e(f'{f} = bitcast {ity} {out} to {ty}')
        return f

    def _r33fclass(self, ty, x):
        """-> (is_inf, is_zero) as <n x i1>"""
        n, el, eb, ity = self._r33fbits(ty)
        ab = self.t(); self.e(f'{ab} = call {ty} @llvm.fabs.{_sve_sfx(n, el)}({ty} {x})')
        inf = {16: '0xH7C00', 32: '0x7FF0000000000000', 64: '0x7FF0000000000000'}[eb]
        ii = self.t()
        self.e(f'{ii} = fcmp oeq {ty} {ab}, {self._r33c(ty, n, [inf] * n)}')
        iz = self.t(); self.e(f'{iz} = fcmp oeq {ty} {ab}, zeroinitializer')
        return ii, iz

    def _r33fma(self, ty, addend, op1, op2):
        """ FPMulAdd(addend, op1, op2): fused, ARM NaN priority addend > op1 > op2, and
            a QUIET-NaN addend with an inf*0 product is the DEFAULT NaN, not the addend."""
        n, el, eb, ity = self._r33fbits(ty)
        r = self.t()
        self.e(f'{r} = call {ty} @llvm.fma.{_sve_sfx(n, el)}({ty} {op1}, {ty} {op2}, '
               f'{ty} {addend})')
        r = self._r33nan(ty, r, [addend, op1, op2])
        i1, z1 = self._r33fclass(ty, op1)
        i2, z2 = self._r33fclass(ty, op2)
        a_ = self.t(); self.e(f'{a_} = and <{n} x i1> {i1}, {z2}')
        b_ = self.t(); self.e(f'{b_} = and <{n} x i1> {z1}, {i2}')
        iz = self.t(); self.e(f'{iz} = or <{n} x i1> {a_}, {b_}')
        ab = self.t(); self.e(f'{ab} = bitcast {ty} {addend} to {ity}')
        an = self.t(); self.e(f'{an} = fcmp uno {ty} {addend}, {addend}')
        qv = self.sve_splat(ity, n, f'i{eb}', str(self.R33_QB[eb]))
        qa = self.t(); self.e(f'{qa} = and {ity} {ab}, {qv}')
        iq = self.t(); self.e(f'{iq} = icmp ne {ity} {qa}, zeroinitializer')
        aq = self.t(); self.e(f'{aq} = and <{n} x i1> {an}, {iq}')
        hit = self.t(); self.e(f'{hit} = and <{n} x i1> {aq}, {iz}')
        rb = self.t(); self.e(f'{rb} = bitcast {ty} {r} to {ity}')
        dnv = self.sve_splat(ity, n, f'i{eb}', str(self.R33_DN[eb]))
        o = self.t(); self.e(f'{o} = select <{n} x i1> {hit}, {ity} {dnv}, {ity} {rb}')
        f = self.t(); self.e(f'{f} = bitcast {ity} {o} to {ty}')
        return f

    def _r33fbin(self, op, ty, x, y):
        n, el, eb, ity = self._r33fbits(ty)
        r = self.t()
        if op in ('fadd', 'fsub', 'fmul'):
            self.e(f'{r} = {op} {ty} {x}, {y}')
        else:
            self.e(f'{r} = call {ty} @llvm.{op}.{_sve_sfx(n, el)}({ty} {x}, {ty} {y})')
        return self._r33nan(ty, r, [x, y])

    @staticmethod
    def _r33fimm(tok, eb):
        """'#-0.93750000' -> the IEEE bit pattern at width eb"""
        import struct as _st
        v = float(tok.strip().lstrip('#'))
        fmt = {16: ('<e', '<H'), 32: ('<f', '<I'), 64: ('<d', '<Q')}[eb]
        return _st.unpack(fmt[1], _st.pack(fmt[0], v))[0]

    def _r33merge(self, pg, r, ty, n, eb, dslot):
        """apply a /m or /z governing predicate to a computed result"""
        p = self._r33p(pg)
        if not p or p[2] not in ('m', 'z'):
            raise NotImplementedError(f'R33: predication {pg!r} unmodelled')
        m = self._r33mask(self._r33pv(p[0]), n, eb)
        if p[2] == 'm':
            ob = self.t(); self.e(f'{ob} = load <{SVL_B} x i8>, ptr %{dslot}')
            old = self.t(); self.e(f'{old} = bitcast <{SVL_B} x i8> {ob} to {ty}')
        else:
            old = 'zeroinitializer'
        s = self.t(); self.e(f'{s} = select <{n} x i1> {m}, {ty} {r}, {ty} {old}')
        return s

    def _r33scalar_out(self, slot, val, el):
        """a scalar SIMD result: element 0 = val, the WHOLE rest of the Z register zero."""
        eb = {'half': 16, 'float': 32, 'double': 64, 'i8': 8, 'i16': 16, 'i32': 32,
              'i64': 64}[el]
        n = SVL_BITS // eb
        v = self.t(); self.e(f'{v} = insertelement <{n} x {el}> zeroinitializer, '
                             f'{el} {val}, i32 0')
        self._r33st(slot, v, f'<{n} x {el}>')

    # ── MOV and its aliases: dup, cpy, sel, orr, mova ────────────────────────────────
    def _r33_mov(self, ops):
        d = ops[0].strip()
        if d.startswith('{'):
            return self._r33_mova_multi(ops)
        if d.lower().startswith('za'):
            return self._r33_mova_w(ops)
        if self._r33p(d):
            return self._r33_pmov(ops)
        zd = self._r33z(d)
        if not zd or zd[1] is None or zd[2] is not None:
            return False
        if len(ops) == 2:
            return self._r33_dup(zd, ops[1])
        if len(ops) == 3:
            if ops[2].strip().lower().startswith('za'):
                return self._r33_mova_r(zd, ops[1], ops[2])
            return self._r33_cpy(zd, ops[1], ops[2])
        return False

    def _r33_src(self, suf, src, fp=False):
        """the value a dup/cpy broadcasts, as a splat of the element type"""
        n, el, eb, ty = self._r33ty(suf)
        s = src.strip().lower()
        if s.startswith('#'):
            if re.search(r'[.]|e[+-]', s):
                v = self._r33fimm(s, eb)
            else:
                v = simm(s) & ((1 << eb) - 1)
            return self.sve_splat(ty, n, el, str(v)), ty, n, el, eb
        sv = self._r33v(s)
        if sv:
            if sv[1] != eb:
                raise NotImplementedError(f'R33: {src!r} width differs from .{suf}')
            x = self.sme_ld(sv[0], n, el)
            r = self.t()
            self.e(f'{r} = shufflevector {ty} {x}, {ty} poison, <{n} x i32> zeroinitializer')
            return r, ty, n, el, eb
        if re.fullmatch(r'[wx]\d+|[wx]zr|sp|wsp', s):
            g = self.rd(s)
            if eb < 64:
                tr = self.t(); self.e(f'{tr} = trunc i64 {g} to {el}'); g = tr
            elif eb > 64:
                raise NotImplementedError(f'R33: {src!r} into .{suf}')
            return self.sve_splat(ty, n, el, g), ty, n, el, eb
        z = self._r33z(s)
        if z and z[1] == suf:
            x = self.sme_ld(z[0], n, el)
            if z[2] is None:
                return x, ty, n, el, eb
            if z[2] >= n:
                return 'zeroinitializer', ty, n, el, eb
            r = self.t()
            self.e(f'{r} = shufflevector {ty} {x}, {ty} poison, '
                   f'<{n} x i32> <{", ".join([f"i32 {z[2]}"] * n)}>')
            return r, ty, n, el, eb
        raise NotImplementedError(f'R33: dup/cpy source {src!r} unmodelled')

    def _r33_dup(self, zd, src):
        v, ty, n, el, eb = self._r33_src(zd[1], src)
        self._r33st(zd[0], v, ty)
        return True

    def _r33_cpy(self, zd, pg, src):
        v, ty, n, el, eb = self._r33_src(zd[1], src)
        self._r33st(zd[0], self._r33merge(pg, v, ty, n, eb, zd[0]), ty)
        return True

    def _r33_fmov(self, ops):
        zd = self._r33z(ops[0])
        if not zd or zd[1] not in ('h', 's', 'd') or not ops[-1].strip().startswith('#'):
            return False
        n, el, eb, ty = self._r33ty(zd[1])
        v = self.sve_splat(ty, n, el, str(self._r33fimm(ops[-1], eb)))
        if len(ops) == 3:
            v = self._r33merge(ops[1], v, ty, n, eb, zd[0])
        elif len(ops) != 2:
            return False
        self._r33st(zd[0], v, ty)
        return True

    def _r33_pmov(self, ops):
        d = self._r33p(ops[0])
        if len(ops) == 2:
            s = self._r33p(ops[1])
            if not s:
                return False
            self.e(f'store i64 {self._r33pv(s[0])}, ptr %{d[0]}')
            return True
        g, s = self._r33p(ops[1]), self._r33p(ops[2])
        if not (g and s) or g[2] not in ('z', 'm'):
            return False
        gv, sv = self._r33pv(g[0]), self._r33pv(s[0])
        r = self.t(); self.e(f'{r} = and i64 {gv}, {sv}')
        if g[2] == 'm':
            ng = self.t(); self.e(f'{ng} = xor i64 {gv}, -1')
            od = self._r33pv(d[0])
            ko = self.t(); self.e(f'{ko} = and i64 {od}, {ng}')
            r2 = self.t(); self.e(f'{r2} = or i64 {r}, {ko}')
            r = r2
        self.e(f'store i64 {r}, ptr %{d[0]}')
        return True

    def _r33_movprfx(self, ops):
        d, s = self._r33z(ops[0]), self._r33z(ops[-1])
        if not (d and s):
            return False
        if len(ops) == 2:
            b = self.t(); self.e(f'{b} = load <{SVL_B} x i8>, ptr %{s[0]}')
            self.e(f'store <{SVL_B} x i8> {b}, ptr %{d[0]}')
            return True
        if len(ops) != 3 or not d[1]:
            return False
        x, ty, n, el, eb = self._r33ld(s[0], d[1])
        self._r33st(d[0], self._r33merge(ops[1], x, ty, n, eb, d[0]), ty)
        return True

    # ── ZA tile slices (any element size, including .q) ─────────────────────────────
    ZA_SL = re.compile(r'^\{?\s*za(\d+)([hv])\.([bhsdq])\[\s*(w\d+)\s*,\s*'
                       r'(-?(?:0x)?[0-9a-f]+)\s*(?::\s*(-?(?:0x)?[0-9a-f]+)\s*)?\]\s*\}?$')

    def _r33slice(self, tok):
        m = self.ZA_SL.match(tok.strip().lower())
        if not m:
            return None
        lo = int(m.group(5), 0)
        hi = int(m.group(6), 0) if m.group(6) else lo
        return {'tile': int(m.group(1)), 'vert': m.group(2) == 'v', 'suf': m.group(3),
                'w': m.group(4), 'off': lo, 'count': hi - lo + 1}

    def _r33sidx(self, sl, k):
        """slice index (w + off + k) mod dim, as i64"""
        eb = SVE_EL[sl['suf']][0]
        dim = SVL_BITS // eb
        w = self.rd(sl['w'])
        cnt = sl.get('count', 1)
        if cnt > 1:
            #  R33c A GROUP STARTS ALIGNED: w=34 on a .d vgx4 read slices 0..3 (M4).
            s = self.t(); self.e(f"{s} = add i64 {w}, {sl['off']}")
            m = self.t(); self.e(f'{m} = and i64 {s}, {(dim - 1) & ~(cnt - 1)}')
            if k:
                m2 = self.t(); self.e(f'{m2} = add i64 {m}, {k}'); m = m2
            return m
        s = self.t(); self.e(f"{s} = add i64 {w}, {sl['off'] + k}")
        m = self.t(); self.e(f'{m} = and i64 {s}, {dim - 1}')
        return m

    def _r33row(self, tile, S, i):
        """array vector of tile row i: T + S*i, i an i64 value or a python int"""
        if isinstance(i, int):
            return tile + S * i
        x = self.t(); self.e(f'{x} = mul i64 {i}, {S}')
        y = self.t(); self.e(f'{y} = add i64 {x}, {tile}')
        return y

    def _r33sl_rd(self, sl, k=0):
        """read slice k of a (possibly ranged) tile slice -> (<n x el> value, ty)"""
        suf = sl['suf']
        eb, ity = SVE_EL[suf][0], SVE_EL[suf][1]
        n = SVL_BITS // eb
        S = eb // 8
        ty = f'<{n} x {ity}>'
        s = self._r33sidx(sl, k)
        if not sl['vert']:
            return self.za_ld(self._r33row(sl['tile'], S, s), n, ity), ty
        acc = 'poison'
        for i in range(n):
            row = self.za_ld(self._r33row(sl['tile'], S, i), n, ity)
            v = self.t(); self.e(f'{v} = extractelement {ty} {row}, i64 {s}')
            nx = self.t(); self.e(f'{nx} = insertelement {ty} {acc}, {ity} {v}, i32 {i}')
            acc = nx
        return acc, ty

    def _r33sl_wr(self, sl, val, mask, k=0):
        """merge val into slice k of sl under mask (<n x i1>)"""
        suf = sl['suf']
        eb, ity = SVE_EL[suf][0], SVE_EL[suf][1]
        n = SVL_BITS // eb
        S = eb // 8
        ty = f'<{n} x {ity}>'
        s = self._r33sidx(sl, k)
        if not sl['vert']:
            row = self._r33row(sl['tile'], S, s)
            old = self.za_ld(row, n, ity)
            r = self.t(); self.e(f'{r} = select <{n} x i1> {mask}, {ty} {val}, {ty} {old}')
            self.za_st(row, r, n, ity)
            return
        for i in range(n):
            row = self._r33row(sl['tile'], S, i)
            old = self.za_ld(row, n, ity)
            cur = self.t(); self.e(f'{cur} = extractelement {ty} {old}, i64 {s}')
            nv = self.t(); self.e(f'{nv} = extractelement {ty} {val}, i32 {i}')
            mb = self.t(); self.e(f'{mb} = extractelement <{n} x i1> {mask}, i32 {i}')
            pick = self.t(); self.e(f'{pick} = select i1 {mb}, {ity} {nv}, {ity} {cur}')
            upd = self.t(); self.e(f'{upd} = insertelement {ty} {old}, {ity} {pick}, i64 {s}')
            self.za_st(row, upd, n, ity)

    def _r33_mova_multi(self, ops):
        if len(ops) != 2:
            return False
        sl = self._r33slice(ops[1])
        if not sl:
            return False
        slots, suf = self.sme_list(ops[0])[:2]
        if suf != sl['suf'] or len(slots) != sl['count']:
            return False
        vals = [self._r33sl_rd(sl, k) for k in range(sl['count'])]
        for slot, (v, ty) in zip(slots, vals):
            self._r33st(slot, v, ty)
        return True

    def _r33_mova_r(self, zd, pg, src):
        sl = self._r33slice(src)
        if not sl or sl['count'] != 1 or sl['suf'] != zd[1]:
            return False
        v, ty = self._r33sl_rd(sl)
        n, eb = int(ty[1:].split(' x ')[0]), SVE_EL[sl['suf']][0]
        self._r33st(zd[0], self._r33merge(pg, v, ty, n, eb, zd[0]), ty)
        return True

    def _r33_mova_w(self, ops):
        if len(ops) >= 2 and ops[1].strip().startswith('{'):
            #  R33e mov za<T><h|v>.<t>[w, lo:hi], { zn.. } — unpredicated, the group
            #    aligned exactly as the read is (R33c/R33d, measured on the M4).
            sl = self._r33slice(ops[0])
            if not sl or sl['count'] < 2:
                return False
            slots, suf = self.sme_list(', '.join(o.strip() for o in ops[1:]))[:2]
            if suf != sl['suf'] or len(slots) != sl['count']:
                return False
            eb, ity = SVE_EL[suf][0], SVE_EL[suf][1]
            n = SVL_BITS // eb
            ones = self.sve_splat(f'<{n} x i1>', n, 'i1', 'true')
            for k, slot in enumerate(slots):
                self._r33sl_wr(sl, self.sme_ld(slot, n, ity), ones, k)
            return True
        if len(ops) != 3:
            return False
        sl, z = self._r33slice(ops[0]), self._r33z(ops[2])
        if not sl or sl['count'] != 1 or not z or z[1] != sl['suf']:
            return False
        eb, ity = SVE_EL[sl['suf']][0], SVE_EL[sl['suf']][1]
        n = SVL_BITS // eb
        p = self._r33p(ops[1])
        if not p or p[2] != 'm':
            return False
        m = self._r33mask(self._r33pv(p[0]), n, eb)
        self._r33sl_wr(sl, self.sme_ld(z[0], n, ity), m)
        return True

    # ── ZA slice / ZA vector / ZT0 memory ───────────────────────────────────────────
    def _r33_slice_mem(self, ops, store):
        sl = self._r33slice(ops[0])
        if not sl or sl['count'] != 1 or len(ops) != 3:
            return None
        eb, ity = SVE_EL[sl['suf']][0], SVE_EL[sl['suf']][1]
        n = SVL_BITS // eb
        p = self._r33p(ops[1])
        if not p or (store and p[2]) or (not store and p[2] != 'z'):
            return None
        addr = self._r33addr(ops[2], SVL_B)
        m = self._r33mask(self._r33pv(p[0]), n, eb)
        if eb == 128:
            #  a .q slice moves as 8 x i64, each quadword's predicate bit twice
            idx = ', '.join(f'i32 {i // 2}' for i in range(8))
            m2 = self.t()
            self.e(f'{m2} = shufflevector <4 x i1> {m}, <4 x i1> poison, <8 x i32> <{idx}>')
            if store:
                v, ty = self._r33sl_rd(sl)
                b = self.t(); self.e(f'{b} = bitcast {ty} {v} to <8 x i64>')
                self._r33mstore(addr, b, 8, 'i64', m2)
            else:
                ld = self._r33mload(addr, 8, 'i64', m2)
                b = self.t(); self.e(f'{b} = bitcast <8 x i64> {ld} to <4 x i128>')
                all1 = '<' + ', '.join(['i1 true'] * 4) + '>'
                self._r33sl_wr(sl, b, all1)
            return True
        if store:
            v, ty = self._r33sl_rd(sl)
            self._r33mstore(addr, v, n, ity, m)
        else:
            ld = self._r33mload(addr, n, ity, m)
            all1 = '<' + ', '.join(['i1 true'] * n) + '>'
            self._r33sl_wr(sl, ld, all1)
        return True

    ZA_VEC = re.compile(r'^za\[\s*(w\d+)\s*,\s*#?((?:0x)?[0-9a-f]+)\s*(?:,\s*mul vl\s*)?\]$')

    def _r33_ldst_whole(self, ops, store):
        """ldr/str of a z register, a p register, a ZA array vector, or ZT0"""
        d = ops[0].strip().lower()
        if len(ops) != 2:
            return False
        if d == 'zt0':
            addr = self._r33addr(ops[1], SVL_B)
            p = self.iptr(addr)
            if store:
                v = self.t(); self.e(f'{v} = load <{SVL_B} x i8>, ptr %zt0')
                self.e(f'store <{SVL_B} x i8> {v}, ptr {p}, align 1')
            else:
                v = self.t(); self.e(f'{v} = load <{SVL_B} x i8>, ptr {p}, align 1')
                self.e(f'store <{SVL_B} x i8> {v}, ptr %zt0')
            return True
        m = self.ZA_VEC.match(d)
        if m:
            #  ldr/str za[Wv, #off], [Xn{, #off, mul vl}]: vector (Wv+off) mod 64 <-> 64
            #    bytes at Xn + off*SVL. The two offsets are ONE encoded field.
            off = int(m.group(2), 0)
            w = self.rd(m.group(1))
            s = self.t(); self.e(f'{s} = add i64 {w}, {off}')
            row = self.t(); self.e(f'{row} = and i64 {s}, {SVL_B - 1}')
            addr = self._r33addr(ops[1], SVL_B)
            p = self.iptr(addr)
            rp = self.za_rowptr(row)
            if store:
                v = self.t(); self.e(f'{v} = load <{SVL_B} x i8>, ptr {rp}')
                self.e(f'store <{SVL_B} x i8> {v}, ptr {p}, align 1')
            else:
                v = self.t(); self.e(f'{v} = load <{SVL_B} x i8>, ptr {p}, align 1')
                self.e(f'store <{SVL_B} x i8> {v}, ptr {rp}')
            return True
        z, pr = self._r33z(d), self._r33p(d)
        if z and z[1] is None and z[2] is None:
            addr = self._r33addr(ops[1], SVL_B)
            p = self.iptr(addr)
            if store:
                v = self.t(); self.e(f'{v} = load <{SVL_B} x i8>, ptr %{z[0]}')
                self.e(f'store <{SVL_B} x i8> {v}, ptr {p}, align 1')
            else:
                v = self.t(); self.e(f'{v} = load <{SVL_B} x i8>, ptr {p}, align 1')
                self.e(f'store <{SVL_B} x i8> {v}, ptr %{z[0]}')
            return True
        if pr and pr[1] is None and pr[2] is None:
            #  A PREDICATE IS SVL/8 = 8 BYTES and its `mul vl` scales by 8, not 64.
            addr = self._r33addr(ops[1], SVL_B // 8)
            p = self.iptr(addr)
            if store:
                v = self._r33pv(pr[0])
                self.e(f'store i64 {v}, ptr {p}, align 1')
            else:
                v = self.t(); self.e(f'{v} = load i64, ptr {p}, align 1')
                self.e(f'store i64 {v}, ptr %{pr[0]}')
            return True
        return False

    def _r33_ldr(self, ops):
        return self._r33_ldst_whole(ops, False)

    def _r33_str(self, ops):
        return self._r33_ldst_whole(ops, True)

    def _r33_zero(self, ops):
        if len(ops) == 1 and ops[0].replace(' ', '').lower() == '{zt0}':
            self.e(f'store <{SVL_B} x i8> zeroinitializer, ptr %zt0')
            return True
        return False

    # ── contiguous / structured / replicating loads and stores ─────────────────────
    MSZ = {'b': 8, 'h': 16, 'w': 32, 'd': 64, 'q': 128}

    def _r33_ld1(self, mn, ops):
        m = re.fullmatch(r'(ld|st)(nt)?1(s?)([bhwd])', mn)
        if not m or len(ops) != 3:
            return False
        store, signed, msz = m.group(1) == 'st', m.group(3) == 's', self.MSZ[m.group(4)]
        if ops[0].strip().startswith('{') and 'za' in ops[0].lower():
            if self._r33slice(ops[0]) is None:
                return False
            r = self._r33_slice_mem(ops, store)
            return bool(r)
        slots, suf, eb, ity = self.sme_list(ops[0])[:4]
        n = SVL_BITS // eb
        nvec = len(slots)
        if eb < msz or (store and eb != msz and nvec > 1) or (eb != msz and nvec > 1):
            return False
        pnt = self.pn_slot(ops[1])
        pr = None if pnt else self._r33p(ops[1])
        if not pnt and not pr:
            return False
        if pr and ((store and pr[2]) or (not store and pr[2] != 'z')):
            return False
        if pnt:
            masks = self.sme_masks(ops[1], n, eb, nvec)
        else:
            if nvec != 1:
                return False
            masks = [self._r33mask(self._r33pv(pr[0]), n, eb)]
        foot = n * msz // 8                     #  one vector's memory footprint
        base = self._r33addr(ops[2], foot)
        mty = f'i{msz}'
        for k, (slot, mk) in enumerate(zip(slots, masks)):
            ad = base
            if k:
                ad = self.t(); self.e(f'{ad} = add i64 {base}, {k * foot}')
            if store:
                v = self.sme_ld(slot, n, ity)
                if msz < eb:
                    tr = self.t(); self.e(f'{tr} = trunc <{n} x {ity}> {v} to <{n} x {mty}>')
                    v = tr
                self._r33mstore(ad, v, n, mty, mk)
            else:
                v = self._r33mload(ad, n, mty, mk)
                if msz < eb:
                    x = self.t()
                    self.e(f'{x} = {"sext" if signed else "zext"} <{n} x {mty}> {v} '
                           f'to <{n} x {ity}>')
                    v = x
                self.sme_st(slot, v, n, ity)
        return True

    def _r33_ld1b(self, ops): return self._r33_ld1('ld1b', ops)
    def _r33_ld1h(self, ops): return self._r33_ld1('ld1h', ops)
    def _r33_ld1w(self, ops): return self._r33_ld1('ld1w', ops)
    def _r33_ld1d(self, ops): return self._r33_ld1('ld1d', ops)
    def _r33_ld1sb(self, ops): return self._r33_ld1('ld1sb', ops)
    def _r33_ld1sh(self, ops): return self._r33_ld1('ld1sh', ops)
    def _r33_ld1sw(self, ops): return self._r33_ld1('ld1sw', ops)
    def _r33_st1b(self, ops): return self._r33_ld1('st1b', ops)
    def _r33_st1h(self, ops): return self._r33_ld1('st1h', ops)
    def _r33_st1w(self, ops): return self._r33_ld1('st1w', ops)
    def _r33_st1d(self, ops): return self._r33_ld1('st1d', ops)
    def _r33_stnt1b(self, ops): return self._r33_ld1('stnt1b', ops)
    def _r33_stnt1h(self, ops): return self._r33_ld1('stnt1h', ops)
    def _r33_stnt1w(self, ops): return self._r33_ld1('stnt1w', ops)
    def _r33_stnt1d(self, ops): return self._r33_ld1('stnt1d', ops)
    def _r33_ldnt1b(self, ops): return self._r33_ld1('ldnt1b', ops)
    def _r33_ldnt1h(self, ops): return self._r33_ld1('ldnt1h', ops)
    def _r33_ldnt1w(self, ops): return self._r33_ld1('ldnt1w', ops)
    def _r33_ldnt1d(self, ops): return self._r33_ld1('ldnt1d', ops)

    def _r33_st1q(self, ops):
        if not ops[0].strip().startswith('{') or self._r33slice(ops[0]) is None:
            return False
        return bool(self._r33_slice_mem(ops, True))

    def _r33_ld1q(self, ops):
        if not ops[0].strip().startswith('{') or self._r33slice(ops[0]) is None:
            return False
        return bool(self._r33_slice_mem(ops, False))

    def _r33_ldn(self, mn, ops):
        """ld2/ld3/ld4 and st2/st3/st4: element i of vector k is memory element N*i + k."""
        m = re.fullmatch(r'(ld|st)([234])([bhwd])', mn)
        if not m or len(ops) != 3:
            return False
        store, N, msz = m.group(1) == 'st', int(m.group(2)), self.MSZ[m.group(3)]
        t = ops[0].strip()
        inner = [x.strip() for x in t[1:-1].replace(' - ', ',').split(',') if x.strip()]
        zs = [self._r33z(x) for x in inner]
        if not all(zs) or len({z[1] for z in zs}) != 1:
            return False
        if len(zs) == 2 and N > 2:
            # `{ z26.s - z29.s }` spelled as a range: expand it
            a0, a1 = int(zs[0][0][1:]), int(zs[1][0][1:])
            slots = [f'v{(a0 + i) % 32}' for i in range((a1 - a0) % 32 + 1)]
        else:
            slots = [z[0] for z in zs]
        if len(slots) != N:
            return False
        suf = zs[0][1]
        eb, ity = SVE_EL[suf][0], SVE_EL[suf][1]
        if eb != msz:
            return False
        n = SVL_BITS // eb
        p = self._r33p(ops[1])
        if not p or (store and p[2]) or (not store and p[2] != 'z'):
            return False
        mk = self._r33mask(self._r33pv(p[0]), n, eb)
        idx = ', '.join(f'i32 {j // N}' for j in range(N * n))
        big = self.t()
        self.e(f'{big} = shufflevector <{n} x i1> {mk}, <{n} x i1> poison, '
               f'<{N * n} x i32> <{idx}>')
        addr = self._r33addr(ops[2], n * msz // 8)
        vty = f'<{n} x {ity}>'
        if store:
            vs = [self.sme_ld(s, n, ity) for s in slots]
            # interleave: out[N*i + k] = v_k[i], built by widening shuffles
            cat = self._r33cat(vs, n, ity)
            order = ', '.join(f'i32 {(j % N) * n + j // N}' for j in range(N * n))
            il = self.t()
            self.e(f'{il} = shufflevector <{N * n} x {ity}> {cat}, <{N * n} x {ity}> poison, '
                   f'<{N * n} x i32> <{order}>')
            self._r33mstore(addr, il, N * n, ity, big)
        else:
            ld = self._r33mload(addr, N * n, ity, big)
            for k, s in enumerate(slots):
                sel = ', '.join(f'i32 {N * i + k}' for i in range(n))
                v = self.t()
                self.e(f'{v} = shufflevector <{N * n} x {ity}> {ld}, <{N * n} x {ity}> poison, '
                       f'<{n} x i32> <{sel}>')
                self.sme_st(s, v, n, ity)
        return True

    def _r33cat(self, vs, n, el):
        """concatenate a list of <n x el> (length 1, 2 or 4) into <len*n x el>"""
        cur, w = vs, n
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur), 2):
                idx = ', '.join(f'i32 {j}' for j in range(2 * w))
                r = self.t()
                self.e(f'{r} = shufflevector <{w} x {el}> {cur[i]}, <{w} x {el}> {cur[i + 1]}, '
                       f'<{2 * w} x i32> <{idx}>')
                nxt.append(r)
            cur, w = nxt, 2 * w
        return cur[0]

    def _r33_ld4w(self, ops): return self._r33_ldn('ld4w', ops)
    def _r33_ld2w(self, ops): return self._r33_ldn('ld2w', ops)
    def _r33_ld2d(self, ops): return self._r33_ldn('ld2d', ops)
    def _r33_ld4h(self, ops): return self._r33_ldn('ld4h', ops)
    def _r33_st2w(self, ops): return self._r33_ldn('st2w', ops)
    def _r33_st2d(self, ops): return self._r33_ldn('st2d', ops)
    def _r33_st4h(self, ops): return self._r33_ldn('st4h', ops)
    def _r33_st4w(self, ops): return self._r33_ldn('st4w', ops)

    def _r33_ld1r(self, mn, ops):
        """ld1r{b,h,w,d}: ONE element, broadcast to the active lanes, inactive zero.
            THE LOAD IS SKIPPED WHEN NO LANE IS ACTIVE (the architecture suppresses the
              access), so its pointer is steered to %zt0 — a real alloca — in that case."""
        m = re.fullmatch(r'ld1r(s?)([bhwd])', mn)
        if not m or len(ops) != 3:
            return False
        signed, msz = m.group(1) == 's', self.MSZ[m.group(2)]
        z = self._r33z(ops[0].strip().strip('{}').strip())
        if not z or not z[1]:
            return False
        n, el, eb, ty = self._r33ty(z[1])
        if eb < msz:
            return False
        p = self._r33p(ops[1])
        if not p or p[2] != 'z':
            return False
        mk = self._r33mask(self._r33pv(p[0]), n, eb)
        addr = self._r33addr(ops[2], 1)
        anyv = self._r33any(mk, n)
        ap = self.iptr(addr)
        sp_ = self.t(); self.e(f'{sp_} = select i1 {anyv}, ptr {ap}, ptr %zt0')
        v = self.t(); self.e(f'{v} = load i{msz}, ptr {sp_}, align 1')
        if msz < eb:
            x = self.t(); self.e(f'{x} = {"sext" if signed else "zext"} i{msz} {v} to {el}')
            v = x
        s = self.sve_splat(ty, n, el, v)
        r = self.t(); self.e(f'{r} = select <{n} x i1> {mk}, {ty} {s}, {ty} zeroinitializer')
        self._r33st(z[0], r, ty)
        return True

    def _r33_ld1rb(self, ops): return self._r33_ld1r('ld1rb', ops)
    def _r33_ld1rh(self, ops): return self._r33_ld1r('ld1rh', ops)
    def _r33_ld1rw(self, ops): return self._r33_ld1r('ld1rw', ops)
    def _r33_ld1rd(self, ops): return self._r33_ld1r('ld1rd', ops)
    def _r33_ld1rsb(self, ops): return self._r33_ld1r('ld1rsb', ops)
    def _r33_ld1rsh(self, ops): return self._r33_ld1r('ld1rsh', ops)
    def _r33_ld1rsw(self, ops): return self._r33_ld1r('ld1rsw', ops)

    def _r33_ld1rq(self, mn, ops):
        """ld1rq{b,h,w,d}: 16 bytes under the FIRST segment's predicate, replicated."""
        m = re.fullmatch(r'ld1rq([bhwd])', mn)
        z = self._r33z(ops[0].strip().strip('{}').strip())
        if not m or len(ops) != 3 or not z or not z[1]:
            return False
        eb, ity = SVE_EL[z[1]][0], SVE_EL[z[1]][1]
        if eb != self.MSZ[m.group(1)]:
            return False
        n, q = SVL_BITS // eb, 128 // eb
        p = self._r33p(ops[1])
        if not p or p[2] != 'z':
            return False
        mk = self._r33mask(self._r33pv(p[0]), n, eb)
        idx = ', '.join(f'i32 {i}' for i in range(q))
        m0 = self.t()
        self.e(f'{m0} = shufflevector <{n} x i1> {mk}, <{n} x i1> poison, <{q} x i32> <{idx}>')
        addr = self._r33addr(ops[2], 16)
        ld = self._r33mload(addr, q, ity, m0)
        rep = ', '.join(f'i32 {i % q}' for i in range(n))
        r = self.t()
        self.e(f'{r} = shufflevector <{q} x {ity}> {ld}, <{q} x {ity}> poison, <{n} x i32> <{rep}>')
        self.sme_st(z[0], r, n, ity)
        return True

    def _r33_ld1rqb(self, ops): return self._r33_ld1rq('ld1rqb', ops)
    def _r33_ld1rqh(self, ops): return self._r33_ld1rq('ld1rqh', ops)
    def _r33_ld1rqw(self, ops): return self._r33_ld1rq('ld1rqw', ops)
    def _r33_ld1rqd(self, ops): return self._r33_ld1rq('ld1rqd', ops)

    def _r33_prf(self, ops):
        """ A PREFETCH CHANGES NO ARCHITECTURAL STATE — but its operands are still
           checked, so a malformed form is not silently accepted as a hint."""
        if len(ops) != 3 or not self._r33p(ops[1]):
            return False
        t = ops[2].strip()
        return t.startswith('[') and t.endswith(']')

    def _r33_prfb(self, ops): return self._r33_prf(ops)
    def _r33_prfh(self, ops): return self._r33_prf(ops)
    def _r33_prfw(self, ops): return self._r33_prf(ops)
    def _r33_prfd(self, ops): return self._r33_prf(ops)

    # ── predicate generation and logic ───────────────────────────────────────────────
    def _r33_ptrue(self, ops):
        p = self._r33p(ops[0])
        if not p or not p[1] or len(ops) > 2:
            return False
        n = SVL_BITS // SVE_EL[p[1]][0]
        cnt = self._r33patcount(ops[1] if len(ops) == 2 else 'all', n)
        stride = SVE_EL[p[1]][0] // 8
        v = sum(1 << (i * stride) for i in range(cnt))
        self.e(f'store i64 {v}, ptr %{p[0]}')
        return True

    def _r33_pfalse(self, ops):
        p = self._r33p(ops[0])
        if not p or len(ops) != 1:
            return False
        self.e(f'store i64 0, ptr %{p[0]}')
        return True

    def _r33_ptest(self, ops):
        g, s = self._r33p(ops[0]), self._r33p(ops[1])
        if not (g and s and s[1]) or len(ops) != 2:
            return False
        pat = self.R33_PAT[s[1]]
        gv = self.t(); self.e(f'{gv} = and i64 {self._r33pv(g[0])}, {pat}')
        self._r33ptest(gv, self._r33pv(s[0]))
        return True

    def _r33plogic(self, ops, fn, flags):
        if len(ops) != 4:
            return False
        d, g, a_, b_ = (self._r33p(o) for o in ops)
        if not (d and g and a_ and b_) or g[2] != 'z' or d[1] != 'b':
            return False
        gv, av, bv = self._r33pv(g[0]), self._r33pv(a_[0]), self._r33pv(b_[0])
        r = fn(gv, av, bv)
        self.e(f'store i64 {r}, ptr %{d[0]}')
        if flags:
            self._r33ptest(gv, r)
        return True

    def _r33_bic(self, ops):
        def f(g, a_, b_):
            nb = self.t(); self.e(f'{nb} = xor i64 {b_}, -1')
            x = self.t(); self.e(f'{x} = and i64 {a_}, {nb}')
            y = self.t(); self.e(f'{y} = and i64 {x}, {g}')
            return y
        return self._r33plogic(ops, f, False) if self._r33p(ops[0]) else False

    def _r33_bics(self, ops):
        def f(g, a_, b_):
            nb = self.t(); self.e(f'{nb} = xor i64 {b_}, -1')
            x = self.t(); self.e(f'{x} = and i64 {a_}, {nb}')
            y = self.t(); self.e(f'{y} = and i64 {x}, {g}')
            return y
        return self._r33plogic(ops, f, True)

    def _r33_not(self, ops):
        # `not pd.b, pg/z, pn.b` IS eor pd, pg/z, pn, pg -> pg AND NOT pn
        if len(ops) != 3:
            return False
        d, g, s = (self._r33p(o) for o in ops)
        if not (d and g and s) or g[2] != 'z':
            return False
        gv, sv = self._r33pv(g[0]), self._r33pv(s[0])
        ns = self.t(); self.e(f'{ns} = xor i64 {sv}, -1')
        r = self.t(); self.e(f'{r} = and i64 {gv}, {ns}')
        self.e(f'store i64 {r}, ptr %{d[0]}')
        return True

    def _r33_brkb(self, ops):
        if len(ops) != 3:
            return False
        d, g, s = (self._r33p(o) for o in ops)
        if not (d and g and s) or g[2] != 'z' or d[1] != 'b':
            return False
        gv, sv = self._r33pv(g[0]), self._r33pv(s[0])
        t = self.t(); self.e(f'{t} = and i64 {sv}, {gv}')
        nt = self.t(); self.e(f'{nt} = sub i64 0, {t}')
        lo = self.t(); self.e(f'{lo} = and i64 {t}, {nt}')
        below = self.t(); self.e(f'{below} = sub i64 {lo}, 1')      # lo==0 -> all ones
        r = self.t(); self.e(f'{r} = and i64 {gv}, {below}')
        self.e(f'store i64 {r}, ptr %{d[0]}')
        return True

    CMP = {'eq': 'eq', 'ne': 'ne', 'hi': 'ugt', 'hs': 'uge', 'lo': 'ult', 'ls': 'ule',
           'gt': 'sgt', 'ge': 'sge', 'lt': 'slt', 'le': 'sle'}

    def _r33_cmpx(self, cc, ops):
        if len(ops) != 4:
            return False
        d, g, z = self._r33p(ops[0]), self._r33p(ops[1]), self._r33z(ops[2])
        if not (d and g and z and d[1] and z[1] == d[1]) or g[2] != 'z' or z[2] is not None:
            return False
        x, ty, n, el, eb = self._r33ld(z[0], z[1])
        o = ops[3].strip()
        if o.startswith('#'):
            y = self.sve_splat(ty, n, el, str(simm(o)))
        else:
            zm = self._r33z(o)
            if not zm or zm[1] != z[1]:
                return False            # the wide (.d) comparand form is a different op
            y = self.sme_ld(zm[0], n, el)
        c = self.t(); self.e(f'{c} = icmp {self.CMP[cc]} {ty} {x}, {y}')
        gv = self.t(); self.e(f'{gv} = and i64 {self._r33pv(g[0])}, {self.R33_PAT[d[1]]}')
        gm = self._r33mask(gv, n, eb)
        r = self.t(); self.e(f'{r} = and <{n} x i1> {c}, {gm}')
        rv = self._r33pack(r, n, eb)
        self.e(f'store i64 {rv}, ptr %{d[0]}')
        self._r33ptest(gv, rv)
        return True

    def _r33_cmpeq(self, ops): return self._r33_cmpx('eq', ops)
    def _r33_cmpne(self, ops): return self._r33_cmpx('ne', ops)
    def _r33_cmphi(self, ops): return self._r33_cmpx('hi', ops)
    def _r33_cmphs(self, ops): return self._r33_cmpx('hs', ops)
    def _r33_cmplo(self, ops): return self._r33_cmpx('lo', ops)
    def _r33_cmpls(self, ops): return self._r33_cmpx('ls', ops)
    def _r33_cmpgt(self, ops): return self._r33_cmpx('gt', ops)
    def _r33_cmpge(self, ops): return self._r33_cmpx('ge', ops)
    def _r33_cmplt(self, ops): return self._r33_cmpx('lt', ops)
    def _r33_cmple(self, ops): return self._r33_cmpx('le', ops)

    FCM = {'fcmeq': 'oeq', 'fcmne': 'une', 'fcmgt': 'ogt', 'fcmge': 'oge', 'fcmlt': 'olt',
           'fcmle': 'ole'}

    def _r33_fcmx(self, mn, ops):
        if len(ops) != 4:
            return False
        d, g, z = self._r33p(ops[0]), self._r33p(ops[1]), self._r33z(ops[2])
        if not (d and g and z and d[1] and z[1] == d[1]) or g[2] != 'z':
            return False
        x, ty, n, el, eb = self._r33ld(z[0], z[1], fp=True)
        o = ops[3].strip()
        if o.startswith('#'):
            if float(o.lstrip('#')) != 0.0:
                return False
            y = 'zeroinitializer'
        else:
            zm = self._r33z(o)
            if not zm or zm[1] != z[1]:
                return False
            y = self.sme_ld(zm[0], n, el)
        c = self.t(); self.e(f'{c} = fcmp {self.FCM[mn]} {ty} {x}, {y}')
        gm = self._r33mask(self._r33pv(g[0]), n, eb)
        r = self.t(); self.e(f'{r} = and <{n} x i1> {c}, {gm}')
        self.e(f'store i64 {self._r33pack(r, n, eb)}, ptr %{d[0]}')
        return True

    def _r33_fcmlt(self, ops): return self._r33_fcmx('fcmlt', ops)
    def _r33_fcmle(self, ops): return self._r33_fcmx('fcmle', ops)
    def _r33_fcmgt(self, ops): return self._r33_fcmx('fcmgt', ops)
    def _r33_fcmge(self, ops): return self._r33_fcmx('fcmge', ops)
    def _r33_fcmeq(self, ops): return self._r33_fcmx('fcmeq', ops)
    def _r33_fcmne(self, ops): return self._r33_fcmx('fcmne', ops)

    def _r33_cntp(self, ops):
        if len(ops) == 3 and ops[1].strip().lower().startswith('pn'):
            m = re.fullmatch(r'vlx([24])', ops[2].strip().lower())
            suf = ops[1].strip().lower().split('.')[-1]
            if not m or suf not in SVE_EL:
                return False
            eb = SVE_EL[suf][0]
            #  R33b count the lanes CounterToPredicate actually sets — with a marker
            #    that differs from .suf the set is not a prefix, so no count arithmetic.
            tot = None
            for mk in self.pn_lanes(ops[1].split('.')[0], eb, 0, int(m.group(1))):
                c = self._r33count(self._r33pack(mk, SVL_BITS // eb, eb), suf)
                if tot is None:
                    tot = c
                else:
                    t2 = self.t(); self.e(f'{t2} = add i64 {tot}, {c}'); tot = t2
            self.wr(ops[0], tot)
            return True
        if len(ops) != 3:
            return False
        g, s = self._r33p(ops[1]), self._r33p(ops[2])
        if not (g and s and s[1]) or not re.fullmatch(r'x\d+', ops[0].strip()):
            return False
        a_ = self.t(); self.e(f'{a_} = and i64 {self._r33pv(g[0])}, {self._r33pv(s[0])}')
        self.wr(ops[0], self._r33count(a_, s[1]))
        return True

    def _r33_incdecp(self, ops, sub, sat, signed):
        if len(ops) != 2:
            return False
        s = self._r33p(ops[1])
        r = ops[0].strip().lower()
        if not s or not s[1] or not re.fullmatch(r'[wx]\d+', r):
            return False
        c = self._r33count(self._r33pv(s[0]), s[1])
        v = self.rd(r)
        if not sat:
            o = self.t(); self.e(f'{o} = {"sub" if sub else "add"} i64 {v}, {c}')
            self.wr(r, o)
            return True
        bits = 32 if r[0] == 'w' else 64
        lo, hi = ((-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1))
        x = self.t()
        if bits == 32:
            tr = self.t(); self.e(f'{tr} = trunc i64 {v} to i32')
            self.e(f'{x} = {"sext" if signed else "zext"} i32 {tr} to i128')
        else:
            self.e(f'{x} = {"sext" if signed else "zext"} i64 {v} to i128')
        c2 = self.t(); self.e(f'{c2} = zext i64 {c} to i128')
        o = self.t(); self.e(f'{o} = {"sub" if sub else "add"} i128 {x}, {c2}')
        a1 = self.t(); self.e(f'{a1} = icmp slt i128 {o}, {lo}')
        o1 = self.t(); self.e(f'{o1} = select i1 {a1}, i128 {lo}, i128 {o}')
        a2 = self.t(); self.e(f'{a2} = icmp sgt i128 {o1}, {hi}')
        o2 = self.t(); self.e(f'{o2} = select i1 {a2}, i128 {hi}, i128 {o1}')
        t64 = self.t(); self.e(f'{t64} = trunc i128 {o2} to i64')
        if bits == 32 and signed:
            #  the 32-bit SIGNED form sign-extends into x (SQINCP Xdn, Pm.T, Wdn); only
            #    reached for `sqincp x0, p0.b, w0`, which carries a third operand — not here.
            pass
        self.wr(r, t64)
        return True

    def _r33_incp(self, ops): return self._r33_incdecp(ops, False, False, False)
    def _r33_decp(self, ops): return self._r33_incdecp(ops, True, False, False)
    def _r33_uqincp(self, ops): return self._r33_incdecp(ops, False, True, False)
    def _r33_uqdecp(self, ops): return self._r33_incdecp(ops, True, True, False)

    def _r33_sqincdec_vec(self, mn, ops):
        """sq/uq inc/dec {h,w,d} on a z register: every element +- count(pattern)*mul, saturated."""
        m = re.fullmatch(r'(sq|uq)(inc|dec)([hwd])', mn)
        z = self._r33z(ops[0])
        if not m or not z or not z[1]:
            return False
        suf = {'h': 'h', 'w': 's', 'd': 'd'}[m.group(3)]
        if z[1] != suf:
            return False
        n, el, eb, ty = self._r33ty(suf)
        pat, mul = 'all', 1
        for o in ops[1:]:
            o = o.strip().lower()
            mm = re.fullmatch(r'mul #((?:0x)?[0-9a-f]+)', o)
            if mm:
                mul = int(mm.group(1), 0)
            else:
                pat = o
        k = self._r33patcount(pat, n) * mul
        signed = m.group(1) == 'sq'
        x = self.sme_ld(z[0], n, el)
        w = f'<{n} x i{2 * eb}>'
        xw = self.t(); self.e(f'{xw} = {"sext" if signed else "zext"} {ty} {x} to {w}')
        kv = self.sve_splat(w, n, f'i{2 * eb}', str(k))
        o = self.t(); self.e(f'{o} = {"sub" if m.group(2) == "dec" else "add"} {w} {xw}, {kv}')
        lo, hi = ((-(1 << (eb - 1)), (1 << (eb - 1)) - 1) if signed else (0, (1 << eb) - 1))
        lv = self.sve_splat(w, n, f'i{2 * eb}', str(lo))
        hv = self.sve_splat(w, n, f'i{2 * eb}', str(hi))
        c1 = self.t(); self.e(f'{c1} = icmp slt {w} {o}, {lv}')
        o1 = self.t(); self.e(f'{o1} = select <{n} x i1> {c1}, {w} {lv}, {w} {o}')
        c2 = self.t(); self.e(f'{c2} = icmp sgt {w} {o1}, {hv}')
        o2 = self.t(); self.e(f'{o2} = select <{n} x i1> {c2}, {w} {hv}, {w} {o1}')
        r = self.t(); self.e(f'{r} = trunc {w} {o2} to {ty}')
        self._r33st(z[0], r, ty)
        return True

    def _r33_sqdecd(self, ops): return self._r33_sqincdec_vec('sqdecd', ops)
    def _r33_sqincd(self, ops): return self._r33_sqincdec_vec('sqincd', ops)
    def _r33_sqdecw(self, ops): return self._r33_sqincdec_vec('sqdecw', ops)
    def _r33_sqincw(self, ops): return self._r33_sqincdec_vec('sqincw', ops)
    def _r33_sqdech(self, ops): return self._r33_sqincdec_vec('sqdech', ops)
    def _r33_sqinch(self, ops): return self._r33_sqincdec_vec('sqinch', ops)

    def _r33_whilex(self, ops, rw):
        """ whilerw: diff = |xm - xn| / esize; whilewr: diff = (xm - xn) / esize.
           Element e is active when diff <= 0 (wr) / diff == 0 (rw), or e < diff."""
        if len(ops) != 3:
            return False
        d = self._r33p(ops[0])
        if not d or not d[1] or d[1] == 'q':
            return False
        eb = SVE_EL[d[1]][0]
        n = SVL_BITS // eb
        xn, xm = self.rd(ops[1]), self.rd(ops[2])
        df = self.t(); self.e(f'{df} = sub i64 {xm}, {xn}')
        if rw:
            ng = self.t(); self.e(f'{ng} = sub i64 0, {df}')
            neg = self.t(); self.e(f'{neg} = icmp slt i64 {df}, 0')
            ab = self.t(); self.e(f'{ab} = select i1 {neg}, i64 {ng}, i64 {df}')
            df = ab
        q = self.t(); self.e(f'{q} = sdiv i64 {df}, {eb // 8}')
        allc = self.t()
        self.e(f'{allc} = icmp {"eq" if rw else "sle"} i64 {q}, 0')
        lim = self.t(); self.e(f'{lim} = select i1 {allc}, i64 {n}, i64 {q}')
        sv = self.sve_splat(f'<{n} x i64>', n, 'i64', lim)
        idx = '<' + ', '.join(f'i64 {i}' for i in range(n)) + '>'
        m = self.t(); self.e(f'{m} = icmp slt <{n} x i64> {idx}, {sv}')
        rv = self._r33pack(m, n, eb)
        self.e(f'store i64 {rv}, ptr %{d[0]}')
        self._r33ptest(str(self.R33_PAT[d[1]]), rv)
        return True

    def _r33_whilerw(self, ops): return self._r33_whilex(ops, True)
    def _r33_whilewr(self, ops): return self._r33_whilex(ops, False)

    # ── permutes ─────────────────────────────────────────────────────────────────────
    def _r33_sel(self, ops):
        if ops[0].strip().startswith('{'):
            if len(ops) != 4 or not self.pn_slot(ops[1]):
                return False
            ds, suf, eb, ity = self.sme_list(ops[0])[:4]
            a_ = self.sme_list(ops[2])[0]; b_ = self.sme_list(ops[3])[0]
            n = SVL_BITS // eb
            if not (len(ds) == len(a_) == len(b_)):
                return False
            masks = self.sme_masks(ops[1], n, eb, len(ds))
            ty = f'<{n} x {ity}>'
            vals = []
            for k in range(len(ds)):
                x, y = self.sme_ld(a_[k], n, ity), self.sme_ld(b_[k], n, ity)
                r = self.t(); self.e(f'{r} = select <{n} x i1> {masks[k]}, {ty} {x}, {ty} {y}')
                vals.append(r)
            for d, v in zip(ds, vals):
                self.sme_st(d, v, n, ity)
            return True
        if len(ops) != 4:
            return False
        pd = self._r33p(ops[0])
        if pd:
            g, a_, b_ = (self._r33p(o) for o in ops[1:])
            if not (g and a_ and b_):
                return False
            gv, av, bv = self._r33pv(g[0]), self._r33pv(a_[0]), self._r33pv(b_[0])
            x = self.t(); self.e(f'{x} = and i64 {gv}, {av}')
            ng = self.t(); self.e(f'{ng} = xor i64 {gv}, -1')
            y = self.t(); self.e(f'{y} = and i64 {ng}, {bv}')
            r = self.t(); self.e(f'{r} = or i64 {x}, {y}')
            self.e(f'store i64 {r}, ptr %{pd[0]}')
            return True
        d, g, a_, b_ = self._r33z(ops[0]), self._r33p(ops[1]), self._r33z(ops[2]), self._r33z(ops[3])
        if not (d and g and a_ and b_ and d[1]) or g[2]:
            return False
        n, el, eb, ty = self._r33ty(d[1])
        m = self._r33mask(self._r33pv(g[0]), n, eb)
        x, y = self.sme_ld(a_[0], n, el), self.sme_ld(b_[0], n, el)
        r = self.t(); self.e(f'{r} = select <{n} x i1> {m}, {ty} {x}, {ty} {y}')
        self._r33st(d[0], r, ty)
        return True

    def _r33_splice(self, ops):
        """ The active SEGMENT of zn — first active element through last — then zm from
           element 0. An all-false predicate gives zm whole."""
        if len(ops) == 3 and ops[2].strip().startswith('{'):
            src = self.sme_list(ops[2])[0]
            if len(src) != 2:
                return False
        elif len(ops) == 4:
            a_, b_ = self._r33z(ops[2]), self._r33z(ops[3])
            if not (a_ and b_):
                return False
            src = [a_[0], b_[0]]
        else:
            return False
        d, g = self._r33z(ops[0]), self._r33p(ops[1])
        if not (d and g and d[1]) or g[2]:
            return False
        n, el, eb, ty = self._r33ty(d[1])
        m = self._r33mask(self._r33pv(g[0]), n, eb)
        mb = self.t(); self.e(f'{mb} = bitcast <{n} x i1> {m} to i{n}')
        mw = mb
        if n < 64:
            mw = self.t(); self.e(f'{mw} = zext i{n} {mb} to i64')
        fz = self.t(); self.e(f'{fz} = call i64 @llvm.cttz.i64(i64 {mw}, i1 false)')
        lz = self.t(); self.e(f'{lz} = call i64 @llvm.ctlz.i64(i64 {mw}, i1 false)')
        last = self.t(); self.e(f'{last} = sub i64 63, {lz}')
        ln0 = self.t(); self.e(f'{ln0} = sub i64 {last}, {fz}')
        ln1 = self.t(); self.e(f'{ln1} = add i64 {ln0}, 1')
        em = self.t(); self.e(f'{em} = icmp eq i64 {mw}, 0')
        L = self.t(); self.e(f'{L} = select i1 {em}, i64 0, i64 {ln1}')
        F = self.t(); self.e(f'{F} = select i1 {em}, i64 0, i64 {fz}')
        x, y = self.sme_ld(src[0], n, el), self.sme_ld(src[1], n, el)
        cat = self._r33cat([x, y], n, el)
        idx = '<' + ', '.join(f'i64 {i}' for i in range(n)) + '>'
        Lv = self.sve_splat(f'<{n} x i64>', n, 'i64', L)
        Fv = self.sve_splat(f'<{n} x i64>', n, 'i64', F)
        inseg = self.t(); self.e(f'{inseg} = icmp ult <{n} x i64> {idx}, {Lv}')
        i1 = self.t(); self.e(f'{i1} = add <{n} x i64> {idx}, {Fv}')
        nv = self.sve_splat(f'<{n} x i64>', n, 'i64', str(n))
        i2a = self.t(); self.e(f'{i2a} = add <{n} x i64> {idx}, {nv}')
        i2 = self.t(); self.e(f'{i2} = sub <{n} x i64> {i2a}, {Lv}')
        ix = self.t(); self.e(f'{ix} = select <{n} x i1> {inseg}, <{n} x i64> {i1}, <{n} x i64> {i2}')
        acc = 'poison'
        for i in range(n):
            j = self.t(); self.e(f'{j} = extractelement <{n} x i64> {ix}, i32 {i}')
            v = self.t(); self.e(f'{v} = extractelement <{2 * n} x {el}> {cat}, i64 {j}')
            nx = self.t(); self.e(f'{nx} = insertelement {ty} {acc}, {el} {v}, i32 {i}')
            acc = nx
        self._r33st(d[0], acc, ty)
        return True

    def _r33_ext(self, ops):
        if len(ops) == 3 and ops[1].strip().startswith('{'):
            src = self.sme_list(ops[1])[0]
            k = imm(ops[2])
        elif len(ops) == 4:
            a_, b_ = self._r33z(ops[1]), self._r33z(ops[2])
            if not (a_ and b_):
                return False
            src, k = [a_[0], b_[0]], imm(ops[3])
        else:
            return False
        d = self._r33z(ops[0])
        if not d or d[1] not in (None, 'b') or len(src) != 2:
            return False
        if k >= SVL_B:
            k = 0                                   #  an out-of-range index reads as 0
        x, y = self.sme_ld(src[0], SVL_B, 'i8'), self.sme_ld(src[1], SVL_B, 'i8')
        idx = ', '.join(f'i32 {k + i}' for i in range(SVL_B))
        r = self.t()
        self.e(f'{r} = shufflevector <{SVL_B} x i8> {x}, <{SVL_B} x i8> {y}, '
               f'<{SVL_B} x i32> <{idx}>')
        self.sme_st(d[0], r, SVL_B, 'i8')
        return True

    def _r33_insr(self, ops):
        d = self._r33z(ops[0])
        if len(ops) != 2 or not d or not d[1]:
            return False
        n, el, eb, ty = self._r33ty(d[1])
        s = ops[1].strip().lower()
        sv = self._r33v(s)
        if sv:
            if sv[1] != eb:
                return False
            v0 = self.sme_ld(sv[0], n, el)
            val = self.t(); self.e(f'{val} = extractelement {ty} {v0}, i32 0')
        elif re.fullmatch(r'[wx](\d+|zr)', s):
            g = self.rd(s)
            val = g
            if eb < 64:
                val = self.t(); self.e(f'{val} = trunc i64 {g} to {el}')
        else:
            return False
        x = self.sme_ld(d[0], n, el)
        ins = self.t(); self.e(f'{ins} = insertelement {ty} poison, {el} {val}, i32 0')
        idx = ', '.join(['i32 0'] + [f'i32 {n + i}' for i in range(n - 1)])
        r = self.t(); self.e(f'{r} = shufflevector {ty} {ins}, {ty} {x}, <{n} x i32> <{idx}>')
        self._r33st(d[0], r, ty)
        return True

    def _r33_zip(self, ops):
        """SME2 ZIP (two or four registers): the lists interleave element by element."""
        if len(ops) == 2 and ops[0].strip().startswith('{'):
            ds, suf, eb, ity = self.sme_list(ops[0])[:4]
            ss = self.sme_list(ops[1])[0]
            N = len(ds)
            if len(ss) != N or N not in (2, 4):
                return False
            n = SVL_BITS // eb
            vs = [self.sme_ld(s, n, ity) for s in ss]
            cat = self._r33cat(vs, n, ity)
            order = [(j % N) * n + j // N for j in range(N * n)]
            outs = []
            for k in range(N):
                sel = ', '.join(f'i32 {order[k * n + i]}' for i in range(n))
                r = self.t()
                self.e(f'{r} = shufflevector <{N * n} x {ity}> {cat}, <{N * n} x {ity}> poison, '
                       f'<{n} x i32> <{sel}>')
                outs.append(r)
            for d, r in zip(ds, outs):
                self.sme_st(d, r, n, ity)
            return True
        return False

    def _r33_revx(self, mn, ops):
        """revb/revh/revw/revd: reverse the (b/h/w/d) elements inside each container."""
        esz = {'revb': 8, 'revh': 16, 'revw': 32, 'revd': 64}[mn]
        if len(ops) != 3:
            return False
        d, g, s = self._r33z(ops[0]), self._r33p(ops[1]), self._r33z(ops[2])
        if not (d and g and s and d[1] and d[1] == s[1]) or g[2] not in ('m', 'z'):
            return False
        ceb = SVE_EL[d[1]][0]
        if ceb <= esz:
            return False
        n = SVL_BITS // esz
        per = ceb // esz
        ty = f'<{n} x i{esz}>'
        x = self.sme_ld(s[0], n, f'i{esz}')
        idx = ', '.join(f'i32 {(i // per) * per + (per - 1 - i % per)}' for i in range(n))
        r = self.t(); self.e(f'{r} = shufflevector {ty} {x}, {ty} poison, <{n} x i32> <{idx}>')
        cn = SVL_BITS // ceb
        cm = self._r33mask(self._r33pv(g[0]), cn, ceb)
        rep = ', '.join(f'i32 {i // per}' for i in range(n))
        m = self.t(); self.e(f'{m} = shufflevector <{cn} x i1> {cm}, <{cn} x i1> poison, <{n} x i32> <{rep}>')
        if g[2] == 'm':
            old = self.sme_ld(d[0], n, f'i{esz}')
        else:
            old = 'zeroinitializer'
        o = self.t(); self.e(f'{o} = select <{n} x i1> {m}, {ty} {r}, {ty} {old}')
        self._r33st(d[0], o, ty)
        return True

    def _r33_revb(self, ops): return self._r33_revx('revb', ops)
    def _r33_revh(self, ops): return self._r33_revx('revh', ops)
    def _r33_revw(self, ops): return self._r33_revx('revw', ops)
    def _r33_revd(self, ops): return self._r33_revx('revd', ops)

    # ── integer arithmetic ───────────────────────────────────────────────────────────
    def _r33_pint(self, mn, ops):
        """predicated destructive integer ops: mla, mls, smax, smin, umax, umin, neg, abs"""
        d = self._r33z(ops[0])
        if not d or not d[1] or len(ops) < 3:
            return False
        g = self._r33p(ops[1])
        if not g or g[2] != 'm':
            return False
        n, el, eb, ty = self._r33ty(d[1])
        srcs = []
        for o in ops[2:]:
            z = self._r33z(o)
            if not z or z[1] != d[1] or z[2] is not None:
                return False
            srcs.append(self.sme_ld(z[0], n, el))
        r = self.t()
        if mn in ('mla', 'mls') and len(srcs) == 2:
            acc = self.sme_ld(d[0], n, el)
            p = self.t(); self.e(f'{p} = mul {ty} {srcs[0]}, {srcs[1]}')
            self.e(f'{r} = {"add" if mn == "mla" else "sub"} {ty} {acc}, {p}')
        elif mn in ('smax', 'smin', 'umax', 'umin') and len(srcs) == 2:
            c = self.t()
            self.e(f'{c} = icmp {mn[0]}{"gt" if mn[1:] == "max" else "lt"} {ty} {srcs[0]}, {srcs[1]}')
            self.e(f'{r} = select <{n} x i1> {c}, {ty} {srcs[0]}, {ty} {srcs[1]}')
        elif mn == 'neg' and len(srcs) == 1:
            self.e(f'{r} = sub {ty} zeroinitializer, {srcs[0]}')
        elif mn == 'abs' and len(srcs) == 1:
            ng = self.t(); self.e(f'{ng} = sub {ty} zeroinitializer, {srcs[0]}')
            c = self.t(); self.e(f'{c} = icmp slt {ty} {srcs[0]}, zeroinitializer')
            self.e(f'{r} = select <{n} x i1> {c}, {ty} {ng}, {ty} {srcs[0]}')
        else:
            return False
        self._r33st(d[0], self._r33merge(ops[1], r, ty, n, eb, d[0]), ty)
        return True

    def _r33_mla(self, ops): return self._r33_pint('mla', ops)
    def _r33_mls(self, ops): return self._r33_pint('mls', ops)
    def _r33_smax(self, ops): return self._r33_pint('smax', ops)
    def _r33_smin(self, ops): return self._r33_pint('smin', ops)
    def _r33_umax(self, ops): return self._r33_pint('umax', ops)
    def _r33_umin(self, ops): return self._r33_pint('umin', ops)
    def _r33_neg(self, ops): return self._r33_pint('neg', ops)
    def _r33_abs(self, ops): return self._r33_pint('abs', ops)

    def _r33_clamp(self, signed, ops):
        if len(ops) != 3:
            return False
        a_, b_ = self._r33z(ops[1]), self._r33z(ops[2])
        if ops[0].strip().startswith('{'):
            ds, suf = self.sme_list(ops[0])[:2]
        else:
            d = self._r33z(ops[0])
            if not d:
                return False
            ds, suf = [d[0]], d[1]
        if not (a_ and b_ and a_[1] == suf == b_[1]):
            return False
        n, el, eb, ty = self._r33ty(suf)
        lo, hi = self.sme_ld(a_[0], n, el), self.sme_ld(b_[0], n, el)
        s = 's' if signed else 'u'
        outs = []
        for d in ds:
            x = self.sme_ld(d, n, el)
            c1 = self.t(); self.e(f'{c1} = icmp {s}gt {ty} {x}, {lo}')
            m1 = self.t(); self.e(f'{m1} = select <{n} x i1> {c1}, {ty} {x}, {ty} {lo}')
            c2 = self.t(); self.e(f'{c2} = icmp {s}lt {ty} {m1}, {hi}')
            m2 = self.t(); self.e(f'{m2} = select <{n} x i1> {c2}, {ty} {m1}, {ty} {hi}')
            outs.append(m2)
        for d, v in zip(ds, outs):
            self._r33st(d, v, ty)
        return True

    def _r33_sclamp(self, ops): return self._r33_clamp(True, ops)
    def _r33_uclamp(self, ops): return self._r33_clamp(False, ops)

    def _r33_cmla(self, ops):
        """integer complex multiply-add, unpredicated, rotation 0/90/180/270"""
        if len(ops) != 4:
            return False
        d, a_, b_ = (self._r33z(o) for o in ops[:3])
        if not (d and a_ and b_ and d[1] and d[1] == a_[1] == b_[1]) or a_[2] is not None \
                or b_[2] is not None:
            return False
        rot = imm(ops[3])
        if rot not in (0, 90, 180, 270):
            return False
        sel_a = 1 if rot in (90, 270) else 0
        sel_b = 1 - sel_a
        sub_r, sub_i = rot in (90, 180), rot in (180, 270)
        n, el, eb, ty = self._r33ty(d[1])
        x, y, acc = self.sme_ld(a_[0], n, el), self.sme_ld(b_[0], n, el), self.sme_ld(d[0], n, el)
        # lane 2e (real) uses n[2e+sel_a]*m[2e+sel_a]; lane 2e+1 (imag) n[2e+sel_a]*m[2e+sel_b]
        ia = ', '.join(f'i32 {(i & ~1) + sel_a}' for i in range(n))
        ib = ', '.join(f'i32 {(i & ~1) + (sel_a if i % 2 == 0 else sel_b)}' for i in range(n))
        xa = self.t(); self.e(f'{xa} = shufflevector {ty} {x}, {ty} poison, <{n} x i32> <{ia}>')
        yb = self.t(); self.e(f'{yb} = shufflevector {ty} {y}, {ty} poison, <{n} x i32> <{ib}>')
        p = self.t(); self.e(f'{p} = mul {ty} {xa}, {yb}')
        ad = self.t(); self.e(f'{ad} = add {ty} {acc}, {p}')
        sb = self.t(); self.e(f'{sb} = sub {ty} {acc}, {p}')
        subm = self._r33c(f'<{n} x i1>', n, ['true' if (sub_r if i % 2 == 0 else sub_i) else 'false'
                                             for i in range(n)])
        r = self.t(); self.e(f'{r} = select <{n} x i1> {subm}, {ty} {sb}, {ty} {ad}')
        self._r33st(d[0], r, ty)
        return True

    def _r33_unpk(self, signed, hi, ops):
        d, s = self._r33z(ops[0]), self._r33z(ops[1])
        if len(ops) != 2 or not (d and s and d[1] and s[1]):
            return False
        n, el, eb, ty = self._r33ty(d[1])
        seb = SVE_EL[s[1]][0]
        if seb * 2 != eb:
            return False
        sn = SVL_BITS // seb
        x = self.sme_ld(s[0], sn, f'i{seb}')
        idx = ', '.join(f'i32 {i + (n if hi else 0)}' for i in range(n))
        h = self.t(); self.e(f'{h} = shufflevector <{sn} x i{seb}> {x}, <{sn} x i{seb}> poison, '
                             f'<{n} x i32> <{idx}>')
        r = self.t(); self.e(f'{r} = {"sext" if signed else "zext"} <{n} x i{seb}> {h} to {ty}')
        self._r33st(d[0], r, ty)
        return True

    def _r33_sunpklo(self, ops): return self._r33_unpk(True, False, ops)
    def _r33_sunpkhi(self, ops): return self._r33_unpk(True, True, ops)
    def _r33_uunpklo(self, ops): return self._r33_unpk(False, False, ops)
    def _r33_uunpkhi(self, ops): return self._r33_unpk(False, True, ops)

    def _r33_halves(self, tok, n, part):
        """the even (part 0, 'b') or odd (part 1, 't') narrow elements, widened later"""
        z = self._r33z(tok)
        seb = SVE_EL[z[1]][0]
        sn = SVL_BITS // seb
        x = self.sme_ld(z[0], sn, f'i{seb}')
        idx = ', '.join(f'i32 {2 * i + part}' for i in range(n))
        h = self.t(); self.e(f'{h} = shufflevector <{sn} x i{seb}> {x}, <{sn} x i{seb}> poison, '
                             f'<{n} x i32> <{idx}>')
        return h, seb

    WIDE = re.compile(r'^([su])(add|sub|mul|abd|aba|mla|mls)l([bt])([bt]?)$')

    def _r33_widen(self, mn, ops):
        """the SVE2 long (widening) family: [su]{add,sub,mul,mla,mls,aba}l{b,t}{,bt,tb}"""
        m = self.WIDE.match(mn)
        if not m or len(ops) != 3:
            return False
        d, a_, b_ = (self._r33z(o) for o in ops)
        if not (d and a_ and b_ and d[1] and a_[1] and a_[1] == b_[1]) or a_[2] is not None \
                or b_[2] is not None:
            return False
        n, el, eb, ty = self._r33ty(d[1])
        if SVE_EL[a_[1]][0] * 2 != eb:
            return False
        sg, op, p1 = m.group(1) == 's', m.group(2), m.group(3)
        p2 = m.group(4) or p1
        x, seb = self._r33_halves(ops[1], n, 0 if p1 == 'b' else 1)
        y, _ = self._r33_halves(ops[2], n, 0 if p2 == 'b' else 1)
        ext = 'sext' if sg else 'zext'
        xw = self.t(); self.e(f'{xw} = {ext} <{n} x i{seb}> {x} to {ty}')
        yw = self.t(); self.e(f'{yw} = {ext} <{n} x i{seb}> {y} to {ty}')
        r = self.t()
        if op in ('add', 'sub', 'mul'):
            self.e(f'{r} = {op} {ty} {xw}, {yw}')
        elif op in ('abd', 'aba'):
            df = self.t(); self.e(f'{df} = sub {ty} {xw}, {yw}')
            ng = self.t(); self.e(f'{ng} = sub {ty} zeroinitializer, {df}')
            c = self.t(); self.e(f'{c} = icmp slt {ty} {df}, zeroinitializer')
            ab = self.t(); self.e(f'{ab} = select <{n} x i1> {c}, {ty} {ng}, {ty} {df}')
            if op == 'abd':
                r = ab
            else:
                acc = self.sme_ld(d[0], n, el)
                self.e(f'{r} = add {ty} {acc}, {ab}')
        else:
            p = self.t(); self.e(f'{p} = mul {ty} {xw}, {yw}')
            acc = self.sme_ld(d[0], n, el)
            self.e(f'{r} = {"add" if op == "mla" else "sub"} {ty} {acc}, {p}')
        self._r33st(d[0], r, ty)
        return True

    def __getattr__(self, name):
        #  the widening family is ~48 mnemonics with one shape; route them by pattern
        #    instead of by 48 one-line methods. ONLY _r33_ names are routed here.
        if name.startswith('_r33_'):
            mn = name[5:]
            if self.WIDE.match(mn):
                return lambda ops: self._r33_widen(mn, ops)
        raise AttributeError(name)

    def _r33_sqxtn(self, mn, ops):
        m = re.fullmatch(r'(sq|uq|squ)xtn([bt])', mn)
        if not m or len(ops) != 2:
            return False
        d, s = self._r33z(ops[0]), self._r33z(ops[1])
        if not (d and s and d[1] and s[1]):
            return False
        deb, seb = SVE_EL[d[1]][0], SVE_EL[s[1]][0]
        if deb * 2 != seb:
            return False
        sn = SVL_BITS // seb
        x = self.sme_ld(s[0], sn, f'i{seb}')
        wty = f'<{sn} x i{seb}>'
        if m.group(1) == 'uq':
            lo, hi = 0, (1 << deb) - 1
        elif m.group(1) == 'squ':
            lo, hi = 0, (1 << deb) - 1
        else:
            lo, hi = -(1 << (deb - 1)), (1 << (deb - 1)) - 1
        cmp_lo = 'slt' if m.group(1) != 'uq' else 'ult'
        cmp_hi = 'sgt' if m.group(1) == 'sq' else ('ugt' if m.group(1) == 'uq' else 'sgt')
        lv = self.sve_splat(wty, sn, f'i{seb}', str(lo))
        hv = self.sve_splat(wty, sn, f'i{seb}', str(hi))
        c1 = self.t(); self.e(f'{c1} = icmp {cmp_lo} {wty} {x}, {lv}')
        o1 = self.t(); self.e(f'{o1} = select <{sn} x i1> {c1}, {wty} {lv}, {wty} {x}')
        c2 = self.t(); self.e(f'{c2} = icmp {cmp_hi} {wty} {o1}, {hv}')
        o2 = self.t(); self.e(f'{o2} = select <{sn} x i1> {c2}, {wty} {hv}, {wty} {o1}')
        nt = self.t(); self.e(f'{nt} = trunc {wty} {o2} to <{sn} x i{deb}>')
        dn = 2 * sn
        dty = f'<{dn} x i{deb}>'
        if m.group(2) == 'b':
            #  BOTTOM: narrowed values in the EVEN elements, the odd ones ZEROED
            idx = ', '.join(f'i32 {i // 2 if i % 2 == 0 else sn}' for i in range(dn))
            r = self.t()
            self.e(f'{r} = shufflevector <{sn} x i{deb}> {nt}, <{sn} x i{deb}> zeroinitializer, '
                   f'<{dn} x i32> <{idx}>')
        else:
            #  TOP: narrowed values in the ODD elements, the even ones KEPT
            old = self.sme_ld(d[0], dn, f'i{deb}')
            wide = self.t()
            idx0 = ', '.join(f'i32 {i // 2}' for i in range(dn))
            self.e(f'{wide} = shufflevector <{sn} x i{deb}> {nt}, <{sn} x i{deb}> poison, '
                   f'<{dn} x i32> <{idx0}>')
            odd = self._r33c(f'<{dn} x i1>', dn, ['true' if i % 2 else 'false' for i in range(dn)])
            r = self.t(); self.e(f'{r} = select <{dn} x i1> {odd}, {dty} {wide}, {dty} {old}')
        self._r33st(d[0], r, dty)
        return True

    def _r33_sqxtnb(self, ops): return self._r33_sqxtn('sqxtnb', ops)
    def _r33_sqxtnt(self, ops): return self._r33_sqxtn('sqxtnt', ops)
    def _r33_uqxtnb(self, ops): return self._r33_sqxtn('uqxtnb', ops)
    def _r33_uqxtnt(self, ops): return self._r33_sqxtn('uqxtnt', ops)
    def _r33_sqxtunb(self, ops): return self._r33_sqxtn('squxtnb', ops)
    def _r33_sqxtunt(self, ops): return self._r33_sqxtn('squxtnt', ops)

    def _r33_sqrshl_x(self, rev, ops):
        """ signed saturating ROUNDING shift by a signed per-element amount (low 8 bits).
           Computed in i128 with the amount clamped to [-eb-1, eb], which covers every
           saturation and every all-rounded-away case exactly."""
        if len(ops) != 4:
            return False
        d, g, a_, b_ = self._r33z(ops[0]), self._r33p(ops[1]), self._r33z(ops[2]), self._r33z(ops[3])
        if not (d and g and a_ and b_ and d[1] and d[1] == a_[1] == b_[1]) or g[2] != 'm':
            return False
        n, el, eb, ty = self._r33ty(d[1])
        x, s = self.sme_ld(a_[0], n, el), self.sme_ld(b_[0], n, el)
        if rev:
            x, s = s, x
        W = f'<{n} x i128>'
        #  R33c THE WHOLE SIGNED ELEMENT is the shift (M4: 224/224 at 64 bits, 132/224
        #    at the low byte the NEON form uses).
        sw = self.t(); self.e(f'{sw} = sext {ty} {s} to {W}')
        lo = self.sve_splat(W, n, 'i128', str(-(eb + 1)))
        hi = self.sve_splat(W, n, 'i128', str(eb))
        c1 = self.t(); self.e(f'{c1} = icmp slt {W} {sw}, {lo}')
        s1 = self.t(); self.e(f'{s1} = select <{n} x i1> {c1}, {W} {lo}, {W} {sw}')
        c2 = self.t(); self.e(f'{c2} = icmp sgt {W} {s1}, {hi}')
        s2 = self.t(); self.e(f'{s2} = select <{n} x i1> {c2}, {W} {hi}, {W} {s1}')
        xw = self.t(); self.e(f'{xw} = sext {ty} {x} to {W}')
        neg = self.t(); self.e(f'{neg} = icmp slt {W} {s2}, zeroinitializer')
        rs = self.t(); self.e(f'{rs} = sub {W} zeroinitializer, {s2}')
        rs1 = self.t(); self.e(f'{rs1} = sub {W} {rs}, {self.sve_splat(W, n, "i128", "1")}')
        # for a left shift rs1 is negative; clamp it so the shl stays defined
        rsc = self.t(); self.e(f'{rsc} = select <{n} x i1> {neg}, {W} {rs1}, {W} zeroinitializer')
        rnd = self.t(); self.e(f'{rnd} = shl {W} {self.sve_splat(W, n, "i128", "1")}, {rsc}')
        rndm = self.t(); self.e(f'{rndm} = select <{n} x i1> {neg}, {W} {rnd}, {W} zeroinitializer')
        ad = self.t(); self.e(f'{ad} = add {W} {xw}, {rndm}')
        rsa = self.t(); self.e(f'{rsa} = select <{n} x i1> {neg}, {W} {rs}, {W} zeroinitializer')
        right = self.t(); self.e(f'{right} = ashr {W} {ad}, {rsa}')
        lsa = self.t(); self.e(f'{lsa} = select <{n} x i1> {neg}, {W} zeroinitializer, {W} {s2}')
        left = self.t(); self.e(f'{left} = shl {W} {xw}, {lsa}')
        r = self.t(); self.e(f'{r} = select <{n} x i1> {neg}, {W} {right}, {W} {left}')
        mn_ = self.sve_splat(W, n, 'i128', str(-(1 << (eb - 1))))
        mx_ = self.sve_splat(W, n, 'i128', str((1 << (eb - 1)) - 1))
        c3 = self.t(); self.e(f'{c3} = icmp slt {W} {r}, {mn_}')
        r1 = self.t(); self.e(f'{r1} = select <{n} x i1> {c3}, {W} {mn_}, {W} {r}')
        c4 = self.t(); self.e(f'{c4} = icmp sgt {W} {r1}, {mx_}')
        r2 = self.t(); self.e(f'{r2} = select <{n} x i1> {c4}, {W} {mx_}, {W} {r1}')
        o = self.t(); self.e(f'{o} = trunc {W} {r2} to {ty}')
        self._r33st(d[0], self._r33merge(ops[1], o, ty, n, eb, d[0]), ty)
        return True

    def _r33_sqrshl(self, ops): return self._r33_sqrshl_x(False, ops)
    def _r33_sqrshlr(self, ops): return self._r33_sqrshl_x(True, ops)

    # ── reductions ───────────────────────────────────────────────────────────────────
    def _r33_red(self, mn, ops):
        if len(ops) != 3:
            return False
        dv, g, z = self._r33v(ops[0]), self._r33p(ops[1]), self._r33z(ops[2])
        if not (dv and g and z and z[1]) or g[2]:
            return False
        isfp = mn[0] == 'f'
        n, el, eb, ty = self._r33ty(z[1], fp=isfp)
        if dv[1] != eb:
            return False
        x = self.sme_ld(z[0], n, el)
        m = self._r33mask(self._r33pv(g[0]), n, eb)
        if isfp:
            ident = {'faddv': 0, 'fmaxv': self._r33fimm('#-inf', eb),
                     'fminv': self._r33fimm('#inf', eb)}[mn]
            ity = f'<{n} x i{eb}>'
            iv = self.sve_splat(ity, n, f'i{eb}', str(ident))
            ivf = self.t(); self.e(f'{ivf} = bitcast {ity} {iv} to {ty}')
            op = {'faddv': 'fadd', 'fmaxv': 'maximum', 'fminv': 'minimum'}[mn]
        else:
            ident = {'smaxv': -(1 << (eb - 1)), 'sminv': (1 << (eb - 1)) - 1,
                     'umaxv': 0, 'uminv': -1}[mn]
            ivf = self.sve_splat(ty, n, el, str(ident))
        v = self.t(); self.e(f'{v} = select <{n} x i1> {m}, {ty} {x}, {ty} {ivf}')
        w = n
        while w > 1:
            h = w // 2
            ev = ', '.join(f'i32 {2 * i}' for i in range(h))
            od = ', '.join(f'i32 {2 * i + 1}' for i in range(h))
            wt = f'<{w} x {el}>'; ht = f'<{h} x {el}>'
            a_ = self.t(); self.e(f'{a_} = shufflevector {wt} {v}, {wt} poison, <{h} x i32> <{ev}>')
            b_ = self.t(); self.e(f'{b_} = shufflevector {wt} {v}, {wt} poison, <{h} x i32> <{od}>')
            if isfp:
                v = self._r33fbin(op, ht, a_, b_)
            else:
                c = self.t()
                cc = {'smaxv': 'sgt', 'sminv': 'slt', 'umaxv': 'ugt', 'uminv': 'ult'}[mn]
                self.e(f'{c} = icmp {cc} {ht} {a_}, {b_}')
                r = self.t(); self.e(f'{r} = select <{h} x i1> {c}, {ht} {a_}, {ht} {b_}')
                v = r
            w = h
        s = self.t(); self.e(f'{s} = extractelement <1 x {el}> {v}, i32 0')
        self._r33scalar_out(dv[0], s, el)
        return True

    def _r33_faddv(self, ops): return self._r33_red('faddv', ops)
    def _r33_fmaxv(self, ops): return self._r33_red('fmaxv', ops)
    def _r33_fminv(self, ops): return self._r33_red('fminv', ops)
    def _r33_smaxv(self, ops): return self._r33_red('smaxv', ops)
    def _r33_sminv(self, ops): return self._r33_red('sminv', ops)
    def _r33_umaxv(self, ops): return self._r33_red('umaxv', ops)
    def _r33_uminv(self, ops): return self._r33_red('uminv', ops)

    # ── floating point, predicated ───────────────────────────────────────────────────
    def _r33_fminmax(self, mn, ops):
        if len(ops) != 4:
            return False
        d, g, a_ = self._r33z(ops[0]), self._r33p(ops[1]), self._r33z(ops[2])
        if not (d and g and a_ and d[1] and d[1] == a_[1] and d[0] == a_[0]) or g[2] != 'm':
            return False
        n, el, eb, ty = self._r33ty(d[1], fp=True)
        x = self.sme_ld(a_[0], n, el)
        o = ops[3].strip()
        if o.startswith('#'):
            iv = self.sve_splat(f'<{n} x i{eb}>', n, f'i{eb}', str(self._r33fimm(o, eb)))
            y = self.t(); self.e(f'{y} = bitcast <{n} x i{eb}> {iv} to {ty}')
        else:
            b_ = self._r33z(o)
            if not b_ or b_[1] != d[1]:
                return False
            y = self.sme_ld(b_[0], n, el)
        r = self._r33fbin('maximum' if mn == 'fmax' else 'minimum', ty, x, y)
        self._r33st(d[0], self._r33merge(ops[1], r, ty, n, eb, d[0]), ty)
        return True

    def _r33_fmax(self, ops): return self._r33_fminmax('fmax', ops)
    def _r33_fmin(self, ops): return self._r33_fminmax('fmin', ops)

    FMA = {  # mnemonic -> (negate op1, negate addend, destructive-multiplicand form)
        'fmla': (False, False, False), 'fmls': (True, False, False),
        'fnmla': (True, True, False), 'fnmls': (False, True, False),
        'fmad': (False, False, True), 'fmsb': (True, False, True),
        'fnmad': (True, True, True), 'fnmsb': (False, True, True)}

    def _r33_fmaf(self, mn, ops):
        if ops[0].strip().lower().startswith('za'):
            return self._r33_fmla_za(mn, ops) if mn in ('fmla', 'fmls') else False
        if len(ops) != 4:
            return False
        d, g, a_, b_ = self._r33z(ops[0]), self._r33p(ops[1]), self._r33z(ops[2]), self._r33z(ops[3])
        if not (d and g and a_ and b_ and d[1] and d[1] == a_[1] == b_[1]) or g[2] != 'm' \
                or a_[2] is not None or b_[2] is not None:
            return False
        neg1, nega, dm = self.FMA[mn]
        n, el, eb, ty = self._r33ty(d[1], fp=True)
        dv = self.sme_ld(d[0], n, el)
        av, bv = self.sme_ld(a_[0], n, el), self.sme_ld(b_[0], n, el)
        if dm:          # fmad zdn, pg/m, zm, za: zdn = za + zdn*zm
            op1, op2, add = dv, av, bv
        else:           # fmla zda, pg/m, zn, zm: zda = zda + zn*zm
            op1, op2, add = av, bv, dv
        if neg1:
            t_ = self.t(); self.e(f'{t_} = fneg {ty} {op1}'); op1 = t_
        if nega:
            t_ = self.t(); self.e(f'{t_} = fneg {ty} {add}'); add = t_
        r = self._r33fma(ty, add, op1, op2)
        self._r33st(d[0], self._r33merge(ops[1], r, ty, n, eb, d[0]), ty)
        return True

    def _r33_fmla(self, ops): return self._r33_fmaf('fmla', ops)
    def _r33_fmls(self, ops): return self._r33_fmaf('fmls', ops)
    def _r33_fnmla(self, ops): return self._r33_fmaf('fnmla', ops)
    def _r33_fnmls(self, ops): return self._r33_fmaf('fnmls', ops)
    def _r33_fmad(self, ops): return self._r33_fmaf('fmad', ops)
    def _r33_fmsb(self, ops): return self._r33_fmaf('fmsb', ops)
    def _r33_fnmad(self, ops): return self._r33_fmaf('fnmad', ops)
    def _r33_fnmsb(self, ops): return self._r33_fmaf('fnmsb', ops)

    def _r33_frsqrte(self, ops):
        d, s = self._r33z(ops[0]), self._r33z(ops[-1])
        if len(ops) != 2 or not (d and s and d[1] in ('s', 'd') and d[1] == s[1]):
            return False
        n, el, eb, ty = self._r33ty(d[1], fp=True)
        x = self.sme_ld(s[0], n, el)
        acc = 'poison'
        for i in range(n):
            v = self.t(); self.e(f'{v} = extractelement {ty} {x}, i32 {i}')
            r = self.t(); self.e(f'{r} = call {el} @__arm2x86_frsqrte_f{eb}({el} {v})')
            nx = self.t(); self.e(f'{nx} = insertelement {ty} {acc}, {el} {r}, i32 {i}')
            acc = nx
        self._r33st(d[0], acc, ty)
        return True

    def _r33_frsqrts(self, ops):
        """ FPRSqrtStepFused: (3 - n*m)/2 with ONE rounding; inf*0 -> 1.5, NaNs by ARM
           priority AFTER op1 is negated."""
        if len(ops) != 3:
            return False
        d, a_, b_ = (self._r33z(o) for o in ops)
        if not (d and a_ and b_ and d[1] in ('h', 's', 'd') and d[1] == a_[1] == b_[1]):
            return False
        n, el, eb, ty = self._r33ty(d[1], fp=True)
        x, y = self.sme_ld(a_[0], n, el), self.sme_ld(b_[0], n, el)
        nx = self.t(); self.e(f'{nx} = fneg {ty} {x}')
        three = self._r33c(ty, n, [_fpbits_literal(3.0, el) if eb != 16 else '0xH4200'] * n)
        half = self._r33c(ty, n, [_fpbits_literal(0.5, el) if eb != 16 else '0xH3800'] * n)
        f = self.t()
        self.e(f'{f} = call {ty} @llvm.fma.{_sve_sfx(n, el)}({ty} {nx}, {ty} {y}, {ty} {three})')
        h = self.t(); self.e(f'{h} = fmul {ty} {f}, {half}')
        r = self._r33nan(ty, h, [nx, y])
        i1, z1 = self._r33fclass(ty, nx)
        i2, z2 = self._r33fclass(ty, y)
        a1 = self.t(); self.e(f'{a1} = and <{n} x i1> {i1}, {z2}')
        a2 = self.t(); self.e(f'{a2} = and <{n} x i1> {z1}, {i2}')
        iz = self.t(); self.e(f'{iz} = or <{n} x i1> {a1}, {a2}')
        opf = self._r33c(ty, n, [_fpbits_literal(1.5, el) if eb != 16 else '0xH3E00'] * n)
        o = self.t(); self.e(f'{o} = select <{n} x i1> {iz}, {ty} {opf}, {ty} {r}')
        self._r33st(d[0], o, ty)
        return True

    # ── BF16 conversions ─────────────────────────────────────────────────────────────
    def _r33bf16(self, xf, n):
        """<n x float> -> <n x i16> BF16, round to nearest even; NaN quieted, sign kept."""
        u = self.t(); self.e(f'{u} = bitcast <{n} x float> {xf} to <{n} x i32>')
        ity = f'<{n} x i32>'
        sh = self.t(); self.e(f'{sh} = lshr {ity} {u}, {self.sve_splat(ity, n, "i32", "16")}')
        lsb = self.t(); self.e(f'{lsb} = and {ity} {sh}, {self.sve_splat(ity, n, "i32", "1")}')
        b1 = self.t(); self.e(f'{b1} = add {ity} {u}, {self.sve_splat(ity, n, "i32", "32767")}')
        b2 = self.t(); self.e(f'{b2} = add {ity} {b1}, {lsb}')
        rn = self.t(); self.e(f'{rn} = lshr {ity} {b2}, {self.sve_splat(ity, n, "i32", "16")}')
        qn = self.t(); self.e(f'{qn} = or {ity} {sh}, {self.sve_splat(ity, n, "i32", "64")}')
        isn = self.t(); self.e(f'{isn} = fcmp uno <{n} x float> {xf}, {xf}')
        s = self.t(); self.e(f'{s} = select <{n} x i1> {isn}, {ity} {qn}, {ity} {rn}')
        t_ = self.t(); self.e(f'{t_} = trunc {ity} {s} to <{n} x i16>')
        return t_

    def _r33_bfcvtx(self, inter, ops):
        if len(ops) != 2 or not ops[1].strip().startswith('{'):
            return False
        d = self._r33z(ops[0])
        ss, suf = self.sme_list(ops[1])[:2]
        if not d or d[1] != 'h' or suf != 's' or len(ss) != 2:
            return False
        n = SVL_BITS // 32
        a_ = self._r33bf16(self.sme_ld(ss[0], n, 'float'), n)
        b_ = self._r33bf16(self.sme_ld(ss[1], n, 'float'), n)
        if inter:
            idx = ', '.join(f'i32 {(i // 2) + (n if i % 2 else 0)}' for i in range(2 * n))
        else:
            idx = ', '.join(f'i32 {i}' for i in range(2 * n))
        r = self.t()
        self.e(f'{r} = shufflevector <{n} x i16> {a_}, <{n} x i16> {b_}, <{2 * n} x i32> <{idx}>')
        self.sme_st(d[0], r, 2 * n, 'i16')
        return True

    def _r33_bfcvt(self, ops): return self._r33_bfcvtx(False, ops)
    def _r33_bfcvtn(self, ops): return self._r33_bfcvtx(True, ops)

    # ── ZA: group-addressed accumulation (SME2) ──────────────────────────────────────
    ZA_RANGE = re.compile(r'^za\.([bhsd])\[\s*(w\d+)\s*,\s*((?:0x)?[0-9a-f]+)\s*'
                          r'(?::\s*((?:0x)?[0-9a-f]+)\s*)?(?:,\s*vgx(\d)\s*)?\]$')

    def _r33za(self, tok):
        m = self.ZA_RANGE.match(tok.strip().lower())
        if not m:
            return None
        lo = int(m.group(3), 0)
        hi = int(m.group(4), 0) if m.group(4) else lo
        return {'suf': m.group(1), 'w': m.group(2), 'lo': lo, 'n': hi - lo + 1,
                'vg': int(m.group(5) or 1)}

    def _r33zarows(self, za):
        """-> list over group members of lists of array-vector indices (i64 values).
            vec = ((Wv + lo) mod (64/VG)) rounded DOWN to the range length; member g's
              rows are vec + g*(64/VG) + r, r < range length."""
        vs = SVL_B // za['vg']
        w = self.rd(za['w'])
        s = self.t(); self.e(f"{s} = add i64 {w}, {za['lo']}")
        m = self.t(); self.e(f'{m} = and i64 {s}, {vs - 1}')
        if za['n'] > 1:
            a_ = self.t(); self.e(f"{a_} = and i64 {m}, {~(za['n'] - 1)}")
            m = a_
        out = []
        for g in range(za['vg']):
            rows = []
            for r in range(za['n']):
                x = self.t(); self.e(f'{x} = add i64 {m}, {g * vs + r}')
                rows.append(x)
            out.append(rows)
        return out

    def _r33srcs(self, tok, vg):
        """a z list or a single z -> vg slots (a single register is shared)"""
        t = tok.strip()
        if t.startswith('{'):
            slots, suf = self.sme_list(t)[:2]
            if len(slots) != vg:
                raise NotImplementedError(f'R33: list {tok!r} is not vgx{vg}')
            return slots, suf, None
        z = self._r33z(t)
        if not z or not z[1]:
            raise NotImplementedError(f'R33: operand {tok!r} unparsed')
        return [z[0]] * vg, z[1], z[2]

    def _r33_fmla_za(self, mn, ops):
        """fmla/fmls za.s[w, off, vgxN], {zn..}, zm.s[idx] — the INDEXED form (the
           non-indexed ones are sme2()'s). zm's element is chosen PER 128-BIT SEGMENT."""
        za = self._r33za(ops[0])
        if not za or za['n'] != 1 or len(ops) != 3:
            return False
        ns, suf, _ = self._r33srcs(ops[1], za['vg'])
        zm = self._r33z(ops[2])
        if not zm or zm[2] is None or suf != za['suf'] or zm[1] != suf:
            return False
        n, el, eb, ty = self._r33ty(suf, fp=True)
        per = 128 // eb
        m = self.sme_ld(zm[0], n, el)
        idx = ', '.join(f'i32 {(i // per) * per + zm[2]}' for i in range(n))
        mb = self.t(); self.e(f'{mb} = shufflevector {ty} {m}, {ty} poison, <{n} x i32> <{idx}>')
        rows = self._r33zarows(za)
        for g in range(za['vg']):
            x = self.sme_ld(ns[g], n, el)
            if mn == 'fmls':
                t_ = self.t(); self.e(f'{t_} = fneg {ty} {x}'); x = t_
            acc = self.za_ld(rows[g][0], n, el)
            r = self._r33dn(ty, self._r33fma(ty, acc, x, mb), n, eb)
            self.za_st(rows[g][0], r, n, el)
        return True

    def _r33_mlal_za(self, mn, ops):
        """fmlal/fmlsl/bfmlal/bfmlsl za.s[w, lo:lo+1{, vgxN}], {zn.h..}, zm.h|{zm.h..}
            row r (0/1) of each member takes the EVEN (r=0) / ODD (r=1) half elements,
              multiplied in f32 with one rounding."""
        za = self._r33za(ops[0])
        if not za or za['n'] != 2 or za['suf'] != 's' or len(ops) != 3:
            return False
        bf = mn.startswith('bf')
        sub = mn.endswith('sl')
        ns, suf, ni = self._r33srcs(ops[1], za['vg'])
        ms, msuf, mi = self._r33srcs(ops[2], za['vg'])
        if suf != 'h' or msuf != 'h' or ni is not None or mi is not None:
            return False
        n = SVL_BITS // 32
        rows = self._r33zarows(za)
        fty = f'<{n} x float>'
        for g in range(za['vg']):
            for r in range(2):
                vals = []
                for slot in (ns[g], ms[g]):
                    h = self.sme_ld(slot, 2 * n, 'i16')
                    idx = ', '.join(f'i32 {2 * i + r}' for i in range(n))
                    s = self.t()
                    self.e(f'{s} = shufflevector <{2 * n} x i16> {h}, <{2 * n} x i16> poison, '
                           f'<{n} x i32> <{idx}>')
                    vals.append(self._r33widen16(s, n, bf))
                x, y = vals
                if sub:
                    t_ = self.t(); self.e(f'{t_} = fneg {fty} {x}'); x = t_
                acc = self.za_ld(rows[g][r], n, 'float')
                o = self._r33dn(fty, self._r33fma(fty, acc, x, y), n, 32)
                self.za_st(rows[g][r], o, n, 'float')
        return True

    def _r33widen16(self, h, n, bf):
        """<n x i16> half or bf16 bits -> <n x float>, exactly"""
        if bf:
            z = self.t(); self.e(f'{z} = zext <{n} x i16> {h} to <{n} x i32>')
            s = self.t(); self.e(f'{s} = shl <{n} x i32> {z}, {self.sve_splat(f"<{n} x i32>", n, "i32", "16")}')
            f = self.t(); self.e(f'{f} = bitcast <{n} x i32> {s} to <{n} x float>')
            return f
        hf = self.t(); self.e(f'{hf} = bitcast <{n} x i16> {h} to <{n} x half>')
        f = self.t(); self.e(f'{f} = fpext <{n} x half> {hf} to <{n} x float>')
        return f

    def _r33_fmlal(self, ops):
        return self._r33_mlal_za('fmlal', ops) if ops[0].strip().lower().startswith('za') else False

    def _r33_fmlsl(self, ops):
        return self._r33_mlal_za('fmlsl', ops) if ops[0].strip().lower().startswith('za') else False

    def _r33_bfmlal(self, ops):
        return self._r33_mlal_za('bfmlal', ops) if ops[0].strip().lower().startswith('za') else False

    def _r33_bfmlsl(self, ops):
        return self._r33_mlal_za('bfmlsl', ops) if ops[0].strip().lower().startswith('za') else False

    def _r33dn(self, ty, r, n, eb):
        """ R33c FP arithmetic INTO ZA returns the DEFAULT NaN (M4), never a payload."""
        it = f'<{n} x i{eb}>'
        isn = self.t(); self.e(f'{isn} = fcmp uno {ty} {r}, {r}')
        b = self.t(); self.e(f'{b} = bitcast {ty} {r} to {it}')
        dn = self.sve_splat(it, n, f'i{eb}', str(self.R33_DN[eb]))
        o = self.t(); self.e(f'{o} = select <{n} x i1> {isn}, {it} {dn}, {it} {b}')
        f = self.t(); self.e(f'{f} = bitcast {it} {o} to {ty}')
        return f

    def _r33fz(self, x, n):
        """flush f32 denormals to a signed zero"""
        ity = f'<{n} x i32>'
        b = self.t(); self.e(f'{b} = bitcast <{n} x float> {x} to {ity}')
        e_ = self.t(); self.e(f'{e_} = and {ity} {b}, {self.sve_splat(ity, n, "i32", str(0x7F800000))}')
        ez = self.t(); self.e(f'{ez} = icmp eq {ity} {e_}, zeroinitializer')
        sg = self.t(); self.e(f'{sg} = and {ity} {b}, {self.sve_splat(ity, n, "i32", str(-0x80000000))}')
        r = self.t(); self.e(f'{r} = select <{n} x i1> {ez}, {ity} {sg}, {ity} {b}')
        f = self.t(); self.e(f'{f} = bitcast {ity} {r} to <{n} x float>')
        return f

    def _r33rto_add(self, a_, b_, n):
        """ BFAdd: f32 add, ROUND TO ODD, inputs and outputs flushed, default NaN.
           Exact via TwoSum in double; the f32 truncation then carries a sticky bit."""
        fty, dty, ity = f'<{n} x float>', f'<{n} x double>', f'<{n} x i32>'
        a_, b_ = self._r33fz(a_, n), self._r33fz(b_, n)
        da = self.t(); self.e(f'{da} = fpext {fty} {a_} to {dty}')
        db = self.t(); self.e(f'{db} = fpext {fty} {b_} to {dty}')
        s = self.t(); self.e(f'{s} = fadd {dty} {da}, {db}')
        bb = self.t(); self.e(f'{bb} = fsub {dty} {s}, {da}')
        t1 = self.t(); self.e(f'{t1} = fsub {dty} {s}, {bb}')
        t2 = self.t(); self.e(f'{t2} = fsub {dty} {da}, {t1}')
        t3 = self.t(); self.e(f'{t3} = fsub {dty} {db}, {bb}')
        er = self.t(); self.e(f'{er} = fadd {dty} {t2}, {t3}')
        f = self.t(); self.e(f'{f} = fptrunc {dty} {s} to {fty}')
        fd = self.t(); self.e(f'{fd} = fpext {fty} {f} to {dty}')
        af = self.t(); self.e(f'{af} = call {dty} @llvm.fabs.{_sve_sfx(n, "double")}({dty} {fd})')
        as_ = self.t(); self.e(f'{as_} = call {dty} @llvm.fabs.{_sve_sfx(n, "double")}({dty} {s})')
        over = self.t(); self.e(f'{over} = fcmp ogt {dty} {af}, {as_}')
        fb = self.t(); self.e(f'{fb} = bitcast {fty} {f} to {ity}')
        one = self.sve_splat(ity, n, 'i32', '1')
        fm1 = self.t(); self.e(f'{fm1} = sub {ity} {fb}, {one}')
        tr = self.t(); self.e(f'{tr} = select <{n} x i1> {over}, {ity} {fm1}, {ity} {fb}')
        # exact at f32 but the TwoSum error points back toward zero -> one ulp down
        trd_f = self.t(); self.e(f'{trd_f} = bitcast {ity} {tr} to {fty}')
        trd = self.t(); self.e(f'{trd} = fpext {fty} {trd_f} to {dty}')
        exact32 = self.t(); self.e(f'{exact32} = fcmp oeq {dty} {trd}, {s}')
        ez = self.t(); self.e(f'{ez} = fcmp one {dty} {er}, zeroinitializer')
        sneg = self.t(); self.e(f'{sneg} = fcmp olt {dty} {s}, zeroinitializer')
        eneg = self.t(); self.e(f'{eneg} = fcmp olt {dty} {er}, zeroinitializer')
        opp = self.t(); self.e(f'{opp} = xor <{n} x i1> {sneg}, {eneg}')
        c1 = self.t(); self.e(f'{c1} = and <{n} x i1> {exact32}, {ez}')
        down = self.t(); self.e(f'{down} = and <{n} x i1> {c1}, {opp}')
        trm = self.t(); self.e(f'{trm} = sub {ity} {tr}, {one}')
        tr2 = self.t(); self.e(f'{tr2} = select <{n} x i1> {down}, {ity} {trm}, {ity} {tr}')
        ne = self.t(); self.e(f'{ne} = fcmp une {dty} {trd}, {s}')
        inex = self.t(); self.e(f'{inex} = or <{n} x i1> {ne}, {ez}')
        odd = self.t(); self.e(f'{odd} = or {ity} {tr2}, {one}')
        rto = self.t(); self.e(f'{rto} = select <{n} x i1> {inex}, {ity} {odd}, {ity} {tr2}')
        # infinities / NaN: take the plain result, NaN becomes the default NaN
        ab = self.t(); self.e(f'{ab} = call {dty} @llvm.fabs.{_sve_sfx(n, "double")}({dty} {s})')
        fin = self.t()
        self.e(f'{fin} = fcmp olt {dty} {ab}, {self._r33c(dty, n, ["0x7FF0000000000000"] * n)}')
        isn = self.t(); self.e(f'{isn} = fcmp uno {dty} {s}, {s}')
        plain = self.t(); self.e(f'{plain} = select <{n} x i1> {fin}, {ity} {rto}, {ity} {fb}')
        dn = self.sve_splat(ity, n, 'i32', str(0x7FC00000))
        o = self.t(); self.e(f'{o} = select <{n} x i1> {isn}, {ity} {dn}, {ity} {plain}')
        of = self.t(); self.e(f'{of} = bitcast {ity} {o} to {fty}')
        return self._r33fz(of, n)

    def _r33bfdot(self, acc, n0, m0, n1, m1, n):
        """BFDotAdd (FEAT_EBF16 off): BFAdd(acc, BFAdd(BFMul(n0,m0), BFMul(n1,m1)))"""
        fty = f'<{n} x float>'
        p = []
        for a_, b_ in ((n0, m0), (n1, m1)):
            a2, b2 = self._r33fz(a_, n), self._r33fz(b_, n)
            q = self.t(); self.e(f'{q} = fmul {fty} {a2}, {b2}')   # exact: 8x8-bit significands
            isn = self.t(); self.e(f'{isn} = fcmp uno {fty} {q}, {q}')
            dn = self._r33c(fty, n, ['0x7FF8000000000000'] * n)
            q2 = self.t(); self.e(f'{q2} = select <{n} x i1> {isn}, {fty} {dn}, {fty} {q}')
            p.append(self._r33fz(q2, n))
        s = self._r33rto_add(p[0], p[1], n)
        return self._r33rto_add(acc, s, n)

    def _r33_dot_za(self, mn, ops):
        """fdot / bfdot za.s[w, off{, vgxN}], {zn.h..}, zm.h|{zm.h..}|zm.h[idx]"""
        za = self._r33za(ops[0])
        if not za or za['n'] != 1 or za['suf'] != 's' or len(ops) != 3:
            return False
        ns, suf, ni = self._r33srcs(ops[1], za['vg'])
        ms, msuf, mi = self._r33srcs(ops[2], za['vg'])
        if suf != 'h' or msuf != 'h' or ni is not None:
            return False
        n = SVL_BITS // 32
        bf = mn == 'bfdot'
        rows = self._r33zarows(za)
        fty, dty = f'<{n} x float>', f'<{n} x double>'
        for g in range(za['vg']):
            parts = []
            for slot, k, isz in ((ns[g], 0, False), (ns[g], 1, False),
                                 (ms[g], 0, True), (ms[g], 1, True)):
                h = self.sme_ld(slot, 2 * n, 'i16')
                if isz and mi is not None:
                    idx = ', '.join(f'i32 {(i // 4) * 8 + 2 * mi + k}' for i in range(n))
                else:
                    idx = ', '.join(f'i32 {2 * i + k}' for i in range(n))
                s = self.t()
                self.e(f'{s} = shufflevector <{2 * n} x i16> {h}, <{2 * n} x i16> poison, '
                       f'<{n} x i32> <{idx}>')
                parts.append(self._r33widen16(s, n, bf))
            n0, n1, m0, m1 = parts
            acc = self.za_ld(rows[g][0], n, 'float')
            if bf:
                r = self._r33bfdot(acc, n0, m0, n1, m1, n)
            else:
                #  R33d FDOT ROUNDS TWICE (M4, 669/669): f32(f32(p0 + p1) + acc).
                #    f16 products are exact in double; their double sum can only lose bits
                #    far below f32's rounding point, so the fptrunc is the f32 rounding.
                ds = []
                for v in (n0, n1, m0, m1):
                    d_ = self.t(); self.e(f'{d_} = fpext {fty} {v} to {dty}'); ds.append(d_)
                p0 = self.t(); self.e(f'{p0} = fmul {dty} {ds[0]}, {ds[2]}')
                p1 = self.t(); self.e(f'{p1} = fmul {dty} {ds[1]}, {ds[3]}')
                sp = self.t(); self.e(f'{sp} = fadd {dty} {p0}, {p1}')
                s32 = self.t(); self.e(f'{s32} = fptrunc {dty} {sp} to {fty}')
                r0 = self.t(); self.e(f'{r0} = fadd {fty} {acc}, {s32}')
                r = self._r33dn(fty, r0, n, 32)
            self.za_st(rows[g][0], r, n, 'float')
        return True

    def _r33_fdot(self, ops):
        return self._r33_dot_za('fdot', ops) if ops[0].strip().lower().startswith('za') else False

    def _r33_bfdot(self, ops):
        return self._r33_dot_za('bfdot', ops) if ops[0].strip().lower().startswith('za') else False

    def _r33_mlall_za(self, mn, ops):
        """smlall/umlall/... za.s|d[w, lo:lo+3{, vgxN}], zn, zm[idx] — 4-way widening,
            row r takes source elements 4e+r; zm's element is chosen per 128-bit segment."""
        za = self._r33za(ops[0])
        if not za or za['n'] != 4 or len(ops) != 3 or za['vg'] != 1:
            return False
        zn, zm = self._r33z(ops[1]), self._r33z(ops[2])
        if not (zn and zm and zn[1] and zn[1] == zm[1]) or zm[2] is None:
            return False
        deb = SVE_EL[za['suf']][0]
        seb = SVE_EL[zn[1]][0]
        if seb * 4 != deb:
            return False
        signed_n = mn[0] == 's'
        signed_m = mn[0] == 's' if mn[:2] not in ('su', 'us') else mn[:2] == 'us'
        sub = mn.endswith('sll')
        n, sn = SVL_BITS // deb, SVL_BITS // seb
        dty = f'<{n} x i{deb}>'
        a_ = self.sme_ld(zn[0], sn, f'i{seb}')
        b_ = self.sme_ld(zm[0], sn, f'i{seb}')
        eps = 128 // deb
        midx = ', '.join(f'i32 {4 * ((e // eps) * eps) + zm[2]}' for e in range(n))
        mb = self.t()
        self.e(f'{mb} = shufflevector <{sn} x i{seb}> {b_}, <{sn} x i{seb}> poison, <{n} x i32> <{midx}>')
        mw = self.t(); self.e(f'{mw} = {"sext" if signed_m else "zext"} <{n} x i{seb}> {mb} to {dty}')
        rows = self._r33zarows(za)[0]
        for r in range(4):
            idx = ', '.join(f'i32 {4 * e + r}' for e in range(n))
            x = self.t()
            self.e(f'{x} = shufflevector <{sn} x i{seb}> {a_}, <{sn} x i{seb}> poison, <{n} x i32> <{idx}>')
            xw = self.t(); self.e(f'{xw} = {"sext" if signed_n else "zext"} <{n} x i{seb}> {x} to {dty}')
            p = self.t(); self.e(f'{p} = mul {dty} {xw}, {mw}')
            acc = self.za_ld(rows[r], n, f'i{deb}')
            o = self.t(); self.e(f'{o} = {"sub" if sub else "add"} {dty} {acc}, {p}')
            self.za_st(rows[r], o, n, f'i{deb}')
        return True

    def _r33_smlall(self, ops): return self._r33_mlall_za('smlall', ops)
    def _r33_umlall(self, ops): return self._r33_mlall_za('umlall', ops)
    def _r33_smlsll(self, ops): return self._r33_mlall_za('smlsll', ops)
    def _r33_umlsll(self, ops): return self._r33_mlall_za('umlsll', ops)

    def _r33_vdot_za(self, mn, ops):
        """suvdot / usvdot / sudot-vertical: za.s[w, off, vgx4], {zn.b x4}, zm.b[idx]
            member r lane i sums zn_k.b[4i+r] * zm.b[16*seg + 4*idx + k] over k=0..3"""
        za = self._r33za(ops[0])
        if not za or za['n'] != 1 or za['vg'] != 4 or za['suf'] != 's' or len(ops) != 3:
            return False
        ns, suf = self.sme_list(ops[1])[:2]
        zm = self._r33z(ops[2])
        if suf != 'b' or len(ns) != 4 or not zm or zm[1] != 'b' or zm[2] is None:
            return False
        sn_, sm_ = {'suvdot': (True, False), 'usvdot': (False, True),
                    'svdot': (True, True), 'uvdot': (False, False)}[mn]
        n = 16
        dty = f'<{n} x i32>'
        rows = self._r33zarows(za)
        mv = self.sme_ld(zm[0], SVL_B, 'i8')
        zs = [self.sme_ld(s, SVL_B, 'i8') for s in ns]
        for r in range(4):
            acc = self.za_ld(rows[r][0], n, 'i32')
            for k in range(4):
                idx = ', '.join(f'i32 {4 * i + r}' for i in range(n))
                x = self.t()
                self.e(f'{x} = shufflevector <{SVL_B} x i8> {zs[k]}, <{SVL_B} x i8> poison, <{n} x i32> <{idx}>')
                midx = ', '.join(f'i32 {16 * (i // 4) + 4 * zm[2] + k}' for i in range(n))
                y = self.t()
                self.e(f'{y} = shufflevector <{SVL_B} x i8> {mv}, <{SVL_B} x i8> poison, <{n} x i32> <{midx}>')
                xw = self.t(); self.e(f'{xw} = {"sext" if sn_ else "zext"} <{n} x i8> {x} to {dty}')
                yw = self.t(); self.e(f'{yw} = {"sext" if sm_ else "zext"} <{n} x i8> {y} to {dty}')
                p = self.t(); self.e(f'{p} = mul {dty} {xw}, {yw}')
                a2 = self.t(); self.e(f'{a2} = add {dty} {acc}, {p}')
                acc = a2
            self.za_st(rows[r][0], acc, n, 'i32')
        return True

    def _r33_suvdot(self, ops): return self._r33_vdot_za('suvdot', ops)
    def _r33_usvdot(self, ops): return self._r33_vdot_za('usvdot', ops)

    # ── ZA: outer products into a tile ───────────────────────────────────────────────
    def _r33mopa_args(self, ops):
        if len(ops) != 5:
            return None
        t = ZA_TILE.match(ops[0].strip().lower())
        pn, pm = self._r33p(ops[1]), self._r33p(ops[2])
        zn, zm = self._r33z(ops[3]), self._r33z(ops[4])
        if not (t and pn and pm and zn and zm) or pn[2] != 'm' or pm[2] != 'm' \
                or zn[1] != zm[1] or not zn[1]:
            return None
        return int(t.group(1)), t.group(2), pn[0], pm[0], zn[0], zm[0], zn[1]

    def _r33_imopa(self, mn, ops):
        """smopa/smops/umopa/umops/sumopa/sumops/usmopa/usmops — 4-way (.b -> .s) and
           2-way (.h -> .s); every (row, col, k) product predicated by BOTH predicates."""
        a_ = self._r33mopa_args(ops)
        if not a_:
            return False
        T, tsuf, pn, pm, zn, zm, ssuf = a_
        deb, seb = SVE_EL[tsuf][0], SVE_EL[ssuf][0]
        if deb % seb or deb // seb not in (2, 4) or tsuf != 's' and tsuf != 'd':
            return False
        K = deb // seb
        sgn_n, sgn_m = {'sm': (True, True), 'um': (False, False),
                        'su': (True, False), 'us': (False, True)}[mn[:2]]
        sub = mn.endswith('ops')
        dim = SVL_BITS // deb
        sn = SVL_BITS // seb
        S = deb // 8
        dty = f'<{dim} x i{deb}>'
        nv, mv = self.sme_ld(zn, sn, f'i{seb}'), self.sme_ld(zm, sn, f'i{seb}')
        nm = self._r33mask(self._r33pv(pn), sn, seb)
        mm = self._r33mask(self._r33pv(pm), sn, seb)
        z0 = f'<{sn} x i{seb}>'
        nz = self.t(); self.e(f'{nz} = select <{sn} x i1> {nm}, {z0} {nv}, {z0} zeroinitializer')
        mz = self.t(); self.e(f'{mz} = select <{sn} x i1> {mm}, {z0} {mv}, {z0} zeroinitializer')
        Ms, As = [], []
        for k in range(K):
            idx = ', '.join(f'i32 {K * j + k}' for j in range(dim))
            mk = self.t(); self.e(f'{mk} = shufflevector {z0} {mz}, {z0} poison, <{dim} x i32> <{idx}>')
            mw = self.t(); self.e(f'{mw} = {"sext" if sgn_m else "zext"} <{dim} x i{seb}> {mk} to {dty}')
            Ms.append(mw)
            ak = self.t(); self.e(f'{ak} = shufflevector {z0} {nz}, {z0} poison, <{dim} x i32> <{idx}>')
            aw = self.t(); self.e(f'{aw} = {"sext" if sgn_n else "zext"} <{dim} x i{seb}> {ak} to {dty}')
            As.append(aw)
        for i in range(dim):
            row = T + S * i
            acc = self.za_ld(row, dim, f'i{deb}')
            for k in range(K):
                s = self.t(); self.e(f'{s} = shufflevector {dty} {As[k]}, {dty} poison, '
                                     f'<{dim} x i32> <{", ".join([f"i32 {i}"] * dim)}>')
                p = self.t(); self.e(f'{p} = mul {dty} {s}, {Ms[k]}')
                o = self.t(); self.e(f'{o} = {"sub" if sub else "add"} {dty} {acc}, {p}')
                acc = o
            self.za_st(row, acc, dim, f'i{deb}')
        return True

    def _r33_smopa(self, ops): return self._r33_imopa('smopa', ops)
    def _r33_smops(self, ops): return self._r33_imopa('smops', ops)
    def _r33_umopa(self, ops): return self._r33_imopa('umopa', ops)
    def _r33_umops(self, ops): return self._r33_imopa('umops', ops)
    def _r33_sumopa(self, ops): return self._r33_imopa('sumopa', ops)
    def _r33_sumops(self, ops): return self._r33_imopa('sumops', ops)
    def _r33_usmopa(self, ops): return self._r33_imopa('usmopa', ops)
    def _r33_usmops(self, ops): return self._r33_imopa('usmops', ops)

    def _r33_bmopx(self, sub, ops):
        a_ = self._r33mopa_args(ops)
        if not a_ or a_[1] != 's' or a_[6] != 's':
            return False
        T, _, pn, pm, zn, zm, _ = a_
        dim = 16
        ty = f'<{dim} x i32>'
        nv, mv = self.sme_ld(zn, dim, 'i32'), self.sme_ld(zm, dim, 'i32')
        nm = self._r33mask(self._r33pv(pn), dim, 32)
        mm = self._r33mask(self._r33pv(pm), dim, 32)
        for i in range(dim):
            row = T + 4 * i
            s = self.t(); self.e(f'{s} = shufflevector {ty} {nv}, {ty} poison, '
                                 f'<{dim} x i32> <{", ".join([f"i32 {i}"] * dim)}>')
            x = self.t(); self.e(f'{x} = xor {ty} {s}, {mv}')
            nx = self.t(); self.e(f'{nx} = xor {ty} {x}, {self.sve_splat(ty, dim, "i32", "-1")}')
            pc = self.t(); self.e(f'{pc} = call {ty} @llvm.ctpop.v16i32({ty} {nx})')
            acc = self.za_ld(row, dim, 'i32')
            o = self.t(); self.e(f'{o} = {"sub" if sub else "add"} {ty} {acc}, {pc}')
            bi = self.t(); self.e(f'{bi} = extractelement <{dim} x i1> {nm}, i32 {i}')
            sm = self.t(); self.e(f'{sm} = select i1 {bi}, <{dim} x i1> {mm}, <{dim} x i1> zeroinitializer')
            r = self.t(); self.e(f'{r} = select <{dim} x i1> {sm}, {ty} {o}, {ty} {acc}')
            self.za_st(row, r, dim, 'i32')
        return True

    def _r33_bmopa(self, ops): return self._r33_bmopx(False, ops)
    def _r33_bmops(self, ops): return self._r33_bmopx(True, ops)

    def _r33_bfmopx(self, sub, ops):
        """ BFMOPA (non-widening SME1 form into .s): BFDotAdd per (row, col) over the two
           half-element pairs; a pair is included only when BOTH predicates hold it, and a
           cell with no active pair is left untouched."""
        a_ = self._r33mopa_args(ops)
        if not a_ or a_[1] != 's' or a_[6] != 'h':
            return False
        T, _, pn, pm, zn, zm, _ = a_
        dim = 16
        fty = f'<{dim} x float>'
        nv, mv = self.sme_ld(zn, 32, 'i16'), self.sme_ld(zm, 32, 'i16')
        nm = self._r33mask(self._r33pv(pn), 32, 16)
        mm = self._r33mask(self._r33pv(pm), 32, 16)
        Mk, Mm = [], []
        for k in range(2):
            idx = ', '.join(f'i32 {2 * j + k}' for j in range(dim))
            s = self.t(); self.e(f'{s} = shufflevector <32 x i16> {mv}, <32 x i16> poison, <{dim} x i32> <{idx}>')
            f = self._r33widen16(s, dim, True)
            if sub:
                t_ = self.t(); self.e(f'{t_} = fneg {fty} {f}'); f = t_
            Mk.append(f)
            mk = self.t(); self.e(f'{mk} = shufflevector <32 x i1> {mm}, <32 x i1> poison, <{dim} x i32> <{idx}>')
            Mm.append(mk)
        nf = self._r33widen16(nv, 32, True)
        for i in range(dim):
            row = T + 4 * i
            acc = self.za_ld(row, dim, 'float')
            ns_, act = [], []
            for k in range(2):
                e_ = self.t(); self.e(f'{e_} = extractelement <32 x float> {nf}, i32 {2 * i + k}')
                sp = self.sve_splat(fty, dim, 'float', e_)
                b_ = self.t(); self.e(f'{b_} = extractelement <32 x i1> {nm}, i32 {2 * i + k}')
                a2 = self.t(); self.e(f'{a2} = select i1 {b_}, <{dim} x i1> {Mm[k]}, <{dim} x i1> zeroinitializer')
                #  R33c EACH OPERAND UNDER ITS OWN PREDICATE (M4): inf * a zeroed partner
                #    is NaN, which the both-active gating could never produce.
                nz = self.t(); self.e(f'{nz} = select i1 {b_}, {fty} {sp}, {fty} zeroinitializer')
                mz = self.t(); self.e(f'{mz} = select <{dim} x i1> {Mm[k]}, {fty} {Mk[k]}, {fty} zeroinitializer')
                ns_.append((nz, mz)); act.append(a2)
            r = self._r33bfdot(acc, ns_[0][0], ns_[0][1], ns_[1][0], ns_[1][1], dim)
            anyp = self.t(); self.e(f'{anyp} = or <{dim} x i1> {act[0]}, {act[1]}')
            o = self.t(); self.e(f'{o} = select <{dim} x i1> {anyp}, {fty} {r}, {fty} {acc}')
            self.za_st(row, o, dim, 'float')
        return True

    def _r33_bfmopa(self, ops): return self._r33_bfmopx(False, ops)
    def _r33_bfmops(self, ops): return self._r33_bfmopx(True, ops)

    # ── ZT0 lookup ───────────────────────────────────────────────────────────────────
    def _r33_luti4(self, ops):
        """ luti4: 4-bit indices taken CONTIGUOUSLY from zn (nibble j = byte j/2, low
           nibble first), segment k selecting which run; ZT0 read as 16 entries of the
           destination element size."""
        if len(ops) != 3 or ops[1].strip().lower() != 'zt0':
            return False
        m = re.fullmatch(r'z(\d+)\[(\d+)\]', ops[2].strip().lower())
        if not m:
            return False
        src, seg = 'v' + m.group(1), int(m.group(2))
        if ops[0].strip().startswith('{'):
            ds, suf = self.sme_list(ops[0])[:2]
        else:
            d = self._r33z(ops[0])
            if not d or not d[1]:
                return False
            ds, suf = [d[0]], d[1]
        eb = SVE_EL[suf][0]
        if eb not in (8, 16, 32):
            return False
        n = SVL_BITS // eb
        tot = n * len(ds)
        if (seg + 1) * tot > SVL_B * 2:
            return False
        zb = self.sme_ld(src, SVL_B, 'i8')
        tab = self.t(); self.e(f'{tab} = load <{SVL_B} x i8>, ptr %zt0')
        #  R33c 16 x 32-BIT ENTRIES whatever eb is; narrower lookups take the low bits.
        tbl = self.t(); self.e(f'{tbl} = bitcast <{SVL_B} x i8> {tab} to <16 x i32>')
        tn = 16
        outs = []
        for v in range(len(ds)):
            acc = 'poison'
            for i in range(n):
                j = seg * tot + v * n + i
                b_ = self.t(); self.e(f'{b_} = extractelement <{SVL_B} x i8> {zb}, i32 {j // 2}')
                if j % 2:
                    s = self.t(); self.e(f'{s} = lshr i8 {b_}, 4'); b_ = s
                a2 = self.t(); self.e(f'{a2} = and i8 {b_}, 15')
                x = self.t(); self.e(f'{x} = extractelement <{tn} x i32> {tbl}, i8 {a2}')
                if eb < 32:
                    x2 = self.t(); self.e(f'{x2} = trunc i32 {x} to i{eb}'); x = x2
                nx = self.t(); self.e(f'{nx} = insertelement <{n} x i{eb}> {acc}, i{eb} {x}, i32 {i}')
                acc = nx
            outs.append(acc)
        for d, v in zip(ds, outs):
            self.sme_st(d, v, n, f'i{eb}')
        return True

    def sve(self, mn, ops, a):
        """ EVERY ARM HERE RE-RAISES NotImplementedError FOR WHAT IT CANNOT DO. An SVE
           form that falls through must abort, never reach a NEON arm that would read the
           low 128 bits of a 512-bit register and return a quarter of the answer."""
        base = mn.split('.', 1)[0]
        # ── streaming mode. MEASURED on an M4: entry AND exit zero the vector file, and
        #    a bare smstart also zeroes the 4096-byte ZA tile. Not a mode flag.
        if base in ('smstart', 'smstop'):
            what = ops[0].strip().lower() if ops else ''
            if what not in ('', 'sm', 'za'):
                raise NotImplementedError(f'{mn} {ops}: unknown streaming operand')
            if what in ('', 'sm'):
                for i in range(32):
                    self.e(f'store <{SVL_B} x i8> zeroinitializer, ptr %v{i}')
                for i in range(16):
                    self.e(f'store i64 0, ptr %p{i}')
            if what in ('', 'za'):
                self.e(f'store [{SVL_B} x <{SVL_B} x i8>] zeroinitializer, ptr %za')
                self.e(f'store <{SVL_B} x i8> zeroinitializer, ptr %zt0')
            #  R24 AND THE MODE ITSELF, WHICH NOTHING TRACKED. Measured on an M4:
            #    SVCR reads 0 outside, 3 after a bare `smstart`, 2 after `smstop sm`,
            #    0 after `smstop za` — bit 0 = SM, bit 1 = ZA, confirmed by the
            #    transitions and not merely by the endpoints.
            #  WITHOUT THIS, `mrs x16, SVCR` HAS NOTHING TO READ. A guest that tests its
            #    own streaming state to decide whether to save ZA would take the branch
            #    the initial value happens to pick, forever.
            bits = {'': 3, 'sm': 1, 'za': 2}[what]
            cur = self.t(); self.e(f'{cur} = load i64, ptr @__arm_svcr')
            nxt = self.t()
            if base == 'smstart':
                self.e(f'{nxt} = or i64 {cur}, {bits}')
            else:
                self.e(f'{nxt} = and i64 {cur}, {~bits}')
            self.e(f'store i64 {nxt}, ptr @__arm_svcr')
            return True

        #  MULTI-VECTOR AND TILE FORMS ARE A DIFFERENT INSTRUCTION, NOT A WIDER ONE.
        #  R18-f THIS MATCHED THE SUBSTRING 'za' IN ANY OPERAND, and `smstart za`'s only
        #    operand IS 'za' - so the instruction that ENABLES the tile was rejected as a
        #    tile operation. It matches a za TOKEN now, and it runs AFTER the streaming arm
        #    because smstart/smstop are what every guarded instruction executes inside of.
        #  R18-i A VECTOR LIST IS NOT A VECTOR. `fcvt z0.h, { z0.s, z1.s }` is the
        #    SME2 two-vector form, and sve_tok() strips the brace - so it would have read
        #    `{ z0.s` as plain z0, converted HALF the data and returned a register that
        #    looks entirely full. Braces block until the multi-vector forms are built.
        #  R22 SME2 RUNS FIRST, AND THE GUARDS BELOW STILL EXIST. sme2() returns True
        #    only for a form it lowers completely; everything else falls through to the
        #    two aborts, so a multi-vector op this patch does not carry is still a named
        #    gap rather than a lowering that quietly handles one vector of four and hands
        #    back a register that looks entirely full.
        if self.sme2(mn, ops, a):
            return True

        if any(('{' in o or '}' in o) for o in ops):
            raise NotImplementedError(f'SVE/SME {mn} {ops} at {a:x}: vector list form '
                                      f'(multi-vector, phase 3)')
        if any(('vgx' in o or 'vlx' in o or 'mul vl' in o
                or ZATOK.match(o.strip().lstrip('{').strip())) for o in ops):
            raise NotImplementedError(f'SVE/SME {mn} {ops} at {a:x}: multi-vector or ZA '
                                      f'tile form (phase 3)')

        #  NO rdsvl ARM HERE. It already has one in lift(), and at the corrected
        #    VL_BYTES that arm is right. A second implementation beside a working one
        #    leaves the old one producing the output that makes the new one look correct.

        if base == 'ptrue':
            slot, suf, eb, ity, fty, n = self.sve_tok(ops[0])
            #  ptrue TAKES A PATTERN (VL1, VL2, MUL3...). Only the all-lanes form is
            #    modelled; any other pattern enables a DIFFERENT set of lanes.
            if len(ops) > 1 and ops[1].strip().lower() not in ('all',):
                raise NotImplementedError(f'ptrue pattern {ops[1]!r} unmodelled')
            self.e(f'store i64 {SVE_PTRUE_PAT[suf]}, ptr %{slot}')
            return True

        # ── conversions, in CONTAINERS of max(src, dst) width ────────────────
        cvt = SVE_CVT.get(base)
        if cvt:
            skind, dkind = cvt
            pred = next((o for o in ops if '/' in o), None)
            srcs = [o for o in ops[1:] if '/' not in o]
            if len(srcs) != 1:
                raise NotImplementedError(f'{mn} {ops}: expected 1 source, '
                                          f'got {len(srcs)}')
            dslot, dsuf, deb, dity, dfty, _ = self.sve_tok(ops[0])
            sslot, ssuf, seb, sity, sfty, _ = self.sve_tok(srcs[0])
            if deb is None or seb is None:
                raise NotImplementedError(f'{mn} {ops}: conversion needs both widths')
            cw = max(seb, deb)                 #  THE CONTAINER, measured
            n = SVL_BITS // cw
            cty = f'<{n} x i{cw}>'
            b = self.t(); self.e(f'{b} = load <{SVL_B} x i8>, ptr %{sslot}')
            sc = self.t(); self.e(f'{sc} = bitcast <{SVL_B} x i8> {b} to {cty}')
            if seb < cw:
                #  A WIDENING CONVERT READS THE LOW BITS OF EACH CONTAINER (measured:
                #    sixteen 1.0f in gave eight 1.0 out, from the low halves).
                tr = self.t(); self.e(f'{tr} = trunc {cty} {sc} to <{n} x i{seb}>')
            else:
                tr = sc
            sity_v = f'<{n} x i{seb}>'
            if skind == 'f':
                if sfty is None:
                    raise NotImplementedError(f'{mn}: .{ssuf} has no float form')
                src = self.t(); self.e(f'{src} = bitcast {sity_v} {tr} to <{n} x {sfty}>')
                sty = f'<{n} x {sfty}>'
            else:
                src, sty = tr, sity_v
            dity_v = f'<{n} x i{deb}>'
            if dkind == 'f':
                if dfty is None:
                    raise NotImplementedError(f'{mn}: .{dsuf} has no float form')
                dty = f'<{n} x {dfty}>'
                r = self.t()
                if skind == 'f':
                    if deb == seb:
                        raise NotImplementedError(f'{mn} {ops}: same-width fp convert')
                    self.e(f'{r} = {"fptrunc" if deb < seb else "fpext"} '
                           f'{sty} {src} to {dty}')
                else:
                    self.e(f'{r} = {"sitofp" if skind == "s" else "uitofp"} '
                           f'{sty} {src} to {dty}')
                rb = self.t(); self.e(f'{rb} = bitcast {dty} {r} to {dity_v}')
            else:
                #  ARM SATURATES AND MAPS NaN TO 0. Plain fptosi/fptoui are POISON out
                #    of range, which lets the optimiser delete live code - R8 paid for
                #    this once already on the NEON side.
                o_ = 'fptosi' if dkind == 's' else 'fptoui'
                rb = self.t()
                self.e(f'{rb} = call {dity_v} @llvm.{o_}.sat.v{n}i{deb}.v{n}'
                       f'{SVE_FN[seb]}({sty} {src})')
            if deb < cw:
                #  AND A NARROWING CONVERT ZEROES THE REST OF THE CONTAINER. The probe
                #    pre-filled z0 with 0x7F and the upper half came back 00, so the whole
                #    container is written - a zext, never a merge.
                z = self.t(); self.e(f'{z} = zext {dity_v} {rb} to {cty}')
            else:
                z = rb
            if pred is not None:
                mode = pred.strip().split('/')[1].strip().lower()
                if mode not in ('m', 'z'):
                    raise NotImplementedError(f'{mn}: predication mode /{mode}')
                m = self.pmask(pred, n, cw)      #  predicate at the CONTAINER width
                if mode == 'm':
                    ob = self.t(); self.e(f'{ob} = load <{SVL_B} x i8>, ptr %{dslot}')
                    old = self.t()
                    self.e(f'{old} = bitcast <{SVL_B} x i8> {ob} to {cty}')
                else:
                    old = 'zeroinitializer'
                sel = self.t()
                self.e(f'{sel} = select <{n} x i1> {m}, {cty} {z}, {cty} {old}')
                z = sel
            self.zwr(ops[0], z, cty)
            return True

        # ── shifts, which SATURATE rather than wrap (measured, see R18-k) ────
        shf = SVE_SHIFT.get(base)
        if shf:
            pred = next((o for o in ops if '/' in o), None)
            srcs = [o for o in ops[1:] if '/' not in o]
            if len(srcs) != 2:
                raise NotImplementedError(f'{mn} {ops}: expected 2 sources')
            dslot, dsuf, eb, ity, _f, n = self.sve_tok(ops[0])
            if eb is None:
                raise NotImplementedError(f'{mn} {ops}: no destination width')
            if self.sve_tok(srcs[0])[2] != eb:
                raise NotImplementedError(f'{mn} {ops}: data width differs from result')
            ty = f'<{n} x {ity}>'
            x, _t, _n, _e = self.zrd(srcs[0], fp=False)
            amt_tok = srcs[1].strip()
            big = None
            if amt_tok.startswith('#'):
                #  AN IMMEDIATE SHIFT IS ENCODED IN RANGE and cannot saturate; the
                #    assembler rejects one that could. No mask needed - but it is still
                #    checked, because an out-of-range constant would be poison.
                k = imm(amt_tok)
                if not 0 <= k < eb:
                    raise NotImplementedError(f'{mn}: immediate {k} out of range for .{dsuf}')
                amtv = self.sve_splat(ty, n, ity, str(k))
            else:
                aslot, asuf, aeb, aity, _af, an = self.sve_tok(amt_tok)
                if aeb is None or aeb < eb:
                    raise NotImplementedError(f'{mn} {ops}: shift-amount width .{asuf}')
                aty = f'<{an} x {aity}>'
                ab = self.t(); self.e(f'{ab} = load <{SVL_B} x i8>, ptr %{aslot}')
                av = self.t(); self.e(f'{av} = bitcast <{SVL_B} x i8> {ab} to {aty}')
                #  THE SATURATION MASK IS BUILT BEFORE THE CLAMP, because the clamp is
                #    what makes the shift itself legal and destroys the evidence.
                lim = self.sve_splat(aty, an, aity, str(eb))
                bm = self.t(); self.e(f'{bm} = icmp uge {aty} {av}, {lim}')
                cap = self.sve_splat(aty, an, aity, str(eb - 1))
                cl = self.t()
                self.e(f'{cl} = call {aty} @llvm.umin.v{an}i{aeb}({aty} {av}, {aty} {cap})')
                if aeb > eb:
                    #  THE WIDE FORM. Every element inside one 64-bit lane takes that
                    #    lane's amount - measured: s[0] and s[1] both used amount 0.
                    tr = self.t()
                    self.e(f'{tr} = trunc {aty} {cl} to <{an} x {ity}>')
                    rep = aeb // eb
                    idx = ', '.join(f'i32 {i // rep}' for i in range(n))
                    amtv = self.t()
                    self.e(f'{amtv} = shufflevector <{an} x {ity}> {tr}, '
                           f'<{an} x {ity}> poison, <{n} x i32> <{idx}>')
                    big = self.t()
                    self.e(f'{big} = shufflevector <{an} x i1> {bm}, <{an} x i1> poison, '
                           f'<{n} x i32> <{idx}>')
                else:
                    amtv, big = cl, bm
            r = self.t(); self.e(f'{r} = {shf} {ty} {x}, {amtv}')
            if big is not None:
                #  SATURATION, MEASURED: asr gives all sign bits, lsr/lsl give zero.
                if shf == 'ashr':
                    signs = self.sve_splat(ty, n, ity, str(eb - 1))
                    sat = self.t(); self.e(f'{sat} = ashr {ty} {x}, {signs}')
                else:
                    sat = 'zeroinitializer'
                sr = self.t()
                self.e(f'{sr} = select <{n} x i1> {big}, {ty} {sat}, {ty} {r}')
                r = sr
            if pred is not None:
                mode = pred.strip().split('/')[1].strip().lower()
                if mode not in ('m', 'z'):
                    raise NotImplementedError(f'{mn}: predication mode /{mode}')
                m = self.pmask(pred, n, eb)
                old = self.zrd(ops[0], fp=False)[0] if mode == 'm' else 'zeroinitializer'
                sel = self.t()
                self.e(f'{sel} = select <{n} x i1> {m}, {ty} {r}, {ty} {old}')
                r = sel
            self.zwr(ops[0], r, ty)
            return True

        # ── element-wise arithmetic ──────────────────────────────────────────
        fp2 = SVE_FP2.get(base); int2 = SVE_INT2.get(base)
        fp1 = SVE_FP1.get(base); rev = SVE_REV.get(base)
        if fp2 or int2 or fp1 or rev:
            isfp = bool(fp2 or fp1) or base in ('fdivr', 'fsubr')
            opc = fp2 or int2 or fp1 or rev
            pred = next((o for o in ops if '/' in o), None)
            srcs = [o for o in ops[1:] if '/' not in o]
            if pred is not None:
                mode = pred.strip().split('/')[1].strip().lower()
                if mode not in ('m', 'z'):
                    raise NotImplementedError(f'{mn}: predication mode /{mode} unmodelled')
            if fp1 and len(srcs) != 1:
                raise NotImplementedError(f'{mn} {ops}: expected 1 source, got {len(srcs)}')
            if not fp1 and len(srcs) != 2:
                raise NotImplementedError(f'{mn} {ops}: expected 2 sources, got {len(srcs)}')
            dslot, suf, eb, ity, fty, n = self.sve_tok(ops[0])
            el = fty if isfp else ity
            if el is None:
                raise NotImplementedError(f'{mn}: .{suf} has no floating-point form')
            ty = f'<{n} x {el}>'
            vals = []
            for sv in srcs:
                sv = sv.strip()
                if sv.startswith('#'):
                    k = imm(sv)
                    lit = str(k) if not isfp else _fpbits_literal(k, el)
                    vals.append(self.sve_splat(ty, n, el, lit))
                else:
                    v, vty, vn, vel = self.zrd(sv, fp=isfp)
                    if vty != ty:
                        raise NotImplementedError(
                            f'{mn}: mixed element widths {vty} vs {ty} (widening form)')
                    vals.append(v)
            r = self.t()
            if fp1:
                if opc == 'fneg':
                    self.e(f'{r} = fneg {ty} {vals[0]}')
                else:
                    self.e(f'{r} = call {ty} @llvm.{opc}.{_sve_sfx(n, el)}({ty} {vals[0]})')
            else:
                x, y = vals
                #  REVERSED FORM: fdivr/subr compute SRC/DST, not DST/SRC.
                if rev:
                    x, y = y, x
                self.e(f'{r} = {opc} {ty} {x}, {y}')
            if pred is not None:
                m = self.pmask(pred, n, eb)
                if pred.strip().split('/')[1].strip().lower() == 'm':
                    old, _, _, _ = self.zrd(ops[0], fp=isfp)
                else:
                    old = 'zeroinitializer'
                sel = self.t()
                self.e(f'{sel} = select <{n} x i1> {m}, {ty} {r}, {ty} {old}')
                r = sel
            self.zwr(ops[0], r, ty)
            return True

        return False

    #  10-03 ARM FLOATING-POINT NaN RULES (FPProcessNaNs, FPCR.DN = 0), found by the instruction certifier: 50 FP forms
    #    differed from the M4 only in WHICH NaN came out. x86 hands back -NaN for an invalid operation and the first source for
    #    two NaNs; ARM hands back the default +NaN, and among NaN inputs: the FIRST signaling NaN (quieted), else the FIRST
    #    quiet NaN, in ARM's operand order (for a fused multiply-add the ADDEND comes first, and operands ARM negates are
    #    negated before the choice). Applied AFTER the arithmetic, per lane, so every emitter path keeps its own maths.
    _FPB = {'half': (16, 0x7c00, 0x03ff, 0x0200, 0x7e00), 'float': (32, 0x7f800000, 0x7fffff, 0x400000, 0x7fc00000),
            'double': (64, 0x7ff0000000000000, 0xfffffffffffff, 0x8000000000000, 0x7ff8000000000000)}

    def arm_nan(self, res, ops, ty, el, n, fma=None):
        """res: the computed result (type ty = '<n x el>' or scalar el when n is None); ops: operand values in ARM's
           NaN-priority order (already negated where ARM negates). fma=(addend, op1, op2) adds ARM's rule that a quiet-NaN
           addend with an infinite x zero product yields the DEFAULT NaN."""
        bits, emask, mmask, qbit, dnan = self._FPB[el]
        ity = f'<{n} x i{bits}>' if n else f'i{bits}'
        K = (lambda v: f'splat (i{bits} {v})') if n else (lambda v: str(v))
        cty = f'<{n} x i1>' if n else 'i1'
        def T(): return self.t()
        def isnan(x): c = T(); self.e(f'{c} = fcmp uno {ty} {x}, {x}'); return c
        def ib(x): c = T(); self.e(f'{c} = bitcast {ty} {x} to {ity}'); return c
        def issnan(x):
            q = T(); self.e(f'{q} = and {ity} {ib(x)}, {K(qbit)}')
            z = T(); self.e(f'{z} = icmp eq {ity} {q}, {K(0)}')
            r = T(); self.e(f'{r} = and {cty} {isnan(x)}, {z}'); return r
        def quiet(x):
            o = T(); self.e(f'{o} = or {ity} {ib(x)}, {K(qbit)}')
            f = T(); self.e(f'{f} = bitcast {ity} {o} to {ty}'); return f
        #  10-03: the choice is made on the INTEGER bits. LLVM treats a NaN's bits as unspecified, so a float-typed
        #    `select(isnan(r), +NaN, r)` may be folded away — fsqrt kept x86's -NaN that way. Integers it must preserve.
        def isn_i(xi):
            e_ = T(); self.e(f'{e_} = and {ity} {xi}, {K(emask)}')
            ee = T(); self.e(f'{ee} = icmp eq {ity} {e_}, {K(emask)}')
            m_ = T(); self.e(f'{m_} = and {ity} {xi}, {K(mmask)}')
            mn_ = T(); self.e(f'{mn_} = icmp ne {ity} {m_}, {K(0)}')
            r_ = T(); self.e(f'{r_} = and {cty} {ee}, {mn_}'); return r_
        ri = ib(res)
        cand = T(); self.e(f'{cand} = select {cty} {isn_i(ri)}, {ity} {K(dnan)}, {ity} {ri}')
        if fma is not None:
            ad, m1, m2 = fma
            def isinf(x):
                ab = T(); self.e(f'{ab} = and {ity} {ib(x)}, {K((emask | mmask))}')
                c = T(); self.e(f'{c} = icmp eq {ity} {ab}, {K(emask)}'); return c
            def iszero(x):
                ab = T(); self.e(f'{ab} = and {ity} {ib(x)}, {K((emask | mmask))}')
                c = T(); self.e(f'{c} = icmp eq {ity} {ab}, {K(0)}'); return c
            i1 = T(); self.e(f'{i1} = and {cty} {isinf(m1)}, {iszero(m2)}')
            i2 = T(); self.e(f'{i2} = and {cty} {iszero(m1)}, {isinf(m2)}')
            inv = T(); self.e(f'{inv} = or {cty} {i1}, {i2}')
            qa = T(); self.e(f'{qa} = and {cty} {isn_i(ib(ad))}, {inv}')
        for x in reversed(ops):
            xi = ib(x)
            c = T(); self.e(f'{c} = select {cty} {isn_i(xi)}, {ity} {xi}, {ity} {cand}'); cand = c
        if fma is not None:
            c = T(); self.e(f'{c} = select {cty} {qa}, {ity} {K(dnan)}, {ity} {cand}'); cand = c
        for x in reversed(ops):
            xi = ib(x)
            q = T(); self.e(f'{q} = and {ity} {xi}, {K(qbit)}')
            z = T(); self.e(f'{z} = icmp eq {ity} {q}, {K(0)}')
            sn = T(); self.e(f'{sn} = and {cty} {isn_i(xi)}, {z}')
            o = T(); self.e(f'{o} = or {ity} {xi}, {K(qbit)}')
            c = T(); self.e(f'{c} = select {cty} {sn}, {ity} {o}, {ity} {cand}'); cand = c
        out = T(); self.e(f'{out} = bitcast {ity} {cand} to {ty}'); cand = out
        return cand

    _NANOPS = {'fadd', 'fsub', 'fmul', 'fdiv', 'fmulx', 'fabd', 'fsqrt', 'fmla', 'fmls', 'fmin', 'fmax', 'fminnm', 'fmaxnm',
               'frecps', 'frsqrts', 'faddp'}

    def neon(self, base, arr, ops, a):
        """ 10-03 ARM NaN rules around every FP NEON op (see arm_nan); everything else goes straight through."""
        if base in ('fcvtzs', 'fcvtzu') and len(ops) == 3 and ops[2].strip().startswith('#') and arr in VARR:
            #  10-03 (certifier vs M4): the VECTOR fixed-point form ignored #fbits (fcvtzu.2s #2 gave x, not x*4).
            #    ARM FPToFixed: round toward zero of x * 2^fbits, saturated, NaN -> 0. A power-of-two multiply is exact.
            fty, n, fel, eb = self.vty(arr, True); ity, _, iel, _ = self.vty(arr, False)
            fb = imm(ops[2])
            x = self.vrd(ops[1].strip(), arr, True)
            sc = self.t(); self.e(f'{sc} = fmul {fty} {x}, splat ({fel} {float(2 ** fb)!r})')
            op = 'fptosi' if base == 'fcvtzs' else 'fptoui'
            r = self.t(); self.e(f'{r} = call {ity} @llvm.{op}.sat.{self._sfx(n, iel)}.{self._sfx(n, fel)}({fty} {sc})')
            self.vwr(ops[0].strip(), arr, r); return
        if base not in self._NANOPS or arr not in VARR or not ops or not re.match(r'^[vqdshb]\d+$', ops[0].strip()):   # v-registers too (VREG is scalar-only)
            return self._neon_impl(base, arr, ops, a)
        ty, n, el, eb = self.vty(arr, True)
        if el not in self._FPB: return self._neon_impl(base, arr, ops, a)
        full = {16: '8h', 32: '4s', 64: '2d'}[eb]
        def rv(tok):
            tok = tok.strip()
            m = re.match(r'^(v\d+)(?:\.\w+)?\[(\d+)\]$', tok)
            if not m: return self.vrd(tok, arr, True)
            fv = self.vrd(m.group(1), full, True)
            x = self.t(); self.e(f'{x} = extractelement <{128 // eb} x {el}> {fv}, i32 {m.group(2)}')
            v = self.t(); self.e(f'{v} = insertelement {ty} poison, {el} {x}, i32 0')
            sp = self.t(); self.e(f'{sp} = shufflevector {ty} {v}, {ty} poison, <{n} x i32> zeroinitializer'); return sp
        def neg(x): g = self.t(); self.e(f'{g} = fneg {ty} {x}'); return g
        if base == 'faddp' and len(ops) != 3:
            return self._neon_impl(base, arr, ops, a)   # scalar pairwise (one source): not hooked, and read nothing first
        self.e('; --- arm-nan snapshot ---')   #  a NAMED SEAM: shape arms measure the emitter without it (selftest strip_nan)
        srcs = [rv(t) for t in ops[1:]]
        dold = self.vrd(ops[0].strip(), arr, True) if base in ('fmla', 'fmls') else None
        if base == 'faddp' and len(srcs) == 2 and n >= 2:
            cat = f'<{2 * n} x {el}>'
            c = self.t(); self.e(f'{c} = shufflevector {ty} {srcs[0]}, {ty} {srcs[1]}, <{2 * n} x i32> <{", ".join(f"i32 {i}" for i in range(2 * n))}>')
            ev = self.t(); self.e(f'{ev} = shufflevector {cat} {c}, {cat} poison, <{n} x i32> <{", ".join(f"i32 {2 * i}" for i in range(n))}>')
            od = self.t(); self.e(f'{od} = shufflevector {cat} {c}, {cat} poison, <{n} x i32> <{", ".join(f"i32 {2 * i + 1}" for i in range(n))}>')
            srcs = [ev, od]
        elif base == 'faddp':
            self.e('; --- arm-nan end ---'); return self._neon_impl(base, arr, ops, a)
        self.e('; --- arm-nan end ---')
        r = self._neon_impl(base, arr, ops, a)
        self.e('; --- arm-nan fix ---')
        res = self.vrd(ops[0].strip(), arr, True)
        fma = None
        if base == 'fmla': oplist = [dold, srcs[0], srcs[1]]; fma = (dold, srcs[0], srcs[1])
        elif base == 'fmls': nn = neg(srcs[0]); oplist = [dold, nn, srcs[1]]; fma = (dold, nn, srcs[1])
        elif base in ('frecps', 'frsqrts'):
            #  ARM: NaNs first (op1 negated); then infinity x zero is the step's CONSTANT (2.0 / 1.5), never a NaN
            bits_, emask_, mmask_ = self._FPB[el][:3]
            ity_ = f'<{n} x i{bits_}>'; cty_ = f'<{n} x i1>'
            def cls(x, want):
                bc = self.t(); self.e(f'{bc} = bitcast {ty} {x} to {ity_}')
                ab = self.t(); self.e(f'{ab} = and {ity_} {bc}, splat (i{bits_} {emask_ | mmask_})')
                c = self.t(); self.e(f'{c} = icmp eq {ity_} {ab}, splat (i{bits_} {want})'); return c
            i1 = self.t(); self.e(f'{i1} = and {cty_} {cls(srcs[0], emask_)}, {cls(srcs[1], 0)}')
            i2 = self.t(); self.e(f'{i2} = and {cty_} {cls(srcs[0], 0)}, {cls(srcs[1], emask_)}')
            inv = self.t(); self.e(f'{inv} = or {cty_} {i1}, {i2}')
            k = '2.0' if base == 'frecps' else '1.5'
            kv = self.t(); self.e(f'{kv} = fadd {ty} zeroinitializer, splat ({el} {k})')
            res2 = self.t(); self.e(f'{res2} = select {cty_} {inv}, {ty} {kv}, {ty} {res}'); res = res2
            oplist = [neg(srcs[0]), srcs[1]]
        elif base in ('fminnm', 'fmaxnm'):
            #  ...NM: a single QUIET NaN yields the OTHER operand; signaling NaNs and two NaNs follow the normal rule
            x, y = srcs
            def isn(v): c = self.t(); self.e(f'{c} = fcmp uno {ty} {v}, {v}'); return c
            nx, ny = isn(x), isn(y)
            cty = f'<{n} x i1>'
            mm = self.t(); self.e(f'{mm} = call {ty} @llvm.{"minimum" if base == "fminnm" else "maximum"}.{self._sfx(n, el)}({ty} {x}, {ty} {y})')
            oy = self.t(); self.e(f'{oy} = select {cty} {nx}, {ty} {y}, {ty} {mm}')
            ox = self.t(); self.e(f'{ox} = select {cty} {ny}, {ty} {x}, {ty} {oy}')
            both = self.t(); self.e(f'{both} = and {cty} {nx}, {ny}')
            pick = self.t(); self.e(f'{pick} = select {cty} {both}, {ty} {x}, {ty} {ox}')
            res = pick; oplist = [x, y]
            #  10-03: was arm_nan(res, []) first — with two quiet NaNs that made the DEFAULT NaN; ARM returns the first.
            #    Only signaling NaNs override the pick (quieted, first wins).
            fixed = self.arm_nan_snan_only(res, oplist, ty, el, n)
            self.vwr(ops[0].strip(), arr, fixed, True); self.e('; --- arm-nan end ---'); return r
        else: oplist = srcs
        fixed = self.arm_nan(res, oplist, ty, el, n, fma)
        if base == 'fabd':   #  ARM FABD = FPAbs(FPSub): the chosen NaN has its sign cleared too
            fa = self.t(); self.e(f'{fa} = call {ty} @llvm.fabs.{self._sfx(n, el)}({ty} {fixed})'); fixed = fa
        self.vwr(ops[0].strip(), arr, fixed, True)
        self.e('; --- arm-nan end ---')
        return r

    def arm_nan_snan_only(self, cand, ops, ty, el, n):
        bits, emask, mmask, qbit, dnan = self._FPB[el]
        ity = f'<{n} x i{bits}>' if n else f'i{bits}'; cty = f'<{n} x i1>' if n else 'i1'
        K = (lambda v: f'splat (i{bits} {v})') if n else (lambda v: str(v))
        for x in reversed(ops):
            b_ = self.t(); self.e(f'{b_} = bitcast {ty} {x} to {ity}')
            un = self.t(); self.e(f'{un} = fcmp uno {ty} {x}, {x}')
            q = self.t(); self.e(f'{q} = and {ity} {b_}, {K(qbit)}')
            z = self.t(); self.e(f'{z} = icmp eq {ity} {q}, {K(0)}')
            sn = self.t(); self.e(f'{sn} = and {cty} {un}, {z}')
            o = self.t(); self.e(f'{o} = or {ity} {b_}, {K(qbit)}')
            f = self.t(); self.e(f'{f} = bitcast {ity} {o} to {ty}')
            c = self.t(); self.e(f'{c} = select {cty} {sn}, {ty} {f}, {ty} {cand}'); cand = c
        return cand

    def _neon_impl(self, base, arr, ops, a):
        """ THE NEON DISPATCH — and NOT ONE llvm.aarch64.* intrinsic appears in it.
           Every arm emits target-neutral vector IR, which is exactly what lets the x86_64
           backend pick the SSE instruction itself. Measured lowerings on this machine
           (llc -mtriple=x86_64-apple-macos -mattr=+sse4.2, 2026-09-22):
             fadd/fsub/fmul/fdiv -> addps/subps/mulps/divps   dup/rev/ext -> pshufd
             and/orr/eor         -> andps/orps/xorps          zip1        -> punpcklbw
             frint{p,m,a,z}      -> roundps                   fsub.2d     -> subpd
             umin -> pminud   abs -> pabsb   addp -> phaddd   sqadd -> paddsw
             umull -> pmovzxbw+pmullw
            This is the R2 insight one layer up: the semantics belong to LLVM, not to us.
              We supply the SHAPE; the backend supplies the instruction."""
        FP = base[0] == 'f' and base != 'fmov'
        ty, n, el, eb = self.vty(arr, FP)
        ones = None if FP else self._splat(el, n, (1 << eb) - 1)
        def iv(tok):
            #  THE BY-LANE FORM, HANDLED ONCE FOR EVERY OP THAT TAKES IT.
            #    `mls.2s v5, v2, v7[0]` multiplies every lane of Vn by ONE lane of Vm.
            #    Splatting that lane makes the by-lane form byte-identical to the vector
            #    form, so this one branch covers mul/mla/mls/fmul/fmla/fmls together.
            #  THE LANE INDEX COUNTS THE FULL REGISTER, NOT THE NARROWED SHAPE. Reading
            #    at `arr` first and then indexing would put v7[3] out of range on a .2s op
            #    and silently read the wrong data on a .8b one.
            tok = tok.strip()
            if '[' not in tok: return self.vrd(tok, arr, FP)
            reg, lane = tok.split('[')
            fa = {8: '16b', 16: '8h', 32: '4s', 64: '2d'}[eb]
            f_ = self.vrd(reg.strip(), fa, FP)
            fty, fn, _, _ = self.vty(fa, FP)
            m = ', '.join([f'i32 {int(lane.rstrip("]"), 0)}'] * n)
            r = self.t()
            self.e(f'{r} = shufflevector {fty} {f_}, {fty} poison, <{n} x i32> <{m}>')
            return r

        def put(v): self.vwr(ops[0], arr, v, FP)

        def bin_(op, x, y):
            r = self.t(); self.e(f'{r} = {op} {ty} {x}, {y}'); return r

        def call_(fn, *xs):
            args = ', '.join(f'{ty} {x}' for x in xs)
            r = self.t()
            self.e(f'{r} = call {ty} @llvm.{fn}.{self._sfx(n, el)}({args})')
            return r

        # ── R9 THE FAMILIES THAT BLOCKED WHOLE FUNCTIONS IN THE 120-IMAGE SWEEP ──
        #  FIRST IN THE DISPATCH ON PURPOSE. R8's finding was that an arm which is never
        #    REACHED looks exactly like an arm that does not exist; putting these ahead of
        #    every existing name makes reachability a property of the file, not of luck.
        wel = f'i{eb * 2}'
        wty = f'<{n} x {wel}>'
        def _wd(v, sg, fr=None):
            r = self.t()
            self.e(f'{r} = {"sext" if sg else "zext"} {fr or ty} {v} to {wty}')
            return r
        def _clamp(vv, vty_, vel_, vn_, lo, hi, sgn):
            gt, lt = ('sgt', 'slt') if sgn else ('ugt', 'ult')
            hc = self._splat(vel_, vn_, hi)
            c1 = self.t(); self.e(f'{c1} = icmp {gt} {vty_} {vv}, {hc}')
            v1 = self.t()
            self.e(f'{v1} = select <{vn_} x i1> {c1}, {vty_} {hc}, {vty_} {vv}')
            lc = self._splat(vel_, vn_, lo)
            c2 = self.t(); self.e(f'{c2} = icmp {lt} {vty_} {v1}, {lc}')
            v2 = self.t()
            self.e(f'{v2} = select <{vn_} x i1> {c2}, {vty_} {lc}, {vty_} {v1}')
            return v2

        # ── R17-b THE LAST ARITHMETIC FAMILIES ────────────────────────────────
        def _abd(x, y, sg, vty_, vn_):
            """|x - y| in the width they are already in.  NOT abs(x-y): see uabd."""
            g = self.t()
            self.e(f'{g} = icmp {"sgt" if sg else "ugt"} {vty_} {x}, {y}')
            d1 = self.t(); self.e(f'{d1} = sub {vty_} {x}, {y}')
            d2 = self.t(); self.e(f'{d2} = sub {vty_} {y}, {x}')
            r = self.t()
            self.e(f'{r} = select <{vn_} x i1> {g}, {vty_} {d1}, {vty_} {d2}')
            return r

        if base in ('aese', 'aesd', 'aesmc', 'aesimc'):
            #  R17-c 8,043 INSTRUCTIONS ONTO THE XEON'S REAL AES-NI. Verified on this
            #    laptop's silicon against FIPS-197 Appendix B round 1: state
            #    193de3be a0f4e22b 9ac68d2a e9f84808 with a zero key gives
            #    d4bf5d30 e0b452ae b84111f1 1e2798e5 after aese, and
            #    046681e5 e0cb199a 48f8d37a 2806264c after aesmc — the published values.
            #    Ground truth from the standard, independent of both machines.
            #
            #      aese  Vd, Vn -> SubBytes(ShiftRows(Vd ^ Vn))       = AESENCLAST(Vd^Vn, 0)
            #      aesd  Vd, Vn -> InvSubBytes(InvShiftRows(Vd ^ Vn)) = AESDECLAST(Vd^Vn, 0)
            #      aesmc Vd, Vn -> MixColumns(Vn)      = AESENC(AESDECLAST(Vn, 0), 0)
            #      aesimc Vd,Vn -> InvMixColumns(Vn)   = AESIMC(Vn)
            #
            #  WHY THE aesmc IDENTITY HOLDS: AESDECLAST(x,0) = InvSubBytes(InvShiftRows(x)).
            #    AESENC then applies ShiftRows, SubBytes, MixColumns. SubBytes is per-byte
            #    and ShiftRows is a permutation, so they commute; ShiftRows cancels
            #    InvShiftRows and SubBytes cancels InvSubBytes, leaving MixColumns alone.
            #  ARM'S OPERAND ORDER IS (accumulator, key), NOT (key, state). aese XORs its
            #    TWO operands before the round — reading Vn as the state and Vd as the key
            #    gives the same answer only because XOR is commutative, but aesmc/aesimc
            #    read ONLY Vn and writing Vd's old value instead would be silent.
            if arr != '16b':
                raise NotImplementedError(f'{base}.{arr} at {a:x}')
            src = self.vrd(ops[1].strip(), '2d', False)
            if base in AESMAP:
                acc = self.vrd(ops[0].strip(), '2d', False)
                x = self.t(); self.e(f'{x} = xor <2 x i64> {acc}, {src}')
                r = self.t()
                self.e(f'{r} = call <2 x i64> @llvm.x86.aesni.{AESMAP[base]}'
                       f'(<2 x i64> {x}, <2 x i64> zeroinitializer)')
            elif base == 'aesimc':
                r = self.t()
                self.e(f'{r} = call <2 x i64> @llvm.x86.aesni.aesimc(<2 x i64> {src})')
            else:
                t1 = self.t()
                self.e(f'{t1} = call <2 x i64> @llvm.x86.aesni.aesdeclast'
                       f'(<2 x i64> {src}, <2 x i64> zeroinitializer)')
                r = self.t()
                self.e(f'{r} = call <2 x i64> @llvm.x86.aesni.aesenc'
                       f'(<2 x i64> {t1}, <2 x i64> zeroinitializer)')
            self.vwr(ops[0].strip(), '2d', r, False)
            return

        if base == 'fmov' and len(ops) == 2 and (
                '[' in ops[0] or '[' in ops[1]):
            #  R17-c `fmov.d v4[1], x7` — the GPR<->high-lane bit move. It is spelled
            #    with an arrangement so it reaches this dispatch, but it is a LANE insert,
            #    not an element-wise operation, and the plain `fmov` arm below only handles
            #    the immediate form.
            #  IT IS A BIT MOVE. Lowering it through the FP path would round.
            fa = {8: '16b', 16: '8h', 32: '4s', 64: '2d'}[eb]
            fty, fn, fel, _ = self.vty(fa, False)
            if '[' in ops[0]:
                reg, lane = ops[0].split('[')
                ln = int(lane.rstrip(']'), 0)
                cur = self.vrd(reg.strip(), fa, False)
                g = self.rd(ops[1])
                if eb < 64:
                    tg = self.t(); self.e(f'{tg} = trunc i64 {g} to {fel}'); g = tg
                r = self.t()
                self.e(f'{r} = insertelement {fty} {cur}, {fel} {g}, i64 {ln}')
                self.vwr(reg.strip(), fa, r, False)
            else:
                reg, lane = ops[1].split('[')
                ln = int(lane.rstrip(']'), 0)
                cur = self.vrd(reg.strip(), fa, False)
                e0 = self.t()
                self.e(f'{e0} = extractelement {fty} {cur}, i64 {ln}')
                if eb < 64:
                    z = self.t(); self.e(f'{z} = zext {fel} {e0} to i64'); e0 = z
                self.wr(ops[0], e0)
            return

        if base.rstrip('2') in ('uaba', 'saba', 'uabal', 'sabal', 'uabdl', 'sabdl'):
            #  THE ABSOLUTE-DIFFERENCE FAMILY, ALL SIX SPELLINGS AT ONCE:
            #      uaba   d += |n - m|           same width
            #      uabdl  d  = |n - m| widened   arr is the WIDE destination
            #      uabal  d += |n - m| widened   arr is the WIDE destination
            #    and the `2` forms read the HIGH half of each source (R9).
            #  THE DIFFERENCE IS TAKEN IN THE **NARROW** WIDTH AND THEN WIDENED, and it
            #    matters: |a-b| of two bytes is at most 255, so widening first would give
            #    the same number here — but widening first with SEXT on the unsigned form
            #    turns 0xFF into -1 and the difference into a negative. Narrow-then-zext
            #    is the definition; it is also the only order that is right for both signs.
            hi2 = base.endswith('2')
            b0 = base.rstrip('2')
            sg = b0[0] == 's'
            wide = b0.endswith('l')
            acc = b0[1:].startswith('ab') and b0[3] == 'a'   # uaba / uabal accumulate
            if wide:
                sarr = NARROW_SRC.get(arr)
                if sarr is None:
                    raise NotImplementedError(f'{base}.{arr}: no narrow source at {a:x}')
                sty, sn, sel, _ = self.vty(sarr, False)
                rdf = self.vrd_hi if hi2 else self.vrd
                x = rdf(ops[1].strip(), sarr, False)
                y = rdf(ops[2].strip(), sarr, False)
                d = _abd(x, y, sg, sty, sn)
                w = self.t()
                self.e(f'{w} = {"sext" if sg else "zext"} {sty} {d} to {ty}')
                res = w
            else:
                if hi2:
                    raise NotImplementedError(f'{base}.{arr} at {a:x}')
                res = _abd(iv(ops[1]), iv(ops[2]), sg, ty, n)
            if acc:
                cur = self.vrd(ops[0], arr, False)
                r = self.t(); self.e(f'{r} = add {ty} {cur}, {res}'); res = r
            put(res); return

        if base in ('srshl', 'urshl', 'sqrshl', 'uqrshl', 'sqshl', 'uqshl', 'sqshlu'):
            #  R17-b ONE MECHANISM, SEVEN MNEMONICS. Every member is
            #        result = SAT( ROUND( Vn << shift ) )
            #    with shift SIGNED (negative means shift right), and with ROUND and SAT
            #    each present or absent. Writing them as one arm is what keeps the
            #    rounding term and the clamp from drifting apart between spellings.
            #
            #  THE INTERMEDIATE IS DOUBLE WIDTH AND THE AMOUNT IS CLAMPED. Two separate
            #    traps, both silent:
            # ARM defines the rounded/saturated value over an intermediate of
            #        unbounded precision. Computed in the element width, `sqshl` can never
            #        detect the overflow it exists to saturate — it would return the
            #        wrapped value, which is a plausible number.
            # LLVM says a shift whose amount is >= the bit width is POISON (R13).
            #        A shift amount of exactly `esize` is a LEGAL ARM encoding meaning
            #        "everything shifted out", so the natural spelling is undefined
            #        behaviour on its most ordinary input. Both directions are clamped
            #        into range and the clamped answer is the same one ARM specifies.
            rnd = 'r' in base[1:3]
            sat = base[0] == 's' and base[1] == 'q' or base[:2] == 'uq'
            sg = base[0] == 's'
            usat = base == 'sqshlu' or base[0] == 'u'
            W = eb * 2
            wty_ = f'<{n} x i{W}>'
            wel_ = f'i{W}'
            xw = self.t()
            self.e(f'{xw} = {"sext" if sg else "zext"} {ty} {iv(ops[1])} to {wty_}')
            if ops[2].strip().startswith('#'):
                #  THE IMMEDIATE FORM IS ALWAYS A LEFT SHIFT and is never rounded.
                k = imm(ops[2])
                if not 0 <= k < eb:
                    raise NotImplementedError(f'{base}.{arr} shift #{k} at {a:x}')
                rw = self.t(); self.e(f'{rw} = shl {wty_} {xw}, {self._splat(wel_, n, k)}')
            else:
                shb = self.t()
                self.e(f'{shb} = trunc {ty} {iv(ops[2])} to <{n} x i8>')
                sh = self.t(); self.e(f'{sh} = sext <{n} x i8> {shb} to {wty_}')
                zc = self._splat(wel_, n, 0)
                neg = self.t(); self.e(f'{neg} = icmp slt {wty_} {sh}, {zc}')
                # LEFT: amount clamped to eb (beyond which every bit is shifted out)
                lk0 = self.t()
                self.e(f'{lk0} = call {wty_} @llvm.umin.{self._sfx(n, wel_)}'
                       f'({wty_} {sh}, {wty_} {self._splat(wel_, n, eb)})')
                lft = self.t(); self.e(f'{lft} = shl {wty_} {xw}, {lk0}')
                # RIGHT: amount = -shift, clamped to eb+1 (beyond which the answer is 0)
                rk = self.t(); self.e(f'{rk} = sub {wty_} {zc}, {sh}')
                rk2 = self.t()
                self.e(f'{rk2} = call {wty_} @llvm.umin.{self._sfx(n, wel_)}'
                       f'({wty_} {rk}, {wty_} {self._splat(wel_, n, eb + 1)})')
                src_ = xw
                if rnd:
                    #  round term = 2^(k-1), written as (1<<k)>>1 so that k == 0 gives 0
                    #    instead of the undefined `1 << -1`. k == 0 cannot reach the right
                    #    branch, but BOTH branches are computed before the select, so it
                    #    must be defined there anyway.
                    one_ = self._splat(wel_, n, 1)
                    p1 = self.t(); self.e(f'{p1} = shl {wty_} {one_}, {rk2}')
                    p2 = self.t(); self.e(f'{p2} = lshr {wty_} {p1}, {one_}')
                    ad = self.t(); self.e(f'{ad} = add {wty_} {xw}, {p2}')
                    src_ = ad
                rgt = self.t()
                self.e(f'{rgt} = {"ashr" if sg else "lshr"} {wty_} {src_}, {rk2}')
                rw = self.t()
                self.e(f'{rw} = select <{n} x i1> {neg}, {wty_} {rgt}, {wty_} {lft}')
            if sat:
                #  sqshlu IS THE ODD ONE: SIGNED source, UNSIGNED saturation. Clamping it
                #    with unsigned predicates would read its negative intermediate as huge
                #    and saturate UP to the maximum, where ARM saturates DOWN to zero.
                #    The comparison stays signed and only the bounds change.
                if usat:
                    rw = _clamp(rw, wty_, wel_, n, 0, (1 << eb) - 1, True)
                else:
                    rw = _clamp(rw, wty_, wel_, n, -(1 << (eb - 1)),
                                (1 << (eb - 1)) - 1, True)
            tr = self.t(); self.e(f'{tr} = trunc {wty_} {rw} to {ty}')
            put(tr); return

        if base in ('usqadd', 'suqadd'):
            #  MIXED-SIGN SATURATING ACCUMULATE. usqadd: UNSIGNED destination plus a
            #    SIGNED operand, saturating unsigned. suqadd is the mirror.
            #  THE TWO OPERANDS ARE EXTENDED DIFFERENTLY, and that is the whole
            #    instruction. Extending both the same way makes it an ordinary sqadd/uqadd
            #    that agrees on every non-negative input — a bug invisible to any test
            #    whose data happens to be positive.
            W = eb * 2; wty_ = f'<{n} x i{W}>'; wel_ = f'i{W}'
            u_first = base == 'usqadd'
            d0 = self.vrd(ops[0], arr, False); s0 = iv(ops[1])
            de = self.t()
            self.e(f'{de} = {"zext" if u_first else "sext"} {ty} {d0} to {wty_}')
            se = self.t()
            self.e(f'{se} = {"sext" if u_first else "zext"} {ty} {s0} to {wty_}')
            sm = self.t(); self.e(f'{sm} = add {wty_} {de}, {se}')
            lo, hi = ((0, (1 << eb) - 1) if u_first
                      else (-(1 << (eb - 1)), (1 << (eb - 1)) - 1))
            cl = _clamp(sm, wty_, wel_, n, lo, hi, True)
            tr = self.t(); self.e(f'{tr} = trunc {wty_} {cl} to {ty}')
            put(tr); return

        if base in ('sqabs', 'sqneg'):
            #  THE ONLY INPUT THAT MATTERS IS INT_MIN. abs(INT_MIN) and -INT_MIN are both
            #    INT_MIN in two's complement; ARM saturates them to INT_MAX. llvm.abs with
            #    is_int_min_poison=true would be UNDEFINED on exactly that value.
            W = eb * 2; wty_ = f'<{n} x i{W}>'; wel_ = f'i{W}'
            xw = self.t(); self.e(f'{xw} = sext {ty} {iv(ops[1])} to {wty_}')
            if base == 'sqabs':
                v = self.t()
                self.e(f'{v} = call {wty_} @llvm.abs.{self._sfx(n, wel_)}'
                       f'({wty_} {xw}, i1 false)')
            else:
                v = self.t()
                self.e(f'{v} = sub {wty_} {self._splat(wel_, n, 0)}, {xw}')
            cl = _clamp(v, wty_, wel_, n, -(1 << (eb - 1)), (1 << (eb - 1)) - 1, True)
            tr = self.t(); self.e(f'{tr} = trunc {wty_} {cl} to {ty}')
            put(tr); return

        if base == 'fcmla':
            #  R17-b 9,031 INSTRUCTIONS — THE LARGEST SINGLE GAP FAMILY IN THE CACHE.
            #    FCMLA is one step of a complex multiply-accumulate: adjacent lane pairs
            #    are (real, imaginary), and #rot picks which of the four partial products
            #    this step contributes. Two FCMLAs (#0 then #90) are a full complex
            #    multiply, which is why they come in pairs in every FFT in the dyld cache.
            #
            #        rot   d.re +=            d.im +=
            #          0   n.re * m.re        n.re * m.im
            #         90  -n.im * m.im        n.im * m.re
            #        180  -n.re * m.re       -n.re * m.im
            #        270   n.im * m.im       -n.im * m.re
            #
            #  THE INDEXED FORM SELECTS A COMPLEX PAIR, NOT A LANE. `v26[0]` means
            #    elements 0 AND 1 of v26, used by every pair of the destination. The
            #    ordinary by-lane helper splats ONE element into every lane, which would
            #    silently multiply the imaginary part by the real one.
            #  AND IT IS A FUSED multiply-add — FPMulAdd, one rounding. Ivy Bridge has no
            #    FMA, so llvm.fma becomes a libcall here and that is the correct answer:
            #    an unfused mul+add would round twice and differ in the last bit, which is
            #    exactly the bit an FFT accumulates.
            rot = imm(ops[3])
            if rot not in (0, 90, 180, 270) or n % 2:
                raise NotImplementedError(f'fcmla.{arr} rot #{rot} at {a:x}')
            fsf = self._sfx(n, el)
            dcur = self.vrd(ops[0], arr, True)
            vn = self.vrd(ops[1], arr, True)
            mtok = ops[2].strip()
            if '[' in mtok:
                reg, lane = mtok.split('[')
                li = int(lane.rstrip(']'), 0)
                vm = self.vrd(reg.strip(), arr, True)
                midx = lambda e: (2 * li, 2 * li + 1)
            else:
                vm = self.vrd(mtok, arr, True)
                midx = lambda e: (2 * e, 2 * e + 1)

            def ex(v, i):
                r = self.t(); self.e(f'{r} = extractelement {ty} {v}, i64 {i}'); return r

            def fneg(v):
                r = self.t(); self.e(f'{r} = fneg {el} {v}'); return r

            def fma(x, y, z):
                r = self.t()
                #  THE INTRINSIC SUFFIX IS f16/f32/f64, NEVER THE LLVM TYPE NAME.
                #    `llvm.fma.double` parses as a call to an undeclared function and
                #    links to nothing; only the f32 case was spelled correctly.
                fs = {'half': 'f16', 'float': 'f32', 'double': 'f64'}[el]
                self.e(f'{r} = call {el} @llvm.fma.{fs}({el} {x}, {el} {y}, {el} {z})')
                return r
            res = dcur
            for e2 in range(n // 2):
                m0, m1 = midx(e2)
                nre, nim = ex(vn, 2 * e2), ex(vn, 2 * e2 + 1)
                mre, mim = ex(vm, m0), ex(vm, m1)
                dre, dim = ex(dcur, 2 * e2), ex(dcur, 2 * e2 + 1)
                if rot == 0:
                    a1, b1, a2, b2 = nre, mre, nre, mim
                elif rot == 90:
                    a1, b1, a2, b2 = fneg(nim), mim, nim, mre
                elif rot == 180:
                    a1, b1, a2, b2 = fneg(nre), mre, fneg(nre), mim
                else:
                    a1, b1, a2, b2 = nim, mim, fneg(nim), mre
                r0, r1 = fma(a1, b1, dre), fma(a2, b2, dim)
                t0 = self.t()
                self.e(f'{t0} = insertelement {ty} {res}, {el} {r0}, i64 {2 * e2}')
                t1 = self.t()
                self.e(f'{t1} = insertelement {ty} {t0}, {el} {r1}, i64 {2 * e2 + 1}')
                res = t1
            self.vwr(ops[0], arr, res, True); return

        # ── R37 THE LAST NEON GAP, CLOSED AGAINST SILICON ─────────────────────────
        #  Every op below was run on an M1 Pro AND an M4 (r37/k.S, 200 records per op, the
        #    two chips byte-identical) and both halves of the lowering replay those records:
        #    r37/rt_check.c runs neon_rt.c natively, r37 runs the LIFTED code on the Xeon.
        #  The C runtime owns the ops with hidden state or FP corner rules (SHA rounds,
        #    round-to-odd, f16 NaN order, bf16 flush + round-to-odd). Inline IR would put x86's
        #    default NaN (sign SET) into ARM results; neon_rt.c decides every NaN in integers.
        if base in R37_SHA:
            d_, n_ = self.vslot(ops[0]), self.vslot(ops[1])
            m_ = self.vslot(ops[2]) if len(ops) > 2 else n_
            self.e(f'call void @__arm2x86_rt_sha(ptr %{d_}, ptr %{n_}, ptr %{m_}, '
                   f'i64 {R37_SHA[base]})')
            return
        if base == 'fcvtxn' and arr == 's':
            self.e(f'call void @__arm2x86_rt_fcvtxn(ptr %{self.vslot(ops[0])}, '
                   f'ptr %{self.vslot(ops[1])}, i64 0)')
            return
        if base == 'faddp' and arr == '2h':
            self.e(f'call void @__arm2x86_rt_faddp_h(ptr %{self.vslot(ops[0])}, '
                   f'ptr %{self.vslot(ops[1])})')
            return
        if base in ('fmlal', 'fmlal2', 'fmlsl', 'fmlsl2', 'bfdot'):
            q_ = {'4s': 1, '2s': 0}.get(arr)
            if q_ is None:
                raise NotImplementedError(f'{base}.{arr} at {a:x}')
            fl = q_ | (2 if base.endswith('2') else 0) | (4 if 'sl' in base else 0)
            mt = ops[2].strip()
            if '[' in mt:
                reg_, lane_ = mt.split('[')
                fl |= 16 | (int(lane_.rstrip(']'), 0) << 8); mt = reg_
            fn_ = 'bfdot' if base == 'bfdot' else 'fmlal'
            self.e(f'call void @__arm2x86_rt_{fn_}(ptr %{self.vslot(ops[0])}, '
                   f'ptr %{self.vslot(ops[1])}, ptr %{self.vslot(mt)}, i64 {fl})')
            return
        if base in ('sqdmlal', 'sqdmlsl', 'sqdmlal2', 'sqdmlsl2'):
            #  2*a*b CAN ONLY SATURATE AT (-2^(w-1))^2, so a widened multiply followed by a
            #    saturating self-add is exact; the accumulate then saturates on its own.
            #  FPSR.QC is not modelled (no NEON op here sets it); nothing in the sampled
            #    images reads it back.
            hi_ = base.endswith('2')
            if arr == 's':
                darr, sarr, dn, dw = 'd', 's', 1, 64
            elif arr in ('2d', '4s'):
                darr, sarr = arr, {'2d': '2s', '4s': '4h'}[arr]
                _, dn, _, dw = self.vty(arr)
            else:
                raise NotImplementedError(f'{base}.{arr} at {a:x}')
            sw = dw // 2
            def src_(t):
                return self.vrd_hi(t, sarr) if hi_ else self.vrd(t, sarr)
            xa = src_(ops[1].strip())
            mt = ops[2].strip()
            if '[' in mt:
                reg_, lane_ = mt.split('[')
                fa_ = {32: '4s', 16: '8h'}[sw]
                full_ = self.vrd(reg_.strip(), fa_); fty_ = self.vty(fa_)[0]
                ix_ = ', '.join([f'i32 {int(lane_.rstrip("]"), 0)}'] * dn)
                xb = self.t()
                self.e(f'{xb} = shufflevector {fty_} {full_}, {fty_} poison, <{dn} x i32> <{ix_}>')
            else:
                xb = src_(mt)
            dty, sty, sfx = f'<{dn} x i{dw}>', f'<{dn} x i{sw}>', f'v{dn}i{dw}'
            e1 = self.t(); self.e(f'{e1} = sext {sty} {xa} to {dty}')
            e2 = self.t(); self.e(f'{e2} = sext {sty} {xb} to {dty}')
            p_ = self.t(); self.e(f'{p_} = mul {dty} {e1}, {e2}')
            p2 = self.t(); self.e(f'{p2} = call {dty} @llvm.sadd.sat.{sfx}({dty} {p_}, {dty} {p_})')
            acc = self.vrd(ops[0].strip(), darr)
            op_ = 'ssub.sat' if 'mlsl' in base else 'sadd.sat'
            r_ = self.t(); self.e(f'{r_} = call {dty} @llvm.{op_}.{sfx}({dty} {acc}, {dty} {p2})')
            self.vwr(ops[0].strip(), darr, r_); return
        if base in ('xar', 'rax1', 'sha1h'):
            #  THE THREE CRYPTO INSTRUCTIONS THAT ARE PURE BIT ARITHMETIC. Unlike the
            #    SHA round instructions these have no hidden constant table and no
            #    compression-function state, so they are exact in plain IR and need no
            #    silicon measurement: the ARM reference IS the implementation.
            #      xar   Vd = ROR(Vn ^ Vm, #imm)   per 64-bit lane   (SHA3 / Keccak)
            #      rax1  Vd = Vn ^ ROL(Vm, 1)      per 64-bit lane
            #      sha1h Sd = ROL(Sn, 30)          the SHA-1 'a' rotate
            if base == 'sha1h':
                x = self.vrd(ops[1], 's', False)
                r = self.t()
                self.e(f'{r} = call <1 x i32> @llvm.fshl.v1i32(<1 x i32> {x}, '
                       f'<1 x i32> {x}, <1 x i32> <i32 30>)')
                self.vwr(ops[0], 's', r, False); return
            x, y = self.vrd(ops[1], arr, False), self.vrd(ops[2], arr, False)
            if base == 'xar':
                e1 = self.t(); self.e(f'{e1} = xor {ty} {x}, {y}')
                amt = self._splat(el, n, imm(ops[3]) % eb)
                r = self.t()
                self.e(f'{r} = call {ty} @llvm.fshr.{self._sfx(n, el)}'
                       f'({ty} {e1}, {ty} {e1}, {ty} {amt})')
            else:
                one_ = self._splat(el, n, 1)
                rl = self.t()
                self.e(f'{rl} = call {ty} @llvm.fshl.{self._sfx(n, el)}'
                       f'({ty} {y}, {ty} {y}, {ty} {one_})')
                r = self.t(); self.e(f'{r} = xor {ty} {x}, {rl}')
            put(r); return

        if base in ('frecps', 'frsqrts'):
            #  THE NEWTON-RAPHSON STEP THAT PAIRS WITH frecpe/frsqrte:
            #      frecps  = 2.0 - n*m          frsqrts = (3.0 - n*m) / 2
            #  AND THE SPECIAL CASE IS THE POINT. When one operand is zero and the other
            #    infinite, n*m is a NaN and the plain formula returns NaN — ARM returns the
            #    ITERATION CONSTANT (2.0 / 1.5), so that a Newton step on 1/0 converges
            #    instead of poisoning the sequence. Dropping this select gives the right
            #    answer on every ordinary input and NaN on the one that matters.
            fty_, _, fel_, _ = self.vty(arr, True)
            xa, xb = self.vrd(ops[1], arr, True), self.vrd(ops[2], arr, True)
            sf = self._sfx(n, fel_)
            pf = {'half': '0xH0000', 'float': '0.0', 'double': '0.0'}[fel_]
            zv = '<' + ', '.join(f'{fel_} {pf}' for _ in range(n)) + '>'
            ab = self.t(); self.e(f'{ab} = call {fty_} @llvm.fabs.{sf}({fty_} {xa})')
            bb = self.t(); self.e(f'{bb} = call {fty_} @llvm.fabs.{sf}({fty_} {xb})')
            inf = '<' + ', '.join(f'{fel_} 0x7FF0000000000000' for _ in range(n)) + '>'
            ai = self.t(); self.e(f'{ai} = fcmp oeq {fty_} {ab}, {inf}')
            bi = self.t(); self.e(f'{bi} = fcmp oeq {fty_} {bb}, {inf}')
            az = self.t(); self.e(f'{az} = fcmp oeq {fty_} {xa}, {zv}')
            bz = self.t(); self.e(f'{bz} = fcmp oeq {fty_} {xb}, {zv}')
            c1 = self.t(); self.e(f'{c1} = and <{n} x i1> {ai}, {bz}')
            c2 = self.t(); self.e(f'{c2} = and <{n} x i1> {az}, {bi}')
            sp = self.t(); self.e(f'{sp} = or <{n} x i1> {c1}, {c2}')
            #  10-03 (certifier vs M4, exact-arithmetic check: M4 == ARM's single rounding, ours 1 ulp off): the step is
            #    FUSED — FPMulAdd(k, -n, m), one rounding. fmul then fsub rounded twice.
            k = 2.0 if base == 'frecps' else 3.0
            kv = '<' + ', '.join(f'{fel_} {k:.1f}' for _ in range(n)) + '>'
            na_ = self.t(); self.e(f'{na_} = fneg {fty_} {xa}')
            df = self.t(); self.e(f'{df} = call {fty_} @llvm.fma.{sf}({fty_} {na_}, {fty_} {xb}, {fty_} {kv})')
            if base == 'frsqrts':
                hv = '<' + ', '.join(f'{fel_} 0.5' for _ in range(n)) + '>'
                hf = self.t(); self.e(f'{hf} = fmul {fty_} {df}, {hv}'); df = hf
            cst = 2.0 if base == 'frecps' else 1.5
            cv = '<' + ', '.join(f'{fel_} {cst}' for _ in range(n)) + '>'
            r = self.t()
            self.e(f'{r} = select <{n} x i1> {sp}, {fty_} {cv}, {fty_} {df}')
            self.vwr(ops[0], arr, r, True); return

        if base in ('bfcvtn', 'bfcvtn2'):
            #  BF16 IS THE TOP HALF OF AN f32 — but NOT by truncation. The conversion
            #    rounds to nearest, ties to even, which is `u + 0x7FFF + ((u>>16)&1)`.
            #    Plain truncation is off by one ulp on half of all inputs and biases the
            #    whole tensor downward, which is precisely the error bf16 exists to avoid.
            #  AND A NaN MUST STAY A NaN. Adding the rounding bias to a NaN whose payload
            #    is all ones carries into the exponent and produces an INFINITY — a
            #    silently finite-looking result from a NaN input. The select restores it.
            hi2 = base.endswith('2')
            dst = arr if hi2 else arr
            harr = HALF.get(arr) if hi2 else arr
            if hi2:
                if harr is None:
                    raise NotImplementedError(f'{base}.{arr}: no half at {a:x}')
            sarr = {'4h': '4s', '8h': '4s'}.get(harr)
            if sarr is None:
                raise NotImplementedError(f'{base}.{arr} at {a:x}')
            sty, sn, _, _ = self.vty(sarr, False)
            u = self.vrd(ops[1].strip(), sarr, False)
            s32 = lambda v: self._splat('i32', sn, v)
            lsb0 = self.t(); self.e(f'{lsb0} = lshr {sty} {u}, {s32(16)}')
            lsb = self.t(); self.e(f'{lsb} = and {sty} {lsb0}, {s32(1)}')
            b1 = self.t(); self.e(f'{b1} = add {sty} {u}, {s32(0x7FFF)}')
            b2 = self.t(); self.e(f'{b2} = add {sty} {b1}, {lsb}')
            rn = self.t(); self.e(f'{rn} = lshr {sty} {b2}, {s32(16)}')
            ax = self.t(); self.e(f'{ax} = and {sty} {u}, {s32(0x7FFFFFFF)}')
            nan = self.t(); self.e(f'{nan} = icmp ugt {sty} {ax}, {s32(0x7F800000)}')
            q0 = self.t(); self.e(f'{q0} = lshr {sty} {u}, {s32(16)}')
            q1 = self.t(); self.e(f'{q1} = or {sty} {q0}, {s32(0x40)}')
            pick = self.t()
            self.e(f'{pick} = select <{sn} x i1> {nan}, {sty} {q1}, {sty} {rn}')
            hty, _, _, _ = self.vty(harr, False)
            tr = self.t(); self.e(f'{tr} = trunc {sty} {pick} to {hty}')
            if hi2:
                self.vwr_hi(ops[0].strip(), harr, tr, False)
            else:
                self.vwr(ops[0].strip(), harr, tr, False)
            return

        if base in ('uabd', 'sabd'):
            #  NOT abs(a - b) IN THE LANE WIDTH. An unsigned difference that wraps cannot
            #    be recovered by abs() — 0x01 - 0xFF is 0x02, whose absolute value is 2 and
            #    whose true |difference| is 254. The comparison has to pick the order.
            x, y = iv(ops[1]), iv(ops[2])
            g = self.t()
            self.e(f'{g} = icmp {"sgt" if base[0] == "s" else "ugt"} {ty} {x}, {y}')
            d1 = bin_('sub', x, y); d2 = bin_('sub', y, x)
            r = self.t()
            self.e(f'{r} = select <{n} x i1> {g}, {ty} {d1}, {ty} {d2}')
            put(r); return

        if base in ('uhadd', 'shadd', 'urhadd', 'srhadd', 'uhsub', 'shsub'):
            #  HALVING ADD/SUB — one extra bit of headroom, then shift back. The whole
            #    point is that it CANNOT overflow, so it must be computed wide.
            sg = base[0] == 's'
            rest = base[1:]
            rnd = rest.startswith('r')
            rest = rest[1:] if rnd else rest
            sub_ = rest == 'hsub'
            x = _wd(iv(ops[1]), sg); y = _wd(iv(ops[2]), sg)
            t1 = self.t()
            self.e(f'{t1} = {"sub" if sub_ else "add"} {wty} {x}, {y}')
            if rnd:
                tb = self.t()
                self.e(f'{tb} = add {wty} {t1}, {self._splat(wel, n, 1)}')
                t1 = tb
            #  ARM TAKES BITS [esize:1] OF A *SIGNED* INTERMEDIATE even for the unsigned
            #    forms — UHSUB's difference is negative whenever a < b.
            op = 'ashr' if (sg or sub_) else 'lshr'
            sh = self.t()
            self.e(f'{sh} = {op} {wty} {t1}, {self._splat(wel, n, 1)}')
            tr = self.t(); self.e(f'{tr} = trunc {wty} {sh} to {ty}')
            put(tr); return

        if base.rstrip('2') in ('uaddw', 'saddw', 'usubw', 'ssubw'):
            #  WIDE + NARROW. `arr` names the WIDE side (ops[0] and ops[1]); ops[2] is the
            #    half-width shape, and the `2` form takes its HIGH half.
            hi2 = base.endswith('2'); b2 = base.rstrip('2')
            sg = b2[0] == 's'
            sarr = NARROW_SRC.get(arr)
            if sarr is None:
                raise NotImplementedError(f'{base}.{arr}: no narrow shape at {a:x}')
            sty_, _, _, _ = self.vty(sarr, False)
            sv = (self.vrd_hi(ops[2].strip(), sarr) if hi2
                  else self.vrd(ops[2].strip(), sarr))
            ex = self.t()
            self.e(f'{ex} = {"sext" if sg else "zext"} {sty_} {sv} to {ty}')
            put(bin_('add' if 'add' in b2 else 'sub', iv(ops[1]), ex)); return

        if base in ('uaddlp', 'saddlp', 'uadalp', 'sadalp'):
            #  PAIRWISE ADD LONG — adds ADJACENT lanes of ONE register and widens. The
            #    arrangement names the (wide, half-count) destination.
            LP = {'8h': '16b', '4h': '8b', '4s': '8h', '2s': '4h', '2d': '4s', '1d': '2s'}
            sg = base[0] == 's'
            acc = base[1:4] == 'ada'
            sarr = LP.get(arr)
            if sarr is None:
                raise NotImplementedError(f'{base}.{arr}: no source shape at {a:x}')
            sty_, sn_, sel_, _ = self.vty(sarr, False)
            sv = self.vrd(ops[1].strip(), sarr)
            ev = ', '.join(f'i32 {2 * i}' for i in range(n))
            od = ', '.join(f'i32 {2 * i + 1}' for i in range(n))
            hty = f'<{n} x {sel_}>'
            e1 = self.t()
            self.e(f'{e1} = shufflevector {sty_} {sv}, {sty_} poison, <{n} x i32> <{ev}>')
            o1 = self.t()
            self.e(f'{o1} = shufflevector {sty_} {sv}, {sty_} poison, <{n} x i32> <{od}>')
            xe = self.t(); self.e(f'{xe} = {"sext" if sg else "zext"} {hty} {e1} to {ty}')
            xo = self.t(); self.e(f'{xo} = {"sext" if sg else "zext"} {hty} {o1} to {ty}')
            r = bin_('add', xe, xo)
            if acc:
                r = bin_('add', r, iv(ops[0]))
            put(r); return

        NARROW_DST = {'8b': '8h', '4h': '4s', '2s': '2d'}
        if base.rstrip('2') in ('shrn', 'rshrn', 'addhn', 'subhn', 'raddhn', 'rsubhn'):
            #  NARROWING. `arr` is the DESTINATION; for a `2` form it is the FULL 128-bit
            #    destination and only HALF[arr] of it is written — the other half belongs
            #    to the non-`2` partner that ran immediately before.
            hi2 = base.endswith('2'); b2 = base.rstrip('2')
            darr = HALF.get(arr) if hi2 else arr
            if darr is None:
                raise NotImplementedError(f'{base}.{arr}: no half at {a:x}')
            dty_, dn_, del_, deb_ = self.vty(darr, False)
            sarr = NARROW_DST.get(darr)
            if sarr is None:
                raise NotImplementedError(f'{base}.{arr}: no wide source at {a:x}')
            sty_, sn_, sel_, _ = self.vty(sarr, False)
            if b2.endswith('shrn'):
                sh = imm(ops[2])
                v = self.vrd(ops[1].strip(), sarr)
                if b2.startswith('r'):
                    vb = self.t()
                    self.e(f'{vb} = add {sty_} {v}, {self._splat(sel_, sn_, 1 << (sh - 1))}')
                    v = vb
                r0 = self.t()
                self.e(f'{r0} = lshr {sty_} {v}, {self._splat(sel_, sn_, sh)}')
            else:
                x = self.vrd(ops[1].strip(), sarr); y = self.vrd(ops[2].strip(), sarr)
                t1 = self.t()
                self.e(f'{t1} = {"sub" if "sub" in b2 else "add"} {sty_} {x}, {y}')
                if b2.startswith('r'):
                    tb = self.t()
                    self.e(f'{tb} = add {sty_} {t1}, '
                           f'{self._splat(sel_, sn_, 1 << (deb_ - 1))}')
                    t1 = tb
                r0 = self.t()
                self.e(f'{r0} = lshr {sty_} {t1}, {self._splat(sel_, sn_, deb_)}')
            tr = self.t(); self.e(f'{tr} = trunc {sty_} {r0} to {dty_}')
            if hi2:
                self.vwr_hi(ops[0], darr, tr)
            else:
                self.vwr(ops[0], darr, tr)
            return

        SATN = ('sqxtn', 'uqxtn', 'sqxtun', 'sqshrn', 'uqshrn',
                'sqrshrn', 'uqrshrn', 'sqshrun', 'sqrshrun')
        if base.rstrip('2') in SATN:
            #  THESE SATURATE, AND A PLAIN trunc DOES NOT. R8 already paid for this in the
            #    scalar FP→int direction (fptosi is POISON out of range, fptosi.sat is not);
            #    the integer narrows are the same trap with a different spelling. The
            #    COMPARISON's signedness comes from the SOURCE, the CLAMP's range from the
            #    destination — `sqxtun` is the one where they disagree, and it is the one
            #    that makes a single shared rule impossible.
            hi2 = base.endswith('2'); b2 = base.rstrip('2')
            darr = HALF.get(arr) if hi2 else arr
            if darr is None:
                raise NotImplementedError(f'{base}.{arr}: no half at {a:x}')
            dty_, dn_, del_, deb_ = self.vty(darr, False)
            sarr = NARROW_DST.get(darr)
            if sarr is None:
                raise NotImplementedError(f'{base}.{arr}: no wide source at {a:x}')
            sty_, sn_, sel_, _ = self.vty(sarr, False)
            src_signed = b2[0] == 's'
            dst_unsigned = b2.endswith('un') or b2[0] == 'u'
            v = self.vrd(ops[1].strip(), sarr)
            if 'shr' in b2:
                sh = imm(ops[2])
                if 'rshr' in b2:
                    vb = self.t()
                    self.e(f'{vb} = add {sty_} {v}, {self._splat(sel_, sn_, 1 << (sh - 1))}')
                    v = vb
                vs = self.t()
                self.e(f'{vs} = {"ashr" if src_signed else "lshr"} {sty_} {v}, '
                       f'{self._splat(sel_, sn_, sh)}')
                v = vs
            if dst_unsigned:
                lo, hi = 0, (1 << deb_) - 1
            else:
                lo, hi = -(1 << (deb_ - 1)), (1 << (deb_ - 1)) - 1
            v = _clamp(v, sty_, sel_, sn_, lo, hi, src_signed)
            tr = self.t(); self.e(f'{tr} = trunc {sty_} {v} to {dty_}')
            if hi2:
                self.vwr_hi(ops[0], darr, tr)
            else:
                self.vwr(ops[0], darr, tr)
            return

        if base in ('sqdmulh', 'sqrdmulh'):
            #  SQDMULH is (2ab) >> esize, i.e. (ab) >> (esize-1).
            #  COMPUTING IT AS `shl 1` THEN `ashr esize` OVERFLOWS THE WIDE TYPE on the
            #    one input the saturation exists for (-2^(e-1) squared), so the doubling is
            #    folded into the shift instead of performed.
            #  SQRDMULH adds 2^(esize-1) BEFORE the doubling is folded out, which is
            #    2^(esize-2) here.
            x = _wd(iv(ops[1]), True); y = _wd(iv(ops[2]), True)
            p = self.t(); self.e(f'{p} = mul {wty} {x}, {y}')
            if base == 'sqrdmulh':
                pb = self.t()
                self.e(f'{pb} = add {wty} {p}, {self._splat(wel, n, 1 << (eb - 2))}')
                p = pb
            sh = self.t()
            self.e(f'{sh} = ashr {wty} {p}, {self._splat(wel, n, eb - 1)}')
            cl = _clamp(sh, wty, wel, n, -(1 << (eb - 1)), (1 << (eb - 1)) - 1, True)
            tr = self.t(); self.e(f'{tr} = trunc {wty} {cl} to {ty}')
            put(tr); return

        if base in ('udot', 'sdot', 'usdot', 'sudot'):
            #  4-WAY BYTE DOT PRODUCT ACCUMULATING INTO THE DESTINATION. Written lane by
            #    lane so it needs no intrinsic; LLVM picks pmaddubsw/pmaddwd itself.
            #  R37 BY-ELEMENT `v2.4b[i]` IS ONE 32-BIT LANE OF Vm SPLATTED, which is
            #    exactly iv()'s by-lane read at .4s/.2s, then reinterpreted as bytes.
            #    usdot = Vn unsigned x Vm signed; sudot the reverse (by-element only).
            if eb != 32:
                raise NotImplementedError(f'{base}.{arr} at {a:x}')
            barr = {4: '16b', 2: '8b'}.get(n)
            if barr is None:
                raise NotImplementedError(f'{base}.{arr} at {a:x}')
            bty, bn_, bel_, _ = self.vty(barr, False)
            xa = self.vrd(ops[1].strip(), barr)
            if '[' in ops[2]:
                sp_ = iv(ops[2]); xb = self.t()
                self.e(f'{xb} = bitcast {ty} {sp_} to {bty}')
            else:
                xb = self.vrd(ops[2].strip(), barr)
            ext1 = 'sext' if base in ('sdot', 'sudot') else 'zext'
            ext2 = 'sext' if base in ('sdot', 'usdot') else 'zext'
            res = iv(ops[0])
            for i in range(n):
                tot = None
                for j in range(4):
                    k = 4 * i + j
                    p1 = self.t(); self.e(f'{p1} = extractelement {bty} {xa}, i64 {k}')
                    p2 = self.t(); self.e(f'{p2} = extractelement {bty} {xb}, i64 {k}')
                    q1 = self.t(); self.e(f'{q1} = {ext1} {bel_} {p1} to {el}')
                    q2 = self.t(); self.e(f'{q2} = {ext2} {bel_} {p2} to {el}')
                    m = self.t(); self.e(f'{m} = mul {el} {q1}, {q2}')
                    if tot is None:
                        tot = m
                    else:
                        nt = self.t(); self.e(f'{nt} = add {el} {tot}, {m}'); tot = nt
                cur = self.t(); self.e(f'{cur} = extractelement {ty} {res}, i64 {i}')
                nv = self.t(); self.e(f'{nv} = add {el} {cur}, {tot}')
                nr = self.t()
                self.e(f'{nr} = insertelement {ty} {res}, {el} {nv}, i64 {i}')
                res = nr
            put(res); return

        # ── R9-h THE LAYER THE R9 SWEEP UNCOVERED ─────────────────────────────
        if base in ('sli', 'sri'):
            #  SHIFT AND INSERT — the destination is a SOURCE: the bits shifted out of
            #    range are not zeroed, they are the destination's own bits kept.
            #  SRI WITH shift == esize SHIFTS EVERYTHING OUT, and `lshr i8 x, 8` is POISON
            #    in LLVM, not zero. It is a legal encoding meaning "leave Vd alone".
            sh = imm(ops[2])
            d, v = iv(ops[0]), iv(ops[1])
            if base == 'sli':
                if not 0 <= sh < eb:
                    raise NotImplementedError(f'sli #{sh} on .{arr} at {a:x}')
                keep = (1 << sh) - 1
                sv = self.t(); self.e(f'{sv} = shl {ty} {v}, {self._splat(el, n, sh)}')
            else:
                if not 1 <= sh <= eb:
                    raise NotImplementedError(f'sri #{sh} on .{arr} at {a:x}')
                if sh == eb:
                    put(d); return
                keep = ((1 << sh) - 1) << (eb - sh)
                sv = self.t(); self.e(f'{sv} = lshr {ty} {v}, {self._splat(el, n, sh)}')
            kd = bin_('and', d, self._splat(el, n, keep))
            put(bin_('or', kd, sv)); return

        #  ONLY THE *ROUNDING* FORMS ARE NEW — plain ssra/usra were already correct
        #    further down this dispatch, and duplicating them here would SHADOW a working
        #    arm with a second copy that nobody would think to keep in step.
        RND_SHR = {'srshr', 'urshr', 'srsra', 'ursra'}
        if base in RND_SHR:
            #  THE ROUNDING CONSTANT OVERFLOWS THE LANE IT IS ADDED IN. For .16b with
            #    Vn = 0x7F and shift 1 the answer is 64, but 127 + 1 in an i8 is -128 and
            #    `ashr` gives -64. The rounding forms MUST be computed one width up; the
            #    non-rounding ones cannot overflow and are done in place.
            sg = base[0] == 's'
            sh = imm(ops[2])
            if not 1 <= sh <= eb:
                raise NotImplementedError(f'{base} #{sh} on .{arr} at {a:x}')
            v = iv(ops[1])
            if True:
                w = _wd(v, sg)
                wr_ = self.t()
                self.e(f'{wr_} = add {wty} {w}, {self._splat(wel, n, 1 << (sh - 1))}')
                ws = self.t()
                self.e(f'{ws} = {"ashr" if sg else "lshr"} {wty} {wr_}, '
                       f'{self._splat(wel, n, sh)}')
                r = self.t(); self.e(f'{r} = trunc {wty} {ws} to {ty}')
            if base.endswith('sra'):
                r = bin_('add', iv(ops[0]), r)
            put(r); return

        if base in ('shll', 'shll2'):
            #  SHIFT LEFT LONG — widen, then shift left by EXACTLY the source element
            #    size, which is the only encodable shift. The low bits are all zero, so
            #    the extension's signedness cannot change the answer.
            hi2 = base.endswith('2')
            sarr = NARROW_SRC.get(arr)
            if sarr is None:
                raise NotImplementedError(f'{base}.{arr}: no narrow shape at {a:x}')
            sh = imm(ops[2]) if len(ops) > 2 else eb // 2
            if sh != eb // 2:
                raise NotImplementedError(f'{base} #{sh} on .{arr} at {a:x}')
            sty_, _, _, _ = self.vty(sarr, False)
            sv = (self.vrd_hi(ops[1].strip(), sarr) if hi2
                  else self.vrd(ops[1].strip(), sarr))
            ex = self.t(); self.e(f'{ex} = zext {sty_} {sv} to {ty}')
            r = self.t(); self.e(f'{r} = shl {ty} {ex}, {self._splat(el, n, sh)}')
            put(r); return

        if base == 'fcadd':
            #  COMPLEX ADD BY ROTATION. Each lane PAIR is one complex number (even = real,
            #    odd = imaginary) and the rotation says which part gets negated:
            #      #90   d.re = n.re - m.im ,  d.im = n.im + m.re
            #      #270  d.re = n.re + m.im ,  d.im = n.im - m.re
            #    so it is ONE pairwise swap of Vm plus a sign flip on alternating lanes.
            #  THE ROTATION IS NOT A FLAG TO IGNORE — #90 and #270 differ by the sign of
            #    both terms, which is a conjugate. Defaulting to either would compute the
            #    complex conjugate of the intended product and still produce finite floats.
            if not FP or n % 2:
                raise NotImplementedError(f'fcadd.{arr} at {a:x}')
            rot = imm(ops[3])
            if rot not in (90, 270):
                raise NotImplementedError(f'fcadd rot #{rot} at {a:x}')
            x, y = iv(ops[1]), iv(ops[2])
            sw = ', '.join(f'i32 {i ^ 1}' for i in range(n))
            ys = self.t()
            self.e(f'{ys} = shufflevector {ty} {y}, {ty} poison, <{n} x i32> <{sw}>')
            neg_even = rot == 90
            sg = '<' + ', '.join(
                f'{el} ' + ('-1.000000e+00' if (i % 2 == 0) == neg_even else '1.000000e+00')
                for i in range(n)) + '>'
            sy = self.t(); self.e(f'{sy} = fmul {ty} {ys}, {sg}')
            put(bin_('fadd', x, sy)); return

        if base == 'bcax':
            #  SHA-3's bit-clear-and-XOR: a ^ (b & ~c).
            put(bin_('xor', iv(ops[1]), bin_('and', iv(ops[2]),
                                             bin_('xor', iv(ops[3]), ones)))); return

        if base in ('frecps', 'frsqrts'):
            #  THE NEWTON-RAPHSON STEPS THAT GO WITH FRECPE/FRSQRTE. These are exact
            #    arithmetic, not estimates — 2 - a*b and (3 - a*b)/2.
            def _fsp(k):
                return '<' + ', '.join(f'{el} {k}' for _ in range(n)) + '>'
            #  10-03 (certifier vs M4, 1 ulp): ARM's steps are FUSED — FPMulAdd(2.0 | 3.0, -a, b), one rounding — and the
            #    halving of the rsqrt step is exact. fmul then fsub rounded twice.
            na = self.t(); self.e(f'{na} = fneg {ty} {iv(ops[1])}')
            k = _fsp('2.000000e+00') if base == 'frecps' else _fsp('3.000000e+00')
            f = self.t(); self.e(f'{f} = call {ty} @llvm.fma.{self._sfx(n, el)}({ty} {na}, {ty} {iv(ops[2])}, {ty} {k})')
            if base == 'frecps':
                put(f); return
            put(bin_('fmul', f, _fsp('5.000000e-01'))); return

        if base == 'cnt':
            if el != 'i8':
                raise NotImplementedError(f'cnt.{arr} (bytes only) at {a:x}')
            put(call_('ctpop', iv(ops[1]))); return

        if base == 'rbit' and not GPRT.match(ops[0].strip()):
            if el != 'i8':
                raise NotImplementedError(f'rbit.{arr} (bytes only) at {a:x}')
            put(call_('bitreverse', iv(ops[1]))); return

        if base == 'cls' and not GPRT.match(ops[0].strip()):
            #  COUNT LEADING SIGN BITS = CLZ(x ^ (x >>a 1)) - 1. Verified by hand on the
            #    four inputs that matter: 0 -> 31, -1 -> 31, 0x40000000 -> 0, 0x80000000 -> 0.
            x = iv(ops[1])
            one = self._splat(el, n, 1)
            sh = self.t(); self.e(f'{sh} = ashr {ty} {x}, {one}')
            xr = bin_('xor', x, sh)
            cz = self.t()
            self.e(f'{cz} = call {ty} @llvm.ctlz.{self._sfx(n, el)}({ty} {xr}, i1 false)')
            put(bin_('sub', cz, one)); return

        # ── moves and constants ───────────────────────────────────────────────
        if base == 'mov' and len(ops) == 2 and GPRT.match(ops[0].strip()):
            #  `mov.s w0, v5[0]` IS `umov`. Apple prints the alias; the same two tokens
            #    mean a vector move when the destination is a V register and a lane read
            #    when it is a W/X one. Dispatch on the OPERAND, never on the mnemonic.
            return self.neon('umov', arr, ops, a)
        if base in ('mov', 'ins') and '[' in ops[0]:
            #  INSERT INTO A LANE — THE OTHER LANES MUST SURVIVE. This is the one
            #    vector write that zeroes nothing, so it cannot go through vwr()'s
            #    arrangement rule; it is a read-modify-write of the whole register.
            lanes = {8: 16, 16: 8, 32: 4, 64: 2}[eb]
            fa = {16: '16b', 8: '8h', 4: '4s', 2: '2d'}[lanes]
            vt = f'<{lanes} x {el}>'
            dreg, dlane = ops[0].split('[')
            cur = self.vrd(dreg.strip(), fa, FP)
            src_ = ops[1].strip()
            if '[' in src_:
                sreg, slane = src_.split('[')
                sv = self.vrd(sreg.strip(), fa, FP)
                x = self.t()
                self.e(f'{x} = extractelement {vt} {sv}, '
                       f'i64 {int(slane.rstrip("]"), 0)}')
            else:
                g = self.rd(src_)
                if eb == 64:
                    x = g
                else:
                    x = self.t(); self.e(f'{x} = trunc i64 {g} to {el}')
            o = self.t()
            self.e(f'{o} = insertelement {vt} {cur}, {el} {x}, '
                   f'i64 {int(dlane.rstrip("]"), 0)}')
            self.vwr(dreg.strip(), fa, o, FP); return
        #  `orr.4s v0, #0x7d` IS NOT A MOVE. This arm exists for the `orr vD, vN` alias
        #    of mov, and a two-operand orr with an IMMEDIATE has the same shape — it was
        #    swallowing the immediate form and handing '#0x7d' to vslot. That is the same
        #    routing-not-semantics bug the sweep reported as `vslot: '#0x3f'`, and it was
        #    hiding one layer further up than the first fix reached.
        if base in ('mov', 'orr') and len(ops) == 2 \
                and not ops[1].strip().startswith('#'):
            put(iv(ops[1])); return
        if base in ('movi', 'mvni'):
            #  THE SHIFTED IMMEDIATE: `movi.4s v0, #0x1, lsl #8` splats 0x100, not 0x1.
            #  WAS A HARD ABORT, and it is the largest single vector blocker in the
            #    cache sweep — 61 of 801 failing functions on 2026-09-22 counting
            #    movi.2s + movi.4s + mvni.4s together.
            #  THE SHIFT IS APPLIED BEFORE THE mvni COMPLEMENT. Complementing first
            #    gives ~0x1 << 8 = 0xFFFFFE00 where ARM produces ~0x100 = 0xFFFFFEFF.
            v = imm(ops[1]) if ops[1].strip().startswith('#') else int(ops[1], 0)
            if len(ops) > 2:
                sh = ops[2].strip()
                m_ = re.match(r'^(lsl|msl)\s*#?(\d+)$', sh, re.I)
                if not m_:
                    raise NotImplementedError(f'{base}.{arr} shift {sh!r} at {a:x}')
                k = int(m_.group(2))
                v <<= k
                #  MSL SHIFTS IN ONES, not zeros — `movi.4s v0, #0x2, msl #8` is 0x2FF.
                if m_.group(1).lower() == 'msl':
                    v |= (1 << k) - 1
            if base == 'mvni': v = ~v
            put(self._splat(el, n, v)); return
        if base == 'fmov' and len(ops) == 2 and ops[1].strip().startswith('#'):
            #  THE FP VECTOR IMMEDIATE: `fmov.2d v0, #1.0` splats a float VALUE.
            #  `FP` is deliberately False for fmov in the preamble (fmov also moves raw
            #    bit patterns between the files), so `ty`/`el` here are the INTEGER view
            #    of the register. Spell the fp type out rather than reusing them, or the
            #    constant is emitted as an integer and 1.0 becomes 1.
            fel = {16: 'half', 32: 'float', 64: 'double'}[eb]
            c = float(ops[1].strip()[1:])
            lit = ', '.join([f'{fel} {c:.8e}'] * n)
            self.vwr(ops[0], arr, f'<{lit}>', True); return
        if base == 'dup':
            src = ops[1]
            if '[' in src:                                  # dup.4s v0, v1[2] — lane splat
                reg, lane = src.split('[')
                idx = ', '.join([f'i32 {int(lane.rstrip("]"), 0)}'] * n)
                #  10-03 (certifier vs M4): the lane index counts the FULL 128-bit register. `dup.2s v3, v1[2]` read v1
                #    as 2 lanes and asked for lane 2 — poison, zeros on x86. Read the full register, then splat.
                fl = 128 // eb; fty = f'<{fl} x {el}>'
                full = self.vrd(reg, {8: '16b', 16: '8h', 32: '4s', 64: '2d'}[eb], FP)
                r = self.t()
                self.e(f'{r} = shufflevector {fty} {full}, {fty} poison, <{n} x i32> <{idx}>')
                put(r); return
            if FP: raise NotImplementedError(f'dup.{arr} fp from GPR at {a:x}')
            g = self.rd(src)                                # dup.4s v0, w8 — from a GPR
            if eb < 64:
                tr = self.t(); self.e(f'{tr} = trunc i64 {g} to {el}'); g = tr
            ins = self.t(); self.e(f'{ins} = insertelement {ty} poison, {el} {g}, i64 0')
            idx = ', '.join(['i32 0'] * n)
            r = self.t()
            self.e(f'{r} = shufflevector {ty} {ins}, {ty} poison, <{n} x i32> <{idx}>')
            put(r); return

        # ── floating point ────────────────────────────────────────────────────
        FBIN = {'fadd': 'fadd', 'fsub': 'fsub', 'fmul': 'fmul', 'fdiv': 'fdiv'}
        if base in FBIN:
            put(bin_(FBIN[base], iv(ops[1]), iv(ops[2]))); return
        if base == 'fneg':
            r = self.t(); self.e(f'{r} = fneg {ty} {iv(ops[1])}'); put(r); return
        if base in ('fabs', 'fsqrt'):
            put(call_({'fabs': 'fabs', 'fsqrt': 'sqrt'}[base], iv(ops[1]))); return
        if base in ('fmla', 'fmls'):
            #  fmla IS FUSED — ONE rounding. Emitting fmul+fadd is TWO roundings and
            #    differs in the last ulp; libsystem_m is precisely where that shows up.
            #    llvm.fma uses the FMA instruction where the CPU has it and a correctly
            #    ROUNDED libcall where it does not. Measured 2026-09-22: the Mac Pro's
            #    Xeon E5-2697 v2 has AVX1.0 and NO FMA, so it takes the libcall — slower,
            #    still correct, and still correct when it later runs on FMA hardware.
            acc, x, y = iv(ops[0]), iv(ops[1]), iv(ops[2])
            if base == 'fmls':
                nx = self.t(); self.e(f'{nx} = fneg {ty} {x}'); x = nx
            put(call_('fma', x, y, acc)); return
        #  THE LOCAL FRINT TABLE HAD frintn->nearbyint AND frinti->rint. Both are
        #    correct-looking and both are wrong; see FRINTS at module scope for the
        #    measurement. The table now lives in ONE place so the scalar and vector
        #    paths cannot drift apart.
        if base in FRINTS:
            put(call_(FRINTS[base], iv(ops[1]))); return
        if base in FMINMAX:
            #  WAS `maxnum` FOR PLAIN fmax. llvm.maxnum is IEEE maxNum, which RETURNS
            #    THE NUMBER when one operand is NaN; ARM's plain FMAX PROPAGATES it.
            #    Every comparison on non-NaN data agrees, which is why it survived.
            put(call_(FMINMAX[base], iv(ops[1]), iv(ops[2]))); return

        # ── integer ───────────────────────────────────────────────────────────
        if base in ('orr', 'bic') and len(ops) >= 2 and ops[1].strip().startswith('#'):
            #  THE IMMEDIATE FORM IS DESTRUCTIVE AND TWO-OPERAND: `orr.4s v0, #0x3f, lsl
            #    #24` reads v0, ORs a splat, writes v0. The register form is three operands.
            #  THIS IS WHY `vslot: '#0x3f'` AND `vslot: 'lsl #8'` APPEARED IN THE SWEEP:
            #    the three-operand arm read the immediate and the shift as REGISTERS. The
            #    error named vslot, but the bug was the routing above it.
            v = imm(ops[1])
            if len(ops) > 2:
                sp = ops[2].strip().split()
                if len(sp) != 2 or sp[0].lower() not in ('lsl', 'msl'):
                    raise NotImplementedError(f'{base}.{arr} shift {ops[2]!r} at {a:x}')
                k = imm(sp[1])
                v = (v << k) | ((1 << k) - 1) if sp[0].lower() == 'msl' else v << k
            sp_ = self._splat(el, n, v if base == 'orr' else ~v)
            put(bin_('or' if base == 'orr' else 'and', iv(ops[0]), sp_)); return
        IBIN = {'add': 'add', 'sub': 'sub', 'mul': 'mul',
                'and': 'and', 'orr': 'or', 'eor': 'xor'}
        if base in IBIN and len(ops) == 3:
            put(bin_(IBIN[base], iv(ops[1]), iv(ops[2]))); return
        if base == 'neg':
            r = self.t(); self.e(f'{r} = sub {ty} zeroinitializer, {iv(ops[1])}')
            put(r); return
        if base in ('not', 'mvn'):
            put(bin_('xor', iv(ops[1]), ones)); return
        if base in ('bic', 'orn'):
            ny = bin_('xor', iv(ops[2]), ones)
            put(bin_('and' if base == 'bic' else 'or', iv(ops[1]), ny)); return
        if base == 'abs':
            r = self.t()
            self.e(f'{r} = call {ty} @llvm.abs.{self._sfx(n, el)}({ty} {iv(ops[1])}, i1 false)')
            put(r); return
        if base in ('umin', 'umax', 'smin', 'smax'):
            put(call_(base, iv(ops[1]), iv(ops[2]))); return
        SAT = {'sqadd': 'sadd.sat', 'uqadd': 'uadd.sat',
               'sqsub': 'ssub.sat', 'uqsub': 'usub.sat'}
        if base in SAT:
            put(call_(SAT[base], iv(ops[1]), iv(ops[2]))); return
        if base in ('shl', 'ushr', 'sshr'):
            #  IMMEDIATE ONLY. sshl/ushl take a SIGNED register amount where a negative
            #    value shifts the other way; mapping those to `shl` would be quietly wrong,
            #    so they fall through and fail loudly instead.
            if not ops[2].startswith('#'):
                raise NotImplementedError(f'{base}.{arr} variable shift at {a:x}')
            k = self._splat(el, n, imm(ops[2]))
            put(bin_({'shl': 'shl', 'ushr': 'lshr', 'sshr': 'ashr'}[base],
                     iv(ops[1]), k)); return
        #  cmlt/cmle EXIST ONLY AGAINST ZERO on ARM — a register form is written the
        #    other way round as cmgt/cmge with the operands swapped. So these two reach
        #    the `#0` branch below by construction, and 6 of the 170 died for want of
        #    two dictionary entries.
        CMP = {'cmeq': 'eq', 'cmgt': 'sgt', 'cmge': 'sge',
               'cmhi': 'ugt', 'cmhs': 'uge', 'cmlt': 'slt', 'cmle': 'sle'}
        if base in CMP:
            x = iv(ops[1])
            y = (self._splat(el, n, 0) if (len(ops) > 2 and ops[2].startswith('#'))
                 else iv(ops[2]))
            c = self.t(); self.e(f'{c} = icmp {CMP[base]} {ty} {x}, {y}')
            #  ARM writes ALL-ONES / ALL-ZEROS per lane, not 0/1. sext does exactly that;
            #    zext would make every later AND with the mask read 1 instead of ~0.
            r = self.t(); self.e(f'{r} = sext <{n} x i1> {c} to {ty}')
            put(r); return
        FCMP = {'fcmeq': 'oeq', 'fcmgt': 'ogt', 'fcmge': 'oge',
                'fcmle': 'ole', 'fcmlt': 'olt'}
        if base in FCMP:
            fty, _, fel, _ = self.vty(arr, True)
            x = self.vrd(ops[1], arr, True)
            y = ('zeroinitializer' if (len(ops) > 2 and ops[2].startswith('#'))
                 else self.vrd(ops[2], arr, True))
            c = self.t(); self.e(f'{c} = fcmp {FCMP[base]} {fty} {x}, {y}')
            ity = f'<{n} x i{eb}>'
            r = self.t(); self.e(f'{r} = sext <{n} x i1> {c} to {ity}')
            self.vwr(ops[0], arr, r, False); return
        if base in ('bsl', 'bit', 'bif'):
            #  bitwise select. bsl's MASK is the destination register; bit/bif use the
            #    third operand and differ only in which way the test runs.
            d, x, y = iv(ops[0]), iv(ops[1]), iv(ops[2])
            m, t_, f_ = {'bsl': (d, x, y), 'bit': (y, x, d), 'bif': (y, d, x)}[base]
            nm = bin_('xor', m, ones)
            put(bin_('or', bin_('and', t_, m), bin_('and', f_, nm))); return

        # ── permutes: all pure shufflevector, all become one x86 shuffle ──────
        if base == 'ext':
            k = imm(ops[3]) if len(ops) > 3 else 0
            idx = ', '.join(f'i32 {k // (eb // 8) + i}' for i in range(n))
            r = self.t()
            self.e(f'{r} = shufflevector {ty} {iv(ops[1])}, {ty} {iv(ops[2])}, '
                   f'<{n} x i32> <{idx}>')
            put(r); return
        if re.match(r'^rev\d+$', base):
            g = int(base[3:]) // eb
            if g < 2: raise NotImplementedError(f'{base}.{arr} at {a:x}')
            order = [i for st in range(0, n, g) for i in range(st + g - 1, st - 1, -1)]
            idx = ', '.join(f'i32 {i}' for i in order)
            r = self.t()
            self.e(f'{r} = shufflevector {ty} {iv(ops[1])}, {ty} poison, '
                   f'<{n} x i32> <{idx}>')
            put(r); return
        if base in ('zip1', 'zip2', 'uzp1', 'uzp2', 'trn1', 'trn2'):
            h = n // 2
            order = {
                'zip1': [j for i in range(h) for j in (i, n + i)],
                'zip2': [j for i in range(h) for j in (h + i, n + h + i)],
                'uzp1': [2 * i for i in range(h)] + [n + 2 * i for i in range(h)],
                'uzp2': [2 * i + 1 for i in range(h)] + [n + 2 * i + 1 for i in range(h)],
                'trn1': [j for i in range(h) for j in (2 * i, n + 2 * i)],
                'trn2': [j for i in range(h) for j in (2 * i + 1, n + 2 * i + 1)],
            }[base]
            idx = ', '.join(f'i32 {i}' for i in order)
            r = self.t()
            self.e(f'{r} = shufflevector {ty} {iv(ops[1])}, {ty} {iv(ops[2])}, '
                   f'<{n} x i32> <{idx}>')
            put(r); return
        if base in ('addp', 'faddp') and len(ops) == 2:
            #  R9 THE SCALAR-DESTINATION FORM — `addp.2d d0, v0` folds ONE register's
            #    lanes into a scalar. It arrived with 2 operands and the vector arm below
            #    indexed ops[2]: an IndexError, which is a parser crash, not a gap.
            x = self.vrd(ops[1], arr, FP)
            acc = None
            for i in range(n):
                lane = self.t(); self.e(f'{lane} = extractelement {ty} {x}, i64 {i}')
                if acc is None:
                    acc = lane
                else:
                    nx = self.t()
                    self.e(f'{nx} = {"fadd" if FP else "add"} {el} {acc}, {lane}')
                    acc = nx
            one = self.t()
            self.e(f'{one} = insertelement <1 x {el}> poison, {el} {acc}, i64 0')
            #  the destination is a d/s register, so it must go through the 64-or-narrower
            #    arrangement whose vwr() zeroes the rest of the 128-bit register.
            self.vwr(ops[0], ops[0].strip()[0], one, FP); return
        if base == 'addp':
            x, y = iv(ops[1]), iv(ops[2])
            ev = ', '.join(f'i32 {2 * i}' for i in range(n))
            od = ', '.join(f'i32 {2 * i + 1}' for i in range(n))
            e1 = self.t(); self.e(f'{e1} = shufflevector {ty} {x}, {ty} {y}, <{n} x i32> <{ev}>')
            o1 = self.t(); self.e(f'{o1} = shufflevector {ty} {x}, {ty} {y}, <{n} x i32> <{od}>')
            put(bin_('fadd' if FP else 'add', e1, o1)); return
        if base in ('addv', 'uaddlv', 'saddlv'):
            #  a horizontal reduction, written as extract+add so it needs no declare.
            #    LLVM folds it into the right SSE sequence on its own.
            #  uaddlv/saddlv WIDEN AS THEY REDUCE. Summing sixteen bytes into a byte
            #    wraps at 255; libz's adler32 tail sums 16 data bytes into an `h`, so the
            #    wrap would be a wrong checksum with no crash and no warning. The
            #    accumulator is DOUBLE the source element width and the destination
            #    register letter follows it (.16b -> h, .8h -> s, .4s -> d).
            wide = base != 'addv'
            ab = eb * 2 if wide else eb
            ael = f'i{ab}'
            x = iv(ops[1]); acc = None
            for i in range(n):
                lane = self.t(); self.e(f'{lane} = extractelement {ty} {x}, i64 {i}')
                if wide:
                    w = self.t()
                    self.e(f'{w} = {"zext" if base[0] == "u" else "sext"} '
                           f'{el} {lane} to {ael}')
                    lane = w
                if acc is None: acc = lane
                else:
                    s = self.t(); self.e(f'{s} = add {ael} {acc}, {lane}'); acc = s
            vv = self.t()
            self.e(f'{vv} = insertelement <1 x {ael}> poison, {ael} {acc}, i64 0')
            self.vwr(ops[0], {8: 'b', 16: 'h', 32: 's', 64: 'd'}[ab], vv, FP); return
        if base in ('umull', 'smull', 'umull2', 'smull2',
                    'umlal', 'smlal', 'umlal2', 'smlal2',
                    'umlsl', 'smlsl', 'umlsl2', 'smlsl2'):
            #  WIDENING: the OPERANDS are half the destination element width.
            #    `umull.8h v0, v1, v2` reads .8b operands and writes .8h.
            #  THE `2` SUFFIX IS NOT A VERSION NUMBER — it reads the HIGH half of the
            #    128-bit source register instead of the low half. Measured 2026-09-22:
            #    libz's adler32 NEON tail alternates umlal/umlal2 over ONE 16-byte load,
            #    so reading the low lanes for a `2` form would silently checksum the same
            #    8 bytes twice and never touch the other 8.
            #  THE `l`+`a`/`s` FORMS ACCUMULATE — Vd is a SOURCE as well as the
            #    destination. Treating umlal as umull drops every prior term and the
            #    result still looks like a plausible checksum.
            hi = base.endswith('2')
            b_ = base[:-1] if hi else base
            src = {'8h': '8b', '4s': '4h', '2d': '2s'}.get(arr)
            if not src: raise NotImplementedError(f'{base}.{arr} at {a:x}')
            wide = {'8b': '16b', '4h': '8h', '2s': '4s'}[src]
            sty, _, _, _ = self.vty(src, False)
            wty, wn, _, _ = self.vty(wide, False)
            ext = 'zext' if b_[0] == 'u' else 'sext'
            def narrow(r):
                #  THE BY-LANE WIDENING FORM REACHES HERE TOO: `umull.2d v0, v1, v7[1]`.
                #    iv() cannot serve it, because iv() indexes in the DESTINATION element
                #    width and this operand is indexed in the SOURCE width. Sending the raw
                #    token 'v7[1]' to vrd() is what produced the slot name '%vv7[1]'.
                r = r.strip()
                if '[' in r:
                    reg, lane = r.split('[')
                    f2 = self.vrd(reg.strip(), wide)
                    m2 = ', '.join([f'i32 {int(lane.rstrip("]"), 0)}'] * n)
                    q = self.t()
                    self.e(f'{q} = shufflevector {wty} {f2}, {wty} poison, '
                           f'<{n} x i32> <{m2}>')
                    return q
                if hi:
                    f_ = self.vrd(r, wide)
                    mask = ', '.join(f'i32 {i}' for i in range(n, wn))
                    h = self.t()
                    self.e(f'{h} = shufflevector {wty} {f_}, {wty} poison, '
                           f'<{n} x i32> <{mask}>')
                    return h
                return self.vrd(r, src)

            half = []
            for r in (ops[1], ops[2]):
                ex_ = self.t()
                self.e(f'{ex_} = {ext} {sty} {narrow(r)} to {ty}'); half.append(ex_)
            pr = bin_('mul', half[0], half[1])
            if b_ in ('umlal', 'smlal'):
                pr = bin_('add', iv(ops[0]), pr)
            elif b_ in ('umlsl', 'smlsl'):
                pr = bin_('sub', iv(ops[0]), pr)
            put(pr); return
        if base in ('uaddl', 'saddl', 'uaddl2', 'saddl2',
                    'usubl', 'ssubl', 'usubl2', 'ssubl2'):
            #  WIDENING ADD/SUB — the same shape as the widening multiply: both
            #    operands are half the destination element width and `2` reads the HIGH
            #    half of the 128-bit source.
            hi = base.endswith('2')
            b_ = base[:-1] if hi else base
            src = {'8h': '8b', '4s': '4h', '2d': '2s'}.get(arr)
            if not src: raise NotImplementedError(f'{base}.{arr} at {a:x}')
            wide = {'8b': '16b', '4h': '8h', '2s': '4s'}[src]
            sty, _, _, _ = self.vty(src, False)
            wty, wn, _, _ = self.vty(wide, False)
            ext = 'zext' if b_[0] == 'u' else 'sext'
            half = []
            for r in (ops[1], ops[2]):
                if hi:
                    f_ = self.vrd(r, wide)
                    mask = ', '.join(f'i32 {i}' for i in range(n, wn))
                    h = self.t()
                    self.e(f'{h} = shufflevector {wty} {f_}, {wty} poison, '
                           f'<{n} x i32> <{mask}>')
                else:
                    h = self.vrd(r, src)
                ex_ = self.t(); self.e(f'{ex_} = {ext} {sty} {h} to {ty}'); half.append(ex_)
            put(bin_('add' if 'add' in b_ else 'sub', half[0], half[1])); return
        if base in ('mla', 'mls'):
            #  Vd IS A SOURCE. iv() handles the by-lane third operand, so the plain and
            #    indexed forms land here together.
            pr = bin_('mul', iv(ops[1]), iv(ops[2]))
            put(bin_('add' if base == 'mla' else 'sub', iv(ops[0]), pr)); return
        if base in ('pmull', 'pmull2'):
            #  THE FIRST AND ONLY TARGET-SPECIFIC EMISSION IN THIS FILE, AND IT IS SAID
            #    OUT LOUD. Carry-less (polynomial) multiply has NO generic LLVM operation:
            #    ARM calls it pmull, x86 calls it pclmulqdq, and they are the same thing, so
            #    this is a 1:1 NAME translation and not a semantics implementation. There is
            #    no portable fallback — emulating GF(2) multiply in generic IR would be
            #    ~64 shifts and xors per call, in libz's CRC32 inner loop.
            #  IT NEEDS THE PCLMUL CPU FEATURE. Present on the Mac Pro's Xeon E5-2697 v2
            #    (Ivy Bridge, verified 2026-09-22) and on everything newer. A pre-Westmere
            #    x86 target must take the scalar CRC path instead, not this.
            #  imm8 picks which 64-bit half of each source: bit0 = src1, bit4 = src2.
            #    pmull reads the low halves (0x00), pmull2 the high ones (0x11).
            x = self.vrd(ops[1], '2d'); y = self.vrd(ops[2], '2d')
            r = self.t()
            self.e(f'{r} = call <2 x i64> @llvm.x86.pclmulqdq(<2 x i64> {x}, '
                   f'<2 x i64> {y}, i8 {17 if base.endswith("2") else 0})')
            self.vwr(ops[0], '2d', r, False); return
        if base in ('umov', 'smov'):
            #  VECTOR LANE -> GPR. Here the suffix is the ELEMENT SIZE, not a shape:
            #    `umov.b w9, v1[0]` reads ONE byte out of a full 128-bit register. So the
            #    lane count is the one that fills 128 bits at that width, NOT what vty()
            #    returns for a bare 'b' (which is the one-lane scalar form, n=1).
            #  umov ZERO-extends, smov SIGN-extends. libz reads a data byte here —
            #    a sext would turn 0x80 into a 64-bit negative and poison the sum with no
            #    crash and no warning.
            lanes = {8: 16, 16: 8, 32: 4, 64: 2}[eb]
            vt = f'<{lanes} x {el}>'
            reg, lane = ops[1].split('[')
            full = self.vrd(reg.strip(), {16: '16b', 8: '8h', 4: '4s', 2: '2d'}[lanes])
            x = self.t()
            self.e(f'{x} = extractelement {vt} {full}, i64 {int(lane.rstrip("]"), 0)}')
            if eb == 64:
                o = x           #  already i64 — an extend to its own type is invalid IR
            else:
                o = self.t()
                self.e(f'{o} = {"zext" if base == "umov" else "sext"} {el} {x} to i64')
            self.wr(ops[0], o); return

        # ── vector memory ─────────────────────────────────────────────────────
        if base in ('ld1', 'st1', 'ld1r',
                    'ld2', 'st2', 'ld3', 'st3', 'ld4', 'st4',
                    'ld2r', 'ld3r', 'ld4r'):
            buf = list(ops)
            lane = None
            if buf and buf[0].lstrip().startswith('{'):
                acc = []
                while buf:
                    tk = buf.pop(0); acc.append(tk)
                    if '}' in tk: break
                #  THIS REJOIN WAS ' '.join(acc) AND IT HID A WHOLE FEATURE. parse()
                #    has already split on commas, so `{ v0, v1 }` came back as the single
                #    token 'v0 v1' and walked straight through the one-register guard that
                #    used to sit here — a guard measured in only one direction. It reached
                #    vslot(), which happily produced the slot name '%vv0 v1', referencing
                #    an alloca that does not exist. NOTHING RAISED; only vslot's type check
                #    caught it. Measured 2026-09-22: libz has 2-, 3- and 4-register lists.
                #  AND THE OTHER HALF, rstrip('}'), IS A NO-OP ON THE LANE FORM:
                #    `{ v1 }[1]` ends in ']', so the token 'v1 }[1]' reached vslot() as a
                #    register name and raised. Measured 2026-09-22 across the 14 failing
                #    images: 177 ld1 + 9 st1 lane instances, the largest single blocker
                #    left in the decoder. Partition on the brace — by construction the
                #    closer is in this text, so the split point is never a guess.
                joined = ', '.join(acc).strip().lstrip('{')
                head, _, tail = joined.partition('}')
                tail = tail.strip()
                if tail.startswith('['):
                    lane = int(tail[1:tail.index(']')], 0)
                elif tail:
                    raise NotImplementedError(f'{base} list tail {tail!r} at {a:x}')
                regs_ = [r.strip() for r in head.split(',') if r.strip()]
            else:
                regs_, buf = [buf[0]], buf[1:]
            #  PRE-INDEX `!` ON A LIST LOAD WOULD HAVE BEEN DROPPED SILENTLY: parts is
            #    built from buf[0].rstrip('!'), so the bang was eaten and no writeback was
            #    ever emitted. Zero instances measured in the cache, so blocking costs
            #    nothing — and an unmodelled address update must never look like success.
            if buf[0].rstrip().endswith('!'):
                raise NotImplementedError(f'{base} pre-index writeback at {a:x}')
            parts = split_ops(buf[0].rstrip('!').strip('[]'))
            base0 = self.rd(parts[0])
            ea = base0
            if len(parts) > 1:
                off = self.opnd(parts[1], parts[2] if len(parts) > 2 else None)
                p = self.t(); self.e(f'{p} = add i64 {ea}, {off}'); ea = p
            ebytes = n * eb // 8
            k = len(regs_)
            nel = int(base[2]) if base[2:3].isdigit() and base != 'ld1r' else 1
            if nel > 1 and k != nel:
                raise NotImplementedError(f'{base} with {k} registers at {a:x}')

            if lane is not None:
                #  THE SINGLE-LANE FORM MOVES ONE ELEMENT AND PRESERVES THE REST of the
                #    destination register — the only vector load here that is not a whole
                #    register write.  AND THE SUFFIX NAMES THE ELEMENT, NOT THE SHAPE:
                #    in `ld1.d { v1 }[1]` the `.d` says 64-bit element and `[1]` indexes
                #    the register's FULL 2-lane view. Reading it in `arr` (VARR['d'] is
                #    (1, 64)) would make lane 1 out of range and, worse, vwr() would zero
                #    the top half — destroying the very lane the instruction preserves.
                farr = {8: '16b', 16: '8h', 32: '4s', 64: '2d'}[eb]
                fty, fn, fel, _fb = self.vty(farr, FP)
                if lane >= fn:
                    raise NotImplementedError(f'{base}.{arr} lane {lane} at {a:x}')
                for i_, rg in enumerate(regs_):
                    #  st3/st4's lane form writes ONE element per register, consecutive
                    #    in memory — the stride is the element, not the register.
                    addr = ea
                    if i_:
                        q = self.t()
                        self.e(f'{q} = add i64 {ea}, {i_ * (eb // 8)}'); addr = q
                    pt = self.t(); self.e(f'{pt} = inttoptr i64 {addr} to ptr')
                    cur = self.vrd(rg, farr, FP)
                    if base[0] == 'l':
                        x = self.t(); self.e(f'{x} = load {fel}, ptr {pt}, align 1')
                        r = self.t()
                        self.e(f'{r} = insertelement {fty} {cur}, {fel} {x}, i32 {lane}')
                        self.vwr(rg, farr, r, FP)
                    else:
                        x = self.t()
                        self.e(f'{x} = extractelement {fty} {cur}, i32 {lane}')
                        self.e(f'store {fel} {x}, ptr {pt}, align 1')
            elif base in ('ld1r', 'ld2r', 'ld3r', 'ld4r'):
                #  ONE ELEMENT PER REGISTER, REPLICATED TO EVERY LANE. Here the
                #    arrangement IS the shape — `ld1r.2d` loads 8 bytes and fills both
                #    lanes with them; `ld4r.2d` loads FOUR consecutive doublewords and
                #    fills v24..v27, one splat each.
                #  R17-b ldNr FOR N>1 WOULD HAVE REACHED THE DE-INTERLEAVE ARM BELOW,
                #    because `nel` is parsed from base[2] and reads 4 for `ld4r` exactly as
                #    it does for `ld4`. Those are different instructions: ld4 scatters
                #    16 elements across 4 registers, ld4r broadcasts 4. It aborted only by
                #    the accident of `ld4r` not being in the base list above — and adding
                #    it there without this branch would have converted a gap into a silent
                #    wrong answer. Checked both ways before the name was added.
                if k != int(base[2]):
                    raise NotImplementedError(f'{base} with {k} registers at {a:x}')
                for j, rg in enumerate(regs_):
                    addr = ea
                    if j:
                        q = self.t()
                        self.e(f'{q} = add i64 {ea}, {j * eb // 8}')
                        addr = q
                    pt = self.t(); self.e(f'{pt} = inttoptr i64 {addr} to ptr')
                    x = self.t(); self.e(f'{x} = load {el}, ptr {pt}, align 1')
                    one = self.t()
                    self.e(f'{one} = insertelement {ty} poison, {el} {x}, i32 0')
                    sp = self.t()
                    self.e(f'{sp} = shufflevector {ty} {one}, {ty} poison, '
                           f'<{n} x i32> zeroinitializer')
                    self.vwr(rg, arr, sp, FP)
            elif nel > 1:
                #  ldN/stN DE-INTERLEAVE. Element t of register j lives at memory slot
                #    t*N + j — NOT one whole register after another. ld1 with a 4-register
                #    list looks identical in the text and is a completely different
                #    instruction; folding the two together would have produced plausible,
                #    silently-wrong addresses.
                big = f'<{k * n} x {el}>'
                pt = self.t(); self.e(f'{pt} = inttoptr i64 {ea} to ptr')
                if base[0] == 'l':
                    m_ = self.t(); self.e(f'{m_} = load {big}, ptr {pt}, align 1')
                    for j, rg in enumerate(regs_):
                        idx = ', '.join(f'i32 {j + t * k}' for t in range(n))
                        s = self.t()
                        self.e(f'{s} = shufflevector {big} {m_}, {big} poison, '
                               f'<{n} x i32> <{idx}>')
                        self.vwr(rg, arr, s, FP)
                else:
                    #  A shufflevector TAKES EXACTLY TWO SOURCES, so no constant-mask
                    #    shuffle can interleave 3 or 4 registers. Lane-by-lane insert is
                    #    exact and target-neutral; LLVM's combiner folds it back into the
                    #    punpck/unpck pattern x86 wants. Correctness first, shape second.
                    cur = 'poison'
                    for j, rg in enumerate(regs_):
                        src_ = self.vrd(rg, arr, FP)
                        for t in range(n):
                            x = self.t()
                            self.e(f'{x} = extractelement {ty} {src_}, i32 {t}')
                            nx = self.t()
                            self.e(f'{nx} = insertelement {big} {cur}, {el} {x}, '
                                   f'i32 {t * k + j}')
                            cur = nx
                    self.e(f'store {big} {cur}, ptr {pt}, align 1')
            else:
                for i_, rg in enumerate(regs_):
                    #  ld1/st1 are CONSECUTIVE — one whole register after another.
                    addr = ea
                    if i_:
                        q = self.t(); self.e(f'{q} = add i64 {ea}, {i_ * ebytes}')
                        addr = q
                    pt = self.t(); self.e(f'{pt} = inttoptr i64 {addr} to ptr')
                    if base == 'ld1':
                        v = self.t(); self.e(f'{v} = load {ty}, ptr {pt}, align 1')
                        self.vwr(rg, arr, v, FP)
                    else:
                        self.e(f'store {ty} {self.vrd(rg, arr, FP)}, ptr {pt}, align 1')

            if len(buf) > 1:
                #  THE REGISTER POST-INDEX WAS BEING DROPPED ON THE FLOOR. The old guard
                #    was `buf[1].startswith('#')`, so `st4.16b { ... }, [x8], x9` emitted
                #    the store and left x8 UNCHANGED — every later iteration of the loop
                #    it lives in writes the same 64 bytes, and NOTHING RAISES. 11 instances
                #    in the 14 failing images. Both forms are modelled now and anything
                #    else BLOCKS: an address update we cannot express is not a no-op.
                tk = buf[1]
                if tk.startswith('#'):
                    off2 = str(imm(tk))
                elif re.fullmatch(r'[wx]\d+|[wx]zr', tk):
                    off2 = self.rd(tk)
                else:
                    raise NotImplementedError(f'{base} writeback {tk!r} at {a:x}')
                o = self.t(); self.e(f'{o} = add i64 {base0}, {off2}')
                self.wr(parts[0], o)
            return

        if base in ('tbl', 'tbx'):
            #  shufflevector CANNOT express this — its mask must be a constant and tbl's
            #    indices are a runtime register. But a DYNAMIC extractelement is legal
            #    LLVM, so the lookup is expressible lane by lane with no target intrinsic,
            #    and x86 has pshufb for exactly this shape.
            #  ARM RETURNS ZERO FOR AN OUT-OF-RANGE INDEX. LLVM's extractelement with an
            #    out-of-range index is POISON — not zero, not wrapped. The mask makes the
            #    extract always in-bounds and the select supplies ARM's zero. Dropping
            #    either one turns a defined ARM result into undefined behaviour.
            #  R9 split_ops() DOES NOT PROTECT BRACES, so `tbl.16b v0, { v1, v2 }, v3`
            #    arrived as ['v0', '{ v1', 'v2 }', 'v3'] and the old code built a ONE-entry
            #    table out of v1, never consulted v2, and took the INDEX from 'v2 }' — the
            #    real index register in ops[3] was ignored entirely. It only raised at all
            #    because 'v2 }' reached vslot(). Multi-register tables are 13 of the 15 in
            #    the cache slice, so this was wrong far more often than it was right.
            #    The braces are re-joined here rather than in split_ops, which is shared.
            if arr not in ('8b', '16b'):
                raise NotImplementedError(f'{base}.{arr} (table lanes are bytes) at {a:x}')
            toks = [o.strip() for o in ops]
            try:
                st = next(i for i, o in enumerate(toks) if o.startswith('{'))
                en = next(i for i, o in enumerate(toks) if o.endswith('}'))
            except StopIteration:
                raise NotImplementedError(f'{base} table braces {ops} at {a:x}')
            tr = [t.lstrip('{').rstrip('}').strip() for t in toks[st:en + 1]]
            tr = [t for t in tr if t]
            if not 1 <= len(tr) <= 4 or en + 1 >= len(toks):
                raise NotImplementedError(f'{base} {len(tr)}-register table at {a:x}')
            #  THE TABLE IS ALWAYS READ AS FULL 128-BIT REGISTERS even when the
            #    destination is 8b — the arrangement names the DESTINATION only.
            fty, fn, _, _ = self.vty('16b', False)
            T = [self.vrd(t, '16b') for t in tr]
            tn = 16 * len(T)
            I = self.vrd(toks[en + 1], arr)
            #  ARM RETURNS ZERO FOR AN OUT-OF-RANGE INDEX (tbl) or LEAVES THE DESTINATION
            #    LANE UNCHANGED (tbx). LLVM's extractelement with an out-of-range index is
            #    POISON — not zero, not wrapped. The mask keeps the extract in bounds and
            #    the select supplies ARM's answer; dropping either is undefined behaviour.
            D = self.vrd(ops[0], arr) if base == 'tbx' else None
            res = 'zeroinitializer'
            for i in range(n):
                ix = self.t(); self.e(f'{ix} = extractelement {ty} {I}, i64 {i}')
                ok = self.t(); self.e(f'{ok} = icmp ult {el} {ix}, {tn}')
                sf = self.t(); self.e(f'{sf} = and {el} {ix}, {tn - 1}')
                ln = self.t(); self.e(f'{ln} = and {el} {sf}, 15')
                v = self.t(); self.e(f'{v} = extractelement {fty} {T[0]}, {el} {ln}')
                for k in range(1, len(T)):
                    vk = self.t()
                    self.e(f'{vk} = extractelement {fty} {T[k]}, {el} {ln}')
                    ge = self.t(); self.e(f'{ge} = icmp uge {el} {sf}, {16 * k}')
                    nv = self.t()
                    self.e(f'{nv} = select i1 {ge}, {el} {vk}, {el} {v}')
                    v = nv
                if D is None:
                    dflt = f'{el} 0'
                else:
                    dl = self.t(); self.e(f'{dl} = extractelement {ty} {D}, i64 {i}')
                    dflt = f'{el} {dl}'
                s = self.t(); self.e(f'{s} = select i1 {ok}, {el} {v}, {dflt}')
                nr = self.t()
                self.e(f'{nr} = insertelement {ty} {res}, {el} {s}, i64 {i}')
                res = nr
            put(res); return

        #  Everything else fails LOUDLY. A NEON op quietly skipped is a wrong answer that
        #    looks exactly like a right one — the single failure mode this whole project
        #    cannot afford.
        _fcv = FCVTR.match(base)
        if base in ('scvtf', 'ucvtf') or _fcv:
            #  VECTOR INT<->FP. The arrangement names the lane WIDTH, which is the same
            #    on both sides; only the element TYPE changes.
            #  `FP` in the preamble is computed from base[0] — 'f' for fcvtz*, 's'/'u'
            #    for *cvtf — so it describes the SOURCE and is wrong for the DESTINATION
            #    in both directions. Spell both types out here instead of reusing ty.
            fel = {16: 'half', 32: 'float', 64: 'double'}[eb]
            ity, fty = f'<{n} x i{eb}>', f'<{n} x {fel}>'
            if _fcv:
                #  R8: THE VECTOR SIDE HAD THE SAME TWO BUGS AS THE SCALAR SIDE.
                #    (a) only fcvtzs/fcvtzu existed, so fcvtns.2d/.4s — 7 of the 170 —
                #        fell through to the raise. The other six rounding modes are not
                #        exotic; libm reaches for them constantly.
                #    (b) plain fptosi/fptoui is POISON out of range, where ARM SATURATES.
                src = self.vrd(ops[1].strip(), arr, True)
                if _fcv.group(1) != 'z':
                    src = self.t_round(fty, self.vrd(ops[1].strip(), arr, True),
                                       FCVTRND[_fcv.group(1)], self._sfx(n, fel))
                r = self.satcvt(fty, ity, src, _fcv.group(2) == 's',
                                self._sfx(n, fel), self._sfx(n, f'i{eb}'))
                self.vwr(ops[0], arr, r, False)
            else:
                src = self.vrd(ops[1].strip(), arr, False)
                op_ = 'sitofp' if base == 'scvtf' else 'uitofp'
                r = self.t(); self.e(f'{r} = {op_} {ity} {src} to {fty}')
                self.vwr(ops[0], arr, r, True)
            return
        if base in ('xtn', 'fcvtn', 'fcvtl', 'xtn2', 'fcvtn2', 'fcvtl2'):
            #  NARROW AND WIDEN, and the ARRANGEMENT IS ALWAYS THE DESTINATION:
            #      xtn.4h   v0, v1   truncates .4s integers to .4h
            #      fcvtn.4h v0, v1   rounds .4s floats to .4h
            #      fcvtl.4s v0, v1   widens .4h floats to .4s
            #    so the SOURCE shape is derived from the destination, never assumed.
            #  R9 THE `2` FORMS, and the asymmetry is the whole trap:
            #      xtn2.4s / fcvtn2.4s   `arr` is the FULL destination; write HALF[arr]
            #                            into its HIGH lanes and PRESERVE the low ones.
            #      fcvtl2.2d             `arr` is the destination as usual; the SOURCE is
            #                            the high half of the narrow shape.
            #    Treating either as the low half checksums the same 8 bytes twice.
            hi2 = base.endswith('2')
            if hi2:
                base = base[:-1]
                if base in ('xtn', 'fcvtn'):
                    arr2 = HALF.get(arr)
                    if arr2 is None:
                        raise NotImplementedError(f'{base}2.{arr}: no half at {a:x}')
                    arr = arr2
                    ty, n, el, eb = self.vty(arr, FP)
            NARROW = {'8b': '8h', '4h': '4s', '2s': '2d'}
            WIDEN = {'8h': '8b', '4s': '4h', '2d': '2s'}
            if base == 'fcvtl':
                s_arr = WIDEN.get(arr)
                if not s_arr: raise NotImplementedError(f'{base}.{arr} at {a:x}')
                sty, _, _, _ = self.vty(s_arr, True)
                dty, _, _, _ = self.vty(arr, True)
                src = (self.vrd_hi(ops[1].strip(), s_arr, True) if hi2
                       else self.vrd(ops[1].strip(), s_arr, True))
                r = self.t(); self.e(f'{r} = fpext {sty} {src} to {dty}')
                self.vwr(ops[0], arr, r, True); return
            s_arr = NARROW.get(arr)
            if not s_arr: raise NotImplementedError(f'{base}.{arr} at {a:x}')
            isfp = base == 'fcvtn'
            sty, _, _, _ = self.vty(s_arr, isfp)
            dty, _, _, _ = self.vty(arr, isfp)
            src = self.vrd(ops[1].strip(), s_arr, isfp)
            r = self.t()
            self.e(f'{r} = {"fptrunc" if isfp else "trunc"} {sty} {src} to {dty}')
            if hi2:
                self.vwr_hi(ops[0], arr, r, isfp); return
            self.vwr(ops[0], arr, r, isfp); return
        if base in ('umaxv', 'uminv', 'smaxv', 'sminv',
                    'fmaxv', 'fminv', 'fmaxnmv', 'fminnmv'):
            #  ACROSS-VECTOR REDUCE, written as extract+fold exactly like addv above,
            #    so it needs no declare and LLVM picks the SSE sequence itself.
            #  UNLIKE uaddlv THESE DO NOT WIDEN — the max of bytes is a byte, and the
            #    destination register letter follows the SOURCE element width.
            x = iv(ops[1]); acc = None
            for i in range(n):
                lane = self.t(); self.e(f'{lane} = extractelement {ty} {x}, i64 {i}')
                if acc is None:
                    acc = lane; continue
                if FP:
                    fn_ = {'fmaxv': 'maximum', 'fminv': 'minimum',
                           'fmaxnmv': 'maxnum', 'fminnmv': 'minnum'}[base]
                    r = self.t()
                    self.e(f'{r} = call {el} @llvm.{fn_}.{SFX1[el]}'
                           f'({el} {acc}, {el} {lane})')
                else:
                    pr = {'umaxv': 'ugt', 'uminv': 'ult',
                          'smaxv': 'sgt', 'sminv': 'slt'}[base]
                    c = self.t(); self.e(f'{c} = icmp {pr} {el} {acc}, {lane}')
                    r = self.t()
                    self.e(f'{r} = select i1 {c}, {el} {acc}, {el} {lane}')
                acc = r
            vv = self.t()
            self.e(f'{vv} = insertelement <1 x {el}> poison, {el} {acc}, i64 0')
            self.vwr(ops[0], {8: 'b', 16: 'h', 32: 's', 64: 'd'}[eb], vv, FP); return
        if base == 'faddp':
            #  PAIRWISE ADD, the fp twin of addp above.
            #  THE TWO-OPERAND FORM IS A DIFFERENT SHAPE: `faddp.2d d0, v1` folds ONE
            #    register down to one lane. It is the common one in libm, and feeding it
            #    through the 3-operand path reads a second register that is not there.
            if len(ops) == 2:
                src = self.vrd(ops[1].strip(), arr, True)
                l0 = self.t(); self.e(f'{l0} = extractelement {ty} {src}, i64 0')
                l1 = self.t(); self.e(f'{l1} = extractelement {ty} {src}, i64 1')
                sm = self.t(); self.e(f'{sm} = fadd {el} {l0}, {l1}')
                vv = self.t()
                self.e(f'{vv} = insertelement <1 x {el}> poison, {el} {sm}, i64 0')
                self.vwr(ops[0], {16: 'h', 32: 's', 64: 'd'}[eb], vv, True); return
            x, y = iv(ops[1]), iv(ops[2])
            ev = ', '.join(f'i32 {2 * i}' for i in range(n))
            od = ', '.join(f'i32 {2 * i + 1}' for i in range(n))
            e1 = self.t()
            self.e(f'{e1} = shufflevector {ty} {x}, {ty} {y}, <{n} x i32> <{ev}>')
            o1 = self.t()
            self.e(f'{o1} = shufflevector {ty} {x}, {ty} {y}, <{n} x i32> <{od}>')
            put(bin_('fadd', e1, o1)); return
        if base == 'eor3':
            #  SHA3's three-way XOR, one extra xor. No intrinsic needed.
            put(bin_('xor', bin_('xor', iv(ops[1]), iv(ops[2])), iv(ops[3]))); return
        if base == 'cmtst':
            x = bin_('and', iv(ops[1]), iv(ops[2]))
            c = self.t(); self.e(f'{c} = icmp ne {ty} {x}, {self._splat(el, n, 0)}')
            r = self.t(); self.e(f'{r} = sext <{n} x i1> {c} to {ty}')
            put(r); return
        if base in ('facge', 'facgt'):
            #  ABSOLUTE compare — |a| vs |b|. fabs then an ordinary predicate.
            fty_, _, fel_, _ = self.vty(arr, True)
            xa = self.vrd(ops[1], arr, True); xb = self.vrd(ops[2], arr, True)
            sf = self._sfx(n, fel_)
            fa = self.t(); self.e(f'{fa} = call {fty_} @llvm.fabs.{sf}({fty_} {xa})')
            fbv = self.t(); self.e(f'{fbv} = call {fty_} @llvm.fabs.{sf}({fty_} {xb})')
            p = 'oge' if base == 'facge' else 'ogt'
            c = self.t(); self.e(f'{c} = fcmp {p} {fty_} {fa}, {fbv}')
            r = self.t(); self.e(f'{r} = sext <{n} x i1> {c} to <{n} x i{eb}>')
            self.vwr(ops[0], arr, r, False); return
        if base == 'fabd':
            d = bin_('fsub', iv(ops[1]), iv(ops[2]))
            put(call_('fabs', d)); return
        if base in ('ushll', 'sshll', 'ushll2', 'sshll2',
                    'sxtl', 'uxtl', 'sxtl2', 'uxtl2'):
            #  R9 SXTL/UXTL ARE THE SAME INSTRUCTION WITH SHIFT 0 — the disassembler
            #    prints the alias and drops the immediate, so they arrive with 2 operands.
            if base.rstrip('2').endswith('xtl'):
                base = ('sshll2' if base == 'sxtl2' else 'ushll2' if base == 'uxtl2'
                        else 'sshll' if base == 'sxtl' else 'ushll')
                ops = list(ops) + ['#0']
            #  WIDENING SHIFT LEFT: the arrangement names the WIDE destination and the
            #    source is the half-width shape beside it (2d<-2s, 4s<-4h, 8h<-8b).
            #  R9 THE `2` FORMS TAKE THE HIGH HALF of the source register. `arr` is
            #    already the 128-bit DESTINATION in both forms, so only the READ changes.
            hi2 = base.endswith('2')
            sarr = NARROW_SRC.get(arr)
            if sarr is None:
                raise NotImplementedError(f'{base}.{arr}: no narrow source shape at {a:x}')
            sty, sn, sel, _ = self.vty(sarr, False)
            s = (self.vrd_hi(ops[1].strip(), sarr, False) if hi2
                 else self.vrd(ops[1].strip(), sarr, False))
            w = self.t()
            self.e(f'{w} = {"zext" if base[0] == "u" else "sext"} {sty} {s} to {ty}')
            sh = imm(ops[2]) if len(ops) > 2 else 0
            put(bin_('shl', w, self._splat(el, n, sh)) if sh else w); return
        if base in ('ssra', 'usra'):
            #  SHIFT RIGHT AND ACCUMULATE — destructive: vD += vS >> n.
            #  READING ops[0] AS A SOURCE IS THE WHOLE INSTRUCTION. Dropping the
            #    accumulate turns it into a plain sshr and the result merely looks small.
            sh = imm(ops[2])
            r = bin_('ashr' if base[0] == 's' else 'lshr',
                     iv(ops[1]), self._splat(el, n, sh))
            put(bin_('add', iv(ops[0]), r)); return
        if base in ('ushl', 'sshl'):
            #  SHIFT BY A REGISTER, and the amount is a SIGNED per-lane byte: positive
            #    shifts left, negative shifts right.
            #  TWO WAYS TO GET POISON HERE, both silent: a shift >= the element width is
            #    UB in LLVM but DEFINED AS ZERO on ARM, and the negative case must shift
            #    by -amt. The masks keep every shift in range and the selects supply ARM's
            #    zero, exactly as the tbl arm does for out-of-range lane indices.
            x = iv(ops[1]); amt = iv(ops[2])
            bmask = self._splat(el, n, 0xFF)
            lowb = bin_('and', amt, bmask)
            sh = self.t()
            self.e(f'{sh} = shl {ty} {lowb}, {self._splat(el, n, eb - 8)}')
            sgn = self.t()
            self.e(f'{sgn} = ashr {ty} {sh}, {self._splat(el, n, eb - 8)}')
            neg = self.t()
            self.e(f'{neg} = sub {ty} {self._splat(el, n, 0)}, {sgn}')
            safe_l = bin_('and', sgn, self._splat(el, n, eb - 1))
            safe_r = bin_('and', neg, self._splat(el, n, eb - 1))
            lft = bin_('shl', x, safe_l)
            rgt = bin_('ashr' if base[0] == 's' else 'lshr', x, safe_r)
            isneg = self.t()
            self.e(f'{isneg} = icmp slt {ty} {sgn}, {self._splat(el, n, 0)}')
            okl = self.t()
            self.e(f'{okl} = icmp ult {ty} {sgn}, {self._splat(el, n, eb)}')
            okr = self.t()
            self.e(f'{okr} = icmp ult {ty} {neg}, {self._splat(el, n, eb)}')
            zero = self._splat(el, n, 0)
            if base[0] == 's':
                satr = self.t()
                self.e(f'{satr} = ashr {ty} {x}, {self._splat(el, n, eb - 1)}')
            else:
                satr = zero
            rr = self.t(); self.e(f'{rr} = select <{n} x i1> {okr}, {ty} {rgt}, {ty} {satr}')
            ll = self.t(); self.e(f'{ll} = select <{n} x i1> {okl}, {ty} {lft}, {ty} {zero}')
            out = self.t()
            self.e(f'{out} = select <{n} x i1> {isneg}, {ty} {rr}, {ty} {ll}')
            put(out); return
        PAIRW = {'umaxp': ('umax', None), 'uminp': ('umin', None),
                 'smaxp': ('smax', None), 'sminp': ('smin', None),
                 'fmaxp': ('maximum', None), 'fminp': ('minimum', None),
                 'fmaxnmp': ('maxnum', None), 'fminnmp': ('minnum', None)}
        if base in PAIRW:
            #  the pairwise twin of addp, same shuffle, different fold.
            x, y = iv(ops[1]), iv(ops[2] if len(ops) > 2 else ops[1])
            ev = ', '.join(f'i32 {2 * i}' for i in range(n))
            od = ', '.join(f'i32 {2 * i + 1}' for i in range(n))
            e1 = self.t()
            self.e(f'{e1} = shufflevector {ty} {x}, {ty} {y}, <{n} x i32> <{ev}>')
            o1 = self.t()
            self.e(f'{o1} = shufflevector {ty} {x}, {ty} {y}, <{n} x i32> <{od}>')
            put(call_(PAIRW[base][0], e1, o1)); return
        if base in ('clz', 'cls'):
            if base == 'cls':
                raise NotImplementedError(f'cls.{arr} at {a:x}')
            r = self.t()
            self.e(f'{r} = call {ty} @llvm.ctlz.{self._sfx(n, el)}({ty} {iv(ops[1])}, i1 false)')
            put(r); return
        if base in ('frecpe', 'frsqrte'):
            #  NOT 1/x AND NOT 1/sqrt(x). ARM defines both as exact 8-bit TABLE estimates.
            #    A true reciprocal is MORE accurate and still WRONG, and it would pass every
            #    eyeball check — the definition of a plausible lie.
            #  The tables and the special-case behaviour were READ OFF THIS MACHINE'S
            #    SILICON and the emitted IR was then diffed against the hardware instruction
            #    over 220,224 inputs with 0 mismatches (recip_model.py / recip_ir.py).
            #    The RSQRT pseudocode recalled from memory disagreed with hardware in
            #    130/256 entries, which is exactly why it was measured instead of written.
            fty_, _, fel_, _ = self.vty(arr, True)
            wn = {'half': 16, 'float': 32, 'double': 64}[fel_]
            s = self.vrd(ops[1].strip(), arr, True)
            res = 'poison'
            for i in range(n):
                lv = self.t()
                self.e(f'{lv} = extractelement {fty_} {s}, i64 {i}')
                cv = self.t()
                self.e(f'{cv} = call {fel_} @__arm2x86_{base}_f{wn}({fel_} {lv})')
                nr = self.t()
                self.e(f'{nr} = insertelement {fty_} {res}, {fel_} {cv}, i64 {i}')
                res = nr
            self.vwr(ops[0], arr, res, True); return
        raise NotImplementedError(f'{base}.{arr} at {a:x}  (ops={ops})')

    def module(self, nargs=4):
        #  A HELPER THAT IS NEVER EMITTED IS A LINK ERROR AT THE WORST MOMENT — the
        #    frecpe/frsqrte arms call these by name, so the definitions ride along.
        return (_module_head() + self.define(nargs)
                + export(self.name, self.lo, nargs))

    def define(self, nargs=8):
        """the `define` for THIS function. Named by ADDRESS so `bl` resolution is purely
           address-based; a friendly C symbol is a thin wrapper (see export())."""
        nargs = 8
        regs = [f'x{i}' for i in range(31)] + ['sp']
        pers = f' personality ptr @{self.eh["pers"]}' if self.eh_pads else ''   #  10-03 C++ exceptions
        head = [f'define {ABI_RET} @fn_{self.lo:x}({ABI_PARAMS}){pers} {{', 'entry:']
        for r in regs: head.append(f'  %{r} = alloca i64')
        #  v0-v31, the NEON register file. These are allocas for the same reason the GPRs
        #    are: mem2reg lifts them into SSA and the x86 backend allocates xmm0-15 itself.
        #  R12 AAPCS64 passes FP/vector arguments in v0-v7 and returns in v0, and this
        #    define() now carries all of them. It used to carry only x0-x7, and the debt was
        #    written here as a  for three sessions before libcompression collected it:
        #    _lzfse_decode_literals takes its four FSE states in d0, read zero, and decoded
        #    1 MB of zeros with no abort and the right output length.
        #  R18 64 BYTES, NOT 16. v0 IS the low 128 bits of z0 on the real machine,
        #    so they are ONE alloca. Every existing `load <16 x i8>, ptr %vN` still reads
        #    the low 16 bytes, which is the aliasing rule, unchanged and untouched.
        for i in range(32): head.append(f'  %v{i} = alloca <{SVL_B} x i8>')
        #  R18 p0-p15. A predicate is SVL/8 = 64 BITS, one per byte lane, held as an
        #    i64 mask. The element mask for a wider lane is a stride-slice of it.
        for i in range(16): head.append(f'  %p{i} = alloca i64')
        #  R18 the ZA tile: SVL x SVL bits = 64 rows of 64 bytes = 4096 bytes.
        head.append(f'  %za = alloca [{SVL_B} x <{SVL_B} x i8>]')
        #  R33 ZT0, the SME2 lookup table: 512 bits, its own register, zeroed
        #    with ZA. It had NO storage before, so luti4 had nothing to read.
        head.append(f'  %zt0 = alloca <{SVL_B} x i8>')
        #  R39 x0-x8 handed to __arm2x86_svc by pointer; it writes back x0/x1 itself, so
        #    only the registers the KERNEL changed are changed.
        head.append('  %svcargs = alloca [9 x i64]')
        head += [f'  %{f} = alloca i1' for f in 'NZCV']
        head += [f'  store i1 false, ptr %{f}' for f in 'NZCV']
        for r in regs: head.append(f'  store i64 0, ptr %{r}')
        for i in range(32):
            head.append(f'  store <{SVL_B} x i8> zeroinitializer, ptr %v{i}')
        for i in range(16):
            head.append(f'  store i64 0, ptr %p{i}')
        head.append(f'  store [{SVL_B} x <{SVL_B} x i8>] zeroinitializer, ptr %za')
        head.append(f'  store <{SVL_B} x i8> zeroinitializer, ptr %zt0')
        #  ONE SHARED STACK, NOT A PRIVATE FRAME PER FUNCTION. Each function used to
        #    alloca its own 4096 bytes; that works for ONE function and is a lie the moment
        #    a callee's frame must sit below the caller's. @__arm_sp is the real ARM sp,
        #    set once by the shim to the top of an mmap'd region. ARM code moves it itself.
        head.append('  %spinit = load i64, ptr @__arm_sp')
        head.append('  store i64 %spinit, ptr %sp')
        for i in range(nargs): head.append(f'  store i64 %a{i}, ptr %x{i}')
        #  AFTER the zeroinitializer loop above, never before it, or the arguments are
        #    overwritten with zeros and the bug comes straight back wearing a fix.
        for i in range(8):
            head.append(f'  %qin{i} = bitcast <2 x i64> %q{i} to <16 x i8>')
            head.append(f'  store <16 x i8> %qin{i}, ptr %v{i}')
        #  rung 6 x8 (sret) — and for an off-contract function every register its caller left — from @__arm_xr.
        #    WAS zero: a C++ function returning a struct by value wrote it to address 0.
        head.append(XR_IN_MARK)   #  10-21 resolved in xr_tail_resolve: + what a tail site will publish
        head.append(f'  br label %L{self.lo:x}')
        self.lift()
        if getattr(self, 'vaconv', False): head.insert(2, '  %vaconv = alloca [24 x i8], align 16')   #  10-03 va_conv
        head, body = self.xr_tail_resolve(head, self.body)
        return '\n'.join(head + body + ['}', ''])

#  MEASURED OFF THIS MACHINE'S SILICON (recip_hw.txt), not written from prose.
#    ARM defines FRECPE/FRSQRTE as exact 8-bit table estimates. A true 1/x is MORE
#    accurate and STILL WRONG, and it passes every eyeball check — a plausible lie.
#  THE RSQRT PSEUDOCODE RECALLED FROM MEMORY WAS WRONG IN 130/256 ENTRIES. That
#    is why these are measurements. The emitted IR was then diffed against the
#    hardware instruction over 220,224 inputs (every f32 exponent x top-8 fraction
#    x both signs, every f64 exponent, and dense sweeps across the overflow
#    threshold): 0 mismatches.
RECIP_TAB = [255, 253, 251, 249, 247, 245, 243, 241, 240, 238, 236, 234, 232, 230, 229, 227, 225, 223, 221, 220, 218, 216, 215, 213, 211, 210, 208, 206, 205, 203, 201, 200, 198, 197, 195, 194, 192, 191, 189, 188, 186, 185, 183, 182, 180, 179, 177, 176, 174, 173, 172, 170, 169, 167, 166, 165, 163, 162, 161, 159, 158, 157, 156, 154, 153, 152, 150, 149, 148, 147, 145, 144, 143, 142, 141, 139, 138, 137, 136, 135, 134, 132, 131, 130, 129, 128, 127, 126, 124, 123, 122, 121, 120, 119, 118, 117, 116, 115, 114, 113, 112, 111, 110, 109, 108, 107, 106, 105, 104, 103, 102, 101, 100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 88, 87, 86, 85, 84, 83, 82, 81, 81, 80, 79, 78, 77, 76, 75, 75, 74, 73, 72, 71, 70, 70, 69, 68, 67, 66, 66, 65, 64, 63, 63, 62, 61, 60, 59, 59, 58, 57, 56, 56, 55, 54, 53, 53, 52, 51, 51, 50, 49, 48, 48, 47, 46, 46, 45, 44, 44, 43, 42, 42, 41, 40, 40, 39, 38, 38, 37, 36, 36, 35, 34, 34, 33, 32, 32, 31, 30, 30, 29, 29, 28, 27, 27, 26, 26, 25, 24, 24, 23, 23, 22, 21, 21, 20, 20, 19, 18, 18, 17, 17, 16, 16, 15, 15, 14, 13, 13, 12, 12, 11, 11, 10, 10, 9, 9, 8, 7, 7, 6, 6, 5, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0]
RSQRT_TAB = [255, 253, 251, 249, 247, 245, 243, 242, 240, 238, 236, 234, 233, 231, 229, 228, 226, 224, 223, 221, 219, 218, 216, 215, 213, 212, 210, 209, 207, 206, 204, 203, 201, 200, 198, 197, 196, 194, 193, 192, 190, 189, 188, 186, 185, 184, 183, 181, 180, 179, 178, 176, 175, 174, 173, 172, 170, 169, 168, 167, 166, 165, 164, 163, 162, 160, 159, 158, 157, 156, 155, 154, 153, 152, 151, 150, 149, 148, 147, 146, 145, 144, 143, 142, 141, 140, 140, 139, 138, 137, 136, 135, 134, 133, 132, 131, 131, 130, 129, 128, 127, 126, 126, 125, 124, 123, 122, 121, 121, 120, 119, 118, 118, 117, 116, 115, 114, 114, 113, 112, 111, 111, 110, 109, 109, 108, 107, 106, 105, 105, 104, 104, 103, 103, 101, 101, 100, 100, 99, 99, 97, 97, 96, 96, 95, 95, 93, 93, 92, 92, 91, 91, 90, 90, 88, 88, 87, 87, 86, 86, 85, 85, 84, 84, 82, 82, 81, 81, 80, 80, 79, 79, 78, 78, 77, 77, 76, 76, 75, 75, 74, 74, 72, 72, 71, 71, 70, 70, 69, 69, 68, 68, 67, 67, 66, 66, 65, 65, 64, 64, 63, 63, 62, 62, 61, 61, 60, 60, 60, 60, 59, 59, 58, 58, 57, 57, 56, 56, 55, 55, 54, 54, 53, 53, 52, 52, 51, 51, 51, 51, 50, 50, 49, 49, 48, 48, 47, 47, 46, 46, 46, 46, 45, 45, 44, 44, 43, 43, 42, 42, 42, 42, 41, 41, 40, 40, 39, 39, 38, 38, 38, 38, 37, 37, 36, 36, 35, 35, 35, 35, 34, 34, 33, 33, 33, 33, 32, 32, 31, 31, 30, 30, 30, 30, 29, 29, 28, 28, 28, 28, 27, 27, 26, 26, 26, 26, 25, 25, 24, 24, 24, 24, 23, 23, 22, 22, 22, 22, 21, 21, 20, 20, 20, 20, 19, 19, 19, 19, 18, 18, 17, 17, 17, 17, 16, 16, 16, 16, 15, 15, 14, 14, 14, 14, 13, 13, 13, 13, 12, 12, 11, 11, 11, 11, 10, 10, 10, 10, 9, 9, 9, 9, 8, 8, 8, 8, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4, 3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 0, 0]

#  R37 16 is a ROW, not a new algorithm: frecpe_ir/frsqrte_ir are written over (fb, eb,
#    bias, emax), and the f16 output was checked against all 65,536 inputs on silicon.
W = {16: (10, 5, 15, 31), 32: (23, 8, 127, 255), 64: (52, 11, 1023, 2047)}
M52 = (1 << 52) - 1

def _est_tables():
    r = ', '.join(f'i8 {v - 256 if v >= 256 else v}' if False else f'i8 {v}' for v in RECIP_TAB)
    s = ', '.join(f'i8 {v}' for v in RSQRT_TAB)
    return (f'@__arm2x86_recip_tab = private unnamed_addr constant [256 x i8] [{r}]\n'
            f'@__arm2x86_rsqrt_tab = private unnamed_addr constant [384 x i8] [{s}]\n')

class _EB:
    def __init__(s): s.n = 0; s.L = []
    def t(s): s.n += 1; return f'%t{s.n}'
    def e(s, x): s.L.append('  ' + x); return None
    def op(s, fmt):
        r = s.t(); s.e(f'{r} = {fmt}'); return r

def _unpack(b, bits, N):
    fb, eb, bias, emax = W[N]
    sign = b.op(f'lshr i64 {bits}, {N - 1}')
    e0   = b.op(f'lshr i64 {bits}, {fb}')
    exp  = b.op(f'and i64 {e0}, {emax}')
    frac = b.op(f'and i64 {bits}, {(1 << fb) - 1}')
    return sign, exp, frac

def frecpe_ir(N):
    fb, eb, bias, emax = W[N]
    ity, fty = f'i{N}', {16: 'half', 32: 'float', 64: 'double'}[N]
    b = _EB()
    bi = b.op(f'bitcast {fty} %x to {ity}')
    bits = bi if N == 64 else b.op(f'zext i{N} {bi} to i64')
    sign, exp, frac = _unpack(b, bits, N)
    isE  = b.op(f'icmp eq i64 {exp}, {emax}')
    fnz  = b.op(f'icmp ne i64 {frac}, 0')
    fz   = b.op(f'icmp eq i64 {frac}, 0')
    isNaN= b.op(f'and i1 {isE}, {fnz}')
    isInf= b.op(f'and i1 {isE}, {fz}')
    e0z  = b.op(f'icmp eq i64 {exp}, 0')
    isZ  = b.op(f'and i1 {e0z}, {fz}')
    fin  = b.op(f'shl i64 {frac}, {52 - fb}')
    hi   = b.op(f'lshr i64 {fin}, 51')
    hib  = b.op(f'icmp eq i64 {hi}, 1')
    s1   = b.op(f'shl i64 {fin}, 1'); s1m = b.op(f'and i64 {s1}, {M52}')
    s2   = b.op(f'shl i64 {fin}, 2'); s2m = b.op(f'and i64 {s2}, {M52}')
    esub = b.op(f'select i1 {hib}, i64 0, i64 -1')
    fsub = b.op(f'select i1 {hib}, i64 {s1m}, i64 {s2m}')
    e    = b.op(f'select i1 {e0z}, i64 {esub}, i64 {exp}')
    f    = b.op(f'select i1 {e0z}, i64 {fsub}, i64 {fin}')
    idx  = b.op(f'lshr i64 {f}, 44')
    gp   = b.op(f'getelementptr inbounds [256 x i8], ptr @__arm2x86_recip_tab, i64 0, i64 {idx}')
    e8   = b.op(f'load i8, ptr {gp}')
    est  = b.op(f'zext i8 {e8} to i64')
    rexp = b.op(f'sub i64 {2 * bias - 1}, {e}')
    fr0  = b.op(f'shl i64 {est}, 44')
    fa0  = b.op(f'lshr i64 {fr0}, 1'); fa = b.op(f'or i64 {fa0}, {1 << 51}')
    fb0  = b.op(f'lshr i64 {fr0}, 2'); fbv= b.op(f'or i64 {fb0}, {1 << 50}')
    r0   = b.op(f'icmp eq i64 {rexp}, 0')
    rm1  = b.op(f'icmp eq i64 {rexp}, -1')
    fsel1= b.op(f'select i1 {rm1}, i64 {fbv}, i64 {fr0}')
    fr   = b.op(f'select i1 {r0}, i64 {fa}, i64 {fsel1}')
    rex  = b.op(f'select i1 {rm1}, i64 0, i64 {rexp}')
    sb   = b.op(f'shl i64 {sign}, {N - 1}')
    eb_  = b.op(f'shl i64 {rex}, {fb}')
    frs  = b.op(f'lshr i64 {fr}, {52 - fb}')
    m1   = b.op(f'or i64 {sb}, {eb_}'); norm = b.op(f'or i64 {m1}, {frs}')
    rnan = b.op(f'or i64 {bits}, {1 << (fb - 1)}')
    rinf = b.op(f'or i64 {sb}, {emax << fb}')
    #  MEASURED: 532/20000 f32 hardware results needed this. ARM tests overflow BEFORE
    #    normalising, so a deeply subnormal input reciprocates to Inf, not to max-normal.
    ovfc = b.op(f'icmp ult i64 {frac}, {1 << (fb - 2)}')
    ovf  = b.op(f'and i1 {e0z}, {ovfc}')
    und  = b.op(f'icmp slt i64 {rexp}, -1')
    ovr  = b.op(f'icmp sge i64 {rexp}, {emax}')
    r    = b.op(f'select i1 {ovr}, i64 {rinf}, i64 {norm}')
    r    = b.op(f'select i1 {und}, i64 {sb}, i64 {r}')
    r    = b.op(f'select i1 {ovf}, i64 {rinf}, i64 {r}')
    r    = b.op(f'select i1 {isZ}, i64 {rinf}, i64 {r}')
    r    = b.op(f'select i1 {isInf}, i64 {sb}, i64 {r}')
    r    = b.op(f'select i1 {isNaN}, i64 {rnan}, i64 {r}')
    out  = r if N == 64 else b.op(f'trunc i64 {r} to i{N}')
    res  = b.op(f'bitcast {ity} {out} to {fty}')
    body = '\n'.join(b.L)
    return (f'define internal {fty} @__arm2x86_frecpe_f{N}({fty} %x) '
            f'#0 {{\nentry:\n{body}\n  ret {fty} {res}\n}}\n')

def frsqrte_ir(N):
    fb, eb, bias, emax = W[N]
    ity, fty = f'i{N}', {16: 'half', 32: 'float', 64: 'double'}[N]
    b = _EB()
    bi = b.op(f'bitcast {fty} %x to {ity}')
    bits = bi if N == 64 else b.op(f'zext i{N} {bi} to i64')
    sign, exp, frac = _unpack(b, bits, N)
    isE  = b.op(f'icmp eq i64 {exp}, {emax}')
    fnz  = b.op(f'icmp ne i64 {frac}, 0')
    fz   = b.op(f'icmp eq i64 {frac}, 0')
    isNaN= b.op(f'and i1 {isE}, {fnz}')
    isInf= b.op(f'and i1 {isE}, {fz}')
    e0z  = b.op(f'icmp eq i64 {exp}, 0')
    isZ  = b.op(f'and i1 {e0z}, {fz}')
    neg  = b.op(f'icmp eq i64 {sign}, 1')
    fin  = b.op(f'shl i64 {frac}, {52 - fb}')
    #  the ARM `while fraction<51> == 0` loop IS a count-leading-zeros.
    lz   = b.op(f'call i64 @llvm.ctlz.i64(i64 {fin}, i1 false)')
    k    = b.op(f'sub i64 {lz}, 12')
    k1   = b.op(f'add i64 {k}, 1')
    sh   = b.op(f'shl i64 {fin}, {k1}')
    fsub = b.op(f'and i64 {sh}, {M52}')
    esub = b.op(f'sub i64 0, {k}')
    e    = b.op(f'select i1 {e0z}, i64 {esub}, i64 {exp}')
    f    = b.op(f'select i1 {e0z}, i64 {fsub}, i64 {fin}')
    par  = b.op(f'and i64 {e}, 1')
    ev   = b.op(f'icmp eq i64 {par}, 0')
    ie   = b.op(f'lshr i64 {f}, 44')          # 0..255 -> table slot 128+
    io   = b.op(f'lshr i64 {f}, 45')          # 0..127 -> table slot 0+
    ie2  = b.op(f'add i64 {ie}, 128')
    idx  = b.op(f'select i1 {ev}, i64 {ie2}, i64 {io}')
    gp   = b.op(f'getelementptr inbounds [384 x i8], ptr @__arm2x86_rsqrt_tab, i64 0, i64 {idx}')
    e8   = b.op(f'load i8, ptr {gp}')
    est  = b.op(f'zext i8 {e8} to i64')
    d    = b.op(f'sub i64 {3 * bias - 1}, {e}')
    rexp = b.op(f'lshr i64 {d}, 1')
    fr0  = b.op(f'shl i64 {est}, 44')
    eb_  = b.op(f'shl i64 {rexp}, {fb}')
    frs  = b.op(f'lshr i64 {fr0}, {52 - fb}')
    norm = b.op(f'or i64 {eb_}, {frs}')
    sb   = b.op(f'shl i64 {sign}, {N - 1}')
    dnan = (emax << fb) | (1 << (fb - 1))
    rnan = b.op(f'or i64 {bits}, {1 << (fb - 1)}')
    rzi  = b.op(f'or i64 {sb}, {emax << fb}')
    r    = b.op(f'select i1 {neg}, i64 {dnan}, i64 {norm}')
    r    = b.op(f'select i1 {isZ}, i64 {rzi}, i64 {r}')
    infr = b.op(f'select i1 {neg}, i64 {dnan}, i64 0')
    r    = b.op(f'select i1 {isInf}, i64 {infr}, i64 {r}')
    r    = b.op(f'select i1 {isNaN}, i64 {rnan}, i64 {r}')
    out  = r if N == 64 else b.op(f'trunc i64 {r} to i{N}')
    res  = b.op(f'bitcast {ity} {out} to {fty}')
    body = '\n'.join(b.L)
    return (f'define internal {fty} @__arm2x86_frsqrte_f{N}({fty} %x) '
            f'#0 {{\nentry:\n{body}\n  ret {fty} {res}\n}}\n')

def _estimate_helpers():
    return (_est_tables() + 'declare i64 @llvm.ctlz.i64(i64, i1)\n'
            + ''.join(frecpe_ir(n) for n in (16, 32, 64))
            + ''.join(frsqrte_ir(n) for n in (16, 32, 64))
            + 'attributes #0 = { alwaysinline nounwind }\n')


def _vec_declares():
    """ NEON NEEDS NO NEW SEMANTICS — only target-NEUTRAL LLVM intrinsics. Measured
       2026-09-22: of 20 blocking NEON ops, 14 lower to plain vector IR (fadd/fsub/mul/
       shufflevector) with nothing written by us, and the 6 that escaped to
       llvm.aarch64.neon.* each have a generic equivalent that becomes ONE SSE
       instruction (umin->pminud, sqadd->paddsw, abs->pabsb, umull->pmovzxbw+pmullw,
       addp->phaddd, tbl1->pshufb). So the x86 backend owns the whole NEON->SSE table,
       exactly as it owned AAPCS64->SystemV in R2.
        Unused declares are legal LLVM and cost nothing; a MISSING one is a hard verify
          error at the worst moment. Declared exhaustively on purpose."""
    out = []
    ints = [('16 x i8', 'v16i8'), ('8 x i8', 'v8i8'), ('8 x i16', 'v8i16'),
            ('4 x i16', 'v4i16'), ('4 x i32', 'v4i32'), ('2 x i32', 'v2i32'),
            ('2 x i64', 'v2i64'), ('1 x i64', 'v1i64')]
    #  R18-h THE SVL-WIDE TYPES. A z register at Apple's measured 512-bit streaming
    #    vector length is <64 x i8> / <32 x i16> / <16 x i32> / <8 x i64>, and none of
    #    those widths were in this list - so the first SVE fsqrt produced a call to an
    #    undeclared symbol. Derived from SVL_B so they cannot drift from the register.
    #  R18-i fptosi.sat/fptoui.sat for every SVE container width. A conversion
    #    lowers into containers of max(src,dst) bits, so the (lanes, int, float) triples
    #    are not the NEON ones and a missing declare is a hard verify error.
    for _s in (16, 32, 64):
        for _d in (16, 32, 64):
            _n = (SVL_B * 8) // max(_s, _d)
            _f = {16: 'half', 32: 'float', 64: 'double'}[_s]
            _fn = {16: 'f16', 32: 'f32', 64: 'f64'}[_s]
            for _o in ('fptosi', 'fptoui'):
                out.append(f'declare <{_n} x i{_d}> @llvm.{_o}.sat.v{_n}i{_d}.v{_n}{_fn}'
                           f'(<{_n} x {_f}>)')
    ints += [(f'{SVL_B} x i8', f'v{SVL_B}i8'), (f'{SVL_B // 2} x i16', f'v{SVL_B // 2}i16'),
             (f'{SVL_B // 4} x i32', f'v{SVL_B // 4}i32'),
             (f'{SVL_B // 8} x i64', f'v{SVL_B // 8}i64')]
    fps  = [('4 x float', 'v4f32'), ('2 x float', 'v2f32'), ('2 x double', 'v2f64')]
    fps += [(f'{SVL_B // 2} x half', f'v{SVL_B // 2}f16'),
            (f'{SVL_B // 4} x float', f'v{SVL_B // 4}f32'),
            (f'{SVL_B // 8} x double', f'v{SVL_B // 8}f64')]
    #  R8: llvm.fptosi.sat / fptoui.sat REPLACE plain fptosi/fptoui everywhere. ARM's
    #    FP->int conversions saturate and map NaN to 0; the plain casts are POISON out of
    #    range, which is not a small inaccuracy — it lets the optimiser delete live code.
    for vn, ib, fb_ in ((2, 32, 'f32'), (4, 32, 'f32'), (2, 64, 'f64'), (4, 16, 'f16'),
                        (8, 16, 'f16')):
        for o in ('fptosi', 'fptoui'):
            out.append(f'declare <{vn} x i{ib}> @llvm.{o}.sat.v{vn}i{ib}.v{vn}{fb_}'
                       f'(<{vn} x {{16: "half", 32: "float", 64: "double"}}[{ib}]>)'
                       .replace('{16: "half", 32: "float", 64: "double"}'
                                f'[{ib}]', {16: 'half', 32: 'float', 64: 'double'}[ib]))
    for iw in (16, 32, 64):
        for fwn, fw in (('f16', 'half'), ('f32', 'float'), ('f64', 'double')):
            for o in ('fptosi', 'fptoui'):
                out.append(f'declare i{iw} @llvm.{o}.sat.i{iw}.{fwn}({fw})')
    for ty, sfx in ints:
        out.append(f'declare <{ty}> @llvm.ctlz.{sfx}(<{ty}>, i1)')
        out.append(f'declare <{ty}> @llvm.abs.{sfx}(<{ty}>, i1)')
        for f in ('umin', 'umax', 'smin', 'smax', 'sadd.sat', 'uadd.sat',
                  'ssub.sat', 'usub.sat'):
            out.append(f'declare <{ty}> @llvm.{f}.{sfx}(<{ty}>, <{ty}>)')
        for f in ('ctpop', 'bitreverse', 'bswap'):
            out.append(f'declare <{ty}> @llvm.{f}.{sfx}(<{ty}>)')
    for ty, sfx in fps:
        out.append(f'declare <{ty}> @llvm.fma.{sfx}(<{ty}>, <{ty}>, <{ty}>)')
        for f in ('fabs', 'sqrt', 'floor', 'ceil', 'trunc', 'rint', 'nearbyint',
                  'round', 'roundeven'):
            out.append(f'declare <{ty}> @llvm.{f}.{sfx}(<{ty}>)')
        for f in ('minnum', 'maxnum', 'minimum', 'maximum'):
            out.append(f'declare <{ty}> @llvm.{f}.{sfx}(<{ty}>, <{ty}>)')
    #  THE SCALAR FP INTRINSICS. R7 lifts frint*/fmadd/fcvt*/fmaxnm in their SCALAR
    #    forms, and those name llvm.floor.f64 — a DIFFERENT symbol from llvm.floor.v2f64.
    #  The vector list above does not cover them, and a missing declare is a hard
    #    verify error at the worst possible moment. Declared for all three widths
    #    whether used or not, exactly as the vector set is.
    for sty, ssfx in (('half', 'f16'), ('float', 'f32'), ('double', 'f64')):
        out.append(f'declare {sty} @llvm.fma.{ssfx}({sty}, {sty}, {sty})')
        for f in ('fabs', 'sqrt', 'floor', 'ceil', 'trunc', 'rint', 'nearbyint',
                  'round', 'roundeven'):
            out.append(f'declare {sty} @llvm.{f}.{ssfx}({sty})')
        for f in ('minnum', 'maxnum', 'minimum', 'maximum'):
            out.append(f'declare {sty} @llvm.{f}.{ssfx}({sty}, {sty})')
    return '\n'.join(out)

#  R38 ids passed to __arm2x86_nofeature (sysreg_rt.c prints the name from the same table).
R38_NOFEAT = {'tindex_el0': 1, 'tchangef': 2, 'tchangeb': 3, 's3_4_c15_c2_7': 4,
              'tchangefnb': 2, 'tchangebnb': 3,
#  R39 INSTRUCTIONS NO OWNED SILICON HAS. The M4 (the newest chip available) reports, via
#    `sysctl hw.optional.arm` on the mini 2026-09-23: FEAT_SVE_B16B16 0, FEAT_SME_B16B16 0,
#    FEAT_SME2p1 0, and no MOP4 key at all. They sit only in libBNNS (bfmax 309, bfmul 198,
#    bfmin 198, movaz 47 — r39/gap_hits.json, all in real code) plus 1 fmop4a. With nothing
#    to measure a lowering against, NOTHING RECALLED GOES INTO ONE: they abort by name.
              'bfmax': 5, 'bfmin': 5, 'bfmul': 5, 'movaz': 6, 'fmop4a': 7, 'usmop4s': 7}
PRELUDE = '''declare void @__arm2x86_unimplemented(i64)
declare void @__arm2x86_trap(i64)
declare i64 @__arm2x86_svc(i64, ptr, i64, i64)
declare ptr @__arm2x86_lookup(i64)
declare void @__arm2x86_rt_sha(ptr, ptr, ptr, i64)
declare void @__arm2x86_rt_fcvtxn(ptr, ptr, i64)
declare void @__arm2x86_rt_faddp_h(ptr, ptr)
declare void @__arm2x86_rt_fmlal(ptr, ptr, ptr, i64)
declare void @__arm2x86_rt_bfdot(ptr, ptr, ptr, i64)
@__arm_excl_addr = external thread_local global i64
@__arm_excl_lo = external thread_local global i64
@__arm_excl_hi = external thread_local global i64
declare i64 @llvm.bswap.i64(i64)
declare i32 @llvm.bswap.i32(i32)
declare i64 @llvm.bitreverse.i64(i64)
declare i32 @llvm.bitreverse.i32(i32)
declare i64 @llvm.ctlz.i64(i64, i1)
declare i32 @llvm.ctlz.i32(i32, i1)
declare <2 x i64> @llvm.x86.pclmulqdq(<2 x i64>, <2 x i64>, i8)
declare <2 x i64> @llvm.x86.aesni.aesenc(<2 x i64>, <2 x i64>)
declare <2 x i64> @llvm.x86.aesni.aesenclast(<2 x i64>, <2 x i64>)
declare <2 x i64> @llvm.x86.aesni.aesdec(<2 x i64>, <2 x i64>)
declare <2 x i64> @llvm.x86.aesni.aesdeclast(<2 x i64>, <2 x i64>)
declare <2 x i64> @llvm.x86.aesni.aesimc(<2 x i64>)
declare i32 @llvm.x86.sse42.crc32.32.8(i32, i8)
declare i32 @llvm.x86.sse42.crc32.32.16(i32, i16)
declare i32 @llvm.x86.sse42.crc32.32.32(i32, i32)
declare i64 @llvm.x86.sse42.crc32.64.64(i64, i64)
declare void @llvm.prefetch.p0(ptr, i32, i32, i32)
declare i64 @llvm.fshr.i64(i64, i64, i64)
declare i32 @llvm.fshr.i32(i32, i32, i32)
''' + _vec_declares() + '''
;  R35 THE ARM STACK POINTER IS PER THREAD. It was one process global, which is right
;    for one thread and silently wrong for two: every translated function reads its frame
;    base from here, so a second guest thread would build its frames on the first one's
;    stack. libParallelCompression runs one worker per core. Each thread gets its own
;    ARM stack from pc_rt.c's pthread_create bridge; main's comes from the shim's boot().
@__arm_sp = external thread_local global i64
;  rung 6 (10-03) THE REST OF AAPCS64. A lifted call carries x0-x7 + v0-v7 in and x0 + v0 out; everything else the
;    contract moves goes through this per-thread block: x8 IN (sret), x1 + v1-v3 OUT (x0:x1 pairs, HFA returns), and for
;    an off-contract callee (abi_scan.py: outlined code) the WHOLE file x1-x28, v1-v31, NZCV both ways.
;    Layout: xN at 8*N (N < 31), NZCV bytes at 248..251, vN at 256 + 16*N. Defined in shim_comp.c.
;     10-20: x8 + x20 + x21 IN and x1-x3 + x21 + v1-v3 OUT on every call — the Swift registers (see XR_ABI_IN).
@__arm_xr = external thread_local global [96 x i64], align 16
declare ptr @llvm.threadlocal.address.p0(ptr)   ;  one TLS access per transfer, see xr_lines
;  10-20 an import stub's word on its native callee's convention (STUB_CC): 0 none, 1 C, 2 Swift. shim_comp.c owns it.
@__arm2x86_native_hint = external thread_local global i8
@__arm2x86_async_carry = external thread_local global i8
;  R23 TPIDR2_EL0, the SME lazy-save pointer. THREAD-LOCAL BY MEASUREMENT, not by
;    assumption: on an M4 a fresh pthread reads 0 here while the parent keeps its own value
;    (tp2.c). A plain global would let two guest threads share one save pointer and a
;    threaded BLAS would corrupt ZA silently.
;  DECLARED, NOT DEFINED — sysreg_rt.c owns the storage, exactly as shim*.c owns @__arm_sp.
@__arm_tpidr2 = external thread_local global i64
@__arm_tsd_off = external global i64
@__arm2x86_rf = external thread_local global [208 x i8], align 16
;  R24 SVCR. bit 0 = SM, bit 1 = ZA — measured on an M4 in all four states (0 outside,
;    3 after `smstart`, 2 after `smstop sm`, 0 after `smstop za`). THREAD-LOCAL because
;    streaming mode is per-thread: one guest thread entering streaming mode must not make
;    another thread's SVCR read back as streaming.
@__arm_svcr = external thread_local global i64
;  R38 S3_6_C15_C1_5, Apple's protection-permission register (the TPRO switch libpthread,
;    dyld and libobjc flip around writes to their own protected data). MEASURED on the M1 Pro
;    AND the M4 (r38/sprr.c): writing either commpage word (0x110 / 0x118) reads back EXACT,
;    a new thread starts at the 0x118 value, and the parent's value survives a child's write —
;    PER-THREAD. So it is a thread-local slot, the same shape as TPIDR2.
@__arm_sprr = external thread_local global i64
;  10-03 FPCR, per thread (measured on the M1: 0 at start, 0 in a NEW thread — not inherited). Cyberpunk ORs in FZ
;    (bit 24) then DN (bit 25); a write also reaches MXCSR through @__arm2x86_set_fpcr (shim_comp.c).
@__arm_fpcr = external thread_local global i64
declare void @__arm2x86_trace(i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64)
declare void @__arm2x86_set_fpcr(i64)
declare i64 @__arm2x86_cntpct()
;  R38 A PATH NO OWNED SILICON CAN RUN: TINDEX_EL0 / tchangef / tchangeb (the newer
;    permission-overlay mechanism) and S3_4_C15_C2_7 (the older APRR register). Neither the
;    M1 Pro nor the M4 selects them, so there is nothing to measure a lowering against, and the
;    commpage we publish (sysreg_rt.c) says this host has no protection hardware at all.
;    Reaching one means the gate failed — it aborts BY NAME, it never guesses.
declare void @__arm2x86_nofeature(i64, i64)

;  R20 APPLE'S AMX COPROCESSOR STATE. Geometry MEASURED on an M1 Pro 2026-09-22 by
;    finding the first register index that aliases index 0 (amx_bits.c) — not assumed
;    from the number of index bits that happened to respond, which would have given X
;    and Z the same size.
;      X   8 regs x 64 B =  512 B   (load op0 / store op2)
;      Y   8 regs x 64 B =  512 B   (load op1 / store op3)
;      Z  64 regs x 64 B = 4096 B   (load op4 / store op5)
;    THREAD-LOCAL BECAUSE THE REAL UNIT IS PER-THREAD. A plain global would let two guest
;    threads share one Z tile, and a threaded BLAS would corrupt silently — the failure
;    would look like a numerical bug, not a translation bug.
;  R21 DECLARED, NOT DEFINED — amx_rt.c owns the storage, exactly as shim*.c owns
;    @__arm_sp. R20 emitted `thread_local global [512 x i8] zeroinitializer` here, which is
;    a DEFINITION in every translated module: it collides with the runtime the moment a
;    shim links amx_rt.c, and two translated modules linked into one image collide with
;    each other. Nothing caught it because exactly one module was ever linked.
@__arm2x86_amx_x = external thread_local global [512 x i8]
@__arm2x86_amx_y = external thread_local global [512 x i8]
@__arm2x86_amx_z = external thread_local global [4096 x i8]
;  R21 (op, operand, guest pc). `operand` is the RUNTIME VALUE of the GPR the
;    instruction names — the 5-bit operand field is a REGISTER NUMBER, never an immediate,
;    so no mode bit of a compute op is knowable at translation time.
declare void @__arm2x86_amx_op(i64, i64, i64)
;  R22 SME2. A MASKED load/store, never a full one plus a select: the inactive lanes
;    of a prefix mask routinely sit past the end of a mapping, and a full load there is a
;    fault the hardware does not take. Declared in the INTEGER type of each width only —
;    the float forms bitcast, which halves the surface without changing a lane.
declare <64 x i8> @llvm.masked.load.v64i8.p0(ptr, i32, <64 x i1>, <64 x i8>)
declare <32 x i16> @llvm.masked.load.v32i16.p0(ptr, i32, <32 x i1>, <32 x i16>)
declare <16 x i32> @llvm.masked.load.v16i32.p0(ptr, i32, <16 x i1>, <16 x i32>)
declare <8 x i64> @llvm.masked.load.v8i64.p0(ptr, i32, <8 x i1>, <8 x i64>)
declare void @llvm.masked.store.v64i8.p0(<64 x i8>, ptr, i32, <64 x i1>)
declare void @llvm.masked.store.v32i16.p0(<32 x i16>, ptr, i32, <32 x i1>)
declare void @llvm.masked.store.v16i32.p0(<16 x i32>, ptr, i32, <16 x i1>)
declare void @llvm.masked.store.v8i64.p0(<8 x i64>, ptr, i32, <8 x i1>)
;  R22 the predicate-as-counter's marker bit is its LOWEST SET BIT, so decoding it is
;    a count-trailing-zeros. is_zero_poison is FALSE at every call site: raw == 0 is the
;    legal "empty" encoding, not an error.
declare i64 @llvm.cttz.i64(i64, i1)
declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1)
declare void @llvm.memset.p0.i64(ptr, i8, i64, i1)

;  R17-c THE REFLECTED CRC STEP, ONE BIT AT A TIME.
;    crc = (crc >> 1) ^ (poly & -((crc ^ (val >> i)) & 1))
;    The CRC32C variants go to the Xeon's real SSE4.2 CRC32 instruction instead; only the
;    CRC-32 (poly 0xEDB88320) forms land here, because x86 has no instruction for that
;    polynomial.  It is a LOOP, not 64 unrolled copies: `crc32x` would otherwise emit
;    ~350 lines of IR per instruction, and there are 97 of them in the cache.
define internal i32 @__arm2x86_crcstep(i32 %crc0, i64 %val, i32 %bits, i32 %poly) {
entry:
  br label %loop
loop:
  %i = phi i32 [ 0, %entry ], [ %i1, %loop ]
  %c = phi i32 [ %crc0, %entry ], [ %cn, %loop ]
  %sh = zext i32 %i to i64
  %vs = lshr i64 %val, %sh
  %v32 = trunc i64 %vs to i32
  %x = xor i32 %c, %v32
  %b = and i32 %x, 1
  %m = sub i32 0, %b
  %pm = and i32 %poly, %m
  %cs = lshr i32 %c, 1
  %cn = xor i32 %cs, %pm
  %i1 = add i32 %i, 1
  %done = icmp eq i32 %i1, %bits
  br i1 %done, label %out, label %loop
out:
  ret i32 %cn
}

'''

def _dispatch_ir():
    """ R12 THE INDIRECT-CALL TRAMPOLINE, IN IR RATHER THAN IN C.

     It used to be a C function. It cannot be one any more: the return is
       {i64, <2 x i64>}, and a C struct of an unsigned long plus an __m128i is 24 bytes,
       which SysV classifies MEMORY and returns through a hidden pointer. LLVM returns the
       IR aggregate in RAX+XMM0. Both are correct for their own language and they are not
       the same ABI — a mismatch that would corrupt every indirect call and abort nowhere.
       So C keeps the part that has no ABI hazard (look an address up, or abort by name)
       and the call itself is emitted where both sides are LLVM's."""
    ps = ', '.join(['i64 %t'] + [f'i64 %a{i}' for i in range(8)]
                   + [f'<2 x i64> %q{i}' for i in range(8)])
    av = ', '.join([f'i64 %a{i}' for i in range(8)] + [f'<2 x i64> %q{i}' for i in range(8)])
    #  R35 THE DOOR NATIVE CODE USES TO ENTER TRANSLATED CODE BY ARM ADDRESS — a thread
    #    start routine, a pthread_once init. Integer args in, x0 out, v0-v7 zero. It lives
    #    here, in IR, for the same ABI reason as the trampoline above: a C caller cannot call
    #    the {i64, <2 x i64>} return directly.
    ca = ', '.join(['i64 %a0', 'i64 %a1'] + ['i64 0'] * 6 + ['<2 x i64> zeroinitializer'] * 8)
    return (f'define internal {ABI_RET} @__arm2x86_dispatch({ps}) {{\n'
            f'  %f = call ptr @__arm2x86_lookup(i64 %t)\n'
            f'  %r = call {ABI_RET} %f({av})\n'
            f'  ret {ABI_RET} %r\n}}\n'
            f'define i64 @__arm2x86_call_arm(i64 %t, i64 %a0, i64 %a1) {{\n'
            f'  %f = call ptr @__arm2x86_lookup(i64 %t)\n'
            f'  %r = call {ABI_RET} %f({ca})\n'
            f'  %x = extractvalue {ABI_RET} %r, 0\n'
            f'  ret i64 %x\n}}\n')


def export(name, addr, nargs):
    """a C-callable symbol in front of the address-named function"""
    ps = ', '.join(f'i64 %p{i}' for i in range(nargs))
    #  R12 the wrapper is the INTEGER entry point: it zeroes v0-v7 and drops the
    #    returned v0. A float-argument export needs its own wrapper and does not have one
    #    yet — say so rather than let a C caller silently pass nothing.
    av = ', '.join(([f'i64 %p{i}' for i in range(nargs)] + ['i64 0'] * 8)[:8]
                   + ['<2 x i64> zeroinitializer'] * 8)
    return (f'define i64 @{name}({ps}) {{\n'
            f'  %r = call {ABI_RET} @fn_{addr:x}({av})\n'
            f'  %x = extractvalue {ABI_RET} %r, 0\n'
            f'  ret i64 %x\n}}\n')


def _r33_declares():
    """ R33 masked memory at every (lanes, element) the R33 lowerings use, the FP
       intrinsics at every power-of-two width a reduction tree halves through, and the
       scalar bit counts.  Unused declares cost nothing; a missing one is a hard verify
       error at the worst moment, so this is exhaustive on purpose."""
    out = ['declare i64 @llvm.ctpop.i64(i64)', 'declare i64 @llvm.cttz.i64(i64, i1)',
           'declare i64 @llvm.ctlz.i64(i64, i1)']
    for eb in (8, 16, 32, 64, 128):
        for n in (1, 2, 4, 8, 16, 32, 64, 128, 256):
            v = f'<{n} x i{eb}>'
            m = f'<{n} x i1>'
            out.append(f'declare {v} @llvm.masked.load.v{n}i{eb}.p0(ptr, i32, {m}, {v})')
            out.append(f'declare void @llvm.masked.store.v{n}i{eb}.p0({v}, ptr, i32, {m})')
    for el, sfx in (('half', 'f16'), ('float', 'f32'), ('double', 'f64')):
        for n in (1, 2, 4, 8, 16, 32, 64):
            v = f'<{n} x {el}>'
            out.append(f'declare {v} @llvm.fabs.v{n}{sfx}({v})')
            out.append(f'declare {v} @llvm.fma.v{n}{sfx}({v}, {v}, {v})')
            for f in ('maximum', 'minimum'):
                out.append(f'declare {v} @llvm.{f}.v{n}{sfx}({v}, {v})')
    return '\n'.join(out) + '\n'


def _module_head():
    """ ONE HEAD FOR BOTH BUILD PATHS, because there were two and they disagreed.

     build() — THE WHOLE-IMAGE PATH, THE ONE THAT SHIPS — emitted PRELUDE and NOT
       _estimate_helpers(). So the FRECPE/FRSQRTE tables, read off real silicon and
       proven to 0 mismatches on 220,224 hardware samples, were reachable only from the
       `--module` CLI. Any image using a reciprocal estimate would emit
       `call @__arm2x86_frecpe_f32` with nothing defining it. libz has no reciprocal
       estimate, so the 3,051-arm R4 suite was green and could not see it: a built organ
       with no caller is a comment. Found by compiling a probe of the mnemonics libz does
       NOT contain — the suite can only test what its one image happens to use.

     AND THE TWO PIECES BOTH DECLARE llvm.ctlz.i64, WHICH LLVM REJECTS outright:
       `invalid redefinition of function`. Each piece stays self-contained on purpose —
       the helpers were proven as a standalone artifact and must stay byte-comparable to
       it — so the SEAM de-duplicates, not the pieces.
    """
    seen, out = set(), []
    for line in (PRELUDE + _estimate_helpers() + _dispatch_ir()
                 + '\n' + _r33_declares()).splitlines():
        if line.startswith('declare '):
            #  R33 KEYED ON THE SYMBOL, not the line: LLVM rejects a second declare of
            #    one symbol however it is spelled.
            key = line.split('@', 1)[1].split('(', 1)[0]
            if key in seen:
                continue
            seen.add(key)
        out.append(line)
    return '\n'.join(out) + '\n'


#  rung 6 the general-purpose register grammar rd()/wr() accept (x0-x30, w0-w30, sp, wsp)
GPR = re.compile(r'^(?:[xw](?:[0-9]|[12][0-9]|30)|w?sp)$')
#  rung 6 stub address -> the translated function its GOT slot resolves to (set by xlat2 before lifting).
ALIASES = {}
#  rung 6 functions abi_scan.py found OFF the AAPCS64 contract (outlined code): called with the full register file
NONABI = set()
#  10-21 SWIFT ASYNC FUNCTIONS (set by xlat2 from abi_scan: the functions that READ x22 on entry — only a swiftasync function
#    does — plus pure forwarders to one). Their final `br` is an ASYNC TAIL CALL: hint 3 for a native target, and a real
#    `musttail` so a chain of resumes that never suspends does not grow the stack (see Lifter.indirect_tail).
ASYNC_FNS = set()
#  10-03 INSTRUMENTED LIFT, for one bug at a time: ARM2X86_TRACE_FNS=1000286e8,... (hex, at LIFT time) makes those functions
#    print every arm64 instruction address + key registers to stderr before executing it (shim_comp.c __arm2x86_trace).
#    Every other function is lifted exactly as before.  A shard lifted WITH it must be re-lifted without it afterwards.
TRACE_FNS = {int(x, 16) for x in __import__('os').environ.get('ARM2X86_TRACE_FNS', '').split(',') if x.strip()}
#  10-20 THE SWIFT REGISTERS RIDE EVERY CALL. arm64 Swift passes `self`/closure context in x20, the error in x21
#    (swifterror: the callee WRITES it, the caller tests it after the call) and returns up to FOUR words in x0-x3. They were
#    not part of this contract, so a native Swift callee reached through the adapter got none of them (measured on macOS 27:
#    eslogger / xprotect died inside Foundation.URL.init and ArgumentParserInternal, fault 0x8 / 0x0). x20/x21 are published
#    at every call and loaded by every prologue — for an on-contract callee they are callee-saved, so it hands back exactly
#    what it loaded, which is the hardware's answer; x2/x3/x21 come back from every callee (x2/x3 are caller-saved, so a
#    reload is never wrong). Only the adapter writes new values into them (swifterror r12, Swift returns rcx/r8).
XR_IN_MARK = '  ;;XRIN'   #  10-21 placeholder for the entry load, resolved once the function's defines are known
#  10-21 + x22, THE SWIFT ASYNC CONTEXT (swiftasync: arm64 x22, x86-64 r14). asyncmx traced it: a NONABI resume function tail-
#    calls an on-contract import stub with x22 = the callee context it just allocated (`mov x22, x8` / `b stub`); emit_call
#    published x8/x20/x21 only, so the adapter read the x22 the function was ENTERED with, handed the native callee the wrong
#    context and patched the wrong ResumeParent. Like self and error it is read by every prologue and published at every call;
#    it comes back unchanged (callee-saved), so it is not in XR_ABI_OUT.
XR_ABI_IN = ['x8', 'x20', 'x21', 'x22']
XR_ABI_OUT = ['x1', 'x2', 'x3', 'x21', 'v1', 'v2', 'v3']
#  10-21 x29 IS A DATA REGISTER OF OFF-CONTRACT CODE, AND IT WAS LEFT OUT OF THE FILE. These sets stopped at x28
#    ("the callee-saved GPRs end at x28"), so an off-contract fragment — which by definition inherits its caller's
#    frame — entered with %x29 still at the prologue's `store i64 0` and read the caller's locals off ADDRESS ZERO.
#    Measured in the Dock: fn_10028fa00 is a 16-byte fall-through fragment whose first instruction is
#    `ldurb w8, [x29, #-81]`; with x29 = 0 the backend folded it to `movzbl -0x51, %r12d` — an absolute load with no
#    base register — and the Dock died there with fault address 0xffffffffffffffaf at `[Spotlight init]`. (The run
#    after it, `orn w8, w8, w0` / `and w8, w8, #1`, consumes that %r12, which is what pins the instruction.)
#    Same class as sp in abi_ret below: a register with a frame ROLE is still a value the fragment reads.
#    x30 stays out on purpose — a translated function returns through the x86 stack, so the guest LR is not a value
#    anything downstream reads, and carrying it would hand every off-contract callee's stale LR back to its caller.
XR_FULL_IN = [f'x{i}' for i in range(8, 30)] + [f'v{i}' for i in range(8, 32)] + ['nzcv']
XR_FULL_OUT = [f'x{i}' for i in range(1, 30)] + [f'v{i}' for i in range(1, 32)] + ['nzcv']
#  10-03 (Cyberpunk, traced): after an INDIRECT TAIL call (`br x2`) an off-contract function returned without writing its
#    file back — the caller reloaded x19-x28 as ZERO and stored through x21 = 0. The tail callee owns x0/x1/v0-v3 (it wrote
#    them); everything else is ours to hand back, exactly as the hardware's callee-saved registers would be.
#     10-20: the tail callee also owns x2/x3/x21 now (XR_ABI_OUT) — an off-contract import stub that tail-calls a native
#    Swift function must not overwrite its error or its third/fourth return word with the stale copy it loaded at entry.
XR_TAIL_KEEP = [r for r in XR_FULL_OUT if r not in XR_ABI_OUT]
#  10-20 import stubs whose callee's calling convention is KNOWN from its symbol (set by xlat2): stub address -> 1 (a C
#    symbol: plain SysV, AL = vector count for a variadic callee) or 2 (a Swift `$s` symbol: swiftcc — x8 -> rax, x20 -> r13,
#    x21 -> r12). The stub's `br x16` stores it in @__arm2x86_native_hint just before the dispatch, and the adapter reads it
#    first; a raw native pointer (no stub) falls back to the shim's per-image answer (does the image carry Swift metadata).
STUB_CC = {}
#  10-03 C++ EXCEPTIONS (eh.py, set by xlat2 per shard): function address -> {'pers': IR personality name,
#    'sites': [(start, end, landing_pad_or_0, clauses)]}, clauses = ((filter, type) ...): filter > 0 catches `type` (an IR
#    global name, None = catch-all), 0 = cleanup, < 0 = an exception specification (type = tuple of names). A call inside a
#    site with a landing pad becomes an `invoke`; its unwind edge hands the arm64 pad exactly what the hardware unwinder
#    would: x0 = the exception, x1 = the arm64 selector (the filter that matched), every other register as at the call.
EH = {}
#  10-03 THIS-RETURNING NATIVE IMPORTS (set by xlat2): import stubs whose native target is a C++ constructor or
#    destructor. Apple's arm64 C++ ABI (ARM's) makes C1/C2/D1/D2 return `this` in x0 and callers USE it (LibError's ctor
#    calls runtime_error(const char*) and then stores its vtable through x0); x86-64's return void, so x0 came back as rax
#    garbage. The lifted stub hands back the x0 it was called with — the arm64 contract — whatever the native returned.
THISRET = set()
#  10-03 CALLS THAT LIFT TO NOTHING (set by xlat2): import stubs of arm64 ___chkstk_darwin. It is a compiler helper with
#    its own contract — frame size in a scratch register, EVERY argument register preserved — and it only probes the stack
#    page by page. Our arm64 stack has a real guard page (shim boot()), so the probe has nothing to add. Cyberpunk build20:
#    the stub reached the NATIVE x86 ___chkstk_darwin, which read its size from rax (0x7fa2c7009a08) and ran off the main
#    stack in 2 s; through the generic path it would also have clobbered x1 and v0-v3, the live arguments of a prologue.
#     It holds stub addresses (a `bl`) AND GOT slot addresses: clang calls it as `adrp x16, slot; ldr x16, [x16, #off];
#    blr x16` (Cyberpunk: every big-frame prologue, size/16 in w9), and that `blr` is recognised by the slot it loaded.
NOOP_CALLS = set()


def xr_lines(regs, put, tag):
    """IR moving `regs` between this function's register allocas and @__arm_xr. put=True: allocas -> block.
        10-21 MATERIALISE THE THREAD-LOCAL BASE ONCE: one `llvm.threadlocal.address` per transfer, then plain
          offsets off that SSA pointer, so the backend lowers ONE TLS access instead of thirty.
        It must be `llvm.threadlocal.address`, NOT `getelementptr @__arm_xr, 0`: instcombine folds a
          zero-offset GEP straight back into the global and every slot GEPs off `@__arm_xr` again — the build
          comes out byte-identical. The intrinsic yields the thread-local address as a real SSA value that
          cannot be folded away.
        10-21 THIS WAS FIRST WRITTEN AS A FIX FOR `movzbl -0x51, %r12d` IN fn_10028fa00, BLAMED ON A DROPPED
          TLV RELOCATION. It is not: that instruction is the lowering of `ldurb w8, [x29, #-81]` with %x29 = 0,
          i.e. x29 missing from XR_FULL_IN/OUT above, and it survived this change byte-for-byte. Keep the single
          base because it is cheaper, not because it fixes anything — the relocation was never dropped (every
          ___arm_xr@TLVP reloc in the module is present; an absolute operand means a guest register read ZERO)."""
    out = [f'  %xrb{tag} = call ptr @llvm.threadlocal.address.p0(ptr @__arm_xr)']
    for r in regs:
        if r == 'nzcv':
            for k, f in enumerate('NZCV'):
                p = f'%xr{tag}_{f}p'
                out.append(f'  {p} = getelementptr inbounds i8, ptr %xrb{tag}, i64 {248 + k}')
                if put:
                    out += [f'  %xr{tag}_{f}b = load i1, ptr %{f}', f'  %xr{tag}_{f}z = zext i1 %xr{tag}_{f}b to i8',
                            f'  store i8 %xr{tag}_{f}z, ptr {p}']
                else:
                    out += [f'  %xr{tag}_{f}l = load i8, ptr {p}', f'  %xr{tag}_{f}t = trunc i8 %xr{tag}_{f}l to i1',
                            f'  store i1 %xr{tag}_{f}t, ptr %{f}']
            continue
        n = int(r[1:]); p = f'%xr{tag}_{r}p'
        if r[0] == 'x':
            out.append(f'  {p} = getelementptr inbounds i8, ptr %xrb{tag}, i64 {8 * n}')
            out += ([f'  %xr{tag}_{r} = load i64, ptr %{r}', f'  store i64 %xr{tag}_{r}, ptr {p}'] if put else
                    [f'  %xr{tag}_{r} = load i64, ptr {p}', f'  store i64 %xr{tag}_{r}, ptr %{r}'])
        else:
            out.append(f'  {p} = getelementptr inbounds i8, ptr %xrb{tag}, i64 {256 + 16 * n}')
            out += ([f'  %xr{tag}_{r} = load <16 x i8>, ptr %{r}', f'  store <16 x i8> %xr{tag}_{r}, ptr {p}, align 16'] if put else
                    [f'  %xr{tag}_{r} = load <16 x i8>, ptr {p}, align 16', f'  store <16 x i8> %xr{tag}_{r}, ptr %{r}'])
    return out


def build(specs, binds=None):
    """specs: [(path, export_name_or_None, nargs)] -> one .ll holding every function.
        TWO PASSES: addresses are collected FIRST so a `bl` can resolve a callee that
          appears LATER in the list. One pass would make linkage order-dependent, which
          is the kind of bug that looks like a miscompile.
        R5 `binds` maps a cross-image target address to a NATIVE x86-64 symbol."""
    binds = dict(binds or {})
    loaded = [(parse(open(p).read()), nm, na) for p, nm, na in specs]
    known = {ins[0][0] for ins, _, _ in loaded}
    out = [_module_head()]
    used = {}
    for ins, nm, na in loaded:
        L = Lifter(ins, nm or f'fn_{ins[0][0]:x}', known, binds)
        out.append(L.define())
        if nm: out.append(export(nm, ins[0][0], na))
        #  R12 THE C BOUNDARY, for EVERY function and not just the named ones. C cannot
        #    spell `{ i64, <2 x i64> }` the way LLVM returns it, and a C prototype that gets
        #    it wrong is silent. `x_fn_<addr>` is the 8-integer-argument door; the raw
        #    `fn_<addr>` is for translated code calling translated code.
        out.append(export(f'x_fn_{ins[0][0]:x}', ins[0][0], 8))
        used.update(L.used_binds)
    #  A BIND REACHED ONLY THROUGH THE fnmap IS STILL A SYMBOL THIS MODULE NAMES. `used` is
    #    filled by emit_bind, i.e. by DIRECT calls, so a target that is only ever reached
    #    INDIRECTLY (through a GOT slot and a blraa) landed in the fnmap with no declare and
    #    llvm-as rejected the module. R8-j's linkage arm asserts over `call` sites and could
    #    not see it — an fnmap row is a reference too.
    for a, b in binds.items():
        if b['sym'] not in used:
            used[b['sym']] = (b['ret'], bind_kinds(b))
    #  R5 declare only the natives actually CALLED. An unused declare is legal but it
    #    would make the module claim a dependency the code does not have.
    for sym, (ret, kinds) in sorted(used.items()):
        #  R14 the declared signature is the REAL one. `declare double @log2(i64)`
        #    links against the host's log2 and passes the argument in rdi.
        out.append(f'declare {ret} @{sym}({", ".join(BIND_TY[c] for c in kinds)})')
    #  R5 THE DISPATCH MAP — ARM address -> function pointer, for `blr`/`blraa`/`br`.
    #    An indirect call has only a runtime address, so the address->code mapping that
    #    the two-pass linker does statically has to exist at runtime too. Sorted, so the
    #    shim can binary-search it.
    #     BOUND STUBS ARE IN HERE TOO, and they are called through an 8-arg i64
    #       signature. That is safe on SysV for argc<=6 (extra register args are ignored)
    #       and every bind has argc<=3 — but a void/i32 bind reached INDIRECTLY yields a
    #       garbage x0, because the shim cannot know the callee's return type. Direct
    #       calls (emit_bind) do know, and get it right.
    fnmap = {ins[0][0]: f'fn_{ins[0][0]:x}' for ins, _, _ in loaded}
    for a, b in binds.items():
        #  R14 NEVER A BARE FP SYMBOL IN THE DISPATCH MAP — see bind_thunk().
        if bind_is_fp(b):
            out.append(bind_thunk(b['sym'], b['ret'], bind_kinds(b)))
            fnmap[a] = f'__arm2x86_bindthunk_{b["sym"]}'
        else:
            fnmap[a] = b['sym']
    rows = ', '.join(f'{{ i64, ptr }} {{ i64 {a}, ptr @{n} }}' for a, n in sorted(fnmap.items()))
    out.append(f'@__arm2x86_fnmap = constant [{len(fnmap)} x {{ i64, ptr }}] [{rows}]')
    out.append(f'@__arm2x86_fnmap_n = constant i64 {len(fnmap)}')
    return '\n'.join(out)

# ── selftest ─────────────────────────────────────────────────────────────────
def selftest():
    fails = 0
    def arm(name, got, want):
        nonlocal fails
        ok = got == want
        if not ok: fails += 1
        print(f'  [{"ok" if ok else "FAIL"}] {name}: got {got!r} want {want!r}')
    print('arm2x86 --selftest')
    arm(' a shift amount is DECIMAL (#15 is fifteen, not 21)', imm('#15'), 15)
    arm(' a data immediate is HEX (#0xfff0 is 65520)', imm('#0xfff0'), 65520)
    arm(' a negative immediate is two-complement 64-bit', imm('#-0xfff1'), (-65521) & M64)
    arm(' a bracket operand is ONE operand, not three',
        split_ops('x9, [x8, x9, lsl #3]'), ['x9', '[x8, x9, lsl #3]'])
    arm('post-index is a third operand', split_ops('w8, [x2], #0x1'), ['w8', '[x2]', '#0x1'])
    arm('a comment is stripped before parsing',
        parse('1000:\tmov\tx9, #-0xfff1            ; =-65521')[0][2], ['x9', '#-0xfff1'])
    # ── R2 arms cross-function linkage ────────────────────────────────────
    def ll(text, known=()):
        ins = parse(text)
        return Lifter(ins, 'f', known).define()

    def strip_nan(ir):
        """ 10-03: drop the ARM-NaN snapshot/fix seams, so a SHAPE arm measures the emitter it was written for. The
           NaN rules themselves are judged by the M4 instruction certifier (ops/risu), not by IR shape."""
        return re.sub(r'; --- arm-nan (?:snapshot|fix) ---.*?; --- arm-nan end ---', '', ir, flags=re.S)

    def vloads(text, known=()):
        """ COUNT ONLY THE INSTRUCTION'S OWN VECTOR READS. R12's epilogue loads %v0 to
           return it (AAPCS64 returns floats and vectors in v0), so a module-wide count of
           `load <16 x i8>` is one too high for every probe that ends by falling off — and
           it silently shifted four arms whose claim is about register reads, not the ABI."""
        m = strip_nan(ll(text, known))
        return m[:m.index('; --- R12 epilogue')].count('load <16 x i8>')

    #  THE ARM THAT CATCHES THE INVERTED STATE CHECK. `adds`/`cmn` stored C=false
    #    unconditionally; inflateStateCheck reads it via `cset w0, lo`.
    body = ll('1000:\tcmn\tw8, #0x20\n1004:\tcset\tw0, lo\n1008:\tret')
    #  THE ARM ITSELF WAS WRONG FIRST TIME: `store i1 false, ptr %C` also appears in the
    #    entry block as the flag INITIALISER, so the naive `in body` matched the wrong line
    #    and read as a failure. Count it: exactly one (the init), plus a COMPUTED store.
    arm(' cmn computes a REAL carry, never a constant false',
        body.count('store i1 false, ptr %C'), 1)
    arm(' cmn stores a computed carry into %C',
        any(l.strip().startswith('store i1 %t') and 'ptr %C' in l for l in body.splitlines()), True)
    arm(' cmn+cset emits an unsigned-wrap test at 32 bits',
        'icmp ult i64' in body and '4294967295' in body, True)

    arm(' retab returns like ret (PAC auth is a no-op on x86)',
        f'ret {ABI_RET}' in ll('1000:\tretab'), True)

    #  a bl INTO the translated set becomes a real call…
    called = ll('1000:\tbl\t0x2000 <_f>\n1004:\tret', known={0x2000})
    arm(' a bl into the set becomes a real LLVM call (ABI handed to the backend)',
        f'call {ABI_RET} @fn_2000(' in called and '@__arm2x86_unimplemented' not in called, True)
    arm(' the shared stack pointer is PUBLISHED before the call',
        'store i64 %t' in called and '@__arm_sp' in called, True)
    #  …and a bl OUT of it still aborts. The guard, measured in BOTH directions.
    outside = ll('1000:\tbl\t0x9000 <_g>\n1004:\tret', known={0x2000})
    arm(' a bl OUT of the set still ABORTS loudly',
        '@__arm2x86_unimplemented(i64 36864)' in outside and f'call {ABI_RET} @fn_' not in outside, True)

    arm(' b into another translated function is a TAIL CALL',
        f'call {ABI_RET} @fn_2000(' in ll('1000:\tb\t0x2000 <_f>', known={0x2000}), True)

    #  sxtw vs uxtw — uxtw worked by accident, sxtw did not
    arm(' sxtw SIGN-extends a 32-bit index', 'sext i32' in ll('1000:\tadd\tx1, x2, w3, sxtw'), True)
    arm(' uxtw zero-extends the same operand', 'zext i32' in ll('1000:\tadd\tx1, x2, w3, uxtw'), True)
    arm(' ldrsw SIGN-extends (zext would make a negative index +4 billion)',
        'sext i32' in ll('1000:\tldrsw\tx8, [x9]'), True)
    arm(' ldur is the unscaled form of the same load',
        'load i64' in ll('1000:\tldur\tx8, [x9, #-0x8]'), True)
    #  THE 32-BIT PAIR, both halves of the bug, measured in both directions
    _lw = ll('1000:\tldp\tw8, w9, [x0]')
    _sw = ll('1000:\tstp\tw8, w9, [x0]')
    _lx = ll('1000:\tldp\tx8, x9, [x0]')
    #  COUNT THE MEMORY ACCESSES, do not test for the ABSENCE of `load i64` — reading the
    #    base register emits one of those itself, which failed a correct fix once already.
    arm(' ldp of a w PAIR strides by 4, not 8', 'add i64 %t1, 4' in _lw, True)
    arm(' ldp of a w pair LOADS 4 BYTES x2 (i64 would read past the field)',
        len(re.findall(r'load (?:atomic )?i32', _lw)), 2)   # 10-05: guest accesses are `load atomic ... monotonic`
    arm(' ...and each half is zero-extended into the 64-bit register',
        _lw.count('zext i32'), 2)
    arm(' stp of a w pair STORES 4 BYTES x2 (i64 would clobber the next field)',
        len(re.findall(r'store (?:atomic )?i32', _sw)), 2)
    arm(' an x pair is UNCHANGED: strides by 8, no 32-bit access',
        'add i64 %t1, 8' in _lx and _lx.count('load i32') == 0, True)
    arm(' a q pair still strides by 16 (the earlier regression stays fixed)',
        ', 16' in ll('1000:\tstp\tq0, q1, [x8, #0x10]'), True)

    arm(' brk TRAPS — it is not a nop',
        'unreachable' in ll('1000:\tbrk\t#0x1'), True)
    arm(' a brk is a TRAP, not an untranslated call (separate symbols)',
        '@__arm2x86_trap(' in ll('1000:\tbrk\t#0x1')
        and '@__arm2x86_unimplemented(' not in ll('1000:\tbrk\t#0x1'), True)
    _sv = ll('1000:\tmov\tx16, #0x4\n1004:\tsvc\t#0x80\n1008:\tret')
    arm(' R39 svc lowers to the runtime syscall, carrying x16 and the site address',
        ('@__arm2x86_svc(' in _sv, '4100' in _sv or 'i64 4100)' in _sv or '0x1004' in _sv.lower()
         or ', i64 4100' in _sv), (True, True))
    arm(' R39 svc is neither a gap nor a trap',
        ('@__arm2x86_unimplemented(' in _sv, '@__arm2x86_trap(' in _sv), (False, False))
    arm(' R39 svc writes the carry the kernel returned (b.lo reads it)',
        'store i1' in _sv.split('@__arm2x86_svc(')[1] and 'ptr %C' in _sv.split('@__arm2x86_svc(')[1], True)
    arm(' R39 svc writes back x0 AND x1 and no other GPR',
        sorted(set(__import__('re').findall(r'store i64 %\w+, ptr %(x\d+)', _sv.split('@__arm2x86_svc(')[1]))),
        ['x0', 'x1'])
    _nf = lambda t: '@__arm2x86_nofeature(' in ll(f'1000:\t{t}\n1004:\tret')
    arm(' R39 ops absent on the M4 (B16B16, SME2p1, MOP4) abort BY NAME, not as a gap',
        tuple(_nf(t) for t in ('bfmax\tz2.h, p0/m, z2.h, z1.h', 'bfmul\tz17.h, z2.h, z6.h',
                               'bfmin\tz16.h, p0/m, z16.h, z3.h', 'movaz\tz4.b, za0h.b[w13, 0]',
                               'fmop4a\tza0.s, z0.s, z16.s')), (True,) * 5)
    arm(' R39 the absent-feature gate does not swallow a real SVE op (fmax still lowers)',
        _nf('fmax\tz2.h, p0/m, z2.h, z1.h'), False)
    arm(' R39 real by-element sdot/fmlal2 words from libwebrtc/libBNNS lift with their raw Q bit',
        tuple('@__arm2x86_unimplemented(' not in ll(t) for t in
              ('1000: 4f83e0c7     \tsdot\tv7, v6, v3[0]\n1004:\tret',
               '1000: 6f90839a     \tfmlal2\tv26, v28, v0[1]\n1004:\tret')), (True, True))
    arm(' autda writes its destination (identity, but written)',
        'store i64' in ll('1000:\tautda\tx8, x9'), True)

    #  two-pass linkage: a callee declared LATER must still resolve
    import tempfile, os
    d = tempfile.mkdtemp()
    a = os.path.join(d, 'a.txt'); b = os.path.join(d, 'b.txt')
    open(a, 'w').write('1000:\tbl\t0x2000 <_late>\n1004:\tret\n')
    open(b, 'w').write('2000:\tmov\tx0, #0x7\n2004:\tret\n')
    mod = build([(a, 'caller', 1), (b, None, 0)])
    #  THE ARM ITSELF WAS WRONG FIRST TIME: the prelude DECLARES __arm2x86_unimplemented,
    #    so `not in mod` was never true. Count CALL SITES, which is the actual claim.
    arm(' a bl resolves a callee that appears LATER in the unit (two-pass)',
        f'call {ABI_RET} @fn_2000(' in mod and mod.count('call void @__arm2x86_unimplemented') == 0, True)
    #  THE EXPECTED COUNT WAS WRONG FIRST TIME (2, not 24) and the arm caught me, not the
    #    code: this unit has THREE exports — the named `caller` plus one x_fn_ door per
    #    lifted function — and each passes 8 zeroed vector registers. State the arithmetic.
    arm(' R12 every lifted function gets an 8-integer-argument C door',
        (mod.count('define i64 @x_fn_2000(i64 %p0, i64 %p1, i64 %p2, i64 %p3, '
                   'i64 %p4, i64 %p5, i64 %p6, i64 %p7)'),
         mod.count('define i64 @x_fn_'),
         mod.count('<2 x i64> zeroinitializer')), (1, 2, 3 * 8 + 8))
    #  R35 + 8: the prelude's __arm2x86_call_arm (native → translated door) zeroes v0-v7 too.
    arm(' every function in the unit gets exactly one define',
        mod.count(f'define {ABI_RET} @fn_'), 2)

    # ── R5 CROSS-IMAGE BINDS ──────────────────────────────────────────────
    c = os.path.join(d, 'c.txt')
    open(c, 'w').write('1000:\tbl\t0x1980f46f0 <stub>\n1004:\tret\n')
    B = {0x1980f46f0: {'sym': 'memmove', 'argc': 3, 'ret': 'i64',
                       'cache': '_platform_memmove'}}
    mb = build([(c, 'bindcaller', 3)], B)
    arm(' R5 a bl to a bound stub calls the NATIVE symbol',
        'call i64 @memmove(' in mb, True)
    arm(' R5 the bind is declared with its TRUE arity, not 8',
        'declare i64 @memmove(i64, i64, i64)' in mb, True)
    arm(' R5 a bound call passes exactly 3 args', mb.count('@memmove(i64 %'), 1)
    #  THE GUARD MEASURED IN BOTH DIRECTIONS — it must ALLOW the bind and FIRE without it
    arm(' R5 a bound call does NOT abort',
        mb.count('call void @__arm2x86_unimplemented'), 0)
    mu = build([(c, 'bindcaller', 3)], {})
    arm(' R5 an UNBOUND cross-image call STILL aborts loudly',
        mu.count('call void @__arm2x86_unimplemented'), 1)
    arm(' R5 an unbound module declares no native symbol',
        'declare i64 @memmove' in mu, False)

    #  a 32-bit return must be zext'd, never read as i64 (Apple arm64: top half undefined)
    open(c, 'w').write('1000:\tbl\t0x1980f5070 <stub>\n1004:\tret\n')
    mi = build([(c, 'closecaller', 1)],
               {0x1980f5070: {'sym': 'close', 'argc': 1, 'ret': 'i32', 'cache': 'close'}})
    arm(' R5 an i32 bind is called as i32 and zext to i64',
        'call i32 @close(' in mi and 'zext i32' in mi, True)

    #  a void bind must not invent a return value
    open(c, 'w').write('1000:\tbl\t0x1980f4630 <stub>\n1004:\tret\n')
    mvd = build([(c, 'freecaller', 1)],
                {0x1980f4630: {'sym': 'free', 'argc': 1, 'ret': 'void', 'cache': 'free'}})
    arm(' R5 a void bind emits `call void` and writes a deterministic x0',
        'call void @free(i64 ' in mvd and 'declare void @free(i64)' in mvd, True)

    #  the runtime address->code map every indirect call needs
    arm(' R5 the module carries an address->function map for dispatch',
        '@__arm2x86_fnmap_n = constant i64' in mb, True)
    arm(' R5 the map holds the translated function AND the bound stub',
        mb.count('{ i64, ptr } { i64 '), 2)
    arm(' R5 the map is sorted by address (the shim binary-searches it)',
        mb.index('i64 4096, ptr') < mb.index('ptr @memmove'), True)

    # ================= R6 — the gap the 2026-09-22 cache sweep measured =================
    #  ORDERED ACCESS. stlr alone was 69.5% of all whole-function failures across
    #    158,888 functions in 40 shared-cache images.
    _st = ll('1000:\tstlr\tw8, [x9]')
    arm(' R6 stlr is a RELEASE store, not a plain store',
        'store atomic i32' in _st and 'release' in _st, True)
    arm(' R6 stlrb stores ONE byte (an i64 store clobbers 7 neighbouring bytes)',
        'store atomic i8' in ll('1000:\tstlrb\tw8, [x9]'), True)
    arm(' R6 ldar is an ACQUIRE load', 'load atomic i64' in ll('1000:\tldar\tx8, [x9]')
        and 'acquire' in ll('1000:\tldar\tx8, [x9]'), True)
    arm(' R6 ldaprb loads ONE byte and zero-extends',
        'load atomic i8' in ll('1000:\tldaprb\tw8, [x9]'), True)
    #  R37 THE EXCLUSIVE MONITOR IS MODELLED (it aborted from R6 until R37). These arms pin
    #    the two properties a plain load/store would lose.
    _lx = ll('1000:\tldxr\tw8, [x9]')
    arm(' R37 ldxr takes a RESERVATION (records its address in the monitor)',
        'ptr @__arm_excl_addr' in _lx and 'load atomic i32' in _lx, True)
    _sx = ll('1000:\tstxr\tw10, w8, [x9]')
    arm(' R37 stxr stores ONLY through cmpxchg, behind the monitor branch (no plain store)',
        ('cmpxchg' in _sx, 'br i1' in _sx, 'store i32' in _sx), (True, True, False))
    arm(' R37 stxp compares BOTH halves as one i128',
        'cmpxchg ptr' in ll('1000:\tstxp\tw3, x2, x4, [x10]') and
        'i128' in ll('1000:\tstxp\tw3, x2, x4, [x10]'), True)
    try:
        ll('1000:\tsdot\tv0, v1, v2[0]'); arm(' R37 by-element sdot WITHOUT raw bytes refuses', False, True)
    except NotImplementedError:
        arm(' R37 by-element sdot WITHOUT raw bytes refuses', True, True)
    arm(' R37 raw Q=0 makes by-element sdot a .2s (0f82e020)',
        parse('     93c: 0f82e020     \tsdot\tv0, v1, v2[0]')[0][1], 'sdot.2s')
    arm(' R37 raw Q=1 makes by-element sdot a .4s (4fa2e020)',
        parse('     8ec: 4fa2e020     \tsdot\tv0, v1, v2[1]')[0][1], 'sdot.4s')

    #  THE LSE ATOMICS
    _la = ll('1000:\tldaddal\tw8, w9, [x10]')
    arm(' R6 ldaddal is an atomicrmw add with acq_rel ordering',
        'atomicrmw add' in _la and 'acq_rel' in _la, True)
    arm(' R6 a bare ldadd is monotonic, not seq_cst',
        'monotonic' in ll('1000:\tldadd\tw8, w9, [x10]'), True)
    _lc = ll('1000:\tldclr\tw8, w9, [x10]')
    arm(' R6 ldclr CLEARS — the operand is complemented before the and',
        'xor i32' in _lc and 'atomicrmw and' in _lc, True)
    arm(' R6 ldset is an or, ldeor an xor',
        ('atomicrmw or' in ll('1000:\tldset\tw8, w9, [x10]'),
         'atomicrmw xor' in ll('1000:\tldeor\tw8, w9, [x10]')), (True, True))
    arm(' R6 ldsmax/ldumin pick the SIGNED vs UNSIGNED rmw op',
        ('atomicrmw max' in ll('1000:\tldsmax\tw8, w9, [x10]'),
         'atomicrmw umin' in ll('1000:\tldumin\tw8, w9, [x10]')), (True, True))
    #  `stadd` is the SAME encoding with the result discarded — it has only two operands,
    #    so writing ops[1] would store the atomic result into the ADDRESS register.
    _sa = ll('1000:\tstaddl\tw8, [x10]')
    arm(' R6 stadd has NO destination register (writing one corrupts the address reg)',
        'atomicrmw add' in _sa and 'store i64' not in _sa.split('atomicrmw')[1].split('; --- R12 epilogue')[0], True)   # rung 6: the epilogue's @__arm_xr hand-back is ABI, not stadd
    arm(' R6 swp is an atomicrmw xchg',
        'atomicrmw xchg' in ll('1000:\tswpal\tw8, w9, [x10]'), True)
    _cs = ll('1000:\tcasal\tw8, w9, [x10]')
    arm(' R6 cas is a cmpxchg returning the OLD value into the compare register',
        'cmpxchg' in _cs and 'extractvalue' in _cs, True)
    arm(' R6 the cmpxchg FAILURE ordering is never stronger than success (LLVM rejects it)',
        'acq_rel acquire' in _cs and not re.search(r'acq_rel (?:acq_rel|release)\b', _cs), True)
    arm(' 10-05 a plain ldr/str is a MONOTONIC atomic (arm64 plain accesses are defined under races; NotAtomic is UB)',
        ('load atomic i64' in ll('1000:\tldr\tx0, [x1]') and 'monotonic' in ll('1000:\tldr\tx0, [x1]'),
         'store atomic i16' in ll('1000:\tstrh\tw0, [x1, #2]')), (True, True))
    arm(' R6 a barrier becomes a fence, not a no-op',
        'fence seq_cst' in ll('1000:\tdmb\tish'), True)

    #  BITFIELD INSERTS — the forms that MERGE
    _bfi = ll('1000:\tbfi\tw8, w9, #4, #8')
    arm(' R6 bfi MERGES — the destination keeps its other bits (ubfiz would zero them)',
        'and i64' in _bfi and 'or i64' in _bfi, True)
    #  ASSERT THE VALUE, NEVER A TEMP NAME. The first version of this arm anchored on
    #    `%t0`, which no lowering emits, and it failed a CORRECT fix — the same trap the
    #    ldp pair arms paid for. The mask IS the specification: 32 bits wide, field cleared.
    arm(' R6 bfi w-form keeps 32 bits of destination, not 64',
        (str(((1 << 32) - 1) & ~(0xff << 4)) in _bfi,
         str(((1 << 64) - 1) & ~(0xff << 4)) in _bfi), (True, False))
    _bx = ll('1000:\tbfxil\tx8, x9, #8, #16')
    arm(' R6 bfxil inserts at bit 0 of the destination (bfi would shift by lsb)',
        'lshr i64' in _bx and 'shl i64' not in _bx, True)

    #  SCALAR FP — 13% of the gap, and the NaN behaviour is the part that hides
    _fc = ll('1000:\tfcmp\td0, d1')
    arm(' R6 fcmp sets V from `uno` — the NaN case the integer flag writer cannot express',
        'fcmp uno double' in _fc and 'ptr %V' in _fc, True)
    arm(' R6 fcmp sets C from NOT olt (C=1 when unordered, not 0)',
        'fcmp olt double' in _fc and 'xor i1' in _fc, True)
    arm(' R6 fcmp against #0.0 reads no second register',
        'fcmp oeq double' in ll('1000:\tfcmp\td0, #0.0'), True)
    arm(' R6 fcvt s->d is an fpext and d->s an fptrunc (never the same op)',
        ('fpext float' in ll('1000:\tfcvt\td0, s1'),
         'fptrunc double' in ll('1000:\tfcvt\ts0, d1')), (True, True))
    arm(' R6 scvtf is sitofp and ucvtf uitofp',
        ('sitofp i64' in ll('1000:\tscvtf\td0, x1'),
         'uitofp i64' in ll('1000:\tucvtf\td0, x1')), (True, True))
    arm(' R6 scvtf with #fbits DIVIDES by 2**fbits (dropping it scales by 256)',
        'fdiv double' in ll('1000:\tscvtf\td0, x1, #8'), True)
    #  THIS ARM USED TO ASSERT 'fptosi double' AND IT PASSED WHILE THE CODE WAS WRONG.
    #    ARM's FCVT* SATURATE; plain fptosi is POISON out of range and on NaN. The arm
    #    could not see it because nothing in it ever went out of range — a success-only
    #    predicate on a failure-only bug. It now asserts the saturating form AND the
    #    ABSENCE of the poisoning one.
    arm(' R6/R8 fcvtzs saturates like ARM — a bare fptosi is poison out of range',
        ('llvm.fptosi.sat.i64.f64' in ll('1000:\tfcvtzs\tx0, d0'),
         ' = fptosi ' in ll('1000:\tfcvtzs\tx0, d0')), (True, False))
    arm(' R6 fcsel selects on the condition flags',
        'select i1' in ll('1000:\tfcsel\td0, d1, d2, eq'), True)
    arm(' R6 fmov d0,#1.0 is a VALUE, not a bit pattern',
        '1.00000000e+00' in ll('1000:\tfmov\td0, #1.00000000'), True)

    # ── R7 — the remaining userland gap, measured from the 40-image cache sweep ──
    def _fma_negpos(txt):
        #  WHICH ARGUMENT of the fma call carries the fneg. This is the whole
        #    specification of the four fmadd forms, and a count of fnegs cannot see it.
        neg = {l.split(' = ')[0].strip() for l in txt.splitlines() if 'fneg double' in l}
        call = [l for l in txt.splitlines() if 'call double @llvm.fma.f64' in l][0]
        args = call.split('(', 1)[1].rsplit(')', 1)[0].split(', ')
        return tuple(i + 1 for i, x in enumerate(args) if x.split()[-1] in neg)

    def _adds(txt, k):
        return any(' = add i64 ' in l and l.rstrip().endswith(f', {k}')
                   for l in txt.splitlines())

    arm(' R7 scalar frintm is FLOOR and frintp is CEIL',
        ('llvm.floor.f64' in ll('1000:\tfrintm\td0, d1'),
         'llvm.ceil.f64' in ll('1000:\tfrintp\td0, d1')), (True, True))
    arm(' R7 frintn is ties-to-EVEN (roundeven); frinta is ties-AWAY (round)',
        ('llvm.roundeven.f64' in ll('1000:\tfrintn\td0, d1'),
         'llvm.round.f64' in ll('1000:\tfrinta\td0, d1')), (True, True))
    arm(' R7 frintn must NOT lower to nearbyint — they agree ONLY in default FPCR mode',
        'nearbyint' in ll('1000:\tfrintn\td0, d1'), False)
    arm(' R7 fmadd is ONE fused llvm.fma, never fmul+fadd (two roundings)',
        ('llvm.fma.f64' in ll('1000:\tfmadd\td0, d1, d2, d3'),
         'fmul double' in ll('1000:\tfmadd\td0, d1, d2, d3')), (True, False))
    arm(' R7 fmsub negates ARG 1 (the product), fnmsub negates ARG 3 (the accumulator)',
        (_fma_negpos(ll('1000:\tfmsub\td0, d1, d2, d3')),
         _fma_negpos(ll('1000:\tfnmsub\td0, d1, d2, d3')),
         _fma_negpos(ll('1000:\tfnmadd\td0, d1, d2, d3'))),
        ((1,), (3,), (1, 3)))
    arm(' R7 fnmul negates the product',
        ('fmul double' in ll('1000:\tfnmul\td0, d1, d2'),
         'fneg double' in ll('1000:\tfnmul\td0, d1, d2')), (True, True))
    #  R17-e THE CLAIM IS THE NaN RULE, NOT THE TYPE SUFFIX. This arm used to read
    #    'llvm.maxnum.f64', and R17-b's routing change made it 'llvm.maxnum.v1f64' — same
    #    meaning, red arm. `maxnum` vs `maximum` is the whole specification here, so that
    #    is what is asserted, and the OPPOSITE spelling must be ABSENT in each case or the
    #    two are indistinguishable.
    _mx = ll('1000:\tfmaxnm\td0, d1, d2'); _mm = ll('1000:\tfmax\td0, d1, d2')
    arm(' R7 fmaxnm QUIETS NaN (maxnum); plain fmax PROPAGATES it (maximum)',
        ('llvm.maxnum.' in _mx, 'llvm.maximum.' in _mx,
         'llvm.maximum.' in _mm, 'llvm.maxnum.' in _mm),
        (True, True, True, False))   #  10-03: fmaxnm also carries `maximum` now — the ARM NaN/±0 selection (arm_nan) is
                                     #    built on it; the M4 instruction certifier is the semantic judge (ops/risu)
    arm(' R7 the VECTOR fmax is maximum too — it was maxnum, and only NaN could tell',
        ('llvm.maximum.v4f32' in ll('1000:\tfmax.4s\tv0, v1, v2'),
         'llvm.maxnum.v4f32' in ll('1000:\tfmax.4s\tv0, v1, v2')), (True, False))
    arm(' R7 fccmp #nzcv is packed N:Z:C:V — #0 sets no literal, #15 sets four',
        (ll('1000:\tfccmp\td0, d1, #4, ne').count('i1 true'),
         ll('1000:\tfccmp\td0, d1, #0, ne').count('i1 true'),
         ll('1000:\tfccmp\td0, d1, #15, ne').count('i1 true')), (1, 0, 4))
    arm(' R7 fccmp models the UNORDERED case (V comes from fcmp uno)',
        'fcmp uno' in ll('1000:\tfccmp\td0, d1, #4, ne'), True)
    arm(' R7 ldpsw SIGN-extends and strides by 4; a plain ldp strides by 8',
        ('sext i32' in ll('1000:\tldpsw\tx8, x9, [x0]'),
         _adds(ll('1000:\tldpsw\tx8, x9, [x0]'), 4),
         _adds(ll('1000:\tldp\tx8, x9, [x0]'), 8)), (True, True, True))
    arm(' R7 an ldp w-pair still ZERO-extends — ldpsw must not have changed it',
        ('zext i32' in ll('1000:\tldp\tw8, w9, [x0]'),
         'sext i32' in ll('1000:\tldp\tw8, w9, [x0]')), (True, False))
    arm(' R7 fcvtms ROUNDS DOWN before converting; fcvtzs does not round at all',
        ('llvm.floor.f64' in ll('1000:\tfcvtms\tx0, d0'),
         'llvm.floor.f64' in ll('1000:\tfcvtzs\tx0, d0')), (True, False))
    arm(' R7 all ten fcvt<mode><sign> forms lift with the right signedness',
        all(('fptosi' if g == 's' else 'fptoui') in ll(f'1000:\tfcvt{m}{g}\tx0, d0')
            for m in 'amnpz' for g in 'su'), True)
    arm(' R7 scvtf/ucvtf from an FP-file register convert the INTEGER lane',
        ('sitofp i64' in ll('1000:\tscvtf\td0, d1'),
         'uitofp i32' in ll('1000:\tucvtf\ts0, s1')), (True, True))
    arm(' R7 ngc adds the CARRY IN — it is sbc from zero, not neg',
        ('load i1, ptr %C' in ll('1000:\tngc\tx0, x1'),
         'zext i1' in ll('1000:\tngc\tx0, x1')), (True, True))
    #  MEASURE THE DELTA, NOT THE TOTAL. The PROLOGUE initialises N/Z/C/V with four
    #    `store i1 false`, so a raw count reads 4 for an instruction that writes no
    #    flags at all and this arm "caught" a bug that was never there. Same trap as the
    #    bfi arm on 2026-09-22: assert the measured quantity, never the incidental text.
    _flag0 = ll('1000:\tmov\tx0, x1').count('store i1')
    arm(' R7 ngc writes NO flags; ngcs writes all four (over the prologue baseline)',
        (ll('1000:\tngc\tx0, x1').count('store i1') - _flag0,
         ll('1000:\tngcs\tx0, x1').count('store i1') - _flag0), (0, 4))
    arm(' 10-20 mrs tpidrro_el0 adds the measured TSD offset to %gs:0 (the array, not pthread_self)',
        ('@__arm_tsd_off' in ll('1000:\tmrs\tx0, tpidrro_el0'), '@__arm_tsd_off = external global i64' in PRELUDE),
        (True, True))
    arm(' R7 mrs tpidrro_el0 is a %gs load (addrspace 256), not a stubbed constant',
        'addrspace(256)' in ll('1000:\tmrs\tx0, tpidrro_el0'), True)
    arm(' R7 movi.4s #0x1,lsl #8 splats 0x100 — dropping the shift splats 0x1',
        ('i32 256' in ll('1000:\tmovi.4s\tv0, #0x1, lsl #8'),
         'i32 1,' in ll('1000:\tmovi.4s\tv0, #0x1, lsl #8')), (True, False))
    arm(' R7 mvni shifts BEFORE complementing: ~0x100 = -257, not ~0x1 << 8',
        ('i32 -257' in ll('1000:\tmvni.4s\tv0, #0x1, lsl #8'),
         'i32 -512' in ll('1000:\tmvni.4s\tv0, #0x1, lsl #8')), (True, False))
    arm(' R7 msl shifts in ONES: movi.4s #0x2, msl #8 is 0x2ff',
        'i32 767' in ll('1000:\tmovi.4s\tv0, #0x2, msl #8'), True)
    arm(' R7 fmov.2d #1.0 splats a double VALUE, not the integer 1',
        ('double 1.00000000e+00' in ll('1000:\tfmov.2d\tv0, #1.00000000'),
         'i64 1,' in ll('1000:\tfmov.2d\tv0, #1.00000000')), (True, False))
    arm(' R7/R8 vector int<->fp converts name BOTH element types explicitly',
        ('sitofp <4 x i32>' in ll('1000:\tscvtf.4s\tv0, v1'),
         'llvm.fptoui.sat.v2i64.v2f64' in ll('1000:\tfcvtzu.2d\tv0, v1')), (True, True))
    arm(' R8 the VECTOR conversion saturates too — a bare fptoui is poison',
        ' = fptoui ' in ll('1000:\tfcvtzu.2d\tv0, v1'), False)
    arm(' R7 xtn.4h narrows FROM .4s — the arrangement names the destination',
        ('trunc <4 x i32>' in ll('1000:\txtn.4h\tv0, v1'),
         'to <4 x i16>' in ll('1000:\txtn.4h\tv0, v1')), (True, True))
    arm(' R7 fcvtn narrows and fcvtl widens, both derived from the destination',
        ('fptrunc <4 x float>' in ll('1000:\tfcvtn.4h\tv0, v1'),
         'fpext <4 x half>' in ll('1000:\tfcvtl.4s\tv0, v1')), (True, True))
    arm(' R7 umaxv folds 4 lanes with 3 compares and does NOT widen the element',
        (ll('1000:\tumaxv.4s\tv0, v1').count('icmp ugt i32'),
         'insertelement <1 x i32>' in ll('1000:\tumaxv.4s\tv0, v1')), (3, True))
    arm(' R7 sminv compares SIGNED where uminv compares unsigned',
        ('icmp slt' in ll('1000:\tsminv.4s\tv0, v1'),
         'icmp ult' in ll('1000:\tuminv.4s\tv0, v1')), (True, True))
    #  COUNT THE REGISTER READS, NOT THE SHUFFLES. vwr emits a shufflevector of its
    #    own to pad a 64-bit write out to the 16-byte slot, so "no shufflevector" is a
    #    claim about vwr, not about how many registers faddp read.
    arm(' R7 faddp.2d reads ONE register; the 3-operand form reads two',
        (vloads('1000:\tfaddp.2d\td0, v1'),
         vloads('1000:\tfaddp.4s\tv0, v1, v2'),
         'insertelement <1 x double>' in ll('1000:\tfaddp.2d\td0, v1')), (1, 2, True))
    arm(' R7 faddp.4s with THREE operands is the pairwise vector form',
        strip_nan(ll('1000:\tfaddp.4s\tv0, v1, v2')).count('shufflevector'), 2)
    arm(' R7 the SCALAR intrinsics are declared — llvm.floor.f64 != llvm.floor.v2f64',
        ('declare double @llvm.floor.f64(double)' in _vec_declares(),
         'declare double @llvm.roundeven.f64(double)' in _vec_declares(),
         'declare double @llvm.maximum.f64(double, double)' in _vec_declares()),
        (True, True, True))

    #  R7 GUARDS MEASURED IN BOTH DIRECTIONS — each of these must FIRE.
    for _bad, _why in (
            ('mrs\tx0, fpsr', 'an mrs with NO x86 equivalent'),   # fpcr is modelled since 10-03; fpsr is not
            ('movi.4s\tv0, #0x1, ror #8', 'a movi shift that is neither lsl nor msl')):
        _name = f' R7 {_why} ABORTS rather than lifting something plausible'
        try:
            Lifter(parse(f'1000:\t{_bad}'), 'x').module(0)
            arm(_name, False, True)
        except NotImplementedError:
            arm(_name, True, True)

    #  R9 SUPERSEDES TWO R7 ARMS. `xtn2.8h` and `fcvtl2.4s` were in the list above
    #    because R7 had no high-half machinery and aborting was the only honest answer.
    #    R9 has it, so the requirement inverted: they must now LIFT, and lift the RIGHT
    #    half. These are the replacements, on the new contract.
    _x2 = ll('1000:\txtn2.8h\tv0, v1')
    _x1 = ll('1000:\txtn.4h\tv0, v1')
    arm(' R9 (was R7-aborts) xtn2 lifts and READS ITS DESTINATION to keep the low half',
        (_x2.count('load <16 x i8>') > _x1.count('load <16 x i8>'),
         'trunc <4 x i32>' in _x2), (True, True))
    _c2 = ll('1000:\tfcvtl2.4s\tv0, v1')
    arm(' R9 (was R7-aborts) fcvtl2 lifts and reads lanes 4-7 of its .8h source',
        ('<4 x i32> <i32 4, i32 5, i32 6, i32 7>' in _c2, 'fpext <4 x half>' in _c2),
        (True, True))

    # ═══ R8 — the 170-function tail measured after R7 ═══════════════════════════
    _f0 = ll('1000:\tmov\tx0, x1').count('store i1')
    arm(' R8 fcvtzs into an FP register writes the VECTOR file, not a GPR',
        ('insertelement <1 x i32>' in ll('1000:\tfcvtzs\ts0, s0'),
         'store <16 x i8>' in ll('1000:\tfcvtzs\ts0, s0')), (True, True))
    arm(' R8 the FIXED-POINT form scales by 2^fbits — dropping it is off by that factor',
        ('fmul double' in ll('1000:\tfcvtzu\td31, d31, #0x1'),
         'fmul double' in ll('1000:\tfcvtzu\td31, d31')), (True, False))
    arm(' R8 vector fcvtns ROUNDS ties-to-even first; fcvtzs does not round at all',
        ('llvm.roundeven.v2f64' in ll('1000:\tfcvtns.2d\tv0, v1'),
         'llvm.roundeven.v2f64' in ll('1000:\tfcvtzs.2d\tv0, v1')), (True, False))
    #  THE ROUTING GAP — 40 of the 170. The arrangement is on the REGISTERS, not the
    #    mnemonic, so the `mn.arr` dispatch never saw these at all.
    arm(' R8 the two-arrangement fcvtl widens 2s->2d (dispatch never saw this form)',
        ('fpext <2 x float>' in ll('1000:\tfcvtl\tv0.2d, v0.2s'),
         'to <2 x double>' in ll('1000:\tfcvtl\tv0.2d, v0.2s')), (True, True))
    arm(' R8 the two-arrangement fcvtn narrows 2d->2s',
        'fptrunc <2 x double>' in ll('1000:\tfcvtn\tv0.2s, v0.2d'), True)
    arm(' R8 fcvtl v0.4s, v0.4h widens HALVES — not the 2s source of the 2d form',
        'fpext <4 x half>' in ll('1000:\tfcvtl\tv0.4s, v0.4h'), True)
    arm(' R8 adc adds the CARRY IN — dropping it is a plain add',
        ('load i1, ptr %C' in ll('1000:\tadc\tx0, x1, x2'),
         ll('1000:\tadc\tx0, x1, x2').count(' = add i64')), (True, 2))
    arm(' R8 adc writes NO flags (measured against the prologue baseline)',
        ll('1000:\tadc\tx0, x1, x2').count('store i1') - _f0, 0)
    arm(' R8 sbc INVERTS the addend — ARM carry means NO borrow, so it is not -C',
        'xor i64' in ll('1000:\tsbc\tx0, x1, x2'), True)
    arm(' R8 extr at shift 0 returns the low register — `shl i64 x, 64` is poison',
        ('shl i64' in ll('1000:\textr\tx0, x1, x2, #0'),
         'shl i64' in ll('1000:\textr\tx0, x1, x2, #13')), (False, True))
    arm(' R8 eor3 is two xors, no intrinsic',
        ll('1000:\teor3.16b\tv0, v1, v2, v3').count(' = xor <16 x i8>'), 2)
    arm(' R8 ushll.2d widens FROM 2s — reading it as 2d takes the wrong lanes',
        ('zext <2 x i32>' in ll('1000:\tushll.2d\tv0, v1, #0x0'),
         'to <2 x i64>' in ll('1000:\tushll.2d\tv0, v1, #0x0')), (True, True))
    arm(' R8 sshll sign-extends where ushll zero-extends',
        ('sext <4 x i16>' in ll('1000:\tsshll.4s\tv0, v1, #0x2'),
         'zext <4 x i16>' in ll('1000:\tushll.4s\tv0, v1, #0x2')), (True, True))
    arm(' R8 ssra ACCUMULATES into the destination — without it, it is a plain sshr',
        ('ashr <2 x i64>' in ll('1000:\tssra.2d\tv6, v1, #0x7'),
         ' = add <2 x i64>' in ll('1000:\tssra.2d\tv6, v1, #0x7')), (True, True))
    arm(' R8 usra shifts LOGICALLY where ssra shifts arithmetically',
        ('lshr <2 x i64>' in ll('1000:\tusra.2d\tv2, v1, #0x1'),
         'ashr <2 x i64>' in ll('1000:\tusra.2d\tv2, v1, #0x1')), (True, False))
    #  ARM DEFINES AN OVER-WIDTH SHIFT AS ZERO; LLVM CALLS IT POISON. The selects are
    #    the whole point of the arm — the same shape as tbl's out-of-range lane index.
    arm(' R8 ushl by a register CLAMPS — an over-width shift is 0 on ARM, poison in LLVM',
        (ll('1000:\tushl.2s\tv0, v0, v1').count('select <2 x i1>'),
         'icmp ult <2 x i32>' in ll('1000:\tushl.2s\tv0, v0, v1')), (3, True))
    arm(' R8 ushl reads the shift amount as a SIGNED byte — negative shifts right',
        ('ashr <2 x i32>' in ll('1000:\tushl.2s\tv0, v0, v1'),
         'lshr <2 x i32>' in ll('1000:\tushl.2s\tv0, v0, v1')), (True, True))
    arm(' R8 cmlt/cmle exist ONLY against zero and now lift',
        ('icmp slt <8 x i8>' in ll('1000:\tcmlt.8b\tv0, v0, #0'),
         'icmp sle <4 x i32>' in ll('1000:\tcmle.4s\tv5, v2, #0')), (True, True))
    arm(' R8 cmtst tests (a AND b) != 0',
        (' = and <4 x i32>' in ll('1000:\tcmtst.4s\tv0, v0, v2'),
         'icmp ne <4 x i32>' in ll('1000:\tcmtst.4s\tv0, v0, v2')), (True, True))
    arm(' R8 facge compares MAGNITUDES — two fabs calls, not a bare fcmp',
        (ll('1000:\tfacge.2d\tv4, v1, v0').count('llvm.fabs.v2f64'),
         'fcmp oge' in ll('1000:\tfacge.2d\tv4, v1, v0')), (2, True))
    arm(' R8 fcmle/fcmlt compare against #0.0 and write an INTEGER mask',
        ('fcmp ole <2 x float>' in ll('1000:\tfcmle.2s\tv1, v0, #0.0'),
         'sext <2 x i1>' in ll('1000:\tfcmle.2s\tv1, v0, #0.0')), (True, True))
    #  R17-e same re-anchoring: the claim is "subtract, then take the magnitude",
    #    which holds whether the scalar form is spelled f32 or v1f32.
    _fs = ll('1000:\tfabd\ts8, s8, s0'); _fv = ll('1000:\tfabd.2d\tv0, v0, v1')
    arm(' R8 fabd is |a-b| — an fsub then fabs, scalar and vector alike',
        ('llvm.fabs.' in _fs, 'fsub' in _fs,
         'llvm.fabs.' in _fv, 'fsub' in _fv), (True, True, True, True))
    #  A RAW shufflevector COUNT MEASURES vrd/vwr, NOT THE INSTRUCTION. A 64-bit
    #    arrangement narrows on every read and pads on every write, so `umaxp.2s` reads 5
    #    and an ordinary `add.2s` reads 3. The QUANTITY THE ARM IS ABOUT is the difference:
    #    the two pairwise shuffles. Third time this trap has been paid (bfi, ngc, faddp) —
    #    assert the measured delta, never the incidental text.
    _shuf0 = ll('1000:\tadd.2s\tv0, v0, v0').count('shufflevector')
    arm(' R8 umaxp folds PAIRWISE — two shuffles beyond an ordinary binary op',
        (ll('1000:\tumaxp.2s\tv0, v0, v0').count('shufflevector') - _shuf0,
         'llvm.umax.v2i32' in ll('1000:\tumaxp.2s\tv0, v0, v0')), (2, True))
    arm(' R8 clz.4s uses the VECTOR ctlz, not four scalar ones',
        'llvm.ctlz.v4i32' in ll('1000:\tclz.4s\tv0, v1'), True)
    #  THE ROUTING BUG THE SWEEP BLAMED ON vslot: the 3-operand arm read the immediate
    #    and the shift as REGISTERS, so the error named vslot and the bug was above it.
    arm(' R8 orr with an immediate is DESTRUCTIVE and two-operand (it read v0, not a 3rd reg)',
        ('load <16 x i8>' in ll('1000:\torr.4s\tv0, #0x3f, lsl #24'),
         ' = or <4 x i32>' in ll('1000:\torr.4s\tv0, #0x3f, lsl #24')), (True, True))
    arm(' R8 orr immediate applies the SHIFT — #0x3f lsl #24 is 0x3f000000, not 0x3f',
        ('i32 1056964608' in ll('1000:\torr.4s\tv0, #0x3f, lsl #24'),
         'i32 63,' in ll('1000:\torr.4s\tv0, #0x3f, lsl #24')), (True, False))
    arm(' R8 bic immediate COMPLEMENTS the splat where orr does not',
        (' = and <4 x i32>' in ll('1000:\tbic.4s\tv0, #0x7d'),
         ' = and <4 x i32>' in ll('1000:\torr.4s\tv0, #0x7d')), (True, False))
    #  THE ESTIMATES — measured off silicon, not computed as 1/x.
    arm(' R8 frecpe is NOT 1/x — it calls the measured table helper and emits NO fdiv',
        ('@__arm2x86_frecpe_f32' in ll('1000:\tfrecpe.2s\tv3, v2'),
         'fdiv' in ll('1000:\tfrecpe.2s\tv3, v2')), (True, False))
    arm(' R8 frsqrte is NOT 1/sqrt(x) — no sqrt intrinsic appears',
        ('@__arm2x86_frsqrte_f64' in ll('1000:\tfrsqrte.2d\tv3, v1'),
         'llvm.sqrt' in ll('1000:\tfrsqrte.2d\tv3, v1')), (True, False))
    #  ll() RETURNS THE FUNCTION, NOT THE MODULE. The helpers ride in the module, so
    #    asserting on ll() here measured the wrong artifact — it would have read False
    #    forever, whether or not the definitions were emitted. A predicate pointed at the
    #    wrong object cannot fail usefully in EITHER direction.
    _mod = Lifter(parse('1000:\tfrecpe.4s\tv3, v0\n1004:\tret'), 'f').module()
    arm(' R8 the estimate helpers and BOTH measured tables ride in the emitted MODULE',
        ('@__arm2x86_recip_tab' in _mod,
         '@__arm2x86_rsqrt_tab' in _mod,
         'define internal float @__arm2x86_frecpe_f32' in _mod), (True, True, True))
    arm(' R8 the recip table is the ARM pseudocode; the rsqrt table is NOT (130/256 differ)',
        (RECIP_TAB == [(((1 << 19) // (2 * (256 + i) + 1)) + 1) // 2 - 256
                       for i in range(256)],
         len(RSQRT_TAB)), (True, 384))
    arm(' R8 a vector estimate converts EVERY lane, not just lane 0',
        (ll('1000:\tfrecpe.4s\tv3, v0').count('@__arm2x86_frecpe_f32'),
         ll('1000:\tfrecpe.2s\tv3, v2').count('@__arm2x86_frecpe_f32')), (4, 2))

    # ── R8-i the vector list-load family ───────────────────────────────────
    def aborts(t):
        """ MEASURED IN BOTH DIRECTIONS — returns False when the lifter ACCEPTS, so an
           arm built on it can fail either way. A guard that can only report 'blocked'
           is the machine-first-guard failure again (raven.md §7)."""
        try:
            ll(t); return False
        except NotImplementedError:
            return True

    def wrote(ir, reg):
        """Did a COMPUTED value land in %reg?

         v1 WAS `startswith('store i64 ')`, AND ITS NEGATIVE CONTROL CAUGHT IT: the
           prologue zero-initialises every alloca with `store i64 0, ptr %x8`, so the
           predicate read True for an instruction with no writeback at all. An instrument
           that cannot tell the thing from its own scaffolding measures the scaffolding.
           The writeback stores a TEMPORARY; the prologue stores a literal.
         rung 6: the prologue now also loads x8 from @__arm_xr (%xrin_x8) — scaffolding again, excluded by name."""
        return any(l.strip().startswith('store i64 %') and not l.strip().startswith('store i64 %xrin_') and l.strip().endswith(f'ptr %{reg}')
                   for l in ir.splitlines())

    _lane = ll('1000:\tld1.d\t{ v1 }[1], [x0]')
    _ins = [l.strip() for l in _lane.splitlines() if 'insertelement' in l]
    arm(' R8 a lane load writes ONE lane, at the index the text names, and reads the '
        'register first so the OTHER lane survives',
        (len(_ins),
         bool(_ins) and '= insertelement <2 x i64>' in _ins[0]
         and _ins[0].endswith(', i32 1'),
         'load i64, ptr' in _lane), (1, True, True))
    arm(' R8 the lane suffix names the ELEMENT — a .d lane op must never narrow to '
        '<1 x i64>, which would zero the lane it exists to preserve',
        ('<1 x i64>' in _lane, '<2 x i64>' in _lane), (False, True))
    _st = ll('1000:\tst1.b\t{ v2 }[8], [x3]')
    _ext = [l.strip() for l in _st.splitlines() if 'extractelement' in l]
    arm(' R8 st1.b lane 8 extracts lane 8 of SIXTEEN and stores exactly one byte',
        (len(_ext),
         bool(_ext) and '<16 x i8>' in _ext[0] and _ext[0].endswith(', i32 8'),
         any(l.strip().startswith('store i8 ') for l in _st.splitlines())),
        (1, True, True))
    _r = ll('1000:\tld1r.2s\t{ v1 }, [x2]')
    arm(' R8 ld1r REPLICATES — ONE element is loaded and every lane gets it',
        (_r.count('load i32, ptr'), 'zeroinitializer' in _r), (1, True))
    _l4 = ll('1000:\tld4.2d\t{ v0, v1, v2, v3 }, [x9]')
    arm(' R8 ld4 DE-INTERLEAVES: v0 takes memory slots 0 and 4, not 0 and 1',
        ('load <8 x i64>' in _l4,
         '<2 x i32> <i32 0, i32 4>' in _l4,
         '<2 x i32> <i32 3, i32 7>' in _l4), (True, True, True))
    _l1 = ll('1000:\tld1.2d\t{ v0, v1, v2, v3 }, [x9]')
    arm(' R8 a 4-register ld1 is CONSECUTIVE, not de-interleaved — identical text, '
        'completely different instruction',
        ('load <8 x i64>' in _l1, _l1.count('load <2 x i64>')), (False, 4))
    _s4 = ll('1000:\tst4.4s\t{ v0, v1, v2, v3 }, [x8], x9')
    arm(' R8 st4 INTERLEAVES back: lane t of register j lands at slot t*4 + j',
        ('store <16 x i32>' in _s4, _s4.count('insertelement <16 x i32>'),
         ', i32 13' in _s4), (True, 16, True))
    arm(' R8 a REGISTER post-index WRITES BACK — it used to be dropped in silence',
        (wrote(_s4, 'x8'),
         wrote(ll('1000:\tst4.4s\t{ v0, v1, v2, v3 }, [x8]'), 'x8'),
         wrote(ll('1000:\tld1.2d\t{ v0 }, [x8], #0x10'), 'x8')), (True, False, True))
    arm(' R8 an address update we cannot model BLOCKS — it is not a no-op',
        (aborts('1000:\tld1.2d\t{ v0 }, [x8]!'),
         aborts('1000:\tld1.2d\t{ v0 }, [x8], lr'),
         aborts('1000:\tld1.2d\t{ v0 }, [x8], x9')), (True, True, False))

    #  THE ARM THAT WOULD HAVE CAUGHT IT. Not "is @__arm2x86_frecpe_f32 present" —
    #    that only ever catches the symbol I already knew about. The predicate is the
    #    LINKAGE INVARIANT: every symbol the module calls is defined or declared IN the
    #    module. It runs through build(), the path that ships, on mnemonics libz lacks.
    import tempfile as _tf
    _d = _tf.mkdtemp(prefix='a2x_arm_')
    _p = os.path.join(_d, 'f.txt')
    open(_p, 'w').write('1000:\tfrsqrte.2d\tv1, v0\n1004:\tclz.4s\tv2, v1\n'
                        '1008:\tfrecpe.4s\tv3, v2\n100c:\tret\n')
    _bm = build([(_p, 'probe', 0)])
    _called = set(re.findall(r'call [^@\n]*@([\w.]+)\(', _bm))
    _defined = set(re.findall(r'define [^@\n]*@([\w.]+)\(', _bm))
    _declared = set(re.findall(r'declare [^@\n]*@([\w.]+)\(', _bm))
    arm(' R8 every symbol the WHOLE-IMAGE path calls is defined or declared in it',
        (bool(_called), sorted(_called - _defined - _declared)), (True, []))
    #  AND AN fnmap ROW IS A REFERENCE TOO. The arm above scans `call` sites only, so a bind
    #    reached ONLY indirectly — through a GOT slot and a blraa, which is how ___chkstk_darwin
    #    is reached — sat in @__arm2x86_fnmap with no declare and llvm-as refused the module
    #    with "use of undefined value". Measured 2026-09-22; the arm passed while it happened.
    _fb = build([(_p, 'probe', 0)], binds={0x180888cf0: {'sym': 'probe_only_indirect',
                                                         'argc': 8, 'ret': 'i64'}})
    _rows = set(re.findall(r'ptr @([\w.]+) \}', _fb))
    _known = set(re.findall(r'(?:define|declare) [^@\n]*@([\w.]+)\(', _fb))
    arm(' R10 every symbol the fnmap NAMES is defined or declared, even if never called',
        sorted(_rows - _known), [])
    #  10-05 NARROW NATIVE RETURNS (os_unfair_lock_trylock returned rax=0x100 for a BUSY lock on studio; `cbz w0`
    #    read it as acquired). A bool/char/short bind is narrowed and re-extended; an int bind is NOT touched.
    import tempfile as _tf
    with _tf.NamedTemporaryFile('w', suffix='.txt', delete=False) as _nf:
        _nf.write('1000:\tbl\t0x2000\n1004:\tcbz\tw0, 0x1000\n1008:\tret\n'); _np = _nf.name
    _nb = build([(_np, 'nr', 0)], binds={0x2000: {'sym': 'os_unfair_lock_trylock', 'argc': 1, 'args': 'i', 'ret': 'i32', 'cret': 'bool'}})
    _ni = build([(_np, 'nr', 0)], binds={0x2000: {'sym': 'pthread_mutex_trylock', 'argc': 1, 'args': 'i', 'ret': 'i32', 'cret': 'int'}})
    _ns = build([(_np, 'nr', 0)], binds={0x2000: {'sym': 'probe_short', 'argc': 1, 'args': 'i', 'ret': 'i32', 'cret': 'short'}})
    os.unlink(_np)
    arm(' 10-05 a bool native return is cut to i8 and ZERO-extended before cbz sees w0',
        ('trunc i32' in _nb, 'zext i8' in _nb), (True, True))
    arm(' 10-05 negative control: an int native return is passed through untouched (no trunc)',
        'trunc i32' in _ni, False)
    arm(' 10-05 a signed short native return is cut to i16 and SIGN-extended',
        ('trunc i32' in _ns, 'sext i16' in _ns), (True, True))
    _dec = [l for l in _bm.splitlines() if l.startswith('declare ')]
    arm(' R8 each intrinsic is declared ONCE — llvm-as rejects a redefinition outright',
        sorted({l for l in _dec if _dec.count(l) > 1}), [])
    arm(' R8 the measured estimate tables ride in the SHIPPED module, not just the CLI',
        ('@__arm2x86_recip_tab' in _bm,
         'define internal float @__arm2x86_frecpe_f32' in _bm), (True, True))

    # ── R9 THE REMAINING USERLAND GAP ─────────────────────────────────────────
    #  EVERY MNEMONIC BELOW BLOCKED A WHOLE FUNCTION in the 120-image sweep of the real
    #    macOS 27 arm64e shared cache (468,208 functions, 585 blocked, 78 distinct kinds).
    #    The arms assert the SEMANTICS that were being dropped, not merely that the
    #    mnemonic stopped raising — "it lifts" is the weakest possible predicate here.
    def _r9(t):
        return ll(f'1000:\t{t}\n1004:\tret')

    def _r9v(t):
        """ the same probe, counting only the INSTRUCTION's vector reads — see vloads()."""
        return vloads(f'1000:\t{t}\n1004:\tret')

    R9_LIFTS = [
        'prfm\tpldl1keep, [x0, #0x40]', 'prfm\tplislcstrm, [x1]',
        'prfm\tpstl2strm, [x0, x1, lsl #3]', 'prfum\tpldl1keep, [x0, #-0x8]',
        'cnt.16b\tv0, v1', 'cnt.8b\tv0, v1', 'rbit.16b\tv0, v1', 'cls.4s\tv0, v1',
        'uabd.16b\tv0, v1, v2', 'sabd.4s\tv0, v1, v2', 'sabd.2s\tv0, v1, v2',
        'uhadd.8b\tv0, v1, v2', 'uhadd.16b\tv0, v1, v2', 'uhadd.2s\tv0, v1, v2',
        'uhadd.4s\tv0, v1, v2', 'uhadd.4h\tv0, v1, v2',
        'shadd.4s\tv0, v1, v2', 'shadd.4h\tv0, v1, v2', 'shadd.2s\tv0, v1, v2',
        'urhadd.16b\tv0, v1, v2', 'uhsub.8b\tv0, v1, v2', 'shsub.4s\tv0, v1, v2',
        'uaddw.4s\tv0, v1, v2', 'uaddw.8h\tv0, v1, v2', 'uaddw2.2d\tv0, v1, v2',
        'saddw.2d\tv0, v1, v2', 'saddw.4s\tv0, v1, v2', 'saddw2.2d\tv0, v1, v2',
        'usubw.8h\tv0, v1, v2', 'usubw.2d\tv0, v1, v2', 'ssubw2.4s\tv0, v1, v2',
        'uaddlp.8h\tv0, v1', 'saddlp.4s\tv0, v1', 'uadalp.2d\tv0, v1',
        'shrn.2s\tv0, v1, #0x5', 'shrn.8b\tv0, v1, #0x3', 'rshrn.8b\tv0, v1, #0x3',
        'shrn2.4s\tv0, v1, #0x7', 'rshrn2.16b\tv0, v1, #0x1',
        'addhn.4h\tv0, v1, v2', 'raddhn.4h\tv0, v1, v2', 'raddhn.2s\tv0, v1, v2',
        'rsubhn2.8h\tv0, v1, v2', 'subhn.8b\tv0, v1, v2',
        'sshll2.2d\tv0, v1, #0x0', 'sshll2.4s\tv0, v1, #0x2',
        'sshll2.8h\tv0, v1, #0x1', 'ushll2.4s\tv0, v1, #0x3',
        'ushll2.8h\tv0, v1, #0x0', 'ushll2.2d\tv0, v1, #0x0',
        'sxtl.8h\tv0, v1', 'uxtl2.4s\tv0, v1', 'sxtl2.2d\tv0, v1',
        'xtn2.4s\tv0, v1', 'fcvtn2\tv0.4s, v1.2d', 'fcvtl2\tv0.2d, v1.4s',
        'fcvtl2\tv0.4s, v1.8h', 'fcvtn2\tv0.8h, v1.4s',
        'sqxtun.8b\tv0, v1', 'sqxtn2.16b\tv0, v1', 'sqrshrn.8b\tv0, v1, #0x2',
        'sqshrun.4h\tv0, v1, #0x3', 'uqxtn.2s\tv0, v1',
        'sqdmulh.8h\tv0, v1, v2', 'sqdmulh.4s\tv0, v1, v2',
        'sqrdmulh.4s\tv0, v1, v2[1]',
        'udot.4s\tv0, v1, v2', 'sdot.2s\tv0, v1, v2', 'bcax.16b\tv0, v1, v2, v3',
        'frecps.4s\tv0, v1, v2', 'frecps.2s\tv0, v1, v2', 'frsqrts.2s\tv0, v1, v2',
        'addp.2d\td0, v0', 'faddp.2s\ts0, v0',
        'tbl.16b\tv0, { v1, v2 }, v3', 'tbl.8b\tv0, { v1 }, v2',
        'tbl.16b\tv0, { v1, v2, v3, v4 }, v5',
        'tbx.16b\tv0, { v1, v2, v3 }, v4',
        'ror\tx10, x10, x1', 'ror\tw9, w9, #0x8', 'ror\tw9, w9, w2',
        'adcs\tx0, x1, x2', 'sbcs\tw0, w1, w2', 'adcs\tw0, w1, w2',
        'caspal\tx0, x1, x2, x3, [x4]', 'casp\tx6, x7, x8, x9, [x10]',
    ]
    _bad = []
    for _t in R9_LIFTS:
        try:
            _r9(_t)
        except Exception as _e:
            _bad.append(f'{_t}  ->  {type(_e).__name__}: {_e}')
    arm(' R9 every family that blocked a whole function in the sweep now lifts', _bad, [])

    #  THE HIGH-HALF ARM, IN BOTH DIRECTIONS. A widening `2` reading lanes 0,1 gives a
    #    plausible wrong answer — the umull2 trap, already paid for once in this file.
    _hi = _r9('sshll2.2d\tv0, v1, #0x0')
    arm(' R9 sshll2 reads the HIGH half of its source, never the low one',
        ('<2 x i32> <i32 2, i32 3>' in _hi, '<2 x i32> <i32 0, i32 1>' in _hi),
        (True, False))
    _fl2 = _r9('fcvtl2\tv0.2d, v1.4s')
    arm(' R9 fcvtl2 reads the HIGH half of its source',
        '<2 x i32> <i32 2, i32 3>' in _fl2, True)

    #  AND A NARROWING `2` MUST NOT ERASE THE HALF ITS PARTNER JUST WROTE. vwr() zeroes
    #    the upper 64 bits by design, so vwr_hi() has to READ the destination first. The
    #    predicate is DIFFERENTIAL against the non-`2` form, which reads nothing.
    for _b, _hn in (('shrn.2s\tv0, v1, #0x7', 'shrn2.4s\tv0, v1, #0x7'),
                    ('fcvtn\tv0.2s, v1.2d', 'fcvtn2\tv0.4s, v1.2d'),
                    ('xtn.2s\tv0, v1', 'xtn2.4s\tv0, v1')):
        arm(f' R9 the narrowing `2` reads its own destination first: {_hn.split(chr(9))[0]}',
            _r9(_hn).count('load <16 x i8>') > _r9(_b).count('load <16 x i8>'), True)

    #  ror ON A w REGISTER ROTATED IN 64 BITS AND wr() MASKED THE WRAPPED BITS AWAY, so
    #    it executed as a plain `lsr`. Every SHA-256 and BLAKE round is `ror w`.
    _rw = _r9('ror\tw9, w9, #0x8'); _rx = _r9('ror\tx9, x9, #0x8')
    arm(' R9 a 32-bit ror rotates in 32 bits, not 64',
        ('@llvm.fshr.i32' in _rw, '@llvm.fshr.i64' in _rw), (True, False))
    arm(' R9 and a 64-bit ror still rotates in 64', '@llvm.fshr.i64' in _rx, True)

    #  split_ops() DOES NOT PROTECT BRACES, so `{ v1, v2 }` arrived as two operands: the
    #    old code built a ONE-register table from v1 and took the index from 'v2 }'.
    _tb = _r9('tbl.16b\tv0, { v1, v2 }, v3')
    _tbn = _r9v('tbl.16b\tv0, { v1, v2 }, v3')
    arm(' R9 a 2-register tbl reads THREE sources (2 table + 1 index)',
        _tbn, 3)
    arm(' R9 a 4-register tbl reads five, and tbx also reads its destination',
        (_r9v('tbl.16b\tv0, { v1, v2, v3, v4 }, v5'),
         _r9v('tbx.16b\tv0, { v1, v2 }, v3')), (5, 4))

    #  prfm is a HINT — a wrong hint is still a correct program, but an ABORTED hint
    #    killed 83 whole functions, the single biggest blocker in the sweep.
    _pf = _r9('prfm\tpldl2keep, [x0, #0x40]')
    arm(' R9 prfm becomes a real llvm.prefetch with decoded rw/locality/cachetype',
        ('call void @llvm.prefetch.p0(' in _pf, 'i32 0, i32 2, i32 1)' in _pf),
        (True, True))
    arm(' R9 pstl1strm decodes as a WRITE with streaming (zero) locality',
        'i32 1, i32 0, i32 1)' in _r9('prfm\tpstl1strm, [x0]'), True)

    #  SVE/SME MUST ABORT AS AN ARCHITECTURAL LIMIT, NOT CRASH AS A PARSER BUG.
    #    `ldr p5, [x5, #0x45, mul vl]` raised ValueError out of imm(), and the sweep
    #    counted that as translator breakage rather than a register file x86-64 lacks.
    def _how(t):
        try:
            ll(f'1000:\t{t}\n1004:\tret'); return 'LIFTED (must not)'
        except NotImplementedError:
            return 'NotImplementedError'
        except Exception as _e:
            return f'{type(_e).__name__} (must be NotImplementedError)'

    def _s2(t):
        """The lifted BODY only — the prologue is 60 lines of register setup that would
           swamp every substring test below."""
        return ll(f'1000:\t{t}\n1004:\tret').split('L1000:')[1]

    #  R23 MEASURED ON AN M4 (tp2.c): tpidr2_el0 round-trips exactly, the storage is
    #    per-thread, and it reads DIFFERENTLY from tpidrro_el0 in the same thread. That last
    #    fact is the whole reason it must not lower to the %gs path — an arm that only
    #    checked "it lowers" would pass while every SME lazy-save read returned the TSD base.
    _tp2 = ll('1000:\tmrs\tx0, tpidr2_el0\n1004:\tret')
    arm(' R23 mrs tpidr2_el0 reads the thread-local slot, NOT the %gs TSD base',
        ('load i64, ptr @__arm_tpidr2' in _tp2, 'addrspace(256)' in _tp2),
        (True, False))
    arm(' R23 msr TPIDR2_EL0 stores to the same slot, and xzr writes a zero',
        ('store i64' in ll('1000:\tmsr\tTPIDR2_EL0, x1\n1004:\tret'),
         '@__arm_tpidr2' in ll('1000:\tmsr\tTPIDR2_EL0, xzr\n1004:\tret')),
        (True, True))
    #  MEASURED IN BOTH DIRECTIONS. A guard that only proves it ALLOWS the register it
    #    knows has never been shown to BLOCK the ones it does not, and a silent msr to an
    #    unmodelled register surfaces arbitrarily far from where it happened.
    arm(' R23 every other system register still aborts, reading AND writing',
        (_how('mrs\tx0, fpsr'), _how('mrs\tx0, ctr_el0'),
         _how('msr\tFPSR, x1'), _how('msr\tTPIDR_EL0, x1')),   # fpcr modelled since 10-03
        ('NotImplementedError',) * 4)
    #  THE SLOT IS DECLARED, NOT DEFINED. A `thread_local global i64 zeroinitializer` in
    #    emitted IR is a definition in EVERY module and collides the moment two are linked —
    #    R20 shipped exactly that bug for the AMX files and R21 paid to undo it.
    _sp = ll('1000:\tmsr\tS3_6_C15_C1_5, x0\n1004:\tisb\n1008:\tmrs\tx9, S3_6_C15_C1_5\n100c:\tret')
    arm(' R38 the TPRO register round-trips through ONE per-thread slot (msr stores, mrs loads)',
        ('store i64' in _sp and '@__arm_sprr' in _sp, 'load i64, ptr @__arm_sprr' in _sp,
         '@__arm_sprr = external thread_local global i64' in PRELUDE), (True, True, True))
    arm(' R38 tchangef / tchangeb / TINDEX_EL0 / the old APRR register abort BY NAME, never lift to a guess',
        tuple('@__arm2x86_nofeature' in ll(f'1000:\t{t}\n1004:\tret') for t in
              ('tchangef\tx0, #0x2', 'tchangeb\tx0, #0x0', 'mrs\tx8, TINDEX_EL0', 'msr\tS3_4_C15_C2_7, x0')),
        (True,) * 4)
    #  MEASURED IN BOTH DIRECTIONS: the new names must not have opened the door for others.
    arm(' R38 a neighbouring Apple register is STILL refused (S3_6_C15_C1_4, S3_6_C15_C1_6)',
        (_how('mrs\tx0, S3_6_C15_C1_4'), _how('msr\tS3_6_C15_C1_6, x0')), ('NotImplementedError',) * 2)
    arm(' R23 the tpidr2 slot is external, so sysreg_rt.c owns the storage',
        ('@__arm_tpidr2 = external thread_local global i64' in PRELUDE,
         'zeroinitializer' in PRELUDE.split('@__arm_tpidr2')[1].split('\n')[0]),
        (True, False))

    #  R24 NZCV, MEASURED ON AN M4 (svcr.c): N=31 Z=30 C=29 V=28, `cmp x0,x0` reads
    #    0x60000000, and a write REACHES the flags (`msr nzcv,0x40000000; csetm eq` = -1).
    #  THE ARM ASSERTS THE MEASURED BIT POSITIONS, not merely that something was emitted.
    #    A lowering that packed the four flags in the wrong order lifts perfectly.
    #  AND IT ASSERTS `sext` IS ABSENT. An i1 sign-extended is all ones, which would
    #    smear garbage across bits 27..0 of a word the guest may compare to a constant.
    _nz = _s2('mrs	x0, nzcv')
    arm(' R24 mrs NZCV packs %N %Z %C %V at the MEASURED bits 31/30/29/28',
        (all(f'load i1, ptr %{n}' in _nz for n in 'NZCV'),
         all(f', {s}' in _nz for s in (31, 30, 29, 28)),
         _nz.count('zext i1'), 'sext' in _nz),
        (True, True, 4, False))
    #  THE WRITE MUST LAND IN THE SAME ALLOCAS A COMPARE WRITES. A shadow word would let
    #    `msr nzcv, x1` be followed by a b.eq reading the PREVIOUS comparison — the silicon
    #    says the write is visible to `csetm eq`, so ours has to be visible to b.eq.
    _mz = _s2('msr	NZCV, x1')
    arm(' R24 msr NZCV unpacks into the SAME four slots every b.cc reads',
        (all(f', ptr %{n}' in _mz for n in 'NZCV'),
         _mz.count('trunc i64'),
         all(f', {s}' in _mz for s in (31, 30, 29, 28))),
        (True, 4, True))
    #  R24 SVCR, MEASURED IN ALL FOUR STATES: 0 outside, 3 after smstart, 2 after
    #    `smstop sm`, 0 after `smstop za`. bit 0 = SM, bit 1 = ZA.
    #  THE READ IS WORTHLESS WITHOUT THE WRITER. Before R24 smstart/smstop tracked no
    #    mode at all, so an arm that only checked `mrs SVCR` lifts would pass while the
    #    value it read stayed whatever the slot was initialised to, forever.
    arm(' R24 mrs SVCR reads the slot smstart/smstop now maintain',
        ('load i64, ptr @__arm_svcr' in _s2('mrs	x0, svcr'),
         '@__arm_svcr' in _s2('smstart'),
         '@__arm_svcr' in _s2('smstop	za')),
        (True, True, True))
    #  MEASURED PER SPELLING, IN BOTH DIRECTIONS. The M4 read 2 — not 0 — after
    #    `smstop sm`, so a lowering that cleared the whole word would drop the ZA bit the
    #    guest still needs. -2 clears bit 0 only; -4 clears both; -3 clears bit 1 only.
    arm(' R24 each streaming spelling touches exactly its own SVCR bits',
        ('or i64' in _s2('smstart	sm') and ', 1' in _s2('smstart	sm'),
         'or i64' in _s2('smstart	za') and ', 2' in _s2('smstart	za'),
         'or i64' in _s2('smstart') and ', 3' in _s2('smstart'),
         'and i64' in _s2('smstop	sm') and ', -2' in _s2('smstop	sm'),
         'and i64' in _s2('smstop	za') and ', -3' in _s2('smstop	za'),
         'and i64' in _s2('smstop') and ', -4' in _s2('smstop'),
         'or i64' in _s2('smstop')),
        (True, True, True, True, True, True, False))
    arm(' R24 the svcr slot is external too, so sysreg_rt.c owns it',
        ('@__arm_svcr = external thread_local global i64' in PRELUDE,
         'zeroinitializer' in PRELUDE.split('@__arm_svcr')[1].split('\n')[0]),
        (True, False))
    #  AND THE REGISTERS WE STILL DO NOT MODEL MUST STILL ABORT — a guard that only ever
    #    proves it ALLOWS has never been shown to BLOCK. `msr SVCR, x1` is in the list on
    #    purpose: the READ is modelled and the WRITE is a different encoding nothing emits.
    #  10-03 THE EXIT MATRIX (note). The tail-thunk bug lived on an exit path no arm covered. Every
    #    way a function can leave x every contract it can keep: an OFF-contract function must hand x19 (slot 152) back on
    #    EVERY exit; an ON-contract one must hand back x1 (slot 8) and never x19.
    _exits = {
        'ret': '1000:\tmov\tx19, #1\n1004:\tret',
        'b tail (translated)': '1000:\tmov\tx19, #1\n1004:\tb\t0x2000',
        'br tail (indirect)': '1000:\tmov\tx19, #1\n1004:\tbr\tx2',
        'runs off its end': '1000:\tmov\tx19, #1',
        'cond branch off its end': '1000:\tcmp\tx0, #1\n1004:\tb.lo\t0x1000',
    }
    _keepm = NONABI.copy()
    for _nm, _src in _exits.items():
        for _off in (True, False):
            NONABI.clear()
            if _off: NONABI.add(0x1000)
            _ir = Lifter(parse(_src), 'fn_1000', {0x1000, 0x2000, 0x1008, 0x1004}, {}).define()
            _st19 = bool(re.search(r'store i64 %xr\w+_x19, ptr %xr\w+_x19p', _ir))   # INTO the block, not the prologue's load
            _st1 = bool(re.search(r'store i64 %xr\w+_x1, ptr %xr\w+_x1p', _ir))
            _tail = _nm.startswith('br')   # the indirect tail callee writes x1/v1-v3 itself: we must NOT overwrite them
            #  10-03 and so does every ON-contract TAIL TRANSFER now (musttail, tail_call()): `b` to a translated function,
            #    running off the end, a conditional branch off the end — the callee's x1/v1-v3 in @__arm_xr are ours
            if not _off and _nm != 'ret': _tail = True
            #  10-21 THE DEFINEDNESS RULE (xr_tail_pub). An ON-contract function hands a callee-saved register back on a
            #    TAIL TRANSFER exactly when it DEFINED it — `mov x19, #1` here does, so the off-contract callee must read 1
            #    and not the grandparent's x19. This arm asserted `x19 handed back == _off` for every exit, which is the
            #    10-20 blanket rule: it kept the callee from reading a register the caller never wrote (right) and also
            #    dropped the ones it did (wrong — 300 differing lines at callmx -Oz, 0 at -O1/-O2). `ret` is not a tail
            #    transfer, so it still publishes XR_ABI_OUT only.
            _w19 = _off or ('x19' in _src and _nm != 'ret')
            arm(f' exit matrix: {_nm}, {"OFF" if _off else "ON"}-contract: x19 handed back={_w19} '
                f'(ON-contract only where this function DEFINES it and the exit is a tail transfer), x1 written={not _tail}',
                (_st19, _st1), (_w19, not _tail))
    #  10-21 THE NEGATIVE ARM FOR THE SAME RULE, AND IT IS THE BUG THAT KILLED THE DOCK ON 10-20. The thunk at
    #    0x100153cb0 is `adrp/add x4, x5; b fn_10015351c` — ON-contract, tail-calling an OFF-contract callee, and it
    #    touches NOTHING in XR_FULL_IN. Publishing the full file there wrote its own entry zeros over the real caller's
    #    x19-x28 and the Swift value the callee should have filled held the thunk's argument pair instead. It must hand
    #    back x8/x20/x21 and not one register more.
    NONABI.clear()
    _thunk20 = Lifter(parse('1000:\tmov\tx4, #1\n1004:\tmov\tx5, #2\n1008:\tb\t0x2000'),
                      'fn_1000', {0x1000, 0x2000, 0x100c}, {}).define()
    arm(' 10-20 an ON-contract thunk that writes only x4/x5 hands back x8/x20/x21 and NO callee-saved register',
        (bool(re.search(r'store i64 %xr\w+_x8, ptr %xr\w+_x8p', _thunk20)),
         bool(re.search(r'store i64 %xr\w+_x19, ptr %xr\w+_x19p', _thunk20)),
         bool(re.search(r'store i64 %xr\w+_x29, ptr %xr\w+_x29p', _thunk20)),
         bool(re.search(r'store <16 x i8> %xr\w+_v8, ptr %xr\w+_v8p', _thunk20))),
        (True, False, False, False))
    #  10-21 and the positive half on the SAME shape: define x9 (what the -Oz callees load from @__arm_xr+72) and it rides.
    _thunk21 = Lifter(parse('1000:\tmov\tx9, #1\n1004:\tb\t0x2000'), 'fn_1000', {0x1000, 0x2000, 0x1008}, {}).define()
    arm(' 10-21 an ON-contract caller that DEFINES x9 publishes x9 at its tail transfer (the callmx -Oz root cause)',
        (bool(re.search(r'store i64 %xr\w+_x9, ptr %xr\w+_x9p', _thunk21)),
         bool(re.search(r'%xr\w+_x9 = load i64, ptr %xr\w+_x9p', _thunk21)),
         bool(re.search(r'store i64 %xr\w+_x19, ptr %xr\w+_x19p', _thunk21))),
        (True, True, False))
    NONABI.clear(); NONABI.update(_keepm)
    _keep = NONABI.copy(); NONABI.clear(); NONABI.add(0x1000)
    _thunk = Lifter(parse('1000:\tldr\tx8, [x0]\n1004:\tldr\tx2, [x8, #0x20]\n1008:\tbr\tx2'), 'fn_1000', {0x1000}, {}).define()
    _tail = _thunk.split('@__arm2x86_dispatch(')[1]
    arm(' 10-03 an OFF-CONTRACT vtable thunk (`br x2`) hands x19-x28 back AFTER the tail call (Cyberpunk: x21 came back 0)',
        ('i64 152' in _tail.split('ret ')[0] and 'store i64' in _tail.split('ret ')[0], 'i64 8\n' not in _tail.split('ret ')[0]), (True, True))
    NONABI.clear()
    _thunk2 = Lifter(parse('1000:\tldr\tx8, [x0]\n1004:\tldr\tx2, [x8, #0x20]\n1008:\tbr\tx2'), 'fn_1000', {0x1000}, {}).define()
    arm(' ... and an ON-contract thunk writes nothing after it (the callee owns x1/v1-v3, x19-x28 never left our frame)',
        'i64 152' in _thunk2.split('@__arm2x86_dispatch(')[1].split('ret ')[0], False)
    NONABI.clear(); NONABI.update(_keep)
    #  10-20 THE SWIFT REGISTERS (XR_ABI_IN/OUT): eslogger/xprotect on macOS 27 reached native Swift with no x20/x21.
    _sw = Lifter(parse('1000:\tmov\tx20, #5\n1004:\tmov\tx21, #0\n1008:\tblr\tx2\n100c:\tcbnz\tx21, 0x1000\n1010:\tret'),
                 'fn_1000', {0x1000}, {}).define()
    _pre, _post = _sw.split('@__arm2x86_dispatch(')[0], _sw.split('@__arm2x86_dispatch(')[1].split('; --- R12 epilogue')[0]
    arm(' 10-20 an indirect call PUBLISHES x20 (Swift self) and x21 (swifterror) and RELOADS x21 after it',
        (bool(re.search(r'store i64 %xr\w+_x20, ptr %xr\w+_x20p', _pre)), bool(re.search(r'store i64 %xr\w+_x21, ptr %xr\w+_x21p', _pre)),
         bool(re.search(r'load i64, ptr %xr\w+_x21p', _post)), bool(re.search(r'load i64, ptr %xr\w+_x20p', _post))),
        (True, True, True, False))
    arm(' 10-20 ... and every on-contract prologue LOADS x20/x21, its epilogue hands x21 (and x2/x3) back',
        (bool(re.search(r'%xrin_x20 = load i64', _sw)), bool(re.search(r'%xrin_x21 = load i64', _sw)),
         all(bool(re.search(rf'store i64 %xr\w+_{r}, ptr %xr\w+_{r}p', _sw.split('; --- R12 epilogue')[1])) for r in ('x2', 'x3', 'x21'))),
        (True, True, True))
    _stub = '1000:\tadrp\tx16, 0x5000\n1004:\tldr\tx16, [x16, #0x8]\n1008:\tbr\tx16'
    _hints = []
    for _cc in (2, 1, None):
        STUB_CC.clear()
        if _cc: STUB_CC[0x1000] = _cc
        _h = Lifter(parse(_stub), 'fn_1000', {0x1000}, {}).define()
        _hints.append(re.findall(r'store i8 (\d), ptr @__arm2x86_native_hint', _h.split('@__arm2x86_dispatch(')[0]))
    STUB_CC.clear()
    arm(' 10-20 an import stub names its callee\'s convention before the dispatch (2 Swift, 1 C); any other `br` names none',
        _hints, [['2'], ['1'], []])
    STUB_CC.clear(); STUB_CC[0x1000] = 3
    _h5 = Lifter(parse(_stub), 'fn_1000', {0x1000}, {}).define(); STUB_CC.clear()
    arm(' 10-22 an ASYNC import stub stores hint 5 (always swifttailcc), not 3 (a `br` that still needs a valid x22)',
        re.findall(r'store i8 (\d), ptr @__arm2x86_native_hint', _h5.split('@__arm2x86_dispatch(')[0]), ['5'])
    #  10-21 SWIFT ASYNC (asyncmx): x22 is the async context and rides every call like x20/x21; an async function's `br` is a
    #    TRUE tail call (musttail) with hint 3, because the nested call it replaces cost 5.4 KB of stack per resumed `for await`
    #    element; a function that touches x6/x7 may pass stack words, which a deferred tail call cannot (hint 4).
    arm(' 10-21 x22 (the swift async context) is published at every call and loaded by every prologue, like x20/x21',
        (bool(re.search(r'store i64 %xr\w+_x22, ptr %xr\w+_x22p', _pre)), bool(re.search(r'%xrin_x22 = load i64', _sw)),
         'x22' in XR_ABI_IN, 'x22' in XR_ABI_OUT), (True, True, True, False))
    def _ay(text, async_set=(), stubs=None, known=(0x1000,)):
        ASYNC_FNS.clear(); ASYNC_FNS.update(async_set); STUB_CC.clear(); STUB_CC.update(stubs or {})
        try: return Lifter(parse(text), 'fn_1000', set(known), {}).define()
        finally: ASYNC_FNS.clear(); STUB_CC.clear()
    _ah = lambda h: re.findall(r'store i8 (\d), ptr @__arm2x86_native_hint', h)
    _marked = '1000:\torr\tx29, x29, #0x1000000000000000\n1004:\tldr\tx1, [x22, #0x8]\n1008:\tbr\tx1'
    _frameless = '1000:\tldr\tx1, [x22, #0x8]\n1004:\tbr\tx1'
    _am, _af, _an = _ay(_marked), _ay(_frameless, {0x1000}), _ay(_frameless)
    arm(' 10-21 an async function\'s `br` is a musttail through lookup with hint 3 (marked, or named by ASYNC_FNS when frameless); '
        'an ordinary function\'s stays call + dispatch with no hint',
        [(('musttail call' in h), ('@__arm2x86_dispatch(' in h), _ah(h)) for h in (_am, _af, _an)],
        [(True, False, ['3']), (True, False, ['3']), (False, True, [])])
    arm(' 10-21 an async function that touches x6/x7 (a 7th/8th integer argument rides the stack) stores hint 4, not 3',
        _ah(_ay('1000:\torr\tx29, x29, #0x1000000000000000\n1004:\tmov\tx6, #0\n1008:\tldr\tx1, [x22, #0x8]\n100c:\tbr\tx1')), ['4'])
    arm(' 10-21 x6/x7 set up BEFORE the previous call are not this call\'s arguments (the -Osize outliner uses them as scratch): hint 3',
        _ah(_ay('1000:\torr\tx29, x29, #0x1000000000000000\n1004:\tmov\tx6, #0\n1008:\tbl\t0x6000\n100c:\tldr\tx1, [x22, #0x8]\n1010:\tbr\tx1',
                known=(0x1000, 0x6000))), ['3'])
    _ab = _ay('1000:\torr\tx29, x29, #0x1000000000000000\n1004:\tmov\tx7, x1\n1008:\tb\t0x5000', stubs={0x5000: 3}, known=(0x1000, 0x5000))
    _ac2 = _ay('1000:\torr\tx29, x29, #0x1000000000000000\n1004:\tb\t0x5000', stubs={0x5000: 3}, known=(0x1000, 0x5000))
    arm(' 10-21 a direct `b stub` into a native async function says "stack words" only when the caller touches x6/x7',
        ('store i8 1, ptr @__arm2x86_async_carry' in _ab, 'store i8 1, ptr @__arm2x86_async_carry' in _ac2), (True, False))
    arm(' 10-20 an off-contract tail dispatch must not overwrite what the tail callee returns (x2/x3/x21)',
        [r for r in ('x1', 'x2', 'x3', 'x21', 'v1') if r in XR_TAIL_KEEP], [])
    arm(' R24 fpsr and the unmodelled writes still abort in BOTH directions (fpcr is modelled since 10-03)',
        (_how('mrs	x0, fpsr'), _how('msr	FPSR, x1'), _how('msr	SVCR, x1')),
        ('NotImplementedError',) * 3)

    #  R18-d `add z0.s, z1.s, z2.s` LEFT THIS LIST BECAUSE IT IS IMPLEMENTED NOW.
    #    The three that remain are still real gaps: a `mul vl` addressing mode, a ZA tile
    #    outer product, and a predicated gather-shaped load. An arm that keeps asserting
    #    a built thing aborts is an arm that will be "fixed" by deleting the build.
    #  R22 `ld1b { z0.b }, p0/z, [x0]` LEFT THIS LIST BECAUSE IT IS BUILT NOW. It is
    #    replaced by luti4, which needs the ZT0 lookup table nobody has measured — a gap
    #    we are NOT working toward, which is the only thing this list may contain.
    #  R33 `ldr p5, [x5, #0x45, mul vl]` LEFT: it lowers now (8-byte predicate, mul vl
    #    x8). A GATHER keeps its place — a vector index is still not an address R33 models.
    #  R39 fmop4a LEFT this list for R38_NOFEAT (absent on the M4); uzpq2 still has no model.
    for _sv in ('ld1w\t{ z0.s }, p0/z, [x0, z1.s, uxtw #2]', 'uzpq2\tz0.h, z1.h, z2.h',
                'luti4\t{ z0.b - z3.b }, zt0, { z4, z5 }'):
        arm(f' R9 SVE/SME aborts as unsupported, not as a crash: {_sv.split(chr(9))[0]}',
            _how(_sv), 'NotImplementedError')
    #  AND THE GUARD MUST NOT OVER-FIRE. `pldl1keep` starts with p+digits nowhere, but
    #    `p0`-shaped hints and the x86 prefetch path would both die if it did.
    arm(' R9 the SVE guard does NOT eat prfm hints or ordinary V/X operands',
        (_how('prfm\tpldl1keep, [x0]'), _how('add\tx0, x1, x2')),
        ('LIFTED (must not)', 'LIFTED (must not)'))

    #  adcs/sbcs SET NZCV, and the carry-OUT depends on the carry-IN, which setflags_add()
    #    structurally cannot see: it derives C from `res < a`, which reads 0 on the exact
    #    input a multiword add exists for (carry-in 1, a+b == all ones).
    _ac = _r9('adcs\tx0, x1, x2'); _ad = _r9('adc\tx0, x1, x2')
    arm(' R9 adcs writes NZCV in a width-plus-one sum; plain adc leaves them alone',
        (_ac.count('store i1') > _ad.count('store i1'), 'i65' in _ac, 'i65' in _ad),
        (True, True, False))
    arm(' R9 a 32-bit adcs computes its carry in i33, not i65',
        ('i33' in _r9('adcs\tw0, w1, w2'), 'i65' in _r9('adcs\tw0, w1, w2')),
        (True, False))

    #  CAS ALWAYS WRITES THE OLD MEMORY VALUE BACK INTO ITS COMPARAND. Dropping that
    #    leaves the caller's retry loop comparing the same stale value forever — a HANG.
    _cp = _r9('caspal\tx0, x1, x2, x3, [x4]')
    arm(' R9 caspal is a real i128 cmpxchg that writes the old value back to the pair',
        ('cmpxchg ptr' in _cp, 'extractvalue' in _cp,
         _cp.count('store i64 %') >= 2), (True, True, True))

    #  R9-g THE TWO FINDINGS FROM THE INSTANCE-LEVEL RULER.
    #  R22 pn8 IS NOT p8, AND IT IS MODELLED NOW RATHER THAN BLOCKED. The distinction
    #    the old arm protected is still the whole point: a predicate-as-counter encodes a
    #    RANGE, so it must be DECODED into a prefix mask and never read as a lane mask.
    #    This arm holds that — the counter's slot goes through the cttz decode, and the
    #    ordinary predicate path (a stride-slice of an i64) is not used for it.
    _pn = _s2('whilelt\tpn8.s, xzr, x0, vlx4')
    arm(' R22 pn8 is DECODED as a counter, never read as p8\'s lane mask',
        (_how('ptrue\tpn8.s'), _how('whilelt\tpn8.s, xzr, x0, vlx4'),
         'store i64' in _pn, 'bitcast i64' in _pn),
        ('LIFTED (must not)', 'LIFTED (must not)', True, False))
    arm(' R18 an ordinary p-register ptrue LIFTS - the pn guard does not over-fire',
        _how('ptrue\tp0.s'), 'LIFTED (must not)')

    # ── R18 SVE/SME at Apple's FIXED 512-bit streaming vector length ───────────
    #  VL_BITS WAS 128. cntb returned 16 where an M4 returns 64, and `addvl sp, sp, #-2`
    #    reserved a QUARTER of the spill space the vectors need - stack corruption, not a
    #    truncated loop. These arms carry the measured numbers so the constant cannot drift
    #    back: vlprobe2.c, streaming mode, values captured before printing.
    arm(' R18 the vector length is the MEASURED 64 bytes, not the 16 we had assumed',
        (VL_BYTES, SVL_B, PL_BYTES), (64, 64, 8))
    arm(' R18 cntb/cnth/cntw/cntd match the M4: 64 32 16 8',
        ('i64 64' in _r9('cntb\tx0') or ' 64' in _r9('cntb\tx0'),
         ' 32' in _r9('cnth\tx0'), ' 16' in _r9('cntw\tx0'), ' 8' in _r9('cntd\tx0')),
        (True, True, True, True))
    arm(' R18 rdvl #1 is 64 and rdsvl #3 is 192, exactly as the silicon returned',
        (' 64' in _r9('rdvl\tx0, #1'), ' 192' in _r9('rdsvl\tx0, #3')), (True, True))

    #  smstart IS NOT A MODE FLAG. Measured on an M4: entry zeroes all Z and V, exit
    #    zeroes them too, and a BARE smstart also zeroes the 4096-byte ZA tile. A
    #    translation that treats it as a no-op leaves stale registers the real machine
    #    could never present - a wrong answer, not a crash.
    #  R18-e MEASURE THE DELTA, NOT THE TOTAL. The prologue already zero-initialises
    #    32 v-registers and 16 predicates, so a raw count credits the instruction with the
    #    prologue's work and reads 64/32 for a 32/16 claim.
    def _sme_delta(t):
        """(z stores, p stores, za stores) that instruction `t` adds over a bare ret."""
        base, got = _r9('nop'), _r9(t)
        z = f'store <{SVL_B} x i8> zeroinitializer, ptr %v'
        p = 'store i64 0, ptr %p'
        za = f'store [{SVL_B} x <{SVL_B} x i8>] zeroinitializer, ptr %za'
        return (got.count(z) - base.count(z), got.count(p) - base.count(p),
                got.count(za) - base.count(za))

    arm(' R18 a bare smstart zeroes 32 z, 16 p AND the ZA tile - it is not a no-op',
        _sme_delta('smstart'), (32, 16, 1))
    #  AND THE OTHER DIRECTION, WHICH IS THE ONE THAT DESTROYS DATA. MEASURED (zasel.c):
    #    write ZA, `smstop sm`, `smstart sm`, read back -> 0x55 x 64/64. The SM-only forms
    #    PRESERVE ZA. Clearing it there would silently destroy a live tile.
    arm(' R18 `smstart sm` preserves ZA (measured 64/64 survive) but still clears z/p',
        _sme_delta('smstart	sm'), (32, 16, 0))
    arm(' R18 `smstart za` touches ONLY the tile, leaving the vector file alone',
        _sme_delta('smstart	za'), (0, 0, 1))
    arm(' R18 the streaming EXIT zeroes the vector file too - measured twice, once by an '
        'all-false p0 making a real st1b write nothing',
        _sme_delta('smstop')[:2], (32, 16))

    #  A PREDICATE BIT IS PER BYTE, NOT PER ELEMENT. p0 holds SVL/8 = 64 bits and the bit
    #    governing element i of a .s vector is bit i*4. Reading one bit per element enables
    #    the WRONG LANES and still produces a full-looking vector - the failure this whole
    #    family is most likely to have and least likely to show.
    _pa = _r9('fadd	z0.s, p0/m, z0.s, z1.s')
    arm(' R18 a .s predicate reads every FOURTH bit of p0, not the low 16',
        ('i32 0, i32 4, i32 8, i32 12' in _pa, f'bitcast i64 %' in _pa), (True, True))
    arm(' R18 ptrue writes the measured byte-lane mask for its element width',
        (str(SVE_PTRUE_PAT['b']) in _r9('ptrue	p0.b'),
         str(SVE_PTRUE_PAT['d']) in _r9('ptrue	p3.d')), (True, True))
    #  MERGING vs ZEROING IS THE DIFFERENCE BETWEEN KEEPING AND DESTROYING THE INACTIVE
    #    LANES. /m selects the old destination, /z selects zero.
    arm(' R18 /m merges into the old destination and /z zeroes the inactive lanes',
        ('select' in _pa and 'zeroinitializer' not in _pa.split('select')[1].split('\n')[0],
         'zeroinitializer' in _r9('fadd	z0.s, p0/z, z0.s, z1.s').split('select')[1]),
        (True, True))
    #  THE REVERSED FORMS COMPUTE SRC/DST, NOT DST/SRC. Identical lifts would be silent.
    arm(' R18 fdivr reverses its operands - it must not lift identically to fdiv',
        _r9('fdivr	z0.s, p0/m, z0.s, z1.s') != _r9('fdiv	z0.s, p0/m, z0.s, z1.s'), True)
    arm(' R18 an unpredicated z add is a plain 16-lane vector add at SVL',
        ('add <16 x i32>' in _r9('add	z0.s, z1.s, z2.s')), True)
    arm(' R18 element width picks the lane count: .d is 8 lanes, .b is 64',
        ('add <8 x i64>' in _r9('add	z0.d, z1.d, z2.d'),
         'add <64 x i8>' in _r9('add	z0.b, z1.b, z2.b')), (True, True))
    #  A WIDENING FORM IS A DIFFERENT INSTRUCTION, NOT A WIDER ONE - it must BLOCK.
    arm(' R18 mixed element widths BLOCK rather than silently using the destination width',
        _how('add	z0.d, z1.s, z2.s'), 'NotImplementedError')
    # ── R18-j CONVERSIONS. Every number here came off an M4 (cvt.c), with z0 pre-filled
    #    with 0x7F so any byte the convert does NOT write is visible in the result.
    #      ucvtf z0.s,p/m,z1.d  ->  | 00 00 80 3f 00 00 00 00 |  1.0f low half, high ZEROED
    #      fcvt  z0.d,p/m,z1.s  ->  | 00 00 00 00 00 00 f0 3f |  reads the LOW f32
    _uc = _r9('ucvtf	z0.s, p0/m, z1.d')
    arm(' R18 a narrowing convert works in EIGHT 64-bit containers, not sixteen lanes',
        ('uitofp <8 x i64>' in _uc, '<16 x float>' in _uc), (True, False))
    #  ANCHORED ON THE CLAIM, NOT ON A TEMP NAME. The first version of this arm read
    #    'zext <8 x i32> %t4 to <8 x i64>' and would have failed the next time an
    #    unrelated instruction shifted the numbering - an arm must assert what it means.
    arm(' R18 and it ZEROES the rest of each container - measured, the 0x7F fill came '
        'back 00, so it is a zext and never a merge',
        any(l.strip().split(' = ')[-1].startswith('zext <8 x i32>') and
            l.strip().endswith('to <8 x i64>') for l in _uc.splitlines()), True)
    _fw = _r9('fcvt	z2.d, p0/m, z3.s')
    arm(' R18 a widening convert reads the LOW half of each container, then fpext',
        ('trunc <8 x i64>' in _fw, 'fpext <8 x float>' in _fw and 'to <8 x double>' in _fw),
        (True, True))
    arm(' R18 a same-width convert needs no container games: scvtf .d<-.d is 8 lanes flat',
        ('sitofp <8 x i64>' in _r9('scvtf	z6.d, p0/m, z7.d'),
         'zext' in _r9('scvtf	z6.d, p0/m, z7.d').split('sitofp')[1].split('store')[0]),
        (True, False))
    #  ARM'S FP->INT SATURATES AND MAPS NaN TO 0. Plain fptosi is POISON out of range,
    #    which does not round differently - it lets the optimiser delete live code.
    _fz = _r9('fcvtzs	z8.s, p0/m, z9.s')
    arm(' R18 fcvtzs uses the SATURATING intrinsic, never a plain fptosi',
        ('llvm.fptosi.sat.v16i32.v16f32' in _fz,
         bool([l for l in _fz.splitlines() if ' = fptosi ' in l])), (True, False))
    arm(' R18 fcvtzu saturates too', 'llvm.fptoui.sat' in _r9('fcvtzu	z10.d, p0/m, z11.d'),
        True)
    #  THE PREDICATE FOLLOWS THE CONTAINER, NOT THE DESTINATION. A .s<-.d convert is
    #    governed at 64 bits, so it reads every EIGHTH bit of p0 - reading every fourth
    #    would enable twice the lanes and still return a full-looking register.
    arm(' R18 a mixed-width convert takes its predicate at the CONTAINER width',
        ('i32 0, i32 8, i32 16, i32 24' in _uc, 'i32 0, i32 4, i32 8, i32 12' in _uc),
        (True, False))
    #  A VECTOR LIST IS NOT A VECTOR, AND IT IS LIFTED NOW RATHER THAN BLOCKED. The
    #    hazard the old arm named is unchanged: sve_tok strips the brace, so a list read
    #    as a single register converts HALF the data and returns a full-looking one. This
    #    arm proves BOTH registers of the list are actually read.
    _fl = _s2('fcvt	z0.h, { z0.s, z1.s }')
    arm(' R22 a vector list reads EVERY register in it, not just the first',
        (_how('fcvt	z0.h, { z0.s, z1.s }'),
         'ptr %v0' in _fl and 'ptr %v1' in _fl,
         _s2('ld1w	{ z4.s - z7.s }, pn8/z, [x22]').count('@llvm.masked.load')),
        ('LIFTED (must not)', True, 4))
    # ── R18-l SHIFTS SATURATE. Measured on an M4, data 0x80000001:
    #      asr z0.s,p0/m,z0.s,z2.s   amt 32/64/255 -> ffffffff   (all sign bits)
    #      lsr z0.s,p0/m,z0.s,z2.s   amt 32/64/255 -> 00000000
    #      asr z0.s,z1.s,z2.d wide   amt 32/64/1000 -> ffffffff
    #  The scalar rule (R13) is MODULO the width, and asr/lsr/lsl sat in the arithmetic
    #    table emitting a plain LLVM shift on that assumption - POISON at >= bitwidth,
    #    which lets the optimiser delete live code. These arms hold the machine's answer.
    _wa = _r9('asr	z0.s, z1.s, z2.d')
    arm(' R18 a wide asr SATURATES to all sign bits, never a plain poison shift',
        ('icmp uge' in _wa, 'llvm.umin' in _wa,
         len([l for l in _wa.splitlines() if ' = ashr <16 x i32>' in l]) >= 2),
        (True, True, True))
    arm(' R18 the wide form groups by 64-bit lane: two .s elements share one amount',
        ('i32 0, i32 0, i32 1, i32 1' in _wa), True)
    _wl = _r9('lsl	z6.b, z7.b, z8.d')
    arm(' R18 a wide lsl saturates to ZERO, and .b takes eight elements per D lane',
        ('zeroinitializer' in _wl.split('select')[1] if 'select' in _wl else False,
         'i32 0, i32 0, i32 0, i32 0, i32 0, i32 0, i32 0, i32 0, i32 1' in _wl),
        (True, True))
    arm(' R18 the SAME-WIDTH predicated shift saturates too - measured amt 255',
        ('icmp uge' in _r9('asr	z9.s, p0/m, z9.s, z10.s'),
         'llvm.umin' in _r9('lsr	z11.d, p0/m, z11.d, z12.d')), (True, True))
    #  AN IMMEDIATE SHIFT CANNOT SATURATE - the assembler rejects one that could - so it
    #    must NOT pay for a mask it can never need.
    _si = _r9('asr	z13.s, z14.s, #4')
    arm(' R18 an immediate shift is in range by encoding and emits no saturation mask',
        ('icmp uge' in _si, 'ashr <16 x i32>' in _si), (False, True))
    arm(' R18 an out-of-range immediate shift BLOCKS rather than emitting poison',
        _how('asr	z0.s, z1.s, #32'), 'NotImplementedError')

    arm(' R18 a same-width fp convert is not a convert and BLOCKS',
        _how('fcvt	z0.s, p0/m, z1.s'), 'NotImplementedError')

    #  THE ZA TILE IS BUILT. fmopa/fmops ACCUMULATE into it — measured separately,
    #    because a probe on a freshly-zeroed ZA cannot tell accumulate from overwrite, and
    #    fmopa followed by fmops with the same operands returns the tile to exactly zero.
    _op = _s2('fmopa	za0.s, p0/m, p1/m, z0.s, z1.s')
    _os = _s2('fmops	za0.s, p0/m, p1/m, z0.s, z1.s')
    #  R33d AND IT IS FUSED (M4: 782/782 fused, 706/782 unfused). The old arm counted
    #    16 fmul + 16 fadd and so asserted the very rounding the silicon does not do.
    arm(' R22/R33d fmopa is ONE fused op per row into ZA, fmops negates — never fmul+fadd',
        (_op.count('@llvm.fma.v16f32'), _os.count('@llvm.fma.v16f32'),
         _op.count('= fneg <16 x float>'), _os.count('= fneg <16 x float>'),
         _op.count('= fmul <16 x float>') + _os.count('= fmul <16 x float>')),
        (16, 16, 0, 16, 0))
    #  AND A MALFORMED MULTI-VECTOR FORM MUST STILL BLOCK. `add zd, {list}, zm` is not
    #    a real instruction; sme2() must decline it rather than invent a reading.
    arm(' R22 a shape sme2 does not recognise still BLOCKS',
        _how('add	z0.s, { z1.s - z2.s }, z3.s'), 'NotImplementedError')

    # ── R22 SME2, EVERY NUMBER MEASURED ON AN M4 ON 2026-09-22 ────────────────
    _g4s = _s2('mov\tza.s[w8, 0, vgx4], { z0.s - z3.s }')
    _g4d = _s2('mov\tza.d[w8, 0, vgx4], { z0.d - z3.d }')
    _g2s = _s2('mov\tza.s[w8, 0, vgx2], { z0.s, z1.s }')
    _str = lambda b: sorted(set(re.findall(r'= add i64 %t\d+, (\d+)', b)), key=int)
    #  THE ARM THAT WOULD HAVE CAUGHT MY WRONG PREDICTION. I predicted a vector group
    #    writes CONSECUTIVE ZA rows. The M4 writes base + g*(64/VG). An arm that checked
    #    "four rows were written" or only read member 0 passes under BOTH readings —
    #    which is exactly how R21's Z-row interleave survived 20 held predictions and
    #    then scored 0/199 against silicon.
    arm(' R22 a ZA vector group is STRIDED by 64/VG, never consecutive',
        (_str(_g4s), _str(_g2s)), (['0', '16', '32', '48'], ['0', '32']))
    #  AND THE STRIDE DOES NOT DEPEND ON THE ELEMENT SIZE. za.d vgx4 is still stride 16,
    #    not 8 — measured. Deriving it from the element width is the plausible wrong model.
    arm(' R22 the group stride is independent of element size: za.d vgx4 is still 16',
        (_str(_g4d) == _str(_g4s), '8' in _str(_g4d)), (True, False))
    #  Wv AND THE IMMEDIATE ADD INTO ONE SLICE INDEX, then wrap mod 64/VG (measured:
    #    vgx4 w8=20 lands exactly where w8=4 does).
    arm(' R22 the slice index wraps mod 64/VG — one index, not a register plus an offset',
        ('= and i64 %t3, 15' in _g4s, '= and i64 %t3, 31' in _g2s), (True, True))

    _z1s = _s2('zero\t{za1.s}')
    #  TILE <T> OF AN esize=E SET HOLDS ROW i AT ARRAY VECTOR T + (E/8)*i. Confirmed
    #    independently: `zero {za1.s}` clears 1, 5, 9, ... 61, not a contiguous block.
    arm(' R22 a ZA tile owns rows T + (esize/8)*i, so zero {za1.s} clears 1,5,9,13...',
        (re.findall(r'i64 0, i64 (\d+)', _z1s)[:4],
         _z1s.count('store <64 x i8> zeroinitializer'),
         _s2('zero\t{za}').count('store <64 x i8> zeroinitializer')),
        (['1', '5', '9', '13'], 16, 64))

    _fc = _s2('fcvt\tz0.h, { z0.s, z1.s }')
    _fn = _s2('fcvtn\tz2.h, { z4.s, z5.s }')
    #  ONE LETTER APART AND COMPLETELY DIFFERENT LAYOUTS (measured). fcvt CONCATENATES
    #    (lanes 0..15 from z0, 16..31 from z1); fcvtn INTERLEAVES (lane 2i from z0).
    #    Either one implemented as the other returns a full register of real numbers in
    #    the wrong order, which no shape check can see.
    arm(' R22 fcvt CONCATENATES and fcvtn INTERLEAVES — the same operands, two layouts',
        ('i32 0, i32 1, i32 2, i32 3' in _fc, 'i32 0, i32 16, i32 1, i32 17' in _fn,
         _fc == _fn), (True, True, False))

    _ldw = _s2('ld1w\t{ z0.s - z3.s }, pn8/z, [x9, #0x4, mul vl]')
    _stw = _s2('st1w\t{ z0.s - z3.s }, pn8, [x9]')
    #  A MASKED LOAD, NOT A FULL LOAD PLUS A SELECT. The inactive lanes of a prefix mask
    #    routinely sit past the end of a mapping; a full load there is a fault the
    #    hardware does not take, and it would only ever show up at a page boundary.
    arm(' R22 a multi-vector load/store is MASKED per vector, never full-width',
        (_ldw.count('@llvm.masked.load'), _stw.count('@llvm.masked.store'),
         'load <16 x i32>, ptr %t' in _ldw), (4, 4, False))
    #  THE `mul vl` IMMEDIATE SCALES BY SVL EXACTLY ONCE — measured: ld1w x4 at #4
    #    starts at SVL chunk 4, not chunk 16. Scaling by the list length is the plausible
    #    wrong model and it reads four vectors from the wrong place, silently.
    arm(' R22 the mul vl immediate scales by SVL once, not by the list length',
        ('= add i64 %t1, 256' in _ldw, '1024' in _ldw), (True, False))

    _w4 = _s2('whilelt\tpn8.s, x8, x9, vlx4')
    _w2 = _s2('whilelt\tpn8.s, x8, x9, vlx2')
    _wg = _s2('whilegt\tpn10.d, x0, x1, vlx4')
    #  THE GROUP WIDTH IS NOT IN THE COUNTER. The same pn8 saturates at 64 lanes for an
    #    x4 consumer and 32 for an x2 one — the capacity comes from the consumer, which is
    #    why a decoder that reads a lane count out of the register alone cannot be right.
    arm(' R22 a predicate-as-counter takes its capacity from the CONSUMER, not itself',
        (re.findall(r'icmp ult i64 %t\d+, (\d+)', _w4)[:1],
         re.findall(r'icmp ult i64 %t\d+, (\d+)', _w2)[:1]), (['64'], ['32']))
    #  whilegt ENCODES inv=1 WITH count = capacity - active; whilelt encodes inv=0.
    #    Both decode to a PREFIX mask — the inversion is in the encoding, not the mask.
    arm(' R22 whilegt sets the counter inversion bit and whilelt does not',
        ('32776' in _wg, '32776' in _s2('whilelt\tpn10.d, x0, x1, vlx4')), (True, False))
    #  AND THE DECODE MUST SURVIVE raw == 0, which is the legal "empty" encoding. A
    #    cttz with is_zero_poison would poison the select that rescues it.
    arm(' R22 the counter decode treats raw == 0 as empty, not as poison',
        ('@llvm.cttz.i64(i64 %t3, i1 false)' in _ldw, 'i1 true)' in _ldw), (True, False))

    _mv = _s2('mova\tz0.s, p0/m, za0v.s[w12, 3]')
    #  A VERTICAL TILE SLICE IS THE EXACT TRANSPOSE (measured): element i of
    #    za<T>v.<t>[Wv,k] is (tile row i)[lane k]. It is n scalar accesses across strided
    #    rows, because a transpose of a strided row set is not a vector operation.
    arm(' R22 a vertical ZA slice is the transpose — one lane read across strided rows',
        (re.findall(r'i64 0, i64 (\d+)\n', _mv)[:4], len(re.findall(r'= load i\d+, ptr %t', _mv))),
        (['0', '4', '8', '12'], 16))

    _tb = _s2('tbl\tz5.b, { z6.b }, z7.b')
    #  AN OUT-OF-RANGE tbl INDEX READS ZERO, IT DOES NOT WRAP (measured). A modulo here
    #    returns a plausible element from the wrong lane and nothing ever looks wrong.
    arm(' R22 tbl reads ZERO out of range — never a wrap, never a clamp',
        (_tb.count('icmp ult i8'), 'urem' in _tb, 'and i8' in _tb), (64, False, False))

    #  WHAT WAS NOT READ OFF SILICON STILL BLOCKS, and it must keep blocking. movaz needs
    #    FEAT_SME2p1 which the M4 does not have (47 instances in the shared cache); luti4
    #    needs ZT0; the bf16 family and the integer outer products were never measured;
    #    splice's first-active-to-last-active copy was not measured either. sme2() returns
    #    False for every one of them and the phase-3 aborts fire exactly as before.
    #  R33 bfmopa, smopa, splice and st2w LEFT THIS LIST: they are judged now by the
    #    R33 oracle on an M4. movaz (FEAT_SME2p1, not on the M4) and the 8-bit luti4 list
    #    form (not in the gap) stay, and must keep blocking.
    #  R39 movaz STILL BLOCKS — now at run time, by name (R38_NOFEAT), because no owned
    #    chip has FEAT_SME2p1. The arm proves the same promise: no lowering is emitted for it.
    _mz = ll('1000:\tmovaz\t{ z0.s - z3.s }, za.s[w8, 0, vgx4]\n1004:\tret')
    arm(' R22/R39 unmeasured movaz blocks by name and lowers nothing',
        #  the span is the site itself: `L1000:` up to the abort must be EMPTY. (A whole-IR
        #    'load <' test hit the ret block's v0 read at 1004 and measured nothing about movaz.)
        ('@__arm2x86_nofeature(' in _mz, 'unreachable' in _mz,
         _mz.split('L1000:')[1].split('call void @__arm2x86_nofeature(')[0].strip()), (True, True, ''))
    for _u in ('luti4\t{ z0.b - z3.b }, zt0, { z4, z5 }',):
        arm(f' R22 unmeasured SME2 still BLOCKS: {_u.split(chr(9))[0]}',
            _how(_u), 'NotImplementedError')
    #  AND THE NEW PATH MUST NOT OVER-FIRE. sme2() runs before the phase-3 guards and
    #    sees EVERY SVE instruction; an arm that only proved the new forms lift would not
    #    notice it swallowing `add z0.s, z1.s, z2.s` on the way past.
    #  R33 ZT0 IS 64 BYTES OF ITS OWN, and ldr/str move all of them.
    _zt = _s2('ldr\tzt0, [x0]')
    arm(' R33 ldr zt0 moves 64 bytes into %zt0, never an i64',
        ('ptr %zt0' in _zt, 'store i64' in _zt.split('ptr %zt0')[0].splitlines()[-1]),
        (True, False))
    arm(' R33 the prologue allocates ZT0 as <64 x i8> and zeroes it',
        ('%zt0 = alloca <64 x i8>' in ll('1000:\tret'),
         'store <64 x i8> zeroinitializer, ptr %zt0' in ll('1000:\tret')), (True, True))
    #  A PREDICATE IS 8 BYTES, so its `mul vl` scales by 8 — #3 is +24, never +192.
    _lp = _s2('ldr\tp1, [x0, #3, mul vl]')
    arm(' R33 ldr p, mul vl scales by the PREDICATE length (8), not the vector length',
        ('add i64' in _lp and ', 24' in _lp, ', 192' in _lp), (True, False))
    #  AN UNKNOWN PATTERN AND A MISMATCHED WIDTH STILL BLOCK — a fallback that guessed
    #    would lower something plausible, the most expensive recurring bug here.
    arm(' R33 an unknown ptrue pattern and a width-mismatched dup still BLOCK',
        (_how('ptrue\tp0.s, vl300'), _how('mov\tz0.s, d1')),
        ('NotImplementedError', 'NotImplementedError'))
    #  THE FALLBACK MUST NOT REPLACE A VERIFIED ARM. `add z0.s, z1.s, z2.s` is R18's;
    #    no R33 handler may appear in its IR (R33 masks read p-registers as i64 bitcasts).
    arm(' R33 a verified SVE arm still owns its form — the fallback does not run',
        '@llvm.masked' in _s2('add\tz0.s, z1.s, z2.s'), False)
    arm(' R22 sme2 does not over-fire — plain SVE and plain predicates are untouched',
        (_how('add\tz0.s, z1.s, z2.s'), _how('ptrue\tp0.s'),
         _how('fmul\tz0.d, z1.d, z2.d')), ('LIFTED (must not)',) * 3)

    _fc9 = _r9('fcadd.4s\tv16, v16, v18, #90')
    _fc27 = _r9('fcadd.4s\tv16, v16, v18, #270')
    arm(' R9 fcadd #90 and #270 are CONJUGATES — the two lifts must not be identical',
        (_fc9 != _fc27, 'i32 1, i32 0, i32 3, i32 2' in _fc9), (True, True))
    arm(' R9 fcadd #90 negates the EVEN lanes and #270 the ODD ones',
        ('<float -1.000000e+00, float 1.000000e+00, '
         'float -1.000000e+00, float 1.000000e+00>' in _fc9,
         '<float 1.000000e+00, float -1.000000e+00, '
         'float 1.000000e+00, float -1.000000e+00>' in _fc27), (True, True))
    arm(' R9 an unrecognised fcadd rotation BLOCKS rather than picking one',
        _how('fcadd.4s\tv0, v1, v2, #45'), 'NotImplementedError')

    #  R9-h THE LAYER THE R9 SWEEP UNCOVERED — these never appeared in the pre-R9
    #    blocker table because their functions were already dying on an earlier insn.
    _bad_h = []
    for _t in ('sri.16b\tv0, v1, #0x3', 'sri.8b\tv0, v1, #0x8', 'sli.4s\tv0, v1, #0x0',
               'sli.2d\tv0, v1, #0x1', 'srshr.16b\tv0, v1, #0x1',
               'urshr.8h\tv0, v1, #0x5', 'srsra.8h\tv0, v1, #0x2',
               'ursra.4s\tv0, v1, #0x3', 'shll2.4s\tv0, v1, #0x10',
               'shll.8h\tv0, v1, #0x8', 'cls\tx0, x1', 'cls\tw0, w1',
               'rev32\tx0, x1'):
        try:
            _r9(_t)
        except Exception as _e:
            _bad_h.append(f'{_t}  ->  {type(_e).__name__}: {_e}')
    arm(' R9-h the second layer of the tail lifts', _bad_h, [])

    #  THE ROUNDING CONSTANT OVERFLOWS THE LANE IT IS ADDED IN — .16b with 0x7F and a
    #    shift of 1 is 64, but 127+1 in an i8 is -128 and ashr gives -64. So srshr MUST
    #    widen and ssra (which cannot overflow) MUST NOT — the differential proves both.
    arm(' R9-h srshr computes its rounding one width UP; ssra stays in the lane',
        ('<16 x i16>' in _r9('srshr.16b\tv0, v1, #0x1'),
         '<16 x i16>' in _r9('ssra.16b\tv0, v1, #0x4')), (True, False))
    #  SRI/SLI READ THEIR OWN DESTINATION — the bits shifted out of range are KEPT, not
    #    zeroed. A lift that does not read Vd is a plain shift wearing the right name.
    arm(' R9-h sri and sli read the destination they insert into',
        (_r9v('sri.16b\tv0, v1, #0x3'),
         _r9v('sli.16b\tv0, v1, #0x3')), (2, 2))
    #  `lshr i8 x, 8` IS POISON, NOT ZERO. sri #esize is a legal encoding meaning
    #    "leave Vd alone", and it must emit no shift at all.
    arm(' R9-h sri #esize leaves Vd alone instead of emitting a poison shift',
        ('lshr' in _r9('sri.8b\tv0, v1, #0x8'),
         'lshr' in _r9('sri.8b\tv0, v1, #0x7')), (False, True))
    arm(' R9-h scalar cls is the same CLZ identity as the vector form',
        ('@llvm.ctlz.i64' in _r9('cls\tx0, x1'),
         '@llvm.ctlz.i32' in _r9('cls\tw0, w1')), (True, True))
    arm(' R9-h rev32 swaps within each WORD (a rotate of bswap), and has no w form',
        ('@llvm.bswap.i64' in _r9('rev32\tx0, x1'), _how('rev32\tw0, w1')),
        (True, 'NotImplementedError'))

    #  R10 bti is a landing pad. All four forms lift, none of them emits anything, and
    #    none of them disturbs a register — the bug it replaces was an ABORT, so the arm
    #    that matters is that the function around it still translates and x0 survives.
    for _f in ('bti', 'bti c', 'bti j', 'bti jc'):
        _ir = ll(f'0: {_f}\n4: add x0, x0, #1\n8: ret\n')
        arm(f' R10 `{_f}` lifts as a landing pad and emits no instruction',
            ('bti' in _ir.lower(), 'add i64' in _ir), (False, True))

    # ── R11 the computed jump table ────────────────────────────────────────
    #  THE ARM THAT WOULD HAVE CAUGHT IT: a `br` whose target is an address INSIDE the
    #    function must become a local branch, not a call into the global fnmap. The shape is
    #    taken from _zlibDecodeBuffer verbatim, including the interior landing site that no
    #    direct branch names.
    _jt = ll('1000:\tadr\tx17, 0x1010\n'
             '1004:\tldrsw\tx16, [x17, x16, lsl #2]\n'
             '1008:\tadd\tx16, x17, x16\n'
             '100c:\tbr\tx16\n'
             '1010:\tmov\tx0, #1\n'
             '1014:\tret\n'
             '1018:\tmov\tx0, #2\n'
             '101c:\tret\n')
    arm(' R11 an indirect br switches over the addresses INSIDE the function',
        ('switch i64' in _jt, 'label %L1018' in _jt, 'label %L1010' in _jt),
        (True, True, True))
    arm(' R11 an address that is in NO block still reaches the global dispatch and aborts',
        ('@__arm2x86_dispatch' in _jt, 'IND100c:' in _jt), (True, True))
    #  AND IT MUST NOT FIRE WHERE THERE IS NO INDIRECT BRANCH. Labelling every address in
    #    every function would bury the real change in noise and cost compile time on all 4,083
    #    images — the superset is scoped to the functions that actually need it.
    _nojt = ll('1000:\tmov\tx0, #1\n1004:\tadd\tx0, x0, #1\n1008:\tret\n')
    arm(' R11 a function with no indirect branch is NOT exploded into per-address blocks',
        ('switch i64' in _nojt, 'L1004:' in _nojt), (False, False))

    # ── R19 the jump table's payload is DATA ───────────────────────────────
    #  THE SHAPE IS JavaScriptCore 0x1a47efbfc VERBATIM, including the adrp+add table
    #    pointer and the SEPARATE adr pc-base that reuses the same register. A positive
    #    entry disassembles as `udf`, a negative one as `<unknown>`; both are the table.
    _r19 = ('1000:\tcmp\tx16, #0x2\n'
            '1004:\tcsel\tx16, x16, xzr, ls\n'
            '1008:\tadrp\tx17, 0x1000\n'
            '100c:\tadd\tx17, x17, #0x20\n'
            '1010:\tldrsw\tx16, [x17, x16, lsl #2]\n'
            '1014:\tadr\tx17, 0x1014\n'
            '1018:\tadd\tx16, x17, x16\n'
            '101c:\tbr\tx16\n'
            '1020:\tudf\t#0x14\n'          # <- payload, 3 entries at 0x1020..0x1028
            '1024:\t<unknown>\n'
            '1028:\tudf\t#0x1c\n'
            '102c:\tmov\tx0, #1\n'
            '1030:\tret\n')
    _j = ll(_r19)
    arm(' R19 a jump table whose payload includes <unknown> TRANSLATES — it is data',
        ('switch i64' in _j, 'define' in _j), (True, True))
    arm(' R19 no payload word becomes a block R11\u2019s switch can branch INTO',
        ('L1020:' in _j, 'L1024:' in _j, 'L1028:' in _j), (False, False, False))
    arm(' R19 real code AFTER the payload is still translated, not truncated',
        ('L102c:' in _j, 'label %L102c' in _j), (True, True))
    #  THE GUARD MUST FIRE IN THE OTHER DIRECTION TOO. A trap that no dispatch indexes
    #    is a REAL trap — Apple's PAC epilogue ends in `brk`, and 5 functions were once
    #    miscounted for exactly this confusion. Swallowing it would invent an answer.
    _nt = ll('1000:\tcmp\tx0, #1\n'
             '1004:\tb.eq\t0x1010\n'
             '1008:\tudf\t#0x0\n'
             '100c:\tret\n'
             '1010:\tret\n')
    arm(' R19 a udf that NO dispatch indexes is still a real trap, not data',
        ('@__arm2x86_trap' in _nt, 'L1008:' in _nt), (True, True))
    #  AND IT MUST NOT FIRE WHEN THE TABLE POINTS AT REAL CODE — that is R11's own
    #    fixture, where adr names a base holding instructions, not a payload.
    arm(' R19 a dispatch whose base holds REAL instructions reclassifies nothing',
        (jump_table_data(parse('1000:\tadr\tx17, 0x1010\n'
                               '1004:\tldrsw\tx16, [x17, x16, lsl #2]\n'
                               '1008:\tadd\tx16, x17, x16\n'
                               '100c:\tbr\tx16\n'
                               '1010:\tmov\tx0, #1\n'
                               '1014:\tret\n')),
         jump_table_data(parse('1000:\tmov\tx0, #1\n1004:\tret\n'))), (set(), set()))
    #  AND THE BASE IT RESOLVES IS THE TABLE, NOT THE PC — the bug that made the first
    #    measurement report base == pc on all 782 JavaScriptCore sites.
    arm(' R19 the resolved base is the adrp+add table pointer, not the adr pc base',
        sorted(jump_table_data(parse(_r19))), [0x1020, 0x1024, 0x1028])

    # ── R20 arms APPLE'S AMX COPROCESSOR ──────────────────────────────────
    #  The fixture is REAL llvm-objdump output shape, verified against libLAPACK on
    #    2026-09-22: `<addr>: <8 hex> \t<unknown>`. An earlier draft of the parser
    #    expected four space-separated byte pairs, matched nothing, and would have shipped
    #    an inert patch under a green suite — so the arms use the measured shape.
    def _amx(w):
        return ll('1000: %08x    \t<unknown>\n1004:\tret' % w)

    def _amx_dir(w):
        """'load' or 'store' — which side of the memcpy the register file sits on."""
        ls = _amx(w).splitlines()
        gep = [l for l in ls if 'getelementptr i8, ptr @__arm2x86_amx_' in l][0]
        reg = gep.split('=')[0].strip()
        args = [l for l in ls if 'llvm.memcpy' in l][0].split('(', 1)[1]
        return 'load' if args.split(',')[0].split()[-1] == reg else 'store'

    def _amx_idx(w):
        ls = _amx(w).splitlines()
        i = [k for k, l in enumerate(ls) if 'lshr i64' in l][0]
        return ls[i + 1].split(',')[-1].strip()

    def _amx_addrmask(w):
        ls = _amx(w).splitlines()
        i = [k for k, l in enumerate(ls) if 'inttoptr i64' in l][0]
        return int(ls[i - 1].split(',')[-1].strip())

    def _amx_memset(w):
        ls = [l for l in _amx(w).splitlines() if 'llvm.memset' in l]
        return (len(ls), sum(int(l.split('i64 ')[1].split(',')[0]) for l in ls))

    #  THE WHOLE FAMILY IS INVISIBLE WITHOUT THE RAW WORD. Six scripts still pass
    #    --no-show-raw-insn, so parse() must read both shapes or this is a regression.
    arm(' R20 parse reads a raw word AND still reads a raw-less line',
        (parse('1000: 00201080    \t<unknown>')[0][1],
         parse('1000:\tmov\tx0, x1')[0][1],
         parse('1000: a9116ffc    \tstp\tx28, x27, [sp, #0x110]')[0][2]),
        ('amx', 'mov', ['x28', 'x27', '[sp, #0x110]']))
    arm(' R20 the AMX word carves into op and operand (0x00201080 = op4 operand0)',
        (parse('1000: 00201080    \t<unknown>')[0][2],
         parse('1000: 00201091    \t<unknown>')[0][2]),
        (['#4', '#0'], ['#4', '#17']))
    #  R19 NEEDS NON-AMX UNDECODABLE WORDS TO STAY `<unknown>` — that is how it finds
    #    jump-table payload. Reclassifying all of them would turn 186,577 DATA words into
    #    instructions and R19's guard would go blind.
    arm(' R20 an undecodable word that is NOT AMX stays `<unknown>`',
        (parse('1000: ffff0000    \t<unknown>')[0][1],
         parse('1000: 00202000    \t<unknown>')[0][1]),
        ('<unknown>', '<unknown>'))
    #  A REVERSED TRANSFER STILL EMITS A MEMCPY and still "translates". Direction is the
    #    one thing a shape check cannot see.
    arm(' R20 op0/op1/op4 load INTO the file, op2/op3/op5 store OUT of it',
        (_amx_dir(0x00201000), _amx_dir(0x00201020), _amx_dir(0x00201080),
         _amx_dir(0x00201040), _amx_dir(0x00201060), _amx_dir(0x002010a0)),
        ('load', 'load', 'load', 'store', 'store', 'store'))
    #  Z HAS 64 REGISTERS AND X/Y HAVE 8 — measured by first aliasing index, not by
    #    counting responding bits. One shared mask would fold Z's 64 registers onto 8 and
    #    a BLAS kernel would read the wrong tile with no error anywhere.
    arm(' R20 the index mask is 7 for X/Y and 63 for Z',
        (_amx_idx(0x00201000), _amx_idx(0x00201020), _amx_idx(0x00201080)),
        ('7', '7', '63'))
    #  THE MASK DROPS THE INDEX BITS AND NOTHING ELSE. It used to clear bit 32 as
    #    well, and this arm asserted that it did — an arm can only ever be as right as the
    #    claim it was written from. Clearing bit 32 points every macOS arm64 pointer below
    #    4 GB, which is unmapped: measured both ways, the address as given loads and the
    #    same address with bit 32 cleared takes a Bus error.
    arm(' R32 the address mask drops ONLY the index bits — bit 32 is an ADDRESS bit',
        (_amx_addrmask(0x00201000) >> 56,
         (_amx_addrmask(0x00201000) >> 32) & 1,
         (_amx_addrmask(0x00201000) >> 33) & 1),
        (0, 1, 1))
    #  ENABLE ZEROES ALL 5120 BYTES. Measured: disable+enable then store X0 reads ZEROS.
    #    Enable-as-a-no-op hands the guest the previous kernel's tile and passes every
    #    arm that only asks "did it translate".
    arm(' R20 op17 operand 0 zeroes all three files (512+512+4096 = 5120 B)',
        _amx_memset(0x00201220), (3, 5120))
    #  A COMPUTE OP MUST NOT BECOME A NO-OP. A nop here makes a BLAS kernel return the
    #    zeros it was initialised with, which reads exactly like success.
    arm(' R21 every AMX compute op calls the runtime helper, and op0 still does not',
        ('@__arm2x86_amx_op' in _amx(0x00201140),   # op10, no operand layout yet
         '@__arm2x86_amx_op' in _amx(0x00201180),   # op12, measured and implemented
         '@__arm2x86_amx_op' in _amx(0x002012c0),   # op22
         '@__arm2x86_amx_op' in _amx(0x002010c0),   # op6, Z interleaved transfer
         '@__arm2x86_amx_op' in _amx(0x00201000)),  # op0 is a LOAD, lowered inline
        (True, True, True, True, False))
    #  THE OPERAND IS A REGISTER NUMBER. The helper must receive what the GPR HOLDS, not
    #    the register's index — reading x5 for `op12 operand 5` is the entire mechanism,
    #    and an arm that only checked "is the helper called" would pass while the
    #    translator handed the runtime a small integer instead of a configuration word.
    arm(' R21 the helper receives the GPR VALUE, and operand N reads register xN',
        (' = load i64, ptr %x5' in _amx(0x00201185),
         ' = load i64, ptr %x5' in _amx(0x00201180)),
        (True, False))
    #  THE STATE IS DECLARED, NOT DEFINED. A `thread_local global ... zeroinitializer` in
    #    emitted IR is a definition in EVERY module: it collides with amx_rt.c and with any
    #    second translated module. One linked module hid this for a whole build.
    arm(' R21 the AMX register files are external, so amx_rt.c owns the storage',
        ('@__arm2x86_amx_x = external thread_local global [512 x i8]' in PRELUDE,
         'zeroinitializer' in PRELUDE.split('@__arm2x86_amx_x')[1].split('\n')[0]),
        (True, False))

    # ── R12 THE FP/SIMD HALF OF AAPCS64 ───────────────────────────────────
    #  THE ARM THAT WOULD HAVE CAUGHT IT. Not "does the signature mention <2 x i64>" —
    #    the claim is that a VALUE PUT IN v0 BEFORE A CALL IS THE VALUE THE CALLEE READS.
    #    Measured in both directions: the caller must pass its own v0 (not a zero), and
    #    the callee's define must store its incoming %q0 into %v0 AFTER the zero-init.
    _vc = ll('1000:\tfmov\td0, x1\n1004:\tbl\t0x2000 <_f>\n1008:\tret\n', known={0x2000})
    _pass = re.search(r'call \{ i64, <2 x i64> \} @fn_2000\(([^)]*)\)', _vc)
    arm(' R12 a bl passes all 16 AAPCS64 argument registers, not 8',
        (bool(_pass), len(_pass.group(1).split(', ')) if _pass else 0), (True, 16))
    arm(' R12 the caller passes its OWN v0, not a zeroinitializer',
        bool(_pass) and 'zeroinitializer' not in _pass.group(1).split(', ')[8], True)
    _dfn = ll('2000:\tumov.h\tw8, v0[0]\n2004:\tret\n')
    #  R18 widened the vector file 16 -> SVL_B bytes, and this arm went looking for
    #    the old width and died. It is anchored on the CONSTANT now, so the ordering
    #    invariant it actually protects survives the next change to the register size.
    _zi = _dfn.index(f'store <{SVL_B} x i8> zeroinitializer, ptr %v0')
    _st = _dfn.index('store <16 x i8> %qin0, ptr %v0')
    arm(' R12 the incoming v0 is stored AFTER the zero-init, not before it',
        _st > _zi, True)
    arm(' R12 the return carries v0 as well as x0 (ARM returns floats in v0)',
        ('insertvalue { i64, <2 x i64> }' in _dfn,
         _dfn.count('ret { i64, <2 x i64> }') >= 1), (True, True))
    #  AND THE INDIRECT PATH TOO — a blraa that dropped v0-v7 would be the same bug
    #    reachable through a different mnemonic, which is how R9-h's queue works.
    _ind = ll('1000:\tblraa\tx8, x9\n1004:\tret\n')
    _ip = re.search(r'call \{ i64, <2 x i64> \} @__arm2x86_dispatch\(([^)]*)\)', _ind)
    arm(' R12 the indirect dispatch carries the vectors too (17 = target + 16)',
        (bool(_ip), len(_ip.group(1).split(', ')) if _ip else 0), (True, 17))
    _hd = _module_head()
    arm(' R12 the dispatch is DEFINED in IR, not declared as C (the sret ABI hazard)',
        ('define internal { i64, <2 x i64> } @__arm2x86_dispatch(' in _hd,
         'declare ptr @__arm2x86_lookup(i64)' in _hd), (True, True))

    # ── R13 variable shifts, every number below measured on real arm64 silicon ──
    #    (shift.c / shift.s, a=0x9e3779b1; the translated side ran on the Xeon)
    def _mask(t, n):
        # anchored on the MASK, not on a temp number: the first version of this
        # arm asserted `and i64 %t2, 31` and failed because rd() spends two temps
        # reading the source register first. The claim is 'a mask by n is
        # emitted', so the arm says that and nothing about numbering.
        import re as _re
        return bool(_re.search(r'and i64 %t\d+, ' + str(n) + '$', _sh(t), _re.M))
    def _sh(t):
        return ll(f'1000:\t{t}\n1004:\tret')
    arm('\u2b50 R13 a 32-bit variable shift masks the amount to 5 bits',
        (_mask('lsr\tw13, w9, w10', 31),
         _mask('lsl\tw13, w9, w10', 31)), (True, True))
    arm('\u2b50 R13 a 64-bit variable shift masks the amount to 6 bits',
        _mask('lsr\tx13, x11, x12', 63), True)
    # \u26d4 THE ARM THAT NAMES THE BUG: an unmasked amount is POISON, not a big shift.
    arm('\u26d4 R13 no shift is emitted with an unmasked amount operand',
        [l for l in _sh('lsr\tw13, w9, w10').splitlines()
         if ('lshr' in l or ' shl ' in l or 'ashr' in l) and '%t2' in l and 'and' not in l],
        [])
    # \u26d4 asr w SHIFTS IN ONES. The old lowering masked the value to 32 bits and shifted
    #    as i64, so it shifted in zeros for every negative operand at EVERY amount \u2014 a
    #    bug that had nothing to do with the amount and would have survived a mask-only fix.
    arm('\u26d4 R13 asr w is performed in i32 so the sign is shifted in',
        ('ashr i32' in _sh('asr\tw13, w9, #0x4'),
         'ashr i32' in _sh('asr\tw13, w9, w10')), (True, True))
    arm('\u2b50 R13 asr x stays 64-bit (a trunc would throw away the sign it needs)',
        ('ashr i64' in _sh('asr\tx13, x11, #0x4'),
         'ashr i32' in _sh('asr\tx13, x11, #0x4')), (True, False))
    arm('\u2b50 R13 the register-form aliases lslv/lsrv/asrv lower like their base',
        (_mask('lsrv\tw13, w9, w10', 31),
         'ashr i32' in _sh('asrv\tw13, w9, w10')), (True, True))
    arm('\u26d4 R13 `ror #0` is the value, not `shl i64 v, 64` (poison)',
        'shl i64 %t1, 64' in _sh('orr\tx0, xzr, x1, ror #0'), False)
    # \u2b50 THE WHOLE IDIOM, END TO END \u2014 this is the sequence libcompression hashes with,
    #    and the constant 18 is what -14 masks to. Named because the name is the spec.
    _hash = ll('1000:\tmov\tw10, #0xe\n1004:\tneg\tw10, w10\n'
               '1008:\tlsr\tw12, w9, w10\n100c:\tret')
    arm('\u2b50 R13 the LZFSE hash idiom `neg w10,w10 ; lsr w12,w9,w10` shifts by 18',
        'and i64 %t' in _hash and 'lshr i32' in _hash, True)

    # ── R13-b the shifted-register OPERAND path (measured on silicon, shop.c) ──
    arm(' R13-b `w, asr #31` shifts in i32 so it broadcasts the sign, not 0 or 1',
        ('ashr i32' in _sh('bic\tw13, w9, w9, asr #31'),
         'ashr i64' in _sh('bic\tw13, w9, w9, asr #31')), (True, False))
    arm(' R13-b an x operand still shifts in i64',
        ('ashr i64' in _sh('add\tx13, x12, x11, asr #4'),
         'ashr i32' in _sh('add\tx13, x12, x11, asr #4')), (True, False))
    arm(' R13-b a 32-bit ror operand rotates within 32 bits',
        '@llvm.fshr.i32' in _sh('eor\tw13, w10, w9, ror #8'), True)
    #  the extend forms must NOT be re-truncated by the new w32 branch: `w2, sxtw #2`
    #    already sign-extends to 64 bits and the shift belongs at 64.
    arm(' R13-b sxtw/uxtw operands are untouched by the 32-bit branch',
        ('shl i64' in _sh('add\tx13, x12, w9, sxtw #2'),
         'sext i32' in _sh('add\tx13, x12, w9, sxtw #2')), (True, True))

    # ── R13-c a ror'd operand is a rotate, and an unknown one aborts ──────────
    #  THE CLAIM IS "A ROTATE IS EMITTED", NOT "THIS INTRINSIC IS EMITTED". The first
    #    version of this arm asserted @llvm.fshr.i64 and failed, because the 64-bit
    #    operand path lowers a constant rotate as lshr+shl+or (equivalent — `a == 0`
    #    returns early above, so neither shift can be by the width). Asserting on the
    #    lowering would have sent me to "fix" correct code.
    def _rot64(t):
        o = _sh(t)
        return ('lshr i64' in o) and ('shl i64' in o) and ('or i64' in o)
    arm(' R13-c a ror-shifted operand is a ROTATE, not a dropped shift',
        ('@llvm.fshr.i32' in _sh('eor\tw13, w10, w9, ror #8'),
         _rot64('and\tx13, x10, x9, ror #8')), (True, True))
    #  BOTH DIRECTIONS. Proving it aborts on nonsense is the half that was missing:
    #    the old code reported a clean translation for an operand it had thrown away.
    def _raises(t):
        try:
            _sh(t); return False
        except Exception:
            return True
    arm(' R13-c an unrecognised operand modifier ABORTS instead of being dropped',
        (_raises('eor\tw13, w10, w9, zzz #4'), _raises('eor\tw13, w10, w9, ror #8')),
        (True, False))

    # ── R14 a bind can carry a floating-point value ──────────────────────────
    _fpb = {0x1980f85b0: {'sym': '__arm2x86_log2l', 'argc': 1, 'ret': 'double',
                          'args': 'd', 'cache': '_log2l', 'target': '1980f85b0',
                          'sites': 1}}
    _fd = _tf.mkdtemp(prefix='a2x_r14_')
    _fp2 = os.path.join(_fd, 'g.txt')
    open(_fp2, 'w').write('1000:\tbl\t0x1980f85b0\n1004:\tret\n')
    _fm = build([(_fp2, 'usesfp', 0)], binds=_fpb)
    arm(' R14 a double argument is read from v0, NOT x0',
        ('extractelement <2 x double>' in _fm,
         'call double @__arm2x86_log2l(double' in _fm), (True, True))
    #  THE DECLARE IS THE HALF THAT LINKS. `declare double @f(i64)` would link against the
    #    real symbol and pass the argument in rdi — wrong, silently, at run time.
    arm(' R14 the declare carries the real signature, not i64',
        ('declare double @__arm2x86_log2l(double)' in _fm,
         'declare double @__arm2x86_log2l(i64)' in _fm), (True, False))
    arm(' R14 the result is written to v0 and x0 is made deterministic',
        ('insertelement <2 x double> zeroinitializer' in _fm,
         'store <16 x i8> %' in _fm), (True, True))
    #  BOTH DIRECTIONS: the map must hold the THUNK, and must NOT hold the bare symbol.
    _row = re.search(r'@__arm2x86_fnmap = constant.*', _fm).group(0)
    arm(' R14 the dispatch map holds the thunk, never the bare FP symbol',
        ('ptr @__arm2x86_bindthunk___arm2x86_log2l' in _row,
         'ptr @__arm2x86_log2l' in _row), (True, False))
    arm(' R14 an all-integer bind is UNCHANGED — it stays bare in the map',
        ('ptr @probe_only_indirect' in
         re.search(r'@__arm2x86_fnmap = constant.*', _fb).group(0),
         'bindthunk' in _fb), (True, False))
    #  a bind whose kinds disagree with its count must BLOCK, not pick one.
    try:
        build([(_fp2, 'usesfp', 0)],
              binds={0x1980f85b0: dict(_fpb[0x1980f85b0], args='dd')})
        arm(' R14 args/argc disagreement BLOCKS', False, True)
    except NotImplementedError:
        arm(' R14 args/argc disagreement BLOCKS', True, True)

    #  R16 THE PAC FAMILY IS 28,929,567 INSTRUCTIONS — 3.2% of everything the cache
    #    executes, the largest mnemonic family we touch, and we lower nearly all of it to
    #    NOTHING. "A no-op is correct" is a CLAIM. The arm is not "does pacibsp emit zero
    #    instructions" — that only restates the lowering. It is the ABORT invariant: every
    #    PAC-family mnemonic that appears in the real cache must LIFT.
    #  The fixed-register forms took no operands and raised IndexError inside the general
    #    handler, so they did not lift wrong, they killed the whole function.
    _pacfam = ['pacibsp', 'autibsp', 'paciasp', 'autiasp', 'pacia', 'pacda', 'pacib',
               'pacdb', 'paciza', 'pacdza', 'autda', 'autdb', 'autia', 'autib', 'autiza',
               'autdza', 'xpaci', 'xpacd', 'pacia1716', 'pacib1716', 'autib171615', 'pacga']
    _ln, _src = 0x1000, []
    for _m in _pacfam:
        if _m.endswith('sp') or _m.endswith('1716') or _m.endswith('171615'):
            _o = ''
        elif _m == 'pacga':
            _o = '\tx3, x1, x2'
        elif _m.endswith('za') or _m == 'xpaci' or _m == 'xpacd':
            _o = '\tx8'
        else:
            _o = '\tx8, x9'
        _src.append(f'{_ln:x}:\t{_m}{_o}')
        _ln += 4
    _src.append(f'{_ln:x}:\tret')
    _pp = os.path.join(_tf.mkdtemp(prefix='a2x_pac_'), 'p.txt')
    open(_pp, 'w').write('\n'.join(_src) + '\n')
    _pm = build([(_pp, 'pacprobe', 0)])
    arm(' R16 every PAC-family mnemonic in the real cache LIFTS (no abort)',
        '__arm2x86_abort' in _pm, False)
    arm(' R16 the fixed-register forms write X17, the implicit destination',
        _pm.count('%x17') > 0, True)
    #  PACGA must be a FUNCTION OF BOTH OPERANDS. A constant, or a mix that drops one
    #    operand, makes two different inputs produce the same code — a comparison meant to
    #    fail would pass. Measured as: the code path loads x1 AND x2, and zeroes the low half.
    arm(' R16 pacga mixes BOTH source registers and zeroes Xd[31:0]',
        ('-7046029254386353131' in _pm, '-4658895280553007687' in _pm,
         'shl i64' in _pm), (True, True, True))

    # ── R17 THE TAIL ──────────────────────────────────────────────────────
    def _ir(txt):
        return Lifter(parse(txt + '\n1100:\tret\n'), 'f').define()

    #  R17-c AES ONTO THE XEON'S REAL AES-NI, verified end to end: the arm64 body and
    #    the translated x86-64 body produced byte-identical 160-byte buffers on two
    #    machines (two different CPUs), and the FIPS-197 Appendix B
    #    round-1 vector was reproduced on silicon before the mapping was written.
    _a = _ir('1000:\taese.16b\tv6, v0\n1004:\taesd.16b\tv2, v0\n'
             '1008:\taesmc.16b\tv2, v2\n100c:\taesimc.16b\tv0, v0')
    arm(' R17 aese/aesd become AESENCLAST/AESDECLAST over the XOR of BOTH operands',
        ('aesni.aesenclast' in _a, 'aesni.aesdeclast' in _a, 'xor <2 x i64>' in _a),
        (True, True, True))
    #  aesmc is NOT one intrinsic. x86 has no bare MixColumns; it is AESENC(AESDECLAST(x,0),0),
    #    and emitting AESENC alone would fold in a SubBytes the instruction does not do.
    arm(' R17 aesmc is the aesdeclast∘aesenc identity, not a single x86 instruction',
        (_a.count('aesni.aesenc(') >= 1, _a.count('aesni.aesdeclast') >= 2), (True, True))
    arm(' R17 aesimc is x86 AESIMC directly', 'aesni.aesimc' in _a, True)

    #  R17-c FJCVTZS WRAPS, IT DOES NOT SATURATE, and its Z flag has an exception the
    #    obvious predicate gets wrong. Both were read off silicon over 33 values:
    #    -2147483649.0 -> +2147483647 and -0.0 -> Z=0 while sitofp(0) oeq -0.0 is TRUE.
    _f = _ir('1000:\tfjcvtzs\tw11, d2')
    arm(' R17 fjcvtzs keeps the -0.0 Z exception (hardware says Z=0, oeq says Z=1)',
        '-9223372036854775808' in _f, True)
    arm(' R17 fjcvtzs truncates modulo 2^32 — a trunc to i32, never a saturating clamp',
        ('trunc i64' in _f, 'sitofp i32' in _f, 'sadd.sat' in _f, 'smin' in _f),
        (True, True, False, False))
    arm(' R17 fjcvtzs shifts are CLAMPED — an unclamped shift of 972 or -1075 is poison',
        _f.count('llvm.umin.i64') == 2, True)

    #  R17-c MTE IS A SUBSTITUTION, NOT A TRANSLATION, and the reason is x86, not ARM:
    #    x86-64 has no top-byte-ignore, so a propagated tag faults on the next access.
    _m = _ir('1000:\tirg\tx8, x8, x11\n1004:\taddg\tx3, x13, #0x300, #0x4\n'
             '1008:\tgmi\tx8, x19, x8\n100c:\tldg\tx10, [x10]')
    #  R17-e THE MASK IS 0xF0FFFFFFFFFFFFFF — bits 59:56 CLEARED, everything else
    #    KEPT. The first version of this arm asserted 0x0FFFFFFFFFFFFFFF, which is the
    #    mask that would throw away the whole top byte INCLUDING bits the address needs.
    #    Asserted as the number the module actually emits, and cross-checked against the
    #    table so a typo in either one cannot agree with itself.
    arm(' R17 every MTE address op clears the tag field (the legal no-MTE state)',
        (MTE_TAGMASK == 0xF0FFFFFFFFFFFFFF, str(MTE_TAGMASK) in _m,
         _m.count('and i64') >= 3), (True, True, True))
    #  STG's DATA HALF IS REAL. stzg zeroes its granule and every form writes the base
    #    back; an allocator loop that lost the writeback would spin on one granule forever.
    #  R17-e EVERY REGISTER HERE IS AN ALLOCA, SO A WRITEBACK *IS* A `store i64`.
    #    The first version of this arm used the absence of `store i64` to mean "no memory
    #    write" and was measuring the register file instead of the instruction. The claim
    #    is differential: the post-index form bumps the base by its immediate and the
    #    plain form does not touch it at all.
    _st = _ir('1000:\tstg\tx9, [x9], #0x10')
    _sp = _ir('1000:\tstg\tx8, [x8]')
    arm(' R17 stg post-index bumps the base; the plain form leaves it alone',
        ('add i64' in _st and ', 16' in _st, 'add i64' in _sp), (True, False))
    #  AND NEITHER FORM MAY WRITE THE GRANULE — only the stzg pair does. A `stg` that
    #    zeroed memory would destroy live data under an allocator that only re-tags.
    #  R17-e/2 THE THIRD TIME IN ONE PATCH. `zeroinitializer` appears 32 times in
    #    EVERY function: the prologue zeroes all 32 vector-register allocas. Counting the
    #    bare word measured the prologue. A store to a MEMORY address goes to an
    #    inttoptr temp (`ptr %tN`); a register write goes to a named alloca (`ptr %v0`).
    #    That distinction is the whole claim, so it is what the arm reads.
    def _gz(ir):
        return len(_GRANULE_Z.findall(ir))
    arm(' R17 stg/st2g touch no memory; the zeroing belongs to stzg/stz2g alone',
        (_gz(_st), _gz(_sp), _gz(_ir('1000:\tstzg\tx8, [x8]')),
         _gz(_ir('1000:\tstz2g\tx8, [x8]'))), (0, 0, 1, 2))
    _sz = _ir('1000:\tstz2g\tx8, [x8]')
    arm(' R17 stz2g really zeroes 32 bytes — the data half is not a no-op',
        _sz.count('store <2 x i64> zeroinitializer') == 2, True)

    #  R17-c THE CSSC W FORM MUST BE COMPUTED IN i32. An unsigned compare on the full
    #    64-bit register reads stale upper bits the program never set.
    _c = _ir('1000:\tumin\tw1, w10, #0xff\n1004:\tumax\tx13, x5, x15')
    arm(' R17 CSSC umin/umax: the w form compares in i32, the x form in i64',
        ('icmp ult i32' in _c, 'icmp ugt i64' in _c), (True, True))

    #  R17-c CRC32C IS THE XEON'S OWN SSE4.2 INSTRUCTION; CRC32 IS NOT AND MUST NOT BE.
    #  The two polynomials differ (0xEDB88320 vs Castagnoli). Routing both to the x86
    #    instruction produces a plausible wrong checksum no shape check could see.
    _r = _ir('1000:\tcrc32cx\tw8, w8, x9\n1004:\tcrc32x\tw8, w8, x10')
    arm(' R17 crc32c goes to x86 CRC32; plain crc32 goes to the bit-loop helper',
        ('llvm.x86.sse42.crc32.64.64' in _r, '__arm2x86_crcstep' in _r), (True, True))
    arm(' R17 the CRC-32 polynomial reaches the helper and is NOT Castagnoli',
        ('3988292384' in _r, '2197175160' in _r), (True, False))

    #  R17-c fmov to a lane is a BIT move. Lowering it through the FP path would round.
    _v = _ir('1000:\tfmov.d\tv4[1], x7\n1004:\tfmov.d\tx7, v4[1]')
    arm(' R17 fmov lane is insertelement/extractelement, never a conversion',
        ('insertelement' in _v, 'extractelement' in _v,
         'sitofp' in _v, 'fptosi' in _v), (True, True, False, False))

    #  R17-c -mattr=+aes IS LOAD-BEARING AND IT IS IN A SHELL SCRIPT, WHERE NO PYTHON
    #    TEST LOOKS. Measured: `llc -mcpu=ivybridge` WITHOUT it dies rc=134 with
    #    "Cannot select: intrinsic %llvm.x86.aesni.aesimc" — so the first image containing
    #    an aese would have failed to build, in a stage whose failure reads as a toolchain
    #    problem rather than as a missing flag. The real Xeon has AES (sysctl says so);
    #    only LLVM's CPU model did not.
    _here = os.path.dirname(os.path.abspath(__file__))
    _flag = {}
    for _sh in ('mko.sh', 'run_r4.sh', 'run_r5.sh'):
        _p = os.path.join(_here, _sh)
        _flag[_sh] = ('-mattr=+aes' in open(_p).read()) if os.path.exists(_p) else 'MISSING'
    arm(' R17 every llc call site passes -mattr=+aes (without it llc aborts rc=134)',
        _flag, {'mko.sh': True, 'run_r4.sh': True, 'run_r5.sh': True})

    #  the guard must FIRE, not just allow
    #  R17-d THIS ARM USED `fjcvtzs` AS ITS STAND-IN FOR "UNKNOWN" AND R17-c
    #    IMPLEMENTED fjcvtzs. The guard would have gone on passing while no longer
    #    testing anything: its subject became supported. Two subjects now — a spelling
    #    that cannot ever be an instruction, and `smstart`, a real remaining gap (SME
    #    streaming mode, 1,545 instructions, outside Layer 1) — so the guard cannot be
    #    emptied by building something.
    #  AND IT HAPPENED AGAIN IN R18: `smstart` IS NOW IMPLEMENTED. That is twice this
    #    arm has been emptied by building its own subject — first fjcvtzs, now smstart —
    #    so the real lesson is that a guard must not be anchored on a gap anyone is
    #    working toward. `cpymrt` (MOPS, 2 instructions in 899M) is explicitly outside
    #    Layer 1 and on nobody's list; the permanent subject carries the guarantee.
    NOOP_CALLS.add(0x3000)
    try:
        _ck = Lifter(parse('1000:\tmov\tx9, #0x5000\n1004:\tbl\t0x3000\n1008:\tsub\tsp, sp, x9\n100c:\tret'), 'fn_1000', {0x1000, 0x3000}, {}).define()
    finally:
        NOOP_CALLS.clear()
    arm(' 10-03 `bl ___chkstk_darwin` lifts to NOTHING: no call, no x1/v0 write-back (build20 ran off the x86 stack)',
        ('@fn_3000(' in _ck, '@__arm2x86_dispatch(' in _ck), (False, False))
    _gsrc = ('1000:\tmov\tw9, #0x1b40\n1004:\tadrp\tx16, 0x106e49000\n1008:\tldr\tx16, [x16, #0xd78]\n100c:\tblr\tx16\n'
             '1010:\tnop\n1014:\tldr\tx16, 0x106e49d78\n1018:\tblr\tx16\n101c:\tret')
    _ct = Lifter(parse('1000:\tcmp\tx0, #1\n1004:\tb.ls\t0x2000\n1008:\tret'), 'fn_1000', {0x1000, 0x2000}, {}).define()
    arm(' 10-03 a CONDITIONAL branch to another function is a tail call, not the abort (Cyberpunk build27, 46 sites)',
        ('@fn_2000(' in _ct.split('OUT2000:')[1] if 'OUT2000:' in _ct else False, '__arm2x86_unimplemented(i64 8192)' in _ct), (True, False))
    _vb = {0x2000: {'sym': 'vsnprintf', 'argc': 4, 'args': 'iiii', 'ret': 'i32', 'sizes': [8, 8, 8, 8], 'valist': [3]}}
    _vir = Lifter(parse('1000:\tbl\t0x2000\n1004:\tret'), 'fn_1000', {0x1000}, _vb).define()
    arm(' 10-03 a va_list passed to native vsnprintf becomes an x86 va_list (gp 48, fp 304, overflow = the arm64 pointer)',
        ('%vaconv = alloca [24 x i8]' in _vir, 'store i32 48, ptr %vaconv' in _vir, 'store i32 304' in _vir,
         bool(re.search(r'call i32 @vsnprintf\(i64 %\w+, i64 %\w+, i64 %\w+, i64 %t\d+\)', _vir))), (True,) * 4)
    NOOP_CALLS.add(0x106e49d78)
    try:
        _g1 = Lifter(parse(_gsrc), 'fn_1000', {0x1000}, {}).define()
    finally:
        NOOP_CALLS.clear()
    _g2 = Lifter(parse(_gsrc), 'fn_1000', {0x1000}, {}).define()
    arm(' 10-03 `blr x16` through the chkstk GOT slot (adrp+ldr AND literal ldr) lifts to nothing; any other slot still calls',
        (_g1.count('@__arm2x86_dispatch('), _g2.count('@__arm2x86_dispatch(')), (0, 2))
    _stub = '1000:\tadrp\tx16, 0x4000\n1004:\tldr\tx16, [x16, #0x8]\n1008:\tbr\tx16'
    THISRET.add(0x1000)
    try:
        _sir = Lifter(parse(_stub), 'fn_1000', {0x1000}, {}).define()
    finally:
        THISRET.clear()
    _sir2 = Lifter(parse(_stub), 'fn_1000', {0x1000}, {}).define()
    arm(' 10-03 a native ctor/dtor stub returns the x0 it was given (arm64: C1/C2/D1/D2 return this); any other stub does not',
        (bool(re.search(r'insertvalue \{ i64, <2 x i64> \} %\w+, i64 %\w+, 0\n  ret', _sir)), 'insertvalue { i64, <2 x i64> } %' in _sir2.split('@__arm2x86_dispatch(')[1]),
        (True, False))
    #  10-03 C++ exceptions: a call inside a site becomes an invoke; its pad hands x0 = exception, x1 = arm64 filter
    _ehsrc = ('1000:\tbl\t0x2000\n1004:\tbl\t0x2000\n1008:\tret\n100c:\tcmp\tw1, #2\n1010:\tb.ne\t0x1018\n'
              '1014:\tret\n1018:\tret')
    EH[0x1000] = {'pers': '__gxx_personality_v0', 'sites': [(0x1000, 0x1004, 0x100c, ((2, '_ZTIi'), (1, None))), (0x1004, 0x1008, 0, ())]}
    try:
        _ehir = Lifter(parse(_ehsrc), 'fn_1000', {0x1000, 0x2000}, {}).define()
    finally:
        EH.clear()
    _ehbody = _ehir.split('\nEHLP')[0]   # the pad BLOCK; the invoke itself names EHLP too
    arm(' 10-03 eh: the bl inside the site is an invoke unwinding to the arm64 pad; the bl outside stays a call',
        (_ehbody.count(' invoke '), _ehbody.count('= call { i64, <2 x i64> } @fn_2000(')), (1, 1))
    _pad = _ehir.split('EHLP100c_0:')[1].split('\nL')[0]
    arm(' 10-03 eh: the pad catches int then everything, maps the typeid to filter 2, else 1, and lands L100c',
        ('catch ptr @"_ZTIi" catch ptr null' in _pad, 'select i1' in _pad and 'i64 2, i64 1' in _pad,
         'store i64' in _pad and 'ptr %x1' in _pad, 'br label %L100c' in _pad), (True,) * 4)
    arm(' 10-03 eh: the function names its personality; a function with no pads names none',
        ('personality ptr @__gxx_personality_v0' in _ehir,
         'personality' in Lifter(parse(_ehsrc), 'fn_1000', {0x1000, 0x2000}, {}).define()), (True, False))
    EH[0x1000] = {'pers': '__gxx_personality_v0', 'sites': [(0x1000, 0x1004, 0x100c, ((-1, ()),))]}
    try:
        _ehf = Lifter(parse(_ehsrc), 'fn_1000', {0x1000, 0x2000}, {}).define()
    finally:
        EH.clear()
    arm(' 10-03 eh: an EMPTY exception spec, throw(), is `filter [0 x ptr] zeroinitializer` (build19: `[]` broke a shard)',
        ('filter [0 x ptr] zeroinitializer' in _ehf, 'filter [0 x ptr] []' in _ehf), (True, False))
    for _un in ('zzz_not_an_instruction', 'cpymrt'):
        try:
            Lifter(parse(f'1000:\t{_un}\tw0, d0'), 'x').module(0)
            arm(f' an unknown mnemonic ABORTS translation ({_un})', False, True)
        except NotImplementedError:
            arm(f' an unknown mnemonic ABORTS translation ({_un})', True, True)
    print(f'{"PASS" if fails == 0 else "FAIL"} — {fails} failed')
    return 1 if fails else 0

if __name__ == '__main__':
    if '--selftest' in sys.argv: sys.exit(selftest())
    if sys.argv[1] == '--module':
        # each spec is path[:export_name[:nargs]]; optional leading --binds <json>
        specs, binds, argv = [], {}, sys.argv[2:]
        if argv and argv[0] == '--binds':
            import json
            binds = {int(k, 16): v for k, v in json.load(open(argv[1])).items()}
            argv = argv[2:]
        for s in argv:
            parts = s.split(':')
            specs.append((parts[0], parts[1] if len(parts) > 1 and parts[1] else None,
                          int(parts[2]) if len(parts) > 2 else 4))
        print(build(specs, binds)); sys.exit(0)
    src, name = sys.argv[1], sys.argv[2]
    nargs = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    print(Lifter(parse(open(src).read()), name).module(nargs))
