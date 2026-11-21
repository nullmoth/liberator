#!/usr/bin/env python3
"""mksigtable.py — generate interp/sig_table.h from the TRANSLATOR'S OWN tables.

    python3 mksigtable.py [output.h]          (default: sig_table.h beside this script)

THIS IS A BUILD STEP, NOT A FILE THAT GETS LEFT BEHIND. mkhost.sh runs it before it compiles anything,
   every build, so the table cannot go stale against sigdb.json. A checked-in sig_table.h would be a SECOND
   copy of a routing table, and a second copy drifts — the failure is a wrong call, not a build error, which
   is how objc_msgSend once ended up bound natively (interp/mkrftable.py's note). interp/sig_table.h is a
   build product: do not commit it, do not edit it.

THE HOST GUESSES THE SHAPE OF EVERY NATIVE CALL. native_door.ll carries a FIXED shape — x0-x7 as eight
   integers, v0-v7 as eight doubles, 16 words blind-copied off the arm64 stack — which is right for scalar
   arguments with an integer or double result and silently wrong otherwise. The per-app translator does not
   guess: sigdb.json holds clang's own declaration for every import, and arm2x86.py:bind() emits a call with
   the real C types. The host cannot reuse that mechanism (it has no compiler at run time) but it can reuse
   the DATA, and this emits it as a header the host links in.

A SECOND COPY OF THIS TABLE WOULD DRIFT, and the failure would be a wrong call rather than a build error —
   the same reason mkrftable.py generates rf_table.h instead of retyping xlat2.py's routing dict. So nothing
   here is typed by hand: the signatures come from sigdb.json and the return-narrowing rules come out of
   arm2x86.py's own NARROW_RET.

IT REFUSES RATHER THAN EMITTING A SHORT TABLE. If sigdb's schema changed, if NARROW_RET is gone, or if the
   entry count collapses, a generated-but-wrong table would route calls through a typed door built on stale
   field names — argument registers read from the wrong place, with nothing failing at build time. Every one
   of those cases exits non-zero and says which check failed.
"""
import importlib.util, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))

# This runs from two different layouts and the build dir is the awkward one. In the tree the generator sits
#    at interp/mksigtable.py beside mkrftable.py, so the root holding sigdb.json is one level up. A build
#    machine may instead run mkhost.sh from a flat copy of interp/ where there is no tree above it — while
#    the source-sync layout puts sigdb.json one level above an interp/ subdirectory. Guessing wrong here does
#    not fail the build, it produces the wrong
#    table, so every candidate is tried, both files must come from the same root (a new sigdb mixed with an
#    old NARROW_RET is a silent wrong answer), the root used is printed, and finding none exits non-zero.
# ARM2X86_SRC=<tree> overrides everything, which is the answer for a build dir that carries neither file.
NEED_AT_ROOT = ('sigdb.json', 'arm2x86.py')
if os.environ.get('ARM2X86_SRC'):
    # An explicit override that falls back is not an override: with ARM2X86_SRC pointing at a directory
    #    holding neither file, a search that walks on builds the table out of a different tree that happens
    #    to be on the machine — a wrong table under a green build, which is the one outcome this generator
    #    exists to prevent. If ARM2X86_SRC is set it is the
    #    only candidate, and a tree that does not hold both files is an error, not a hint.
    CAND = [os.path.abspath(os.environ['ARM2X86_SRC'])]
else:
    # And no $HOME guess. A fallback to a fixed checkout under the home directory would read a stale clone on
    #    a build machine and say nothing; every candidate below is derived from where this script is or where
    #    it was run.
    # translator/ beside interp/ in this tree; then the walk-up for a flat build copy
    CAND = [os.path.normpath(os.path.join(HERE, os.pardir, 'translator'))]
    CAND += [os.path.normpath(os.path.join(HERE, *([os.pardir] * n))) for n in (0, 1, 2, 3)]
    CAND += [os.path.abspath(os.curdir),
             os.path.normpath(os.path.join(os.path.abspath(os.curdir), os.pardir))]
seen, ROOT = set(), None
for d in CAND:
    if d in seen:
        continue
    seen.add(d)
    if all(os.path.exists(os.path.join(d, f)) for f in NEED_AT_ROOT):
        ROOT = d
        break
if not ROOT:
    why = ('ARM2X86_SRC=' + os.environ['ARM2X86_SRC'] + ' does not hold both of them (an explicit override '
           'is never second-guessed)') if os.environ.get('ARM2X86_SRC') else \
          ('tried:\n  ' + '\n  '.join(sorted(seen)))
    sys.exit('mksigtable: could not find BOTH ' + ' and '.join(NEED_AT_ROOT) + ' in ONE directory — ' + why
             + '\nREFUSING: the host\'s typed door is built from the translator\'s own tables and there is '
               'no second source. Point ARM2X86_SRC at the arm2x86 tree.')
POS = [a for a in sys.argv[1:] if not a.startswith('-')]
OUT = POS[0] if POS else os.path.join(HERE, 'sig_table.h')


def selftest():
    """EVERY REFUSAL BELOW IS MEASURED IN BOTH DIRECTIONS: each arm proves the guard FIRES, and the last
    arm proves the real tree still passes. A guard that only ever allows has not been measured.
    The first run of these arms found a real bug: ARM2X86_SRC pointing at a directory with neither table
       fell THROUGH to another tree on the machine, so a build dir with no sigdb.json would have produced a
       table out of a stale clone, green. An explicit override that falls back is not an override.
    Every arm writes only inside its own tempfile.TemporaryDirectory — a selftest never writes a real
       store, and the real interp/sig_table.h is never touched by this."""
    import json as _j, re as _r, subprocess as _s, tempfile as _t
    sigs = open(os.path.join(ROOT, 'sigdb.json')).read()
    arm = open(os.path.join(ROOT, 'arm2x86.py')).read()
    support = {name: open(os.path.join(ROOT, name)).read() for name in
               ('ops/abigen/abi_gen.py', 'ops/abigen/private_abi.json')}

    def arm_run(label, files, want_refusal):
        with _t.TemporaryDirectory() as d:
            for nm, body in {**support, **files}.items():
                os.makedirs(os.path.dirname(os.path.join(d, nm)), exist_ok=True)
                open(os.path.join(d, nm), 'w').write(body)
            p = _s.run([sys.executable, '-I', os.path.abspath(__file__), os.path.join(d, 'out.h')],
                       capture_output=True, text=True, env=dict(os.environ, ARM2X86_SRC=d))
            refused = p.returncode != 0
            ok = refused == want_refusal
            msg = ((p.stderr or p.stdout).strip().splitlines() or [''])[0]
            print(f'  {"ok  " if ok else "FAIL"} {label:<48} rc={p.returncode}  {msg[:92]}')
            return ok

    arms = []
    arms.append(arm_run('NARROW_RET gone from arm2x86.py refuses',
                        {'sigdb.json': sigs,
                         'arm2x86.py': _r.sub(r'^NARROW_RET = \{.*?\}$', 'GONE = {}', arm, count=1,
                                              flags=_r.S | _r.M)}, True))
    d50 = _j.loads(sigs)
    arms.append(arm_run('a collapsed sigdb refuses',
                        {'sigdb.json': _j.dumps({k: d50[k] for k in list(d50)[:50]}),
                         'arm2x86.py': arm}, True))
    ren = _j.loads(sigs)
    for e in ren.values():
        e['szs'] = e.pop('sizes')
    arms.append(arm_run('a renamed sigdb field refuses', {'sigdb.json': _j.dumps(ren), 'arm2x86.py': arm}, True))
    for label, probe in (('an unknown argument kind refuses',
                          {'argc': 1, 'args': 'q', 'sizes': [8], 'ret': 'i64', 'cret': 'long',
                           'ctypes': ['long'], 'va': 0, 'blk': [], 'fnp': []}),
                         ('an unknown return code refuses',
                          {'argc': 0, 'args': '', 'sizes': [], 'ret': 'fp128', 'cret': '__float128',
                           'ctypes': [], 'va': 0, 'blk': [], 'fnp': []})):
        t = _j.loads(sigs)
        t['zz_probe'] = probe
        arms.append(arm_run(label, {'sigdb.json': _j.dumps(t), 'arm2x86.py': arm}, True))
    arms.append(arm_run('an empty ARM2X86_SRC refuses (no fallthrough)', {}, True))
    arms.append(arm_run('sigdb.json without arm2x86.py beside it refuses', {'sigdb.json': sigs}, True))
    # the other direction
    arms.append(arm_run('the real tree still EMITS', {'sigdb.json': sigs, 'arm2x86.py': arm}, False))
    bad = arms.count(False)
    print(f'mksigtable --selftest: {len(arms) - bad}/{len(arms)} arms ok, {bad} failed')
    sys.exit(1 if bad else 0)


if '--selftest' in sys.argv[1:]:
    selftest()

# ── sigdb.json: the signatures ────────────────────────────────────────────────────────────────────────────
sig = json.load(open(os.path.join(ROOT, 'sigdb.json')))
if not isinstance(sig, dict):
    sys.exit('mksigtable: sigdb.json is not a name -> signature object any more — REFUSING.')
if len(sig) < 8000:
    sys.exit(f'mksigtable: sigdb.json holds only {len(sig)} symbols (expected ~11,347 on 10-26) — the table '
             f'shape or the umbrella must have changed, and a short table would leave the typed door blind '
             f'to imports it used to carry. REFUSING.')

# The aggregate generator owns verified private types and signatures too.
abi_path = os.path.join(ROOT, 'ops', 'abigen', 'abi_gen.py')
abi_spec = importlib.util.spec_from_file_location('a2x_private_abi', abi_path)
abi_module = importlib.util.module_from_spec(abi_spec)
abi_spec.loader.exec_module(abi_module)
abi_module.load_private_abi(sig)

# Every field the door reads is checked by name. sigdb.py could rename one and this would otherwise emit a
#    table of zeros: argc 0, no sizes, every entry "typed" and every argument read from the wrong place.
NEED = ('argc', 'args', 'sizes', 'ret', 'cret', 'va')
missing = sorted({k for e in sig.values() for k in NEED if k not in e})
if missing:
    sys.exit(f'mksigtable: sigdb entries no longer carry {missing} — sigdb.py\'s schema changed and the typed '
             f'door reads those fields by name. REFUSING rather than emitting a table of defaults.')

# The argument alphabet is A fence, not A HINT. 'x' means sigdb refused the type (struct by value, long
#    double, __int128, vector, unknown spelling). A new letter would silently fall into whichever branch of
#    the door sorts last, so an unknown one stops the build.
KINDS = set('ifdx')
RETS = {'void', 'i32', 'i64', 'float', 'double', 'x'}
badk = sorted({c for e in sig.values() for c in e['args'] if c not in KINDS})
badr = sorted({e['ret'] for e in sig.values() if e['ret'] not in RETS})
if badk: sys.exit(f'mksigtable: unknown argument kind(s) {badk} in sigdb — REFUSING.')
if badr: sys.exit(f'mksigtable: unknown return code(s) {badr} in sigdb — REFUSING.')

# Private platform SPI has a verified C prototype even when the SDK omits it.
# Keep its declared byte-sized Boolean result on the typed native boundary.
private_feature = dict(argc=2, args='ii', sizes=[8, 8], ret='i32', cret='bool',
                       ctypes=['const char *', 'const char *'], va=0, fnp=[], blk=[])
if '_os_feature_enabled_impl' in sig:
    for key in ('argc', 'args', 'sizes', 'ret', 'cret', 'va'):
        if sig['_os_feature_enabled_impl'][key] != private_feature[key]:
            sys.exit('mksigtable: private feature SPI conflicts with SDK declaration')
else:
    sig['_os_feature_enabled_impl'] = private_feature
private_lazy = dict(argc=2, args='ii', sizes=[8, 8], ret='void', cret='void',
                    ctypes=['uint32_t *', 'const struct mach_header *'], va=0, fnp=[], blk=[])
if '_dyld_lazy_load' in sig:
    for key in ('argc', 'args', 'sizes', 'ret', 'cret', 'va'):
        if sig['_dyld_lazy_load'][key] != private_lazy[key]:
            sys.exit('mksigtable: private lazy loader SPI conflicts with SDK declaration')
else:
    sig['_dyld_lazy_load'] = private_lazy

# ── arm2x86.py: the return-narrowing rules, read from the translator, never retyped ───────────────────────
# arm2x86.py NARROW_RET: a bool/char/short return is narrowed and re-extended. x86-64 SysV leaves bits
#    8..63 of rax undefined for a Boolean return; arm64 callers read w0 whole (clang emits `cbz w0`), so the
#    leftovers of a previous computation decide the branch. The per-app bind applies this and
#    the host must apply the identical rule — so it is parsed out of the same dict, not copied.
asrc = open(os.path.join(ROOT, 'arm2x86.py')).read()
m = re.search(r'^NARROW_RET = \{(.*?)\}$', asrc, re.S | re.M)
if not m:
    sys.exit('mksigtable: arm2x86.py has no NARROW_RET dict any more — REFUSING rather than emitting a table '
             'whose narrow returns are all "none", which would put undefined x86 rax bits into x0 for every '
             'Boolean the guest branches on.')
NARROW = {k: (int(b), int(s)) for k, b, s in re.findall(r"'([^']+)':\s*\((\d+),\s*(\d+)\)", m.group(1))}
if len(NARROW) < 15:
    sys.exit(f'mksigtable: NARROW_RET parsed to only {len(NARROW)} spellings (19 on 10-26) — the dict\'s shape '
             f'changed and the parse is dropping rules. REFUSING.')

RETC = {'void': 'SIG_VOID', 'i32': 'SIG_I32', 'i64': 'SIG_I64', 'float': 'SIG_F32', 'double': 'SIG_F64'}
SZC = {1: '1', 2: '2', 4: '4', 8: '8'}

rows, xrows, dropped, n_va, n_need = [], [], [], 0, 0
for name in sig:
    e = sig[name]
    if e['ret'] == 'x' or 'x' in e['args']:
        # These are the calls that are wrong on the fixed-shape door and say nothing. sigdb refused the type (struct by
        #    value, long double, __int128, vector), so the typed door must refuse it too — but the fixed-shape
        #    door then runs it anyway and gets it wrong in a way nothing reports: a return larger than 16
        #    bytes goes in x8 on arm64 and in rdi on x86, which shifts every integer argument by one register.
        #    The names are emitted so the door can at least name the call instead of quietly mis-placing it.
        #    'r' the return is untypeable, 'a' an argument is, 'b' both.
        w = ('b' if (e['ret'] == 'x' and 'x' in e['args']) else ('r' if e['ret'] == 'x' else 'a'))
        xrows.append((name.encode(), name, w))
        continue
    if len(e['args']) != e['argc']:
        # arm2x86.bind_kinds() blocks on this rather than picking one, because a disagreement here is a
        #    wrong-register read. Dropping the entry is the host's equivalent: the untyped door still runs it.
        dropped.append(f'{name}:args {e["args"]!r} vs argc {e["argc"]}')
        continue
    ni = e['args'].count('i')
    nf = e['argc'] - ni
    spill = ni > 8 or nf > 8
    # AAPCS64-Darwin packs a spilled argument at its natural alignment, so a stack argument whose size
    #    sigdb could not take from clang's type cannot be read at all. arm2x86.from_stack() raises
    #    NotImplementedError; here the entry is dropped and named.
    sizes = e['sizes'] or []
    # All 9,581 typed entries carry exactly argc sizes, every one of them 1, 2, 4 or 8.
    #    So this does not fire on the current sigdb — and that is the reason to make it a refusal rather than a
    #    default of 8: a defaulted size reads a spilled argument at the wrong offset and shifts every one after it.
    if len(sizes) != e['argc'] or any(s not in SZC for s in sizes):
        dropped.append(f'{name}:sizes {sizes} do not match argc {e["argc"]} or are not all 1/2/4/8')
        continue
    szs = ''.join(SZC[s] for s in sizes)
    cret = (e['cret'] or '').replace('const ', '').strip()
    nb, ns = NARROW.get(cret, (0, 0)) if e['ret'] == 'i32' else (0, 0)
    va = 1 if e['va'] else 0
    n_va += va
    # "NEEDS the typed door" = the fixed-shape door is provably wrong here, counted over the 65
    #    macOS 27 apps: 14 spillers (29 call slots) and 118 narrowing returns (309 slots). These route
    #    through the typed door by default; everything else keeps the untyped path unless ARM2X86_SIGDOOR=all.
    #    A float or double in a register is not in this set: the untyped door moves the raw low 64 bits of
    #       vN into xmmN, so a float's bits 0..31 land exactly where x86 reads them.
    need = 1 if (spill or nb) else 0
    n_need += need
    flags = (va and 1) | (need and 2) | (4 if (e.get('fnp') or e.get('blk')) else 0)
    rows.append((name.encode(), name, e['args'], szs, RETC[e['ret']], (nb << 1) | ns, flags))

# Private BOOL SPI is not in sigdb, so it was never narrowed. sigdb is clang over the public SDK
#    headers; os/feature_private.h and os/variant_private.h are not in it, so these imports fell to the fixed
#    shape and x0 got rax whole. Seen in the guest with a native x86_64 probe:
#    _os_feature_enabled_impl("IDS","UseNewThreadArch_v1") -> rax 0x2c31a7aa8729ff00, al 0 (real 27 on arm64:
#    w0 0). The arm64 caller's `cbz w0` read that OFF flag as ON, so identityservicesd took its new-queue
#    branch, ran a MainActor init on a private queue and died in dispatch_assert_queue — 517 restarts, and
#    every app that asks IDS (FaceTime, Phone, Messages) waited on it. The AOT bind carries this one as
#    BOOL_NATIVE_WRAPPERS in xlat.py; the interpreter did not. Declarations are libplatform's:
#    bool _os_feature_enabled_impl(const char *domain, const char *feature);
#    bool os_variant_*(const char *subsystem);
#    sigdb wins if it ever learns one of these.
PRIVATE_BOOL_SPI = {
    '_os_feature_enabled_impl': 'ii',
    'os_variant_has_internal_content': 'i',
    'os_variant_has_internal_diagnostics': 'i',
    'os_variant_has_internal_ui': 'i',
    'os_variant_allows_internal_security_policies': 'i',
    'os_variant_has_factory_content': 'i',
    'os_variant_is_darwinos': 'i',
    'os_variant_is_recovery': 'i',
    'os_variant_is_basesystem': 'i',
    'os_variant_uses_ephemeral_storage': 'i',
}
have = {r[1] for r in rows}
for name, kinds in PRIVATE_BOOL_SPI.items():
    if name in have or name in sig:
        continue
    rows.append((name.encode(), name, kinds, '8' * len(kinds), 'SIG_I32', (8 << 1) | 0, 2))
    n_need += 1

# a half-generated table is the failure this whole file exists to prevent
if len(dropped) > len(rows) // 100:
    sys.exit(f'mksigtable: {len(dropped)} entries dropped against {len(rows)} kept — more than 1%, so this is '
             f'a schema change, not a handful of odd declarations. First few: {dropped[:5]}. REFUSING.')
if len(rows) < 8000:
    sys.exit(f'mksigtable: only {len(rows)} typed entries of {len(sig)} (expected ~9,581 on 10-26) — REFUSING. '
             f'A short table does not fail the build: it silently sends calls the host used to type back '
             f'through the fixed-shape door, which is the bug this table exists to close.')

if len(xrows) < 1000:
    sys.exit(f'mksigtable: only {len(xrows)} untypeable entries (1,766 on 10-26) — REFUSING. That list is how '
             f'the door NAMES a call it cannot type; emitting a short one turns those calls back into silent '
             f'wrong answers, which is the failure this table exists to end.')

rows.sort(key=lambda r: r[0])          # byte order, because the door binary-searches with strcmp
xrows.sort(key=lambda r: r[0])
for tbl in (rows, xrows):
    for a, b in zip(tbl, tbl[1:]):
        if a[0] >= b[0]:
            sys.exit(f'mksigtable: {a[1]} and {b[1]} are out of order or duplicated — REFUSING (the door\'s '
                     f'binary search would miss entries past the break).')

out = [
    '// sig_table.h — GENERATED by interp/agents/native-door/mksigtable.py from sigdb.json and arm2x86.py\'s',
    '// NARROW_RET. Do not edit: regenerate it.',
    '//',
    '// One row per native symbol the translator\'s own signature table can type. The host\'s typed door',
    '// (sig_door.c) places the call from this instead of the fixed shape native_door.ll carries.',
    '//   kinds  — one char per named parameter: i integer/pointer, d double, f float',
    '//   sizes  — that parameter\'s natural size in bytes ("1","2","4","8"); only read for a SPILLED',
    '//            argument, which AAPCS64-Darwin packs at its natural alignment on the arm64 stack',
    '//   narrow — (bits << 1) | signed for a return x86 may leave garbage above (Boolean, char, short); 0 = none',
    '//   flags  — 1 variadic (vararg.c owns those), 2 the fixed-shape door is provably wrong here,',
    '//            4 carries a function-pointer or block parameter',
    '#pragma once',
    '',
    'enum { SIG_VOID = 0, SIG_I32 = 1, SIG_I64 = 2, SIG_F32 = 3, SIG_F64 = 4 };',
    'enum { SIGF_VA = 1, SIGF_NEED = 2, SIGF_CB = 4 };',
    '',
    'struct a64_sig {',
    '    const char *name;',
    '    const char *kinds;',
    '    const char *sizes;',
    '    unsigned char argc, ret, narrow, flags;',
    '};',
    '',
    'static const struct a64_sig A64_SIG[] = {',
]
for _, name, kinds, szs, ret, narrow, flags in rows:
    out.append(f'    {{ "{name}", "{kinds}", "{szs}", {len(kinds)}, {ret}, {narrow}, {flags} }},')
out += ['};', f'#define A64_SIG_N {len(rows)}', '']
out += [
    '',
    '// THE CALLS WE CANNOT TYPE, BY NAME. sigdb refused a parameter or the return (struct by value, long',
    '//    double, __int128, vector), so the typed door refuses them too and they fall back to the fixed-shape',
    '//    door — which, for a return larger than 16 bytes, puts the result buffer in x8 where x86 wants rdi',
    '//    and shifts every integer argument by one register. Nothing about that failure is visible, so the',
    '//    door names the callee the first time it sees one. "r" the return, "a" an argument, "b" both.',
    'struct a64_sig_x { const char *name; char which; };',
    'static const struct a64_sig_x A64_SIG_X[] = {',
]
for _, name, w in xrows:
    out.append(f'    {{ "{name}", \'{w}\' }},')
out += ['};', f'#define A64_SIG_X_N {len(xrows)}', '']

tmp = OUT + '.tmp'
open(tmp, 'w').write('\n'.join(out) + '\n')
os.replace(tmp, OUT)                   # atomic: a torn header is a build that fails far from here
print(f'{os.path.basename(OUT)}: {len(rows)} typed signatures of {len(sig)} sigdb symbols '
      f'({len(xrows)} refused by sigdb as untypeable and named instead, {len(dropped)} dropped here)')
print(f'  read from {ROOT}')           # which tree answered — the build dir has more than one candidate
print(f'  {n_need} entries the fixed-shape door gets wrong (routed through the typed door by default), '
      f'{n_va} variadic (left to vararg.c), NARROW_RET rules read from arm2x86.py: {len(NARROW)}')
if dropped:
    print('  dropped: ' + ', '.join(dropped[:8]) + (' …' if len(dropped) > 8 else ''))
