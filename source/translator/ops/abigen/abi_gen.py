#!/usr/bin/env python3
"""abi_gen.py — generate the native handlers for every import that passes or returns a STRUCT BY VALUE.

 WHY THIS EXISTS. sigdb is built from headers; anything it cannot classify it writes as `x`, and an import
   with any `x` falls to the GENERIC native adapter, which is correct ONLY for scalar arguments and an x0/v0
   return. A struct by value is then passed or returned as garbage. Measured 10-20 across the seven translated
   macOS 27 GUI binaries: 116 distinct imports in that state. One of them, CGRectGetWidth, is why the Dock read
   a screen with a correct origin and NO SIZE, aborted, and held the whole desktop at the login window.

 THE TWO ABIs, which is all a handler has to know (AAPCS64 vs SysV x86-64):
     ARGUMENTS   HFA (all leaves the same float type, at most 4)  -> one v register per leaf, low half
                 composite <= 16 bytes                            -> one or two x registers, packed
                 composite  > 16 bytes                            -> a POINTER in one x register
                 (x86-64 instead copies the bytes onto the stack — so the handler only has to read the
                  arm64 side correctly and then make a normal C call; clang lays out x86.)
     RETURNS     HFA (<= 4 leaves)   -> v0..v3
                 <= 16 bytes         -> x0, x1
                 >  16 bytes         -> the caller passed a buffer in x8; write through it
 Not every `x` is a struct: sigdb also writes `x` for an ENUM, which the scalar path already passes
   correctly. A type must be in TYPES below to get a handler — an unknown type is REPORTED, never guessed.
"""
import json, sys, os

# name -> (C definition, size in bytes, kind, leaves)
#   kind 'hfa'  : `leaves` members, all double/float      -> v registers
#   kind 'int'  : integer-ish composite, size <= 16       -> x registers
#   kind 'big'  : anything over 16 bytes that is not an HFA -> pointer in an x register
#  Every size here is the measured Apple layout, not a guess; the C definitions reproduce it exactly, so
#    clang classifies them for x86 the same way the real headers do.
TYPES = {
    'CGRect':        ('typedef struct { double x, y, w, h; } %s;',                 32, 'hfa', 4),
    'NSRect':        ('typedef struct { double x, y, w, h; } %s;',                 32, 'hfa', 4),
    'CGPoint':       ('typedef struct { double x, y; } %s;',                       16, 'hfa', 2),
    'NSPoint':       ('typedef struct { double x, y; } %s;',                       16, 'hfa', 2),
    'CGSize':        ('typedef struct { double w, h; } %s;',                       16, 'hfa', 2),
    'NSSize':        ('typedef struct { double w, h; } %s;',                       16, 'hfa', 2),
    'CGVector':      ('typedef struct { double dx, dy; } %s;',                     16, 'hfa', 2),
    'NSEdgeInsets':  ('typedef struct { double t, l, b, r; } %s;',                 32, 'hfa', 4),
    'CGAffineTransform': ('typedef struct { double a, b, c, d, tx, ty; } %s;',     48, 'big', 0),
    'CATransform3D': ('typedef struct { double m[16]; } %s;',                     128, 'big', 0),
    'CMTime':        ('typedef struct { long long v; int s; unsigned f; long long e; } %s;', 24, 'big', 0),
    'NSMapEnumerator': ('typedef struct { unsigned long pi, si; void *bs; } %s;', 24, 'big', 0),
    'NSHashEnumerator': ('typedef struct { unsigned long pi, si; void *bs; } %s;', 24, 'big', 0),
    'NSRange':       ('typedef struct { unsigned long loc, len; } %s;',            16, 'int', 2),
    'CFRange':       ('typedef struct { long loc, len; } %s;',                     16, 'int', 2),
    'CFUUIDBytes':   ('typedef struct { unsigned long lo, hi; } %s;',              16, 'int', 2),
    'CFStreamError': ('typedef struct { long domain; int error; } %s;',            16, 'int', 2),
    'audit_token_t': ('typedef struct { unsigned int v[8]; } %s;',                 32, 'big', 0),
}
SCALAR_RET = {'void': 'void', 'i32': 'int', 'i64': 'long', 'double': 'double', 'float': 'float'}
# Explicit unsigned result types must keep their zero extension at the C boundary.
SCALAR_C_RET = {'uint32_t': 'unsigned int', 'uint64_t': 'unsigned long long'}

def load_private_abi(db):
    """Supplement SDK declarations with verified private provider contracts."""
    path = os.path.join(os.path.dirname(__file__), 'private_abi.json')
    catalog = json.load(open(path))
    for name, spec in catalog['types'].items():
        value = (spec['definition'], spec['size'], spec['kind'], spec['leaves'])
        if name in TYPES and TYPES[name] != value:
            raise ValueError('private ABI type conflicts with known layout: ' + name)
        TYPES[name] = value
    for name, signature in catalog['symbols'].items():
        if name in db:
            for field in ('argc', 'args', 'sizes', 'ret', 'cret', 'ctypes', 'va'):
                if db[name].get(field) != signature[field]:
                    raise ValueError('private ABI conflicts with SDK declaration: ' + name)
        else:
            db[name] = signature

def base(t):
    """strip qualifiers/nullability so 'CGRect' is recognised in 'const CGRect _Nonnull'."""
    t = t.replace('const', ' ').replace('_Nonnull', ' ').replace('_Nullable', ' ').replace('*', ' * ')
    return t.strip().split()[0] if t.strip() else ''

class Walk:
    """AAPCS64 argument assignment: integers take x0..x7, floats v0..v7, anything past that the arm64 stack."""
    def __init__(self): self.ngrn = 0; self.nsrn = 0; self.stack = 0
    def x(self):
        if self.ngrn < 8: self.ngrn += 1; return ('x', self.ngrn - 1)
        self.stack += 8; return ('s', self.stack - 8)
    def v(self, n=1):
        if self.nsrn + n <= 8: self.nsrn += n; return ('v', self.nsrn - n)
        self.stack += 8 * n; return ('s', self.stack - 8 * n)

def emit(sym, e, out):
    args, ct = e.get('args', ''), [base(c) for c in (e.get('ctypes') or [])]
    ret, cret = e['ret'], base(e.get('cret') or 'void')
    if e.get('va'): return 'variadic'
    kinds = []
    for i, a in enumerate(args):
        if a in 'idf': kinds.append((a, None)); continue
        if a != 'x': return 'unmodelled arg code %r' % a
        t = ct[i] if i < len(ct) else ''
        if t not in TYPES: return 'unknown arg type %r' % t
        kinds.append(('x', t))
    rkind = None
    if ret == 'x':
        if cret not in TYPES: return 'unknown return type %r' % cret
        rkind = cret
    elif ret not in SCALAR_RET: return 'unknown return %r' % ret

    w, decl, read, call = Walk(), [], [], []
    for i, (a, t) in enumerate(kinds):
        n = 'a%d' % i
        if a == 'i':
            loc = w.x(); read.append('    unsigned long %s = %s;' % (n, src(loc))); decl.append('unsigned long')
        elif a == 'd':
            loc = w.v(); read.append('    double %s = %s;' % (n, vsrc(loc))); decl.append('double')
        elif a == 'f':
            loc = w.v(); read.append('    float %s = %s;' % (n, fsrc(loc))); decl.append('float')
        else:
            sz, kind, leaves = TYPES[t][1], TYPES[t][2], TYPES[t][3]
            decl.append(t)
            if kind == 'hfa':
                loc = w.v(leaves)
                parts = ', '.join(vsrc(('v', loc[1] + k)) if loc[0] == 'v' else src(('s', loc[1] + 8 * k))
                                  for k in range(leaves))
                read.append('    %s %s = (%s){ %s };' % (t, n, t, parts))
            elif kind == 'int':
                lo, hi = w.x(), w.x()
                read.append('    %s %s; { unsigned long _w[2] = { %s, %s }; __builtin_memcpy(&%s, _w, sizeof %s); }'
                            % (t, n, src(lo), src(hi), n, n))
            else:   # > 16 bytes: arm64 hands over a POINTER
                loc = w.x()
                read.append('    %s %s = *(const %s *)(%s);' % (t, n, t, src(loc)))
        call.append(n)
    rt = rkind if rkind else SCALAR_C_RET.get(e.get('cret'), SCALAR_RET[ret])
    out.append('void __arm2x86_abi_gen_%s(void) {' % sym)
    out.append('    static %s (*f)(%s); if (!f) f = a2x_need("%s");' % (rt, ', '.join(decl) or 'void', sym))
    out += read
    if rkind:
        sz, kind, leaves = TYPES[rkind][1], TYPES[rkind][2], TYPES[rkind][3]
        out.append('    %s r = f(%s);' % (rt, ', '.join(call)))
        if kind == 'hfa':
            out.append('    memset(__arm2x86_rf + 80, 0, 64);')
            for k in range(leaves):
                out.append('    A2X_VD(%d) = ((const double *)&r)[%d];' % (k, k))
                if k: out.append('    A2X_XRV(%d) = ((const double *)&r)[%d];' % (k, k))
        elif kind == 'int':
            out.append('    { unsigned long _w[2] = {0,0}; __builtin_memcpy(_w, &r, sizeof r);')
            out.append('      A2X_RX(0) = _w[0]; A2X_RX(1) = _w[1]; A2X_XRX1(_w[1]); }')
        else:   # > 16 bytes comes back through the caller's x8 buffer
            out.append('    __builtin_memcpy((void *)A2X_RX(8), &r, sizeof r);')
    elif ret == 'void':
        out.append('    f(%s);' % ', '.join(call))
    elif ret == 'double' or ret == 'float':
        out.append('    double r = f(%s); A2X_VD(0) = r;' % ', '.join(call))
    else:
        out.append('    A2X_RX(0) = (unsigned long)f(%s);' % ', '.join(call))
    out.append('}')
    return None

def src(loc):  return 'A2X_RX(%d)' % loc[1] if loc[0] == 'x' else '*(unsigned long *)(__arm_sp + %d)' % loc[1]
def vsrc(loc): return 'A2X_VD(%d)' % loc[1] if loc[0] == 'v' else '*(double *)(__arm_sp + %d)' % loc[1]
def fsrc(loc): return 'A2X_VF(%d)' % loc[1] if loc[0] == 'v' else '*(float *)(__arm_sp + %d)' % loc[1]

def main():
    db = json.load(open(os.path.join(os.path.dirname(__file__), '..', '..', 'sigdb.json')))
    load_private_abi(db)
    want = [l.strip() for l in open(sys.argv[1])] if len(sys.argv) > 1 else None
    syms = [s for s in (want or db) if s in db and (db[s]['ret'] == 'x' or 'x' in db[s].get('args', ''))]
    out, skipped = [], {}
    for s in sorted(syms):
        why = emit(s, db[s], out)
        if why: skipped[s] = why
    print('/* GENERATED by ops/abigen/abi_gen.py — do not edit by hand. %d handlers. */' % (len(syms) - len(skipped)))
    for t, (cdef, sz, kind, leaves) in sorted(TYPES.items()):
        print(cdef % t, '/* %d bytes, %s */' % (sz, kind))
    print('\n'.join(out))
    sys.stderr.write('generated %d, skipped %d\n' % (len(syms) - len(skipped), len(skipped)))
    for s, w in sorted(skipped.items())[:40]: sys.stderr.write('  SKIP %-44s %s\n' % (s, w))

if __name__ == '__main__':
    main()
