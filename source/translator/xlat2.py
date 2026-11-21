#!/usr/bin/env python3
"""xlat2.py — ladder rung 6: a whole arm64 PROGRAM (its executable + every arm64 library it ships) -> one x86_64 executable.

    python3 xlat2.py <app>/Contents/MacOS/<exe> <outdir> [jobs]

 One translated address space, the way Rosetta treats a process. The executable keeps its addresses; every library it loads
   from inside its bundle (@rpath / @executable_path / @loader_path) is REBASED (rebase_macho.py) past the previous image, and
   all of them are lifted together. Consequences, each one the point:
   - a call from the program into its own library is an arm64->arm64 call INSIDE the translation: no ABI crossing at all;
   - a <weak-def-coalesce> bind resolves to the first image that defines the symbol, exactly as dyld does (program first);
   - only real system imports cross into native code: a sigdb-typed bind where the signature is known, otherwise the stub
     itself is lifted and its `br x16` reaches the native function through the register-mapping adapter (__arm2x86_native_adapter).
 Startup = dyld's order: images mapped + fixed up (loader), ObjC registration and selector uniquing per image, thread-local
   registration (tlv.c), every image's __init_offsets (libraries first, the program last), then the entry point.
 SCALE: functions are lifted and compiled in parallel shards (opt -O2 + llc each); ONE global module holds the address->code
   map, the dispatcher, the native adapter and the C-callable doors. A shard defines its functions and DECLARES what it calls.
 Refusals are loud: an internal bind whose symbol the target image does not export is listed and its slot left 0 (reaching it
   aborts by address); C++ exceptions unwinding through translated frames are not implemented (a throw terminates)."""
import json, os, re, struct, subprocess, sys, time
from concurrent.futures import ProcessPoolExecutor
import split_fns
import abi_scan
import arm2x86
import xlat

S = os.path.dirname(os.path.abspath(__file__))
LLVM = xlat.LLVM
sh = xlat.sh
LC_SEGMENT_64, LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB, LC_RPATH, LC_MAIN, LC_REEXPORT_DYLIB = \
    0x19, 0xC, 0xD, 0x80000018, 0x8000001C, 0x80000028, 0x8000001F
ABI_RET = '{ i64, <2 x i64> }'


def macho(path):
    """The load commands of a THIN arm64 Mach-O: segments, sections, id, dependent dylibs, rpaths, entry offset."""
    b = open(path, 'rb').read(1 << 20)
    magic, cpu, _, ftype, ncmds = struct.unpack_from('<IIIII', b, 0)
    if magic != 0xFEEDFACF or cpu != 0x0100000C: raise SystemExit(f'{path}: not a thin arm64 Mach-O')
    o, m = 32, {'segs': [], 'sects': {}, 'deps': [], 'rpaths': [], 'id': None, 'entryoff': None, 'filetype': ftype}
    for _ in range(ncmds):
        cmd, sz = struct.unpack_from('<II', b, o)
        if cmd == LC_SEGMENT_64:
            name = b[o + 8:o + 24].split(b'\0')[0].decode()
            vm, vsz, foff, fsz = struct.unpack_from('<QQQQ', b, o + 24)
            m['segs'].append((name, vm, vsz, foff, fsz))
            for k in range(struct.unpack_from('<I', b, o + 64)[0]):
                so = o + 72 + k * 80
                sect = b[so:so + 16].split(b'\0')[0].decode(); seg = b[so + 16:so + 32].split(b'\0')[0].decode()
                addr, size = struct.unpack_from('<QQ', b, so + 32); off = struct.unpack_from('<I', b, so + 48)[0]
                m['sects'][(seg, sect)] = (addr, size, off)
        elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_ID_DYLIB, LC_RPATH):
            so = struct.unpack_from('<I', b, o + 8)[0]
            s = b[o + so:o + sz].split(b'\0')[0].decode()
            if cmd == LC_ID_DYLIB: m['id'] = s
            elif cmd == LC_RPATH: m['rpaths'].append(s)
            else: m['deps'].append(s)
        elif cmd == LC_MAIN:
            m['entryoff'] = struct.unpack_from('<Q', b, o + 8)[0]
        o += sz
    segs = [s for s in m['segs'] if s[0] != '__PAGEZERO']
    m['lo'] = min(s[1] for s in segs if s[0] != '__LINKEDIT')
    m['hi'] = max(s[1] + s[2] for s in segs)
    return m


def thin_arm64(path, out):
    archs = sh('lipo', '-archs', path).split()
    #  10-21 KEY OFF THE MAGIC, NOT THE ARCH COUNT. `lipo -archs` prints
    #    `arm64` for a THIN file and for a one-slice FAT alike, so this early
    #    return used to hand a fat container straight back and the parse then
    #    died with "not a thin arm64 Mach-O". Hit by Flutter's FlutterMacOS and
    #    App.framework (autoxlat, RustDesk/Flutter translation).
    with open(path, 'rb') as _f: _magic = _f.read(4)
    _is_fat = _magic in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca')
    if not _is_fat and archs in (['arm64'], ['arm64e']): return path
    #  macOS 27 system binaries are arm64e-only (launchd, xpcproxy …): same cputype, PAC instructions are lifted (pac_probe),
    #    and auth-rebase/auth-bind fixups come through dyld_info like plain ones (FIXROW).
    a = 'arm64' if 'arm64' in archs else 'arm64e' if 'arm64e' in archs else None
    if a is None: raise SystemExit(f'{path}: no arm64 slice ({archs})')
    subprocess.run(['lipo', '-thin', a, path, '-output', out], check=True); return out


def resolve_dep(dep, loader_dir, exe_dir, rpaths):
    for pre, base in (('@executable_path/', exe_dir), ('@loader_path/', loader_dir)):
        if dep.startswith(pre): return os.path.normpath(os.path.join(base, dep[len(pre):]))
    if dep.startswith('@rpath/'):
        for rp in rpaths:
            for pre, base in (('@executable_path', exe_dir), ('@loader_path', loader_dir)):
                if rp.startswith(pre):
                    cand = os.path.normpath(os.path.join(base + rp[len(pre):], dep[len('@rpath/'):]))
                    if os.path.exists(cand): return cand
    return None


def section_bytes(path, m, seg, sect):
    if (seg, sect) not in m['sects']: return b''
    addr, size, off = m['sects'][(seg, sect)]
    if not off: return b''
    with open(path, 'rb') as f:
        f.seek(off); return f.read(size)


STRIP = re.compile(r' <[^>]*>')
#  10-23: llvm-objdump appends a flag token to a bind row for a WEAK IMPORT, e.g.
#    `__DATA_CONST __got 0x10000C548 pointer 0 libSystem __availability_version_check (weak_import)`.
#    The three table regexes ended at the symbol with \s*$, so those rows did NOT match, the binds
#    vanished from the opcode set, and the `dyld_binds <= binds` invariant tripped with
#    "classic bind tables and dyld_info disagree" - refusing two perfectly ordinary weak imports.
#    Measured on startosinstall: dyld_binds 164 vs opcode 162, the two missing slots exactly these.
OBJDFLAG = r'(?:\s*\((?:weak_import|weak_def|weak)\))?\s*$'
FIXROW = re.compile(r'\s+\S+\s+\S+\s+0x([0-9A-Fa-f]+)\s+(rebase|auth-rebase|bind|auth-bind|weak-bind|lazy-bind)\s+(\S+)'   # lazy-bind: bound up front like any bind
                    r'(?:\s*\+\s*(0x[0-9A-Fa-f]+|\d+))?(?:\s*\[[^\]]*\])*'   # [weak-import]: 0 if absent = an unresolved slot
                    r'(?:\s*\(div=[^)]*\))?\s*$')   #  arm64e auth fixups carry (div= ad= key=): PAC metadata, plain pointer on x86


#  10-03 system libraries whose ARM64 build is translated with the program (see the dep walk in main())
SUBST = {'/usr/lib/libc++.1.dylib': os.path.join(S, 'vendor', 'libc++.1.0.dylib')}
if os.environ.get('ARM2X86_LAUNCHSERVICES_SUPPORT'):
    SUBST['/usr/lib/libLaunchServicesSupport.dylib'] = os.environ['ARM2X86_LAUNCHSERVICES_SUPPORT']


def x86_asm_names(names):
    """ 10-03 THE x86-64 SYMBOL FOR A C NAME IS NOT ALWAYS THE NAME. On arm64 `stat`, `readdir`, `opendir` ... ARE the
       64-bit-inode functions; on x86-64 those plain names are the LEGACY 32-bit-inode layouts and the modern ones are
       `stat$INODE64`, `readdir$INODE64` (the SDK's __DARWIN_INODE64 / __DARWIN_ALIAS_I asm labels). Cyberpunk build26
       opened `base/ultiplayer.ini` and `mac/lay.ini`: struct dirent read at the arm64 offset (21) out of a legacy one (8).
       Copy the compiler: reference every name for x86-64 against the same umbrella headers and read the asm symbol clang
       emits. -> {c name: x86 symbol without the leading underscore}, only where they differ."""
    import tempfile   # noqa: PLC0415
    names, dropped = sorted(names), []
    for _round in range(4):   #  a name the umbrella does not declare (__stack_chk_fail, _tlv_atexit: runtime helpers, no
        src = open(os.path.join(S, 'sigdb_umbrella.c')).read() + '\n' + ''.join(   #    inode variant) is dropped, by name
            f'void *__arm2x86_ref_{i} = (void *)&{n};\n' for i, n in enumerate(names))
        with tempfile.TemporaryDirectory() as td:
            open(os.path.join(td, 'r.m'), 'w').write(src)
            r = subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=15.0', '-w', '-ferror-limit=0', '-S',
                                '-o', '-', '-x', 'objective-c', os.path.join(td, 'r.m')], capture_output=True, text=True)
        if not r.returncode: break
        bad = set(re.findall(r"undeclared identifier '([^']+)'", r.stderr))
        #  10-10 macOS 27 SYSTEM binaries (loginwindow) import APIs the SDK marks UNAVAILABLE — e.g.
        #    "error: 'CGDisplayCreateImage' is unavailable: obsoleted in macOS 15.0". That is a hard ERROR, not a
        #    warning, so the '-w' above does not cover it and the whole reference file fails to compile. Such a name
        #    needs no $INODE64 mapping (it is not a dirent/stat layout alias), so drop it exactly like an undeclared
        #    one and keep the name as-is.
        bad |= set(re.findall(r"'([^']+)' is unavailable", r.stderr))
        if not bad: raise SystemExit(f'x86_asm_names: the reference file did not compile: {r.stderr[:600]}')
        dropped += sorted(bad); names = [n for n in names if n not in bad]
    else:
        raise SystemExit(f'x86_asm_names: still failing after dropping {len(dropped)} names')
    if dropped: print(f'asm names: {len(dropped)} sigdb names not declared by the umbrella, kept as-is: {dropped[:8]}')
    got = dict(re.findall(r'^___arm2x86_ref_(\d+):\s*\n\s*\.quad\s+_(\S+)', r.stdout, re.M))
    if len(got) != len(names): raise SystemExit(f'x86_asm_names: {len(got)} symbols read back for {len(names)} names')
    #  only the LAYOUT difference ($INODE64, x86-only). `$DARWIN_EXTSN` comes from the umbrella's _DARWIN_C_SOURCE and is a
    #    semantic choice the arm64 import already made in its own name (Cyberpunk imports `realpath$DARWIN_EXTSN` as such).
    return {n: n + '$INODE64' for i, n in enumerate(names) if '$INODE64' in got[str(i)]}


def ctor_dtor(d):
    """ 10-03 is this demangled name a constructor (X::X(...)) or destructor (X::~X(...))? Template arguments and
       [abi:...] tags are ignored; an `operator<`-style name unbalances the brackets and reads as NOT one (safe side)."""
    depth, cut = 0, None
    for i, ch in enumerate(d):
        if ch == '(' and depth == 0: cut = i; break
        if ch in '<(': depth += 1
        elif ch in '>)': depth -= 1
    if cut is None: return False
    parts, depth, cur, i, name = [], 0, '', 0, d[:cut]
    while i < len(name):
        ch = name[i]
        if ch == '<': depth += 1
        elif ch == '>': depth -= 1
        if depth == 0 and name.startswith('::', i): parts.append(cur); cur = ''; i += 2; continue
        cur += ch; i += 1
    parts.append(cur)
    if len(parts) < 2: return False
    base = lambda s: re.sub(r'\[abi:[^\]]*\]', '', s.split('<')[0]).strip()
    last, cls = base(parts[-1]), base(parts[-2])
    return bool(cls) and (last == cls or last == '~' + cls)


def eh_extract(path, m):
    """ 10-03 C++ exceptions: every function's LSDA, found the way the unwinder finds it — compact unwind's LSDA
       descriptors — parsed into call sites (eh.py). -> {fstart: (personality GOT slot, sites)}. Type-table entries stay
       GOT slots / addresses here; main() names them after the binds are resolved.
        A function whose unwind info is DWARF (mode 3) keeps its LSDA in __eh_frame, which this does not read: COUNTED
          and printed, never silently treated as having no handlers."""
    import eh   # noqa: PLC0415
    txt = sh(xlat.OBJDUMP, 'llvm-objdump', '--macho', '--unwind-info', path)
    lo = m['lo']
    pers = {int(i): int(v, 16) + lo for i, v in re.findall(r'personality\[(\d+)\]: 0x([0-9a-f]+)', txt)}
    enc = {int(f, 16) + lo: int(e, 16) for f, e in re.findall(r'function offset=0x([0-9a-f]+), encoding(?:\[\d+\])?=0x([0-9a-f]+)', txt)}
    lsda = {}
    sec = txt.split('LSDA descriptors:')[1].split('Second level indices:')[0] if 'LSDA descriptors:' in txt else ''
    for f, l in re.findall(r'function offset=0x([0-9a-f]+), LSDA offset=0x([0-9a-f]+)', sec):
        lsda[int(f, 16) + lo] = int(l, 16) + lo
    segs = [s for s in m['segs'] if s[4]]
    fh = open(path, 'rb')
    def read(a, n):
        for _, vm, _, foff, fsz in segs:
            if vm <= a < vm + fsz:
                fh.seek(foff + a - vm); b = fh.read(min(n, vm + fsz - a)); return b + bytes(n - len(b))
        raise ValueError(f'LSDA read at 0x{a:x} outside the file')
    out, dwarf = {}, 0
    for f, l in lsda.items():
        e = enc.get(f, 0)
        pi = (e >> 28) & 3
        if not pi: raise SystemExit(f'{path}: function 0x{f:x} has an LSDA and no personality')
        out[f] = (pers[pi], eh.parse_lsda(read, l, f))
    for f, e in enc.items():
        if (e & 0x0f000000) == 0x03000000 and (e >> 28) & 3: dwarf += 1
    fh.close()
    m['eh_dwarf'] = dwarf
    return out


CPG_BASE = 0xFFFFFC000


def commpage_gate(images):
    """ 10-11 THE ARM64 COMMPAGE: every offset the program reads must be one the shim fills.

    0xFFFFFC000 is a kernel page present in every arm64 process and in NO x86 process, and arm64 code reads it
    INLINE (a bitmask-immediate `mov` + `movk`, then a load) — no call, no stub, nothing to bind, so a read is
    simply a SIGSEGV. macOS 27's opendirectoryd died that way at 0xfffffc104, and diagnosticd and logd read the
    same word. shim_comp.c maps the page and fills the offsets in its CPG_TABLE from values measured on real
    arm64 Macs; an offset NOT in that table would read a silent zero, which is a wrong answer rather than a
    crash — the worse failure. So the offsets are parsed out of the shim and a read of anything else STOPS here.
     A MATERIALISED COMMPAGE ADDRESS IS NOT ALWAYS A READ. macOS 27's WindowManager builds 0xFFFFFFF3C into
       x10 and does `cmp x9, x10` — a sentinel it compares against and never dereferences — so counting every
       materialisation would have blocked WindowManager for nothing. The three cases are kept apart: a
       dereference of that register BLOCKS on an unlisted offset, a comparison with no dereference is reported
       and allowed, and anything else BLOCKS, because an address parked in a callee-saved register and loaded
       far away (logd does exactly that with x22) must not be the case that slips through.
    """
    src = os.path.join(S, 'shim_comp.c')
    txt = open(src).read()
    b, e = txt.find('/* CPG_TABLE_BEGIN'), txt.find('/* CPG_TABLE_END')
    if b < 0 or e < 0 or e < b:
        raise SystemExit(f'{src}: CPG_TABLE markers missing — cannot tell which commpage offsets the shim fills')
    known = {int(mo.group(1), 16) for mo in
             (re.match(r'\s*\{\s*(0x[0-9a-fA-F]+)\s*,', ln) for ln in txt[b:e].splitlines()) if mo}
    hits, cmpd, bad = {}, {}, []
    for img in images:
        lines = open(os.path.join(img['dir'], 'full.txt')).read().splitlines()
        fn = img['name']
        for i, ln in enumerate(lines):
            if ln.rstrip().endswith('>:'):
                fn = ln.strip().rstrip(':'); continue
            #  THERE IS MORE THAN ONE WAY TO BUILD THIS ADDRESS and the scan used to know only one.
            #    `mov xN, #0xfffff0000` + `movk` is what the compiler emitted in the cases we found, but
            #    0xFFFFFC000 is ITSELF a valid arm64 bitmask immediate, so `mov xN, #0xfffffc000` followed
            #    by `add xN, xN, #0x104` assembles fine (verified with the assembler) and that form matched
            #    nothing here -- not the movk path, and not the catch-all either, since the `ldr` line
            #    carries no literal. It would have walked straight through the gate.
            mb = re.search(r'\b(?:mov|orr)\s+(x\d+),(?:\s*xzr,)?\s*#(0x[0-9a-fA-F]+)', ln)
            base = int(mb.group(2), 16) if mb else None
            if base is None or not (0xFFFFF0000 <= base <= 0xFFFFFFFFF):
                # a dereference of a literal commpage address in any other shape: decoded or not, it is a read
                #  10-18 only the OPERANDS, never the address column: Cyberpunk's `100fffffc: ldr d0, [x9, #0xe28]`
                #    matched 'fffffc' in its own address and stopped the game build.
                ins = ln.split(':', 1)[1] if re.match(r'\s*[0-9a-f]+:', ln) else ln
                if 'fffffc' in ins and re.search(r'\b(ld|st)r?[bhsw]?\b.*\[', ins): bad.append((fn, ln.strip()))
                continue
            reg, addr = mb.group(1), base
            built = 0   # index (in lines[i+1:]) of the movk/add that finished building the address, if any
            for j, nx in enumerate(lines[i + 1:i + 6]):
                mk = re.search(r'\bmovk\s+' + reg + r',\s*#(0x[0-9a-fA-F]+)', nx)
                if mk: addr = (addr & ~0xFFFF) | int(mk.group(1), 16); built = j + 1; break
                ma = re.search(r'\badd\s+' + reg + r',\s*' + reg + r',\s*#(0x[0-9a-fA-F]+)', nx)
                if ma: addr = addr + int(ma.group(1), 16); built = j + 1; break
            off = addr - CPG_BASE
            if off < 0 or off >= 0x4000: bad.append((fn, ln.strip())); continue
            #  10-18 THE WINDOW ENDS WHERE THE REGISTER IS OVERWRITTEN. Cyberpunk builds the 36-bit MASK 0xffffffff0
            #    (= commpage +0x3ff0 by value) and does `add x8, x22, x8; and x8, x8, #0xffffffff0`: an arithmetic
            #    operand combined with another register, never an address. A later `ldr [x8]` reads the NEW x8.
            #    So: the first instruction that writes `reg` closes the window, and if that write combines reg with a
            #    DIFFERENT register it is an operand (reported, allowed, like a comparison). Any other write that
            #    consumes reg (mov xN, reg; add reg, reg, #imm) is not an operand use, so the read checks still run
            #    on the lines before it.
            win, operand = [], False
            for w in lines[i + 1 + built:i + 10 + built]:
                body = w.split(':', 1)[1] if re.match(r'\s*[0-9a-f]+:', w) else w
                dst = re.match(r'\s*[a-z.0-9]+\s+([xw]\d+)\b', body)
                if dst and dst.group(1)[1:] == reg[1:] and not re.match(r'\s*(?:st|cmp|cmn|tst|ccmp)', body):
                    srcs = re.findall(r'\b[xw](\d+)\b', body.split(',', 1)[1] if ',' in body else '')
                    if re.match(r'\s*(?:add|sub|and|orr|eor)\s', body) and reg[1:] in srcs and any(x != reg[1:] for x in srcs):
                        operand = True
                    win.append(w); break
                win.append(w)
            if operand and not any(re.search(r'\b(?:ld|st)\w*\s+\w+,\s*\[' + reg + r'\b', w) for w in win[:-1]):
                cmpd.setdefault(off, set()).add(fn); continue
            deref = any(re.search(r'\b(?:ld|st)\w*\s+\w+,\s*\[' + reg + r'\b', w) for w in win)
            #  10-18 flag-setting TESTS are comparisons too: Cyberpunk does `bics xzr, x11, x10` with the 36-bit mask
            #    0xffffffff0 in x11 (2 sites, measured by running this gate with its hits printed).
            compared = any(re.search(r'\b(?:cmp|cmn|subs|ccmp|ccmn|tst|bics|ands|adds)\b.*\b' + reg + r'\b', w) for w in win)
            if deref:                     hits.setdefault(off, set()).add(fn)
            elif compared:                cmpd.setdefault(off, set()).add(fn)
            else:                         hits.setdefault(off, set()).add(fn)
    if hits:
        print('commpage: reads ' + ', '.join(
            f'+{o:#05x} ({len(hits[o])} site{"" if len(hits[o]) == 1 else "s"})' for o in sorted(hits)))
    if cmpd:
        print('commpage: ' + ', '.join(f'+{o:#05x}' for o in sorted(cmpd))
              + ' used as a sentinel to compare against, never dereferenced — allowed, nothing to publish')
    unknown = sorted(o for o in hits if o not in known)
    if unknown or bad:
        for o in unknown:
            print(f'  +{o:#05x} is NOT filled by CPG_TABLE in shim_comp.c — read by: '
                  + ', '.join(sorted(hits[o])[:4]))
        for fn, ln in bad[:8]:
            print(f'  commpage address this scan cannot decode, in {fn}: {ln}')
        raise SystemExit('commpage: a read the shim does not fill would return a SILENT ZERO — measure the '
                         'value on a real arm64 Mac and add it to CPG_TABLE in shim_comp.c')


def analyze(img):
    """Per image: functions, stubs, objc stubs, fixups (rebases + binds WITH addends), exports, init offsets, TLV, objc."""
    path, m, out = img['path'], img['m'], img['dir']
    os.makedirs(out, exist_ok=True)
    dis = os.path.join(out, 'full.txt')
    #  10-03 the disassembly is cached on the image's bytes (+ this stage's code): an unchanged game re-disassembles nothing
    import hashlib   # noqa: PLC0415
    dkey = hashlib.sha256(open(path, 'rb').read() + STRIP.pattern.encode()).hexdigest()
    dstamp = dis + '.sha'
    cached = os.path.exists(dis) and os.path.exists(dstamp) and open(dstamp).read().strip() == dkey
    if not cached:
      with open(dis + '.tmp', 'w') as f:   #  symbol annotations are comments; the address always precedes them
        for ln in sh(xlat.OBJDUMP, 'llvm-objdump', '-d', '--no-show-raw-insn', '--section=__text', path).splitlines():
            #  10-03: WAS `if ln[:1].isspace()` — instruction lines start with the ADDRESS at column 0, so nothing was stripped
            #    and `ldr x16, 0x… <dyld_stub_binder+…>` lifted as a REGISTER named %0x…. Only a function header keeps its <name>.
            f.write((ln if ln.rstrip().endswith('>:') else STRIP.sub('', ln)) + '\n')
      os.replace(dis + '.tmp', dis); open(dstamp, 'w').write(dkey)
    #  10-03: the rows are INDENTED; `^0x` matched nothing and every image became one function
    # `<unknown>` is objdump's marker for an undecodable word (data / M5-only forms): split_fns treats it as data on purpose
    left = sum(1 for ln in open(dis) if '<' in ln.replace('<unknown>', '') and not ln.rstrip().endswith('>:'))
    if left: raise SystemExit(f'{path}: {left} instruction lines still carry a <symbol> annotation')   #  refuse, never lift one
    #  10-03: WAS `xcrun dyld_info -function_starts`; the mini's dyld_info VALIDATES the image first and refused a rebased
    #    lib6 ("initializer 0/1 is not in an executable segment") that runs identical to the M4. LC_FUNCTION_STARTS is the same
    #    data either way (libsteam_api: 1,187 = 1,187, same addresses); llvm-objdump just reads it.
    st = re.findall(r'^([0-9a-fA-F]{8,})$', sh(xlat.OBJDUMP, 'llvm-objdump', '--macho', '--function-starts=addrs', path), re.M)
    if not st:
        #  10-10 SOME macOS 27 BINARIES SHIP WITH NO LC_FUNCTION_STARTS AND NO SYMBOLS — WindowServer is one
        #    (__text 0x4f4 bytes, one symbol: __mh_execute_header). Recover the starts from the only two things the
        #    image still states about itself: the LC_MAIN entry, and every address a `bl` names. A `bl` target IS a
        #    function; a `b` target is NOT added, because a plain branch is also how a function jumps inside itself
        #    and splitting there would cut a function in half.  This is a FALLBACK, not a parser: it is announced,
        #    and a function reached only by a tail `b` would be missed — the lifter's "running off the end continues
        #    into the next function" is what keeps that correct. Verified on WindowServer: 2 functions recovered
        #    (entry 0x100000718 and 0x100000798), and every other bl target is an __auth_stubs entry.
        tsec = m['sects'].get(('__TEXT', '__text'))
        if not tsec: raise SystemExit(f'{path}: no function starts (LC_FUNCTION_STARTS) and no __TEXT,__text')
        tlo, tsz = tsec[0], tsec[1]
        if m['entryoff'] is None: raise SystemExit(f'{path}: no function starts (LC_FUNCTION_STARTS) and no LC_MAIN')
        rec = {m['lo'] + m['entryoff']}
        for a_ in re.findall(r'^\s*[0-9a-f]+:\s+bl\s+0x([0-9a-f]+)', open(dis).read(), re.M):
            v = int(a_, 16)
            if tlo <= v < tlo + tsz: rec.add(v)
        for ln in sh('nm', '-arch', 'arm64e', '-n', path).splitlines():
            mnm = re.match(r'^([0-9a-f]{8,})\s+[tT]\s', ln)
            if mnm and tlo <= int(mnm.group(1), 16) < tlo + tsz: rec.add(int(mnm.group(1), 16))
        if not rec: raise SystemExit(f'{path}: no function starts (LC_FUNCTION_STARTS) and none could be recovered')
        st = [f'{v:x}' for v in sorted(rec)]
        print(f'starts: {path} has NO LC_FUNCTION_STARTS — {len(st)} recovered from LC_MAIN + bl targets in __text')
    starts = os.path.join(out, 'starts.txt')
    open(starts, 'w').write(''.join(f'{int(a, 16):016x}\n' for a in st))
    fsegs, rep = split_fns.split(dis, starts)
    img['fsegs'] = fsegs; img['nfn'] = len(fsegs)
    img['eh'] = eh_extract(path, m)
    stub_slot, stub_lines, cur = {}, {}, None
    #  10-10 AN arm64e IMAGE KEEPS ITS STUBS IN __TEXT,__auth_stubs — NOT __TEXT,__stubs. Every macOS 27 system
    #    binary is arm64e, and 27's loginwindow has no __stubs section at all, so reading only __stubs found ZERO stubs
    #    and every `bl <stub>` lifted to __arm2x86_unimplemented (the first one reached was _stat's stub at 0x1000d32b4,
    #    on the very first /var/run/com.apple.loginwindow.didRunThisBoot check). The authenticated entry is FOUR
    #    instructions and carries the page offset in an `add`, not in the load:
    #        adrp x17, <page> ; add x17, x17, #<off> ; ldr x16, [x17] ; braa x16, x17
    sd = ''
    for sec in ('__stubs', '__auth_stubs'):
        try: sd += sh(xlat.OBJDUMP, 'llvm-objdump', '-d', '--no-show-raw-insn', f'--section={sec}', path) + '\n'
        except subprocess.CalledProcessError: pass
    for ln in sd.splitlines():
        ln = STRIP.sub('', ln)
        mm = re.match(r'\s*([0-9a-f]+):\s+(\w+)\s*(.*)', ln)   #  10-03: \s* — a bare `nop` has no operands
        if not mm: continue
        a, op, rest = int(mm.group(1), 16), mm.group(2), mm.group(3)
        if op == 'adrp':
            cur = [a, int(re.search(r'0x([0-9a-f]+)', rest).group(1), 16)]; stub_lines[a] = [ln]
        elif op == 'nop':
            #  10-03: the CLASSIC stub of an LC_DYLD_INFO image is `nop; ldr x16, <lazy pointer>; br x16` — no adrp.
            #    libsteam_api and Bink are built that way, and all 100 of their stubs were skipped: every import call they
            #    made went to __arm2x86_unimplemented (first launch: ___cxa_guard_acquire at 0x10c00a624).
            cur = [a, None]; stub_lines[a] = [ln]
        elif op == 'add' and cur and cur[1] is not None:
            #  the __auth_stubs entry finishes the page-relative address here, before the load (see above).
            imm = re.search(r'#(0x[0-9a-f]+|\d+)\s*$', rest.strip())
            if not imm: raise SystemExit(f'{path}: stub at 0x{cur[0]:x} has an unexpected add: {ln.strip()}')
            cur[1] += int(imm.group(1), 0); stub_lines[cur[0]].append(ln)
        elif op == 'ldr' and cur:
            if cur[1] is None:
                lit = re.match(r'x16,\s*0x([0-9a-f]+)\s*$', rest.strip())
                if not lit: raise SystemExit(f'{path}: classic stub at 0x{cur[0]:x} has an unexpected load: {ln.strip()}')
                stub_slot[cur[0]] = int(lit.group(1), 16)
            else:
                off = re.search(r'#(0x[0-9a-f]+|\d+)\]', rest)
                stub_slot[cur[0]] = cur[1] + (int(off.group(1), 0) if off else 0)
            stub_lines[cur[0]].append(ln)
        elif op in ('br', 'braa', 'brab', 'braaz', 'brabz') and cur:
            #  an __auth_stubs entry ends in `braa x16, x17` — `br` alone never closed it.
            stub_lines[cur[0]].append(ln); cur = None
    img['stub_slot'], img['stub_lines'] = stub_slot, stub_lines
    sel, cur = {}, None
    try: ods = sh(xlat.OBJDUMP, 'llvm-objdump', '-d', '--no-show-raw-insn', '--section=__objc_stubs', path)
    except subprocess.CalledProcessError: ods = ''
    for ln in ods.splitlines():
        mm = re.match(r'\s*([0-9a-f]+):\s+(\w+)\s+(.*)', STRIP.sub('', ln))
        if not mm: continue
        a, op, rest = int(mm.group(1), 16), mm.group(2), mm.group(3)
        if op == 'adrp' and rest.startswith('x1,'): cur = [a, int(re.search(r'0x([0-9a-f]+)', rest).group(1), 16)]
        elif op == 'ldr' and rest.startswith('x1,') and cur:
            off = re.search(r'#(0x[0-9a-f]+|\d+)\]', rest); sel[cur[0]] = cur[1] + (int(off.group(1), 0) if off else 0); cur = None
    img['objc_stub_sel'] = sel
    rebases, binds = [], []
    #  10-03: an LC_DYLD_INFO (classic) image lists a rebase's target as the pointer's RAW CONTENT, which rebase_macho
    #    leaves unslid (libsteam_api, Bink: 0x828 where 0x101000828 is meant). Chained fixups encode the real target.
    classic = 'LC_DYLD_CHAINED_FIXUPS' not in sh('xcrun', 'otool', '-l', path)
    slide = img.get('slide', 0) if classic else 0
    for ln in sh('xcrun', 'dyld_info', '-fixups', path).splitlines():
        mm = FIXROW.match(ln)
        if not mm:
            if re.match(r'\s+__\S+\s+\S+\s+0x[0-9A-Fa-f]+\s+\S', ln): raise SystemExit(f'unparsed fixup row: {ln!r}')
            continue
        a, kind, t = int(mm.group(1), 16), mm.group(2), mm.group(3)
        add = int(mm.group(4), 0) if mm.group(4) else 0
        if 'rebase' in kind: rebases.append((a, int(t, 16) + slide))
        else:
            lib, sym = t.split('/', 1); binds.append((a, lib, sym, add))
    if classic:
        #  10-03: `dyld_info -fixups` MIS-DECODES a classic image's weak binds — l6's GOT 0x4010 (a weak bind to the
        #    coalesced template static __ZZN7CounterIiE4bumpEvE1n) printed as `bind libSystem/__tlv_bootstrap`, and the
        #    constructor's increment wrote into our code. The three classic tables are read from llvm-objdump instead;
        #    dyld_info is kept for the rebases (decoded right, slid above). The row counts must agree.
        nb = len(binds); binds = []
        od = lambda flag: sh('xcrun', 'llvm-objdump', '--macho', flag, path).splitlines()
        for ln in od('--bind'):
            mm = re.match(r'\s*\S+\s+\S+\s+0x([0-9a-fA-F]+)\s+\S+\s+(-?\d+)\s+(\S+)\s+(\S+)' + OBJDFLAG, ln)
            if mm: binds.append((int(mm.group(1), 16), mm.group(3), mm.group(4), int(mm.group(2))))
        for ln in od('--weak-bind'):
            mm = re.match(r'\s*\S+\s+\S+\s+0x([0-9a-fA-F]+)\s+\S+\s+(-?\d+)\s+(\S+)' + OBJDFLAG, ln)
            if mm: binds.append((int(mm.group(1), 16), '<weak-def-coalesce>', mm.group(3), int(mm.group(2))))
        for ln in od('--lazy-bind'):
            mm = re.match(r'\s*\S+\s+\S+\s+0x([0-9a-fA-F]+)\s+(\S+)\s+(\S+)' + OBJDFLAG, ln)
            if mm: binds.append((int(mm.group(1), 16), mm.group(2), mm.group(3), 0))
        #  compared by ADDRESS: one slot may carry a bind AND a weak bind (operator new/delete — the C++ rule that a program
        #    may replace them), which dyld_info shows as one merged row and llvm-objdump as two (libsteam_api: 82 vs 74).
        rows_ = [m_ for m_ in (FIXROW.match(l_) for l_ in sh('xcrun', 'dyld_info', '-fixups', path).splitlines()) if m_]
        dyld_binds = {int(m_.group(1), 16) for m_ in rows_ if 'rebase' not in m_.group(2)}
        dyld_all = {int(m_.group(1), 16) for m_ in rows_}
        #  10-03: a weak-def slot that resolves to the image's OWN definition (lib6: Counter<int>::bump()::n) is a weak bind
        #    to llvm-objdump and a REBASE row to the mini's dyld_info. Both are right: every dyld_info bind must be in the
        #    opcode tables, and every opcode bind must be SOME dyld_info fixup.
        if not (dyld_binds <= {b_[0] for b_ in binds} <= dyld_all):
            raise SystemExit(f'{path}: classic bind tables and dyld_info disagree on WHICH slots are bound — refusing to guess')
    img['rebases'], img['binds'] = rebases, binds
    ex = {}
    for ln in sh('xcrun', 'dyld_info', '-exports', path).splitlines():
        mm = re.match(r'\s+0x([0-9A-Fa-f]+)\s+(\S+)', ln)
        if mm: ex[mm.group(2)] = int(mm.group(1), 16) + m['lo']   # export offsets are from the image's __TEXT
    img['exports'] = ex
    io = section_bytes(path, m, '__TEXT', '__init_offsets')
    img['inits'] = [m['lo'] + struct.unpack_from('<I', io, k)[0] for k in range(0, len(io), 4)]
    #  10-03: a classic image's initializers are POINTERS in __mod_init_func (each one rebased), not __init_offsets.
    #    They were never run: the l6 ruler's library (classic since 10-03) printed nothing at all.
    mif = next((v for (sg, sc), v in m['sects'].items() if sc == '__mod_init_func'), None)
    if mif and mif[1]:
        rb = dict(rebases)
        miss = [hex(a) for a in range(mif[0], mif[0] + mif[1], 8) if a not in rb]
        if miss: raise SystemExit(f'{path}: __mod_init_func slots with no rebase: {miss[:5]}')
        img['inits'] += [rb[a] for a in range(mif[0], mif[0] + mif[1], 8)]
    img['tlv'] = (m['sects'].get(('__DATA', '__thread_vars')), m['sects'].get(('__DATA', '__thread_data')),
                  m['sects'].get(('__DATA', '__thread_bss')))
    img['osec'] = {}
    for nm in ('__objc_selrefs', '__objc_classlist', '__objc_catlist', '__objc_classrefs', '__objc_superrefs',
               '__objc_protolist', '__objc_protorefs'):   #  10-22 protocols: see __arm2x86_objc_protocols
        img['osec'][nm] = next((v[:2] for (sg, sc), v in m['sects'].items() if sc == nm), (0, 0))
    for nm in ('__swift5_proto', '__swift5_types', '__swift5_protos'):   #  10-20 see __arm2x86_swift_register
        img['osec'][nm] = m['sects'].get(('__TEXT', nm), (0, 0))[:2]
    return img


_SHAPE_ADDR = re.compile(r'0x[0-9a-f]+')
_SHAPE_IMM = re.compile(r'#-?(?:0x[0-9a-f]+|\d+(?:\.\d+)?(?:e[-+]?\d+)?)')
_SHAPE_REG = re.compile(r'(?<![\w.])([xwqdshbvzp])\d+\b')


def insn_shape(line):
    """'10e9b8110: ldr x3, 0x10e9b8020' -> 'ldr xN, A': the mnemonic and operand FORM the lifter dispatches on — register
       CLASS and arrangement kept, numbers dropped. One real instance per shape exercises every lifter path the program has."""
    p = abi_scan.parse_line(line)
    if not p: return None
    ops = _SHAPE_REG.sub(lambda m: m.group(1) + 'N', _SHAPE_IMM.sub('#I', _SHAPE_ADDR.sub('A', p[2])))
    return p[1] + ' ' + ops


def preflight_chunk(job):
    """Lift (no compile) each representative function; return every failure with its reason."""
    items, known, binds, aliases, nonabi = job
    arm2x86.ALIASES.clear(); arm2x86.ALIASES.update(aliases)
    arm2x86.NONABI.clear(); arm2x86.NONABI.update(nonabi)
    bad = []
    for a, text in items:
        try:
            arm2x86.Lifter(arm2x86.parse(text), f'fn_{a:x}', known, binds).define()
        except Exception as e:   # the reason rides back, every one of them
            bad.append((a, f'{type(e).__name__}: {e}'[:200]))
    return bad


#  10-04 NATIVE FUNCTIONS THAT RETURN TWICE. Cyberpunk calls native setjmp/longjmp (libpng's png_error shape and two
#    more sites), Galaxy calls sigsetjmp/_setjmp. Each is a typed bind called straight from the lifted frame and was
#    DECLARED WITHOUT returns_twice, so LLVM optimised that frame as if setjmp returned once (stack-slot reuse, values
#    cached across the call) and the second return — the longjmp — could land in a frame whose spills were recycled.
#    Clang marks these exactly so; LLVM reads the attribute from the callee's declaration at every call site.
RETURNS_TWICE = frozenset({'setjmp', '_setjmp', 'sigsetjmp', '__sigsetjmp', 'savectx', 'vfork', 'getcontext'})
def _rt(sym):
    return ' returns_twice' if sym in RETURNS_TWICE else ''


def assemble(texts, known, binds):
    """One LLVM module from arm64 function texts (the globals ALIASES/NONABI/EH/THISRET already set): definitions, then
       the declarations they need. -> (parts, body). Shared by lift_shard and the module preflight."""
    eh_decls = set()
    head = arm2x86._module_head().replace('define i64 @__arm2x86_call_arm(', 'define linkonce_odr i64 @__arm2x86_call_arm(')
    parts, used, defined = [head], {}, set()
    for text in texts:
        ins = arm2x86.parse(text)
        L = arm2x86.Lifter(ins, f'fn_{ins[0][0]:x}', known, binds)
        parts.append(L.define()); used.update(L.used_binds); defined.add(ins[0][0]); eh_decls |= L.eh_decls
    parts += sorted(eh_decls)
    body = '\n'.join(parts)
    called = {int(x, 16) for x in re.findall(r'@fn_([0-9a-f]+)\(', body)} - defined
    for a in sorted(called): parts.append(f'declare {ABI_RET} @fn_{a:x}({arm2x86.ABI_PARAMS})')
    for sym, (ret, kinds) in sorted(used.items()):
        parts.append(f'declare {ret} @{sym}({", ".join(arm2x86.BIND_TY[c] for c in kinds)}){_rt(sym)}')
    return parts, body


#  10-03 part of every shard's hash: change a compile flag here and every shard recompiles, as it must
COMPILE_SIG = '; arm2x86 shard: opt -O2/-O1/-O0 (300 s each), llc -O2/-O0 (600 s) -mcpu={cpu} -mattr=+aes,+pclmul\n'


class ShardMemoryCap(Exception):
    """opt or llc outgrew its memory share; the shard drops to the next optimisation level like a timeout does."""


def _gb_env(name, default):
    try: return float(os.environ.get(name, default))
    except ValueError: return float(default)


def _free_percent():
    # kern.memorystatus_level = the free-memory percentage jetsam itself acts on; None if unreadable (then only the cap applies)
    try:
        return int(subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.memorystatus_level'], capture_output=True, text=True,
                                  timeout=5).stdout.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def _capped_run(cmd, timeout):
    #  10-20 THE MINI WENT DARK: macOS 27 system binaries made shards whose opt reached 27 GB and llc 11 GB, three or
    #    four at once on a 16 GB machine. Jetsam killed system daemons for 36 minutes (nine JetsamEvent reports, 11:21-11:57)
    #    and ssh stopped answering on the machine Raven lives on. A timeout cannot catch this: the box is gone long before
    #    300 s. Each compile now has a resident-memory cap (ARM2X86_SHARD_GB, default 3) and the whole machine a floor
    #    (ARM2X86_FREE_FLOOR, default 25 % free): past either, the child is killed and the shard falls to the next level.
    cap_kb = int(_gb_env('ARM2X86_SHARD_GB', 3) * 1024 * 1024)
    floor = _gb_env('ARM2X86_FREE_FLOOR', 25)
    p = subprocess.Popen(cmd)
    t0 = time.time()
    while True:
        try:
            rc = p.wait(timeout=0.5)
            if rc: raise subprocess.CalledProcessError(rc, cmd)
            return
        except subprocess.TimeoutExpired:
            pass
        why = None
        if timeout is not None and time.time() - t0 > timeout:
            p.kill(); p.wait()
            raise subprocess.TimeoutExpired(cmd, timeout)
        try:
            rss = int(subprocess.run(['/bin/ps', '-o', 'rss=', '-p', str(p.pid)], capture_output=True, text=True,
                                     timeout=5).stdout.strip() or 0)
        except (OSError, ValueError, subprocess.SubprocessError):
            rss = 0
        if rss > cap_kb:
            why = f'{rss / 1048576:.1f} GB resident, cap {cap_kb / 1048576:.1f} GB'
        else:
            free = _free_percent()
            if free is not None and free < floor and rss > 512 * 1024:
                why = f'machine at {free} % free (floor {floor:.0f} %), this compile {rss / 1048576:.1f} GB'
        if why:
            p.kill(); p.wait()
            raise ShardMemoryCap(why)


def lift_shard(job):
    """Lift one shard of functions -> .ll -> opt -O2 -> llc -> .o. Runs in a worker process."""
    k, paths, known, binds, aliases, nonabi, out, cpu, eh, thisret, noop = job[:11]
    stub_cc = job[11] if len(job) > 11 else {}   #  10-20 STUB_CC; a jobs.pkl written before it has 11 fields
    async_fns = job[12] if len(job) > 12 else ()   #  10-21 ASYNC_FNS; a jobs.pkl written before it has 12 fields
    o_done = os.path.join(out, f'shard{k:04d}.o')
    #  10-03 (note): INCREMENTAL BY CONSTRUCTION. Every shard is re-lifted
    #    (cheap: ~40 s for the whole game on 10 cores) and its IR, with the compile settings, is hashed. Same hash = the
    #    existing .o is reused, whatever changed elsewhere; different = only this shard recompiles.  WAS: reuse by INDEX if
    #    a .o existed, guarded by a lifter FINGERPRINT and hand-written ARM2X86_RELIFT lists — every lifter change meant a
    #    full rebuild or a guess about which functions it touched.
    arm2x86.ALIASES.clear(); arm2x86.ALIASES.update(aliases)
    arm2x86.NONABI.clear(); arm2x86.NONABI.update(nonabi)   #  rung 6 off-contract functions (abi_scan.py)
    arm2x86.EH.clear(); arm2x86.EH.update(eh)   #  10-03 C++ exceptions: this shard's landing pads (eh.py)
    arm2x86.THISRET.clear(); arm2x86.THISRET.update(thisret)   #  10-03 native ctor/dtor stubs return `this`
    arm2x86.NOOP_CALLS.clear(); arm2x86.NOOP_CALLS.update(noop)   #  10-03 ___chkstk_darwin lifts to nothing
    arm2x86.STUB_CC.clear(); arm2x86.STUB_CC.update(stub_cc)   #  10-20 import stubs name their callee's convention
    arm2x86.ASYNC_FNS.clear(); arm2x86.ASYNC_FNS.update(async_fns)   #  10-21 swift async functions: musttail + hint 3 at `br`
    parts, body = assemble([open(p).read() for p in paths], known, binds)
    import hashlib   # noqa: PLC0415
    ll = os.path.join(out, f'shard{k:04d}.ll'); text = '\n'.join(parts)
    key = hashlib.sha256((COMPILE_SIG.format(cpu=cpu) + text).encode()).hexdigest()
    shaf = os.path.join(out, f'shard{k:04d}.sha')
    if os.path.exists(o_done):
        prev = open(shaf).read().strip() if os.path.exists(shaf) else None
        #  10-05 ONLY IF THE .ll IS NOT NEWER THAN THE .o. A compile that died after writing the new .ll (and removing
        #    the .sha) left fresh IR beside the OLD object; this path then hashed the fresh .ll, matched, and reused the stale
        #    .o — measured: the narrow-return fix rebuilt "0 of 373" shards while shard0000.ll held the new code.
        if prev is None and os.path.exists(ll) and os.path.getmtime(ll) <= os.path.getmtime(o_done):
            prev = hashlib.sha256((COMPILE_SIG.format(cpu=cpu)).encode() + open(ll, 'rb').read()).hexdigest()
            if prev == key: open(shaf + '.tmp', 'w').write(key); os.replace(shaf + '.tmp', shaf)
        if prev == key: return k, o_done, len(paths), 0.0, -1   # -1 = reused, IR identical
    if os.path.exists(shaf): os.remove(shaf)   #  the hash is written only AFTER the new .o is in place
    open(ll, 'w').write(text)
    t0 = time.time()
    #  10-03: shard 1 holds a 45,000-line function and opt -O2 ran 2 h 25 min on it without finishing (build5, measured;
    #    an orphan was still at it). Every shard gets a clock: -O2, then -O1, then -O0 — slower code for that ONE shard,
    #    never a stuck build. Each fallback is printed with the shard number.
    for lvl, lim in (('-O2', 300), ('-O1', 300), ('-O0', None)):
        try:
            _capped_run([f'{LLVM}/opt', lvl, ll, '-o', ll[:-3] + '.bc'], lim); break
        except subprocess.TimeoutExpired:
            print(f'  shard {k}: opt {lvl} passed {lim} s — falling back', flush=True)
        except ShardMemoryCap as e:
            if lvl == '-O0': raise RuntimeError(f'shard {k}: opt -O0 still over the memory cap ({e}); split this shard') from e
            print(f'  shard {k}: opt {lvl} {e} — falling back', flush=True)
    for lvl, lim in (('-O2', 600), ('-O0', None)):
        try:
            _capped_run([f'{LLVM}/llc', lvl, '-mtriple=x86_64-apple-macosx', f'-mcpu={cpu}', '-mattr=+aes,+pclmul', '-filetype=obj',
                         ll[:-3] + '.bc', '-o', ll[:-3] + '.o.tmp'], lim); break
        except subprocess.TimeoutExpired:
            print(f'  shard {k}: llc {lvl} passed {lim} s — falling back', flush=True)
        except ShardMemoryCap as e:
            if lvl == '-O0': raise RuntimeError(f'shard {k}: llc -O0 still over the memory cap ({e}); split this shard') from e
            print(f'  shard {k}: llc {lvl} {e} — falling back', flush=True)
    os.replace(ll[:-3] + '.o.tmp', ll[:-3] + '.o')   #  atomic: a killed build never leaves a truncated .o for resume
    open(shaf + '.tmp', 'w').write(key); os.replace(shaf + '.tmp', shaf)
    os.remove(ll[:-3] + '.bc')
    return k, ll[:-3] + '.o', len(paths), time.time() - t0, len(body)


#  10-21 the Swift runtime's own swiftasync C entry points (Concurrency.h SWIFT_CC(swiftasync)): the context is the first
#    non-result argument and rides r14. A stub reached by an async function's tail branch is found from the code itself
#    (main, `async_stubs`); this set names the ones a marker-less partial-apply thunk would tail-call.
ASYNC_RT_SYMS = {'_swift_task_switch', '_swift_task_future_wait', '_swift_task_future_wait_throwing', '_swift_continuation_await',
                 '_swift_asyncLet_get', '_swift_asyncLet_get_throwing', '_swift_asyncLet_wait', '_swift_asyncLet_wait_throwing',
                 '_swift_asyncLet_finish', '_swift_asyncLet_consume', '_swift_asyncLet_consume_throwing',
                 '_swift_taskGroup_wait_next_throwing', '_swift_taskGroup_waitAll', '_swift_task_suspend'}

NATIVE_ADAPTER_IR = '''
;  rung 6 the NATIVE-POINTER ADAPTER: translated code called a native function pointer. AAPCS64 and SysV both put integer
;   and float arguments in separate register classes, so x0..x7 -> rdi..r9 + stack and v0..v7 (low 64 bits) -> xmm0..7 is the
;   same call. Variadic-safe on the C path (AL is set). The target comes from this thread's slot, written by __arm2x86_lookup.
@__arm2x86_native_target = external thread_local global i64
declare ptr @__arm2x86_tlv_get(ptr)
declare i64 @__arm2x86_cbarg(i64)
;  10-20 shim_comp.c: the target image's Swift answer (set by __arm2x86_lookup) and the bounded arm64 stack-word copy
@__arm2x86_native_swift = external thread_local global i8
declare void @__arm2x86_stack_args(i64, ptr)
declare i64 @__arm2x86_async_ctx(i64)
declare void @__arm2x86_async_run(ptr)
; The callback door and native drain share a depth guard and one pending async call.
; The pending record includes stack arguments, so outlined fragments need no arity inference.
@__arm2x86_async_depth = external thread_local global i64
@__arm2x86_async_pend = external thread_local global [37 x i64]
define {ABI} @__arm2x86_native_adapter(i64 %a0, i64 %a1, i64 %a2, i64 %a3, i64 %a4, i64 %a5, i64 %a6, i64 %a7, <2 x i64> %q0, <2 x i64> %q1, <2 x i64> %q2, <2 x i64> %q3, <2 x i64> %q4, <2 x i64> %q5, <2 x i64> %q6, <2 x i64> %q7) {
entry:
  %stk = alloca [16 x i64], align 16
  %err = alloca swifterror ptr, align 8
  %arec = alloca [37 x i64], align 16
  %t = load i64, ptr @__arm2x86_native_target
  ;  10-20 the stub's convention hint is consumed on EVERY path (the TLV branch too), so it never outlives this call
  %hint = load i8, ptr @__arm2x86_native_hint
  store i8 0, ptr @__arm2x86_native_hint
  %carry0 = load i8, ptr @__arm2x86_async_carry
  store i8 0, ptr @__arm2x86_async_carry
  ; Darwin TLV thunks preserve the caller's registers except x0. The lifted call reloads
  ; x1 and v1-v3 from the shared return file; publish their incoming values rather than
  ; letting an earlier unrelated call's return replace them. Keep v0 unchanged as well.
  %tlv_target = ptrtoint ptr @__arm2x86_tlv_get to i64
  %is_tlv = icmp eq i64 %t, %tlv_target
  br i1 %is_tlv, label %tlv, label %native
tlv:
  %desc = inttoptr i64 %a0 to ptr
  %address = call ptr @__arm2x86_tlv_get(ptr %desc)
  %tlv_x1 = getelementptr i8, ptr @__arm_xr, i64 8
  store i64 %a1, ptr %tlv_x1
  %tlv_v1 = getelementptr i8, ptr @__arm_xr, i64 272
  store <2 x i64> %q1, ptr %tlv_v1, align 16
  %tlv_v2 = getelementptr i8, ptr @__arm_xr, i64 288
  store <2 x i64> %q2, ptr %tlv_v2, align 16
  %tlv_v3 = getelementptr i8, ptr @__arm_xr, i64 304
  store <2 x i64> %q3, ptr %tlv_v3, align 16
  ;  10-20 x2/x3 come back from every call now (XR_ABI_OUT): the thunk preserves them, so hand back what came in
  %tlv_x2 = getelementptr i8, ptr @__arm_xr, i64 16
  store i64 %a2, ptr %tlv_x2
  %tlv_x3 = getelementptr i8, ptr @__arm_xr, i64 24
  store i64 %a3, ptr %tlv_x3
  %tlv_x0 = ptrtoint ptr %address to i64
  %tlv_o1 = insertvalue {ABI} undef, i64 %tlv_x0, 0
  %tlv_o2 = insertvalue {ABI} %tlv_o1, <2 x i64> %q0, 1
  ret {ABI} %tlv_o2
native:
  %f = inttoptr i64 %t to ptr
DOUBLES
  ;  10-11 this call has NO signature — the target is a dlsym result or a plug-in entry point — so nothing
  ;   has told us which argument is a callback. Any integer argument that is an EXACT known guest function start
  ;   is swapped for a trampoline here; everything else passes through untouched (see __arm2x86_cbarg).
  %c0 = call i64 @__arm2x86_cbarg(i64 %a0)
  %c1 = call i64 @__arm2x86_cbarg(i64 %a1)
  %c2 = call i64 @__arm2x86_cbarg(i64 %a2)
  %c3 = call i64 @__arm2x86_cbarg(i64 %a3)
  %c4 = call i64 @__arm2x86_cbarg(i64 %a4)
  %c5 = call i64 @__arm2x86_cbarg(i64 %a5)
  %c6 = call i64 @__arm2x86_cbarg(i64 %a6)
  %c7 = call i64 @__arm2x86_cbarg(i64 %a7)
  ;  10-21 SWIFT ASYNC (hint 3): the target is swifttailcc. arm64 x22 (the async context) -> r14, x20 -> r13, and the
  ;   integer/float arguments are the same registers as swiftcc. There is no x8 sret (an async function's indirect result is an
  ;   ordinary leading argument) and no swifterror (errors come back as a result passed to the resume function). The callee's
  ;   context holds a GUEST resume function — __arm2x86_async_ctx swaps it for its trampoline before the native code runs.
  ;   Integer arguments beyond the native registers, guest stack words, and
  ;   swifterror travel in the record consumed by the assembly caller.
  %h_as = icmp ugt i8 %hint, 2
  br i1 %h_as, label %async, label %cont
async:
  %ax22p = getelementptr i8, ptr @__arm_xr, i64 176
  %ax22 = load i64, ptr %ax22p
  ;  10-21 hint 3 is stored for EVERY `br` of an async guest function, so it also reaches ordinary native callees, and x22
  ;   is then whatever the guest left there: ControlCenter traced 7 such calls (resume slot 0x0, 0x3, 0x7fffffff7fffffff) and
  ;   the 8th x22 was non-canonical (#GP in the slot read). A real async context always has code in ResumeParent; when it
  ;   does not, this is not an async call, so it takes the ordinary Swift path below (cont, which treats hint>2 as swiftcc).
  %actxok = call i64 @__arm2x86_async_ctx(i64 %ax22)
  %actxv = icmp ne i64 %actxok, 0
  ;  10-22 hint 5 = an async IMPORT stub: the callee is swifttailcc whatever x22 holds (see arm2x86.native_hint)
  %h_imp = icmp eq i8 %hint, 5
  %ago = or i1 %actxv, %h_imp
  br i1 %ago, label %async_go, label %cont
async_go:
  %ax20p = getelementptr i8, ptr @__arm_xr, i64 160
  %ax20 = load i64, ptr %ax20p
  %aself = inttoptr i64 %ax20 to ptr
  %actx = inttoptr i64 %ax22 to ptr
  ; Every pending call carries the same argument area as the immediate path.
  ; The drain's depth guard makes nested resumes return to its loop, so even
  ; stack-bearing calls do not accumulate native frames per stream element.
  %ax21p = getelementptr i8, ptr @__arm_xr, i64 168
  %ax21 = load i64, ptr %ax21p
  %asp = load i64, ptr @__arm_sp
  call void @__arm2x86_stack_args(i64 %asp, ptr %stk)
STACKWORDS
  %adep = load i64, ptr @__arm2x86_async_depth
  %adeep = icmp sgt i64 %adep, 0
  br i1 %adeep, label %async_defer, label %async_now
async_defer:
  store i64 %t, ptr @__arm2x86_async_pend
PENDSTORES
  ret {ABI} zeroinitializer
async_now:
  store i64 %t, ptr %arec
RECSTORES
  call void @__arm2x86_async_run(ptr %arec)
  ret {ABI} zeroinitializer
cont:
  ;  10-20 ARGUMENTS PAST x7 LIVE ON THE arm64 STACK, and this call passed none of them: macOS 27's xprotect calls
  ;   ArgumentParser's CommandConfiguration.init with 8 register words + 7 stack words, and the native init read its
  ;   ninth argument from x86 stack garbage. 16 words from the arm64 sp follow x6/x7 on the x86 stack, in order — the
  ;   same place a SysV/Swift callee looks for its 7th+ integer argument. Extra words are harmless (the caller pops).
  ;    Read through the shim, never here: sp near the top of a thread's arm64 stack mapping must not fault.
  %spv = load i64, ptr @__arm_sp
  call void @__arm2x86_stack_args(i64 %spv, ptr %stk)
CSTACKWORDS
  ;  10-20 WHICH CONVENTION: an import stub names it (hint 1 = C, 2 = Swift, by symbol); else the shim's answer for
  ;   the target's image (Swift metadata present).
  %imgsw = load i8, ptr @__arm2x86_native_swift
  %h_sw = icmp eq i8 %hint, 2
  %h_none = icmp eq i8 %hint, 0
  %i_sw = icmp ne i8 %imgsw, 0
  %by_img = and i1 %h_none, %i_sw
  %h_as2 = icmp ugt i8 %hint, 2
  %is_sw0 = or i1 %h_sw, %by_img
  %is_sw = or i1 %is_sw0, %h_as2
  br i1 %is_sw, label %swift, label %ccall
swift:
  ;  10-20 SWIFT'S REGISTERS ARE NOT C'S ON EITHER SIDE. arm64: indirect result x8, self/context x20, error x21.
  ;   x86-64: indirect result RAX, self R13, error R12. The C call below put AL = 8 (the variadic vector count) where
  ;   the indirect result belongs: eslogger's Foundation.URL.init(fileURLWithPath:) wrote its URL to address 0x8
  ;   (SIGSEGV, fault 0x8, measured on macOS 27). swiftcc + sret/swiftself/swifterror is exactly that mapping (llc
  ;   22.1.8, checked: sret -> rax, swiftself -> r13, swifterror -> r12, 7th+ ints on the stack, returns
  ;   rax/rdx/rcx/r8 + xmm0-3 = arm64's x0-x3 + v0-v3). A non-variadic C function called this way sees the same
  ;   arguments — rax/r12/r13 mean nothing to it and it preserves r12/r13 — so only a VARIADIC C callee needs the C path.
  ;    10-21 swiftasync (x22 -> r14) and swifttailcc async entry points are the `async` block above (hint 3), not this path.
  %x8p = getelementptr i8, ptr @__arm_xr, i64 64
  %x8v = load i64, ptr %x8p
  %x20p = getelementptr i8, ptr @__arm_xr, i64 160
  %x20v = load i64, ptr %x20p
  %x21p = getelementptr i8, ptr @__arm_xr, i64 168
  %x21v = load i64, ptr %x21p
  %sret = inttoptr i64 %x8v to ptr
  %self = inttoptr i64 %x20v to ptr
  %errin = inttoptr i64 %x21v to ptr
  store ptr %errin, ptr %err
  %sr = call swiftcc { i64, i64, i64, i64, double, double, double, double } %f(ptr sret(i8) %sret, i64 %c0, i64 %c1, i64 %c2, i64 %c3, i64 %c4, i64 %c5, i64 %c6, i64 %c7, double %d0, double %d1, double %d2, double %d3, double %d4, double %d5, double %d6, double %d7, STACKARGS, ptr swiftself %self, ptr swifterror %err)
  %errout = load ptr, ptr %err
  %erri = ptrtoint ptr %errout to i64
  store i64 %erri, ptr %x21p
  %sx0 = extractvalue { i64, i64, i64, i64, double, double, double, double } %sr, 0
  %sx1 = extractvalue { i64, i64, i64, i64, double, double, double, double } %sr, 1
  %sx2 = extractvalue { i64, i64, i64, i64, double, double, double, double } %sr, 2
  %sx3 = extractvalue { i64, i64, i64, i64, double, double, double, double } %sr, 3
  %sx1p = getelementptr i8, ptr @__arm_xr, i64 8
  store i64 %sx1, ptr %sx1p
  %sx2p = getelementptr i8, ptr @__arm_xr, i64 16
  store i64 %sx2, ptr %sx2p
  %sx3p = getelementptr i8, ptr @__arm_xr, i64 24
  store i64 %sx3, ptr %sx3p
SWIFTVEC
  %so1 = insertvalue {ABI} undef, i64 %sx0, 0
  %so2 = insertvalue {ABI} %so1, <2 x i64> %sv0, 1
  ret {ABI} %so2
ccall:
  ;  10-20 rdx and xmm1 come back too: a 16-byte struct return (two words, or two doubles) is x0:x1 / d0:d1 on
  ;   arm64 and rax:rdx / xmm0:xmm1 here.  WAS dropped — x1 after a native call through a pointer was whatever the
  ;   previous call left in the block. {i64, i64, double, double} still returns in registers (llc 22.1.8, checked).
  ;  10-20 x21 IS CALLEE-SAVED ACROSS A C CALL, BUT ITS SLOT IS NOT: a native callee that calls back into translated
  ;   code goes through the door, and the door hands back the NATIVE caller's r12 as x21 (eslogger: swift_getWitnessTable
  ;   called a translated accessor with r12 = 1, the slot came back 1, and the translated caller reloaded x21 = 1 ->
  ;   SIGSEGV at 0x1 in checkTransitiveCompleteness). The C callee preserved r12, so the slot is put back as it came in.
  %cx21p = getelementptr i8, ptr @__arm_xr, i64 168
  %cx21 = load i64, ptr %cx21p
  %r = call { i64, i64, double, double } (i64, ...) %f(i64 %c0, i64 %c1, i64 %c2, i64 %c3, i64 %c4, i64 %c5, i64 %c6, i64 %c7, double %d0, double %d1, double %d2, double %d3, double %d4, double %d5, double %d6, double %d7, STACKARGS)
  %x = extractvalue { i64, i64, double, double } %r, 0
  %x1 = extractvalue { i64, i64, double, double } %r, 1
  %y = extractvalue { i64, i64, double, double } %r, 2
  %y1 = extractvalue { i64, i64, double, double } %r, 3
  %cx1p = getelementptr i8, ptr @__arm_xr, i64 8
  store i64 %x1, ptr %cx1p
  store i64 %cx21, ptr %cx21p
  %y1b = bitcast double %y1 to i64
  %v1 = insertelement <2 x i64> zeroinitializer, i64 %y1b, i32 0
  %cv1p = getelementptr i8, ptr @__arm_xr, i64 272
  store <2 x i64> %v1, ptr %cv1p, align 16
  %yb = bitcast double %y to i64
  %v = insertelement <2 x i64> zeroinitializer, i64 %yb, i32 0
  %o1 = insertvalue {ABI} undef, i64 %x, 0
  %o2 = insertvalue {ABI} %o1, <2 x i64> %v, 1
  ret {ABI} %o2
}
@__arm2x86_native_adapter_p = constant ptr @__arm2x86_native_adapter

;  rung 1 THE INTERPRETER'S DOOR. Same shape and the same reason as the native adapter above: the C side
;    cannot define a function returning {i64, <2 x i64>} (SysV classifies the equivalent struct MEMORY and
;    returns it through a hidden pointer, which is a different ABI), so the register marshalling is emitted
;    here and the work itself is a plain C call through pointers.
;    xs = x0..x30 then sp (32 slots) vs = v0..v31. x8 and the Swift registers come in through @__arm_xr,
;    exactly as a lifted callee reads them.
declare i32 @__arm2x86_interp_run(i64, ptr, ptr)
@__arm2x86_interp_target = external thread_local global i64
define {ABI} @__arm2x86_interp_entry(i64 %a0, i64 %a1, i64 %a2, i64 %a3, i64 %a4, i64 %a5, i64 %a6, i64 %a7, <2 x i64> %q0, <2 x i64> %q1, <2 x i64> %q2, <2 x i64> %q3, <2 x i64> %q4, <2 x i64> %q5, <2 x i64> %q6, <2 x i64> %q7) {
entry:
  %xs = alloca [32 x i64], align 16
  %vs = alloca [32 x <2 x i64>], align 16
  store [32 x i64] zeroinitializer, ptr %xs
  store [32 x <2 x i64>] zeroinitializer, ptr %vs
  %t = load i64, ptr @__arm2x86_interp_target
  %ia0p = getelementptr [32 x i64], ptr %xs, i64 0, i64 0
  store i64 %a0, ptr %ia0p
  %iv0p = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 0
  store <2 x i64> %q0, ptr %iv0p
  %ia1p = getelementptr [32 x i64], ptr %xs, i64 0, i64 1
  store i64 %a1, ptr %ia1p
  %iv1p = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 1
  store <2 x i64> %q1, ptr %iv1p
  %ia2p = getelementptr [32 x i64], ptr %xs, i64 0, i64 2
  store i64 %a2, ptr %ia2p
  %iv2p = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 2
  store <2 x i64> %q2, ptr %iv2p
  %ia3p = getelementptr [32 x i64], ptr %xs, i64 0, i64 3
  store i64 %a3, ptr %ia3p
  %iv3p = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 3
  store <2 x i64> %q3, ptr %iv3p
  %ia4p = getelementptr [32 x i64], ptr %xs, i64 0, i64 4
  store i64 %a4, ptr %ia4p
  %iv4p = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 4
  store <2 x i64> %q4, ptr %iv4p
  %ia5p = getelementptr [32 x i64], ptr %xs, i64 0, i64 5
  store i64 %a5, ptr %ia5p
  %iv5p = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 5
  store <2 x i64> %q5, ptr %iv5p
  %ia6p = getelementptr [32 x i64], ptr %xs, i64 0, i64 6
  store i64 %a6, ptr %ia6p
  %iv6p = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 6
  store <2 x i64> %q6, ptr %iv6p
  %ia7p = getelementptr [32 x i64], ptr %xs, i64 0, i64 7
  store i64 %a7, ptr %ia7p
  %iv7p = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 7
  store <2 x i64> %q7, ptr %iv7p
  ; sp is the real guest stack pointer, published by every caller before the transfer
  %spv = load i64, ptr @__arm_sp
  %spp = getelementptr [32 x i64], ptr %xs, i64 0, i64 31
  store i64 %spv, ptr %spp
  ; x8 (sret) and the Swift registers the contract moves through @__arm_xr
  %xi8s = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 8
  %xi8 = load i64, ptr %xi8s
  %xi8d = getelementptr [32 x i64], ptr %xs, i64 0, i64 8
  store i64 %xi8, ptr %xi8d
  %xi20s = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 20
  %xi20 = load i64, ptr %xi20s
  %xi20d = getelementptr [32 x i64], ptr %xs, i64 0, i64 20
  store i64 %xi20, ptr %xi20d
  %xi21s = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 21
  %xi21 = load i64, ptr %xi21s
  %xi21d = getelementptr [32 x i64], ptr %xs, i64 0, i64 21
  store i64 %xi21, ptr %xi21d
  %xi22s = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 22
  %xi22 = load i64, ptr %xi22s
  %xi22d = getelementptr [32 x i64], ptr %xs, i64 0, i64 22
  store i64 %xi22, ptr %xi22d
  %rc = call i32 @__arm2x86_interp_run(i64 %t, ptr %xs, ptr %vs)
  %ok = icmp eq i32 %rc, 0
  br i1 %ok, label %good, label %bad
bad:
  ; the C side has already printed the reason, the instruction and the address
  call void @__arm2x86_interp_failed(i64 %t)
  unreachable
good:
  %x0p = getelementptr [32 x i64], ptr %xs, i64 0, i64 0
  %x0 = load i64, ptr %x0p
  %v0 = load <2 x i64>, ptr %vs
  ; publish what the contract says a callee returns besides x0/v0
  %xo1s = getelementptr [32 x i64], ptr %xs, i64 0, i64 1
  %xo1 = load i64, ptr %xo1s
  %xo1d = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 1
  store i64 %xo1, ptr %xo1d
  %xo2s = getelementptr [32 x i64], ptr %xs, i64 0, i64 2
  %xo2 = load i64, ptr %xo2s
  %xo2d = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 2
  store i64 %xo2, ptr %xo2d
  %xo3s = getelementptr [32 x i64], ptr %xs, i64 0, i64 3
  %xo3 = load i64, ptr %xo3s
  %xo3d = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 3
  store i64 %xo3, ptr %xo3d
  %xo21s = getelementptr [32 x i64], ptr %xs, i64 0, i64 21
  %xo21 = load i64, ptr %xo21s
  %xo21d = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 21
  store i64 %xo21, ptr %xo21d
  %vo1s = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 1
  %vo1 = load <2 x i64>, ptr %vo1s
  %vo1d = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 34
  store <2 x i64> %vo1, ptr %vo1d
  %vo2s = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 2
  %vo2 = load <2 x i64>, ptr %vo2s
  %vo2d = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 36
  store <2 x i64> %vo2, ptr %vo2d
  %vo3s = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 3
  %vo3 = load <2 x i64>, ptr %vo3s
  %vo3d = getelementptr [96 x i64], ptr @__arm_xr, i64 0, i64 38
  store <2 x i64> %vo3, ptr %vo3d
  %spo = load i64, ptr %spp
  store i64 %spo, ptr @__arm_sp
  %r1 = insertvalue {ABI} undef, i64 %x0, 0
  %r2 = insertvalue {ABI} %r1, <2 x i64> %v0, 1
  ret {ABI} %r2
}
declare void @__arm2x86_interp_failed(i64)
@__arm2x86_interp_entry_p = constant ptr @__arm2x86_interp_entry

;  rung 1 THE INTERPRETER'S NATIVE CALL. This is the whole reason the OS can do the interpreting: a
;    program being interpreted spends most of its time calling the real x86 frameworks, and C cannot make
;    this call — the proven shape is a VARIADIC `(i64, ...)` returning {i64, i64, double, double} (rax, rdx,
;    xmm0, xmm1) with 8 integers, 8 doubles and 16 stack words, exactly as __arm2x86_native_adapter above
;    does it. Taking the register file by pointer makes that same call reachable from the interpreter loop.
;  Integer arguments go through @__arm2x86_cbarg first: an argument that is a known guest function start is
;    a CALLBACK, and native code must get a native-callable trampoline for it, not an arm64 address.
define void @__arm2x86_interp_native(i64 %t, ptr %xs, ptr %vs, i64 %asp) {
entry:
  %stk = alloca [16 x i64], align 16
  call void @__arm2x86_stack_args(i64 %asp, ptr %stk)
  %ns0p = getelementptr i64, ptr %stk, i64 0
  %ns0 = load i64, ptr %ns0p
  %ns1p = getelementptr i64, ptr %stk, i64 1
  %ns1 = load i64, ptr %ns1p
  %ns2p = getelementptr i64, ptr %stk, i64 2
  %ns2 = load i64, ptr %ns2p
  %ns3p = getelementptr i64, ptr %stk, i64 3
  %ns3 = load i64, ptr %ns3p
  %ns4p = getelementptr i64, ptr %stk, i64 4
  %ns4 = load i64, ptr %ns4p
  %ns5p = getelementptr i64, ptr %stk, i64 5
  %ns5 = load i64, ptr %ns5p
  %ns6p = getelementptr i64, ptr %stk, i64 6
  %ns6 = load i64, ptr %ns6p
  %ns7p = getelementptr i64, ptr %stk, i64 7
  %ns7 = load i64, ptr %ns7p
  %ns8p = getelementptr i64, ptr %stk, i64 8
  %ns8 = load i64, ptr %ns8p
  %ns9p = getelementptr i64, ptr %stk, i64 9
  %ns9 = load i64, ptr %ns9p
  %ns10p = getelementptr i64, ptr %stk, i64 10
  %ns10 = load i64, ptr %ns10p
  %ns11p = getelementptr i64, ptr %stk, i64 11
  %ns11 = load i64, ptr %ns11p
  %ns12p = getelementptr i64, ptr %stk, i64 12
  %ns12 = load i64, ptr %ns12p
  %ns13p = getelementptr i64, ptr %stk, i64 13
  %ns13 = load i64, ptr %ns13p
  %ns14p = getelementptr i64, ptr %stk, i64 14
  %ns14 = load i64, ptr %ns14p
  %ns15p = getelementptr i64, ptr %stk, i64 15
  %ns15 = load i64, ptr %ns15p
  %f = inttoptr i64 %t to ptr
  %g0 = getelementptr [32 x i64], ptr %xs, i64 0, i64 0
  %a0v = load i64, ptr %g0
  %n0 = call i64 @__arm2x86_cbarg(i64 %a0v)
  %h0 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 0
  %q0v = load <2 x i64>, ptr %h0
  %e0 = extractelement <2 x i64> %q0v, i32 0
  %m0 = bitcast i64 %e0 to double
  %g1 = getelementptr [32 x i64], ptr %xs, i64 0, i64 1
  %a1v = load i64, ptr %g1
  %n1 = call i64 @__arm2x86_cbarg(i64 %a1v)
  %h1 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 1
  %q1v = load <2 x i64>, ptr %h1
  %e1 = extractelement <2 x i64> %q1v, i32 0
  %m1 = bitcast i64 %e1 to double
  %g2 = getelementptr [32 x i64], ptr %xs, i64 0, i64 2
  %a2v = load i64, ptr %g2
  %n2 = call i64 @__arm2x86_cbarg(i64 %a2v)
  %h2 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 2
  %q2v = load <2 x i64>, ptr %h2
  %e2 = extractelement <2 x i64> %q2v, i32 0
  %m2 = bitcast i64 %e2 to double
  %g3 = getelementptr [32 x i64], ptr %xs, i64 0, i64 3
  %a3v = load i64, ptr %g3
  %n3 = call i64 @__arm2x86_cbarg(i64 %a3v)
  %h3 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 3
  %q3v = load <2 x i64>, ptr %h3
  %e3 = extractelement <2 x i64> %q3v, i32 0
  %m3 = bitcast i64 %e3 to double
  %g4 = getelementptr [32 x i64], ptr %xs, i64 0, i64 4
  %a4v = load i64, ptr %g4
  %n4 = call i64 @__arm2x86_cbarg(i64 %a4v)
  %h4 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 4
  %q4v = load <2 x i64>, ptr %h4
  %e4 = extractelement <2 x i64> %q4v, i32 0
  %m4 = bitcast i64 %e4 to double
  %g5 = getelementptr [32 x i64], ptr %xs, i64 0, i64 5
  %a5v = load i64, ptr %g5
  %n5 = call i64 @__arm2x86_cbarg(i64 %a5v)
  %h5 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 5
  %q5v = load <2 x i64>, ptr %h5
  %e5 = extractelement <2 x i64> %q5v, i32 0
  %m5 = bitcast i64 %e5 to double
  %g6 = getelementptr [32 x i64], ptr %xs, i64 0, i64 6
  %a6v = load i64, ptr %g6
  %n6 = call i64 @__arm2x86_cbarg(i64 %a6v)
  %h6 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 6
  %q6v = load <2 x i64>, ptr %h6
  %e6 = extractelement <2 x i64> %q6v, i32 0
  %m6 = bitcast i64 %e6 to double
  %g7 = getelementptr [32 x i64], ptr %xs, i64 0, i64 7
  %a7v = load i64, ptr %g7
  %n7 = call i64 @__arm2x86_cbarg(i64 %a7v)
  %h7 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 7
  %q7v = load <2 x i64>, ptr %h7
  %e7 = extractelement <2 x i64> %q7v, i32 0
  %m7 = bitcast i64 %e7 to double
  %r = call { i64, i64, double, double } (i64, ...) %f(i64 %n0, i64 %n1, i64 %n2, i64 %n3, i64 %n4, i64 %n5, i64 %n6, i64 %n7, double %m0, double %m1, double %m2, double %m3, double %m4, double %m5, double %m6, double %m7, i64 %ns0, i64 %ns1, i64 %ns2, i64 %ns3, i64 %ns4, i64 %ns5, i64 %ns6, i64 %ns7, i64 %ns8, i64 %ns9, i64 %ns10, i64 %ns11, i64 %ns12, i64 %ns13, i64 %ns14, i64 %ns15)
  %rx0 = extractvalue { i64, i64, double, double } %r, 0
  %rx1 = extractvalue { i64, i64, double, double } %r, 1
  %rv0 = extractvalue { i64, i64, double, double } %r, 2
  %rv1 = extractvalue { i64, i64, double, double } %r, 3
  ; x0, x1 and the low lanes of v0, v1 are everything AAPCS64 returns in registers
  %o0 = getelementptr [32 x i64], ptr %xs, i64 0, i64 0
  store i64 %rx0, ptr %o0
  %o1 = getelementptr [32 x i64], ptr %xs, i64 0, i64 1
  store i64 %rx1, ptr %o1
  %rv0b = bitcast double %rv0 to i64
  %rv1b = bitcast double %rv1 to i64
  %p0 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 0
  %w0 = insertelement <2 x i64> zeroinitializer, i64 %rv0b, i32 0
  store <2 x i64> %w0, ptr %p0
  %p1 = getelementptr [32 x <2 x i64>], ptr %vs, i64 0, i64 1
  %w1 = insertelement <2 x i64> zeroinitializer, i64 %rv1b, i32 0
  store <2 x i64> %w1, ptr %p1
  ret void
}
@__arm2x86_interp_native_p = constant ptr @__arm2x86_interp_native
'''.replace('{ABI}', ABI_RET).replace('DOUBLES', '\n'.join(
    f'  %e{i} = extractelement <2 x i64> %q{i}, i32 0\n  %d{i} = bitcast i64 %e{i} to double' for i in range(8))).replace(
    'CSTACKWORDS', '\n'.join(f'  %csk{i}p = getelementptr i64, ptr %stk, i64 {i}\n  %csk{i} = load i64, ptr %csk{i}p' for i in range(16))).replace(
    'STACKWORDS', '\n'.join(f'  %sk{i}p = getelementptr i64, ptr %stk, i64 {i}\n  %sk{i} = load i64, ptr %sk{i}p' for i in range(16))).replace(
    'STACKARGS', ', '.join(f'i64 %csk{i}' for i in range(16))).replace(
    'RECSTORES', '\n'.join(
        [f'  %ri{i}p = getelementptr i64, ptr %arec, i64 {1 + i}\n  store i64 %c{i}, ptr %ri{i}p' for i in range(6)]
        + [f'  %rdb{i} = bitcast double %d{i} to i64\n  %rd{i}p = getelementptr i64, ptr %arec, i64 {7 + i}\n  store i64 %rdb{i}, ptr %rd{i}p'
           for i in range(8)]
        + ['  %rr13p = getelementptr i64, ptr %arec, i64 15\n  store i64 %ax20, ptr %rr13p',
           '  %rr14p = getelementptr i64, ptr %arec, i64 16\n  store i64 %ax22, ptr %rr14p',
           '  %rs6p = getelementptr i64, ptr %arec, i64 18\n  store i64 %c6, ptr %rs6p',
           '  %rs7p = getelementptr i64, ptr %arec, i64 19\n  store i64 %c7, ptr %rs7p',
           '  %re21p = getelementptr i64, ptr %arec, i64 36\n  store i64 %ax21, ptr %re21p']
        + [f'  %rstk{i}p = getelementptr i64, ptr %arec, i64 {20 + i}\n  store i64 %sk{i}, ptr %rstk{i}p' for i in range(16)])).replace(
    'PENDSTORES', '\n'.join(
        [f'  %pi{i}p = getelementptr i64, ptr @__arm2x86_async_pend, i64 {1 + i}\n  store i64 %c{i}, ptr %pi{i}p' for i in range(6)]
        + [f'  %pdb{i} = bitcast double %d{i} to i64\n  %pd{i}p = getelementptr i64, ptr @__arm2x86_async_pend, i64 {7 + i}\n'
           f'  store i64 %pdb{i}, ptr %pd{i}p' for i in range(8)]
        + ['  %pr13p = getelementptr i64, ptr @__arm2x86_async_pend, i64 15\n  store i64 %ax20, ptr %pr13p',
           '  %pr14p = getelementptr i64, ptr @__arm2x86_async_pend, i64 16\n  store i64 %ax22, ptr %pr14p',
           '  %ps6p = getelementptr i64, ptr @__arm2x86_async_pend, i64 18\n  store i64 %c6, ptr %ps6p',
           '  %ps7p = getelementptr i64, ptr @__arm2x86_async_pend, i64 19\n  store i64 %c7, ptr %ps7p',
           '  %pe21p = getelementptr i64, ptr @__arm2x86_async_pend, i64 36\n  store i64 %ax21, ptr %pe21p',
           '  %pvp = getelementptr i64, ptr @__arm2x86_async_pend, i64 17\n  store i64 1, ptr %pvp']
        + [f'  %pstk{i}p = getelementptr i64, ptr @__arm2x86_async_pend, i64 {20 + i}\n  store i64 %sk{i}, ptr %pstk{i}p' for i in range(16)])).replace(
    'SWIFTVEC', '\n'.join(
        f'  %sd{i} = extractvalue {{ i64, i64, i64, i64, double, double, double, double }} %sr, {4 + i}\n'
        f'  %sb{i} = bitcast double %sd{i} to i64\n  %sv{i} = insertelement <2 x i64> zeroinitializer, i64 %sb{i}, i32 0'
        + (f'\n  %sv{i}p = getelementptr i8, ptr @__arm_xr, i64 {256 + 16 * i}\n  store <2 x i64> %sv{i}, ptr %sv{i}p, align 16' if i else '')
        for i in range(4)))


def main(exe, out, jobs=None):
    #  10-20 "0.26 GB/shard, CPU-bound" was Cyberpunk. macOS 27 shards reached 27 GB (see _capped_run), so the default
    #    worker count is what memory allows: physical RAM minus 8 GB kept for everything else, over the per-shard cap.
    if not jobs:
        try:
            mem_gb = int(subprocess.run(['/usr/sbin/sysctl', '-n', 'hw.memsize'], capture_output=True, text=True,
                                        timeout=5).stdout) / 2**30
        except (OSError, ValueError, subprocess.SubprocessError):
            mem_gb = 16
        jobs = max(1, min(os.cpu_count() or 4, int((mem_gb - 8) // _gb_env('ARM2X86_SHARD_GB', 3))))
    jobs = int(jobs)
    #  x86-64-v3 = Haswell (AVX2/FMA/BMI2): SIGILL on the Mac Pro's Ivy Bridge Xeon (AVX1 only). macOS 27 system code for
    #    the Mac Pro is built with ARM2X86_CPU=ivybridge; studio (Arrow Lake) keeps the default. The cpu is in every shard hash.
    cpu = os.environ.get('ARM2X86_CPU', 'x86-64-v3')
    t_start = time.time()
    os.makedirs(out, exist_ok=True)
    exe = os.path.abspath(exe); exe_dir = os.path.dirname(exe)
    main_thin = thin_arm64(exe, os.path.join(out, 'main.arm64'))
    mm = macho(main_thin)
    #  10-10 TRANSLATING A BUNDLE OR A DYLIB, NOT A PROGRAM. macOS 27's opendirectoryd requires five OpenDirectory
    #    module bundles by hard-coded path and one of them, proxy.bundle, ships arm64e ONLY — so the daemon panics
    #    ("Required bundle at path %@ could not be loaded") until that bundle is translated too. Such an image has
    #    MH_BUNDLE/MH_DYLIB, NO LC_MAIN, and is linked at vmaddr 0; it is entered through its EXPORTS, not an entry
    #    point. It is rebased off 0 exactly like a bundle-local library, the start-up work runs from a constructor,
    #    and every export gets an x86 wrapper (see BUNDLE_BASE / the export wrappers below).
    MH_EXECUTE = 2
    bundle = mm['entryoff'] is None
    if bundle:
        if mm['filetype'] == MH_EXECUTE:
            raise SystemExit(f'{exe}: MH_EXECUTE with no LC_MAIN — refusing to guess an entry point')
        #  NOT 0x100000000: that is where a translated PROGRAM's guest image sits, and a bundle is loaded INTO such
        #    a program — two reservations at one address cannot both exist. opendirectoryd's own guest image is
        #    0x100000000..0x10007c000, so its modules go well above it. Override with ARM2X86_BUNDLE_BASE when a
        #    host maps more than 4 GB of guest or when two translated bundles must coexist.
        BUNDLE_BASE = int(os.environ.get('ARM2X86_BUNDLE_BASE', '0x200000000'), 0)
        if mm['lo'] != BUNDLE_BASE:
            reb = os.path.join(out, 'main.rebased.arm64')
            subprocess.run([sys.executable, os.path.join(S, 'rebase_macho.py'), main_thin, reb, hex(BUNDLE_BASE)], check=True)
            main_thin = reb; mm = macho(reb)
        print(f'image: filetype {mm["filetype"]} with no LC_MAIN — translating as a BUNDLE/DYLIB, '
              f'rebased to 0x{mm["lo"]:x}, entered through its exports')
    images = [{'name': os.path.basename(exe), 'kind': 'main', 'path': main_thin, 'orig': exe, 'm': mm, 'base': mm['lo'],
               'dir': os.path.join(out, 'img0'), 'id': None}]
    # --- every arm64 library the program loads from inside its own bundle, transitively ------------------------------
    todo, seen, cur = [(exe_dir, mm)], {exe}, (mm['hi'] + 0xFFFFFF) & ~0xFFFFFF
    libdir = os.path.join(out, 'MacOS-arm2x86'); os.makedirs(libdir, exist_ok=True)
    while todo:
        ldir, m0 = todo.pop(0)
        for dep in m0['deps']:
            #  10-03 THE PROGRAM'S C++ RUNTIME IS TRANSLATED WITH IT. Apple's arm64 libc++ lays std::string out as
            #    {data, size, cap|bit63} / {chars..., size byte 23}; x86-64's as {cap|1, size, data} / {size*2, chars...}
            #    (measured on the M4 vs Rosetta). Every string, stream and path crossing into the NATIVE libc++ was misread
            #    (ehmx: "\"multiplayer.ini//"). The arm64 libc++ (vendor/, LLVM 22.1.8, the same alternate layout, exports all
            #    230 non-abi libc++ symbols Cyberpunk imports) stands in for /usr/lib/libc++.1.dylib.  libc++abi and
            #    libunwind stay NATIVE: the exception runtime is the native unwinder's (eh.py), and their ABI is plain C or
            #    layout-identical (std::exception = vptr; the 76 abi symbols the game imports via libc++ resolve there).
            if dep in SUBST: p = SUBST[dep]
            elif re.search(r'/lib(c\+\+abi|unwind)[.\d]*\.dylib$', dep): continue
            else: p = resolve_dep(dep, ldir, exe_dir, m0['rpaths'] + mm['rpaths'])
            if not p or p in seen or not os.path.exists(p): continue
            seen.add(p)
            if not set(sh('lipo', '-archs', p).split()) & {'arm64', 'arm64e'}: continue
            name = os.path.basename(p)
            thin = thin_arm64(p, os.path.join(libdir, name + '.thin'))
            lm0 = macho(thin); base = cur
            reb = os.path.join(libdir, name + '.arm64')
            subprocess.run([sys.executable, os.path.join(S, 'rebase_macho.py'), thin, reb, hex(base)], check=True)
            lm = macho(reb); cur = (lm['hi'] + 0xFFFFFF) & ~0xFFFFFF
            images.append({'name': name, 'kind': 'lib', 'path': reb, 'orig': p, 'm': lm, 'base': base,
                           'slide': 0,   #  10-03: rebase_macho.py now slides a CLASSIC image's rebase pointers itself
                           'dir': os.path.join(out, f'img{len(images)}'), 'id': lm0['id']})
            todo.append((os.path.dirname(p), lm0))
    hi_all = cur
    print('images: ' + ', '.join(f"{i['name']} @0x{i['base']:x}" for i in images) + f'; address space 0x{mm["lo"]:x}..0x{hi_all:x}')
    t = time.time()
    for img in images: analyze(img)
    print(f'analysed {sum(i["nfn"] for i in images)} functions in {time.time() - t:.0f} s')
    commpage_gate(images)
    # --- resolve binds: internal (another translated image / weak-def-coalesce) or native -------------------------------
    leaf = {os.path.splitext(os.path.basename(img['id'] or img['name']))[0]: img for img in images if img['kind'] == 'lib'}
    #  10-03 dyld_info names a bind's library by its leaf WITHOUT the version (`libc++` for libc++.1.dylib)
    leaf.update({re.sub(r'(\.\d+)+$', '', k): v for k, v in list(leaf.items())})
    order = images   # dyld's coalescing order: the program, then its libraries in load order
    recs, slot_sym, slot_add, missing = [], {}, {}, []
    for img in images:
        recs += img['rebases']
        for a, lib, sym, add in img['binds']:
            tgt = None
            if lib == '<weak-def-coalesce>':
                tgt = next((o['exports'][sym] for o in order if sym in o['exports']), None)
            elif lib in leaf:
                tgt = leaf[lib]['exports'].get(sym)
                if tgt is None: missing.append(f'{lib}/{sym}')
            if tgt is not None:
                recs.append((a, tgt + add))
                #  a later weak bind that resolves INSIDE the program (its own operator new) overrides an earlier by-name
                #    native bind of the same slot — exactly dyld's coalescing.  WAS: the name stayed, and the host filled the
                #    slot with libc++'s operator new after the fixups ran.
                slot_sym.pop(a, None); slot_add.pop(a, None)
            else:
                slot_sym[a] = sym; slot_add[a] = add; recs.append((a, 0))
    known = set()
    for img in images:
        for _, ls in img['fsegs']: known.add(int(re.match(r'^\s*([0-9a-f]+):', ls[0]).group(1), 16))
    internal_by_slot = {a: v for a, v in recs if v}
    # --- C++ exceptions: name every personality and caught type now that every GOT slot is resolved ---------------------
    #  10-03 a NATIVE type_info (libc++abi's int, std::exception, ...) is named by its symbol, so the x86 LSDA points at
    #    the same object dlsym put in the arm64 GOT slot. A type the PROGRAM defines lives in the mapped arm64 data at a
    #    fixed address and gets an absolute symbol there (module asm in the global module): one object, one address, both sides.
    eh_abs, EHF, eh_bad = set(), {}, []
    def eh_ti(v, ind):
        if v is None: return None
        if ind:
            if v in slot_sym:
                if slot_add.get(v): raise SystemExit(f'type_info GOT slot 0x{v:x} has an addend')
                s = slot_sym[v]; return s[1:] if s.startswith('_') else s
            v = internal_by_slot.get(v) or next((t for a, t in img_rebases_all if a == v), None)
            if not v: raise SystemExit('a type_info GOT slot resolves to nothing')
        eh_abs.add(v); return f'__arm2x86_ti_{v:x}'
    img_rebases_all = [r for img in images for r in img['rebases']]
    # --- non-unique RTTI ------------------------------------------------------------------------------------------------
    #  10-03 (ehmx: LibError thrown in the library, caught in the program -> std::terminate): Apple's arm64 RTTI sets BIT 63
    #    of a type_info's name pointer when each image keeps its OWN copy of the type ("non-unique": arm64 libc++abi compares
    #    those by STRING). x86 libc++abi compares name POINTERS, so two copies never matched, and native name() handed strlen
    #    a non-canonical address. Every same-named copy now points at ONE canonical string with the bit cleared: equal
    #    pointers satisfy both runtimes' rules, and the string is a plain pointer again. A type_info is found by its vptr:
    #    a slot bound to one of libc++abi's __cxxabiv1 vtables; the name pointer is the next word.
    fhs = {}
    def cstr(a):
        for img_ in images:
            for _, vm, _, foff, fsz in img_['m']['segs']:
                if fsz and vm <= a < vm + fsz:
                    fh = fhs.get(img_['path']) or fhs.setdefault(img_['path'], open(img_['path'], 'rb'))
                    fh.seek(foff + a - vm); return fh.read(4096).split(b'\0')[0]
        return None
    name_at = {a + 8 for a, s in slot_sym.items() if s.startswith('__ZTVN10__cxxabiv1')}
    canon, nfix = {}, 0
    for i_, (a, v) in enumerate(recs):
        if a in name_at and v >> 63:
            s_ = cstr(v & ~(1 << 63))
            if not s_: raise SystemExit(f'type_info name at 0x{a:x} -> 0x{v:x} reads nothing')
            recs[i_] = (a, canon.setdefault(s_, v & ~(1 << 63))); nfix += 1
    for fh in fhs.values(): fh.close()
    print(f'rtti: {len(name_at)} type_info objects, {nfix} non-unique names -> {len(canon)} canonical strings (bit 63 cleared)')
    for img in images:
        for f, (pslot, sites) in img['eh'].items():
            if not any(lp for _, _, lp, _ in sites): continue
            ps = slot_sym.get(pslot)
            #  10-19 macOS 27's Finder has ONE function (0x100781e40) whose personality is
            #    `__swift_exceptionPersonality`, and this gate's two hardcoded names stopped the whole
            #    translation. MEASURED on a real arm64 Mac running the SAME build as the target (27.0 /
            #    26A5425a), with dlopen+dlsym: /usr/lib/swift/libswiftCore.dylib AND the global namespace both
            #    export it (dlsym name `_swift_exceptionPersonality`, i.e. Mach-O `__swift_exceptionPersonality`),
            #    exactly as they export __gxx_personality_v0. So the native runtime DOES have it and the
            #    landing pads can bind to it like the other two; `pers` below strips one underscore to the C
            #    name, which is the name dlsym found.
            #     Still a gate, not a free pass: a personality the runtime does NOT export must keep failing
            #    here rather than bind to something invented.
            if ps not in ('___gxx_personality_v0', '___objc_personality_v0', '__swift_exceptionPersonality'):
                raise SystemExit(f'function 0x{f:x}: personality {ps!r} is not one the native runtime has')
            ss = []
            for st, en, lp, ch in sites:
                cl = tuple((flt, (tuple(eh_ti(x, ind) for x in v) if flt < 0 else eh_ti(v, ind) if flt > 0 else None))
                           for flt, v, ind in ch)
                ss.append((st, en, lp, cl))
            EHF[f] = {'pers': ps[1:], 'sites': ss}
    dw = sum(img['m'].get('eh_dwarf', 0) for img in images)
    print(f'eh: {len(EHF)} functions with landing pads, {sum(len(v["sites"]) for v in EHF.values())} call sites, '
          f'{len(eh_abs)} program-defined types; {dw} DWARF-unwind functions with a personality (LSDA in __eh_frame: NOT read)')
    stub_slot, objc_sel, aliases = {}, {}, {}
    for img in images:
        stub_slot.update(img['stub_slot']); objc_sel.update(img['objc_stub_sel'])
    for stub, slot in stub_slot.items():
        v = internal_by_slot.get(slot)
        if v and v in known: aliases[stub] = v
    native_stub_slot = {s: sl for s, sl in stub_slot.items() if s not in aliases}
    sig = json.load(open(os.path.join(S, 'sigdb.json')))
    binds, thunks, unbound = xlat.make_binds(native_stub_slot, slot_sym, objc_sel, sig)
    #  libc++ functions whose RETURN the adapter cannot carry (sret / two-register): exact full-register handlers
    CXX = {'_SLSDisplayGetTiming': '__arm2x86_sls_display_get_timing',   #  10-21 struct returned through x8 (cxx_bridge.cpp)
           '__ZNKSt3__115basic_stringbufIcNS_11char_traitsIcEENS_9allocatorIcEEE3strEv': '__arm2x86_cxx_stringbuf_str',
           '__ZNKSt3__18ios_base6getlocEv': '__arm2x86_cxx_ios_getloc',
           '__ZNKSt3__14__fs10filesystem4path13__parent_pathEv': '__arm2x86_cxx_path_parent_path',
           '__ZNKSt3__14__fs10filesystem4path6__stemEv': '__arm2x86_cxx_path_stem',
           '__ZNSt3__19to_stringEj': '__arm2x86_cxx_to_string_u',
           '_CFStringGetBytes': '__arm2x86_abi_CFStringGetBytes', '_CGDisplayBounds': '__arm2x86_abi_CGDisplayBounds',
           '_SLSTransactionSetWindowTransform3D': '__arm2x86_abi_sls_SLSTransactionSetWindowTransform3D',
           '_SLSTransactionSetWindowTransform': '__arm2x86_abi_sls_SLSTransactionSetWindowTransform',
           '_SLSTransactionSetWindowLockedBounds': '__arm2x86_abi_sls_SLSTransactionSetWindowLockedBounds',
           '_SLSTransactionSetWindowLockedBoundsAtPlace': '__arm2x86_abi_sls_SLSTransactionSetWindowLockedBoundsAtPlace',
           '_SLSTransactionSetSpaceTransform': '__arm2x86_abi_sls_SLSTransactionSetSpaceTransform',
           '_SLSSetDockRectWithOrientation': '__arm2x86_abi_spi_SLSSetDockRectWithOrientation',
           '_CGRegionCreateWithRect': '__arm2x86_abi_spi_CGRegionCreateWithRect',
           '_BSStringFromCGRect': '__arm2x86_abi_spi_BSStringFromCGRect',
           '_CA_CGPointApplyTransform': '__arm2x86_abi_spi_CA_CGPointApplyTransform',
           '_CAColorMatrixConcat': '__arm2x86_abi_spi_CAColorMatrixConcat',
           '_TCCAccessPreflightWithAuditToken': '__arm2x86_abi_spi_TCCAccessPreflightWithAuditToken',
           '_sandbox_container_path_for_audit_token': '__arm2x86_abi_spi_sandbox_container_path_for_audit_token',
           '_sandbox_extension_issue_file_to_process': '__arm2x86_abi_spi_sandbox_extension_issue_file_to_process',
           '_RBImageSimpleTransform': '__arm2x86_abi_spi_RBImageSimpleTransform',
           '_UIEdgeInsetsReplace': '__arm2x86_abi_spi_UIEdgeInsetsReplace',
           '_UIEdgeInsetsAdd': '__arm2x86_abi_spi_UIEdgeInsetsAdd',
           '_AXFGeometryCenterOfRect': '__arm2x86_abi_spi_AXFGeometryCenterOfRect',
           '_AXFGeometryIsValidRect': '__arm2x86_abi_spi_AXFGeometryIsValidRect',
           '_AXFGeometryDistanceBetweenRects': '__arm2x86_abi_spi_AXFGeometryDistanceBetweenRects',
           '_AXFGeometryNormalizePointRelativeToRect': '__arm2x86_abi_spi_AXFGeometryNormalizePointRelativeToRect',
           '_AXFGeometryShiftPointFullyWithinContainerRect': '__arm2x86_abi_spi_AXFGeometryShiftPointFullyWithinContainerRect',
           '_AXFGeometryShiftRectFullyWithinContainerRect': '__arm2x86_abi_spi_AXFGeometryShiftRectFullyWithinContainerRect',
           '_AXFGeometryIsRectVerticallyAlignedWithRectWithThreshold': '__arm2x86_abi_spi_AXFGeometryIsRectVerticallyAlignedWithRectWithThreshold',
           # MapKit / CoreLocation / CAFrameRateRange by-value structs (interp/abi_spi.c)
           '_MKCoordinateRegionMakeWithDistance': '__arm2x86_abi_spi_MKCoordinateRegionMakeWithDistance',
           '_MKCoordinateRegionForMapRect': '__arm2x86_abi_spi_MKCoordinateRegionForMapRect',
           '_MKMapRectUnion': '__arm2x86_abi_spi_MKMapRectUnion',
           '_MKMapRectInset': '__arm2x86_abi_spi_MKMapRectInset',
           '_MKMapRectOffset': '__arm2x86_abi_spi_MKMapRectOffset',
           '_MKMapRectContainsPoint': '__arm2x86_abi_spi_MKMapRectContainsPoint',
           '_MKMapRectContainsRect': '__arm2x86_abi_spi_MKMapRectContainsRect',
           '_MKMapRectIntersectsRect': '__arm2x86_abi_spi_MKMapRectIntersectsRect',
           '_MKCoordinateForMapPoint': '__arm2x86_abi_spi_MKCoordinateForMapPoint',
           '_MKMapPointForCoordinate': '__arm2x86_abi_spi_MKMapPointForCoordinate',
           '_MKMetersBetweenMapPoints': '__arm2x86_abi_spi_MKMetersBetweenMapPoints',
           '_CLLocationCoordinate2DIsValid': '__arm2x86_abi_spi_CLLocationCoordinate2DIsValid',
           '_CLLocationCoordinate2DMake': '__arm2x86_abi_spi_CLLocationCoordinate2DMake',
           '__MKMapRectThatFits': '__arm2x86_abi_spi__MKMapRectThatFits',
           '_CAFrameRateRangeIsEqualToRange': '__arm2x86_abi_spi_CAFrameRateRangeIsEqualToRange',
           '_MKDefaultCoordinateRegion': '__arm2x86_abi_spi_MKDefaultCoordinateRegion',
           '_MKMapRectForCoordinateRegion': '__arm2x86_abi_spi_MKMapRectForCoordinateRegion',
           '_MKMapRectMakeWithRadialDistance': '__arm2x86_abi_spi_MKMapRectMakeWithRadialDistance',
           '_MKMapRectBoundingMapPoints': '__arm2x86_abi_spi_MKMapRectBoundingMapPoints',   #  10-03
           '_NSPointInRect': '__arm2x86_abi_NSPointInRect', '_CAFrameRateRangeMake': '__arm2x86_abi_CAFrameRateRangeMake',
           #  10-20 SkyLight iterator getters return a CGRect by value and are SPI sigdb cannot see (see objc_bridge.c)
           #  10-20 the CGRect family takes/returns the rectangle BY VALUE (v0-v3 on arm64, the stack on
           #    x86): sigdb types the argument 'x' and the generic adapter passed scalars only (objc_bridge.c)
           '_CGRectGetWidth': '__arm2x86_abi_CGRectGetWidth',
           '_CGRectGetHeight': '__arm2x86_abi_CGRectGetHeight',
           '_CGRectGetMinX': '__arm2x86_abi_CGRectGetMinX',
           '_CGRectGetMinY': '__arm2x86_abi_CGRectGetMinY',
           '_CGRectGetMaxX': '__arm2x86_abi_CGRectGetMaxX',
           '_CGRectGetMaxY': '__arm2x86_abi_CGRectGetMaxY',
           '_CGRectGetMidX': '__arm2x86_abi_CGRectGetMidX',
           '_CGRectGetMidY': '__arm2x86_abi_CGRectGetMidY',
           '_CGRectIsEmpty': '__arm2x86_abi_CGRectIsEmpty',
           '_CGRectIsNull': '__arm2x86_abi_CGRectIsNull',
           '_CGRectIsInfinite': '__arm2x86_abi_CGRectIsInfinite',
           '_CGRectContainsRect': '__arm2x86_abi_CGRectContainsRect',
           '_CGRectIntersectsRect': '__arm2x86_abi_CGRectIntersectsRect',
           '_CGRectIntersection': '__arm2x86_abi_CGRectIntersection',
           '_CGRectUnion': '__arm2x86_abi_CGRectUnion',
           '_CGRectInset': '__arm2x86_abi_CGRectInset',
           '_CGRectOffset': '__arm2x86_abi_CGRectOffset',
           '_CGRectIntegral': '__arm2x86_abi_CGRectIntegral',
           '_CGRectContainsPoint': '__arm2x86_abi_CGRectContainsPoint',
           '_CGContextFillRect': '__arm2x86_abi_CGContextFillRect',
           '_CGContextClearRect': '__arm2x86_abi_CGContextClearRect',
           '_CGContextClipToRect': '__arm2x86_abi_CGContextClipToRect',
           '_CGContextDrawImage': '__arm2x86_abi_CGContextDrawImage',
           '_CGEventGetLocation': '__arm2x86_abi_CGEventGetLocation',
           '_CGEventSetLocation': '__arm2x86_abi_CGEventSetLocation',
           '_CGGetDisplaysWithRect': '__arm2x86_abi_CGGetDisplaysWithRect',
           '_CGGetDisplaysWithPoint': '__arm2x86_abi_CGGetDisplaysWithPoint',
           #  10-20 swift_once takes a TRANSLATED function pointer and is not in sigdb (objc_bridge.c)
           '_swift_once': '__arm2x86_abi_swift_once',
           #  10-20 GENERATED by-value struct handlers (ops/abigen/abi_gen.py)
           '_CATransform3DConcat': '__arm2x86_abi_gen_CATransform3DConcat',
           '_CATransform3DEqualToTransform': '__arm2x86_abi_gen_CATransform3DEqualToTransform',
           '_CATransform3DGetAffineTransform': '__arm2x86_abi_gen_CATransform3DGetAffineTransform',
           '_CATransform3DIsAffine': '__arm2x86_abi_gen_CATransform3DIsAffine',
           '_CATransform3DMakeRotation': '__arm2x86_abi_gen_CATransform3DMakeRotation',
           '_CATransform3DMakeScale': '__arm2x86_abi_gen_CATransform3DMakeScale',
           '_CATransform3DMakeTranslation': '__arm2x86_abi_gen_CATransform3DMakeTranslation',
           '_CATransform3DScale': '__arm2x86_abi_gen_CATransform3DScale',
           '_CATransform3DTranslate': '__arm2x86_abi_gen_CATransform3DTranslate',
           '_CFArrayAppendArray': '__arm2x86_abi_gen_CFArrayAppendArray',
           '_CFArrayApplyFunction': '__arm2x86_abi_gen_CFArrayApplyFunction',
           '_CFArrayContainsValue': '__arm2x86_abi_gen_CFArrayContainsValue',
           '_CFDataGetBytes': '__arm2x86_abi_gen_CFDataGetBytes',
           '_CFStringCompareWithOptions': '__arm2x86_abi_gen_CFStringCompareWithOptions',
           '_CFStringCompareWithOptionsAndLocale': '__arm2x86_abi_gen_CFStringCompareWithOptionsAndLocale',
           '_CFStringCreateWithSubstring': '__arm2x86_abi_gen_CFStringCreateWithSubstring',
           '_CFStringFindAndReplace': '__arm2x86_abi_gen_CFStringFindAndReplace',
           '_CFStringFindWithOptions': '__arm2x86_abi_gen_CFStringFindWithOptions',
           '_CFStringGetCharacters': '__arm2x86_abi_gen_CFStringGetCharacters',
           '_CFStringReplace': '__arm2x86_abi_gen_CFStringReplace',
           '_CFStringTokenizerCopyBestStringLanguage': '__arm2x86_abi_gen_CFStringTokenizerCopyBestStringLanguage',
           '_CFWriteStreamGetError': '__arm2x86_abi_gen_CFWriteStreamGetError',
           '_CGAffineTransformConcat': '__arm2x86_abi_gen_CGAffineTransformConcat',
           '_CGAffineTransformInvert': '__arm2x86_abi_gen_CGAffineTransformInvert',
           '_CGAffineTransformIsIdentity': '__arm2x86_abi_gen_CGAffineTransformIsIdentity',
           '_CGAffineTransformMakeRotation': '__arm2x86_abi_gen_CGAffineTransformMakeRotation',
           '_CGAffineTransformMakeScale': '__arm2x86_abi_gen_CGAffineTransformMakeScale',
           '_CGAffineTransformMakeTranslation': '__arm2x86_abi_gen_CGAffineTransformMakeTranslation',
           '_CGAffineTransformScale': '__arm2x86_abi_gen_CGAffineTransformScale',
           '_CGAffineTransformTranslate': '__arm2x86_abi_gen_CGAffineTransformTranslate',
           '_CGContextConcatCTM': '__arm2x86_abi_gen_CGContextConcatCTM',
           '_CGContextGetCTM': '__arm2x86_abi_gen_CGContextGetCTM',
           '_CGContextSetShadowWithColor': '__arm2x86_abi_gen_CGContextSetShadowWithColor',
           '_CGDisplayCreateImageForRect': '__arm2x86_abi_gen_CGDisplayCreateImageForRect',
           '_CGEventCreateMouseEvent': '__arm2x86_abi_gen_CGEventCreateMouseEvent',
           '_CGImageCreateWithImageInRect': '__arm2x86_abi_gen_CGImageCreateWithImageInRect',
           '_CGPDFPageGetBoxRect': '__arm2x86_abi_gen_CGPDFPageGetBoxRect',
           '_CGPDFPageGetDrawingTransform': '__arm2x86_abi_gen_CGPDFPageGetDrawingTransform',
           '_CGPathCreateWithRect': '__arm2x86_abi_gen_CGPathCreateWithRect',
           '_CGPathGetBoundingBox': '__arm2x86_abi_gen_CGPathGetBoundingBox',
           '_CGPointApplyAffineTransform': '__arm2x86_abi_gen_CGPointApplyAffineTransform',
           '_CGPointCreateDictionaryRepresentation': '__arm2x86_abi_gen_CGPointCreateDictionaryRepresentation',
           '_CGPointEqualToPoint': '__arm2x86_abi_gen_CGPointEqualToPoint',
           '_CGRectApplyAffineTransform': '__arm2x86_abi_gen_CGRectApplyAffineTransform',
           '_CGRectStandardize': '__arm2x86_abi_gen_CGRectStandardize',
           '_CGSizeCreateDictionaryRepresentation': '__arm2x86_abi_gen_CGSizeCreateDictionaryRepresentation',
           '_CGWindowListCreateImage': '__arm2x86_abi_gen_CGWindowListCreateImage',
           '_CTFontGetBoundingBox': '__arm2x86_abi_gen_CTFontGetBoundingBox',
           '_CTFramesetterSuggestFrameSizeWithConstraints': '__arm2x86_abi_gen_CTFramesetterSuggestFrameSizeWithConstraints',
           '_NSAccessibilityFrameInView': '__arm2x86_abi_gen_NSAccessibilityFrameInView',
           '_NSContainsRect': '__arm2x86_abi_gen_NSContainsRect',
           '_NSDrawThreePartImage': '__arm2x86_abi_gen_NSDrawThreePartImage',
           '_NSEdgeInsetsEqual': '__arm2x86_abi_gen_NSEdgeInsetsEqual',
           '__LSVersionNumberGetMajorComponent': '__arm2x86_abi_gen__LSVersionNumberGetMajorComponent',
           '__LSVersionNumberGetMinorComponent': '__arm2x86_abi_gen__LSVersionNumberGetMinorComponent',
           '__LSVersionNumberGetBugFixComponent': '__arm2x86_abi_gen__LSVersionNumberGetBugFixComponent',
           '__LSVersionNumberHash': '__arm2x86_abi_gen__LSVersionNumberHash',
           '__LSVersionNumberCompare': '__arm2x86_abi_gen__LSVersionNumberCompare',
           '__LSVersionNumberGetDYLDVersion': '__arm2x86_abi_gen__LSVersionNumberGetDYLDVersion',
           '__LSGetVersionFromString': '__arm2x86_abi_gen__LSGetVersionFromString',
           '__LSVersionNumberMakeWithString': '__arm2x86_abi_gen__LSVersionNumberMakeWithString',
           '_NSEnumerateHashTable': '__arm2x86_abi_gen_NSEnumerateHashTable',
           '_NSEnumerateMapTable': '__arm2x86_abi_gen_NSEnumerateMapTable',
           '_NSEqualPoints': '__arm2x86_abi_gen_NSEqualPoints',
           '_NSEqualRects': '__arm2x86_abi_gen_NSEqualRects',
           '_NSEqualSizes': '__arm2x86_abi_gen_NSEqualSizes',
           '_NSInsetRect': '__arm2x86_abi_gen_NSInsetRect',
           #  10-26 199 MORE GENERATED ABI HANDLERS, routed so the untyped adapter never sees them.
           #    ops/abigen/abi_gen.py emits a handler for every sigdb entry marked 'x' (untypeable by the
           #    generic path) from the AAPCS64-vs-SysV rules, and each one calls through a REAL C prototype
           #    so clang lays out the x86 side - a MEMORY argument on the stack, a hidden sret in rdi -
           #    instead of us building an ffi_type tree and hoping libffi agrees.
           #  ONLY names the generated file actually DEFINES, and never a key already in this dict: a
           #    duplicate key in a dict literal silently WINS, and 113 of these symbols already have a
           #    HAND-WRITTEN handler (CGRectGetWidth, CGRectInset, the CGContext family, CFUUID*) that is
           #    tuned and must keep winning. Regenerate with the FULL 1766-name want-list, never a subset:
           #    abi_gen.py prints only the want-list's handlers, so a short list would DROP the handlers
           #    that already exist while rf_table.h still declares them, and the host would not link.
           '_CATransform3DInvert': '__arm2x86_abi_gen_CATransform3DInvert',
           '_CATransform3DIsIdentity': '__arm2x86_abi_gen_CATransform3DIsIdentity',
           '_CATransform3DMakeAffineTransform': '__arm2x86_abi_gen_CATransform3DMakeAffineTransform',
           '_CATransform3DRotate': '__arm2x86_abi_gen_CATransform3DRotate',
           '_CFArrayBSearchValues': '__arm2x86_abi_gen_CFArrayBSearchValues',
           '_CFArrayGetCountOfValue': '__arm2x86_abi_gen_CFArrayGetCountOfValue',
           '_CFArrayGetFirstIndexOfValue': '__arm2x86_abi_gen_CFArrayGetFirstIndexOfValue',
           '_CFArrayGetLastIndexOfValue': '__arm2x86_abi_gen_CFArrayGetLastIndexOfValue',
           '_CFArrayGetValues': '__arm2x86_abi_gen_CFArrayGetValues',
           '_CFArrayReplaceValues': '__arm2x86_abi_gen_CFArrayReplaceValues',
           '_CFArraySortValues': '__arm2x86_abi_gen_CFArraySortValues',
           '_CFAttributedStringCreateWithSubstring': '__arm2x86_abi_gen_CFAttributedStringCreateWithSubstring',
           '_CFAttributedStringGetAttributeAndLongestEffectiveRange': '__arm2x86_abi_gen_CFAttributedStringGetAttributeAndLongestEffectiveRange',
           '_CFAttributedStringGetAttributesAndLongestEffectiveRange': '__arm2x86_abi_gen_CFAttributedStringGetAttributesAndLongestEffectiveRange',
           '_CFAttributedStringGetBidiLevelsAndResolvedDirections': '__arm2x86_abi_gen_CFAttributedStringGetBidiLevelsAndResolvedDirections',
           '_CFAttributedStringGetStatisticalWritingDirections': '__arm2x86_abi_gen_CFAttributedStringGetStatisticalWritingDirections',
           '_CFAttributedStringRemoveAttribute': '__arm2x86_abi_gen_CFAttributedStringRemoveAttribute',
           '_CFAttributedStringReplaceAttributedString': '__arm2x86_abi_gen_CFAttributedStringReplaceAttributedString',
           '_CFAttributedStringReplaceString': '__arm2x86_abi_gen_CFAttributedStringReplaceString',
           '_CFAttributedStringSetAttribute': '__arm2x86_abi_gen_CFAttributedStringSetAttribute',
           '_CFAttributedStringSetAttributes': '__arm2x86_abi_gen_CFAttributedStringSetAttributes',
           '_CFBitVectorContainsBit': '__arm2x86_abi_gen_CFBitVectorContainsBit',
           '_CFBitVectorFlipBits': '__arm2x86_abi_gen_CFBitVectorFlipBits',
           '_CFBitVectorGetBits': '__arm2x86_abi_gen_CFBitVectorGetBits',
           '_CFBitVectorGetCountOfBit': '__arm2x86_abi_gen_CFBitVectorGetCountOfBit',
           '_CFBitVectorGetFirstIndexOfBit': '__arm2x86_abi_gen_CFBitVectorGetFirstIndexOfBit',
           '_CFBitVectorGetLastIndexOfBit': '__arm2x86_abi_gen_CFBitVectorGetLastIndexOfBit',
           '_CFBitVectorSetBits': '__arm2x86_abi_gen_CFBitVectorSetBits',
           '_CFCalendarGetMaximumRangeOfUnit': '__arm2x86_abi_gen_CFCalendarGetMaximumRangeOfUnit',
           '_CFCalendarGetMinimumRangeOfUnit': '__arm2x86_abi_gen_CFCalendarGetMinimumRangeOfUnit',
           '_CFCalendarGetRangeOfUnit': '__arm2x86_abi_gen_CFCalendarGetRangeOfUnit',
           '_CFCharacterSetAddCharactersInRange': '__arm2x86_abi_gen_CFCharacterSetAddCharactersInRange',
           '_CFCharacterSetCreateWithCharactersInRange': '__arm2x86_abi_gen_CFCharacterSetCreateWithCharactersInRange',
           '_CFCharacterSetRemoveCharactersInRange': '__arm2x86_abi_gen_CFCharacterSetRemoveCharactersInRange',
           '_CFDataDeleteBytes': '__arm2x86_abi_gen_CFDataDeleteBytes',
           '_CFDataFind': '__arm2x86_abi_gen_CFDataFind',
           '_CFDataReplaceBytes': '__arm2x86_abi_gen_CFDataReplaceBytes',
           '_CFReadStreamGetError': '__arm2x86_abi_gen_CFReadStreamGetError',
           '_CFStringCreateArrayWithFindResults': '__arm2x86_abi_gen_CFStringCreateArrayWithFindResults',
           '_CFStringDelete': '__arm2x86_abi_gen_CFStringDelete',
           '_CFStringFind': '__arm2x86_abi_gen_CFStringFind',
           '_CFStringFindCharacterFromSet': '__arm2x86_abi_gen_CFStringFindCharacterFromSet',
           '_CFStringFindWithOptionsAndLocale': '__arm2x86_abi_gen_CFStringFindWithOptionsAndLocale',
           '_CFStringGetHyphenationLocationBeforeIndex': '__arm2x86_abi_gen_CFStringGetHyphenationLocationBeforeIndex',
           '_CFStringGetLineBounds': '__arm2x86_abi_gen_CFStringGetLineBounds',
           '_CFStringGetParagraphBounds': '__arm2x86_abi_gen_CFStringGetParagraphBounds',
           '_CFStringGetRangeOfComposedCharactersAtIndex': '__arm2x86_abi_gen_CFStringGetRangeOfComposedCharactersAtIndex',
           '_CFStringTokenizerCreate': '__arm2x86_abi_gen_CFStringTokenizerCreate',
           '_CFStringTokenizerGetCurrentTokenRange': '__arm2x86_abi_gen_CFStringTokenizerGetCurrentTokenRange',
           '_CFStringTokenizerSetString': '__arm2x86_abi_gen_CFStringTokenizerSetString',
           '_CFURLGetByteRangeForComponent': '__arm2x86_abi_gen_CFURLGetByteRangeForComponent',
           '_CGAffineTransformMake': '__arm2x86_abi_gen_CGAffineTransformMake',
           '_CGAffineTransformRotate': '__arm2x86_abi_gen_CGAffineTransformRotate',
           '_CGContextAddEllipseInRect': '__arm2x86_abi_gen_CGContextAddEllipseInRect',
           '_CGContextAddRect': '__arm2x86_abi_gen_CGContextAddRect',
           '_CGContextBeginTransparencyLayerWithRect': '__arm2x86_abi_gen_CGContextBeginTransparencyLayerWithRect',
           '_CGContextClipToMask': '__arm2x86_abi_gen_CGContextClipToMask',
           '_CGContextConvertPointToDeviceSpace': '__arm2x86_abi_gen_CGContextConvertPointToDeviceSpace',
           '_CGContextConvertPointToUserSpace': '__arm2x86_abi_gen_CGContextConvertPointToUserSpace',
           '_CGContextConvertRectToDeviceSpace': '__arm2x86_abi_gen_CGContextConvertRectToDeviceSpace',
           '_CGContextConvertRectToUserSpace': '__arm2x86_abi_gen_CGContextConvertRectToUserSpace',
           '_CGContextConvertSizeToDeviceSpace': '__arm2x86_abi_gen_CGContextConvertSizeToDeviceSpace',
           '_CGContextConvertSizeToUserSpace': '__arm2x86_abi_gen_CGContextConvertSizeToUserSpace',
           '_CGContextDrawConicGradient': '__arm2x86_abi_gen_CGContextDrawConicGradient',
           '_CGContextDrawImageApplyingToneMapping': '__arm2x86_abi_gen_CGContextDrawImageApplyingToneMapping',
           '_CGContextDrawLayerAtPoint': '__arm2x86_abi_gen_CGContextDrawLayerAtPoint',
           '_CGContextDrawLayerInRect': '__arm2x86_abi_gen_CGContextDrawLayerInRect',
           '_CGContextDrawLinearGradient': '__arm2x86_abi_gen_CGContextDrawLinearGradient',
           '_CGContextDrawPDFDocument': '__arm2x86_abi_gen_CGContextDrawPDFDocument',
           '_CGContextDrawRadialGradient': '__arm2x86_abi_gen_CGContextDrawRadialGradient',
           '_CGContextDrawTiledImage': '__arm2x86_abi_gen_CGContextDrawTiledImage',
           '_CGContextFillEllipseInRect': '__arm2x86_abi_gen_CGContextFillEllipseInRect',
           '_CGContextGetClipBoundingBox': '__arm2x86_abi_gen_CGContextGetClipBoundingBox',
           '_CGContextGetPathBoundingBox': '__arm2x86_abi_gen_CGContextGetPathBoundingBox',
           '_CGContextGetPathCurrentPoint': '__arm2x86_abi_gen_CGContextGetPathCurrentPoint',
           '_CGContextGetTextMatrix': '__arm2x86_abi_gen_CGContextGetTextMatrix',
           '_CGContextGetTextPosition': '__arm2x86_abi_gen_CGContextGetTextPosition',
           '_CGContextGetUserSpaceToDeviceSpaceTransform': '__arm2x86_abi_gen_CGContextGetUserSpaceToDeviceSpaceTransform',
           '_CGContextPathContainsPoint': '__arm2x86_abi_gen_CGContextPathContainsPoint',
           '_CGContextSetPatternPhase': '__arm2x86_abi_gen_CGContextSetPatternPhase',
           '_CGContextSetShadow': '__arm2x86_abi_gen_CGContextSetShadow',
           '_CGContextSetTextMatrix': '__arm2x86_abi_gen_CGContextSetTextMatrix',
           '_CGContextStrokeEllipseInRect': '__arm2x86_abi_gen_CGContextStrokeEllipseInRect',
           '_CGContextStrokeRect': '__arm2x86_abi_gen_CGContextStrokeRect',
           '_CGContextStrokeRectWithWidth': '__arm2x86_abi_gen_CGContextStrokeRectWithWidth',
           '_CGDisplayMoveCursorToPoint': '__arm2x86_abi_gen_CGDisplayMoveCursorToPoint',
           '_CGDisplayScreenSize': '__arm2x86_abi_gen_CGDisplayScreenSize',
           '_CGEventGetUnflippedLocation': '__arm2x86_abi_gen_CGEventGetUnflippedLocation',
           '_CGFontGetFontBBox': '__arm2x86_abi_gen_CGFontGetFontBBox',
           '_CGLayerCreateWithContext': '__arm2x86_abi_gen_CGLayerCreateWithContext',
           '_CGLayerGetSize': '__arm2x86_abi_gen_CGLayerGetSize',
           '_CGPDFContextAddDestinationAtPoint': '__arm2x86_abi_gen_CGPDFContextAddDestinationAtPoint',
           '_CGPDFContextSetDestinationForRect': '__arm2x86_abi_gen_CGPDFContextSetDestinationForRect',
           '_CGPDFContextSetURLForRect': '__arm2x86_abi_gen_CGPDFContextSetURLForRect',
           '_CGPDFDocumentGetArtBox': '__arm2x86_abi_gen_CGPDFDocumentGetArtBox',
           '_CGPDFDocumentGetBleedBox': '__arm2x86_abi_gen_CGPDFDocumentGetBleedBox',
           '_CGPDFDocumentGetCropBox': '__arm2x86_abi_gen_CGPDFDocumentGetCropBox',
           '_CGPDFDocumentGetMediaBox': '__arm2x86_abi_gen_CGPDFDocumentGetMediaBox',
           '_CGPDFDocumentGetTrimBox': '__arm2x86_abi_gen_CGPDFDocumentGetTrimBox',
           '_CGPathAddEllipseInRect': '__arm2x86_abi_gen_CGPathAddEllipseInRect',
           '_CGPathAddRect': '__arm2x86_abi_gen_CGPathAddRect',
           '_CGPathAddRoundedRect': '__arm2x86_abi_gen_CGPathAddRoundedRect',
           '_CGPathContainsPoint': '__arm2x86_abi_gen_CGPathContainsPoint',
           '_CGPathCreateWithEllipseInRect': '__arm2x86_abi_gen_CGPathCreateWithEllipseInRect',
           '_CGPathCreateWithRoundedRect': '__arm2x86_abi_gen_CGPathCreateWithRoundedRect',
           '_CGPathGetCurrentPoint': '__arm2x86_abi_gen_CGPathGetCurrentPoint',
           '_CGPathGetPathBoundingBox': '__arm2x86_abi_gen_CGPathGetPathBoundingBox',
           '_CGPatternCreate': '__arm2x86_abi_gen_CGPatternCreate',
           '_CGRectCreateDictionaryRepresentation': '__arm2x86_abi_gen_CGRectCreateDictionaryRepresentation',
           '_CGRectDivide': '__arm2x86_abi_gen_CGRectDivide',
           '_CGShadingCreateAxial': '__arm2x86_abi_gen_CGShadingCreateAxial',
           '_CGShadingCreateAxialWithContentHeadroom': '__arm2x86_abi_gen_CGShadingCreateAxialWithContentHeadroom',
           '_CGShadingCreateRadial': '__arm2x86_abi_gen_CGShadingCreateRadial',
           '_CGShadingCreateRadialWithContentHeadroom': '__arm2x86_abi_gen_CGShadingCreateRadialWithContentHeadroom',
           '_CGSizeApplyAffineTransform': '__arm2x86_abi_gen_CGSizeApplyAffineTransform',
           '_CGSizeEqualToSize': '__arm2x86_abi_gen_CGSizeEqualToSize',
           '_CGWarpMouseCursorPosition': '__arm2x86_abi_gen_CGWarpMouseCursorPosition',
           '_CGWindowListCreateImageFromArray': '__arm2x86_abi_gen_CGWindowListCreateImageFromArray',
           '_CMTimeAbsoluteValue': '__arm2x86_abi_gen_CMTimeAbsoluteValue',
           '_CMTimeCodeFormatDescriptionCreate': '__arm2x86_abi_gen_CMTimeCodeFormatDescriptionCreate',
           '_CMTimeCodeFormatDescriptionGetFrameDuration': '__arm2x86_abi_gen_CMTimeCodeFormatDescriptionGetFrameDuration',
           '_CMTimeCompare': '__arm2x86_abi_gen_CMTimeCompare',
           '_CMTimeConvertScale': '__arm2x86_abi_gen_CMTimeConvertScale',
           '_CMTimeCopyAsDictionary': '__arm2x86_abi_gen_CMTimeCopyAsDictionary',
           '_CMTimeCopyDescription': '__arm2x86_abi_gen_CMTimeCopyDescription',
           '_CMTimeMake': '__arm2x86_abi_gen_CMTimeMake',
           '_CMTimeMakeFromDictionary': '__arm2x86_abi_gen_CMTimeMakeFromDictionary',
           '_CMTimeMakeWithEpoch': '__arm2x86_abi_gen_CMTimeMakeWithEpoch',
           '_CMTimeMakeWithSeconds': '__arm2x86_abi_gen_CMTimeMakeWithSeconds',
           '_CMTimeMaximum': '__arm2x86_abi_gen_CMTimeMaximum',
           '_CMTimeMinimum': '__arm2x86_abi_gen_CMTimeMinimum',
           '_CMTimeMultiply': '__arm2x86_abi_gen_CMTimeMultiply',
           '_CMTimeMultiplyByFloat64': '__arm2x86_abi_gen_CMTimeMultiplyByFloat64',
           '_CMTimeMultiplyByRatio': '__arm2x86_abi_gen_CMTimeMultiplyByRatio',
           '_CMTimeShow': '__arm2x86_abi_gen_CMTimeShow',
           '_CMTimeSubtract': '__arm2x86_abi_gen_CMTimeSubtract',
           '_CMVideoFormatDescriptionGetCleanAperture': '__arm2x86_abi_gen_CMVideoFormatDescriptionGetCleanAperture',
           '_CMVideoFormatDescriptionGetPresentationDimensions': '__arm2x86_abi_gen_CMVideoFormatDescriptionGetPresentationDimensions',
           '_CTFontCreateForString': '__arm2x86_abi_gen_CTFontCreateForString',
           '_CTFontCreateForStringWithLanguage': '__arm2x86_abi_gen_CTFontCreateForStringWithLanguage',
           '_CTFontDrawImageFromAdaptiveImageProviderAtPoint': '__arm2x86_abi_gen_CTFontDrawImageFromAdaptiveImageProviderAtPoint',
           '_CTFontGetBoundingRectsForGlyphs': '__arm2x86_abi_gen_CTFontGetBoundingRectsForGlyphs',
           '_CTFontGetMatrix': '__arm2x86_abi_gen_CTFontGetMatrix',
           '_CTFontGetOpticalBoundsForGlyphs': '__arm2x86_abi_gen_CTFontGetOpticalBoundsForGlyphs',
           '_CTFontGetTypographicBoundsForAdaptiveImageProvider': '__arm2x86_abi_gen_CTFontGetTypographicBoundsForAdaptiveImageProvider',
           '_CTFrameGetLineOrigins': '__arm2x86_abi_gen_CTFrameGetLineOrigins',
           '_CTFrameGetStringRange': '__arm2x86_abi_gen_CTFrameGetStringRange',
           '_CTFrameGetVisibleStringRange': '__arm2x86_abi_gen_CTFrameGetVisibleStringRange',
           '_CTFramesetterCreateFrame': '__arm2x86_abi_gen_CTFramesetterCreateFrame',
           '_CTLineGetBoundsWithOptions': '__arm2x86_abi_gen_CTLineGetBoundsWithOptions',
           '_CTLineGetImageBounds': '__arm2x86_abi_gen_CTLineGetImageBounds',
           '_CTLineGetStringIndexForPosition': '__arm2x86_abi_gen_CTLineGetStringIndexForPosition',
           '_CTLineGetStringRange': '__arm2x86_abi_gen_CTLineGetStringRange',
           '_CTRunDraw': '__arm2x86_abi_gen_CTRunDraw',
           '_CTRunGetAdvances': '__arm2x86_abi_gen_CTRunGetAdvances',
           '_CTRunGetBaseAdvancesAndOrigins': '__arm2x86_abi_gen_CTRunGetBaseAdvancesAndOrigins',
           '_CTRunGetGlyphs': '__arm2x86_abi_gen_CTRunGetGlyphs',
           '_CTRunGetImageBounds': '__arm2x86_abi_gen_CTRunGetImageBounds',
           '_CTRunGetPositions': '__arm2x86_abi_gen_CTRunGetPositions',
           '_CTRunGetStringIndices': '__arm2x86_abi_gen_CTRunGetStringIndices',
           '_CTRunGetStringRange': '__arm2x86_abi_gen_CTRunGetStringRange',
           '_CTRunGetTextMatrix': '__arm2x86_abi_gen_CTRunGetTextMatrix',
           '_CTRunGetTypographicBounds': '__arm2x86_abi_gen_CTRunGetTypographicBounds',
           '_CTTypesetterCreateLine': '__arm2x86_abi_gen_CTTypesetterCreateLine',
           '_CTTypesetterCreateLineWithOffset': '__arm2x86_abi_gen_CTTypesetterCreateLineWithOffset',
           '_CVImageBufferGetCleanRect': '__arm2x86_abi_gen_CVImageBufferGetCleanRect',
           '_CVImageBufferGetDisplaySize': '__arm2x86_abi_gen_CVImageBufferGetDisplaySize',
           '_CVImageBufferGetEncodedSize': '__arm2x86_abi_gen_CVImageBufferGetEncodedSize',
           '_DCSCopyTextDefinition': '__arm2x86_abi_gen_DCSCopyTextDefinition',
           '_DCSGetTermRangeInString': '__arm2x86_abi_gen_DCSGetTermRangeInString',
           '_HIDictionaryWindowShow': '__arm2x86_abi_gen_HIDictionaryWindowShow',
           '_NSAccessibilityPointInView': '__arm2x86_abi_gen_NSAccessibilityPointInView',
           '_NSCopyBits': '__arm2x86_abi_gen_NSCopyBits',
           '_NSDivideRect': '__arm2x86_abi_gen_NSDivideRect',
           '_NSDottedFrameRect': '__arm2x86_abi_gen_NSDottedFrameRect',
           '_NSDrawBitmap': '__arm2x86_abi_gen_NSDrawBitmap',
           '_NSDrawButton': '__arm2x86_abi_gen_NSDrawButton',
           '_NSDrawColorTiledRects': '__arm2x86_abi_gen_NSDrawColorTiledRects',
           '_NSDrawDarkBezel': '__arm2x86_abi_gen_NSDrawDarkBezel',
           '_NSDrawGrayBezel': '__arm2x86_abi_gen_NSDrawGrayBezel',
           '_NSDrawGroove': '__arm2x86_abi_gen_NSDrawGroove',
           '_NSDrawLightBezel': '__arm2x86_abi_gen_NSDrawLightBezel',
           '_NSDrawNinePartImage': '__arm2x86_abi_gen_NSDrawNinePartImage',
           '_NSDrawTiledRects': '__arm2x86_abi_gen_NSDrawTiledRects',
           '_NSDrawWhiteBezel': '__arm2x86_abi_gen_NSDrawWhiteBezel',
           '_NSDrawWindowBackground': '__arm2x86_abi_gen_NSDrawWindowBackground',
           '_NSEraseRect': '__arm2x86_abi_gen_NSEraseRect',
           '_NSFrameRect': '__arm2x86_abi_gen_NSFrameRect',
           '_NSFrameRectWithWidth': '__arm2x86_abi_gen_NSFrameRectWithWidth',
           '_NSFrameRectWithWidthUsingOperation': '__arm2x86_abi_gen_NSFrameRectWithWidthUsingOperation',
           '_NSHighlightRect': '__arm2x86_abi_gen_NSHighlightRect',
           '_NSRangeFromString': '__arm2x86_abi_gen_NSRangeFromString',
           '_NSReadPixel': '__arm2x86_abi_gen_NSReadPixel',
           '_NSShowAnimationEffect': '__arm2x86_abi_gen_NSShowAnimationEffect',
           '_NSStringFromRange': '__arm2x86_abi_gen_NSStringFromRange',
           '_SKSearchResultsGetInfoInRange': '__arm2x86_abi_gen_SKSearchResultsGetInfoInRange',
           '___CFRangeMake': '__arm2x86_abi_gen___CFRangeMake',
           '_proc_signal_delegate': '__arm2x86_abi_gen_proc_signal_delegate',
           '_proc_terminate_delegate': '__arm2x86_abi_gen_proc_terminate_delegate',
           '_NSIntegralRect': '__arm2x86_abi_gen_NSIntegralRect',
           '_NSIntegralRectWithOptions': '__arm2x86_abi_gen_NSIntegralRectWithOptions',
           '_NSIntersectionRange': '__arm2x86_abi_gen_NSIntersectionRange',
           '_NSIntersectionRect': '__arm2x86_abi_gen_NSIntersectionRect',
           '_NSIntersectsRect': '__arm2x86_abi_gen_NSIntersectsRect',
           '_NSIsEmptyRect': '__arm2x86_abi_gen_NSIsEmptyRect',
           '_NSMouseInRect': '__arm2x86_abi_gen_NSMouseInRect',
           '_NSOffsetRect': '__arm2x86_abi_gen_NSOffsetRect',
           '_NSPointFromString': '__arm2x86_abi_gen_NSPointFromString',
           '_NSRectClip': '__arm2x86_abi_gen_NSRectClip',
           '_NSRectFill': '__arm2x86_abi_gen_NSRectFill',
           '_NSRectFillUsingOperation': '__arm2x86_abi_gen_NSRectFillUsingOperation',
           '_NSRectFromString': '__arm2x86_abi_gen_NSRectFromString',
           '_NSSizeFromString': '__arm2x86_abi_gen_NSSizeFromString',
           '_NSStringFromPoint': '__arm2x86_abi_gen_NSStringFromPoint',
           '_NSStringFromRect': '__arm2x86_abi_gen_NSStringFromRect',
           '_NSStringFromSize': '__arm2x86_abi_gen_NSStringFromSize',
           '_NSUnionRange': '__arm2x86_abi_gen_NSUnionRange',
           '_NSUnionRect': '__arm2x86_abi_gen_NSUnionRect',
           '_SecTaskCreateWithAuditToken': '__arm2x86_abi_gen_SecTaskCreateWithAuditToken',
           '_SIOpenIndex': '__arm2x86_abi_gen_SIOpenIndex',
           '_SICreateNewIndex': '__arm2x86_abi_gen_SICreateNewIndex',
           '_TCCAccessCheckAuditToken': '__arm2x86_abi_gen_TCCAccessCheckAuditToken',
           # end generated by-value struct handlers
           #  10-21 a guest Swift class IS its own metadata; objc_allocateClassPair cannot set the
           #    stable-ABI bit, so the native runtime wrapped it and dynamic casts failed (ControlCenter)
           '_swift_getObjCClassMetadata': '__arm2x86_abi_swift_getObjCClassMetadata',
           '_swift_getObjectType': '__arm2x86_abi_swift_getObjectType',
           '_swift_updateClassMetadata': '__arm2x86_abi_swift_updateClassMetadata',
           '_swift_updateClassMetadata2': '__arm2x86_abi_swift_updateClassMetadata2',
           '_swift_getObjCClassFromMetadata': '__arm2x86_abi_swift_getObjCClassFromMetadata',
           #  10-21 objc_opt_* takes a guest class — map it (see objc_bridge.c)
           '_objc_opt_self': '__arm2x86_abi_objc_opt_self',
           '_objc_opt_class': '__arm2x86_abi_objc_opt_class',
           '_objc_opt_new': '__arm2x86_abi_objc_opt_new',
           '_objc_opt_isKindOfClass': '__arm2x86_abi_objc_opt_isKindOfClass',
           '_objc_opt_respondsToSelector': '__arm2x86_abi_objc_opt_respondsToSelector',
           #  10-21 the objc_alloc family takes a guest class TOO, and the bad isa it writes outlives the
           #    call — a native msgSend on the object faults later, in another image (Finder: SIGSEGV in
           #    objc_lookUpImpOrForward under DesktopServicesPriv). See objc_bridge.c beside A2X_OPT1.
           '_objc_alloc': '__arm2x86_abi_objc_alloc',
           '_objc_alloc_init': '__arm2x86_abi_objc_alloc_init',
           '_objc_allocWithZone': '__arm2x86_abi_objc_allocWithZone',
           '_CFUUIDGetUUIDBytes': '__arm2x86_abi_CFUUIDGetUUIDBytes',
           '_CFUUIDCreateFromUUIDBytes': '__arm2x86_abi_CFUUIDCreateFromUUIDBytes',
           '_SLSManagedDisplayIteratorGetBounds': '__arm2x86_abi_SLSManagedDisplayIteratorGetBounds',
           '_SLSWindowIteratorGetBounds': '__arm2x86_abi_SLSWindowIteratorGetBounds',
           '_SLSWindowIteratorGetFrameBounds': '__arm2x86_abi_SLSWindowIteratorGetFrameBounds',
           '_SLSWindowIteratorGetLastNonEmptyFrameBounds': '__arm2x86_abi_SLSWindowIteratorGetLastNonEmptyFrameBounds',
           #  10-05 SSLCipherSuite = uint16 on arm64, uint32 on x86-64: the native call overflowed the game's heap
           '_SSLGetSupportedCiphers': '__arm2x86_abi_SSLGetSupportedCiphers', '_SSLSetEnabledCiphers': '__arm2x86_abi_SSLSetEnabledCiphers',
           '_SSLGetNegotiatedCipher': '__arm2x86_abi_SSLGetNegotiatedCipher',
           #  10-05 variadic, no sigdb entry: the value is on the arm64 STACK, the untyped adapter passed x2
           '_curl_easy_setopt': '__arm2x86_abi_curl_easy_setopt', '_curl_easy_getinfo': '__arm2x86_abi_curl_easy_getinfo',
           #  10-05 bool return through the untyped adapter: x86 leaves the version in %eax's upper bytes
           '__availability_version_check': '__arm2x86_abi_availability_version_check',
           #  10-20 a STRUCT BY VALUE (CMTime 24 B, CGAffineTransform 48 B, CGRect 32 B): arm64 passes it by pointer
           #    (or as an HFA in v0-v3), x86-64 on the stack, and sigdb marks these 'x', so the untyped adapter handed
           #    the callee a pointer where it wanted the bytes — avmediainfo printed `Duration: nan`, native 0.768
           '_CMTimeGetSeconds': '__arm2x86_abi_CMTimeGetSeconds', '_CMTimeAdd': '__arm2x86_abi_CMTimeAdd',
           '_CGAffineTransformEqualToTransform': '__arm2x86_abi_CGAffineTransformEqualToTransform',
           '_CGRectEqualToRect': '__arm2x86_abi_CGRectEqualToRect',
           '___sincos_stret': '__arm2x86_sincos_stret', '___sincosf_stret': '__arm2x86_sincosf_stret',   #  10-03 HFA {sin,cos}
           '___sincospi_stret': '__arm2x86_sincospi_stret', '___sincospif_stret': '__arm2x86_sincospif_stret',
           '__ZNSt3__19to_stringEi': '__arm2x86_cxx_to_string_i',
           '__ZNSt3__19to_stringEl': '__arm2x86_cxx_to_string_l',
           '__ZNSt3__19to_stringEm': '__arm2x86_cxx_to_string_m',
           '__ZNSt3__19to_stringEx': '__arm2x86_cxx_to_string_x',
           '__ZNSt3__19to_stringEy': '__arm2x86_cxx_to_string_y',
           '__ZNSt3__19to_stringEf': '__arm2x86_cxx_to_string_f',
           '__ZNSt3__19to_stringEd': '__arm2x86_cxx_to_string_d',
           '__ZNSt3__1plIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EEPKS6_RKS9_': '__arm2x86_cxx_plus_cstr_string'}
    #  10-25 arm64-only libobjc helpers: object in xN, not x0 (cxx_bridge.cpp OBJC_RR_X). x18 is the platform register.
    XIN = {}
    for _n in [n for n in range(29) if n != 18]:
        CXX[f'_objc_retain_x{_n}'] = '__arm2x86_objc_retain_xin'; XIN[f'_objc_retain_x{_n}'] = _n
        CXX[f'_objc_release_x{_n}'] = '__arm2x86_objc_release_xin'; XIN[f'_objc_release_x{_n}'] = _n
    for stub, slot in native_stub_slot.items():
        if slot_sym.get(slot) in CXX:
            binds[stub] = {'sym': CXX[slot_sym[slot]], 'argc': 0, 'args': '', 'ret': 'void', 'rf': 1, 'va': 1}
            if slot_sym[slot] in XIN: binds[stub]['xin'] = XIN[slot_sym[slot]]
    #  10-03 a native C++ constructor / non-deleting destructor returns `this` on arm64 and void on x86-64 (see
    #    arm2x86.THISRET). Each such import leaves the typed binds and is lifted as a stub that returns its own x0.
    #    Classified from the DEMANGLED name (a ctor is X::X(, a dtor X::~X(); D0 demangles alike and is harmless: void).
    cand = {s: slot_sym[sl] for s, sl in native_stub_slot.items() if slot_sym.get(sl, '').startswith('__ZN')}
    dem = dict(zip(sorted(set(cand.values())), subprocess.run(['xcrun', 'c++filt', '-_'], input='\n'.join(sorted(set(cand.values()))),
                                                              capture_output=True, text=True, check=True).stdout.splitlines()))
    thisret = {s for s, sym in cand.items() if ctor_dtor(dem.get(sym, ''))}
    noop = {s for s, sl in native_stub_slot.items() if slot_sym.get(sl) == '___chkstk_darwin'}   # see arm2x86.NOOP_CALLS
    noop |= {sl for sl, sym in slot_sym.items() if sym == '___chkstk_darwin'}   #  and its GOT slots: `blr x16` prologues
    for s in noop: binds.pop(s, None)
    #  10-03 x86 asm labels ($INODE64 ...): every native C import with a sigdb declaration, typed bind or runtime slot
    asm_map = x86_asm_names({sym[1:] for sym in set(slot_sym.values()) if sym.startswith('_') and sym[1:] in sig})
    for b_ in binds.values():
        if not b_.get('rf') and b_['sym'] in asm_map: b_['sym'] = asm_map[b_['sym']]
    print(f'asm names: {len(asm_map)} imports have a different x86-64 symbol: {sorted(asm_map.items())[:12]}')
    print(f'noop: {len(noop)} ___chkstk_darwin stubs + GOT slots: their calls lift to nothing (the arm64 stack has a guard page)')
    for s in thisret: binds.pop(s, None)
    print(f'thisret: {len(thisret)} native constructor/destructor imports return `this` (of {len(cand)} C++ imports)')
    #  an import sigdb cannot type: lift the STUB itself — its `br x16` reaches the native function via the adapter
    stubdir = os.path.join(out, 'stubfn'); os.makedirs(stubdir, exist_ok=True)
    stub_specs = []
    for img in images:
        for s, lines in img['stub_lines'].items():
            #  10-10 3 = the classic/non-auth stub, 4 = the arm64e __auth_stubs entry (adrp/add/ldr/braa).  WAS 3
            #    only, so on macOS 27 every untypeable import was dropped here and its call reached
            #    __arm2x86_unimplemented — os_log_type_enabled's stub (0x1000d3084) was the first one loginwindow hit.
            if s in aliases or s in binds or len(lines) not in (3, 4): continue
            p = os.path.join(stubdir, f'{s:x}.txt'); open(p, 'w').write('\n'.join(lines) + '\n'); stub_specs.append(p)
            known.add(s)
    if thisret - known: raise SystemExit(f'{len(thisret - known)} ctor/dtor stubs could not be lifted (not 3 or 4 instructions)')
    #  10-20 THE STUB KNOWS ITS CALLEE'S LANGUAGE. A Swift symbol (`_$s…`) is swiftcc on both sides: arm64 x8/x20/x21 must
    #    reach x86 rax/r13/r12 (arm2x86.STUB_CC, the adapter's swift path). Anything else is C — including an @objc thunk
    #    (`…To`), whose convention is C, and the Swift runtime's own C entry points (`_swift_retain`, …).  Measured on
    #    macOS 27: 100% of eslogger's / xprotect's untyped Swift imports reached native code with x8 in the wrong register.
    lifted_stubs = {int(os.path.basename(p_)[:-4], 16) for p_ in stub_specs}
    #  10-21 SWIFT ASYNC IMPORTS (3 = swifttailcc, the async context in r14 = arm64 x22). An async function is only ever
    #    entered by a TAIL transfer, and every arm64 async function opens with the extended-frame marker (arm2x86.Lifter.async_fn),
    #    so a stub that an async function tail-branches to (`b stub`) IS an async import — whatever its name: the runtime's
    #    C entry points (`_swift_task_switch`, `_swift_task_future_wait` ...) and the mangled `$s…Ya…` ones alike. Read off
    #    the program's own code instead of a name list; the list below only covers a thunk that has no marker of its own.
    async_stubs = set()
    for img_ in images:
        for _, ls_ in img_['fsegs']:
            if not ls_: continue
            ps_ = [abi_scan.parse_line(l_) for l_ in ls_[:3]]
            if not any(p_ and p_[1] == 'orr' and p_[2].replace(' ', '') == 'x29,x29,#0x1000000000000000' for p_ in ps_): continue
            for l_ in ls_:
                p_ = abi_scan.parse_line(l_)
                if p_ and p_[1] == 'b':
                    t_ = abi_scan._target(p_[2])
                    if t_ in native_stub_slot: async_stubs.add(t_)
    #  10-21 AN ASYNC IMPORT REACHED BY A `bl` WAS CALLED AS PLAIN swiftcc AND LOST ITS CONTEXT.
    #    `async_stubs` above reads the program's own code, which is right, but it only sees a TAIL branch
    #    (`b stub`) out of a frame-marked async function — and the premise above it, "an async function is only
    #    ever entered by a TAIL transfer", is FALSE at -Osize, where the outliner emits an ordinary `bl` to the
    #    import stub. Then `_$s…` fell through to 2, the adapter took its swiftcc path, r14 (arm64 x22) was
    #    never loaded, and native `withTaskGroup` dereferenced a null async context 0x1a into its prologue:
    #    `CRASH signal 11 … fault address 0x128`, r14 = 0 (asyncmx -Osize, macpro27).
    #     The control is inside the measurement: of the SIX async imports in that build, the five reached by a
    #    tail branch were all classified 3 correctly — ScG/ScS.Iterator.next, ScI.next, Task.value, Task.sleep —
    #    and `withTaskGroup`, the only one CALLED, was the only one classified 2, and the only one that faulted.
    #     So ask the CALLEE too, not just the call shape: Swift emits an async function pointer record
    #    `<symbol>Tu` for every async function, and a caller has to load it to size the context, so the companion
    #    is bound wherever the function is reachable. That is structural.  NOT a substring test for the `Ya`
    #    async marker: mangled identifiers are length-prefixed, not delimited, so any identifier containing "Ya"
    #    (`5Yacht`) would fire. Measured here: 6 of 98 Swift imports carry a `Tu` companion and all 6 are async.
    async_tu = {v_[:-2] for v_ in slot_sym.values() if v_.endswith('Tu')}
    stub_cc = {s_: (3 if s_ in async_stubs or slot_sym.get(sl_, '') in ASYNC_RT_SYMS
                         or slot_sym.get(sl_, '') in async_tu else
                    2 if slot_sym.get(sl_, '').startswith('_$s') and not slot_sym[sl_].endswith('To') else 1)
               for s_, sl_ in native_stub_slot.items() if s_ in lifted_stubs and s_ not in thisret}
    print(f'stub cc: {sum(1 for v_ in stub_cc.values() if v_ == 3)} Swift ASYNC (swifttailcc) + '
          f'{sum(1 for v_ in stub_cc.values() if v_ == 2)} Swift (swiftcc) + {sum(1 for v_ in stub_cc.values() if v_ == 1)} C '
          f'untyped imports through the native adapter')
    print(f'binds: {len(binds)} typed natives, {len(stub_specs)} stubs lifted to the native adapter, {len(aliases)} stubs -> '
          f'translated functions, {len(missing)} internal symbols MISSING {missing[:5]}')
    # --- the calling contract (abi_scan.py) ------------------------------------------------------------------------------
    #  rung 6 (10-03): outlined code keeps no calling convention; every function that reads or hands back a register off
    #    the AAPCS64 contract is called with the full register file. The reason for each one is written to nonabi.txt.
    t0 = time.time(); fmap = {}
    for img in images:
        for _, ls in img['fsegs']: fmap[int(re.match(r'^\s*([0-9a-f]+):', ls[0]).group(1), 16)] = ls
    why = {}
    #  a typed native stub reads exactly its named arguments (sigdb) — printf reads x0, not x1-x7 or x8
    stub_reads = {}
    for st_, b_ in binds.items():
        if b_.get('rf'): continue                      # a full-register-file bridge (objc_msgSend) may read anything
        ni = nf = 0; rr = set()
        for c_ in b_.get('args', ''):
            if c_ == 'i':
                if ni < 8: rr.add(f'x{ni}')
                ni += 1
            else:
                if nf < 8: rr.add(f'v{nf}')
                nf += 1
        stub_reads[st_] = rr
    #  10-22 A SWIFT IMPORT READS x8. An untyped stub is assumed to read x0-x7/v0-v7 only (abi_scan.UNK: x8 is the
    #    commonest scratch register), but the adapter's swiftcc path hands x8 to the native callee as its indirect result
    #    (rax). ControlCenter: an outlined helper set x8 for `bl` AsyncStream.Continuation.yield (its generic YieldResult
    #    returns indirectly), stayed on-contract, the x8 was dropped, and __swift_destroy_strong then released garbage
    #    (SIGSEGV in doDecrementSlow / a jump into the heap). C stubs keep the narrow set: only hint 2 counts x8.
    for st_, cc_ in stub_cc.items():
        if cc_ == 2 and st_ not in stub_reads:
            stub_reads[st_] = abi_scan.UNK | {'x8'}
    prev_nonabi = None
    if os.path.exists(os.path.join(out, 'nonabi.txt')):
        prev_nonabi = {int(l.split()[0], 16) for l in open(os.path.join(out, 'nonabi.txt')) if l.strip()}
    #  10-03 cached on its exact inputs (every function text, the call graph's endpoints, the scanner's own code): 105 s
    #    on Cyberpunk, and identical on every run that did not touch them
    import hashlib, pickle   # noqa: PLC0415
    hk = hashlib.sha256(open(os.path.join(S, 'abi_scan.py'), 'rb').read())
    for a_ in sorted(fmap): hk.update(f'{a_:x}\n'.encode()); hk.update('\n'.join(fmap[a_]).encode())
    hk.update(repr((sorted(known), sorted(aliases.items()), sorted((k_, sorted(v_)) for k_, v_ in stub_reads.items()))).encode())
    hk = hk.hexdigest(); cache_ = os.path.join(out, 'abi_cache.pkl')
    hit = pickle.load(open(cache_, 'rb')) if os.path.exists(cache_) else None
    if hit and hit[0] == hk:
        nonabi, why = hit[1], hit[2]; print('abi: cached (inputs identical)')
    else:
        nonabi = abi_scan.classify(fmap, known, aliases, why, stub_reads, jobs=jobs)   #  the configured worker count
        pickle.dump((hk, nonabi, why), open(cache_ + '.tmp', 'wb')); os.replace(cache_ + '.tmp', cache_)
    #  10-20 THE INTERNAL RETURN CONTRACT IS {x0, v0} — ONE vector. A function that returns an HFA wider than
    #    that (a CGRect is four doubles in d0-d3) therefore came back TRUNCATED: measured on the Dock, the handler
    #    wrote v0..v3 = 1234 5678 11 22 into the register file and the program read 1234 5678 0 0, i.e. a screen with
    #    a correct origin and NO SIZE. The Dock logged `CGDisplayBounds(0xb41a2f3) returned 0.000000 ...` and aborted,
    #    and because every AppKit app registers with the Dock at startup, that one truncation held the whole desktop
    #    at the login spinner. The mirror of this on the argument side is already handled by the rf binds.
    #    So: any function that CALLS an HFA-returning native takes the full register file, which carries v0..v7 back
    #    to ITS caller intact. Conservative by design — it costs a wider move on a handful of functions and cannot
    #    silently drop half a rectangle.
    hfa_syms = {'__arm2x86_abi_CGDisplayBounds', '__arm2x86_abi_CAFrameRateRangeMake',
                '__arm2x86_abi_SLSManagedDisplayIteratorGetBounds', '__arm2x86_abi_SLSWindowIteratorGetBounds',
                '__arm2x86_abi_SLSWindowIteratorGetFrameBounds', '__arm2x86_abi_SLSWindowIteratorGetLastNonEmptyFrameBounds',
                '__arm2x86_sincos_stret', '__arm2x86_sincosf_stret', '__arm2x86_sincospi_stret', '__arm2x86_sincospif_stret'}
    hfa_stubs = {s_ for s_, b_ in binds.items() if b_.get('sym') in hfa_syms}
    if hfa_stubs:
        _blpat = re.compile(r'\bbl\s+0x([0-9a-f]+)')
        _add = set()
        for a_, ls_ in fmap.items():
            if a_ in nonabi: continue
            for l_ in ls_:
                m_ = _blpat.search(l_)
                if m_ and int(m_.group(1), 16) in hfa_stubs: _add.add(a_); break
        for a_ in _add:
            why.setdefault(a_, 'calls an HFA-returning native: the {x0,v0} return contract would truncate v1-v3')
        nonabi |= _add
        print(f'abi: {len(_add)} callers of an HFA-returning native -> full register file (of {len(hfa_stubs)} such stubs)')
    #  10-03 a function whose register-file status CHANGED since the last run invalidates its own shard and every
    #    shard that calls or tail-branches to it (their call sites move different registers). Applied below, by index.
    relift = set()
    if prev_nonabi is not None and prev_nonabi != nonabi:
        delta = nonabi ^ prev_nonabi
        relift |= delta
        for a_, ls_ in fmap.items():
            for ln_ in ls_:
                m_ = re.search(r'\t(?:bl|b)\t(0x[0-9a-f]+)', ln_)
                if m_ and aliases.get(int(m_.group(1), 16), int(m_.group(1), 16)) in delta: relift.add(a_); break
        print(f'abi: {len(delta)} functions changed contract since the last run -> {len(relift)} functions to re-lift')
    if os.environ.get('ARM2X86_RELIFT'):   # a file of function addresses whose LIFT changed (one hex per line)
        relift |= {int(l.split()[0], 16) for l in open(os.environ['ARM2X86_RELIFT']) if l.strip()}
    #  10-03 a CONDITIONAL TAIL BRANCH target (b.cond/cbz/tbz into another function's start — split asm fragments)
    #    receives the whole register file, exactly like a fall-through successor: the fragments share registers freely.
    CB_ = re.compile(r'^\s*([0-9a-f]+):\s+(?:b\.\w+|bc\.\w+|cbz|cbnz|tbz|tbnz)\s+.*?0x([0-9a-f]+)\s*$')
    ctail = set()
    for a_, ls_ in fmap.items():
        e_ = int(re.match(r'^\s*([0-9a-f]+):', ls_[-1]).group(1), 16) + 4
        for l_ in ls_:
            m_ = CB_.match(l_)
            if m_:
                t_ = int(m_.group(2), 16)
                if not (a_ <= t_ < e_) and t_ in known and t_ not in nonabi: ctail.add(t_)
    for t_ in ctail: nonabi.add(t_); why[t_] = 'conditional tail-branch target (split fragment)'
    print(f'abi: {len(ctail)} conditional tail-branch targets moved to the full register file')
    #  10-03 a landing pad outside its function (function starts split it) cannot be an LLVM unwind target: refused by name
    for f_, e_ in EHF.items():
        aset = {int(re.match(r'^\s*([0-9a-f]+):', l_).group(1), 16) for l_ in fmap.get(f_, ())}
        if not aset: eh_bad.append(f'0x{f_:x} has an LSDA but is not a lifted function'); continue
        for _, _, lp_, _ in e_['sites']:
            if lp_ and lp_ not in aset: eh_bad.append(f'0x{f_:x}: landing pad 0x{lp_:x} outside the function')
    if eh_bad: raise SystemExit(f'eh: {len(eh_bad)} unsupported: {eh_bad[:8]}')
    ae_ = abi_scan.async_entries(fmap, why)   #  10-21 before the function texts are freed: the swifttailcc entries (see abi_scan.async_entries)
    async_set = set(ae_)
    #  one async function with an indirect `br` goes through the module verifier too (its tail transfer is a `musttail`)
    ae_rep = next(((a_, '\n'.join(fmap[a_]) + '\n') for a_ in ae_ if a_ in fmap
                   and any((p_ := abi_scan.parse_line(l_)) and p_[1] == 'br' for l_ in fmap[a_])), None)
    del fmap
    open(os.path.join(out, 'nonabi.txt'), 'w').write(''.join(f'{a:x} {why.get(a, "")}\n' for a in sorted(nonabi)))
    print(f'abi: {len(nonabi)} functions off the AAPCS64 contract -> full register file ({time.time() - t0:.0f} s, nonabi.txt)')
    # --- preflight: every instruction FORM the program uses, lifted once, BEFORE anything compiles -------------------------
    #  10-03: fpcr, cntpct_el0 and `ldr xN, <literal>` were found only after a 25-minute build died on 8 shards.
    #    One real function per distinct instruction shape is lifted here (no opt, no llc); any failure stops the build
    #    with the WHOLE list at once. ARM2X86_PREFLIGHT=warn lets a build continue past it (say why).
    t0 = time.time(); seen, reps = set(), {}
    #  10-03 ...and one function per LANDING-PAD shape (cleanup / catch / catch-all / filter empty / filter typed),
    #    which the module preflight below runs through LLVM's verifier.  build19: `filter [0 x ptr] []` broke shard 360
    #    after 40 minutes; instruction shapes alone never exercise a clause kind.
    def pad_kind(cl):
        return tuple(sorted({'cleanup' if f == 0 else 'filter0' if f < 0 and not t else 'filterN' if f < 0
                             else 'catchall' if t is None else 'catch' for f, t in cl} or {'cleanup'}))
    eh_pick, eh_seen = set(), set()
    for f_, e_ in sorted(EHF.items()):
        for _, _, lp_, cl_ in e_['sites']:
            k_ = pad_kind(cl_)
            if lp_ and k_ not in eh_seen: eh_seen.add(k_); eh_pick.add(f_)
    eh_reps = {}
    for img in images:
        for _, ls in img['fsegs']:
            if eh_pick:
                a_ = int(re.match(r'^\s*([0-9a-f]+):', ls[0]).group(1), 16)
                if a_ in eh_pick: eh_reps[a_] = '\n'.join(ls) + '\n'
            for ln in ls:
                sh_ = insn_shape(ln)
                if sh_ and sh_ not in seen:
                    seen.add(sh_); a0 = int(re.match(r'^\s*([0-9a-f]+):', ls[0]).group(1), 16); reps[a0] = '\n'.join(ls) + '\n'
    items = sorted(reps.items()); step = max(1, len(items) // (jobs * 4))
    bad = []
    with ProcessPoolExecutor(jobs) as ex:
        for part in ex.map(preflight_chunk, [(items[i:i + step], known, binds, aliases, nonabi) for i in range(0, len(items), step)]):
            bad += part
    open(os.path.join(out, 'preflight.txt'), 'w').write(''.join(f'{a:x} {m}\n' for a, m in bad))
    print(f'preflight: {len(seen)} instruction shapes, {len(reps)} functions lifted, {len(bad)} FAILED ({time.time() - t0:.0f} s, preflight.txt)')
    if bad:
        import collections   # noqa: PLC0415
        for m, n in collections.Counter(re.sub(r'0x[0-9a-f]+|\b[0-9a-f]{8,}\b', 'A', m) for _, m in bad).most_common(25): print(f'  {n:5d}  {m}')
        if os.environ.get('ARM2X86_PREFLIGHT') != 'warn':
            raise SystemExit('preflight FAILED — fix the lifter first (or ARM2X86_PREFLIGHT=warn to build past it)')
    # --- module preflight: the representatives AS ONE MODULE through LLVM's verifier, before any shard compiles ----------
    #  10-03 lifting proves the lifter did not raise; only `opt -passes=verify` proves the IR is legal. Every instruction
    #    representative, one function per landing-pad shape (with its EH), and every this-returning stub, in one module.
    t0 = time.time()
    arm2x86.ALIASES.clear(); arm2x86.ALIASES.update(aliases); arm2x86.NONABI.clear(); arm2x86.NONABI.update(nonabi)
    arm2x86.EH.clear(); arm2x86.EH.update({a_: EHF[a_] for a_ in eh_reps})
    arm2x86.THISRET.clear(); arm2x86.THISRET.update(thisret)
    arm2x86.NOOP_CALLS.clear(); arm2x86.NOOP_CALLS.update(noop)
    arm2x86.STUB_CC.clear(); arm2x86.STUB_CC.update(stub_cc)
    arm2x86.ASYNC_FNS.clear(); arm2x86.ASYNC_FNS.update(async_set)
    texts = {a_: t_ for a_, t_ in reps.items() if a_ not in {b_ for b_, _ in bad}}
    texts.update(eh_reps)
    if ae_rep: texts[ae_rep[0]] = ae_rep[1]
    #  10-20 one stub of each convention hint goes through the verifier too (the hint store is new IR)
    cc_reps = {min((a_ for a_, v_ in stub_cc.items() if v_ == c_), default=None) for c_ in (1, 2, 3)} - {None}
    texts.update({int(os.path.basename(p_)[:-4], 16): open(p_).read() for p_ in stub_specs
                  if int(os.path.basename(p_)[:-4], 16) in thisret | cc_reps})
    vparts, _ = assemble([texts[a_] for a_ in sorted(texts)], known, binds)
    arm2x86.EH.clear(); arm2x86.THISRET.clear(); arm2x86.NOOP_CALLS.clear(); arm2x86.STUB_CC.clear(); arm2x86.ASYNC_FNS.clear()
    vll = os.path.join(out, 'preflight.ll'); open(vll, 'w').write('\n'.join(vparts))
    vr = subprocess.run([f'{LLVM}/opt', '-passes=verify', '-disable-output', vll], capture_output=True, text=True)
    print(f'preflight module: {len(texts)} functions ({len(eh_reps)} landing-pad shapes {sorted(eh_seen)}), '
          f'LLVM verifier {"OK" if vr.returncode == 0 else "REFUSED"} ({time.time() - t0:.0f} s)')
    if vr.returncode:
        print(vr.stderr[:3000]); raise SystemExit('preflight module REFUSED by the LLVM verifier — fix the lifter first')
    # --- shard fingerprint: never reuse a .o lifted by a DIFFERENT lifter in silence --------------------------------------
    #  10-03: resume reuses shardNNNN.o by INDEX. That is only right when the lifter change since is ADDITIVE (it only
    #    handles forms that used to abort). Any other change must re-lift every shard. The stamp names the lifter.
    import hashlib   # noqa: PLC0415
    fp = hashlib.sha256()
    for f_ in ('arm2x86.py', 'xlat.py', 'xlat2.py', 'abi_scan.py', 'sigdb.json', 'split_fns.py', 'rebase_macho.py', 'eh.py',
               'vendor/libc++.1.0.dylib'):
        fp.update(open(os.path.join(S, f_), 'rb').read())
    fp = fp.hexdigest()[:16]
    stamp = os.path.join(out, 'shards', 'FINGERPRINT')
    old_o = [f_ for f_ in (os.listdir(os.path.join(out, 'shards')) if os.path.isdir(os.path.join(out, 'shards')) else []) if f_.endswith('.o')]
    if old_o:
        prev = open(stamp).read().split('\n')[-2].split()[0] if os.path.exists(stamp) and open(stamp).read().strip() else 'none'   #  10-03: the LAST stamp, not the first
        if prev != fp:   #  10-03 informational now: each shard's IR hash decides what recompiles (lift_shard)
            print(f'lifter {prev} -> {fp}: shards recompile only where their IR changed')
    os.makedirs(os.path.join(out, 'shards'), exist_ok=True)
    with open(stamp, 'a') as f_: f_.write(f'{fp} {time.strftime("%Y-%m-%d %H:%M:%S")} {os.environ.get("ARM2X86_REUSE_SHARDS", "fresh")}\n')
    # --- shards ---------------------------------------------------------------------------------------------------------
    specs = []
    for img in images:
        fd = os.path.join(img['dir'], 'fn'); os.makedirs(fd, exist_ok=True)
        for _, ls in img['fsegs']:
            a0 = int(re.match(r'^\s*([0-9a-f]+):', ls[0]).group(1), 16)
            p = os.path.join(fd, f'{a0:x}.txt'); open(p, 'w').write('\n'.join(ls) + '\n'); specs.append((p, len(ls)))
        img['fsegs'] = None   # free the text
    # the second element is only the instruction count used to size a shard — a lifted stub is 3 or 4 instructions
    specs += [(p, sum(1 for _ in open(p))) for p in stub_specs]
    target = 60000   # instructions per shard (chosen by us: ~45 MB of IR, one opt+llc of a few minutes)
    shards, cur_s, n = [], [], 0
    for p, c in specs:
        cur_s.append(p); n += c
        if n >= target: shards.append(cur_s); cur_s, n = [], 0
    if cur_s: shards.append(cur_s)
    sd = os.path.join(out, 'shards'); os.makedirs(sd, exist_ok=True)
    print(f'{len(specs)} functions in {len(shards)} shards on {jobs} workers', flush=True)
    objs, t = [None] * len(shards), time.time()
    with ProcessPoolExecutor(jobs) as ex:
        #  10-03 (note): the shard jobs go to disk so another Mac with the SAME LLVM can take shards
        #    from the far end (remote_shards.py); a shard whose .o already exists is skipped by lift_shard's resume check.
        import pickle   # noqa: PLC0415
        if relift:
            gone = 0
            for k, ps in enumerate(shards):
                if any(int(os.path.basename(p_)[:-4], 16) in relift for p_ in ps) and os.path.exists(os.path.join(sd, f'shard{k:04d}.o')):
                    os.remove(os.path.join(sd, f'shard{k:04d}.o')); gone += 1
            print(f'invalidated {gone} shards for re-lift', flush=True)
        shard_jobs = [(k, ps, known, binds, aliases, nonabi, sd, cpu,
                       {a_: EHF[a_] for a_ in (int(os.path.basename(p_)[:-4], 16) for p_ in ps) if a_ in EHF}, thisret, noop,
                       {a_: stub_cc[a_] for a_ in (int(os.path.basename(p_)[:-4], 16) for p_ in ps) if a_ in stub_cc},
                       tuple(a_ for a_ in (int(os.path.basename(p_)[:-4], 16) for p_ in ps) if a_ in async_set))
                      for k, ps in enumerate(shards)]   #  not `jobs`: that is the worker count
        with open(os.path.join(out, 'jobs.pkl.tmp'), 'wb') as f_: pickle.dump(shard_jobs, f_)
        os.replace(os.path.join(out, 'jobs.pkl.tmp'), os.path.join(out, 'jobs.pkl'))
        futs = [ex.submit(lift_shard, j) for j in shard_jobs]; n_reused, n_built = 0, []
        for i, f in enumerate(futs):
            k, o, nf, dt, sz = f.result(); objs[k] = o
            if sz == -1: n_reused += 1
            else: n_built.append(k)
            if sz != -1 and (len(n_built) <= 20 or i == len(shards) - 1):
                print(f'  shard {k}: {nf} fns, {sz >> 20} MB IR, opt+llc {dt:.0f} s  [{i + 1}/{len(shards)} at {time.time() - t:.0f} s]', flush=True)
    print(f'shards: {n_reused} reused (IR identical), {len(n_built)} recompiled {n_built[:20]}', flush=True)
    # --- the global module: fnmap, dispatcher, native adapter, doors -----------------------------------------------------
    entry = None if bundle else mm['lo'] + mm['entryoff']
    #  10-03 dyld order: a library's initializers run AFTER its dependencies'. The translated C++ runtime (SUBST) depends
    #    on nothing translated and everything else may use iostreams/locale from it in a static initializer — it goes first.
    subst_paths = set(SUBST.values())
    lib_order = [i for i in images[1:] if i['orig'] in subst_paths] + [i for i in images[1:] if i['orig'] not in subst_paths]
    inits = [a for img in lib_order for a in img['inits']] + images[0]['inits']
    gm = [arm2x86._module_head().replace('define i64 @__arm2x86_call_arm(', 'define linkonce_odr i64 @__arm2x86_call_arm(')]
    fnmap = {a: f'fn_{a:x}' for a in known}
    thunked = set()   #  10-03: one thunk per SYMBOL, not per stub — the exe and a library both import modf (opt refused the dup)
    declared = set()
    for a, b in binds.items():
        if arm2x86.bind_is_fp(b):
            if b['sym'] not in thunked:
                gm.append(arm2x86.bind_thunk(b['sym'], b['ret'], arm2x86.bind_kinds(b))); thunked.add(b['sym'])
                #  10-03: the thunk CALLS the native function, which was never declared here — 46 of them (cos, pow,
                #    CACurrentMediaTime, AudioUnitSetParameter, ...); opt refused the module. Declared with the bind's signature.
                if b['sym'] not in declared:
                    gm.append(f'declare {b["ret"]} @{b["sym"]}({", ".join(arm2x86.BIND_TY[c] for c in arm2x86.bind_kinds(b))}){_rt(b["sym"])}')
                    declared.add(b['sym'])
            fnmap[a] = f'__arm2x86_bindthunk_{b["sym"]}'
        else:
            fnmap[a] = b['sym']
    for a, nm in sorted(fnmap.items()):
        if nm.startswith('fn_'): gm.append(f'declare {ABI_RET} @{nm}({arm2x86.ABI_PARAMS})')
        elif nm not in declared and not nm.startswith('__arm2x86_bindthunk_'):
            b = binds[a]; gm.append(f'declare {b["ret"]} @{nm}({", ".join(arm2x86.BIND_TY[c] for c in arm2x86.bind_kinds(b))}){_rt(nm)}')
            declared.add(nm)
    rows = ', '.join(f'{{ i64, ptr }} {{ i64 {a}, ptr @{n} }}' for a, n in sorted(fnmap.items()))
    gm.append(f'@__arm2x86_fnmap = constant [{len(fnmap)} x {{ i64, ptr }}] [{rows}]')
    gm.append(f'@__arm2x86_fnmap_n = constant i64 {len(fnmap)}')
    #  rung 1 WHICH NATIVE ADDRESSES THE INTERPRETER MUST ENTER THROUGH THE REGISTER FILE. A bridge
    #    wrapper takes no arguments and returns nothing (the rf=1 binds routed through CXX above), so
    #    entering one through the native adapter hands it garbage. interp/host_facts.c answers
    #    a64_is_rf_callee from this table.  interp/rf_table.h cannot: it names all 214 wrappers and only
    #    the ones THIS image binds are emitted, so linking it would leave the rest undefined (the TLV
    #    probe binds 4 natives). Every symbol here was already declared by the fnmap loop above.
    rfc = sorted({b['sym'] for b in binds.values() if b.get('rf')})
    gm.append(f'@__arm2x86_rfcallees = constant [{len(rfc)} x ptr] '
              f'[{", ".join(f"ptr @{s}" for s in rfc)}]' if rfc else
              '@__arm2x86_rfcallees = constant [0 x ptr] zeroinitializer')
    gm.append(f'@__arm2x86_rfcallees_n = constant i64 {len(rfc)}')
    #  10-21 the swifttailcc entries (see abi_scan.async_entries): shim_comp.c / the callback door binary-search this
    gm.append(f'@__arm2x86_async_entries = constant [{len(ae_)} x i64] [{", ".join(f"i64 {a_}" for a_ in ae_)}]' if ae_ else
              '@__arm2x86_async_entries = constant [0 x i64] zeroinitializer')
    gm.append(f'@__arm2x86_async_entries_n = constant i64 {len(ae_)}')
    print(f'async entries: {len(ae_)} guest functions are entered with the Swift async convention (callback trampolines return retq $8)')
    #  10-10 A BUNDLE/DYLIB IS ENTERED THROUGH ITS EXPORTS, so each one needs an x86 symbol of the same name that
    #    hands control to the translated body — and therefore an `x_fn_` door, exactly like the entry point and the
    #    initializers. dyld_info already gave us name -> address (img['exports'], collected for every image).
    #     LIMITS, SAID OUT LOUD: the wrapper forwards the six INTEGER registers x86-64 passes in registers and
    #    nothing else — a floating-point argument, a 7th+ integer argument, or a struct by value is NOT forwarded.
    #    Every export of proxy.bundle (the image this was built for) is pointer/integer only; check a new bundle
    #    before trusting it. A native thread calling in has never run translated code, so it needs an arm64 stack
    #    first — the same reason the callback door calls __arm2x86_ensure_stack.
    #     A PROGRAM may need this too: opendirectoryd exports 1,145 symbols and its OpenDirectory modules bind to
    #    them, so a translated module cannot resolve od_release / odproplist_* / odrequest_* unless the translated
    #    host exports them as real x86 symbols. It is opt-in (ARM2X86_EXPORTS=1) because publishing a program's
    #    whole export table could shadow a native symbol of the same name in an unrelated program.
    exp_wrap, exp_addrs = [], []
    #  The LINKER owns a few of these names, and the export trie of a PROGRAM lists them. `_main` is a lifted
    #    FUNCTION, so filtering only the data exports still produced `main(unsigned long, ... x6)` —
    #    "too many parameters (6) for 'main'". __mh_execute_header collides with the linker's own definition.
    RESERVED = {'__mh_execute_header', '__mh_dylib_header', '__mh_bundle_header', '_main',
                '_NXArgc', '_NXArgv', '_environ', '___progname', 'dyld_stub_binder'}
    if bundle or os.environ.get('ARM2X86_EXPORTS') == '1':
        for nm, a in sorted(images[0]['exports'].items()):
            if a not in known or nm in RESERVED: continue
            exp_addrs.append(a)
            c = nm[1:] if nm.startswith('_') else nm
            exp_wrap.append(
                f'unsigned long {c}(unsigned long a0, unsigned long a1, unsigned long a2, unsigned long a3, '
                f'unsigned long a4, unsigned long a5) {{ __arm2x86_ensure_stack(); '
                f'return x_fn_{a:x}(a0, a1, a2, a3, a4, a5, 0, 0); }}')
        # a DATA export is not a function: resolve it to its address inside the mapped guest image (see xlat.py)
        data_ex = sorted((n, a) for n, a in images[0]['exports'].items()
                         if a not in known and n not in RESERVED)
        for nm, a in data_ex:
            s = nm if nm.startswith('_') else '_' + nm
            gm.append(f'module asm ".globl {s}"'); gm.append(f'module asm "{s} = 0x{a:x}"')
        print(f'exports: {len(exp_wrap)} functions wrapped, {len(data_ex)} data symbols at their guest address'
              + (f' {[n for n, _ in data_ex][:5]}' if data_ex else ''))
        #  10-21 A PLUG-IN IS REACHED THROUGH ITS ObjC CLASSES, NOT ITS EXPORTS. Calendar's and System Settings'
        #    .docktileplugin export nothing: the Dock loads the bundle and asks for its NSPrincipalClass by name, and
        #    __arm2x86_objc_register (below) publishes every guest class at load. "No export" refused both. Only an
        #    image with no export AND no class, category or Swift record is truly unreachable.
        osec = images[0]['osec']
        runtime_reach = any(osec[k_][1] for k_ in ('__objc_classlist', '__objc_catlist', '__swift5_proto', '__swift5_types'))
        if bundle and not exp_wrap and not data_ex and not runtime_reach:
            raise SystemExit('a bundle/dylib with no export and no ObjC/Swift class is unreachable — refusing')
    for a in sorted(set(([entry] if entry is not None else []) + inits + exp_addrs)):
        if a in known: gm.append(arm2x86.export(f'x_fn_{a:x}', a, 8))
    gm.append(NATIVE_ADAPTER_IR); gm.append(xlat.CB_IR)
    for v in sorted(eh_abs):   #  10-03 a program-defined type_info, at its fixed arm64 address (see eh_ti above)
        gm.append(f'module asm ".globl ___arm2x86_ti_{v:x}"'); gm.append(f'module asm "___arm2x86_ti_{v:x} = 0x{v:x}"')
    gll = os.path.join(sd, 'global.ll'); open(gll, 'w').write('\n'.join(gm))
    subprocess.run([f'{LLVM}/opt', '-O2', gll, '-o', gll[:-3] + '.bc'], check=True)
    subprocess.run([f'{LLVM}/llc', '-mtriple=x86_64-apple-macosx', f'-mcpu={cpu}', '-filetype=obj', gll[:-3] + '.bc',
                    '-o', gll[:-3] + '.o'], check=True)
    objs.append(gll[:-3] + '.o')
    # --- host main.c ------------------------------------------------------------------------------------------------------
    kslots = []
    for a, s in sorted(slot_sym.items()):
        c = s[1:] if s.startswith('_') else s
        c = asm_map.get(c, c)   #  10-03 stat -> stat$INODE64 (x86_asm_names)
        if c in ('vm_page_size', 'vm_page_mask', 'vm_page_shift'): c = '__arm2x86_id_' + c
        if c == '_tlv_bootstrap': c = '__arm2x86_tlv_get'
        if c == '__cxa_throw': c = '__arm2x86_cxa_throw'   #  the destructor goes through a native trampoline
        if c == '__chkstk_darwin': c = '__arm2x86_chkstk_darwin'   #  10-03 an INDIRECT call: the x0-preserving no-op, never x86's
        if c == 'objc_retainBlock': c = '__arm2x86_objc_retainBlock'   #  10-17 libobjc copies the block natively (objc_bridge.c)
        kslots.append(f'  {{0x{a:x}UL, "{c}", 0x{slot_add[a]:x}UL}}')
    umbrella = open(os.path.join(S, 'sigdb_umbrella.c')).read()
    per_image = []
    for img in images:
        o = img['osec']; tv, td, tb = img['tlv']
        if o['__objc_selrefs'][1]:
            per_image.append(f'    selrefs(0x{o["__objc_selrefs"][0]:x}UL, 0x{o["__objc_selrefs"][1]:x}UL, ps);')
        #  10-21 SWIFT TYPES MUST BE REGISTERED BEFORE THE CLASSES ARE REALIZED. objc_register now hands each
        #    guest Swift class to _objc_realizeClassFromSwift, so the runtime treats it as a real Swift class and will
        #    complete its metadata — and completing it needs THIS image's own types, which the runtime only learns from
        #    the __swift5_* records registered below. Registered afterwards, it cannot resolve them and a field's
        #    TypeLayout comes back size 0 / stride 0 / flags 0x00400000 (ValueWitnessFlags::Incomplete). Measured: the
        #    Dock, WindowManager and ControlCenter all died in _swift_updateClassMetadataImpl+0x1a7 reading [r14+8]
        #    with r14 = 0x80080000 (0x88080000 in ControlCenter), and fieldTypes[4] was VWT+0x40 of such a type.
        if any(o[k_][1] for k_ in ('__swift5_proto', '__swift5_types', '__swift5_protos')):
            per_image.append(f'    __arm2x86_swift_register(0x{o["__swift5_proto"][0]:x}UL, 0x{o["__swift5_proto"][1]:x}UL, '
                             f'0x{o["__swift5_types"][0]:x}UL, 0x{o["__swift5_types"][1]:x}UL, '
                             f'0x{o["__swift5_protos"][0]:x}UL, 0x{o["__swift5_protos"][1]:x}UL);')
        #  10-22 PROTOCOLS BEFORE CLASSES: a class's protocol list is resolved by name (objc_getProtocol), so a guest-only
        #    protocol must already be registered when its conforming class is (objc_bridge.c __arm2x86_objc_protocols).
        if o.get('__objc_protolist', (0, 0))[1] or o.get('__objc_protorefs', (0, 0))[1]:
            per_image.append(f'    __arm2x86_objc_protocols(0x{o["__objc_protolist"][0]:x}UL, 0x{o["__objc_protolist"][1] // 8:x}UL, '
                             f'0x{o["__objc_protorefs"][0]:x}UL, 0x{o["__objc_protorefs"][1] // 8:x}UL);')
        per_image.append(f'    __arm2x86_objc_register(0x{o["__objc_classlist"][0]:x}UL, 0x{o["__objc_classlist"][1] // 8:x}UL, '
                         f'0x{o["__objc_catlist"][0]:x}UL, 0x{o["__objc_catlist"][1] // 8:x}UL, 0x{o["__objc_classrefs"][0]:x}UL, '
                         f'0x{o["__objc_classrefs"][1] // 8:x}UL, 0x{o["__objc_superrefs"][0]:x}UL, 0x{o["__objc_superrefs"][1] // 8:x}UL);')
        #  10-20 THE NATIVE SWIFT RUNTIME NEVER SAW THE GUEST IMAGE. It learns a program's conformances, types and
        #    protocols from dyld's add-image callback over each loaded Mach-O's __swift5_proto / __swift5_types /
        #    __swift5_protos — and a guest image is mapped by the shim, not by dyld. eslogger, measured on macOS 27:
        #    "unable to demangle the type of field '_common' … subject type x does not conform to protocol
        #    ParsableArguments", then a nil metadata read at -8. Registered here, the way dyld would, before any initializer.
        if tv and tv[1]:
            parts = [x for x in (td, tb) if x and x[1]]
            lo_t = min(x[0] for x in parts); hi_t = max(x[0] + x[1] for x in parts)
            tdsz = (td[0] + td[1] - lo_t) if td and td[1] else 0
            per_image.append(f'    __arm2x86_tlv_register(0x{tv[0]:x}UL, {tv[1] // 24}UL, 0x{lo_t:x}UL, 0x{tdsz:x}UL, 0x{hi_t - lo_t:x}UL);')
    skipped = [a for a in inits if a not in known]
    if skipped: raise SystemExit(f'{len(skipped)} initializers are not lifted functions (first {[hex(a) for a in skipped[:5]]}) — refusing')
    initcalls = '\n'.join(f'    x_fn_{a:x}((unsigned long)argc, (unsigned long)argv, (unsigned long)envp, (unsigned long)apple, 0, 0, 0, 0);'
                          for a in inits if a in known)
    xdecl = '\n'.join(f'extern unsigned long x_fn_{a:x}(unsigned long, unsigned long, unsigned long, unsigned long, '
                      f'unsigned long, unsigned long, unsigned long, unsigned long);'
                      for a in sorted(set(([entry] if entry is not None else []) + inits + exp_addrs)) if a in known)
    if bundle:
        #  10-10 no entry point: the start-up work runs from a constructor. Priority 102 puts it AFTER xlat_self
        #    (101, which sets ARM_IMAGE/ARM_FIXUPS and re-execs the loader) and after the shim has mapped the arm
        #    image, which is the same order main() gave it. On Darwin a constructor is called with the same
        #    (argc, argv, envp, apple) main gets, so the initializer calls below are unchanged.
        tailc = ('    return 0;\n}\n'
                 '__attribute__((constructor(102))) static void arm2x86_boot(int argc, char **argv, char **envp, char **apple) {\n'
                 #  10-21 A BUNDLE REACHES GUEST CODE FROM HERE, BEFORE THE GUEST STACK EXISTS.
                 #    shim_comp.c's boot() publishes __arm_sp and installs the crash handler, but it is an
                 #    UNPRIORITISED constructor, so dyld runs it AFTER this one (102). A dylib that reaches
                 #    guest code during its own initializers (ObjC +load, class setup) therefore ran with
                 #    __arm_sp == 0. Measured on translated libLaunchServicesSupport: fn_20104416c+154,
                 #    `mov [r12-0x20], r15` with r12 = 0, faulting at -32 — and WITNESS-FREE, because
                 #    crash_bt was not installed yet either. Both calls are idempotent, so a program
                 #    (where boot() has already run) is unaffected.
                 '    extern void __arm2x86_ensure_stack(void); extern void crash_bt_install(void);\n'
                 '    crash_bt_install(); __arm2x86_ensure_stack();\n'
                 '    arm2x86_start(argc, argv, envp, apple);\n}\n'
                 '/* the exports: an x86 symbol per arm64 export, forwarding into the translated body */\n'
                 + '\n'.join(exp_wrap))
    else:
        tailc = (f'    unsigned long rc = x_fn_{entry:x}((unsigned long)argc, (unsigned long)argv, '
                 f'(unsigned long)envp, (unsigned long)apple, 0, 0, 0, 0);\n'
                 '    exit((int)rc);\n}\n'
                 'int main(int argc, char **argv, char **envp, char **apple) {\n'
                 '    return arm2x86_start(argc, argv, envp, apple);\n}'
                 #  a program that publishes its exports (ARM2X86_EXPORTS) must EMIT the wrappers too — they were
                 #    computed and then dropped here, so opendirectoryd linked with 512 doors and exported none of them
                 + ('\n/* the exports: an x86 symbol per arm64 export, for a plugin to bind to */\n'
                    + '\n'.join(exp_wrap) if exp_wrap else ''))
    #  10-10 how the image finds ITSELF, and how it gets mapped.
    #    A PROGRAM is its own executable, and it publishes ARM_IMAGE/ARM_FIXUPS for the shim's own initializer to read.
    #     A BUNDLE cannot do either: _NSGetExecutablePath names the HOST process, and ARM_IMAGE is already set by
    #    that host for its own image, so the old `if (getenv("ARM_IMAGE")) return;` made the bundle map nothing at all
    #    (measured: 14 opendirectoryd launches, 14 host [shim] blocks, not one line from proxy). A bundle finds its
    #    own file with dladdr on a symbol it defines, and maps itself by calling the loader directly.
    if bundle:
        selfpath = ('    {\n'
                    '        Dl_info di_;\n'
                    '        if (!dladdr((const void *)&xlat_self, &di_) || !di_.dli_fname) return;\n'
                    '        snprintf(p, sizeof p, "%s", di_.dli_fname);\n'
                    '    }')
        selfload = ('    /* map our own guest image now — the host already consumed ARM_IMAGE for its own */\n'
                    #  v and fx are COLON-SEPARATED LISTS (self + each sidecar), exactly what a program
                    #    publishes in ARM_IMAGE/ARM_FIXUPS. load_one takes ONE image, so passing the whole
                    #    string meant the libc++ sidecar was never loaded and its chained fixups never
                    #    applied — its vtables read 0 and the first virtual call in DoIOSInit dispatched to
                    #    0. load_list reuses the same splitter boot() uses.
                    '    { extern void __arm2x86_load_list(const char *, const char *, const char *);\n'
                    '      __arm2x86_load_list(v, fx, 0); }')
    else:
        #  10-20 An ARM_IMAGE already in the environment is honoured ONLY if it names this executable. A child of a
        #    translated parent used to inherit the parent's list and map the PARENT's images (SetupAssistantSpringboard
        #    under loginwindow: "already mapped at 0x101000000", abort, login stuck at 60%). The shim now also clears the
        #    variables once consumed; this guard covers children of parents built before that.
        selfpath = ('    uint32_t n = sizeof p; if (_NSGetExecutablePath(p, &n) != 0) return;\n'
                    '    { const char *ai = getenv("ARM_IMAGE"); char me[4096];\n'
                    '      if (ai && realpath(p, me) && !strncmp(ai, me, strlen(me)) && (ai[strlen(me)] == 0 || ai[strlen(me)] == 0x40 || ai[strlen(me)] == 0x3a)) return; }')
        selfload = '    setenv("ARM_IMAGE", v, 1); setenv("ARM_FIXUPS", fx, 1);'
    rsv = hi_all - mm['lo']
    libnames = [i['name'] + '.arm64' for i in images[1:]]
    #  one fixup table PER IMAGE, applied as that image is mapped (the loader refuses an image with data and no table)
    blobs = []
    for k, img in enumerate(images):
        lo_i, hi_i = img['m']['lo'], img['m']['hi']
        mine = [(a, v) for a, v in recs if lo_i <= a < hi_i]
        blobs.append(f'static const unsigned long long kFix{k}[] = {{ ' + ', '.join([f'0x{len(mine):x}ULL'] + [f'0x{a:x}ULL, 0x{v:x}ULL' for a, v in mine]) + ' };')
    if sum(1 for a, _ in recs if not any(i['m']['lo'] <= a < i['m']['hi'] for i in images)): raise SystemExit('a fixup lies outside every image')
    libarr = ', '.join('"' + l + '"' for l in libnames) or '0'
    #  10-10 the LC_LOAD_DYLIB / LC_RPATH lists every translated image carries, for the runtime dlopen pass
    #    (kDylibs). A dep that WE replaced (SUBST, e.g. the vendor libc++) or that we TRANSLATED (it is one of
    #    `images`, so the rebased copy is already mapped) must NOT pull its native twin into the process.
    translated = {img['orig'] for img in images} | {img['m']['id'] for img in images if img['m']['id']}
    dylibs, rpaths = [], []
    for img in images:
        for dep in img['m']['deps']:
            if dep in SUBST or dep in translated or os.path.basename(dep) in {os.path.basename(t) for t in translated}: continue
            #  10-20 libc++abi and libunwind are deliberately NOT translated (the same skip as the image walk
            #    above), but this list still asked dyld to dlopen them — and the vendor libc++ names them through
            #    ITS own @rpath (@loader_path/../unwind), which does not exist in an installed .app. Translated
            #    Finder therefore opened with two scary lines and "2 of 126 dependencies did not load" every run,
            #    for libraries that were already in the process natively (binds reported 0 symbols MISSING).
            #    A check that cries wolf is one nobody reads the day it means something.
            if re.search(r'/lib(c\+\+abi|unwind)[.\d]*\.dylib$', dep): continue
            if dep not in dylibs: dylibs.append(dep)
        for rp in img['m']['rpaths']:
            if rp not in rpaths: rpaths.append(rp)
    dylib_c = ''.join(f'"{d}", ' for d in dylibs)
    rpath_c = ''.join(f'"{r}", ' for r in rpaths)
    print(f'deps: {len(dylibs)} dependencies dlopened at start-up, {len(rpaths)} rpath(s)')
    mainc = f'''/* generated by xlat2.py for {os.path.basename(exe)} — do not edit */
{umbrella}
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <err.h>
#include <wchar.h>
#include <dlfcn.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <objc/runtime.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach/machine.h>
#include <libkern/OSByteOrder.h>
extern __thread unsigned long __arm_sp;
__attribute__((section("__ARMRSV,__rsv,zerofill"), used)) static char arm2x86_rsv[0x{rsv:x}UL];
char *const __arm2x86_rsv_base = arm2x86_rsv;
const unsigned long __arm2x86_rsv_len = sizeof arm2x86_rsv;
static void arm_va(va_list ap) {{ ap[0].gp_offset = 48; ap[0].fp_offset = 176; ap[0].overflow_arg_area = (void *)__arm_sp; ap[0].reg_save_area = NULL; }}
{xlat.CB_C}
{chr(10).join(thunks)}
static const struct {{ unsigned long slot; const char *sym; unsigned long add; }} kSlots[] = {{
{(',' + chr(10)).join(kslots)}
}};
/* 10-10 THE IMAGE'S OWN DEPENDENCIES MUST BE IN THE PROCESS BEFORE A SINGLE SYMBOL IS BOUND — that is what dyld
   does, and the slot loop below is our dyld.  WAS: dlsym(RTLD_DEFAULT, ...) against whatever the LINK happened to pull
   in, which is only the PUBLIC frameworks and /usr/lib (see the -framework/-l list in the link step). macOS 27 ships NO
   on-disk stub for a PrivateFramework, so the linker cannot name one — measured on 27's loginwindow: 145 of its 1063
   imports stayed at slot 0 (LFSM*, DisplayServices*, FMM*, CP_*, Swift FileVault) and the first call through one of them
   died in __arm2x86_unimplemented, ALTHOUGH the x86_64 dyld cache exports 1060 of the 1063 (probe: dlopen 82/83 ok,
   dlsym 1060 ok / 3 missing — the 3 are AppleInternal TapToRadarKit classes, which are soft-linked and absent on every
   shipping Mac). dlopen by PATH reaches a cache-only dylib, so loading the LC_LOAD_DYLIB list closes the whole gap. */
static const char *const kDylibs[] = {{ {dylib_c}NULL }};
static const char *const kRpaths[] = {{ {rpath_c}NULL }};
static int dl_try(const char *p) {{ return dlopen(p, RTLD_LAZY | RTLD_GLOBAL) != NULL; }}
static int dl_dep(const char *d, const char *exedir) {{
    char b[2048];
    if (d[0] != '@') return dl_try(d);
    /* @executable_path and @loader_path are the same directory for a main executable. */
    if (!strncmp(d, "@executable_path/", 17) || !strncmp(d, "@loader_path/", 13)) {{
        snprintf(b, sizeof b, "%s/%s", exedir, strchr(d + 1, '/') + 1); return dl_try(b);
    }}
    if (!strncmp(d, "@rpath/", 7)) {{
        for (unsigned i = 0; kRpaths[i]; i++) {{
            const char *r = kRpaths[i]; char rb[1024];
            if (!strncmp(r, "@executable_path/", 17) || !strncmp(r, "@loader_path/", 13))
                snprintf(rb, sizeof rb, "%s/%s", exedir, strchr(r + 1, '/') + 1);
            else if (r[0] == '@') continue;
            else snprintf(rb, sizeof rb, "%s", r);
            snprintf(b, sizeof b, "%s/%s", rb, d + 7);
            if (dl_try(b)) return 1;
        }}
    }}
    return 0;
}}
{xdecl}
void __arm2x86_tlv_register(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
void __arm2x86_swift_register(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
void __arm2x86_objc_register(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
void __arm2x86_objc_protocols(unsigned long, unsigned long, unsigned long, unsigned long);
unsigned long __arm2x86_cb_unwrap(unsigned long t) {{
    unsigned long b = (unsigned long)__arm2x86_cb_slots;
    return (t >= b && t < b + 16UL * {xlat.CB_SLOTS} && (t - b) / 16 < cb_n) ? cb_fn[(t - b) / 16] : t;
}}
static void selrefs(unsigned long lo, unsigned long len, unsigned long ps) {{
    for (unsigned long p = lo; p < lo + len; p += 8) {{
        void *pg = (void *)(p & ~(ps - 1)); mprotect(pg, ps, PROT_READ | PROT_WRITE);
        *(SEL *)p = sel_registerName(*(const char **)p);
    }}
}}
static int arm2x86_start(int argc, char **argv, char **envp, char **apple) {{
    unsigned long ps = (unsigned long)sysconf(_SC_PAGESIZE);
    unsigned missing = 0;
    /* load the image's own dependencies FIRST (see kDylibs). A dependency that will not load is reported, never
       swallowed: a weak or AppleInternal one is legitimately absent, a real one is the reason a later bind is 0. */
    char exepath[2048]; uint32_t exesz = (uint32_t)sizeof exepath;
    if (_NSGetExecutablePath(exepath, &exesz) != 0) exepath[0] = 0;
    char exedirbuf[2048]; snprintf(exedirbuf, sizeof exedirbuf, "%s", exepath);
    const char *exedir = exepath[0] ? dirname(exedirbuf) : ".";
    unsigned dlok = 0, dlfail = 0;
    for (unsigned i = 0; kDylibs[i]; i++) {{
        if (dl_dep(kDylibs[i], exedir)) {{ dlok++; continue; }}
        if (dlfail++ < 20) fprintf(stderr, "[xlat2] dependency %s did not load: %s\\n", kDylibs[i], dlerror());
    }}
    if (dlfail) fprintf(stderr, "[xlat2] %u of %u dependencies did not load\\n", dlfail, dlok + dlfail);
    for (unsigned i = 0; i < sizeof kSlots / sizeof kSlots[0]; i++) {{
        void *p = dlsym(RTLD_DEFAULT, kSlots[i].sym);
        if (!p) {{ if (missing++ < 20) fprintf(stderr, "[xlat2] import %s has no native definition — its slot stays 0\\n", kSlots[i].sym); continue; }}
        void *pg = (void *)(kSlots[i].slot & ~(ps - 1));
        if (mprotect(pg, ps, PROT_READ | PROT_WRITE) != 0) {{ perror("[xlat2] mprotect GOT"); return 120; }}
        *(unsigned long *)kSlots[i].slot = (unsigned long)p + kSlots[i].add;
    }}
    if (missing) fprintf(stderr, "[xlat2] %u imports have no native definition\\n", missing);
{chr(10).join(per_image)}
{initcalls}
{tailc}
{chr(10).join(blobs)}
static const unsigned long long *const kFixAll[] = {{ {', '.join(f'kFix{k}' for k in range(len(images)))} }};
const unsigned long long *const *const __arm2x86_fixups_blobs = kFixAll;
__attribute__((constructor(101))) static void xlat_self(void) {{
    char p[4096];
{selfpath}
    char rp[4096]; if (!realpath(p, rp)) return;
    int fd = open(rp, O_RDONLY); if (fd < 0) return;
    struct fat_header fh; unsigned long long off = 0;
    if (pread(fd, &fh, sizeof fh, 0) == sizeof fh && OSSwapBigToHostInt32(fh.magic) == FAT_MAGIC) {{
        uint32_t na = OSSwapBigToHostInt32(fh.nfat_arch);
        for (uint32_t i = 0; i < na; i++) {{ struct fat_arch fa;
            if (pread(fd, &fa, sizeof fa, sizeof fh + i * sizeof fa) != sizeof fa) break;
            if ((cpu_type_t)OSSwapBigToHostInt32((uint32_t)fa.cputype) == CPU_TYPE_ARM64) {{ off = OSSwapBigToHostInt32(fa.offset); break; }} }}
    }}
    close(fd);
    if (!off) {{ fprintf(stderr, "[xlat2] %s has no arm64 slice — nothing to run\\n", rp); return; }}
    static const char *libs[] = {{ {libarr} }};
    char dir[4096]; strncpy(dir, rp, sizeof dir - 1); dir[sizeof dir - 1] = 0; char *d = dirname(dir);
    static char v[65536]; snprintf(v, sizeof v, "%s@%llu", rp, off);
    static char fx[4096]; strcpy(fx, "@embedded0");
    for (unsigned i = 0; i < {len(libnames)}; i++) {{
        size_t l = strlen(v); snprintf(v + l, sizeof v - l, ":%s/MacOS-arm2x86/%s", d, libs[i]);
        size_t f2 = strlen(fx); snprintf(fx + f2, sizeof fx - f2, ":@embedded%u", i + 1);
    }}
{selfload}
}}
'''
    mp = os.path.join(out, 'main.c'); open(mp, 'w').write(mainc)
    # --- link ---------------------------------------------------------------------------------------------------------------
    linkfw, libs = [], []
    for img in images:
        for dep in img['m']['deps']:
            if dep in SUBST or dep in translated:
                continue
            #  10-20 macOS 27's afinfo/afconvert/afclip link AudioToolboxCore, a PRIVATE framework; typed binds
            #    reference _AudioFileOpenURL directly and ld refused them. The SDK ships .tbd stubs for 2,201 private
            #    frameworks, so they link the same way (-F below); one with no stub is dropped by the retry loop.
            mfw = re.match(r'/System/Library/(?:Private)?Frameworks/(\w+)\.framework/', dep)
            if mfw and mfw.group(1) not in linkfw: linkfw.append(mfw.group(1))
            ml = re.match(r'/usr/lib/lib([\w+-]+?)(\.[\d.]+)?\.dylib$', dep)
            if ml and ml.group(1) not in ('System', 'objc', 'c++') and '-l' + ml.group(1) not in libs: libs.append('-l' + ml.group(1))
    fl = os.path.join(out, 'objs.txt'); open(fl, 'w').write('\n'.join(objs) + '\n')
    xe = os.path.join(out, os.path.basename(exe) + '.x86')
    #  10-10 a bundle is linked with -bundle and stays position-independent; -no_pie/-image_base are for the
    #    program case only. __ARMRSV still has to land exactly on the arm image's base — that is the reservation the
    #    shim maps the guest into — so the segaddr is kept in both cases.
    kind = (['-dynamiclib', '-Wl,-install_name,' + (mm['id'] or exe)] if mm['filetype'] == 6 else
            ['-bundle'] if bundle else ['-Wl,-no_pie', '-Wl,-image_base,0x400000000',
                                        '-Wl,-stack_size,' + os.environ.get('ARM2X86_STACK', '0x3C00000')])
    #  10-20 THE DEFAULT 8 MB MAIN-THREAD STACK IS NOT ENOUGH FOR TRANSLATED CODE. Dock and SystemUIServer both died
    #    in ___chkstk_darwin at the SAME fault address having used all 8 MB (0x7ff7bff00000 - 0x7ff7bf700000 = 0x800000),
    #    so macOS 27 came up with no Dock. A lifted frame carries the materialised register file, so it is far wider than
    #    the arm64 frame it replaces and the depth the app expects no longer fits.
    #  LC_MAIN's stacksize (ld64 -stack_size) is what dyld gives the main thread; it is reserved address space, paid for
    #    only as it is touched. 0x3C00000 = 60 MB, under the box's 65532 KB RLIMIT_STACK hard limit — above that the
    #    kernel clamps it back and the bigger stack silently does not happen. Secondary threads are NOT covered by this.
    if exp_wrap and not bundle: kind.append('-Wl,-export_dynamic')   # a plugin must be able to bind to them
    #  10-20 ld refused every macOS 27 HID plug-in ("Shared cache eligible dylibs cannot use -undefined
    #    dynamic_lookup"): it judges a /System/Library image cache-eligible. A translated image never goes in the
    #    shared cache, so opt it out rather than drop the dynamic lookup the shim's binds rely on.
    if mm['filetype'] == 6 or bundle: kind.append('-Wl,-not_for_dyld_shared_cache')
    #  10-20 METADATA THAT NATIVE CODE READS OFF THE RUNNING SLICE WAS LEFT BEHIND IN THE arm64 ONE. A command-line
    #    tool's Info.plist is `__TEXT,__info_plist` in its own executable, and CFBundleGetMainBundle reads it from the x86
    #    slice that is running: translated `hiutil -h` printed "hiutil version (null) ((null))", native "hiutil version 2.0
    #    (68)" — 82 of 268 macOS 27 sources carry one (launchctl, hdiutil, osascript, ssh-add …). Same for the sections
    #    the SYSTEM inspects by name on a main executable: `__TEXT,__launchd_plist` (launchd / ServiceManagement),
    #    `__RESTRICT,__restrict` (dyld: no DYLD_* variables — amfid, mdmclient) and `__CGPreLoginApp,__cgpreloginapp`
    #    (SkyLight: may connect before login — hidd, biometrickitd, PerfPowerServices). Copied byte for byte with ld's
    #    -sectcreate.  Not the tools' own data sections (`__TEXT,__launchctl` …): translated code reaches those at their
    #    arm64 addresses inside the guest image, never through the x86 header.
    for seg_, sect_ in (('__TEXT', '__info_plist'), ('__TEXT', '__launchd_plist'), ('__RESTRICT', '__restrict'),
                        ('__CGPreLoginApp', '__cgpreloginapp')):
        if (seg_, sect_) not in mm['sects']: continue
        _, sz_, off_ = mm['sects'][(seg_, sect_)]
        with open(main_thin, 'rb') as f_:
            f_.seek(off_); blob_ = f_.read(sz_) if sz_ else b''
        if len(blob_) != sz_: raise SystemExit(f'{main_thin}: {seg_},{sect_} is {sz_} bytes but only {len(blob_)} could be read')
        sp_ = os.path.join(out, f'sect{seg_}{sect_}.bin')
        with open(sp_ + '.tmp', 'wb') as f_: f_.write(blob_)
        os.replace(sp_ + '.tmp', sp_)
        kind.append(f'-Wl,-sectcreate,{seg_},{sect_},{sp_}')
        print(f'sectcreate: {seg_},{sect_} ({sz_} bytes) copied into the x86_64 image')
    base = ['xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=15.0', '-O1', '-w'] + kind + [
            f'-Wl,-segaddr,__ARMRSV,0x{mm["lo"]:x}', '-x', 'objective-c', mp, '-x', 'none',
            os.path.join(S, 'shim_comp.c'), os.path.join(S, 'identity.c'), os.path.join(S, 'objc_bridge.c'),
            os.path.join(S, 'tlv.c'), os.path.join(S, 'cxx_bridge.cpp'),
            os.path.join(S, 'callback_bridge.c'),
            #  10-11 sysreg_rt.c WAS IN NO LINK LINE AT ALL, so the R23/R38/R39 state it defines
            #    (__arm_tpidr2, __arm_svcr, __arm_sprr, __arm2x86_nofeature, __arm2x86_svc) existed only as
            #    `external` declarations in emitted IR: the first daemon to use `svc` or an arm system
            #    register would have failed to LINK, with the definitions sitting right there on disk. It
            #    collides with nothing (measured: no symbol in it is defined by any other linked file) and,
            #    now that the commpage moved to shim_comp.c, it registers no constructor — so a program that
            #    uses none of it links the same as before.
            os.path.join(S, 'sysreg_rt.c'),
            os.path.join(S, 'neon_rt.c'),   #  10-03: sha + the ldxr/stxr exclusive monitor live here; the game link refused without it
            #  rung 1 the interpreter (interp/, all 2,224 risu forms certified byte-identical to an M4).
            #    Behind ARM2X86_INTERP=1 for now: it changes what a MISSING translation does, so it is proven
            #    app by app before becoming the default. Linked unconditionally — a program that never misses
            #    links the same as before, and a program that does gets a report instead of a dead process.
            os.path.join(S, 'interp', 'a64_rt.c'),
            #  10-26 THESE TWO WERE IN NO LINK LINE and a64_rt.c calls into both, so every translated
            #    program failed to LINK (_a64_is_rf_callee, _a64_native_name, _a64_variadic_fixup) — the
            #    whole certifier gate, not one ruler. host.c answers those two questions for the generic
            #    host and CANNOT be linked here (it owns `main` and redefines __arm2x86_stack_args/_cbarg/
            #    _svc), so host_facts.c answers them for a translated image. Same shape as sysreg_rt.c.
            os.path.join(S, 'interp', 'host_facts.c'), os.path.join(S, 'interp', 'vararg.c'),
            os.path.join(S, 'interp', 'a64i.c'), os.path.join(S, 'interp', 'a64_util.c'),
            os.path.join(S, 'interp', 'a64_dpimm.c'), os.path.join(S, 'interp', 'a64_dpreg.c'),
            os.path.join(S, 'interp', 'a64_brsys.c'), os.path.join(S, 'interp', 'a64_ldst.c'),
            os.path.join(S, 'interp', 'a64_ldstruct.c'), os.path.join(S, 'interp', 'a64_fp.c'),
            os.path.join(S, 'interp', 'a64_fpsc.c'), os.path.join(S, 'interp', 'a64_simd.c'),
            os.path.join(S, 'interp', 'a64_simd3.c'), os.path.join(S, 'interp', 'a64_simdsh.c'),
            os.path.join(S, 'interp', 'a64_simdfp.c'), os.path.join(S, 'interp', 'a64_simdidx.c'),
            os.path.join(S, 'interp', 'a64_est.c'), os.path.join(S, 'interp', 'a64_crypto.c'),
            f'-Wl,-filelist,{fl}', '-lffi', '-lobjc', '-lc++', '-framework', 'Foundation', '-framework', 'AppKit',
            #  10-19 macOS 27's Finder has one function whose EH personality is `__swift_exceptionPersonality`,
            #    so the emitted IR references it and ld failed: `Undefined symbols for architecture x86_64`.
            #    It CANNOT be linked here: the symbol lives in /usr/lib/swift/libswiftCore.dylib, and this build
            #    runs on Apple silicon, whose libswiftCore has no x86_64 slice to link against. It does not need
            #    to be: MEASURED on a real arm64 Mac on the target's own build (27.0 / 26A5425a), libswiftCore AND
            #    the global namespace both export it, so it resolves at RUNTIME on the target — the same deal the
            #    cache-only dependencies above get (dlopened at start-up, never linked). -U allows exactly this
            #    one symbol to stay undefined; everything else still has to link.
            '-Wl,-U,__swift_exceptionPersonality']
    #  ARM2X86_LINK_DYLIB — colon-separated dylibs linked into the image, for host facts the
    #    translated program needs supplied. OPT-IN: unset, the link line is byte-for-byte what it was, so
    #    no existing target gains a dependency it could fail to find at run time.
    #     Interposing (`__DATA,__interpose`) is honoured from a LINKED dependency, not only from
    #    DYLD_INSERT_LIBRARIES — measured, because DYLD_* is ignored for an entitled agent such as
    #    MenuBarAgent, which is exactly the case this exists for.
    #    The install_name must be the path on the TARGET; the path given here is only the link-time copy.
    for _extra in [x for x in os.environ.get('ARM2X86_LINK_DYLIB', '').split(':') if x]:
        if not os.path.exists(_extra):
            raise SystemExit(f'ARM2X86_LINK_DYLIB: {_extra} does not exist')
        base.append(_extra)
        print(f'link dylib: {_extra} (install_name must exist on the target)')
    #  10-10 A macOS 27 DEPENDENCY MAY NOT BE LINKABLE AT ALL. The system ships no on-disk stub for a cache-only
    #    library and the SDK carries no .tbd for a private one, so `-lmis`, `-lCoreEntitlements`,
    #    `-lDetachedCertificates`, `-lMobileGestalt` (amfid) make ld fail outright. Those names are NOT needed at
    #    link time: every dependency is dlopened by path at start-up (kDylibs) and every import is bound through
    #    kSlots. So drop exactly the ones ld says it cannot find and link again — never drop one ld did not name.
    dropped = []
    #  10-21 the cap WAS `range(8)` and findmydevice-user-agent dropped exactly eight
    #    frameworks before falling out of the loop — the budget expired while the link line
    #    was still shrinking. Every surviving iteration drops at least one name (an iteration
    #    that names none raises below), so bound it by how many names there are to drop.
    for _ in range(len(libs) + len(linkfw) + 8):
        #  10-20 ARM2X86_EXTRA_DYLIBS: x86 dylibs every translated program must LOAD at launch (an LC_LOAD_DYLIB, which
        #    dyld always honours — DYLD_INSERT_LIBRARIES is ignored for a binary with private entitlements like loginwindow).
        #    The Mac Pro uses it for libm27resolve.dylib: its /private is a symlink standing in for Apple's firmlink, and
        #    Setup Assistant's /.resolve/33/ lookups (no symlinks allowed) failed there, so 27 decided setup never ran.
        extra = [p for p in os.environ.get('ARM2X86_EXTRA_DYLIBS', '').split(':') if p]
        cmd = (base + ['-F' + os.path.join(sh('xcrun', '--show-sdk-path').strip(), 'System/Library/PrivateFrameworks')]
               + [x for fw in linkfw for x in ('-framework', fw)] + libs + extra + ['-o', xe])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0: break
        #  ld words it three ways: "library 'X' not found" (no -l!), "library not found for -lX", and the
        #    framework equivalents. Matching only the -l spelling left amfid failing with the name right there.
        gone_l = (set(re.findall(r"library ['\"]-?l?([\w+.-]+)['\"] not found", r.stderr))
                  | set(re.findall(r'library not found for -l([\w+.-]+)', r.stderr)))
        gone_f = (set(re.findall(r"framework ['\"]([\w+.-]+)['\"] not found", r.stderr))
                  | set(re.findall(r'framework not found ([\w+.-]+)', r.stderr))
                  #  10-20 an allowable-clients list (SwiftUICore) refuses the link outright; like a missing
                  #    stub, the framework is still dlopened by path at start-up, so drop it from the LINK only.
                  | set(re.findall(r"cannot link directly with '([\w+.-]+)' because product being built is not an "
                                   r"allowed client", r.stderr)))
        if not gone_l and not gone_f:
            raise SystemExit(f'link failed and ld named no missing library:\n{r.stderr[-2000:]}')
        libs = [l for l in libs if l[2:] not in gone_l]
        linkfw = [f for f in linkfw if f not in gone_f]
        dropped += [f'-l{l}' for l in sorted(gone_l)] + [f'-framework {f}' for f in sorted(gone_f)]
    else:
        #  10-21 this used to print only `dropped` and swallow ld's own words, so the
        #    log ended at a list of removals with no statement of what ld objected to.
        raise SystemExit(f'link still failing after dropping {dropped}\n{r.stderr[-2000:]}')
    if dropped:
        print(f'link: {len(dropped)} dependencies are not linkable on this system (no stub/.tbd) and are reached only '
              f'through the start-up dlopen: {", ".join(dropped)}')
    uni = os.path.join(out, os.path.basename(exe))
    #  10-10 pair the translated x86_64 with the THIN arm64 slice, never with the original file: a macOS 27
    #    system binary is often ALREADY fat (x86_64 + arm64e — ReportCrash, osanalyticshelper, opendirectoryd), and
    #    `lipo -create` refuses two x86_64 slices ("duplicate architecture"). main_thin is the arm64/arm64e slice the
    #    shim actually reads, so it is also the right one to carry.
    subprocess.run(['lipo', '-create', xe, main_thin, '-output', uni + '.tmp'], check=True); os.replace(uni + '.tmp', uni)
    #  10-21 AN AD-HOC SIGNATURE DROPS THE ORIGINAL'S ENTITLEMENTS, AND WindowServer CHECKS THEM.
    #    Measured on the Dock: `CGSSetUniversalOwner(connection)` returned 1002 (kCGErrorInvalidConnection)
    #    and the Dock went straight to `exit(-1)` — it had none of the Dock's private windowserver
    #    entitlements, because `codesign -s -` writes a signature with no entitlement blob at all. Every
    #    translated system binary lost its privileges this way, so carry the original's over verbatim.
    ents = subprocess.run(['codesign', '-d', '--entitlements', '-', '--xml', exe],
                          capture_output=True, text=True).stdout
    sign = ['codesign', '-f', '-s', '-']
    if ents.lstrip().startswith('<'):
        ep = uni + '.entitlements.plist'
        with open(ep, 'w') as f:
            f.write(ents)
        sign += ['--entitlements', ep]
        print(f'entitlements: carried {ents.count("<key>")} keys from the original signature')
    else:
        print('entitlements: the original binary has none')
    #  10-21 AND IT DROPS THE ORIGINAL'S IDENTIFIER. `codesign -s -` names the binary `<name>-<cdhash>`, and
    #    the App Sandbox finds a process's container by that identifier: WallpaperAgent signed as
    #    `WallpaperAgent-5555…` died in libsystem_secinit right after `AppSandbox` with SIGILL (rc=132), and
    #    re-signed as `com.apple.wallpaper.agent` it ran on into its own code. Carry the identifier over too.
    ident = subprocess.run(['codesign', '-dv', exe], capture_output=True, text=True).stderr
    ident = next((l.split('=', 1)[1] for l in ident.splitlines() if l.startswith('Identifier=')), '')
    if ident:
        sign += ['-i', ident]
        print(f'identifier: carried {ident}')
    else:
        print('identifier: the original binary has none')
    subprocess.run(sign + [uni], check=True, capture_output=True)
    print(f'wrote {uni} + {len(libnames)} rebased libraries in {libdir}  ({time.time() - t_start:.0f} s total)')


if __name__ == '__main__':
    main(*sys.argv[1:])
