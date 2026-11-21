#!/usr/bin/env python3
"""mkrftable.py — generate interp/rf_table.h from xlat2.py's own symbol -> bridge-wrapper table.

A NATIVE SYMBOL IS NOT ALWAYS CALLED NATIVELY. Some have to go through the bridge instead: objc_alloc
   takes a GUEST class and the native runtime has never heard of it, objc_msgSend has to find the guest's
   method, swift_once takes a guest function pointer. xlat2 keeps that routing table and the per-app runtime
   bakes it in; the host needs the same table, so it is GENERATED from xlat2.py rather than retyped — a
   second copy would drift the moment either side learned a new symbol, and the failure would be a wrong
   call, not a build error.

These wrappers take no arguments and return nothing: they read and write the register file
   (__arm2x86_rf), which is why the host marshals into it before calling and reads x0/v0 back after.
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))

def _translator(name):
    # the translator sits in translator/ beside interp/ in this tree; a flat build copy keeps it one level up
    for cand in (os.path.join(HERE, '..', 'translator', name), os.path.join(HERE, '..', name)):
        if os.path.exists(cand):
            return cand
    return os.path.join(HERE, '..', 'translator', name)

X = _translator('xlat2.py')
src = open(X).read()

# '<symbol>': '<wrapper>' pairs, exactly as xlat2 writes them
pairs = dict(re.findall(r"'(_[A-Za-z0-9_$]+)':\s*'(__arm2x86[A-Za-z0-9_]*)'", src))

# The routing table is in two files. xlat.py carries its own RF dict for the message sends — objc_msgSend
#    and objc_msgSendSuper2 — and reading only xlat2.py left those bound natively: the native runtime then
#    could not find a guest method and the message went to forwarding, which raises
#    "unrecognized selector" from somewhere that looks nothing like the cause.
XL = _translator('xlat.py')
xsrc = open(XL).read()
m = re.search(r"RF = \{([^}]*)\}", xsrc)
if not m:
    sys.exit('mkrftable: xlat.py has no RF table any more — REFUSING rather than generating without the '
             'message sends, which would route them natively and fail far from here.')
for sym, fn in re.findall(r"'([A-Za-z0-9_$]+)':\s*'(__arm2x86[A-Za-z0-9_]*)'", m.group(1)):
    pairs['_' + sym] = fn

# the generated objc_retain_xN / objc_release_xN family: xlat2 builds those names in a loop
# one wrapper per N, and the _swift_ family too. The shared 'xin' handler reads register-file
#    slot 0, which is only the object when the per-app lifter has moved xN there first; the host interprets
#    and never moves it, so N != 0 retained the wrong pointer and N > 8 was not even carried. The wrapper's
#    own address is what a64_is_rf_callee keys on, so a distinct function per N is how N survives the call.
# _swift_* is not a rename of _objc_*: a native Swift object has its own refcount word and must go to
#    swift_retain/swift_release. Maps, for one, imports both families, x1 through x28.
pairs['_class_getMethodImplementation'] = '__arm2x86_rf_class_getMethodImplementation'
pairs['_method_getImplementation'] = '__arm2x86_rf_method_getImplementation'
pairs['_imp_implementationWithBlock'] = '__arm2x86_rf_imp_implementationWithBlock'
pairs['___chkstk_darwin'] = '__arm2x86_chkstk_noop'   # stack probe: a no-op, all registers preserved
# audit_token_t BY VALUE in imports sigdb has no header for (abi_audit.c). Generic-bound, the native
#    callee read the token off its own stack: MenuBarAgent saw every peer as LSAuditToken = 32 zero bytes and
#    refused every app's menus. Keyed on the type, so every interpreted daemon that names its peers is covered.
for s in ['audit_token_to_auid', 'audit_token_to_euid', 'audit_token_to_egid', 'audit_token_to_ruid',
          'audit_token_to_rgid', 'audit_token_to_pid', 'audit_token_to_asid', 'audit_token_to_pidversion',
          'audit_token_to_au32', 'tcc_credential_create_for_process_with_audit_token',
          '_LSCopyLSASNForAuditToken', 'sandbox_check_by_audit_token']:
    assert '_' + s not in pairs, s
    pairs['_' + s] = '__arm2x86_abi_at_' + s
for n in [k for k in range(29) if k != 18]:
    pairs[f'_objc_retain_x{n}']   = f'__arm2x86_objc_retain_x{n}'
    pairs[f'_objc_release_x{n}']  = f'__arm2x86_objc_release_x{n}'
    pairs[f'_swift_retain_x{n}']  = f'__arm2x86_swift_retain_x{n}'
    pairs[f'_swift_release_x{n}'] = f'__arm2x86_swift_release_x{n}'

# Host-only routes: private by-value-struct entry points only the interpreter needs (the per-app
#    translator table is kept unchanged). rf_host_extra.txt: one symbol<TAB>wrapper per line. A wrapper missing
#    from abi_structs_gen.c, or a symbol already routed, refuses the build (a silent native bind is the bug class).
_gen = open(os.path.join(HERE, "abi_structs_gen.c")).read() + open(os.path.join(HERE, "abi_hfa_gen.c")).read() + open(os.path.join(HERE, "abi_cfdate.c")).read() + open(os.path.join(HERE, "abi_rect2.c")).read() + open(os.path.join(HERE, "abi_sbx.c")).read() + open(os.path.join(HERE, "abi_swiftrepl.c")).read()
for _l in open(os.path.join(HERE, "rf_host_extra.txt")).read().splitlines():
    _l = _l.strip()
    if not _l or _l.startswith("#"): continue
    _s, _f = _l.split("	")
    if _s in pairs: sys.exit(f"mkrftable: {_s} is already routed to {pairs[_s]} — REFUSING a second route")
    if f"void {_f}(void)" not in _gen: sys.exit(f"mkrftable: {_f} is not in abi_structs_gen.c — REFUSING")
    pairs[_s] = _f
if len(pairs) < 100:
    sys.exit(f'mkrftable: only {len(pairs)} entries found in xlat2.py — the table shape must have changed, '
             f'and generating a short table would silently route symbols natively that must not be. REFUSING.')

out = [
    '// rf_table.h — GENERATED by interp/mkrftable.py from xlat2.py. Do not edit.',
    '//',
    '// Symbols that must go through the bridge instead of being called natively, with the wrapper for each.',
    '// The wrappers take no arguments and return nothing: they read and write __arm2x86_rf.',
    '#pragma once',
    '',
]
for sym, fn in sorted(pairs.items()):
    out.append(f'extern void {fn}(void);')
out += ['', 'static const struct { const char *sym; void (*fn)(void); } A64_RF_TABLE[] = {']
for sym, fn in sorted(pairs.items()):
    out.append(f'    {{ "{sym}", {fn} }},')
out += ['};', f'#define A64_RF_TABLE_N {len(pairs)}', '']

open(os.path.join(HERE, 'rf_table.h'), 'w').write('\n'.join(out) + '\n')
print(f'rf_table.h: {len(pairs)} symbols routed through the bridge')
