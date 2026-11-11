#!/usr/bin/env python3
"""Which OpenCore kernel patches written for macOS 26 can be carried to macOS 27, checked against both kernels.

    kernel_patches_27.py check <kernel 26> <kernel 27> [--kext <bundle id>=<binary 26>,<binary 27>]... <plist>... -o <out.json>
    kernel_patches_27.py --selftest

A PC with an AMD processor starts macOS only with a list of kernel patches, and every patch in such a list is bounded
by kernel version: one written for macOS 26 ends at 25.99.99, so the macOS 27 kernel starts without it and stops
before its first line. Raising the limit by hand works only if the patch still finds the same code. This tool answers
that per patch, and Golden Gate raises the limit only for the patches named in its output.

A patch is carried when, in the macOS 27 binary it names:
  - the symbol it starts from exists (when it names one),
  - its bytes are found as many times as it wants, the way OpenCore searches (from the symbol, within Limit bytes
    when Limit is not 0, with Mask),
  - a patch that changes every occurrence (Count 0) finds as many occurrences as in macOS 26,
  - and the occurrences it will change lie in the same named functions as in macOS 26.
Anything else is left out and the reason is printed. The same checks must pass in the macOS 26 binary first: a patch
that does not work on the system it was written for proves nothing.

A patch is named by mark(): a digest of what OpenCore matches on (not of what it writes, which holds the user's own
core count in one of them). The shell script computes the same digest from the user's config.
"""
import base64
import hashlib
import json
import os
import plistlib
import struct
import sys

DARWIN_26 = 25          # the kernel major of macOS 26; a patch must cover it to be considered at all
FIELDS = ("Identifier", "Base", "Find", "Mask", "Count", "Limit", "Skip")


def mark(p):
    """The digest of one patch entry. Data as base64 and numbers in decimal, as `plutil -extract ... raw` prints them;
    a key that is absent is an empty field. Joined with '|' and a trailing '|'."""
    out = []
    for k in FIELDS:
        v = p.get(k)
        if v is None:
            out.append("")
        elif isinstance(v, (bytes, bytearray)):
            out.append(base64.b64encode(bytes(v)).decode())
        elif isinstance(v, bool):
            out.append("true" if v else "false")
        else:
            out.append(str(v))
    return hashlib.sha256(("|".join(out) + "|").encode()).hexdigest()


def macho(path):
    """(bytes of the x86_64 image, [(vmaddr, filesize, fileoff)], {symbol: vmaddr})."""
    with open(path, "rb") as fh:
        b = fh.read()
    if struct.unpack_from(">I", b, 0)[0] in (0xCAFEBABE, 0xCAFEBABF):
        for i in range(struct.unpack_from(">I", b, 4)[0]):
            cpu, _, off, size, _ = struct.unpack_from(">IIIII", b, 8 + i * 20)
            if cpu == 0x01000007:
                b = b[off:off + size]
                break
        else:
            raise ValueError(f"{path}: no x86_64 part")
    magic, cpu = struct.unpack_from("<II", b, 0)
    if magic != 0xFEEDFACF or cpu != 0x01000007:
        raise ValueError(f"{path}: not a 64-bit Intel Mach-O")
    ncmds = struct.unpack_from("<I", b, 16)[0]
    segs, syms, off = [], {}, 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", b, off)
        if cmd == 0x19:
            vm, _vsz, fo, fsz = struct.unpack_from("<QQQQ", b, off + 24)
            segs.append((vm, fsz, fo))
        elif cmd == 0x2:
            so, ns, sto, _ = struct.unpack_from("<IIII", b, off + 8)
            for i in range(ns):
                strx, typ, _, _, val = struct.unpack_from("<IBBHQ", b, so + i * 16)
                if typ & 0x0E == 0x0E and strx:
                    e = b.index(b"\0", sto + strx)
                    syms[b[sto + strx:e].decode("latin1")] = val
        off += size
    return b, segs, syms


def offset_of(segs, vm):
    for a, fsz, fo in segs:
        if a <= vm < a + fsz:
            return fo + (vm - a)
    return None


def find_all(buf, start, end, find, mask):
    """Every offset in [start, end) where find matches under mask (an empty mask is all ones)."""
    n = len(find)
    if n == 0:
        return []
    if not mask:
        mask = b"\xff" * n
    want = bytes(a & m for a, m in zip(find, mask))
    best, cur, cs = (0, 0), 0, 0
    for i, m in enumerate(mask):                       # the longest run of exact bytes is the anchor for the search
        if m == 0xFF:
            if cur == 0:
                cs = i
            cur += 1
            if cur > best[1]:
                best = (cs, cur)
        else:
            cur = 0
    a0, alen = best
    out = []
    if alen == 0:                                      # no exact byte at all: every position is compared
        for s in range(start, end - n + 1):
            if all((buf[s + k] & mask[k]) == want[k] for k in range(n)):
                out.append(s)
        return out
    anchor = find[a0:a0 + alen]
    i = buf.find(anchor, start + a0, end)
    while i != -1:
        s = i - a0
        if s >= start and s + n <= end and all((buf[s + k] & mask[k]) == want[k] for k in range(n)):
            out.append(s)
        i = buf.find(anchor, i + 1, end)
    return out


class Image:
    def __init__(self, data, segs, syms):
        self.data, self.segs, self.syms = data, segs, syms
        self._starts = sorted((offset_of(segs, v), n) for n, v in syms.items() if offset_of(segs, v) is not None)

    @classmethod
    def load(cls, path):
        return cls(*macho(path))

    def owner(self, off):
        """The name of the nearest symbol at or before a file offset."""
        lo, hi = 0, len(self._starts)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._starts[mid][0] <= off:
                lo = mid + 1
            else:
                hi = mid
        return self._starts[lo - 1][1] if lo else None

    def hits(self, p):
        """(list of offsets, reason). reason is None when the search could be made."""
        base = p.get("Base") or ""
        start = 0
        if base:
            if base not in self.syms:
                return None, f"the symbol {base!r} is not in this binary"
            start = offset_of(self.segs, self.syms[base])
            if start is None:
                return None, f"the symbol {base!r} is outside the file"
        limit = int(p.get("Limit") or 0)
        end = min(len(self.data), start + limit) if limit else len(self.data)
        find, mask = bytes(p.get("Find") or b""), bytes(p.get("Mask") or b"")
        if not find:
            return None, "the patch has no bytes to find"
        if mask and len(mask) != len(find):
            return None, "the mask and the bytes differ in length"
        return find_all(self.data, start, end, find, mask), None


def covers_26(p):
    def major(s, d):
        try:
            return int(str(s).split(".")[0]) if s else d
        except ValueError:
            return None
    lo, hi = major(p.get("MinKernel", ""), 0), major(p.get("MaxKernel", ""), 999)
    return lo is not None and hi is not None and lo <= DARWIN_26 <= hi


def judge(p, img26, img27):
    """(carried, reason, detail). Both images are for the binary the patch names."""
    if p.get("Arch") not in (None, "", "Any", "x86_64"):
        return False, "not an x86_64 patch", {}
    if int(p.get("Skip") or 0) != 0:
        return False, "it skips occurrences; that order is not compared here", {}
    h26, why = img26.hits(p)
    if why:
        return False, "macOS 26: " + why, {}
    h27, why = img27.hits(p)
    if why:
        return False, "macOS 27: " + why, {}
    count = int(p.get("Count") or 0)
    need = count if count else 1
    detail = {"found_26": len(h26), "found_27": len(h27)}
    if len(h26) < need:
        return False, f"macOS 26 has {len(h26)} of the {need} it wants: it does not work where it was written for", detail
    if len(h27) < need:
        return False, f"macOS 27 has {len(h27)} of the {need} it wants", detail
    if count == 0 and len(h27) != len(h26):
        return False, f"it changes every occurrence, and macOS 27 has {len(h27)} where macOS 26 has {len(h26)}", detail
    take26, take27 = (h26, h27) if count == 0 else (h26[:count], h27[:count])
    own26, own27 = [img26.owner(o) for o in take26], [img27.owner(o) for o in take27]
    detail["in"] = own27
    if own26 != own27:
        return False, f"it would change {own27} on macOS 27 and {own26} on macOS 26", detail
    return True, "", detail


# Patches of ours for macOS 27, each standing in for one macOS 26 patch that cannot be carried.
#
# "thread_invoke, thread_dispatch | Remove non-monotonic time panic" matches 13 bytes of which 5 are free and wants the
# first two matches. In the macOS 26 kernel the first is the check it is named for (sub r14, [rdi+0x488]; jb) and the
# second is unrelated code that an AMD processor never runs. In the macOS 27 kernel a new first match appears inside
# do_stackshot, so the patch would cut six bytes out of that function and reach the real check only second. Ours names
# the check exactly and changes that one place.
OWN = [
    {"for": {"Identifier": "kernel", "Base": "", "Find": bytes.fromhex("480000800400000f0000000000"),
             "Mask": bytes.fromhex("480000f0ffffffff0000000000"), "Count": 2, "Limit": 0, "Skip": 0},
     "patch": {"Identifier": "kernel", "Base": "", "Comment": "NullMoth | thread_invoke | Remove non-monotonic time check | macOS 27",
               "Find": bytes.fromhex("4c2bb7880400000f82a9000000"), "Replace": bytes.fromhex("4c2bb788040000669066906690"),
               "Mask": b"", "ReplaceMask": b"", "Count": 1, "Limit": 0}},
]


def judge_own(own, img26, img27):
    """An own patch is good when its exact bytes are once in macOS 27, once in macOS 26, and the macOS 26 place is one
    the patch it stands in for changes there: then it is the same code, named without the loose mask."""
    p, old = own["patch"], own["for"]
    h27, _ = img27.hits(p)
    h26, _ = img26.hits(p)
    old26, why = img26.hits(old)
    if why:
        return False, "macOS 26: " + why
    if len(h27 or []) != p["Count"]:
        return False, f"macOS 27 has its bytes {len(h27 or [])} times, not {p['Count']}"
    if len(h26 or []) != 1 or h26[0] not in old26[:int(old.get("Count") or 0) or len(old26)]:
        return False, "its bytes are not a place the macOS 26 patch changes"
    if len(p["Find"]) != len(p["Replace"]):
        return False, "it would change the length of the code"
    return True, ""


def check(k26, k27, kexts, plists):
    images = {"kernel": (Image.load(k26), Image.load(k27))}
    for ident, (a, b) in kexts.items():
        images[ident] = (Image.load(a), Image.load(b))
    carried, left, seen = [], [], set()
    for path in plists:
        with open(path, "rb") as fh:
            patches = plistlib.load(fh).get("Kernel", {}).get("Patch", [])
        for p in patches:
            if not covers_26(p):
                continue
            m = mark(p)
            if m in seen:
                continue
            seen.add(m)
            ident = p.get("Identifier", "")
            if ident not in images:
                left.append({"comment": p.get("Comment", ""), "why": f"no macOS 26 and 27 binaries were given for {ident!r}"})
                continue
            ok, why, detail = judge(p, *images[ident])
            row = {"comment": p.get("Comment", ""), "identifier": ident, **detail}
            if ok:
                carried.append({"mark": m, **row})
            else:
                left.append({**row, "why": why})
    own = []
    for o in OWN:
        ident = o["patch"]["Identifier"]
        ok, why = judge_own(o, *images[ident]) if ident in images else (False, f"no binaries for {ident!r}")
        if not ok:
            raise SystemExit(f"own patch {o['patch']['Comment']!r} does not hold on these kernels: {why}")
        b64 = lambda v: base64.b64encode(bytes(v)).decode()  # noqa: E731
        p = o["patch"]
        own.append({"for": mark(o["for"]), "patch": {"identifier": ident, "base": p["Base"], "comment": p["Comment"], "count": p["Count"],
                    "limit": p["Limit"], "find": b64(p["Find"]), "replace": b64(p["Replace"]), "mask": b64(p["Mask"]), "replace_mask": b64(p["ReplaceMask"])}})
    return carried, left, own


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def selftest():
    fails = []

    def arm(name, ok, detail=""):
        print(("ok   " if ok else "FAIL ") + name + ("" if ok else "  " + str(detail)))
        if not ok:
            fails.append(name)

    def image(code, symbols):
        return Image(bytes(code), [(0x1000, len(code), 0)], {n: 0x1000 + o for n, o in symbols.items()})

    pad = b"\x90" * 16
    f1 = b"\x0f\x30"                                    # stands for a wrmsr the patch removes
    a = image(pad + f1 + pad + b"\xc1\xe8\x1a\x11\x22" + pad, {"_first": 0, "_second": 34})
    b_same = image(b"\x90" * 5 + pad + f1 + pad + b"\xc1\xea\x1a\x33\x44" + pad, {"_first": 0, "_second": 39})
    plain = {"Identifier": "kernel", "Find": f1, "Count": 1, "MinKernel": "17.0.0", "MaxKernel": "25.99.99"}
    ok, why, d = judge(plain, a, b_same)
    arm("a patch whose bytes are in both kernels, in the same function, is carried", ok and d["in"] == ["_first"], (why, d))
    masked = {"Identifier": "kernel", "Base": "_second", "Find": b"\xc1\xe8\x1a\x00\x00", "Mask": b"\xff\xfd\xff\x00\x00", "Count": 1}
    ok, why, d = judge(masked, a, b_same)
    arm("a masked patch that starts from a symbol is found although the code moved and its free bytes differ", ok and d["in"] == ["_second"], (why, d))
    gone = image(pad * 3, {"_first": 0, "_second": 34})
    ok, why, _ = judge(plain, a, gone)
    arm("bytes that macOS 27 does not have leave the patch out, and say so", not ok and "macOS 27 has 0 of the 1" in why, why)
    ok, why, _ = judge(plain, gone, a)
    arm("a patch that does not work on macOS 26 proves nothing and is left out", not ok and "does not work where it was written for" in why, why)
    nosym = image(pad + f1 + pad, {"_first": 0})
    ok, why, _ = judge(masked, a, nosym)
    arm("a symbol macOS 27 lost leaves the patch out", not ok and "'_second' is not in this binary" in why, why)
    moved = image(pad + pad + b"\x90\x90" + pad + f1 + pad, {"_first": 0, "_second": 34})
    ok, why, _ = judge(plain, a, moved)
    arm("the same bytes in another function are not the same patch", not ok and "would change ['_second']" in why, why)
    every = {"Identifier": "kernel", "Find": f1, "Count": 0}
    twice = image(pad + f1 + pad + f1 + pad, {"_first": 0})
    ok, why, _ = judge(every, a, twice)
    arm("a patch for every occurrence is left out when the number of occurrences changed", not ok and "macOS 27 has 2 where macOS 26 has 1" in why, why)
    ok, why, _ = judge(every, twice, twice)
    arm("control: with the same number it is carried", ok, why)
    lim = dict(plain, Base="_first", Limit=10)
    ok, why, _ = judge(lim, a, b_same)
    arm("Limit bounds the search: bytes past it are not found", not ok and "macOS 26 has 0 of the 1" in why, why)
    arm("a patch that ends before macOS 26 is not looked at", not covers_26({"MaxKernel": "24.99.99"}) and covers_26({"MinKernel": "24.0.0", "MaxKernel": "25.99.99"}) and covers_26({}))
    m1 = mark({"Identifier": "kernel", "Find": b"\x01\x02", "Count": 1, "Replace": b"\x09\x09"})
    m2 = mark({"Identifier": "kernel", "Find": b"\x01\x02", "Count": 1, "Replace": b"\x08\x08", "Comment": "x", "MaxKernel": "27.99.99"})
    m3 = mark({"Identifier": "kernel", "Find": b"\x01\x03", "Count": 1})
    arm("the mark ignores what a patch writes, its comment and its limits, and changes with what it matches", m1 == m2 and m1 != m3)
    arm("the mark is the digest the shell computes: fields joined with '|', data as base64, absent fields empty",
        m1 == hashlib.sha256(b"kernel||AQI=||1|||").hexdigest(), m1)
    loose = {"Identifier": "kernel", "Base": "", "Find": b"\x48\x00\x0f", "Mask": b"\x48\x00\xff", "Count": 1, "Limit": 0, "Skip": 0}
    site = b"\x4c\x2b\x0f\x82"
    o26 = image(pad + site + pad, {"_sched": 0})
    o27 = image(b"\x49\x39\x0f\x96" + pad + site + pad, {"_shot": 0, "_sched": 4})
    ok, why, _ = judge(loose, o26, o27)
    arm("a loose patch whose first match on macOS 27 is in other code is left out", not ok and "would change ['_shot']" in why, why)
    mine = {"for": loose, "patch": {"Identifier": "kernel", "Base": "", "Comment": "x", "Find": site, "Replace": b"\x4c\x2b\x66\x90", "Mask": b"", "ReplaceMask": b"", "Count": 1, "Limit": 0}}
    ok, why = judge_own(mine, o26, o27)
    arm("our exact patch for the place the loose one changes on macOS 26 holds on both", ok, why)
    ok, why = judge_own(mine, o26, image(pad + site + site + pad, {"_sched": 0}))
    arm("our patch is refused when its bytes are twice in macOS 27", not ok and "2 times" in why, why)
    other = dict(mine, patch=dict(mine["patch"], Find=b"\x90\x90\x90\x4c"))
    ok, why = judge_own(other, o26, o27)
    arm("our patch is refused when it is not a place the macOS 26 patch changes", not ok, why)
    print(f"{len(fails)} failed")
    return 1 if fails else 0


def main(argv):
    if argv[1:] == ["--selftest"]:
        return selftest()
    if len(argv) < 6 or argv[1] != "check" or "-o" not in argv:
        sys.exit(__doc__.strip().split("\n\n")[0] + "\n\n" + "\n".join(__doc__.splitlines()[2:4]))
    k26, k27, rest = argv[2], argv[3], argv[4:]
    out = rest[rest.index("-o") + 1]
    kexts, plists, i = {}, [], 0
    while i < len(rest):
        if rest[i] == "-o":
            i += 2
        elif rest[i] == "--kext":
            ident, pair = rest[i + 1].split("=", 1)
            kexts[ident] = tuple(pair.split(","))
            i += 2
        else:
            plists.append(rest[i])
            i += 1
    carried, left, own = check(k26, k27, kexts, plists)
    doc = {"kernel_26_sha256": sha256_of(k26), "kernel_27_sha256": sha256_of(k27),
           "binaries": {ident: {"sha256_26": sha256_of(a), "sha256_27": sha256_of(b)} for ident, (a, b) in kexts.items()},
           "carried": carried, "left": left, "own": own}
    tmp = out + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    os.replace(tmp, out)
    for r in carried:
        print(f"carried  {r['comment'][:84]}  ({r['found_26']} | {r['found_27']})")
    for r in left:
        print(f"LEFT     {r['comment'][:84]}: {r['why']}")
    for o in own:
        print(f"own      {o['patch']['comment']}  (stands in for {o['for'][:12]})")
    print(f"{len(carried)} carried to macOS 27, {len(left)} left at macOS 26, {len(own)} of our own -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
