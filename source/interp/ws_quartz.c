/* ws_quartz.c — the host's WindowServer fix for QuartzCore's prepare_one_filter call through a short table.
 *
 * reuses: mini wsfilter-1028/a2xwsfix.c (same 14-byte site, same 6-byte replacement, same exactly-one-hit refusal).
 * new-because: 11-01 the stock-27 bench may not carry a2xwsfix (it was a DYLD_INSERT in Apple's WindowServer plist,
 *   which stock forbids); the host is ours, so the fix lives here and every Apple file stays stock.
 *
 *  THE BUG (measured 10-28, 9 WindowServer crashes, one frame; 11-01 bench: exit 139 x9, the same no-.ips shape):
 *    QuartzCore CA::OGL::prepare_one_filter +0x7cd: rax = obj->vfn(+0x10)(); call *0x3e0(*rax). The object is
 *    SkyLight's quartzcore_vtable, a 14-entry dlsym table (0x70 bytes); +0x3e0 lies 0x370 past its end, on a SkyLight
 *    debug flag that is 0 → call 0. A WindowServer crash takes the whole GUI session with it.
 *  11-01 offline: 27's own x86_64 QuartzCore (Rosetta cryptex dyld_shared_cache_x86_64) holds the site exactly
 *    once, QuartzCore __TEXT +0x1c9e72 — the library the host binds natively in the guest.
 *  THE FIX: the call returns a bool, and FALSE is the branch QuartzCore takes when there is no delegate at all.
 *    The 6-byte call becomes `xor eax,eax; nopl 0(%rax)`. Nothing else is touched; refuses unless exactly one hit.
 *  The table cannot be patched instead: the word at +0x3e0 is a live SkyLight flag.
 * Armed only when the guest program is WindowServer; patches when QuartzCore is added (or at once if it already is).
 */
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const unsigned char WSQ_SITE[] = {0x48,0x8b,0x08, 0x48,0x89,0xc7, 0xff,0x91,0xe0,0x03,0x00,0x00, 0x84,0xc0};
/* 11-03 27.2 (26B123) QuartzCore grew its render structures by 0x10 (dsc272x86/qc272.py, 27.2 Rosetta x86 cache):
 *    delegate slot 0x3e0 -> 0x3f0; Update flag qword 0x540 -> 0x550, so backdrop-finalized 0x543&4 -> 0x553&4 and the
 *    added-all bit 38 (0x544&0x40) -> bit 39 (0x554&0x80). Every other byte of the three sites is identical. The layout
 *    is decided by whichever site matches first; every later site must agree or it is refused. */
static const unsigned char WSQ_SITE_272[] = {0x48,0x8b,0x08, 0x48,0x89,0xc7, 0xff,0x91,0xf0,0x03,0x00,0x00, 0x84,0xc0};
static int wsq_layout = -1;                       /* -1 unknown 0 = 27.0 1 = 27.2 */
static int wsq_layout_agree(int l, const char *what) {
    if (wsq_layout < 0) wsq_layout = l;
    if (wsq_layout == l) return 1;
    fprintf(stderr, "[wsquartz] REFUSED: %s is layout %d but an earlier site was layout %d — nothing changed\n", what, l, wsq_layout);
    return 0;
}
static const unsigned char WSQ_FIX[]  = {0x31,0xc0, 0x0f,0x1f,0x40,0x00};   /* replaces WSQ_SITE[6..11] */
static volatile int wsq_done;

/* 11-02 THE SECOND SITE: CARenderUpdateAddedAllContexts is DEAD CODE in 27's QuartzCore (1223.2.2, both arches):
 *    `cmpl $0, 0x21c(%rdi); je ret` tests an Update field nothing in the image ever writes (arm64e twin: 0x22c), so the
 *    call never reaches Update::added_all_contexts(false) -> add_backdrop_invalidations -> finalize_backdrop_invalidations,
 *    the ONLY writer of the flag prepare_layers_roi asserts on (ogl-layer.cpp:7179, bit 2 of byte 0x543).
 *    Real Macs never notice: SkyLight's Metal path (MetalCompositeLayer) has CARenderUpdateAddContext2 reach
 *    added_all_contexts on its own. The bench has no accelerator, so SkyLight composites in software
 *    (CompositorSW::CompositeLayersToDestination -> layer_tile_traverse), which calls ONLY CARenderUpdateAddedAllContexts
 *    before rendering -> unfinalized Update -> abort(), 20 runs on 11-02 (serial-1101au.log 11249, 13039).
 *  THE FIX: test the Update's real "added all contexts" bit instead — bit 38 of the flag word (0x544 & 0x40), the
 *    bit added_all_contexts sets and CARenderUpdateFinish already tests before calling it. An Update that was never
 *    finalized now is; one that was stays untouched. 9 bytes change at +4; the tail `jmp added_all_contexts` keeps its
 *    offset, so its rel32 is byte-identical. The address comes from dlsym (exported C symbol), the 23 bytes are checked
 *    exactly (rel32 wildcarded); anything else is refused and nothing changes. A2X_WSQUARTZ_AAC=0 turns it off. */
static const unsigned char WSQ_AAC_SITE[23] = {
    0x55, 0x48,0x89,0xe5,                         /* push rbp; mov rbp,rsp                       */
    0x83,0xbf,0x1c,0x02,0x00,0x00,0x00,           /* cmpl $0, 0x21c(%rdi)        <- replaced     */
    0x74,0x08,                                    /* je +8 -> pop rbp; ret       <- replaced     */
    0x31,0xf6, 0x5d,                              /* xor esi,esi; pop rbp                        */
    0xe9, 0,0,0,0,                                /* jmp added_all_contexts (rel32, wildcard)    */
    0x5d, 0xc3 };                                 /* pop rbp; ret                                */
static const unsigned char WSQ_AAC_FIX[9] = {
    0xf6,0x87,0x44,0x05,0x00,0x00,0x40,           /* testb $0x40, 0x544(%rdi): added all already? */
    0x75,0x08 };                                  /* jne +8 -> pop rbp; ret                        */
static const unsigned char WSQ_AAC_FIX_272[9] = {
    0xf6,0x87,0x54,0x05,0x00,0x00,0x80,           /* 27.2: testb $0x80, 0x554(%rdi)                */
    0x75,0x08 };
enum { WSQ_AAC_AT = 4, WSQ_AAC_REL = 17 };
static volatile int wsq_aac_done;

/* 11-02 the REAL WindowServer render-path fix: NOP the prepare_layers_roi backdrop-finalized assertion.
 *    bytes = testb $0x4,0x543(%rcx) ; je <__assert_rtn ogl-layer.cpp:7179>. If the Update's finalized bit is clear the
 *    software compositor path asserts and WindowServer abort()s (48x on the VGA bench). NOP the 6-byte je so it always
 *    falls through (= treat as finalized, the only path a GPU Mac takes). rel32 pins the anchor to this exact 27 build. */
static const unsigned char WSQ_BD_SITE[23] = {0xf6,0x81,0x43,0x05,0x00,0x00,0x04, 0x0f,0x84,0x7b,0x0f,0x00,0x00,
    0x8b,0x91,0x18,0x02,0x00,0x00, 0x85,0xd2, 0x0f,0x84};  /* + movl 0x218(%rcx),%edx; testl; je <no-backdrop exit> */
/* the je at +7 becomes je rel32 0xdf = the same no-backdrop exit as the je at +21 (rel 0xd1, 14 bytes later). */
static const unsigned char WSQ_BD_NEW[6] = {0x0f,0x84,0xdf,0x00,0x00,0x00};
enum { WSQ_BD_JE = 7, WSQ_BD_JELEN = 6 };
static volatile int wsq_bd_done;

static int wsq_bd_patch(const struct mach_header_64 *mh, const char *name, uint64_t tsize) {
    if (!__sync_bool_compare_and_swap(&wsq_bd_done, 0, 1)) return 0;
    const unsigned char *text = (const unsigned char *)mh, *hit = 0; int n = 0;
    int lay = -1;
    for (int l = 0; l < 2; l++) {
        unsigned char pat[sizeof WSQ_BD_SITE];
        memcpy(pat, WSQ_BD_SITE, sizeof pat);
        if (l) pat[2] = 0x53;                                   /* 27.2: the flag byte is 0x553 */
        for (const unsigned char *q = text; q + sizeof pat <= text + tsize; q++)
            if (*q == pat[0] && !memcmp(q, pat, sizeof pat)) { hit = q; n++; lay = l; }
    }
    if (n != 1) { fprintf(stderr, "[wsquartz] REFUSED: backdrop assert site matched %d times in %s (expected 1)\n", n, name); return -1; }
    if (!wsq_layout_agree(lay, "backdrop assert site")) return -1;
    unsigned char *at = (unsigned char *)hit + WSQ_BD_JE;
    mach_vm_address_t pg = (mach_vm_address_t)at & ~(mach_vm_address_t)(vm_page_size - 1);
    mach_vm_size_t len = ((mach_vm_address_t)at + WSQ_BD_JELEN - pg + vm_page_size - 1) & ~(mach_vm_size_t)(vm_page_size - 1);
    kern_return_t kr0 = mach_vm_protect(mach_task_self(), pg, len, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr0) { fprintf(stderr, "[wsquartz] REFUSED: mach_vm_protect rw (backdrop): %s\n", mach_error_string(kr0)); return -1; }
    if (memcmp(hit + 21, "\x0f\x84\xd1\x00\x00\x00", 6)) { fprintf(stderr, "[wsquartz] REFUSED: backdrop exit je differs in %s\n", name); return -1; }
    memcpy(at, WSQ_BD_NEW, WSQ_BD_JELEN);
    kern_return_t kr = mach_vm_protect(mach_task_self(), pg, len, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    fprintf(stderr, "[wsquartz] patched prepare_layers_roi backdrop assertion -> no-backdrop exit (je +0x1e8) at %p pid %d%s\n",
            (void *)at, getpid(), kr ? " — r-x restore FAILED" : "");
    return 0;
}

/* 0 patched -1 refused (reason printed, bytes untouched). f = CARenderUpdateAddedAllContexts. */
static int wsq_aac_patch(unsigned char *f, const char *name) {
    for (unsigned i = 0; i < sizeof WSQ_AAC_SITE; i++) {
        if (i >= WSQ_AAC_REL && i < WSQ_AAC_REL + 4) continue;
        if (f[i] != WSQ_AAC_SITE[i]) {
            fprintf(stderr, "[wsquartz] REFUSED: CARenderUpdateAddedAllContexts byte %u is %02x, expected %02x in %s — nothing changed\n",
                    i, f[i], WSQ_AAC_SITE[i], name);
            return -1;
        }
    }
    if (wsq_layout < 0) {
        fprintf(stderr, "[wsquartz] REFUSED: CARenderUpdateAddedAllContexts: QuartzCore layout unknown (no other site matched) in %s — nothing changed\n", name);
        return -1;
    }
    const unsigned char *fix = wsq_layout == 1 ? WSQ_AAC_FIX_272 : WSQ_AAC_FIX;
    unsigned char *at = f + WSQ_AAC_AT;
    mach_vm_address_t pg = (mach_vm_address_t)at & ~(mach_vm_address_t)(vm_page_size - 1);
    mach_vm_size_t len = ((mach_vm_address_t)at + sizeof WSQ_AAC_FIX - pg + vm_page_size - 1)
                         & ~(mach_vm_size_t)(vm_page_size - 1);
    kern_return_t kr = mach_vm_protect(mach_task_self(), pg, len, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr) {
        fprintf(stderr, "[wsquartz] REFUSED: mach_vm_protect rw (AddedAllContexts): %s — nothing changed\n", mach_error_string(kr));
        return -1;
    }
    memcpy(at, fix, sizeof WSQ_AAC_FIX);
    kr = mach_vm_protect(mach_task_self(), pg, len, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    fprintf(stderr, "[wsquartz] patched CARenderUpdateAddedAllContexts at %p: finalizes an update that never added contexts, pid %d%s%s\n",
            (void *)f, getpid(), kr ? " — restoring r-x FAILED: " : "", kr ? mach_error_string(kr) : "");
    return 0;
}

static int wsq_aac_try(const char *name) {
    if (!__sync_bool_compare_and_swap(&wsq_aac_done, 0, 1)) return 0;
    const char *off = A2X_DBGENV("A2X_WSQUARTZ_AAC");
    if (off && off[0] == '0') { fprintf(stderr, "[wsquartz] AddedAllContexts fix off (A2X_WSQUARTZ_AAC=0)\n"); return -1; }
    unsigned char *f = (unsigned char *)dlsym(RTLD_DEFAULT, "CARenderUpdateAddedAllContexts");
    if (!f) { fprintf(stderr, "[wsquartz] REFUSED: CARenderUpdateAddedAllContexts not exported by %s — nothing changed\n", name); return -1; }
    return wsq_aac_patch(f, name);
}

/* 0 patched 1 not QuartzCore -1 refused (reason printed). */
static int wsq_try(const struct mach_header *mh0, const char *name) {
    if (!name || !strstr(name, "/QuartzCore.framework/") || strstr(name, ".framework/Frameworks/")) return 1;
    if (!__sync_bool_compare_and_swap(&wsq_done, 0, 1)) return 0;
    const struct mach_header_64 *mh = (const struct mach_header_64 *)mh0;
    if (mh->magic != MH_MAGIC_64) { fprintf(stderr, "[wsquartz] REFUSED: QuartzCore is not a 64-bit image\n"); return -1; }
    uint64_t tsize = 0;
    const struct load_command *lc = (const void *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++, lc = (const void *)((const char *)lc + lc->cmdsize))
        if (lc->cmd == LC_SEGMENT_64 && !strcmp(((const struct segment_command_64 *)lc)->segname, "__TEXT")) {
            tsize = ((const struct segment_command_64 *)lc)->vmsize; break;
        }
    if (!tsize) { fprintf(stderr, "[wsquartz] REFUSED: no __TEXT in %s\n", name); return -1; }
    const unsigned char *text = (const unsigned char *)mh, *hit = 0;
    int nhit = 0;
    int lay = -1;
    for (const unsigned char *p = text; p + sizeof WSQ_SITE <= text + tsize; p++) {
        if (*p != WSQ_SITE[0]) continue;
        if (!memcmp(p, WSQ_SITE, sizeof WSQ_SITE)) { hit = p; nhit++; lay = 0; }
        else if (!memcmp(p, WSQ_SITE_272, sizeof WSQ_SITE_272)) { hit = p; nhit++; lay = 1; }
    }
    if (nhit != 1) {
        fprintf(stderr, "[wsquartz] REFUSED: the call site matched %d times in %s (expected 1) — nothing changed\n",
                nhit, name);
        wsq_bd_patch(mh, name, tsize);   /* 11-03: an independent site — on 27.2 this refusal kept the real fix from running */
        return -1;
    }
    if (!wsq_layout_agree(lay, "delegate call site")) { wsq_bd_patch(mh, name, tsize); return -1; }
    unsigned char *at = (unsigned char *)hit + 6;
    mach_vm_address_t pg = (mach_vm_address_t)at & ~(mach_vm_address_t)(vm_page_size - 1);
    mach_vm_size_t len = ((mach_vm_address_t)at + sizeof WSQ_FIX - pg + vm_page_size - 1)
                         & ~(mach_vm_size_t)(vm_page_size - 1);
    kern_return_t kr = mach_vm_protect(mach_task_self(), pg, len, FALSE,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr) {
        fprintf(stderr, "[wsquartz] REFUSED: mach_vm_protect rw: %s — nothing changed\n", mach_error_string(kr));
        return -1;
    }
    memcpy(at, WSQ_FIX, sizeof WSQ_FIX);
    kr = mach_vm_protect(mach_task_self(), pg, len, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    fprintf(stderr, "[wsquartz] patched QuartzCore prepare_one_filter delegate call at %p (+0x%lx) pid %d%s%s\n",
            (void *)at, (unsigned long)(at - text), getpid(), kr ? " — restoring r-x FAILED: " : "",
            kr ? mach_error_string(kr) : "");
    wsq_bd_patch(mh, name, tsize);   /* 11-02 the render-path backdrop assertion, same QuartzCore image */
    return 0;
}

static void wsq_added(const struct mach_header *mh, intptr_t slide) {
    (void)slide;
    if (wsq_done) return;
    /* dyld's add-image callback gives no name; find this header among the loaded images. */
    for (uint32_t i = 0, n = _dyld_image_count(); i < n; i++)
        if (_dyld_get_image_header(i) == mh) {
            const char *nm = _dyld_get_image_name(i);
            if (wsq_try(mh, nm) != 1) wsq_aac_try(nm);   /* the same QuartzCore image carries both sites */
            return;
        }
}

/* Called once by the host with the guest's path. Arms only for WindowServer (A2X_WSQUARTZ=0 turns it off). */
void a2x_wsquartz_arm(const char *gpath) {
    const char *b = gpath ? strrchr(gpath, '/') : 0;
    b = b ? b + 1 : gpath;
    if (!b || strcmp(b, "WindowServer")) return;
    const char *off = A2X_DBGENV("A2X_WSQUARTZ");
    if (off && off[0] == '0') { fprintf(stderr, "[wsquartz] off (A2X_WSQUARTZ=0)\n"); return; }
    fprintf(stderr, "[wsquartz] armed for %s\n", gpath);
    _dyld_register_func_for_add_image(wsq_added);   /* also replays every image already loaded */
}

#ifdef WSQ_SELFTEST
/* Selftest: a fake image with the site once / twice / never, run through the same scanner. */
#include <sys/mman.h>
static int run(int copies, const char *label, int want) {
    size_t sz = 3 * 16384;
    unsigned char *m = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    memset(m, 0x90, sz);
    struct mach_header_64 *mh = (void *)m; mh->magic = MH_MAGIC_64; mh->ncmds = 1;
    struct segment_command_64 *sg = (void *)(mh + 1); sg->cmd = LC_SEGMENT_64; sg->cmdsize = sizeof *sg;
    strcpy(sg->segname, "__TEXT"); sg->vmsize = sz;
    for (int c = 0; c < copies; c++) memcpy(m + 20000 + c * 100, WSQ_SITE, sizeof WSQ_SITE);
    mprotect(m, sz, PROT_READ | PROT_EXEC);
    wsq_done = 0;
    int r = wsq_try((void *)m, "/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore");
    int ok = r == want && (want != 0 || !memcmp(m + 20006, WSQ_FIX, sizeof WSQ_FIX));
    if (copies == 2) ok = ok && !memcmp(m + 20006, WSQ_SITE + 6, 6);   /* refused = untouched */
    printf("%s %s (r=%d want %d)\n", ok ? "ok  " : "FAIL", label, r, want);
    return !ok;
}
int main(void) {
    int f = 0;
    f += run(1, " one site → patched to xor eax,eax", 0);
    f += run(2, " two sites → REFUSED and the bytes stay untouched", -1);
    f += run(0, " no site → REFUSED", -1);
    /* the second site: a fake CARenderUpdateAddedAllContexts, exact bytes / one byte off / switched off */
    {
        unsigned char *m = mmap(0, 16384, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        memset(m, 0xcc, 16384);
        wsq_layout = 0;                                                   /* the 27.0 arms below */
        unsigned char *fn = m + 1000;
        memcpy(fn, WSQ_AAC_SITE, sizeof WSQ_AAC_SITE);
        fn[17] = 0xc9; fn[18] = 0x71; fn[19] = 0xff; fn[20] = 0xff;      /* the real rel32 of 27's QuartzCore */
        mprotect(m, 16384, PROT_READ | PROT_EXEC);
        int r = wsq_aac_patch(fn, "fake QuartzCore");
        int ok = r == 0 && !memcmp(fn + 4, WSQ_AAC_FIX, 9) && !memcmp(fn, WSQ_AAC_SITE, 4)
                 && !memcmp(fn + 13, WSQ_AAC_SITE + 13, 4) && fn[17] == 0xc9 && fn[20] == 0xff && fn[21] == 0x5d && fn[22] == 0xc3
                 && fn[-1] == 0xcc && fn[23] == 0xcc;
        printf("%s  AddedAllContexts: exact 23 bytes → 9 patched, prologue/tail/rel32/neighbours untouched (r=%d)\n", ok ? "ok  " : "FAIL", r);
        f += !ok;
        unsigned char *fn2 = m + 2000;
        mprotect(m, 16384, PROT_READ | PROT_WRITE);
        memcpy(fn2, WSQ_AAC_SITE, sizeof WSQ_AAC_SITE);
        fn2[6] = 0x2c;                                                    /* a different field offset = not our build */
        unsigned char keep[23]; memcpy(keep, fn2, 23);
        mprotect(m, 16384, PROT_READ | PROT_EXEC);
        r = wsq_aac_patch(fn2, "fake QuartzCore");
        ok = r == -1 && !memcmp(fn2, keep, 23);
        printf("%s  AddedAllContexts: one byte off → REFUSED and untouched (r=%d)\n", ok ? "ok  " : "FAIL", r);
        f += !ok;
        setenv("A2X_WSQUARTZ_AAC", "0", 1); wsq_aac_done = 0;
        r = wsq_aac_try("fake QuartzCore");
        printf("%s  A2X_WSQUARTZ_AAC=0 → off (r=%d)\n", r == -1 ? "ok  " : "FAIL", r);
        f += r != -1;
        unsetenv("A2X_WSQUARTZ_AAC");
    }
    /* 11-03 27.2: the 0x3f0 delegate site is recognised (layout 1); AddedAllContexts then gets the 0x554&0x80 test;
     *  with the layout unknown AddedAllContexts is refused and untouched. */
    {
        size_t sz = 3 * 16384;
        unsigned char *m = mmap(0, sz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        memset(m, 0x90, sz);
        struct mach_header_64 *mh = (void *)m; mh->magic = MH_MAGIC_64; mh->ncmds = 1;
        struct segment_command_64 *sg = (void *)(mh + 1); sg->cmd = LC_SEGMENT_64; sg->cmdsize = sizeof *sg;
        strcpy(sg->segname, "__TEXT"); sg->vmsize = sz;
        memcpy(m + 20000, WSQ_SITE_272, sizeof WSQ_SITE_272);
        unsigned char *fn = m + 30000, *fn2 = m + 31000;
        memcpy(fn, WSQ_AAC_SITE, sizeof WSQ_AAC_SITE); memcpy(fn2, WSQ_AAC_SITE, sizeof WSQ_AAC_SITE);
        mprotect(m, sz, PROT_READ | PROT_EXEC);
        wsq_done = 0; wsq_layout = -1;
        int r = wsq_try((void *)m, "/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore");
        int ok = r == 0 && wsq_layout == 1 && !memcmp(m + 20006, WSQ_FIX, sizeof WSQ_FIX);
        printf("%s  27.2 delegate site (slot 0x3f0) → patched, layout 1 (r=%d layout=%d)\n", ok ? "ok  " : "FAIL", r, wsq_layout);
        f += !ok;
        r = wsq_aac_patch(fn, "fake 27.2 QuartzCore");
        ok = r == 0 && !memcmp(fn + 4, WSQ_AAC_FIX_272, 9);
        printf("%s  27.2 AddedAllContexts → testb $0x80,0x554 (r=%d)\n", ok ? "ok  " : "FAIL", r);
        f += !ok;
        wsq_layout = -1;
        unsigned char keep[23]; memcpy(keep, fn2, 23);
        r = wsq_aac_patch(fn2, "fake QuartzCore, layout unknown");
        ok = r == -1 && !memcmp(fn2, keep, 23);
        printf("%s  layout unknown → AddedAllContexts REFUSED and untouched (r=%d)\n", ok ? "ok  " : "FAIL", r);
        f += !ok;
    }
    wsq_done = 0;
    f += wsq_try((void *)&f, "/usr/lib/libz.1.dylib") == 1 ? 0 : 1;
    printf("%s a non-QuartzCore image is ignored\n", f ? "FAIL" : "ok  ");
    printf("%d failed\n", f);
    return f != 0;
}
#endif
