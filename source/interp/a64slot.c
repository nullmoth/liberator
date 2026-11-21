/* a64slot.c - fixed-slot execution of arm64 code on x86-64.

   Every arm64 instruction at address A in an image's text gets one 32-byte slot of x86 code at
       slot(A) = SB + (A - TB) * 8.
   Any arm64 address (a function start, a branch into the middle of a function, a return address) is turned into
   an x86 address by that arithmetic, so the processor follows direct branches itself and indirect branches cost one
   range check. There is no lookup table and no dispatch loop between instructions.

   Semantics have one source: the interpreter's decoders (a64_*_spec) say what an instruction is, and any instruction
   without a template runs through the interpreter's own a64_step from inside its slot ("helper" slots), with the
   guest registers written back to the state first. Anything that must leave (a system call, a trap, a branch out of
   the image) is an "exit" slot: control returns to the caller with s->pc at that instruction, not yet executed, so
   the interpreter runs it exactly as it would have anyway. The certifier (slotcert.c) checks every template against
   a64_step on random states.

   Register file while in slots:
     rbx = the a64 state.  rax, rcx, rdx, r11 = scratch.
     Ten guest registers live in host registers (the most used ones in the M6 census): sp, x0, x1, x2, x8, x9, x19,
     x20, x21, x30. The rest live in the state. All mapped registers are written back before any C call.
   Flags while in slots: s->nzcv holds an x86 flag image (AH from LAHF, AL = OF), with the carry stored INVERTED
   relative to arm64 C (x86 "borrow" form), so every arm64 condition is a single x86 condition code. slot_run()
   converts on the way in and out; the helper converts around each a64_step. */
#include "a64_priv.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include "a64slot.h"

enum { RAX = 0, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 };
#define SLOT 32
#define GSP 31                      /* index of the guest stack pointer in map[] / goff() */

/* THE MAPPING IS PER IMAGE, chosen from that image's own register use when it is converted (rmap_choose). A
      fixed set (sp x0 x1 x2 x8 x9 x19 x20 x21 x30, from the M6 census over whole programs) left a leaf kernel's
      x10-x17 in memory and measured 3.72x native on the PC. Eleven host registers carry guest registers; rax, rcx
      and rdx are scratch and rbx is the state. */
static const int HOSTREGS[] = {RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15};
#define NHOST ((int)(sizeof HOSTREGS / sizeof HOSTREGS[0]))
struct rmap { int8_t g2h[32]; int n; int8_t g[16], h[16]; };
static const struct rmap *CM;           /* the map of the image being emitted */

static int32_t goff(int g) { return g == GSP ? (int32_t)offsetof(a64, sp) : (int32_t)(offsetof(a64, x) + 8 * g); }
#define OFF_PC   ((int32_t)offsetof(a64, pc))
#define OFF_NZ   ((int32_t)offsetof(a64, nzcv))
#define OFF_ARGW ((int32_t)offsetof(a64, argw))
#define OFF_HOSTSP ((int32_t)offsetof(a64, hostsp))
#define OFF_ARGWX ((int32_t)offsetof(a64, argwx))
int slot_opt;                           /* OPT_* for images added from now on (a64slot.h) */
static int OPT;                         /* the options of the image being emitted */
static int ZXD;                         /* the template's last op already zero-extended its 32-bit result (OPT_NOZX) */

/* ───────────────────────── the x86 encoder ───────────────────────── */
typedef struct { uint8_t buf[512]; int n; uint64_t va; } E;   /* va = run address of buf[0] */
static uint64_t ecur(E *e) { return e->va + (uint64_t)e->n; }
/* LZCNT (CPUID 0x80000001 ECX bit 5). Older CPUs decode its bytes as BSR, so the CLZ template is used only when set. */
static int slot_has_lzcnt(void) {
    static int v = -1;
    if (v < 0) {
        unsigned a = 0x80000000u, b, c, d;
        __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d) : "c"(0));
        if (a < 0x80000001u) v = 0;
        else { a = 0x80000001u; __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d) : "c"(0)); v = (c >> 5) & 1; }
    }
    return v;
}
static void b1(E *e, unsigned v) { e->buf[e->n++] = (uint8_t)v; }
static void b4(E *e, uint32_t v) { memcpy(e->buf + e->n, &v, 4); e->n += 4; }
static void b8(E *e, uint64_t v) { memcpy(e->buf + e->n, &v, 8); e->n += 8; }
static void rex(E *e, int w, int r, int x, int b, int force) {
    unsigned v = 0x40 | (w ? 8 : 0) | ((r & 8) ? 4 : 0) | ((x & 8) ? 2 : 0) | ((b & 8) ? 1 : 0);
    if (v != 0x40 || force) b1(e, v);
}
typedef struct { int base, index, scale; int32_t disp; } M;    /* index -1 = none; scale = 0..3 (log2) */
static M mb(int base, int32_t disp) { M m = {base, -1, 0, disp}; return m; }
static void modrm_mem(E *e, int reg, M m) {
    int mod = (m.disp == 0 && (m.base & 7) != 5) ? 0 : (m.disp >= -128 && m.disp <= 127) ? 1 : 2;
    if (m.index < 0 && (m.base & 7) != 4) {
        b1(e, (unsigned)(mod << 6 | (reg & 7) << 3 | (m.base & 7)));
    } else {
        int idx = m.index < 0 ? 4 : m.index;
        b1(e, (unsigned)(mod << 6 | (reg & 7) << 3 | 4));
        b1(e, (unsigned)(m.scale << 6 | (idx & 7) << 3 | (m.base & 7)));
    }
    if (mod == 1) b1(e, (unsigned)(uint8_t)m.disp); else if (mod == 2) b4(e, (uint32_t)m.disp);
}
/* opcode bytes (1 or 2; 0x0f first), reg field, memory operand */
static void op_m(E *e, int pfx66, int w, int force, unsigned o1, int o2, int reg, M m) {
    if (pfx66) b1(e, 0x66);
    rex(e, w, reg, m.index < 0 ? 0 : m.index, m.base, force);
    b1(e, o1); if (o2 >= 0) b1(e, (unsigned)o2);
    modrm_mem(e, reg, m);
}
static void op_r(E *e, int w, int force, unsigned o1, int o2, int reg, int rm) {
    rex(e, w, reg, 0, rm, force);
    b1(e, o1); if (o2 >= 0) b1(e, (unsigned)o2);
    b1(e, (unsigned)(0xc0 | (reg & 7) << 3 | (rm & 7)));
}
/* ALU r/m <- reg: add 01, or 09, and 21, sub 29, xor 31, cmp 39, test 85, mov 89 */
static void alu_rr(E *e, unsigned opc, int w, int dst, int src) { op_r(e, w, 0, opc, -1, src, dst); }
static void mov_rr(E *e, int w, int dst, int src) { if (dst != src || !w) alu_rr(e, 0x89, w, dst, src); }
/* ALU with immediate: /0 add /1 or /4 and /5 sub /6 xor /7 cmp */
static void alu_ri(E *e, int ext, int w, int dst, int32_t imm) {
    if (imm >= -128 && imm <= 127) { op_r(e, w, 0, 0x83, -1, ext, dst); b1(e, (unsigned)(uint8_t)imm); }
    else { op_r(e, w, 0, 0x81, -1, ext, dst); b4(e, (uint32_t)imm); }
}
static void mov_ri(E *e, int dst, uint64_t v) {
    if (v <= 0xffffffffull) { rex(e, 0, 0, 0, dst, 0); b1(e, 0xb8 + (dst & 7)); b4(e, (uint32_t)v); }
    else if ((int64_t)v == (int32_t)v) { op_r(e, 1, 0, 0xc7, -1, 0, dst); b4(e, (uint32_t)v); }
    else { rex(e, 1, 0, 0, dst, 0); b1(e, 0xb8 + (dst & 7)); b8(e, v); }
}
static void ld64(E *e, int dst, M m) { op_m(e, 0, 1, 0, 0x8b, -1, dst, m); }
static void st64(E *e, M m, int src) { op_m(e, 0, 1, 0, 0x89, -1, src, m); }
/* shift by immediate: /0 rol /1 ror /4 shl /5 shr /7 sar ; by cl: D3 */
static void sh_ri(E *e, int ext, int w, int r, unsigned n) { if (n) { op_r(e, w, 0, 0xc1, -1, ext, r); b1(e, n); } }
static void sh_rcl(E *e, int ext, int w, int r) { op_r(e, w, 0, 0xd3, -1, ext, r); }
static void unary(E *e, int ext, int w, int r) { op_r(e, w, 0, 0xf7, -1, ext, r); }    /* /2 not /3 neg /4 mul /5 imul /6 div /7 idiv */
static void imul_rr(E *e, int w, int dst, int src) { op_r(e, w, 0, 0x0f, 0xaf, dst, src); }
static void cmov(E *e, int cc, int w, int dst, int src) { op_r(e, w, 0, 0x0f, 0x40 + cc, dst, src); }
static void lea(E *e, int dst, M m) { op_m(e, 0, 1, 0, 0x8d, -1, dst, m); }
/* EVERY rel32 IS CHECKED. Code lives in separate mappings (slots, stubs, skills); a jump that does not fit in
      +-2 GB was silently truncated before, and where it landed depended on where the OS put the mappings - suspected
      cause of an intermittent total failure (1.85M mismatches once, then 6 clean runs) on 11-16. All code now comes
      from one arena (code_alloc), and a distance that still does not fit stops the process with its numbers. */
static uint32_t rel32(uint64_t from, uint64_t to) {
    int64_t d = (int64_t)(to - from);
    if (d != (int32_t)d) { fprintf(stderr, "a64slot: rel32 out of range: %llx -> %llx\n", (unsigned long long)from, (unsigned long long)to); abort(); }
    return (uint32_t)(int32_t)d;
}
static void jmp_to(E *e, uint64_t t) { b1(e, 0xe9); b4(e, rel32(ecur(e) + 4, t)); }
static void call_to(E *e, uint64_t t) { b1(e, 0xe8); b4(e, rel32(ecur(e) + 4, t)); }
static void jcc_to(E *e, int cc, uint64_t t) { b1(e, 0x0f); b1(e, 0x80 + (unsigned)cc); b4(e, rel32(ecur(e) + 4, t)); }
/* short forward jump, patched by fix8() */
static int jcc8(E *e, int cc) { b1(e, cc < 0 ? 0xeb : 0x70 + (unsigned)cc); b1(e, 0); return e->n; }
static void fix8(E *e, int at) { e->buf[at - 1] = (uint8_t)(e->n - at); }

/* ───────────────────────── guest registers and flags ───────────────────────── */
/* THE EMISSION CONTEXT. Ordinary slots: every field 0. A learned skill (slot_consolidate) sets them per instruction:
      fuse_out  the setter leaves its flags in EFLAGS (borrow form) and does NOT write the image (the next instruction
                reads them, nothing after it does, and nothing can enter between the two);
      fuse_in   the reader finds its flags in EFLAGS and does NOT load the image;
      noflag    zeroes and +1s are done with mov/lea so they cannot disturb live EFLAGS;
      tgt       where a direct branch to an arm64 address goes (the skill's own copy of that instruction). */
static struct { int fuse_out, fuse_in, noflag; uint64_t (*tgt)(uint64_t); } X;
static uint64_t branch_to(const void *m, uint64_t t);

/* read a guest register into host register h. sp=1: register 31 is the stack pointer; sp=0: it reads zero. */
static void gld(E *e, int h, int r, int sp) {
    if (r == 31 && !sp) { if (X.noflag) mov_ri(e, h, 0); else alu_rr(e, 0x31, 0, h, h); return; }
    int g = r == 31 ? GSP : r;
    if (CM->g2h[g] >= 0) mov_rr(e, 1, h, CM->g2h[g]); else ld64(e, h, mb(RBX, goff(g)));
}
/* write host register h to a guest register at width w (0 = W, zero the top half). Never touches the flags
   except through the argw mark, so callers save the flags BEFORE calling this. */
static void gst(E *e, int r, int h, int w, int sp) {
    if (r == 31 && !sp) return;
    int g = r == 31 ? GSP : r;
    /* OPT_NOZX: a 32-bit x86 op already cleared the top half, so the extra mov is skipped when the template says so */
    if (!w && !((OPT & OPT_NOZX) && ZXD)) mov_rr(e, 0, h, h);
    ZXD = 0;
    if (CM->g2h[g] >= 0) mov_rr(e, 1, CM->g2h[g], h); else st64(e, mb(RBX, goff(g)), h);
    /* MEASURED 11-16: an `or byte [argw]` per x6/x7 write chained every write of the hash loop through one byte of
          memory (11 a round). A plain byte store per register has no read and no flags. The runtime folds argwx into
          argw (a64_rt must read argw | argwx[0] | argwx[1] << 1 and clear all three at a call boundary). */
    if (r == 6 || r == 7) { op_m(e, 0, 0, 0, 0xc6, -1, 0, mb(RBX, OFF_ARGWX + (r - 6))); b1(e, 1); }
}
static void spill_all(E *e) { for (int i = 0; i < CM->n; i++) st64(e, mb(RBX, goff(CM->g[i])), CM->h[i]); }
static void reload_all(E *e) { for (int i = 0; i < CM->n; i++) ld64(e, CM->h[i], mb(RBX, goff(CM->g[i]))); }
/* x30 <- host register h (BL / BLR) */
static void set_lr(E *e, int h) { if (CM->g2h[30] >= 0) mov_rr(e, 1, CM->g2h[30], h); else st64(e, mb(RBX, goff(30)), h); }
/* op reg, [rip + target]: a constant beside the code, so no scratch register is needed to hold it */
static void op_rip(E *e, int w, unsigned opc, int reg, uint64_t target) {
    rex(e, w, reg, 0, 0, 0); b1(e, opc); b1(e, (unsigned)(0x05 | (reg & 7) << 3));
    b4(e, rel32(ecur(e) + 4, target));
}
/* the current x86 flags -> the state (clobbers rax) */
static void flags_save(E *e) {
    b1(e, 0x9f);                                    /* lahf */
    b1(e, 0x0f); b1(e, 0x90); b1(e, 0xc0);          /* seto al */
    /* a 32-bit store and load, not 16: AX is a partial register, and on Intel a 16-bit write after LAHF/SETO
          costs merge uops on every flag-setting instruction. The upper bytes are don't-care (the image is AX). */
    op_m(e, 0, 0, 0, 0x89, -1, RAX, mb(RBX, OFF_NZ));   /* mov [nz], eax */
}
/* the state -> x86 flags (clobbers rax) */
static void flags_load(E *e) {
    op_m(e, 0, 0, 0, 0x8b, -1, RAX, mb(RBX, OFF_NZ));   /* mov eax, [nz] (a full write: no merge) */
    b1(e, 0x04); b1(e, 0x7f);                       /* add al, 0x7f: OF = (al == 1) */
    b1(e, 0x9e);                                    /* sahf */
}
/* arm64 condition -> x86 condition code, with the carry in borrow form. 14/15 = always (-1). */
static const int CC[16] = {4, 5, 3, 2, 8, 9, 0, 1, 7, 6, 0xd, 0xc, 0xf, 0xe, -1, -1};
static uint16_t img_of(unsigned n, unsigned z, unsigned c, unsigned v) {
    return (uint16_t)(((n << 7) | (z << 6) | 0x02 | (c ? 0 : 1)) << 8 | v);
}
static void arm2img(a64 *s) {
    uint64_t f = s->nzcv;
    s->nzcv = img_of((unsigned)(f >> 31) & 1, (unsigned)(f >> 30) & 1, (unsigned)(f >> 29) & 1, (unsigned)(f >> 28) & 1);
}
static void img2arm(a64 *s) {
    unsigned ah = (unsigned)(s->nzcv >> 8) & 0xff, al = (unsigned)s->nzcv & 1;
    s->nzcv = (uint64_t)(((ah >> 7) & 1) << 31 | ((ah >> 6) & 1) << 30 | ((~ah) & 1) << 29 | al << 28);
}

/* ───────────────────────── images and their stubs ───────────────────────── */
typedef struct {
    uint64_t tb, tlen;          /* arm64 text */
    uint64_t sb;                /* slot base */
    struct rmap map;            /* which guest registers live in host registers inside this image */
    int opt;                    /* OPT_* this image was converted with */
    uint64_t enter;             /* reload this image's registers, then jmp rax */
    uint64_t exit;              /* leave before the instruction whose address is in rdx */
    uint64_t helper;            /* run the instruction at rdx through a64_step (entered by call) */
    uint64_t ijmp, icall;       /* indirect branch: rax = target, rdx = the branch's address */
    uint64_t lookj, lookc;      /* the same, when the target is not in this image */
    uint64_t konst;             /* tb, tlen, sb as data for RIP-relative operands */
    uint8_t *ovf, *ovf_end;     /* this image's overflow area (templates longer than a slot) */
    uint64_t hot;               /* a loop got hot: the engine learns its function (entered like the helper) */
    uint8_t *lab;               /* per instruction: 1 = a label (branch target / return point: patchable NOP first),
                                   2 = a backward direct branch (counts down in cnt[]) */
    uint32_t *cnt;              /* per instruction: the back-edge countdown */
    uint8_t *hcur, *hend;       /* the hot-call stubs */
} img_t;
#define MAXIMG 256
static img_t imgs[MAXIMG];
static int nimg;
static uint64_t ENTER, EXIT_TAIL;
static uint64_t (*slot_enter)(a64 *, uint64_t slot, uint64_t enter_stub);
static uint8_t *code_lo;
static struct slot_stats st;
int slot_break;

/* CODE IS READ THROUGH slot_word(). Inside the generic host a guest code page can be SEALED (PROT_NONE, so a native
   jump into guest code faults and is redirected); the host keeps a read-only alias of it. Reading the page itself
   faulted 64 times a page while an image was converted (measured 11-16, awk). The interpreter's a64_fetch reads the
   same way. Outside the host (certifier, bench) there is no seal and the word is read in place. */
#if A2X_SLOTS
extern unsigned char *a2x_pg_sealed;
extern unsigned long a2x_alias_delta;
static uint32_t slot_word(uint64_t a) {
    if (a2x_pg_sealed && a - 0x100000000ull < 0x80000000ull && a2x_pg_sealed[(a - 0x100000000ull) >> 12] == 1) a += a2x_alias_delta;
    uint32_t w; memcpy(&w, (const void *)(uintptr_t)a, 4); return w;
}
#else
static uint32_t slot_word(uint64_t a) { uint32_t w; memcpy(&w, (const void *)(uintptr_t)a, 4); return w; }
#endif
/* n words from a into one buffer the converter reuses (conversion is single-threaded: the host holds its lock) */
static const uint32_t *slot_words(uint64_t a, size_t n) {
    static uint32_t *buf; static size_t cap;
    if (n > cap) { free(buf); cap = n; buf = malloc(n * 4); if (!buf) { cap = 0; return 0; } }
    for (size_t k = 0; k < n; k++) buf[k] = slot_word(a + 4 * k);
    return buf;
}

static const img_t *img_find(uint64_t a) {
    for (int i = 0, ni = __atomic_load_n(&nimg, __ATOMIC_ACQUIRE); i < ni; i++) if (a - imgs[i].tb < imgs[i].tlen) return &imgs[i];
    return 0;
}

/* C side of a helper slot: run one instruction through the interpreter. 0 = carry on with the next slot;
   SLOT_EXIT = leave with s->pc at the next unexecuted instruction; SLOT_EVENT|ev = it executed a control
   transfer (only reachable if the classifier sent a branch here). */
/* the helper census (slot_census = 1): which instructions the helper runs, by address, so the next templates are chosen
   from what real programs execute, not from what we guess they do */
int slot_census;
#define CEN_N 4096
static struct { uint64_t a, n; uint32_t w; } cen[CEN_N];
static void census_hit(uint64_t A, uint32_t w) {
    for (unsigned h = (unsigned)(A >> 2) & (CEN_N - 1), k = 0; k < 16; k++, h = (h + 1) & (CEN_N - 1)) {
        if (cen[h].a == A) { cen[h].n++; return; }
        if (!cen[h].a) { cen[h].a = A; cen[h].w = w; cen[h].n = 1; return; }
    }
}
void slot_census_dump(FILE *f, int top) {
    for (int t = 0; t < top; t++) {
        int b = -1;
        for (int i = 0; i < CEN_N; i++) if (cen[i].n && (b < 0 || cen[i].n > cen[b].n)) b = i;
        if (b < 0) break;
        fprintf(f, "[census] %#llx %08x %llu\n", (unsigned long long)cen[b].a, cen[b].w, (unsigned long long)cen[b].n);
        cen[b].n = 0;
    }
}
static uint64_t slot_hot_c(a64 *s, uint64_t A);
__thread uint64_t slot_ev_pc;
static uint64_t slot_helper_c(a64 *s, uint64_t A) {
    slot_ev_pc = A;
    uint32_t insn = slot_word(A);
    if (slot_census) census_hit(A, insn);
    unsigned gen = __atomic_load_n(&a64_code_gen, __ATOMIC_ACQUIRE);
    img2arm(s);
    s->pc = A;
    int ev = a64_step(s, insn);
    arm2img(s);
    st.helper++;
    if (ev == A64_NEXT) {
        s->pc = A + 4;
        /* code changed under us (IC IVAU): the slots of the changed code are stale, so leave and let the caller
           reconvert before running on */
        if (__atomic_load_n(&a64_code_gen, __ATOMIC_ACQUIRE) != gen) return SLOT_EXIT;
        return 0;
    }
    if ((ev == A64_UNDEF || ev == A64_BRK) && s->pc == A) return SLOT_EXIT;
    return SLOT_EVENT | (uint64_t)ev;
}
/* C side of an indirect branch that left its own image: {slot of the target, that image's enter stub}, or {0, 0}.
   Two words come back in rax:rdx. */
struct slot_pair { uint64_t slot, enter; };
static struct slot_pair slot_lookup_c(uint64_t t) {
    const img_t *m = img_find(t);
    struct slot_pair r = {0, 0};
    st.ilookup++;
    if (!m || (t & 3)) return r;
    r.slot = m->sb + (t - m->tb) * 8; r.enter = m->enter;
    return r;
}

/* ONE ARENA for all generated code: reserved once (1 GiB of address space; pages are only backed when written), handed
   out by a bump pointer, so any two pieces of generated code are within rel32 reach of each other. */
#define ARENA (1ull << 30)
static uint8_t *arena, *arena_cur;
static uint8_t *code_alloc(size_t n) {
    if (!arena) {
        /* MEASURED 11-16 on macOS 27.2 (Intel): a plain anonymous rwx mapping is refused (EACCES) with or without the
              cs entitlements; the same request with MAP_JIT is granted and executes. Tahoe grants both. */
        void *p = mmap(0, ARENA, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
        if (p == MAP_FAILED) p = mmap(0, ARENA, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (p == MAP_FAILED) return 0;
        arena = arena_cur = (uint8_t *)p;
    }
    n = (n + 4095) & ~(size_t)4095;
    if ((size_t)(arena + ARENA - arena_cur) < n) return 0;
    uint8_t *r = arena_cur; arena_cur += n;
    return r;
}
static uint8_t *place(E *e, uint8_t *at) { memcpy(at, e->buf, (size_t)e->n); return at + e->n; }
static void call_c(E *e, uint64_t fn) { mov_ri(e, RAX, fn); b1(e, 0xff); b1(e, 0xd0); }   /* call rax */

/* the two stubs every image shares: they touch no guest register */
static int stubs_init(void) {
    if (code_lo) return 0;
    code_lo = code_alloc(1 << 12);
    if (!code_lo) return -1;
    uint8_t *p = code_lo;
    E e;
    static const int SAVED[] = {RBX, RBP, R12, R13, R14, R15};
    /* slot_enter(state, slot, image enter stub): save the callee-saved registers and go through the image's
       enter stub. Six pushes + the return address leave rsp 8 off; the sub makes it 16-aligned for every C call. */
    e.n = 0; e.va = (uint64_t)p; ENTER = e.va;
    for (int i = 0; i < 6; i++) { rex(&e, 0, 0, 0, SAVED[i], 0); b1(&e, 0x50 + (SAVED[i] & 7)); }
    alu_ri(&e, 5, 1, RSP, 8);
    mov_rr(&e, 1, RBX, RDI);
    mov_rr(&e, 1, RAX, RSI);
    b1(&e, 0xff); b1(&e, 0xe2);                     /* jmp rdx */
    slot_enter = (uint64_t (*)(a64 *, uint64_t, uint64_t))(uintptr_t)e.va;
    p = place(&e, p);
    /* leave: the state is already written and the result is in rax */
    e.n = 0; e.va = (uint64_t)p; EXIT_TAIL = e.va;
    alu_ri(&e, 0, 1, RSP, 8);
    for (int i = 5; i >= 0; i--) { rex(&e, 0, 0, 0, SAVED[i], 0); b1(&e, 0x58 + (SAVED[i] & 7)); }
    b1(&e, 0xc3);
    p = place(&e, p);
    return 0;
}

/* Count how often each guest register is named in the image and give the busiest ones host registers. A static
   count, not a time-weighted one: the hot loop's registers are not known at conversion time. */
static void rmap_choose_w(struct rmap *mp, const uint32_t *w, size_t n, const uint64_t *wt) {
    uint64_t cnt[32] = {0};
    for (size_t k = 0; k < n; k++) {
        uint64_t one = wt ? wt[k] : 1;
        if (!one) continue;
        uint32_t i = w[k];
        struct a64_dec d;
        int id = a64_spec(i, &d);
        unsigned rd = B(i, 4, 0), rn = B(i, 9, 5), rm = B(i, 20, 16);
        switch (id) {
        case A64X_LDST_PAIR: case A64X_LDST_REG:
            cnt[rn == 31 ? GSP : rn] += one;
            if (!(d.f & 1)) { if (rd != 31) cnt[rd] += one; if (id == A64X_LDST_PAIR && d.ra != 31) cnt[d.ra] += one; }
            if (id == A64X_LDST_REG && d.op == 3 && rm != 31) cnt[rm] += one;
            break;
        case A64X_B: if (d.op) cnt[30] += one; break;
        case A64X_ADR: case A64X_MOVW: if (rd != 31) cnt[rd] += one; break;
        case A64X_ADDSUB_IMM: case A64X_LOGIC_IMM:
            cnt[rn == 31 ? GSP : rn] += one; cnt[rd == 31 ? GSP : rd] += one; break;
        default:
            if ((B(i, 28, 25) & 0x7) == 0x7) break;                  /* FP/SIMD: vector registers */
            if (rd != 31) cnt[rd] += one;
            if (rn != 31) cnt[rn] += one;
            if (rm != 31) cnt[rm] += one;
            if (B(i, 31, 25) == 0x6b) cnt[30] += one;                     /* blr/ret */
            break;
        }
    }
    cnt[GSP] += 1;                                                   /* ties go to sp */
    if (OPT & OPT_RSP) cnt[GSP] = 0;                                 /* sp lives in rsp: not one of the eleven */
    if (0) {}
    memset(mp->g2h, -1, sizeof mp->g2h);
    mp->n = 0;
    for (int k = 0; k < NHOST; k++) {
        int best = -1;
        for (int g = 0; g < 32; g++) if (mp->g2h[g] < 0 && cnt[g] && (best < 0 || cnt[g] > cnt[best])) best = g;
        if (best < 0) break;
        mp->g2h[best] = (int8_t)HOSTREGS[k];
        mp->g[mp->n] = (int8_t)best; mp->h[mp->n] = (int8_t)HOSTREGS[k]; mp->n++;
        cnt[best] = 0;
    }
    /* OPT_RSP: the guest stack pointer IS the host rsp, and it is reloaded LAST (after it, the host stack is gone
          until a stub switches back to state->hostsp). Nothing in a slot pushes or calls in this mode: the helper is
          reached by jmp with the resume address in rcx, and every stub that calls C runs on the host stack. */
    if (OPT & OPT_RSP) { mp->g2h[GSP] = RSP; mp->g[mp->n] = GSP; mp->h[mp->n] = RSP; mp->n++; }
}

static void rmap_choose(struct rmap *mp, const uint32_t *w, size_t n) { rmap_choose_w(mp, w, n, 0); }

/* the stubs that spill or reload: one set per image, because each image has its own map */
static uint8_t *emit_image_stubs(img_t *m, uint8_t *p) {
    E e;
    CM = &m->map; OPT = m->opt;
    int R = OPT & OPT_RSP;
    /* constants for the RIP-relative operands */
    m->konst = (uint64_t)(uintptr_t)p;
    memcpy(p, &m->tb, 8); memcpy(p + 8, &m->tlen, 8); memcpy(p + 16, &m->sb, 8);
    p += 32;
    /* enter: rax = slot */
    e.n = 0; e.va = (uint64_t)p; m->enter = e.va;
    if (R) st64(&e, mb(RBX, OFF_HOSTSP), RSP);      /* the host stack, for every stub that calls C */
    reload_all(&e);
    b1(&e, 0xff); b1(&e, 0xe0);                     /* jmp rax */
    p = place(&e, p);
    /* exit before the instruction at rdx */
    e.n = 0; e.va = (uint64_t)p; m->exit = e.va;
    st64(&e, mb(RBX, OFF_PC), RDX);
    spill_all(&e);
    if (R) ld64(&e, RSP, mb(RBX, OFF_HOSTSP));
    mov_ri(&e, RAX, SLOT_EXIT);
    jmp_to(&e, EXIT_TAIL);
    p = place(&e, p);
    /* helper: entered by `call` from a slot, rdx = the instruction's address; rsp is 8 off on entry */
    e.n = 0; e.va = (uint64_t)p; m->helper = e.va;
    spill_all(&e);
    if (R) {                                        /* entered by jmp, resume address in rcx; the host stack from here */
        ld64(&e, RSP, mb(RBX, OFF_HOSTSP));
        b1(&e, 0x51);                               /* push rcx */
        alu_ri(&e, 5, 1, RSP, 8);
    }
    mov_rr(&e, 1, RDI, RBX); mov_rr(&e, 1, RSI, RDX);
    if (!R) alu_ri(&e, 5, 1, RSP, 8);
    call_c(&e, (uint64_t)(uintptr_t)slot_helper_c);
    alu_ri(&e, 0, 1, RSP, 8);
    if (R) b1(&e, 0x59);                            /* pop rcx */
    alu_rr(&e, 0x85, 1, RAX, RAX);
    int j = jcc8(&e, 5);                            /* jnz leave */
    reload_all(&e);
    if (R) { b1(&e, 0xff); b1(&e, 0xe1); }          /* jmp rcx */
    else b1(&e, 0xc3);
    fix8(&e, j);
    if (!R) alu_ri(&e, 0, 1, RSP, 8);               /* drop the return address into the slot */
    jmp_to(&e, EXIT_TAIL);
    p = place(&e, p);
    /* hot: a back-edge counter reached zero; the same entry as the helper, rdx = the branch's address */
    e.n = 0; e.va = (uint64_t)p; m->hot = e.va;
    spill_all(&e);
    if (R) {                                        /* entered by jmp, resume address in rcx; the host stack from here */
        ld64(&e, RSP, mb(RBX, OFF_HOSTSP));
        b1(&e, 0x51);                               /* push rcx */
        alu_ri(&e, 5, 1, RSP, 8);
    }
    mov_rr(&e, 1, RDI, RBX); mov_rr(&e, 1, RSI, RDX);
    if (!R) alu_ri(&e, 5, 1, RSP, 8);
    call_c(&e, (uint64_t)(uintptr_t)slot_hot_c);
    alu_ri(&e, 0, 1, RSP, 8);
    if (R) b1(&e, 0x59);                            /* pop rcx */
    alu_rr(&e, 0x85, 1, RAX, RAX);
    int jh = jcc8(&e, 5);                            /* jnz leave */
    reload_all(&e);
    if (R) { b1(&e, 0xff); b1(&e, 0xe1); }          /* jmp rcx */
    else b1(&e, 0xc3);
    fix8(&e, jh);
    if (!R) alu_ri(&e, 0, 1, RSP, 8);               /* drop the return address into the slot */
    jmp_to(&e, EXIT_TAIL);
    p = place(&e, p);
    /* indirect branch out of this image: rax = target, rdx = the branch's address */
    for (int call = 0; call < 2; call++) {
        e.n = 0; e.va = (uint64_t)p;
        if (call) m->lookc = e.va; else m->lookj = e.va;
        spill_all(&e);
        if (R) ld64(&e, RSP, mb(RBX, OFF_HOSTSP));
        b1(&e, 0x52);                               /* push rdx: the branch's address (8 + 8 keeps alignment) */
        alu_ri(&e, 5, 1, RSP, 8);
        mov_rr(&e, 1, RDI, RAX);
        call_c(&e, (uint64_t)(uintptr_t)slot_lookup_c);   /* rax = slot, rdx = its image's enter stub */
        alu_ri(&e, 0, 1, RSP, 8);
        b1(&e, 0x59);                               /* pop rcx */
        alu_rr(&e, 0x85, 1, RAX, RAX);
        int miss = jcc8(&e, 4);
        if (call) { lea(&e, RCX, mb(RCX, 4)); st64(&e, mb(RBX, goff(30)), RCX); }   /* x30, in the state: the target image reloads it */
        b1(&e, 0xff); b1(&e, 0xe2);                 /* jmp rdx: the target image's enter stub, rax = slot */
        fix8(&e, miss);
        st64(&e, mb(RBX, OFF_PC), RCX);             /* leave before the branch; the state is already written */
        mov_ri(&e, RAX, SLOT_EXIT);
        jmp_to(&e, EXIT_TAIL);
        p = place(&e, p);
    }
    /* indirect branch: in this image and aligned -> straight to the slot; otherwise the lookup */
    for (int call = 0; call < 2; call++) {
        e.n = 0; e.va = (uint64_t)p;
        if (call) m->icall = e.va; else m->ijmp = e.va;
        mov_rr(&e, 1, RCX, RAX);
        op_rip(&e, 1, 0x2b, RCX, m->konst);                           /* sub rcx, [tb] */
        op_rip(&e, 1, 0x3b, RCX, m->konst + 8);                       /* cmp rcx, [tlen] */
        jcc_to(&e, 3, call ? m->lookc : m->lookj);                    /* jae: not in this image */
        b1(&e, 0xf6); b1(&e, 0xc1); b1(&e, 3);                        /* test cl, 3 */
        jcc_to(&e, 5, call ? m->lookc : m->lookj);                    /* misaligned: the lookup refuses it */
        if (call) { lea(&e, RAX, mb(RDX, 4)); set_lr(&e, RAX); }
        b1(&e, 0x48); b1(&e, 0x8d); b1(&e, 0x04); b1(&e, 0xcd); b4(&e, 0);   /* lea rax, [rcx*8 + 0] (no base: mod 00, base 101) */
        op_rip(&e, 1, 0x03, RAX, m->konst + 16);                      /* add rax, [sb] */
        b1(&e, 0xff); b1(&e, 0xe0);                                   /* jmp rax */
        p = place(&e, p);
    }
    return p;
}

/* ───────────────────────── templates ───────────────────────── */
enum { K_TEMPLATE, K_HELPER, K_EXIT };
static int in_img(const img_t *m, uint64_t t) { return t - m->tb < m->tlen && !(t & 3); }
static uint64_t slot_of(const img_t *m, uint64_t a) { return m->sb + (a - m->tb) * 8; }
static uint64_t branch_to(const void *m, uint64_t t) { return X.tgt ? X.tgt(t) : slot_of((const img_t *)m, t); }
static void emit_exit(E *e, const img_t *m, uint64_t A) { mov_ri(e, RDX, A); jmp_to(e, m->exit); }
/* run the instruction at A through the interpreter and come back to the next one */
static void emit_hot_call(E *e, const img_t *m, uint64_t A) {
    if (!(m->opt & OPT_RSP)) { mov_ri(e, RDX, A); call_to(e, m->hot); return; }
    b1(e, 0x48); b1(e, 0x8d); b1(e, 0x0d); int at = e->n; b4(e, 0);   /* lea rcx, [rip + resume] */
    mov_ri(e, RDX, A); jmp_to(e, m->hot);
    uint32_t disp = (uint32_t)(e->n - (at + 4)); memcpy(e->buf + at, &disp, 4);
}
static void emit_helper_call(E *e, const img_t *m, uint64_t A) {
    if (!(m->opt & OPT_RSP)) { mov_ri(e, RDX, A); call_to(e, m->helper); return; }
    b1(e, 0x48); b1(e, 0x8d); b1(e, 0x0d); int at = e->n; b4(e, 0);   /* lea rcx, [rip + resume] */
    mov_ri(e, RDX, A); jmp_to(e, m->helper);
    uint32_t disp = (uint32_t)(e->n - (at + 4)); memcpy(e->buf + at, &disp, 4);
}

/* load/store address -> M; may load rcx (base) and rdx (index) */
static M ldst_addr(E *e, const struct a64_dec *d, int pair, int64_t *wboff, int *wb) {
    gld(e, RCX, d->rn, 1);
    int64_t imm = (int64_t)d->imm;
    *wb = 0; *wboff = 0;
    if (pair) {
        if (d->op == 1) { *wb = 1; *wboff = imm; return mb(RCX, 0); }
        if (d->op == 3) { *wb = 1; *wboff = imm; }
        return mb(RCX, (int32_t)imm);
    }
    switch (d->op) {
    case 0: return mb(RCX, (int32_t)imm);
    case 1: *wb = 1; *wboff = imm; return mb(RCX, 0);
    case 2: *wb = 1; *wboff = imm; return mb(RCX, (int32_t)imm);
    default: {
        gld(e, RDX, d->rm, 0);
        switch (d->ra) { case 2: mov_rr(e, 0, RDX, RDX); break; case 6: op_r(e, 1, 0, 0x63, -1, RDX, RDX); break; default: break; }
        /* a Q register's index scales by 16 and x86 addressing stops at 8: the scale field took 4 & 3 = 0 and
              every scaled q access with a register index went to the wrong address (certifier, 11-16) */
        if (d->S > 3) { sh_ri(e, 4, 1, RDX, d->S); M m = {RCX, RDX, 0, 0}; return m; }
        M m = {RCX, RDX, d->S, 0};
        return m;
    }
    }
}
static void wback(E *e, const struct a64_dec *d, int wb, int64_t off) {
    if (!wb) return;
    if (off) lea(e, RCX, mb(RCX, (int32_t)off));
    gst(e, d->rn, RCX, 1, 1);
}
/* load n bytes from m into rax; sign/to64 as the interpreter's ldwrite */
static void load_n(E *e, int h, M m, unsigned n, int sign, int to64) {
    switch (n) {
    case 1: op_m(e, 0, sign && to64, 0, 0x0f, sign ? 0xbe : 0xb6, h, m); break;
    case 2: op_m(e, 0, sign && to64, 0, 0x0f, sign ? 0xbf : 0xb7, h, m); break;
    case 4: if (sign) op_m(e, 0, 1, 0, 0x63, -1, h, m); else op_m(e, 0, 0, 0, 0x8b, -1, h, m); break;
    default: ld64(e, h, m); break;
    }
}
static void store_n(E *e, M m, int h, unsigned n) {
    switch (n) {
    case 1: op_m(e, 0, 0, h >= 4, 0x88, -1, h, m); break;
    case 2: op_m(e, 1, 0, 0, 0x89, -1, h, m); break;
    case 4: op_m(e, 0, 0, 0, 0x89, -1, h, m); break;
    default: st64(e, m, h); break;
    }
}

/* FP/SIMD register <-> memory, n = 1..16 bytes (OFF_V is defined with the FP/SIMD templates below) */
static void v_load(E *e, M a, unsigned n, int vr);
static void v_store(E *e, M a, unsigned n, int vr);

/* OPT_INPLACE: when the guest registers an instruction names all live in host registers, operate on those
      registers directly instead of copying through rcx/rdx and back. -1 = not this shape, use the general template.
      The same rules as the general template: x6/x7 writes keep the general path (the argw mark), a 32-bit result is
      zero-extended by the 32-bit op itself, and flags follow fuse_out exactly as there. */
static int hreg(int r, int sp) { if (r == 31) return sp ? CM->g2h[GSP] : -2; return CM->g2h[r]; }
/* the x6/x7 write marks as plain byte stores into state->argwx (no read-modify-write, no flags) */
static void argmark(E *e, int r) { if (r == 6 || r == 7) { op_m(e, 0, 0, 0, 0xc6, -1, 0, mb(RBX, OFF_ARGWX + (r - 6))); b1(e, 1); } }
/* a guest register as an operand: its host register, or loaded into scratch h (zero for ZR / sp=0) */
static int opnd(E *e, int r, int sp, int h) { int x = hreg(r, sp); if (x >= 0) return x; gld(e, h, r, sp); return h; }
static int emit_inplace(E *e, const img_t *m, uint64_t A, int id, const struct a64_dec *dd, uint32_t i) {
    struct a64_dec d = *dd; int sf = d.sf;
    static const int SH[4] = {4, 5, 7, 1};
    switch (id) {
    case A64X_ADDSUB_IMM: {
        if (slot_break) d.imm += 1;
        int hn = hreg(d.rn, 1), hd = hreg(d.rd, d.S ? 0 : 1);
        int32_t im = (int32_t)d.imm;
        if (d.S && d.rd == 31 && d.op && hn >= 0) { alu_ri(e, 7, sf, hn, im); if (!X.fuse_out) flags_save(e); return K_TEMPLATE; }   /* CMP */
        if (hn < 0 || hd < 0) return -1;
        argmark(e, d.rd);
        if (hd != hn) mov_rr(e, 1, hd, hn);
        if (d.imm || d.S) alu_ri(e, d.op ? 5 : 0, sf, hd, im);
        else if (!sf) mov_rr(e, 0, hd, hd);
        if (d.S) { if (!d.op) b1(e, 0xf5); if (!X.fuse_out) flags_save(e); }
        return K_TEMPLATE;
    }
    case A64X_ADDSUB_REG: {
        int ha, hb;
        if (!d.f) {                                                     /* shifted: Rn reads ZR */
            if (d.rn == 31) return -1;
            if (d.imm == 0) hb = opnd(e, d.rm, 0, RCX);
            else { gld(e, RCX, d.rm, 0); sh_ri(e, SH[d.ra], sf, RCX, (unsigned)d.imm); hb = RCX; }
            ha = opnd(e, d.rn, 0, RDX);
        } else {                                                        /* extended: Rn is SP-capable */
            gld(e, RCX, d.rm, 0);
            switch (d.ra) {
            case 0: op_r(e, 0, 0, 0x0f, 0xb6, RCX, RCX); break;
            case 1: op_r(e, 0, 0, 0x0f, 0xb7, RCX, RCX); break;
            case 2: mov_rr(e, 0, RCX, RCX); break;
            case 4: op_r(e, 1, 0, 0x0f, 0xbe, RCX, RCX); break;
            case 5: op_r(e, 1, 0, 0x0f, 0xbf, RCX, RCX); break;
            case 6: op_r(e, 1, 0, 0x63, -1, RCX, RCX); break;
            default: break;
            }
            sh_ri(e, 4, 1, RCX, (unsigned)d.imm);
            hb = RCX; ha = opnd(e, d.rn, 1, RDX);
        }
        if (d.S && d.rd == 31) {                                        /* CMP / CMN */
            if (d.op) alu_rr(e, 0x39, sf, ha, hb);
            else { mov_rr(e, 1, RAX, ha); alu_rr(e, 0x01, sf, RAX, hb); b1(e, 0xf5); }
            if (!X.fuse_out) flags_save(e);
            return K_TEMPLATE;
        }
        int hd = hreg(d.rd, d.S ? 0 : 1);
        if (hd < 0) return -1;
        argmark(e, d.rd);
        unsigned opc = d.op ? 0x29 : 0x01;
        if (hd == ha) alu_rr(e, opc, sf, hd, hb);
        else if (hd == hb) {
            if (d.op) { mov_rr(e, 1, RCX, hb); mov_rr(e, 1, hd, ha); alu_rr(e, opc, sf, hd, RCX); }
            else alu_rr(e, opc, sf, hd, ha);
        } else { mov_rr(e, 1, hd, ha); alu_rr(e, opc, sf, hd, hb); }
        if (d.S) { if (!d.op) b1(e, 0xf5); if (!X.fuse_out) flags_save(e); }
        return K_TEMPLATE;
    }
    case A64X_LOGIC_REG: {
        int hd = hreg(d.rd, 0);
        if (d.op == 1 && d.rn == 31 && !d.f && !d.ra) {                 /* MOV */
            if (hd < 0) return -1;
            argmark(e, d.rd);
            int hm = hreg(d.rm, 0);
            if (hm >= 0) mov_rr(e, sf, hd, hm);
            else if (d.rm == 31) mov_ri(e, hd, 0);
            else { ld64(e, hd, mb(RBX, goff(d.rm))); if (!sf) mov_rr(e, 0, hd, hd); }
            return K_TEMPLATE;
        }
        if (d.rn == 31) return -1;
        int hb;
        if (!d.ra && !d.f) hb = opnd(e, d.rm, 0, RCX);
        else { gld(e, RCX, d.rm, 0); sh_ri(e, SH[d.S], sf, RCX, d.ra); if (d.f) unary(e, 2, sf, RCX); hb = RCX; }
        int ha = opnd(e, d.rn, 0, RDX);
        if (d.op == 3 && d.rd == 31) { alu_rr(e, 0x85, sf, ha, hb); b1(e, 0xf9); if (!X.fuse_out) flags_save(e); return K_TEMPLATE; }   /* TST */
        if (hd < 0) return -1;
        argmark(e, d.rd);
        unsigned opc = d.op == 1 ? 0x09 : d.op == 2 ? 0x31 : 0x21;
        if (hd == ha) alu_rr(e, opc, sf, hd, hb);
        else if (hd == hb) alu_rr(e, opc, sf, hd, ha);                  /* and/or/eor commute */
        else { mov_rr(e, 1, hd, ha); alu_rr(e, opc, sf, hd, hb); }
        if (d.op == 3) { b1(e, 0xf9); if (!X.fuse_out) flags_save(e); }
        return K_TEMPLATE;
    }
    case A64X_MOVW: {
        int hd = hreg(d.rd, 0);
        if (hd < 0) return -1;
        argmark(e, d.rd);
        if (d.op == 0) mov_ri(e, hd, trw(~d.imm, sf));
        else if (d.op == 2) mov_ri(e, hd, d.imm);
        else {
            mov_ri(e, RAX, ~(0xffffULL << (16 * d.ra))); alu_rr(e, 0x21, 1, hd, RAX);
            mov_ri(e, RAX, d.imm); alu_rr(e, 0x09, 1, hd, RAX);
            if (!sf) mov_rr(e, 0, hd, hd);
        }
        return K_TEMPLATE;
    }
    case A64X_MADD: {                                                   /* MADD / MSUB / MUL / MNEG */
        int hd = hreg(d.rd, 0);
        if (hd < 0) return -1;
        gld(e, RAX, d.rn, 0);
        int hm = opnd(e, d.rm, 0, RCX);
        imul_rr(e, sf, RAX, hm);
        argmark(e, d.rd);
        if (d.ra == 31) { if (d.op) unary(e, 3, sf, RAX); mov_rr(e, sf, hd, RAX); }
        else { int ha = opnd(e, d.ra, 0, RDX); mov_rr(e, 1, hd, ha); alu_rr(e, d.op ? 0x29 : 0x01, sf, hd, RAX); }
        return K_TEMPLATE;
    }
    case A64X_LDST_REG: {
        int V = d.f & 1, is_load = (d.f >> 1) & 1, sign = (d.f >> 2) & 1, to64 = (d.f >> 3) & 1, prfm = (d.f >> 4) & 1;
        if (V || prfm) return -1;
        int wb = d.op == 1 || d.op == 2;
        int hb = hreg(d.rn, 1);
        if (hb < 0) { if (wb) return -1; gld(e, RCX, d.rn, 1); hb = RCX; }
        if (wb && is_load && d.rd == d.rn) return -1;
        M a;
        if (d.op == 3) {
            int hi;
            if (d.rm == 31) hi = -1;
            else if (d.ra == 3 || d.ra == 7) hi = opnd(e, d.rm, 0, RDX);
            else if (d.ra == 2) { int x = opnd(e, d.rm, 0, RDX); mov_rr(e, 0, RDX, x); hi = RDX; }
            else if (d.ra == 6) { int x = opnd(e, d.rm, 0, RDX); op_r(e, 1, 0, 0x63, -1, RDX, x); hi = RDX; }
            else return -1;
            if (hi == RSP) return -1;
            a = hi < 0 ? mb(hb, 0) : (M){hb, hi, d.S, 0};
        } else a = mb(hb, d.op == 1 ? 0 : (int32_t)(int64_t)d.imm);
        if (is_load) {
            int ht = hreg(d.rd, 0);
            if (ht >= 0) { argmark(e, d.rd); load_n(e, ht, a, d.sf, sign, to64); }
            else { load_n(e, RAX, a, d.sf, sign, to64); ZXD = 1; gst(e, d.rd, RAX, sign ? to64 : d.sf == 8, 0); }
        } else {
            if (d.rd == 31) {                                           /* store zero: an immediate, no register */
                switch (d.sf) {
                case 1: op_m(e, 0, 0, 0, 0xc6, -1, 0, a); b1(e, 0); break;
                case 2: op_m(e, 1, 0, 0, 0xc7, -1, 0, a); b1(e, 0); b1(e, 0); break;
                case 4: op_m(e, 0, 0, 0, 0xc7, -1, 0, a); b4(e, 0); break;
                default: op_m(e, 0, 1, 0, 0xc7, -1, 0, a); b4(e, 0); break;
                }
            } else store_n(e, a, opnd(e, d.rd, 0, RAX), d.sf);
        }
        if (wb) lea(e, hb, mb(hb, (int32_t)(int64_t)d.imm));
        return K_TEMPLATE;
    }
    case A64X_CB: {
        uint64_t t = A + d.imm;
        if (!in_img(m, t)) return -1;
        int ht = opnd(e, d.rd, 0, RCX);
        alu_rr(e, 0x85, sf, ht, ht);
        jcc_to(e, d.op ? 5 : 4, branch_to(m, t));
        return K_TEMPLATE;
    }
    case A64X_TB: {
        uint64_t t = A + d.imm;
        if (!in_img(m, t)) return -1;
        int ht = opnd(e, d.rd, 0, RCX);
        op_r(e, 1, 0, 0x0f, 0xba, 4, ht); b1(e, d.ra);
        jcc_to(e, d.op ? 2 : 3, branch_to(m, t));
        return K_TEMPLATE;
    }
    default: break;
    }
    if (id != A64X_NONE) return -1;
    /* forms without a pre-decode: the same tests as emit_insn's own */
    int rd = (int)B(i, 4, 0), rn = (int)B(i, 9, 5), rm = (int)B(i, 20, 16);
    sf = (int)BIT(i, 31);
    unsigned D = sf ? 64 : 32;
    int hd = hreg(rd, 0);
    if (hd < 0) return -1;
    if (B(i, 28, 23) == 0x26) {                                         /* SBFM / UBFM */
        unsigned opc = B(i, 30, 29), N = BIT(i, 22), immr = B(i, 21, 16), imms = B(i, 15, 10);
        if (!((opc == 0 || opc == 2) && N == (unsigned)sf && (sf || (immr < 32 && imms < 32)))) return -1;
        int ext = opc == 0 ? 7 : 5;
        int hn = opnd(e, rn, 0, RCX);
        argmark(e, rd);
        mov_rr(e, 1, hd, hn);
        unsigned l, r;
        if (imms >= immr) { unsigned w = imms - immr + 1; l = D - 1 - imms; r = D - w; }
        else { unsigned w = imms + 1; l = D - w; r = immr - imms - 1; }
        sh_ri(e, 4, sf, hd, l); sh_ri(e, ext, sf, hd, r);
        if (!sf && !l && !r) mov_rr(e, 0, hd, hd);
        return K_TEMPLATE;
    }
    if (B(i, 30, 29) == 0 && B(i, 28, 23) == 0x27 && !BIT(i, 21)) {   /* EXTR / ROR */
        unsigned N = BIT(i, 22), lsb = B(i, 15, 10);
        if (!(N == (unsigned)sf && (sf || lsb < 32))) return -1;
        argmark(e, rd);
        if (rn == rm) {
            int hn = opnd(e, rn, 0, RCX);
            mov_rr(e, 1, hd, hn);
            if (lsb) sh_ri(e, 1, sf, hd, lsb); else if (!sf) mov_rr(e, 0, hd, hd);
            return K_TEMPLATE;
        }
        gld(e, RDX, rn, 0);                                             /* the high half, copied before hd changes */
        int hm = opnd(e, rm, 0, RCX);
        mov_rr(e, 1, hd, hm);
        if (lsb) { op_r(e, sf, 0, 0x0f, 0xac, RDX, hd); b1(e, lsb); } else if (!sf) mov_rr(e, 0, hd, hd);
        return K_TEMPLATE;
    }
    if (B(i, 28, 24) == 0x1b && B(i, 30, 29) == 0 && sf) {             /* long multiplies, high halves */
        unsigned op31 = B(i, 23, 21), o0 = BIT(i, 15); int ra = (int)B(i, 14, 10);
        if (op31 == 1 || op31 == 5) {
            int hn = opnd(e, rn, 0, RAX);
            if (op31 == 1) op_r(e, 1, 0, 0x63, -1, RAX, hn); else mov_rr(e, 0, RAX, hn);
            int hm = opnd(e, rm, 0, RCX);
            if (op31 == 1) op_r(e, 1, 0, 0x63, -1, RCX, hm); else mov_rr(e, 0, RCX, hm);
            imul_rr(e, 1, RAX, RCX);
            argmark(e, rd);
            if (ra == 31) { if (o0) unary(e, 3, 1, RAX); mov_rr(e, 1, hd, RAX); }
            else { int ha = opnd(e, ra, 0, RDX); mov_rr(e, 1, hd, ha); alu_rr(e, o0 ? 0x29 : 0x01, 1, hd, RAX); }
            return K_TEMPLATE;
        }
        if ((op31 == 2 || op31 == 6) && !o0) {
            gld(e, RAX, rn, 0);
            int hm = opnd(e, rm, 0, RCX);
            unary(e, op31 == 2 ? 5 : 4, 1, hm);
            argmark(e, rd);
            mov_rr(e, 1, hd, RDX);
            return K_TEMPLATE;
        }
        return -1;
    }
    if (!BIT(i, 30) && !BIT(i, 29) && B(i, 28, 21) == 0xd6) {          /* LSLV LSRV ASRV RORV */
        unsigned opc = B(i, 15, 10);
        if (opc < 8 || opc > 11) return -1;
        gld(e, RCX, rm, 0);
        int hn = opnd(e, rn, 0, RAX);
        argmark(e, rd);
        mov_rr(e, 1, hd, hn);
        sh_rcl(e, SH[opc - 8], sf, hd);
        return K_TEMPLATE;
    }
    return -1;
}

/* ───────────────────────── FP / SIMD ─────────────────────────
    The vector registers stay in the state (s->v, 16-byte aligned); xmm0/xmm1 are scratch, nothing lives in them
   between instructions. Every form here copies the interpreter's own definition (a64_fpsc.c, a64_simd*.c):
 a scalar write zeroes the rest of the register (vzw), a 64-bit vector op zeroes the upper half;
 FP arithmetic is the host's IEEE double/single op, round-to-nearest, exactly what a64_fpsc.c computes;
 ANY NaN RESULT TAKES THE SLOW PATH: the inputs are untouched until the result is stored, so the helper
     re-runs the instruction through a64_step and the NaN that comes out is the interpreter's, bit for bit
     (x86 and arm64 disagree on which NaN propagates and on the sign of a generated one);
 FCVTZS: cvtt*2si's out-of-range/NaN answer is one sentinel value, and that value also goes to the helper
     (which saturates the way the architecture says); a true INT_MIN result just takes the slow road. */
#define OFF_V(r) ((int32_t)(offsetof(a64, v) + 16 * (r)))
static void sse_m(E *e, unsigned pfx, unsigned op, int x, M m) {
    if (pfx) b1(e, pfx);
    rex(e, 0, x, m.index < 0 ? 0 : m.index, m.base, 0); b1(e, 0x0f); b1(e, op); modrm_mem(e, x, m);
}
static void sse_r(E *e, unsigned pfx, int w, unsigned op, int reg, int rm) {
    if (pfx) b1(e, pfx);
    rex(e, w, reg, 0, rm, 0); b1(e, 0x0f); b1(e, op); b1(e, (unsigned)(0xc0 | (reg & 7) << 3 | (rm & 7)));
}
#define XMM0 0
#define XMM1 1
static void v_load(E *e, M a, unsigned n, int vr) {
    if (n == 16) { sse_m(e, 0xf3, 0x6f, XMM0, a); sse_m(e, 0xf3, 0x7f, XMM0, mb(RBX, OFF_V(vr))); return; }
    if (n == 8) sse_m(e, 0xf3, 0x7e, XMM0, a);                      /* movq xmm0, m64 (zero-extends) */
    else if (n == 4) sse_m(e, 0x66, 0x6e, XMM0, a);                 /* movd xmm0, m32 */
    else { load_n(e, RAX, a, n, 0, 1); sse_r(e, 0x66, 1, 0x6e, XMM0, RAX); }
    sse_m(e, 0xf3, 0x7f, XMM0, mb(RBX, OFF_V(vr)));
}
static void v_store(E *e, M a, unsigned n, int vr) {
    if (n == 16) { sse_m(e, 0xf3, 0x6f, XMM0, mb(RBX, OFF_V(vr))); sse_m(e, 0xf3, 0x7f, XMM0, a); return; }
    ld64(e, RAX, mb(RBX, OFF_V(vr)));
    store_n(e, a, RAX, n);
}
static void v_set_gp(E *e, int vr, int h) {                       /* v[vr] = zero-extended h: movq xmm0, h; one 16-byte store */
    sse_r(e, 0x66, 1, 0x6e, XMM0, h);
    sse_m(e, 0xf3, 0x7f, XMM0, mb(RBX, OFF_V(vr)));
}
/* the template's slow path: run this one instruction through the helper, then carry on after the template */
static void slow_tail(E *e, const img_t *m, uint64_t A, int jslow) {
    int jd = jcc8(e, -1);
    fix8(e, jslow);
    emit_helper_call(e, m, A);
    fix8(e, jd);
}
static int emit_fpsimd(E *e, const img_t *m, uint64_t A, uint32_t i) {
    unsigned rd = B(i, 4, 0), rn = B(i, 9, 5), rm = B(i, 20, 16);
    /* hints (NOP, YIELD, the PAC-on-LR and BTI hints): the interpreter's a64_brsys.c returns A64_NEXT for crn == 2 */
    if (B(i, 31, 22) == 0x354 && B(i, 20, 19) == 0 && B(i, 4, 0) == 0x1f && B(i, 15, 12) == 2) return K_TEMPLATE;
    /* the PAC data family (PACIA..XPACD, opcode <= 0x11): identity on the value, nothing written (a64_dpreg.c) */
    if (B(i, 30, 21) == 0x2d6 && !BIT(i, 29) && B(i, 20, 16) == 1 && B(i, 15, 10) <= 0x11) return K_TEMPLATE;

    /* Advanced SIMD three-same, integer: 0 Q U 01110 size 1 Rm opcode 1 Rn Rd */
    if (!BIT(i, 31) && B(i, 28, 24) == 0x0e && BIT(i, 21) && BIT(i, 10)) {
        unsigned Q = BIT(i, 30), U = BIT(i, 29), size = B(i, 23, 22), opc = B(i, 15, 11);
        int op = -1, swap = 0;
        if (opc == 0x03) {                                          /* logical: size picks the op */
            static const int LU0[4] = {0xdb, 0xdf, 0xeb, -1}, LU1[4] = {0xef, -1, -1, -1};   /* and bic orr (orn) / eor (bsl bit bif) */
            op = U ? LU1[size] : LU0[size];
            swap = !U && size == 1;                                 /* BIC = n & ~m = pandn with m first */
        } else if (opc == 0x10 && (Q || size != 3)) {              /* ADD / SUB (.1d is reserved: the interpreter refuses it) */
            static const int AD[4] = {0xfc, 0xfd, 0xfe, 0xd4}, SB[4] = {0xf8, 0xf9, 0xfa, 0xfb};
            op = U ? SB[size] : AD[size];
        } else if (size <= 1 && (opc == 0x01 || opc == 0x05)) {     /* saturating add / sub, bytes and halfwords */
            static const int T[2][2][2] = {{{0xec, 0xed}, {0xe8, 0xe9}}, {{0xdc, 0xdd}, {0xd8, 0xd9}}};   /* [U][sub][size] */
            op = T[U][opc == 0x05][size];
        } else if (opc == 0x11 && U && size <= 2) {                 /* CMEQ */
            op = 0x74 + size;
        } else if (opc == 0x06 && !U && size <= 2) {                /* CMGT (signed) */
            op = 0x64 + size;
        }
        if (op < 0) return -1;
        if (swap) { sse_m(e, 0xf3, 0x6f, XMM0, mb(RBX, OFF_V(rm))); sse_m(e, 0xf3, 0x6f, XMM1, mb(RBX, OFF_V(rn))); }
        else { sse_m(e, 0xf3, 0x6f, XMM0, mb(RBX, OFF_V(rn))); sse_m(e, 0xf3, 0x6f, XMM1, mb(RBX, OFF_V(rm))); }
        sse_r(e, 0x66, 0, (unsigned)op, XMM0, XMM1);
        if (!Q) sse_r(e, 0xf3, 0, 0x7e, XMM0, XMM0);                /* movq xmm0, xmm0: a 64-bit op zeroes the top */
        sse_m(e, 0xf3, 0x7f, XMM0, mb(RBX, OFF_V(rd)));
        return K_TEMPLATE;
    }
    /* Advanced SIMD modified immediate (MOVI / MVNI / FMOV vector): the result is a constant whenever it does not read
       Rd, and then the interpreter itself computes it once, here, on a scratch state; ORR/BIC immediate read Rd. */
    if (!BIT(i, 31) && B(i, 28, 19) == 0x1e0 && BIT(i, 10)) {
        unsigned cmode = B(i, 15, 12);
        if ((cmode & 1) && cmode < 12) return -1;                   /* ORR / BIC (immediate) */
        static a64 t1, t2;
        memset(&t1, 0, sizeof t1); memset(&t2, 0xa5, sizeof t2);
        t1.pc = t2.pc = A;
        if (a64_step(&t1, i) != A64_NEXT || a64_step(&t2, i) != A64_NEXT || memcmp(t1.v[rd], t2.v[rd], 16)) return -1;
        uint64_t lo, hi; memcpy(&lo, t1.v[rd], 8); memcpy(&hi, t1.v[rd] + 8, 8);
        mov_ri(e, RAX, lo); sse_r(e, 0x66, 1, 0x6e, XMM0, RAX);
        if (hi) { if (hi != lo) mov_ri(e, RAX, hi); sse_r(e, 0x66, 1, 0x6e, XMM1, RAX); sse_r(e, 0x66, 0, 0x6c, XMM0, XMM1); }   /* punpcklqdq */
        sse_m(e, 0xf3, 0x7f, XMM0, mb(RBX, OFF_V(rd)));
        return K_TEMPLATE;
    }

    /* scalar floating point: M=0 S=0 11110 type 1 ..., single (type 0) and double (type 1) only */
    if (B(i, 30, 24) == 0x1e && BIT(i, 21) && B(i, 23, 22) <= 1) {
        unsigned type = B(i, 23, 22), sf = BIT(i, 31);
        unsigned pfx = type ? 0xf2 : 0xf3;                          /* sd / ss */
        M vn = mb(RBX, OFF_V(rn)), vm = mb(RBX, OFF_V(rm)), vd = mb(RBX, OFF_V(rd));
        if (!sf && B(i, 11, 10) == 2) {                             /* 2-source: FMUL FDIV FADD FSUB */
            unsigned opcode = B(i, 15, 12);
            static const unsigned OP[4] = {0x59, 0x5e, 0x58, 0x5c};
            if (opcode > 3) return -1;
            sse_m(e, pfx, 0x10, XMM0, vn); sse_m(e, pfx, 0x10, XMM1, vm);
            sse_r(e, pfx, 0, OP[opcode], XMM0, XMM1);
            sse_r(e, type ? 0x66 : 0, 0, 0x2e, XMM0, XMM0);         /* ucomis: unordered = NaN */
            int js = jcc8(e, 0xa);
            sse_m(e, 0xf3, 0x7f, XMM0, vd);
            slow_tail(e, m, A, js);
            return K_TEMPLATE;
        }
        if (!sf && B(i, 11, 10) == 3) {                             /* FCSEL */
            int cc = CC[B(i, 15, 12)];
            if (type) { ld64(e, RDX, vn); if (cc >= 0) { ld64(e, RCX, vm); flags_load(e); cmov(e, cc ^ 1, 1, RDX, RCX); } }
            else { op_m(e, 0, 0, 0, 0x8b, -1, RDX, vn); if (cc >= 0) { op_m(e, 0, 0, 0, 0x8b, -1, RCX, vm); flags_load(e); cmov(e, cc ^ 1, 0, RDX, RCX); } }
            if (!type) mov_rr(e, 0, RDX, RDX);
            v_set_gp(e, (int)rd, RDX);
            return K_TEMPLATE;
        }
        if (!sf && B(i, 15, 10) == 0x08 && !B(i, 2, 0)) {           /* FCMP / FCMPE, register and #0.0 */
            sse_m(e, pfx, 0x10, XMM0, vn);
            if (BIT(i, 3)) b1(e, 0x0f), b1(e, 0x57), b1(e, 0xc9);   /* xorps xmm1, xmm1 */
            else sse_m(e, pfx, 0x10, XMM1, vm);
            sse_r(e, type ? 0x66 : 0, 0, 0x2e, XMM0, XMM1);
            mov_ri(e, RAX, img_of(0, 0, 1, 0));                     /* greater */
            mov_ri(e, RCX, img_of(1, 0, 0, 0)); cmov(e, 2, 0, RAX, RCX);   /* below: less */
            mov_ri(e, RCX, img_of(0, 1, 1, 0)); cmov(e, 4, 0, RAX, RCX);   /* equal */
            mov_ri(e, RCX, img_of(0, 0, 1, 1)); cmov(e, 0xa, 0, RAX, RCX); /* parity: unordered (sets ZF and CF too) */
            op_m(e, 0, 0, 0, 0x89, -1, RAX, mb(RBX, OFF_NZ));
            return K_TEMPLATE;
        }
        if (!sf && B(i, 14, 10) == 0x10) {                          /* 1-source */
            unsigned opcode = B(i, 20, 15);
            if (opcode <= 2) {                                      /* FMOV FABS FNEG: bit operations, as the interpreter's */
                if (type) { ld64(e, RAX, vn); if (opcode) { op_r(e, 1, 0, 0x0f, 0xba, opcode == 1 ? 6 : 7, RAX); b1(e, 63); } }
                else { op_m(e, 0, 0, 0, 0x8b, -1, RAX, vn); if (opcode) { op_r(e, 0, 0, 0x0f, 0xba, opcode == 1 ? 6 : 7, RAX); b1(e, 31); } }
                v_set_gp(e, (int)rd, RAX);
                return K_TEMPLATE;
            }
            if (opcode == 3 || (opcode == 5 && type == 0) || (opcode == 4 && type == 1)) {   /* FSQRT, FCVT s->d, d->s */
                sse_m(e, pfx, 0x10, XMM0, vn);
                b1(e, 0x0f); b1(e, 0x57); b1(e, 0xc9);              /* xorps xmm1, xmm1: the result's top must be zero */
                sse_r(e, pfx, 0, opcode == 3 ? 0x51 : 0x5a, XMM1, XMM0);
                sse_r(e, (opcode == 3 ? type : opcode == 5) ? 0x66 : 0, 0, 0x2e, XMM1, XMM1);
                int js = jcc8(e, 0xa);
                sse_m(e, 0xf3, 0x7f, XMM1, vd);
                slow_tail(e, m, A, js);
                return K_TEMPLATE;
            }
            return -1;
        }
        if (!B(i, 15, 10)) {                                        /* conversions between FP and integer */
            unsigned rmode = B(i, 20, 19), opcode = B(i, 18, 16);
            if (rmode == 0 && opcode >= 6 && type == sf) {          /* FMOV W<->S, X<->D */
                if (opcode == 6) { if (sf) ld64(e, RAX, vn); else op_m(e, 0, 0, 0, 0x8b, -1, RAX, vn); gst(e, (int)rd, RAX, (int)sf, 0); }
                else { gld(e, RAX, (int)rn, 0); if (!sf) mov_rr(e, 0, RAX, RAX); v_set_gp(e, (int)rd, RAX); }
                return K_TEMPLATE;
            }
            if (rmode == 0 && (opcode == 2 || (opcode == 3 && !sf))) {   /* SCVTF; UCVTF from W (zero-extended, then signed 64) */
                gld(e, RAX, (int)rn, 0);
                if (!sf) { if (opcode == 2) op_r(e, 1, 0, 0x63, -1, RAX, RAX); else mov_rr(e, 0, RAX, RAX); }
                b1(e, 0x0f); b1(e, 0x57); b1(e, 0xc0);              /* xorps xmm0, xmm0 */
                sse_r(e, 0xf2, 1, 0x2a, XMM0, RAX);                 /* cvtsi2sd xmm0, rax: the interpreter converts to double first */
                if (!type) { b1(e, 0x0f); b1(e, 0x57); b1(e, 0xc9); sse_r(e, 0xf2, 0, 0x5a, XMM1, XMM0); sse_m(e, 0xf3, 0x7f, XMM1, vd); }
                else sse_m(e, 0xf3, 0x7f, XMM0, vd);
                return K_TEMPLATE;
            }
            if (rmode == 3 && opcode == 0) {                        /* FCVTZS */
                sse_m(e, pfx, 0x10, XMM0, vn);
                sse_r(e, pfx, (int)sf, 0x2c, RAX, XMM0);            /* cvtt{s,d}2si */
                if (sf) { mov_ri(e, RCX, 0x8000000000000000ull); alu_rr(e, 0x39, 1, RAX, RCX); }
                else alu_ri(e, 7, 0, RAX, (int32_t)0x80000000);
                int js = jcc8(e, 4);
                gst(e, (int)rd, RAX, (int)sf, 0);
                slow_tail(e, m, A, js);
                return K_TEMPLATE;
            }
            return -1;
        }
    }
    return -1;
}

/* Emit the code for one instruction. Returns the kind; for K_TEMPLATE the code is in e. fall = does control reach
   the end of the code (then it must continue at the next slot). */
static int emit_insn(E *e, const img_t *m, uint64_t A, uint32_t i, int *fall) {
    struct a64_dec d;
    int id = a64_spec(i, &d), sf = d.sf;
    *fall = 1;
    ZXD = 0;
    if (OPT & OPT_INPLACE) { int r = emit_inplace(e, m, A, id, &d, i); if (r >= 0) return r; }
    switch (id) {
    case A64X_ADR: {
        uint64_t v = d.op ? ((A & ~0xfffULL) + (d.imm << 12)) : (A + d.imm);
        mov_ri(e, RCX, v); gst(e, d.rd, RCX, 1, 0);
        return K_TEMPLATE;
    }
    case A64X_ADDSUB_IMM:
        if (slot_break) d.imm += 1;                 /* the certifier's negative control (slotcert --break) */
        gld(e, RCX, d.rn, 1);
        if (d.imm || d.S) alu_ri(e, d.op ? 5 : 0, sf, RCX, (int32_t)d.imm);
        ZXD = d.imm || d.S;
        if (d.S) { if (!d.op) b1(e, 0xf5); if (!X.fuse_out) flags_save(e); gst(e, d.rd, RCX, sf, 0); }
        else gst(e, d.rd, RCX, sf, 1);
        return K_TEMPLATE;
    case A64X_LOGIC_IMM: {
        static const int EXT[4] = {4, 1, 6, 4};
        gld(e, RCX, d.rn, 0);
        uint64_t mk = d.imm;
        if (!sf || (int64_t)mk == (int32_t)mk) alu_ri(e, EXT[d.op], sf, RCX, (int32_t)(uint32_t)mk);
        else { mov_ri(e, RAX, mk); alu_rr(e, d.op == 1 ? 0x09 : d.op == 2 ? 0x31 : 0x21, 1, RCX, RAX); }
        ZXD = 1;
        if (d.op == 3) { b1(e, 0xf9); if (!X.fuse_out) flags_save(e); gst(e, d.rd, RCX, sf, 0); }
        else gst(e, d.rd, RCX, sf, 1);
        return K_TEMPLATE;
    }
    case A64X_MOVW:
        if (d.op == 0) mov_ri(e, RCX, trw(~d.imm, sf));
        else if (d.op == 2) mov_ri(e, RCX, d.imm);
        else {
            uint64_t keep = ~(0xffffULL << (16 * d.ra));
            gld(e, RCX, d.rd, 0);
            mov_ri(e, RAX, keep); alu_rr(e, 0x21, 1, RCX, RAX);
            mov_ri(e, RAX, d.imm); alu_rr(e, 0x09, 1, RCX, RAX);
        }
        ZXD = d.op != 3;
        gst(e, d.rd, RCX, sf, 0);
        return K_TEMPLATE;
    case A64X_LOGIC_REG: {
        static const int SH[4] = {4, 5, 7, 1};
        gld(e, RCX, d.rm, 0);
        sh_ri(e, SH[d.S], sf, RCX, d.ra);
        if (d.f) unary(e, 2, sf, RCX);
        gld(e, RDX, d.rn, 0);
        alu_rr(e, d.op == 1 ? 0x09 : d.op == 2 ? 0x31 : 0x21, sf, RDX, RCX);
        if (d.op == 3) { b1(e, 0xf9); if (!X.fuse_out) flags_save(e); }
        ZXD = 1;
        gst(e, d.rd, RDX, sf, 0);
        return K_TEMPLATE;
    }
    case A64X_ADDSUB_REG: {
        gld(e, RCX, d.rm, 0);
        if (!d.f) {
            static const int SH[3] = {4, 5, 7};
            sh_ri(e, SH[d.ra], sf, RCX, (unsigned)d.imm);
            gld(e, RDX, d.rn, 0);
        } else {
            switch (d.ra) {
            case 0: op_r(e, 0, 0, 0x0f, 0xb6, RCX, RCX); break;
            case 1: op_r(e, 0, 0, 0x0f, 0xb7, RCX, RCX); break;
            case 2: mov_rr(e, 0, RCX, RCX); break;
            case 4: op_r(e, 1, 0, 0x0f, 0xbe, RCX, RCX); break;
            case 5: op_r(e, 1, 0, 0x0f, 0xbf, RCX, RCX); break;
            case 6: op_r(e, 1, 0, 0x63, -1, RCX, RCX); break;
            default: break;
            }
            sh_ri(e, 4, 1, RCX, (unsigned)d.imm);
            gld(e, RDX, d.rn, 1);
        }
        alu_rr(e, d.op ? 0x29 : 0x01, sf, RDX, RCX);
        ZXD = 1;
        if (d.S) { if (!d.op) b1(e, 0xf5); if (!X.fuse_out) flags_save(e); gst(e, d.rd, RDX, sf, 0); }
        else gst(e, d.rd, RDX, sf, 1);
        return K_TEMPLATE;
    }
    case A64X_CSEL: {
        gld(e, RCX, d.rm, 0);
        if (d.op) unary(e, d.S ? 3 : 2, sf, RCX);
        else if (d.S) { if (X.noflag) lea(e, RCX, mb(RCX, 1)); else alu_ri(e, 0, sf, RCX, 1); }   /* lea: flags stay live */
        gld(e, RDX, d.rn, 0);
        int cc = CC[d.ra];
        if (cc < 0) mov_rr(e, 1, RCX, RDX);
        else { if (!X.fuse_in) flags_load(e); cmov(e, cc, sf, RCX, RDX); }
        ZXD = cc >= 0;
        gst(e, d.rd, RCX, sf, 0);
        return K_TEMPLATE;
    }
    case A64X_MADD:
        gld(e, RAX, d.rn, 0); gld(e, RCX, d.rm, 0);
        imul_rr(e, sf, RAX, RCX);
        gld(e, RDX, d.ra, 0);
        alu_rr(e, d.op ? 0x29 : 0x01, sf, RDX, RAX);
        ZXD = 1;
        gst(e, d.rd, RDX, sf, 0);
        return K_TEMPLATE;
    case A64X_B: {
        uint64_t t = A + d.imm;
        if (!in_img(m, t)) return K_EXIT;
        if (d.op) { mov_ri(e, RCX, A + 4); set_lr(e, RCX); }
        jmp_to(e, branch_to(m, t));
        *fall = 0;
        return K_TEMPLATE;
    }
    case A64X_CB: {
        uint64_t t = A + d.imm;
        if (!in_img(m, t)) return K_EXIT;
        gld(e, RCX, d.rd, 0);
        alu_rr(e, 0x85, sf, RCX, RCX);
        jcc_to(e, d.op ? 5 : 4, branch_to(m, t));
        return K_TEMPLATE;
    }
    case A64X_TB: {
        uint64_t t = A + d.imm;
        if (!in_img(m, t)) return K_EXIT;
        gld(e, RCX, d.rd, 0);
        op_r(e, 1, 0, 0x0f, 0xba, 4, RCX); b1(e, d.ra);                    /* bt rcx, bit */
        jcc_to(e, d.op ? 2 : 3, branch_to(m, t));
        return K_TEMPLATE;
    }
    case A64X_BCOND: {
        uint64_t t = A + d.imm;
        if (!in_img(m, t)) return K_EXIT;
        int cc = CC[d.ra];
        if (cc < 0) { jmp_to(e, branch_to(m, t)); *fall = 0; return K_TEMPLATE; }
        if (!X.fuse_in) flags_load(e);
        jcc_to(e, cc, branch_to(m, t));
        return K_TEMPLATE;
    }
    case A64X_LDST_REG: {
        int V = d.f & 1, is_load = (d.f >> 1) & 1, sign = (d.f >> 2) & 1, to64 = (d.f >> 3) & 1, prfm = (d.f >> 4) & 1;
        int64_t off; int wb;
        if (V) {                                                    /* B H S D Q: a load zero-extends to 128 bits */
            M a = ldst_addr(e, &d, 0, &off, &wb);
            if (is_load) v_load(e, a, d.sf, d.rd); else v_store(e, a, d.sf, d.rd);
            wback(e, &d, wb, off);
            return K_TEMPLATE;
        }
        M a = ldst_addr(e, &d, 0, &off, &wb);
        if (!prfm) {
            if (is_load) { load_n(e, RAX, a, d.sf, sign, to64); ZXD = 1; gst(e, d.rd, RAX, sign ? to64 : d.sf == 8, 0); }
            else { gld(e, RAX, d.rd, 0); store_n(e, a, RAX, d.sf); }
        }
        wback(e, &d, wb, off);
        return K_TEMPLATE;
    }
    case A64X_LDST_PAIR: {
        int V = d.f & 1, L = (d.f >> 1) & 1, sign = (d.f >> 2) & 1;
        int64_t off; int wb;
        M a = ldst_addr(e, &d, 1, &off, &wb);
        M a2 = a; a2.disp += d.sf;
        if (V) {
            if (L) { v_load(e, a, d.sf, d.rd); v_load(e, a2, d.sf, d.ra); }
            else { v_store(e, a, d.sf, d.rd); v_store(e, a2, d.sf, d.ra); }
            wback(e, &d, wb, off);
            return K_TEMPLATE;
        }
        if (L) {
            load_n(e, RAX, a, d.sf, sign, 1); load_n(e, RDX, a2, d.sf, sign, 1);
            int w = sign ? 1 : d.sf == 8;
            ZXD = 1; gst(e, d.rd, RAX, w, 0); ZXD = 1; gst(e, d.ra, RDX, w, 0);
        } else {
            gld(e, RAX, d.rd, 0); gld(e, RDX, d.ra, 0);
            store_n(e, a, RAX, d.sf); store_n(e, a2, RDX, d.sf);
        }
        wback(e, &d, wb, off);
        return K_TEMPLATE;
    }
    default: break;
    }

    /* forms the interpreter does not pre-decode but compilers emit everywhere */
    { int k = emit_fpsimd(e, m, A, i); if (k >= 0) return k; }
    unsigned rd = B(i, 4, 0), rn = B(i, 9, 5), rm = B(i, 20, 16);
    sf = (int)BIT(i, 31);
    unsigned D = sf ? 64 : 32;
    if (B(i, 28, 23) == 0x26) {                                     /* bitfield: SBFM / UBFM (BFM -> helper) */
        unsigned opc = B(i, 30, 29), N = BIT(i, 22), immr = B(i, 21, 16), imms = B(i, 15, 10);
        if ((opc == 0 || opc == 2) && N == (unsigned)sf && (sf || (immr < 32 && imms < 32))) {
            int ext = opc == 0 ? 7 : 5;
            gld(e, RCX, (int)rn, 0);
            if (imms >= immr) { unsigned w = imms - immr + 1; sh_ri(e, 4, sf, RCX, D - 1 - imms); sh_ri(e, ext, sf, RCX, D - w); }
            else { unsigned w = imms + 1; sh_ri(e, 4, sf, RCX, D - w); sh_ri(e, ext, sf, RCX, immr - imms - 1); }
            gst(e, (int)rd, RCX, sf, 0);
            return K_TEMPLATE;
        }
        return K_HELPER;
    }
    if (B(i, 30, 29) == 0 && B(i, 28, 23) == 0x27 && !BIT(i, 21)) {  /* EXTR (ROR immediate) */
        unsigned N = BIT(i, 22), lsb = B(i, 15, 10);
        if (N == (unsigned)sf && (sf || lsb < 32)) {
            gld(e, RCX, (int)rm, 0); gld(e, RDX, (int)rn, 0);
            if (lsb) { op_r(e, sf, 0, 0x0f, 0xac, RDX, RCX); b1(e, lsb); }   /* shrd rcx, rdx, lsb */
            gst(e, (int)rd, RCX, sf, 0);
            return K_TEMPLATE;
        }
        return K_HELPER;
    }
    if (B(i, 28, 24) == 0x1b && B(i, 30, 29) == 0 && sf) {         /* 3-source: long multiplies and high halves */
        unsigned op31 = B(i, 23, 21), o0 = BIT(i, 15), ra = B(i, 14, 10);
        if (op31 == 1 || op31 == 5) {                               /* SMADDL SMSUBL UMADDL UMSUBL */
            gld(e, RAX, (int)rn, 0); gld(e, RCX, (int)rm, 0);
            if (op31 == 1) { op_r(e, 1, 0, 0x63, -1, RAX, RAX); op_r(e, 1, 0, 0x63, -1, RCX, RCX); }
            else { mov_rr(e, 0, RAX, RAX); mov_rr(e, 0, RCX, RCX); }
            imul_rr(e, 1, RAX, RCX);
            gld(e, RDX, (int)ra, 0);
            alu_rr(e, o0 ? 0x29 : 0x01, 1, RDX, RAX);
            gst(e, (int)rd, RDX, 1, 0);
            return K_TEMPLATE;
        }
        if ((op31 == 2 || op31 == 6) && !o0) {                       /* SMULH / UMULH */
            gld(e, RAX, (int)rn, 0); gld(e, RCX, (int)rm, 0);
            unary(e, op31 == 2 ? 5 : 4, 1, RCX);
            gst(e, (int)rd, RDX, 1, 0);
            return K_TEMPLATE;
        }
        return K_HELPER;
    }
    if (!BIT(i, 30) && !BIT(i, 29) && B(i, 28, 21) == 0xd6) {     /* 2-source */
        unsigned opc = B(i, 15, 10);
        if (opc >= 8 && opc <= 11) {                                /* LSLV LSRV ASRV RORV: x86 masks the count the same way */
            static const int SH[4] = {4, 5, 7, 1};
            gld(e, RCX, (int)rm, 0); gld(e, RAX, (int)rn, 0);
            sh_rcl(e, SH[opc - 8], sf, RAX);
            gst(e, (int)rd, RAX, sf, 0);
            return K_TEMPLATE;
        }
        if (opc == 2 || opc == 3) {                                 /* UDIV / SDIV: x/0 = 0, MIN/-1 = MIN, no traps */
            gld(e, RCX, (int)rm, 0); gld(e, RAX, (int)rn, 0);
            alu_rr(e, 0x85, sf, RCX, RCX);
            int jz = jcc8(e, 4), jm1 = 0, jd1;
            if (opc == 3) {
                alu_ri(e, 7, sf, RCX, -1);
                int jn = jcc8(e, 5);
                unary(e, 3, sf, RAX);
                jm1 = jcc8(e, -1);
                fix8(e, jn);
                if (sf) b1(e, 0x48);
                b1(e, 0x99);                                         /* cqo / cdq */
                unary(e, 7, sf, RCX);
            } else {
                alu_rr(e, 0x31, 0, RDX, RDX);
                unary(e, 6, sf, RCX);
            }
            jd1 = jcc8(e, -1);
            fix8(e, jz);
            alu_rr(e, 0x31, 0, RAX, RAX);
            fix8(e, jd1); if (opc == 3) fix8(e, jm1);
            gst(e, (int)rd, RAX, sf, 0);
            return K_TEMPLATE;
        }
        return K_HELPER;
    }
    if (BIT(i, 30) && !BIT(i, 29) && B(i, 28, 21) == 0xd6 && B(i, 20, 16) == 0) {   /* 1-source */
        unsigned opc = B(i, 15, 10);
        if (opc == 4 && slot_has_lzcnt()) {                         /* CLZ */
            gld(e, RCX, (int)rn, 0);
            b1(e, 0xf3); op_r(e, sf, 0, 0x0f, 0xbd, RAX, RCX);      /* lzcnt */
            gst(e, (int)rd, RAX, sf, 0);
            return K_TEMPLATE;
        }
        if ((sf && opc == 3) || (!sf && opc == 2)) {                /* REV */
            gld(e, RAX, (int)rn, 0);
            rex(e, sf, 0, 0, RAX, 0); b1(e, 0x0f); b1(e, 0xc8);
            gst(e, (int)rd, RAX, sf, 0);
            return K_TEMPLATE;
        }
        return K_HELPER;
    }
    if (BIT(i, 29) && B(i, 28, 21) == 0xd2 && !BIT(i, 10) && !BIT(i, 4)) {   /* CCMP / CCMN, register and immediate */
        int isimm = (int)BIT(i, 11), sub = (int)BIT(i, 30);
        unsigned cond = B(i, 15, 12), nzcv = B(i, 3, 0);
        gld(e, RCX, (int)rn, 0);
        if (!isimm) gld(e, RDX, (int)rm, 0);
        int cc = CC[cond], jn = 0;
        if (cc >= 0) { flags_load(e); jn = jcc8(e, cc ^ 1); }
        if (sub) { if (isimm) alu_ri(e, 7, sf, RCX, (int32_t)rm); else alu_rr(e, 0x39, sf, RCX, RDX); }
        else { if (isimm) alu_ri(e, 0, sf, RCX, (int32_t)rm); else alu_rr(e, 0x01, sf, RCX, RDX); b1(e, 0xf5); }
        flags_save(e);
        if (cc >= 0) {
            int jd = jcc8(e, -1);
            fix8(e, jn);
            op_m(e, 0, 0, 0, 0xc7, -1, 0, mb(RBX, OFF_NZ));     /* 32-bit, so the next flag load forwards from it */
            b4(e, img_of(nzcv >> 3, (nzcv >> 2) & 1, (nzcv >> 1) & 1, nzcv & 1));
            fix8(e, jd);
        }
        return K_TEMPLATE;
    }
    if (B(i, 31, 25) == 0x6b) {                                     /* BR / BLR / RET and their authenticated forms */
        unsigned opc = B(i, 24, 21), op2 = B(i, 20, 16), op3 = B(i, 15, 10), op4 = B(i, 4, 0);
        int auth = op3 == 2 || op3 == 3;
        if (op2 != 0x1f || (!auth && op3 != 0)) return K_EXIT;
        int reg;
        if (opc == 0 || opc == 1) { if (op4 != (auth ? 0x1fu : 0u)) return K_EXIT; reg = (int)rn; }
        else if (opc == 2) { if (auth) { if (rn != 0x1f || op4 != 0x1f) return K_EXIT; reg = 30; } else { if (op4) return K_EXIT; reg = (int)rn; } }
        else return K_EXIT;
        gld(e, RAX, reg, 0);
        mov_ri(e, RDX, A);
        jmp_to(e, opc == 1 ? m->icall : m->ijmp);
        *fall = 0;
        return K_TEMPLATE;
    }

    /* everything else: the interpreter, from inside the slot, or a clean exit */
    unsigned op0 = B(i, 28, 25);
    if ((op0 & 0xe) == 0xa) {                                       /* branches, exceptions, system */
        if (B(i, 31, 24) == 0xd4) return K_EXIT;                    /* SVC BRK HLT */
        if (B(i, 30, 26) == 0x05 || B(i, 30, 25) == 0x1a || B(i, 30, 25) == 0x1b || B(i, 31, 25) == 0x2a) return K_EXIT;
        return K_HELPER;                                            /* hints, barriers, MRS/MSR, SYS */
    }
    if (op0 == 0 || op0 == 1 || op0 == 2 || op0 == 3) return K_EXIT;   /* UDF, unallocated, SVE */
    return K_HELPER;
}

/* PADDING IS EXECUTED: control falls through it into the next slot on every instruction. One-byte NOPs made
      that ~20 instructions of padding per guest instruction (measured on the PC: 7.1x native). Intel's recommended
      multi-byte NOPs keep it to at most three. */
static void nopfill(uint8_t *p, int n) {
    static const uint8_t NOP[12][11] = {
        {0}, {0x90}, {0x66, 0x90}, {0x0f, 0x1f, 0x00}, {0x0f, 0x1f, 0x40, 0x00}, {0x0f, 0x1f, 0x44, 0x00, 0x00},
        {0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00}, {0x0f, 0x1f, 0x80, 0, 0, 0, 0}, {0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0},
        {0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0}, {0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0},
        {0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0},
    };
    while (n > 0) { int k = n > 11 ? 11 : n; memcpy(p, NOP[k], (size_t)k); p += k; n -= k; }
}

/* Place one instruction's code: in its slot if it fits, else in the overflow area with a jump from the slot. */
/* THE PATCHABLE LABEL: a 5-byte NOP at offset 0 of a 32-byte-aligned slot. Consolidation replaces exactly these
      five bytes with `jmp skill` in one aligned 8-byte store (the other three bytes are rewritten with themselves). */
static const uint8_t LABNOP[5] = {0x0f, 0x1f, 0x44, 0x00, 0x00};
/* SLOT_MAPFILE=<path>: where generated code came from, for a sampling profiler (images and skills) */
static FILE *mapf(void) {
    static FILE *f; static int tried;
    if (!tried) { tried = 1; const char *p = getenv("SLOT_MAPFILE"); if (p) f = fopen(p, "w"); }
    return f;
}
#define CNT_NEVER 0x7fffffffu
int slot_hot_threshold = 2000;
static void emit_label_nop(E *e, const img_t *m, uint64_t A) {
    if (m->lab && (m->lab[(A - m->tb) / 4] & 1)) for (int i = 0; i < 5; i++) b1(e, LABNOP[i]);
}
/* the back-edge countdown: sub dword [rip + cnt], 1 ; jz <stub: hot call, jmp back> */
static void emit_backedge_count(E *e, img_t *m, uint64_t A) {
    size_t k = (A - m->tb) / 4;
    if (!m->lab || !(m->lab[k] & 6) || m->hend - m->hcur < 64) return;
    b1(e, 0x83); b1(e, 0x2d); b4(e, rel32(ecur(e) + 5, (uint64_t)(uintptr_t)&m->cnt[k])); b1(e, 1);
    b1(e, 0x0f); b1(e, 0x84); int at = e->n; b4(e, 0);
    uint64_t resume = ecur(e);
    E hs; hs.n = 0; hs.va = (uint64_t)(uintptr_t)m->hcur;
    emit_hot_call(&hs, m, A);
    jmp_to(&hs, resume);
    memcpy(m->hcur, hs.buf, (size_t)hs.n); m->hcur += hs.n;
    uint32_t r = rel32(resume, hs.va); memcpy(e->buf + at, &r, 4);
}
uint64_t slot_force_lo, slot_force_hi;     /* [lo, hi): templates replaced by the helper (debug bisection) */
static int place_insn(img_t *m, uint64_t A, uint32_t insn) {
    CM = &m->map; OPT = m->opt;
    uint8_t *slot = (uint8_t *)(uintptr_t)slot_of(m, A);
    E e; e.n = 0; e.va = (uint64_t)(uintptr_t)slot;
    emit_label_nop(&e, m, A);
    emit_backedge_count(&e, m, A);
    int pre = e.n;
    int fall, k = emit_insn(&e, m, A, insn, &fall);
    if (A >= slot_force_lo && A < slot_force_hi && k == K_TEMPLATE) { k = K_HELPER; e.n = pre; st.k_template--; }
    if (k == K_HELPER) { e.n = pre; emit_helper_call(&e, m, A); fall = 1; st.k_helper++; }
    else if (k == K_EXIT) { e.n = pre; emit_exit(&e, m, A); fall = 0; st.k_exit++; }
    else st.k_template++;
    if (e.n <= SLOT) {
        memcpy(slot, e.buf, (size_t)e.n);
        nopfill(slot + e.n, SLOT - e.n);                            /* fall through the padding into the next slot */
        return 0;
    }
    /* too big: emit again at the overflow cursor, then jump back to the next slot */
    if (m->ovf_end - m->ovf < 600) { fprintf(stderr, "a64slot: overflow area full at %llx\n", (unsigned long long)A); return -1; }
    uint8_t *ovf = m->ovf;
    E o; o.n = 0; o.va = (uint64_t)(uintptr_t)ovf;
    emit_backedge_count(&o, m, A);
    int opre = o.n;
    int fall2; int k2 = emit_insn(&o, m, A, insn, &fall2);
    if (k2 == K_HELPER) { o.n = opre; emit_helper_call(&o, m, A); fall2 = 1; }
    else if (k2 == K_EXIT) { o.n = opre; emit_exit(&o, m, A); fall2 = 0; }
    if (fall2) jmp_to(&o, (uint64_t)(uintptr_t)slot + SLOT);
    memcpy(ovf, o.buf, (size_t)o.n);
    E j; j.n = 0; j.va = (uint64_t)(uintptr_t)slot;
    emit_label_nop(&j, m, A);
    jmp_to(&j, (uint64_t)(uintptr_t)ovf);
    memcpy(slot, j.buf, (size_t)j.n);
    memset(slot + j.n, 0xcc, (size_t)(SLOT - j.n));
    m->ovf += o.n;
    st.overflow++;
    return 0;
}

int (*slot_func_bounds)(uint64_t a, uint64_t *lo, uint64_t *hi);
int slot_learn;                          /* 1 = images added from now on carry labels and back-edge counters */
static pthread_mutex_t slot_mu = PTHREAD_MUTEX_INITIALIZER;
/* direct branch target of word w at A (B, BL, B.cond, CBZ/CBNZ, TBZ/TBNZ), or 0; *call = it is BL */
static uint64_t direct_target(uint64_t A, uint32_t w, int *call) {
    struct a64_dec d; int id = a64_spec(w, &d);
    *call = 0;
    if (id == A64X_B) { *call = d.op; return A + d.imm; }
    if (id == A64X_BCOND || id == A64X_CB || id == A64X_TB) return A + d.imm;
    return 0;
}
static int is_blr(uint32_t w) { return B(w, 31, 25) == 0x6b && B(w, 24, 21) == 1; }
static int image_add_locked(uint64_t tb, uint64_t tlen) {
    if (stubs_init() || nimg >= MAXIMG || (tb & 3) || (tlen & 3)) return -1;
    size_t n = (size_t)(tlen / 4);
    const uint32_t *w = slot_words(tb, n);
    if (!w) return -1;
    size_t nbe = 0;
    uint8_t *lab = 0;
    if (slot_learn) {
        lab = calloc(n + 1, 1);
        if (!lab) return -1;
        for (size_t k = 0; k < n; k++) {
            int call; uint64_t t = direct_target(tb + 4 * k, w[k], &call);
            if (call || is_blr(w[k])) lab[k + 1] |= 1;                  /* the return point */
            if (t && t - tb < tlen && !(t & 3)) {
                lab[(t - tb) / 4] |= 1;
                if (!call && t <= tb + 4 * k) { lab[k] |= 2; nbe++; }
                if (call) { lab[k] |= 4; nbe++; }
            }
        }
    }
    size_t sz = n * SLOT + n * 24 + 4096 + (1 << 16) + (lab ? n * 4 + 8 : 0) + nbe * 2 * 48 + 64;
    uint8_t *p = code_alloc(sz);
    if (!p) { free(lab); return -1; }
    img_t *m = &imgs[nimg];
    memset(m, 0, sizeof *m);
    m->tb = tb; m->tlen = tlen; m->sb = (uint64_t)(uintptr_t)p;
    m->opt = slot_opt; OPT = slot_opt;
    rmap_choose(&m->map, w, n);
    uint8_t *after = emit_image_stubs(m, p + n * SLOT);
    if (lab) {
        m->lab = lab;
        m->cnt = (uint32_t *)(uintptr_t)(((uintptr_t)after + 7) & ~(uintptr_t)7);
        after = (uint8_t *)(m->cnt + n);
        for (size_t k = 0; k < n; k++) m->cnt[k] = (lab[k] & 6) ? (uint32_t)slot_hot_threshold : CNT_NEVER;
        m->hcur = after; m->hend = after + nbe * 2 * 48 + 64;
        after = m->hend;
    }
    m->ovf = after; m->ovf_end = p + sz;
    for (size_t k = 0; k < n; k++)
        if (place_insn(m, tb + 4 * k, w[k])) return -2;
    if (mapf()) { fprintf(mapf(), "I %llx %llx %llx\n", (unsigned long long)m->sb, (unsigned long long)tb, (unsigned long long)tlen); fflush(mapf()); }
    /* counted only now: another thread may look images up while this one is being converted */
    __atomic_store_n(&nimg, nimg + 1, __ATOMIC_RELEASE);
    return 0;
}
int slot_image_add(uint64_t tb, uint64_t tlen) {
    pthread_mutex_lock(&slot_mu);
    int r = image_add_locked(tb, tlen);
    pthread_mutex_unlock(&slot_mu);
    return r;
}

/* re-convert one instruction in place (the certifier; also a code change at one address) */
static img_t *img_find_w(uint64_t a) {
    for (int i = 0; i < nimg; i++) if (a - imgs[i].tb < imgs[i].tlen) return &imgs[i];
    return 0;
}
static img_t *PATCHED;                  /* the image slot_patch last touched: its overflow is what mark/reset mean */
int slot_patch(uint64_t A) {
    img_t *m = img_find_w(A);
    if (!m) return -1;
    PATCHED = m;
    return place_insn(m, A, slot_word(A));
}
void slot_overflow_mark(void **mk) { *mk = PATCHED ? PATCHED->ovf : 0; }
void slot_overflow_reset(void *mk) { if (PATCHED && mk) PATCHED->ovf = (uint8_t *)mk; }

int slot_covers(uint64_t pc) { return img_find(pc) != 0 && !(pc & 3); }

uint64_t slot_run(a64 *s) {
    const img_t *m = img_find(s->pc);
    if (!m || (s->pc & 3)) return SLOT_NONE;
    arm2img(s);
    uint64_t r = slot_enter(s, slot_of(m, s->pc), m->enter);
    img2arm(s);
    st.runs++;
    return r;
}

void slot_stats_get(struct slot_stats *o) { *o = st; }

/* ───────────────────────── consolidation: a learned skill for one function ─────────────────────────
   The worker has run the function (an episode: how often each instruction ran). Consolidation grows a native skill:
 registers: the eleven host registers go to the guest registers that actually carried the work (weighted by
       how often each instruction ran, not by how often it is written down);
 flags: a flag-liveness pass over the function's own control flow; a compare whose flags are read only by the
       very next instruction (a branch or a select) leaves them in EFLAGS - no image write, no image read - and a
       setter whose flags nobody reads writes nothing; anything the pass cannot see (a helper, an unknown branch)
       counts as a reader, so the image stays correct there;
 layout: the instructions packed back to back (no slot padding), direct branches straight to the skill's copy.
   The function's entry slot is patched to jump into the skill; every other slot keeps its strict code, so a jump
   into the middle of the function from anywhere still runs correct code. */
static void remap(E *e, const struct rmap *from, const struct rmap *to) {
    if (!memcmp(from, to, sizeof *from)) return;
    for (int i = 0; i < from->n; i++) st64(e, mb(RBX, goff(from->g[i])), from->h[i]);
    for (int i = 0; i < to->n; i++) ld64(e, to->h[i], mb(RBX, goff(to->g[i])));
}
struct frw { int rd, wr, kind, fall, succ_in, ret, unknown; uint64_t t; };
static void flag_info(const img_t *m, uint64_t A, uint32_t i, uint64_t fb, uint64_t fl, struct frw *f) {
    struct a64_dec d; int id = a64_spec(i, &d);
    memset(f, 0, sizeof *f); f->fall = 1;
    switch (id) {
    case A64X_ADDSUB_IMM: case A64X_ADDSUB_REG: f->wr = d.S; return;
    case A64X_LOGIC_IMM: case A64X_LOGIC_REG: f->wr = d.op == 3; return;
    case A64X_CSEL: f->rd = CC[d.ra] >= 0; return;
    case A64X_ADR: case A64X_MOVW: case A64X_MADD: case A64X_LDST_PAIR: case A64X_LDST_REG: return;
    case A64X_B: f->t = A + d.imm; f->succ_in = f->t - fb < fl;
        if (d.op) { f->rd = 1; f->wr = 1; f->succ_in = 0; return; }     /* BL: an outlined callee may read and set them */
        f->fall = 0; if (!f->succ_in) f->unknown = 1; return;
    case A64X_CB: case A64X_TB: f->t = A + d.imm; f->succ_in = f->t - fb < fl; if (!f->succ_in) f->unknown = 1; return;
    case A64X_BCOND: f->t = A + d.imm; f->succ_in = f->t - fb < fl; if (!f->succ_in) f->unknown = 1;
        if (CC[d.ra] < 0) f->fall = 0; else f->rd = 1; return;
    default: break;
    }
    if (B(i, 29, 29) && B(i, 28, 21) == 0xd2 && !BIT(i, 10) && !BIT(i, 4)) { f->rd = CC[B(i, 15, 12)] >= 0; f->wr = 1; return; }  /* CCMP */
    if (B(i, 30, 24) == 0x1e && BIT(i, 21) && !BIT(i, 31)) {           /* scalar FP */
        if (B(i, 15, 10) == 0x08 && !B(i, 2, 0)) { f->wr = 1; return; }  /* FCMP */
        if (B(i, 11, 10) == 3) { f->rd = 1; return; }                    /* FCSEL */
        if (B(i, 11, 10) == 1) { f->rd = 1; f->wr = 1; return; }         /* FCCMP */
    }
    if (B(i, 31, 25) == 0x6b) {
        unsigned opc = B(i, 24, 21);
        if (opc == 2) { f->fall = 0; f->unknown = 1; return; }           /* RET: an outlined callee returns flags */
        if (opc == 1) { f->rd = 1; f->wr = 1; return; }                  /* BLR: the callee may read and set them */
        f->fall = 0; f->unknown = 1; return;                             /* BR: a jump table we cannot see */
    }
    E tmp; tmp.n = 0; tmp.va = slot_of(m, A); int fall;
    struct rmap save = *CM; (void)save;
    int k = emit_insn(&tmp, m, A, i, &fall);
    if (k != K_TEMPLATE) { f->rd = 1; f->kind = k; }                     /* helper / exit: assume it reads the flags */
}

static const img_t *SK_IMG; static uint64_t SK_FB, SK_FL, SK_BASE, *SK_OFF, *SK_OUT, SK_NOUT; static uint64_t SK_OUTT[256], SK_OUTA[256];
static uint64_t skill_tgt(uint64_t t) {
    if (t - SK_FB < SK_FL) return SK_BASE + SK_OFF[(t - SK_FB) / 4];
    for (uint64_t j = 0; j < SK_NOUT; j++) if (SK_OUTT[j] == t) return SK_OUTA[j];
    return SK_BASE;                                                      /* unreachable: every out target has a thunk */
}

struct slot_learnst LST;
/* every crash report names the functions learning compiled last: the annotation record crash reports print as
      "Application Specific Information", rewritten after each learn (cheap: it happens a few hundred times a process) */
struct slot_crashinfo { uint64_t version, message, signature, backtrace, message2, thread, dialog_mode, abort_cause; };
__attribute__((section("__DATA,__crash_info"), used)) struct slot_crashinfo slot_crash_info = {5, 0, 0, 0, 0, 0, 0, 0};
static char slot_crash_msg[640];
extern uint64_t slot_learned_ring[16]; extern unsigned slot_learned_n;
static void crash_note(void) {
    int k = snprintf(slot_crash_msg, sizeof slot_crash_msg, "a2x slots: learned %u (hot %llu); last, newest first:", slot_learned_n, (unsigned long long)LST.hot);
    for (unsigned i = 0; i < 16 && i < slot_learned_n && k < (int)sizeof slot_crash_msg - 24; i++)
        k += snprintf(slot_crash_msg + k, sizeof slot_crash_msg - k, " 0x%llx", (unsigned long long)slot_learned_ring[(slot_learned_n - 1 - i) & 15]);
    slot_crash_info.message = (uint64_t)(uintptr_t)slot_crash_msg;
}
static int consolidate_in(uint64_t fb, uint64_t fl, const uint64_t *exec, int control_break, struct slot_skill *rep, int live);
uint64_t slot_learned_ring[16]; unsigned slot_learned_n;
int slot_consolidate(uint64_t fb, uint64_t fl, const uint64_t *exec, int control_break, struct slot_skill *rep) {
    pthread_mutex_lock(&slot_mu);
    int r = consolidate_in(fb, fl, exec, control_break, rep, 0);
    pthread_mutex_unlock(&slot_mu);
    return r;
}
static int consolidate_in(uint64_t fb, uint64_t fl, const uint64_t *exec, int control_break, struct slot_skill *rep, int live) {
    const img_t *m = img_find(fb);
    if (!m || fb + fl > m->tb + m->tlen || (fb & 3) || (fl & 3)) return -1;
    size_t n = (size_t)(fl / 4);
    const uint32_t *w = slot_words(fb, n);
    if (!w) return -1;
    static img_t sk;                                                      /* the skill's own stubs and map */
    sk = *m; OPT = m->opt;
    /* a function that calls keeps the image's map: every return lands on a patched return point, and with one map
          that is a single jmp back into the skill instead of an eleven-register shuffle */
    int calls = 0;
    for (size_t k = 0; k < n; k++) { int c; direct_target(fb + 4 * k, w[k], &c); if (c || is_blr(w[k])) calls = 1; }
    if (!(live && calls)) rmap_choose_w(&sk.map, w, n, exec);
    struct frw *f = calloc(n, sizeof *f);
    int *lin = calloc(n, sizeof(int)), *lout = calloc(n, sizeof(int)), *label = calloc(n, sizeof(int));
    uint64_t *off = calloc(n + 1, sizeof(uint64_t));
    CM = &sk.map;
    for (size_t k = 0; k < n; k++) {
        flag_info(&sk, fb + 4 * k, w[k], fb, fl, &f[k]);
        if (f[k].succ_in) label[(f[k].t - fb) / 4] = 1;
    }
    label[0] = 1;
    size_t k0 = (fb - m->tb) / 4;
    if (live && m->lab) for (size_t k = 0; k < n; k++) if (m->lab[k0 + k] & 1) label[k] = 1;   /* every way in from outside */
    /* flag liveness, to a fixed point */
    for (int changed = 1; changed;) {
        changed = 0;
        for (size_t k = n; k-- > 0;) {
            int o = 0;
            if (f[k].unknown) o = 1;
            if (f[k].fall) o |= k + 1 < n ? lin[k + 1] : 1;
            if (f[k].succ_in) o |= lin[(f[k].t - fb) / 4];
            if (f[k].ret) o = 0;
            int in = f[k].rd | (o & !f[k].wr);
            if (o != lout[k] || in != lin[k]) { lout[k] = o; lin[k] = in; changed = 1; }
        }
    }
    /* which setter/reader pairs fuse */
    int *fo = calloc(n, sizeof(int)), *fi = calloc(n, sizeof(int)), *nf = calloc(n, sizeof(int));
    int fused = 0, dead = 0;
    for (size_t k = 0; k < n; k++) {
        struct a64_dec d; int id = a64_spec(w[k], &d);
        int setter = (id == A64X_ADDSUB_IMM || id == A64X_ADDSUB_REG) ? d.S : (id == A64X_LOGIC_IMM || id == A64X_LOGIC_REG) ? d.op == 3 : 0;
        if (!setter) continue;
        if (control_break) { fo[k] = 1; continue; }                     /* negative control: every flag save dropped */
        if (!lout[k]) { fo[k] = 1; dead++; continue; }
        if (k + 1 >= n || label[k + 1]) continue;
        struct a64_dec r; int rid = a64_spec(w[k + 1], &r);
        int reader = (rid == A64X_BCOND && CC[r.ra] >= 0) || (rid == A64X_CSEL && CC[r.ra] >= 0 && !(r.op && r.S));
        if (!reader) continue;
        fi[k + 1] = 1; nf[k + 1] = rid == A64X_CSEL;
        fo[k] = !lout[k + 1];                                            /* still needed after the reader: keep the save */
        fused++;
    }
    /* layout: stubs, thunks, then the body */
    size_t sz = n * 96 + 8192;
    uint8_t *p = code_alloc(sz), *p0 = p;
    if (!p) return -2;
    p = emit_image_stubs(&sk, p);                                       /* exit/helper/lookup in the skill's map */
    E e;
    for (int call = 0; call < 2; call++) {                               /* indirect branches: back to the image's map first */
        e.n = 0; e.va = (uint64_t)(uintptr_t)p;
        remap(&e, &sk.map, &m->map);
        jmp_to(&e, call ? m->icall : m->ijmp);
        if (call) sk.icall = e.va; else sk.ijmp = e.va;
        p = place(&e, p);
    }
    {
        uint64_t u[256]; size_t nu = 0; int over = 0;
        for (size_t k = 0; k < n && !over; k++)
            if (f[k].t && !f[k].succ_in && (f[k].t - m->tb) < m->tlen) {
                int seen = 0; for (size_t j = 0; j < nu; j++) if (u[j] == f[k].t) seen = 1;
                if (!seen) { if (nu == 256) over = 1; else u[nu++] = f[k].t; }
            }
        if (over) { free(f); free(lin); free(lout); free(label); free(off); free(fo); free(fi); free(nf); return -4; }
    }
    SK_NOUT = 0;
    for (size_t k = 0; k < n; k++)                                       /* direct branches that leave the function */
        if (f[k].t && !f[k].succ_in && (f[k].t - m->tb) < m->tlen && SK_NOUT < 256) {
            int seen = 0; for (uint64_t j = 0; j < SK_NOUT; j++) if (SK_OUTT[j] == f[k].t) seen = 1;
            if (seen) continue;
            e.n = 0; e.va = (uint64_t)(uintptr_t)p;
            remap(&e, &sk.map, &m->map);
            jmp_to(&e, slot_of(m, f[k].t));
            SK_OUTT[SK_NOUT] = f[k].t; SK_OUTA[SK_NOUT++] = e.va;
            p = place(&e, p);
        }
    uint64_t endt; { e.n = 0; e.va = (uint64_t)(uintptr_t)p; remap(&e, &sk.map, &m->map); jmp_to(&e, slot_of(m, fb + fl)); endt = e.va; p = place(&e, p); }
    uint64_t entry; uint8_t *ep = p; p += 256;                           /* entry thunk, written after the body is placed */
    SK_IMG = &sk; SK_FB = fb; SK_FL = fl; SK_BASE = (uint64_t)(uintptr_t)p; SK_OFF = off;
    X.tgt = skill_tgt;
    for (int pass = 0; pass < 2; pass++) {
        uint64_t at = 0;
        for (size_t k = 0; k < n; k++) {
            if (pass == 1 && at != off[k]) { X.tgt = 0; memset(&X, 0, sizeof X); return -3; }
            off[k] = at;
            X.fuse_out = fo[k]; X.fuse_in = fi[k]; X.noflag = nf[k];
            E b; b.n = 0; b.va = SK_BASE + at;
            int fall, kind = emit_insn(&b, &sk, fb + 4 * k, w[k], &fall);
            if (kind == K_HELPER) { b.n = 0; emit_helper_call(&b, &sk, fb + 4 * k); }
            else if (kind == K_EXIT) { b.n = 0; mov_ri(&b, RDX, fb + 4 * k); jmp_to(&b, sk.exit); }
            if (pass == 1) memcpy(p + at, b.buf, (size_t)b.n);
            at += (uint64_t)b.n;
        }
        off[n] = at;
        if (pass == 1) { E t; t.n = 0; t.va = SK_BASE + at; jmp_to(&t, endt); memcpy(p + at, t.buf, (size_t)t.n); }
    }
    memset(&X, 0, sizeof X);
    if (getenv("SLOT_DUMP_SKILL")) {                                    /* debug: the skill as an assembler file */
        FILE *df = fopen(getenv("SLOT_DUMP_SKILL"), "w");
        for (size_t k = 0; k < n; k++) {
            fprintf(df, "i%zu:\n", k);
            for (uint64_t b2 = off[k]; b2 < off[k + 1]; b2++) fprintf(df, "  .byte 0x%02x\n", p[b2]);
        }
        fclose(df);
    }
    if (live) {
        /* every patchable way in (branch target, return point) now leads into the skill at that instruction */
        uint8_t *tp = p + off[n] + 8;
        int same = !memcmp(&m->map, &sk.map, sizeof sk.map);
        int np = 0;
        for (size_t k = 0; k < n; k++) {
            if (!(m->lab[k0 + k] & 1)) continue;
            uint8_t *slot = (uint8_t *)(uintptr_t)slot_of(m, fb + 4 * k);
            if (memcmp(slot, LABNOP, 5)) continue;                       /* already patched, or not a NOP: leave it */
            uint64_t dest = SK_BASE + off[k];
            if (!same) {
                if ((size_t)(tp - p0) + 256 > sz) break;                    /* out of room: the rest stay plain (correct) */
                E t; t.n = 0; t.va = (uint64_t)(uintptr_t)tp; remap(&t, &m->map, &sk.map); jmp_to(&t, dest);
                memcpy(tp, t.buf, (size_t)t.n); dest = t.va; tp += t.n;
            }
            uint64_t old; memcpy(&old, slot, 8);
            uint64_t nw = old;
            uint8_t *nb = (uint8_t *)&nw;
            nb[0] = 0xe9; uint32_t r = rel32((uint64_t)(uintptr_t)slot + 5, dest); memcpy(nb + 1, &r, 4);
            __atomic_store_n((uint64_t *)(void *)slot, nw, __ATOMIC_RELEASE);
            np++;
        }
        LST.patched += (uint64_t)np;
        if (mapf()) { for (size_t k = 0; k <= n; k++) fprintf(mapf(), "S %llx %llx\n", (unsigned long long)(SK_BASE + off[k]), (unsigned long long)(fb + 4 * k)); fflush(mapf()); }
        (void)ep; (void)entry;
    } else {
    /* entry: the image's map -> the skill's map, into the skill */
    e.n = 0; e.va = (uint64_t)(uintptr_t)ep; remap(&e, &m->map, &sk.map); jmp_to(&e, SK_BASE); entry = e.va; place(&e, ep);
    /* the function's own slot now leads into the skill */
    uint8_t *slot = (uint8_t *)(uintptr_t)slot_of(m, fb);
    E j; j.n = 0; j.va = (uint64_t)(uintptr_t)slot; jmp_to(&j, entry);
    memcpy(slot, j.buf, (size_t)j.n); memset(slot + j.n, 0xcc, (size_t)(SLOT - j.n));
    }
    if (rep) {
        rep->insns = (int)n; rep->fused = fused; rep->dead_saves = dead; rep->bytes = (int)off[n];
        rep->slot_bytes = (int)(n * SLOT); rep->nmapped = sk.map.n;
        for (int i = 0; i < sk.map.n && i < 16; i++) rep->mapped[i] = sk.map.g[i];
    }
    (void)p0; free(f); free(lin); free(lout); free(label); free(fo); free(fi); free(nf); if (live) free(off);
    /* off is kept: skill_tgt is only used while emitting, but keep it simple */
    return 0;
}


/* ───────────────────────── learning in a live process ─────────────────────────
   A loop got hot (its back edge counted down to zero). Learn the function it is in: the episode is the counters -
   each back edge's measured iteration count weights the instructions of its loop - and the skill replaces the
   function's patchable labels. Every counter in the function is then retired. */
static void learn_fn(img_t *m, uint64_t lo, uint64_t hi, uint64_t hotk, int uniform) {
    if (lo < m->tb) lo = m->tb;
    if (hi > m->tb + m->tlen) hi = m->tb + m->tlen;
    if (hi <= lo || (lo & 3) || (hi & 3)) { LST.nobounds++; return; }
    size_t k0 = (lo - m->tb) / 4, n = (hi - lo) / 4;
    if (n > 16384) { LST.toobig++; for (size_t k = 0; k < n; k++) if (m->cnt) m->cnt[k0 + k] = CNT_NEVER; return; }
    uint64_t *ex = calloc(n, sizeof *ex);
    if (!ex) return;
    for (size_t j = 0; j < n; j++) ex[j] = 1;
    if (!uniform && m->cnt)
        for (size_t j = 0; j < n; j++) {
            size_t k = k0 + j;
            if (!(m->lab[k] & 2)) continue;
            uint32_t c = m->cnt[k];
            uint64_t taken = k == hotk ? (uint64_t)slot_hot_threshold : c <= (uint32_t)slot_hot_threshold ? (uint64_t)(slot_hot_threshold - (int)c) : 0;
            int call; uint64_t t = direct_target(m->tb + 4 * k, slot_word(m->tb + 4 * k), &call);
            if (t >= lo && t <= m->tb + 4 * k) for (size_t i = (t - lo) / 4; i <= j; i++) ex[i] += taken;
        }
    if (m->cnt) for (size_t j = 0; j < n; j++) m->cnt[k0 + j] = CNT_NEVER;
    int rc = consolidate_in(lo, hi - lo, ex, 0, 0, 1);
    free(ex);
    if (rc) LST.failed++; else { LST.skills++; slot_learned_ring[slot_learned_n++ & 15] = lo; crash_note(); }
}
/* functions already learned (each once): a small open-addressed set keyed by start */
static uint64_t LEARNED[1 << 14];
static int learned_at(uint64_t lo) {
    for (unsigned h = (unsigned)(lo >> 2) & ((1 << 14) - 1), i = 0; i < 64; i++, h = (h + 1) & ((1 << 14) - 1)) {
        if (LEARNED[h] == lo) return 1;
        if (!LEARNED[h]) { LEARNED[h] = lo; return 0; }
    }
    return 1;                                                            /* the set is full: learn nothing more */
}
static uint64_t slot_hot_c(a64 *s, uint64_t A) {
    (void)s;
    pthread_mutex_lock(&slot_mu);
    img_t *m = img_find_w(A);
    if (m && m->cnt) {
        size_t k = (A - m->tb) / 4;
        m->cnt[k] = CNT_NEVER;
        LST.hot++;
        uint64_t lo, hi;
        int call; uint64_t t = direct_target(A, slot_word(A), &call);
        uint64_t at = (m->lab[k] & 4) ? t : A;                          /* a hot call site: learn the callee */
        if (slot_func_bounds && !slot_func_bounds(at, &lo, &hi) && !learned_at(lo)) learn_fn(m, lo, hi, (m->lab[k] & 4) ? (uint64_t)-1 : k, 0);
        else LST.nobounds++;
    }
    pthread_mutex_unlock(&slot_mu);
    return 0;
}
/* the stress mode: learn EVERY function of the image at once (uniform weights) */
int slot_learn_all(uint64_t tb, uint64_t tlen) {
    if (!slot_func_bounds) return -1;
    pthread_mutex_lock(&slot_mu);
    img_t *m = img_find_w(tb);
    int nf = 0;
    if (m)
        for (uint64_t a = tb; a < tb + tlen;) {
            uint64_t lo, hi;
            if (slot_func_bounds(a, &lo, &hi) || hi <= a) { a += 4; continue; }
            if (lo == a) { learn_fn(m, lo, hi, (uint64_t)-1, 1); nf++; }
            a = hi;
        }
    pthread_mutex_unlock(&slot_mu);
    return nf;
}
void slot_learn_stats(struct slot_learnst *o) { *o = LST; }

int slot_learn_function(uint64_t lo, uint64_t hi) {
    pthread_mutex_lock(&slot_mu);
    img_t *m = img_find_w(lo);
    uint64_t f0 = LST.failed;
    if (m) learn_fn(m, lo, hi, (uint64_t)-1, 1);
    pthread_mutex_unlock(&slot_mu);
    return m ? (LST.failed != f0 ? -2 : 0) : -1;
}
