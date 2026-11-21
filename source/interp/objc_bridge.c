/* objc_bridge.c — ladder rung 3: Objective-C message sends and blocks between translated arm64 code and the NATIVE runtime.
 *
 *  objc_msgSend has no fixed signature: its arguments are what the METHOD declares, and the method is only known at run
 *    time. The lifter's full-register bind ('rf') hands us the whole arm64 argument state in the thread-local
 *    __arm2x86_rf (x0..x8 at +8*i, v0..v7 at +80+16*j) with the arm64 sp published in __arm_sp. We read the method's TYPE
 *    ENCODING from the native runtime, take every argument from where AAPCS64 (Apple) put it, call the NATIVE
 *    objc_msgSend through libffi with the SysV signature that encoding describes, and write the result back where an arm64
 *    caller reads it: x0 (+x1) for integers and small structs, v0..v3 for floating point and HFAs (CGRect), and the
 *    memory at x8 for a large struct.
 *  x86_64 returns a struct > 16 bytes through a hidden pointer, and the runtime has a separate entry for that:
 *    objc_msgSend_stret / objc_msgSendSuper2_stret. Using plain objc_msgSend there shifts every argument by one register.
 *  A method the runtime cannot describe (no Method, no NSMethodSignature) ABORTS BY NAME, never "best effort".
 *  Not yet: long double arguments (refused by name). Variadic methods go to their va_list twins (rung 3c), unions are
 *    a struct with the union's size, alignment and per-eightbyte class (parse_union), and a native va_list parameter is
 *    rebuilt as an x86 va_list (msg_send).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <unistd.h>
#include <objc/runtime.h>
extern FILE *a2x_errf(void);   /* the runtime's report stream (ARM2X86_ERRFILE, else stderr) */
#include <objc/message.h>
#include <ffi/ffi.h>
#include <dlfcn.h>

extern __thread unsigned long __arm_sp;
__thread unsigned char __arm2x86_rf[208] __attribute__((aligned(16)));
extern unsigned long __arm_text_base, __arm_text_size;
unsigned long __arm2x86_cb(unsigned long fn);               /* xlat main.c: arm64 function -> native trampoline */
extern void NSGetSizeAndAlignment(const char *, unsigned long *, unsigned long *);  /* Foundation, C-callable */
extern void objc_msgSendSuper2(void); extern void objc_msgSendSuper2_stret(void);   /* exported by libobjc, not in the public header */

void a2x_dump_msgring(void);
extern void a2x_stop(const char *reason, const char *detail);
extern void a2x_stop_objc(const char *sel, const char *cls);
/* a named stop of the bridge: the stop record carries the reason line; the message ring is a lab diagnostic */
static void die2(const char *m, const char *a) {
    char r[256]; snprintf(r, sizeof r, "objc_bridge: %s", m);
    a2x_stop(r, a ? a : "");
    abort(); }
#define RX(i) (((uint64_t *)__arm2x86_rf)[i])
#define RV(j) (__arm2x86_rf + 80 + 16 * (j))   /* 16-aligned: +72 faulted on vmovaps */

static const char *skipq(const char *t) { while (*t && strchr("rnNoORVA", *t)) t++; return t; }

/* ---- ffi types from an encoding (cached; types live for the process) --------------------------------------------------- */
struct tcache { struct tcache *next; char *enc; ffi_type *t; };
static struct tcache *gT; static pthread_mutex_t gTm = PTHREAD_MUTEX_INITIALIZER;
static const char *parse_type(const char *t, ffi_type **out);
static const char *skip_type(const char *t);
static int hfa(ffi_type *t, int *isd);

/* 10-20 UNIONS. /usr/bin/log on macOS 27 died at EVERY start: `union argument (not yet bridged) (?={?=CCSI}QAQ)16`,
      thrown while add_methods registered the binary's OWN methods, before main. libffi has no union type, so a union
      becomes an FFI_TYPE_STRUCT that reproduces the three things either ABI looks at:
       size = the largest member rounded to the alignment, alignment = the largest member's;
       x86-64 SysV class: the union is cut into chunks of its own alignment A (<= 8: a member wider than A would raise A),
         each chunk is INTEGER if any member puts an integer byte in it, SSE if only float/double bytes. One element per
         chunk (uintA, or float/double) gives libffi exactly that classification, and it still holds when the union sits
         at a non-eightbyte offset inside a parent struct (a chunk never straddles an eightbyte). A chunk no member covers
         is called INTEGER — the SysV merge would leave it NO_CLASS; only a padding-only chunk next to a float differs.
       AAPCS64 HFA: clang (isHomogeneousAggregate) takes the MAX member count over members of ONE base type and requires
         size == count * base. {double; float} is SSE on x86 yet NOT an HFA on arm64, which the element list cannot say,
         so each union's HFA answer is recorded here and hfa() reads it first. Not an HFA: <= 16 bytes rides x registers,
         larger goes by reference — the existing struct paths, unchanged. */
struct uinfo { struct uinfo *next; ffi_type *t; int nh, isd; };
static struct uinfo *gU;   /* append-only, prepended under gTm; read lock-free (a node is complete before it is linked) */
static struct uinfo *ufind(ffi_type *t) {
    for (struct uinfo *u = __atomic_load_n(&gU, __ATOMIC_ACQUIRE); u; u = u->next) if (u->t == t) return u;
    return NULL;
}
/* Lay out a struct now (libffi's initialize_aggregate does the same at prep time and skips a type whose size is set).
    alignment is stored BEFORE size: another thread's ffi_prep_cif treats size != 0 as "laid out" and reads alignment. */
static void lay(ffi_type *t) {
    if (t->type != FFI_TYPE_STRUCT || t->size || !t->elements) return;
    size_t off = 0, al = 1;
    for (ffi_type **e = t->elements; *e; e++) {
        lay(*e); size_t a = (*e)->alignment ? (*e)->alignment : 1;
        off = (off + a - 1) & ~(a - 1); off += (*e)->size; if (a > al) al = a;
    }
    __atomic_store_n(&t->alignment, (unsigned short)al, __ATOMIC_RELAXED);
    __atomic_store_n(&t->size, (off + al - 1) & ~(al - 1), __ATOMIC_RELEASE);
}
/* chunk classes at granularity A: 0 none, 1 SSE, 2 INTEGER (INTEGER wins the merge, as in SysV) */
static void mark(ffi_type *t, size_t off, unsigned char *cls, size_t nch, size_t A) {
    if (t->type == FFI_TYPE_STRUCT) {
        size_t o = off;
        for (ffi_type **e = t->elements; e && *e; e++) {
            size_t a = (*e)->alignment ? (*e)->alignment : 1;
            o = (o + a - 1) & ~(a - 1); mark(*e, o, cls, nch, A); o += (*e)->size;
        }
        return;
    }
    if (!t->size) return;
    unsigned char c = (t->type == FFI_TYPE_FLOAT || t->type == FFI_TYPE_DOUBLE) ? 1 : 2;
    for (size_t b = off / A; b <= (off + t->size - 1) / A && b < nch; b++) if (cls[b] < c) cls[b] = c;
}
/* one past the encoding that starts at t, brackets balanced ({..} (..) [..] and "quoted names") */
static const char *enc_end(const char *t) {
    int d = 0;
    do {
        if (!*t) return t;
        if (*t == '"') { t++; while (*t && *t != '"') t++; if (!*t) return t; }
        else if (*t == '(' || *t == '{' || *t == '[') d++;
        else if (*t == ')' || *t == '}' || *t == ']') d--;
        t++;
    } while (d > 0);
    return t;
}
/* 10-20 A POINTEE IS SKIPPED, NEVER BUILT. skip_type WAS parse_type: every `^{...}` argument built (and cached) ffi
      types for a struct nobody passes by value, so /usr/bin/log — past the union — died `unknown type encoding b48b16`
      on a BITFIELD inside ^{firehose_tracepoint_s=...(?={?=b48b16}QAQ)[0C]}, a pointer. Only a by-value type needs a
      layout; a pointer's target only needs its end. */
/* 10-20 A BLOCK PARAMETER CAN CARRY ITS OWN SIGNATURE: @?<v@?@"NSError">. macOS 27's mbsystemadministration
      registers methods typed that way and the bridge died on "unknown type encoding <v@?@"NSError">". The <...> part is
      the block's prototype, only metadata for us (the argument itself is still one pointer). It nests, and a quoted
      class name inside it can hold <Protocol> brackets of its own, so skip quotes while counting. */
static const char *skip_block_sig(const char *t) {
    if (*t != '<') return t;
    int depth = 0;
    for (; *t; t++) {
        if (*t == '"') { t++; while (*t && *t != '"') t++; if (!*t) return t; continue; }
        if (*t == '<') depth++;
        else if (*t == '>' && --depth == 0) return t + 1;
    }
    return t;
}
static const char *skip_type(const char *t) {
    t = skipq(t);
    switch (*t) {
    case 0: return t;
    case '{': case '(': case '[': return enc_end(t);
    case '^': return skip_type(t + 1);
    case 'b': t++; while (*t >= '0' && *t <= '9') t++; return t;
    /* 10-26 _Complex T is 'j' then T, and skip_type stepped over the 'j' as if it were the whole type,
          leaving the base type to be read as the next member. */
    case 'j': return skip_type(t + 1);
    /* 10-26 AN EMPTY TYPE CONSUMES NOTHING, AND THE OLD `default: return t + 1` ATE THE `]`. A vector
          encodes as no characters at all (see a2x_lane), so `[4]` is a count with no element: the cursor
          arrives on the `]`, which belongs to the array branch that called us. Stepping past it left that
          branch looking at `}` and the whole struct was mis-read from there on. */
    case ']': case ')': case '}': return t;
    case '@': t++; if (*t == '?') return skip_block_sig(t + 1);
        if (*t == '"') { t++; while (*t && *t != '"') t++; if (*t) t++; }
        return t;
    default: return t + 1;
    }
}
/* 10-26 A VECTOR TYPE ENCODES AS NOTHING AT ALL, AND THAT IS WHAT KILLED THREE APPS AT START-UP.
      clang writes NO characters for an ext_vector_type — every simd_ and vector_ type — so the vector is simply
      ABSENT from the encoding and the parse cursor stops on whatever byte follows it. MEASURED in the macOS 27
      binaries, read straight out of __TEXT,__objc_methtype:
        Chess     {?=[4]}16@0:8                      -> cursor on "]}16@0:8"   (an array element that is not there)
        Freeform  v104@0:8@16@24{?=[4]}32@?96        -> cursor on "]}32@?96"
        Music     v36@0:8{vec3=}16f32                -> a struct with ZERO members, whose size stays 0
       The `types` pointer was never wrong, and neither was the relative-method-list reader: every one of
         those error strings is a VALID encoding read from the middle, which is exactly what a parse cursor
         looks like. A method list entry's three int32 offsets are each relative to their OWN field and the
         code already reads them that way — test_mlist.c locks that down so it cannot drift.
    THE WIDTH IS NOT IN THE ENCODING; the method's own frame offsets carry it, and every instance in the
      65-app sweep measures 16 bytes per lane. Chess's and Freeform's `{?=[4]}` spans offsets 24->88 and
      32->96 (64 bytes over 4 elements), Music's `{vec3=}` spans 16->32, and Music's named
      {Uniforms="viewMatrix"{?="columns"[4]}"time"f...} lays out to 368 bytes against its own frame size of
      384-16 = 368. So one lane is 16 bytes at 16-byte alignment — and make_imp below checks that against the
      offsets for every argument, in both directions, rather than trusting it.
    FOUR FLOATS IS THE RIGHT ELEMENT LIST FOR BOTH ABIs. x86-64 SysV classes a 16-byte vector SSE whatever
      its element type (__m128, __m128i and __m128d alike), which {f,f,f,f} reproduces exactly; size and
      alignment are set here so libffi's initialize_aggregate sees a laid-out type and leaves them alone.
    NOT AN HFA, DELIBERATELY: {f,f,f,f} would otherwise count as an HFA of four floats and arm64 would place
      it in s0-s3 instead of one q register. The lane is recorded in the gU table with nh = 0, which is how a
      union already tells hfa() "this element list describes x86, not arm64" — so hfa() answers "not an HFA"
      and a lane rides the plain aggregate paths.
    WHAT IS STILL WRONG, AND IT IS NAMED RATHER THAN HIDDEN: AAPCS64 passes an HVA of 1-4 lanes in v0-v3 and
      returns it there. The plain aggregate paths put a 16-byte lane in x0:x1 and a 64-byte one through the
      indirect buffer, so a method that really takes or returns a vector has its REGISTER PLACEMENT wrong even
      though its size and its x86 class are right. That is the half that is not built; see NOTES.md. */
static ffi_type *a2x_lane_el[5] = { &ffi_type_float, &ffi_type_float, &ffi_type_float, &ffi_type_float, NULL };
static ffi_type a2x_lane_t = { .size = 16, .alignment = 16, .type = FFI_TYPE_STRUCT, .elements = a2x_lane_el };
/* set whenever a lane was synthesised while parsing the CURRENT type, so make_imp knows which arguments to
      measure against the frame offsets. Per-thread: parse_type runs on whatever thread sends the message. */
static __thread int a2x_lane_used;
static ffi_type *a2x_lane(void) {
    static int inGU;                         /* the lane joins the gU table exactly once */
    a2x_lane_used = 1;
    pthread_mutex_lock(&gTm);
    if (!inGU) {
        struct uinfo *u = calloc(1, sizeof *u);
        if (!u) { pthread_mutex_unlock(&gTm); die2("out of memory recording a vector lane", ""); }
        u->t = &a2x_lane_t; u->nh = 0; u->isd = -1;   /* nh = 0: hfa() answers "not an HFA" and means it */
        u->next = gU; __atomic_store_n(&gU, u, __ATOMIC_RELEASE);
        inGU = 1;
    }
    pthread_mutex_unlock(&gTm);
    return &a2x_lane_t;
}
/* 10-26 THE LANE WIDTH IS A MEASUREMENT, SO IT IS CHECKED WHERE THE MEASUREMENT LIVES. A wrong argument
      size does not fail by itself — it slides every LATER argument one place. That is the audit_token_t bug
      already recorded in this file, where a 32-byte token sized at 8 handed FSKit the token's bytes as a
      reply block. So compare the size we built against the gap the method's own offsets measure: a gap
      SMALLER than our type means we overlap the next argument, which is impossible, and a gap a whole lane
      larger means we are short by at least one lane. One lane of slack is allowed because the next argument's
      offset is rounded up to its own alignment, and 16 is the largest alignment anything here produces. */
/* 10-27 A LANE IS NOT ALWAYS 16 BYTES, AND WHEN IT IS NOT THE WHOLE AGGREGATE IS STILL A KNOWN SIZE.
      Books -[... setVertexUniforms:] is typed {?={?=[4]}fff{?=[3]}fB[9][9f]} with a frame gap of 256; this bridge
      built it at 336 because the `[9]` array is simd_float2 (8-byte lanes), which clang writes no width for.
      Mixed lane widths inside one struct cannot be told from the encoding, but the offsets still give the
      struct's rounded size, and a by-value aggregate wider than 16 bytes is passed in memory by both ABIs
      (AAPCS64 by reference, SysV on the stack), so only its size and alignment matter. So a gap wider than one
      register is trusted over the lane guess and the argument becomes an opaque laid-out block of that size.
       Narrower than that (a single 8-byte lane, a gap that disagrees at register width) stays fatal: the
         register class decides placement there and a guess would misplace every later argument. */
static ffi_type *a2x_opaque(size_t size) {
    char key[48];
    int kl = snprintf(key, sizeof key, "a2x.opaque.%zu", size);
    pthread_mutex_lock(&gTm);
    for (struct tcache *c = gT; c; c = c->next)
        if (strlen(c->enc) == (size_t)kl && !memcmp(c->enc, key, (size_t)kl)) {
            ffi_type *t = c->t; pthread_mutex_unlock(&gTm); return t;
        }
    size_t n = size / 4;
    ffi_type **el = calloc(n + 1, sizeof *el);
    ffi_type *st = calloc(1, sizeof *st);
    struct tcache *c = calloc(1, sizeof *c);
    if (!el || !st || !c) { pthread_mutex_unlock(&gTm); die2("out of memory building an opaque aggregate", ""); }
    for (size_t i = 0; i < n; i++) el[i] = &ffi_type_float;
    st->type = FFI_TYPE_STRUCT; st->elements = el;
    st->size = size; st->alignment = (size % 16 == 0) ? 16 : 8;   /* laid out here; libffi leaves a sized type alone */
    c->enc = strdup(key); c->t = st; c->next = gT; gT = c;
    pthread_mutex_unlock(&gTm);
    return st;
}
static ffi_type *a2x_lane_check(const char *sel, const char *types, int arg, size_t ours, unsigned long gap) {
    if (gap >= ours && gap < ours + 16) return NULL;
    if (gap > 16 && gap % 8 == 0 && gap <= 4096) {
        fprintf(a2x_errf(), "[objc] %s argument %d: vector lanes are not all 16 bytes here — using the method's own "
                "frame gap, %lu bytes, as one opaque by-value block (this bridge had %zu)\n",
                sel ? sel : "(unnamed selector)", arg, gap, ours);
        return a2x_opaque((size_t)gap);
    }
    fprintf(a2x_errf(), "[objc] %s argument %d: this bridge sized its vector(s) at %zu bytes, the method's own "
            "frame offsets measure %lu — types=\"%s\"\n",
            sel ? sel : "(unnamed selector)", arg, ours, gap, types ? types : "(null)");
    die2("a vector argument's width disagrees with the method's frame offsets, so one lane is not 16 bytes in "
         "this program and every argument after it is misplaced:", sel);
    return NULL;
}
/* a cached FFI_TYPE_STRUCT of n copies of base, keyed on the encoding text [enc, enc+len) like parse_union's */
static ffi_type *a2x_repeat(const char *enc, size_t len, ffi_type *base, int n) {
    pthread_mutex_lock(&gTm);
    for (struct tcache *c = gT; c; c = c->next)
        if (strlen(c->enc) == len && !memcmp(c->enc, enc, len)) {
            ffi_type *t = c->t; pthread_mutex_unlock(&gTm); return t;
        }
    ffi_type **el = calloc((size_t)n + 1, sizeof *el);
    ffi_type *st = calloc(1, sizeof *st);
    struct tcache *c = calloc(1, sizeof *c);
    char *key = strndup(enc, len);
    if (!el || !st || !c || !key) { pthread_mutex_unlock(&gTm); die2("out of memory building a repeated type", ""); }
    for (int i = 0; i < n; i++) el[i] = base;
    st->type = FFI_TYPE_STRUCT; st->elements = el;
    lay(st);                                  /* exact by construction: n members of one laid-out type */
    c->enc = key; c->t = st; c->next = gT; gT = c;
    pthread_mutex_unlock(&gTm);
    return st;
}
static const char *parse_union(const char *t, ffi_type **out) {
    const char *start = t, *end = enc_end(t); size_t len = (size_t)(end - start);
    pthread_mutex_lock(&gTm);   /* cached by encoding text BEFORE parsing: msg_send re-parses on every call */
    for (struct tcache *c = gT; c; c = c->next)
        if (strlen(c->enc) == len && !memcmp(c->enc, start, len)) { *out = c->t; pthread_mutex_unlock(&gTm); return end; }
    pthread_mutex_unlock(&gTm);
    const char *p = t + 1;
    while (*p && *p != '=' && *p != ')') p++;
    if (*p == '=') p++;
    ffi_type *mt[128]; size_t mn[128]; int nm = 0;
    while (*p && *p != ')') {
        if (nm >= 128) die2("union with > 128 members", start);
        size_t cnt = 1; ffi_type *et;
        if (*p == '[') {   /* an array member is inline bytes (see the struct case below) */
            const char *q = p + 1; cnt = 0;
            while (*q >= '0' && *q <= '9') cnt = cnt * 10 + (size_t)(*q++ - '0');
            q = parse_type(q, &et); if (*q == ']') q++; p = q;
        } else { const char *was = p; p = parse_type(p, &et);   /* 10-26: see the struct member loop */
                 if (p == was) die2("a union member encoding that consumes nothing (corrupt) at", p); }
        lay(et); mt[nm] = et; mn[nm] = cnt; nm++;
    }
    size_t sz = 0, A = 1;
    for (int i = 0; i < nm; i++) {
        size_t s = mt[i]->size * mn[i], a = mt[i]->alignment ? mt[i]->alignment : 1;
        if (s > sz) sz = s;
        if (a > A) A = a;
    }
    if (A > 8) die2("union member aligned beyond 8 bytes (long double / vector: not bridged)", start);
    sz = (sz + A - 1) & ~(A - 1);
    size_t nch = sz / A; unsigned char *cls = calloc(nch ? nch : 1, 1);
    for (int i = 0; i < nm; i++) for (size_t k = 0; k < mn[i]; k++) mark(mt[i], k * mt[i]->size, cls, nch, A);
    int isd = -1, nh = 0, ok = nm > 0;
    for (int i = 0; i < nm && ok; i++) { int h = hfa(mt[i], &isd); if (h <= 0) ok = 0; else if ((size_t)h * mn[i] > (size_t)nh) nh = h * (int)mn[i]; }
    if (!ok || nh < 1 || nh > 4 || sz != (size_t)nh * (isd ? 8 : 4)) nh = 0;
    ffi_type **els = calloc(nch + 1, sizeof *els);
    for (size_t b = 0; b < nch; b++) {
        if (cls[b] == 1) {
            if (A < 4) die2("union float chunk narrower than 4 bytes (impossible encoding)", start);
            els[b] = A == 8 ? &ffi_type_double : &ffi_type_float;
        } else els[b] = A == 8 ? &ffi_type_uint64 : A == 4 ? &ffi_type_uint32 : A == 2 ? &ffi_type_uint16 : &ffi_type_uint8;
    }
    free(cls);
    ffi_type *st = calloc(1, sizeof *st); st->type = FFI_TYPE_STRUCT; st->elements = els;
    if (nch) lay(st);   /* exact by construction: nch chunks of A bytes at alignment A = sz */
    struct uinfo *u = calloc(1, sizeof *u); u->t = st; u->nh = nh; u->isd = isd;
    pthread_mutex_lock(&gTm);
    for (struct tcache *c = gT; c; c = c->next)   /* another thread built it meanwhile: use theirs */
        if (strlen(c->enc) == len && !memcmp(c->enc, start, len)) { *out = c->t; pthread_mutex_unlock(&gTm); free(els); free(st); free(u); return end; }
    u->next = gU; __atomic_store_n(&gU, u, __ATOMIC_RELEASE);
    struct tcache *c = calloc(1, sizeof *c); c->enc = strndup(start, len); c->t = st; c->next = gT; gT = c;
    pthread_mutex_unlock(&gTm);
    *out = st; return end;
}
static const char *parse_type(const char *t, ffi_type **out) {
    t = skipq(t);
    switch (*t) {
    case 'c': *out = &ffi_type_sint8; return t + 1;   case 'C': *out = &ffi_type_uint8; return t + 1;
    case 'B': *out = &ffi_type_uint8; return t + 1;
    case 's': *out = &ffi_type_sint16; return t + 1;  case 'S': *out = &ffi_type_uint16; return t + 1;
    case 'i': *out = &ffi_type_sint32; return t + 1;  case 'I': *out = &ffi_type_uint32; return t + 1;
    case 'l': case 'q': *out = &ffi_type_sint64; return t + 1;
    case 'L': case 'Q': *out = &ffi_type_uint64; return t + 1;
    case 'f': *out = &ffi_type_float; return t + 1;   case 'd': *out = &ffi_type_double; return t + 1;
    case 'v': *out = &ffi_type_void; return t + 1;
    case '*': case '#': case ':': *out = &ffi_type_pointer; return t + 1;
    case '@': *out = &ffi_type_pointer; t++;
        if (*t == '?') t = skip_block_sig(t + 1);             /* @? block, optional <signature> */
        else if (*t == '"') { t++; while (*t && *t != '"') t++; if (*t) t++; }
        return t;
    case '^': *out = &ffi_type_pointer; return skip_type(t + 1);
    case '?': *out = &ffi_type_pointer; return t + 1;
    case '[': { /* an array argument decays to a pointer; inside a struct it is inline — handled as bytes there */
        *out = &ffi_type_pointer; t++; while (*t >= '0' && *t <= '9') t++; t = skip_type(t); return *t == ']' ? t + 1 : t; }
    case '{': {
        const char *start = t, *p = t + 1;
        while (*p && *p != '=' && *p != '}') p++;
        if (*p == '=') p++;
        /* 10-20 WAS a fixed el[128]: macOS 27's mds passes {MDCredential=Ii[16I]ii[1024c]} — 1,044 members once the
              inline arrays are expanded — and died "struct array member too large to bridge". The list grows. */
        int cap = 32, n = 0; ffi_type **el = malloc((size_t)cap * sizeof *el);
        if (!el) die2("out of memory parsing struct", start);
        while (*p && *p != '}') {
            if (n + 1 >= cap) { cap *= 2; el = realloc(el, (size_t)cap * sizeof *el); if (!el) die2("out of memory parsing struct", start); }
            /* 10-20 AN ARRAY INSIDE A STRUCT IS INLINE BYTES, NOT A POINTER. audit_token_t is {?=[8I]}: parsed
                  as one pointer member it came out 8 bytes, so macOS 27's diskarbitrationd passed
                  -[FSClient installedExtensionsForUser:replyHandler:] its 32-byte token in a register and every later
                  argument slid one place: FSKit retained the token's bytes as the reply block (objc_retain, fault 0x20).
                  Expand [N t] into N members of t so libffi sizes the struct and picks MEMORY class exactly as clang. */
            if (*p == '[') {
                const char *q = p + 1; int cnt = 0;
                while (*q >= '0' && *q <= '9') cnt = cnt * 10 + (*q++ - '0');
                ffi_type *et; q = parse_type(q, &et);
                if (*q == ']') q++;
                if (cnt > (1 << 20)) die2("struct array member too large to bridge", start);
                if (n + cnt + 1 >= cap) { while (n + cnt + 1 >= cap) cap *= 2; el = realloc(el, (size_t)cap * sizeof *el); if (!el) die2("out of memory parsing struct", start); }
                for (int k = 0; k < cnt; k++) el[n++] = et;
                p = q; continue;
            }
            /* 10-20 BITFIELDS INSIDE A BY-VALUE STRUCT. macOS 27's mds registers a method taking a struct whose
                  encoding ends ...b8b4b1b51}: the bridge refused ("layout unknowable") and mds aborted at start-up,
                  which kept loginwindow blocked on its mds.legacy port. The encoding gives widths, not the storage unit,
                  but the compiler packs a run of consecutive bitfields into integer units, so sum the run and lay it out
                  as the fewest u64/u32/u16/u8 that hold it — exact in size and in register class (INTEGER) whenever the
                  run fills its unit, as 8+4+1+51 = 64 bits does here. */
            if (*p == 'b') {
                unsigned bits = 0;
                while (*p == 'b') { p++; unsigned w = 0; while (*p >= '0' && *p <= '9') w = w * 10 + (unsigned)(*p++ - '0'); bits += w; }
                while (bits) {
                    ffi_type *it = bits > 32 ? &ffi_type_uint64 : bits > 16 ? &ffi_type_uint32 : bits > 8 ? &ffi_type_uint16 : &ffi_type_uint8;
                    unsigned take = bits > 64 ? 64 : bits > 32 ? bits : bits > 16 ? bits : bits > 8 ? bits : bits;
                    if (n + 1 >= cap) { cap *= 2; el = realloc(el, (size_t)cap * sizeof *el); if (!el) die2("out of memory parsing struct", start); }
                    el[n++] = it; bits -= take;
                }
                continue;
            }
            /* 10-26 A MEMBER THAT CONSUMES NOTHING WOULD SPIN THIS LOOP FOR EVER and grow the
                  element list until the allocator gave up — a hang instead of a message. parse_type now
                  returns without consuming for an empty type, which is right for an array element and for
                  a whole argument but is NOT readable at a member position (a zero-length member in the
                  middle of a member list cannot be told from no member at all), so a cursor that did not
                  move here means the encoding is corrupt. Name it and stop. */
            { const char *was = p; p = parse_type(p, &el[n++]);
              if (p == was) die2("a struct member encoding that consumes nothing (corrupt) at", p); }
        }
        /* 10-26 A BY-VALUE STRUCT WITH NO MEMBERS HOLDS A VECTOR. macOS 27 Music died
              "FATAL: objc_bridge: ffi_prep_cif (closure) setRenderColor:withAlpha:". That method is typed
              v36@0:8{vec3=}16f32, and {vec3=} parsed to a struct with zero elements whose size therefore
              stayed 0 — libffi's initialize_aggregate ends with `if (arg->size == 0) return FFI_BAD_TYPEDEF`,
              which is the whole of that abort. Its own offsets measure the type at 32 - 16 = 16 bytes:
              one lane.
            AN INCOMPLETE STRUCT CANNOT BE PASSED BY VALUE IN C, so a zero-member struct reaching this
              branch is never an opaque handle: ^{CGImage=}, ^{CGColor=}, ^{_NSZone=} and the forty-odd other
              opaque types in these binaries arrive as POINTERS, and skip_type steps over a pointee without
              ever building it. What is missing is a member clang could not write, and the only member clang
              writes nothing for is a vector.
            A by-value UNION with no members is left alone: it does not occur anywhere in the 65-app sweep,
              and parse_union would refuse a 16-aligned member anyway ("aligned beyond 8 bytes"). It keeps
              dying loudly rather than being guessed at. */
        if (!n) el[n++] = a2x_lane();
        if (*p == '}') p++;
        size_t len = (size_t)(p - start);
        pthread_mutex_lock(&gTm);
        for (struct tcache *c = gT; c; c = c->next) if (strlen(c->enc) == len && !memcmp(c->enc, start, len)) { *out = c->t; pthread_mutex_unlock(&gTm); free(el); return p; }
        ffi_type *st = calloc(1, sizeof *st); ffi_type **els = calloc((size_t)n + 1, sizeof *els);
        memcpy(els, el, (size_t)n * sizeof *els); free(el); st->type = FFI_TYPE_STRUCT; st->elements = els;
        struct tcache *c = calloc(1, sizeof *c); c->enc = strndup(start, len); c->t = st; c->next = gT; gT = c;
        pthread_mutex_unlock(&gTm);
        *out = st; return p; }
    case '(': return parse_union(t, out);
    case 'b': {   /* a bitfield run outside a struct (a union member): one integer unit wide enough for the run */
        unsigned bits = 0;
        while (*t == 'b') { t++; unsigned w = 0; while (*t >= '0' && *t <= '9') w = w * 10 + (unsigned)(*t++ - '0'); bits += w; }
        if (bits > 64) die2("bitfield run wider than 64 bits outside a struct", t);
        *out = bits > 32 ? &ffi_type_uint64 : bits > 16 ? &ffi_type_uint32 : bits > 8 ? &ffi_type_uint16 : &ffi_type_uint8;
        return t; }
    /* 10-26 _Complex HAD NO CASE. macOS 27 Grapher died at start-up with "unknown type encoding
          jd)}16@0:8" — the cursor on the `j` of a _Complex double inside its own number type,
          {_NComplex=(?={?=dd}jd)}16@0:8. clang encodes _Complex T as 'j' followed by T.
        _Complex T IS A PAIR OF T TO BOTH ABIs, so it needs no new rule anywhere else: AAPCS64 makes it an
          HFA of two T (d0,d1 for a double) and x86-64 SysV classes it SSE,SSE (xmm0,xmm1), and a two-member
          struct of T is exactly that on both sides — it goes through the HFA and struct paths already here. */
    case 'j': {
        const char *start = t; ffi_type *bt;
        t = parse_type(t + 1, &bt);
        *out = a2x_repeat(start, (size_t)(t - start), bt, 2);
        return t; }
    /* 10-26 AN EMPTY TYPE IS A VECTOR (a2x_lane has the measurements). Exactly two positions can hold an
          empty type and still be unambiguous:
 the element of an array, where the cursor sits on the `]` closing a count that MUST have an
              element — Chess's {?=[4]}16@0:8;
 a whole argument or return in a method encoding, where the cursor sits on the byte offset that
              follows every type — Chess's -[MBCBoardView lightPosition] is typed exactly "16@0:8", a frame
              size and two arguments with no return type in front of them.
        NOTHING IS CONSUMED HERE, deliberately. The `]` belongs to the array branch that called us and the
          digits belong to the caller's offset skip, so both callers still advance and neither can spin.
        A MEMBER POSITION IS NOT IN THIS SET. A zero-length member in the middle of a member list cannot be
          told apart from no member at all, and returning without consuming there WOULD spin the member loop
          for ever. The one member case that is detectable is a member list that is EMPTY, and that is handled
          at the end of the struct branch below. */
    case ']': *out = a2x_lane(); return t;
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9': *out = a2x_lane(); return t;
    case 'D': die2("long double argument (arm64 double, x86 80-bit — not bridged)", t);
    }
    /* MEASURE AT THE FAILURE, WHATEVER PATH IT CAME FROM. Guarding add_methods only caught two of these;
          the next one arrived through a protocol method description instead. Dumping the bytes AROUND the
          pointer shows where the real string starts, which turns "unknown type encoding" into an offset. */
    {
        const char *q = t - 64;
        fprintf(stderr, "[objc] encoding parse failed at \"%s\"\n       64 before: ", t);
        for (int k = 0; k < 64; k++) { unsigned char c = (unsigned char)q[k]; fputc((c >= 32 && c < 127) ? c : '.', stderr); }
        fprintf(stderr, "\n       64 after:  ");
        for (int k = 0; k < 64; k++) { unsigned char c = (unsigned char)t[k]; fputc((c >= 32 && c < 127) ? c : '.', stderr); }
        fputc('\n', stderr);
    }
    die2("unknown type encoding", t); return t;
}

/* HFA: every leaf is the same floating type and there are 1..4 leaves. Returns leaf count (0 = not an HFA), *isd = double. */
static int hfa(ffi_type *t, int *isd) {
    if (t->type == FFI_TYPE_FLOAT || t->type == FFI_TYPE_DOUBLE) { int d = t->type == FFI_TYPE_DOUBLE;
        if (*isd < 0) *isd = d; return *isd == d ? 1 : -100; }
    if (t->type != FFI_TYPE_STRUCT) return -100;
    struct uinfo *u = ufind(t);   /* a union answers for itself: its element list says x86, not arm64 (parse_union) */
    if (u) { if (!u->nh) return -100; if (*isd < 0) *isd = u->isd; return *isd == u->isd ? u->nh : -100; }
    int n = 0; for (ffi_type **e = t->elements; *e; e++) n += hfa(*e, isd);
    return n;
}
/* 10-20 AAPCS64's HFA is CAPPED AT 4 leaves, and hfa() returns the RAW leaf count — so a wider all-float struct came
      back as 5, 6, 8 … and every caller's `nh >= 1 && nh <= 4` test sent it down a path meant for something else; make_imp
      simply died. Dock's `previewRect` returns {?={CGRect={CGPoint=dd}{CGSize=dd}}{CGPoint=dd}} = SIX doubles / 48 bytes
      and aborted the whole process at class registration, so macOS 27 came up with no Dock.
    Past 4 leaves it is NOT an HFA: > 16 bytes goes indirect (x8 on arm64, sret on x86) and <= 16 bytes rides x0:x1 —
      both already implemented below. clang's isHomogeneousAggregate also demands no padding, hence the size check. */
static int hfa4(ffi_type *t, int *isd) {
    int n = hfa(t, isd);
    if (n < 1 || n > 4) return 0;
    if (t->size != (size_t)n * (*isd ? 8 : 4)) return 0;
    return n;
}
static void hfa_leaves(ffi_type *t, unsigned char *base, size_t *off, unsigned char **leaf, int *k) {
    if (t->type == FFI_TYPE_STRUCT) {
        for (ffi_type **e = t->elements; *e; e++) hfa_leaves(*e, base, off, leaf, k);
        return;
    }
    *off = (*off + t->alignment - 1) & ~(size_t)(t->alignment - 1);
    leaf[(*k)++] = base + *off; *off += t->size;
}

/* ---- blocks crossing to native: invoke and copy/dispose become trampolines, IN PLACE ------------------------------------- */
struct blk_desc { unsigned long reserved, size; unsigned long copy, dispose; };
struct blk { void *isa; int flags, reserved; unsigned long invoke; struct blk_desc *desc; };
static int in_text(unsigned long a) { return a >= __arm_text_base && a < __arm_text_base + __arm_text_size; }
static void make_writable(void *p, size_t n) {
    unsigned long ps = (unsigned long)sysconf(_SC_PAGESIZE), a = (unsigned long)p & ~(ps - 1);
    mprotect((void *)a, ((unsigned long)p + n - a + ps - 1) & ~(ps - 1), PROT_READ | PROT_WRITE);
}
/* The trampoline is also understood by __arm2x86_lookup (shim_comp.c), so arm64 code that calls the SAME block later
 *    still lands in translated code: one pointer serves both worlds. */
#include "block_signature.h"
static IMP make_imp(unsigned long armimp, const char *types, const char *selname);
/* Aggregate arguments require the typed route: the two ABIs may allocate them differently. */
static const char *a2x_block_typed_signature(struct blk *b) {
    const char *sig = a2x_block_descriptor_signature((unsigned)b->flags, b->desc);
    if (!sig) return NULL;
    ffi_type *ty; const char *t = parse_type(sig, &ty);
    while (*t >= '0' && *t <= '9') ++t;
    int indirect = 0;
    while (*t) {
        t = parse_type(t, &ty); lay(ty);
        if (ty->type == FFI_TYPE_STRUCT) indirect = 1;
        while (*t >= '0' && *t <= '9') ++t;
    }
    return indirect ? sig : NULL;
}
/* A block context is argument zero, so instances with the same invoke/signature share one typed door. */
struct a2x_block_door { unsigned long invoke, door; char *signature; struct a2x_block_door *next; };
static struct a2x_block_door *a2x_block_doors;
static pthread_mutex_t a2x_block_doorm = PTHREAD_MUTEX_INITIALIZER;
static unsigned long a2x_block_door(unsigned long invoke, const char *signature) {
    pthread_mutex_lock(&a2x_block_doorm);
    for (struct a2x_block_door *p = a2x_block_doors; p; p = p->next)
        if (p->invoke == invoke && !strcmp(p->signature, signature)) {
            unsigned long door = p->door; pthread_mutex_unlock(&a2x_block_doorm); return door;
        }
    struct a2x_block_door *p = calloc(1, sizeof *p);
    if (!p || !(p->signature = strdup(signature))) die2("block door allocation", signature);
    p->invoke = invoke; p->door = (unsigned long)make_imp(invoke, signature, "block invoke");
    p->next = a2x_block_doors; a2x_block_doors = p;
    pthread_mutex_unlock(&a2x_block_doorm);
    return p->door;
}
void *__arm2x86_blk(void *b0) {
    struct blk *b = b0;
    if (!b) return b0;
    unsigned long invoke = __atomic_load_n(&b->invoke, __ATOMIC_ACQUIRE);
    if (!in_text(invoke)) return b0;
    /* 10-11 DIAGNOSTIC: the block we wrapped and the invoke we replaced. Compare against the a0 the door
       reports (ARM2X86_TRACE_CB): if native code later invokes with a DIFFERENT pointer, it copied the block
       and the copy is what matters. */
    { static int tr = -1; if (tr < 0) tr = A2X_DBGENV("ARM2X86_TRACE_CB") ? 1 : 0;
      if (tr) fprintf(a2x_errf(), "[blk] wrap block=%p invoke=0x%lx flags=0x%x\n", b0, b->invoke, b->flags); }
    make_writable(&b->invoke, 8);
    const char *signature = a2x_block_typed_signature(b);
    unsigned long wrapped = signature ? a2x_block_door(invoke, signature)
                                      : __arm2x86_cb(invoke);
    /* A competing caller may already have wrapped this same block. Never wrap its native closure. */
    __atomic_compare_exchange_n(&b->invoke, &invoke, wrapped, 0,
                                __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);
    if ((b->flags & (1 << 25)) && b->desc) {
        unsigned long *slots[] = { &b->desc->copy, &b->desc->dispose };
        for (unsigned i = 0; i < 2; ++i) {
            unsigned long old = __atomic_load_n(slots[i], __ATOMIC_ACQUIRE);
            if (!in_text(old)) continue;
            make_writable(b->desc, sizeof *b->desc);
            unsigned long helper = __arm2x86_cb(old);
            __atomic_compare_exchange_n(slots[i], &old, helper, 0,
                                        __ATOMIC_RELEASE, __ATOMIC_ACQUIRE);
        }
    }
    return b0;
}

/* A copied __block C++ value has a second pair of callbacks, in the byref
 * header rather than the block descriptor. libclosure invokes these natively.
 * Bridge before native copy/release, retaining libclosure's forwarding and
 * reference-count implementation. The same entry points also cover indirect
 * imports; native-only blocks pass through without pointer changes. */
struct a2x_byref {
    void *isa;
    struct a2x_byref *forwarding;
    int32_t flags, size;
};
struct a2x_byref_helpers { unsigned long keep, destroy; };
static void a2x_prepare_byref(const void *object) {
    struct a2x_byref *b = (struct a2x_byref *)object;
    if (!b) return;
    b = b->forwarding;
    if (!b || !(b->flags & (1 << 25))) return;
    if (b->size < (int32_t)(sizeof *b + sizeof(struct a2x_byref_helpers)))
        die2("invalid byref helper header", NULL);
    struct a2x_byref_helpers *h = (void *)(b + 1);
    unsigned long *slots[] = { &h->keep, &h->destroy };
    for (int i = 0; i < 2; ++i) {
        unsigned long old = __atomic_load_n(slots[i], __ATOMIC_ACQUIRE);
        if (in_text(old)) {
            unsigned long native = __arm2x86_cb(old);
            __atomic_compare_exchange_n(slots[i], &old, native, 0,
                                       __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        }
    }
}
static pthread_once_t a2x_block_runtime_once = PTHREAD_ONCE_INIT;
static void (*a2x_real_assign)(void *, const void *, int);
static void (*a2x_real_dispose)(const void *, int);
static void *(*a2x_real_copy)(const void *);
static void (*a2x_real_release)(const void *);
static void a2x_resolve_block_runtime(void) {
    a2x_real_assign = dlsym(RTLD_NEXT, "_Block_object_assign");
    a2x_real_dispose = dlsym(RTLD_NEXT, "_Block_object_dispose");
    a2x_real_copy = dlsym(RTLD_NEXT, "_Block_copy");
    a2x_real_release = dlsym(RTLD_NEXT, "_Block_release");
    if (!a2x_real_assign || !a2x_real_dispose || !a2x_real_copy || !a2x_real_release)
        die2("native block runtime unavailable", NULL);
}
void *_Block_copy(const void *block) {
    pthread_once(&a2x_block_runtime_once, a2x_resolve_block_runtime);
    return a2x_real_copy(__arm2x86_blk((void *)block));
}
/* 10-17 A BLOCK THAT CROSSES AS AN OBJECT IS STILL A BLOCK. Measured (slice/objc1.m): ARC turns
      `void (^b)(int) = ^...` into objc_retainBlock, libobjc calls _Block_copy in libsystem_blocks directly, and a call
      between two system libraries never reaches the override above -- native code ran the arm64 copy helper
      (SIGBUS at ___copy_helper_block_e8_32r). So the wrap happens at OUR boundary: objc_retainBlock, and every '@'
      argument whose isa is one of the three block classes.
    isa is the test, never shape. Tagged pointers (low bit on x86) and small values are never dereferenced. */
extern void *_NSConcreteStackBlock[], *_NSConcreteMallocBlock[], *_NSConcreteGlobalBlock[];
const void *(*a2x_block_probe_view)(unsigned long);
#include "safe_block_probe.h"
static int a2x_is_block(uint64_t v) {
    uint64_t word;
    if (!a2x_read_block_isa(v, &word)) return 0;
    void *isa = (void *)(uintptr_t)word;
    return isa == (void *)_NSConcreteStackBlock || isa == (void *)_NSConcreteMallocBlock || isa == (void *)_NSConcreteGlobalBlock;
}
extern id objc_retainBlock(id);
id __arm2x86_objc_retainBlock(id b) { return objc_retainBlock((id)__arm2x86_blk((void *)b)); }
void _Block_release(const void *block) {
    pthread_once(&a2x_block_runtime_once, a2x_resolve_block_runtime);
    a2x_real_release(__arm2x86_blk((void *)block));
}
void _Block_object_assign(void *dest, const void *object, int flags) {
    pthread_once(&a2x_block_runtime_once, a2x_resolve_block_runtime);
    if ((flags & 15) == 8) a2x_prepare_byref(object);
    else if ((flags & 15) == 7) object = __arm2x86_blk((void *)object);
    a2x_real_assign(dest, object, flags);
}
void _Block_object_dispose(const void *object, int flags) {
    pthread_once(&a2x_block_runtime_once, a2x_resolve_block_runtime);
    if ((flags & 15) == 8) a2x_prepare_byref(object);
    a2x_real_dispose(object, flags);
}

/* rung 3b: translated code may hold an ARM class or metaclass ADDRESS (a class in the same image is referenced
   directly — adrp/add OBJC_CLASS_$_X — with no classref to patch). Every boundary into the native runtime maps it. */
unsigned long __arm2x86_mapcls(unsigned long a);
/* categories on Swift classes that are reached through an ObjC class stub (__objc_catlist2); defined beside add_methods */
static unsigned long gNSCopen;
static int a2x_stubcat_poll(id rcv);
/* 10-21 reverse of the twin map: which GUEST class address was this native twin built for, 0 if it is not
      one of ours. Diagnostics need identity by twin, not by name — two classes can share a name. Defined with
      the twin table far below. */
static unsigned long a2x_twin_guest_addr(Class c);
/* ---- the message send ------------------------------------------------------------------------------------------------------ */
/* rung 3c VARIADIC METHODS. A type encoding never marks a method variadic, and Apple arm64 puts every variadic argument
 *    on the STACK — so stringWithFormat: through the generic path passes nothing for its tail (measured: the l3c report
 *    printed "device 925 ... status 7"). Each variadic Foundation method goes to its va_list counterpart over a SysV
 *    va_list whose overflow area IS the arm64 stack (the printf bridge, R34); nil-terminated lists are read to the nil. */
#include <stdarg.h>
#include "vtail.h"
static void arm_va2(va_list ap) { ap[0].gp_offset = 48; ap[0].fp_offset = 176; ap[0].overflow_arg_area = (void *)__arm_sp; ap[0].reg_save_area = NULL; }
static id msg(id r, const char *s) { return ((id (*)(id, SEL))objc_msgSend)(r, sel_registerName(s)); }
/* 10-24 THE SELECTOR IS CHECKED BY POINTER, BEFORE ANYTHING ELSE. This function runs on every non-super
      send, and it used to map the receiver's class, call sel_getName and then walk up to 13 strcmp — all to
      recognise 13 variadic selectors that a game sends rarely. A send costs ~65 ns in total (ops/objcbench),
      so that was a large part of the bridge for nothing. Selectors are interned, so a pointer compare is not an
      approximation of the name compare: it is exact. Everything below is unchanged.
    The table is published with a release store AFTER it is filled, and read with an acquire load. Two threads
      racing both write the same interned pointers, but a reader must never see a half-filled table: a MISS here
      does not fall back, it sends the variadic selector down the fixed-argument path and loses its arguments. */
static const char *const A2X_VARSELS[] = {
    "stringWithFormat:", "initWithFormat:", "localizedStringWithFormat:", "stringByAppendingFormat:",
    "appendFormat:", "predicateWithFormat:", "raise:format:", "arrayWithObjects:", "setWithObjects:",
    "initWithObjects:", "orderedSetWithObjects:", "dictionaryWithObjectsAndKeys:", "initWithObjectsAndKeys:",
    "propertyMapWithPropertiesAndValues:",
    "logFromCodeLocation:subsystem:level:format:", "logCrashReporterMessageFromCodeLocation:format:",
};
#define A2X_NVARSEL ((int)(sizeof A2X_VARSELS / sizeof A2X_VARSELS[0]))
static SEL a2x_varsel[A2X_NVARSEL];
static int a2x_varsel_ready;

/* Keep the variadic constructor workspace out of every ordinary send frame.
 * Collection storage is sized to the supplied list instead of its maximum. */
__attribute__((noinline)) static int var_send(void) {
    if (!__atomic_load_n(&a2x_varsel_ready, __ATOMIC_ACQUIRE)) {
        for (int i = 0; i < A2X_NVARSEL; i++) a2x_varsel[i] = sel_registerName(A2X_VARSELS[i]);
        __atomic_store_n(&a2x_varsel_ready, 1, __ATOMIC_RELEASE);
    }
    { SEL s = (SEL)RX(1); int i = 0;
      while (i < A2X_NVARSEL && s != a2x_varsel[i]) i++;
      if (i == A2X_NVARSEL) return 0; }        /* the overwhelmingly common case: not a variadic selector */
    id self = (id)__arm2x86_mapcls(RX(0)); const char *sn = sel_getName((SEL)RX(1)); id r = nil; va_list ap;
    if (!self) return 0;
    /* A class-method selector sent to an INSTANCE is some other method that shares the name (Calendar sends an
       NSDate -localizedStringWithFormat:). Rebuilding it as +[NSString ...] sent `alloc` to the instance. */
    { int inst_sel = !strcmp(sn, "initWithFormat:") || !strcmp(sn, "stringByAppendingFormat:") || !strcmp(sn, "appendFormat:") ||
                     !strcmp(sn, "initWithObjects:") || !strcmp(sn, "initWithObjectsAndKeys:") ||
                     !strcmp(sn, "logFromCodeLocation:subsystem:level:format:");
      if (!inst_sel && !object_isClass(self)) return 0; }
    #define FMT_INIT(obj) ((id (*)(id, SEL, id, va_list))objc_msgSend)(obj, sel_registerName("initWithFormat:arguments:"), (id)RX(2), ap)
    if (!strcmp(sn, "stringWithFormat:")) { arm_va2(ap); r = msg(FMT_INIT(msg(self, "alloc")), "autorelease"); }
    else if (!strcmp(sn, "initWithFormat:")) { arm_va2(ap); r = FMT_INIT(self); }
    else if (!strcmp(sn, "localizedStringWithFormat:")) { arm_va2(ap);
        r = ((id (*)(id, SEL, id, id, va_list))objc_msgSend)(msg(self, "alloc"), sel_registerName("initWithFormat:locale:arguments:"),
                                                           (id)RX(2), msg((id)objc_getClass("NSLocale"), "currentLocale"), ap);
        r = msg(r, "autorelease"); }
    else if (!strcmp(sn, "stringByAppendingFormat:")) { arm_va2(ap); id t = FMT_INIT(msg((id)objc_getClass("NSString"), "alloc"));
        r = ((id (*)(id, SEL, id))objc_msgSend)(self, sel_registerName("stringByAppendingString:"), msg(t, "autorelease")); }
    else if (!strcmp(sn, "appendFormat:")) { arm_va2(ap); id t = FMT_INIT(msg((id)objc_getClass("NSString"), "alloc"));
        ((void (*)(id, SEL, id))objc_msgSend)(self, sel_registerName("appendString:"), msg(t, "autorelease")); }
    else if (!strcmp(sn, "predicateWithFormat:")) { arm_va2(ap);
        r = ((id (*)(id, SEL, id, va_list))objc_msgSend)(self, sel_registerName("predicateWithFormat:arguments:"), (id)RX(2), ap); }
    else if (!strcmp(sn, "raise:format:")) { arm_va2(ap);
        ((void (*)(id, SEL, id, id, va_list))objc_msgSend)(self, sel_registerName("raise:format:arguments:"), (id)RX(2), (id)RX(3), ap); }
    else if (!strcmp(sn, "logFromCodeLocation:subsystem:level:format:")) {
        /* The Photos logger. The code location is a structure of five pointers: the caller passes its address, the
           native method takes it by value. The format's arguments are on the caller's stack. */
        struct a2x_codeloc { char *a, *b, *c, *d; void *e; };
        SEL vs = sel_registerName("logFromCodeLocation:subsystem:level:format:arguments:");
        if (!RX(2) || !class_respondsToSelector(object_getClass(self), vs)) return 0;
        arm_va2(ap);
        ((void (*)(id, SEL, struct a2x_codeloc, id, int, id, va_list))objc_msgSend)(self, vs, *(struct a2x_codeloc *)RX(2),
                                                                                  (id)RX(3), (int)RX(4), (id)RX(5), ap); }
    else if (!strcmp(sn, "logCrashReporterMessageFromCodeLocation:format:")) {
        struct a2x_codeloc { char *a, *b, *c, *d; void *e; };
        SEL ms = sel_registerName("logCrashReporterMessage:fromCodeLocation:");
        if (!RX(2) || !class_respondsToSelector(object_getClass(self), ms)) return 0;
        arm_va2(ap);
        id t = ((id (*)(id, SEL, id, va_list))objc_msgSend)(msg((id)objc_getClass("NSString"), "alloc"),
                                                           sel_registerName("initWithFormat:arguments:"), (id)RX(3), ap);
        ((void (*)(id, SEL, id, struct a2x_codeloc))objc_msgSend)(self, ms, msg(t, "autorelease"), *(struct a2x_codeloc *)RX(2)); }
    else if (!strcmp(sn, "propertyMapWithPropertiesAndValues:")) {
        /* a property number first, then value and property in turn, ended by a zero property: the class's own
           constructor with an argument list does the reading */
        if (!class_respondsToSelector(object_getClass(msg(self, "alloc")), sel_registerName("initWithFirstKey:andArgumentList:"))) return 0;
        arm_va2(ap);
        r = ((id (*)(id, SEL, int, va_list))objc_msgSend)(msg(self, "alloc"), sel_registerName("initWithFirstKey:andArgumentList:"), (int)RX(2), ap);
        r = msg(r, "autorelease"); }
    else if (!strcmp(sn, "arrayWithObjects:") || !strcmp(sn, "setWithObjects:") || !strcmp(sn, "initWithObjects:") ||
             !strcmp(sn, "orderedSetWithObjects:")) {
        unsigned long n = 0; id first = (id)RX(2), o = first;
        unsigned long *st = (unsigned long *)__arm_sp;
        while (o && n < 4096) { n++; o = (id)st[n - 1]; }
        id *objs = (id *)__builtin_alloca((n ? n : 1) * sizeof *objs);
        if (n) objs[0] = first;
        for (unsigned long i = 1; i < n; i++) objs[i] = (id)st[i - 1];
        const char *cs = !strcmp(sn, "initWithObjects:") ? "initWithObjects:count:" :
                         !strcmp(sn, "setWithObjects:") ? "setWithObjects:count:" :
                         !strcmp(sn, "orderedSetWithObjects:") ? "orderedSetWithObjects:count:" : "arrayWithObjects:count:";
        r = ((id (*)(id, SEL, id *, unsigned long))objc_msgSend)(self, sel_registerName(cs), objs, n); }
    else if (!strcmp(sn, "dictionaryWithObjectsAndKeys:") || !strcmp(sn, "initWithObjectsAndKeys:")) {
        unsigned long n = 0; unsigned long *st = (unsigned long *)__arm_sp;
        id first = (id)RX(2), v = first;
        while (v && n < 2048) { n++; v = (id)st[2 * n - 1]; }
        id *vals = (id *)__builtin_alloca((n ? n : 1) * sizeof *vals);
        id *keys = (id *)__builtin_alloca((n ? n : 1) * sizeof *keys);
        for (unsigned long i = 0; i < n; i++) {
            vals[i] = i ? (id)st[2 * i - 1] : first;
            keys[i] = (id)st[2 * i];
        }
        r = ((id (*)(id, SEL, id *, id *, unsigned long))objc_msgSend)(self, sel_registerName(
                !strcmp(sn, "initWithObjectsAndKeys:") ? "initWithObjects:forKeys:count:" : "dictionaryWithObjects:forKeys:count:"),
                vals, keys, n); }
    else return 0;
    RX(0) = (uint64_t)r; return 1;
}

/* 10-28 A NATIVE VARIADIC METHOD OUTSIDE THE TABLE ABOVE GETS ITS TAIL. Apple arm64 left every variadic argument
      in 8-byte stack slots at __arm_sp; x86-64 SysV wants them in the integer registers after the fixed ones, then on
      the stack — which is exactly where a `...` call puts trailing arguments. Measured: revisiond's
      -[PQLConnection execute:@"... %@", x] reached -[PQLStatement translate:hasInjections:arguments:] with x3 = 0 and
      faulted at 0x18. Twelve slots are passed; a fixed-argument callee ignores them by the ABI.
    Integer-class only. A double in the tail (a %f) arrives in a stack slot here but x86 reads it from xmm — the same
      wrong value as before this change, never a new failure. Named, not fixed: no measured caller yet.
    The read is bounded by the mapped region that holds the arm stack, cached per thread, so a send from the very
      top of a thread's stack can never read off its end. */
static __thread uint64_t a2x_vt_lo, a2x_vt_hi;
static uint64_t a2x_vtail_call(void (*f)(void), const uint64_t *a, int na, uint64_t sp) {
    uint64_t t[12] = {0};
    if (sp < a2x_vt_lo || sp >= a2x_vt_hi) {
        uint64_t rm = a2x_region_room(sp);
        if (rm) { a2x_vt_lo = sp; a2x_vt_hi = sp + rm; } else { a2x_vt_lo = a2x_vt_hi = 0; }
    }
    uint64_t room = (sp >= a2x_vt_lo && sp < a2x_vt_hi) ? (a2x_vt_hi - sp) / 8 : 0;
    memcpy(t, (const void *)(uintptr_t)sp, (room < 12 ? room : 12) * 8);
    typedef uint64_t (*V)(uint64_t, uint64_t, ...);
    V g = (V)f;
#define A2X_T12 t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10], t[11]
    switch (na) {
    case 2: return g(a[0], a[1], A2X_T12);
    case 3: return g(a[0], a[1], a[2], A2X_T12);
    case 4: return g(a[0], a[1], a[2], a[3], A2X_T12);
    case 5: return g(a[0], a[1], a[2], a[3], a[4], A2X_T12);
    case 6: return g(a[0], a[1], a[2], a[3], a[4], a[5], A2X_T12);
    case 7: return g(a[0], a[1], a[2], a[3], a[4], a[5], a[6], A2X_T12);
    case 8: return g(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], A2X_T12);
    }
#undef A2X_T12
    return 0;
}

/* 10-03 BRING-UP ONLY, OPT-IN: ARM2X86_GPU_AS_M4=1 answers -[MTLDevice supportsFamily:] the way the M4 did for this
      game (captured: Apple1-9, Common1-3, Mac2, Metal3, Metal4 YES; Apple10 NO), inside THIS process only. Nothing system-wide,
      nothing in the driver: it lets the game pass its GPU checks so the M4 diff shows which Metal features it USES next.
      The driver claims a family only when those features are implemented and proven (the north-star rule). */
static int gpu_as_m4(SEL sel, uint64_t fam, uint64_t *out) {
    static int on = -1; static SEL sf;
    if (on < 0) { on = A2X_DBGENV("ARM2X86_GPU_AS_M4") != 0; sf = sel_registerName("supportsFamily:");
                  if (on) fprintf(a2x_errf(), "[xlat2]  GPU families answered AS THE M4 (ARM2X86_GPU_AS_M4, bring-up only)\n"); }
    if (!on || sel != sf) return 0;
    *out = (fam >= 1001 && fam <= 1009) || fam == 2001 || fam == 2002 || (fam >= 3001 && fam <= 3003) || fam == 5001 || fam == 5002;
    return 1;
}
/* 10-20 THE LAST MESSAGES SENT, so a runaway can be read off instead of guessed at. A translated ObjC method that
      re-enters itself through the bridge eats the stack and dies in whatever frame happened to be entering — the crash
      site names the victim, never the loop. (Chasing that cost a day: the repeating frames were msg_send, imp_handler
      and __arm2x86_call_rf, i.e. the bridge round-trip, which says a message recurses but not WHICH one.)
      A ring of the last 64 selectors costs two stores per message and names the cycle outright. */
/* 10-20 NAMING A RECEIVER'S CLASS CAN ITSELF CRASH. A diagnostic that called class_getName() on whatever the
      guest passed died inside objc_class::demangledName on fault address 0x3 — the receiver was a TAGGED pointer
      (arm64 marks tagged in bit 63, x86_64 in bit 0), so object_getClass() handed back something that is not a class.
      A diagnostic must never be the thing that kills the process: refuse to dereference anything that is not a plain,
      aligned, canonical pointer and say what it looks like instead. */
static const char *a2x_cname(Class c);   /* registry-checked name, defined below */
static const char *a2x_clsname(const void *p) {
    uintptr_t v = (uintptr_t)p;
    if (!v) return "(nil)";
    if (v & 1) return "(tagged: low bit, x86_64 form)";
    if (v >> 63) return "(tagged: high bit, arm64 form)";
    if (v & 7) return "(misaligned)";
    if (v < 0x1000) return "(not a pointer)";
    Class c = object_getClass((id)p);
    if (!c || ((uintptr_t)c & 7) || (uintptr_t)c < 0x1000) return "(no class)";
    return a2x_cname(c);
}
#define A2X_MSGRING 64
/* 10-24 POINTERS, not names: sel_getName + a2x_clsname + class_getName used to run on EVERY send to fill a
   ring that is only ever read at a crash (~65 ns a send in total, ops/objcbench). A SEL and a Class are permanent,
   so resolving them in the dump is both cheaper and safer than reading a receiver that may be gone by then. */
static struct { SEL sel; Class rcls; Class start; const void *rcv; int super; } g_msgring[A2X_MSGRING];
static unsigned g_msgring_n;
void a2x_dump_msgring(void) {
    unsigned n = g_msgring_n < A2X_MSGRING ? g_msgring_n : A2X_MSGRING;
    if (!n) { fprintf(a2x_errf(), "[xlat2]   no ObjC messages recorded\n"); return; }
    fprintf(a2x_errf(), "[xlat2]   last %u ObjC messages (newest first):\n", n);
    for (unsigned i = 0; i < n; i++) {
        unsigned k = (g_msgring_n - 1 - i) % A2X_MSGRING;
        /* the RECEIVER distinguishes one object recursing from a fresh object built on every pass (a once/
              singleton that never latches) — two very different bugs that produce an identical selector sequence. */
        /* a Class that was nil at send time falls back to reading the receiver, exactly as this line used to */
        const char *cname = g_msgring[k].rcls ? a2x_cname(g_msgring[k].rcls) : a2x_clsname(g_msgring[k].rcv);
        const char *sname = g_msgring[k].sel ? sel_getName(g_msgring[k].sel) : "?";
        const char *start = g_msgring[k].start ? a2x_cname(g_msgring[k].start) : 0;
        fprintf(a2x_errf(), "[xlat2]     %2u %s[%s %s]  receiver=%p%s%s\n", i, g_msgring[k].super ? "super " : "",
                cname ? cname : "?", sname, g_msgring[k].rcv,
                start ? "  lookup starts at " : "", start ? start : "");
    }
}
/* 10-05 was `send`: <curl/curl.h> brings <sys/socket.h>, whose send(2) conflicted */
/* 10-21 imp_handler's SRET VERDICT, CARRIED BACK TO msg_send. The 10-20 fix taught the NATIVE->GUEST
      direction that a struct return of <= 16 bytes can still be a memory return (a C++ class with a copy
      constructor or a destructor is returned in memory at any size, and the type encoding cannot tell us:
      {Trivial=^v} and {NonTrivial=^v} encode identically). The GUEST->NATIVE direction still wrote every
      <= 16-byte struct into x0/x1, so the arm64 caller's x8 buffer was never filled.
    MEASURED IN Finder: `-[TNodeViewSettings isAllMyFilesTarget]` does `add x8, sp, #8` and sends
      `node`; `-[TNodeViewSettings node]` is `add x1, x0, #0x20 / mov x0, x8 / b <copy ctor>`, i.e. an
      8-byte TNodeRef copy-constructed INTO x8. With the slot left unwritten, the next instruction
      (`ldr x0, [x0]` in the shared helper at 0x100014b90) read a stale stack word -- a
      Browser::TListBrowserSettings* -- and handed it to DesktopServicesPriv's _NodeGetCustomNode, which
      objc_msgSends it: SIGSEGV in objc_lookUpImpOrForward with the C++ vtable 0x100adb4f0 as the class.
    No new heuristic: imp_handler already ASKS the callee with a poisoned buffer. This only reports what it
      found, so the two directions cannot disagree. Nesting is safe because each imp_handler stores its verdict
      AFTER its own guest call returns and each msg_send reads it immediately after ffi_call. */
static __thread int a2x_sret_via_x8;
unsigned long __arm2x86_objc_imp_target(unsigned long t);
extern void __arm2x86_call_rf(unsigned long imp);

/* ==== THE PER-(CLASS, SELECTOR) CALL PLAN ==================================================================================
 *  10-24 MEASURED on Cyberpunk 2077, 1080p, ray tracing off (29.1 fps; `sample` of the game's busiest thread, 93%
 *    running): msg_send's own work was 12.1% of that thread and libffi another 13%, because EVERY send re-derived what
 *    depends only on the receiver's class and the selector — class_getInstanceMethod, method_getTypeEncoding, a copy of
 *    the encoding, the argument parse, and a full ffi_prep_cif (examine_argument and classify_argument were leaves in the
 *    profile). A plan is built once per (class, selector) and read without a lock.
 *  ONLY a non-super send whose Method was found is cached. forwardingTargetForSelector: and methodSignatureForSelector:
 *    answer PER CALL — caching a plan there would freeze one call's forwarding target for every later send.
 *  The IMP is NOT cached. The call still goes through objc_msgSend, so method_setImplementation, KVO and
 *    class_addMethod keep working; only the TYPE SIGNATURE is remembered, and that does not change for a (class, selector).
 *  Entries are never freed: a Class that is unloaded would leave a stale key, and objc class unloading does not happen
 *    in a translated process (no dlclose of an image whose classes we registered). */
#define A2X_PLANS 4096                 /* a power of two: the index is a mask of the hash */
#define A2X_PLAN_PROBE 8               /* linear probes before giving up and taking the uncached path */
struct a2x_plan {
    Class cls; SEL sel;
    char *types;                       /* owned copy: aenc[] points into it */
    ffi_type *rt; int na; int simple;
    int vtail;                         /* 10-28 the native IMP is variadic (vtail.h): pass the arm stack tail */
/* HOW MANY ARGUMENTS ONE OBJC SEND CAN CARRY.  WAS A BARE 24 IN NINE PLACES, and macOS 27 apps
      exceed it: Books aborts on -initWithItemType:identifier:... and Freeform on
      -initWithValueType:format:..., both "> 24 args", after their class graphs register cleanly.
    It stays a HARD REFUSAL rather than a truncation: silently dropping arguments past the limit
      would call a real method with garbage, which is worse than a named stop. The arrays below are
      all sized from this one constant so they can never disagree again. */
#define A2X_MAXARG 64

    ffi_type *at[A2X_MAXARG]; const char *aenc[A2X_MAXARG];
    /* per argument, for the simple path: its width in bytes, and WHICH transform the encoding asks for.
       Deriving these per call meant re-reading the encoding text on every send. */
    unsigned char abytes[A2X_MAXARG];
    unsigned char xform[A2X_MAXARG];           /* 0 none 1 '@?' block 2 '@' i<2 3 '@' i>=2 4 '#' i>=2 */
    ffi_cif cif;                       /* prepared on THIS plan's at[], which ffi keeps a pointer to */
};
static struct a2x_plan *g_plans[A2X_PLANS];
static pthread_mutex_t g_planm = PTHREAD_MUTEX_INITIALIZER;

static unsigned a2x_plan_hash(Class cls, SEL sel) {
    uint64_t h = (uint64_t)(uintptr_t)cls * 0x9E3779B97F4A7C15ULL ^ (uint64_t)(uintptr_t)sel * 0xC2B2AE3D27D4EB4FULL;
    return (unsigned)((h >> 32) ^ h);
}

static struct a2x_plan *a2x_plan_find(Class cls, SEL sel) {
    unsigned h = a2x_plan_hash(cls, sel);
    for (unsigned i = 0; i < A2X_PLAN_PROBE; i++) {
        struct a2x_plan *p = __atomic_load_n(&g_plans[(h + i) & (A2X_PLANS - 1)], __ATOMIC_ACQUIRE);
        if (!p) return 0;              /* an empty slot ends the probe: an insert never skips one */
        if (p->cls == cls && p->sel == sel) return p;
    }
    return 0;
}

/* The direct call below places every argument as one 8-byte general register or stack slot. A float, a double, an HFA
      or a struct needs libffi's own classification, and a struct return needs the _stret entry — none of those is simple. */
static int a2x_int_class(ffi_type *t) {
    switch (t->type) {
    case FFI_TYPE_INT: case FFI_TYPE_SINT8: case FFI_TYPE_UINT8: case FFI_TYPE_SINT16: case FFI_TYPE_UINT16:
    case FFI_TYPE_SINT32: case FFI_TYPE_UINT32: case FFI_TYPE_SINT64: case FFI_TYPE_UINT64: case FFI_TYPE_POINTER:
        return 1;
    default: return 0;
    }
}

/* 10-30 ONE classification for every plan, cached or direct: simple (integer-only), per-argument widths and
      transforms, and whether the native IMP is variadic. A direct IMP plan (a2x_record_native_imp) used to skip this
      and so never saw vtail: a guest that cached the IMP of -[IMLogger logFile:lineNumber:format:] called it through
      ffi with five fixed arguments, and the first tail slot (r9) held a stale host return address. */
static void a2x_plan_classify(struct a2x_plan *p, const void *imp) {
    p->simple = p->na <= 8 && (p->rt->type == FFI_TYPE_VOID || a2x_int_class(p->rt));
    for (int i = 0; i < p->na; i++) {
        size_t sz = p->at[i]->size;
        p->abytes[i] = (unsigned char)(sz > 8 ? 8 : (sz ? sz : 8));
        const char *e = p->aenc[i];
        /* the same order the generic marshalling loop uses, so neither can drift from the other */
        if (e[0] == '@' && e[1] == '?') p->xform[i] = 1;
        else if (e[0] == '@') p->xform[i] = (i >= 2) ? 3 : 2;
        else if (e[0] == '#' && i >= 2) p->xform[i] = 4;
        else p->xform[i] = 0;
        if (!a2x_int_class(p->at[i])) p->simple = 0;
        /* a va_list argument needs the arena: the generic path builds an x86 va_list at store[i]+16 */
        if (!strncmp(e, "[1{__va_list_tag", 16) || !strncmp(e, "^{__va_list_tag", 15)) p->simple = 0;
    }
    p->vtail = p->simple && a2x_imp_is_variadic(imp);
}

static struct a2x_plan *a2x_plan_add(Class cls, SEL sel, const char *types) {
    struct a2x_plan *p = (struct a2x_plan *)calloc(1, sizeof *p);
    if (!p) return 0;
    p->cls = cls; p->sel = sel;
    if (!(p->types = strdup(types))) { free(p); return 0; }
    const char *t = p->types;
    t = parse_type(t, &p->rt); while (*t >= '0' && *t <= '9') t++;
    while (*t) {
        if (p->na == 24) { free(p->types); free(p); return 0; }   /* refused here, reported by the uncached path */
        p->aenc[p->na] = skipq(t); t = parse_type(t, &p->at[p->na]);
        while (*t >= '0' && *t <= '9') t++; p->na++;
    }
    if (p->na < 2 || ffi_prep_cif(&p->cif, FFI_DEFAULT_ABI, (unsigned)p->na, p->rt, p->at) != FFI_OK) {
        free(p->types); free(p); return 0;
    }
    a2x_plan_classify(p, (const void *)class_getMethodImplementation(cls, sel));

    unsigned h = a2x_plan_hash(cls, sel);
    pthread_mutex_lock(&g_planm);
    for (unsigned i = 0; i < A2X_PLAN_PROBE; i++) {
        struct a2x_plan **slot = &g_plans[(h + i) & (A2X_PLANS - 1)];
        if (*slot) {
            if ((*slot)->cls == cls && (*slot)->sel == sel) {     /* another thread built it first: use theirs */
                struct a2x_plan *won = *slot;
                pthread_mutex_unlock(&g_planm);
                free(p->types); free(p);
                return won;
            }
            continue;
        }
        __atomic_store_n(slot, p, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&g_planm);
        return p;
    }
    pthread_mutex_unlock(&g_planm);    /* the probe window is full: this selector stays on the uncached path */
    free(p->types); free(p);
    return 0;
}

static int is_arm(unsigned long a);
/* a class name that cannot fault: a raw guest class (an object allocated without going through the twin map keeps the
   guest isa) has an arm64 class_ro_t that x86 libobjc misreads (App Store, name pointer 0x228000000 in demangledName) */
/* 10-30 b32h still died here: rcls was neither tagged nor an arm64 address, yet class_getName faulted in demangledName
   (name pointer 0x228000000, an arm64-layout class_ro_t read by x86 libobjc). The only test that never dereferences the
   suspect is membership in the registered class list. Diagnostic paths only: it is O(classes). */
static int a2x_cls_registered(Class c) {
    unsigned n = 0; int found = 0;
    Class *all = objc_copyClassList(&n);
    for (unsigned i = 0; all && i < n; i++) if (all[i] == c) { found = 1; break; }
    free(all);
    return found;
}
static const char *a2x_cname(Class c) {
    static __thread char raw[96];
    if (!c) return "(nil)";
    if (((uintptr_t)c & 7) || is_arm((unsigned long)c)) return "(unmapped guest class)";
    if (a2x_cls_registered(c)) return class_getName(c);
    snprintf(raw, sizeof raw, "(not a registered class: %p)", (void *)c);
    return raw;
}
/* the first words of a suspect object or class, readable-checked, so the next run says what it was */
static void a2x_dump_words(const char *tag, const void *p) {
    uintptr_t v = (uintptr_t)p; char r = 0;
    if (v < 0x1000 || (v & 7) || mincore((void *)(v & ~(uintptr_t)0xFFF), 0x1000, &r) != 0 ||
        mincore((void *)((v + 40) & ~(uintptr_t)0xFFF), 0x1000, &r) != 0) {
        fprintf(a2x_errf(), "  %s %p unreadable\n", tag, p); return; }
    const unsigned long *w = (const unsigned long *)p;
    fprintf(a2x_errf(), "  %s %p words %#lx %#lx %#lx %#lx %#lx %#lx\n", tag, p, w[0], w[1], w[2], w[3], w[4], w[5]);
}
/* next link of a chain, only through a registered class */
static Class a2x_super_of(Class k) { return a2x_cls_registered(k) ? class_getSuperclass(k) : Nil; }
static void msg_send(int super, struct a2x_plan *direct_plan, unsigned long direct_target) {
    uint64_t x0 = RX(0); SEL sel = (SEL)RX(1); struct objc_super sup_copy;
    Class cls = Nil; Method m = NULL; struct a2x_plan *pl = direct_plan;
    if (!direct_plan) {
    { uint64_t r_; if (!super && RX(0) && gpu_as_m4((SEL)RX(1), RX(2), &r_)) { RX(0) = r_; return; } }
    if (!super && var_send()) return;
    if (!x0) { RX(0) = 0; RX(1) = 0; memset(RV(0), 0, 64); return; }     /* message to nil: zeros, as objc_msgSend does */
    if (super) { struct objc_super *sp = (struct objc_super *)x0;
                 sup_copy.receiver = (id)__arm2x86_mapcls((unsigned long)sp->receiver);
                 sup_copy.super_class = (Class)__arm2x86_mapcls((unsigned long)sp->super_class);
                 RX(0) = (uint64_t)&sup_copy;
                 /* 10-20 a NIL super_class is not dispatchable: libobjc would restart the lookup at the receiver and
                       find the very method that sent `super`, which is an unbounded recursion that ends as a stack
                       overflow in whatever frame happens to be next (Dock's SystemAppearanceMonitor init). It is also
                       what crashed objc_lookUpImpOrForward here, because class_getInstanceMethod(nil, …) faults.
                       Name it and stop — a wrong answer that burns 60 MB of stack is worse than a clear death. */
                 if (!sup_copy.super_class) die2("super send with a NULL super_class (its __objc_superrefs slot was "
                                                 "never filled) — super would restart at the receiver", sel_getName(sel));
                 cls = class_getSuperclass(sup_copy.super_class);
                 /* 10-20 a class that is ITS OWN superclass makes `super` an infinite loop. Name it once: this is
                       cheap and the failure it catches costs the whole stack and names the wrong function. */
                 /* 10-20 ROOT CAUSE, MEASURED: a Swift `super.init` does NOT read __objc_superrefs. It calls
                       swift_getObjectType(self) and puts the RESULT in objc_super.super_class (arm64:
                       `bl _swift_getObjectType; mov x19,x0; ... stp x20,x19,[sp]; bl _objc_msgSendSuper2`).
                       swift_getObjectType returns real Swift metadata only when the class carries the "is Swift
                       stable" bit in class->bits; objc_allocateClassPair() — which is how this bridge registers every
                       guest class — CANNOT set it. So the Swift runtime falls through to swift_getObjCClassMetadata
                       and hands back an **ObjCClassWrapper** record {kind=0x305, Class} carved out of libswiftCore's
                       static arena `_ZL21InitialAllocationPool`. Measured on the target: two such classes 0x20 apart
                       (0x7ff84383e758 / 0x7ff84383e778), wrapper[1] == the class, and
                       class_getSuperclass(wrapper) reads word 1 and returns THE CLASS ITSELF — so objc_msgSendSuper2
                       restarts the lookup on the sending class, finds its own init, and recurses until the stack is
                       gone. class_getName(wrapper) reads wrapper+32, i.e. arena garbage: the fault at 0x3 inside
                       objc_class::demangledName.
                     Unwrap it: an ObjCClassWrapper is {MetadataKind kind; Class cls}, kind 0x305. Taking word 1 gives
                       the class Swift meant, which is exactly what Super2 needs. This is the precise fix; the
                       reachability check below stays as a backstop for anything else that is not a class. */
                 if (sup_copy.super_class) {
                     const uintptr_t *w = (const uintptr_t *)sup_copy.super_class;
                     if (!((uintptr_t)w & 7) && w[0] == 0x305 && w[1] && !(w[1] & 7)) {
                         static int said;
                         if (said < 4) { said++;
                             fprintf(a2x_errf(), "objc_bridge: [super %s]: super_class %p is a Swift ObjCClassWrapper "
                                     "(objc_allocateClassPair cannot carry Swift metadata) — unwrapping to the class %p\n",
                                     sel_getName(sel), (void *)w, (void *)w[1]); }
                         sup_copy.super_class = (Class)w[1];
                         cls = class_getSuperclass(sup_copy.super_class);
                         m = cls ? class_getInstanceMethod(cls, sel) : 0;
                     }
                 }
                 /* 10-20 THE __objc_superrefs SLOT CANNOT BE TRUSTED, AND A BAD ONE IS AN INFINITE LOOP.
                       Measured on Dock: the slot for `[super init]` in DockCore.SystemAppearanceMonitor held
                       0x7ff84383e758 = libswiftCore's `_ZL21InitialAllocationPool+0x2360` — not a class at all.
                       objc_msgSendSuper2 starts at class_getSuperclass(super_class), so from that value it landed back
                       on the class's OWN init: init -> NSUserDefaults -> init -> ... until 60 MB of stack was gone, and
                       the crash then named whatever frame happened to be entering. class_getName() on it faults too.
                     Validate it: a real class answers class_getName() with a readable name and is reachable from the
                       receiver's own chain. When it is not, start from the receiver's class's superclass, which is the
                       right answer whenever the sending method belongs to the receiver's class — the common case — and
                       is always better than looping. Say so every time; this is a bind defect, not something to absorb. */
                 {
                     Class rcls = sup_copy.receiver ? object_getClass((id)sup_copy.receiver) : Nil;
                     /* 10-30 the receiver isa can be the raw GUEST class; its twin is what the chain walk, the
                        reachability test and every name below must see */
                     if (rcls) rcls = (Class)__arm2x86_mapcls((unsigned long)rcls);
                     /* reachability is the test that needs no dereference of the suspect value: a legitimate Super2
                        super_class is always the receiver's class or one of its ancestors. */
                     /* 10-21 COMPARE BY TWIN IDENTITY, NOT BY POINTER — ONE GUEST CLASS HAS TWO
                          REPRESENTATIONS. Measured in pkd: the superrefs slot was RIGHT (the PKDServer twin
                          0x6000019e8d20, twin_of_guest=0x200033a88) while the RECEIVER's isa was the raw GUEST
                          class 0x200033a88, never mapped — the class of objects allocated through a path that
                          does not go through __arm2x86_mapcls ([[project_arm2x86_objc_alloc_guest_isa_1021]]).
                          A pointer comparison between a twin and a guest chain can never match, so a correct
                          slot was rejected on every super send and the fallback ran instead. Reducing both
                          sides to the GUEST address makes the two representations compare equal. */
                     int bad = !cls, reachable = 0;
                     unsigned long sg = a2x_twin_guest_addr(sup_copy.super_class);
                     if (!sg) sg = (unsigned long)sup_copy.super_class;
                     for (Class k = rcls; k; k = class_getSuperclass(k)) {
                         unsigned long kg = a2x_twin_guest_addr(k);
                         if (!kg) kg = (unsigned long)k;
                         if (k == sup_copy.super_class || kg == sg) { reachable = 1; break; }
                     }
                     if (!reachable) bad = 1;
                     if (bad || cls == rcls) {
                         static int said;
                         if (said < 8) { said++;
                             fprintf(a2x_errf(), "objc_bridge: [super %s]: the __objc_superrefs slot holds %p, which is not "
                                     "this receiver's superclass — starting from %s's superclass instead\n",
                                     sel_getName(sel), (void *)sup_copy.super_class, a2x_cname(rcls));
                             a2x_dump_words("receiver", (void *)sup_copy.receiver);
                             a2x_dump_words("rcls    ", (void *)rcls);
                             /* 10-21 WHAT IS ACTUALLY IN THAT SLOT. Measured from the arm64 image: PKDServer is
                                  instanceStart 8 / instanceSize 64 while PKDatabase is instanceSize 88, so PKDServer
                                  CANNOT be a PKDatabase subclass — yet this fallback resolved its `super` to
                                  PKDatabase. Either a twin was built with the wrong superclass, or two twins exist
                                  for one guest class. Running the wrong class's init lays ivars out at the wrong
                                  offsets, which is the measured deterministic fault (objc_release on a pointer read
                                  out of the middle of a "com.apple…" string, same address across two builds).
                                  Identity is printed by TWIN as well as by name, because two classes can share a
                                  name and still be different objects. */
                             Class sl = sup_copy.super_class;
                             const char *sn = a2x_cname(sl);
                             fprintf(a2x_errf(),
                                     "  slot      %p name=%-26s size=%-5lu byname=%p %s twin_of_guest=0x%lx\n",
                                     (void *)sl, sn, (sl && a2x_cls_registered(sl)) ? (unsigned long)class_getInstanceSize(sl) : 0UL,
                                     (void *)(a2x_cls_registered(sl) ? objc_getClass(sn) : Nil),
                                     (sl && a2x_cls_registered(sl) && objc_getClass(sn) == sl) ? "(SAME)" : "(DIFFERENT!)",
                                     sl ? a2x_twin_guest_addr(sl) : 0UL);
                             fprintf(a2x_errf(), "  receiver  %p class=%p %s\n",
                                     (void *)sup_copy.receiver, (void *)rcls, a2x_cname(rcls));
                             for (Class k = rcls; k; k = a2x_super_of(k))
                                 fprintf(a2x_errf(), "    chain   %p %-26s size=%-5lu twin_of_guest=0x%lx%s\n",
                                         (void *)k, a2x_cname(k), (unsigned long)(a2x_cls_registered(k) ? class_getInstanceSize(k) : 0),
                                         a2x_twin_guest_addr(k), k == sl ? "   <== THE SLOT" : "");
                         }
                         /* 10-21 DO NOT GUESS WHEN THE SLOT IS A LEGITIMATE TWIN. Substituting the
                              RECEIVER's class is wrong whenever the receiver is a subclass of the class whose
                              method is executing: `[super init]` must start at the SENDING class's superclass,
                              and starting at the receiver's instead runs a different class's init, which lays
                              ivars out at different offsets. The fallback exists only for a slot that is not a
                              class at all (the Dock's libswiftCore garbage, 10-20) — so it is now limited to
                              that case and says so, instead of silently papering over a correct slot. */
                         if (a2x_twin_guest_addr(sup_copy.super_class)) {
                             fprintf(a2x_errf(), "  -> KEEPING the slot: it is our twin of guest class 0x%lx, so the "
                                     "reachability miss is a representation mismatch, not a bad slot\n",
                                     a2x_twin_guest_addr(sup_copy.super_class));
                         } else if (rcls) {
                             fprintf(a2x_errf(), "  -> the slot is NOT a known class; falling back to %s's superclass %s. "
                                     " If this receiver is a SUBCLASS of the sending class this runs the WRONG init.\n",
                                     a2x_cname(rcls),
                                     a2x_super_of(rcls) ? a2x_cname(a2x_super_of(rcls)) : "(nil)");
                             sup_copy.super_class = rcls; cls = class_getSuperclass(rcls);
                             m = cls ? class_getInstanceMethod(cls, sel) : 0;
                         }
                     }
                 }
                 if (cls == sup_copy.super_class) {
                     static int said;
                     if (!said++) fprintf(a2x_errf(), "objc_bridge: %s is its OWN superclass — every `super` send on it "
                                          "recurses forever (first seen on %s)\n",
                                          a2x_cname(sup_copy.super_class), sel_getName(sel));
                 }

                 m = cls ? class_getInstanceMethod(cls, sel) : 0; }
    else { x0 = __arm2x86_mapcls(x0); RX(0) = x0; cls = object_getClass((id)x0);
           /* an instance whose isa is the raw GUEST class (VoiceMemos: "(unmapped guest class)") has no Method on that
              arm64-layout record; look the selector up on its twin / realized class, as the super path does above */
           if (is_arm((unsigned long)cls)) cls = (Class)__arm2x86_mapcls((unsigned long)cls);
           { static SEL sdec, senc; static Class ca, cu; static int init;
             if (!init) { sdec = sel_registerName("decodeValueOfObjCType:at:"); senc = sel_registerName("encodeValueOfObjCType:at:");
                          ca = objc_getClass("NSArchiver"); cu = objc_getClass("NSUnarchiver"); init = 1; }
             /* A typedstream (NSArchiver/NSUnarchiver) names a BOOL 'c'. arm64 @encode(BOOL) is 'B'; arm64 Foundation
                accepts the two as one, x86 Foundation does not ("read 'c', expecting 'B'"). Both are one byte. */
             if ((sel == sdec || sel == senc) && RX(2) > 4096) {
                 const char *ty = (const char *)RX(2);
                 if (ty[0] == 'B' && ty[1] == 0) {
                     for (Class k = cls; k; k = class_getSuperclass(k))
                         if (k == ca || k == cu) { static const char c_ty[] = "c"; RX(2) = (uint64_t)c_ty; break; } } } }
           /* a plan hit skips the Method lookup, the encoding copy AND the parse below */
           pl = a2x_plan_find(cls, sel); m = pl ? 0 : class_getInstanceMethod(cls, sel); }
    /* A category in __objc_catlist2 waits until its Swift class exists. The first send that is not served by a plan
       checks the receiver's class chain once; when a category was attached just now, the lookup is repeated. */
    if (gNSCopen && !pl) {
        id rcv_s = super ? sup_copy.receiver : (id)x0;
        if (rcv_s && a2x_stubcat_poll(rcv_s) && !m && cls) m = class_getInstanceMethod(cls, sel);
    }
    } /* direct calls already carry the saved authoritative type plan */
    /* 10-24 ONE thread-local resolve for the whole send. RX() and RV() each expand to __arm2x86_rf, and on
       Darwin every textual use of a __thread variable is a call to _tlv_get_addr — 4.7% of the game's busiest
       thread, because the marshalling loop below touches a register per argument and clang cannot hoist the
       resolve across the calls inside that loop. The macros are restored right after this function. */
    uint64_t *const a2x_rfx = (uint64_t *)__arm2x86_rf;
    unsigned char *const a2x_rfv = __arm2x86_rf + 80;
#undef RX
#undef RV
#define RX(i) (a2x_rfx[i])
#define RV(j) (a2x_rfv + 16 * (j))
    /* 10-21 WAS `char types[512]` and a die2 past it: the macOS 27 Dock aborted
          "method encoding exceeds bridge capacity dragEnter:" on the first click of a tile (a drag-capable mouse-down),
          crash-looping the Dock. Encodings that embed structs by value run past 512 bytes. Sized per call with alloca,
          like the argument arena below: no cap, and a nested send through a callback gets its own buffer. */
    /* the signature: a plan carries it, otherwise it is derived here and a plan is built from it */
    ffi_type *rt = 0; int na = 0; ffi_type *const *at = 0; const char *const *aenc = 0; ffi_cif *cif = 0;
    const char *sig = 0;               /* the encoding, for the diagnostics after this block */
    ffi_type *at_l[A2X_MAXARG]; const char *aenc_l[A2X_MAXARG]; ffi_cif cif_l;
    if (!pl) {
    char tbuf[512]; char *types = tbuf; size_t tcap = sizeof tbuf; types[0] = 0;
    if (m) {
        const char *te = method_getTypeEncoding(m);
        if (te) {
            size_t tl = strlen(te);
            if (tl >= tcap) { tcap = tl + 1; types = (char *)__builtin_alloca(tcap); }
            memcpy(types, te, tl + 1);
        }
    }
    /* 10-21 Finder crash-looped "no method / type encoding for selector validateNewFinderWindow:": its
          TApplicationController answers respondsToSelector: YES for window selectors and hands them on through
          forwardingTargetForSelector: (to TGlobalWindowController), so the receiver has no Method AND no
          methodSignatureForSelector: answer. That is the runtime's FIRST forwarding step, and it runs before the
          NSMethodSignature path below: take the encoding from the target's own Method. The call still goes through
          objc_msgSend on the original receiver, so the runtime forwards it itself exactly as it would natively. */
    /* A super send that finds no method in the superclass chain enters the same forwarding path in libobjc, and that
       path asks the receiver (forwardingTargetForSelector:, then methodSignatureForSelector:), not the superclass.
       Maps: -[IOSBasedChromeViewController mapView:didFailToLocateUserWithError:] calls super, ChromeViewController
       has no such method and implements forwardInvocation: instead. The encoding is taken from the receiver here and
       the call below still goes through objc_msgSendSuper2, so libobjc starts at the lexical superclass and forwards. */
    id a2x_frcv = super ? sup_copy.receiver : (id)x0;
    if (!types[0] && a2x_frcv) {
        /* Finder stopped on every window open with no encoding for validateToolbarEditTags:. In the real Finder the
           window controller forwards to the container controller, which forwards again to the view controller, the
           class that implements it. The runtime follows that chain one objc_msgSend at a time; one step here found no
           Method on the middle object and gave up. Walk the chain (bounded, and it ends on a target that repeats) and
           take the encoding from the first Method found. */
        id a2x_fcur = a2x_frcv;
        for (int a2x_fdepth = 0; a2x_fdepth < 8 && !types[0]; ++a2x_fdepth) {
            id tgt = ((id (*)(id, SEL, SEL))objc_msgSend)(a2x_fcur, sel_registerName("forwardingTargetForSelector:"), sel);
            if (!tgt || tgt == a2x_fcur || tgt == a2x_frcv) break;
            Method fm = class_getInstanceMethod(object_getClass(tgt), sel);
            const char *te = fm ? method_getTypeEncoding(fm) : 0;
            if (te) {
                size_t tl = strlen(te);
                if (tl >= tcap) { tcap = tl + 1; types = (char *)__builtin_alloca(tcap); }
                memcpy(types, te, tl + 1);
            }
            a2x_fcur = tgt;
        }
    }
    /* Forwarded messages have no Method on the receiver. Ask the receiver for
     * its authoritative NSMethodSignature, as native forwarding does, then
     * call objc_msgSend normally so its forwarding/NSInvocation path runs.
     * A super send must retain its lexical superclass lookup. */
    if (!types[0] && a2x_frcv) {
        id signature = ((id (*)(id, SEL, SEL))objc_msgSend)(
            a2x_frcv, sel_registerName("methodSignatureForSelector:"), sel);
        if (signature) {
            const char *ret_type = ((const char *(*)(id, SEL))objc_msgSend)(
                signature, sel_registerName("methodReturnType"));
            unsigned long count = ((unsigned long (*)(id, SEL))objc_msgSend)(
                signature, sel_registerName("numberOfArguments"));
            if (count > A2X_MAXARG) die2("too many arguments for the bridge", sel_getName(sel));
            if (!ret_type) die2("invalid forwarded return encoding", sel_getName(sel));
            /* measure first, then size the buffer: the same no-cap rule as the Method path above */
            size_t need = strlen(ret_type) + 1;
            for (unsigned long i = 0; i < count; ++i) {
                const char *arg_type = ((const char *(*)(id, SEL, unsigned long))objc_msgSend)(
                    signature, sel_registerName("getArgumentTypeAtIndex:"), i);
                if (!arg_type) die2("invalid forwarded argument encoding", sel_getName(sel));
                need += strlen(arg_type);
            }
            if (need > tcap) { tcap = need; types = (char *)__builtin_alloca(tcap); }
            strcpy(types, ret_type);
            size_t used = strlen(types);
            for (unsigned long i = 0; i < count; ++i) {
                const char *arg_type = ((const char *(*)(id, SEL, unsigned long))objc_msgSend)(
                    signature, sel_registerName("getArgumentTypeAtIndex:"), i);
                size_t al = strlen(arg_type);
                if (al >= tcap - used) die2("forwarded encoding changed while it was copied", sel_getName(sel));
                memcpy(types + used, arg_type, al + 1);
                used += al;
            }
        }
    }
    if (!types[0]) {
        /* 10-27 SAY WHO WAS ASKED. A guest class whose method list never registered is
              indistinguishable from a native class that genuinely does not implement the selector
              unless the receiver, its metaclass bit and its twin mapping are printed. */
        id rcv_d = super ? sup_copy.receiver : (id)x0;
        Class rc = rcv_d ? object_getClass(rcv_d) : (Class)0;
        fprintf(a2x_errf(),
                "[objc] NO ENCODING %s: receiver=%p class=%s meta=%d guestTwin=0x%lx respondsTo=%d "
                "inst=%p cls=%p nameOfPtr=%s\n",
                sel_getName(sel), (void *)rcv_d, a2x_cname(rc),
                (rc && a2x_cls_registered(rc)) ? (int)class_isMetaClass(rc) : -1, rc ? a2x_twin_guest_addr(rc) : 0UL,
                (rcv_d && rc && a2x_cls_registered(rc)) ? (int)((BOOL (*)(id, SEL, SEL))objc_msgSend)(rcv_d, sel_registerName("respondsToSelector:"), sel) : -1,
                (void *)((rc && a2x_cls_registered(rc)) ? class_getInstanceMethod(rc, sel) : 0),
                (void *)((rc && a2x_cls_registered(rc)) ? class_getClassMethod(rc, sel) : 0),
                (rc && a2x_cls_registered(rc)) ? (a2x_clsname((const void *)rcv_d) ? a2x_clsname((const void *)rcv_d) : "?")
                                               : "(receiver has no registered class)");
        /* The runtime's own last step for a selector nobody implements and nobody gives a signature for is
           -doesNotRecognizeSelector:, which raises NSInvalidArgumentException. The exception unwinds through this
           frame like one raised by any native method, so a caller that catches it keeps running. */
        if (rcv_d && rc && a2x_cls_registered(rc))
            ((void (*)(id, SEL, SEL))objc_msgSend)(rcv_d, sel_registerName("doesNotRecognizeSelector:"), sel);
        a2x_stop_objc(sel_getName(sel), (rc && a2x_cls_registered(rc)) ? class_getName(rc) : "?");
        die2("no method / type encoding for selector", sel_getName(sel));
    }
    /* the encoding is "<ret><frame>@0:8<arg>16..." — offsets are interleaved digits; skip them */
    const char *t = types; t = parse_type(t, &rt); while (*t >= '0' && *t <= '9') t++;
    while (*t) { if (na == A2X_MAXARG) die2("too many arguments for the bridge", sel_getName(sel)); aenc_l[na] = skipq(t); t = parse_type(t, &at_l[na]);
                 while (*t >= '0' && *t <= '9') t++; na++; }
    if (na < 2) die2("encoding has no self/_cmd", types);
    sig = types;
    if (m && !super) pl = a2x_plan_add(cls, sel, types);   /* every later send of this selector reads the plan */
    if (!pl) {
        if (ffi_prep_cif(&cif_l, FFI_DEFAULT_ABI, (unsigned)na, rt, at_l) != FFI_OK) die2("ffi_prep_cif refused", types);
        at = at_l; aenc = aenc_l; cif = &cif_l;
    }
    }
    if (pl) { rt = pl->rt; na = pl->na; at = pl->at; aenc = pl->aenc; cif = &pl->cif; sig = pl->types; }

    /* 10-24 AN INTEGER-ONLY SEND NEVER BUILDS THE ARGUMENT ARENA. Every argument is one 64-bit general
       register or stack slot and the return is void or an integer/pointer, all of which the plan already
       decided — so the size loop, the alloca, the memset, the store[]/av[] pass, the per-argument type
       branching and the return buffer below are all skipped. Measured on the shapes a Metal setter uses
       (ops/objcbench): this is the last large piece of the bridge's own cost.
        The generic path's semantics are reproduced exactly, not approximated — see the notes on each step. */
    if (pl && pl->simple) {
        uint64_t a[8] = {0};
        int ngrn = 0; unsigned long nsaa = __arm_sp;
        for (int i = 0; i < na; i++) {
            size_t sz = pl->abytes[i];
            uint64_t v;
            if (ngrn < 8) v = RX(ngrn++);
            else {   /* aligned to the argument's own size, as the generic path aligns nsaa */
                nsaa = (nsaa + sz - 1) & ~(unsigned long)(sz - 1);
                v = 0; memcpy(&v, (void *)nsaa, sz); nsaa += sz;
            }
            /* narrower than a register arrives ZERO-EXTENDED: the generic path copied sz bytes into a
                  zeroed slot and the callee read a whole register back out of it. */
            if (sz < 8) v &= (1ULL << (sz * 8)) - 1ULL;
            switch (pl->xform[i]) {
            case 1: v = (uint64_t)__arm2x86_blk((void *)v); break;                 /* a block native will call */
            case 2: if (a2x_is_block(v)) v = (uint64_t)__arm2x86_blk((void *)v); break;
            case 3: if (a2x_is_block(v)) v = (uint64_t)__arm2x86_blk((void *)v);   /* [blk copy] in a collection */
                    else v = __arm2x86_mapcls(v); break;
            case 4: v = __arm2x86_mapcls(v); break;
            default: break;
            }
            a[i] = v;
        }
        /* no stret here: a simple plan's return is void or an integer/pointer by construction */
        void (*sfn)(void) = direct_target ? (void (*)(void))direct_target : super ? (void (*)(void))objc_msgSendSuper2 : (void (*)(void))objc_msgSend;
        uint64_t r;
        if (pl->vtail) r = a2x_vtail_call(sfn, a, na, __arm_sp);
        else switch (na) {
        case 2: r = ((uint64_t (*)(uint64_t, uint64_t, ...))sfn)(a[0], a[1]); break;
        case 3: r = ((uint64_t (*)(uint64_t, uint64_t, uint64_t, ...))sfn)(a[0], a[1], a[2]); break;
        case 4: r = ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, ...))sfn)(a[0], a[1], a[2], a[3]); break;
        case 5: r = ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, ...))sfn)
                        (a[0], a[1], a[2], a[3], a[4]); break;
        case 6: r = ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, ...))sfn)
                        (a[0], a[1], a[2], a[3], a[4], a[5]); break;
        case 7: r = ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, ...))sfn)
                        (a[0], a[1], a[2], a[3], a[4], a[5], a[6]); break;
        case 8: r = ((uint64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                   uint64_t, ...))sfn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]); break;
        default: r = 0; die2("a simple plan with an impossible argument count", sel_getName(sel));
        }
        if (rt->type == FFI_TYPE_VOID) return;
        /* the same widths the generic switch reads out of ffi's ffi_arg buffer, read out of a register */
        uint64_t rv = 0;
        switch (rt->type) {
        case FFI_TYPE_SINT8:  rv = (uint64_t)(int64_t)(int8_t)r; break;   case FFI_TYPE_UINT8:  rv = (uint8_t)r; break;
        case FFI_TYPE_SINT16: rv = (uint64_t)(int64_t)(int16_t)r; break;  case FFI_TYPE_UINT16: rv = (uint16_t)r; break;
        case FFI_TYPE_SINT32: rv = (uint64_t)(int64_t)(int32_t)r; break;  case FFI_TYPE_UINT32: rv = (uint32_t)r; break;
        default: rv = r;
        }
        RX(0) = rv;
        return;
    }
    /* arguments, taken from where AAPCS64 (Apple) put them.
        10-20 WAS `store[24][64]` and `ret[64]`: avmediainfo died `return larger than 64 bytes` on a 96-byte pair of
          CMTimeRanges. Each argument gets its own 16-aligned slot of its real size (>= 8: ffi reads a full register) in one
          per-call alloca, plus 32 bytes for a rebuilt va_list; a total over 64 KiB is refused by name, never truncated. */
    size_t need = 0;
    for (int i = 0; i < na; i++) need += ((at[i]->size < 8 ? 8 : at[i]->size) + 15 + 32) & ~15UL;
    if (need > 65536) die2("arguments larger than 64 KiB in total", sig);
    unsigned char *arena = (unsigned char *)(((uintptr_t)__builtin_alloca(need + 15) + 15) & ~(uintptr_t)15);
    memset(arena, 0, need);
    unsigned char *store[A2X_MAXARG]; void *av[A2X_MAXARG];
    { size_t o = 0; for (int i = 0; i < na; i++) { store[i] = arena + o; o += ((at[i]->size < 8 ? 8 : at[i]->size) + 15 + 32) & ~15UL; } }
    int ngrn = 0, nsrn = 0; unsigned long nsaa = __arm_sp;
    for (int i = 0; i < na; i++) {
        ffi_type *ty = at[i]; size_t sz = ty->size, al = ty->alignment ? ty->alignment : 1;
        av[i] = store[i];
        int isd = -1, nh = (ty->type == FFI_TYPE_STRUCT) ? hfa4(ty, &isd) : 0;
        if (ty->type == FFI_TYPE_FLOAT || ty->type == FFI_TYPE_DOUBLE) {
            if (nsrn < 8) memcpy(store[i], RV(nsrn++), sz);
            else { nsaa = (nsaa + sz - 1) & ~(sz - 1); memcpy(store[i], (void *)nsaa, sz); nsaa += sz; }
        } else if (nh >= 1 && nh <= 4) {
            unsigned char *leaf[4]; size_t off = 0; int k = 0; hfa_leaves(ty, store[i], &off, leaf, &k);
            size_t ls = isd ? 8 : 4;
            if (nsrn + nh <= 8) for (int j = 0; j < nh; j++) memcpy(leaf[j], RV(nsrn++), ls);
            else { nsrn = 8; nsaa = (nsaa + al - 1) & ~(al - 1); memcpy(store[i], (void *)nsaa, sz); nsaa += (sz + 7) & ~7UL; }
        } else if (ty->type == FFI_TYPE_STRUCT && sz > 16) {           /* by reference: a pointer in the next x register */
            void *src = (void *)(ngrn < 8 ? RX(ngrn++) : *(uint64_t *)(nsaa = (nsaa + 7) & ~7UL, nsaa += 8, nsaa - 8));
            memcpy(store[i], src, sz);
        } else if (ty->type == FFI_TYPE_STRUCT) {                       /* <= 16 bytes, not an HFA: 1-2 x registers */
            int w = (int)((sz + 7) / 8);
            if (ngrn + w <= 8) { memcpy(store[i], &RX(ngrn), sz); ngrn += w; }
            else { ngrn = 8; nsaa = (nsaa + al - 1) & ~(al - 1); memcpy(store[i], (void *)nsaa, sz); nsaa += (sz + 7) & ~7UL; }
        } else {                                                        /* integer, pointer, object, selector, block */
            uint64_t v;
            if (ngrn < 8) v = RX(ngrn++);
            else { nsaa = (nsaa + sz - 1) & ~(sz - 1); v = 0; memcpy(&v, (void *)nsaa, sz); nsaa += sz; }
            if (aenc[i][0] == '@' && aenc[i][1] == '?') v = (uint64_t)__arm2x86_blk((void *)v);   /* a block native will call */
            else if (aenc[i][0] == '@' && a2x_is_block(v)) v = (uint64_t)__arm2x86_blk((void *)v);  /* [blk copy], a block in a collection */
            else if (i >= 2 && (aenc[i][0] == '@' || aenc[i][0] == '#')) v = __arm2x86_mapcls(v);
            /* 10-20 A va_list PARAMETER OF A NATIVE METHOD. qlmanage -h and mcxquery faulted at 0x0 in
                  __CFStringAppendFormatCore under -[NSPlaceholderString initWithFormat:locale:arguments:]: the arm64
                  caller's va_list (Apple arm64: a char * to 8-byte stack slots) went in as if it were x86's 24-byte
                  {gp_offset, fp_offset, overflow_arg_area, reg_save_area}, so CF read the slots' contents as offsets and
                  pointers.  Detected by the NATIVE encoding, which is the x86 one — measured on macOS 27:
                  `[1{__va_list_tag=II^v^v}]` for initWithFormat:arguments:, initWithFormat:locale:arguments:,
                  raise:format:arguments:, predicateWithFormat:arguments:. No selector-name fallback is needed: a
                  native x86 method that takes a va_list always encodes the tag, and a TRANSLATED method's arm64
                  encoding (`*`) means its imp is arm64 code that wants the char * unchanged. Rebuilt the way
                  arm2x86.py va_conv does for C (gp 48, fp 304: every register consumed, so x86 reads every argument
                  from overflow_arg_area in 8-byte slots — the arm64 layout). The struct lives in this call's arena,
                  which outlives the native callee. */
            if (!strncmp(aenc[i], "[1{__va_list_tag", 16) || !strncmp(aenc[i], "^{__va_list_tag", 15)) {
                struct { uint32_t gp, fp; void *ovf, *reg; } *xv = (void *)(store[i] + 16);
                xv->gp = 48; xv->fp = 304; xv->ovf = (void *)v; xv->reg = NULL; v = (uint64_t)xv;
            }
            memcpy(store[i], &v, sz);
        }
    }
    /* 10-30 A WEAK REFERENCE CANNOT BE MEMCPY'D. A guest method that returns a small C++ struct holding a
          __weak (Finder's TNSWeakPtr<T>, returned through x8 at any size because it is not trivially copyable) was
          run by imp_handler with x8 = a scratch buffer on imp_handler's x86 stack. The callee's objc_initWeak
          registered THAT address in the referent's weak table; the bytes were then copied to the caller's buffer,
          which the table never heard of. MEASURED, Apple's thin Finder under the host: 15 x "Attempted to
          unregister unknown __weak variable at 0x180cd4..." (the guest stack) and "__weak variable at 0x7ff7bfee...
          holds 0x2 instead of ..." (imp_handler's dead frame), then a dangling weak was messaged after its object
          died: SIGSEGV, rc 139, a launchd crash loop. Calculator and TextEdit: 0 such lines.
        When the method is ours, the guest caller already laid out an AAPCS64 call, x8 included, so it is run AS
          that call: same registers, same sp, the callee writes its result (weak slot and all) at its final address.
          No poison buffer, no copy. Only this return shape needs it; every other send keeps the ffi path. */
    if (rt->type == FFI_TYPE_STRUCT && rt->size <= 16) {
        int gisd = -1, gnh = hfa4(rt, &gisd);
        if (!(gnh >= 1 && gnh <= 4)) {
            Class lc = super ? cls : object_getClass((id)x0);   /* Super2: lookup starts at the superclass */
            unsigned long t = direct_target ? direct_target
                            : (lc ? (unsigned long)class_getMethodImplementation(lc, sel) : 0);
            unsigned long g = __arm2x86_objc_imp_target(t);
            if (g) {
                if (super) RX(0) = (uint64_t)((struct objc_super *)x0)->receiver;
                __arm2x86_call_rf(g);
                return;
            }
        }
    }
    /* x86_64 returns a struct > 16 bytes in memory: that is the _stret entry, never plain objc_msgSend */
    int stret = rt->type == FFI_TYPE_STRUCT && rt->size > 16;
    void (*fn)(void) = direct_target ? (void (*)(void))direct_target : super ? (stret ? (void (*)(void))objc_msgSendSuper2_stret : (void (*)(void))objc_msgSendSuper2)
                             : (stret ? (void (*)(void))objc_msgSend_stret : (void (*)(void))objc_msgSend);
    /* the result buffer has the return's own size (>= 16: ffi writes a whole ffi_arg / both halves of a 16-byte pair).
       x86: > 16 bytes is the hidden pointer of the _stret entry; arm64: the caller's buffer at x8 (copied below). */
    size_t rsz = rt->size < 16 ? 16 : (rt->size + 15) & ~15UL;
    if (rsz > 65536) die2("return larger than 64 KiB", sig);
    unsigned char *ret = (unsigned char *)(((uintptr_t)__builtin_alloca(rsz + 15) + 15) & ~(uintptr_t)15);
    memset(ret, 0, rsz);
    a2x_sret_via_x8 = 0;   /* 10-21 only a callee that writes through x8 sets this (see the note above) */
    uint64_t caller_x8 = RX(8);
    /* the integer-only path returned long before here (see the simple path above), so every send that
       reaches this line needs libffi to place its arguments: a float, a struct, an HFA, a va_list, more
       than eight arguments, or a memory return. */
    ffi_call(cif, fn, ret, av);
    /* the result, written back the arm64 way */
    if (rt->type == FFI_TYPE_VOID) return;
    int isd = -1, nh = (rt->type == FFI_TYPE_STRUCT) ? hfa4(rt, &isd) : 0;
    if (rt->type == FFI_TYPE_FLOAT || rt->type == FFI_TYPE_DOUBLE) { memset(RV(0), 0, 16); memcpy(RV(0), ret, rt->size); }
    else if (nh >= 1 && nh <= 4) {
        unsigned char *leaf[4]; size_t off = 0; int k = 0; hfa_leaves(rt, ret, &off, leaf, &k);
        for (int j = 0; j < nh; j++) { memset(RV(j), 0, 16); memcpy(RV(j), leaf[j], isd ? 8 : 4); }
    } else if (rt->type == FFI_TYPE_STRUCT && rt->size > 16) memcpy((void *)RX(8), ret, rt->size);
    else if (rt->type == FFI_TYPE_STRUCT && a2x_sret_via_x8) {
        /* 10-21 the callee returned this through x8, so the arm64 caller reads its own buffer, not x0/x1.
           x0/x1 are set as well: they are call-clobbered, so a caller that ignores them is unharmed, and at -O0
           AAPCS64's "the result block's address is returned in x0" still holds. */
        if (!caller_x8 || (caller_x8 & 7)) {
            static int said; if (!said) { said = 1;
                fprintf(a2x_errf(), "objc_bridge: %s returns in memory but the caller's x8 is 0x%llx -- the "
                        "result is dropped. The caller did not supply an indirect-result buffer.\n",
                        sig, (unsigned long long)caller_x8); }
        } else memcpy((void *)caller_x8, ret, rt->size);
        RX(0) = caller_x8; RX(1) = 0;
    }
    else if (rt->type == FFI_TYPE_STRUCT) { RX(0) = 0; RX(1) = 0; memcpy(&RX(0), ret, rt->size); }
    else {   /* ffi widens integer returns to a full register (ffi_arg) */
        uint64_t v = 0;
        switch (rt->type) {
        case FFI_TYPE_SINT8: v = (uint64_t)(int64_t)*(int8_t *)ret; break;   case FFI_TYPE_UINT8: v = *(uint8_t *)ret; break;
        case FFI_TYPE_SINT16: v = (uint64_t)(int64_t)*(int16_t *)ret; break; case FFI_TYPE_UINT16: v = *(uint16_t *)ret; break;
        case FFI_TYPE_SINT32: v = (uint64_t)(int64_t)*(int32_t *)ret; break; case FFI_TYPE_UINT32: v = *(uint32_t *)ret; break;
        default: memcpy(&v, ret, 8);
        }
        RX(0) = v;
    }
}
/* the register-file macros, back to resolving the thread-local themselves (msg_send hoisted it above) */
#undef RX
#undef RV
#define RX(i) (((uint64_t *)__arm2x86_rf)[i])
#define RV(j) (__arm2x86_rf + 80 + 16 * (j))
void __arm2x86_objc_msgSend(void) { msg_send(0, NULL, 0); }
void __arm2x86_objc_msgSendSuper2(void) { msg_send(1, NULL, 0); }

/* ==== rung 3b CLASSES THE PROGRAM DEFINES, REGISTERED WITH THE NATIVE RUNTIME ============================================
 *  dyld never saw this image, so its classes (an app delegate, an NSView subclass ...) exist only as arm64 metadata.
 *    Each is rebuilt natively: objc_allocateClassPair + ivars + methods + protocols, registered in superclass order. Every
 *    method's IMP is a libffi CLOSURE built from its own type encoding: native code calls it with the SysV signature, the
 *    closure places each argument where AAPCS64 (Apple) puts it (x0..x7, v0..v7, HFAs, small structs, the arm64 stack),
 *    runs the translated method through the IR door __arm2x86_call_rf and converts the result back.
 *  The lifter's internal ABI returns x0 and v0 only (abi_ret): a translated METHOD returning a 16-byte struct (x0+x1) or
 *    an HFA wider than one register (v0..v3) is refused by name at registration, never returned half-filled.
 *  The class's ivar OFFSET VARIABLES (what arm64 code reads) are rewritten to the native layout after registration. */
/* 10-03 THE FOUR NATIVE IMPORTS WHOSE C SIGNATURE THE TWO ABIs PASS DIFFERENTLY (measured over all 17 struct/enum-typed
      imports of Cyberpunk; the other 13 are register-identical). Full-register handlers: arm64 registers (and the arm64 stack
      at __arm_sp) in, the C call with real types (clang lays out x86), the result written back the arm64 way.
       CFStringGetBytes: the by-value CFRange takes x1+x2, so the 8th argument is on the ARM64 STACK — the generic adapter
         dropped it and the native function wrote through garbage (Cyberpunk build31: fault at 0xffffffff).
      CGDisplayBounds / CAFrameRateRangeMake return an HFA (d0-d3 / s0-s2) that x86 returns in memory / packed xmm;
      NSPointInRect's NSRect is d2-d5 on arm64 and the STACK on x86. Resolved by dlsym, so every host still links. */
#include <dlfcn.h>
typedef struct { double x, y; } a2x_p2; typedef struct { double x, y, w, h; } a2x_r4;
typedef struct { float lo, hi, pref; } a2x_f3; typedef struct { long loc, len; } a2x_cfr;
#define A2X_RX(i) (((uint64_t *)__arm2x86_rf)[i])
/* 10-20 AN OFF-CONTRACT CALLEE RETURNS x1 AND v1-v3 THROUGH @__arm_xr, not through the register file —
   that is the same channel the ObjC bridge uses to carry an HFA back. These handlers only ever wrote the
   register file, so a CGRect came back with its origin intact and its SIZE ZERO: measured on the Dock, the
   handler wrote v0..v3 = 1234 5678 11 22 and the program read 1234 5678 0 0, logged
   "CGDisplayBounds(0xb41a2f3) returned 0.000000 ..." and aborted. Publish both channels. */
extern __thread unsigned long __arm_xr[96];
#define A2X_XRV(j) (*(double *)((char *)__arm_xr + 256 + 16 * (j)))
#define A2X_VD(j) (*(double *)(__arm2x86_rf + 80 + 16 * (j)))
#define A2X_VF(j) (*(float *)(__arm2x86_rf + 80 + 16 * (j)))
static void *a2x_need(const char *s) { void *p = dlsym(RTLD_DEFAULT, s); if (!p) { a2x_stop("native function not found", s); abort(); } return p; }
/* SkyLight defines only the low byte of this result on x86. ARM callers
   consume w0, including loginwindow's session safe-boot decision. */
uint64_t __arm2x86_bool_os_feature_enabled_impl(const char *domain,const char *feature) {
    static _Bool (*native)(const char *,const char *);
    if (!native) native=(_Bool (*)(const char *,const char *))dlsym(RTLD_DEFAULT,"_os_feature_enabled_impl");
    if (!native) { a2x_stop("native function not found", "_os_feature_enabled_impl"); abort(); }
    return (uint64_t)native(domain,feature);
}

void __arm2x86_abi_CGSServerOperationState(void) {
    static uint8_t (*f)(uint32_t);
    if (!f) f = a2x_need("CGSServerOperationState");
    A2X_RX(0) = f((uint32_t)A2X_RX(0));
}
void __arm2x86_abi_CFStringGetBytes(void) {
    static long (*f)(const void *, a2x_cfr, uint32_t, unsigned char, unsigned char, unsigned char *, long, long *);
    if (!f) f = a2x_need("CFStringGetBytes");
    a2x_cfr r = { (long)A2X_RX(1), (long)A2X_RX(2) }; long *used = *(long **)__arm_sp;
    A2X_RX(0) = (uint64_t)f((const void *)A2X_RX(0), r, (uint32_t)A2X_RX(3), (unsigned char)A2X_RX(4), (unsigned char)A2X_RX(5),
                            (unsigned char *)A2X_RX(6), (long)A2X_RX(7), used);
}
void __arm2x86_abi_CGDisplayBounds(void) {
    static a2x_r4 (*f)(uint32_t); if (!f) f = a2x_need("CGDisplayBounds");
    a2x_r4 r = f((uint32_t)A2X_RX(0)); memset(__arm2x86_rf + 80, 0, 64);
    A2X_VD(0) = r.x; A2X_VD(1) = r.y; A2X_VD(2) = r.w; A2X_VD(3) = r.h;
    A2X_XRV(1) = r.y; A2X_XRV(2) = r.w; A2X_XRV(3) = r.h;
    /* 10-20 Dock printed `CGDisplayBounds(0xb41a2f3) returned 0 0 0 0` while a NATIVE probe in the same
       session got 1920x1080 for that display, so say what this handler was handed and what it hands back:
       a zero HERE means CoreGraphics really returned nothing, a correct rect here means the caller never
       read v0-v3 and the fault is the call site, not the ABI. */
    if (A2X_DBGENV("ARM2X86_SHIM_VERBOSE"))
        fprintf(a2x_errf(), "[abi] CGDisplayBounds(0x%x) -> %g %g %g %g  x8=0x%llx caller=%p\n",
                (uint32_t)A2X_RX(0), r.x, r.y, r.w, r.h, (unsigned long long)A2X_RX(8), __builtin_return_address(0));
}
/* 10-20 SkyLight's display/window ITERATOR getters return a CGRect BY VALUE, and they are private SPI
   with no header, so sigdb has NO entry for them at all and they fell to the generic adapter, which carries
   x0/v0 only. The Dock's `Displays init:` therefore read 0,0,0,0 for a 1920x1080 screen, logged
   "CGDisplayBounds(0xb41a2f3) returned 0.000000 ..." and aborted — that abort is what held macOS 27 at the
   login spinner with Finder and SystemUIServer already running.
    Measured in the native x86 code rather than assumed: all four begin
       55 48 89 e5 41 56 53 48 89 f3 49 89 fe   push rbp / mov rbp,rsp / push r14 / push rbx
                                                / mov rbx,RSI / mov r14,RDI
   then copy 32 bytes with two movups into [r14] — so x86 takes the hidden sret pointer in rdi and the
   iterator in rsi. macOS 27 also takes the explicit iterator index in x1 on arm64 and rdx on x86.
   Both arguments must cross the bridge; dropping the index aborts in iterator_seek. The CGRect
   result is an HFA returned in v0-v3 on arm64. */
#define A2X_RECT_OF_PTR(name)                                                   \
void __arm2x86_abi_##name(void) {                                               \
    static a2x_r4 (*f)(void *, long); if (!f) f = a2x_need(#name);              \
    a2x_r4 r = f((void *)A2X_RX(0), (long)A2X_RX(1));                          \
    memset(__arm2x86_rf + 80, 0, 64);                                         \
    A2X_VD(0) = r.x; A2X_VD(1) = r.y; A2X_VD(2) = r.w; A2X_VD(3) = r.h;         \
    A2X_XRV(1) = r.y; A2X_XRV(2) = r.w; A2X_XRV(3) = r.h;                       \
}
/* 10-20 CFUUIDBytes is 16 BYTES BY VALUE, which AAPCS64 and SysV both pass/return in two INTEGER
   registers (arm64 x0+x1, x86-64 rax+rdx) — but sigdb marks it `x` (untypeable), so these two went through
   the generic adapter, which carries x0 only. Half of every display UUID was therefore garbage: the Dock
   logged "uuid: %{uuid_t}.16P" as a compose failure and could not resolve a display, which is the abort in
   `Displays init:` that kept macOS 27 at the login spinner. {uint64,uint64} has the identical layout and
   register class, so clang places it exactly as the real CFUUIDBytes. */
/* 10-21 THE objc_opt_* FAMILY WAS HANDED A GUEST CLASS. A non-generic Swift class's metadata
      accessor is `adrp x0, <class> ; bl objc_opt_self ; mov x1, #0 ; ret`, so objc_opt_self's RESULT *is*
      the type metadata. The record it names -- 0x1004058a0 in the Dock -- is one of the image's 341
      __objc_classlist entries, i.e. a TEMPLATE this bridge rebuilt with objc_allocateClassPair, never a
      class the native runtime registered. Bound straight through, native objc_opt_self returned 0x48, and
      Swift used that as metadata: $sSqMa (Optional's accessor) took the payload layout from T-8 = 0x40 and
      swift_initEnumMetadataSinglePayload faulted reading it (Dock, 5/5 runs, in DOCKGestures start-up).
      msg_send already maps every receiver through __arm2x86_mapcls; these entry points are the same door
      and need the same map. Mapping is identity for anything that is not a guest class, so an ordinary
      object argument is untouched. */
#define A2X_OPT1(nm)                                                                   \
    void __arm2x86_abi_##nm(void) {                                                    \
        static unsigned long (*f)(unsigned long); if (!f) f = a2x_need(#nm);           \
        A2X_RX(0) = (uint64_t)f(__arm2x86_mapcls(A2X_RX(0)));                          \
    }
A2X_OPT1(objc_opt_self)
A2X_OPT1(objc_opt_class)
A2X_OPT1(objc_opt_new)
/* 10-21 THE objc_alloc FAMILY IS THE SAME HOLE, AND IT OUTLIVES THE CALL. A plain ObjC guest class is
      registered here through objc_allocateClassPair(), which builds a TWIN at a different address — so, unlike
      a Swift guest class (realized IN PLACE, where the guest pointer IS a valid Class), the guest record is not
      dispatchable natively. Bound straight through, native objc_alloc(guest) allocates a real heap object and
      writes the GUEST TEMPLATE into its isa. Nothing notices at first: __arm2x86_objc_msgSend maps every
      receiver through __arm2x86_mapcls, so translated code keeps working on that object — the first NATIVE
      objc_msgSend on it walks the fake isa and dies in someone else's frame. Measured on Finder (macOS 27):
      SIGSEGV at objc_lookUpImpOrForward+0x4c, fault address 0x0, through _objc_msgSend_uncached <-
      objc_cast<FIDSNode, FINode*> <- TNode::NodeFromNodeRef <- _NodeGetCustomNode in DesktopServicesPriv, with
      rdi = 0x6000034e4880 (a real object) whose isa read 0x100adb4f0 — a guest arm64 class pointer. Not a
      Finder bug: _objc_alloc is undefined in 15 of the 16 m27gui2 targets, _objc_alloc_init in 13,
      _objc_allocWithZone in 7.
    All three are single-Class takers — `id objc_alloc(Class)`, `id objc_alloc_init(Class)`,
      `id objc_allocWithZone(Class)` — so this is the same door and the same map as objc_opt_* above, and the
      map is identity for anything that is not a guest class.
    NOT swift_allocObject / swift_initStackObject / swift_initStaticObject: a Swift guest class is realized in
      place, so their metadata argument is already natively valid and the map would be identity. And NOT
      object_getClass (2 targets) — that is the REVERSE direction, native twin -> guest constant, a separate
      question that is unproven. */
A2X_OPT1(objc_alloc)
A2X_OPT1(objc_alloc_init)
A2X_OPT1(objc_allocWithZone)
void __arm2x86_abi_objc_opt_isKindOfClass(void) {
    static unsigned long (*f)(unsigned long, unsigned long); if (!f) f = a2x_need("objc_opt_isKindOfClass");
    A2X_RX(0) = (uint64_t)f(__arm2x86_mapcls(A2X_RX(0)), __arm2x86_mapcls(A2X_RX(1)));
}
void __arm2x86_abi_objc_opt_respondsToSelector(void) {   /* x1 is a SEL, not a class */
    static unsigned long (*f)(unsigned long, unsigned long); if (!f) f = a2x_need("objc_opt_respondsToSelector");
    A2X_RX(0) = (uint64_t)f(__arm2x86_mapcls(A2X_RX(0)), A2X_RX(1));
}
typedef struct { uint64_t lo, hi; } a2x_b16;
void __arm2x86_abi_CFUUIDGetUUIDBytes(void) {
    static a2x_b16 (*f)(const void *); if (!f) f = a2x_need("CFUUIDGetUUIDBytes");
    a2x_b16 r = f((const void *)A2X_RX(0));
    A2X_RX(0) = r.lo; A2X_RX(1) = r.hi;
}
void __arm2x86_abi_CFUUIDCreateFromUUIDBytes(void) {
    static void *(*f)(const void *, a2x_b16); if (!f) f = a2x_need("CFUUIDCreateFromUUIDBytes");
    a2x_b16 b = { A2X_RX(1), A2X_RX(2) };          /* the struct follows the allocator: x1+x2 */
    A2X_RX(0) = (uint64_t)f((const void *)A2X_RX(0), b);
}
A2X_RECT_OF_PTR(SLSManagedDisplayIteratorGetBounds)
A2X_RECT_OF_PTR(SLSWindowIteratorGetBounds)
A2X_RECT_OF_PTR(SLSWindowIteratorGetScreenRect)
A2X_RECT_OF_PTR(SLSWindowIteratorGetFrameBounds)
A2X_RECT_OF_PTR(SLSWindowIteratorGetLastNonEmptyFrameBounds)

/* 10-20 THE CGRect ACCESSORS TAKE THE RECTANGLE BY VALUE, and sigdb types that argument `x`
   (untypeable), so they went through the generic adapter, which passes scalars only. AAPCS64 hands a
   CGRect to a callee in v0-v3; SysV puts those 32 bytes on the STACK. The callee therefore read garbage
   and returned 0.
    Measured in the Dock's own code at 0x1001d5e54: it logs the ORIGIN straight out of d8/d9 and then
      asks for the SIZE by calling CGRectGetWidth/CGRectGetHeight with the rect in v0-v3 — which is why
      the log read "returned 0.000000 ..." with a correct origin and a zero size, and why the Dock
      aborted and held the whole desktop at the login window.
   Each handler rebuilds the arguments from the arm64 register file and calls the real function with real
   C types, so clang lays the x86 side out; the result goes back the arm64 way (a double in d0, a bool in
   x0, a rectangle as an HFA in v0-v3). */
#define A2X_RECT(j) ((a2x_r4){ A2X_VD(j), A2X_VD((j) + 1), A2X_VD((j) + 2), A2X_VD((j) + 3) })
#define A2X_PUT_RECT(r) do { memset(__arm2x86_rf + 80, 0, 64);                                  \
    A2X_VD(0) = (r).x; A2X_VD(1) = (r).y; A2X_VD(2) = (r).w; A2X_VD(3) = (r).h;                 \
    A2X_XRV(1) = (r).y; A2X_XRV(2) = (r).w; A2X_XRV(3) = (r).h; } while (0)

#define A2X_D_OF_RECT(name)                                                                     \
void __arm2x86_abi_##name(void) {                                                               \
    static double (*f)(a2x_r4); if (!f) f = a2x_need(#name);                                    \
    double d = f(A2X_RECT(0)); A2X_VD(0) = d;                                                   \
}
A2X_D_OF_RECT(CGRectGetWidth)  A2X_D_OF_RECT(CGRectGetHeight)
A2X_D_OF_RECT(CGRectGetMinX)   A2X_D_OF_RECT(CGRectGetMinY)
A2X_D_OF_RECT(CGRectGetMaxX)   A2X_D_OF_RECT(CGRectGetMaxY)
A2X_D_OF_RECT(CGRectGetMidX)   A2X_D_OF_RECT(CGRectGetMidY)

#define A2X_B_OF_RECT(name)                                                                     \
void __arm2x86_abi_##name(void) {                                                               \
    static int (*f)(a2x_r4); if (!f) f = a2x_need(#name);                                       \
    A2X_RX(0) = (uint64_t)(unsigned char)!!f(A2X_RECT(0));                                      \
}
A2X_B_OF_RECT(CGRectIsEmpty)  A2X_B_OF_RECT(CGRectIsNull)  A2X_B_OF_RECT(CGRectIsInfinite)

#define A2X_B_OF_2RECT(name)                                                                    \
void __arm2x86_abi_##name(void) {                                                               \
    static int (*f)(a2x_r4, a2x_r4); if (!f) f = a2x_need(#name);                               \
    A2X_RX(0) = (uint64_t)(unsigned char)!!f(A2X_RECT(0), A2X_RECT(4));                         \
}
A2X_B_OF_2RECT(CGRectContainsRect)  A2X_B_OF_2RECT(CGRectIntersectsRect)

#define A2X_R_OF_2RECT(name)                                                                    \
void __arm2x86_abi_##name(void) {                                                               \
    static a2x_r4 (*f)(a2x_r4, a2x_r4); if (!f) f = a2x_need(#name);                            \
    a2x_r4 r = f(A2X_RECT(0), A2X_RECT(4)); A2X_PUT_RECT(r);                                    \
}
A2X_R_OF_2RECT(CGRectIntersection)  A2X_R_OF_2RECT(CGRectUnion)

#define A2X_R_OF_RECT_DD(name)                                                                  \
void __arm2x86_abi_##name(void) {                                                               \
    static a2x_r4 (*f)(a2x_r4, double, double); if (!f) f = a2x_need(#name);                    \
    a2x_r4 q = A2X_RECT(0); double a = A2X_VD(4), b = A2X_VD(5);                                \
    a2x_r4 r = f(q, a, b); A2X_PUT_RECT(r);                                                     \
}
A2X_R_OF_RECT_DD(CGRectInset)  A2X_R_OF_RECT_DD(CGRectOffset)

void __arm2x86_abi_CGRectIntegral(void) {
    static a2x_r4 (*f)(a2x_r4); if (!f) f = a2x_need("CGRectIntegral");
    a2x_r4 r = f(A2X_RECT(0)); A2X_PUT_RECT(r);
}
void __arm2x86_abi_CGRectContainsPoint(void) {
    static int (*f)(a2x_r4, a2x_p2); if (!f) f = a2x_need("CGRectContainsPoint");
    a2x_p2 p = { A2X_VD(4), A2X_VD(5) };
    A2X_RX(0) = (uint64_t)(unsigned char)!!f(A2X_RECT(0), p);
}
/* CGRectEqualToRect already had a handler by this name; keep that one. */

#define A2X_CTX_RECT(name)                                                                      \
void __arm2x86_abi_##name(void) {                                                               \
    static void (*f)(void *, a2x_r4); if (!f) f = a2x_need(#name);                              \
    f((void *)A2X_RX(0), A2X_RECT(0));                                                          \
}
A2X_CTX_RECT(CGContextFillRect)  A2X_CTX_RECT(CGContextClearRect)  A2X_CTX_RECT(CGContextClipToRect)

void __arm2x86_abi_CGContextDrawImage(void) {
    static void (*f)(void *, a2x_r4, void *); if (!f) f = a2x_need("CGContextDrawImage");
    f((void *)A2X_RX(0), A2X_RECT(0), (void *)A2X_RX(1));
}
void __arm2x86_abi_CGEventGetLocation(void) {
    static a2x_p2 (*f)(void *); if (!f) f = a2x_need("CGEventGetLocation");
    a2x_p2 p = f((void *)A2X_RX(0)); memset(__arm2x86_rf + 80, 0, 32);
    A2X_VD(0) = p.x; A2X_VD(1) = p.y; A2X_XRV(1) = p.y;
}
void __arm2x86_abi_CGEventSetLocation(void) {
    static void (*f)(void *, a2x_p2); if (!f) f = a2x_need("CGEventSetLocation");
    a2x_p2 p = { A2X_VD(0), A2X_VD(1) };
    f((void *)A2X_RX(0), p);
}
void __arm2x86_abi_CGGetDisplaysWithRect(void) {
    static int (*f)(a2x_r4, uint32_t, uint32_t *, uint32_t *); if (!f) f = a2x_need("CGGetDisplaysWithRect");
    A2X_RX(0) = (uint64_t)(uint32_t)f(A2X_RECT(0), (uint32_t)A2X_RX(0), (uint32_t *)A2X_RX(1), (uint32_t *)A2X_RX(2));
}
void __arm2x86_abi_CGGetDisplaysWithPoint(void) {
    static int (*f)(a2x_p2, uint32_t, uint32_t *, uint32_t *); if (!f) f = a2x_need("CGGetDisplaysWithPoint");
    a2x_p2 p = { A2X_VD(0), A2X_VD(1) };
    A2X_RX(0) = (uint64_t)(uint32_t)f(p, (uint32_t)A2X_RX(0), (uint32_t *)A2X_RX(1), (uint32_t *)A2X_RX(2));
}

/* 10-20 the rest of the by-value struct class, GENERATED from sigdb by ops/abigen/abi_gen.py:
   116 such imports across the seven translated macOS 27 GUI binaries, of which these are the ones
   whose C type is known.  Hand-written handlers above win — the generator never re-emits a name
   that already has one. */
#define A2X_XRX1(v) (__arm_xr[1] = (unsigned long)(v))
/* 10-20 swift_once IS NOT IN SIGDB, AND ITS SECOND ARGUMENT IS A FUNCTION POINTER INTO TRANSLATED CODE.
   Untyped, the generic adapter hands libswiftCore the raw arm64 address; libswiftCore CALLS it and the CPU
   executes the arm64 image, which is mapped read-only — the kernel logged
      "Data/Stack execution not permitted: Dock[...] at virtual address 0x1001d5000, protections were read-only"
    The initializer therefore never runs and the Swift global it was meant to fill stays ZERO. Measured in the
      Dock: `swift_cvw_initWithCopy` on EyeCandySwift.WeakIdentitySet.Identity copied a weak slot holding
      0x100400ae0 — a zero-filled global in the translated image's __DATA, not a heap object — so objc_copyWeak
      -> objc_retain read isa 0 and faulted at 0x20.
   `__arm2x86_cb` is the engine's existing answer for exactly this (sigdb marks such an argument `fnp`, see
   xlat.py rung 2); swift_once simply has no sigdb entry to be marked in. */
extern unsigned long __arm2x86_cb(unsigned long fn);
void __arm2x86_abi_swift_once(void) {
    static void (*f)(long *, void (*)(void *), void *); if (!f) f = a2x_need("swift_once");
    f((long *)A2X_RX(0), (void (*)(void *))__arm2x86_cb(A2X_RX(1)), (void *)A2X_RX(2));
}
#include "abi_structs_gen.c"
#include "abi_audit.c"   /* audit_token_t by value outside sigdb (10-29, the menu bar) */
#include "abi_sls.c"     /* transforms by value into SkyLight SPI (11-09, the window drag) */
#include "abi_hfa_gen.c" /* results of three or four doubles, layouts measured on both architectures */
#include "abi_sbx.c"    /* sandbox_check: a daemon asking whether it entered its own sandbox */
#include "abi_rect2.c"  /* structure results of calls that take pointers or large structures, read from the x86 code */
#include "abi_cfdate.c"  /* Gregorian dates: an integer and a floating half in one 16-byte value */
#include "abi_swiftrepl.c" /* a function address compared by the Swift runtime must arrive unchanged */
#include "abi_spi.c"     /* the rest of the stack-argument sweep (11-09) */

void __arm2x86_abi_NSPointInRect(void) {
    static signed char (*f)(a2x_p2, a2x_r4); if (!f) f = a2x_need("NSPointInRect");
    a2x_p2 p = { A2X_VD(0), A2X_VD(1) }; a2x_r4 r = { A2X_VD(2), A2X_VD(3), A2X_VD(4), A2X_VD(5) };
    A2X_RX(0) = (uint64_t)(unsigned char)f(p, r);
}
void __arm2x86_abi_CAFrameRateRangeMake(void) {
    static a2x_f3 (*f)(float, float, float); if (!f) f = a2x_need("CAFrameRateRangeMake");
    a2x_f3 r = f(A2X_VF(0), A2X_VF(1), A2X_VF(2)); memset(__arm2x86_rf + 80, 0, 48);
    A2X_VF(0) = r.lo; A2X_VF(1) = r.hi; A2X_VF(2) = r.pref;
}
/* 10-05 SSLCipherSuite is uint16_t on arm64 and uint32_t on x86-64 (measured: ops structsz, every pointer arg of every
   import sized on both targets — these three are the only cipher-array imports, all called by Galaxy's curl/SecureTransport).
   Bound natively, SSLGetSupportedCiphers wrote count*4 bytes into curl's count*2 buffer: a HEAP OVERFLOW on every TLS
   connect (curl_global_init_mem routes curl's malloc to the game). SSLSetEnabledCiphers read pairs of suites as one;
   SSLGetNegotiatedCipher wrote 4 bytes into a 2-byte variable. The arrays are widened / narrowed here, element by element. */
#include <stdint.h>
void __arm2x86_abi_SSLGetSupportedCiphers(void) {
    static int (*f)(void *, uint32_t *, size_t *); if (!f) f = a2x_need("SSLGetSupportedCiphers");
    uint16_t *out = (uint16_t *)A2X_RX(1); size_t *num = (size_t *)A2X_RX(2), cap = num ? *num : 0;
    uint32_t *wide = calloc(cap ? cap : 1, sizeof *wide);
    int st = f((void *)A2X_RX(0), out ? wide : 0, num);
    if (out && num) for (size_t i = 0; i < *num && i < cap; i++) out[i] = (uint16_t)wide[i];
    free(wide); A2X_RX(0) = (uint64_t)(int64_t)st;
}
void __arm2x86_abi_SSLSetEnabledCiphers(void) {
    static int (*f)(void *, const uint32_t *, size_t); if (!f) f = a2x_need("SSLSetEnabledCiphers");
    const uint16_t *in = (const uint16_t *)A2X_RX(1); size_t n = (size_t)A2X_RX(2);
    uint32_t *wide = calloc(n ? n : 1, sizeof *wide);
    for (size_t i = 0; in && i < n; i++) wide[i] = in[i];
    int st = f((void *)A2X_RX(0), in ? wide : 0, n); free(wide); A2X_RX(0) = (uint64_t)(int64_t)st;
}
void __arm2x86_abi_SSLGetNegotiatedCipher(void) {
    static int (*f)(void *, uint32_t *); if (!f) f = a2x_need("SSLGetNegotiatedCipher");
    uint16_t *out = (uint16_t *)A2X_RX(1); uint32_t w = 0;
    int st = f((void *)A2X_RX(0), out ? &w : 0); if (out) *out = (uint16_t)w; A2X_RX(0) = (uint64_t)(int64_t)st;
}
/* 10-05 curl_easy_setopt / curl_easy_getinfo are VARIADIC, and Apple arm64 passes EVERY variadic argument on the STACK
   (measured: all 26 setopt sites in Cyberpunk do `str <value>, [sp]` and never set x2). sigdb has no curl, so both went
   through the untyped x0-x7 adapter and native libcurl took x2 — whatever the previous call left — as CURLOPT_URL,
   CURLOPT_WRITEDATA and CURLOPT_WRITEFUNCTION (ops/boundary: the variadic-through-adapter census, 10-05). Every option
   value is one 8-byte slot (long, pointer, curl_off_t, function); function options are arm64 code and are adapted. */
#include <curl/curl.h>
void __arm2x86_abi_curl_easy_setopt(void) {
    static CURLcode (*f)(CURL *, CURLoption, ...); if (!f) f = a2x_need("curl_easy_setopt");
    long opt = (long)(int32_t)A2X_RX(1); unsigned long v = *(unsigned long *)__arm_sp;
    if (opt >= CURLOPTTYPE_FUNCTIONPOINT && opt < CURLOPTTYPE_OFF_T) v = __arm2x86_cb(v);
    A2X_RX(0) = (uint64_t)(uint32_t)f((CURL *)A2X_RX(0), (CURLoption)opt, v);
}
void __arm2x86_abi_curl_easy_getinfo(void) {
    static CURLcode (*f)(CURL *, CURLINFO, ...); if (!f) f = a2x_need("curl_easy_getinfo");
    A2X_RX(0) = (uint64_t)(uint32_t)f((CURL *)A2X_RX(0), (CURLINFO)(int32_t)A2X_RX(1), *(void **)__arm_sp);
}
/* 10-05 _availability_version_check returns bool, and x86 libsystem leaves the VERSION in %eax's upper bytes
   (`movl 12(%rsi),%eax; cmpl ..; setbe %al; retq`, disassembled on the mini). It reaches the untyped adapter (no sigdb
   entry), and the arm64 caller tests the whole register (`cbz w0` after __isPlatformVersionAtLeast): every @available
   check read TRUE. The answer is narrowed to 0/1, the way an arm64 callee hands back a bool. */
void __arm2x86_abi_availability_version_check(void) {
    static _Bool (*f)(uint32_t, const void *); if (!f) f = a2x_need("_availability_version_check");
    A2X_RX(0) = f((uint32_t)A2X_RX(0), (const void *)A2X_RX(1)) ? 1 : 0;
}
/* 10-20 avmediainfo on macOS 27 printed a track's `Duration: nan seconds` (native 0.768) and a `Movie matrix` line
      native never prints. Not the message send — the asset's own CMTime came back through msg_send's _stret path intact
      (`0.768 seconds (36887/48000)`). Both come from C imports sigdb marks 'x' (a struct by value), which reached the
      untyped adapter: AAPCS64 passes a > 16-byte struct as a POINTER in x0/x1, x86-64 passes the bytes ON THE STACK, so
      native CMTimeGetSeconds / CGAffineTransformEqualToTransform read whatever the stack held (a stale copy of the
      asset's CMTime made the first line look right). CGRect is an HFA (d0-d3, d4-d7) on arm64 and MEMORY on x86;
      CMTimeAdd also returns 24 bytes: x8 on arm64, the hidden pointer on x86. Full-register handlers, as above. */
typedef struct { int64_t value; int32_t timescale; uint32_t flags; int64_t epoch; } a2x_cmtime;
typedef struct { double a, b, c, d, tx, ty; } a2x_xform;
void __arm2x86_abi_CMTimeGetSeconds(void) {
    static double (*f)(a2x_cmtime); if (!f) f = a2x_need("CMTimeGetSeconds");
    double r = f(*(a2x_cmtime *)A2X_RX(0)); memset(__arm2x86_rf + 80, 0, 16); A2X_VD(0) = r;
}
void __arm2x86_abi_CMTimeAdd(void) {
    static a2x_cmtime (*f)(a2x_cmtime, a2x_cmtime); if (!f) f = a2x_need("CMTimeAdd");
    *(a2x_cmtime *)A2X_RX(8) = f(*(a2x_cmtime *)A2X_RX(0), *(a2x_cmtime *)A2X_RX(1));
}
void __arm2x86_abi_CGAffineTransformEqualToTransform(void) {
    static _Bool (*f)(a2x_xform, a2x_xform); if (!f) f = a2x_need("CGAffineTransformEqualToTransform");
    A2X_RX(0) = f(*(a2x_xform *)A2X_RX(0), *(a2x_xform *)A2X_RX(1)) ? 1 : 0;
}
void __arm2x86_abi_CGRectEqualToRect(void) {
    static _Bool (*f)(a2x_r4, a2x_r4); if (!f) f = a2x_need("CGRectEqualToRect");
    a2x_r4 a = { A2X_VD(0), A2X_VD(1), A2X_VD(2), A2X_VD(3) }, b = { A2X_VD(4), A2X_VD(5), A2X_VD(6), A2X_VD(7) };
    A2X_RX(0) = f(a, b) ? 1 : 0;
}
extern void __arm2x86_call_rf(unsigned long imp);   /* IR door (xlat.py): x0..x7,v0..v7 from rf -> fn -> x0,v0 back */
void __arm2x86_ensure_stack(void);                    /* xlat main.c: give this thread an arm64 stack if it has none */
struct imp_ctx { unsigned long imp; ffi_cif cif; ffi_type *at[A2X_MAXARG]; const char *aenc[A2X_MAXARG]; int na; ffi_type *rt; char *types; };

static void imp_handler(ffi_cif *cif, void *ret, void **args, void *ud) {
    struct imp_ctx *c = ud; (void)cif;
    __arm2x86_ensure_stack();
    unsigned char saved[208] __attribute__((aligned(16))); memcpy(saved, __arm2x86_rf, sizeof saved);   /* reentrancy */
    memset(__arm2x86_rf, 0, sizeof saved);
    unsigned long sp0 = __arm_sp;
    /* pass 1: registers; collect stack arguments */
    int ngrn = 0, nsrn = 0; unsigned char stk[512] __attribute__((aligned(16))); size_t ns = 0;
    void *argument_copies[A2X_MAXARG]; unsigned n_copies = 0;
    for (int i = 0; i < c->na; i++) {
        ffi_type *ty = c->at[i]; size_t sz = ty->size, al = ty->alignment ? ty->alignment : 1;
        int isd = -1, nh = (ty->type == FFI_TYPE_STRUCT) ? hfa4(ty, &isd) : 0;
        if (ty->type == FFI_TYPE_FLOAT || ty->type == FFI_TYPE_DOUBLE) {
            if (nsrn < 8) memcpy(RV(nsrn++), args[i], sz);
            else { ns = (ns + sz - 1) & ~(sz - 1); memcpy(stk + ns, args[i], sz); ns += sz; }
        } else if (nh >= 1 && nh <= 4) {
            unsigned char *leaf[4]; size_t off = 0; int k = 0; hfa_leaves(ty, args[i], &off, leaf, &k);
            if (nsrn + nh <= 8) for (int j = 0; j < nh; j++) memcpy(RV(nsrn++), leaf[j], isd ? 8 : 4);
            else { nsrn = 8; ns = (ns + al - 1) & ~(al - 1); memcpy(stk + ns, args[i], sz); ns += (sz + 7) & ~7UL; }
        } else if (ty->type == FFI_TYPE_STRUCT && sz > 16) {   /* by reference: AAPCS64 passes a pointer to a COPY */
            void *cp = malloc(sz);
            if (!cp) die2("argument copy allocation", c->types);
            memcpy(cp, args[i], sz); argument_copies[n_copies++] = cp;
            uint64_t v = (uint64_t)cp;
            if (ngrn < 8) RX(ngrn++) = v; else { ns = (ns + 7) & ~7UL; memcpy(stk + ns, &v, 8); ns += 8; }
        } else if (ty->type == FFI_TYPE_STRUCT) {
            int w = (int)((sz + 7) / 8);
            if (ngrn + w <= 8) { memcpy(&RX(ngrn), args[i], sz); ngrn += w; }
            else { ngrn = 8; ns = (ns + al - 1) & ~(al - 1); memcpy(stk + ns, args[i], sz); ns += (sz + 7) & ~7UL; }
        } else {
            uint64_t v = 0;
            switch (ty->type) {   /* AAPCS64: the callee reads only the declared width; extend for determinism */
            case FFI_TYPE_SINT8: v = (uint64_t)(int64_t)*(int8_t *)args[i]; break;  case FFI_TYPE_UINT8: v = *(uint8_t *)args[i]; break;
            case FFI_TYPE_SINT16: v = (uint64_t)(int64_t)*(int16_t *)args[i]; break; case FFI_TYPE_UINT16: v = *(uint16_t *)args[i]; break;
            case FFI_TYPE_SINT32: v = (uint64_t)(int64_t)*(int32_t *)args[i]; break; case FFI_TYPE_UINT32: v = *(uint32_t *)args[i]; break;
            default: memcpy(&v, args[i], 8);
            }
            if (ngrn < 8) RX(ngrn++) = v; else { ns = (ns + sz - 1) & ~(sz - 1); memcpy(stk + ns, &v, sz); ns += sz; }
        }
        if (ns > sizeof stk - 64) die2("more than 448 bytes of stack arguments", c->types);
    }
    if (ns) { unsigned long sp = (sp0 - ns) & ~15UL; memcpy((void *)sp, stk, ns); __arm_sp = sp; }
    /* 10-20 A SMALL STRUCT RETURN CAN STILL BE A MEMORY RETURN, AND x8 ARRIVED AS 0. The rule here was
          "struct larger than 16 bytes -> x8", which is only half of AAPCS64: a Composite Type that is NOT
          trivially copyable (a C++ class with a copy constructor or a destructor) is returned in memory at
          ANY size. Finder's -[TRunAfterHelper postFunctor:delayInSec:onMainThread:] is encoded
          `{TNSWeakPtr<TRunAfterHelper>=@}36@0:8^v16d24B32` — an EIGHT byte struct — and its arm64 code saves
          x8 on entry (`mov x20, x8`) and hands it to the next call, because TNSWeakPtr holds a weak
          reference and has both. With x8 left 0, that callee's `str xzr, [x19]` wrote to address 0 and
          Finder died with SIGSEGV in fn_10011b484+0x8b.
        THE TYPE ENCODING CANNOT TELL US. Measured on a genuine macOS 27 Mac: a trivially copyable
          {Trivial=^v} and a non-trivially-copyable {NonTrivial=^v} both encode as `{X=^v}16@0:8`, and the
          first comes back in x0 while the second comes back through x8. Identical strings, opposite ABIs.
        So the callee is ASKED instead: give every non-HFA struct return a buffer in x8 and see whether the
          callee wrote through it. A buffer is cheap and a callee that ignores x8 is unharmed by one.
        AND THE SIGNAL IS THE BUFFER, NOT x0. The first version of this read x0, because AAPCS64 describes
          the result block's address as being returned there and an oracle built at -O0 agreed. ops/objcabi
          then measured all four levels: at -O1, -O2 and -Oz the same method writes through x8 and leaves x0
          alone, so trusting x0 takes the wrong branch in optimized code — which is every real program.
          A write to this buffer IS sound: the callee runs on the arm64 stack, so the only way it can reach
          imp_handler's own x86 stack is through the x8 we just handed it. x0 is kept only as a second
          positive signal, since it does hold at -O0. */
    int sret = 0;
    static const unsigned char A2X_SRET_POISON[16] = {
        0xA5, 0xC3, 0x5E, 0x11, 0xD0, 0x6B, 0x47, 0x92, 0xA5, 0xC3, 0x5E, 0x11, 0xD0, 0x6B, 0x47, 0x92 };
    unsigned char sbuf[16] __attribute__((aligned(16)));
    if (c->rt->type == FFI_TYPE_STRUCT) { int isd_ = -1, nh_ = hfa4(c->rt, &isd_);
        if (!(nh_ >= 1 && nh_ <= 4)) {
            if (c->rt->size > 16) { RX(8) = (uint64_t)ret; sret = 1; }   /* AAPCS64: x8 = result buffer */
            else { memcpy(sbuf, A2X_SRET_POISON, sizeof sbuf); RX(8) = (uint64_t)sbuf; sret = 2; }
        } }
    __arm2x86_call_rf(c->imp);
    for (unsigned i = 0; i < n_copies; ++i) free(argument_copies[i]);
    __arm_sp = sp0;
    ffi_type *rt = c->rt;
    if (rt->type != FFI_TYPE_VOID) {
        if (rt->type == FFI_TYPE_FLOAT || rt->type == FFI_TYPE_DOUBLE) memcpy(ret, RV(0), rt->size);
        else if (rt->type == FFI_TYPE_STRUCT) {
            int isd = -1, nh = hfa4(rt, &isd);
            if (nh >= 1 && nh <= 4) {   /* HFA: element j is the low 4/8 bytes of vj */
                unsigned char *leaf[4]; size_t off = 0; int k = 0; hfa_leaves(rt, ret, &off, leaf, &k);
                for (int j = 0; j < nh; j++) memcpy(leaf[j], RV(j), isd ? 8 : 4);
            } else if (sret == 1) {
                /* the callee wrote the result through x8 into ret already */
                a2x_sret_via_x8 = 1;
            } else if (sret == 2 && (memcmp(sbuf, A2X_SRET_POISON, rt->size) != 0 || RX(0) == (uint64_t)sbuf)) {
                memcpy(ret, sbuf, rt->size);   /* not trivially copyable: it came back through x8 */
                a2x_sret_via_x8 = 1;           /* 10-21 and tell msg_send, so the CALLER's x8 gets it too */
            } else {   /* <= 16 bytes: x0 then x1 */
                a2x_sret_via_x8 = 0;
                memcpy(ret, &RX(0), rt->size > 8 ? 8 : rt->size);
                if (rt->size > 8) memcpy((unsigned char *)ret + 8, &RX(1), rt->size - 8);
            }
        } else { ffi_arg v = (ffi_arg)RX(0); memcpy(ret, &v, sizeof v); }   /* libffi wants integer returns as ffi_arg */
    }
    memcpy(__arm2x86_rf, saved, sizeof saved);
}

/* 10-28 A NATIVE CALLER ENTERING A RAW GUEST IMP WITH A MEMORY (sret) RETURN SHIFTED EVERY ARGUMENT BY ONE.
      A guest class that libobjc realized in place keeps the guest's own IMPs, so AppKit's objc_msgSend_stret lands on
      guest code through the universal trampoline (host.c recover_guest_call), which mapped rdi->x0 blindly. For a
      method returning a struct > 16 bytes (NSRect from -splitView:effectiveRect:forDrawnRect:ofDividerAtIndex:) rdi is
      the RESULT BUFFER, so the guest got self = a native stack address, _cmd = self, arg2 = _cmd (measured in App Store:
      x0 = rbx = 0x7ff7bfef9368 on the native stack, x2 = a SEL), and objc_retain(x0) faulted reading its isa.
    No signature at the fault, so the IMP itself is the key: a table filled at registration from the guest class's
      own method lists (see below). info: [0] 1 memory / 2 HFA-in-memory,
      [1] size, [2] ffi_type*. Anything unproven returns 0 and the old register mapping stands. */
/* 10-28 23:4x THE FIRST PROBE ASKED THE RUNTIME (object_getClass + class_getInstanceMethod) FROM INSIDE A
      NATIVE->GUEST ENTRY, and a native caller can be libobjc itself mid-lookup: Terminal and Console died in
      objc_lookUpImpOrForward (A/B: without the probe ALIVE 2/2, with it rc=139 2/2). The answer is now read once,
      at registration, off the guest class's own method lists, and the probe is a table lookup that calls nothing.
    Only in-place classes keep raw guest IMPs (twins get make_imp wrappers), so they are the ones scanned. */
/* 11-05 r14i: A NATIVE CALLER PASSING A STRUCT WIDER THAN 16 BYTES BY VALUE TO A RAW GUEST IMP. x86-64 puts it in memory on the
      stack; arm64 puts an all-float struct of up to 4 leaves in v registers and anything else behind a pointer. The trampoline
      copied xmm0-7 to v0-7, so the guest read stale registers. Measured: MenuBarCore.DisplayItemAppKitWindow
      -constrainFrameRect:toScreen: was asked for {0,1050,1920,30} and AppKit received {0,1920,0,0}, then {1920,nan}: uncaught
      NSInternalInconsistencyException in _reallySetFrame:, no menu bar contents.
      The layout is read from the method's own encoding at registration with no runtime call and no parse_type (which aborts on
      types only a pointer carries). An encoding this reader does not fully understand gets no entry and keeps the old mapping. */
#define A2X_BV_N 8192u
#define A2X_BV_ARGS 12
enum { A2X_BV_INT, A2X_BV_D, A2X_BV_F, A2X_BV_HFAMEM, A2X_BV_HFAREG, A2X_BV_IND, A2X_BV_GPW };
struct a2x_bv_arg { unsigned char k, n, isd; unsigned short size; };
struct a2x_bv_e { unsigned long imp; unsigned char n; struct a2x_bv_arg a[A2X_BV_ARGS]; };
static struct a2x_bv_e a2x_bv_tab[A2X_BV_N];
static unsigned a2x_bv_n;
/* leaves of a struct's text: *nd doubles, *nf floats, *nw 8-byte integer or pointer words. 0 = something else is in it. */
static int a2x_bv_leaves(const char *t, const char *end, int *nd, int *nf, int *nw) {
    while (t < end) {
        char c = *t;
        if (c == '{') {
            int depth = 0; const char *q = t;
            do { if (*q == '{') depth++; else if (*q == '}') depth--; else if (!*q) return 0; q++; } while (depth);
            const char *eq = t + 1;
            while (eq < q && *eq != '=' && *eq != '{' && *eq != '}') eq++;
            if (eq >= q || *eq != '=') return 0;
            if (!a2x_bv_leaves(eq + 1, q - 1, nd, nf, nw)) return 0;
            t = q;
        } else if (c == 'd') { (*nd)++; t++; }
        else if (c == 'f') { (*nf)++; t++; }
        else if (c == 'q' || c == 'Q' || c == 'l' || c == 'L' || c == '@' || c == '#' || c == ':' || c == '*') { (*nw)++; t++; }
        else return 0;
    }
    return 1;
}
static void a2x_bv_put(unsigned long imp, const char *ty) {
    if (!imp || !ty || !strchr(ty, '{')) return;
    const char *t = skip_type(ty);
    if (!t) return;
    struct a2x_bv_e e; memset(&e, 0, sizeof e); e.imp = imp;
    int idx = 0, gi = 2, fi = 0, mem = 0;
    for (;;) {
        while (*t >= '0' && *t <= '9') t++;
        if (*t == '-') { t++; while (*t >= '0' && *t <= '9') t++; }
        while (*t && strchr("rnNoORV", *t)) t++;
        if (!*t) break;
        const char *nx = skip_type(t);
        if (!nx || nx == t) return;
        if (idx++ < 2) { if (idx == 1 ? *t != '@' && *t != '#' : *t != ':') return; t = nx; continue; }
        if (e.n >= A2X_BV_ARGS) return;
        struct a2x_bv_arg *a = &e.a[e.n++];
        char c = *t;
        if (c == '{') {
            const char *eq = t + 1;
            while (eq < nx && *eq != '=' && *eq != '{' && *eq != '}') eq++;
            if (eq >= nx || *eq != '=') return;
            int nd = 0, nf = 0, nw = 0;
            if (!a2x_bv_leaves(eq + 1, nx - 1, &nd, &nf, &nw)) return;
            int fp = nd + nf, size = nd * 8 + nf * 4 + nw * 8;
            if ((nd && nf) || (fp && nw) || !size || size > 4096) return;
            a->size = (unsigned short)size; a->isd = nd > 0; a->n = (unsigned char)fp;
            if (size > 16) {
                mem = 1;
                if (fp >= 1 && fp <= 4) { a->k = A2X_BV_HFAMEM; fi += fp; }
                else { a->k = A2X_BV_IND; gi++; }
            } else if (fp) { a->k = A2X_BV_HFAREG; fi += fp; }
            else { a->k = A2X_BV_GPW; a->n = (unsigned char)nw; gi += nw; }
        } else if (c == 'd') { a->k = A2X_BV_D; fi++; }
        else if (c == 'f') { a->k = A2X_BV_F; fi++; }
        else if (strchr("cislqCISLQB@#:*^", c)) { a->k = A2X_BV_INT; gi++; }
        else return;
        if (gi > 8 || fi > 8) return;
        t = nx;
    }
    if (!mem) return;
    if (a2x_bv_n >= A2X_BV_N / 2) {
        static int said; if (!said) { said = 1; fprintf(stderr, "objc_bridge: by-value table full (%u), later IMPs keep the old entry mapping\n", a2x_bv_n); }
        return;
    }
    unsigned h = (unsigned)(imp >> 2) & (A2X_BV_N - 1);
    while (a2x_bv_tab[h].imp && a2x_bv_tab[h].imp != imp) h = (h + 1) & (A2X_BV_N - 1);
    if (a2x_bv_tab[h].imp == imp) return;
    e.imp = 0; memcpy(&a2x_bv_tab[h], &e, sizeof e);
    __atomic_store_n(&a2x_bv_tab[h].imp, imp, __ATOMIC_RELEASE);   /* the key last */
    a2x_bv_n++;
    if (A2X_DBGENV("ARM2X86_TRACE_SRET")) fprintf(stderr, "[byval] imp %#lx %s\n", imp, ty);
}
/* Called from the trampoline: a table lookup, then register and stack reads only. gpr = rdi rsi rdx rcx r8 r9, stack = the word
   above the return address, xmm = 8 x 16 bytes as they arrived. Fills x0.. and v0.. exactly as AAPCS64 expects. */
int a2x_tramp_byval(unsigned long imp, int is_sret, const unsigned long *gpr, const unsigned long *stack, const unsigned char *xmm, unsigned long *xs, unsigned char *vs) {
    if (!a2x_bv_n) return 0;
    unsigned h = (unsigned)(imp >> 2) & (A2X_BV_N - 1); const struct a2x_bv_e *e = 0;
    for (unsigned k = 0; k < A2X_BV_N; k++, h = (h + 1) & (A2X_BV_N - 1)) {
        unsigned long v = __atomic_load_n(&a2x_bv_tab[h].imp, __ATOMIC_ACQUIRE);
        if (!v) return 0;
        if (v == imp) { e = &a2x_bv_tab[h]; break; }
    }
    if (!e) return 0;
    int g = is_sret ? 1 : 0, xi = 0, fi = 0, ai = 0; const unsigned long *s = stack;
    xs[ai++] = gpr[g++]; xs[ai++] = gpr[g++];
    for (int i = 0; i < e->n; i++) {
        const struct a2x_bv_arg *a = &e->a[i];
        switch (a->k) {
        case A2X_BV_INT: xs[ai++] = g < 6 ? gpr[g++] : *s++; break;
        case A2X_BV_D: case A2X_BV_F: {
            memset(vs + 16 * fi, 0, 16);
            if (xi < 8) memcpy(vs + 16 * fi, xmm + 16 * xi++, 8); else memcpy(vs + 16 * fi, s++, 8);
            fi++; break; }
        case A2X_BV_HFAMEM: {
            const unsigned char *m = (const unsigned char *)s; int w = a->isd ? 8 : 4;
            for (int j = 0; j < a->n; j++, fi++) { memset(vs + 16 * fi, 0, 16); memcpy(vs + 16 * fi, m + j * w, w); }
            s += (a->size + 7) / 8; break; }
        case A2X_BV_HFAREG: {
            int words = (a->size + 7) / 8, w = a->isd ? 8 : 4; unsigned char tmp[16];
            if (xi + words <= 8) { for (int j = 0; j < words; j++) memcpy(tmp + 8 * j, xmm + 16 * xi++, 8); }
            else { memcpy(tmp, s, 8 * words); s += words; }
            for (int j = 0; j < a->n; j++, fi++) { memset(vs + 16 * fi, 0, 16); memcpy(vs + 16 * fi, tmp + j * w, w); }
            break; }
        case A2X_BV_IND: xs[ai++] = (unsigned long)s; s += (a->size + 7) / 8; break;
        case A2X_BV_GPW:
            if (g + a->n <= 6) { for (int j = 0; j < a->n; j++) xs[ai++] = gpr[g++]; }
            else { for (int j = 0; j < a->n; j++) xs[ai++] = *s++; }
            break;
        }
    }
    return 1;
}
#define A2X_SRET_N 16384u
struct a2x_sret_e { unsigned long imp, kind, size, rt; };
static struct a2x_sret_e a2x_sret_tab[A2X_SRET_N];
static unsigned a2x_sret_n;
static int is_arm(unsigned long a);
static void a2x_sret_put(unsigned long imp, const char *ty) {
    a2x_bv_put(imp, ty);
    ffi_type *rt = 0;
    /* 10-29 parse_type leaves a plain struct UNLAID (size 0; libffi lays it at prep time), so `size <= 16` refused
          EVERY struct and the table stayed empty: measured 0 entries in Shortcuts with 9 struct returns in its lists. */
    if (!imp || !ty || !*ty || !parse_type(ty, &rt) || !rt || rt->type != FFI_TYPE_STRUCT) return;
    lay(rt);
    /* A C++ class that is not trivially copyable is returned through the hidden pointer whatever its size, on both
       architectures: a shared_ptr is 16 bytes and still arrives as x8 on arm64 and rdi on x86-64. The encoding names
       the class, so the ones the standard library defines are recognised by name. */
    int cxxmem = 0;
    if (rt->size <= 16 && ty[0] == '{') {
        const char *eq = strchr(ty, '='); size_t nl = eq ? (size_t)(eq - ty) : strlen(ty); char nm_[160];
        if (nl >= sizeof nm_) nl = sizeof nm_ - 1;
        memcpy(nm_, ty, nl); nm_[nl] = 0;
        static const char *const cxx[] = { "shared_ptr<", "unique_ptr<", "weak_ptr<", "basic_string<", "vector<", "function<",
                                           "map<", "set<", "list<", "deque<", "unordered_", "RetainPtr<" };
        for (unsigned ci = 0; ci < sizeof cxx / sizeof cxx[0]; ci++) if (strstr(nm_, cxx[ci])) { cxxmem = 1; break; }
    }
    if (rt->size <= 16 && !cxxmem) return;
    if (a2x_sret_n >= A2X_SRET_N / 2) {
        static int said; if (!said) { said = 1; fprintf(stderr, "objc_bridge: sret table full (%u), later memory-return IMPs keep the old entry mapping\n", a2x_sret_n); }
        return;
    }
    unsigned h = (unsigned)(imp >> 2) & (A2X_SRET_N - 1);
    while (a2x_sret_tab[h].imp && a2x_sret_tab[h].imp != imp) h = (h + 1) & (A2X_SRET_N - 1);
    if (a2x_sret_tab[h].imp == imp) return;
    int isd = -1, nh = hfa4(rt, &isd);
    /* kind 3: 16 bytes or fewer, written through x8 by the method, read from two registers by a caller that only
       knows the encoding (key-value coding, an invocation). Arguments are not shifted for it. */
    a2x_sret_tab[h].kind = cxxmem ? 3 : (nh >= 1 && nh <= 4) ? 2 : 1; a2x_sret_tab[h].size = rt->size; a2x_sret_tab[h].rt = (unsigned long)rt;
    __atomic_store_n(&a2x_sret_tab[h].imp, imp, __ATOMIC_RELEASE);   /* the key last: a reader that sees it sees the rest */
    a2x_sret_n++;
    if (A2X_DBGENV("ARM2X86_TRACE_SRET")) fprintf(stderr, "[sret] imp %#lx size %zu %s %s\n", imp, rt->size, nh >= 1 && nh <= 4 ? "hfa" : "x8", ty);
}
/* same method_list_t reader as add_methods: relative lists (bit 31) hold int32 offsets {name, types, imp} */
static void a2x_sret_scan_list(unsigned long ml) {
    if (!ml || !is_arm(ml)) return;
    uint32_t ef = *(uint32_t *)ml, n = *(uint32_t *)(ml + 4), es = ef & 0xFFFC;
    if (!es || n > 65536) return;
    for (uint32_t i = 0; i < n; i++) {
        unsigned long e = ml + 8 + (unsigned long)i * es;
        if (ef & 0x80000000u) a2x_sret_put(e + 8 + *(int32_t *)(e + 8), (const char *)(e + 4 + *(int32_t *)(e + 4)));
        else a2x_sret_put(*(unsigned long *)(e + 16), *(const char **)(e + 8));
    }
}
/* 10-30 EVERY class_ro_t THE IMAGE OWNS, NOT ONLY THE CLASSES THE REGISTRATION PATHS HAPPEN TO TOUCH.
      App Store ShelfPagingControlsView: ro 0x1005bbcf8 (flags 0x184, name _TtC9App_Store23ShelfPagingControlsView)
      sits in __DATA,__objc_data beside its metadata, the class is NOT in __objc_classlist, no swift_updateClassMetadata
      ran for it, and its baseMethods list (0x1005bbba0, 14 entries, entsize 24) holds the -frame IMP 0x100017514
      {CGRect=..}16@0:8. The table is keyed on the IMP, so it does not matter when or where the class is instantiated:
      find the ro structures themselves. A class_ro_t is recognised by its name field (+0x18) pointing into the image's
      __objc_classname section, which no other structure in these sections does at that offset except a category's
      protocol slot; baseMethods (+0x20) must then look like a method list (entsize 12 relative or 24 absolute, a sane
      count) before anything is read from it. Metaclass ro_ts match the same way, so class methods are covered. */
void __arm2x86_objc_ro_sweep(unsigned long na, unsigned long nn, unsigned long c0, unsigned long cn,
                             unsigned long d0, unsigned long dn) {
    unsigned before = a2x_sret_n, seen = 0;
    if (!na || !nn) return;
    for (int sec = 0; sec < 2; sec++) {
        unsigned long a0 = sec ? d0 : c0, n = sec ? dn : cn;
        if (!a0 || n < 0x28) continue;
        for (unsigned long a = a0; a + 0x28 <= a0 + n; a += 8) {
            unsigned long nm = *(unsigned long *)(a + 0x18);
            if (nm < na || nm >= na + nn) continue;
            unsigned long ml = *(unsigned long *)(a + 0x20);
            if (!ml || (ml & 3) || !is_arm(ml)) continue;
            uint32_t ef = *(uint32_t *)ml, cnt = *(uint32_t *)(ml + 4), es = ef & 0xFFFC;
            if ((es != 12 && es != 24) || !cnt || cnt > 8192) continue;
            seen++;
            a2x_sret_scan_list(ml);
        }
    }
    if (A2X_DBGENV("ARM2X86_TRACE_SRET"))
        fprintf(stderr, "[sret] ro sweep: %u class_ro_t method lists read, table %u -> %u\n", seen, before, a2x_sret_n);
}
/* an UNREALIZED class: bits (+0x20, low flag bits masked) is its class_ro_t, and ro+0x20 is baseMethods */
static int a2x_readable(const void *p);
/* A Swift class whose metadata the runtime instantiates lives on the heap, not in the image: only its class_ro_t is in
   the image. App Store ShelfPagingControlsView (slot 0x7fe5bc928088, twin_of_guest 0, size 1256): the guest -frame
   override (IMP 0x100017514, a `[super frame]` thunk, encoding {CGRect=..}16@0:8) was never entered in a2x_sret_tab
   although 62 other memory-return IMPs were, because this scan required the CLASS address itself to be inside the
   arm64 image (is_arm(k)). AppKit -[NSView(NSSafeAreas) computedSafeAreaInsets] then reached it through
   objc_msgSend_stret, the probe missed, nothing shifted, and the guest's self was the result buffer. */
static int a2x_sret_class_ok(unsigned long k) {
    return k && !(k & 7) && (is_arm(k) || (a2x_readable((void *)k) && a2x_readable((char *)k + 0x28)));
}
static void a2x_sret_scan_class(unsigned long c) {
    if (!a2x_sret_class_ok(c)) return;
    for (int meta = 0; meta < 2; meta++) {
        unsigned long k = meta ? *(unsigned long *)c : c;
        if (!a2x_sret_class_ok(k)) continue;
        unsigned long ro = *(unsigned long *)(k + 0x20) & 0x7ffffffffff8UL;
        if (is_arm(ro)) a2x_sret_scan_list(*(unsigned long *)(ro + 0x20));
    }
}
/* the entry stub's word that a guest method wrote its small result through x8: the sender copies it to its own x8 */
void a2x_tramp_result_via_x8(void) { a2x_sret_via_x8 = 1; }
int a2x_tramp_sret_probe(unsigned long rsi, unsigned long rdx, unsigned long imp, unsigned long *info) {
    (void)rsi; (void)rdx;
    if (!a2x_sret_n) return 0;
    unsigned h = (unsigned)(imp >> 2) & (A2X_SRET_N - 1);
    for (unsigned k = 0; k < A2X_SRET_N; k++, h = (h + 1) & (A2X_SRET_N - 1)) {
        unsigned long v = __atomic_load_n(&a2x_sret_tab[h].imp, __ATOMIC_ACQUIRE);
        if (!v) return 0;
        if (v == imp) { info[0] = a2x_sret_tab[h].kind; info[1] = a2x_sret_tab[h].size; info[2] = a2x_sret_tab[h].rt; return 1; }
    }
    return 0;
}
/* an HFA result goes from v0..v3 into the caller's buffer; a non-HFA one was written through x8 (= the buffer) already */
void a2x_tramp_sret_store(const unsigned long *info, void *buf, const unsigned char *vs) {
    if (info[0] != 2) return;
    ffi_type *rt = (ffi_type *)info[2]; int isd = -1, nh = hfa4(rt, &isd);
    unsigned char *leaf[4]; size_t off = 0; int k = 0; hfa_leaves(rt, (unsigned char *)buf, &off, leaf, &k);
    for (int j = 0; j < nh && j < k; j++) memcpy(leaf[j], vs + 16 * j, isd ? 8 : 4);
}

/* rung 6 (10-03 review): __cxa_atexit WITHOUT the callback pool. Cyberpunk makes 109,941 static-destructor registrations
 *    through at least 3,294 distinct functions (measured off its disassembly); the 2,048-slot trampoline pool would abort
 *    before the first frame. Each registration becomes a heap record {fn, obj} under ONE native handler, which runs the
 *    arm64 destructor through the register-file door. dso passes through untouched (libSystem groups by it, __cxa_finalize). */
struct atx { unsigned long fn, obj; };
extern int __cxa_atexit(void (*)(void *), void *, void *);
static void atx_run(void *p) {
    struct atx *r = p;
    __arm2x86_ensure_stack();
    unsigned char saved[208] __attribute__((aligned(16))); memcpy(saved, __arm2x86_rf, sizeof saved);   /* reentrancy */
    memset(__arm2x86_rf, 0, sizeof saved); RX(0) = r->obj;
    __arm2x86_call_rf(r->fn);
    memcpy(__arm2x86_rf, saved, sizeof saved);
    free(r);
}
int __arm2x86_cxa_atexit(unsigned long fn, unsigned long obj, unsigned long dso) {
    if (!in_text(fn)) return __cxa_atexit((void (*)(void *))fn, (void *)obj, (void *)dso);   /* NULL or native: as is */
    struct atx *r = malloc(sizeof *r);
    if (!r) { fprintf(a2x_errf(), "FATAL: [xlat] __cxa_atexit record: out of memory\n"); a2x_stop("out of memory", "exit handler record"); abort(); }
    r->fn = fn; r->obj = obj;
    return __cxa_atexit(atx_run, r, (void *)dso);
}

/* 10-20 libffi's own ffi_closure_alloc asks for an anonymous W+X mapping, and macOS 27 refuses it in some
      processes: the translated mbsystemadministration (Setup Assistant's daemon) died registering its first method
      ("FATAL: objc_bridge: ffi closure isInClamshellMode"), the springboard waited on it forever, and loginwindow never
      got past 60%. 10-13 fixed the same refusal for loginwindow/WindowServer alone with libffj.dylib's MAP_JIT
      allocator; this is that allocator inside the bridge, so every translated program has it. On x86_64 a MAP_JIT
      region is plainly RWX (the write-protect toggle is an arm64 rule), which is exactly what ffi_prep_closure_loc
      needs: it writes the trampoline through the same pointer the trampoline is called at. Closures are never freed
      (one per method, registered once), so a bump arena is the whole allocator. libffi stays the fallback. */
#include <errno.h>
/* The arenas stay on a list so __arm2x86_objc_imp_target() below can recognise one of our own
      closures by address. `used` only ever grows and `base` never moves, so an unlocked reader can
      at worst read a stale `used` and miss a closure created this instant — it can never invent one. */
#define A2X_ARENAS 64
static struct { char *base; size_t used; } gArena[A2X_ARENAS];
static int gNArena;
static ffi_closure *a2x_closure_alloc(void **code) {
    static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    static char *arena; static size_t used, cap;
    const size_t sz = (sizeof(ffi_closure) + 15) & ~(size_t)15;
    pthread_mutex_lock(&mu);
    if (!arena || used + sz > cap) {
        size_t n = 1 << 20;
        void *m = mmap(NULL, n, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
        if (m == MAP_FAILED) {
            int e = errno; pthread_mutex_unlock(&mu);
            ffi_closure *f = ffi_closure_alloc(sizeof(ffi_closure), code);
            if (!f) fprintf(a2x_errf(), "objc_bridge: MAP_JIT closure arena refused (errno %d) and libffi's allocator too\n", e);
            return f;
        }
        arena = m; used = 0; cap = n;
        if (gNArena < A2X_ARENAS) { gArena[gNArena].base = arena; gNArena++; }
        else fprintf(a2x_errf(), "objc_bridge: more than %d closure arenas — an IMP called from translated "
                                 "code will not be recognised\n", A2X_ARENAS);
    }
    ffi_closure *c = (ffi_closure *)(arena + used); used += sz;
    /* the record for THIS arena is the last one appended while `arena` has not changed */
    if (gNArena && gArena[gNArena - 1].base == arena) gArena[gNArena - 1].used = used;
    pthread_mutex_unlock(&mu);
    *code = c;
    return c;
}

/* 10-20 A TRANSLATED INDIRECT CALL CAN LAND ON ONE OF OUR OWN IMP CLOSURES. SystemUIServer does
      `IMP imp = [obj methodForSelector:sel]; imp(obj, sel);` — in the genuine arm64 binary that is
      fn_10000b2f8's `bl _objc_msgSend` / `mov x8, x0` / `blraaz x8` — so the real ObjC runtime hands
      the translated program back the closure make_imp() registered for that method, and the translated
      `blr` then asks __arm2x86_dispatch for an "arm64 address" that was never one.
    MEASURED: "__arm2x86_dispatch: no entry for 0x1018c0510 in a 3451-entry map", called from
      fn_10000b2f8+8047, and SystemUIServer aborted inside -[NSApplication run]. The closure arena is
      anonymous MAP_JIT memory, so __arm2x86_lookup's native-pointer rung could not save it either:
      dyld_image_header_containing_address() only knows about loaded images.
    The answer is the arm64 IMP the closure wraps, NOT an ffi call into it: the translated caller has
      already laid the arguments out per AAPCS64, which is exactly the contract that arm64 IMP expects,
      so going through libffi would re-marshal registers that are already right.
    ->fun is the proof of ownership: only our closures run imp_handler, so a stray pointer that merely
      happens to sit in an arena slot cannot be mistaken for a method. */
unsigned long __arm2x86_objc_imp_target(unsigned long t) {
    if (!t || (t & 15)) return 0;                                   /* every arena slot is 16-byte aligned */
    for (int i = 0; i < gNArena; i++) {
        char *b = gArena[i].base;
        if (!b || t < (unsigned long)b || t >= (unsigned long)b + gArena[i].used) continue;
        ffi_closure *cl = (ffi_closure *)t;
        if (cl->fun != imp_handler) return 0;
        struct imp_ctx *c = cl->user_data;
        return c ? c->imp : 0;
    }
    return 0;
}

static IMP make_imp(unsigned long armimp, const char *types, const char *selname) {
    struct imp_ctx *c = calloc(1, sizeof *c); c->imp = armimp;
    /* 10-20 WAS strncpy into char[256]: a longer encoding was cut mid-type and parsed as a different signature */
    c->types = strdup(types);
    const char *t = parse_type(c->types, &c->rt);
    /* 10-26 THE FRAME SIZE IS READ, NOT SKIPPED. With the per-argument offsets below it is the only thing
          in a method encoding that measures a type clang wrote no width for, and a2x_lane's 16 bytes is a
          measurement that has to be checkable. The last argument is measured against this. */
    unsigned long frame = 0;
    while (*t >= '0' && *t <= '9') frame = frame * 10 + (unsigned long)(*t++ - '0');
    int lane_arg = -1; unsigned long lane_off = 0; size_t lane_sz = 0;   /* the last argument that held a lane */
    while (*t) {
        if (c->na == A2X_MAXARG) die2("too many arguments for the bridge", selname);
        c->aenc[c->na] = skipq(t);
        a2x_lane_used = 0;
        t = parse_type(t, &c->at[c->na]);
        int haveoff = (*t >= '0' && *t <= '9');
        unsigned long off = 0;
        while (*t >= '0' && *t <= '9') off = off * 10 + (unsigned long)(*t++ - '0');
        /* this argument's offset closes the measurement the PREVIOUS lane argument opened */
        if (lane_sz && haveoff && off > lane_off) { ffi_type *fx = a2x_lane_check(selname, c->types, lane_arg, lane_sz, off - lane_off); if (fx) c->at[lane_arg] = fx; }
        lane_sz = 0;
        if (a2x_lane_used && haveoff) { lane_arg = c->na; lane_off = off; lane_sz = c->at[c->na]->size; }
        c->na++;
    }
    /* a lane in the LAST argument is measured against the frame size, which is where the frame ends */
    if (lane_sz && frame > lane_off) { ffi_type *fx = a2x_lane_check(selname, c->types, lane_arg, lane_sz, frame - lane_off); if (fx) c->at[lane_arg] = fx; }
    /* 10-03 every AAPCS64 struct return is carried now (@__arm_xr brings x1 and v1-v3 back, takes x8 in):
       HFA of 1-4 in v0-v3, any other struct of <= 16 bytes in x0:x1, a larger one through the x8 buffer.
        WAS: only nh == 1 or <= 8 bytes — Cyberpunk's -windowResolution (a size) stopped the first launch.
        10-20 a `nh > 4` die2 stood here and killed Dock on `previewRect` (6 doubles). hfa4() now calls that
          NOT an HFA, which is what AAPCS64 says, and the x8 path above already carries it — nothing left to refuse. */
    if (ffi_prep_cif(&c->cif, FFI_DEFAULT_ABI, (unsigned)c->na, c->rt, c->at) != FFI_OK) die2("ffi_prep_cif (closure)", selname);
    void *code = NULL; ffi_closure *cl = a2x_closure_alloc(&code);
    if (!cl || ffi_prep_closure_loc(cl, &c->cif, imp_handler, c, code) != FFI_OK) die2("ffi closure", selname);
    return (IMP)code;
}

/* 10-20 THE C++ IVARS OF A TRANSLATED CLASS WERE NEVER CONSTRUCTED. 996 of Finder's 1,742 classes
      carry RO_HAS_CXX_STRUCTORS, and the runtime decides whether to run .cxx_construct from THAT flag in
      the class_ro_t — not from the method list. objc_allocateClassPair() builds a fresh class_ro_t without
      it and no API can set it, so for every class this bridge rebuilds, the runtime installed our
      .cxx_construct and then never called it, leaving every C++ ivar zeroed.
    MEASURED: Finder died with SIGSEGV at address 0 in fn_100145ad8+0x80, which is
      std::__tree::__insert_node_at doing `ldr x8,[x0]; ldr x8,[x8]` — reading __begin_node_ out of a
      std::map held in an ivar at object+0x10 of TPrefsObserverBridge, while it set up global pref
      observation. An unconstructed std::map has __begin_node_ == 0; a constructed empty one never does.
      An oracle on a genuine macOS 27 Mac confirmed both halves: a normally compiled class's C++ ivar IS
      constructed, and a class built this bridge's way misses it, with .cxx_construct demonstrably installed.
    So the chain is run here instead, from a +allocWithZone: of our own (a2x_alloc_with_zone below).
    AND THE TWO SELECTORS ARE DELIBERATELY NOT REGISTERED AS METHODS. objc4 propagates hasCxxCtor from
      the superclass, so a translated class under a NATIVE class that has C++ structors DOES get its
      .cxx_construct called by the runtime — measured, "HAZARD REAL" — and with it in the method list every
      such ivar would be constructed TWICE. Keeping it out of the list leaves exactly one caller: ours. */
static int a2x_is_cxx_structor(const char *sel, int *is_ctor) {
    if (!sel || sel[0] != '.') return 0;
    if (!strcmp(sel, ".cxx_construct")) { *is_ctor = 1; return 1; }
    if (!strcmp(sel, ".cxx_destruct"))  { *is_ctor = 0; return 1; }
    return 0;
}

/* Class -> its OWN .cxx_construct closure. A linear scan would be thousands of compares per allocation
   (Finder registers 1,742 classes), so this is an open-addressed table keyed by the class pointer. */
struct a2x_ctor_ent { Class c; IMP f; char warned; };
static struct a2x_ctor_ent *gCtor; static unsigned long gCtorCap, gCtorN;
static unsigned long ctor_slot(Class c, unsigned long cap) { return ((unsigned long)(void *)c >> 4) & (cap - 1); }
static void ctor_put(Class c, IMP f) {
    if (!c || !f) return;
    if (gCtorN * 2 + 2 > gCtorCap) {                                  /* grow at 50% load */
        unsigned long ncap = gCtorCap ? gCtorCap * 2 : 1024;
        void *n = calloc(ncap, sizeof *gCtor);
        if (!n) { fprintf(a2x_errf(), "FATAL: objc_bridge: out of memory for the C++ constructor table\n"); a2x_stop("out of memory", "constructor table"); abort(); }
        struct a2x_ctor_ent *old = gCtor; unsigned long ocap = gCtorCap;
        gCtor = n; gCtorCap = ncap;
        for (unsigned long i = 0; i < ocap; i++) if (old[i].c) {
            unsigned long s = ctor_slot(old[i].c, ncap);
            while (gCtor[s].c) s = (s + 1) & (ncap - 1);
            gCtor[s] = old[i];
        }
        free(old);
    }
    unsigned long s = ctor_slot(c, gCtorCap);
    while (gCtor[s].c && gCtor[s].c != c) s = (s + 1) & (gCtorCap - 1);
    if (!gCtor[s].c) gCtorN++;
    gCtor[s].c = c; gCtor[s].f = f;
}
static struct a2x_ctor_ent *ctor_ent(Class c) {
    if (!gCtorCap || !c) return 0;
    unsigned long s = ctor_slot(c, gCtorCap);
    while (gCtor[s].c) { if (gCtor[s].c == c) return &gCtor[s]; s = (s + 1) & (gCtorCap - 1); }
    return 0;
}
static IMP ctor_get(Class c) { struct a2x_ctor_ent *e = ctor_ent(c); return e ? e->f : 0; }

/* superclass first, exactly as objc4's object_cxxConstructFromClass does, and only for classes this
      bridge built — a native class in the chain had its own constructor run by class_createInstance. */
static void a2x_cxx_construct_chain(id obj, Class c) {
    if (!c) return;
    a2x_cxx_construct_chain(obj, class_getSuperclass(c));
    IMP f = ctor_get(c);
    if (f) ((id (*)(id, SEL))f)(obj, sel_registerName(".cxx_construct"));
}
/* 10-20 THIS MUST NOT ALLOCATE THE OBJECT ITSELF. It did (class_createInstance), and a guard was then
      added that refused to install the override wherever the inherited +allocWithZone: was not NSObject's —
      which took 4 REAL Finder classes out (TBrowserWindow, TCA3PartLayer, TShrinkToFitTextView,
      TShrinkToFitWindow) and left their C++ ivars zeroed again, because NSWindow, CALayer and NSTextView all
      override +allocWithZone: WITHOUT being placeholder clusters. Allocating through the nearest inherited
      implementation covers both: a class with a native allocator is still allocated its way.
    The cluster case (NSString, NSNumber) is then caught by the object itself rather than guessed at from
      the class: a cluster hands back a PLACEHOLDER of a private class, so the ivars of self_ are only
      constructed when the object really is one of self_'s instances.
    Skipping this override while looking up the inherited one is what keeps a chain of translated classes
      from calling back into itself forever. */
static id a2x_alloc_with_zone(Class self_, SEL _cmd, void *zone) {
    IMP sup = 0;
    for (Class k = class_getSuperclass(self_); k; k = class_getSuperclass(k)) {
        IMP f = class_getMethodImplementation(object_getClass((id)k), _cmd);
        if (f && f != (IMP)a2x_alloc_with_zone) { sup = f; break; }
    }
    id o = sup ? ((id (*)(Class, SEL, void *))sup)(self_, _cmd, zone) : class_createInstance(self_, 0);
    if (!o) return o;
    Class got = object_getClass(o);
    int mine = 0;
    for (Class k = got; k; k = class_getSuperclass(k)) if (k == self_) { mine = 1; break; }
    if (mine) a2x_cxx_construct_chain(o, self_);
    else {
        struct a2x_ctor_ent *e = ctor_ent(self_);
        if (e && !e->warned) { e->warned = 1;
            fprintf(a2x_errf(), "objc_bridge: +allocWithZone: for %s returned a %s, so %s's C++ ivars are left "
                    "unconstructed (a class cluster placeholder)\n",
                    class_getName(self_), class_getName(got), class_getName(self_)); }
    }
    return o;
}

/* method_list_t: u32 entsizeAndFlags, u32 count; RELATIVE lists (bit 31) hold int32 offsets {name->selref, types, imp} */
/* class_ro_t.baseProperties (+64) -> the twin. objc_allocateClassPair builds a class with NO property list, so a
   property the guest declares @dynamic (D) was invisible to the runtime: QuartzCore's +resolveInstanceMethod: and
   Core Data both find a dynamic accessor by looking the property up on the class, and found nothing
   (AirPort Utility: BubbleTextLayer `fillColor` T^{CGColor=},&,D,N -> "no method / type encoding for setFillColor:").
   The list is image data: entsize|flags u32, count u32, then {name*, attributes*}. */
static void a2x_add_properties(Class ns, unsigned long pl) {
    if (!pl) return;
    uint32_t es = *(uint32_t *)pl & ~3u, n = *(uint32_t *)(pl + 4);
    if (es < 16 || n > 4096) return;
    for (uint32_t k = 0; k < n; k++) {
        unsigned long e = pl + 8 + (unsigned long)k * es;
        const char *nm = *(const char **)e, *at = *(const char **)(e + 8);
        if (!nm || !at || class_getProperty(ns, nm)) continue;
        char buf[1024]; objc_property_attribute_t av[16]; unsigned na = 0;
        if (strlen(at) >= sizeof buf) continue;
        strcpy(buf, at);
        for (char *c = buf; *c && na < 16; ) {
            char *v = c + 1; int depth = 0, q = 0; char *end = v;
            for (; *end && !(*end == ',' && !depth && !q); end++) {      /* split on top-level commas only */
                if (*end == '"') q = !q;
                else if (!q && (*end == '{' || *end == '(' || *end == '[')) depth++;
                else if (!q && (*end == '}' || *end == ')' || *end == ']')) depth--;
            }
            char nmc[2] = { c[0], 0 };
            int last = !*end; *end = 0;
            av[na].name = strdup(nmc); av[na].value = strdup(v); na++;
            if (last) break;
            c = end + 1;
        }
        class_addProperty(ns, nm, av, na);
        for (unsigned i = 0; i < na; i++) { free((void *)av[i].name); free((void *)av[i].value); }
    }
}
static void add_methods(Class cls, unsigned long ml, int replace, IMP *cxx_ctor_out) {
    if (!ml) return;
    uint32_t ef = *(uint32_t *)ml, n = *(uint32_t *)(ml + 4), es = ef & 0xFFFC;
    for (uint32_t i = 0; i < n; i++) {
        unsigned long e = ml + 8 + (unsigned long)i * es; SEL sel; const char *types; unsigned long imp;
        if (ef & 0x80000000u) {
            int32_t no = *(int32_t *)e, to = *(int32_t *)(e + 4), io = *(int32_t *)(e + 8);
            sel = *(SEL *)(e + no); types = (const char *)(e + 4 + to); imp = e + 8 + io;
        } else {
            sel = sel_registerName(*(const char **)e); types = *(const char **)(e + 8); imp = *(unsigned long *)(e + 16);
        }
        const char *sn = sel_getName(sel);
        /* 10-26 THIS GUARD SKIPPED EVERY METHOD THAT TAKES OR RETURNS A VECTOR, AND ITS REASONING WAS
              WRONG. It refused any encoding starting with a digit or a closing bracket on the grounds that
              "the types pointer lands inside a longer string". It does not: the pointer is correct, and so
              is the relative-method-list reader above. What those strings are is a PARSE CURSOR — Chess's
              -[MBCBoardView lightPosition] really is typed "16@0:8", because clang writes NO characters at
              all for a vector return, and "]}16@0:8" is the cursor inside {?=[4]}16@0:8 where the array's
              element should be. Both are read properly now (see a2x_lane), so skipping them here would take
              the implementation off a method the bridge can build.
            What is left is the one thing that is genuinely unusable: no encoding at all. A method with no
              type string cannot be given an IMP whatever we do, so it is named and skipped, and the window
              of bytes around the pointer stays — it is how the next surprise gets measured instead of
              guessed at. */
        if (!types || !*types) {
            fprintf(stderr, "[objc] %s %s: types is %s — this method gets no implementation\n",
                    class_getName(cls), sn, types ? "an empty string" : "NULL");
            continue;
        }
        if (A2X_DBGENV("ARM2X86_TRACE_METHODS"))
            fprintf(stderr, "[objc] %s %s types=%s (list %s, entsize %u)\n", class_getName(cls), sn, types,
                    (ef & 0x80000000u) ? "relative" : "absolute", es);
        int is_ctor = 0;
        IMP ni = make_imp(imp, types, sn);
        if (a2x_is_cxx_structor(sn, &is_ctor)) {
            /* captured, never installed — see the block above for why both halves matter */
            if (is_ctor && cxx_ctor_out) *cxx_ctor_out = ni;
            continue;
        }
        if (replace) class_replaceMethod(cls, sel, ni, types); else class_addMethod(cls, sel, ni, types);
    }
}

struct armcls { unsigned long a; Class n; int pending; unsigned long bits0; };   /* pending = a Swift class not yet realized; bits0 = its class word at +0x20 BEFORE realization (the class_ro_t) */
/* CATEGORIES ON SWIFT CLASSES WITH AN OBJC CLASS STUB (__objc_catlist2).
   A Swift class whose superclass is resilient or generic (a UIHostingController subclass, for one) has no fixed class
   object in the image. The image carries a two-word stub {1, initializer} instead, the stubs are listed in
   __objc_stublist, and a category on such a class (every @objc member of a Swift extension) is emitted into
   __objc_catlist2 with cat->cls pointing at the stub. libobjc keeps those categories unattached and attaches them when
   the Swift runtime hands it the finished class together with its stub (_objc_realizeClassFromSwift(cls, stub)).
   Here libobjc never saw the guest image, so nobody attached them: Voice Memos sent setHideTrackSwitch: to its
   _RCMultipleWaveformsViewController, whose only source for that method is such a category, and the lookup failed.
   The finished class names its stub in its Swift class descriptor (the ObjCResilientClassStubInfo trailing object), so
   the class a stub belongs to is recognised exactly, without running the stub's initializer. */
struct a2x_scat { unsigned long stub, ct; int done; };
static struct a2x_scat *gSC; static unsigned long gNSC;
static pthread_mutex_t gSCm = PTHREAD_MUTEX_INITIALIZER;
#define A2X_SCSEEN 1024                        /* classes already examined; a class's stub never changes */
static _Atomic(Class) gSCseen[A2X_SCSEEN];
static int is_arm(unsigned long a);
static void a2x_sret_scan_list(unsigned long ml);
void __arm2x86_objc_register_stubcats(unsigned long cat, unsigned long ncat) {
    for (unsigned long i = 0; i < ncat; i++) {
        unsigned long ct = ((unsigned long *)cat)[i];
        if (!ct || !is_arm(ct)) continue;
        unsigned long tg = *(unsigned long *)(ct + 8);
        const char *cn = *(const char **)ct;
        /* a stub's first word is a small integer where a class has its isa (libobjc: isStubClass, isa in 1..15) */
        if (!tg || !is_arm(tg) || *(unsigned long *)tg == 0 || *(unsigned long *)tg >= 16) {
            fprintf(a2x_errf(), "objc_bridge: __objc_catlist2 category %s targets %#lx, which is not an ObjC class stub - "
                    "its methods are NOT attached\n", cn ? cn : "(unnamed)", tg);
            continue;
        }
        a2x_sret_scan_list(*(unsigned long *)(ct + 16));
        a2x_sret_scan_list(*(unsigned long *)(ct + 24));
        pthread_mutex_lock(&gSCm);
        gSC = realloc(gSC, (gNSC + 1) * sizeof *gSC);
        gSC[gNSC].stub = tg; gSC[gNSC].ct = ct; gSC[gNSC].done = 0; gNSC++; gNSCopen++;
        pthread_mutex_unlock(&gSCm);
        if (A2X_DBGENV("ARM2X86_TRACE_REGCLS"))
            fprintf(a2x_errf(), "[stubcat] parked category %s on class stub %#lx\n", cn ? cn : "(unnamed)", tg);
    }
}
/* The stub a finished Swift class was built for, or 0. Class metadata holds its descriptor at +0x40; the descriptor is
   the fixed 0x2c-byte class header followed by trailing records in a fixed order: resilient superclass (4 bytes),
   foreign (4) or singleton (12) metadata initialization, vtable header (8) and its 8-byte method records, override
   header (4) and its 12-byte records, then the stub reference (a 4-byte relative pointer). Which records are present is
   in the kind-specific flags (high 16 bits of the first word) and in ExtraClassFlags (+0x1c, bit 0 = has a stub).
   Checked offline against every __objc_catlist2 category of Voice Memos, Journal, Books and Reminders (10 of 10). */
static unsigned long a2x_stub_of_class(Class k) {
    const unsigned long *w = (const unsigned long *)k;
    if (!(w[4] & 3)) return 0;                               /* not a Swift class: it has no descriptor word */
    unsigned long d = w[8];
    if (!d || (d & 3) || !is_arm(d)) return 0;                /* the descriptor must be the guest image's own */
    uint32_t fl = *(const uint32_t *)d, ks = fl >> 16;
    if ((fl & 0x1f) != 16 || (fl & 0x80)) return 0;           /* a class, and not a generic one (extra records) */
    if (!(ks & (1u << 13))) return 0;                         /* no resilient superclass: no stub */
    if (!(*(const uint32_t *)(d + 0x1c) & 1)) return 0;       /* ExtraClassFlags: no ObjC resilient class stub */
    unsigned long p = d + 0x2c + 4;
    if ((ks & 3) == 2) p += 4; else if ((ks & 3) == 1) p += 12;
    if (ks & (1u << 15)) { uint32_t n = *(const uint32_t *)(p + 4); if (n > 65536) return 0; p += 8 + 8UL * n; }
    if (ks & (1u << 14)) { uint32_t n = *(const uint32_t *)p; if (n > 65536) return 0; p += 4 + 12UL * n; }
    int32_t r = *(const int32_t *)p;
    return r ? p + (long)r : 0;
}
static void add_methods(Class cls, unsigned long ml, int replace, IMP *cxx_ctor_out);
/* returns 1 when a category was attached to a class in the receiver's chain during this call */
static int a2x_stubcat_poll(id rcv) {
    Class c = object_getClass(rcv);
    if (!c) return 0;
    if (class_isMetaClass(c)) c = (Class)rcv;                 /* a class receiver: examine the class itself */
    int hit = 0;
    for (Class k = c; k; k = class_getSuperclass(k)) {
        unsigned slot = (unsigned)(((unsigned long)k >> 4) * 0x9E3779B1u) % A2X_SCSEEN, seen = 0;
        for (unsigned q = 0; q < 8; q++) {
            Class s = gSCseen[(slot + q) % A2X_SCSEEN];
            if (s == k) { seen = 1; break; }
            if (!s) break;
        }
        if (seen) break;                                      /* this class and everything above it was examined */
        unsigned long stub = a2x_stub_of_class(k);
        if (stub) {
            pthread_mutex_lock(&gSCm);
            for (unsigned long i = 0; i < gNSC; i++) {
                if (gSC[i].done || gSC[i].stub != stub) continue;
                unsigned long ct = gSC[i].ct;
                gSC[i].done = 1; gNSCopen--; hit = 1;
                add_methods(k, *(unsigned long *)(ct + 16), 1, 0);
                add_methods(object_getClass((id)k), *(unsigned long *)(ct + 24), 1, 0);
                if (A2X_DBGENV("ARM2X86_TRACE_REGCLS"))
                    fprintf(a2x_errf(), "[stubcat] attached category %s to %s (%p) through class stub %#lx\n",
                            *(const char **)ct ? *(const char **)ct : "(unnamed)", class_getName(k), (void *)k, stub);
            }
            pthread_mutex_unlock(&gSCm);
        }
        for (unsigned q = 0; q < 8; q++) {
            Class expect = Nil;
            if (atomic_compare_exchange_strong(&gSCseen[(slot + q) % A2X_SCSEEN], &expect, k) || expect == k) break;
        }
    }
    return hit;
}
static struct armcls *gCls; static unsigned long gNCls;
/* 10-26 classes whose superclass has not arrived yet, carried from one image's registration call to the
      next. See __arm2x86_objc_register: waiting inside a single call cannot work, because the superclass may
      live in an image that is registered later. */
static unsigned long *gOwed; static unsigned long gNOwed;
/* 10-21 REALIZE A SWIFT CLASS LATE, NOT AT REGISTRATION — THE ORDER IS THE WHOLE BUG.
      `_swift_updateClassMetadataImpl` finds a class's ivars with libobjc's own fast-data trick:
          movabsq $0x7FFFFFFFFFF8, %rcx ; andq 32(%rax), %rcx   ; rcx = self->bits & FAST_DATA_MASK
          movq 48(%rcx), %r14                                   ; r14 = ro->ivars   (class_ro_t + 0x30)
          shlq $5, %rbx ; movq 8(%r14,%rbx), %rcx               ; &ivars[i].offset  (ivar_t is 32 bytes)
      That masked word is a **class_ro_t** only while the class is UNREALIZED. `_objc_realizeClassFromSwift`
      swaps `bits` to a **class_rw_t**, which has no `ivars` at +0x30 — it is only 0x20 bytes — so r14 came
      back 0x80080000 and the read of `ivars[0].offset` faulted at 0x80080008. Measured identically in the
      Dock, WindowManager and ControlCenter (r14 = 0x80080000 / 0x88080000), with every other candidate
      proven clean first: field layouts complete, descriptor right (NumFields 6, FieldOffsetVectorOffset 10),
      fieldOffsets = self+0x50 as the descriptor says, superclass a correct native root class.
    Apple's order is Swift metadata completion FIRST, objc realization later (lazily, on first use), so do
      the same: register the class in the map now and realize it the first time anything asks for it. */
static void a2x_realize_now(struct armcls *e) {
    static Class (*rfs)(Class, void *); static int looked;
    static int busy;                                  /* realization re-enters through Swift -> objc -> mapcls */
    if (!e->pending || busy) return;
    if (!looked) { looked = 1; rfs = (Class (*)(Class, void *))dlsym(RTLD_DEFAULT, "_objc_realizeClassFromSwift"); }
    if (!rfs) { e->pending = 0; return; }
    e->pending = 0; busy = 1;
    /* libobjc's own order for a Swift class is: run the class's Swift metadata initializer (ro->swiftMetadataInitializer,
       present when RO_HAS_SWIFT_INITIALIZER, flags bit 6), THEN realize. _objc_realizeClassFromSwift is only the second
       half, so a class first reached from native ObjC (+alloc, NSClassFromString) never had its metadata completed and
       every field-offset variable stayed 0: the first store in its init landed on the isa. */
    if (e->bits0) {
        unsigned long ro = e->bits0 & 0x00007FFFFFFFFFF8UL;
        if (ro > 0x100000000UL && (*(uint32_t *)ro & 0x40u)) {
            void *ini = *(void **)(ro + 0x48);
            if (ini) {
                if (A2X_DBGENV("ARM2X86_TRACE_REGCLS"))
                    fprintf(a2x_errf(), "objc_bridge: running the Swift metadata initializer %p for %p before realizing it\n", ini, (void *)e->n);
                ((Class (*)(Class, void *))ini)(e->n, 0);
            }
        }
    }
    rfs(e->n, 0);
    busy = 0;
}
/* 10-27 A CATEGORY ON A SWIFT CLASS THE IMAGE NEVER LISTED IS PARKED, NOT DROPPED. Such a class (Reminders'
      TTRMTemplatesListCellView, Shortcuts, FindMy) is absent from __objc_classlist and its static record is a metadata
      TEMPLATE — superclass word 0, no bind — which the Swift runtime completes IN PLACE the first time a metadata
      accessor runs (swift_updateClassMetadata{,2}). Calling class_replaceMethod on the template died in libobjc's
      prepareMethodLists at 0x20. libobjc parks the category on an unrealized class and attaches it when the class
      appears; this table does the same: {template, category} waits here and a2x_pc_poll attaches it the moment the
      record's superclass word is filled in. Polled after every swift_updateClassMetadata{,2} and from mapcls().
      Anything still parked at exit is named by a2x_pc_atexit. */
struct a2x_pcat { unsigned long tg, ct; int done; };
static struct a2x_pcat *gPC; static unsigned long gNPC; static int gPCbusy, gPCatexit;
static int is_arm(unsigned long a);
static void a2x_pc_atexit(void) {
    for (unsigned long i = 0; i < gNPC; i++)
        if (!gPC[i].done)
            fprintf(stderr, "objc_bridge: the category %s is DROPPED — its target Swift class %#lx was never completed by the "
                    "Swift runtime before exit, so its methods were never attached\n",
                    *(const char **)(gPC[i].ct) ? *(const char **)(gPC[i].ct) : "(unnamed)", gPC[i].tg);
}
static void a2x_pc_park(unsigned long tg, unsigned long ct) {
    gPC = realloc(gPC, (gNPC + 1) * sizeof *gPC);
    gPC[gNPC].tg = tg; gPC[gNPC].ct = ct; gPC[gNPC].done = 0; gNPC++;
    if (!gPCatexit) { gPCatexit = 1; atexit(a2x_pc_atexit); }
}
static void a2x_pc_poll(unsigned long a) {
    if (!gNPC || gPCbusy || !a) return;
    int hit = 0;
    for (unsigned long i = 0; i < gNPC; i++) if (!gPC[i].done && gPC[i].tg == a) hit = 1;
    if (!hit || !*(unsigned long *)(a + 8)) return;          /* not parked, or the Swift runtime has not completed it yet */
    gPCbusy = 1;
    static Class (*rfs)(Class, void *); static int looked;
    if (!looked) { looked = 1; rfs = (Class (*)(Class, void *))dlsym(RTLD_DEFAULT, "_objc_realizeClassFromSwift"); }
    if (rfs) rfs((Class)a, 0);
    int known = 0;
    for (unsigned long k = 0; k < gNCls; k++) if (gCls[k].a == a) known = 1;
    if (!known) {
        gCls = realloc(gCls, (gNCls + 4) * sizeof *gCls);
        gCls[gNCls].a = a; gCls[gNCls].n = (Class)a; gCls[gNCls].pending = 0; gCls[gNCls].bits0 = 0; gNCls++;
        gCls[gNCls].a = *(unsigned long *)a; gCls[gNCls].n = object_getClass((id)a); gCls[gNCls].pending = 0; gCls[gNCls].bits0 = 0; gNCls++;
    }
    for (unsigned long i = 0; i < gNPC; i++) {
        if (gPC[i].done || gPC[i].tg != a) continue;
        unsigned long ct = gPC[i].ct; gPC[i].done = 1;
        Class tc = (Class)a;
        if (A2X_DBGENV("ARM2X86_TRACE_REGCLS"))
            fprintf(stderr, "[regcat] ATTACH category %s to completed Swift class %s (%p) sup=%#lx\n",
                    *(const char **)(ct) ? *(const char **)(ct) : "?", class_getName(tc), (void *)tc, *(unsigned long *)(a + 8));
        add_methods(tc, *(unsigned long *)(ct + 16), 1, 0);
        add_methods(object_getClass((id)tc), *(unsigned long *)(ct + 24), 1, 0);
        if (A2X_DBGENV("ARM2X86_TRACE_REGCLS")) {
            unsigned long ml = *(unsigned long *)(ct + 16);
            if (ml) { uint32_t ef = *(uint32_t *)ml, es = ef & 0xFFFC, n = *(uint32_t *)(ml + 4);
                if (n) { unsigned long e = ml + 8; SEL sel = (ef & 0x80000000u) ? *(SEL *)(e + *(int32_t *)e) : sel_registerName(*(const char **)e);
                    fprintf(stderr, "[regcat]   first instance method %s: respondsToSelector=%d (list of %u)\n", sel_getName(sel),
                            (int)class_respondsToSelector(tc, sel), n); (void)es; } }
        }
    }
    gPCbusy = 0;
}
/* 10-21 THE NAME HAS TO BE IN libobjc's TABLE WHEN NATIVE CODE ASKS FOR IT, AND REALIZATION IS WHAT PUBLISHES IT.
      Lazy realization (above) kept Swift happy and hid every Swift class from `NSClassFromString`: native AppKit's
      NSApplicationMain looks up the NSPrincipalClass BY NAME before any guest code touches the class, got nil, and
      exited ("Unable to find class: Application"). A guest-side hook cannot help — the caller is native.
    libobjc has a hook for exactly this: `objc_setHook_getClass`, called when a by-name lookup MISSES. Install one
      and realize the named class JUST IN TIME, from inside the native lookup, then answer with it. A class nobody asks
      for by name stays lazy; a class somebody does ask for is realized at the moment of the question.
    A class realized this way may not have had its Swift metadata completed yet, and `swift_updateClassMetadata` reads
      `bits` as a class_ro_t (see the order note above). a2x_ucm puts the pre-realization word back for the duration of
      that one call, so the two orders — name lookup first, metadata completion first — are both safe. */
static const char *a2x_cls_name_unrealized(unsigned long c) {
    unsigned long ro = *(unsigned long *)(c + 0x20) & 0x00007FFFFFFFFFF8UL;
    return ro ? *(const char **)(ro + 24) : 0;
}
static BOOL (*a2x_old_getclass_hook)(const char *, Class *);
static BOOL a2x_getclass_hook(const char *name, Class *out) {
    if (name) for (unsigned long i = 0; i < gNCls; i++)
        if (gCls[i].pending && gCls[i].bits0) {
            const char *n = a2x_cls_name_unrealized(gCls[i].a);   /* pending ⇒ the word at +0x20 is still the ro */
            if (n && !strcmp(n, name)) {
                a2x_realize_now(&gCls[i]);
                *out = gCls[i].n;
                fprintf(a2x_errf(), "objc_bridge: native lookup of Swift class %s -> realized on demand (%p)\n", name, (void *)*out);
                return YES;
            }
        }
    return a2x_old_getclass_hook ? a2x_old_getclass_hook(name, out) : NO;
}
static void a2x_install_getclass_hook(void) {
    static int done; if (done) return; done = 1;
    void (*set)(BOOL (*)(const char *, Class *), BOOL (**)(const char *, Class *)) =
        (void (*)(BOOL (*)(const char *, Class *), BOOL (**)(const char *, Class *)))dlsym(RTLD_DEFAULT, "objc_setHook_getClass");
    if (!set) { fprintf(a2x_errf(), "objc_bridge: objc_setHook_getClass is absent — a Swift class is invisible to a native "
                        "lookup by name until it is first used by translated code\n"); return; }
    set(a2x_getclass_hook, &a2x_old_getclass_hook);
}
static void a2x_pc_poll_all(void) {
    if (gPCbusy) return;
    for (unsigned long i = 0; i < gNPC; i++)
        if (!gPC[i].done && *(unsigned long *)(gPC[i].tg + 8)) a2x_pc_poll(gPC[i].tg);
}
static Class mapcls(unsigned long a) {
    if (gNPC) a2x_pc_poll_all();
    for (unsigned long i = 0; i < gNCls; i++)
        if (gCls[i].a == a) { if (gCls[i].pending) a2x_realize_now(&gCls[i]); return gCls[i].n; }
    return (Class)a;
}
static int is_arm(unsigned long a) { return a >= __arm_text_base && a < __arm_text_base + (1UL << 32); }   /* inside the image's range */
unsigned long __arm2x86_mapcls(unsigned long a) { if (!is_arm(a)) return a; return (unsigned long)mapcls(a); }
static unsigned long a2x_twin_guest_addr(Class c) {
    for (unsigned long i = 0; i < gNCls; i++) if (gCls[i].n == c) return gCls[i].a;
    return 0;   /* not one of our twins: a real native class, or something that is not a class at all */
}
/* the guest class record a registered class stands for, for callers outside this file (host.c: bundleForClass:) */
unsigned long __arm2x86_twin_guest_addr(void *cls) { return a2x_twin_guest_addr((Class)cls); }

/* 10-21 ONE CLASS, TWO IDENTITIES — `Could not cast value of type 'Application' (0x60000070de00)
      to 'Application' (0x7ff8496e4658)`, then swift_dynamicCastFailure -> abort. That is ControlCenter's SIGABRT,
      19 times in ten minutes of a live session.
      WHY: `swift_getObjCClassMetadata(cls)` returns `cls` itself when `cls->isTypeMetadata()` — a real Swift
      class IS its own metadata — and otherwise mints an ObjCClassWrapper {kind=0x305, Class}. isTypeMetadata()
      reads the "is Swift stable ABI" bit in class->bits, and `objc_allocateClassPair`, which is how this bridge
      registers every guest class, CANNOT set it (the same mechanism the [super init] unwrap above documents).
      So every guest Swift class got a WRAPPER as its metadata. `swift_getObjCClassFromMetadata` unwraps that
      correctly, which is why `[super sharedApplication]` dispatched fine — but
      `swift_dynamicCastClassUnconditional` compares raw class pointers up the isa chain
      (0x60000070de00 -> NSApplication -> NSResponder -> NSObject) and never meets the wrapper, so an
      unconditional cast of an object to its OWN type fails.
       THE FIX: for a class this bridge rebuilt FROM A GUEST SWIFT CLASS, answer the way a real Mac does and
      return the class itself. A genuine Objective-C class still gets its wrapper from the native runtime, which
      is correct — for those, metadata really is not the class. The guest record's is-Swift bit is bits 0/1 of
      its `data` word at +0x20, the same test the class-tail copy uses. */
static int a2x_guest_swift_class(unsigned long c) {
    if (!c || (c & 7)) return 0;
    for (unsigned long i = 0; i < gNCls; i++)
        if ((unsigned long)gCls[i].n == c)
            return (*(unsigned long *)(gCls[i].a + 0x20) & 3) != 0;
    return 0;
}
void __arm2x86_abi_swift_getObjCClassMetadata(void) {
    unsigned long c = __arm2x86_mapcls(A2X_RX(0));
    if (a2x_guest_swift_class(c)) { A2X_RX(0) = c; return; }
    static unsigned long (*f)(unsigned long); if (!f) f = a2x_need("swift_getObjCClassMetadata");
    A2X_RX(0) = f(c);
}
/* the matched pair: with the above, metadata for one of our Swift classes IS the class, so hand it straight
      back rather than letting the native unwrapper assert on a class without the stable-ABI bit. */
/* 10-21 BOTH PRODUCERS OF A TYPE MUST AGREE, OR THE FIX BECOMES THE BUG. `swift_getObjCClassMetadata`
      and `swift_getObjectType` are two doors to the same answer; ControlCenter calls the first 31 times and the
      SECOND 355 times, 8 of those feeding objc_msgSendSuper2 directly. Overriding only the first would leave
      `swift_getObjectType(anInstance)` still handing back the ObjCClassWrapper, so `type(of: x) == T.self` and
      `swift_dynamicCast` (which takes BOTH source and target metadata) would mismatch — the same defect inverted.
      With the guest record realized, native would answer correctly on its own; this keeps the two doors in step
      on the fallback path too, where the class was rebuilt and carries no stable-ABI bit. */
/* 10-21 DIAGNOSTIC: swift_updateClassMetadata faults identically in the Dock AND WindowManager —
      `_swift_updateClassMetadataImpl+0x1a7`, fault address 0x80080008, r14 = 0x80080000, i.e. it read [r14+8]
      with r14 a field TYPE LAYOUT pointer of 0x80080000. That path only exists now that realization made our
      guest classes genuine Swift classes, so the runtime completes them and asks for their field layouts.
      Print what the GUEST actually hands over before delegating, so the next run names the bad field instead
      of leaving a bare register value. Signature:
        swift_updateClassMetadata(ClassMetadata *self, ClassLayoutFlags flags, size_t numFields,
                                  const TypeLayout * const *fieldTypes, size_t *fieldOffsets)
       Returned as a two-word pair: the real entry point hands back a MetadataResponse/MetadataDependency in
      x0:x1 on arm64 and rax:rdx here, which is what the generic adapter would have carried. */
typedef struct { unsigned long w0, w1; } a2x_w2;
/* a page-resident test, so a diagnostic can never be the thing that crashes the process */
static int a2x_readable(const void *p) {
    char v = 0;
    uintptr_t pg = (uintptr_t)p & ~(uintptr_t)0xFFF;
    return p && mincore((void *)pg, 0x1000, &v) == 0 && (v & MINCORE_INCORE);
}
static void a2x_ucm(const char *nm, void *fp) {
    unsigned long self_ = A2X_RX(0), fl = A2X_RX(1), n = A2X_RX(2), fts = A2X_RX(3), fos = A2X_RX(4);
    static int said;
    /* C2 11-06 this dump prints n+3 fieldTypes on purpose ("PAST THE END") on EVERY hosted Swift program, and the
          kmutil report on the 27.2 box was read as a crash because of it. It is a diagnostic: ask for it. */
    static int want = -1;
    if (want < 0) want = A2X_DBGENV("ARM2X86_TRACE_UCM") ? 1 : 0;
    if (want && said < 4) {
        said++;
        fprintf(a2x_errf(), "objc_bridge: %s(self=%#lx flags=%#lx numFields=%lu fieldTypes=%#lx fieldOffsets=%#lx)\n",
                nm, self_, fl, n, fts, fos);
        if (self_ > 0x1000 && !(self_ & 7) && a2x_readable((void *)(self_ - 8)))
            fprintf(a2x_errf(), "    self vwt(-8)=%#lx  descriptor(+0x40)=%#lx\n",
                    *(unsigned long *)(self_ - 8), *(unsigned long *)(self_ + 0x40));
            {
                unsigned long sup_ = *(unsigned long *)(self_ + 8);
                fprintf(a2x_errf(), "    self->Superclass(+8)=%#lx%s\n", sup_,
                        (sup_ < 0x10000 || (sup_ & 7)) ? "   <== NOT A CLASS POINTER" : "");
                if (sup_ > 0x10000 && !(sup_ & 7) && a2x_readable((void *)sup_))
                    fprintf(a2x_errf(), "        super: isa=%#lx superclass=%#lx vwt(-8)=%#lx\n",
                            *(unsigned long *)sup_, *(unsigned long *)(sup_ + 8),
                            a2x_readable((void *)(sup_ - 8)) ? *(unsigned long *)(sup_ - 8) : 0xdeadUL);
                else
                    fprintf(a2x_errf(), "        super is NOT READABLE\n");
            }
        if (fts > 0x1000 && !(fts & 7) && n && n < 64 && a2x_readable((void *)fts))
            for (unsigned long i = 0; i < n + 3; i++) {
                unsigned long t = ((unsigned long *)fts)[i];
                fprintf(a2x_errf(), "    fieldTypes[%lu]%s = %#lx%s\n", i, i >= n ? " (PAST THE END)" : "", t,
                        (t < 0x10000 || (t & 7)) ? "   <== NOT A POINTER" : "");
                if (t > 0x10000 && !(t & 7) && a2x_readable((void *)t)) {
                    unsigned long sz = ((unsigned long *)t)[0], st = ((unsigned long *)t)[1];
                    unsigned fl = ((unsigned *)t)[4], xi = ((unsigned *)t)[5];
                    fprintf(a2x_errf(), "        size=%#lx stride=%#lx flags=%#010x xi=%#x%s\n", sz, st, fl, xi,
                            (fl & 0x00400000u) ? "   <== Incomplete" : "");
                }
            }
    }
    /* a Swift class the runtime completes here may never have passed the in-place registration scan */
    if (self_ > 0x1000 && !(self_ & 7) && a2x_sret_class_ok(self_)) a2x_sret_scan_class(self_);
    /* a class the name hook realized BEFORE its metadata was completed: show the runtime its class_ro_t again for this
       one call, then put the realized word back */
    unsigned long *bw = 0, saved = 0;
    for (unsigned long i = 0; i < gNCls; i++)
        if (gCls[i].a == self_ && gCls[i].bits0 && !gCls[i].pending && (unsigned long)gCls[i].n == self_) {
            bw = (unsigned long *)(self_ + 0x20);
            if ((*bw & 0x00007FFFFFFFFFF8UL) != (gCls[i].bits0 & 0x00007FFFFFFFFFF8UL)) { saved = *bw; *bw = gCls[i].bits0; }
            else bw = 0;
            break;
        }
    a2x_w2 r = ((a2x_w2 (*)(unsigned long, unsigned long, unsigned long, unsigned long, unsigned long))fp)
               (self_, fl, n, fts, fos);
    if (bw) *bw = saved;
    if (gNPC) a2x_pc_poll(self_);
    A2X_RX(0) = r.w0; A2X_RX(1) = r.w1;
}
void __arm2x86_abi_swift_updateClassMetadata(void) {
    static void *f; if (!f) f = a2x_need("swift_updateClassMetadata");
    a2x_ucm("swift_updateClassMetadata", f);
}
void __arm2x86_abi_swift_updateClassMetadata2(void) {
    static void *f; if (!f) f = a2x_need("swift_updateClassMetadata2");
    a2x_ucm("swift_updateClassMetadata2", f);
}
void __arm2x86_abi_swift_getObjectType(void) {
    unsigned long o = __arm2x86_mapcls(A2X_RX(0));
    if (o > 0x1000 && !(o & 7)) {
        Class k = object_getClass((id)o);
        if (a2x_guest_swift_class((unsigned long)k)) { A2X_RX(0) = (unsigned long)k; return; }
    }
    static unsigned long (*f)(unsigned long); if (!f) f = a2x_need("swift_getObjectType");
    A2X_RX(0) = f(o);
}
void __arm2x86_abi_swift_getObjCClassFromMetadata(void) {
    unsigned long m = __arm2x86_mapcls(A2X_RX(0));
    if (a2x_guest_swift_class(m)) { A2X_RX(0) = m; return; }
    static unsigned long (*f)(unsigned long); if (!f) f = a2x_need("swift_getObjCClassFromMetadata");
    A2X_RX(0) = f(m);
}
#define RO(c) ((*(unsigned long *)((c) + 32)) & 0x00007ffffffffff8UL)

/* 10-22 GUEST PROTOCOLS WERE NEVER GIVEN TO THE RUNTIME. libobjc fixes up a loaded image's protocols itself (sets the isa,
      folds a duplicate into the canonical copy, rewrites __objc_protorefs); a guest image is mapped by the shim, so its
      protocol_t records kept isa 0 and every `@protocol(X)` handed native code a guest struct. MenuBarAgent: BoardServices
      `+[BSObjCProtocol protocolForProtocol:]` got 0x10043b120 (isa 0) and objc_retain faulted at 0x20. Map each one to the
      native Protocol of the same name — Apple's, when a framework already defines it — or build and register it from the
      guest's method lists and conformances; then point every protoref slot at it. Idempotent: a native Protocol maps to
      itself by name. protocol_t: isa, name +8, protocols +16, instance/class methods +24/+32, optional +40/+48. */
static void a2x_proto_methods(Protocol *pr, unsigned long ml, BOOL req, BOOL inst) {
    if (!ml) return;
    uint32_t ef = *(uint32_t *)ml, n = *(uint32_t *)(ml + 4), es = ef & 0xFFFC;
    for (uint32_t i = 0; i < n; i++) {
        unsigned long e = ml + 8 + (unsigned long)i * es; const char *name, *types;
        if (ef & 0x80000000u) {
            int32_t no = *(int32_t *)e, to = *(int32_t *)(e + 4);
            name = sel_getName(*(SEL *)(e + no)); types = (const char *)(e + 4 + to);
        } else { name = *(const char **)e; types = *(const char **)(e + 8); }
        if (name && types) protocol_addMethodDescription(pr, sel_registerName(name), types, req, inst);
    }
}
static Protocol *a2x_map_protocol(unsigned long p, int depth) {
    if (!p || depth > 32) return 0;
    const char *name = *(const char **)(p + 8);
    if (!name) return 0;
    Protocol *pr = objc_getProtocol(name);
    if (pr) return pr;
    pr = objc_allocateProtocol(name);
    if (!pr) return objc_getProtocol(name);   /* allocated concurrently under the same name */
    unsigned long pl = *(unsigned long *)(p + 16);
    if (pl) {
        unsigned long n = *(unsigned long *)pl;
        for (unsigned long k = 0; k < n; k++) {
            Protocol *s = a2x_map_protocol(((unsigned long *)(pl + 8))[k], depth + 1);
            if (s) protocol_addProtocol(pr, s);
        }
    }
    a2x_proto_methods(pr, *(unsigned long *)(p + 24), YES, YES);
    a2x_proto_methods(pr, *(unsigned long *)(p + 32), YES, NO);
    a2x_proto_methods(pr, *(unsigned long *)(p + 40), NO, YES);
    a2x_proto_methods(pr, *(unsigned long *)(p + 48), NO, NO);
    objc_registerProtocol(pr);
    /* 10-27 THE RUNTIME API CANNOT EXPRESS _extendedMethodTypes, SO THE REBUILT PROTOCOL HAD NONE.
          Maps died on `+[NSXPCInterface interfaceWithProtocol:]`: NSInvalidArgumentException, "Unable to get
          extended method signature from Protocol data (MapsConnectionBrokerEndpointConsumer /
          listenerEndpointDidChange:forInterface:)". Foundation needs the EXTENDED encoding (the one that
          spells out block and object types, "@\"NSString\"" rather than "@") to build an NSXPCInterface, and
          it reads it through _protocol_getMethodTypeEncoding(), which returns nil the moment
          protocol_t->_extendedMethodTypes is NULL. objc_allocateProtocol +
          protocol_addMethodDescription fill the four method lists and nothing else; there is no
          protocol_addExtendedMethodTypes(), so the array is copied from the guest's own record.
        WHY A STRAIGHT POINTER COPY IS CORRECT. libobjc indexes that array positionally, by the method's
          position inside the concatenation of the four lists in the canonical order required-instance,
          required-class, optional-instance, optional-class. a2x_proto_methods above walks the guest's four
          lists in that same order and protocol_addMethodDescription appends without de-duplicating, so the
          native protocol's indices equal the guest's. The strings are plain C strings in the guest's mapped
          __TEXT, which lives as long as the process.
        size (+64) GATES THE FIELD: hasExtendedMethodTypes() is a size test, so a guest record too short
          to contain the field must not be read at +72, and the native record must be long enough to hold it.
          Both are checked, and a record that fails the test is left exactly as it was — strictly additive. */
    {
        unsigned gsize = *(unsigned *)(p + 64);
        if (gsize >= 80) {
            const char **ext = *(const char ***)(p + 72);
            unsigned nsize = *(unsigned *)((char *)pr + 64);
            if (ext && nsize >= 80) {
                *(const char ***)((char *)pr + 72) = ext;
                if (A2X_DBGENV("ARM2X86_TRACE_OBJC"))
                    fprintf(a2x_errf(), "objc_bridge: protocol %s given its guest extended method types %p\n",
                            name, (void *)ext);
            } else if (!ext) {
                /* NOT silent: a protocol an XPC interface is built from and that has no extended types
                      in the guest either is a different bug, and this is where it would show. */
                static int said;
                if (!said++) fprintf(a2x_errf(), "objc_bridge: guest protocol %s carries NO extended method "
                                     "types (size %u) — an NSXPCInterface over it will raise\n", name, gsize);
            } else {
                fprintf(a2x_errf(), "objc_bridge: the native protocol record for %s is only %u bytes, too "
                        "short for _extendedMethodTypes — not written\n", name, nsize);
            }
        }
    }
    return pr;
}
void __arm2x86_objc_protocols(unsigned long pl, unsigned long npl, unsigned long refs, unsigned long nrefs) {
    unsigned long made = 0, fixed = 0;
    for (unsigned long i = 0; i < npl; i++) if (a2x_map_protocol(((unsigned long *)pl)[i], 0)) made++;
    for (unsigned long i = 0; i < nrefs; i++) {
        unsigned long *slot = (unsigned long *)refs + i;
        Protocol *pr = a2x_map_protocol(*slot, 0);
        if (pr && (unsigned long)pr != *slot) { *slot = (unsigned long)pr; fixed++; }
    }
    if (A2X_DBGENV("ARM2X86_TRACE_OBJC"))
        fprintf(a2x_errf(), "objc_bridge: %lu of %lu guest protocols mapped, %lu of %lu protorefs rewritten\n", made, npl, fixed, nrefs);
}
void __arm2x86_objc_register(unsigned long cl, unsigned long ncl, unsigned long cat, unsigned long ncat,
                             unsigned long refs, unsigned long nrefs, unsigned long srefs, unsigned long nsrefs) {
    /* 10-03: WAS an unconditional calloc — called once per IMAGE, it dropped the earlier images' classes while gNCls kept
          counting, so the next image wrote past the new array. Allocate once; the realloc after each add grows it. */
    if (!gCls) gCls = calloc(2, sizeof *gCls);
    const unsigned long first = gNCls;   /* this image's classes start here */
    /* 10-30 THE MEMORY-RETURN (sret) TABLE WAS FILLED ONLY ON TWO REGISTRATION PATHS, AND NEVER FOR CATEGORIES.
          App Store: a native caller (objc_msgSend_stret from AppKit) entered a guest -frame override, rdi was the
          NSRect result buffer, recover_guest_call did not shift (the IMP was not in a2x_sret_tab) and [super frame]
          ran with self = a native stack address. The table is keyed by IMP and is read by the trampoline, so it must
          hold EVERY guest method whose encoding returns a >16-byte struct, whichever way its class is registered:
          scan the image's whole class list (instance and class methods) and category list here, once per image,
          before any class is built. Re-scanning a class later is harmless (a2x_sret_put dedupes on the IMP). */
    for (unsigned long i = 0; i < ncl; i++) {
        unsigned long c = ((unsigned long *)cl)[i];
        if (c && is_arm(c)) a2x_sret_scan_class(c);
    }
    for (unsigned long i = 0; i < ncat; i++) {   /* cat_t {name, cls, instanceMethods, classMethods, ...} */
        unsigned long ct = ((unsigned long *)cat)[i];
        if (!ct || !is_arm(ct)) continue;
        a2x_sret_scan_list(*(unsigned long *)(ct + 16));
        a2x_sret_scan_list(*(unsigned long *)(ct + 24));
    }
    if (A2X_DBGENV("ARM2X86_TRACE_SRET")) fprintf(stderr, "[sret] image scan done: %u memory-return IMPs in the table\n", a2x_sret_n);
    /* 10-26 A SUPERCLASS IN ANOTHER GUEST IMAGE STALLED THIS LOOP, AND THE ABORT BLAMED THE WRONG THING.
          Registration runs once per IMAGE (host.c walks g_img and calls this for each one), and the wait below
          — "its superclass is ours and not built yet" — can only ever be satisfied from the SAME call's list.
          So a class whose superclass lives in a different guest image never became built, no pass made
          progress, and the run ended on FATAL "a class's superclass never resolved" with an EMPTY second
          argument: no class named, no superclass named, no count.
        MEASURED STATICALLY on macOS 27 Books: its main binary lists 719 classes, and 18 of its 56 distinct
          superclass binds name classes defined in Books.app's OWN embedded frameworks — BookCore's
          IMAccessibilitySafeCategory has 36 subclasses in the main binary, BKLibrary's BKLibraryDataSource 3,
          across 6 frameworks. The main binary therefore cannot be registered before those images, whatever
          order they arrive in, and nothing guarantees an order.
        So an unresolved class is OWED to the next call instead of killing the process: the work list is this
          image's classlist plus everything still owed from earlier calls, and a slot is zeroed as it is
          settled. Ordering between images stops mattering, which is the property a real app's class graph
          needs. */
    unsigned long nwork = gNOwed + ncl;
    unsigned long *work = (unsigned long *)malloc((nwork ? nwork : 1) * sizeof *work);
    if (!work) die2("out of memory building the class work list", "");
    for (unsigned long i = 0; i < gNOwed; i++) work[i] = gOwed[i];
    for (unsigned long i = 0; i < ncl; i++) work[gNOwed + i] = ((unsigned long *)cl)[i];
    int progress = 1; unsigned long done = 0;
    while (done < nwork && progress) {   /* superclasses first */
        progress = 0;
        for (unsigned long i = 0; i < nwork; i++) {
            unsigned long c = work[i]; int seen = 0;
            if (!c) continue;                        /* settled on an earlier pass of this call */
            for (unsigned long k = 0; k < gNCls; k++) if (gCls[k].a == c) seen = 1;
            /* 10-26 A CLASS ALREADY REGISTERED IS SETTLED, NOT PENDING. `done` counted REGISTRATIONS, so
                  a class some earlier call had already built — which the owed list above hands straight back,
                  and which two images listing the same record also produces — left done < ncl for ever and
                  the loop died on its own success. */
            if (seen) { work[i] = 0; done++; progress = 1; continue; }
            unsigned long sup = *(unsigned long *)(c + 8);
            /* 10-21 ASK THE MAP, NOT mapcls()'s FALLBACK. mapcls() returns (Class)a when it holds no entry,
                  so `mapcls(sup) == sup` used to mean "ours and not built yet". A REALIZED Swift class maps to its OWN
                  guest record, so that test now means BOTH "not built" and "built" — the loop skipped every class on
                  every pass, made no progress, and died with FATAL "a class's superclass never resolved" (Dock, 5/5
                  runs, SIGABRT). The map is the only honest answer to "is it built". */
            if (sup && is_arm(sup)) {
                int built = 0;
                for (unsigned long k = 0; k < gNCls; k++) if (gCls[k].a == sup) { built = 1; break; }
                if (!built) continue;   /* its superclass is ours and not built yet */
            }
            unsigned long ro = RO(c), mro = RO(*(unsigned long *)c);
            const char *name = *(const char **)(ro + 24);
            /* 10-20 A ZERO SUPERCLASS SLOT IS ALMOST NEVER A ROOT CLASS. In the image the slot reads 0 and carries a
                  BIND to a native class (Dock's DockCore.SystemAppearanceMonitor: `superclass 0x0 _OBJC_CLASS_$_NSObject`),
                  so if the superclass bind has not landed before this runs we hand allocateClassPair Nil and silently
                  create a ROOT class. Its `super` then resolves nowhere — and -[SystemAppearanceMonitor init] was
                  re-entering itself through the bridge until the stack was gone. Genuine root classes are a handful
                  (NSObject, NSProxy); a translated program normally defines none, so say it every time. */
            if (A2X_DBGENV("ARM2X86_TRACE_REGCLS")) { fprintf(a2x_errf(), "[regcls] %s rec=%#lx sup=%#lx supmap=%p\n", name, c, sup, sup ? (void *)mapcls(sup) : 0); fflush(a2x_errf()); }
            if (!sup) fprintf(a2x_errf(), "objc_bridge: %s has a NULL superclass slot — registering it as a ROOT class. If it"
                              " is not genuinely a root class, its superclass bind had not been applied yet.\n", name);
            /* 10-20 A SWIFT CLASS IS WIDER THAN AN ObjC ONE, AND THE EXTRA WORDS ARE LOAD-BEARING.
                  objc's class object ends at 0x28 (isa, superclass, cache, bits); a Swift class metadata continues
                  with flags, instance/class sizes and — at +0x40 — its CONTEXT DESCRIPTOR. Rebuilt with
                  objc_allocateClassPair(…, 0) those words do not exist, so the descriptor reads 0.
                Measured: swift::TargetMetadata::isCanonicalStaticallySpecializedGenericMetadata does
                     movq 0x40(%rdi), %rax ; testb $-0x80, (%rax)
                  with NO null check, so instantiating ANY generic over such a class faults at 0. A five-line repro
                  (`struct Box<T> { var v: T?; let id: Int }`) died 10/10, and that is what kept the Dock — and with
                  it every AppKit app, because they all register with the Dock — off the macOS 27 desktop.
                So ask for the guest class's own tail as extraBytes and copy it below, after registration. */
            uint32_t gclsz = 0;
            {   unsigned long dataw = *(unsigned long *)(c + 0x20);     /* bits 0/1 = is-Swift (legacy/stable) */
                if (dataw & 3) { uint32_t sz = *(uint32_t *)(c + 0x38); /* classSize */
                    if (sz > 0x28 && sz < 0x4000) gclsz = sz; } }
            /* 10-21 A SWIFT CLASS IS ITS OWN METADATA — REALIZE THE GUEST RECORD, DO NOT REBUILD IT.
                  Rebuilding with objc_allocateClassPair cannot reproduce two things the Swift runtime requires, and
                  both cost a desktop app tonight:
                  • the FULL-METADATA PREFIX at cls-8. `Metadata::getTypeLayout()` is
                    `*(this-8) + offsetof(ValueWitnessTable, size)`, and that offset is 8 function pointers = 0x40, so a
                    rebuilt class used as metadata yields a payload TypeLayout of exactly 0x40.
                    swift_initEnumMetadataSinglePayload then dereferences 0x40 — the Dock's SIGSEGV, 5/5 runs, in
                    DOCKGestures start-up (rdx=0x40, fault address 0x40).
                  • the "is Swift stable ABI" bit in bits, so swift_getObjCClassMetadata minted an ObjCClassWrapper
                    {kind=0x305} instead of returning the class, and swift_dynamicCastClassUnconditional — which walks
                    raw class pointers up the isa chain — never met it: `Could not cast value of type 'Application'
                    (0x60000070de00) to 'Application' (0x7ff8496e4658)`, swift_dynamicCastFailure, abort. That is
                    ControlCenter's SIGABRT, 19 times in ten minutes of a live session.
                THE GUEST RECORD ALREADY HAS ALL OF IT, and Apple's own fixups prove the record is MEANT to be the
                  metadata: in the Dock, the class template 0x1004058a0 has `__DATA,__data 0x100405898 auth-bind
                  libswiftCore/_$sBoWV` — the value-witness table for Builtin.NativeObject — bound at exactly cls-8.
                  The descriptor at +0x40, the field offsets, the instance size and the stable-ABI bit are all there too.
                  So hand the record to the runtime the way the Swift runtime itself does, with libobjc's
                  `_objc_realizeClassFromSwift`, and the class, its metadata and its identity become ONE pointer.
                  Its method IMPs are arm64 addresses; a native dispatch to one faults on the instruction fetch and the
                  lazy trampoline resumes it at that function's callback door — the mechanism callbacks already use.
                A guest class with NO Swift metadata (a plain ObjC class) still takes the rebuild path below: it has
                  no prefix to realize, and for those metadata genuinely is not the class. */
            Class ns = Nil;
            int realized = 0;
            int pending_realize = 0;
            IMP cxxctor = 0;
            if (gclsz) {
                static Class (*rfs)(Class, void *); static int looked;
                if (!looked) { looked = 1; rfs = (Class (*)(Class, void *))dlsym(RTLD_DEFAULT, "_objc_realizeClassFromSwift"); }
                if (rfs) {
                    /* the superclass slot carries a bind; point it at the real class before the runtime reads it */
                    if (sup) { make_writable((void *)(c + 8), 8); *(unsigned long *)(c + 8) = (unsigned long)mapcls(sup); }
                    /* the METACLASS has its own superclass word, and for a same-image ObjC superclass it is a rebased guest
                       address of that class's guest metaclass (Music: SMPreviewPlayer meta+8 = 0x1021c8130 = IntPreviewPlayer's),
                       not a bind. That metaclass was never registered (the superclass is a twin), so realization died with
                       "no class for metaclass". Map it the same way the class word is mapped: the map holds every guest
                       metaclass of a registered class. */
                    a2x_sret_scan_class(c);   /* raw guest IMPs: note the memory-return ones for the trampoline */
                    {   unsigned long m = *(unsigned long *)c;
                        if (is_arm(m)) { unsigned long msup = *(unsigned long *)(m + 8);
                            if (msup && is_arm(msup)) { make_writable((void *)(m + 8), 8); *(unsigned long *)(m + 8) = (unsigned long)mapcls(msup); } } }
                    ns = (Class)c; realized = 1; pending_realize = 1;   /* realized on first use, see a2x_realize_now */
                    a2x_install_getclass_hook();   /* ...or the first time native code asks for it BY NAME */
                } else {
                    static int said;
                    if (!said) { said = 1;
                        fprintf(a2x_errf(), "objc_bridge: _objc_realizeClassFromSwift is absent — Swift classes are being "
                                "rebuilt instead, so their metadata prefix and stable-ABI bit are missing\n"); }
                }
            }
            /* 10-21 AN EXPORTED CLASS MUST BE REGISTERED AT ITS GUEST ADDRESS, OR NATIVE CONSUMERS GET AN
                  UNREGISTERED STRUCT. xlat2 emits every data export as an ABSOLUTE symbol equal to the guest
                  address (`_OBJC_CLASS_$_X = 0x2000xxxxx`, xlat2.py ~1609), so a native binary that links this
                  dylib binds `_OBJC_CLASS_$_X` to the guest class record. Build a twin elsewhere and that symbol
                  still points at a struct the runtime never registered — readable and entirely plausible
                  (class_getName, class_getSuperclass and class_getInstanceSize all answer correctly) but absent
                  from objc_copyClassList.
                MEASURED END TO END: Apple's own untranslated `/usr/libexec/pkd` imports exactly one class,
                  `_OBJC_CLASS_$_PKDServer`, and does `[PKDServer new]`. dtrace caught
                  `objc_opt_new(GUEST class 0x200033a88) <- pkd`; the instance came back with a packed isa of
                  0x11d800200033a8d (& 0x00007ffffffffff8 = 0x200033a88, the guest class); and native
                  objc_release later walked that struct and faulted at 0x70612e6d6f80 — a pointer read out of the
                  middle of a "com.apple…" string inside the guest class data. Deterministic across builds.
                So if THIS class is one the image exports, register the guest record IN PLACE with
                  objc_readClassPair, the way the Swift path above realizes its own record. The exported absolute
                  symbol is then the live class and nothing downstream needs to know. Scoped strictly to exported
                  classes: every other class takes the unchanged twin path below, so a program with no exported
                  classes (Dock, Finder, WindowManager) is bit-for-bit unaffected.
                FAILS SAFE: if the runtime refuses the record we fall through to the twin and say so loudly. A
                  class that failed to register at all would be worse than a twin a native consumer cannot see. */
            /* ARM2X86_NO_INPLACE=1 forces the old twin path, so one build gives a before/after A/B.
                  The certifier wants both halves from the SAME binary; a toggle is cheaper than two builds. */
            if (!realized && name && !A2X_DBGENV("ARM2X86_NO_INPLACE")) {
                static Class (*readpair)(Class, const void *); static int rp_looked;
                if (!rp_looked) { rp_looked = 1;
                    readpair = (Class (*)(Class, const void *))dlsym(RTLD_DEFAULT, "objc_readClassPair"); }
                char expsym[512];
                snprintf(expsym, sizeof expsym, "OBJC_CLASS_$_%s", name);   /* dlsym takes the name without the _ */
                if (readpair && dlsym(RTLD_DEFAULT, expsym) == (void *)c) {
                    /* the superclass slot carries a bind; point it at the real class before the runtime reads it */
                    if (sup) { make_writable((void *)(c + 8), 8); *(unsigned long *)(c + 8) = (unsigned long)mapcls(sup); }
                    a2x_sret_scan_class(c);
                    {   unsigned long m = *(unsigned long *)c;   /* same metaclass-superclass fix as the Swift path above */
                        if (is_arm(m)) { unsigned long msup = *(unsigned long *)(m + 8);
                            if (msup && is_arm(msup)) { make_writable((void *)(m + 8), 8); *(unsigned long *)(m + 8) = (unsigned long)mapcls(msup); } } }
                    make_writable((void *)c, 0x28);
                    static const struct { uint32_t version, flags; } a2x_ii = { 0, 0 };
                    Class got = readpair((Class)c, &a2x_ii);
                    if (got) {
                        ns = got; realized = 1;
                        fprintf(a2x_errf(), "objc_bridge: %s is EXPORTED — registered IN PLACE at its guest address "
                                "%p, so a native consumer of _OBJC_CLASS_$_%s binds to the live class\n",
                                name, (void *)c, name);
                    } else {
                        fprintf(a2x_errf(), "objc_bridge: %s is exported but objc_readClassPair REFUSED the guest "
                                "record — falling back to a twin, so a native consumer of _OBJC_CLASS_$_%s will "
                                "bind to an UNREGISTERED struct\n", name, name);
                    }
                }
            }
            if (!realized) {
            ns = objc_allocateClassPair(sup ? mapcls(sup) : Nil, name, gclsz ? gclsz - 0x28 : 0);
            /* 10-20 A CLASS NAME A NATIVE FRAMEWORK ALREADY REGISTERED. macOS 27's SetupAssistantSpringboard defines
                  SAFacelessConfiguration, which the native SetupAssistant framework also defines; allocateClassPair refused
                  the duplicate, the bridge died, the springboard aborted, and loginwindow waited forever at 60% for its
                  macbuddy.ready signal — the black screen. Apple's runtime keeps BOTH ("Class X is implemented in both"):
                  the program's own references bind to its own class, a lookup by name finds one of them. So register ours
                  under a private name; mapcls() still sends every reference the guest makes to it. */
            if (!ns && objc_getClass(name)) {
                char alt[512];
                for (int k = 1; !ns && k < 100; k++) {
                    snprintf(alt, sizeof alt, "%s.arm2x86.%d", name, k);
                    ns = objc_allocateClassPair(sup ? mapcls(sup) : Nil, alt, gclsz ? gclsz - 0x28 : 0);
                }
                if (ns) fprintf(a2x_errf(), "objc[%d]: Class %s is implemented in both a native image and the translated "
                                "program. The program's own references use its copy (registered as %s).\n",
                                getpid(), name, class_getName(ns));
            }
            if (!ns) die2("objc_allocateClassPair refused (name taken?)", name);
            unsigned long iv = *(unsigned long *)(ro + 48);
            if (iv) { uint32_t es = *(uint32_t *)iv, n = *(uint32_t *)(iv + 4);
                for (uint32_t k = 0; k < n; k++) { unsigned long e = iv + 8 + (unsigned long)k * es;
                    uint32_t al = *(uint32_t *)(e + 24), sz = *(uint32_t *)(e + 28);
                    class_addIvar(ns, *(const char **)(e + 8), sz, (uint8_t)(al == 0xFFFFFFFFu ? 3 : al), *(const char **)(e + 16)); } }
            add_methods(ns, *(unsigned long *)(ro + 32), 0, &cxxctor);
            add_methods(object_getClass((id)ns), *(unsigned long *)(mro + 32), 0, 0);
            a2x_add_properties(ns, *(unsigned long *)(ro + 64));
            unsigned long pl = *(unsigned long *)(ro + 40);
            if (pl) { unsigned long n = *(unsigned long *)pl;
                for (unsigned long k = 0; k < n; k++) { unsigned long p = ((unsigned long *)(pl + 8))[k];
                    /* 10-20 a null entry in the protocol list read through null; the list is image data, never trusted */
                    if (!p) continue;
                    const char *pn = *(const char **)(p + 8);
                    Protocol *pr = pn ? objc_getProtocol(pn) : 0; if (pr) class_addProtocol(ns, pr); } }
            /* The guest class carries ARC ownership metadata that objc_allocateClassPair cannot synthesize: the strong and
               weak ivar layouts and RO_IS_ARC. Without them ivar_getOffsetAndMemoryManagement() reports "unknown" for every
               ivar and KVC (nib outlet connection) stores the object unretained, so the nib's top-level array is the only
               owner and the outlet dangles when the autorelease pool pops. */
            { unsigned long il = *(unsigned long *)(ro + 16), wl = *(unsigned long *)(ro + 56);
              if (il) class_setIvarLayout(ns, (const uint8_t *)il);
              if (wl) class_setWeakIvarLayout(ns, (const uint8_t *)wl);
              if (*(uint32_t *)ro & 0x80u) {
                  unsigned long rw = *(unsigned long *)((char *)ns + 32) & 0x00007ffffffffff8ul;
                  unsigned long nro = rw ? *(unsigned long *)(rw + 8) : 0;
                  if (nro & 1) nro = *(unsigned long *)(nro & ~1ul);   /* class_rw_ext_t: ro is its first field */
                  if (nro) { make_writable((void *)nro, 4); *(uint32_t *)nro |= 0x80u; }
                  else fprintf(a2x_errf(), "objc_bridge: %s - cannot set RO_IS_ARC (ro=%#lx)\n", class_getName(ns), nro); } }
            objc_registerClassPair(ns);
            /* the Swift tail: flags, instanceAddressPoint, instance/class sizes, the context DESCRIPTOR at +0x40 and
               the ivar destroyer. Copied verbatim from the guest class, which already holds the right values; objc
               itself never reads past 0x28, so these bytes are ours. */
            if (gclsz) memcpy((char *)ns + 0x28, (const char *)(c + 0x28), gclsz - 0x28);
            /* 10-20 A NULL DEREF AT ADDRESS 0 KILLED FINDER HERE, three frames from main. class_addIvar() above is
                  allowed to FAIL (the runtime refuses a duplicate name, and refuses everything once the pair is
                  registered), and this loop then called ivar_getOffset(NULL), which reads through null. The ivar's
                  offset variable can also be absent, and *off = … then WRITES to null. Neither case said anything.
                Both are now named and skipped: a missing ivar is a real defect in this class's layout, so it is
                  reported every time rather than swallowed — translated code reading that offset gets the 0 already
                  there, which is wrong but diagnosable, instead of the process dying with no message. */
            if (iv) { uint32_t es = *(uint32_t *)iv, n = *(uint32_t *)(iv + 4);   /* arm64 code reads these offset variables */
                for (uint32_t k = 0; k < n; k++) { unsigned long e = iv + 8 + (unsigned long)k * es;
                    const char *ivn = *(const char **)(e + 8);
                    Ivar v = class_getInstanceVariable(ns, ivn);
                    int32_t *off = *(int32_t **)e;
                    if (!v || !off) {
                        fprintf(a2x_errf(), "objc_bridge: %s.%s — %s; its offset variable is left as found\n",
                                class_getName(ns), ivn ? ivn : "(unnamed)",
                                !v ? "class_addIvar did not take this ivar" : "no offset variable in the image");
                        continue;
                    }
                    make_writable(off, 4); *off = (int32_t)ivar_getOffset(v); } }
            }   /* end of the rebuild path; a realized Swift class needed none of it */
            /* the C++ constructor chain: record this class's own, then give it a +allocWithZone: that runs
                  the chain. Installed on every class that HAS one — a subclass without its own inherits this
                  override, and `self` there is the subclass, so the walk still covers the whole chain.
                  a2x_alloc_with_zone allocates through the nearest INHERITED +allocWithZone:, so a class under
                  NSWindow or CALayer keeps its native allocator and only the placeholder case is skipped. */
            if (cxxctor) {
                ctor_put(ns, cxxctor);
                class_addMethod(object_getClass((id)ns), sel_registerName("allocWithZone:"),
                                (IMP)a2x_alloc_with_zone, "@@:^v");
            }
            gCls[gNCls].pending = pending_realize;
            gCls[gNCls].bits0 = pending_realize ? *(unsigned long *)(c + 0x20) : 0;
            gCls[gNCls].a = c; gCls[gNCls].n = ns; gNCls++; gCls[gNCls].a = *(unsigned long *)c;   /* metaclass too */
            gCls[gNCls].n = object_getClass((id)ns); gCls[gNCls].pending = 0; gCls[gNCls].bits0 = 0; gNCls++; gCls = realloc(gCls, (gNCls + 2) * sizeof *gCls);
            work[i] = 0; done++; progress = 1;
        }
    }
    /* 10-26 OWED, NOT FATAL — and it says WHICH class and WHICH superclass, which the empty die2 never
          did. A class still unsettled here is waiting on a guest image that has not registered yet, and the
          next call retries the whole list. The cost of the trade is explicit: if no later image ever supplies
          the superclass, the program runs with those classes unregistered instead of aborting, and these
          lines are the only warning — so they are printed every time, never once. */
    if (done < nwork) {
        unsigned long *ow = (unsigned long *)malloc((nwork - done) * sizeof *ow);
        if (!ow) die2("out of memory recording the classes still owed", "");
        unsigned long n = 0;
        for (unsigned long i = 0; i < nwork; i++) {
            if (!work[i]) continue;
            unsigned long k = work[i], sup = *(unsigned long *)(k + 8);
            const char *nm = *(const char **)(RO(k) + 24);
            /* the superclass record is NOT dereferenced for a name: it is the thing we could not resolve,
                  so it may not be a class at all, and a diagnostic that faults is worse than no diagnostic. */
            fprintf(a2x_errf(), "objc_bridge: %s is NOT REGISTERED YET — its superclass is the guest record "
                    "%#lx, which no image has registered. It is owed to the next image's registration.\n",
                    nm ? nm : "(unnamed)", sup);
            ow[n++] = k;
        }
        free(gOwed); gOwed = ow; gNOwed = n;
    } else { free(gOwed); gOwed = 0; gNOwed = 0; }
    free(work);
    for (unsigned long i = 0; i < ncat; i++) {   /* categories: cat_t {name, cls, instanceMethods, classMethods, protocols ...} */
        unsigned long ct = ((unsigned long *)cat)[i]; Class tc = mapcls(*(unsigned long *)(ct + 8));
        /* 10-27 THIS SKIP WAS SILENT, and it is the only place a category on a class whose
              _OBJC_CLASS_$_ import never resolved could ever have been reported. Photos sends a category
              CLASS method to the NATIVE AVPlayer metaclass and the runtime has never heard of it
              ("NO ENCODING px_enableAutomaticContentAwareAudioRouting: class=AVPlayer meta=1 guestTwin=0x0
              respondsTo=0"), which is indistinguishable from a bad receiver until this line says which
              category it dropped and what it could not resolve. */
        /* 10-27 A CATEGORY ON A SWIFT CLASS THE IMAGE NEVER LISTED CRASHED libobjc (pc 0, fault 0x20, in
              prepareMethodLists — Reminders `Reminders` on TTRMTemplatesListCellView 0x1005926f0; Shortcuts the same shape).
              That class is not in __objc_classlist (Swift registers it lazily through its metadata accessor), so nothing here
              ever built it and mapcls() fell back to the raw GUEST record — which class_replaceMethod then walked as if it
              were a registered class. libobjc itself parks a category on a not-yet-realized class until the class appears;
              we cannot wait for the accessor, so give the record the same pending entry a listed Swift class gets (it is
              realized on first use, and just below because the category needs it now). Scoped to a guest record whose
              is-Swift bits are set and that no gCls entry holds, so every other category is untouched. */
        {   unsigned long tg = *(unsigned long *)(ct + 8);
            if (tc == (Class)tg && is_arm(tg) && (*(unsigned long *)(tg + 0x20) & 3)) {
                unsigned long tsup = *(unsigned long *)(tg + 8);
                /* MEASURED on Reminders (0x1005926f0): isa and the SUPERCLASS WORD ARE BOTH SET BY THE SWIFT RUNTIME LATER —
                      the static record's superclass slot is 0 and so is its metaclass's, with no bind on either. It is a metadata
                      TEMPLATE, not a class, and the runtime that eventually builds the live class builds it elsewhere, so no
                      realization of this record can make class_replaceMethod valid. Registering it still died in
                      prepareMethodLists at 0x20. Say so, name it, and skip the category: its methods do not exist and a send
                      of one raises, which is the same trade the DROPPED branch below makes for an unresolved target. */
                if (!tsup) {
                    if (A2X_DBGENV("ARM2X86_TRACE_REGCLS")) { unsigned long *t = (unsigned long *)tg; unsigned long d = t[8];
                        fprintf(a2x_errf(), "[regcat]   template words:"); for (int q = 0; q < 12; q++) fprintf(a2x_errf(), " %#lx", t[q]);
                        if (is_arm(d)) fprintf(a2x_errf(), " | descriptor %#lx flags=%#x parent=%#x name=%#x acc=%#x fields=%#x", d, ((unsigned *)d)[0], ((unsigned *)d)[1], ((unsigned *)d)[2], ((unsigned *)d)[3], ((unsigned *)d)[4]);
                        fprintf(a2x_errf(), "\n"); }
                    a2x_pc_park(tg, ct);
                    if (A2X_DBGENV("ARM2X86_TRACE_REGCLS"))
                        fprintf(a2x_errf(), "[regcat] PARKED category %s on Swift template %#lx (superclass word 0) until the Swift runtime completes it\n",
                                *(const char **)(ct) ? *(const char **)(ct) : "(unnamed)", tg);
                    continue;
                }
                if (tsup) { make_writable((void *)(tg + 8), 8); *(unsigned long *)(tg + 8) = (unsigned long)mapcls(tsup); }
                gCls = realloc(gCls, (gNCls + 4) * sizeof *gCls);
                gCls[gNCls].a = tg; gCls[gNCls].n = (Class)tg; gCls[gNCls].pending = 1;
                gCls[gNCls].bits0 = *(unsigned long *)(tg + 0x20); gNCls++;
                gCls[gNCls].a = *(unsigned long *)tg; gCls[gNCls].n = object_getClass((id)tg);
                gCls[gNCls].pending = 0; gCls[gNCls].bits0 = 0; gNCls++;
                if (A2X_DBGENV("ARM2X86_TRACE_REGCLS")) { unsigned long *t = (unsigned long *)tg, *m = (unsigned long *)t[0];
                    fprintf(a2x_errf(), "[regcat]   cls isa=%#lx sup=%#lx cache=%#lx bits=%#lx | meta isa=%#lx sup=%#lx bits=%#lx\n", t[0], t[1], t[2], t[4],
                            is_arm(t[0]) ? m[0] : 0, is_arm(t[0]) ? m[1] : 0, is_arm(t[0]) ? m[4] : 0); fflush(a2x_errf()); }
                tc = (Class)tg;
                fprintf(a2x_errf(), "objc_bridge: category %s targets Swift class %#lx that is not in __objc_classlist — "
                        "registered it as a pending in-place class\n", *(const char **)(ct) ? *(const char **)(ct) : "(unnamed)", tg);
            }
        }
        if (!tc) {
            const char *cnm = *(const char **)(ct);
            fprintf(a2x_errf(), "objc_bridge: the category %s is DROPPED — its target class record %#lx did "
                    "not resolve, so none of its methods exist and every send of one raises\n",
                    cnm ? cnm : "(unnamed)", *(unsigned long *)(ct + 8));
            continue;
        }
        /* 10-25 A CATEGORY ON A PENDING (UNREALIZED) SWIFT CLASS CRASHED libobjc. macOS 27 Shortcuts has a category
              `Shortcuts` on its own Swift class 0x100137c48; class_replaceMethod(windowShouldClose:) on the unrealized
              class died in prepareMethodLists (fault 0x20). Realize it at the moment something needs it to be a class,
              the same just-in-time rule as the by-name hook — eager realization for everything stays off. */
        if (A2X_DBGENV("ARM2X86_TRACE_REGCLS")) { int fk = -1; for (unsigned long k = 0; k < gNCls; k++) if (gCls[k].n == tc) { fk = (int)k; break; }
            fprintf(a2x_errf(), "[regcat] %s target=%#lx tc=%p gcls_idx=%d pending=%d\n", *(const char **)(ct) ? *(const char **)(ct) : "?",
                    *(unsigned long *)(ct + 8), (void *)tc, fk, fk >= 0 ? gCls[fk].pending : -1); fflush(a2x_errf()); }
        if (A2X_DBGENV("ARM2X86_TRACE_REGCLS")) { unsigned long tg = *(unsigned long *)(ct + 8); int incl = 0;
            for (unsigned long q = 0; q < ncl; q++) if (((unsigned long *)cl)[q] == tg) incl = 1;
            const char *tn = "?"; if (is_arm(tg)) { unsigned long ro2 = *(unsigned long *)(tg + 0x20) & 0x7ffffffffff8UL; if (is_arm(ro2)) tn = *(const char **)(ro2 + 24); }
            fprintf(a2x_errf(), "[regcat]   target name=%s in_classlist=%d ncl=%lu bits=%#lx\n", tn ? tn : "?", incl, ncl, is_arm(tg) ? *(unsigned long *)(tg + 0x20) : 0); fflush(a2x_errf()); }
        for (unsigned long k = 0; k < gNCls; k++)
            if (gCls[k].n == tc && gCls[k].pending) { a2x_realize_now(&gCls[k]); break; }
        /* a category cannot add ivars, so it cannot bring a C++ constructor the class did not already have */
        add_methods(tc, *(unsigned long *)(ct + 16), 1, 0);
        add_methods(object_getClass((id)tc), *(unsigned long *)(ct + 24), 1, 0);
    }
    /* TEST HOOK, off unless ARM2X86_TEST_COMPLETE_PARKED=1: ask the real Swift runtime to initialise every parked category
          target now (swift_getInitializedObjCClass is what a guest metadata accessor calls), so the attach can be seen on an
          app that would not touch the class inside the test window. It exercises the same poll the live path uses. */
    if (gNPC && A2X_DBGENV("ARM2X86_TEST_COMPLETE_PARKED")) {
        /* a class whose descriptor says singleton metadata initialization is completed by swift_getSingletonMetadata(request,
              descriptor) — the call its guest metadata accessor makes */
        a2x_w2 (*gsm)(unsigned long, unsigned long) = (a2x_w2 (*)(unsigned long, unsigned long))dlsym(RTLD_DEFAULT, "swift_getSingletonMetadata");
        for (unsigned long i = 0; gsm && i < gNPC; i++) if (!gPC[i].done) {
            unsigned long desc = *(unsigned long *)(gPC[i].tg + 0x40);
            fprintf(a2x_errf(), "[regcat] TEST completing %#lx via swift_getSingletonMetadata(0, %#lx)\n", gPC[i].tg, desc);
            a2x_w2 got = gsm(0, desc);
            fprintf(a2x_errf(), "[regcat] TEST   -> %#lx/%#lx sup now %#lx\n", got.w0, got.w1, *(unsigned long *)(gPC[i].tg + 8));
            a2x_pc_poll_all(); }
    }
    for (unsigned long i = 0; i < nrefs; i++) { unsigned long *r = (unsigned long *)refs + i;
        if (is_arm(*r)) { make_writable(r, 8); *r = (unsigned long)mapcls(*r); } }
    /* 10-20 A ZERO __objc_superrefs SLOT IS A SILENT INFINITE RECURSION. objc_msgSendSuper2 starts its lookup at
          class_getSuperclass(super_class); hand it nil and libobjc restarts from the RECEIVER, so `super init` finds the
          class's own init and the object initialises itself until the stack is gone — measured on Dock's
          DockCore.SystemAppearanceMonitor, which looped init -> NSUserDefaults -> init through 60 MB of stack.
          The loop below only ever rewrote slots that are already guest addresses, so a zero slot passed through unsaid. */
    { unsigned long zero = 0;
      for (unsigned long i = 0; i < nsrefs; i++) { unsigned long *r = (unsigned long *)srefs + i;
          if (!*r) { zero++; continue; }
          if (is_arm(*r)) { make_writable(r, 8); *r = (unsigned long)mapcls(*r); } }
      if (zero) fprintf(a2x_errf(), "objc_bridge: %lu of %lu __objc_superrefs slots are NULL — every `super` send through one"
                        " of them restarts at the receiver and recurses forever\n", zero, nsrefs); }
    /* 10-21 ONE GUEST CLASS, HOW MANY LIVE CLASSES? There are two registration paths — a Swift class is
          realized IN PLACE (`ns = (Class)c`, so the guest address itself becomes a valid Class) and a plain
          ObjC class gets an `objc_allocateClassPair` TWIN at a different address. If both ever happen for one
          guest class the program holds two live classes with the same name: `objc_getClass(name)` returns one
          while instances carry the other, and every identity comparison between them fails. Measured in pkd —
          the PKDServer twin at 0x6000019e8d20 (twin_of_guest=0x200033a88) alongside instances whose isa is
          0x200033a88, itself a walkable class with the right name, size 144 and the right superclass chain.
           COUNT IT; do not infer it from class_ro sizes. Static instanceStart/instanceSize are compile-time
          snapshots and libobjc SLIDES ivars at realization (PKDServer: static 8/64 over a superclass of 88,
          live 144 = 88 + (64-8)), so a static-vs-live size comparison flags classes that are perfectly
          correct. Registration identity is the fact; sizes are not. objc_copyClassList is the safe test — it
          asks the runtime which addresses are really registered instead of dereferencing a suspect pointer. */
    if (A2X_DBGENV("ARM2X86_CLSDUMP")) {
        unsigned int nall = 0; Class *all = objc_copyClassList(&nall);
        unsigned long inplace = 0, inplace_reg = 0, inplace_cls = 0, inplace_meta = 0, twinned = 0, dup = 0, tot = 0;
        for (unsigned long i = first; i < gNCls; i++) {
            if (!gCls[i].n) continue;
            tot++;
            int is_inplace = (gCls[i].n == (Class)gCls[i].a), guest_registered = 0;
            for (unsigned int k = 0; k < nall; k++)
                if (all[k] == (Class)gCls[i].a) { guest_registered = 1; break; }
            /* an in-place class is only correct if the runtime really REGISTERED it at the guest address —
                  that is the whole point of the exported-class fix, so count it rather than assume it. */
            /* gCls holds a CLASS and its METACLASS alternately (the +load loop walks i += 2), and a
                  metaclass is NEVER in objc_copyClassList — so split the count, or a perfectly correct
                  result reads as half-failed. Any REAL class in place but unlisted is named. */
            if (is_inplace) {
                inplace++;
                if (class_isMetaClass(gCls[i].n)) inplace_meta++;
                else { inplace_cls++;
                       if (guest_registered) inplace_reg++;
                       else fprintf(a2x_errf(), "  UNLISTED  %-26s guest=0x%lx in place but NOT in "
                                    "objc_copyClassList\n", class_getName(gCls[i].n), gCls[i].a); }
            }
            else twinned++;
            if (!is_inplace && guest_registered) {
                dup++;
                if (dup <= 12) {
                    const char *nm = class_getName(gCls[i].n);
                    fprintf(a2x_errf(), "  DUP  %-28s guest=0x%-11lx twin=%p byname=%p %s\n",
                            nm, gCls[i].a, (void *)gCls[i].n, (void *)objc_getClass(nm),
                            objc_getClass(nm) == gCls[i].n ? "(name->twin)" : "(name->the OTHER one)");
                }
            }
        }
        fprintf(a2x_errf(), "objc_bridge: CLSDUMP %lu guest classes: %lu in place (%lu real classes, %lu CONFIRMED listed; %lu metaclasses, never listed), %lu twinned, "
                "**%lu DUPLICATE** (twin AND guest address both registered)\n", tot, inplace, inplace_cls, inplace_reg, inplace_meta, twinned, dup);
        free(all);
    }
    /* 10-23 OPT-IN EAGER REALIZATION — OFF BY DEFAULT, a diagnostic for one measured failure.
          ControlCenter's Swift exclusivity trap fires two callback levels deep inside
          swift::MetadataCacheEntryBase<SingletonMetadataCacheEntry>::doInitialization: metadata for a guest
          class is being completed in the middle of unrelated work (a block copy helper, via
          _call_copy_helpers_excp) while a modify access on a DarwinNotification is still open. Realizing
          this image's classes up front moves that completion out of there, which is the hypothesis to test.
        NOT the default, and do not make it one on a hunch: lazy realization exists BECAUSE realizing
          early hid every Swift class from NSClassFromString and NSApplicationMain exited with
          "Unable to find class: Application" — the by-name hook above is what repaired that. */
    if (A2X_DBGENV("ARM2X86_EAGER_REALIZE"))
        for (unsigned long i = first; i < gNCls; i++)
            if (gCls[i].pending) a2x_realize_now(&gCls[i]);
    /* 10-03: WAS from 0 — once per IMAGE, every earlier image's +load ran again. Only this image's classes. */
    for (unsigned long i = first; i < gNCls; i += 2) {   /* +load, as the runtime would for an image it loaded */
        Class c = gCls[i].n; unsigned int n = 0; Method *ms = class_copyMethodList(object_getClass((id)c), &n);
        for (unsigned int k = 0; k < n; k++) if (method_getName(ms[k]) == sel_registerName("load")) {
            ((void (*)(id, SEL))objc_msgSend)((id)c, sel_registerName("load")); break; }
        free(ms);
    }
}

/* Explicit native API boundary: libobjc may copy/invoke the block internally. */
void __arm2x86_rf_imp_implementationWithBlock(void) {
    RX(0) = (unsigned long)imp_implementationWithBlock(__arm2x86_blk((void *)RX(0)));
}

/* A direct IMP must keep its original signature and bypass any later swizzled dispatch. */
struct a2x_native_imp_entry {
    unsigned long target; SEL sel; struct a2x_plan *plan;
    unsigned conflict; struct a2x_native_imp_entry *next;
};
#define A2X_NATIVE_IMP_BUCKETS 4096u
static struct a2x_native_imp_entry *a2x_native_imps[A2X_NATIVE_IMP_BUCKETS];
static unsigned a2x_native_imp_bucket(unsigned long target, SEL sel) {
    return (unsigned)((target >> 4) ^ ((unsigned long)sel >> 3)) & (A2X_NATIVE_IMP_BUCKETS - 1);
}
static pthread_mutex_t a2x_native_impm = PTHREAD_MUTEX_INITIALIZER;
static void a2x_record_native_imp(IMP imp, SEL sel, const char *types) {
    Dl_info native_image;
    if (!imp || !sel || !a2x_encoded_signature_valid(types, 0) || !dladdr((void *)imp, &native_image)) return;
    unsigned bucket = a2x_native_imp_bucket((unsigned long)imp, sel);
    pthread_mutex_lock(&a2x_native_impm);
    for (struct a2x_native_imp_entry *e = a2x_native_imps[bucket]; e; e = e->next) {
        if (e->target == (unsigned long)imp && e->sel == sel) {
            if (strcmp(e->plan->types, types)) __atomic_store_n(&e->conflict, 1, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&a2x_native_impm); return;
        }
    }
    struct a2x_native_imp_entry *e = calloc(1, sizeof *e);
    struct a2x_plan *p = calloc(1, sizeof *p);
    if (!e || !p || !(p->types = strdup(types))) die2("native IMP plan allocation", types);
    const char *t = parse_type(p->types, &p->rt);
    while (*t >= '0' && *t <= '9') ++t;
    while (*t) {
        if (p->na == A2X_MAXARG) die2("native IMP argument count", types);
        p->aenc[p->na] = skipq(t); t = parse_type(t, &p->at[p->na++]);
        while (*t >= '0' && *t <= '9') ++t;
    }
    if (p->na < 2 || ffi_prep_cif(&p->cif, FFI_DEFAULT_ABI, p->na, p->rt, p->at) != FFI_OK)
        die2("native IMP signature", types);
    /* Keep the existing generic marshaller; no receiver lookup and no objc_msgSend dispatch.
        10-30 EXCEPT for a variadic IMP: only then is the plan classified, so it takes the simple path with the arm
       stack tail (vtail). Every other direct IMP keeps exactly the ffi path it had. */
    { a2x_plan_classify(p, (const void *)imp); if (!p->vtail) { p->simple = 0; p->vtail = 0; } }
    e->target = (unsigned long)imp; e->sel = sel; e->plan = p; e->next = a2x_native_imps[bucket];
    __atomic_store_n(&a2x_native_imps[bucket], e, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&a2x_native_impm);
}
void *a2x_native_imp_plan(unsigned long target, unsigned long selector) {
    unsigned bucket = a2x_native_imp_bucket(target, (SEL)selector);
    for (struct a2x_native_imp_entry *e = __atomic_load_n(&a2x_native_imps[bucket], __ATOMIC_ACQUIRE); e; e = e->next)
        if (e->target == target && e->sel == (SEL)selector) {
            if (__atomic_load_n(&e->conflict, __ATOMIC_ACQUIRE)) die2("conflicting native IMP signatures", sel_getName(e->sel));
            return e->plan;
        }
    return NULL;
}
void a2x_call_native_imp(unsigned long target, void *plan) { msg_send(0, plan, target); }
void __arm2x86_rf_class_getMethodImplementation(void) {
    Class cls = (Class)__arm2x86_mapcls(RX(0)); SEL sel = (SEL)RX(1);
    IMP imp = class_getMethodImplementation(cls, sel);
    Method method = class_getInstanceMethod(cls, sel);
    if (method && method_getImplementation(method) == imp)
        a2x_record_native_imp(imp, sel, method_getTypeEncoding(method));
    RX(0) = (unsigned long)imp;
}
void __arm2x86_rf_method_getImplementation(void) {
    Method method = (Method)RX(0); IMP imp = method_getImplementation(method);
    if (method) a2x_record_native_imp(imp, method_getName(method), method_getTypeEncoding(method));
    RX(0) = (unsigned long)imp;
}
