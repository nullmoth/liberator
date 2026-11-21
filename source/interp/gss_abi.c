/* gss_abi.c — GSS-API across the arm64 / x86_64 boundary. The x86_64 GSS headers are #pragma pack(2); arm64's are not.
   reuses: host.c a2x_late_wrapper (the name -> host function table every bind consults first) — this file answers its
     misses; native GSS.framework does all the real work, this file only re-lays the structs that differ.
   new-because: 11-01 offline ssh ruler (vm/stock27-1101/sshrun.sh), host 1101aa: the stock-27 sshd-auth SIGSEGVs in native
     gss_test_oid_set_member with rdi = 0x0005e661_00000000 — the guest pointer 0x1_0005e661 read 4 bytes early. Apple's
     x86_64 gssapi.h wraps every type in #pragma pack(push,2) ("Compatibility with MIT Kerberos on the Mac"); the arm64
     build does not. So gss_OID_desc {u32 length; void *elements} is 12 bytes with elements at +4 on x86 and 16 bytes with
     elements at +8 on arm64; a gss_OID_set's array strides 12 vs 16; gss_channel_bindings_struct is 56 vs 64.
     gss_buffer_desc and gss_OID_set_desc themselves are {size_t, pointer} and do not differ.

    THE RULE: an OID or OID set the GUEST can see is always arm64 layout; one native GSS sees is always packed.
      - The OID-set functions that are pure data structure (create_empty, add_member, test_member, release) run HERE on
        arm64-layout sets. A set native GSS returns is converted at once and released natively.
      - OIDs going in: guest desc -> interned packed copy. Coming out: native desc -> interned arm64 copy. Interned copies
        are never freed (an OID is a constant; a process sees a handful; the table is capped and says so when full).
      - OID data exports (GSS_C_NT_* pointer variables, __gss_*_oid_desc descriptors) bind to arm64 copies.
    NOT covered — named so nobody assumes they are: krb5.h structs (krb5_creds etc. are pack(2) on x86 too; reached only
      by KerberosAuthentication / password-to-ticket), gss_duplicate_oid / gss_release_oid, and the Apple/Heimdal
      extensions that take OIDs (gss_inquire_attrs_for_mech, gss_aapl_*, ...). Every wrapped name is in g_fn below.
   ARM2X86_NO_GSSABI=1 turns the whole layer off (binds go native exactly as before); ARM2X86_TRACE_GSS=1 traces it.
   Selftest (studio, real x86 GSS): clang -arch x86_64 -DGSS_ABI_SELFTEST gss_abi.c -framework GSS -o gsst && ./gsst
*/
#include <dlfcn.h>
#include <os/lock.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t OM;
typedef struct { uint32_t length; uint32_t pad_; void *elements; } g_oid;      /* arm64: 16 bytes, elements @+8 */
typedef struct { size_t length; void *value; } gbuf;                           /* identical on both */
typedef struct { uint32_t ia_type; uint32_t p0_; gbuf ia; uint32_t aa_type; uint32_t p1_; gbuf aa; gbuf app; } g_cb;
#pragma pack(push, 2)
typedef struct { uint32_t length; void *elements; } n_oid;                     /* x86_64 GSS: 12 bytes, elements @+4 */
typedef struct { uint32_t ia_type; gbuf ia; uint32_t aa_type; gbuf aa; gbuf app; } n_cb;
#pragma pack(pop)
typedef struct { size_t count; g_oid *elements; } g_set;
typedef struct { size_t count; n_oid *elements; } n_set;
_Static_assert(sizeof(g_oid) == 16 && offsetof(g_oid, elements) == 8, "arm64 gss_OID_desc");
_Static_assert(sizeof(n_oid) == 12 && offsetof(n_oid, elements) == 4, "x86_64 pack(2) gss_OID_desc");
_Static_assert(sizeof(g_cb) == 64 && sizeof(n_cb) == 56, "gss_channel_bindings_struct");

#define GSS_FAIL    0x000d0000u   /* GSS_S_FAILURE                13 << 16 */
#define GSS_BADREAD 0x01000000u   /* GSS_S_CALL_INACCESSIBLE_READ  1 << 24 */
#define GSS_BADWR   0x02000000u   /* GSS_S_CALL_INACCESSIBLE_WRITE 2 << 24 */
#define OID_MAXLEN  1024u         /* chosen: a real OID is < 40 bytes; a length past this is a misread desc, not an OID */
#define INTERN_MAX  512u          /* chosen: Heimdal ships ~60 mech + name-type OIDs */

static int gtr(void) { static int t = -1; if (t < 0) t = A2X_DBGENV("ARM2X86_TRACE_GSS") != 0; return t; }

/* native symbol: Kerberos (the MIT-compat names), then GSS, then the flat walk. NOLOAD: binding never loads anything. */
static void *gsym(const char *n) {
    static void *hk, *hg; static int tried;
    if (!tried) {
        hk = dlopen("/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos", RTLD_LAZY | RTLD_NOLOAD);
        hg = dlopen("/System/Library/Frameworks/GSS.framework/Versions/A/GSS", RTLD_LAZY | RTLD_NOLOAD);
        tried = 1;
    }
    void *p = hg ? dlsym(hg, n) : 0;
    if (!p && hk) p = dlsym(hk, n);
    if (!p) p = dlsym(RTLD_DEFAULT, n);
    return p;
}
#define NATIVE(T, n)                                                                         \
    static T fp_;                                                                            \
    if (!fp_) fp_ = (T)gsym(n);                                                              \
    if (!fp_) { fprintf(stderr, "[gss-abi] native %s not found: GSS_S_FAILURE\n", n); return GSS_FAIL; }

/* ── interning ───────────────────────────────────────────────────────────────────────────────────────────── */
struct ient { g_oid *g; n_oid *n; };
static struct ient g_it[INTERN_MAX];
static unsigned g_in;
static os_unfair_lock g_lk = OS_UNFAIR_LOCK_INIT;

static struct ient *intern_l(uint32_t len, const void *bytes) {          /* g_lk held */
    if (len > OID_MAXLEN || (len && !bytes)) return 0;
    for (unsigned i = 0; i < g_in; i++)
        if (g_it[i].g->length == len && (!len || !memcmp(g_it[i].g->elements, bytes, len))) return &g_it[i];
    if (g_in >= INTERN_MAX) {
        static int said; if (!said++) fprintf(stderr, "[gss-abi] intern table full (%u OIDs): further OIDs fail\n", INTERN_MAX);
        return 0;
    }
    void *b = malloc(len ? len : 1); g_oid *g = calloc(1, sizeof *g); n_oid *n = calloc(1, sizeof *n);
    if (!b || !g || !n) { free(b); free(g); free(n); return 0; }
    if (len) memcpy(b, bytes, len);
    g->length = n->length = len; g->elements = n->elements = b;
    g_it[g_in].g = g; g_it[g_in].n = n;
    return &g_it[g_in++];
}
/* guest (arm64) desc -> packed desc native GSS can read. *bad = 1 when it cannot be done (the caller fails the call). */
static const n_oid *to_native(const g_oid *g, int *bad) {
    if (!g) return 0;
    const n_oid *r = 0;
    os_unfair_lock_lock(&g_lk);
    for (unsigned i = 0; i < g_in && !r; i++) if (g_it[i].g == g) r = g_it[i].n;
    if (!r) { struct ient *e = intern_l(g->length, g->elements); if (e) r = e->n; }
    os_unfair_lock_unlock(&g_lk);
    if (!r) { *bad = 1; fprintf(stderr, "[gss-abi] guest OID %p (length %u) could not be re-laid: GSS_S_FAILURE\n",
                                (const void *)g, g->length); }
    return r;
}
/* native (packed) desc -> arm64 desc the guest can read */
static const g_oid *to_guest(const n_oid *n) {
    if (!n) return 0;
    const g_oid *r = 0;
    os_unfair_lock_lock(&g_lk);
    for (unsigned i = 0; i < g_in && !r; i++) if (g_it[i].n == n) r = g_it[i].g;
    if (!r) { struct ient *e = intern_l(n->length, n->elements); if (e) r = e->g; }
    os_unfair_lock_unlock(&g_lk);
    if (!r) fprintf(stderr, "[gss-abi] native OID %p (length %u) could not be re-laid: the guest gets GSS_C_NO_OID\n",
                    (const void *)n, n->length);
    return r;
}
static int same(const g_oid *a, const g_oid *b) {
    return a->length == b->length && (!a->length || !memcmp(a->elements, b->elements, a->length));
}

/* ── sets ────────────────────────────────────────────────────────────────────────────────────────────────── */
static void rel_native_set(n_set **s) {
    typedef OM (*F)(OM *, n_set **);
    static F f; if (!f) f = (F)gsym("gss_release_oid_set");
    OM m = 0;
    if (f && s && *s) f(&m, s);
}
static g_set *set_from_native(const n_set *ns) {
    g_set *s = calloc(1, sizeof *s);
    if (!s) return 0;
    if (ns && ns->count) {
        if (!(s->elements = calloc(ns->count, sizeof *s->elements))) { free(s); return 0; }
        for (size_t i = 0; i < ns->count; i++) { const g_oid *g = to_guest(&ns->elements[i]); if (g) s->elements[s->count++] = *g; }
    }
    if (gtr()) fprintf(stderr, "[gss-abi] native set of %zu -> guest set of %zu\n", ns ? ns->count : 0, s->count);
    return s;
}
/* guest set -> a temporary packed set in *tmp (array in *arr, the caller frees it). 0 = fine, else the GSS error. */
static OM set_to_native(const g_set *g, n_set *tmp, n_oid **arr, n_set **out) {
    *arr = 0; *out = 0;
    if (!g) return 0;
    if (g->count) {
        if (!(*arr = calloc(g->count, sizeof **arr))) return GSS_FAIL;
        for (size_t i = 0; i < g->count; i++) {
            int bad = 0; const n_oid *n = to_native(&g->elements[i], &bad);
            if (bad) { free(*arr); *arr = 0; return GSS_FAIL; }
            (*arr)[i] = *n;
        }
    }
    tmp->count = g->count; tmp->elements = *arr; *out = tmp;
    return 0;
}
static const n_cb *cb_to_native(const g_cb *g, n_cb *t) {
    if (!g) return 0;                                   /* GSS_C_NO_CHANNEL_BINDINGS */
    t->ia_type = g->ia_type; t->ia = g->ia; t->aa_type = g->aa_type; t->aa = g->aa; t->app = g->app;
    return t;
}

/* ── the wrappers ────────────────────────────────────────────────────────────────────────────────────────── */
static OM w_create_empty_oid_set(OM *min, g_set **out) {
    if (min) *min = 0;
    if (!out) return GSS_BADWR;
    *out = calloc(1, sizeof **out);
    return *out ? 0 : GSS_FAIL;
}
static OM w_test_oid_set_member(OM *min, const g_oid *m, const g_set *s, int *present) {
    if (min) *min = 0;
    if (!m || !s || !present) return GSS_BADREAD;
    *present = 0;
    for (size_t i = 0; i < s->count; i++) if (same(&s->elements[i], m)) { *present = 1; break; }
    return 0;
}
static OM w_add_oid_set_member(OM *min, const g_oid *m, g_set **sp) {
    if (min) *min = 0;
    if (!m || !sp || !*sp) return GSS_BADREAD;
    int p = 0; w_test_oid_set_member(0, m, *sp, &p);
    if (p) return 0;                                    /* Heimdal: already a member is success, nothing added */
    os_unfair_lock_lock(&g_lk);
    struct ient *e = intern_l(m->length, m->elements);  /* stable bytes: the caller's may be on its stack */
    os_unfair_lock_unlock(&g_lk);
    if (!e) return GSS_FAIL;
    g_oid *a = realloc((*sp)->elements, ((*sp)->count + 1) * sizeof *a);
    if (!a) return GSS_FAIL;
    (*sp)->elements = a; a[(*sp)->count++] = *e->g;
    return 0;
}
static OM w_release_oid_set(OM *min, g_set **sp) {
    if (min) *min = 0;
    if (sp && *sp) { free((*sp)->elements); free(*sp); *sp = 0; }
    return 0;
}
static OM w_indicate_mechs(OM *min, g_set **out) {
    typedef OM (*F)(OM *, n_set **); NATIVE(F, "gss_indicate_mechs");
    if (!out) return GSS_BADWR;
    n_set *ns = 0; OM r = fp_(min, &ns);
    *out = 0;
    if (ns) { *out = set_from_native(ns); rel_native_set(&ns); if (!*out && !r) r = GSS_FAIL; }
    return r;
}
static OM w_import_name(OM *min, void *buf, const g_oid *t, void **name) {
    typedef OM (*F)(OM *, void *, const n_oid *, void **); NATIVE(F, "gss_import_name");
    int bad = 0; const n_oid *n = to_native(t, &bad);
    return bad ? GSS_FAIL : fp_(min, buf, n, name);
}
static OM w_display_status(OM *min, OM st, int type, const g_oid *mech, OM *ctx, void *buf) {
    typedef OM (*F)(OM *, OM, int, const n_oid *, OM *, void *); NATIVE(F, "gss_display_status");
    int bad = 0; const n_oid *n = to_native(mech, &bad);
    return bad ? GSS_FAIL : fp_(min, st, type, n, ctx, buf);
}
static OM w_display_name(OM *min, void *name, void *buf, const g_oid **type) {
    typedef OM (*F)(OM *, void *, void *, const n_oid **); NATIVE(F, "gss_display_name");
    const n_oid *n = 0; OM r = fp_(min, name, buf, type ? &n : 0);
    if (type) *type = to_guest(n);
    return r;
}
static OM w_canonicalize_name(OM *min, void *name, const g_oid *mech, void **out) {
    typedef OM (*F)(OM *, void *, const n_oid *, void **); NATIVE(F, "gss_canonicalize_name");
    int bad = 0; const n_oid *n = to_native(mech, &bad);
    return bad ? GSS_FAIL : fp_(min, name, n, out);
}
static OM w_acquire_cred(OM *min, void *name, OM t, const g_set *des, int usage, void **cred, g_set **act, OM *trec) {
    typedef OM (*F)(OM *, void *, OM, const n_set *, int, void **, n_set **, OM *); NATIVE(F, "gss_acquire_cred");
    n_set tmp, *nd; n_oid *arr; OM e = set_to_native(des, &tmp, &arr, &nd);
    if (e) return e;
    n_set *na = 0;
    OM r = fp_(min, name, t, nd, usage, cred, act ? &na : 0, trec);
    free(arr);
    if (act) { *act = 0; if (na) { *act = set_from_native(na); rel_native_set(&na); } }
    return r;
}
static OM w_accept_sec_context(OM *min, void **ctx, void *acred, void *in, const g_cb *cb, void **src,
                               const g_oid **mech, void *out, OM *flags, OM *trec, void **deleg) {
    typedef OM (*F)(OM *, void **, void *, void *, const n_cb *, void **, const n_oid **, void *, OM *, OM *, void **);
    NATIVE(F, "gss_accept_sec_context");
    n_cb t; const n_oid *n = 0;
    OM r = fp_(min, ctx, acred, in, cb_to_native(cb, &t), src, mech ? &n : 0, out, flags, trec, deleg);
    if (mech) *mech = to_guest(n);
    return r;
}
static OM w_init_sec_context(OM *min, void *cred, void **ctx, void *target, const g_oid *mech, OM fl, OM t,
                             const g_cb *cb, void *in, const g_oid **amech, void *out, OM *rfl, OM *trec) {
    typedef OM (*F)(OM *, void *, void **, void *, const n_oid *, OM, OM, const n_cb *, void *, const n_oid **, void *,
                    OM *, OM *);
    NATIVE(F, "gss_init_sec_context");
    int bad = 0; const n_oid *nm = to_native(mech, &bad);
    if (bad) return GSS_FAIL;
    n_cb tc; const n_oid *na = 0;
    OM r = fp_(min, cred, ctx, target, nm, fl, t, cb_to_native(cb, &tc), in, amech ? &na : 0, out, rfl, trec);
    if (amech) *amech = to_guest(na);
    return r;
}
static OM w_inquire_cred(OM *min, void *cred, void **name, OM *life, int *usage, g_set **mechs) {
    typedef OM (*F)(OM *, void *, void **, OM *, int *, n_set **); NATIVE(F, "gss_inquire_cred");
    n_set *ns = 0; OM r = fp_(min, cred, name, life, usage, mechs ? &ns : 0);
    if (mechs) { *mechs = 0; if (ns) { *mechs = set_from_native(ns); rel_native_set(&ns); } }
    return r;
}
static OM w_inquire_context(OM *min, void *ctx, void **src, void **targ, OM *life, const g_oid **mech, OM *fl,
                            int *local, int *open) {
    typedef OM (*F)(OM *, void *, void **, void **, OM *, const n_oid **, OM *, int *, int *);
    NATIVE(F, "gss_inquire_context");
    const n_oid *n = 0; OM r = fp_(min, ctx, src, targ, life, mech ? &n : 0, fl, local, open);
    if (mech) *mech = to_guest(n);
    return r;
}
static OM w_inquire_names_for_mech(OM *min, const g_oid *mech, g_set **names) {
    typedef OM (*F)(OM *, const n_oid *, n_set **); NATIVE(F, "gss_inquire_names_for_mech");
    int bad = 0; const n_oid *n = to_native(mech, &bad);
    if (bad) return GSS_FAIL;
    n_set *ns = 0; OM r = fp_(min, n, names ? &ns : 0);
    if (names) { *names = 0; if (ns) { *names = set_from_native(ns); rel_native_set(&ns); } }
    return r;
}
static OM w_inquire_mechs_for_name(OM *min, void *name, g_set **mechs) {
    typedef OM (*F)(OM *, void *, n_set **); NATIVE(F, "gss_inquire_mechs_for_name");
    n_set *ns = 0; OM r = fp_(min, name, mechs ? &ns : 0);
    if (mechs) { *mechs = 0; if (ns) { *mechs = set_from_native(ns); rel_native_set(&ns); } }
    return r;
}
static int w_oid_equal(const g_oid *a, const g_oid *b) {
    if (a == b) return 1;
    if (!a || !b) return 0;
    return same(a, b);
}

static const struct { const char *n; void *f; } g_fn[] = {
    { "gss_accept_sec_context", (void *)w_accept_sec_context }, { "gss_acquire_cred", (void *)w_acquire_cred },
    { "gss_add_oid_set_member", (void *)w_add_oid_set_member }, { "gss_canonicalize_name", (void *)w_canonicalize_name },
    { "gss_create_empty_oid_set", (void *)w_create_empty_oid_set }, { "gss_display_name", (void *)w_display_name },
    { "gss_display_status", (void *)w_display_status }, { "gss_import_name", (void *)w_import_name },
    { "gss_indicate_mechs", (void *)w_indicate_mechs }, { "gss_init_sec_context", (void *)w_init_sec_context },
    { "gss_inquire_context", (void *)w_inquire_context }, { "gss_inquire_cred", (void *)w_inquire_cred },
    { "gss_inquire_mechs_for_name", (void *)w_inquire_mechs_for_name },
    { "gss_inquire_names_for_mech", (void *)w_inquire_names_for_mech }, { "gss_oid_equal", (void *)w_oid_equal },
    { "gss_release_oid_set", (void *)w_release_oid_set }, { "gss_test_oid_set_member", (void *)w_test_oid_set_member },
};

/* an OID data export: a pointer variable (MIT names) or a descriptor (Heimdal __gss_*_oid_desc). */
static int is_desc_name(const char *nm) {
    size_t L = strlen(nm);
    return !strncmp(nm, "__gss_", 6) && L > 9 && !strcmp(nm + L - 9, "_oid_desc");
}
static int is_ptr_name(const char *nm) {
    size_t L = strlen(nm);
    if (!strncmp(nm, "GSS_C_NT_", 9) || !strncmp(nm, "GSS_KRB5_NT_", 12) || !strncmp(nm, "GSS_C_MA_", 9)
        || !strncmp(nm, "GSS_C_INQ_", 10) || !strncmp(nm, "gss_mech_", 9) || !strncmp(nm, "gss_nt_", 7)) return 1;
    return !strncmp(nm, "GSS_", 4) && L > 10 && !strcmp(nm + L - 10, "_MECHANISM");
}
static int plausible(const n_oid *n) {
    Dl_info di;
    return n && dladdr(n, &di) && n->length >= 1 && n->length <= 64 && n->elements && dladdr(n->elements, &di);
}
static void *data_oid(const char *nm) {
    int desc = is_desc_name(nm);
    if (!desc && !is_ptr_name(nm)) return 0;
    void *s = gsym(nm);
    if (!s) return 0;
    Dl_info di;
    const n_oid *n = desc ? (const n_oid *)s : (dladdr(*(void **)s, &di) ? *(const n_oid **)s : 0);
    if (!plausible(n)) {
        if (gtr()) fprintf(stderr, "[gss-abi] %s: not a recognisable OID (%s), bound natively\n", nm, desc ? "desc" : "pointer");
        return 0;
    }
    const g_oid *g = to_guest(n);
    if (!g) return 0;
    if (desc) return (void *)g;                        /* the guest takes &desc: hand it the arm64 desc */
    const g_oid **cell = malloc(sizeof *cell);          /* the guest loads the pointer variable: hand it one */
    if (!cell) return 0;
    *cell = g;
    return (void *)cell;
}

/* host.c a2x_late_wrapper's miss path: a GSS function or OID export -> the arm64-layout version; anything else -> 0. */
void *a2x_gss_wrapper(const char *nm) {
    if (!nm || !(nm[0] == 'g' || nm[0] == 'G' || nm[0] == '_')) return 0;
    if (A2X_DBGENV("ARM2X86_NO_GSSABI")) return 0;
    void *r = 0;
    if (nm[0] == 'g' && !strncmp(nm, "gss_", 4))
        for (unsigned i = 0; i < sizeof g_fn / sizeof g_fn[0] && !r; i++) if (!strcmp(nm, g_fn[i].n)) r = g_fn[i].f;
    if (!r) r = data_oid(nm);
    if (r && gtr()) fprintf(stderr, "[gss-abi] bind %s -> arm64-layout %p\n", nm, r);
    return r;
}

#ifdef GSS_ABI_SELFTEST
static int fails, arms;
static void arm(int ok, const char *name, const char *got) {
    arms++; if (!ok) fails++;
    printf("%s %s  [%s]\n", ok ? "ok  " : "FAIL", name, got);
}
static uint8_t KRB5[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 };              /* 1.2.840.113554.1.2.2 */
static uint8_t HBS[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x04 };        /* 1.2.840.113554.1.2.1.4 */
static uint8_t STRANGER[] = { 0x2a, 0x03, 0x04, 0x05 };
int main(void) {
    char b[200];
    dlopen("/System/Library/Frameworks/GSS.framework/Versions/A/GSS", RTLD_LAZY);
    dlopen("/System/Library/Frameworks/Kerberos.framework/Versions/A/Kerberos", RTLD_LAZY);
    g_oid krb5 = { sizeof KRB5, 0, KRB5 }, stranger = { sizeof STRANGER, 0, STRANGER };

    /* the bug, measured in this process: the native export read with the guest's layout */
    const n_oid *nh = *(const n_oid **)gsym("GSS_C_NT_HOSTBASED_SERVICE");
    uint64_t at8 = 0; memcpy(&at8, (const char *)nh + 8, 8);
    snprintf(b, sizeof b, "length %u, elements@+4 %p, the guest's elements@+8 0x%llx", nh->length, nh->elements,
             (unsigned long long)at8);
    arm(nh->length == sizeof HBS && !memcmp(nh->elements, HBS, sizeof HBS) && at8 != (uint64_t)(uintptr_t)nh->elements,
        " the native GSS_C_NT_HOSTBASED_SERVICE is packed: read at +8 (arm64) it is NOT the elements pointer", b);

    const g_oid **cell = a2x_gss_wrapper("GSS_C_NT_HOSTBASED_SERVICE");
    snprintf(b, sizeof b, "cell %p length %u", (void *)cell, cell && *cell ? (*cell)->length : 0);
    arm(cell && *cell && (*cell)->length == sizeof HBS && !memcmp((*cell)->elements, HBS, sizeof HBS),
        " the GSS_C_NT_HOSTBASED_SERVICE bind hands the guest an arm64 desc with the right 10 bytes", b);

    g_set *mechs = 0; OM min = 0; OM r = ((OM (*)(OM *, g_set **))a2x_gss_wrapper("gss_indicate_mechs"))(&min, &mechs);
    int present = -1;
    if (!r && mechs) w_test_oid_set_member(&min, &krb5, mechs, &present);
    snprintf(b, sizeof b, "r 0x%x, %zu mechs, krb5 present %d", r, mechs ? mechs->count : 0, present);
    arm(!r && mechs && mechs->count >= 1 && present == 1, " indicate_mechs returns an arm64 set in which krb5 is found", b);
    present = -1;
    if (mechs) w_test_oid_set_member(&min, &stranger, mechs, &present);
    snprintf(b, sizeof b, "present %d", present);
    arm(present == 0, " a stranger OID is NOT a member of that set", b);
    w_release_oid_set(&min, &mechs);
    arm(mechs == 0, "release_oid_set clears the caller's pointer", mechs ? "non-null" : "null");

    g_set *s = 0; w_create_empty_oid_set(&min, &s);
    uint8_t onstack[sizeof KRB5]; memcpy(onstack, KRB5, sizeof KRB5);
    g_oid tmp = { sizeof onstack, 0, onstack };
    w_add_oid_set_member(&min, &tmp, &s); w_add_oid_set_member(&min, &krb5, &s);
    memset(onstack, 0, sizeof onstack);                  /* the caller's bytes go away: the set must not care */
    present = -1; w_test_oid_set_member(&min, &krb5, s, &present);
    snprintf(b, sizeof b, "count %zu, present %d", s ? s->count : 0, present);
    arm(s && s->count == 1 && present == 1, "add_oid_set_member dedups and keeps its own bytes after the caller's die", b);

    void *name = 0; gbuf in = { 14, (void *)"host@localhost" };
    r = w_import_name(&min, &in, *cell, &name);
    gbuf out = { 0, 0 }; const g_oid *type = 0; OM r2 = name ? w_display_name(&min, name, &out, &type) : 0xffffffffu;
    snprintf(b, sizeof b, "import 0x%x display 0x%x type %p len %u '%.*s'", r, r2, (const void *)type,
             type ? type->length : 0, (int)out.length, out.value ? (char *)out.value : "");
    arm(!r && !r2 && type && same(type, *cell),
        " import_name takes the guest OID and display_name returns the name type as an arm64 desc", b);

    void *cred = 0; g_set *act = 0; OM tr = 0;
    r = w_acquire_cred(&min, 0, 0, s, 2 /* ACCEPT */, &cred, &act, &tr);
    snprintf(b, sizeof b, "r 0x%x minor 0x%x act %zu (no keytab here: failure is the honest answer)", r, min,
             act ? act->count : 0);
    arm(1, "acquire_cred with a guest desired set returns instead of faulting", b);
    w_release_oid_set(&min, &act);

    int bad = 0; const n_oid *a = to_native(*cell, &bad), *a2 = to_native(type, &bad);
    snprintf(b, sizeof b, "%p %p bad %d", (const void *)a, (const void *)a2, bad);
    arm(!bad && a == a2 && a->length == sizeof HBS && !memcmp(a->elements, HBS, sizeof HBS),
        "an interned arm64 OID maps back to ONE packed copy with the same bytes", b);

    snprintf(b, sizeof b, "malloc %p, GSS_C_NT_nonexistent %p", a2x_gss_wrapper("malloc"),
             a2x_gss_wrapper("GSS_C_NT_NO_SUCH_NAME_1101"));
    arm(!a2x_gss_wrapper("malloc") && !a2x_gss_wrapper("GSS_C_NT_NO_SUCH_NAME_1101"),
        " a non-GSS name and an absent GSS name bind nothing", b);
    setenv("ARM2X86_NO_GSSABI", "1", 1);
    void *off = a2x_gss_wrapper("gss_indicate_mechs");
    unsetenv("ARM2X86_NO_GSSABI");
    arm(!off && a2x_gss_wrapper("gss_indicate_mechs"), " ARM2X86_NO_GSSABI=1 turns the layer off, and only while set",
        off ? "still bound" : "off, then on");

    printf("%d arms, %d failed\n", arms, fails);
    return fails != 0;
}
#endif
