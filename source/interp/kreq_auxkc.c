/* kreq_auxkc.c — kext_request as an Intel kernelmanagerd sends it.
 *
 * WHY: macOS 27.2 ships kernelmanagerd for Apple silicon only. On Apple silicon the bootloader maps the auxiliary
 * kernel collection, so kernelmanagerd's first "loadfilesetkc" request names only the pageable (System) collection.
 * On Intel nothing else loads the auxiliary collection: an Intel kernelmanagerd names BOTH in that first request.
 * The kernel accepts the auxiliary collection ONLY in that first request of a boot: OSKext::loadFileSetKexts
 * (27.2 KDK 0xffffff8000989540) gates the AuxKCName branch on a flag that is cleared once the pageable collection
 * has been loaded, logs "KextLog: Ignoring AuxKC load from %s" and returns kOSKextReturnUnsupported (0xdc008009)
 * for any later request (measured on the box 11-06: a separate aux-only request returned exactly 0xdc008009).
 * Measured on the box 11-06 with the GPU up: "Loading FileSet KC(s)" -> "Loading Pageable KC from file
 * …SystemKernelExtensions.kc" and never "Loading Aux KC from file …", so every kext in
 * /Library/KernelCollections/AuxiliaryKernelExtensions.kc stayed unloaded.
 *
 * WHAT: the host exports kext_request; a guest's libSystem import binds here (the host answering the flat lookup is
 * deliberate, host.c a2x_flat_is_deliberate). Every request passes through unchanged EXCEPT an XML "loadfilesetkc"
 * request that names PageableKCName and no AuxKCName while the auxiliary collection file exists: that one gets
 * AuxKCName added, which is the request an Intel kernelmanagerd sends. The kernel still does every check itself
 * (the collection must be linked against the running boot collection), so this never builds, rewrites or deletes
 * a collection. A binary-serialized request is passed through untouched and said so on stderr.
 */
#include <mach/mach.h>
#include <mach/host_priv.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define KREQ_AUX_PATH "/Library/KernelCollections/AuxiliaryKernelExtensions.kc"

typedef kern_return_t (*kreq_fn)(host_priv_t, uint32_t, vm_offset_t, mach_msg_type_number_t, vm_offset_t *,
                                 mach_msg_type_number_t *, vm_offset_t *, mach_msg_type_number_t *, kern_return_t *);

/* Returns a malloc'd request with AuxKCName added, or NULL when the request must pass through unchanged.
 * Pure function of its inputs (aux_present is passed in) so the selftest can drive every arm. */
static char *kreq_add_aux(const char *req, size_t len, int aux_present, size_t *out_len, const char **why)
{
    *why = "not a loadfilesetkc request";
    if (!req || len < 8 || len > (1u << 20)) return NULL;
    if (req[0] != '<') {                         /* binary OSSerialize: never edited; memmem, since it holds NULs */
        if (memmem(req, len, "loadfilesetkc", 13)) *why = "binary-serialized loadfilesetkc (left unchanged)";
        return NULL;
    }
    if (memchr(req, 0, len) == NULL) { *why = "request not NUL-terminated"; return NULL; }
    if (!strstr(req, ">loadfilesetkc<")) return NULL;
    if (strstr(req, "<key>AuxKCName</key>")) { *why = "AuxKCName already present"; return NULL; }
    const char *pk = strstr(req, "<key>PageableKCName</key>");
    if (!pk) { *why = "no PageableKCName (not the first load)"; return NULL; }
    if (!aux_present) { *why = "no auxiliary collection file"; return NULL; }
    static const char ins[] = "<key>AuxKCName</key><string>" KREQ_AUX_PATH "</string>";
    size_t pre = (size_t)(pk - req), n = strlen(req), il = sizeof ins - 1;
    char *o = malloc(n + il + 1);
    if (!o) { *why = "out of memory"; return NULL; }
    memcpy(o, req, pre); memcpy(o + pre, ins, il); memcpy(o + pre + il, req + pre, n - pre + 1);
    *out_len = n + il + 1;                        /* the kernel parses a C string: count the NUL */
    *why = "added AuxKCName";
    return o;
}

static int __attribute__((unused)) kreq_aux_present(void)
{
    struct stat st;
    return stat(KREQ_AUX_PATH, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 4096;
}

/* MissingAuxKCBundles — the kernel's own definition (xnu kext_request_keys.h): "kexts which have been removed from
 * disk, but still exist in the AuxKC"; OSKext::isLoadable refuses to match any ID on that list. An Intel
 * kernelmanagerd lists an ID only when its bundle is gone from /Library/Extensions. Measured 11-06 on the box: the
 * interpreted Apple-silicon kernelmanagerd sends this request (the string is in its 27.2 binary) and the four aux
 * NVIDIA kexts never auto-loaded, although their bundles are on disk and a direct LoadFromKC loaded each one. So an
 * ID whose bundle IS on disk is dropped from the list; an ID whose bundle is really gone stays listed. */
typedef int (*kreq_on_disk_fn)(const char *bundle_id);

static char *kreq_filter_missing(const char *req, size_t len, kreq_on_disk_fn on_disk, size_t *out_len, int *dropped)
{
    *dropped = 0;
    if (!req || len < 8 || req[0] != '<' || !memchr(req, 0, len)) return NULL;
    if (!strstr(req, ">MissingAuxKCBundles<")) return NULL;
    const char *k = strstr(req, "<key>Missing Bundle IDs</key>");
    if (!k) return NULL;
    const char *a = strstr(k, "<array");
    if (!a) return NULL;
    const char *ae = strstr(a, "</array>");
    if (!ae) return NULL;                         /* "<array/>" (empty list): nothing to filter */
    size_t n = strlen(req);
    char *o = malloc(n + 1), *w = o;
    if (!o) return NULL;
    const char *p = req;
    while (p < ae) {
        const char *s = strstr(p, "<string");
        if (!s || s >= ae) break;
        const char *gt = strchr(s, '>'), *se = gt ? strstr(gt, "</string>") : NULL;
        if (!gt || !se || se > ae) break;
        char id[256]; size_t il = (size_t)(se - gt - 1);
        int keep = 1;
        if (il > 0 && il < sizeof id) { memcpy(id, gt + 1, il); id[il] = 0; keep = !on_disk(id); }
        memcpy(w, p, (size_t)(s - p)); w += s - p;  /* everything before this element */
        if (keep) { memcpy(w, s, (size_t)(se + 9 - s)); w += se + 9 - s; } else (*dropped)++;
        p = se + 9;
    }
    memcpy(w, p, n - (size_t)(p - req) + 1);
    if (!*dropped) { free(o); return NULL; }
    *out_len = strlen(o) + 1;
    return o;
}

/* EXPLICIT-LOAD KEXTS IN THE AUXILIARY COLLECTION (rev-auxmatch 11-06).
 * WHY: the aux collection loads (dmesg "Loading Aux KC from file", kern.auxiliaryfilesetuuid 6A2F45EA…) yet none
 * of its four kexts ever loads by matching, and the kernel log shows no attempt. Cause, read from the collection
 * and the 27.2 kernel, not guessed:
 *  - kmutil wrote OSBundleRequireExplicitLoad=<true/> into the prelink info of ALL FOUR kexts (aux KC 6A2F45EA,
 *    __PRELINK_INFO: NMXAudio, NVAccel, NVRMAGDC, NVRMFB each carry it; their source Info.plists do not).
 *  - OSKext::initWithPrelinkedInfoDict turns that key into flags.requireExplicitLoad, and
 *    OSKext::copyAllKextPersonalities (27.2 KDK 0xffffff800098a659: testb $0x40,0x81(%r12)) SKIPS that kext's
 *    personalities, logging "requires an explicit kextload; omitting its personalities" at DEBUG level (0x27),
 *    which no saved log shows. So sendAllKextPersonalitiesToCatalog(true), which loadFileSetKexts does run,
 *    sends nothing of ours to the IOCatalogue: nothing can match, so nothing is ever asked to load.
 *  - A "LoadFromKC" request goes OSKext::loadKextFromKC -> load() -> sendPersonalitiesToCatalog(true), which
 *    copies the kext's own personalities with no explicit-load filter: that is why a direct LoadFromKC loaded
 *    each kext and it then matched at once (measured on the box 11-06).
 * WHAT: the explicit load is the kernel's documented contract for such a kext, and "LoadFromKC" is the request
 * `kmutil load -b <id>` makes kernelmanagerd send. Right after the first loadfilesetkc (the one we add AuxKCName
 * to) succeeds, send one LoadFromKC per aux kext that carries OSBundleRequireExplicitLoad=true, read from the
 * collection file itself (O_RDONLY). A kext without the key is left to matching, as Apple would.
 *  Not done here: rewriting the collection to drop the key (the kernel never re-reads it, and this file never
 * builds, rewrites or deletes a collection). */
#define KREQ_ID_MAX   128
#define KREQ_IDS_MAX  16

static int kreq_starts(const char *p, const char *end, const char *lit)
{
    size_t l = strlen(lit);
    return (size_t)(end - p) >= l && memcmp(p, lit, l) == 0;
}

/* A bundle ID we are willing to put back into an XML request: reverse-DNS characters only, so no escaping is
 * ever needed and nothing in the collection can inject markup into a kernel request. */
static int kreq_id_ok(const char *s, size_t n)
{
    if (n == 0 || n >= KREQ_ID_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'))
            return 0;
    }
    return 1;
}

/* Pure: from prelink-info XML, the CFBundleIdentifier of every kext dict directly inside _PrelinkInfoDictionary
 * whose OWN (depth-1) keys hold OSBundleRequireExplicitLoad=<true/>. Personality dicts are depth 2+, so their
 * CFBundleIdentifier / publisher keys are never taken for the kext's. Returns the count, or -1 when the XML has
 * no _PrelinkInfoDictionary array (the caller then says so; it never reads that as "nothing to load"). */
static int kreq_explicit_ids(const char *x, size_t len, char ids[][KREQ_ID_MAX], int max)
{
    const char *end = x + len;
    const char *p = x ? memmem(x, len, "<key>_PrelinkInfoDictionary</key>", sizeof "<key>_PrelinkInfoDictionary</key>" - 1) : NULL;
    if (!p) return -1;
    p = memmem(p, (size_t)(end - p), "<array>", 7);
    if (!p) return -1;
    p += 7;
    int n = 0, depth = 0, have_id = 0, expl = 0;
    char id[KREQ_ID_MAX] = {0};
    const char *key = NULL; size_t keyl = 0;
    while (p < end && *p) {
        const char *lt = memchr(p, '<', (size_t)(end - p));
        if (!lt) break;
        p = lt;
        if (depth == 0 && kreq_starts(p, end, "</array>")) break;
        if (kreq_starts(p, end, "<dict/>")) { p += 7; key = NULL; continue; }
        if (kreq_starts(p, end, "<dict")) {
            if (++depth == 1) { have_id = 0; expl = 0; }
            key = NULL; p += 5; continue;
        }
        if (kreq_starts(p, end, "</dict>")) {
            if (depth == 1 && have_id && expl && n < max) { memcpy(ids[n], id, sizeof id); n++; }
            if (depth > 0) depth--;
            key = NULL; p += 7; continue;
        }
        if (depth == 1 && kreq_starts(p, end, "<key>")) {
            const char *ke = memmem(p + 5, (size_t)(end - p - 5), "</key>", 6);
            if (!ke) break;
            key = p + 5; keyl = (size_t)(ke - key); p = ke + 6; continue;
        }
        if (depth == 1 && key) {
            if (keyl == 18 && !memcmp(key, "CFBundleIdentifier", 18) && kreq_starts(p, end, "<string")) {
                const char *gt = memchr(p, '>', (size_t)(end - p));
                const char *se = gt ? memmem(gt, (size_t)(end - gt), "</string>", 9) : NULL;
                if (!se) break;
                size_t il = (size_t)(se - gt - 1);
                if (kreq_id_ok(gt + 1, il)) { memcpy(id, gt + 1, il); id[il] = 0; have_id = 1; }
                key = NULL; p = se + 9; continue;
            }
            if (keyl == 27 && !memcmp(key, "OSBundleRequireExplicitLoad", 27)) expl = kreq_starts(p, end, "<true/>");
            key = NULL;                            /* any other value ends this key */
        }
        p++;
    }
    return n;
}

/* Pure: the LoadFromKC request `kmutil load -b <id>` makes kernelmanagerd send (xnu kext_request_keys.h:
 * kKextRequestPredicateLoadFromKC "LoadFromKC", argument CFBundleIdentifier; the exclude levels default to
 * "start it and send its personalities with matching"). Returns the length counting the NUL, or 0. */
static size_t kreq_loadfromkc_req(const char *id, char *out, size_t cap)
{
    if (!id || !kreq_id_ok(id, strlen(id))) return 0;
    int n = snprintf(out, cap, "<dict><key>Kext Request Predicate</key><string>LoadFromKC</string>"
                               "<key>Kext Request Arguments</key><dict><key>CFBundleIdentifier</key><string>%s</string>"
                               "</dict></dict>", id);
    return (n > 0 && (size_t)n < cap) ? (size_t)n + 1 : 0;
}

/* Pure: fire the explicit loads only after the request we gave AuxKCName came back clean — kr and the kernel's
 * own op result both success. A failed collection load means the kexts are not in the kernel: sending LoadFromKC
 * then would only add "not found" noise and hide the real failure. */
static int kreq_should_load_explicit(int added_aux, kern_return_t kr, int have_op, kern_return_t op)
{
    return added_aux && kr == KERN_SUCCESS && have_op && op == 0;
}

/* Pure: is `id` one whole line of `list`? The bring-up skip list holds kexts that must stay unloaded for now
 * (11-06: NVAccel panics a restart until the getVRAMRange window fix is proven on a boot). Whole-line match only,
 * so "com.nullmoth.NVRMFB" never skips "com.nullmoth.NVRMFBx" or the reverse. */
static int kreq_id_skipped(const char *list, const char *id)
{
    size_t l = strlen(id);
    if (!list || !l) return 0;
    for (const char *p = list; *p; ) {
        const char *e = strchr(p, '\n'); size_t n = e ? (size_t)(e - p) : strlen(p);
        while (n && (p[n-1] == '\r' || p[n-1] == ' ')) n--;
        if (n == l && memcmp(p, id, l) == 0) return 1;
        if (!e) break; p = e + 1;
    }
    return 0;
}
#ifndef KREQ_SELFTEST
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
/* Is a kext bundle with this CFBundleIdentifier installed in /Library/Extensions? Reads each bundle's XML
 * Info.plist; a binary plist is not parsed and counts as "not this one" (the ID then stays listed: the safe side). */
static int kreq_bundle_on_disk(const char *bundle_id)
{
    DIR *d = opendir("/Library/Extensions");
    if (!d) return 0;
    struct dirent *e; int found = 0;
    static char buf[65536];
    while (!found && (e = readdir(d))) {
        size_t nl = strlen(e->d_name);
        if (nl < 6 || strcmp(e->d_name + nl - 5, ".kext")) continue;
        char path[1024];
        snprintf(path, sizeof path, "/Library/Extensions/%s/Contents/Info.plist", e->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        ssize_t r = read(fd, buf, sizeof buf - 1); close(fd);
        if (r <= 0) continue;
        buf[r] = 0;
        const char *k = strstr(buf, "<key>CFBundleIdentifier</key>");
        if (!k) continue;
        const char *s = strstr(k, "<string>");
        if (!s) continue;
        s += 8;
        const char *se = strstr(s, "</string>");
        if (se && (size_t)(se - s) == strlen(bundle_id) && !strncmp(s, bundle_id, (size_t)(se - s))) found = 1;
    }
    closedir(d);
    return found;
}

/* Every request kernelmanagerd sends, bounded (256 KB, then truncated once), so a boot shows what it asked for. */
static void kreq_log(const char *what, const char *req, size_t len, kern_return_t kr, kern_return_t op)
{
#if A2X_SHIP
    (void)what; (void)req; (void)len; (void)kr; (void)op;     /* the request log is a lab diagnostic */
#else
    int fd = open("/var/tmp/a2x-reports/kext_request.log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
    if (fd < 0) return;
    if (lseek(fd, 0, SEEK_END) > (256 << 10)) { ftruncate(fd, 0); }
    char line[700];
    int n = snprintf(line, sizeof line, "[%d] %s kr=0x%x op=0x%x len=%zu %.400s\n", getpid(), what, kr, op, len,
                     (req && len && req[0] == '<') ? req : "(binary)");
    if (n > 0) write(fd, line, (size_t)(n < (int)sizeof line ? n : (int)sizeof line - 1));
    close(fd);
#endif
}

#define KREQ_SKIP_PATH "/Library/NullMoth/bringup/explicit-load.skip"

/* Read the aux collection O_RDONLY (bounded: 256 MB), list its explicit-load kexts, and LoadFromKC each one.
 * Every request and its kernel result goes to the request log; the count goes to stderr. */
static void kreq_load_explicit(kreq_fn real, host_priv_t hp, uint32_t flags)
{
    int fd = open(KREQ_AUX_PATH, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "[host] explicit-load: cannot open %s\n", KREQ_AUX_PATH); return; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 4096 || st.st_size > (256LL << 20)) {
        close(fd); fprintf(stderr, "[host] explicit-load: %s has an unusable size\n", KREQ_AUX_PATH); return;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    ssize_t got = 0;
    while (buf && got < st.st_size) { ssize_t r = read(fd, buf + got, (size_t)(st.st_size - got)); if (r <= 0) break; got += r; }
    close(fd);
    if (!buf || got != st.st_size) { free(buf); fprintf(stderr, "[host] explicit-load: short read of %s\n", KREQ_AUX_PATH); return; }
    buf[got] = 0;
    static char ids[KREQ_IDS_MAX][KREQ_ID_MAX];
    int n = kreq_explicit_ids(buf, (size_t)got, ids, KREQ_IDS_MAX);
    free(buf);
    if (n < 0) { fprintf(stderr, "[host] explicit-load: no _PrelinkInfoDictionary in %s — UNKNOWN, nothing sent\n", KREQ_AUX_PATH); return; }
    char skip[2048] = {0};
    int sfd = open(KREQ_SKIP_PATH, O_RDONLY);
    if (sfd >= 0) { ssize_t sr = read(sfd, skip, sizeof skip - 1); if (sr < 0) skip[0] = 0; close(sfd); }
    int ok = 0;
    for (int i = 0; i < n; i++) {
        char r[512];
        if (kreq_id_skipped(skip, ids[i])) {
            fprintf(stderr, "[host] explicit-load: %s skipped (listed in %s)\n", ids[i], KREQ_SKIP_PATH);
            kreq_log("LoadFromKC SKIPPED (bring-up skip list)", ids[i], strlen(ids[i]), 0, 0);
            continue;
        }
        size_t rl = kreq_loadfromkc_req(ids[i], r, sizeof r);
        if (!rl) continue;
        vm_offset_t resp = 0, lg = 0; mach_msg_type_number_t resp_len = 0, lg_len = 0; kern_return_t op = 0;
        kern_return_t kr = real(hp, flags, (vm_offset_t)r, (mach_msg_type_number_t)rl, &resp, &resp_len, &lg, &lg_len, &op);
        if (resp && resp_len) vm_deallocate(mach_task_self(), resp, resp_len);
        if (lg && lg_len) vm_deallocate(mach_task_self(), lg, lg_len);
        kreq_log("LoadFromKC (explicit-load aux kext)", r, rl, kr, op);
        if (kr == KERN_SUCCESS && op == 0) ok++;
    }
    fprintf(stderr, "[host] explicit-load: %d of %d aux kexts with OSBundleRequireExplicitLoad loaded via LoadFromKC\n", ok, n);
}

kern_return_t kext_request(host_priv_t hp, uint32_t flags, vm_offset_t req, mach_msg_type_number_t len,
                           vm_offset_t *resp, mach_msg_type_number_t *resp_len, vm_offset_t *log,
                           mach_msg_type_number_t *log_len, kern_return_t *op)
{
    static kreq_fn real;
    if (!real) {
        void *h = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_LAZY | RTLD_NOLOAD);
        real = h ? (kreq_fn)dlsym(h, "kext_request") : NULL;
        if (!real) { fprintf(stderr, "[host] kext_request: libsystem_kernel kext_request not found\n"); return KERN_FAILURE; }
    }
    size_t nl = 0; const char *why = ""; int dropped = 0;
    char *nreq = kreq_add_aux((const char *)req, len, kreq_aux_present(), &nl, &why);
    if (strcmp(why, "not a loadfilesetkc request") != 0)
        fprintf(stderr, "[host] kext_request loadfilesetkc: %s\n", why);
    const char *tag = nreq ? "loadfilesetkc +AuxKCName" : "request";
    if (!nreq && (nreq = kreq_filter_missing((const char *)req, len, kreq_bundle_on_disk, &nl, &dropped)))
        tag = "MissingAuxKCBundles (on-disk IDs dropped)";
    kern_return_t kr;
    if (!nreq) {
        kr = real(hp, flags, req, len, resp, resp_len, log, log_len, op);
        kreq_log(tag, (const char *)req, len, kr, op ? *op : 0);
        return kr;
    }
    kr = real(hp, flags, (vm_offset_t)nreq, (mach_msg_type_number_t)nl, resp, resp_len, log, log_len, op);
    kreq_log(tag, (const char *)req, len, kr, op ? *op : 0);
    kreq_log("  sent as", nreq, nl, kr, op ? *op : 0);
    fprintf(stderr, "[host] kext_request %s: kr=0x%x op=0x%x dropped=%d\n", tag, kr, op ? *op : 0, dropped);
    int added_aux = !strcmp(tag, "loadfilesetkc +AuxKCName");
    free(nreq);
    if (kreq_should_load_explicit(added_aux, kr, op != NULL, op ? *op : -1))
        kreq_load_explicit(real, hp, flags);       /* after the caller's reply buffers are filled; ours are freed */
    return kr;
}
#else
static int test_on_disk(const char *id) { return !strcmp(id, "com.x.A") || !strcmp(id, "com.x.C"); }
int main(void)
{
    int fail = 0; size_t nl; const char *why; char *o;
    const char *first = "<dict><key>Kext Request Predicate</key><string>loadfilesetkc</string><key>Kext Request Arguments</key>"
                        "<dict><key>PageableKCName</key><string>/System/Library/KernelCollections/SystemKernelExtensions.kc</string></dict></dict>";
#define ARM(name, cond) do { if (cond) printf("ok   %s\n", name); else { printf("FAIL %s (%s)\n", name, why); fail++; } } while (0)
    o = kreq_add_aux(first, strlen(first) + 1, 1, &nl, &why);
    ARM("the first load request gains AuxKCName with the collection path, before PageableKCName",
        o && strstr(o, "<key>AuxKCName</key><string>" KREQ_AUX_PATH "</string><key>PageableKCName</key>") && nl == strlen(o) + 1);
    free(o);
    o = kreq_add_aux(first, strlen(first) + 1, 0, &nl, &why);
    ARM("NEG: no auxiliary collection file -> request unchanged", !o);
    const char *has = "<dict><key>Kext Request Predicate</key><string>loadfilesetkc</string><key>Kext Request Arguments</key>"
                      "<dict><key>AuxKCName</key><string>/x</string><key>PageableKCName</key><string>/y</string></dict></dict>";
    o = kreq_add_aux(has, strlen(has) + 1, 1, &nl, &why);
    ARM("NEG: a request that already names AuxKCName is unchanged", !o);
    const char *aux_only = "<dict><key>Kext Request Predicate</key><string>loadfilesetkc</string><key>Kext Request Arguments</key>"
                           "<dict><key>Codeless</key><array/></dict></dict>";
    o = kreq_add_aux(aux_only, strlen(aux_only) + 1, 1, &nl, &why);
    ARM("NEG: a later request without PageableKCName is unchanged", !o);
    const char *other = "<dict><key>Kext Request Predicate</key><string>Get Loaded Kext Info</string></dict>";
    o = kreq_add_aux(other, strlen(other) + 1, 1, &nl, &why);
    ARM("NEG: other predicates are unchanged", !o && !strcmp(why, "not a loadfilesetkc request"));
    char bin[64] = {(char)0xd3, 0, 0, 0}; strcpy(bin + 4, "loadfilesetkc");
    o = kreq_add_aux(bin, sizeof bin, 1, &nl, &why);
    ARM("NEG: a binary-serialized request is unchanged and named", !o && strstr(why, "binary"));
    char nonul[16]; memset(nonul, 'a', sizeof nonul);
    o = kreq_add_aux(nonul, sizeof nonul, 1, &nl, &why);
    ARM("NEG: a request with no NUL is unchanged", !o);
    /* MissingAuxKCBundles arms: a fake on-disk set {com.x.A, com.x.C} */
    int dropped;
    const char *miss = "<dict><key>Kext Request Predicate</key><string>MissingAuxKCBundles</string><key>Kext Request Arguments</key>"
                       "<dict><key>Missing Bundle IDs</key><array><string>com.x.A</string><string ID=\"3\">com.x.B</string>"
                       "<string>com.x.C</string></array></dict></dict>";
    o = kreq_filter_missing(miss, strlen(miss) + 1, test_on_disk, &nl, &dropped);
    why = o ? o : "(null)";
    ARM("on-disk IDs A and C are dropped from the missing list, gone-from-disk B stays (with its ID attribute)",
        o && dropped == 2 && !strstr(o, "com.x.A") && !strstr(o, "com.x.C") && strstr(o, "<array><string ID=\"3\">com.x.B</string></array>")
          && nl == strlen(o) + 1);
    free(o);
    const char *missB = "<dict><key>Kext Request Predicate</key><string>MissingAuxKCBundles</string><key>Kext Request Arguments</key>"
                        "<dict><key>Missing Bundle IDs</key><array><string>com.x.B</string></array></dict></dict>";
    o = kreq_filter_missing(missB, strlen(missB) + 1, test_on_disk, &nl, &dropped);
    why = "unexpected rewrite";
    ARM("NEG: a list of only really-missing bundles is left unchanged", !o && dropped == 0);
    const char *empty = "<dict><key>Kext Request Predicate</key><string>MissingAuxKCBundles</string><key>Kext Request Arguments</key>"
                        "<dict><key>Missing Bundle IDs</key><array/></dict></dict>";
    o = kreq_filter_missing(empty, strlen(empty) + 1, test_on_disk, &nl, &dropped);
    ARM("NEG: an empty missing list is left unchanged", !o);
    o = kreq_filter_missing(first, strlen(first) + 1, test_on_disk, &nl, &dropped);
    ARM("NEG: a loadfilesetkc request is never touched by the missing-list filter", !o);

    /* explicit-load arms: a fixture shaped like kmutil's prelink info (personality dicts nest their own IDs) */
    static char ids[KREQ_IDS_MAX][KREQ_ID_MAX];
    const char *pl =
        "<dict><key>_BootKCID</key><data>AA==</data><key>_PrelinkInfoDictionary</key><array>"
        "<dict><key>CFBundleIdentifier</key><string>com.x.Explicit</string><key>IOKitPersonalities</key><dict>"
        "<key>P</key><dict><key>CFBundleIdentifier</key><string>com.x.Other</string>"
        "<key>OSBundleRequireExplicitLoad</key><false/></dict></dict>"
        "<key>OSBundleLibraries</key><dict/><key>OSBundleRequireExplicitLoad</key><true/></dict>"
        "<dict><key>OSBundleRequireExplicitLoad</key><false/><key>CFBundleIdentifier</key><string>com.x.Matches</string></dict>"
        "<dict><key>CFBundleIdentifier</key><string>com.x.NoKey</string><key>IOKitPersonalities</key><dict>"
        "<key>Q</key><dict><key>OSBundleRequireExplicitLoad</key><true/></dict></dict></dict>"
        "<dict><key>OSBundleRequireExplicitLoad</key><true/><key>CFBundleIdentifier</key><string ID=\"7\">com.x.Second</string></dict>"
        "</array><key>_PageableKCID</key><data>AA==</data></dict>";
    int ne = kreq_explicit_ids(pl, strlen(pl) + 1, ids, KREQ_IDS_MAX);
    why = ne >= 1 ? ids[0] : "(none)";
    ARM(" only kexts whose OWN dict says OSBundleRequireExplicitLoad=true are listed (Explicit, Second, in order)",
        ne == 2 && !strcmp(ids[0], "com.x.Explicit") && !strcmp(ids[1], "com.x.Second"));
    why = "a nested personality key leaked into the kext's";
    int leak = 0; for (int i = 0; i < ne; i++) leak |= !strcmp(ids[i], "com.x.Other") || !strcmp(ids[i], "com.x.NoKey");
    ARM("NEG: a personality's own CFBundleIdentifier or explicit key never stands for its kext", ne >= 0 && !leak);
    ARM("NEG: an explicit=false kext is left to matching (not listed)", ne >= 0 && strcmp(ids[0], "com.x.Matches") && (ne < 2 || strcmp(ids[1], "com.x.Matches")));
    const char *noinfo = "<dict><key>Other</key><array></array></dict>";
    why = "returned a count";
    ARM("NEG: XML with no _PrelinkInfoDictionary is UNKNOWN (-1), never \"nothing to load\"",
        kreq_explicit_ids(noinfo, strlen(noinfo) + 1, ids, KREQ_IDS_MAX) == -1);
    const char *bad = "<dict><key>_PrelinkInfoDictionary</key><array><dict><key>CFBundleIdentifier</key>"
                      "<string>com.x&lt;/string&gt;evil</string><key>OSBundleRequireExplicitLoad</key><true/></dict></array></dict>";
    ARM("NEG: an ID with markup characters is refused, never copied into a kernel request",
        kreq_explicit_ids(bad, strlen(bad) + 1, ids, KREQ_IDS_MAX) == 0);
    char rq[512];
    size_t rl = kreq_loadfromkc_req("com.nullmoth.NVRMFB", rq, sizeof rq);
    why = rl ? rq : "(empty)";
    ARM("the LoadFromKC request names the predicate and CFBundleIdentifier exactly as kext_request_keys.h does",
        rl == strlen(rq) + 1 && strstr(rq, "<key>Kext Request Predicate</key><string>LoadFromKC</string>")
          && strstr(rq, "<key>Kext Request Arguments</key><dict><key>CFBundleIdentifier</key><string>com.nullmoth.NVRMFB</string></dict>"));
    why = "built a request";
    ARM("the skip list skips a listed ID (CRLF and trailing space tolerated)",
        kreq_id_skipped("com.a.X\ncom.nullmoth.NVAccel \r\n", "com.nullmoth.NVAccel"));
    ARM("NEG: the skip list never skips a prefix, a longer ID, or anything from an empty list",
        !kreq_id_skipped("com.nullmoth.NVRMFB\n", "com.nullmoth.NVRMFBx") && !kreq_id_skipped("com.nullmoth.NVRMFBx\n", "com.nullmoth.NVRMFB")
        && !kreq_id_skipped("", "com.nullmoth.NVAccel") && !kreq_id_skipped(NULL, "com.nullmoth.NVAccel"));
    ARM("NEG: no LoadFromKC request for an empty or unsafe ID", !kreq_loadfromkc_req("", rq, sizeof rq) && !kreq_loadfromkc_req("a<b", rq, sizeof rq));
    why = "gate";
    ARM("explicit loads fire after the +AuxKCName request returns kr=0 op=0", kreq_should_load_explicit(1, KERN_SUCCESS, 1, 0));
    ARM("NEG: no explicit loads when the collection load failed (op=0xdc008009) or we did not add AuxKCName",
        !kreq_should_load_explicit(1, KERN_SUCCESS, 1, (kern_return_t)0xdc008009) && !kreq_should_load_explicit(0, KERN_SUCCESS, 1, 0)
          && !kreq_should_load_explicit(1, KERN_FAILURE, 1, 0) && !kreq_should_load_explicit(1, KERN_SUCCESS, 0, 0));

    /* the real collection, when KREQ_SELFTEST_AUXKC names one: the box's aux KC 6A2F45EA must list all four */
    const char *real_kc = A2X_DBGENV("KREQ_SELFTEST_AUXKC");
    if (real_kc) {
        FILE *f = fopen(real_kc, "rb");
        char *kb = NULL; long ks = 0;
        if (f && fseek(f, 0, SEEK_END) == 0 && (ks = ftell(f)) > 0 && fseek(f, 0, SEEK_SET) == 0 && (kb = malloc((size_t)ks + 1))
            && fread(kb, 1, (size_t)ks, f) == (size_t)ks) {
            kb[ks] = 0;
            int nk = kreq_explicit_ids(kb, (size_t)ks, ids, KREQ_IDS_MAX);
            char got[600] = ""; for (int i = 0; i < nk; i++) { strcat(got, ids[i]); strcat(got, " "); }
            why = got;
            printf("     real collection %s: %d explicit-load kexts: %s\n", real_kc, nk, got);
            ARM(" the real aux KC lists exactly NMXAudio NVAccel NVRMAGDC NVRMFB as explicit-load",
                nk == 4 && strstr(got, "com.nullmoth.NMXAudio ") && strstr(got, "com.nullmoth.NVAccel ")
                  && strstr(got, "com.nullmoth.NVRMAGDC ") && strstr(got, "com.nullmoth.NVRMFB "));
        } else { why = real_kc; ARM("the real aux KC named by KREQ_SELFTEST_AUXKC is readable", 0); }
        if (f) fclose(f);
        free(kb);
    }
    printf("%s, %d failed\n", fail ? "FAILED" : "PASSED", fail);
    return fail != 0;
}
#endif
