/* a2xdispatch — the single interpreter the kernel exec hook substitutes.
 *
 *  WHY THIS EXISTS AT ALL. The kernel redirect can name exactly ONE interpreter path, and the
 *    arm64 host's platform is a LINK-TIME property it cannot change at runtime: dyld refuses
 *    /System/iOSSupport frameworks to a process whose own LC_BUILD_VERSION platform is MACOS, so a
 *    Mac Catalyst guest needs a macabi-platform host. MEASURED 2026-10-27, and the reverse is NOT
 *    symmetric — the Catalyst host is not a superset:
 *
 *      app      macOS host   Catalyst host
 *      Chess    alive        alive
 *      Photos   alive        rc=134 (named ObjC-bridge abort)
 *
 *    So "just always use the Catalyst host" costs working apps. This picks per guest instead.
 *
 *  THE DISCRIMINATOR IS THE GUEST'S OWN BYTES, NEVER A LIST. A hard-coded list of "the Catalyst
 *    apps" poisoned two whole sweeps on 2026-10-27: it ran four plain-macOS apps on the Catalyst
 *    host and missed nine real Catalyst apps. The test is the presence of the literal
 *    "/System/iOSSupport" in the Mach-O, which was validated in both directions across 11 apps.
 *
 *  IT ALSO SETS CFProcessPath. A hosted guest's process executable is the interpreter, which is
 *    not inside a bundle, so [[NSBundle mainBundle] bundleIdentifier] is nil and UIKit asserts
 *    'Invalid parameter not satisfying: bundleIdentifier' in
 *    -[UISApplicationState initForCurrentApplication]. CoreFoundation derives the main bundle from
 *    the process path and honours CFProcessPath, so exporting it gives the guest its own bundle,
 *    identifier and name. MEASURED: the assertion disappears in all five Catalyst apps and the
 *    process renames itself ("Maps application main() started").
 *
 *  One exec, not two chained interpreters: this dispatcher execs the host directly, so the kernel
 *    sees a normal x86_64 exec of a thin binary and the activator iteration limit (3) is untouched.
 *
 *  IT MUST STAY THIN x86_64. The kernel reaches it on pass 3 of exec_activate_image (fat guest
 *    header, our redirect, the host); a fat interpreter would need a fourth pass and the exec would
 *    fail with EBADEXEC on exactly the guests a fat file covers.
 *
 *  ON ANY FAILURE IT SAYS WHY ON stderr AND EXITS NON-ZERO. A dispatcher that silently falls back
 *    to the wrong host would show up as an app-specific bug days later.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <mach/mach.h>

#define HOST_DIR  "/usr/libexec/a2x"
#define HOST_CAT  HOST_DIR "/a2xhost-cat"
#define HOST_MAC  HOST_DIR "/a2xhost-mac"
#define NEEDLE    "/System/iOSSupport"

/* Scan the whole file for the needle. memmem is in libSystem, and the guest is mapped read-only
 * and never executed here, so this cannot run guest code. Returns -1 when the file is unreadable,
 * which is reported rather than guessed around. */
static int guest_is_catalyst(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) { close(fd); return -1; }
    size_t len = (size_t)st.st_size;
    void *m = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) return -1;
    int hit = memmem(m, len, NEEDLE, sizeof NEEDLE - 1) != 0;
    munmap(m, len);
    return hit;
}

/* In the shipped flavour the detailed lines above are not built; one reason line per failure is. */
#if A2X_SHIP
static void stop_line(const char *m) { ssize_t r = write(2, m, strlen(m)); (void)r; }
#else
#define stop_line(m) ((void)0)
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "a2xdispatch: usage: %s <arm64 binary> [args...]\n", argv[0]);
        return 2;
    }
    const char *guest = argv[1];

    int cat = guest_is_catalyst(guest);
    if (cat < 0) {
        fprintf(stderr, "a2xdispatch: cannot read the guest %s: %s\n", guest, strerror(errno));
        stop_line("FATAL: the program to run could not be read\n");
        return 3;
    }
    const char *host = cat ? HOST_CAT : HOST_MAC;

    /* The guest's own path, so CoreFoundation builds the guest's bundle and not the host's. */
    if (setenv("CFProcessPath", guest, 1) != 0) {
        fprintf(stderr, "a2xdispatch: setenv CFProcessPath failed: %s\n", strerror(errno));
        stop_line("FATAL: the environment could not be set up\n");
        return 4;
    }

    if (A2X_DBGENV("A2XDISPATCH_TRACE"))
        fprintf(stderr, "a2xdispatch: %s -> %s (catalyst=%d)\n", guest, host, cat);

    /* The app's OWN argv goes to the host: [guest, original args...]. The guest path rides in A2X_GUEST.
     *  WAS execv(host, [host, guest, args...]): Foundation snapshots argv before the host's main runs, so
     *    the app saw [app, app] and AppKit opened its own executable as a document at finishLaunching —
     *    a SIGSEGV in LSCopyKindStringForTypeInfo for Stickies and System Information (10-28, 2/2 each). */
    if (setenv("A2X_GUEST", guest, 1) != 0) {
        fprintf(stderr, "a2xdispatch: setenv A2X_GUEST failed: %s\n", strerror(errno));
        stop_line("FATAL: the environment could not be set up\n");
        return 4;
    }
    execv(host, argv + 1);
    fprintf(stderr, "a2xdispatch: execv %s failed: %s\n", host, strerror(errno));
    stop_line("FATAL: the interpreter could not be started\n");
    return 5;
}
