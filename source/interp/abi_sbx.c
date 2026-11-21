/* abi_sbx.c - sandbox_check(pid, operation, filter type, ...).
   Variadic: on Apple arm64 the unnamed argument (at most one for every filter type) is on the stack, so the first stack
   slot is forwarded, as abi_audit.c does for the audit-token form.
   A translated daemon that enters its own named sandbox and then asks the kernel whether it is sandboxed
   (pid = itself, no operation) gets -1/ESRCH on this platform and stops: wifip2pd logs "Sandbox check failed with
   error: No such process" and exits 1, 111 times in a row, and airportd waits forever on it. Its sandbox_init returned
   success, so that one question is answered with what the daemon asked for. A program that never entered a
   sandbox is told it is not in one: tools that refuse to run sandboxed (log) must run. Every other question goes
   through unchanged. */
#include <errno.h>
#include <unistd.h>
extern int a2x_sbx_entered;            /* host.c: this program entered a sandbox of its own */
void __arm2x86_abi_sbx_sandbox_check(void) {
    static int (*f)(int, const char *, int, ...); if (!f) f = a2x_need("sandbox_check");
    const int pid = (int)A2X_RX(0); const char *op = (const char *)A2X_RX(1); const int type = (int)A2X_RX(2);
    int r = f(pid, op, type, *(unsigned long *)(__arm_sp + 0), *(unsigned long *)(__arm_sp + 8));
    /* The kernel answers 0 (not sandboxed) or -1/ESRCH here: no translated process is sandboxed on this platform.
     * The daemon asked for its own sandbox, so it is told it is in one, as it would be on the platform it was built for. */
    /* A program the system starts (an app, a service, a widget extension: its parent is launchd) is sandboxed on the
     * platform it was built for by the system's start-up code, not by a call of its own, and it expects to hear so:
     * told otherwise, NotificationCenter was ended by the system about once a minute and every widget extension
     * stopped answering its host. A program a person starts from a shell is told the truth, so tools that refuse to
     * run sandboxed (log) run. */
    static int managed = -1;
    if (managed < 0) managed = (getppid() == 1);
    if (r <= 0 && (a2x_sbx_entered || managed) && op == NULL && (type & 0xffff) == 0 && pid == getpid()) { r = 1; errno = 0; }
    else if (r < 0 && op == NULL && pid == getpid()) { r = 0; errno = 0; }   /* started by hand and never entered one */
    A2X_RX(0) = (unsigned long)(unsigned int)r;
}
