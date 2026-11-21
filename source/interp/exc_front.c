/* exc_front.c - the host answers its own faults ahead of a program's Mach exception handler.

   The interpreter enters guest functions that native code calls, and recovers sealed code pages, through
   SIGSEGV/SIGBUS. A thread exception port sees a fault before it becomes a signal, so a program that installs one
   for EXC_BAD_ACCESS is handed every one of those entries first. Spotlight's index does (identity-protected
   behaviour): its handler declines each one without releasing the task identity token the kernel sent, and mds
   is killed for holding too many ports (267,834 after about 100 s on macOS 27.2).

   When the fault handler finds such a port on its thread it puts the host's port in front and remembers the
   program's. The host's server thread declines faults in the guest image (they go on to become the signal the
   interpreter recovers) and passes every other exception to the program's port unchanged, so the program's own
   guard-page handling keeps working. Only the identity-protected behaviour is fronted; other handlers are left
   as they are. */
#include <mach/mach.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define mach_exception_raise                    a2xf_u_raise
#define mach_exception_raise_state              a2xf_u_raise_state
#define mach_exception_raise_state_identity     a2xf_u_raise_state_identity
#define mach_exception_raise_identity_protected a2xf_u_raise_identity_protected
#define mach_exception_raise_state_identity_protected a2xf_u_raise_state_identity_protected
#define mach_exc_server                         a2xf_server
#define mach_exc_server_routine                 a2xf_server_routine
#define catch_mach_exception_raise              a2xf_c_raise
#define catch_mach_exception_raise_state        a2xf_c_raise_state
#define catch_mach_exception_raise_state_identity a2xf_c_raise_state_identity
#define catch_mach_exception_raise_identity_protected a2xf_c_raise_identity_protected
#define catch_mach_exception_raise_state_identity_protected a2xf_c_raise_state_identity_protected
#define mig_external static
#include "exc_front_user.c"
#undef mig_external
#include "exc_front_server.h"

#define FRONT_GUEST_BASE 0x100000000UL      /* host.c A2X_GUEST_BASE / A2X_GUEST_LEN */
#define FRONT_GUEST_LEN  0x80000000UL
#define FRONT_SLOTS 128

static mach_port_t g_front_port;             /* receive right + one send right, made once */
static int g_front_state;                    /* 0 not started, 1 starting, 2 running, 3 unavailable */
static struct { uint64_t tid; mach_port_t port; } g_front_tab[FRONT_SLOTS];
static int g_front_tab_lk;
unsigned long a2x_exc_front_declined, a2x_exc_front_passed;

static void tab_lock(void) { while (__atomic_exchange_n(&g_front_tab_lk, 1, __ATOMIC_ACQUIRE)) sched_yield(); }
static void tab_unlock(void) { __atomic_store_n(&g_front_tab_lk, 0, __ATOMIC_RELEASE); }

static mach_port_t tab_find(uint64_t tid) {
    mach_port_t p = MACH_PORT_NULL;
    tab_lock();
    for (int i = 0; i < FRONT_SLOTS; i++) if (g_front_tab[i].tid == tid) { p = g_front_tab[i].port; break; }
    tab_unlock();
    return p;
}

/* remember the program's port for this thread; the table owns the send right it is given */
static int tab_put(uint64_t tid, mach_port_t port) {
    int at = -1; mach_port_t old = MACH_PORT_NULL;
    tab_lock();
    for (int i = 0; i < FRONT_SLOTS; i++) {
        if (g_front_tab[i].tid == tid) { at = i; break; }
        if (at < 0 && !g_front_tab[i].tid) at = i;
    }
    if (at >= 0) { if (g_front_tab[at].tid == tid) old = g_front_tab[at].port; g_front_tab[at].tid = tid; g_front_tab[at].port = port; }
    tab_unlock();
    if (old != MACH_PORT_NULL && old != port) mach_port_deallocate(mach_task_self(), old);
    return at >= 0;
}

kern_return_t a2xf_c_raise(mach_port_t ep, mach_port_t thread, mach_port_t task, exception_type_t e,
                           mach_exception_data_t code, mach_msg_type_number_t n) {
    (void)ep; (void)e; (void)code; (void)n;
    mach_port_deallocate(mach_task_self(), thread); mach_port_deallocate(mach_task_self(), task);
    return KERN_FAILURE;
}
kern_return_t a2xf_c_raise_state(mach_port_t ep, exception_type_t e, const mach_exception_data_t code,
        mach_msg_type_number_t n, int *flavor, const thread_state_t os, mach_msg_type_number_t osn,
        thread_state_t ns, mach_msg_type_number_t *nsn) {
    (void)ep; (void)e; (void)code; (void)n; (void)flavor; (void)os; (void)osn; (void)ns; (void)nsn;
    return KERN_FAILURE;
}
kern_return_t a2xf_c_raise_state_identity(mach_port_t ep, mach_port_t thread, mach_port_t task, exception_type_t e,
        mach_exception_data_t code, mach_msg_type_number_t n, int *flavor, thread_state_t os,
        mach_msg_type_number_t osn, thread_state_t ns, mach_msg_type_number_t *nsn) {
    (void)ep; (void)e; (void)code; (void)n; (void)flavor; (void)os; (void)osn; (void)ns; (void)nsn;
    mach_port_deallocate(mach_task_self(), thread); mach_port_deallocate(mach_task_self(), task);
    return KERN_FAILURE;
}

/* The one behaviour that is fronted. Declining returns the fault to the kernel, which then raises the signal. */
kern_return_t a2xf_c_raise_identity_protected(mach_port_t ep, uint64_t thread_id, mach_port_t token,
        exception_type_t e, mach_exception_data_t code, mach_msg_type_number_t n) {
    (void)ep;
    kern_return_t kr = KERN_FAILURE;
    unsigned long fa = n >= 2 ? (unsigned long)code[1] : 0;
    int ours = e == EXC_BAD_ACCESS && (fa == 0 || (fa >= FRONT_GUEST_BASE && fa < FRONT_GUEST_BASE + FRONT_GUEST_LEN));
    if (ours) {
        __atomic_add_fetch(&a2x_exc_front_declined, 1, __ATOMIC_RELAXED);
    } else {
        mach_port_t p = tab_find(thread_id);
        if (p != MACH_PORT_NULL) kr = a2xf_u_raise_identity_protected(p, thread_id, token, e, code, n);
        __atomic_add_fetch(&a2x_exc_front_passed, 1, __ATOMIC_RELAXED);
    }
    if (MACH_PORT_VALID(token)) mach_port_deallocate(mach_task_self(), token);
    return kr;
}

static void *front_serve(void *arg) {
    (void)arg;
    pthread_setname_np("a2x exception front");
    union { mach_msg_header_t h; char b[4096]; } req, rep;
    for (;;) {
        memset(&req.h, 0, sizeof req.h);
        kern_return_t kr = mach_msg(&req.h, MACH_RCV_MSG, 0, sizeof req, g_front_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr != KERN_SUCCESS) continue;
        memset(&rep, 0, sizeof(mig_reply_error_t));
        if (!a2xf_server(&req.h, &rep.h)) continue;          /* not an exception message; nothing to answer */
        if (rep.h.msgh_remote_port == MACH_PORT_NULL) continue;
        mach_msg(&rep.h, MACH_SEND_MSG, rep.h.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
    return 0;
}

static int front_start(void) {
    int s = __atomic_load_n(&g_front_state, __ATOMIC_ACQUIRE);
    if (s == 2) return 1;
    if (s == 3) return 0;
    int z = 0;
    if (!__atomic_compare_exchange_n(&g_front_state, &z, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return 0;   /* another thread is starting it */
    mach_port_options_t o; memset(&o, 0, sizeof o);
    o.flags = MPO_INSERT_SEND_RIGHT;
    mach_port_t p = MACH_PORT_NULL;
    pthread_t t; pthread_attr_t a;
    if (mach_port_construct(mach_task_self(), &o, 0, &p) != KERN_SUCCESS) goto off;
    g_front_port = p;
    pthread_attr_init(&a); pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &a, front_serve, 0)) { pthread_attr_destroy(&a); goto off; }
    pthread_attr_destroy(&a);
    __atomic_store_n(&g_front_state, 2, __ATOMIC_RELEASE);
    return 1;
off:
    __atomic_store_n(&g_front_state, 3, __ATOMIC_RELEASE);
    return 0;
}

/* Called from the fault handler on its own thread, on every fault: a program that installs its handler around each
   operation (Spotlight's index does) undoes the front each time, and every fault its handler sees costs a port.
   One thread_get_exception_ports per fault is small beside the signal that brought the fault here. */
void a2x_exc_front_tick(void) {
    static int off = -1;
    if (off < 0) off = A2X_DBGENV("ARM2X86_NO_EXCFRONT") ? 1 : 0;
    if (off || __atomic_load_n(&g_front_state, __ATOMIC_ACQUIRE) == 3) return;
    mach_port_t th = mach_thread_self();
    exception_mask_t masks[EXC_TYPES_COUNT]; mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behs[EXC_TYPES_COUNT]; thread_state_flavor_t flvs[EXC_TYPES_COUNT];
    mach_msg_type_number_t cnt = EXC_TYPES_COUNT;
    if (thread_get_exception_ports(th, EXC_MASK_BAD_ACCESS, masks, &cnt, ports, behs, flvs) == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < cnt; i++) {
            mach_port_t p = ports[i];
            if (!MACH_PORT_VALID(p)) continue;
            int keep = 0;
            if (p != g_front_port && behs[i] == (exception_behavior_t)(EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES) && front_start()) {
                uint64_t tid = 0; pthread_threadid_np(0, &tid);
                if (tid && tab_put(tid, p)) {
                    keep = 1;
                    if (thread_set_exception_ports(th, masks[i], g_front_port, behs[i], flvs[i]) != KERN_SUCCESS) {
                        keep = 0; tab_lock();
                        for (int k = 0; k < FRONT_SLOTS; k++) if (g_front_tab[k].tid == tid) { g_front_tab[k].tid = 0; g_front_tab[k].port = MACH_PORT_NULL; }
                        tab_unlock();
                    }
                }
            }
            if (!keep) mach_port_deallocate(mach_task_self(), p);
        }
    }
    mach_port_deallocate(mach_task_self(), th);
}

#include "exc_front_server.c"
