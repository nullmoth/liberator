// a64i.h — the arm64 interpreter core: one instruction at a time against an explicit register file.
// // 10-25 RUNG 1 OF UNIVERSAL-27-PLAN.md. Translation stays the fast path; this runs code the translator never
// saw (a target outside every lifted function, a first launch before the background translation exists), so a
// miss in __arm2x86_lookup becomes execution instead of `no entry for <addr>` + abort.
// The core is host-independent C: memory is the process's own (arm64 images are mapped at their addresses),
// so a load is a load. It is certified by the same 2,224-form, 16-state M4 truth the lifter is (ops/risu,
// interp/idriver), on the mini (arm64 host) and on studio (x86 host).
// It never guesses. An encoding it does not implement returns A64_UNDEF with the pc unchanged, and the caller
// reports the word and the address; nothing is approximated.
#pragma once
#include <stdint.h>

typedef struct a64 {
    uint64_t x[31];                 // x0..x30
    uint64_t sp;
    uint64_t pc;
    uint64_t nzcv;                  // N Z C V at bits 31..28, exactly as `mrs x, nzcv` reads it
    uint64_t fpcr, fpsr;
    _Alignas(16) uint8_t v[32][16]; // v0..v31, low 128 bits
    uint64_t tsd;                   // what `mrs tpidrro_el0` returns (the TSD array base on this thread)
    uint64_t tpidr2;                // TPIDR2_EL0, the SME lazy-save pointer
    uint64_t (*cntvct)(void);       // CNTVCT_EL0 at 24 MHz; 0 -> the instruction is UNDEF
    // exclusive monitor: stxr succeeds iff memory still holds what ldxr read (compare-and-swap), so it is atomic
    // against other threads the way the hardware's monitor is, up to ABA on an unchanged value.
    uint64_t excl_addr, excl_val[2];
    int excl_size;                  // bytes per register; 0 = no reservation
    int excl_pair;
    // bit0 = x6 and bit1 = x7 were WRITTEN since the last call boundary (set by wz/wsp, cleared by the runtime).
    // A shadow compare of the VALUE cannot tell "rewritten with the same value" from "never written".
    uint8_t argw;
    // the slot engine's x6/x7 write marks as two plain bytes (no read-modify-write); the runtime ORs them into argw
    uint8_t argwx[2];
    // 10-31 the a64_code_gen this run's decode-cache epoch was taken against (a64_cache.c). A generic entry that
    // finds the generation moved (a guest IC IVAU, or another thread's code change followed by this thread's ISB or
    // any other generic instruction) hands control back so the run takes a new epoch before the next fetch.
    unsigned cgen;
    uint64_t hostsp;                // the slot engine's host stack pointer while guest sp lives in rsp (a64slot.c OPT_RSP)
} a64;

enum {
    A64_NEXT = 0,   // fell through; pc advanced by 4
    A64_JUMP,       // b / b.cond / cbz / tbz / br taken: pc = target
    A64_CALL,       // bl / blr: x30 = return address, pc = target
    A64_RET,        // ret: pc = target
    A64_SVC,        // svc: pc already advanced; x16 holds the number, the caller performs it
    A64_BRK,        // brk / udf: pc unchanged
    A64_UNDEF,      // not implemented here: pc unchanged
};

int a64_step(a64 *s, uint32_t insn);
const char *a64_event_name(int ev);
