/* a64slot.h - fixed-slot execution of arm64 code on x86-64 (a64slot.c). */
#pragma once
#include <stdint.h>
#include "a64i.h"

#define SLOT_NONE  0xffffffffull    /* the pc is not in any converted image */
#define SLOT_EXIT  1ull             /* left: s->pc = the next instruction to run, NOT yet executed */
#define SLOT_EVENT 0x100ull
#define OPT_INPLACE 1                /* operate on mapped registers directly */
#define OPT_RSP     2                /* guest sp lives in the host rsp: one more register for the guest */
#define OPT_NOZX    4                /* skip zero-extends a 32-bit op already did */
extern int slot_opt;                 /* OPT_* applied to images added from now on */         /* | a64 event: an instruction run by the helper transferred control (pc set) */

struct slot_stats { uint64_t runs, helper, ilookup, k_template, k_helper, k_exit, overflow; };

int slot_image_add(uint64_t tb, uint64_t tlen);     /* convert an image's text (all of it, now) */
int slot_patch(uint64_t addr);                      /* reconvert one instruction */
int slot_covers(uint64_t pc);
uint64_t slot_run(a64 *s);                          /* run from s->pc until something must leave */
void slot_overflow_mark(void **mk);
void slot_overflow_reset(void *mk);
void slot_stats_get(struct slot_stats *o);
extern int slot_break;
extern __thread uint64_t slot_ev_pc;               /* the instruction a SLOT_EVENT came from */
extern int slot_census;                             /* count what the helper runs (slot_census_dump) */
#include <stdio.h>
void slot_census_dump(FILE *f, int top);                              /* certifier negative control: breaks ADD/SUB immediate */
struct slot_skill { int insns, fused, dead_saves, bytes, slot_bytes, nmapped; int8_t mapped[16]; };
/* grow a learned native skill for the function [fb, fb+fl) from an episode (exec[k] = times instruction k ran) */
int slot_consolidate(uint64_t fb, uint64_t fl, const uint64_t *exec, int control_break, struct slot_skill *rep);
/* learning in a live process: the host names functions; back edges count down from slot_hot_threshold */
extern int (*slot_func_bounds)(uint64_t a, uint64_t *lo, uint64_t *hi);
extern int slot_learn, slot_hot_threshold;
struct slot_learnst { uint64_t hot, skills, failed, nobounds, toobig, patched; };
void slot_learn_stats(struct slot_learnst *o);
int slot_learn_all(uint64_t tb, uint64_t tlen);     /* stress: learn every function of an image now */
int slot_learn_function(uint64_t lo, uint64_t hi);  /* learn one function as a live process would (certifier) */
extern uint64_t slot_force_lo, slot_force_hi;      /* debug: these addresses use the helper, not their templates */
extern uint64_t slot_learned_ring[16]; extern unsigned slot_learned_n;   /* the last functions learned */
