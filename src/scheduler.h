#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "common.h"

#define EVENT_MAX BIT(8)

typedef struct _3DS E3DS;

typedef union {
    size_t i;
    void* p;
} SchedEventArg;

#define SEA_NONE ((SchedEventArg) {})
#define SEA_INT(_i) ((SchedEventArg) {.i = _i})
#define SEA_PTR(_p) ((SchedEventArg) {.p = _p})

typedef void (*SchedEventHandler)(E3DS*, SchedEventArg);

typedef struct {
    u64 time;
    SchedEventHandler handler;
    SchedEventArg arg;
} SchedulerEvent;

typedef struct _3DS E3DS;

typedef struct {
    u64 now;

    E3DS* master;

    FIFO(SchedulerEvent, EVENT_MAX) event_queue;
} Scheduler;

void run_to_present(Scheduler* sched);
int run_next_event(Scheduler* sched);

#define EVENT_PENDING(sched)                                                   \
    (sched).event_queue.size &&                                                \
        (sched).now >= FIFO_peek((sched).event_queue).time

void add_event(Scheduler* sched, SchedEventHandler f, SchedEventArg event_arg,
               s64 reltime);
void remove_event(Scheduler* sched, SchedEventHandler f,
                  SchedEventArg event_arg);
u64 find_event(Scheduler* sched, SchedEventHandler f);

void print_scheduled_events(Scheduler* sched);

#endif