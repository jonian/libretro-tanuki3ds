#ifndef _3DS_H
#define _3DS_H

#include "arm/arm_core.h"
#include "gpu.h"
#include "kernel.h"
#include "memory.h"
#include "scheduler.h"
#include "service_data.h"
#include "srv.h"
#include "types.h"

#define CPU_CLK BIT(28)
#define FPS 60

#define FCRAMSIZE BIT(27)

typedef struct _3DS {
    ArmCore cpu;

    GPU gpu;

    u8* virtmem;

    KernelData kernel;

    ServiceData services;

    bool frame_complete;

    Scheduler sched;
} HLE3DS;

#define R(n) s->cpu.r[n]
#define RR(n) (s->cpu.rr[n >> 1])
#define PTR(addr) ((void*) &s->virtmem[addr])

#define PAGE_SIZE BIT(12)

#define HEAP_BASE BIT(27)

#define STACK_BASE BIT(28)
#define STACK_SIZE BIT(14)

#define lINEAR_HEAP_BASE (BIT(28) + BIT(26))

#define CONFIG_MEM 0x1ff80000

#define TLS_BASE 0x1ff82000
#define TLS_SIZE 0x200
#define IPC_CMD_OFF 0x80

void hle3ds_init(HLE3DS* s, char* romfile);
void hle3ds_destroy(HLE3DS* s);

void hle3ds_run_frame(HLE3DS* s);

#endif
