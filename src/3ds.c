#include "3ds.h"

#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "loader.h"
#include "svc_types.h"

void hle3ds_init(HLE3DS* s, char* romfile) {
    memset(s, 0, sizeof *s);

    s->sched.master = s;

    cpu_init(s);

    hle3ds_memory_init(s);

    u32 entrypoint = 0;

    char* ext = strrchr(romfile, '.');
    if (!ext) {
        eprintf("unsupported file format\n");
        exit(1);
    }
    if (!strcmp(ext, ".elf")) {
        entrypoint = load_elf(s, romfile);
    } else {
        eprintf("unsupported file format\n");
        exit(1);
    }

    hle3ds_vmalloc(s, STACK_BASE - STACK_SIZE, STACK_SIZE, PERM_RW,
                   MEMST_PRIVATE);

    hle3ds_vmalloc(s, CONFIG_MEM, PAGE_SIZE, PERM_R, MEMST_STATIC);
    hle3ds_vmalloc(s, TLS_BASE, TLS_SIZE * MAX_RES, PERM_RW, MEMST_PRIVATE);

    init_services(s);

    thread_init(s, entrypoint);

    add_event(&s->sched, EVENT_GSP, GSPEVENT_VBLANK0, CPU_CLK / FPS);
}

void hle3ds_destroy(HLE3DS* s) {
    cpu_free(s);

    hle3ds_memory_destroy(s);
}

void hle3ds_run_frame(HLE3DS* s) {
    while (!s->frame_complete) {
        cpu_run(s, FIFO_peek(s->sched.event_queue).time - s->sched.now);
        run_next_event(&s->sched);
        while (s->cpu.wfe) {
            s->cpu.wfe = false;
            run_next_event(&s->sched);
        }
    }
    s->frame_complete = false;
}