#ifndef MEMORY_H
#define MEMORY_H

#include "types.h"

typedef struct _3DS HLE3DS;

typedef struct _VMBlock {
    u32 startpg;
    u32 endpg;
    u32 perm;
    u32 state;
    struct _VMBlock* next;
    struct _VMBlock* prev;
} VMBlock;

typedef struct {
    u32 vaddr;
} SHMemBlock;

void hle3ds_memory_init(HLE3DS* system);
void hle3ds_memory_destroy(HLE3DS* system);

void hle3ds_vmalloc(HLE3DS* system, u32 base, u32 size, u32 perm, u32 state);
VMBlock* hle3ds_vmquery(HLE3DS* system, u32 addr);

#endif
