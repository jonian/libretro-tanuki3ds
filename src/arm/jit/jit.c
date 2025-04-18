#include "jit.h"

#include "backend/backend.h"
#include "optimizer.h"
#include "register_allocator.h"
#include "translator.h"

// #define JIT_DISASM
// #define JIT_CPULOG
// #define IR_INTERPRET
// #define NO_OPTS
// #define NO_LINKING

#ifdef JIT_DISASM
#define IR_DISASM
#define BACKEND_DISASM
#endif

bool g_jit_opt_literals = true;

JITBlock* create_jit_block(ArmCore* cpu, u32 addr) {
    JITBlock* block = malloc(sizeof *block);
    block->attrs = cpu->cpsr.w & 0x3f;
    block->start_addr = addr;

    Vec_init(block->linkingblocks);

    IRBlock ir;
    irblock_init(&ir);

    compile_block(cpu, &ir, addr);

    block->numinstr = ir.numinstr;

#ifndef NO_OPTS
    optimize_loadstore(&ir);
    optimize_constprop(&ir);
    if (g_jit_opt_literals) optimize_literals(&ir, cpu);
    optimize_chainjumps(&ir);
    optimize_loadstore(&ir);
    optimize_constprop(&ir);
    optimize_chainjumps(&ir);
    optimize_deadcode(&ir);
#ifndef NO_LINKING
    optimize_blocklinking(&ir, cpu);
#endif
#endif

    block->end_addr = ir.end_addr;

    RegAllocation regalloc = allocate_registers(&ir);

    block->backend = backend_generate_code(&ir, &regalloc, cpu);
    block->code = backend_get_code(block->backend);

    block->cpu = cpu;

    cpu->jit_cache[block->attrs][addr >> 16][(addr & 0xffff) >> 1] = block;
    backend_patch_links(block);

#ifdef IR_DISASM
    ir_disassemble(&ir);
    regalloc_print(&regalloc);
#endif
#ifdef BACKEND_DISASM
    backend_disassemble(block->backend);
#endif

    regalloc_free(&regalloc);
#ifdef IR_INTERPRET
    block->ir = malloc(sizeof(IRBlock));
    *block->ir = ir;
#else
    irblock_free(&ir);
#endif

    return block;
}

void destroy_jit_block(JITBlock* block) {
#ifdef IR_INTERPRET
    irblock_free(block->ir);
    free(block->ir);
#endif

    block->cpu->jit_cache[block->attrs][block->start_addr >> 16]
                         [(block->start_addr & 0xffff) >> 1] = nullptr;
    backend_free(block->backend);
    Vec_foreach(l, block->linkingblocks) {
        if (!(block->cpu->jit_cache[l->attrs] &&
              block->cpu->jit_cache[l->attrs][l->addr >> 16]))
            continue;
        JITBlock* linkingblock =
            block->cpu
                ->jit_cache[l->attrs][l->addr >> 16][(l->addr & 0xffff) >> 1];
        if (linkingblock) destroy_jit_block(linkingblock);
    }
    Vec_free(block->linkingblocks);
    free(block);
}

void jit_exec(JITBlock* block) {
#ifdef JIT_CPULOG
    cpu_print_state(block->cpu);
#endif
#ifdef IR_INTERPRET
    ir_interpret(block->ir, block->cpu);
#else
    block->code();
#endif
}

// the jit cache is formatted as follows
// 64 root entries corresponding to low 6 bits of cpsr of the block
// then BIT(16) entries corresponding to bit[31:16] of start addr
// then BIT(15) entries corresponding to bit[15:1] of start addr
// jit blocks will never cross page boundaries
JITBlock* get_jitblock(ArmCore* cpu, u32 attrs, u32 addr) {
    u32 addrhi = addr >> 16;
    u32 addrlo = (addr & 0xffff) >> 1;

    if (!cpu->jit_cache[attrs]) {
        cpu->jit_cache[attrs] = calloc(BIT(16), sizeof(JITBlock**));
    }

    if (!cpu->jit_cache[attrs][addrhi]) {
        cpu->jit_cache[attrs][addrhi] = calloc(BIT(16) >> 1, sizeof(JITBlock*));
    }

    JITBlock* block = nullptr;
    if (!cpu->jit_cache[attrs][addrhi][addrlo]) {
        u32 old = cpu->cpsr.jitattrs;
        cpu->cpsr.jitattrs = attrs;
        block = create_jit_block(cpu, addr);
        cpu->cpsr.jitattrs = old;
        cpu->jit_cache[attrs][addrhi][addrlo] = block;
    } else {
        block = cpu->jit_cache[attrs][addrhi][addrlo];
    }

    return block;
}

// start is page aligned
void jit_invalidate_range(ArmCore* cpu, u32 start_addr, u32 len) {
    u32 end_addr = start_addr + len;
    u32 startpg = start_addr >> 16;
    u32 endpg = end_addr >> 16;
    for (int i = 0; i < 64; i++) {
        if (!cpu->jit_cache[i]) continue;
        for (int j = startpg; j < endpg; j++) {
            if (!cpu->jit_cache[i][j]) continue;
            for (int k = 0; k < BIT(16) >> 1; k++) {
                if (cpu->jit_cache[i][j][k]) {
                    destroy_jit_block(cpu->jit_cache[i][j][k]);
                    cpu->jit_cache[i][j][k] = nullptr;
                }
            }
        }
        if (!cpu->jit_cache[i][endpg]) continue;
        for (int k = 0; k < (end_addr & MASK(16)) >> 1; k++) {
            if (cpu->jit_cache[i][endpg][k]) {
                destroy_jit_block(cpu->jit_cache[i][endpg][k]);
                cpu->jit_cache[i][endpg][k] = nullptr;
            }
        }
    }
}

void jit_free_all(ArmCore* cpu) {
    for (int i = 0; i < 64; i++) {
        if (!cpu->jit_cache[i]) continue;
        for (int j = 0; j < BIT(16); j++) {
            if (!cpu->jit_cache[i][j]) continue;
            for (int k = 0; k < BIT(16) >> 1; k++) {
                if (cpu->jit_cache[i][j][k]) {
                    destroy_jit_block(cpu->jit_cache[i][j][k]);
                    cpu->jit_cache[i][j][k] = nullptr;
                }
            }
            free(cpu->jit_cache[i][j]);
            cpu->jit_cache[i][j] = nullptr;
        }
        free(cpu->jit_cache[i]);
        cpu->jit_cache[i] = nullptr;
    }
}

void arm_exec_jit(ArmCore* cpu) {
    JITBlock* block = get_jitblock(cpu, cpu->cpsr.jitattrs, cpu->pc);
    jit_exec(block);
}
