#include "shaderjit.h"

#include "video/gpu.h"
#include "video/gpu_hash.h"

#include "shaderjit_backend.h"

ShaderJitFunc shaderjit_get(GPU* gpu, ShaderUnit* shu) {
    u64 hash = gpu_hash_sw_shader(shu);
    auto block = LRU_load(gpu->vshaders_sw, hash);
    if (block->hash != hash) {
        block->hash = hash;
        shaderjit_backend_free(block->backend);
        block->backend = shaderjit_backend_init();
    }
    return shaderjit_backend_get_code(block->backend, shu);
}

void shaderjit_free_all(GPU* gpu) {
    for (int i = 0; i < VSH_MAX; i++) {
        shaderjit_backend_free(gpu->vshaders_sw.d[i].backend);
    }
}