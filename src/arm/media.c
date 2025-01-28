#include "media.h"

// interpreter implementations of the integer SIMD "media" instructions

u32 media_uadd8(ArmCore* cpu, u32 a, u32 b) {
    u32 res = 0;
    for (int i = 0; i < 4; i++) {
        u32 sum = (a & 0xff) + (b & 0xff);
        if (sum >= 0x100) cpu->cpsr.ge |= BIT(i);
        else cpu->cpsr.ge &= ~BIT(i);
        sum &= 0xff;
        res |= sum << 8 * i;
        a >>= 8;
        b >>= 8;
    }
    return res;
}

u32 media_uqsub8(ArmCore* cpu, u32 a, u32 b) {
    u32 res = 0;
    for (int i = 0; i < 4; i++) {
        u32 diff = (a & 0xff) - (b & 0xff);
        if (diff > UINT8_MAX) diff = 0;
        res |= diff << 8 * i;
        a >>= 8;
        b >>= 8;
    }
    return res;
}

u32 media_qsub8(ArmCore* cpu, u32 a, u32 b) {
    u32 res = 0;
    for (int i = 0; i < 4; i++) {
        s32 diff = (s32) (s8) (a & 0xff) - (s32) (s8) (b & 0xff);
        if (diff > INT8_MAX) diff = INT8_MAX;
        if (diff < INT8_MIN) diff = INT8_MIN;
        res |= (diff & 0xff) << 8 * i;
        a >>= 8;
        b >>= 8;
    }
    return res;
}

u32 media_sel(ArmCore* cpu, u32 a, u32 b) {
    u32 mask = 0;
    for (int i = 0; i < 4; i++) {
        if (cpu->cpsr.ge & BIT(i)) mask |= 0xff << 8 * i;
    }
    return (a & mask) | (b & ~mask);
}