#include "emulator.h"

#include <fcntl.h>
#include <sys/stat.h>

#include "3ds.h"
#include "config.h"

#ifdef _WIN32
#define mkdir(path, ...) mkdir(path)
#endif

bool g_infologs = false;
EmulatorState ctremu;

void emulator_init() {
    mkdir("3ds", S_IRWXU);
    mkdir("3ds/savedata", S_IRWXU);
    mkdir("3ds/extdata", S_IRWXU);
    mkdir("3ds/sdmc", S_IRWXU);
    mkdir("3ds/sdmc/3ds", S_IRWXU);
    // homebrew needs this file to exist but the contents dont matter for hle
    // audio
    FILE* fp;
    if ((fp = fopen("3ds/sdmc/3ds/dspfirm.cdc", "wx"))) fclose(fp);

    ctremu.videoscale = 1;
    ctremu.shaderjit = true;
    ctremu.hwvshaders = true;
    ctremu.safeShaderMul = true;
    ctremu.hashTextures = true;

    load_config();

    if (ctremu.videoscale < 1) ctremu.videoscale = 1;
    if (ctremu.vshthreads > MAX_VSH_THREADS)
        ctremu.vshthreads = MAX_VSH_THREADS;
    if (ctremu.vshthreads < 0) ctremu.vshthreads = 0;

    save_config();
}

void emulator_quit() {
    if (ctremu.initialized) {
        e3ds_destroy(&ctremu.system);
        ctremu.initialized = false;
    }

    free(ctremu.romfilenoext);
    free(ctremu.romfile);
    ctremu.romfile = nullptr;
    ctremu.romfilenodir = nullptr;
    ctremu.romfilenoext = nullptr;
}

void emulator_set_rom(const char* filename) {
    free(ctremu.romfile);
    ctremu.romfile = nullptr;
    free(ctremu.romfilenoext);
    ctremu.romfilenoext = nullptr;

    if (!filename) {
        ctremu.romfile = nullptr;
        return;
    }

    ctremu.romfile = strdup(filename);

    ctremu.romfilenodir = strrchr(ctremu.romfile, '/');
#ifdef _WIN32
    if (!ctremu.romfilenodir) {
        ctremu.romfilenodir = strrchr(ctremu.romfile, '\\');
    }
#endif
    if (ctremu.romfilenodir) ctremu.romfilenodir++;
    else ctremu.romfilenodir = ctremu.romfile;
    ctremu.romfilenoext = strdup(ctremu.romfilenodir);
    char* c = strrchr(ctremu.romfilenoext, '.');
    if (c) *c = '\0';
}

bool emulator_reset() {
    if (ctremu.initialized) {
        e3ds_destroy(&ctremu.system);
        ctremu.initialized = false;
    }

    if (!ctremu.romfile) return true;

    if (!e3ds_init(&ctremu.system, ctremu.romfile)) {
        emulator_set_rom(nullptr);
        return false;
    }

    ctremu.initialized = true;

    return true;
}
