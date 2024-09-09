#include <SDL2/SDL.h>
#include <stdio.h>

#include "3ds.h"
#include "emulator.h"
#include "pica/gpu_gl.h"

char wintitle[200];

int main(int argc, char** argv) {

    if (emulator_init(argc, argv) < 0) return -1;

    SDL_Init(SDL_INIT_VIDEO);

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 4);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 6);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK,
                        SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_Window* window = SDL_CreateWindow("ctremu", 0, 0, SCREEN_WIDTH,
                                          SCREEN_HEIGHT, SDL_WINDOW_OPENGL);

    SDL_GLContext glcontext = SDL_GL_CreateContext(window);
    if (!glcontext) {
        SDL_Quit();
        return 1;
    }
    glewInit();

    glViewport(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);

    gpu_gl_setup();

    Uint64 prev_time = SDL_GetPerformanceCounter();
    Uint64 prev_fps_update = prev_time;
    Uint64 prev_fps_frame = 0;
    const Uint64 frame_ticks = SDL_GetPerformanceFrequency() / FPS;
    Uint64 frame = 0;

    ctremu.running = true;
    while (ctremu.running) {
        Uint64 cur_time;
        Uint64 elapsed;

        if (!(ctremu.pause)) {
            do {
                hle3ds_run_frame(&ctremu.system);
                frame++;

                cur_time = SDL_GetPerformanceCounter();
                elapsed = cur_time - prev_time;
            } while (ctremu.uncap && elapsed < frame_ticks);
        }

        SDL_GL_SwapWindow(window);

        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) {
                ctremu.running = false;
                break;
            }
        }

        if (!ctremu.uncap) {
            cur_time = SDL_GetPerformanceCounter();
            elapsed = cur_time - prev_time;
            Sint64 wait = frame_ticks - elapsed;
            Sint64 waitMS =
                wait * 1000 / (Sint64) SDL_GetPerformanceFrequency();
            if (waitMS > 1 && !ctremu.uncap) {
                SDL_Delay(waitMS);
            }
        }
        cur_time = SDL_GetPerformanceCounter();
        elapsed = cur_time - prev_fps_update;
        if (elapsed >= SDL_GetPerformanceFrequency() / 2) {
            double fps = (double) SDL_GetPerformanceFrequency() *
                         (frame - prev_fps_frame) / elapsed;
            snprintf(wintitle, 199, "ctremu | %s | %.2lf FPS",
                     ctremu.romfilenodir, fps);
            SDL_SetWindowTitle(window, wintitle);
            prev_fps_update = cur_time;
            prev_fps_frame = frame;
        }
        prev_time = cur_time;
    }

    SDL_Quit();

    emulator_quit();

    return 0;
}
