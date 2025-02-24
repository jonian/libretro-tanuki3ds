#ifndef RENDERER_GL_H
#define RENDERER_GL_H

#include <GL/glew.h>
#ifdef __APPLE__
#include <OpenGL/gl.h>
#else
#include <GL/gl.h>
#endif

#include "common.h"

#define MAX_PROGRAM 1024

typedef struct _GPU GPU;

typedef struct _ProgCacheEntry {
    union {
        struct {
            GLuint vs;
            GLuint fs;
        };
        u64 key;
    };
    GLuint prog;

    struct _ProgCacheEntry *next, *prev;
} ProgCacheEntry;

typedef struct {
    GPU* gpu;

    GLuint main_vao;
    GLuint main_vbo;
    GLuint main_program;

    GLuint gpu_vao;
    GLuint gpu_vbos[12];
    GLuint gpu_ebo;

    GLuint gpu_vs;
    GLuint gpu_uberfs;

    LRUCache(ProgCacheEntry, MAX_PROGRAM) progcache;

    GLuint screentex[2];
    GLuint screenfbo[2];

    GLuint swrendertex;
    GLuint swrenderfbo;

    GLuint blanktex;

    union {
        GLuint ubos[4];
        struct {
            GLuint vert_ubo;
            GLuint uber_ubo;
            GLuint frag_ubo;
            GLuint freecam_ubo;
        };
    };

} GLState;

void renderer_gl_init(GLState* state, GPU* gpu);
void renderer_gl_destroy(GLState* state);

void renderer_gl_setup_gpu(GLState* state);
void render_gl_main(GLState* state, int view_w, int view_h);
void renderer_gl_update_freecam(GLState* state);

void gpu_gl_load_prog(GLState* state, GLuint vs, GLuint fs);

#endif
