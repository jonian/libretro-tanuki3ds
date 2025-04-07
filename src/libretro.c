#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "libretro.h"

#include "3ds.h"
#include "cpu.h"
#include "emulator.h"
#include "video/renderer_gl.h"

#ifndef GIT_VERSION
#define GIT_VERSION "0.1.0"
#endif

static retro_environment_t environ_cb;
static retro_video_refresh_t video_cb;
static retro_audio_sample_batch_t audio_batch_cb;
static retro_input_poll_t input_poll_cb;
static retro_input_state_t input_state_cb;

static struct retro_log_callback logging;
static retro_log_printf_t log_cb;

static struct retro_hw_render_callback hw_render;
static bool pending_reset;

static char* system_path;
static char* saves_path;

static char* game_path;
static char* save_path;

static int touch_x = 0;
static int touch_y = 0;

static uint32_t clamp(uint32_t value, uint32_t min, uint32_t max)
{
  if (value < min) return min;
  if (value > max) return max;
  return value;
}

static char* concat(const char *s1, const char *s2)
{
  char *result = malloc(strlen(s1) + strlen(s2) + 1);
  strcpy(result, s1);
  strcat(result, s2);
  return result;
}

static char* normalize_path(const char* path, bool add_slash)
{
  char *new_path = malloc(strlen(path) + 1);
  strcpy(new_path, path);

  if (add_slash && new_path[strlen(new_path) - 1] != '/')
    strcat(new_path, "/");

#ifdef WINDOWS
  for (char* p = new_path; *p; p++)
    if (*p == '\\') *p = '/';
#endif

  return new_path;
}

static char* get_name_from_path(const char* path)
{
  char *base = malloc(strlen(path) + 1);
  strcpy(base, strrchr(path, '/') + 1);

  char* delims[] = { ".zip#", ".7z#", ".apk#" };
  for (int i = 0; i < 3; i++)
  {
    char* delim_pos = strstr(base, delims[i]);
    if (delim_pos) *delim_pos = '\0';
  }

  char* ext = strrchr(base, '.');
  if (ext) *ext = '\0';

  return base;
}

static void log_fallback(enum retro_log_level level, const char *fmt, ...)
{
  (void)level;
  va_list va;
  va_start(va, fmt);
  vfprintf(stderr, fmt, va);
  va_end(va);
}

static void* get_gl_proc_address(const char* name)
{
  return (void*)hw_render.get_proc_address(name);
}

static void video_reset_context()
{
  if (!gladLoadGLLoader(get_gl_proc_address))
    log_cb(RETRO_LOG_ERROR, "OpenGL init failed\n");

  renderer_gl_init(&ctremu.system.gpu.gl, &ctremu.system.gpu);
}

static void video_destroy_context()
{
  renderer_gl_destroy(&ctremu.system.gpu.gl, &ctremu.system.gpu);
}

static bool set_hw_render(enum retro_hw_context_type type)
{
  hw_render.context_type = type;
  hw_render.context_reset = video_reset_context;
  hw_render.context_destroy = video_destroy_context;
  hw_render.bottom_left_origin = true;

  if (type == RETRO_HW_CONTEXT_OPENGL_CORE)
  {
    hw_render.version_major = 4;
    hw_render.version_minor = 1;

    if (environ_cb(RETRO_ENVIRONMENT_SET_HW_RENDER, &hw_render))
      return true;
  }

  return false;
}

static void init_video()
{
  enum retro_hw_context_type preferred = RETRO_HW_CONTEXT_NONE;
  environ_cb(RETRO_ENVIRONMENT_GET_PREFERRED_HW_RENDER, &preferred);

  if (preferred && set_hw_render(preferred)) return;
  if (set_hw_render(RETRO_HW_CONTEXT_OPENGL_CORE)) return;
  if (set_hw_render(RETRO_HW_CONTEXT_OPENGL)) return;
  if (set_hw_render(RETRO_HW_CONTEXT_OPENGLES3)) return;

  hw_render.context_type = RETRO_HW_CONTEXT_NONE;
}

static char* fetch_variable(const char* key, const char* def)
{
  struct retro_variable var = {0};
  var.key = key;

  if (!environ_cb(RETRO_ENVIRONMENT_GET_VARIABLE, &var) || var.value == NULL)
  {
    log_cb(RETRO_LOG_WARN, "Fetching variable %s failed.\n", var.key);

    char* default_value = (char*)malloc(strlen(def) + 1);
    strcpy(default_value, def);

    return default_value;
  }

  char* value = (char*)malloc(strlen(var.value) + 1);
  strcpy(value, var.value);

  return value;
}

static bool fetch_variable_bool(const char* key, bool def)
{
  char* result = fetch_variable(key, def ? "enabled" : "disabled");
  bool is_enabled = strcmp(result, "enabled") == 0;

  free(result);
  return is_enabled;
}

static int fetch_variable_int(const char* key, int def)
{
  char* result = fetch_variable(key, NULL);
  if (result == NULL) return def;

  char* endptr;
  int value = strtol(result, &endptr, 10);

  free(result);
  return value;
}

static char* get_save_dir()
{
  char* dir = NULL;
  if (!environ_cb(RETRO_ENVIRONMENT_GET_SAVE_DIRECTORY, &dir) || dir == NULL)
  {
    log_cb(RETRO_LOG_INFO, "No save directory provided by LibRetro.\n");
    return "ctremu";
  }
  return dir;
}

static char* get_system_dir()
{
  char* dir = NULL;
  if (!environ_cb(RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY, &dir) || dir == NULL)
  {
    log_cb(RETRO_LOG_INFO, "No system directory provided by LibRetro.\n");
    return "ctremu";
  }
  return dir;
}

static bool get_button_state(unsigned id)
{
  return input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, id);
}

static int get_axis_state(uint index, uint id)
{
  return input_state_cb(0, RETRO_DEVICE_ANALOG, index, id);
}

static void init_input(void)
{
  static const struct retro_controller_description controllers[] = {
    { "Nintendo 3DS", RETRO_DEVICE_JOYPAD },
    { NULL, 0 },
  };

  static const struct retro_controller_info ports[] = {
    { controllers, 1 },
    { NULL, 0 },
  };

  environ_cb(RETRO_ENVIRONMENT_SET_CONTROLLER_INFO, (void*)ports);

  struct retro_input_descriptor desc[] = {
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_LEFT,  "Left" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_UP,    "Up" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_DOWN,  "Down" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_RIGHT, "Right" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_A, "A" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_B, "B" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_SELECT, "Select" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_START,  "Start" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_R, "R" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_L, "L" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_X, "X" },
    { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_Y, "Y" },
    { 0, RETRO_DEVICE_ANALOG, RETRO_DEVICE_INDEX_ANALOG_LEFT, RETRO_DEVICE_ID_ANALOG_X, "Circle Pad X" },
    { 0, RETRO_DEVICE_ANALOG, RETRO_DEVICE_INDEX_ANALOG_LEFT, RETRO_DEVICE_ID_ANALOG_Y, "Circle Pad Y" },
    { 0 },
  };

  environ_cb(RETRO_ENVIRONMENT_SET_INPUT_DESCRIPTORS, desc);
}

static void init_config()
{
  static const struct retro_variable values[] = {
    { "tanuki3ds_videoscale", "Video resolution scale factor; 1|2|3|4|5" },
    { "tanuki3ds_shaderjit", "Enable JIT shader compiler; enabled|disabled" },
    { "tanuki3ds_hwvshaders", "Enable HW shader mode; enabled|disabled" },
    { "tanuki3ds_safeShaderMul", "Use safe shader multiplier; enabled|disabled" },
    { "tanuki3ds_hashTextures", "Enable texture hashing; enabled|disabled" },
    { NULL, NULL }
  };

  environ_cb(RETRO_ENVIRONMENT_SET_VARIABLES, (void*)values);
}

static void update_config()
{
  ctremu.videoscale = fetch_variable_int("tanuki3ds_videoscale", 1);
  ctremu.shaderjit = fetch_variable_bool("tanuki3ds_shaderjit", true);
  ctremu.hwvshaders = fetch_variable_bool("tanuki3ds_hwvshaders", true);
  ctremu.safeShaderMul = fetch_variable_bool("tanuki3ds_safeShaderMul", true);
  ctremu.hashTextures = fetch_variable_bool("tanuki3ds_hashTextures", true);
}

static void check_config_variables()
{
  bool updated = false;
  environ_cb(RETRO_ENVIRONMENT_GET_VARIABLE_UPDATE, &updated);

  if (updated) update_config();
}

static void core_audio_callback(int16_t (*samples)[2], uint32_t count)
{
  if (!ctremu.mute)
  {
    static int16_t buffer[FRAME_SAMPLES * 2];

    for (uint32_t i = 0; i < count; i++)
    {
      buffer[i * 2 + 0] = samples[i][0];
      buffer[i * 2 + 1] = samples[i][1];
    }

    audio_batch_cb(buffer, count);
  }
}

void retro_get_system_info(struct retro_system_info* info)
{
  info->need_fullpath = true;
  info->valid_extensions = "3ds|cci|cxi|app|elf";
  info->library_version = GIT_VERSION;
  info->library_name = "Tanuki3DS";
  info->block_extract = false;
}

void retro_get_system_av_info(struct retro_system_av_info* info)
{
  info->geometry.base_width = SCREEN_WIDTH_TOP;
  info->geometry.base_height = SCREEN_HEIGHT * 2;

  info->geometry.max_width = info->geometry.base_width;
  info->geometry.max_height = info->geometry.base_height;
  info->geometry.aspect_ratio = 5.0 / 6.0;

  info->timing.fps = 60.0;
  info->timing.sample_rate = 32768;
}

void retro_set_environment(retro_environment_t cb)
{
  environ_cb = cb;
}

void retro_set_video_refresh(retro_video_refresh_t cb)
{
  video_cb = cb;
}

void retro_set_audio_sample_batch(retro_audio_sample_batch_t cb)
{
  audio_batch_cb = cb;
}

void retro_set_audio_sample(retro_audio_sample_t cb)
{
}

void retro_set_input_poll(retro_input_poll_t cb)
{
  input_poll_cb = cb;
}

void retro_set_input_state(retro_input_state_t cb)
{
  input_state_cb = cb;
}

void retro_init(void)
{
  enum retro_pixel_format xrgb888 = RETRO_PIXEL_FORMAT_XRGB8888;
  environ_cb(RETRO_ENVIRONMENT_SET_PIXEL_FORMAT, &xrgb888);

  if (environ_cb(RETRO_ENVIRONMENT_GET_LOG_INTERFACE, &logging))
    log_cb = logging.log;
  else
    log_cb = log_fallback;

  system_path = normalize_path(get_system_dir(), true);
  saves_path = normalize_path(get_save_dir(), true);
}

void retro_deinit(void)
{
  log_cb = NULL;
}

bool retro_load_game(const struct retro_game_info* info)
{
  const char* name = get_name_from_path(info->path);
  const char* save = concat(name, ".sav");

  game_path = normalize_path(info->path, false);
  save_path = normalize_path(concat(saves_path, save), false);

  init_config();
  init_input();
  init_video();

  update_config();

  emulator_init();
  emulator_set_rom(game_path);

  ctremu.audio_cb = core_audio_callback;
  pending_reset = true;

  return true;
}

bool retro_load_game_special(unsigned type, const struct retro_game_info* info, size_t info_size)
{
  return false;
}

void retro_unload_game(void)
{
  emulator_quit();
}

void retro_reset(void)
{
  if (emulator_reset())
  {
    ctremu.pause = false;
    log_cb(RETRO_LOG_DEBUG, "ROM loaded successfully\n");
  }
  else
  {
    log_cb(RETRO_LOG_ERROR, "ROM loading failed\n");
    ctremu.pause = true;
  }
}

void retro_run(void)
{
  check_config_variables();
  input_poll_cb();

  if (pending_reset)
  {
    glClear(GL_COLOR_BUFFER_BIT);
    ctremu.running = true;

    pending_reset = false;
    retro_reset();
  }

  if (!ctremu.pause)
  {
    PadState btn = {};

    int cx = get_axis_state(RETRO_DEVICE_INDEX_ANALOG_LEFT, RETRO_DEVICE_ID_ANALOG_X);
    int cy = get_axis_state(RETRO_DEVICE_INDEX_ANALOG_LEFT, RETRO_DEVICE_ID_ANALOG_Y);

    btn.a = get_button_state(RETRO_DEVICE_ID_JOYPAD_A);
    btn.b = get_button_state(RETRO_DEVICE_ID_JOYPAD_B);
    btn.x = get_button_state(RETRO_DEVICE_ID_JOYPAD_X);
    btn.y = get_button_state(RETRO_DEVICE_ID_JOYPAD_Y);
    btn.l = get_button_state(RETRO_DEVICE_ID_JOYPAD_L);
    btn.r = get_button_state(RETRO_DEVICE_ID_JOYPAD_R);
    btn.start = get_button_state(RETRO_DEVICE_ID_JOYPAD_START);
    btn.select = get_button_state(RETRO_DEVICE_ID_JOYPAD_SELECT);
    btn.up = get_button_state(RETRO_DEVICE_ID_JOYPAD_UP);
    btn.down = get_button_state(RETRO_DEVICE_ID_JOYPAD_DOWN);
    btn.left = get_button_state(RETRO_DEVICE_ID_JOYPAD_LEFT);
    btn.right = get_button_state(RETRO_DEVICE_ID_JOYPAD_RIGHT);

    btn.cup = cy > INT16_MAX / 2;
    btn.cdown = cy < INT16_MIN / 2;
    btn.cleft = cx < INT16_MIN / 2;
    btn.cright = cx > INT16_MAX / 2;

    hid_update_pad(&ctremu.system, btn.w, cx, cy);

    bool touch = false;

    int pos_x = input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_X);
    int pos_y = input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_Y);

    int new_x = (int)((pos_x + 0x7fff) / (float)(0x7fff * 2) * (SCREEN_WIDTH_BOT));
    int new_y = (int)((pos_y + 0x7fff) / (float)(0x7fff * 2) * (SCREEN_HEIGHT * 2));

    bool in_screen_x = new_x >= 0 && new_x <= SCREEN_WIDTH_BOT;
    bool in_screen_y = new_y >= SCREEN_HEIGHT && new_y <= (SCREEN_HEIGHT * 2);

    if (in_screen_x && in_screen_y)
    {
      touch |= input_state_cb(0, RETRO_DEVICE_MOUSE, 0, RETRO_DEVICE_ID_MOUSE_LEFT);
      touch |= input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_PRESSED);

      touch_x = clamp(new_x, 0, SCREEN_WIDTH_BOT);
      touch_y = clamp(new_y - SCREEN_HEIGHT, 0, SCREEN_HEIGHT);
    }

    hid_update_touch(&ctremu.system, touch_x, touch_y, touch);

    gpu_gl_start_frame(&ctremu.system.gpu);
    e3ds_run_frame(&ctremu.system);
  }

  render_gl_main(&ctremu.system.gpu.gl, SCREEN_WIDTH_TOP, SCREEN_HEIGHT * 2);
  video_cb(RETRO_HW_FRAME_BUFFER_VALID, SCREEN_WIDTH_TOP, SCREEN_HEIGHT * 2, 0);
}

void retro_set_controller_port_device(unsigned port, unsigned device)
{
}

size_t retro_serialize_size(void)
{
  return 0;
}

bool retro_serialize(void* data, size_t size)
{
  return false;
}

bool retro_unserialize(const void* data, size_t size)
{
  return false;
}

unsigned retro_get_region(void)
{
  return RETRO_REGION_NTSC;
}

unsigned retro_api_version()
{
  return RETRO_API_VERSION;
}

size_t retro_get_memory_size(unsigned id)
{
  if (id == RETRO_MEMORY_SYSTEM_RAM)
  {
    return 0;
  }
  return 0;
}

void* retro_get_memory_data(unsigned id)
{
  if (id == RETRO_MEMORY_SYSTEM_RAM)
  {
    return NULL;
  }
  return NULL;
}

void retro_cheat_set(unsigned index, bool enabled, const char* code)
{
}

void retro_cheat_reset(void)
{
}
