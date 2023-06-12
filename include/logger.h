#ifndef LOGGER_H
  #define LOGGER_H

#include <stdio.h>

#define END_TITLE "\e[0m"
#define ERROR_CODE "\e[31;1m"
#define DEBUG_CODE "\e[1;3m"
#define WARNING_CODE "\e[33;1m"
#define INFO_CODE "\e[34;1m"

#define N_INFO_TXT "\n"INFO_CODE"INFO:"END_TITLE" "
#define N_WARN_TXT "\n"WARNING_CODE"WARN:"END_TITLE" "
#define N_ERROR_TXT "\n"ERROR_CODE"ERROR:"END_TITLE" "
#define N_DEBUG_TXT "\n"DEBUG_CODE"DEBUG:"END_TITLE" "

#define N_INFO(msg) \
  fprintf(stdout, N_INFO_TXT msg);

#define N_INFOF(msg, ...) \
  fprintf(stdout, N_INFO_TXT msg, __VA_ARGS__);

#define N_WARN(msg) \
  fprintf(stdout, N_WARN_TXT msg);

#define N_WARNF(msg, ...) \
  fprintf(stdout, N_WARN_TXT msg, __VA_ARGS__);

#define N_ERROR(msg) \
  fprintf(stderr, N_ERROR_TXT msg);

#define N_ERRORF(msg, ...) \
  fprintf(stderr, N_ERROR_TXT msg, __VA_ARGS__);

#ifdef DEBUG

void debug_dump(uint8_t *, size_t);
void debug_dump_ascii(uint8_t *, size_t);
int is_vec_content_eq(
  uint8_t *, size_t,
  uint8_t *, size_t
);

  #define N_DEBUG(msg) \
    fprintf(stdout, N_DEBUG_TXT msg);

  #define N_DEBUGF(msg, ...) \
    fprintf(stdout, N_DEBUG_TXT msg, __VA_ARGS__);

  #define N_DEBUG_DUMP(data, data_sz) \
    debug_dump((uint8_t *)data, (size_t)data_sz);

  #define N_DEBUG_DUMP_A(data, data_sz) \
    debug_dump_ascii((uint8_t *)data, (size_t)data_sz);

  #define N_DEBUG_COMP_VEC(a, a_sz, b, b_sz) \
    N_DEBUGF("Comparing vector \"" #a "\" at (%p) with size %lu with vector \"" #b "\" at (%p) with size %lu", a, a_sz, b, b_sz) \
    if (is_vec_content_eq((uint8_t *)a, (size_t)a_sz, (uint8_t *)b, (size_t)b_sz)) { \
      N_DEBUG(#a " and " #b " are EQUALS") \
      N_DEBUG_DUMP(a, a_sz) \
    } else { \
      N_DEBUG("\n" #a " and " #b " are NOT EQUALS\n\t" #a " value:") \
      N_DEBUG_DUMP(a, a_sz) \
      N_DEBUG("\n\t" #b " value:") \
      N_DEBUG_DUMP(b, b_sz) \
    }

#else
  #define N_DEBUG(msg, ...)
  #define N_DEBUGF(msg, ...)
  #define N_DEBUG_DUMP(data, data_sz)
  #define N_DEBUG_DUMP_A(data, data_sz)
  #define N_DEBUG_COMP_VEC(a, a_sz, b, b_sz)
#endif

#endif

