/**
 * Copyright (c) 2020 rxi
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See `log.c` for details.
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define LOG_VERSION "0.1.0"

typedef struct {
  va_list ap;
  const char *fmt;
  const char *file;
  struct tm *time;
  void *udata;
  int line;
  int level;
  /* The line as the built-in sinks emit it, formatted once per log_log call:
   * "YYYY-MM-DD HH:MM:SS LEVEL file:line: message\n". A callback may write
   * it with one write(2) instead of formatting ev->fmt / ev->ap itself. */
  const char *line_buf;
  size_t line_len;
} log_Event;

typedef void (*log_LogFn)(log_Event *ev);
typedef void (*log_LockFn)(bool lock, void *udata);

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

#define log_trace(...) log_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...)  log_log(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...)  log_log(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

const char* log_level_string(int level);
void log_set_lock(log_LockFn fn, void *udata);
void log_set_level(int level);
void log_set_quiet(bool enable);
int log_add_callback(log_LogFn fn, void *udata, int level);
int log_add_fp(FILE *fp, int level);


/* After log_async_start() a log call copies its line into the calling
 * thread's ring and returns; one writer thread writes the sinks, rotates a
 * file sink and reports what was dropped. A full ring drops the line and
 * counts it. log_async_stop() empties the rings and makes log calls write
 * for themselves again; it waits timeout_ms for a writer held by a stalled
 * sink and returns -1 if that was not enough. A FATAL line is always
 * written by its caller. */
int  log_async_start(void);
int  log_async_stop(int timeout_ms);
/* Wait until what is queued now has been handed to the sinks; -1 on timeout. */
int  log_flush(int timeout_ms);
/* Lines dropped on a full ring since start, by level. */
uint64_t log_dropped(int level);
/* The writer renames path and opens it anew when the file behind fp would
 * pass max_bytes (0 = never). fp is a sink already added with log_add_fp. */
int  log_rotate_fp(FILE *fp, const char *path, uint64_t max_bytes);
/* Async-signal-safe: the calling thread's unwritten lines, written to fd. */
void log_emergency_dump(int fd);

void log_log(int level, const char *file, int line, const char *fmt, ...);

#endif
