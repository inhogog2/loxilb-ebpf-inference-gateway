/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * sockproxy_parser_once.h — llhttp settings shared by every connection, set
 * exactly once.
 *
 * A framer whose callbacks are the same for every connection keeps one
 * llhttp_settings_t for all of them. Every worker's parser reads it on every
 * byte, so it must be complete before the first parser that uses it starts
 * and must never be written again: a lazy "fill it if not filled yet" lets
 * two workers that meet their first connection together both fill it, and
 * the second fill's memset zeroes callbacks the first worker's parser is
 * reading. llhttp skips a NULL callback, so that parser silently loses a
 * response's status, headers or end.
 *
 * SP_PARSER_SETTINGS_ONCE(name, fill) defines `name##_settings_get()`, which
 * returns the settings after fill() has run on them once, under
 * pthread_once: every caller, on any thread, sees them filled.
 *
 * Deliberately free of project includes beyond llhttp so a unit can use it.
 */
#ifndef __SOCKPROXY_PARSER_ONCE_H__
#define __SOCKPROXY_PARSER_ONCE_H__

#include <pthread.h>
#include "llhttp.h"

#define SP_PARSER_SETTINGS_ONCE(name, fill)                                   \
  static llhttp_settings_t name##_settings;                                   \
  static pthread_once_t name##_settings_once = PTHREAD_ONCE_INIT;             \
  static void name##_settings_fill_once(void)                                 \
  {                                                                           \
    llhttp_settings_init(&name##_settings);                                   \
    fill(&name##_settings);                                                   \
  }                                                                           \
  static const llhttp_settings_t *name##_settings_get(void)                   \
  {                                                                           \
    pthread_once(&name##_settings_once, name##_settings_fill_once);           \
    return &name##_settings;                                                  \
  }

#endif /* __SOCKPROXY_PARSER_ONCE_H__ */
