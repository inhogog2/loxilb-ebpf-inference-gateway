/* SPDX-License-Identifier: BSD-3-Clause
 * Finish evidence for a P/D decode stream. An idle transport, or a closed
 * one, is never evidence of success on its own: what tells a finished
 * generation whose [DONE] was lost from a generation the engine cut is the
 * SSE events the client already received. */
#ifndef SOCKPROXY_PD_TERMINAL_H
#define SOCKPROXY_PD_TERMINAL_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Generation ended when a complete, bounded SSE data event finished every
 * choice and nothing came after it but events that carry no choice (the
 * usage event of stream_options.include_usage) or [DONE]. A later event with
 * content or an error, an oversized or malformed event, or a data event still
 * partial clears it. `proof` keeps the evidence across those neutral events;
 * `finished` is the verdict now (0 while an event is partial). */
#define SP_PD_EVENT_MAX 4096u
struct sp_pd_finish {
  char line[SP_PD_EVENT_MAX], event[SP_PD_EVENT_MAX];
  size_t line_len, event_len;
  uint8_t line_overflow, event_bad, has_data, finished, proof;
};
typedef struct sp_pd_finish sp_pd_finish_t;

void sp_pd_finish_feed(sp_pd_finish_t *state, const char *data, size_t len);

/* A new response: no line, no event, no evidence. The buffers are not
 * cleared; the lengths bound every read of them. */
static inline void sp_pd_finish_reset(sp_pd_finish_t *s)
{
  s->line_len = s->event_len = 0;
  s->line_overflow = s->event_bad = s->has_data = s->finished = s->proof = 0;
}
#endif
