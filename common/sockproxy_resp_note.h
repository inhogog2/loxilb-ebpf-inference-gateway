/* sockproxy_resp_note.h - the once-per-request latch of the client-visible
 * response record (proxy_note_response_ in sockproxy_http.c).
 *
 * A request's response is recorded once: its status, the responses-by-status
 * class counter and, for a backend reply, the TTFB sample. Three kinds of
 * site record it: the backend response capture, a path that answers the
 * client from the P/D prefill leg, whose reply the capture skips, and a
 * response the gateway writes itself (a refusal, an outage). They run on
 * different workers, so the latch is an atomic exchange, and a second call
 * for the same request is a no-op. Pure and header-only, so the unit TU
 * (test_pd_complete) pins the literal latch the shipped code takes.
 */
#ifndef SOCKPROXY_RESP_NOTE_H
#define SOCKPROXY_RESP_NOTE_H

#include <stdint.h>

/* Returns 1 to the first caller for the request, which records; 0 to every
 * later caller until resp_note_rearm. */
static inline int
resp_note_claim(uint8_t *noted)
{
  return __atomic_exchange_n(noted, (uint8_t)1, __ATOMIC_ACQ_REL) == 0;
}

/* Re-opened at the start of each request (keep-alive reuse). */
static inline void
resp_note_rearm(uint8_t *noted)
{
  __atomic_store_n(noted, (uint8_t)0, __ATOMIC_RELEASE);
}

/* What one record call takes: nothing (0) once the request is recorded,
 * else the status and class, and the TTFB sample only for a backend reply.
 * A gateway-local answer reaches its first byte in microseconds; sampling it
 * would pull the inference latency distribution down under a refusal storm. */
#define RESP_NOTE_COUNT 0x1
#define RESP_NOTE_TTFB  0x2

static inline int
resp_note_take(uint8_t *noted, int sample_ttfb)
{
  if (!resp_note_claim(noted))
    return 0;
  return RESP_NOTE_COUNT | (sample_ttfb ? RESP_NOTE_TTFB : 0);
}

/* The responses-by-status class of a status: 2..5, or 0 for none (1xx
 * interim, out of range). */
static inline int
resp_status_class(unsigned int status)
{
  return (status >= 200 && status < 600) ? (int)(status / 100) : 0;
}

#endif /* SOCKPROXY_RESP_NOTE_H */
