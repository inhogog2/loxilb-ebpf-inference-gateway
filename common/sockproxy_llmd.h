/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * The llm-d request headers the capacity gate reads and writes when a rule
 * runs with fc_llmd_headers on. Kept apart from the proxy so the unit test
 * runs the same code on buffers of exact size.
 *
 *   x-llm-d-inference-ttl           read: how long the client will wait, in
 *                                   Go duration syntax; it shortens the
 *                                   wait of that request, never extends it
 *   x-llm-d-request-dropped-reason  written on a refusal the gate made
 *   x-llm-d-inference-objective     forwarded: the class the gateway resolved
 *   x-llm-d-inference-fairness-id   forwarded: the tenant the gateway resolved
 */
#ifndef __SOCKPROXY_LLMD_H__
#define __SOCKPROXY_LLMD_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define SP_LLMD_TTL_HDR        "x-llm-d-inference-ttl"
#define SP_LLMD_REASON_HDR     "x-llm-d-request-dropped-reason"
#define SP_LLMD_OBJECTIVE_HDR  "x-llm-d-inference-objective"
#define SP_LLMD_FAIRNESS_HDR   "x-llm-d-inference-fairness-id"
/* The deprecated names of the same two: a client's copy of either is dropped
 * before the resolved value is written, so a backend reads one. */
#define SP_LLMD_OBJECTIVE_OLD  "x-gateway-inference-objective"
#define SP_LLMD_FAIRNESS_OLD   "x-gateway-inference-fairness-id"

/* Whether a header name is one of the four the gateway writes itself when it
 * forwards the resolved objective and fairness identity: the names compared
 * whole, without case. */
static inline int
sp_llmd_forwarded_name(const char *name, size_t len)
{
  static const char *const names[] = {
    SP_LLMD_OBJECTIVE_HDR, SP_LLMD_OBJECTIVE_OLD,
    SP_LLMD_FAIRNESS_HDR, SP_LLMD_FAIRNESS_OLD,
  };

  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    if (len == strlen(names[i]) && !strncasecmp(name, names[i], len))
      return 1;
  return 0;
}

/* A TTL of a day or more is no shorter than any window a rule can hold. */
#define SP_LLMD_TTL_MAX_MS     86400000ULL
/* The longest duration Go's time.ParseDuration accepts, in nanoseconds. */
#define SP_LLMD_GO_MAX_NS      ((unsigned __int128)9223372036854775807ULL)

/*
 * Go duration syntax (time.ParseDuration), positive values only: a decimal
 * number with an optional fraction and a unit, one or more times, units
 * ns, us, µs, ms, s, m, h. A sign, an empty text, a number without a unit
 * (except "0"), an unknown unit or a total beyond what Go holds (2^63 - 1
 * ns, as time.ParseDuration refuses it) is not a duration. Returns 1 and the
 * whole milliseconds rounded up (at least 1, at most SP_LLMD_TTL_MAX_MS) when
 * the text is one and is not zero; 0 otherwise, and *ms is left alone.
 */
static inline int
sp_llmd_parse_ttl_ms(const char *s, size_t len, uint32_t *ms)
{
  unsigned __int128 total_ns = 0;
  size_t i = 0;
  int any = 0;

  if (!s || len == 0 || len > 40)
    return 0;
  if (len == 1 && s[0] == '0')
    return 0;
  while (i < len) {
    unsigned __int128 whole = 0, frac = 0, scale = 1;
    uint64_t unit_ns;
    int digits = 0;

    while (i < len && s[i] >= '0' && s[i] <= '9') {
      whole = whole * 10 + (unsigned)(s[i] - '0');
      if (whole > SP_LLMD_GO_MAX_NS)
        return 0;
      i++; digits++;
    }
    if (i < len && s[i] == '.') {
      i++;
      while (i < len && s[i] >= '0' && s[i] <= '9') {
        if (scale < 1000000000ULL) {
          frac = frac * 10 + (unsigned)(s[i] - '0');
          scale *= 10;
        }
        i++; digits++;
      }
    }
    if (digits == 0)
      return 0;
    if (i + 1 < len && (unsigned char)s[i] == 0xC2 &&
        (unsigned char)s[i + 1] == 0xB5 && i + 2 < len && s[i + 2] == 's') {
      unit_ns = 1000; i += 3;              /* µs (U+00B5) */
    } else if (i + 1 < len && !strncmp(s + i, "ns", 2)) {
      unit_ns = 1; i += 2;
    } else if (i + 1 < len && !strncmp(s + i, "us", 2)) {
      unit_ns = 1000; i += 2;
    } else if (i + 1 < len && !strncmp(s + i, "ms", 2)) {
      unit_ns = 1000000ULL; i += 2;
    } else if (i < len && s[i] == 's') {
      unit_ns = 1000000000ULL; i++;
    } else if (i < len && s[i] == 'm') {
      unit_ns = 60ULL * 1000000000ULL; i++;
    } else if (i < len && s[i] == 'h') {
      unit_ns = 3600ULL * 1000000000ULL; i++;
    } else {
      return 0;
    }
    /* whole <= 2^63 and unit_ns < 2^42: the product fits in 128 bits. */
    total_ns += whole * unit_ns + frac * unit_ns / scale;
    if (total_ns > SP_LLMD_GO_MAX_NS)
      return 0;
    any = 1;
  }
  if (!any || total_ns == 0)
    return 0;
  {
    unsigned __int128 m = (total_ns + 999999) / 1000000;

    if (m > SP_LLMD_TTL_MAX_MS)
      m = SP_LLMD_TTL_MAX_MS;
    if (m == 0)
      m = 1;
    *ms = (uint32_t)m;
  }
  return 1;
}

/* The capture of the TTL header on one request. A value can arrive in
 * several fragments (a read boundary inside it); they are appended. A header
 * repeated is last-one-wins, like the proxy's other captures. */
typedef struct sp_ttl_hint {
  char    buf[48];
  uint8_t len;
  uint8_t capturing;     /* the value in progress is the TTL header's */
  uint8_t oversize;      /* longer than any duration is: ignored */
} sp_ttl_hint_t;

static inline int
sp_ttl_hint_which(const char *hname, size_t hlen)
{
  return hlen == sizeof(SP_LLMD_TTL_HDR) - 1 &&
         !strncasecmp(hname, SP_LLMD_TTL_HDR, hlen);
}

static inline void
sp_ttl_hint_reset(sp_ttl_hint_t *h)
{
  memset(h, 0, sizeof(*h));
}

/* A new header name: whatever value was being collected is complete. */
static inline void
sp_ttl_hint_name(sp_ttl_hint_t *h)
{
  h->capturing = 0;
}

static inline void
sp_ttl_hint_val(sp_ttl_hint_t *h, const char *at, size_t len)
{
  if (!h->capturing) {
    h->capturing = 1;
    h->len = 0;
    h->oversize = 0;
    h->buf[0] = '\0';
  }
  if (h->oversize || len == 0)
    return;
  if ((size_t)h->len + len >= sizeof(h->buf)) {
    h->oversize = 1;
    h->len = 0;
    h->buf[0] = '\0';
    return;
  }
  memcpy(h->buf + h->len, at, len);
  h->len += (uint8_t)len;
  h->buf[h->len] = '\0';
}

/* The TTL the request asked for in whole milliseconds; 0 = none, or not a
 * duration. */
static inline uint32_t
sp_ttl_hint_ms(const sp_ttl_hint_t *h)
{
  uint32_t ms = 0;

  if (h->oversize || h->len == 0)
    return 0;
  return sp_llmd_parse_ttl_ms(h->buf, h->len, &ms) ? ms : 0;
}

/* The upstream reason a refusal of ours is, by the code in its body (the
 * mapping DESIGN 5.3 lists); NULL for a code that is not a capacity
 * refusal. */
static inline const char *
sp_llmd_reason_of(const char *code)
{
  if (!code)
    return NULL;
  if (!strcmp(code, "admission_capacity") || !strcmp(code, "admission_shed") ||
      !strcmp(code, "admission_tenant_share"))
    return "rejected-saturated";
  if (!strcmp(code, "admission_queue_timeout") ||
      !strcmp(code, "admission_ttl_expired"))
    return "rejected-ttl-expired";
  if (!strcmp(code, "admission_no_capacity"))
    return "rejected-no-endpoints";
  if (!strcmp(code, "gateway_draining") || !strcmp(code, "admission_drained"))
    return "rejected-shutting-down";
  return NULL;
}

#endif /* __SOCKPROXY_LLMD_H__ */
