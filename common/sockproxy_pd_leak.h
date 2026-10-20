/* sockproxy_pd_leak.h - Pure, unit-testable primitives for the 
 * P/D streaming-completion connection-leak fix.
 *
 * This header factors the two testable primitives the fixes depend on
 * into PURE, self-contained `static inline` functions that carry NO dependency
 * on the global proxy machinery, so a unit TU (test_pd_leak.c) can include them
 * directly the way test_pd_rewriter includes sockproxy_pd.c, while the shipped
 * code in sockproxy_http.c / sockproxy_health.c includes the SAME helpers (no
 * copy, no drift).
 *
 *   (1) pd_detect_http_msg_end(buf, len)
 *         Fragmentation-safe HTTP message-end detector. Returns nonzero when the
 *         already-accumulated buffer contains a complete HTTP message end:
 *           - the chunked transfer-coding last-chunk terminator "0\r\n\r\n", OR
 *           - an SSE "[DONE]" done-marker (the in-tree PROXY_SSE_DONE_STR1/2
 *             semantics).
 * (prefill, sockproxy_http.c:~1099) and (non-SSE decode,
 *         sockproxy_http.c:~1296) call this beside the existing Content-Length
 *         check so chunked / CL-less responses still complete.
 *
 *         V5 Input Validation: the scan is bounded by the caller-supplied `len`
 *         ONLY — it NEVER reads past buf+len. Callers pass the FULL accumulated
 *         heap buffer (pd_prefill_resp_buf / the decode resp buffer) plus its
 *         current length; because the buffer is accumulated, a single bounded
 *         memmem over the whole buffer is correct and is the simplest correct
 *         generalization of the C-5 sliding-window scanner.
 *
 *   (2) pd_teardown_legs(pfe, notify_del, ns)
 *         Encodes the safe two-leg teardown SEQUENCE from
 *         force_close_endpoint_connections() (sockproxy_health.c:133-150):
 *         deregister + close + zero each backend rfd[], then the client fd.
 * the Wave 1 reaper sites ( in
 *         sockproxy_health.c) call this helper and then SEPARATELY invoke the
 *         production fd-context release (the proxy_release_*fd_ctx machinery).
 *
 *         The production fd-context release is INTENTIONALLY NOT called here: it
 *         already re-enters pd_cleanup() (sockproxy_conn.c:758), so folding it
 *         into this helper would create the pd_cleanup re-entrancy / double-free
 *         hazard (RESEARCH Pitfall 1). Keeping it out also gives this helper zero
 *         dependency on the proxy machinery, which is what makes it unit-testable.
 *
 * Build: header-only. Production includes it after sockproxy_proto.h (so the
 * real `struct proxy_fd_ent` is visible). The unit TU defines
 * SOCKPROXY_PD_LEAK_FAKE_ENT before including, supplying its own fake struct
 * (the test_pd_cache_aware.c stub-struct precedent).
 */
#ifndef SOCKPROXY_PD_LEAK_H
#define SOCKPROXY_PD_LEAK_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE   /* memmem() */
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>     /* time_t */
#include <unistd.h>   /* close() */

#ifdef __cplusplus
extern "C" {
#endif

/* When the test TU defines SOCKPROXY_PD_LEAK_FAKE_ENT it supplies its own
 * `struct proxy_fd_ent { int fd; int rfd[...]; int n_rfd; };` BEFORE including
 * this header. Otherwise we rely on the real struct from sockproxy_proto.h,
 * which production TUs include ahead of this header; a forward declaration keeps
 * the pointer-typed signature valid even if only the forward decl is visible. */
#ifndef SOCKPROXY_PD_LEAK_FAKE_ENT
struct proxy_fd_ent;
#endif

/* The chunked transfer-coding last-chunk terminator: a zero-length chunk
 * ("0\r\n") followed by the trailing CRLF that closes the message. */
#define PD_CHUNKED_LAST_CHUNK     "0\r\n\r\n"
#define PD_CHUNKED_LAST_CHUNK_LEN 5

/* SSE "[DONE]" done-markers — mirrors PROXY_SSE_DONE_STR1/2 in sockproxy_http.c.
 * We accept either spacing variant a vLLM/OpenAI-style SSE stream emits. */
#define PD_SSE_DONE_STR1          "data:[DONE]"
#define PD_SSE_DONE_STR2          "data: [DONE]"

/*
 * pd_detect_http_msg_end - return nonzero iff [buf, buf+len) contains a complete
 * HTTP message end (chunked last-chunk terminator OR an SSE [DONE] marker).
 *
 * The scan is bounded strictly by `len`; memmem never reads past buf+len. A NULL
 * buffer or len shorter than the shortest terminator yields 0 (not complete).
 */
static inline int
pd_detect_http_msg_end(const uint8_t *buf, size_t len)
{
  if (buf == NULL || len == 0) {
    return 0;
  }

  /* Chunked transfer-coding: the last-chunk "0\r\n\r\n" terminator. Bounded by
   * `len` only (V5: never trust / scan beyond the supplied length). */
  if (len >= PD_CHUNKED_LAST_CHUNK_LEN &&
      memmem(buf, len, PD_CHUNKED_LAST_CHUNK, PD_CHUNKED_LAST_CHUNK_LEN) != NULL) {
    return 1;
  }

  /* SSE done-marker: "data:[DONE]" / "data: [DONE]" (token form, spacing-tolerant).
   * Same bounded scan over the accumulated buffer. */
  {
    size_t done1_len = sizeof(PD_SSE_DONE_STR1) - 1;
    size_t done2_len = sizeof(PD_SSE_DONE_STR2) - 1;
    if (len >= done1_len &&
        memmem(buf, len, PD_SSE_DONE_STR1, done1_len) != NULL) {
      return 1;
    }
    if (len >= done2_len &&
        memmem(buf, len, PD_SSE_DONE_STR2, done2_len) != NULL) {
      return 1;
    }
  }

  return 0;
}

/*
 * pd_http_resp_status - parse the status code out of an accumulated HTTP
 * response buffer's status line ("HTTP/1.x NNN ...").
 *
 * Same charter as the other helpers here: pure, bounded strictly by `len`,
 * no dependency on the proxy machinery, so the unit TU exercises the literal
 * production parser. Returns the 3-digit status (100..599) or 0 when the
 * buffer does not start with a well-formed HTTP/1.x status line — callers
 * treat 0 as "status unknown", never as a success or an error.
 */
static inline int
pd_http_resp_status(const uint8_t *buf, size_t len)
{
  /* "HTTP/1.x NNN" — 12 bytes minimum. */
  if (buf == NULL || len < 12 || memcmp(buf, "HTTP/1.", 7) != 0) {
    return 0;
  }
  if (buf[8] != ' ' ||
      buf[9]  < '0' || buf[9]  > '9' ||
      buf[10] < '0' || buf[10] > '9' ||
      buf[11] < '0' || buf[11] > '9') {
    return 0;
  }
  {
    int st = (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
    return (st >= 100 && st <= 599) ? st : 0;
  }
}

/*
 * pd_resp_error_excerpt - the origin's error string from an HTTP error reply,
 * for the log line of a reject the gateway relays.
 *
 * Copies the first JSON "message" string of the body (vLLM's
 * {"object":"error","message":...} and {"error":{"message":...}} shapes),
 * else the body's leading bytes, into out (NUL-terminated, at most cap - 1
 * bytes). Bounded by len and cap; a byte outside printable ASCII becomes '.',
 * so the excerpt stays one log line. Returns its length; 0 when the buffer
 * holds no body.
 */
static inline size_t
pd_resp_error_excerpt(const uint8_t *buf, size_t len, char *out, size_t cap)
{
  const uint8_t *b, *e, *p;
  int quoted = 0, esc = 0;
  size_t n = 0;

  if (out == NULL || cap == 0) return 0;
  out[0] = '\0';
  if (buf == NULL) return 0;
  b = (const uint8_t *)memmem(buf, len, "\r\n\r\n", 4);
  if (b == NULL) return 0;
  b += 4;
  e = buf + len;
  p = (const uint8_t *)memmem(b, (size_t)(e - b), "\"message\"", 9);
  if (p != NULL) {
    p += 9;
    while (p < e && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':'))
      p++;
    if (p < e && *p == '"') {
      b = p + 1;
      quoted = 1;
    }
  }
  for (p = b; p < e && n + 1 < cap; p++) {
    if (quoted && !esc && *p == '"') break;
    esc = quoted && !esc && *p == '\\';
    out[n++] = (*p >= 0x20 && *p < 0x7f) ? (char)*p : '.';
  }
  out[n] = '\0';
  return n;
}

/*
 * pd_prefill_status_verdict - what the sequential P/D machine does with a
 * prefill reply of the given status.
 *
 * PD_PR_RELAY: an origin 4xx is a deterministic client error that every
 * engine would repeat (unknown model, malformed body, prompt over the context
 * window). The decode leg would answer the same 4xx, so the client gets the
 * prefill reply and decode is not called. A reply cut at the buffer cap is
 * relayed by its status: the cut body is not the origin's any more, so the
 * relay writes a short gateway body in its place (pd_prefill_cut_reject)
 * rather than spend a decode call on the same reject.
 *
 * PD_PR_DECODE: everything else. A 5xx keeps the documented degradation (the
 * decode leg recomputes the prefill and the request is served; the breaker's
 * origin streak sees the 5xx), and an unknown status (0) is neither. 408 and
 * 429 are the prefill engine timing out or shedding load, transient like a
 * 5xx, so they take the same decode recompute.
 */
#define PD_PR_DECODE 0
#define PD_PR_RELAY  1

static inline int
pd_prefill_status_verdict(int status)
{
  return (status >= 400 && status < 500 && status != 408 && status != 429)
             ? PD_PR_RELAY : PD_PR_DECODE;
}

/*
 * pd_prefill_cut_reject - the response a client gets for an origin 4xx whose
 * prefill reply was cut at the buffer cap: the engine's status, and a short
 * gateway body in place of the cut one, framed by its length. Returns the
 * length written into out, 0 when it does not fit.
 */
static inline size_t
pd_prefill_cut_reject(int status, char *out, size_t cap)
{
  char body[160];
  const char *reason;
  int bl, n;

  switch (status) {
  case 400: reason = "Bad Request"; break;
  case 401: reason = "Unauthorized"; break;
  case 403: reason = "Forbidden"; break;
  case 404: reason = "Not Found"; break;
  case 413: reason = "Content Too Large"; break;
  case 422: reason = "Unprocessable Content"; break;
  default:  reason = "Client Error"; break;
  }
  bl = snprintf(body, sizeof(body),
                "{\"error\":\"prefill_rejected\",\"status\":%d,"
                "\"detail\":\"the engine's reply was cut at the gateway's buffer cap\"}",
                status);
  if (bl <= 0 || (size_t)bl >= sizeof(body))
    return 0;
  n = snprintf(out, cap,
               "HTTP/1.1 %d %s\r\n"
               "Content-Type: application/json\r\n"
               "Content-Length: %d\r\n"
               "\r\n"
               "%s", status, reason, bl, body);
  return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

/*
 * pd_prefill_fallback_reason - why a prefill reply that pd_prefill_status_verdict
 * sent to the decode leg was recomputed there (loxilb_ai_pd_prefill_fallback_total
 * {reason}); PD_FB_NONE when it was not a fallback. The reason is the condition
 * that forced the fallback, in verdict order: when the status alone forces it,
 * the status is the reason, whether or not the body was cut; when the reply
 * would have been used and the fallback happened only because it was cut at
 * the buffer cap, the reason is truncated (a cut 2xx).
 *
 *   >= 500             -> PD_FB_ORIGIN_5XX  (cut or not)
 *   408 / 429          -> PD_FB_ORIGIN_408 / PD_FB_ORIGIN_429  (cut or not)
 *   0 (unreadable)     -> PD_FB_NO_STATUS   (cut or not: the status alone forces it)
 *   1xx, 3xx           -> PD_FB_OTHER       (an unusable reply)
 *   2xx cut            -> PD_FB_TRUNCATED
 *   2xx not cut        -> PD_FB_NONE        (the normal path)
 *   other 4xx          -> PD_FB_NONE        (relayed, cut or not: never reaches decode)
 */
#define PD_FB_NONE        0
#define PD_FB_ORIGIN_5XX  1
#define PD_FB_ORIGIN_408  2
#define PD_FB_ORIGIN_429  3
#define PD_FB_NO_STATUS   4
#define PD_FB_TRUNCATED   5
#define PD_FB_OTHER       6
static inline int
pd_prefill_fallback_reason(int status, int truncated)
{
  if (status >= 500) return PD_FB_ORIGIN_5XX;
  if (status == 408) return PD_FB_ORIGIN_408;
  if (status == 429) return PD_FB_ORIGIN_429;
  if (status <= 0) return PD_FB_NO_STATUS;
  if (status < 200 || (status >= 300 && status < 400)) return PD_FB_OTHER;
  if (status >= 400) return PD_FB_NONE;
  return truncated ? PD_FB_TRUNCATED : PD_FB_NONE;
}

/*
 * pd_decode_error_phase - the llb_ai_pd_record error_phase of a P/D request
 * whose decode leg delivered its whole response, from the status the client
 * received (the decode leg's; the prefill reply is not captured).
 *
 *   2xx, 3xx -> 0  complete / success
 *   4xx      -> 6  decode / rejected  (origin refused; relayed verbatim)
 *   5xx      -> 2  decode / error
 *   0, 1xx   -> 7  decode / unknown   (no final status line was read)
 *
 * An unknown status is not a success. The capture reads the status line at
 * the start of the decode leg's first read; a first read of 16 bytes or less,
 * a status line split across reads, or a reply that is not HTTP/1.x leaves it
 * unread, and no other record names that request's outcome.
 */
static inline int
pd_decode_error_phase(int status)
{
  if (status < 200) return 7;
  if (status < 400) return 0;
  if (status < 500) return 6;
  return 2;
}

/*
 * pd_reap_error_phase - the llb_ai_pd_record error_phase of a P/D request a
 * reaper ends while it is still in flight, from its pd_phase (the numbers are
 * sockproxy.h's PD_PHASE_*; sockproxy_health.c asserts them):
 *
 *   1..3  PREFILL_SENDING / _WAITING / _DONE -> 1  prefill / timeout
 *   4     DECODE_SENDING  (no decode byte)   -> 3  decode / timeout
 *   5     DECODE_STREAMING (the answer began) -> 8  decode / truncated
 *   else  not in flight                       -> -1 nothing to record
 *
 * The phase names the cause. A begun answer a reaper ends was ended by the
 * gateway: the engine went silent (the sweep, the stream timeout, the idle
 * cap) or a policy cap ended it (the duration cap), so it is decode/truncated
 * whether the gateway wrote a terminator or cut it with an error;
 * pd_terminator_synthesized tells the two apart. decode/error (2) is the
 * engine's death, which only the decode leg sees. A client that stopped
 * reading is the client's abort: the stall reaper records decode/aborted (9),
 * not this table's value. -1 for every other
 * phase is what makes the record once: the reaper moves the request to ERROR
 * after recording it.
 */
static inline int
pd_reap_error_phase(int pd_phase)
{
  if (pd_phase >= 1 && pd_phase <= 3) return 1;
  if (pd_phase == 4) return 3;
  if (pd_phase == 5) return 8;
  return -1;
}

/* PD_MSG_END_TAIL_KEEP - bytes of trailing context carried between successive
 * reads so a message-end terminator that straddles two TCP segments is still
 * detected. Must be >= the longest terminator pd_detect_http_msg_end matches:
 *   strlen("data: [DONE]") = 12, strlen("0\r\n\r\n") = 5.
 * 20 matches the in-tree PROXY_SSE_TAIL_KEEP (sockproxy_http.c) and the
 * proxy_fd_ent.sse_tail[20] field this rides on, with headroom for the SSE
 * done-line's trailing "\n\n". */
#define PD_MSG_END_TAIL_KEEP 20

/*
 * pd_scan_msg_end_window - fragmentation-safe HTTP message-end detector.
 *
 * pd_detect_http_msg_end() sees only ONE packet, so a terminator split across two
 * reads (e.g. "...data: [DO" | "NE]\n\n") is missed. This wrapper keeps a sliding
 * tail of the last PD_MSG_END_TAIL_KEEP bytes in caller-owned state (`tail` /
 * `*tail_len` — e.g. proxy_fd_ent.sse_tail / .sse_tail_len) and scans BOTH the
 * overlap window (old tail + new data tail) AND the full current packet, so a
 * terminator is detected wherever it lands:
 *   - straddling the read boundary  -> caught by the overlap window;
 *   - wholly inside this packet      -> caught by the full-packet scan (the
 *     window can be shorter than the packet when len > PD_MSG_END_TAIL_KEEP).
 *
 * Caller-state contract: `tail` points to a buffer of >= PD_MSG_END_TAIL_KEEP
 * bytes; `*tail_len` is 0 on the first call for a connection and is maintained
 * here thereafter. Either pointer may be NULL, degrading to a single-packet scan
 * (correct, just not fragmentation-safe). Bounded strictly by `len`; never reads
 * past msg+len. Returns nonzero iff a complete HTTP message end is present.
 *
 * T3: on the sse_active==0 stall path this is the ONLY decode
 * completion detector, and a split terminator under load is exactly what stranded
 * the decode leg with the single-packet scan.
 */
static inline int
pd_scan_msg_end_window(uint8_t *tail, uint8_t *tail_len,
                       const uint8_t *msg, size_t len)
{
  if (msg == NULL || len == 0) {
    return 0;
  }

  uint8_t window[PD_MSG_END_TAIL_KEEP * 2];
  uint8_t old_len = (tail != NULL && tail_len != NULL &&
                     *tail_len <= PD_MSG_END_TAIL_KEEP) ? *tail_len : 0;
  uint8_t new_len = (len < PD_MSG_END_TAIL_KEEP) ? (uint8_t)len
                                                 : PD_MSG_END_TAIL_KEEP;

  if (old_len > 0) {
    memcpy(window, tail, old_len);
  }
  memcpy(window + old_len, msg + (len - new_len), new_len);
  size_t window_len = (size_t)old_len + new_len;

  /* Advance the sliding tail to the end of the current packet. */
  if (tail != NULL && tail_len != NULL) {
    memcpy(tail, msg + (len - new_len), new_len);
    *tail_len = new_len;
  }

  if (pd_detect_http_msg_end(window, window_len)) {
    return 1;
  }
  if (pd_detect_http_msg_end(msg, len)) {
    return 1;
  }
  return 0;
}

/* PROXY_PD_DECODE_IDLE_CAP_SEC - default backend-idle window (seconds) after which
 * a decode-streaming SSE connection whose backend leg has gone silent is reaped
 * with a SYNTHESIZED graceful "data: [DONE]\n\n" terminator instead of hanging.
 *
 * (RESOLVED): vLLM's P/D-disagg path FINISHES generation but omits the
 * closing "data: [DONE]" SSE chunk for ~2.5% of streams under concurrency (loxilb
 * exonerated — its :1198 scanner completes 100% of TERMINATED streams). Without a
 * terminator the decode leg never reaches PD_PHASE_COMPLETE and the client hangs
 * until a wall-clock backstop ( 502 @120s / 504 @180s) injects a
 * malformed HTTP status line into a live SSE body. This safety-net converts that
 * forever-hang into a protocol-correct completion.
 *
 * Chosen ~25s: a healthy decode stream emits a token every few hundred ms, so 25s
 * of TOTAL backend silence strongly implies generation is over. Gated on the
 * LAST-BACKEND-BYTE timestamp (pd_last_decode_ts), NOT wall-clock-since-start, so a
 * legitimately slow-but-still-streaming response is never truncated. */
#ifndef PROXY_PD_DECODE_IDLE_CAP_SEC
#define PROXY_PD_DECODE_IDLE_CAP_SEC 25
#endif

/*
 * pd_should_graceful_complete - decide whether a P/D decode-streaming connection
 * should be force-completed with a synthesized SSE [DONE] terminator.
 *
 * Pure predicate (no proxy machinery) so the reaper's decision is unit-testable.
 * Returns nonzero IFF ALL hold:
 *   - is_decode_streaming : pd_phase == PD_PHASE_DECODE_STREAMING (the only phase
 *     where the client has already received "200 OK" + SSE chunks, making a
 *     synthesized "data: [DONE]" the protocol-correct termination);
 *   - sse_active          : this is a live SSE stream (not a non-SSE JSON body —
 *     injecting "data: [DONE]" into a non-SSE body would be garbage);
 *   - stream_end_ts == 0  : the real [DONE] has not already been seen;
 *   - last_decode_ts  > 0 : at least one backend byte was relayed (we have a
 *     meaningful idle clock to measure against);
 *   - idle_cap_sec    > 0 : the safety-net is enabled;
 *   - (now - last_decode_ts) >= idle_cap_sec : the BACKEND leg has been silent
 *     past the cap. Measuring from last_decode_ts (refreshed per relayed byte),
 *     NOT from stream_start_ts, is what guarantees a still-streaming response is
 *     not truncated.
 */
static inline int
pd_should_graceful_complete(int is_decode_streaming, int sse_active,
                            time_t stream_end_ts, time_t last_decode_ts,
                            time_t now, uint32_t idle_cap_sec)
{
  if (!is_decode_streaming) {
    return 0;
  }
  if (!sse_active) {
    return 0;
  }
  if (stream_end_ts != 0) {
    return 0;
  }
  if (last_decode_ts <= 0) {
    return 0;
  }
  if (idle_cap_sec == 0) {
    return 0;
  }
  return (now - last_decode_ts) >= (time_t)idle_cap_sec;
}

/*
 * pd_teardown_legs - safe two-leg teardown of a P/D connection.
 *
 * Encodes the close SEQUENCE from force_close_endpoint_connections()
 * (sockproxy_health.c:133-150) WITHOUT calling the production fd-context
 * release machinery:
 *   - for each backend leg pfe->rfd[i] (i < pfe->n_rfd) that is > 0:
 *       notify_del(ns, rfd[i], 0); close(rfd[i]); rfd[i] = -1;
 *   - then if the client fd pfe->fd > 0:
 *       notify_del(ns, pfe->fd, 0); close(pfe->fd); pfe->fd = -1;
 *
 * `notify_del` is the notifier-deregister callback (production passes a thunk
 * over notify_delete_ent; the unit TU passes a recording fake). It may be NULL,
 * in which case deregistration is skipped (close still happens). The caller —
 * the Wave 1 reaper — is responsible for invoking the production fd-context
 * release (pfe, 1) AFTER this helper returns (kept out here to avoid the
 * pd_cleanup re-entrancy hazard; see header banner).
 *
 * Returns the number of fds closed (backend legs + client), for assertions.
 */
static inline int
pd_teardown_legs(struct proxy_fd_ent *pfe,
                 int (*notify_del)(void *ns, int fd, int arg),
                 void *ns)
{
  int closed = 0;

  if (pfe == NULL) {
    return 0;
  }

  for (int i = 0; i < pfe->n_rfd; i++) {
    if (pfe->rfd[i] > 0) {
      if (notify_del != NULL) {
        notify_del(ns, pfe->rfd[i], 0);
      }
      close(pfe->rfd[i]);
      pfe->rfd[i] = -1;
      closed++;
    }
  }

  if (pfe->fd > 0) {
    if (notify_del != NULL) {
      notify_del(ns, pfe->fd, 0);
    }
    close(pfe->fd);
    pfe->fd = -1;
    closed++;
  }

  return closed;
}

#ifdef __cplusplus
}
#endif

#endif /* SOCKPROXY_PD_LEAK_H */
