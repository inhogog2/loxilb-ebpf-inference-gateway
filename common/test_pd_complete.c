/* test_pd_complete.c - Unit tests for the T3 load-path stall fix
 * (: streaming-completion stall when sse_active never flips under TCP
 * fragmentation). Exercises the PURE windowed detector pd_scan_msg_end_window()
 * in sockproxy_pd_leak.h.
 *
 * Build: gcc -Wall -Wextra -fsanitize=address -o test_pd_complete \
 *        test_pd_complete.c -I. -DTEST_PD_COMPLETE
 *
 * Idiom mirrors test_pd_leak.c: assert() per case, "ALL PASS" at the end, exit 0
 * on success / nonzero (assert abort) on failure.
 *
 * The regression these guard: scanned only the CURRENT packet,
 * so a message-end terminator split across two reads was missed. On the
 * sse_active==0 path (fragmented Content-Type under load) that is the
 * ONLY decode completion detector, so the missed terminator stranded the decode
 * leg forever (~50% of high-rate points at conc=64 were watchdog-reaped).
 * pd_scan_msg_end_window() keeps a sliding tail so the straddling terminator is
 * detected on the read that completes it. Each split-terminator case also asserts
 * the OLD single-packet pd_detect_http_msg_end() would have MISSED it, pinning
 * the window as the thing that fixes the bug.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The header defines pd_teardown_legs() as a static inline that dereferences
 * struct proxy_fd_ent, so the TU must supply a complete struct (we don't call it
 * here — pd_scan_msg_end_window/pd_detect_http_msg_end take no struct). Mirrors
 * the test_pd_leak.c / test_pd_cache_aware.c fake-ent precedent. */
#define SOCKPROXY_PD_LEAK_FAKE_ENT
struct proxy_fd_ent {
  int fd;
  int rfd[8];
  int n_rfd;
};

#include "sockproxy_pd_leak.h"
#include "sockproxy_resp_note.h"
#include <pthread.h>

/* A per-"connection" sliding-tail fixture, mirroring the proxy_fd_ent.sse_tail /
 * .sse_tail_len fields the production call site rides on. Zero-initialised =
 * the fresh-connection state (tail_len == 0). */
struct tail_state {
  uint8_t tail[PD_MSG_END_TAIL_KEEP];
  uint8_t tail_len;
};

static int
scan(struct tail_state *ts, const char *pkt)
{
  return pd_scan_msg_end_window(ts->tail, &ts->tail_len,
                                (const uint8_t *)pkt, strlen(pkt));
}

/* The response-record latch (proxy_note_client_response): one record per
 * request whichever site reaches it first (the decode capture or a prefill-leg
 * answer); every later call for that request is a no-op; the next request on
 * the connection records again. */
static uint8_t race_latch;
static int race_wins;

static void *
race_claim(void *arg)
{
  (void)arg;
  if (resp_note_claim(&race_latch)) __atomic_fetch_add(&race_wins, 1, __ATOMIC_RELAXED);
  return NULL;
}

static void
test_resp_note_latch(void)
{
  uint8_t noted = 0;   /* pfe_alloc zeroes the field: the latch starts open */

  assert(resp_note_claim(&noted) == 1 && "first site records");
  assert(resp_note_claim(&noted) == 0 && "second site for the same request is a no-op");
  assert(resp_note_claim(&noted) == 0);
  resp_note_rearm(&noted);   /* next request on the kept-alive connection */
  assert(resp_note_claim(&noted) == 1 && "re-armed per request");
  assert(resp_note_claim(&noted) == 0);

  /* the two sites run on different workers: exactly one wins a race */
  for (int round = 0; round < 200; round++) {
    pthread_t th[8];
    race_latch = 0;
    race_wins = 0;
    for (int i = 0; i < 8; i++) assert(pthread_create(&th[i], NULL, race_claim, NULL) == 0);
    for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
    assert(race_wins == 1 && "exactly one record per request under a race");
  }

  assert(resp_status_class(0) == 0 && resp_status_class(100) == 0 && resp_status_class(199) == 0);
  assert(resp_status_class(200) == 2 && resp_status_class(299) == 2);
  assert(resp_status_class(302) == 3 && resp_status_class(404) == 4 && resp_status_class(429) == 4);
  assert(resp_status_class(500) == 5 && resp_status_class(599) == 5 && resp_status_class(600) == 0);
  printf("  [PASS] resp_note latch: once per request, no-op after, re-armed, one winner in a race\n");
}

/* The two wrappers over the one writer (proxy_note_client_response = take
 * with a TTFB sample, proxy_note_local_answer = take without) share the
 * latch: whichever answer the client got first is the request's record. */
static void
test_resp_note_take_local_and_backend(void)
{
  uint8_t noted = 0;

  /* a refusal: status and class, no TTFB sample */
  assert(resp_note_take(&noted, 0) == RESP_NOTE_COUNT);
  /* a backend reply racing it for the same request records nothing */
  assert(resp_note_take(&noted, 1) == 0 && "a local answer then a backend reply records once");
  assert(resp_note_take(&noted, 0) == 0);

  /* next request: a backend reply samples TTFB, a late local answer is a no-op */
  resp_note_rearm(&noted);
  assert(resp_note_take(&noted, 1) == (RESP_NOTE_COUNT | RESP_NOTE_TTFB));
  assert(resp_note_take(&noted, 0) == 0 && "a backend reply then a local answer records once");

  /* the streamed gate's re-arm while the previous record is still owed
   * changes nothing: the latch already reads open */
  noted = 0;
  resp_note_rearm(&noted);
  assert(resp_note_take(&noted, 0) == RESP_NOTE_COUNT);
  printf("  [PASS] resp_note take: a local answer and a backend reply share one record; TTFB only for the backend reply\n");
}

/* The status-line sniff of the backend capture records an answer only. A
 * backend's own interim "100 Continue" (the gateway forwarded Expect) used to
 * take the latch: no class (1xx has none), the TTFB sample at the 100, and the
 * 200 or 5xx behind it a latched no-op, so the answer was never counted
 * (F-21). The framer decides by the same predicate. */
static void
test_resp_sniff_status_line(void)
{
  uint16_t st = 0;
  uint8_t noted = 0;
  const char ok200[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
  const char cont100[] = "HTTP/1.1 100 Continue\r\n\r\n";
  const char sw101[] = "HTTP/1.1 101 Switching Protocols\r\n\r\n";
  const char hints103[] = "HTTP/1.1 103 Early Hints\r\nLink: </s>\r\n\r\n";
  const char err500[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
  const char short200[] = "HTTP/1.1 200";                 /* 12 bytes: a cut */
  const char bad6[] = "HTTP/1.1 6ab Nope\r\n\r\n";
  const char bad0[] = "HTTP/1.1 099 Nope\r\n\r\n";
  const char badalpha[] = "HTTP/1.1 2x0 Nope\r\n\r\n";
  const char notresp[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";

  assert(resp_status_is_answer(200) && resp_status_is_answer(299) && resp_status_is_answer(500));
  assert(resp_status_is_answer(101) && "101 ends HTTP on the connection: it answers");
  assert(!resp_status_is_answer(100) && !resp_status_is_answer(102) && !resp_status_is_answer(103));
  assert(!resp_status_is_answer(0) && !resp_status_is_answer(199));

  assert(resp_sniff_status_line(ok200, sizeof(ok200) - 1, &st) == 1 && st == 200);
  st = 0;
  assert(resp_sniff_status_line(err500, sizeof(err500) - 1, &st) == 1 && st == 500);
  st = 0;
  assert(resp_sniff_status_line(sw101, sizeof(sw101) - 1, &st) == 1 && st == 101);
  st = 0;
  assert(resp_sniff_status_line(cont100, sizeof(cont100) - 1, &st) == 0 && st == 0 &&
         "a backend's 100 Continue is not the answer");
  assert(resp_sniff_status_line(hints103, sizeof(hints103) - 1, &st) == 0 && st == 0);
  assert(resp_sniff_status_line(short200, sizeof(short200) - 1, &st) == 0 && st == 0 &&
         "12 bytes is a cut status line: the framer records it");
  assert(resp_sniff_status_line(ok200, 13, &st) == 1 && st == 200 && "13 bytes carry the three digits");
  st = 0;
  assert(resp_sniff_status_line(bad6, sizeof(bad6) - 1, &st) == 0 && st == 0);
  assert(resp_sniff_status_line(bad0, sizeof(bad0) - 1, &st) == 0 && st == 0);
  assert(resp_sniff_status_line(badalpha, sizeof(badalpha) - 1, &st) == 0 && st == 0);
  assert(resp_sniff_status_line(notresp, sizeof(notresp) - 1, &st) == 0 && st == 0);

  /* the sequence the bug was: the backend's 100, then its 200, against one
   * latch. The 100 is skipped, the latch stays open, the 200 takes it with a
   * TTFB sample; a second record for the request is a no-op. */
  assert(resp_sniff_status_line(cont100, sizeof(cont100) - 1, &st) == 0);
  assert(resp_sniff_status_line(ok200, sizeof(ok200) - 1, &st) == 1 && st == 200);
  assert(resp_note_take(&noted, 1) == (RESP_NOTE_COUNT | RESP_NOTE_TTFB) &&
         "the answer behind a backend 100 takes the record");
  assert(resp_status_class(st) == 2);
  assert(resp_note_take(&noted, 1) == 0);
  printf("  [PASS] resp_sniff_status_line: an answer only; a backend 100 Continue leaves the latch to the answer\n");
}

/* ---- Case 1: terminator wholly inside one packet still completes ---- */
static void
test_done_whole_packet(void)
{
  struct tail_state ts = {{0}, 0};
  assert(scan(&ts, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n") == 0);
  assert(scan(&ts, "data: [DONE]\n\n") != 0 &&
         "whole-packet data: [DONE] must complete");
  printf("  [PASS] whole-packet data: [DONE] -> complete\n");
}

/* ---- Case 2 (THE regression): [DONE] split across two reads ---- */
static void
test_done_split_across_reads(void)
{
  struct tail_state ts = {{0}, 0};

  /* The single-packet detector sees nothing in packet 1 ... */
  assert(pd_detect_http_msg_end((const uint8_t *)"id: 1\ndata: [DO", 14) == 0);
  assert(scan(&ts, "id: 1\ndata: [DO") == 0 &&
         "partial terminator must NOT complete");

  /* ... and STILL nothing in packet 2 ALONE (this is what missed)... */
  assert(pd_detect_http_msg_end((const uint8_t *)"NE]\n\n", 5) == 0);

  /* ... but the windowed scan, carrying the tail from packet 1, completes. */
  assert(scan(&ts, "NE]\n\n") != 0 &&
         "split data: [DONE] across two reads must complete via the sliding tail");
  printf("  [PASS] split data: [DONE] across two reads -> complete (sliding tail)\n");
}

/* ---- Case 3: chunked last-chunk "0\r\n\r\n" split across two reads ---- */
static void
test_chunked_terminator_split(void)
{
  struct tail_state ts = {{0}, 0};

  assert(pd_detect_http_msg_end((const uint8_t *)"5\r\nhello\r\n0\r", 12) == 0);
  assert(scan(&ts, "5\r\nhello\r\n0\r") == 0 &&
         "partial chunk terminator must NOT complete");

  assert(pd_detect_http_msg_end((const uint8_t *)"\n\r\n", 3) == 0);
  assert(scan(&ts, "\n\r\n") != 0 &&
         "split chunked 0\\r\\n\\r\\n must complete via the sliding tail");
  printf("  [PASS] split chunked 0\\r\\n\\r\\n across two reads -> complete\n");
}

/* ---- Case 4: a long stream of data with NO terminator never false-completes ---- */
static void
test_no_terminator_no_completion(void)
{
  struct tail_state ts = {{0}, 0};
  for (int i = 0; i < 50; i++) {
    assert(scan(&ts, "data: {\"choices\":[{\"delta\":{\"content\":\"tok\"}}]}\n\n") == 0 &&
           "data chunks without a terminator must never complete");
  }
  printf("  [PASS] 50 data chunks, no terminator -> no false completion\n");
}

/* ---- Case 5: the Bug-A scenario end to end (sse_active never set) ----
 * Read 1 = status line + a header that is NOT "Content-Type: text/event-stream"
 * (so the :1157 sniff would never flip sse_active), the body arrives in
 * fragments, and the [DONE] terminator straddles the final two reads. The
 * windowed detector — the only completion path on the sse_active==0 branch —
 * must still complete. */
static void
test_bug_a_fragmented_no_content_type(void)
{
  struct tail_state ts = {{0}, 0};

  /* read 1: status line + chunked header; Content-Type fragmented to a later seg */
  assert(scan(&ts, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n") == 0);
  /* read 2: rest of headers — Content-Type lands here, AFTER the sniff window */
  assert(scan(&ts, "Content-Type: text/event-stream\r\n\r\n") == 0);
  /* reads 3..N: streamed tokens */
  assert(scan(&ts, "data: {\"delta\":\"a\"}\n\n") == 0);
  assert(scan(&ts, "data: {\"delta\":\"b\"}\n\n") == 0);
  /* final terminator split across the last two reads */
  assert(scan(&ts, "data: [DON") == 0);
  assert(scan(&ts, "E]\n\n") != 0 &&
         "completion must fire on the sse_active==0 path even with a "
         "fragmented Content-Type and a split terminator");
  printf("  [PASS] Bug-A fragmented Content-Type + split [DONE] -> complete\n");
}

/* --- (RESOLVED) graceful-[DONE] safety-net predicate ----
 * pd_should_graceful_complete() decides whether a decode-streaming SSE connection
 * whose backend leg went silent (vLLM dropped its closing "data: [DONE]") should
 * be force-completed with a synthesized terminator. The load-bearing property is
 * that the decision is gated on the LAST-BACKEND-BYTE timestamp, NOT
 * wall-clock-since-start — so a slow-but-still-streaming response is never
 * truncated. The helper does not even take a stream-start argument, which is the
 * structural guarantee. */

/* A synthetic "now"; absolute value is irrelevant, only deltas matter. */
#define NOW ((time_t)1000000)
#define CAP 25u

/* ---- Case 6: backend idle past the cap -> reap (graceful complete) ---- */
static void
test_graceful_idle_reaped(void)
{
  /* decode streaming, sse active, not yet terminated, last byte 30s ago, cap 25s */
  assert(pd_should_graceful_complete(1, 1, 0, NOW - 30, NOW, CAP) != 0 &&
         "30s backend-idle (> 25s cap) must reap");
  /* exact boundary: now - last == cap -> reap (>=) */
  assert(pd_should_graceful_complete(1, 1, 0, NOW - (time_t)CAP, NOW, CAP) != 0 &&
         "idle exactly at cap must reap (>=)");
  printf("  [PASS] backend-idle past cap -> graceful complete\n");
}

/* ---- Case 7 (THE truncation guard): slow-but-streaming is NOT reaped ----
 * A long-running generation that emitted a token 5s ago must survive, even though
 * the stream started long ago — proven by the helper carrying no start time at
 * all and gating purely on last_decode_ts. */
static void
test_graceful_slow_stream_not_reaped(void)
{
  assert(pd_should_graceful_complete(1, 1, 0, NOW - 5, NOW, CAP) == 0 &&
         "a stream that relayed a byte 5s ago must NOT be reaped");
  /* just under the boundary */
  assert(pd_should_graceful_complete(1, 1, 0, NOW - ((time_t)CAP - 1), NOW, CAP) == 0 &&
         "idle one second under cap must NOT reap");
  printf("  [PASS] slow-but-streaming (recent backend byte) -> not reaped\n");
}

/* ---- Case 8: all the guards individually suppress the reap ---- */
static void
test_graceful_guards(void)
{
  /* not in decode-streaming phase */
  assert(pd_should_graceful_complete(0, 1, 0, NOW - 30, NOW, CAP) == 0 &&
         "non-decode-streaming phase must not reap");
  /* not an SSE stream (would inject [DONE] into a non-SSE body) */
  assert(pd_should_graceful_complete(1, 0, 0, NOW - 30, NOW, CAP) == 0 &&
         "non-SSE stream must not get a synthesized [DONE]");
  /* the real [DONE] already arrived (stream_end_ts set) */
  assert(pd_should_graceful_complete(1, 1, NOW - 1, NOW - 30, NOW, CAP) == 0 &&
         "already-terminated stream must not be re-completed");
  /* no backend byte ever relayed -> no meaningful idle clock */
  assert(pd_should_graceful_complete(1, 1, 0, 0, NOW, CAP) == 0 &&
         "last_decode_ts==0 must not reap");
  /* safety-net disabled */
  assert(pd_should_graceful_complete(1, 1, 0, NOW - 30, NOW, 0u) == 0 &&
         "cap==0 disables the safety-net");
  printf("  [PASS] guards (phase/sse/terminated/no-byte/disabled) all suppress\n");
}

/* ---- Case 9: pd_http_resp_status — the origin-feed status glance ----
 * The vLLM sequential machine swallows the prefill response (a 5xx degrades
 * to decode-recompute), so the breaker's origin-error feed reads the status
 * straight off the accumulated response buffer with this parser. Malformed /
 * truncated / non-HTTP buffers must yield 0 ("status unknown" — fed as
 * NEITHER error nor success), never a fabricated code. */
static void
test_http_resp_status(void)
{
  static const char ok200[]  = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
  static const char err500[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
  static const char err503[] = "HTTP/1.0 503 Service Unavailable\r\n\r\n";
  static const char cli400[] = "HTTP/1.1 400 Bad Request\r\n\r\n";

  assert(pd_http_resp_status((const uint8_t *)ok200, sizeof(ok200) - 1) == 200);
  assert(pd_http_resp_status((const uint8_t *)err500, sizeof(err500) - 1) == 500);
  assert(pd_http_resp_status((const uint8_t *)err503, sizeof(err503) - 1) == 503);
  assert(pd_http_resp_status((const uint8_t *)cli400, sizeof(cli400) - 1) == 400);

  /* status line truncated mid-code: too short to trust */
  assert(pd_http_resp_status((const uint8_t *)"HTTP/1.1 50", 11) == 0 &&
         "truncated status line must be status-unknown");
  /* not an HTTP response at all (e.g. a raw JSON error body) */
  assert(pd_http_resp_status((const uint8_t *)"{\"error\":1}", 11) == 0 &&
         "non-HTTP buffer must be status-unknown");
  /* non-digit where the code belongs */
  assert(pd_http_resp_status((const uint8_t *)"HTTP/1.1 OK 200\r\n", 17) == 0 &&
         "non-numeric code must be status-unknown");
  /* out-of-range 3-digit code */
  assert(pd_http_resp_status((const uint8_t *)"HTTP/1.1 999 Nope\r\n", 19) == 0 &&
         "out-of-range code must be status-unknown");
  /* NULL / empty */
  assert(pd_http_resp_status(NULL, 64) == 0);
  assert(pd_http_resp_status((const uint8_t *)"", 0) == 0);
  printf("  [PASS] pd_http_resp_status: codes parsed, malformed -> unknown\n");
}

/* pd_resp_error_excerpt: the engine's error string for the relay's log line,
 * from either vLLM error shape, else the body's leading bytes; bounded, and
 * one log line whatever the body holds. */
static void
test_resp_error_excerpt(void)
{
  char out[64];
  static const char flat[] =
      "HTTP/1.1 404 Not Found\r\ncontent-type: application/json\r\n\r\n"
      "{\"object\":\"error\",\"message\":\"The model `mon03-alias` does not exist.\","
      "\"type\":\"NotFoundError\",\"param\":null,\"code\":404}";
  static const char nested[] =
      "HTTP/1.1 400 Bad Request\r\n\r\n"
      "{\"error\": {\"message\" : \"max_tokens \\\"1\\\" invalid\", \"code\": 400}}";
  static const char plain[] = "HTTP/1.1 413 Payload Too Large\r\n\r\ntoo\r\nlarge";
  static const char nobody[] = "HTTP/1.1 404 Not Found\r\ncontent-length: 0";

  assert(pd_resp_error_excerpt((const uint8_t *)flat, sizeof(flat) - 1, out, sizeof(out)) > 0);
  assert(strcmp(out, "The model `mon03-alias` does not exist.") == 0);
  pd_resp_error_excerpt((const uint8_t *)nested, sizeof(nested) - 1, out, sizeof(out));
  assert(strcmp(out, "max_tokens \\\"1\\\" invalid") == 0 && "an escaped quote does not end it");
  pd_resp_error_excerpt((const uint8_t *)plain, sizeof(plain) - 1, out, sizeof(out));
  assert(strcmp(out, "too..large") == 0 && "no message key: the body, control bytes masked");
  assert(pd_resp_error_excerpt((const uint8_t *)nobody, sizeof(nobody) - 1, out, sizeof(out)) == 0 &&
         out[0] == '\0');
  assert(pd_resp_error_excerpt(NULL, 0, out, sizeof(out)) == 0 && out[0] == '\0');
  {
    char small[8];
    assert(pd_resp_error_excerpt((const uint8_t *)flat, sizeof(flat) - 1, small, sizeof(small)) == 7);
    assert(strcmp(small, "The mod") == 0 && "bounded by cap");
    /* bounded by len: the message is cut where the buffer ends */
    size_t cut = (size_t)(strstr(flat, "does") - flat);
    pd_resp_error_excerpt((const uint8_t *)flat, cut, out, sizeof(out));
    assert(strcmp(out, "The model `mon03-alias` ") == 0);
  }
  printf("  [PASS] pd_resp_error_excerpt: message of either shape, else body; bounded\n");
}

/* pd_prefill_status_verdict: an origin 4xx prefill reply is relayed and
 * decode is not called, cut at the buffer cap or not (F-12); a 5xx, a 408
 * and a 429 keep the decode-recompute degradation; an unknown status is
 * neither. pd_prefill_cut_reject is what a cut 4xx is relayed as. */
static void
test_prefill_status_verdict(void)
{
  assert(pd_prefill_status_verdict(0)   == PD_PR_DECODE && "unknown -> decode");
  assert(pd_prefill_status_verdict(200) == PD_PR_DECODE);
  assert(pd_prefill_status_verdict(204) == PD_PR_DECODE);
  assert(pd_prefill_status_verdict(301) == PD_PR_DECODE);
  assert(pd_prefill_status_verdict(399) == PD_PR_DECODE);
  assert(pd_prefill_status_verdict(400) == PD_PR_RELAY);
  assert(pd_prefill_status_verdict(404) == PD_PR_RELAY && "unknown model is a reject");
  assert(pd_prefill_status_verdict(408) == PD_PR_DECODE && "engine timeout is transient");
  assert(pd_prefill_status_verdict(409) == PD_PR_RELAY);
  assert(pd_prefill_status_verdict(413) == PD_PR_RELAY);
  assert(pd_prefill_status_verdict(422) == PD_PR_RELAY);
  assert(pd_prefill_status_verdict(429) == PD_PR_DECODE && "engine backpressure is transient");
  assert(pd_prefill_status_verdict(499) == PD_PR_RELAY);
  {
    /* a cut 4xx: the engine's status, the gateway's body, framed by length */
    char out[384];
    size_t n = pd_prefill_cut_reject(404, out, sizeof(out));
    const char *body;
    assert(n > 0 && n == strlen(out));
    assert(strncmp(out, "HTTP/1.1 404 Not Found\r\n", 24) == 0);
    body = strstr(out, "\r\n\r\n");
    assert(body && strstr(out, "Content-Length: ") &&
           (size_t)atoi(strstr(out, "Content-Length: ") + 16) == strlen(body + 4));
    assert(strstr(body, "\"error\":\"prefill_rejected\",\"status\":404"));
    assert(pd_prefill_cut_reject(499, out, sizeof(out)) > 0 &&
           strncmp(out, "HTTP/1.1 499 Client Error\r\n", 27) == 0);
    assert(pd_prefill_cut_reject(404, out, 40) == 0 && "no room: nothing");
  }
  assert(pd_prefill_status_verdict(500) == PD_PR_DECODE && "5xx keeps decode recompute");
  assert(pd_prefill_status_verdict(503) == PD_PR_DECODE);
  assert(pd_prefill_status_verdict(599) == PD_PR_DECODE);
  /* composed with the parser, as pd_initiate_decode uses them */
  {
    static const char nf404[] = "HTTP/1.1 404 Not Found\r\ncontent-length: 2\r\n\r\n{}";
    static const char ok200[] = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";
    assert(pd_prefill_status_verdict(
               pd_http_resp_status((const uint8_t *)nf404, sizeof(nf404) - 1)) == PD_PR_RELAY);
    assert(pd_prefill_status_verdict(
               pd_http_resp_status((const uint8_t *)ok200, sizeof(ok200) - 1)) == PD_PR_DECODE);
    assert(pd_prefill_status_verdict(
               pd_http_resp_status((const uint8_t *)"HTTP/1.1 40", 11)) == PD_PR_DECODE &&
           "an unparsable status line is unknown, not a reject");
  }
  printf("  [PASS] pd_prefill_status_verdict: 4xx relay (cut: by status, gateway body), 5xx/408/429/unknown decode\n");
}

/* pd_decode_error_phase: a completed decode leg is recorded by the status its
 * client received. An unread status is its own outcome (7), never a success. */
static void
test_decode_error_phase(void)
{
  static const struct { int status, phase; } cases[] = {
    {   0, 7 }, { 100, 7 }, { 199, 7 },            /* no final status line read */
    { 200, 0 }, { 204, 0 }, { 301, 0 }, { 399, 0 }, /* complete / success */
    { 400, 6 }, { 404, 6 }, { 429, 6 }, { 499, 6 }, /* decode / rejected */
    { 500, 2 }, { 502, 2 }, { 503, 2 }, { 599, 2 }, /* decode / error */
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    if (pd_decode_error_phase(cases[i].status) != cases[i].phase) {
      fprintf(stderr, "pd_decode_error_phase(%d) = %d, want %d\n", cases[i].status,
              pd_decode_error_phase(cases[i].status), cases[i].phase);
      assert(0);
    }
  }
  /* composed with the parser: a status line too short to read is unknown */
  assert(pd_decode_error_phase(pd_http_resp_status((const uint8_t *)"HTTP/1.1 5", 10)) == 7);
  printf("  [PASS] pd_decode_error_phase: 2xx/3xx 0, 4xx 6, 5xx 2, unread 7\n");
}

/* pd_prefill_fallback_reason: the condition that forced the fallback, in
 * verdict order. The status is the reason when it alone forces decode, cut or
 * not; a reply that would have been used is truncated only because it was
 * cut (a cut 4xx is relayed, never a fallback); a reply that is no status at all is no_status; 1xx/3xx other. */
static void
test_prefill_fallback_reason(void)
{
  static const struct { int status, cut, reason; } cases[] = {
    { 500, 0, PD_FB_ORIGIN_5XX }, { 503, 1, PD_FB_ORIGIN_5XX }, { 599, 0, PD_FB_ORIGIN_5XX },
    { 408, 0, PD_FB_ORIGIN_408 }, { 408, 1, PD_FB_ORIGIN_408 },
    { 429, 0, PD_FB_ORIGIN_429 }, { 429, 1, PD_FB_ORIGIN_429 },
    {   0, 0, PD_FB_NO_STATUS },  {   0, 1, PD_FB_NO_STATUS },
    { 100, 0, PD_FB_OTHER },      { 301, 0, PD_FB_OTHER },      { 304, 1, PD_FB_OTHER },
    { 200, 1, PD_FB_TRUNCATED },  { 204, 1, PD_FB_TRUNCATED },
    { 200, 0, PD_FB_NONE },       { 204, 0, PD_FB_NONE },
    { 404, 0, PD_FB_NONE },       /* relayed: never reaches the decode leg */
    { 404, 1, PD_FB_NONE },       { 422, 1, PD_FB_NONE },  /* relayed by status (F-12) */
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int got = pd_prefill_fallback_reason(cases[i].status, cases[i].cut);
    if (got != cases[i].reason) {
      fprintf(stderr, "pd_prefill_fallback_reason(%d, cut=%d) = %d, want %d\n",
              cases[i].status, cases[i].cut, got, cases[i].reason);
      assert(0);
    }
    /* a reason exactly when the verdict sends the reply to decode and the
     * reply was not a clean 2xx */
    int to_decode = pd_prefill_status_verdict(cases[i].status) == PD_PR_DECODE;
    int clean = cases[i].status >= 200 && cases[i].status < 300 && !cases[i].cut;
    assert((got != PD_FB_NONE) == (to_decode && !clean));
  }
  printf("  [PASS] pd_prefill_fallback_reason: status first (5xx/408/429/none/other), truncated only for a cut 2xx\n");
}

/* pd_reap_error_phase: a request a reaper ends is named by the phase it was
 * in; a begun answer the gateway ended is decode/truncated, never the engine's
 * death (2); anything not in flight has no record to make, which is what keeps
 * the record to one once the reaper moves the request to ERROR. */
static void
test_reap_error_phase(void)
{
  static const struct { int pd_phase, phase; } cases[] = {
    { 0, -1 },                         /* NONE: not a P/D request */
    { 1, 1 }, { 2, 1 }, { 3, 1 },      /* prefill legs: prefill / timeout */
    { 4, 3 },                          /* decode dispatched, no byte: decode / timeout */
    { 5, 8 },                          /* the answer began: decode / truncated */
    { 6, -1 }, { 7, -1 }, { 8, -1 },   /* COMPLETE, ERROR, PARKED */
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    if (pd_reap_error_phase(cases[i].pd_phase) != cases[i].phase) {
      fprintf(stderr, "pd_reap_error_phase(%d) = %d, want %d\n", cases[i].pd_phase,
              pd_reap_error_phase(cases[i].pd_phase), cases[i].phase);
      assert(0);
    }
  }
  printf("  [PASS] pd_reap_error_phase: prefill 1, decode-sending 3, streaming 8, else none\n");
}

int
main(void)
{
  printf("test_pd_complete: load-path (windowed completion + graceful [DONE])\n");
  test_resp_note_latch();
  test_resp_note_take_local_and_backend();
  test_resp_sniff_status_line();
  test_done_whole_packet();
  test_done_split_across_reads();
  test_chunked_terminator_split();
  test_no_terminator_no_completion();
  test_bug_a_fragmented_no_content_type();
  test_graceful_idle_reaped();
  test_graceful_slow_stream_not_reaped();
  test_graceful_guards();
  test_http_resp_status();
  test_resp_error_excerpt();
  test_prefill_status_verdict();
  test_decode_error_phase();
  test_reap_error_phase();
  test_prefill_fallback_reason();
  printf("ALL PASS (test_pd_complete)\n");
  return 0;
}
