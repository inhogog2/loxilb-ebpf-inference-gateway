/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
/*
 * test_llmd.c - the llm-d headers of the capacity gate: the TTL a client
 * asks for (Go duration syntax), the dropped-reason of a refusal, and the
 * objective and fairness identity that leave for the backend.
 *
 *   make test_llmd
 *
 * Every buffer that is edited is a heap buffer of the exact size the edit
 * may use, so the sanitizers see a byte written outside it.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define log_error(...) ((void)0)
#include "sockproxy_l7hdr_guard.h"
#include "sockproxy_h1_hdr.h"
#include "sockproxy_obj_hint.h"
#include "sockproxy_llmd_fwd.h"
#include "sockproxy_native_prio.h"

static int failures = 0;
static int checks   = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { failures++; printf("  FAIL "); printf(__VA_ARGS__); printf("\n"); } \
    else { printf("  ok   "); printf(__VA_ARGS__); printf("\n"); } \
  } while (0)

static uint32_t
ttl(const char *s)
{
  uint32_t ms = 0;

  return sp_llmd_parse_ttl_ms(s, strlen(s), &ms) ? ms : 0;
}

static void
test_parse(void)
{
  CHECK(ttl("500ms") == 500, "500ms is 500");
  CHECK(ttl("2s") == 2000, "2s is 2000");
  CHECK(ttl("1m30s") == 90000, "1m30s is 90000");
  CHECK(ttl("1.5s") == 1500, "1.5s is 1500");
  CHECK(ttl("0.25s") == 250, "0.25s is 250");
  CHECK(ttl("1h") == 3600000, "1h is 3600000");
  CHECK(ttl("1h2m3s4ms") == 3723004, "1h2m3s4ms adds up");
  CHECK(ttl("2500us") == 3, "2500us rounds up to 3 ms");
  CHECK(ttl("1ns") == 1, "1ns is at least 1 ms");
  CHECK(ttl("1\xc2\xb5s") == 1, "1 microsign s is 1 ms");
  CHECK(ttl("100h") == 86400000, "a TTL over a day is held at a day");
  CHECK(ttl("0") == 0, "0 is no TTL");
  CHECK(ttl("0s") == 0, "0s is no TTL");
  CHECK(ttl("0.0ms") == 0, "0.0ms is no TTL");
  CHECK(ttl("") == 0, "empty is no TTL");
  CHECK(ttl("5") == 0, "a number without a unit is none");
  CHECK(ttl("-5s") == 0, "negative is none");
  CHECK(ttl("+5s") == 0, "a sign is none");
  CHECK(ttl("5 s") == 0, "a space is none");
  CHECK(ttl("5d") == 0, "an unknown unit is none");
  CHECK(ttl("s") == 0, "a unit alone is none");
  CHECK(ttl("1.s") == 1000, "1.s is Go syntax for 1s");
  CHECK(ttl(".5s") == 500, ".5s is Go syntax for 500ms");
  CHECK(ttl("5s5") == 0, "a trailing number is none");
  CHECK(ttl("99999999999999999999999999999999999999h") == 0, "overflow is none, not wrapped");
  CHECK(ttl("340282366920938463463374607432s") == 0, "a total past 128 bits is none, not wrapped");
  CHECK(ttl("2562047h") == 86400000, "the longest whole hours Go holds: held at one day");
  CHECK(ttl("2562048h") == 0, "past Go's range (2^63 - 1 ns) is none");
  CHECK(ttl("2562047h47m16.854775807s") == 86400000, "Go's longest duration exactly: held at one day");
  CHECK(ttl("2562047h47m16.854775808s") == 0, "one nanosecond past it is none");
}

static void
feed(sp_ttl_hint_t *h, const char *name, const char *v, size_t cut)
{
  /* One header whose value arrives in two fragments cut at `cut`. */
  sp_ttl_hint_name(h);
  if (sp_ttl_hint_which(name, strlen(name))) {
    size_t n = strlen(v);

    if (cut == 0 || cut >= n) {
      sp_ttl_hint_val(h, v, n);
    } else {
      sp_ttl_hint_val(h, v, cut);
      sp_ttl_hint_val(h, v + cut, n - cut);
    }
  }
}

static void
test_hint(void)
{
  sp_ttl_hint_t h;

  sp_ttl_hint_reset(&h);
  CHECK(sp_ttl_hint_ms(&h) == 0, "no header, no TTL");
  feed(&h, "X-Llm-D-Inference-TTL", "2s", 0);
  CHECK(sp_ttl_hint_ms(&h) == 2000, "the name is compared without case");
  feed(&h, "x-llm-d-inference-ttl", "1500ms", 3);
  CHECK(sp_ttl_hint_ms(&h) == 1500, "a repeated header is last-one-wins; a split value is whole");
  feed(&h, "x-llm-d-inference-ttl-extra", "1s", 0);
  CHECK(sp_ttl_hint_ms(&h) == 1500, "a longer name is not the header");
  feed(&h, "x-other", "9s", 0);
  CHECK(sp_ttl_hint_ms(&h) == 1500, "another header does not disturb it");
  feed(&h, "x-llm-d-inference-ttl", "not-a-duration", 0);
  CHECK(sp_ttl_hint_ms(&h) == 0, "a value that is not a duration is no TTL");
  {
    char big[200];

    memset(big, '9', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    feed(&h, "x-llm-d-inference-ttl", big, 7);
    CHECK(sp_ttl_hint_ms(&h) == 0, "a value longer than any duration is no TTL");
  }
  feed(&h, "x-llm-d-inference-ttl", "3s", 0);
  CHECK(sp_ttl_hint_ms(&h) == 3000, "the next valid header recovers");
  sp_ttl_hint_reset(&h);
  CHECK(sp_ttl_hint_ms(&h) == 0, "the keep-alive boundary clears it");
}

static void
test_reason(void)
{
  CHECK(!strcmp(sp_llmd_reason_of("admission_capacity"), "rejected-saturated"), "capacity");
  CHECK(!strcmp(sp_llmd_reason_of("admission_shed"), "rejected-saturated"), "shed");
  CHECK(!strcmp(sp_llmd_reason_of("admission_tenant_share"), "rejected-saturated"), "tenant share");
  CHECK(!strcmp(sp_llmd_reason_of("admission_queue_timeout"), "rejected-ttl-expired"), "queue timeout");
  CHECK(!strcmp(sp_llmd_reason_of("admission_ttl_expired"), "rejected-ttl-expired"), "client ttl");
  CHECK(!strcmp(sp_llmd_reason_of("admission_no_capacity"), "rejected-no-endpoints"), "no capacity");
  CHECK(!strcmp(sp_llmd_reason_of("gateway_draining"), "rejected-shutting-down"), "draining");
  CHECK(!strcmp(sp_llmd_reason_of("admission_drained"), "rejected-shutting-down"), "drained");
  CHECK(sp_llmd_reason_of("objective_not_allowed") == NULL, "a policy refusal is not ours to map");
  CHECK(sp_llmd_reason_of(NULL) == NULL, "none");
}

/* The request head in a heap buffer of exactly the room the edit may use. */
static uint8_t *
head(const char *text, size_t room, size_t *len)
{
  uint8_t *b = malloc(room);

  *len = strlen(text);
  memcpy(b, text, *len);
  return b;
}

static void
test_rewrite(void)
{
  const char *req =
    "POST /v1/chat/completions HTTP/1.1\r\n"
    "Host: gw\r\n"
    "X-Llm-D-Inference-Objective: spoofed\r\n"
    "x-gateway-inference-objective: spoofed-old\r\n"
    "X-Llm-D-Inference-Fairness-Id: someone-else\r\n"
    "x-gateway-inference-fairness-id: someone-else-old\r\n"
    "Content-Length: 2\r\n"
    "\r\n{}";
  const char *want =
    "POST /v1/chat/completions HTTP/1.1\r\n"
    "Host: gw\r\n"
    "Content-Length: 2\r\n"
    "x-llm-d-inference-objective: critical\r\n"
    "x-llm-d-inference-fairness-id: tenant-a\r\n"
    "\r\n{}";
  size_t len, room;
  uint8_t *b;

  /* The room is exactly the result: a byte written past it is the
   * sanitizer's to see. (The splice keeps one byte in hand.) */
  room = strlen(want) + 1;
  b = head(req, room > strlen(req) ? room : strlen(req) + 1, &len);
  CHECK(sp_llmd_rewrite_head(b, &len, room > strlen(req) ? room : strlen(req) + 1,
                             "critical", "tenant-a", 1) == 0, "the rewrite succeeds");
  CHECK(len == strlen(want) && !memcmp(b, want, len),
        "the client's four copies are gone and the resolved two are written (got %.*s)", (int)len, b);
  free(b);

  /* Not at the gate: strip only. */
  b = head(req, strlen(req) + 1, &len);
  CHECK(sp_llmd_rewrite_head(b, &len, strlen(req) + 1, "critical", "tenant-a", 0) == 0 &&
        !memmem(b, len, "nference-objective", 18) && !memmem(b, len, "nference-fairness-id", 20) &&
        len < strlen(req), "off the gate: the client's copies go, nothing is written");
  free(b);

  /* A chunked request: the client's copies go, nothing is spliced. */
  {
    const char *ck =
      "POST /v1/chat/completions HTTP/1.1\r\n"
      "Transfer-Encoding: chunked\r\n"
      "x-llm-d-inference-objective: spoofed\r\n"
      "\r\n2\r\n{}\r\n0\r\n\r\n";
    b = head(ck, strlen(ck) + 1, &len);
    CHECK(sp_llmd_rewrite_head(b, &len, strlen(ck) + 1, "critical", "tenant-a", 1) == 0 &&
          !memmem(b, len, "x-llm-d", 7) && memmem(b, len, "\r\n2\r\n{}\r\n0\r\n\r\n", 14),
          "chunked: stripped, not spliced, the body after the head intact");
    free(b);
  }

  /* No tenant: the objective is written, no fairness identity is. */
  b = head("GET / HTTP/1.1\r\nHost: g\r\n\r\n", 256, &len);
  CHECK(sp_llmd_rewrite_head(b, &len, 256, "standard", NULL, 1) == 0 &&
        memmem(b, len, "x-llm-d-inference-objective: standard\r\n", 39) &&
        !memmem(b, len, "fairness", 8), "no tenant, no fairness identity");
  free(b);

  /* A head without its terminator is left as it was. */
  b = head("GET / HTTP/1.1\r\nHost: g\r\n", 64, &len);
  {
    size_t before = len;

    CHECK(sp_llmd_rewrite_head(b, &len, 64, "standard", "t", 1) == -1 && len == before,
          "an incomplete head is left alone");
  }
  free(b);
}

static void
test_native_prio(void)
{
  const char *req =
    "POST /v1/chat/completions HTTP/1.1\r\n"
    "Host: gw\r\n"
    "X-Vllm-Priority: -100\r\n"
    "Content-Type: application/json\r\n"
    "x-vllm-priority: 7\r\n"
    "Content-Length: 2\r\n"
    "\r\n{}";
  const char *want =
    "POST /v1/chat/completions HTTP/1.1\r\n"
    "Host: gw\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 2\r\n"
    "\r\n{}";
  const char *plain =
    "POST /v1/chat/completions HTTP/1.1\r\n"
    "Host: gw\r\n"
    "X-Vllm-Priority-Hint: 1\r\n"
    "Content-Length: 20\r\n"
    "\r\nX-Vllm-Priority: 1\r\n";
  size_t len, before;
  uint8_t *b;

  /* Every spelling of the header goes, the rest of the head and the body
   * stay byte for byte. */
  b = head(req, strlen(req) + 1, &len);
  CHECK(sp_native_prio_strip_head(b, &len) == 1, "a head with the header: stripped");
  CHECK(len == strlen(want) && !memcmp(b, want, len),
        "both spellings are gone, nothing else moved (got %.*s)", (int)len, b);
  CHECK(sp_native_prio_strip_head(b, &len) == 0 && len == strlen(want),
        "stripped again: nothing to do, the head as it was");
  free(b);

  /* Another name with the same prefix is not the header; a body line that
   * looks like it is body, not head. */
  b = head(plain, strlen(plain) + 1, &len);
  before = len;
  CHECK(sp_native_prio_strip_head(b, &len) == 0 && len == before &&
        !memcmp(b, plain, len), "a different name and a body line: untouched");
  free(b);

  /* No terminator in the buffer: refused, nothing written. */
  {
    const char *cut = "POST / HTTP/1.1\r\nX-Vllm-Priority: 1\r\n";
    b = head(cut, strlen(cut) + 1, &len);
  }
  before = len;
  CHECK(sp_native_prio_strip_head(b, &len) == -1 && len == before,
        "a head without its terminator is left as it was");
  free(b);

  CHECK(sizeof(SP_NATIVE_PRIO_RENAMED) == sizeof(SP_NATIVE_PRIO_BODY_KEY),
        "the renamed body key has the body key's length: the body keeps its size");
}

int
main(void)
{
  test_parse();
  test_hint();
  test_reason();
  test_rewrite();
  test_native_prio();
  printf("test_llmd: %d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
