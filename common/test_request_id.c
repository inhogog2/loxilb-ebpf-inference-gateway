/*
 * Unit tests for vLLM Request-ID generation and injection
 * Build: gcc -Wall -Wextra -o test_request_id test_request_id.c -I. -DTEST_REQUEST_ID
 * Run:   ./test_request_id
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

/* Minimal stubs for testing - xorshift64* PRNG */
static uint64_t test_rng_state = 0x123456789abcdef0ULL;

static uint64_t xorshift64star(uint64_t *state) {
  uint64_t x = *state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *state = x;
  return x * 0x2545F4914F6CDD1DULL;
}

static uint64_t lxb_gen_trace_id_part(void) {
  return xorshift64star(&test_rng_state);
}

/* Minimal proxy_fd_ent_t for testing */
typedef struct {
  char     vllm_request_id[256];
  uint8_t  has_vllm_request_id;
  uint8_t  request_id_injected;
} proxy_fd_ent_t;

/* ---- generate_vllm_request_id (copy for standalone testing) ---- */
static void
generate_vllm_request_id(proxy_fd_ent_t *pfe,
                         const char *prefill_ep,
                         const char *decode_ep)
{
  uint64_t hi, lo;

  hi = lxb_gen_trace_id_part();
  lo = lxb_gen_trace_id_part();

  /* Set UUID v4 version bits */
  hi = (hi & ~((uint64_t)0xF << 12)) | ((uint64_t)0x4 << 12);
  lo = (lo & ~((uint64_t)0x3 << 62)) | ((uint64_t)0x2 << 62);

  char uuid_buf[33];
  snprintf(uuid_buf, sizeof(uuid_buf), "%016llx%016llx",
           (unsigned long long)hi, (unsigned long long)lo);

  if (prefill_ep && decode_ep) {
    snprintf(pfe->vllm_request_id, sizeof(pfe->vllm_request_id),
             "___prefill_addr_%s___decode_addr_%s_%s",
             prefill_ep, decode_ep, uuid_buf);
  } else {
    strncpy(pfe->vllm_request_id, uuid_buf, sizeof(pfe->vllm_request_id) - 1);
    pfe->vllm_request_id[sizeof(pfe->vllm_request_id) - 1] = '\0';
  }

  pfe->has_vllm_request_id = 0;
  pfe->request_id_injected = 0;
}

/* ---- inject_request_id_header (copy for standalone testing) ---- */
static int
inject_request_id_header(void *msg, size_t *len, size_t bufsize,
                         const char *req_id)
{
  char inject_buf[512];
  size_t inject_len;
  uint8_t *headers_end;
  uint8_t *insert_point;
  size_t tail_len;
  uint8_t *existing;

  if (!req_id || req_id[0] == '\0')
    return -1;

  inject_len = (size_t)snprintf(inject_buf, sizeof(inject_buf),
                                "X-Request-Id: %s\r\n", req_id);
  if (inject_len >= sizeof(inject_buf))
    return -1;

  headers_end = memmem(msg, *len, "\r\n\r\n", 4);
  if (!headers_end)
    return -1;

  /* Strip existing X-Request-Id if present */
  existing = memmem(msg, (size_t)(headers_end - (uint8_t *)msg + 4),
                    "X-Request-Id:", 13);
  if (!existing) {
    existing = memmem(msg, (size_t)(headers_end - (uint8_t *)msg + 4),
                      "x-request-id:", 13);
  }
  if (existing) {
    uint8_t *line_end = memmem(existing,
                               *len - (size_t)(existing - (uint8_t *)msg),
                               "\r\n", 2);
    if (line_end) {
      line_end += 2;
      size_t remove_len = (size_t)(line_end - existing);
      memmove(existing, line_end,
              *len - (size_t)(line_end - (uint8_t *)msg));
      *len -= remove_len;
      headers_end = memmem(msg, *len, "\r\n\r\n", 4);
      if (!headers_end)
        return -1;
    }
  }

  if (*len + inject_len >= bufsize)
    return -1;

  insert_point = headers_end + 2;
  tail_len = *len - (size_t)(insert_point - (uint8_t *)msg);
  memmove(insert_point + inject_len, insert_point, tail_len);
  memcpy(insert_point, inject_buf, inject_len);
  *len += inject_len;
  return 0;
}

/* ============ TEST HARNESS ============ */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
  tests_run++; \
  printf("  TEST %d: %s ... ", tests_run, name); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* ============ TEST CASES ============ */

static void test_uuid_format(void) {
  TEST("UUID v4 format (32 hex chars)");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe, NULL, NULL);
  if (strlen(pfe.vllm_request_id) != 32) {
    char errbuf[128];
    snprintf(errbuf, sizeof(errbuf), "Expected 32 chars, got %zu: '%s'",
             strlen(pfe.vllm_request_id), pfe.vllm_request_id);
    FAIL(errbuf);
    return;
  }
  for (int i = 0; i < 32; i++) {
    char c = pfe.vllm_request_id[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      FAIL("Non-hex character found");
      return;
    }
  }
  PASS();
}

static void test_uuid_v4_bits(void) {
  TEST("UUID v4 version and variant bits");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe, NULL, NULL);

  /* Version nibble is char index 12 (bits 12-15 of hi = 4) */
  char version = pfe.vllm_request_id[3]; /* 4th hex digit of hi (0-indexed: bit positions 12-15) */
  /* Actually, snprintf produces "%016llx%016llx" so positions are:
   * hi occupies chars 0-15, lo occupies chars 16-31.
   * Bits 12-15 of hi correspond to hex digit at position:
   *   hi >> 12 & 0xF = digit at position (16 - 1 - 12/4) = position 12/4 from right
   *   In "%016llx": digit 0 is MSB. Bits 63-60 = digit 0.
   * Bits 12-15 = digit /4 = digit 12.75...
   *   Actually: digit_index = (60 - bit_position) / 4 ... no.
   *   Digit 0 = bits 63-60, digit 1 = bits 59-56, ...
   *   Digit k = bits (63 - 4k) to (60 - 4k)
   * For bits 12-15: k = /4 = 12, so digit 12 */
  version = pfe.vllm_request_id[12];
  if (version != '4') {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "Version nibble expected '4', got '%c'", version);
    FAIL(errbuf);
    return;
  }

  /* Variant bits: bits 62-63 of lo = 0b10 => hex digit 0 of lo (chars 16) should be 8,9,a,b */
  char variant = pfe.vllm_request_id[16];
  if (variant != '8' && variant != '9' && variant != 'a' && variant != 'b') {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "Variant nibble expected [89ab], got '%c'", variant);
    FAIL(errbuf);
    return;
  }
  PASS();
}

static void test_uuid_uniqueness(void) {
  TEST("UUID uniqueness (100 IDs)");
  char ids[100][33];
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  for (int i = 0; i < 100; i++) {
    generate_vllm_request_id(&pfe, NULL, NULL);
    strncpy(ids[i], pfe.vllm_request_id, 32);
    ids[i][32] = '\0';
  }
  for (int i = 0; i < 100; i++) {
    for (int j = i + 1; j < 100; j++) {
      if (strcmp(ids[i], ids[j]) == 0) {
        FAIL("Duplicate ID found");
        return;
      }
    }
  }
  PASS();
}

static void test_flags_after_generate(void) {
  TEST("Flags cleared after auto-generation");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  pfe.has_vllm_request_id = 1;
  pfe.request_id_injected = 1;
  generate_vllm_request_id(&pfe, NULL, NULL);
  if (pfe.has_vllm_request_id != 0) { FAIL("has_vllm_request_id not cleared"); return; }
  if (pfe.request_id_injected != 0) { FAIL("request_id_injected not cleared"); return; }
  PASS();
}

static void test_pd_format(void) {
  TEST("P/D format with endpoint addresses");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe, "10.0.1.1:8080", "10.0.1.2:8081");
  if (!strstr(pfe.vllm_request_id, "___prefill_addr_10.0.1.1:8080")) {
    FAIL("Missing prefill addr");
    return;
  }
  if (!strstr(pfe.vllm_request_id, "___decode_addr_10.0.1.2:8081")) {
    FAIL("Missing decode addr");
    return;
  }
  /* Should also contain UUID suffix */
  char *last_underscore = strrchr(pfe.vllm_request_id, '_');
  if (!last_underscore || strlen(last_underscore + 1) != 32) {
    FAIL("Missing or wrong-length UUID suffix");
    return;
  }
  PASS();
}

static void test_pd_format_zmq(void) {
  TEST("P/D format with ZMQ-style endpoints");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe,
                           "tcp://10.0.1.1:5556",
                           "tcp://10.0.1.2:5557");
  if (!strstr(pfe.vllm_request_id, "___prefill_addr_tcp://10.0.1.1:5556")) {
    FAIL("Missing ZMQ prefill addr");
    return;
  }
  if (!strstr(pfe.vllm_request_id, "___decode_addr_tcp://10.0.1.2:5557")) {
    FAIL("Missing ZMQ decode addr");
    return;
  }
  PASS();
}

static void test_inject_basic(void) {
  TEST("Header injection into valid HTTP request");
  char buf[4096];
  const char *req = "POST /v1/chat/completions HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    "{\"model\":\"llama\"}";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), "test-id-123");
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }
  if (!strstr(buf, "X-Request-Id: test-id-123\r\n")) { FAIL("Header not found"); return; }
  if (!strstr(buf, "\r\n\r\n")) { FAIL("Header-body separator broken"); return; }
  /* Verify body preserved */
  if (!strstr(buf, "{\"model\":\"llama\"}")) { FAIL("Body corrupted"); return; }
  PASS();
}

static void test_inject_preserves_body(void) {
  TEST("Header injection preserves full body content");
  char buf[4096];
  const char *body = "{\"model\":\"llama-70b\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}";
  char req[2048];
  snprintf(req, sizeof(req),
           "POST /v1/chat/completions HTTP/1.1\r\n"
           "Host: api.example.com\r\n"
           "Content-Length: %zu\r\n"
           "\r\n%s", strlen(body), body);
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), "uuid-abcdef");
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }
  /* Verify body is intact after injection */
  char *body_start = strstr(buf, "\r\n\r\n");
  if (!body_start) { FAIL("No header-body separator"); return; }
  body_start += 4;
  if (strcmp(body_start, body) != 0) {
    FAIL("Body content changed after injection");
    return;
  }
  PASS();
}

static void test_inject_null_id(void) {
  TEST("Reject NULL request ID");
  char buf[256];
  const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  size_t len = strlen(req);
  memcpy(buf, req, len);
  int rc = inject_request_id_header(buf, &len, sizeof(buf), NULL);
  if (rc != -1) { FAIL("Should reject NULL req_id"); return; }
  PASS();
}

static void test_inject_empty_id(void) {
  TEST("Reject empty request ID");
  char buf[256];
  const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  size_t len = strlen(req);
  memcpy(buf, req, len);
  int rc = inject_request_id_header(buf, &len, sizeof(buf), "");
  if (rc != -1) { FAIL("Should reject empty req_id"); return; }
  PASS();
}

static void test_inject_no_headers(void) {
  TEST("Reject request without header-body separator");
  char buf[256];
  const char *req = "GET / HTTP/1.1\r\nHost: x";
  size_t len = strlen(req);
  memcpy(buf, req, len);
  int rc = inject_request_id_header(buf, &len, sizeof(buf), "test-id");
  if (rc != -1) { FAIL("Should reject incomplete headers"); return; }
  PASS();
}

static void test_inject_overflow(void) {
  TEST("Header injection overflow protection");
  char buf[64];
  const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf),
    "very-long-request-id-that-will-overflow-the-tiny-buffer-easily");
  if (rc != -1) { FAIL("Should have returned -1 for overflow"); return; }
  PASS();
}

static void test_inject_strip_existing(void) {
  TEST("Strip existing X-Request-Id before injection");
  char buf[4096];
  const char *req = "POST /v1/chat HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "X-Request-Id: old-id-999\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    "{\"model\":\"llama\"}";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), "new-id-123");
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }
  if (strstr(buf, "old-id-999")) { FAIL("Old ID still present"); return; }
  if (!strstr(buf, "X-Request-Id: new-id-123\r\n")) { FAIL("New ID not found"); return; }
  /* Verify only one X-Request-Id header */
  char *first = strstr(buf, "X-Request-Id:");
  if (first) {
    char *second = strstr(first + 13, "X-Request-Id:");
    if (second) { FAIL("Multiple X-Request-Id headers"); return; }
  }
  PASS();
}

static void test_inject_strip_lowercase(void) {
  TEST("Strip existing lowercase x-request-id");
  char buf[4096];
  const char *req = "POST /v1/chat HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "x-request-id: old-lower-id\r\n"
                    "\r\n"
                    "body";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), "new-id-456");
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }
  if (strstr(buf, "old-lower-id")) { FAIL("Old lowercase ID still present"); return; }
  if (!strstr(buf, "X-Request-Id: new-id-456\r\n")) { FAIL("New ID not found"); return; }
  PASS();
}

static void test_inject_long_uuid(void) {
  TEST("Inject full-length P/D format request ID");
  char buf[4096];
  const char *req = "POST /v1/chat/completions HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "\r\n"
                    "{\"model\":\"llama\"}";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  const char *pd_id = "___prefill_addr_tcp://10.0.1.1:5556"
                       "___decode_addr_tcp://10.0.1.2:5557"
                       "_0123456789abcdef0123456789abcdef";
  int rc = inject_request_id_header(buf, &len, sizeof(buf), pd_id);
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error for long P/D ID"); return; }
  if (!strstr(buf, pd_id)) { FAIL("P/D ID not found in output"); return; }
  PASS();
}

static void test_end_to_end(void) {
  TEST("End-to-end: generate then inject");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe, NULL, NULL);

  char buf[4096];
  const char *req = "POST /v1/chat/completions HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    "{\"model\":\"llama\"}";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), pfe.vllm_request_id);
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }

  /* Verify the generated UUID appears in the output */
  char expected_header[300];
  snprintf(expected_header, sizeof(expected_header),
           "X-Request-Id: %s\r\n", pfe.vllm_request_id);
  if (!strstr(buf, expected_header)) { FAIL("Generated UUID not found in headers"); return; }
  PASS();
}

/* ============ MAIN ============ */


/* ---- P/D receipt rewrite (sockproxy_pd_receipt.h) ---- */
#include "sockproxy_pd_receipt.h"

#define RID_UUID "0123456789abcdef0123456789abcdef"
#define RID_P    "10.0.1.1:9001"
#define RID_D    "10.0.1.2:9002"
#define RID_REQ_FMT "POST /v1/completions HTTP/1.1\r\nHost: vip\r\n" \
                    "X-Request-Id: ___prefill_addr_%s___decode_addr_%s_" RID_UUID "\r\n" \
                    "Content-Length: 12\r\n\r\n{\"body\":\"__\"}"

static size_t rid_build(uint8_t *buf, size_t cap, const char *p, const char *d) {
  int n = snprintf((char *)buf, cap, RID_REQ_FMT, p, d);
  return n > 0 ? (size_t)n : 0;
}

/* The pre-F-5 helper, verbatim (loxilb-ebpf f515ab5, sockproxy_pd_vllm.c:56-75):
 * the prefill retry's call must keep producing these exact bytes. */
static int
legacy_prefill_rewrite(uint8_t *buf, size_t *len, size_t cap, const char *n_addr)
{
  uint8_t *he = memmem(buf, *len, "\r\n\r\n", 4);
  size_t hdr_len = he ? (size_t)(he + 4 - buf) : 0;
  char *tag = hdr_len ? memmem(buf, hdr_len, "___prefill_addr_", 16) : NULL;
  char *a_start = tag ? tag + 16 : NULL;
  char *a_end = a_start ? memmem(a_start, (size_t)((char *)buf + hdr_len - a_start),
                                 "___decode_addr_", 15) : NULL;
  if (!a_start || !a_end) return -1;

  int n_len = (int)strlen(n_addr);
  int o_len = (int)(a_end - a_start);
  int shift = n_len - o_len;
  if (n_len <= 0 || *len + (size_t)(shift > 0 ? shift : 0) > cap) return -1;
  if (shift != 0) {
    memmove(a_end + shift, a_end, *len - (size_t)(a_end - (char *)buf));
    *len = (size_t)((ssize_t)*len + shift);
  }
  memcpy(a_start, n_addr, (size_t)n_len);
  return 0;
}

static void test_receipt_decode_half_rewritten(void) {
  TEST("receipt: decode half re-rendered, prefill half and uuid untouched (longer address)");
  uint8_t buf[512], want[512];
  size_t len = rid_build(buf, sizeof(buf), RID_P, RID_D);
  size_t want_len = rid_build(want, sizeof(want), RID_P, "10.0.1.30:19004");
  int rc = pd_receipt_rewrite(buf, &len, sizeof(buf), PD_RECEIPT_DECODE, "10.0.1.30:19004");
  if (rc != 0) { FAIL("rc != 0"); return; }
  if (len != want_len || memcmp(buf, want, len) != 0) { FAIL("bytes differ from the expected request"); return; }
  if (!memmem(buf, len, "___prefill_addr_" RID_P "___decode_addr_10.0.1.30:19004_" RID_UUID "\r\n", 16 + 13 + 15 + 15 + 1 + 32 + 2)) { FAIL("receipt not as expected"); return; }
  { static const char tail[] = "\r\n\r\n{\"body\":\"__\"}";
    if (len < sizeof(tail) - 1 || memcmp(buf + len - (sizeof(tail) - 1), tail, sizeof(tail) - 1) != 0) { FAIL("body moved or damaged"); return; } }
  PASS();
}

static void test_receipt_decode_half_shorter(void) {
  TEST("receipt: decode half re-rendered with a shorter address (buffer shrinks, body intact)");
  uint8_t buf[512], want[512];
  size_t len = rid_build(buf, sizeof(buf), RID_P, "10.0.1.200:19002");
  size_t want_len = rid_build(want, sizeof(want), RID_P, "10.0.1.3:9003");
  int rc = pd_receipt_rewrite(buf, &len, sizeof(buf), PD_RECEIPT_DECODE, "10.0.1.3:9003");
  if (rc != 0 || len != want_len || memcmp(buf, want, len) != 0) { FAIL("shrink rewrite differs"); return; }
  PASS();
}

static void test_receipt_prefill_half_untouched_by_decode(void) {
  TEST("receipt: a decode-half rewrite never moves the prefill half");
  uint8_t buf[512];
  size_t len = rid_build(buf, sizeof(buf), "192.168.100.250:65000", RID_D);
  char *before = memmem(buf, len, "___prefill_addr_192.168.100.250:65000___decode_addr_", 52);
  if (!before) { FAIL("setup"); return; }
  size_t p_off = (size_t)((uint8_t *)before - buf);
  if (pd_receipt_rewrite(buf, &len, sizeof(buf), PD_RECEIPT_DECODE, "1.2.3.4:5") != 0) { FAIL("rc"); return; }
  if (memcmp(buf + p_off, "___prefill_addr_192.168.100.250:65000___decode_addr_1.2.3.4:5_" RID_UUID, 16 + 21 + 15 + 9 + 1 + 32) != 0) { FAIL("prefill half or uuid changed"); return; }
  PASS();
}

static void test_receipt_noop_same_ep(void) {
  TEST("receipt: no-op (rc 1, not a byte changed) when the decode EP did not change");
  uint8_t buf[512], copy[512];
  size_t len = rid_build(buf, sizeof(buf), RID_P, RID_D), len0 = len;
  memcpy(copy, buf, len);
  int rc = pd_receipt_rewrite(buf, &len, sizeof(buf), PD_RECEIPT_DECODE, RID_D);
  if (rc != 1) { FAIL("rc != 1"); return; }
  if (len != len0 || memcmp(buf, copy, len) != 0) { FAIL("buffer changed on a no-op"); return; }
  PASS();
}

static void test_receipt_cap_respected(void) {
  TEST("receipt: a longer address that would overflow cap is refused (rc -1) and leaves the buffer intact");
  uint8_t buf[512], copy[512];
  size_t len = rid_build(buf, sizeof(buf), RID_P, RID_D), len0 = len;
  memcpy(copy, buf, len);
  /* cap == len: zero slack, any growth must be refused */
  int rc = pd_receipt_rewrite(buf, &len, len, PD_RECEIPT_DECODE, "10.0.1.2:19002");
  if (rc != -1 || len != len0 || memcmp(buf, copy, len) != 0) { FAIL("overflow not refused cleanly"); return; }
  /* cap == len + growth: exactly enough */
  rc = pd_receipt_rewrite(buf, &len, len0 + 1, PD_RECEIPT_DECODE, "10.0.1.2:19002");
  if (rc != 0 || len != len0 + 1) { FAIL("exact-fit growth refused"); return; }
  PASS();
}

static void test_receipt_no_receipt(void) {
  TEST("receipt: a client-supplied plain X-Request-Id has no receipt (rc -1, untouched)");
  const char *req = "POST / HTTP/1.1\r\nX-Request-Id: client-abc-123\r\n\r\n{}";
  uint8_t buf[256]; size_t len = strlen(req); memcpy(buf, req, len);
  int rc = pd_receipt_rewrite(buf, &len, sizeof(buf), PD_RECEIPT_DECODE, "1.2.3.4:5");
  if (rc != -1 || len != strlen(req) || memcmp(buf, req, len) != 0) { FAIL("plain id was touched"); return; }
  PASS();
}

static void test_receipt_bare_id_copies(void) {
  TEST("receipt: the pfe's bare id copies (vllm_request_id / resp_request_id) are re-rendered and NUL-terminated");
  char id[256];
  snprintf(id, sizeof(id), "___prefill_addr_%s___decode_addr_%s_%s", RID_P, RID_D, RID_UUID);
  int rc = pd_receipt_rewrite_str(id, sizeof(id), PD_RECEIPT_DECODE, "10.0.1.30:19004");
  if (rc != 0) { FAIL("rc"); return; }
  if (strcmp(id, "___prefill_addr_" RID_P "___decode_addr_10.0.1.30:19004_" RID_UUID) != 0) { FAIL("bare id wrong"); return; }
  if (pd_receipt_rewrite_str(id, sizeof(id), PD_RECEIPT_DECODE, "10.0.1.30:19004") != 1) { FAIL("second call not a no-op"); return; }
  char empty[256] = "";
  if (pd_receipt_rewrite_str(empty, sizeof(empty), PD_RECEIPT_DECODE, "1.2.3.4:5") != -1) { FAIL("empty id accepted"); return; }
  PASS();
}

static void test_receipt_prefill_call_byte_identical(void) {
  TEST("receipt: the prefill retry's call (PD_RECEIPT_PREFILL) is byte-identical to the pre-F-5 helper");
  static const char *addrs[] = { "10.0.1.1:9001", "10.0.1.100:19001", "1.1.1.1:1", "172.16.0.9:8100" };
  static const char *news[]  = { "10.0.1.50:9005", "1.2.3.4:5", "192.168.200.200:65535", "10.0.1.1:9001" };
  for (size_t i = 0; i < 4; i++) for (size_t j = 0; j < 4; j++) {
    uint8_t a[512], b[512];
    size_t la = rid_build(a, sizeof(a), addrs[i], RID_D), lb = la;
    memcpy(b, a, la);
    int ra = legacy_prefill_rewrite(a, &la, sizeof(a), news[j]);
    int rb = pd_receipt_rewrite(b, &lb, sizeof(b), PD_RECEIPT_PREFILL, news[j]);
    /* rc differs only in the same-address case (legacy 0, new 1): the bytes must not */
    if ((ra == 0) != (rb == 0 || rb == 1) || la != lb || memcmp(a, b, la) != 0) { FAIL("prefill rewrite diverged from the legacy bytes"); return; }
    if (strcmp(addrs[i], news[j]) == 0 && rb != 1) { FAIL("same-address prefill call should be rc 1"); return; }
    /* saved-headers shape: header block only, no body */
    uint8_t *he = memmem(a, la, "\r\n\r\n", 4); size_t hl = (size_t)(he + 4 - a);
    uint8_t sa[512], sb[512]; size_t lsa = hl, lsb = hl; memcpy(sa, a, hl); memcpy(sb, a, hl);
    size_t l0 = rid_build(sa, sizeof(sa), addrs[i], RID_D); he = memmem(sa, l0, "\r\n\r\n", 4); lsa = (size_t)(he + 4 - sa); memcpy(sb, sa, lsa); lsb = lsa;
    ra = legacy_prefill_rewrite(sa, &lsa, lsa + 80, news[j]);
    rb = pd_receipt_rewrite(sb, &lsb, lsb + 80, PD_RECEIPT_PREFILL, news[j]);
    if ((ra == 0) != (rb == 0 || rb == 1) || lsa != lsb || memcmp(sa, sb, lsa) != 0) { FAIL("saved-headers prefill rewrite diverged"); return; }
  }
  PASS();
}

int main(void) {
  printf("===: Request-ID Unit Tests ===\n\n");

  /* UUID generation tests */
  test_uuid_format();
  test_uuid_v4_bits();
  test_uuid_uniqueness();
  test_flags_after_generate();
  test_pd_format();
  test_pd_format_zmq();

  /* Header injection tests */
  test_inject_basic();
  test_inject_preserves_body();
  test_inject_null_id();
  test_inject_empty_id();
  test_inject_no_headers();
  test_inject_overflow();
  test_inject_strip_existing();
  test_inject_strip_lowercase();
  test_inject_long_uuid();

  /* End-to-end test */
  test_end_to_end();

  /* P/D receipt rewrite (prefill retry half, connect-time decode fallback half) */
  test_receipt_decode_half_rewritten();
  test_receipt_decode_half_shorter();
  test_receipt_prefill_half_untouched_by_decode();
  test_receipt_noop_same_ep();
  test_receipt_cap_respected();
  test_receipt_no_receipt();
  test_receipt_bare_id_copies();
  test_receipt_prefill_call_byte_identical();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
