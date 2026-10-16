/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_deny_free.c - nothing reads an HTTP/2 stream after an answer that
 * may have freed it.
 *
 * When the client has sent all of its request, an answer from the gateway
 * (a deny, an L7 reject) ends the stream on both sides as soon as nghttp2
 * writes it, and nghttp2's close callback frees the stream before the send
 * returns. proxy_h2_forward_to_backend used to log the stream's id (and, for
 * a model with no pool, the model name held in the stream) after such an
 * answer: a heap-use-after-free, seen live under ASan when a listener was
 * deleted while its streams were being dispatched.
 *
 * This drives the REAL proxy_h2_forward_to_backend over a REAL gateway
 * session (proxy_setup_h2_session: the product's callbacks, sending on a
 * socketpair), with the request parsed by those callbacks, for the four
 * answers it gives itself:
 *   - a model with no pool: 503 model_unavailable;
 *   - an admission refusal: 401;
 *   - an L7 reject: 403;
 *   - a capacity refusal: 429 (sp_fc_h2_shed, which also records the
 *     refusal and releases the stream's permit: it used to do both AFTER
 *     the answer, a write into the freed stream).
 * Each case checks the answer reached the client AND that the stream was
 * freed (otherwise the case could not catch a read of it). The gateway code
 * is built with ASan here (sockproxy_h2_asan.o), so a read after the free
 * aborts the test; putting any one site's old code back turns it red.
 *
 * Build: make test_h2deny (ASan + UBSan, the gateway object included).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <nghttp2/nghttp2.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_h2.h"
#include "sockproxy_pool.h"
#include "sockproxy_qsbr.h"
#include "sockproxy_ai_admit.h"
#include "sockproxy_l7policy.h"
#include "sockproxy_internal.h"

/* The gateway's globals the linked code uses. */
proxy_global_stats_t global_stats;
proxy_struct_t *proxy_struct;
static proxy_struct_t ps;

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("  (%s:%d)\n", __FILE__, __LINE__);                     \
    }                                                                \
  } while (0)

/* What the cases set for the product's seams below. */
enum { CASE_NO_POOL, CASE_ADMIT_DENY, CASE_L7_REJECT, CASE_CAPACITY };
static int the_case;
static int admit_calls, l7_calls, lpm_calls;
static proxy_epval_t *lpm_pool;   /* what the lookup finds, CASE_CAPACITY */

int
ai_gw_admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  (void)req;
  admit_calls++;
  memset(res, 0, sizeof(*res));
  if (the_case == CASE_ADMIT_DENY) {
    res->verdict = AI_GW_ADMIT_DENY;
    res->http_status = 401;
    snprintf(res->error_code, sizeof(res->error_code), "invalid_api_key");
    snprintf(res->error_msg, sizeof(res->error_msg), "the key is not known");
  } else if (the_case == CASE_CAPACITY) {
    res->verdict = AI_GW_ADMIT_ALLOW;
    snprintf(res->tenant_id, sizeof(res->tenant_id), "t1");
  } else {
    res->verdict = AI_GW_ADMIT_UNMETERED;
  }
  return 0;
}

int
l7_route_dispatch(struct proxy_fd_ent *pfe, struct proxy_map_ent *ent,
                  struct proxy_epval **tepval_out)
{
  (void)ent;
  l7_calls++;
  *tepval_out = NULL;
  /* The product's reject, l7_send_reject on an HTTP/2 connection. */
  if (proxy_h2_send_l7_synthetic(pfe, 403, NULL, NULL) != 0)
    return L7_DISPATCH_FALLTHROUGH;
  return L7_DISPATCH_TERMINATED;
}

proxy_epval_t *
find_endpoint_lpm(proxy_map_ent_t *ent, const char *host, const char *path,
                  const char *model)
{
  (void)ent; (void)host; (void)path; (void)model;
  lpm_calls++;
  /* CASE_NO_POOL: the listener's pool is gone (deleted under the streams). */
  return the_case == CASE_CAPACITY ? lpm_pool : NULL;
}

static void
no_final(proxy_epval_t *p)
{
  (void)p;
}

/* The test client, reading the gateway's side of the socketpair. */
static int sv[2];
static nghttp2_session *cl;
static int got_status[16];

#define C2G_CAP (1 << 20)
static uint8_t *c2g;
static size_t c2g_len;

static ssize_t
cl_send(nghttp2_session *s, const uint8_t *data, size_t len, int flags, void *u)
{
  (void)s; (void)flags; (void)u;
  /* Held until to_gateway() feeds it to the gateway session. */
  assert(c2g_len + len <= C2G_CAP);
  memcpy(c2g + c2g_len, data, len);
  c2g_len += len;
  return (ssize_t)len;
}

static int
cl_on_header(nghttp2_session *s, const nghttp2_frame *f, const uint8_t *name,
             size_t namelen, const uint8_t *value, size_t valuelen,
             uint8_t flags, void *u)
{
  (void)s; (void)flags; (void)u;
  if (f->hd.type == NGHTTP2_HEADERS && namelen == 7 &&
      !memcmp(name, ":status", 7) && f->hd.stream_id / 2 < 16) {
    char v[8] = { 0 };
    memcpy(v, value, valuelen < 7 ? valuelen : 7);
    got_status[f->hd.stream_id / 2] = atoi(v);
  }
  return 0;
}

/* Everything the gateway wrote, into the client. */
static void
deliver(void)
{
  uint8_t b[65536];
  ssize_t n;

  while ((n = read(sv[1], b, sizeof(b))) > 0)
    assert(nghttp2_session_mem_recv(cl, b, (size_t)n) == n);
  assert(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
}

/* The client's pending frames, into the gateway, through the product's
 * receive callbacks. */
static void
to_gateway(proxy_fd_ent_t *pfe)
{
  assert(nghttp2_session_send(cl) == 0);
  ssize_t rv = nghttp2_session_mem_recv(pfe->h2_session->session, c2g, c2g_len);
  assert(rv == (ssize_t)c2g_len);
  c2g_len = 0;
  assert(nghttp2_session_send(pfe->h2_session->session) == 0);
  deliver();
}

static proxy_h2_stream_t *
stream_of(proxy_fd_ent_t *pfe, int32_t id)
{
  proxy_h2_stream_t *st = NULL;
  HASH_FIND_INT(pfe->h2_session->streams, &id, st);
  return st;
}

/* One complete request (END_STREAM on HEADERS), an inference POST naming a model in x-model,
 * which the gateway keeps in the stream. */
static int32_t
request(proxy_fd_ent_t *pfe)
{
  nghttp2_nv req[] = {
    { (uint8_t *)":method", (uint8_t *)"POST", 7, 4, 0 },
    { (uint8_t *)":path", (uint8_t *)"/v1/chat/completions", 5, 20, 0 },
    { (uint8_t *)":scheme", (uint8_t *)"http", 7, 4, 0 },
    { (uint8_t *)":authority", (uint8_t *)"all.example", 10, 11, 0 },
    { (uint8_t *)"x-model", (uint8_t *)"m-gone", 7, 6, 0 },
  };
  int32_t id = nghttp2_submit_request(cl, NULL, req, 5, NULL, NULL);

  assert(id > 0);
  to_gateway(pfe);
  return id;
}

static void
run(proxy_fd_ent_t *pfe, int which, int want_status, const char *what)
{
  int32_t id;
  proxy_h2_stream_t *st;
  int rc;

  the_case = which;
  id = request(pfe);
  st = stream_of(pfe, id);
  CHECK(st && st->headers_complete && st->data_complete && !st->response_sent,
        "%s: the request is complete on stream %d", what, id);
  if (!st)
    return;
  rc = proxy_h2_forward_to_backend(pfe, st);
  deliver();
  CHECK(rc == 0, "%s: answered by the gateway itself (rc %d)", what, rc);
  CHECK(got_status[id / 2] == want_status, "%s: the client got %d (got %d)",
        what, want_status, got_status[id / 2]);
  CHECK(stream_of(pfe, id) == NULL,
        "%s: the answer ended the stream and freed it (the case can see a read after the free)",
        what);
}

int
main(void)
{
  proxy_map_ent_t ent = { 0 };
  proxy_fd_ent_t *pfe = calloc(1, sizeof(*pfe));
  nghttp2_session_callbacks *ccb;
  proxy_epval_t *pool;

  setvbuf(stdout, NULL, _IONBF, 0);
  assert(pfe);
  c2g = malloc(C2G_CAP);
  assert(c2g);
  pthread_rwlock_init(&ps.lock, NULL);
  ps.head = &ent;
  proxy_struct = &ps;
  sp_pool_init(no_final);
  assert(sp_pool_index_publish(&ent) == 0);

  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  assert(fcntl(sv[1], F_SETFL, O_NONBLOCK) == 0);
  pfe->fd = sv[0];
  pfe->head = &ent;
  assert(proxy_setup_h2_session(pfe, 0) == 0);

  nghttp2_session_callbacks_new(&ccb);
  nghttp2_session_callbacks_set_send_callback(ccb, cl_send);
  nghttp2_session_callbacks_set_on_header_callback(ccb, cl_on_header);
  assert(nghttp2_session_client_new(&cl, ccb, NULL) == 0);
  nghttp2_session_callbacks_del(ccb);
  assert(nghttp2_submit_settings(cl, NGHTTP2_FLAG_NONE, NULL, 0) == 0);
  deliver();             /* the gateway's preface */
  to_gateway(pfe);       /* the client's, and the acknowledgements */

  /* No pool on the listener (deleted under its streams): no admission, the
   * model has no pool, 503. The model name the log prints is the stream's. */
  run(pfe, CASE_NO_POOL, 503, "no pool for the model");
  CHECK(admit_calls == 0 && lpm_calls == 1, "no admission without a pool, one lookup");

  /* The listener has its pool; admission refuses. */
  pool = sp_pool_alloc();
  assert(pool);
  snprintf(pool->ephash_key, sizeof(pool->ephash_key), "all.example");
  assert(sp_pool_link(&ent, pool) == 0);
  run(pfe, CASE_ADMIT_DENY, 401, "admission refusal");
  CHECK(admit_calls == 1, "admission ran once");

  /* An L7 policy rejects (the flag l7_policy_on reads). */
  ent.has_l7_policy = 1;
  run(pfe, CASE_L7_REJECT, 403, "L7 reject");
  CHECK(l7_calls == 1, "the L7 dispatch ran once");
  ent.has_l7_policy = 0;

  /* An AI pool with a ceiling of one, held by another request: the stream
   * is refused at the service level (it never held a unit). What this case
   * catches is the refusal reading or releasing through the freed stream;
   * the counts below only show the other request's unit is untouched. */
  {
    fc_cfg_t cfg = { 0 };
    fc_permit_t other = { 0 };

    lpm_pool = sp_pool_alloc();
    assert(lpm_pool);
    snprintf(lpm_pool->ephash_key, sizeof(lpm_pool->ephash_key), "all.example|m-gone");
    lpm_pool->ai_gw_mode = 1;
    lpm_pool->n_eps = 1;
    pthread_mutex_init(&lpm_pool->fc.queue.lock, NULL);
    cfg.mode = FC_MODE_ENFORCE;
    cfg.max_outstanding = 1;
    fc_state_apply(&lpm_pool->fc, &cfg);
    assert(fc_service_acquire(&lpm_pool->fc, &other) == FC_ADMIT);
    run(pfe, CASE_CAPACITY, 429, "capacity refusal");
    CHECK(fc_inflight(&lpm_pool->fc) == 1,
          "only the other request's unit is in flight (inflight %u)",
          fc_inflight(&lpm_pool->fc));
    fc_permit_release(&other);
    CHECK(fc_inflight(&lpm_pool->fc) == 0, "and none after it ends");
    fc_permit_unbind(&other);
  }

  /* Teardown, so the leak check reads only the code under test. The
   * listener's pool goes the product's way (unlinked, freed after the grace
   * period, which no registered reader holds open). */
  nghttp2_session_del(cl);
  nghttp2_session_del(pfe->h2_session->session);
  free(pfe->h2_session);
  assert(sp_pool_unlink(&ent, pool) == 0);
  for (int i = 0; i < 16 && sp_qsbr_pending(); i++)
    sp_qsbr_run_ready();
  fc_state_destroy(&lpm_pool->fc);
  sp_pool_discard(lpm_pool);
  close(sv[0]);
  close(sv[1]);
  free(c2g);
  free(pfe);

  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
