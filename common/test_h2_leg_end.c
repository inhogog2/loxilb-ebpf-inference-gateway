/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_leg_end.c - one HTTP/2 backend leg ending reaches only the client
 * streams it carries.
 *
 * An HTTP/2 client connection has one backend leg per endpoint it reached.
 * When one leg ends (the endpoint closed an idle connection, restarted, or
 * reset it), its teardown used to cascade to the client, the HTTP/1.1
 * one-to-one rule: the client connection closed and every stream on it, on
 * every other endpoint too, was lost without an answer. Now the leg answers
 * its own streams (proxy_h2_backend_leg_end) and is detached from the client
 * (proxy_h2_h1_backend_detach) before its teardown releases anything.
 *
 * This drives the REAL functions out of sockproxy_h2.c over a real nghttp2
 * server session, and reads what reached the wire with an nghttp2 client:
 *   - a stream of the ended leg with no response yet is answered 503;
 *   - one whose response had started is reset (the rest cannot come);
 *   - a stream on the other leg gets nothing;
 *   - a second end of the same leg answers nothing again;
 *   - the detach takes the leg off the client and keeps the other leg.
 * The mutation twins in wp8/twins-h2leg.sh must each turn this red.
 *
 * Build: make test_h2leg (ASan + UBSan).
 */
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nghttp2/nghttp2.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_h2.h"
#include "sockproxy_pool.h"
#include "sockproxy_qsbr.h"

static int checks, failures;

/* The stream's response record lives in sockproxy_http.c, which this test
 * does not link: the answers the leg's end writes take their class count
 * through this stand-in. */
int
proxy_h2_note_stream_response(proxy_h2_stream_t *stream, uint16_t status,
                              int sample_ttfb)
{
  (void)stream; (void)status; (void)sample_ttfb;
  return 1;
}

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

/* Reached only from a mapping's load release; no mapping here holds one. */
void
chwbl_dec_runtime(proxy_epval_t *epv, int ep_idx)
{
  (void)epv;
  (void)ep_idx;
}

static void
no_final(proxy_epval_t *p)
{
  (void)p;
}

/* The wire, gateway -> test client. */
static uint8_t wire[65536];
static size_t wire_len;

static ssize_t
gw_send(nghttp2_session *s, const uint8_t *data, size_t len, int flags, void *u)
{
  (void)s; (void)flags; (void)u;
  assert(wire_len + len <= sizeof(wire));
  memcpy(wire + wire_len, data, len);
  wire_len += len;
  return (ssize_t)len;
}

/* The test client: what each stream received. */
#define NSTREAMS 8
static int got_status[NSTREAMS];
static uint32_t got_rst[NSTREAMS];

static int
cl_on_header(nghttp2_session *s, const nghttp2_frame *f, const uint8_t *name,
             size_t namelen, const uint8_t *value, size_t valuelen,
             uint8_t flags, void *u)
{
  (void)s; (void)flags; (void)u;
  if (f->hd.type == NGHTTP2_HEADERS && namelen == 7 &&
      !memcmp(name, ":status", 7) && f->hd.stream_id / 2 < NSTREAMS) {
    char v[8] = { 0 };
    memcpy(v, value, valuelen < 7 ? valuelen : 7);
    got_status[f->hd.stream_id / 2] = atoi(v);
  }
  return 0;
}

static int
cl_on_frame(nghttp2_session *s, const nghttp2_frame *f, void *u)
{
  (void)s; (void)u;
  if (f->hd.type == NGHTTP2_RST_STREAM && f->hd.stream_id / 2 < NSTREAMS) {
    got_rst[f->hd.stream_id / 2] = f->rst_stream.error_code + 1;
  }
  return 0;
}

static uint8_t c2g[65536];
static size_t c2g_len;

static ssize_t
cl_send(nghttp2_session *s, const uint8_t *data, size_t len, int flags, void *u)
{
  (void)s; (void)flags; (void)u;
  assert(c2g_len + len <= sizeof(c2g));
  memcpy(c2g + c2g_len, data, len);
  c2g_len += len;
  return (ssize_t)len;
}

/* Gateway output since the last call, into the test client. */
static void
deliver(nghttp2_session *cl)
{
  ssize_t rv = nghttp2_session_mem_recv(cl, wire, wire_len);
  assert(rv == (ssize_t)wire_len);
  wire_len = 0;
}

static void
reset_seen(void)
{
  memset(got_status, 0, sizeof(got_status));
  memset(got_rst, 0, sizeof(got_rst));
}

static proxy_h2_stream_t *
add_stream(proxy_h2_session_t *sess, int32_t id)
{
  proxy_h2_stream_t *st = calloc(1, sizeof(*st));

  assert(st);
  st->stream_id = id;
  HASH_ADD_INT(sess->streams, stream_id, st);
  sess->active_stream_count++;
  return st;
}

static backend_h2_session_t *
add_leg(proxy_fd_ent_t *client, proxy_fd_ent_t *bpfe, int slot)
{
  backend_h2_session_t *bs = calloc(1, sizeof(*bs));

  assert(bs);
  bs->slot = slot;
  bs->ep_idx = slot;
  bs->backend_fd = -1;
  bs->connected = 1;
  bs->client_session = client->h2_session;
  pthread_mutex_init(&bs->send_lock, NULL);
  HASH_ADD_INT(client->h2_session->backend_sessions, slot, bs);
  bpfe->odir = 1;
  bpfe->fd = -1;
  bpfe->backend_h2_session = bs;
  bpfe->rfd_ent[0] = client;
  bpfe->rfd[0] = client->fd;
  bpfe->n_rfd = 1;
  client->rfd_ent[slot] = bpfe;
  client->rfd[slot] = 100 + slot;
  if (client->n_rfd < slot + 1)
    client->n_rfd = slot + 1;
  return bs;
}

static void
map(backend_h2_session_t *bs, int32_t client_id, int32_t backend_id)
{
  stream_mapping_t *m = calloc(1, sizeof(*m));

  assert(m);
  m->client_stream_id = client_id;
  m->backend_stream_id = backend_id;
  m->ep_idx = bs->ep_idx;
  HASH_ADD_INT(bs->stream_map, client_stream_id, m);
}

int
main(void)
{
  proxy_map_ent_t ent = { 0 };
  proxy_fd_ent_t *client = calloc(1, sizeof(*client));
  proxy_fd_ent_t *legA = calloc(1, sizeof(*legA));
  proxy_fd_ent_t *legB = calloc(1, sizeof(*legB));
  proxy_h2_session_t *sess = calloc(1, sizeof(*sess));
  nghttp2_session_callbacks *gcb, *ccb;
  nghttp2_session *gw, *cl;
  backend_h2_session_t *bsA, *bsB, *left;
  proxy_h2_stream_t *s1, *s3, *s5, *s7;
  void *answer1;
  nghttp2_nv req[] = {
    { (uint8_t *)":method", (uint8_t *)"GET", 7, 3, 0 },
    { (uint8_t *)":path", (uint8_t *)"/", 5, 1, 0 },
    { (uint8_t *)":scheme", (uint8_t *)"http", 7, 4, 0 },
    { (uint8_t *)":authority", (uint8_t *)"t", 10, 1, 0 },
  };
  ssize_t rv;

  setvbuf(stdout, NULL, _IONBF, 0);
  assert(client && legA && legB && sess);
  sp_pool_init(no_final);
  assert(sp_pool_index_publish(&ent) == 0);

  /* The gateway's side of the client connection, a real server session. */
  nghttp2_session_callbacks_new(&gcb);
  nghttp2_session_callbacks_set_send_callback(gcb, gw_send);
  assert(nghttp2_session_server_new(&gw, gcb, NULL) == 0);
  nghttp2_session_callbacks_new(&ccb);
  nghttp2_session_callbacks_set_send_callback(ccb, cl_send);
  nghttp2_session_callbacks_set_on_header_callback(ccb, cl_on_header);
  nghttp2_session_callbacks_set_on_frame_recv_callback(ccb, cl_on_frame);
  assert(nghttp2_session_client_new(&cl, ccb, NULL) == 0);

  /* Streams 1, 3, 5, 7 open on the client connection. The server's SETTINGS
   * is its preface and must go out before it acknowledges the client's. */
  assert(nghttp2_submit_settings(gw, NGHTTP2_FLAG_NONE, NULL, 0) == 0);
  assert(nghttp2_submit_settings(cl, NGHTTP2_FLAG_NONE, NULL, 0) == 0);
  for (int i = 0; i < 4; i++)
    assert(nghttp2_submit_request(cl, NULL, req, 4, NULL, NULL) == 2 * i + 1);
  assert(nghttp2_session_send(cl) == 0);
  rv = nghttp2_session_mem_recv(gw, c2g, c2g_len);
  assert(rv == (ssize_t)c2g_len);
  assert(nghttp2_session_send(gw) == 0);
  deliver(cl);
  reset_seen();

  client->fd = -1;
  client->head = &ent;
  client->h2_session = sess;
  client->protocol_version = 2;
  sess->session = gw;
  sess->pfe = client;
  sess->h2_enabled = 1;
  s1 = add_stream(sess, 1);
  s3 = add_stream(sess, 3);
  s5 = add_stream(sess, 5);
  s7 = add_stream(sess, 7);

  /* Leg A (slot 0) carries 1 (no response yet), 3 (response started) and 7
   * (response complete, still queued on its relay); leg B (slot 1) carries
   * 5. The response of 3 starts on the wire. */
  bsA = add_leg(client, legA, 0);
  bsB = add_leg(client, legB, 1);
  map(bsA, 1, 1);
  map(bsA, 3, 3);
  map(bsA, 7, 5);
  s7->resp.eos_pending = 1;
  map(bsB, 5, 1);
  {
    nghttp2_nv ok[] = { { (uint8_t *)":status", (uint8_t *)"200", 7, 3, 0 } };
    assert(nghttp2_submit_headers(gw, NGHTTP2_FLAG_NONE, 3, NULL, ok, 1, NULL) == 0);
    assert(nghttp2_session_send(gw) == 0);
    s3->resp.final_headers_sent = 1;
    deliver(cl);
    CHECK(got_status[1] == 200, "stream 3's response started (status %d)", got_status[1]);
    reset_seen();
  }

  /* Leg A ends. */
  CHECK(proxy_h2_backend_leg_end(legA) == 1, "the leg is an HTTP/2 leg of its client");
  deliver(cl);
  CHECK(got_status[0] == 503, "stream 1, no response yet, is answered 503 (got %d)",
        got_status[0]);
  CHECK(got_rst[1] == NGHTTP2_INTERNAL_ERROR + 1 && got_status[1] == 0,
        "stream 3, response started, is reset, not answered again (rst %u status %d)",
        got_rst[1] ? got_rst[1] - 1 : 0, got_status[1]);
  CHECK(got_status[2] == 0 && got_rst[2] == 0,
        "stream 5, on the other leg, gets nothing (status %d rst %u)",
        got_status[2], got_rst[2]);
  {
    proxy_h2_stream_t *f = NULL;
    int32_t id = 5;
    HASH_FIND_INT(sess->streams, &id, f);
    CHECK(nghttp2_session_find_stream(gw, 5) != NULL && f == s5,
          "stream 5 is still open on the client connection");
  }
  CHECK(got_status[3] == 0 && got_rst[3] == 0 && !s7->response_sent,
        "stream 7, its response complete on the relay, is left to the relay (status %d rst %u)",
        got_status[3], got_rst[3]);
  CHECK(s1->response_sent && s3->response_sent && !s5->response_sent,
        "the answered streams are marked answered, the other leg's is not");
  reset_seen();
  answer1 = s1->deny_body_ctx;
  CHECK(answer1 != NULL, "stream 1 owns its answer's body");

  /* The same leg's end seen twice (a TLS error before the teardown, then the
   * teardown) answers nothing more. */
  CHECK(proxy_h2_backend_leg_end(legA) == 1, "a second end is still recognised");
  deliver(cl);
  CHECK(got_status[0] == 0 && got_rst[0] == 0 && got_rst[1] == 0 &&
        s1->deny_body_ctx == answer1,
        "and answers nothing again: no frame, the first answer still the stream's");

  /* The teardown's detach, under PROXY_LOCK in the product. */
  proxy_h2_h1_backend_detach(legA);
  CHECK(client->rfd_ent[0] == NULL && client->rfd[0] == -1,
        "the ended leg is off the client");
  CHECK(client->rfd_ent[1] == legB && client->n_rfd == 2,
        "the other leg stays (n_rfd %d)", client->n_rfd);
  CHECK(legA->n_rfd == 0 && legA->rfd_ent[0] == NULL && legA->backend_h2_session == NULL,
        "the ended leg has no client left to cascade to");
  left = NULL;
  {
    int slot = 1;
    HASH_FIND_INT(sess->backend_sessions, &slot, left);
  }
  CHECK(HASH_COUNT(sess->backend_sessions) == 1 && left == bsB,
        "the client keeps only the other leg's session");

  /* A leg whose client has gone is not answered from. */
  CHECK(proxy_h2_backend_leg_end(legA) == 0, "a detached leg is no HTTP/2 leg any more");

  /* A new leg takes its pool and no P/D unit: from the allocator's zeroed
   * shell, both P/D indices must be cleared, or its teardown (pd_cleanup,
   * which runs for any entry holding a pool) releases endpoint 0's units. */
  {
    proxy_fd_ent_t *leg = calloc(1, sizeof(*leg));
    backend_h2_session_t *bs = calloc(1, sizeof(*bs));
    proxy_epval_t *pool = sp_pool_alloc();

    assert(leg && bs && pool);
    pool->n_eps = 3;
    pool->eps[2].xip = htonl(0x0a000205);   /* 10.0.2.5 */
    pool->eps[2].xport = htons(8002);
    proxy_h2_backend_leg_init(leg, 77, NULL, &ent, 2, pool, bs);
    CHECK(leg->leg_ep_xip == htonl(0x0a000205) && leg->leg_ep_xport == htons(8002),
          "and keeps its endpoint's address from creation, for the client's end line");
    CHECK(leg->pd_decode_ep_idx == -1,
          "a new leg holds no decode unit (pd_decode_ep_idx %d)", leg->pd_decode_ep_idx);
    CHECK(leg->pd_prefill_ep_idx == -1,
          "a new leg holds no prefill unit (pd_prefill_ep_idx %d)", leg->pd_prefill_ep_idx);
    CHECK(leg->epv == pool && leg->ep_num == 2 && leg->odir == 1 &&
          leg->backend_h2_session == bs,
          "and keeps its pool and endpoint as its slot identity");
    sp_pool_hold(&leg->epv, NULL);
    sp_pool_unlinked(pool);   /* never linked: the allocation's own reference */
    for (int i = 0; i < 16 && sp_qsbr_pending(); i++)
      sp_qsbr_run_ready();
    free(bs);
    free(leg);
  }

  proxy_h2_cleanup_session(client);   /* frees sess and its server session */
  nghttp2_session_del(cl);
  nghttp2_session_callbacks_del(gcb);
  nghttp2_session_callbacks_del(ccb);
  free(client);
  free(legA);
  free(legB);

  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
