#!/usr/bin/env python3
"""Every reaper that ends an answer the client was already receiving leaves
exactly one request record (loxilb_ai_requests_total) with the status the
client received: completed/200.

The production reaper writers run on the owner worker (sp_reap_finish and
sp_reap_record, sockproxy_health.c) with the production request recorders
(sockproxy_http.c), against a client whose 200 has gone out and whose record
is still owed (it waits for the [DONE] scanner or the usage object). Then the
connection ends the way that reaper kind ends it:
  - a teardown kind goes through pd_teardown_conn, which frees the client
    inline: proxy_pdestroy, and the record a teardown owes, never run there;
  - a shutdown kind (the SSE duration cap, the stalled client) is cleaned up
    by the event loop: proxy_pdestroy collects what the connection owes by
    the shared rule (sockproxy_teardown_settle.h) and writes it.
Both models are tied to the source below. The twin is the same reaper before
any answer began: its own status, once."""
from pathlib import Path
import os, re, subprocess, sys, tempfile
root = Path(__file__).resolve().parent
health = (root / 'sockproxy_health.c').read_text()
http = (root / 'sockproxy_http.c').read_text()
if os.environ.get('REAP_TEST_HEALTH'):
    health = Path(os.environ['REAP_TEST_HEALTH']).read_text()
if os.environ.get('REAP_TEST_HTTP'):
    http = Path(os.environ['REAP_TEST_HTTP']).read_text()

def body(src, start):
    i = src.index(start)
    return src[i:src.index('\n}\n', i) + 3]

# The teardown each kind gets is the model's only assumption; check it.
td = body(health, 'static int\npd_teardown_conn(')
assert 'proxy_try_free_fd_ctx(client);' in td, 'pd_teardown_conn no longer frees the client inline'
for rec in ('proxy_collect_conn_settles', 'llb_ai_record_request', 'proxy_ai_record_completion',
            'proxy_record_'):
    assert rec not in td, 'pd_teardown_conn now records (%s): update this model' % rec
pd = body(http, 'static void\nproxy_collect_conn_settles(')
assert 'u->owes_record  = teardown_owes_completion(&v);' in pd
assert re.search(r'if \(u->owes_record\) \{\s*llb_ai_record_request\(', http), \
    'proxy_pdestroy no longer writes the record a teardown owes'

t0 = health.index('typedef struct sp_reap_text {')
t1 = health.index('\n};\n', health.index('[SP_REAP_SSE_STALL]', t0)) + 4
reaper = (health[t0:t1] + body(health, 'static int\nsp_reap_client_chunked(')
          + body(health, 'static size_t\nsp_reap_body_frame(')
          + body(health, 'static void\nsp_reap_record(')
          + body(health, 'void\nsp_reap_finish(proxy_fd_ent_t *pfe)'))
a = http.index('static int\nproxy_owes_completion(')
b = http.index('static const char *strnstr_portable', a)
recorders = (http[a:b] + body(http, 'void\nproxy_record_local_completion(')
             + body(http, 'static void\nproxy_teardown_view('))

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include "llhttp.h"
#include "sockproxy_teardown_settle.h"
#define log_warn(...) ((void)0)
#define log_error(...) ((void)0)
#define log_debug(...) ((void)0)
#define PROXY_LOCK() ((void)0)
#define PROXY_UNLOCK() ((void)0)
#define AI_GW_STAGE_CAPACITY 3
#define AI_GW_CLASS_INFO(a,b,c,d) 0
typedef struct proxy_fd_ent proxy_fd_ent_t;
struct proxy_fd_ent {
  int fd, odir, ai_gw_mode, metric_ai_recorded, metric_response_status, noted, fc;
  int usage_reserved_toks, usage_consumed, usage_prompt_toks, usage_complet_toks;
  int auth_src, adm_priority, adm_class_set, adm_class, adm_objective_denied, adm_hint_not_applied;
  void *h2_session; uint8_t sse_active, reap_resp; time_t stream_start_ts;
  _Atomic uint8_t cresp_in_msg, cresp_answer_open; llhttp_t cresp_parser;
  uint64_t metric_req_start_ns;
  char tenant_id[32], auth_user_id[32], auth_key_id[32], l7_peer_ip[32];
  char auth_net_identity[32], adm_objective[32], request_id[32], model[32];
};
enum { SP_REAP_NONE = 0, SP_REAP_SSE_CAP, SP_REAP_PD_PREFILL_TIMEOUT, SP_REAP_PD_DECODE_TIMEOUT,
  SP_REAP_PD_PARK_TIMEOUT, SP_REAP_PD_GRACEFUL_DONE, SP_REAP_PD_STREAM_TIMEOUT, SP_REAP_PD_IDLE_TIMEOUT,
  SP_REAP_FC_QUEUE_TIMEOUT, SP_REAP_FC_DRAINED, SP_REAP_SSE_STALL, SP_REAP_KINDS };
static int records, record_status, record_stream, freed_inline;
static void capture(int status, int stream) { records++; record_status = status; record_stream = stream; }
#define llb_ai_record_request(t,m,st,lat,ti,to,a,b,c,r,u,k,svc,stream,worker,peer,origin,hops,auth,net,prio,cls,obj) \
 ((void)(t),(void)(m),(void)(lat),(void)(ti),(void)(to),(void)(r),(void)(u),(void)(k),(void)(svc),(void)(worker), \
  (void)(peer),(void)(origin),(void)(hops),(void)(auth),(void)(net),(void)(prio),(void)(cls),(void)(obj),capture(st,stream))
static uint64_t get_timestamp_ns(void) { return 2000000; }
static const char *proxy_effective_model(proxy_fd_ent_t *p) { return p->model; }
static const char *proxy_request_id(proxy_fd_ent_t *p) { return p->request_id; }
static const char *proxy_origin_ip(proxy_fd_ent_t *p) { return p->l7_peer_ip; }
static int proxy_origin_trusted_hops(proxy_fd_ent_t *p) { (void)p; return 0; }
static int notify_worker_id(void) { return 2; }
static void proxy_pfe_svc_ident(proxy_fd_ent_t *p, char *s, size_t n) { (void)p; snprintf(s, n, "svc"); }
static void fc_permit_release(int *p) { *p = 0; }
/* The response record's latch, as the product keeps it: once per request,
 * client leg only, and it sets the status. */
static int proxy_note_local_answer(proxy_fd_ent_t *p, uint16_t s) {
  if (p->odir || p->noted) return 0;
  p->noted = 1; p->metric_response_status = s; return 1;
}
static int proxy_note_local_refusal(proxy_fd_ent_t *p, uint16_t s) {
  int n = proxy_note_local_answer(p, s); if (n) p->metric_ai_recorded = 1; return n;
}
static void proxy_record_local_deny(proxy_fd_ent_t *p, int st, int s, const char *c) { (void)p; (void)st; (void)s; (void)c; }
static size_t sp_reap_fc_format(proxy_fd_ent_t *p, uint8_t k, char *o, size_t c) { (void)p; (void)k; (void)o; (void)c; return 0; }
static int sp_answer_started(proxy_fd_ent_t *p) { return atomic_load(&p->cresp_in_msg) || atomic_load(&p->cresp_answer_open); }
static void sp_end_started_answer(proxy_fd_ent_t *p, const void *b, size_t n) { (void)p; (void)b; (void)n; }
static int proxy_send_local_response_and_shutdown(proxy_fd_ent_t *p, const void *b, size_t n) { (void)p; (void)b; (void)n; return 0; }
/* Frees the client inline: proxy_pdestroy never runs for it (checked above). */
static int pd_teardown_conn(proxy_fd_ent_t *p) { (void)p; freed_inline++; return 1; }
'''

main = r'''
static const char *kname(int k) {
  switch (k) {
  case SP_REAP_PD_GRACEFUL_DONE: return "graceful-[DONE] sweep";
  case SP_REAP_PD_STREAM_TIMEOUT: return "stream-silence (ERR-01)";
  case SP_REAP_PD_IDLE_TIMEOUT: return "generic idle reaper";
  case SP_REAP_SSE_CAP: return "duration cap";
  case SP_REAP_SSE_STALL: return "stalled client";
  default: return "?";
  }
}
static llhttp_settings_t cs;
static proxy_fd_ent_t client(int answered) {
  proxy_fd_ent_t c;
  memset(&c, 0, sizeof(c));
  c.fd = 9; c.ai_gw_mode = 1; c.fc = 1; c.metric_req_start_ns = 1000000;
  strcpy(c.tenant_id, "tenant-a"); strcpy(c.model, "model-a"); strcpy(c.request_id, "req-a");
  llhttp_settings_init(&cs);
  llhttp_init(&c.cresp_parser, HTTP_RESPONSE, &cs);
  if (answered) {
    /* the 200 went out; the record waits for the [DONE] scanner */
    static const char h[] = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert(llhttp_execute(&c.cresp_parser, h, strlen(h)) == HPE_OK);
    c.noted = 1; c.metric_response_status = 200;
    atomic_store(&c.cresp_in_msg, 1); atomic_store(&c.cresp_answer_open, 1);
    c.stream_start_ts = 100;
  }
  return c;
}
/* The reaper's hand-off on the owner worker, then the end of the connection. */
static void reap(proxy_fd_ent_t *c, int k) {
  records = 0; freed_inline = 0;
  c->sse_active = 0;   /* every body kind's reaper ends the stream gauge first */
  c->reap_resp = (uint8_t)k;
  sp_reap_finish(c);
  if (!sp_reap_texts[k].teardown) {
    /* a shutdown: the event loop's proxy_pdestroy settles what is owed */
    teardown_conn_t v;
    proxy_teardown_view(c, &v);
    if (teardown_conn_owes_settle(TEARDOWN_CONN, &v) && teardown_owes_completion(&v)) {
      capture(c->metric_response_status, 0);
      c->metric_ai_recorded = 1;
    }
  } else {
    assert(freed_inline == 1);
  }
}
int main(void) {
  static const int kinds[] = { SP_REAP_PD_GRACEFUL_DONE, SP_REAP_PD_STREAM_TIMEOUT,
                               SP_REAP_PD_IDLE_TIMEOUT, SP_REAP_SSE_CAP, SP_REAP_SSE_STALL };
  int bad = 0;
  for (unsigned i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
    int k = kinds[i];
    proxy_fd_ent_t c = client(1);
    reap(&c, k);
    if (records)
      printf("  after a 200: %-24s -> %d request record(s), status %d\n", kname(k), records, record_status);
    else
      printf("  after a 200: %-24s -> no request record\n", kname(k));
    if (records != 1 || record_status != 200) bad = 1;
  }
  /* The twins: the same reapers before any answer began write their own
   * status, once (the SSE kinds have no answer to end there). */
  {
    static const struct { int k, status; } twin[] = {
      { SP_REAP_PD_STREAM_TIMEOUT, 502 }, { SP_REAP_PD_IDLE_TIMEOUT, 504 },
    };
    for (unsigned i = 0; i < sizeof(twin) / sizeof(twin[0]); i++) {
      proxy_fd_ent_t c = client(0);
      reap(&c, twin[i].k);
      printf("  no answer yet: %-23s -> %d request record(s), status %d\n", kname(twin[i].k),
             records, record_status);
      if (records != 1 || record_status != twin[i].status) bad = 1;
    }
  }
  if (bad) { puts("FAIL: a reaped answer has no request record, or more than one"); return 1; }
  puts("reaped answers: every reaper after a 200 leaves one request record, completed/200; before an answer, its own status, once PASS");
  return 0;
}
'''

with tempfile.TemporaryDirectory() as tdir:
    p = Path(tdir)
    (p / 'test.c').write_text(prefix + recorders + reaper + main)
    cc = os.environ.get('CC', 'cc')
    subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-Wno-missing-field-initializers',
                    '-fsanitize=address,undefined',
                    '-I', str(root), '-o', str(p / 'rec'), str(p / 'test.c'),
                    str(root / 'llhttp.c'), str(root / 'http.c'), str(root / 'httpapi.c')],
                   check=True)
    sys.exit(subprocess.run([str(p / 'rec')]).returncode)
