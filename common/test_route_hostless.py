#!/usr/bin/env python3
"""A request that reaches dispatch with no usable Host (proxy_setup_ep__,
sockproxy_ep.c) is routed by sp_route_hostless's decision, never "the first
pool" on a listener whose pools name models (ROUTE-01's second defence).

The host_str == NULL branch of proxy_setup_ep__ and sp_route_model are
compiled from the source; sp_route_hostless (unit-tested in
test_model_routing.c) returns each decision in turn:
  MODEL   the pool that names the model; counted in route_host_missing
  REFUSE  503 model_unavailable (or no_route when the request names no
          model), a route-stage refusal; counted; dispatch ends (-1)
  FIRST   the first pool, as before; not counted
and the model it is asked for follows the routing priority. Each mutation in
MUTATIONS must turn this red (run with --mutations)."""
from pathlib import Path
import os, subprocess, sys, tempfile
root = Path(__file__).resolve().parent

def build(ep, hdr):
    m0 = ep.index('static const char *\nsp_route_model(')
    model = ep[m0:ep.index('\n}\n', m0) + 3]
    b0 = ep.index('        // Criterion A/C: the model, resolved once for both branches.\n')
    b1 = ep.index('        } else {\n          // Strip port from hostname', b0)
    branch = ep[b0:b1] + '        }\n'
    e0 = hdr.index('enum sp_hostless {')
    enum = hdr[e0:hdr.index('};', e0) + 2]
    return r'''
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define log_info(...) ((void)0)
#define AI_GW_STAGE_ROUTE 7
typedef struct proxy_fd_ent {
  char effective_model[64], x_model_header[64];
  struct { char model[64]; } prefix_key;
  int fd, lb_err_body_sent;
} proxy_fd_ent_t;
typedef struct proxy_epval { int id; } proxy_epval_t;
typedef struct proxy_map_ent { int id; } proxy_map_ent_t;
''' + enum + r'''
static struct { _Atomic uint64_t route_host_missing; } global_stats;
static int hl_ret; static proxy_epval_t *hl_pool; static char hl_model[64];
static int sp_route_hostless(const proxy_map_ent_t *e, const char *m, proxy_epval_t **p) {
  (void)e; snprintf(hl_model, sizeof(hl_model), "%s", m ? m : "(null)"); *p = hl_pool; return hl_ret; }
static int refusals, ref_stage, ref_status; static char ref_code[32], ref_body[512];
static int sp_send_local_refusal(proxy_fd_ent_t *pfe, int stage, uint16_t status, const char *code,
                                 const char *b, size_t n) {
  (void)pfe; refusals++; ref_stage = stage; ref_status = status;
  snprintf(ref_code, sizeof(ref_code), "%s", code); snprintf(ref_body, sizeof(ref_body), "%.*s", (int)n, b);
  return 0; }
''' + model + r'''
static int dispatch(proxy_fd_ent_t *pfe, proxy_map_ent_t *node, const char *host_str, proxy_epval_t **out) {
  proxy_epval_t *tepval = NULL;
''' + branch + r'''
  *out = tepval;
  return 0;
}
static int fails;
#define CHECK(c, m) do { if (!(c)) { printf("FAIL: %s\n", m); fails++; } } while (0)
int main(void) {
  proxy_map_ent_t node = {1}; proxy_epval_t b = {2}, first = {3}; proxy_epval_t *got;
  proxy_fd_ent_t c; memset(&c, 0, sizeof(c)); c.fd = 9;
  strcpy(c.prefix_key.model, "body-model"); strcpy(c.x_model_header, "hdr-model");
  strcpy(c.effective_model, "gate-model");

  hl_ret = SP_HOSTLESS_MODEL; hl_pool = &b;
  CHECK(dispatch(&c, &node, NULL, &got) == 0 && got == &b && refusals == 0,
        "MODEL: dispatch goes on with the pool that names the model");
  CHECK(strcmp(hl_model, "gate-model") == 0, "the admission gate's model is asked for first");
  CHECK(atomic_load(&global_stats.route_host_missing) == 1, "MODEL is counted");
  c.effective_model[0] = 0; dispatch(&c, &node, NULL, &got);
  CHECK(strcmp(hl_model, "hdr-model") == 0, "then the X-Model header");
  c.x_model_header[0] = 0; dispatch(&c, &node, NULL, &got);
  CHECK(strcmp(hl_model, "body-model") == 0, "then the body's model");
  c.prefix_key.model[0] = 0; dispatch(&c, &node, NULL, &got);
  CHECK(strcmp(hl_model, "") == 0, "then none");

  atomic_store(&global_stats.route_host_missing, 0);
  strcpy(c.effective_model, "model-z");
  hl_ret = SP_HOSTLESS_REFUSE; hl_pool = NULL;
  CHECK(dispatch(&c, &node, NULL, &got) == -1, "REFUSE: dispatch ends");
  CHECK(refusals == 1 && ref_status == 503 && ref_stage == AI_GW_STAGE_ROUTE &&
        strcmp(ref_code, "model_unavailable") == 0 && strstr(ref_body, "\"model\":\"model-z\"") &&
        strncmp(ref_body, "HTTP/1.1 503 ", 13) == 0 && c.lb_err_body_sent,
        "REFUSE: a 503 model_unavailable naming the model, refused at the route stage");
  c.effective_model[0] = 0; c.lb_err_body_sent = 0;
  CHECK(dispatch(&c, &node, NULL, &got) == -1 && refusals == 2 && strcmp(ref_code, "no_route") == 0 &&
        c.lb_err_body_sent, "REFUSE with no model: a 503 no_route");
  CHECK(atomic_load(&global_stats.route_host_missing) == 2, "REFUSE is counted");

  atomic_store(&global_stats.route_host_missing, 0);
  hl_ret = SP_HOSTLESS_FIRST; hl_pool = &first;
  CHECK(dispatch(&c, &node, NULL, &got) == 0 && got == &first && refusals == 2,
        "FIRST: the first pool, as before");
  CHECK(atomic_load(&global_stats.route_host_missing) == 0, "FIRST is not counted");
  hl_ret = SP_HOSTLESS_REFUSE; hl_pool = NULL;
  CHECK(dispatch(NULL, &node, NULL, &got) == 0 && got == NULL && refusals == 2,
        "no connection (raw path): nothing is sent, dispatch finds no pool");

  if (fails) return 1;
  puts("hostless dispatch: the pool that names the model, or a counted 503 route refusal; the first pool only where no pool names a model PASS");
  return 0;
}
'''

def run(ep, hdr):
    with tempfile.TemporaryDirectory() as t:
        p = Path(t)
        (p / 'test.c').write_text(build(ep, hdr))
        cc = os.environ.get('CC', 'cc')
        r = subprocess.run([cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                            '-fsanitize=address,undefined', '-o', str(p / 't'), str(p / 'test.c')],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return r.returncode, r.stderr
        r = subprocess.run([str(p / 't')], capture_output=True, text=True)
        return r.returncode, r.stdout

ep = (root / 'sockproxy_ep.c').read_text()
hdr = (root / 'sockproxy_routing.h').read_text()
MUTATIONS = {
  'the counter is dropped': ('            atomic_fetch_add(&global_stats.route_host_missing, 1);\n', ''),
  'a refusal falls through to dispatch': ('          if (hl == SP_HOSTLESS_REFUSE && pfe) {', '          if (0) {'),
  'the first pool is taken again': ('          int hl = sp_route_hostless(node, effective_model, &tepval);',
                                    '          int hl = sp_route_hostless(node, effective_model, &tepval);\n'
                                    '          if (hl == SP_HOSTLESS_MODEL) { tepval = NULL; }'),
  'the gate\'s model is not asked for first': ('  if (pfe && pfe->effective_model[0] != \'\\0\') {', '  if (0) {'),
}
if '--mutations' in sys.argv:
    killed = 0
    for name, (a, b) in MUTATIONS.items():
        assert ep.count(a) == 1, name
        rc, _ = run(ep.replace(a, b), hdr)
        killed += rc != 0
        print(('killed: ' if rc else 'SURVIVED: ') + name)
    print(f'test_route_hostless mutations: {killed}/{len(MUTATIONS)} killed')
    sys.exit(0 if killed == len(MUTATIONS) else 1)
rc, out = run(ep, hdr)
print(out, end='')
sys.exit(rc)
