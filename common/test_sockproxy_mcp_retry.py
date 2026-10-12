#!/usr/bin/env python3
"""Actual retry reservation helper + production FC CAS regression (no Gateway claim)."""
from pathlib import Path
import os
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parent
source = (ROOT / "sockproxy_ep.c").read_text()
start = source.index("static int\nsp_mcp_retry_reserve(")
end = source.index("/* Retry only the held request", start)
helper = source[start:end]
# These dispatch sites must remain wired; the helper alone cannot guard a dial.
assert "!sp_mcp_retry_reserve(tepval,pfe,cand)" in source
assert "fc_release_role(&pfe->fc, FC_ROLE_NORMAL); /* failed original dial */" in source
assert "if (tepval->mcp_stateless)\n                fc_release_role(&pfe->fc, FC_ROLE_NORMAL);\n              circuit_breaker_record_failure" in source
PREFIX = r'''
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "sockproxy_fc.h"
#define MAX_PROXY_EP 32
typedef struct {int n_eps;fc_state_t fc;} proxy_epval_t;
typedef struct {fc_permit_t fc;int mcp_route_active;uint32_t mcp_route_mask;} proxy_fd_ent_t;
static int probe_ok=1,probes;
static int sp_mcp_reserve_probe(proxy_epval_t *pool,int ep){(void)pool;(void)ep;probes++;return probe_ok;}
'''
SUFFIX = r'''
int main(void){
 proxy_epval_t pool={.n_eps=3};proxy_fd_ent_t req={.mcp_route_active=1,.mcp_route_mask=3};fc_permit_t hold;
 fc_cfg_t cfg={.mode=FC_MODE_ENFORCE,.max_outstanding=8,.ep_cap={1,0,0}};
 fc_state_init(&pool.fc);fc_state_apply(&pool.fc,&cfg);
 assert(fc_service_acquire(&pool.fc,&hold)==FC_ADMIT);
 assert(fc_ep_acquire(&pool.fc,&hold,1,FC_ROLE_NORMAL)==FC_ADMIT);
 assert(fc_service_acquire(&pool.fc,&req.fc)==FC_ADMIT);
 assert(fc_ep_acquire(&pool.fc,&req.fc,0,FC_ROLE_NORMAL)==FC_ADMIT);
 uint64_t admitted=atomic_load(&pool.fc.decisions[FC_R_ADMITTED]);
 fc_release_role(&req.fc,FC_ROLE_NORMAL); /* production original-failure boundary */
 assert(fc_inflight(&pool.fc)==2&&fc_ep_inflight(&pool.fc,0,0)==0);
 assert(!sp_mcp_retry_reserve(&pool,&req,1)); /* full candidate must not dial/probe */
 assert(probes==0&&req.fc.ep[0]==-1&&fc_ep_inflight(&pool.fc,1,0)==1);
 assert(!sp_mcp_retry_reserve(&pool,&req,2)); /* free but outside route */
 assert(!sp_mcp_retry_reserve(&pool,&req,-1));assert(!sp_mcp_retry_reserve(&pool,&req,32));assert(probes==0);
 fc_permit_release(&hold);assert(fc_inflight(&pool.fc)==1);
 probe_ok=0;assert(!sp_mcp_retry_reserve(&pool,&req,1));
 assert(probes==1&&req.fc.ep[0]==-1&&fc_ep_inflight(&pool.fc,1,0)==0);
 probe_ok=1;assert(sp_mcp_retry_reserve(&pool,&req,1));
 assert(probes==2&&req.fc.ep[0]==1&&fc_ep_inflight(&pool.fc,1,0)==1&&fc_inflight(&pool.fc)==1);
 for(int i=0;i<10000;i++) {
  fc_release_role(&req.fc,FC_ROLE_NORMAL); /* failed retry dial */
  assert(fc_ep_inflight(&pool.fc,1,0)==0&&fc_inflight(&pool.fc)==1);
  assert(sp_mcp_retry_reserve(&pool,&req,1));
 }
 assert(atomic_load(&pool.fc.decisions[FC_R_ADMITTED])==admitted);
 fc_permit_release(&req.fc);assert(!fc_inflight(&pool.fc)&&!fc_ep_inflight(&pool.fc,1,0));
 assert(!atomic_load(&fc_anomaly_total[FC_A_UNDERFLOW]));
 fc_state_destroy(&pool.fc);
 /* Default/off takes no permit and still performs the final health probe. */
 fc_state_init(&pool.fc);cfg.mode=FC_MODE_OFF;fc_state_apply(&pool.fc,&cfg);
 assert(fc_service_acquire(&pool.fc,&req.fc)==FC_ADMIT&&req.fc.state==FC_P_BYPASS);
 int before=probes;assert(sp_mcp_retry_reserve(&pool,&req,1));assert(probes==before+1);
 assert(!fc_inflight(&pool.fc)&&!fc_ep_inflight(&pool.fc,1,0));fc_permit_release(&req.fc);
 fc_state_destroy(&pool.fc);
 /* Observe records pressure but preserves the documented unbounded dispatch. */
 fc_state_init(&pool.fc);cfg.mode=FC_MODE_OBSERVE;fc_state_apply(&pool.fc,&cfg);
 assert(fc_service_acquire(&pool.fc,&hold)==FC_ADMIT);assert(fc_ep_acquire(&pool.fc,&hold,1,0)==FC_ADMIT);
 assert(fc_service_acquire(&pool.fc,&req.fc)==FC_ADMIT);assert(fc_ep_acquire(&pool.fc,&req.fc,0,0)==FC_ADMIT);
 fc_release_role(&req.fc,0);before=probes;assert(sp_mcp_retry_reserve(&pool,&req,1));
 assert(probes==before+1&&fc_ep_inflight(&pool.fc,1,0)==2&&fc_inflight(&pool.fc)==2);
 assert(atomic_load(&pool.fc.decisions[FC_R_OBSERVE_WOULD_SHED])==1);
 fc_permit_release(&req.fc);fc_permit_release(&hold);assert(!fc_inflight(&pool.fc)&&!fc_ep_inflight(&pool.fc,1,0));
 fc_state_destroy(&pool.fc);
 puts("PASS actual MCP retry FC enforce/off/observe, route exclusion, health race, 10000 releases");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix="mcp-retry-") as tmp:
    c = Path(tmp) / "retry.c"
    exe = Path(tmp) / "retry"
    c.write_text(PREFIX + helper + SUFFIX)
    subprocess.run([os.environ.get("CC", "clang"), "-std=c11", "-D_POSIX_C_SOURCE=200809L",
                    "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer", "-g", "-pthread", "-I", str(ROOT),
                    str(c), str(ROOT / "sockproxy_fc.c"), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
