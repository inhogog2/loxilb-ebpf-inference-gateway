#!/usr/bin/env python3
"""Execute the production async retry selector against actual FC CAS state."""
from pathlib import Path
import os
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parent
source = (ROOT / "sockproxy_ep.c").read_text()
start = source.index("static int\nsp_mcp_retry_reserve(")
end = source.index("/* =========================================================================", start)
helper = source[start:end]
PREFIX = r'''
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "sockproxy_fc.h"
#define MAX_PROXY_EP 32
typedef struct {int n_eps,mcp_stateless;uint32_t _id;fc_state_t fc;
 struct {uint32_t xip;uint16_t xport;uint8_t protocol;} eps[32];} proxy_epval_t;
typedef struct {fc_permit_t fc;void *epv,*head;int mcp_route_active,ep_num,mcp_retry_pending;
 uint32_t mcp_route_mask,mcp_retry_excluded;} proxy_fd_ent_t;
typedef struct {struct {int ep_cfd,ep_num,connect_pending;} ep_cfds[32];int n_eps;} proxy_ep_sel_t;
static struct { _Atomic uint64_t pd_connect_failover;} global_stats;
static int tls_enabled;
static void *proxy_ent_epctx(void *head){(void)head;return tls_enabled ? (void *)1:NULL;}
static int dial_result[32],dial_count[32],failed,answered,probes;
static int sp_mcp_candidate(proxy_epval_t *pool,int c){(void)pool;(void)c;return 1;}
static int sp_mcp_reserve_probe(proxy_epval_t *pool,int c){(void)pool;(void)c;probes++;return 1;}
static int proxy_setup_ep_connect_async(uint32_t c,uint16_t port,uint8_t protocol,
 proxy_fd_ent_t *pfe,const void *hdr,int len,int *pending){
 (void)port;(void)protocol;(void)hdr;(void)len;
 /* Every socket must follow a capacity reservation; retained pool permit. */
 assert(pfe->fc.ep[0]==(int)c && pfe->fc.state==FC_P_EXECUTING);
 dial_count[c]++;*pending=dial_result[c]>0;return dial_result[c]<0?-1:100+(int)c;
}
static void circuit_breaker_record_failure(proxy_epval_t *p,int c){(void)p;(void)c;failed++;}
static void circuit_breaker_record_success(proxy_epval_t *p,int c){(void)p;(void)c;}
static void proxy_send_backend_unreachable(proxy_fd_ent_t *p,const char *s){(void)p;(void)s;answered++;}
#define lb_err_body_sent unused
'''
# Production struct includes the local response marker.
PREFIX = PREFIX.replace('uint32_t mcp_route_mask,mcp_retry_excluded;',
                         'int unused;uint32_t mcp_route_mask,mcp_retry_excluded;')
SUFFIX = r'''
int main(void){
 proxy_epval_t pool={.n_eps=4,.mcp_stateless=1,._id=42};
 for(int c=0;c<4;c++){pool.eps[c].xip=c;pool.eps[c].protocol=6;}
 proxy_fd_ent_t req={.epv=&pool,.mcp_route_active=1,.mcp_route_mask=7,
  .ep_num=0,.mcp_retry_pending=1,.mcp_retry_excluded=1};
 fc_cfg_t cfg={.mode=FC_MODE_ENFORCE,.max_outstanding=8,.ep_cap={1,0,0}};
 fc_state_init(&pool.fc);fc_state_apply(&pool.fc,&cfg);
 assert(fc_service_acquire(&pool.fc,&req.fc)==FC_ADMIT);
 assert(fc_ep_acquire(&pool.fc,&req.fc,0,0)==FC_ADMIT);
 uint64_t admitted=atomic_load(&pool.fc.decisions[FC_R_ADMITTED]);
 proxy_ep_sel_t out={0};proxy_epval_t *selected=0;uint32_t rid=0;
 tls_enabled=1;
 assert(proxy_setup_mcp_retry(&req,&out,&selected,&rid,NULL,0)<0);
 assert(dial_count[1]==0 && req.fc.ep[0]==0 && req.mcp_retry_pending);
 tls_enabled=0;
 dial_result[1]=-1;dial_result[2]=1;
 assert(!proxy_setup_mcp_retry(&req,&out,&selected,&rid,NULL,0));
 assert(selected==&pool&&rid==42&&out.n_eps==1&&out.ep_cfds[0].ep_num==2);
 assert(out.ep_cfds[0].connect_pending==1&&req.mcp_retry_pending==0);
 assert(dial_count[0]==0&&dial_count[1]==1&&dial_count[2]==1&&dial_count[3]==0);
 assert(req.mcp_retry_excluded==7&&failed==1&&probes==2);
 assert(req.fc.ep[0]==2&&fc_inflight(&pool.fc)==1&&fc_ep_inflight(&pool.fc,0,0)==0);
 /* A second async failure can never revisit the earlier two sockets. */
 req.ep_num=2;req.mcp_retry_pending=1;
 assert(proxy_setup_mcp_retry(&req,&out,&selected,&rid,NULL,0)<0);
 assert(answered==1&&!req.mcp_retry_pending&&req.fc.ep[0]==-1);
 assert(dial_count[1]==1&&dial_count[2]==1&&dial_count[3]==0);
 assert(fc_inflight(&pool.fc)==1&&atomic_load(&pool.fc.decisions[FC_R_ADMITTED])==admitted);
 fc_permit_release(&req.fc);assert(!fc_inflight(&pool.fc));
 /* Full in-route endpoint plus free out-of-route endpoint cannot escape. */
 fc_permit_t hold;assert(fc_service_acquire(&pool.fc,&hold)==FC_ADMIT);
 assert(fc_ep_acquire(&pool.fc,&hold,1,0)==FC_ADMIT);
 assert(fc_service_acquire(&pool.fc,&req.fc)==FC_ADMIT);
 req.ep_num=0;req.mcp_route_mask=3;req.mcp_retry_excluded=1;req.mcp_retry_pending=1;
 assert(proxy_setup_mcp_retry(&req,&out,&selected,&rid,NULL,0)<0);
 assert(dial_count[1]==1&&dial_count[2]==1&&dial_count[3]==0&&fc_ep_inflight(&pool.fc,1,0)==1);
 fc_permit_release(&req.fc);fc_permit_release(&hold);
 assert(!fc_inflight(&pool.fc)&&!atomic_load(&fc_anomaly_total[FC_A_UNDERFLOW]));
 fc_state_destroy(&pool.fc);
 puts("PASS production async retry bounded attempts, route scope, capacity reservation and single admission");
}
'''
with tempfile.TemporaryDirectory(prefix="mcp-async-retry-") as tmp:
    c, exe = Path(tmp)/"retry.c", Path(tmp)/"retry"
    c.write_text(PREFIX + helper + SUFFIX)
    subprocess.run([os.environ.get("CC", "clang"), "-std=c11", "-D_POSIX_C_SOURCE=200809L",
                    "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-pthread",
                    "-I", str(ROOT), str(c), str(ROOT/"sockproxy_fc.c"), "-o", str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
