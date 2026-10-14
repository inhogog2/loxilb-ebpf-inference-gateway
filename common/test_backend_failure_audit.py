#!/usr/bin/env python3
"""Run production H1 local-failure/complete code with callback capture."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parent
source = (root / 'sockproxy_http.c').read_text()
if os.environ.get('AUDIT_TEST_SOURCE'):
    source = Path(os.environ['AUDIT_TEST_SOURCE']).read_text()
a = source.index('static int\nproxy_owes_completion(')
b = source.index('static const char *strnstr_portable', a)
c = source.index('int\nproxy_send_backend_unreachable(')
d = source.index('\nstatic int\nproxy_send_local_100_continue', c)
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef struct {
 int odir, ai_gw_mode, metric_ai_recorded, metric_response_status, fc;
 uint64_t metric_req_start_ns;
 int usage_prompt_toks, usage_complet_toks, auth_src, adm_priority;
 int adm_class_set, adm_class, adm_objective_denied, adm_hint_not_applied;
 char tenant_id[32], auth_user_id[32], auth_key_id[32], l7_peer_ip[32];
 char auth_net_identity[32], adm_objective[32], request_id[32], model[32];
} proxy_fd_ent_t;
static int emitted, released, sent, send_rc, observed_status;
static char observed_request[32], observed_tenant[32], observed_key[32];
static uint64_t get_timestamp_ns(void){return 2000000;}
static const char *proxy_effective_model(proxy_fd_ent_t *p){return p->model;}
static const char *proxy_request_id(proxy_fd_ent_t *p){return p->request_id;}
static const char *proxy_origin_ip(proxy_fd_ent_t *p){return p->l7_peer_ip;}
static int proxy_origin_trusted_hops(proxy_fd_ent_t *p){(void)p;return 0;}
static int notify_worker_id(void){return 2;}
static void proxy_pfe_svc_ident(proxy_fd_ent_t *p,char *s,size_t n){(void)p;snprintf(s,n,"lab-service");}
static void fc_permit_release(int *p){if(*p){released++;*p=0;}}
#define AI_GW_CLASS_INFO(a,b,c,d) 0
static void capture(const char *t,int status,const char *r,const char *k){
 emitted++;observed_status=status;
 snprintf(observed_tenant,sizeof(observed_tenant),"%s",t);
 snprintf(observed_request,sizeof(observed_request),"%s",r);
 snprintf(observed_key,sizeof(observed_key),"%s",k);
}
#define llb_ai_record_request(t,m,st,lat,ti,to,a,b,c,r,u,k,svc,stream,worker,peer,origin,hops,auth,net,prio,cls,obj) \
 ((void)(m),(void)(lat),(void)(ti),(void)(to),(void)(svc),(void)(worker),(void)(origin),(void)(hops),capture(t,st,r,k))
static int proxy_send_local_response(proxy_fd_ent_t *p,const void *buf,size_t n){
 (void)p;sent++;
 assert(n==strlen(buf));assert(strstr(buf,"HTTP/1.1 502 Bad Gateway\r\n"));
 assert(strstr(buf,"Content-Length:"));assert(strstr(buf,"backend_unreachable"));
 return send_rc;
}
'''
suffix = r'''
static proxy_fd_ent_t request(void){
 proxy_fd_ent_t p={.ai_gw_mode=1,.metric_req_start_ns=1000000,.fc=1};
 strcpy(p.tenant_id,"tenant-a");strcpy(p.auth_key_id,"opaque-key-id");
 strcpy(p.request_id,"test-request-a");strcpy(p.model,"model-a");return p;
}
int main(void){
 proxy_fd_ent_t p=request();
 assert(proxy_send_backend_unreachable(&p,"connect failed")==0);
 assert(emitted==1 && observed_status==502 && p.metric_response_status==502);
 assert(!strcmp(observed_request,"test-request-a"));
 assert(!strcmp(observed_tenant,"tenant-a") && !strcmp(observed_key,"opaque-key-id"));
 assert(released==1 && p.metric_ai_recorded && !p.fc);
 proxy_ai_record_completion(&p); /* teardown or next-request boundary */
 proxy_send_backend_unreachable(&p,"another terminal notification");
 assert(emitted==1 && released==1);
 p=request();send_rc=-1;
 assert(proxy_send_backend_unreachable(&p,"TLS refused")==-1);
 assert(emitted==2 && observed_status==502 && released==2);
 p=request();p.ai_gw_mode=0;proxy_send_backend_unreachable(&p,"raw proxy");
 p=request();p.odir=1;proxy_send_backend_unreachable(&p,"backend leg");
 p=request();p.metric_response_status=200;proxy_send_backend_unreachable(&p,"response began");
 assert(p.metric_response_status==200);
 p=request();p.metric_ai_recorded=1;proxy_send_backend_unreachable(&p,"already recorded");
 assert(emitted==2 && sent==7);
 puts("backend-failure audit: identity/status, once-only, send failure, non-AI/backend/started guards PASS");
}
'''
with tempfile.TemporaryDirectory() as td:
    p=Path(td);(p/'test.c').write_text(prefix+source[a:b]+source[c:d]+suffix)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-o',str(p/'test'),str(p/'test.c')],check=True)
    subprocess.run([str(p/'test')],check=True)
