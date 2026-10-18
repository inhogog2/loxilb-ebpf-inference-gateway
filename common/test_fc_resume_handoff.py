#!/usr/bin/env python3
"""Exercise production resume/drain handoff in both deterministic lock orders.

Only surrounding transport is stubbed. The extracted production functions run
with real pthread rwlocks; --mutation-check requires the old unlocked handoff
to fail. This component test is not a deployed Gateway qualification.
"""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent
source = (root / 'sockproxy_http.c').read_text()
a = source.index('void\npd_resume_parked(int fd)')
b = source.index('\n/* The writable or error event', a)
resume = source[a:b]
a = source.index('struct sp_fc_drain_ctx {')
b = source.index('\nvoid\nsp_fc_drain_pool', a)
drain = source[a:b]
mutation = sys.argv[1:] == ['--mutation-check']
if sys.argv[1:] and not mutation:
    raise SystemExit('usage: test_fc_resume_handoff.py [--mutation-check]')
if mutation:
    resume = resume.replace('PROXY_RDLOCK();', '(void)0;').replace('PROXY_UNLOCK();', '(void)0;')
prefix = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
enum { FC_P_NONE, FC_P_QUEUED, PD_PHASE_NONE, PD_PHASE_PARKED,
       PD_PHASE_ERROR, SP_REAP_FC_SHED, SP_FWD_PARKED, SP_FWD_CONNECTING,
       SP_FWD_KEPT, SP_FWD_RESTART, NOTI_TYPE_IN=32, NOTI_TYPE_HUP=64 };
typedef struct { void *fc; int state,woken,q_parked,q_fd;
                 uint64_t q_gen,q_enqueue_ns; } permit;
typedef struct { int fd, pd_phase, reap_resp, read_paused, park_ep_idx;
                 int park_start_ts,http_hvok; const char *host_url;
                 _Atomic uint64_t gen; permit fc; } proxy_fd_ent_t;
typedef struct { int fd; uint64_t gen; } fc_queue_ent_t;
struct llb_sockmap_key { int unused; };
static struct { void *ns; pthread_rwlock_t lock; } global;
static void *proxy_struct_ptr = &global;
#define proxy_struct ((typeof(global) *)proxy_struct_ptr)
static proxy_fd_ent_t client;
static _Atomic int attempted,claim_entered,sweep_attempted;
static int mode,pending,forwarded,answered,reaped,held;
#define log_warn(...) ((void)0)
#define log_debug(...) ((void)0)
#define log_error(...) ((void)0)
static void rdlock(void) { atomic_store(&attempted,1); assert(!pthread_rwlock_rdlock(&global.lock)); held=1; }
static void unlock(void) { held=0; assert(!pthread_rwlock_unlock(&global.lock)); }
#define PROXY_RDLOCK() rdlock()
#define PROXY_UNLOCK() unlock()
static void *notify_priv_of_fd(void *ns,int fd,uint64_t *gen) { (void)ns;(void)fd;*gen=7;return &client; }
static int qos_resume_reader(int fd,proxy_fd_ent_t *p) { (void)fd;(void)p;return mode==5; }
static int fc_queue_evicted_claim(void *fc,int fd,uint64_t gen) {
  (void)fc;(void)fd;(void)gen;
  if(mode==1) {
    atomic_store(&claim_entered,1);
    while(!atomic_load(&sweep_attempted)) sched_yield();
    /* The sweep is excluded through the owner taking its eviction. */
    assert(held);
  }
  int got=pending;pending=0;return got;
}
static int fc_queue_holds(void *fc,permit *p) {(void)fc;(void)p;return mode==3;}
static void fc_queue_resumed(void *fc,permit *p,uint64_t now) {(void)fc;(void)now;assert(held);p->state=FC_P_NONE;p->woken=1;}
static void fc_permit_unbind(permit *p) {p->fc=NULL;}
static void sp_reap_request(proxy_fd_ent_t *p,uint8_t kind) {p->reap_resp=kind;}
static void sp_reap_finish(proxy_fd_ent_t *p) {(void)p;assert(!held);reaped++;}
static int sp_h1_refusal_keeps_connection(proxy_fd_ent_t *p) {(void)p;return 1;}
static int sp_fc_shed_answer_kept(proxy_fd_ent_t *p) {(void)p;assert(!held);answered++;return 0;}
static void cresp_note_local_answer(proxy_fd_ent_t *p) {(void)p;}
static void sp_h1_kept_request_reset(proxy_fd_ent_t *p) {(void)p;}
static void sp_notify_arm(void *ns,int fd,int flags,proxy_fd_ent_t *p,uint64_t gen) {(void)ns;(void)fd;(void)flags;(void)p;(void)gen;}
static uint64_t qos_now_ns(void) {return 100;}
static int pd_setup_and_forward(int fd,proxy_fd_ent_t *p,void *k,void *r,const char *h) {
  (void)fd;(void)p;(void)k;(void)r;(void)h;assert(!held);forwarded++;return SP_FWD_KEPT;
}
static void notify_delete_ent(void *ns,int fd,int evict) {(void)ns;(void)fd;(void)evict;abort();}
'''
suffix = r'''
static void reset(int which) {
 memset(&client,0,sizeof(client)); client.fd=9;client.gen=7;
 client.pd_phase=PD_PHASE_PARKED;client.fc.state=FC_P_QUEUED;
 client.fc.fc=&global;client.fc.q_fd=9;client.fc.q_gen=7;
 mode=which;pending=1;forwarded=answered=reaped=held=0;
 attempted=claim_entered=sweep_attempted=0;
}
static void *owner(void *unused) {(void)unused;pd_resume_parked(9);return NULL;}
static void publish_shed(void) {
 fc_queue_ent_t e={.fd=9,.gen=7};
 struct sp_fc_drain_ctx ctx={.kind=SP_REAP_FC_SHED};
 pending=0;assert(sp_fc_drain_cb(&ctx,&e)==1);
}
static void *sweep_second(void *unused) {
 (void)unused;
 while(!atomic_load(&claim_entered)) sched_yield();
 int rc=pthread_rwlock_trywrlock(&global.lock);
 assert(rc==EBUSY);atomic_store(&sweep_attempted,1);
 assert(!pthread_rwlock_wrlock(&global.lock));
 if(pending) publish_shed();
 assert(!pthread_rwlock_unlock(&global.lock));return NULL;
}
int main(void) {
 pthread_t worker,sweep;global.ns=&global;
 assert(!pthread_rwlock_init(&global.lock,NULL));
 /* Sweep has removed the entry but has not published its response yet. */
 reset(0);assert(!pthread_rwlock_wrlock(&global.lock));pending=0;
 assert(!pthread_create(&worker,NULL,owner,NULL));
 while(!atomic_load(&attempted)) sched_yield();
 publish_shed();assert(!pthread_rwlock_unlock(&global.lock));
 assert(!pthread_join(worker,NULL));assert(reaped==1&&answered==0&&forwarded==0);
 puts("PASS sweep first: no replay between removal and reap publication");
 reset(1);assert(!pthread_create(&sweep,NULL,sweep_second,NULL));
 assert(!pthread_create(&worker,NULL,owner,NULL));
 assert(!pthread_join(worker,NULL));assert(!pthread_join(sweep,NULL));
 assert(answered==1&&reaped==0&&forwarded==0);
 puts("PASS owner first: one shed response and no sweep decision");
 reset(2);pending=0;pd_resume_parked(9);
 assert(forwarded==1&&answered==0&&reaped==0&&held==0);
 puts("PASS normal popped waiter: dispatch after releasing handoff lock");
 reset(3);pending=0;pd_resume_parked(9);
 assert(!forwarded&&!answered&&!reaped&&!held);
 assert(client.pd_phase==PD_PHASE_PARKED);
 puts("PASS still queued: remains parked and releases handoff lock");
 reset(4);client.pd_phase=PD_PHASE_NONE;pd_resume_parked(9);assert(!held&&!forwarded);
 puts("PASS duplicate resume: no dispatch, lock released");
 reset(5);pd_resume_parked(9);assert(!held&&!forwarded&&!reaped&&!answered);
 puts("PASS QoS resume: handoff lock released");
 reset(6);client.gen=8;pd_resume_parked(9);assert(!held&&!forwarded&&!reaped&&!answered);
 puts("PASS recycled generation: no handoff or dispatch");
 assert(!pthread_rwlock_destroy(&global.lock));return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='fc-resume-') as temp:
    path = Path(temp)
    (path / 'test.c').write_text(prefix + drain + resume + suffix)
    flags = shlex.split(os.environ.get('CFLAGS', '-O1 -g'))
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-pthread', *flags,
                    str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    try:
        result = subprocess.run([str(path / 'test')], timeout=10,
                                capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        if mutation:
            print('PASS mutation rejected: unlocked handoff cannot reach the lock barrier')
            raise SystemExit(0)
        raise
    print(result.stdout, end='')
    if mutation:
        if result.returncode == 0:
            raise SystemExit('FAIL mutation survived')
        print('PASS mutation rejected')
    else:
        if result.returncode:
            print(result.stderr, file=sys.stderr)
        raise SystemExit(result.returncode)
