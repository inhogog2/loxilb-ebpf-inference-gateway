/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "security_aggregate.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct security_aggregate_state shared;
static struct security_aggregate_budget budget = { .version=1, .syn=17 };
static unsigned int admitted;
static void *worker(void *unused) {
    (void)unused;
    for (int i=0;i<1000;i++) {
        pthread_mutex_lock(&mutex);
        admitted += security_aggregate_decide(&shared,&budget,10,1,0,40)==0;
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}
int main(void) {
    pthread_t threads[8];
    for (int i=0;i<8;i++) assert(pthread_create(&threads[i],NULL,worker,NULL)==0);
    for (int i=0;i<8;i++) assert(pthread_join(threads[i],NULL)==0);
    assert(admitted==17 && shared.syn_count==18);
    assert(security_aggregate_decide(&shared,&budget,11,1,0,40)==0);
    budget.version=2;budget.syn=0;budget.conn=1;
    assert(security_aggregate_decide(&shared,&budget,11,1,0,40)==0);
    assert(security_aggregate_decide(&shared,&budget,11,1,0,40)==2);
    budget.version=3;budget.conn=0;budget.udp=10;budget.bytes=100;
    assert(security_aggregate_decide(&shared,&budget,11,0,1,40)==0);
    assert(security_aggregate_decide(&shared,&budget,11,0,1,40)==0);
    assert(security_aggregate_decide(&shared,&budget,11,0,1,40)==3);
    assert(security_aggregate_decide(&shared,&budget,12,0,1,101)==3);
    budget.version=4;budget.bytes=0;budget.udp=1;
    assert(security_aggregate_decide(&shared,&budget,12,0,1,65535)==0);
    assert(security_aggregate_decide(&shared,&budget,12,0,1,1)==3);
    budget.version=5;budget.udp=0;
    assert(security_aggregate_decide(&shared,&budget,12,1,0,40)==0);
    assert(security_aggregate_decide(&shared,&budget,12,0,1,40)==0);
    assert(shared.syn_count==0 && shared.conn_count==0 && shared.udp_count==0 && shared.udp_bytes==0);
    budget.version=6;budget.syn=1;
    assert(security_aggregate_decide(&shared,&budget,12,1,0,40)==0);
    shared.syn_count=~(__u64)0;
    assert(security_aggregate_decide(&shared,&budget,12,1,0,40)==1);
    assert(shared.syn_count==~(__u64)0);
    puts("security aggregate: concurrent ceiling, rollover, reconfigure, byte/packet bounds, zero and saturation PASS");
    return 0;
}
