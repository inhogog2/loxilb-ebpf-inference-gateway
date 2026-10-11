/* Copyright (c) 2026 LoxiLB Authors. SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include "sockproxy_mcp_rr.h"
static _Atomic uint64_t cursor;
static _Atomic unsigned counts[32];
static sp_mcp_selector_state weighted;
static _Atomic unsigned weighted_counts[32];
static void *requests(void *unused)
{
  (void)unused;
  for (unsigned i=0;i<12000;i++) {
    uint64_t ticket=atomic_fetch_add_explicit(&cursor,1,memory_order_relaxed);
    int ep=sp_mcp_rr_index((UINT32_C(1)<<2)|(UINT32_C(1)<<9)|(UINT32_C(1)<<31),ticket);
    assert(ep==2 || ep==9 || ep==31);
    atomic_fetch_add_explicit(&counts[ep],1,memory_order_relaxed);
  }
  return NULL;
}
static void *weighted_requests(void *unused)
{
  (void)unused;
  uint8_t weights[32]={0}; weights[2]=3; weights[31]=1;
  for (unsigned i=0;i<12000;i++) {
    int ep=sp_mcp_wrr_index(&weighted,(UINT32_C(1)<<2)|(UINT32_C(1)<<31),weights);
    assert(ep==2 || ep==31);
    atomic_fetch_add_explicit(&weighted_counts[ep],1,memory_order_relaxed);
  }
  return NULL;
}
static void *replacement_requests(void *arg)
{
  uintptr_t seed=(uintptr_t)arg;
  uint8_t weights[32]={0};
  for (unsigned i=0;i<12000;i++) {
    uint32_t mask=(i+seed)&1 ? UINT32_C(1)<<9 : (UINT32_C(1)<<2)|(UINT32_C(1)<<31);
    weights[2]=(uint8_t)(1+(i%255)); weights[31]=(uint8_t)(255-(i%255)); weights[9]=1;
    int ep=sp_mcp_wrr_index(&weighted,mask,weights);
    assert(ep>=0 && ep<32 && (mask & (UINT32_C(1)<<ep)));
  }
  return NULL;
}
int main(void)
{
  assert(sp_mcp_rr_index(0,0)==-1);
  assert(sp_mcp_rr_index(UINT32_C(1)<<31,UINT64_MAX)==31);
  assert(sp_mcp_rr_index(5,UINT64_MAX)==2);
  assert(sp_mcp_rr_index(5,0)==0);
  pthread_t threads[8];
  for (unsigned i=0;i<8;i++) assert(!pthread_create(&threads[i],NULL,requests,NULL));
  for (unsigned i=0;i<8;i++) assert(!pthread_join(threads[i],NULL));
  assert(atomic_load(&cursor)==96000);
  for (unsigned i=0;i<32;i++)
    assert(atomic_load(&counts[i])==((i==2 || i==9 || i==31)?32000U:0U));
  for (unsigned i=0;i<8;i++) assert(!pthread_create(&threads[i],NULL,weighted_requests,NULL));
  for (unsigned i=0;i<8;i++) assert(!pthread_join(threads[i],NULL));
  assert(atomic_load(&weighted_counts[2])==72000);
  assert(atomic_load(&weighted_counts[31])==24000);
  uint8_t weights[32]={0}; weights[2]=3; weights[31]=1;
  /* Health membership changes clear prior accumulators and cannot escape the
   * eligible original indices. Restoration starts a deterministic schedule. */
  for (unsigned i=0;i<10000;i++) assert(sp_mcp_wrr_index(&weighted,UINT32_C(1)<<31,weights)==31);
  unsigned a=0,b=0;
  weights[2]=1; weights[31]=3; /* configuration replacement reverses weights */
  for (unsigned i=0;i<100000;i++) {
    int ep=sp_mcp_wrr_index(&weighted,(UINT32_C(1)<<2)|(UINT32_C(1)<<31),weights);
    if (ep==2) a++; else { assert(ep==31); b++; }
  }
  assert(a==25000 && b==75000);
  assert(sp_mcp_wrr_index(&weighted,0,weights)==-1);
  weights[2]=255; weights[31]=254; a=0; b=0;
  for (unsigned i=0;i<50900;i++) {
    int ep=sp_mcp_wrr_index(&weighted,(UINT32_C(1)<<2)|(UINT32_C(1)<<31),weights);
    if (ep==2) a++; else { assert(ep==31); b++; }
  }
  assert(a==25500 && b==25400);
  /* Eligible zero weights retain the existing default weight of one.
   * Exclusion comes from eligibility, never from a zero weight. */
  weights[2]=0; weights[31]=1; a=0; b=0;
  for (unsigned i=0;i<10000;i++) {
    int ep=sp_mcp_wrr_index(&weighted,(UINT32_C(1)<<2)|(UINT32_C(1)<<31),weights);
    if (ep==2) a++; else { assert(ep==31); b++; }
  }
  assert(a==5000 && b==5000);
  assert(weighted.weights[2]==1);
  for (unsigned i=0;i<100;i++) assert(sp_mcp_wrr_index(&weighted,UINT32_C(1)<<31,weights)==31);
  for (unsigned i=0;i<32;i++) assert(weighted.current[i]>-10000 && weighted.current[i]<10000);
  for (unsigned i=0;i<8;i++) assert(!pthread_create(&threads[i],NULL,replacement_requests,(void *)(uintptr_t)i));
  for (unsigned i=0;i<8;i++) assert(!pthread_join(threads[i],NULL));
  puts("PASS MCP RR/WRR sparse indices, unsigned wrap, concurrent exact 3:1, concurrent health/config changes, long run");
  return 0;
}
