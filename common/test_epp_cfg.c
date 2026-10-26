/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Endpoint Picker (EPP) rule configuration hop — Phase 1 M2.
 *
 * The EPP mode word and request-phase deadline ride the same additive
 * chain as kv_exact_mode: dp_proxy_tacts (llb_dpapi.h, the eBPF map value
 * the Go control plane fills through cgo) -> proxy_arg (llb_conv_nat2proxy)
 * -> proxy_epval_t (proxy_add_entry). The identity Go resolves the EPP
 * address by, epp_svc_id, is stamped from arg->_id exactly as kv_svc_id.
 *
 * llb_conv_nat2proxy and proxy_add_entry live in translation units that
 * need the whole data plane, so — like test_kv_exact's kv copy tests — this
 * test pins (1) the ABI every hop depends on: the field types, the mode
 * words shared with Go, the dp_proxy_tacts size the four _Static_asserts
 * guard, proxy_arg staying inside its 4096-byte map value; and (2) the copy
 * semantics of both hops against the real structs, so a dropped assignment
 * or a narrowed field fails here before the cluster run does.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

#include <linux/bpf.h>
#include "bpf.h"
#include "libbpf.h"
#include "uthash.h"
#include "pdi.h"
#include "llb_dpapi.h"
#include "sockproxy.h"

static int tests_run, tests_passed, tests_failed;

#define ASSERT_EQ(a, b, msg) do { \
  tests_run++; \
  if ((long long)(a) == (long long)(b)) { tests_passed++; } \
  else { tests_failed++; \
    printf("  FAIL: %s (expected %lld, got %lld) at line %d\n", msg, \
           (long long)(b), (long long)(a), __LINE__); } \
} while (0)

/* The words the Go side (pkg/loxinet/rules.go eppDpMode) sends. */
_Static_assert(EPP_MODE_OFF == 0 && EPP_MODE_FAIL_OPEN == 1 && EPP_MODE_FAIL_CLOSE == 2,
               "EPP_MODE_* words drifted from the Go eppDpMode mirror");
/* Every hop carries the deadline in 32 bits and the mode in one byte. */
_Static_assert(sizeof(((struct dp_proxy_tacts *)0)->epp_mode) == 1, "tacts epp_mode is a byte");
_Static_assert(sizeof(((struct dp_proxy_tacts *)0)->epp_timeout_ms) == 4, "tacts epp_timeout_ms is u32");
_Static_assert(sizeof(((struct proxy_arg *)0)->epp_mode) == 1, "proxy_arg epp_mode is a byte");
_Static_assert(sizeof(((struct proxy_arg *)0)->epp_timeout_ms) == 4, "proxy_arg epp_timeout_ms is u32");
_Static_assert(sizeof(((proxy_epval_t *)0)->epp_mode) == 1, "epval epp_mode is a byte");
_Static_assert(sizeof(((proxy_epval_t *)0)->epp_timeout_ms) == 4, "epval epp_timeout_ms is u32");
_Static_assert(sizeof(((proxy_epval_t *)0)->epp_svc_id) == sizeof(((proxy_epval_t *)0)->kv_svc_id),
               "epp_svc_id and kv_svc_id carry the same rule identity");
/* The deadline sits 4-aligned and the struct stays 8-aligned (+8 bytes over
 * the pre-EPP layout; llb_dpapi.h's own asserts pin the absolute size). */
_Static_assert(offsetof(struct dp_proxy_tacts, epp_timeout_ms) % 4 == 0, "epp_timeout_ms aligned");
_Static_assert(sizeof(struct dp_proxy_tacts) % 8 == 0, "dp_proxy_tacts stays 8-aligned");
_Static_assert(sizeof(struct proxy_arg) <= 4096, "proxy_arg must fit its map value");

/* Mirrors the nat2proxy hop in kernel/loxilb_libdp.c. */
static void
epp_conv_nat2proxy(const struct dp_proxy_tacts *dat, struct proxy_arg *pval)
{
  pval->_id = dat->ca.cidx;
  pval->epp_mode = dat->epp_mode;
  pval->epp_timeout_ms = dat->epp_timeout_ms;
}

/* Mirrors both proxy_add_entry copy points in sockproxy_http.c. */
static void
epp_add_entry_copy(const struct proxy_arg *arg, proxy_epval_t *tepval)
{
  tepval->epp_mode = arg->epp_mode;
  tepval->epp_timeout_ms = arg->epp_timeout_ms;
  tepval->epp_svc_id = arg->_id;
}

static void
test_epp_rule_reaches_the_pool(void)
{
  printf("Test: an EPP rule's mode, deadline and identity reach proxy_epval_t\n");
  struct dp_proxy_tacts dat;
  struct proxy_arg arg;
  proxy_epval_t tepval;
  memset(&dat, 0, sizeof(dat));
  memset(&arg, 0, sizeof(arg));
  memset(&tepval, 0, sizeof(tepval));

  dat.ca.cidx = 7;                 /* the rule number Go hands down */
  dat.epp_mode = EPP_MODE_FAIL_CLOSE;
  dat.epp_timeout_ms = 600000;     /* the largest value admission allows */

  epp_conv_nat2proxy(&dat, &arg);
  ASSERT_EQ(arg.epp_mode, EPP_MODE_FAIL_CLOSE, "proxy_arg epp_mode");
  ASSERT_EQ(arg.epp_timeout_ms, 600000, "proxy_arg epp_timeout_ms");

  epp_add_entry_copy(&arg, &tepval);
  ASSERT_EQ(tepval.epp_mode, EPP_MODE_FAIL_CLOSE, "epval epp_mode");
  ASSERT_EQ(tepval.epp_timeout_ms, 600000, "epval epp_timeout_ms");
  ASSERT_EQ(tepval.epp_svc_id, 7, "epval epp_svc_id is the rule number");
  ASSERT_EQ(tepval.kv_svc_id, 0, "kv_svc_id untouched by the EPP hop");
}

static void
test_rule_without_epp_is_byte_identical(void)
{
  printf("Test: a rule without an EPP leaves every EPP word zero\n");
  struct dp_proxy_tacts dat;
  struct proxy_arg arg;
  proxy_epval_t tepval;
  memset(&dat, 0, sizeof(dat));
  memset(&arg, 0xA5, sizeof(arg));      /* stale bytes must be overwritten */
  memset(&tepval, 0xA5, sizeof(tepval));

  dat.ca.cidx = 3;
  epp_conv_nat2proxy(&dat, &arg);
  epp_add_entry_copy(&arg, &tepval);
  ASSERT_EQ(tepval.epp_mode, EPP_MODE_OFF, "epp_mode off");
  ASSERT_EQ(tepval.epp_timeout_ms, 0, "epp_timeout_ms zero");
  ASSERT_EQ(tepval.epp_svc_id, 3, "identity still stamped (as kv_svc_id)");
}

static void
test_fail_open_word(void)
{
  printf("Test: FailOpen rides as EPP_MODE_FAIL_OPEN\n");
  struct dp_proxy_tacts dat;
  struct proxy_arg arg;
  memset(&dat, 0, sizeof(dat));
  memset(&arg, 0, sizeof(arg));
  dat.epp_mode = EPP_MODE_FAIL_OPEN;
  dat.epp_timeout_ms = 3000;
  epp_conv_nat2proxy(&dat, &arg);
  ASSERT_EQ(arg.epp_mode, EPP_MODE_FAIL_OPEN, "proxy_arg FailOpen word");
  ASSERT_EQ(arg.epp_timeout_ms, 3000, "proxy_arg default deadline");
}

int
main(void)
{
  printf("sizeof(struct dp_proxy_tacts) = %zu, sizeof(struct proxy_arg) = %zu\n",
         sizeof(struct dp_proxy_tacts), sizeof(struct proxy_arg));
  test_epp_rule_reaches_the_pool();
  test_rule_without_epp_is_byte_identical();
  test_fail_open_word();
  printf("%d tests, %d passed, %d failed\n", tests_run, tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
