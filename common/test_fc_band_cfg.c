/*
 * Copyright (c) 2026 LoxiLB Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * The band knobs of the capacity gate's configuration, driven alone: the
 * four switches from the environment and a rule's tri-states over them,
 * the rule-only numeric knobs (the critical reserve folded into the
 * critical floor), the values held at their bounds, the derived `bands`
 * flag, and fc_cfg_equal seeing a change of every field while a rule that
 * declares none of them resolves equal to a pool configured before they
 * existed; and fc_cfg_band_guard holding an inherited combination the
 * control plane refuses a declaring rule to what the gate may run.
 *
 * Build: make test_fc_band_cfg (also run by `make test_fc`).
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sockproxy_fc.h"

#define C FC_BAND_CRITICAL
#define S FC_BAND_STANDARD
#define B FC_BAND_SHEDDABLE

static const char *envs[] = { "LLB_FC_WAKE_POLICY", "LLB_FC_SHED_QUEUE",
                              "LLB_FC_TENANT_WAKE", "LLB_FC_LLMD_HEADERS",
                              "LLB_FC_MODE", "LLB_FC_MAX_QUEUE_DEPTH" };

static void
clear_env(void)
{
  for (size_t i = 0; i < sizeof(envs) / sizeof(envs[0]); i++)
    unsetenv(envs[i]);
}

static void
test_switch_defaults_and_environment(void)
{
  fc_cfg_t env;

  clear_env();
  fc_cfg_from_env(&env);
  assert(env.wake_policy == FC_WAKE_STRICT && env.shed_queue == 0 &&
         env.tenant_wake == FC_TENANT_WAKE_FIFO && env.llmd_headers == 0);
  for (int l = FC_L_WAKE_POLICY; l < FC_LIMITS; l++)
    assert(env.src[l] == FC_SRC_DEFAULT);
  assert(env.bands == 0);

  setenv("LLB_FC_WAKE_POLICY", "weighted", 1);
  setenv("LLB_FC_SHED_QUEUE", "ON", 1);
  setenv("LLB_FC_TENANT_WAKE", "rr", 1);
  setenv("LLB_FC_LLMD_HEADERS", "on", 1);
  fc_cfg_from_env(&env);
  assert(env.wake_policy == FC_WAKE_WEIGHTED && env.shed_queue == 1 &&
         env.tenant_wake == FC_TENANT_WAKE_RR && env.llmd_headers == 1);
  assert(env.src[FC_L_WAKE_POLICY] == FC_SRC_ENV);
  assert(env.src[FC_L_SHED_QUEUE] == FC_SRC_ENV);
  assert(env.src[FC_L_TENANT_WAKE] == FC_SRC_ENV);
  assert(env.src[FC_L_LLMD_HEADERS] == FC_SRC_ENV);
  assert(env.bands == 1);

  /* The default named explicitly is the environment's; anything else is
   * not a value and leaves the default. */
  setenv("LLB_FC_WAKE_POLICY", "strict", 1);
  setenv("LLB_FC_SHED_QUEUE", "maybe", 1);
  unsetenv("LLB_FC_TENANT_WAKE");
  setenv("LLB_FC_LLMD_HEADERS", "off", 1);
  fc_cfg_from_env(&env);
  assert(env.wake_policy == FC_WAKE_STRICT && env.src[FC_L_WAKE_POLICY] == FC_SRC_ENV);
  assert(env.shed_queue == 0 && env.src[FC_L_SHED_QUEUE] == FC_SRC_DEFAULT);
  assert(env.tenant_wake == FC_TENANT_WAKE_FIFO && env.src[FC_L_TENANT_WAKE] == FC_SRC_DEFAULT);
  assert(env.llmd_headers == 0 && env.src[FC_L_LLMD_HEADERS] == FC_SRC_ENV);
  /* llm-d headers are not a band knob. */
  setenv("LLB_FC_LLMD_HEADERS", "on", 1);
  setenv("LLB_FC_WAKE_POLICY", "strict", 1);
  unsetenv("LLB_FC_SHED_QUEUE");
  fc_cfg_from_env(&env);
  assert(env.llmd_headers == 1 && env.bands == 0);
  clear_env();
}

static void
test_rule_over_environment(void)
{
  fc_cfg_t env, out;
  fc_rule_cfg_t r;

  clear_env();
  setenv("LLB_FC_WAKE_POLICY", "weighted", 1);
  setenv("LLB_FC_SHED_QUEUE", "on", 1);
  fc_cfg_from_env(&env);

  /* Inherit: the environment's values and sources. */
  memset(&r, 0, sizeof(r));
  fc_cfg_resolve(&out, &env, &r);
  assert(out.wake_policy == FC_WAKE_WEIGHTED && out.src[FC_L_WAKE_POLICY] == FC_SRC_ENV);
  assert(out.shed_queue == 1 && out.src[FC_L_SHED_QUEUE] == FC_SRC_ENV);

  /* The rule's own say wins, both ways. */
  r.wake_policy = FC_RULE_WAKE_STRICT;
  r.shed_queue = FC_RULE_SWITCH_OFF;
  r.tenant_wake = FC_RULE_TENANT_WAKE_RR;
  r.llmd_headers = FC_RULE_SWITCH_ON;
  fc_cfg_resolve(&out, &env, &r);
  assert(out.wake_policy == FC_WAKE_STRICT && out.src[FC_L_WAKE_POLICY] == FC_SRC_RULE);
  assert(out.shed_queue == 0 && out.src[FC_L_SHED_QUEUE] == FC_SRC_RULE);
  assert(out.tenant_wake == FC_TENANT_WAKE_RR && out.src[FC_L_TENANT_WAKE] == FC_SRC_RULE);
  assert(out.llmd_headers == 1 && out.src[FC_L_LLMD_HEADERS] == FC_SRC_RULE);
  r.wake_policy = FC_RULE_WAKE_WEIGHTED;
  r.tenant_wake = FC_RULE_TENANT_WAKE_FIFO;
  fc_cfg_resolve(&out, &env, &r);
  assert(out.wake_policy == FC_WAKE_WEIGHTED && out.tenant_wake == FC_TENANT_WAKE_FIFO);
  assert(out.src[FC_L_TENANT_WAKE] == FC_SRC_RULE);
  /* Out-of-range encodings inherit. */
  r.wake_policy = 9;
  r.shed_queue = 7;
  fc_cfg_resolve(&out, &env, &r);
  assert(out.src[FC_L_WAKE_POLICY] == FC_SRC_ENV && out.src[FC_L_SHED_QUEUE] == FC_SRC_ENV);
  clear_env();
}

static void
test_numeric_knobs_are_the_rules(void)
{
  fc_cfg_t env, out;
  fc_rule_cfg_t r;

  clear_env();
  fc_cfg_from_env(&env);
  memset(&r, 0, sizeof(r));
  fc_cfg_resolve(&out, &env, &r);
  for (int b = 0; b < FC_BANDS; b++)
    assert(!out.band_weight[b] && !out.band_min_share_pct[b] &&
           !out.band_wait_ms[b] && !out.band_queue_pct[b]);
  assert(out.src[FC_L_BAND_WEIGHTS] == FC_SRC_DEFAULT);
  assert(out.src[FC_L_CRITICAL_RESERVE] == FC_SRC_DEFAULT);
  assert(out.bands == 0);

  /* Each triple lands by band, sources say rule. */
  r.band_weight[C] = 8; r.band_weight[S] = 3; r.band_weight[B] = 1;
  r.band_min_share_pct[S] = 20;
  r.band_wait_ms[S] = 5000; r.band_wait_ms[B] = 500;
  r.band_queue_pct[C] = 25; r.band_queue_pct[S] = 50; r.band_queue_pct[B] = 25;
  fc_cfg_resolve(&out, &env, &r);
  assert(out.band_weight[C] == 8 && out.band_weight[S] == 3 && out.band_weight[B] == 1);
  assert(out.band_min_share_pct[S] == 20 && out.band_min_share_pct[C] == 0);
  assert(out.band_wait_ms[S] == 5000 && out.band_wait_ms[B] == 500 && out.band_wait_ms[C] == 0);
  assert(out.band_queue_pct[C] == 25 && out.band_queue_pct[S] == 50);
  assert(out.src[FC_L_BAND_WEIGHTS] == FC_SRC_RULE);
  assert(out.src[FC_L_BAND_MIN_SHARE] == FC_SRC_RULE);
  assert(out.src[FC_L_BAND_WAIT] == FC_SRC_RULE);
  assert(out.src[FC_L_BAND_QUEUE] == FC_SRC_RULE);
  assert(out.bands == 1);

  /* The reserve is the critical floor. */
  memset(&r, 0, sizeof(r));
  r.critical_reserve_pct = 25;
  fc_cfg_resolve(&out, &env, &r);
  assert(out.band_min_share_pct[C] == 25);
  assert(out.src[FC_L_CRITICAL_RESERVE] == FC_SRC_RULE);
  assert(out.src[FC_L_BAND_MIN_SHARE] == FC_SRC_DEFAULT);
  assert(out.bands == 1);

  /* Values past their bounds are held at them. */
  memset(&r, 0, sizeof(r));
  r.band_weight[C] = 200;
  r.band_min_share_pct[B] = 150;
  r.critical_reserve_pct = 101;
  r.band_wait_ms[S] = FC_QUEUE_WAIT_MS_MAX + 1;
  r.band_queue_pct[S] = 255;
  fc_cfg_resolve(&out, &env, &r);
  assert(out.band_weight[C] == FC_BAND_WEIGHT_MAX);
  assert(out.band_min_share_pct[B] == 100 && out.band_min_share_pct[C] == 100);
  assert(out.band_wait_ms[S] == FC_QUEUE_WAIT_MS_MAX);
  assert(out.band_queue_pct[S] == 100);
}

static void
test_equal_sees_every_band_field(void)
{
  fc_cfg_t env, base, cfg;
  fc_rule_cfg_t r;

  clear_env();
  fc_cfg_from_env(&env);
  memset(&r, 0, sizeof(r));
  fc_cfg_resolve(&base, &env, &r);
  /* A rule that declares no band knob, resolved again, is no change. */
  fc_cfg_resolve(&cfg, &env, &r);
  assert(fc_cfg_equal(&base, &cfg));

  /* A pool configured before the band knobs existed holds zeros in every
   * band field and defaults in their sources: equal to the same rule
   * resolved now. */
  cfg = base;
  memset(cfg.band_weight, 0, sizeof(cfg.band_weight));
  memset(cfg.band_min_share_pct, 0, sizeof(cfg.band_min_share_pct));
  memset(cfg.band_wait_ms, 0, sizeof(cfg.band_wait_ms));
  memset(cfg.band_queue_pct, 0, sizeof(cfg.band_queue_pct));
  cfg.wake_policy = 0; cfg.shed_queue = 0; cfg.tenant_wake = 0;
  cfg.llmd_headers = 0; cfg.bands = 0;
  cfg.wake_policy_cfg = 0; cfg.shed_queue_cfg = 0; cfg.tenant_wake_cfg = 0;
  cfg.band_fallback = 0;
  for (int l = FC_L_WAKE_POLICY; l < FC_LIMITS; l++)
    cfg.src[l] = FC_SRC_DEFAULT;
  assert(fc_cfg_equal(&base, &cfg));

#define CHANGED(stmt) do { cfg = base; stmt; assert(!fc_cfg_equal(&base, &cfg)); } while (0)
  CHANGED(cfg.wake_policy = FC_WAKE_WEIGHTED);
  CHANGED(cfg.shed_queue = 1);
  CHANGED(cfg.tenant_wake = FC_TENANT_WAKE_RR);
  CHANGED(cfg.llmd_headers = 1);
  CHANGED(cfg.bands = 1);
  CHANGED(cfg.wake_policy_cfg = FC_WAKE_WEIGHTED);
  CHANGED(cfg.shed_queue_cfg = 1);
  CHANGED(cfg.tenant_wake_cfg = FC_TENANT_WAKE_RR);
  CHANGED(cfg.band_fallback = FC_BAND_FB_SOCKMAP);
  for (int b = 0; b < FC_BANDS; b++) {
    CHANGED(cfg.band_weight[b] = 1);
    CHANGED(cfg.band_min_share_pct[b] = 1);
    CHANGED(cfg.band_wait_ms[b] = 1);
    CHANGED(cfg.band_queue_pct[b] = 1);
  }
  for (int l = FC_L_WAKE_POLICY; l < FC_LIMITS; l++)
    CHANGED(cfg.src[l] = FC_SRC_RULE);
#undef CHANGED
}

/* What a declaring rule is refused, an inheriting one does not run: the
 * guard falls back, keeps the configured switches beside the effective
 * ones and names the first reason. */
static void
test_guard_holds_the_refused_combinations(void)
{
  fc_cfg_t env, cfg;
  fc_rule_cfg_t r;

  /* Weighted from the environment on a sockmap rule: all defaults. */
  clear_env();
  setenv("LLB_FC_WAKE_POLICY", "weighted", 1);
  setenv("LLB_FC_LLMD_HEADERS", "on", 1);
  fc_cfg_from_env(&env);
  memset(&r, 0, sizeof(r));
  r.band_weight[C] = 8; r.band_weight[S] = 3; r.band_weight[B] = 1;
  r.band_min_share_pct[S] = 20;
  r.band_wait_ms[B] = 500;
  r.band_queue_pct[C] = 30;
  fc_cfg_resolve(&cfg, &env, &r);
  assert(cfg.wake_policy == FC_WAKE_WEIGHTED && cfg.band_fallback == FC_BAND_FB_NONE);
  assert(fc_cfg_band_guard(&cfg, 1) == FC_BAND_FB_SOCKMAP);
  assert(cfg.wake_policy == FC_WAKE_STRICT && cfg.wake_policy_cfg == FC_WAKE_WEIGHTED);
  assert(cfg.src[FC_L_WAKE_POLICY] == FC_SRC_ENV);
  for (int b = 0; b < FC_BANDS; b++)
    assert(!cfg.band_weight[b] && !cfg.band_min_share_pct[b] &&
           !cfg.band_wait_ms[b] && !cfg.band_queue_pct[b]);
  assert(cfg.bands == 0 && cfg.llmd_headers == 1);
  assert(!strcmp(fc_band_fallback_name(cfg.band_fallback), "sockmap_request"));

  /* The same rule where the gate sees the request: it runs as configured. */
  fc_cfg_resolve(&cfg, &env, &r);
  assert(fc_cfg_band_guard(&cfg, 0) == FC_BAND_FB_NONE);
  assert(cfg.wake_policy == FC_WAKE_WEIGHTED && cfg.band_weight[C] == 8 && cfg.bands);

  /* A sockmap rule with no band setting at all: nothing to fall back from. */
  clear_env();
  fc_cfg_from_env(&env);
  memset(&r, 0, sizeof(r));
  fc_cfg_resolve(&cfg, &env, &r);
  assert(fc_cfg_band_guard(&cfg, 1) == FC_BAND_FB_NONE);

  /* Weighted from the environment, no weights on the rule: strict. */
  setenv("LLB_FC_WAKE_POLICY", "weighted", 1);
  fc_cfg_from_env(&env);
  fc_cfg_resolve(&cfg, &env, &r);
  assert(fc_cfg_band_guard(&cfg, 0) == FC_BAND_FB_NO_WEIGHTS);
  assert(cfg.wake_policy == FC_WAKE_STRICT && cfg.wake_policy_cfg == FC_WAKE_WEIGHTED);
  assert(cfg.bands == 0);
  assert(!strcmp(fc_band_fallback_name(cfg.band_fallback), "zero_weight"));
  /* One zero among the weights is strict too. */
  r.band_weight[C] = 4; r.band_weight[S] = 2;
  fc_cfg_resolve(&cfg, &env, &r);
  assert(fc_cfg_band_guard(&cfg, 0) == FC_BAND_FB_NO_WEIGHTS);
  assert(cfg.wake_policy == FC_WAKE_STRICT && cfg.band_weight[C] == 4);

  /* Shed queue from the environment with no queue: off. With a depth: on. */
  clear_env();
  setenv("LLB_FC_SHED_QUEUE", "on", 1);
  fc_cfg_from_env(&env);
  memset(&r, 0, sizeof(r));
  fc_cfg_resolve(&cfg, &env, &r);
  assert(fc_cfg_band_guard(&cfg, 0) == FC_BAND_FB_NO_QUEUE);
  assert(cfg.shed_queue == 0 && cfg.shed_queue_cfg == 1);
  r.max_queue_depth = 8;
  fc_cfg_resolve(&cfg, &env, &r);
  assert(fc_cfg_band_guard(&cfg, 0) == FC_BAND_FB_NONE && cfg.shed_queue == 1);

  /* A fallback is a change fc_cfg_equal sees: the same values reached by
   * the guard and by a declaration differ in the configured switch. */
  {
    fc_cfg_t declared;

    clear_env();
    fc_cfg_from_env(&env);
    memset(&r, 0, sizeof(r));
    fc_cfg_resolve(&declared, &env, &r);
    fc_cfg_band_guard(&declared, 0);
    setenv("LLB_FC_WAKE_POLICY", "weighted", 1);
    fc_cfg_from_env(&env);
    fc_cfg_resolve(&cfg, &env, &r);
    fc_cfg_band_guard(&cfg, 0);
    assert(cfg.wake_policy == declared.wake_policy);
    assert(!fc_cfg_equal(&cfg, &declared));
  }
  clear_env();
}

int
main(void)
{
  test_switch_defaults_and_environment();
  test_rule_over_environment();
  test_numeric_knobs_are_the_rules();
  test_equal_sees_every_band_field();
  test_guard_holds_the_refused_combinations();
  printf("test_fc_band_cfg: all passed\n");
  return 0;
}
