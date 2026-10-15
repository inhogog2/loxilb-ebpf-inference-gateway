/* test_model_routing.c - model-aware hostname/path lookup regressions. */

#include <assert.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "uthash.h"
#include "sockproxy_internal.h"
#include "sockproxy_routing.h"

static void
add_pool(proxy_map_ent_t *service, proxy_epval_t *pool, const char *key,
         uint32_t id)
{
  memset(pool, 0, sizeof(*pool));
  pool->_id = id;
  strncpy(pool->ephash_key, key, sizeof(pool->ephash_key) - 1);
  HASH_ADD_STR(service->val.ephash, ephash_key, pool);
  /* Lookups read the published index, as the workers do. */
  assert(sp_pool_index_publish(service) == 0);
}

static void
del_pool(proxy_map_ent_t *service, proxy_epval_t *pool)
{
  HASH_DEL(service->val.ephash, pool);
  assert(sp_pool_index_publish(service) == 0);
}

static void
test_hostname_only_model_pool(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t model_pool;

  add_pool(&service, &model_pool,
           "inference.example||Qwen/Qwen2.5-7B-Instruct", 101);

  proxy_epval_t *got = find_endpoint_lpm(
      &service, "inference.example", "/v1/completions",
      "Qwen/Qwen2.5-7B-Instruct");
  assert(got == &model_pool);

  del_pool(&service, &model_pool);
}

static void
test_model_pool_precedes_wildcard_path(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t model_pool;
  proxy_epval_t wildcard_path;

  add_pool(&service, &model_pool, "inference.example||model-a", 201);
  add_pool(&service, &wildcard_path, "inference.example|/v1", 202);

  proxy_epval_t *got = find_endpoint_lpm(
      &service, "inference.example", "/v1/completions", "model-a");
  assert(got == &model_pool);

  del_pool(&service, &model_pool);
  del_pool(&service, &wildcard_path);
}

static void
test_unknown_model_uses_wildcard_path(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t wildcard_path;

  add_pool(&service, &wildcard_path, "inference.example|/v1", 301);

  proxy_epval_t *got = find_endpoint_lpm(
      &service, "inference.example", "/v1/completions", "unknown-model");
  assert(got == &wildcard_path);

  del_pool(&service, &wildcard_path);
}

/* An exact pool may win the full path, never an ancestor candidate. */
static void
test_exact_path_does_not_match_children(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t exact, root;
  add_pool(&service, &exact, "inference.example|/v1/exact|model-a", 401);
  exact.path_match_mode = 2;
  add_pool(&service, &root, "inference.example|/|model-a", 402);
  root.path_match_mode = 1;
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact", "model-a") == &exact);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact?probe=1", "model-a") == &exact);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact/child", "model-a") == &root);
  del_pool(&service, &root);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact/child", "model-a") == NULL);
  del_pool(&service, &exact);
}

static void
test_wildcard_exact_and_root_are_exact(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t exact, prefix, root;
  add_pool(&service, &exact, "inference.example|/v1/exact", 501);
  exact.path_match_mode = 2;
  add_pool(&service, &prefix, "inference.example|/v1", 502);
  prefix.path_match_mode = 1;
  add_pool(&service, &root, "inference.example|/", 503);
  root.path_match_mode = 2;
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact", "unknown") == &exact);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact?probe=1", "unknown") == &exact);
  assert(find_endpoint_lpm(&service, "inference.example", "/v1/exact/child", "unknown") == &prefix);
  assert(find_endpoint_lpm(&service, "inference.example", "/", "unknown") == &root);
  assert(find_endpoint_lpm(&service, "inference.example", "/?probe=1", "unknown") == &root);
  assert(find_endpoint_lpm(&service, "inference.example", "/other", "unknown") == NULL);
  assert(find_endpoint_lpm(&service, "inference.example", "/other", "") == NULL);
  del_pool(&service, &exact);
  del_pool(&service, &prefix);
  del_pool(&service, &root);
}

static void
set_listener(proxy_map_ent_t *service)
{
  assert(inet_pton(AF_INET, "127.0.0.1", &service->key.xip) == 1);
  service->key.xport = htons(2086);
}

static void
test_listener_model_root_and_longest_path(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t root, prefix, longer;
  set_listener(&service);
  add_pool(&service, &root, "127.0.0.1:2086|/|model-a", 601);
  add_pool(&service, &prefix, "127.0.0.1:2086|/v1|model-a", 602);
  add_pool(&service, &longer, "127.0.0.1:2086|/v1/chat|model-a", 603);
  assert(find_endpoint_lpm(&service, "floating.example", "/v1/chat/completions", "model-a") == &longer);
  assert(find_endpoint_lpm(&service, "floating.example", "/v1/other", "model-a") == &prefix);
  assert(find_endpoint_lpm(&service, "floating.example", "/other", "model-a") == &root);
  assert(find_endpoint_lpm(&service, "floating.example", "/v1/chat", "wrong-model") == NULL);
  del_pool(&service, &longer);
  del_pool(&service, &prefix);
  del_pool(&service, &root);
}

static void
test_listener_exact_query_and_wrong_path(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t exact;
  set_listener(&service);
  add_pool(&service, &exact, "127.0.0.1:2086|/v1/exact|model-a", 701);
  exact.path_match_mode = 2;
  assert(find_endpoint_lpm(&service, "client.example", "/v1/exact", "model-a") == &exact);
  assert(find_endpoint_lpm(&service, "client.example", "/v1/exact?probe=1", "model-a") == &exact);
  assert(find_endpoint_lpm(&service, "client.example", "/v1/exact/child", "model-a") == NULL);
  assert(find_endpoint_lpm(&service, "client.example", "/other", "model-a") == NULL);
  assert(find_endpoint_lpm(&service, "client.example", "/v1/exact", "wrong-model") == NULL);
  del_pool(&service, &exact);
}

static void
test_listener_wildcard_path_and_host_precedence(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t model, wildcard, explicit_host;
  set_listener(&service);
  add_pool(&service, &model, "127.0.0.1:2086|/v1|model-a", 801);
  add_pool(&service, &wildcard, "127.0.0.1:2086|/v1/chat", 802);
  add_pool(&service, &explicit_host, "client.example|/|model-a", 803);
  assert(find_endpoint_lpm(&service, "other.example", "/v1/chat/completions", "model-a") == &model);
  assert(find_endpoint_lpm(&service, "other.example", "/v1/chat/completions", "unknown") == &wildcard);
  assert(find_endpoint_lpm(&service, "other.example", "/outside", "unknown") == NULL);
  assert(find_endpoint_lpm(&service, "client.example", "/v1/chat/completions", "model-a") == &explicit_host);
  del_pool(&service, &explicit_host);
  del_pool(&service, &wildcard);
  del_pool(&service, &model);
}

static void
test_listener_without_path_remains_supported(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t model, wildcard;
  set_listener(&service);
  add_pool(&service, &model, "127.0.0.1:2086||model-a", 901);
  add_pool(&service, &wildcard, "127.0.0.1:2086", 902);
  assert(find_endpoint_lpm(&service, "client.example", "/any", "model-a") == &model);
  assert(find_endpoint_lpm(&service, "client.example", "/any", "unknown") == &wildcard);
  del_pool(&service, &wildcard);
  del_pool(&service, &model);
}

/* The admission gate asks for the default reservation of the rule a request
 * routes to: the pool this lookup selects, whichever was installed first. */
static void
test_default_reservation_is_the_routed_pools(void)
{
  proxy_map_ent_t service = {0};
  proxy_epval_t first_off, model_on, model_third, wildcard;

  add_pool(&service, &first_off, "inference.example||model-off", 901);
  add_pool(&service, &model_on, "inference.example||model-on", 902);
  add_pool(&service, &model_third, "inference.example||model-third", 903);
  model_on.ai_default_tokens = 800;
  model_third.ai_default_tokens = 300;

  assert(sp_resv_default_tokens_route(&service, "inference.example", "/v1/chat/completions", "model-off") == 0);
  assert(sp_resv_default_tokens_route(&service, "inference.example", "/v1/chat/completions", "model-on") == 800);
  assert(sp_resv_default_tokens_route(&service, "inference.example", "/v1/chat/completions", "model-third") == 300);
  /* no pool for the model and no wildcard: no rule, nothing reserved by default */
  assert(sp_resv_default_tokens_route(&service, "inference.example", "/v1/chat/completions", "model-none") == 0);
  assert(sp_resv_default_tokens_route(&service, "other.example", "/", "model-on") == 0);
  /* a wildcard pool takes the models that have none of their own */
  add_pool(&service, &wildcard, "inference.example|/", 904);
  wildcard.ai_default_tokens = 64;
  assert(sp_resv_default_tokens_route(&service, "inference.example", "/v1/chat/completions", "model-none") == 64);
  assert(sp_resv_default_tokens_route(&service, "inference.example", "/v1/chat/completions", "") == 64);
  assert(sp_resv_default_tokens_route(&service, "inference.example", "/v1/chat/completions", "model-on") == 800);
  /* no usable Host: dispatch takes the listener's first pool, and so does this */
  assert(sp_resv_default_tokens_route(&service, NULL, "/", "model-on") == 0);
  first_off.ai_default_tokens = 5;
  assert(sp_resv_default_tokens_route(&service, NULL, NULL, NULL) == 5);
  assert(sp_resv_default_tokens_route(NULL, "inference.example", "/", "model-on") == 0);

  HASH_CLEAR(hh, service.val.ephash);
}

int
main(void)
{
  test_exact_path_does_not_match_children();
  test_wildcard_exact_and_root_are_exact();
  test_hostname_only_model_pool();
  test_model_pool_precedes_wildcard_path();
  test_unknown_model_uses_wildcard_path();
  test_listener_model_root_and_longest_path();
  test_listener_exact_query_and_wrong_path();
  test_listener_wildcard_path_and_host_precedence();
  test_listener_without_path_remains_supported();
  test_default_reservation_is_the_routed_pools();
  puts("test_model_routing: ALL PASS");
  return 0;
}
