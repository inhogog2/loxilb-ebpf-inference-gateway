/* test_pd_cache_aware.c - Unit tests for P/D cache-aware routing (US-PD805)
 * Standalone test binary: no sockproxy.c dependencies.
 * Build: gcc -Wall -Wextra -fsanitize=address -o test_pd_cache_aware \
 *        test_pd_cache_aware.c -I. -DTEST_PD_CACHE_AWARE -lpthread
 *
 * Suite A: 8 radix trie tests
 * Suite B: 7 session table tests (added by Plan 05-02)
 * Suite C: 5 integration tests (added by Plan 05-02)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include "sockproxy_fc.h"  /* pd_select_prefill reads tepval->fc.cfg.telemetry_stale_ms */
#include <limits.h>
#include <time.h>
#include <errno.h>  /* .1 Plan 02: EDEADLK for Suite D */

/* ===== Constants (from sockproxy.h) ===== */
#define MAX_PROXY_EP      32
#define MAX_PREFIX_LEN    512
#define MAX_MODEL_LEN     128
#define MAX_CONV_ID_LEN   128
#define MAX_LORA_LEN      128
#define MAX_HASH_LEN      64
#define MAX_SALT_LEN      64

/* Circuit breaker states */
#define CB_STATE_CLOSED    0
#define CB_STATE_OPEN      1
#define CB_STATE_HALF_OPEN 2

/* C2 capacity-aware symbols referenced by pd_select_prefill's Tier-2 scorer.
 * The mock never sets ep_sel = PROXY_SEL_GPU_AWARE, so the C2 branch is not exercised
 * by these tests — these only need to be DECLARED for sockproxy_pd.c to compile here.
 * (Previously absent -> this whole target failed to build; un-blocks it.) */
#ifndef PROXY_SEL_GPU_AWARE
#define PROXY_SEL_GPU_AWARE      4
#define DEFAULT_QUEUE_WEIGHT     1
#define DEFAULT_KV_CACHE_WEIGHT  1
#define DEFAULT_SWAP_WEIGHT      1
#endif

/* bounded backpressured admission — parked FIFO mock (mirrors
 * sockproxy.h). test_pd_cache_aware never SETs LLB_PD_QUEUE_DEPTH_PER_EP, so the
 * enqueue path in sockproxy_pd.c is never taken here (default-off); these are only
 * needed for the TU to COMPILE the parked-branch references. */
#ifndef PD_MAX_QUEUE_DEPTH
#define PD_MAX_QUEUE_DEPTH 64
#endif
typedef struct {
  int      fd;
  uint64_t gen;
  uint64_t enqueue_ns;
} pd_parked_ent_t;
typedef struct {
  pd_parked_ent_t slot[PD_MAX_QUEUE_DEPTH];
  uint16_t head, tail, count;
} pd_parked_fifo_t;

/* ===== uthash (vendored in same directory) ===== */
#include "uthash.h"

/* ===== Struct stubs ===== */

typedef struct {
  uint32_t xip;
  uint16_t xport;
  uint8_t  inv;        /* 0=active, non-zero=inactive */
  uint8_t  protocol;
  uint8_t  weight;
  uint8_t  pad;
  uint16_t nixl_port;
} proxy_ent_t;

typedef struct {
  uint8_t state;  /* CB_STATE_CLOSED, CB_STATE_OPEN, CB_STATE_HALF_OPEN */
} circuit_breaker_t;

typedef struct {
  _Atomic uint32_t active_conns;
  _Atomic uint32_t queued_requests;  /* .1 Plan 02: sync with sockproxy.h:214 (COMP-07) */
  _Atomic uint64_t total_requests;
  uint64_t last_update_ts;
  int ep_available;
  _Atomic uint32_t num_gpu_blocks;   /* capacity-weighted scorer input */
  _Atomic uint32_t swap_pressure;    /* capacity-weighted scorer input */
  _Atomic uint8_t  kv_usage_enc;     /* decode KV pressure: 0 = unknown, 1..101 = pct + 1 */
} ep_load_tracker_t;

typedef struct llm_prefix_key {
  /* Level 1: Global */
  char prefix[MAX_PREFIX_LEN];
  char model[MAX_MODEL_LEN];
  uint32_t flags;
  char lora_adapter[MAX_LORA_LEN];
  char image_hash[MAX_HASH_LEN];
  char audio_hash[MAX_HASH_LEN];
  char cache_salt[MAX_SALT_LEN];
  char tool_schemas_hash[MAX_HASH_LEN];
  /* Level 2 */
  char session_context_hash[MAX_HASH_LEN];
  /* Level 3 */
  char rag_template_hash[MAX_HASH_LEN];
  char rag_doc_ids_hash[MAX_HASH_LEN];
  /* Computed */
  uint64_t hash;
  int valid;
  int level;
} llm_prefix_key_t;

/* Forward declaration for opaque trie type (defined in sockproxy_pd_trie.c) */
typedef struct pd_trie pd_trie_t;

typedef struct pd_session_mapping {
  char     conv_id[MAX_CONV_ID_LEN];
  int      prefill_ep_idx;
  int      decode_ep_idx;
  uint64_t created_ts;
  _Atomic uint64_t last_access_ts;
  uint32_t request_count;
  UT_hash_handle hh;
} pd_session_mapping_t;

typedef struct proxy_epval {
  int n_eps;
  int ep_sel;
  int select;
  proxy_ent_t eps[MAX_PROXY_EP];

  circuit_breaker_t circuit_breakers[MAX_PROXY_EP];
  uint8_t cb_enabled;

  uint8_t  pd_disagg_enabled;
  uint8_t  ai_gw_mode;
  uint8_t  ep_role[MAX_PROXY_EP];
  int      n_prefill_eps;
  int      n_decode_eps;

  /* P/D Cache-Aware Routing fields */
  uint8_t  pd_cache_aware_mode;
  uint8_t  pd_cache_threshold;
  uint8_t  pd_balance_abs_threshold;
  uint8_t  kv_exact_mode;  /* .1 Plan 02: KV exact routing mode (0=off, 1=zmq) */
  _Atomic uint32_t pd_tier2_rr;
  _Atomic uint32_t pd_decode_rr;  /* .1 Plan 02: sync with sockproxy.h:377 (P2 TB3/TB4) */
  _Atomic uint8_t  pd_kv_fill_state;  /* plan A4: [PD_DEC] fill transition state (sockproxy.h) */
  uint32_t pd_session_ttl_sec;
  ep_load_tracker_t pd_ep_loads[MAX_PROXY_EP];

  /* controller advisory mirror (sockproxy.h) — the #included
   * sockproxy_pd.c reads these in pd_select_prefill. memset-0 init == mode 0 ==
   * byte-identical selection (G3), so every existing case is untouched. */
  _Atomic uint32_t pd_ctrl_ep[MAX_PROXY_EP];
  _Atomic uint8_t  pd_ctrl_mode;

  /* parked FIFO mock (unused here — default-off) */
  pd_parked_fifo_t  pd_parked[MAX_PROXY_EP];
  pthread_mutex_t   pd_parked_lock;

  pd_trie_t           *pd_trie;
  pthread_rwlock_t     pd_trie_lock;

  pd_session_mapping_t *pd_session_map;
  pthread_rwlock_t      pd_session_lock;

  /* capacity admission state (sockproxy.h): pd_select_prefill reads
   * fc.cfg.telemetry_stale_ms for the queue-depth freshness window;
   * memset-0 == the default window. */
  fc_state_t fc;

  UT_hash_handle hh;
} proxy_epval_t;

typedef struct proxy_fd_ent {
  int      fd;                            /* .1 Plan 02: log fd for sockproxy_pd.c */
  _Atomic uint64_t gen;                   /* pfe pool generation (parked staleness guard) */
  char conversation_id[MAX_CONV_ID_LEN];
  int has_conv_id;
  char user_id[128];
  int  has_user_id;
  llm_prefix_key_t prefix_key;
  char     x_model_header[MAX_MODEL_LEN]; /* .1 Plan 02: model hint header */
  int      pd_decode_ep_idx;
  int      park_ep_idx;                   /* parked-behind prefill EP (-1 = not parked) */
  uint64_t park_start_ts;                 /* CLOCK_MONOTONIC ns at park enqueue */
} proxy_fd_ent_t;

/* ===== Log stubs ===== */
#define log_error(fmt, ...) fprintf(stderr, "ERROR: " fmt "\n", ##__VA_ARGS__)
#define log_warn(fmt, ...) fprintf(stderr, "WARN: " fmt "\n", ##__VA_ARGS__)
#define log_debug(fmt, ...) ((void)0)
#define log_info(fmt, ...)  ((void)0)

/* ===== sync-event stubs =====
 * sockproxy_pd.c references proxy_sync_event_t / SYNC_SESSION_*  /
 * llb_sockproxy_emit_sync_event from sockproxy_internal.h. The test build
 * does NOT pull in sockproxy_internal.h (to avoid the proxy_struct singleton
 * and full sockproxy_ep.c link surface), so we provide minimal local stubs
 * here. Mirrors the wire shape from sockproxy_internal.h:171-188 to keep
 * pd_session_build_event() compile-clean even when its body is no-op'd by
 * the TEST_PD_CACHE_AWARE guard in sockproxy_pd.c.
 *
 *.1 Plan 02 Task 2: added to unblock the existing Suite
 * A/B/C tests AND to support the new test_concurrent_cleanup_recursive_lock
 * which exercises the two-pass gather-then-evict idiom under concurrent
 * eviction. */
typedef enum {
    SYNC_SESSION_CREATE = 0,
    SYNC_SESSION_UPDATE = 1,
    SYNC_SESSION_DELETE = 2,
    SYNC_CONV_CREATE    = 3,
    SYNC_CONV_UPDATE    = 4,
    SYNC_CONV_DELETE    = 5,
} proxy_sync_event_kind_t;

typedef struct proxy_sync_event {
    int      kind;
    char     service_key[64];
    char     conv_id[MAX_CONV_ID_LEN];
    int      prefill_ep_idx;
    int      decode_ep_idx;
    int      ep_idx;
    uint64_t created_ts;
    uint64_t last_access_ts;
    uint32_t request_count;
} proxy_sync_event_t;

/* No-op emit sink for test builds — production links the Go //export. */
static inline void llb_sockproxy_emit_sync_event(const proxy_sync_event_t *ev) {
    (void)ev;
}

/* ===== global_stats stub (.1 Plan 02) =====
 * sockproxy_pd.c:958 references `global_stats.pd_kv_t15_fallthrough_total`
 * (and potentially other atomic counters). Mirror only the fields the
 * P/D code touches — anything else stays absent so the compiler flags
 * unanticipated dependencies. */
typedef struct proxy_global_stats {
    _Atomic uint64_t pd_kv_t15_fallthrough_total;
    _Atomic uint64_t conversation_ttl_expirations;
} proxy_global_stats_t;
static proxy_global_stats_t global_stats;

/* pd_kv_exact_select stub: production lives in sockproxy_kv_exact.c (not
 * included in this standalone test build). Tier 1.5 is gated by
 * tepval->kv_exact_mode == 1 — Suites A/B/C never set kv_exact_mode, so the
 * gate is false and this stub is unreachable for them. We still need the
 * symbol present so the link succeeds. Return -1 to mean "Tier 1.5 declined". */
struct proxy_epval; struct proxy_fd_ent;
static inline int pd_kv_exact_select(struct proxy_epval *tepval,
                                     struct proxy_fd_ent *pfe,
                                     int *ep_out, uint32_t excluded_mask) {
    (void)tepval; (void)pfe; (void)ep_out; (void)excluded_mask;
    return -1;
}

/* C2 capacity-aware scorer helpers are static-inline in sockproxy_kv_exact.h, which is
 * NOT included in TEST_PD_CACHE_AWARE mode. The C2 branch in pd_select_prefill is never
 * taken by these tests (ep_sel != PROXY_SEL_GPU_AWARE), so stub them to satisfy the
 * linker. (Defined before the include so there is no implicit-declaration either.) */
uint64_t pd_kv_clamp_capacity(uint32_t capacity) { return capacity ? capacity : 1ULL; }
uint64_t pd_capacity_blend_score(uint32_t a, uint32_t q, uint32_t s,
                                 uint64_t ci, uint64_t tc, int n,
                                 uint32_t qw, uint32_t kw, uint32_t sw) {
  (void)a; (void)q; (void)s; (void)ci; (void)tc; (void)n; (void)qw; (void)kw; (void)sw;
  return 0;
}

/* ===== Include implementations ===== */
/* Override wall time only in this standalone translation unit. The default
 * delegates to the real clock so unrelated concurrency tests are unchanged. */
static time_t session_test_now;
static time_t session_test_time(time_t *out) {
  time_t now = session_test_now ? session_test_now : time(NULL);
  if (out) *out = now;
  return now;
}
#define time session_test_time
/* Trie must be included BEFORE sockproxy_pd.c (defines pd_trie_t type) */
#include "sockproxy_pd_trie.c"
#include "sockproxy_pd.c"

/* ===== Test framework ===== */
static int tests_run = 0;
static int tests_passed = 0;

#define ASSERT_EQ(a, b, msg) do { \
  if ((a) != (b)) { \
    printf("  FAIL: %s (expected %d, got %d)\n", msg, (int)(b), (int)(a)); \
    return 0; \
  } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
  if (!(cond)) { \
    printf("  FAIL: %s\n", msg); \
    return 0; \
  } \
} while(0)

#define RUN_TEST(fn) do { \
  tests_run++; \
  printf("  [%d] %s ... ", tests_run, #fn); \
  if (fn()) { tests_passed++; printf("PASS\n"); } \
  else { printf("\n"); } \
} while(0)

/* ===== Helper functions ===== */

static void init_cache_aware_epval(proxy_epval_t *ev, int n_prefill, int n_decode) {
  memset(ev, 0, sizeof(*ev));
  ev->n_eps = n_prefill + n_decode;
  ev->pd_disagg_enabled = 1;
  ev->pd_cache_aware_mode = 1;
  ev->pd_cache_threshold = 20;
  ev->pd_balance_abs_threshold = 3;
  ev->pd_session_ttl_sec = 300;
  pthread_rwlock_init(&ev->pd_session_lock, NULL);
  pthread_rwlock_init(&ev->pd_trie_lock, NULL);
  pthread_mutex_init(&ev->pd_parked_lock, NULL);  /* (unused: default-off) */
  ev->pd_trie = pd_trie_create();
  ev->pd_session_map = NULL;

  /* Set up roles: first n_prefill as prefill (1), rest as decode (2) */
  for (int i = 0; i < n_prefill; i++) ev->ep_role[i] = 1;
  for (int i = n_prefill; i < ev->n_eps; i++) ev->ep_role[i] = 2;
  ev->n_prefill_eps = n_prefill;
  ev->n_decode_eps = n_decode;
}

static void cleanup_cache_aware_epval(proxy_epval_t *ev) {
  /* Free session entries */
  pd_session_mapping_t *m, *tmp;
  HASH_ITER(hh, ev->pd_session_map, m, tmp) {
    HASH_DEL(ev->pd_session_map, m);
    free(m);
  }
  if (ev->pd_trie) pd_trie_free(ev->pd_trie);
  pthread_rwlock_destroy(&ev->pd_session_lock);
  pthread_rwlock_destroy(&ev->pd_trie_lock);
}

static void init_test_pfe(proxy_fd_ent_t *pfe) {
  memset(pfe, 0, sizeof(*pfe));
  pfe->pd_decode_ep_idx = -1;
}

/* ===== Suite A: Trie Tests (8 cases) ===== */

/* A1: Basic insert and exact match */
static int test_trie_insert_match(void) {
  pd_trie_t *t = pd_trie_create();
  ASSERT_TRUE(t != NULL, "trie created");

  pd_trie_insert(t, "You are a helpful assistant", 27, 0);

  int ep = -1; float rate = 0.0f;
  ASSERT_EQ(pd_trie_match(t, "You are a helpful assistant", 27, &ep, &rate), 0, "exact match");
  ASSERT_EQ(ep, 0, "ep_idx=0");
  ASSERT_TRUE(rate > 0.99f, "rate ~1.0");

  pd_trie_free(t);
  return 1;
}

/* A2: Prefix match returns longest match */
static int test_trie_prefix_match(void) {
  pd_trie_t *t = pd_trie_create();
  pd_trie_insert(t, "You are a helpful", 17, 0);
  pd_trie_insert(t, "You are a helpful assistant for coding", 38, 1);

  int ep = -1; float rate = 0.0f;
  pd_trie_match(t, "You are a helpful assistant for coding tasks", 44, &ep, &rate);
  ASSERT_EQ(ep, 1, "longest prefix match returns EP 1");

  pd_trie_free(t);
  return 1;
}

/* A3: No match returns -1 */
static int test_trie_no_match(void) {
  pd_trie_t *t = pd_trie_create();
  pd_trie_insert(t, "Hello world", 11, 0);

  int ep = -1; float rate = 0.0f;
  ASSERT_EQ(pd_trie_match(t, "Goodbye world", 13, &ep, &rate), -1, "no match");

  pd_trie_free(t);
  return 1;
}

/* A4: Remove EP clears all nodes for that EP */
static int test_trie_remove_ep(void) {
  pd_trie_t *t = pd_trie_create();
  pd_trie_insert(t, "prompt A", 8, 0);
  pd_trie_insert(t, "prompt B", 8, 0);
  pd_trie_insert(t, "prompt C", 8, 1);

  pd_trie_remove_ep(t, 0);

  int ep = -1; float rate = 0.0f;
  ASSERT_EQ(pd_trie_match(t, "prompt A", 8, &ep, &rate), -1, "EP0 entries gone");
  ASSERT_EQ(pd_trie_match(t, "prompt C", 8, &ep, &rate), 0, "EP1 entry remains");

  pd_trie_free(t);
  return 1;
}

/* A5: Node count tracks insertions */
static int test_trie_node_count(void) {
  pd_trie_t *t = pd_trie_create();
  ASSERT_EQ((int)pd_trie_node_count(t), 1, "root only");

  pd_trie_insert(t, "abc", 3, 0);
  ASSERT_TRUE(pd_trie_node_count(t) > 1, "count increases");

  pd_trie_free(t);
  return 1;
}

/* A6: LRU eviction removes oldest leaf */
static int test_trie_evict_lru(void) {
  pd_trie_t *t = pd_trie_create();
  pd_trie_insert(t, "aaa", 3, 0);
  pd_trie_insert(t, "bbb", 3, 1);
  pd_trie_insert(t, "ccc", 3, 2);
  pd_trie_insert(t, "ddd", 3, 3);

  size_t before = pd_trie_node_count(t);
  pd_trie_evict_lru(t, 3);
  ASSERT_TRUE(pd_trie_node_count(t) <= 3, "evicted to max_nodes");
  (void)before;

  pd_trie_free(t);
  return 1;
}

/* A7: Match rate calculation */
static int test_trie_match_rate(void) {
  pd_trie_t *t = pd_trie_create();
  pd_trie_insert(t, "abcdef", 6, 0);

  int ep = -1; float rate = 0.0f;
  /* Query "abcdefghij" (10 chars) should match 6/10 = 0.6 */
  pd_trie_match(t, "abcdefghij", 10, &ep, &rate);
  ASSERT_EQ(ep, 0, "partial match EP");
  ASSERT_TRUE(rate >= 0.55f && rate <= 0.65f, "match_rate ~0.6");

  pd_trie_free(t);
  return 1;
}

/* A8: Overwrite existing entry with different EP */
static int test_trie_overwrite_ep(void) {
  pd_trie_t *t = pd_trie_create();
  pd_trie_insert(t, "same prompt", 11, 0);
  pd_trie_insert(t, "same prompt", 11, 1);

  int ep = -1; float rate = 0.0f;
  pd_trie_match(t, "same prompt", 11, &ep, &rate);
  ASSERT_EQ(ep, 1, "overwritten to EP1");

  pd_trie_free(t);
  return 1;
}

/* ===== Suite B: Session Tests (7 cases) ===== */

/* B1: Store and lookup */
static int test_session_store_lookup(void) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);

  pd_session_store(&ev, "conv-123", 0, 3);

  int p = -1, d = -1;
  ASSERT_EQ(pd_session_lookup(&ev, "conv-123", &p, &d), 0, "session found");
  ASSERT_EQ(p, 0, "prefill EP");
  ASSERT_EQ(d, 3, "decode EP");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* B2: Lookup miss returns -1 */
static int test_session_lookup_miss(void) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);

  int p = -1, d = -1;
  ASSERT_EQ(pd_session_lookup(&ev, "nonexistent", &p, &d), -1, "miss returns -1");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* B3: TTL expiry returns -1 */
static int test_session_ttl_expiry(void) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);
  ev.pd_session_ttl_sec = 1;

  pd_session_store(&ev, "conv-ttl", 0, 3);

  /* Manipulate last_access_ts to simulate expiry */
  pd_session_mapping_t *m = NULL;
  HASH_FIND_STR(ev.pd_session_map, "conv-ttl", m);
  ASSERT_TRUE(m != NULL, "entry found before manipulation");
  atomic_store(&m->last_access_ts, (uint64_t)(time(NULL) - 3));

  /* Lookup should detect expiry */
  int p = -1, d = -1;
  ASSERT_EQ(pd_session_lookup(&ev, "conv-ttl", &p, &d), -1, "expired entry returns -1");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* B4: LRU eviction at capacity */
static int test_session_lru_eviction(void) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);

  /* Store PD_SESSION_MAX_ENTRIES + 1 entries */
  char key[64];
  for (int i = 0; i < PD_SESSION_MAX_ENTRIES + 1; i++) {
    snprintf(key, sizeof(key), "conv-%d", i);
    pd_session_store(&ev, key, 0, 3);
  }

  /* Count should be capped at PD_SESSION_MAX_ENTRIES */
  unsigned int count = HASH_COUNT(ev.pd_session_map);
  ASSERT_EQ((int)count, PD_SESSION_MAX_ENTRIES, "capped at max entries");

  /* First entry should have been evicted (LRU) */
  int p = -1, d = -1;
  ASSERT_EQ(pd_session_lookup(&ev, "conv-0", &p, &d), -1, "oldest entry evicted");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* B5: Evict by key removes specific entry */
static int test_session_evict_key(void) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);

  pd_session_store(&ev, "keep-me", 0, 3);
  pd_session_store(&ev, "remove-me", 1, 4);

  pd_session_evict_key(&ev, "remove-me");

  int p = -1, d = -1;
  ASSERT_EQ(pd_session_lookup(&ev, "remove-me", &p, &d), -1, "evicted entry gone");
  ASSERT_EQ(pd_session_lookup(&ev, "keep-me", &p, &d), 0, "kept entry remains");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* B6: Upsert updates existing session */
static int test_session_upsert(void) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);

  pd_session_store(&ev, "conv-upd", 0, 3);
  pd_session_store(&ev, "conv-upd", 1, 4);

  int p = -1, d = -1;
  ASSERT_EQ(pd_session_lookup(&ev, "conv-upd", &p, &d), 0, "upsert found");
  ASSERT_EQ(p, 1, "updated prefill EP");
  ASSERT_EQ(d, 4, "updated decode EP");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* B7: Batch TTL eviction */
static int test_session_batch_evict(void) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);
  ev.pd_session_ttl_sec = 1;

  pd_session_store(&ev, "old-1", 0, 3);
  pd_session_store(&ev, "old-2", 1, 4);
  pd_session_store(&ev, "fresh", 2, 3);

  /* Make old-1 and old-2 expired */
  pd_session_mapping_t *m1 = NULL, *m2 = NULL;
  HASH_FIND_STR(ev.pd_session_map, "old-1", m1);
  HASH_FIND_STR(ev.pd_session_map, "old-2", m2);
  ASSERT_TRUE(m1 != NULL && m2 != NULL, "entries found");
  uint64_t expired = (uint64_t)(time(NULL) - 3);
  atomic_store(&m1->last_access_ts, expired);
  atomic_store(&m2->last_access_ts, expired);

  pd_session_evict(&ev);

  int p = -1, d = -1;
  ASSERT_EQ(pd_session_lookup(&ev, "old-1", &p, &d), -1, "old-1 evicted");
  ASSERT_EQ(pd_session_lookup(&ev, "old-2", &p, &d), -1, "old-2 evicted");
  ASSERT_EQ(pd_session_lookup(&ev, "fresh", &p, &d), 0, "fresh remains");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* ===== Suite C: Integration Tests (5 cases) ===== */

/* Zero means the 300s default. Literal expectations deliberately do not use
 * the production default constant: changing it accidentally must fail tests.
 * Clean up before assertions so expected RED does not create fixture leaks. */
static int test_session_zero_ttl_lookup(void) {
  for (unsigned age = 299; age <= 301; age++) {
    proxy_epval_t ev;
    init_cache_aware_epval(&ev, 3, 2);
    ev.pd_session_ttl_sec = 0;
    session_test_now = 1700000000;
    pd_session_store(&ev, "zero-lookup", 1, 4);
    session_test_now += age;
    int p = -1, d = -1;
    int rc = pd_session_lookup(&ev, "zero-lookup", &p, &d);
    cleanup_cache_aware_epval(&ev);
    session_test_now = 0;
    ASSERT_EQ(rc, age <= 300 ? 0 : -1, "default lookup boundary is idle > 300s");
    ASSERT_EQ(p, age <= 300 ? 1 : -1, "lookup only returns a live prefill hint");
    ASSERT_EQ(d, age <= 300 ? 4 : -1, "lookup only returns a live decode hint");
  }
  return 1;
}

static int test_session_zero_ttl_evict(void) {
  for (unsigned age = 299; age <= 301; age++) {
    proxy_epval_t ev;
    init_cache_aware_epval(&ev, 3, 2);
    ev.pd_session_ttl_sec = 0;
    session_test_now = 1700000000;
    pd_session_store(&ev, "zero-evict", 1, 4);
    session_test_now += age;
    pd_session_evict(&ev);
    unsigned count = HASH_COUNT(ev.pd_session_map);
    cleanup_cache_aware_epval(&ev);
    session_test_now = 0;
    ASSERT_EQ(count, age <= 300 ? 1 : 0, "default eviction boundary is idle > 300s");
  }
  return 1;
}

static int test_session_positive_ttl_controls(void) {
  const uint32_t ttls[] = {1, 300, 600, INT32_MAX};
  for (unsigned i = 0; i < sizeof(ttls) / sizeof(ttls[0]); i++) {
    for (int offset = -1; offset <= 1; offset++) {
      for (int lookup = 0; lookup <= 1; lookup++) {
        proxy_epval_t ev;
        init_cache_aware_epval(&ev, 3, 2);
        ev.pd_session_ttl_sec = ttls[i];
        session_test_now = 1700000000;
        pd_session_store(&ev, "positive-ttl", 1, 4);
        session_test_now += (time_t)ttls[i] + offset;
        int p = -1, d = -1;
        int live;
        if (lookup) {
          live = pd_session_lookup(&ev, "positive-ttl", &p, &d) == 0;
        } else {
          pd_session_evict(&ev);
          live = HASH_COUNT(ev.pd_session_map) == 1;
        }
        cleanup_cache_aware_epval(&ev);
        session_test_now = 0;
        ASSERT_EQ(live, offset <= 0, "positive TTL lookup and eviction honor exact override boundary");
      }
    }
  }
  return 1;
}

static int test_session_sliding_ttl_refresh(void) {
  const uint32_t ttls[] = {0, 600};
  for (unsigned i = 0; i < sizeof(ttls) / sizeof(ttls[0]); i++) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);
  ev.pd_session_ttl_sec = ttls[i];
  session_test_now = 1700000000;
  pd_session_store(&ev, "refresh-ttl", 1, 4);
  pd_session_mapping_t *m = NULL;
  HASH_FIND_STR(ev.pd_session_map, "refresh-ttl", m);
  session_test_now += 200;
  uint64_t start = (uint64_t)session_test_now;
  int p = -1, d = -1;
  int rc = pd_session_lookup(&ev, "refresh-ttl", &p, &d);
  uint64_t refreshed = atomic_load(&m->last_access_ts);
  session_test_now += 200;
  pd_session_evict(&ev);
  unsigned retained = HASH_COUNT(ev.pd_session_map);
  pd_session_store(&ev, "refresh-ttl", 1, 4);
  HASH_FIND_STR(ev.pd_session_map, "refresh-ttl", m);
  uint64_t stored = atomic_load(&m->last_access_ts);
  cleanup_cache_aware_epval(&ev);
  session_test_now = 0;
  ASSERT_EQ(rc, 0, "unexpired session lookup succeeds");
  ASSERT_TRUE(refreshed == start, "successful access refreshes sliding expiry");
  ASSERT_EQ(retained, 1, "TTL is idle time, not time since creation");
  ASSERT_TRUE(stored == start + 200, "upsert refreshes the idle timestamp");
  }
  return 1;
}

static int test_session_zero_ttl_capacity_bound(void) {
  proxy_epval_t ev;
  init_cache_aware_epval(&ev, 3, 2);
  ev.pd_session_ttl_sec = 0;
  char key[64];
  for (int i = 0; i <= PD_SESSION_MAX_ENTRIES; i++) {
    snprintf(key, sizeof(key), "zero-capacity-%d", i);
    pd_session_store(&ev, key, 0, 3);
  }
  unsigned count = HASH_COUNT(ev.pd_session_map);
  cleanup_cache_aware_epval(&ev);
  ASSERT_EQ(count, PD_SESSION_MAX_ENTRIES, "default TTL must preserve the memory capacity bound");
  return 1;
}

static int test_session_ttl_without_trie(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);
  ev.pd_cache_aware_mode = 0;
  ev.pd_session_ttl_sec = 0;
  pfe.has_user_id = 1;
  strcpy(pfe.user_id, "ttl-without-trie");
  session_test_now = 1700000000;
  pd_session_store(&ev, pfe.user_id, 1, 4);
  int pre = -1;
  int hit = pd_select_prefill(&ev, &pfe, &pre, 0);
  int hinted_decode = pfe.pd_decode_ep_idx;
  session_test_now += 301;
  pfe.pd_decode_ep_idx = -1;
  int fallback = pd_select_prefill(&ev, &pfe, &pre, 0);
  int expired_hint = pfe.pd_decode_ep_idx;
  cleanup_cache_aware_epval(&ev);
  session_test_now = 0;
  ASSERT_EQ(hit, 0, "Tier 0 works without trie affinity");
  ASSERT_EQ(hinted_decode, 4, "Tier 0 supplies the stored pair hint");
  ASSERT_EQ(fallback, 0, "expiry proceeds to lower-tier selection");
  ASSERT_EQ(expired_hint, -1, "expired pair does not supply a decode hint");
  return 1;
}

/* C1: Tier 0 session hit returns cached EP */
static int test_select_prefill_tier0_session(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);

  /* Pre-store session */
  pd_session_store(&ev, "user-abc", 1, 4);

  /* Set up pfe with user_id */
  pfe.has_user_id = 1;
  strncpy(pfe.user_id, "user-abc", sizeof(pfe.user_id) - 1);

  int ep = -1;
  ASSERT_EQ(pd_select_prefill(&ev, &pfe, &ep, 0), 0, "Tier 0 hit");
  ASSERT_EQ(ep, 1, "session prefill EP");
  ASSERT_EQ(pfe.pd_decode_ep_idx, 4, "decode hint set");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* C2: Tier 1 trie hit with sufficient match_rate */
static int test_select_prefill_tier1_trie(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);

  /* Insert trie entry */
  pd_trie_insert(ev.pd_trie, "You are a code assistant", 24, 2);

  /* Set prefix */
  strncpy(pfe.prefix_key.prefix, "You are a code assistant", MAX_PREFIX_LEN - 1);
  pfe.prefix_key.level = 1;

  ev.pd_cache_threshold = 20; /* 20% minimum match rate */

  int ep = -1;
  ASSERT_EQ(pd_select_prefill(&ev, &pfe, &ep, 0), 0, "Tier 1 hit");
  ASSERT_EQ(ep, 2, "trie EP");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* C3: Tier 2 min-load fallback */
static int test_select_prefill_tier2_minload(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);

  /* No session, no trie match (empty prefix) */
  /* Set different loads on prefill EPs */
  atomic_store(&ev.pd_ep_loads[0].active_conns, 5);
  atomic_store(&ev.pd_ep_loads[1].active_conns, 2);
  atomic_store(&ev.pd_ep_loads[2].active_conns, 8);

  int ep = -1;
  ASSERT_EQ(pd_select_prefill(&ev, &pfe, &ep, 0), 0, "Tier 2 fallback");
  ASSERT_EQ(ep, 1, "min-load EP");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* C4: Load-imbalance guard bypasses trie */
static int test_select_prefill_load_imbalance_guard(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);

  /* Insert trie entry pointing to EP 0 */
  pd_trie_insert(ev.pd_trie, "prompt X", 8, 0);

  /* Set high load imbalance: ep0=10, ep1=2, ep2=3 */
  atomic_store(&ev.pd_ep_loads[0].active_conns, 10);
  atomic_store(&ev.pd_ep_loads[1].active_conns, 2);
  atomic_store(&ev.pd_ep_loads[2].active_conns, 3);

  ev.pd_balance_abs_threshold = 3;  /* max_load(10) - min_load(2) = 8 > 3 */

  /* Set prefix to match trie */
  strncpy(pfe.prefix_key.prefix, "prompt X", MAX_PREFIX_LEN - 1);
  pfe.prefix_key.level = 1;

  int ep = -1;
  ASSERT_EQ(pd_select_prefill(&ev, &pfe, &ep, 0), 0, "guard bypass");
  ASSERT_EQ(ep, 1, "redirected to min-load EP instead of trie EP");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* C5: Decode EP selection: session hint then min-load */
static int test_select_decode_session_hint(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);

  /* Test 1: Session hint from Tier 0 */
  pfe.pd_decode_ep_idx = 4;  /* Simulating hint from pd_select_prefill */

  int ep = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "decode with hint");
  ASSERT_EQ(ep, 4, "respects session hint");

  /* Test 2: Without hint, uses min-load */
  pfe.pd_decode_ep_idx = -1;
  atomic_store(&ev.pd_ep_loads[3].active_conns, 5);
  atomic_store(&ev.pd_ep_loads[4].active_conns, 2);

  ep = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "decode min-load");
  ASSERT_EQ(ep, 4, "min-load decode EP");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* ===== Suite D: Concurrent cleanup recursive-lock test (.1) ===== */

/* Mock proxy_struct singleton — file-local. The real proxy_struct lives in
 * sockproxy_ep.c which is NOT linked into this standalone test (verified via
 * the Makefile target at L226-227: only test_pd_cache_aware.c +
 * sockproxy_pd.c + sockproxy_pd_trie.c). So this stub is collision-free.
 * The stub mirrors only the lock field — that's all the gather/evict idiom
 * needs to exercise. */
typedef struct test_proxy_struct {
  pthread_rwlock_t lock;  /* Pri-1 — wrlock by cleanup, rdlock by the mock
                             pd_session_evict stub to mimic the production
                             pd_session_resolve_service_key recursion site. */
} test_proxy_struct_t;
static test_proxy_struct_t proxy_struct_stub;

/* Mock ephash entry — kept minimal. */
typedef struct test_pd_tepval {
  int pd_disagg_enabled;
  int ep_idx;
  pthread_rwlock_t pd_session_lock;  /* Pri-4 */
  UT_hash_handle hh;
} test_pd_tepval_t;

#define D5_NUM_TEPVALS         80   /* >65 to force heap-spill (CONTEXT) */
#define D5_EVICTOR_THREADS     4    /* concurrent request-path simulators */
#define D5_EVICTOR_ITERATIONS  500  /* per-thread loop count */

/* Shared state for the test. */
typedef struct test_d5_state {
  test_pd_tepval_t  pool[D5_NUM_TEPVALS];
  test_pd_tepval_t *ephash;
  _Atomic int       evictor_edeadlk;        /* set if any evictor sees EDEADLK */
  _Atomic int       cleanup_edeadlk;        /* set if cleanup sees EDEADLK */
  _Atomic int       evict_stub_invocations; /* counts mock pd_session_evict calls */
  _Atomic int       shutdown;
} test_d5_state_t;

/* Mock pd_session_evict — mimics the production recursion site:
 *   wrlock pd_session_lock (Pri-4)
 *   then rdlock proxy_struct_stub.lock (Pri-1, the very recursion the
 *     two-pass refactor avoids)
 *   then unlock both.
 * If the cleanup thread is still holding proxy_struct_stub.lock as wrlock
 * when this runs, glibc may return EDEADLK or silently deadlock. The
 * two-pass refactor guarantees this is called AFTER PROXY_UNLOCK, so the
 * rdlock here is acquired cleanly. */
static void
d5_pd_session_evict_stub(test_d5_state_t *st, test_pd_tepval_t *tepval) {
  int rc = pthread_rwlock_wrlock(&tepval->pd_session_lock);
  if (rc == EDEADLK) atomic_store(&st->cleanup_edeadlk, 1);
  /* Pretend to do work — pd_session_map walk would happen here. */
  pthread_rwlock_unlock(&tepval->pd_session_lock);

  rc = pthread_rwlock_rdlock(&proxy_struct_stub.lock);
  if (rc == EDEADLK) atomic_store(&st->cleanup_edeadlk, 1);
  /* This is the recursion check — if the caller is still holding the
   * wrlock on proxy_struct_stub.lock, POSIX rwlock recursion is UB. */
  pthread_rwlock_unlock(&proxy_struct_stub.lock);

  atomic_fetch_add(&st->evict_stub_invocations, 1);
}

/* Request-path simulator: takes/releases pd_session_lock on random tepvals,
 * concurrent with the cleanup thread. */
static void *
d5_evictor_thread(void *arg) {
  test_d5_state_t *st = (test_d5_state_t *)arg;
  unsigned int seed = (unsigned int)(uintptr_t)arg ^ (unsigned int)time(NULL);
  for (int i = 0; i < D5_EVICTOR_ITERATIONS; i++) {
    if (atomic_load(&st->shutdown)) break;
    int idx = rand_r(&seed) % D5_NUM_TEPVALS;
    int rc = pthread_rwlock_wrlock(&st->pool[idx].pd_session_lock);
    if (rc == EDEADLK) atomic_store(&st->evictor_edeadlk, 1);
    /* Simulate a small request-path mutation. */
    pthread_rwlock_unlock(&st->pool[idx].pd_session_lock);
  }
  return NULL;
}

/* Cleanup thread: implements the SAME two-pass gather-then-evict idiom that
 * Task 1 added to sockproxy_ep.c. Gathers victims under wrlock; releases
 * wrlock; calls d5_pd_session_evict_stub() on each victim. */
static void *
d5_cleanup_thread(void *arg) {
  test_d5_state_t *st = (test_d5_state_t *)arg;

  /* Gather */
  test_pd_tepval_t *victims_stack[64];
  test_pd_tepval_t **victims = victims_stack;
  size_t n_v = 0, cap_v = 64;
  int spill_taken = 0;

  int rc = pthread_rwlock_wrlock(&proxy_struct_stub.lock);
  if (rc == EDEADLK) atomic_store(&st->cleanup_edeadlk, 1);

  test_pd_tepval_t *iter, *tmp;
  HASH_ITER(hh, st->ephash, iter, tmp) {
    if (iter->pd_disagg_enabled) {
      if (n_v == cap_v) {
        cap_v *= 2;
        spill_taken = 1;
        if (victims == victims_stack) {
          test_pd_tepval_t **heap = malloc(cap_v * sizeof *heap);
          memcpy(heap, victims_stack, n_v * sizeof *heap);
          victims = heap;
        } else {
          victims = realloc(victims, cap_v * sizeof *victims);
        }
      }
      victims[n_v++] = iter;
    }
  }

  pthread_rwlock_unlock(&proxy_struct_stub.lock);

  /* Evict AFTER unlock — the entire point of. */
  for (size_t i = 0; i < n_v; i++) {
    d5_pd_session_evict_stub(st, victims[i]);
  }

  if (victims != victims_stack) free(victims);

  /* Encode (n_v << 1) | spill_taken in the return — caller asserts both. */
  return (void *)(uintptr_t)((n_v << 1) | (spill_taken ? 1 : 0));
}

/* D1: Two-pass gather-then-evict under 4 concurrent request-path threads.
 *
 * Forces heap-spill by inserting 80 mock tepvals (D5_NUM_TEPVALS > 64 stack
 * cap). Verifies:
 *   (a) no EDEADLK from cleanup or evictor threads
 *   (b) all 80 victims evicted exactly once
 *   (c) realloc spill branch actually executed (spill_taken bit set)
 *   (d) ASan clean (no UAF; gather under wrlock, evict after unlock)
 */
static int test_concurrent_cleanup_recursive_lock(void) {
  test_d5_state_t st;
  memset(&st, 0, sizeof(st));
  pthread_rwlock_init(&proxy_struct_stub.lock, NULL);

  /* Build the ephash. */
  for (int i = 0; i < D5_NUM_TEPVALS; i++) {
    st.pool[i].pd_disagg_enabled = 1;
    st.pool[i].ep_idx = i;
    pthread_rwlock_init(&st.pool[i].pd_session_lock, NULL);
    HASH_ADD_INT(st.ephash, ep_idx, &st.pool[i]);
  }

  /* Spawn request-path evictor threads BEFORE the cleanup thread so the
   * cleanup thread immediately faces concurrent load. */
  pthread_t evictors[D5_EVICTOR_THREADS];
  for (int i = 0; i < D5_EVICTOR_THREADS; i++) {
    pthread_create(&evictors[i], NULL, d5_evictor_thread, &st);
  }

  /* Run cleanup thread inline (it returns the (n_v, spill_taken) encoding). */
  pthread_t cleanup;
  pthread_create(&cleanup, NULL, d5_cleanup_thread, &st);

  void *cleanup_ret = NULL;
  pthread_join(cleanup, &cleanup_ret);

  /* Signal evictors to stop and join. */
  atomic_store(&st.shutdown, 1);
  for (int i = 0; i < D5_EVICTOR_THREADS; i++) {
    pthread_join(evictors[i], NULL);
  }

  uintptr_t encoded = (uintptr_t)cleanup_ret;
  size_t n_v = encoded >> 1;
  int spill_taken = (int)(encoded & 1);

  /* (a) no EDEADLK */
  ASSERT_EQ(atomic_load(&st.cleanup_edeadlk), 0, "cleanup no EDEADLK");
  ASSERT_EQ(atomic_load(&st.evictor_edeadlk), 0, "evictor no EDEADLK");

  /* (b) victim count exact */
  ASSERT_EQ((int)n_v, D5_NUM_TEPVALS, "gathered n_v == D5_NUM_TEPVALS");
  ASSERT_EQ(atomic_load(&st.evict_stub_invocations), D5_NUM_TEPVALS,
            "evict stub called once per victim");

  /* (c) spill branch exercised (80 > 64 stack cap) */
  ASSERT_TRUE(spill_taken, "realloc spill branch executed");

  /* (d) ASan-clean — implicit; if UAF occurred it would have aborted. */

  /* Cleanup. */
  for (int i = 0; i < D5_NUM_TEPVALS; i++) {
    HASH_DEL(st.ephash, &st.pool[i]);
    pthread_rwlock_destroy(&st.pool[i].pd_session_lock);
  }
  pthread_rwlock_destroy(&proxy_struct_stub.lock);

  return 1;
}

/* ===== main() ===== */

/* =====: per-EP in-flight admission-cap tests =====
 * Run as a SEPARATE process (argv "cap") with LLB_PD_MAX_INFLIGHT_PER_EP set, because
 * pd_max_inflight_per_ep() caches the env once per process. cap=4 throughout. */

/* E1: an over-cap EP is hidden from selection -> spill to an under-cap EP (even when
 * the trie/cache owner is the over-cap EP). */
static int test_cap_spill_from_over_cap_owner(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);

  ev.pd_balance_abs_threshold = 100;   /* keep the trie guard from bypassing */
  pd_trie_insert(ev.pd_trie, "prompt X", 8, 0);   /* trie -> EP0 (the cache owner) */
  strncpy(pfe.prefix_key.prefix, "prompt X", MAX_PREFIX_LEN - 1);
  pfe.prefix_key.level = 1;

  /* EP0 (the owner) is AT cap=4; EP1=1, EP2=2 are under cap. */
  atomic_store(&ev.pd_ep_loads[0].active_conns, 4);
  atomic_store(&ev.pd_ep_loads[1].active_conns, 1);
  atomic_store(&ev.pd_ep_loads[2].active_conns, 2);

  int ep = -1;
  ASSERT_EQ(pd_select_prefill(&ev, &pfe, &ep, 0), 0, "spill: rc ok");
  ASSERT_EQ(ep, 1, "spill: routed to under-cap min-load EP1, not over-cap owner EP0");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E2: ALL healthy prefill EPs at/over cap -> shed (PD_PREFILL_NO_CAPACITY). */
static int test_cap_all_at_cap_sheds(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);

  atomic_store(&ev.pd_ep_loads[0].active_conns, 4);   /* all at cap=4 */
  atomic_store(&ev.pd_ep_loads[1].active_conns, 5);
  atomic_store(&ev.pd_ep_loads[2].active_conns, 4);

  int ep = -99;
  ASSERT_EQ(pd_select_prefill(&ev, &pfe, &ep, 0),
            PD_PREFILL_NO_CAPACITY, "all-at-cap -> NO_CAPACITY");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E3: all under cap -> the cap is inert; normal min-load selection. */
static int test_cap_under_cap_normal(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 3, 2);
  init_test_pfe(&pfe);

  atomic_store(&ev.pd_ep_loads[0].active_conns, 3);   /* all < cap=4 */
  atomic_store(&ev.pd_ep_loads[1].active_conns, 1);
  atomic_store(&ev.pd_ep_loads[2].active_conns, 2);

  int ep = -1;
  ASSERT_EQ(pd_select_prefill(&ev, &pfe, &ep, 0), 0, "under-cap: rc ok");
  ASSERT_EQ(ep, 1, "under-cap: normal min-load EP1");

  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* ===== Suite E: Decode KV-pressure scoring (plan A3, LLB_PD_DECODE_KV_WEIGHT) =====
 *
 * Default run: the env is unset, pd_decode_kv_weight() == 0, the selector is the
 * shipped min-load scorer — test_kv_w0_identity pins that with mixed KV values.
 * "kv" run (Makefile: LLB_PD_DECODE_KV_WEIGHT=8 ./test_pd_cache_aware kv): the
 * weight is read once at the first selection, so the whole kv suite runs at W=8.
 *
 * Topology: init_cache_aware_epval(&ev, 2, 3) → EP0/EP1 prefill, EP2/EP3/EP4
 * decode. kv_usage_enc is the production encoding (pct + 1, 0 = unknown).
 * Freshness is the queue-depth stamp: kv_stamp_fresh() writes "now" in
 * CLOCK_MONOTONIC seconds (the production clock), kv_stamp_stale() a stamp
 * older than the default telemetry window (memset-0 fc.cfg → the default). */

static uint64_t kv_now_sec(void) { return pd_now_ns() / 1000000000ULL; }

static void kv_set(proxy_epval_t *ev, int ep, uint32_t conns, int kv_pct /* -1 = unknown */) {
  atomic_store(&ev->pd_ep_loads[ep].active_conns, conns);
  atomic_store(&ev->pd_ep_loads[ep].kv_usage_enc,
               kv_pct < 0 ? (uint8_t)0 : (uint8_t)(kv_pct + 1));
}
static void kv_stamp_fresh(proxy_epval_t *ev, int ep) {
  /* plain store: the test mirror declares last_update_ts non-atomic (as the
   * other suites do); the selector's atomic_load is a plain read here. */
  ev->pd_ep_loads[ep].last_update_ts = kv_now_sec();
}
static void kv_stamp_stale(proxy_epval_t *ev, int ep) {
  /* 1 s after boot: older than FC_TELEMETRY_STALE_MS_DEFAULT on any host that
   * has been up longer than the window (the unit bed always has). */
  ev->pd_ep_loads[ep].last_update_ts = (uint64_t)1;
}

/* E0 (default run, W=0): mixed KV values change nothing — the pick is the
 * pre-change expectation, min active_conns, even though EP2 is at 92 %. */
static int test_kv_w0_identity(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);
  ASSERT_EQ(pd_decode_kv_weight(), 0, "W unset reads 0");

  kv_set(&ev, 2, 10, 92); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 11, 40); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 11, 50); kv_stamp_fresh(&ev, 4);

  for (int round = 0; round < 8; round++) {
    int ep = -1;
    pfe.pd_decode_ep_idx = -1;
    ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "W=0: rc ok");
    ASSERT_EQ(ep, 2, "W=0: min active_conns wins regardless of KV");
  }
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E1 (kv run): the plan §2 example. conns 10/11/11, KV 92/40/50 → with W=8
 * the scores are 17 / 14 / 15, so EP3 wins over the lightly-connected EP2. */
static int test_kv_pressure_ordering(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);
  ASSERT_EQ(pd_decode_kv_weight(), 8, "kv run: W=8 cached");

  kv_set(&ev, 2, 10, 92); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 11, 40); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 11, 50); kv_stamp_fresh(&ev, 4);

  for (int round = 0; round < 8; round++) {
    int ep = -1;
    pfe.pd_decode_ep_idx = -1;
    ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "ordering: rc ok");
    ASSERT_EQ(ep, 3, "ordering: lowest conns + kv term wins");
    ASSERT_EQ(pfe.pd_decode_ep_idx, 3, "ordering: hint written by the score path");
  }
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E2 (kv run): an EP that never reported (enc 0) is neutralized to the fleet
 * mean, never read as 0 %. conns 11/10/10, KV unknown/90/90: with the mean
 * (90) EP2 scores 18 against 17/17 and loses; read as 0 % it would score 11
 * and win — the §3.3 row-1 failure. */
static int test_kv_unknown_neutralised(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 11, -1); kv_stamp_fresh(&ev, 2);   /* queue reported, usage family absent */
  kv_set(&ev, 3, 10, 90); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 10, 90); kv_stamp_fresh(&ev, 4);

  for (int round = 0; round < 8; round++) {
    int ep = -1;
    pfe.pd_decode_ep_idx = -1;
    ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "unknown: rc ok");
    ASSERT_TRUE(ep == 3 || ep == 4, "unknown: EP2 is not read as idle");
  }
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E3 (kv run): a reading older than the telemetry window is neutralized the
 * same way as unknown (mirrors the H-17 rule for queued). Same numbers as E2
 * but EP2 reported 0 % — with a stale stamp. */
static int test_kv_stale_neutralised(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 11, 0);  kv_stamp_stale(&ev, 2);   /* 0 % but stale → fill */
  kv_set(&ev, 3, 10, 90); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 10, 90); kv_stamp_fresh(&ev, 4);

  for (int round = 0; round < 8; round++) {
    int ep = -1;
    pfe.pd_decode_ep_idx = -1;
    ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "stale: rc ok");
    ASSERT_TRUE(ep == 3 || ep == 4, "stale: a stale 0 % does not attract load");
  }
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E4 (kv run): "reported 0 %" (enc 1) is a reading, scored as 0 — not unknown.
 * conns 11/10/10, KV 0/90/90 all fresh: EP2 = 11, EP3/EP4 = 17 → EP2. Treated
 * as unknown it would be neutralized to 90 (score 18) and lose. */
static int test_kv_zero_reported_is_zero(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 11, 0);  kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 10, 90); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 10, 90); kv_stamp_fresh(&ev, 4);

  for (int round = 0; round < 8; round++) {
    int ep = -1;
    pfe.pd_decode_ep_idx = -1;
    ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "zero: rc ok");
    ASSERT_EQ(ep, 2, "zero: a fresh 0 % reading scores 0");
  }
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E5 (kv run): the session hint (branch [1]) is returned as-is whatever the
 * pressure — D8. EP2 at 100 % with the hint on it stays the answer. */
static int test_kv_hint_precedence(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 50, 100); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 0, 0);    kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 0, 0);    kv_stamp_fresh(&ev, 4);

  pfe.pd_decode_ep_idx = 2;
  int ep = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "hint: rc ok");
  ASSERT_EQ(ep, 2, "hint: pinned EP kept under pressure");
  ASSERT_EQ(pfe.pd_decode_ep_idx, 2, "hint: not rewritten");

  /* The same hint on an excluded EP falls through to the score path. */
  ASSERT_EQ(pd_select_decode_excluding(&ev, &pfe, &ep, 1u << 2), 0, "hint excluded: rc ok");
  ASSERT_TRUE(ep == 3 || ep == 4, "hint excluded: scored among the rest");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E6 (kv run): the excluded mask composes with the kv term. KV 90/10/50 at
 * equal conns → EP3 wins; excluding EP3 → EP4 (score 4) over EP2 (score 7). */
static int test_kv_excluded_with_pressure(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 10, 90); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 10, 10); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 10, 50); kv_stamp_fresh(&ev, 4);

  int ep = -1;
  ASSERT_EQ(pd_select_decode_excluding(&ev, &pfe, &ep, 0), 0, "excl: rc ok");
  ASSERT_EQ(ep, 3, "excl: unconstrained pick");
  pfe.pd_decode_ep_idx = -1;
  ASSERT_EQ(pd_select_decode_excluding(&ev, &pfe, &ep, 1u << 3), 0, "excl: rc ok with mask");
  ASSERT_EQ(ep, 4, "excl: next-best under the mask");
  pfe.pd_decode_ep_idx = -1;
  ASSERT_EQ(pd_select_decode_excluding(&ev, &pfe, &ep, (1u << 2) | (1u << 3) | (1u << 4)), -1,
            "excl: empty candidate set still returns -1");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E7 (kv run): nobody reports → every kv term is 0 → the pick is the W=0
 * pick (min active_conns), in every round. Mirrors a TRT-LLM pool or a
 * scraper that is off (the zero-filled pool). */
static int test_kv_all_unknown_equals_w0(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 10, -1);
  kv_set(&ev, 3, 11, -1);
  kv_set(&ev, 4, 11, -1);

  for (int round = 0; round < 8; round++) {
    int ep = -1;
    pfe.pd_decode_ep_idx = -1;
    ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "all-unknown: rc ok");
    ASSERT_EQ(ep, 2, "all-unknown: identical to the W=0 pick");
  }
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E8 (kv run): ties on the full score still rotate through pd_decode_rr —
 * equal conns and equal KV give every decode EP its turn. */
static int test_kv_tie_rotates(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);
  int seen[MAX_PROXY_EP] = {0};

  for (int ep_i = 2; ep_i <= 4; ep_i++) { kv_set(&ev, ep_i, 5, 60); kv_stamp_fresh(&ev, ep_i); }
  for (int round = 0; round < 9; round++) {
    int ep = -1;
    pfe.pd_decode_ep_idx = -1;
    ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "tie: rc ok");
    ASSERT_TRUE(ep >= 2 && ep <= 4, "tie: a decode EP");
    seen[ep]++;
  }
  ASSERT_EQ(seen[2], 3, "tie: EP2 three of nine");
  ASSERT_EQ(seen[3], 3, "tie: EP3 three of nine");
  ASSERT_EQ(seen[4], 3, "tie: EP4 three of nine");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* ----- Suite E, plan A4: what the recorder is told (PR-3) -----
 * The unit build's pd_record_decode_selected parks the last (path, kv_fill)
 * in pd_test_last_decode_path / pd_test_last_decode_kv_fill; -1 = nothing
 * recorded since the reset. pd_kv_fill_state is the one-shot transition
 * state the production log_info keys on (a no-op macro here). */
static void kv_record_reset(void) {
  pd_test_last_decode_path = -1;
  pd_test_last_decode_kv_fill = -1;
}

/* E9 (kv run): the plan §2 shape at equal conns (92/40/40, all fresh) is a
 * score_kv pick — the kv term removed EP2 from the best set — with no fill. */
static int test_kv_record_score_kv(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 10, 92); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 10, 40); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 10, 40); kv_stamp_fresh(&ev, 4);

  kv_record_reset();
  int ep = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "score_kv: rc ok");
  ASSERT_TRUE(ep == 3 || ep == 4, "score_kv: EP2 avoided");
  ASSERT_EQ(pd_test_last_decode_path, PD_DEC_PATH_SCORE_KV, "score_kv: path recorded");
  ASSERT_EQ(pd_test_last_decode_kv_fill, 0, "score_kv: no fill");
  ASSERT_EQ(atomic_load(&ev.pd_kv_fill_state), 0, "score_kv: fill state untouched");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E10 (kv run): a kv term that leaves the shipped best set as it was is
 * `score`, not score_kv — conns 10/11/11 at equal KV keeps {EP2}. */
static int test_kv_record_score_when_set_unchanged(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 10, 40); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 11, 40); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 11, 40); kv_stamp_fresh(&ev, 4);

  kv_record_reset();
  int ep = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "score: rc ok");
  ASSERT_EQ(ep, 2, "score: the shipped pick");
  ASSERT_EQ(pd_test_last_decode_path, PD_DEC_PATH_SCORE, "score: path recorded");
  ASSERT_EQ(pd_test_last_decode_kv_fill, 0, "score: no fill");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E11 (kv run): the session hint records `hint`, never a fill, and leaves
 * the fill state alone — nothing was scored. */
static int test_kv_record_hint(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 50, 100); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 0, -1);
  kv_set(&ev, 4, 0, -1);

  pfe.pd_decode_ep_idx = 2;
  kv_record_reset();
  int ep = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "hint: rc ok");
  ASSERT_EQ(ep, 2, "hint: pinned EP kept");
  ASSERT_EQ(pd_test_last_decode_path, PD_DEC_PATH_HINT, "hint: path recorded");
  ASSERT_EQ(pd_test_last_decode_kv_fill, 0, "hint: never a fill");
  ASSERT_EQ(atomic_load(&ev.pd_kv_fill_state), 0, "hint: fill state untouched");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E12 (kv run): fill accounting and the one-shot transition state. One
 * unknown candidate → kv_fill 1 and the state goes 0→1 (its fill is the mean
 * of the other two, so the best set is unchanged: `score`); every candidate
 * fresh again → kv_fill 0 and the state goes 1→0; nobody reporting → kv_fill
 * 1 with a fill of 0 (the all-unknown == W=0 case still counts as a broken
 * signal). */
static int test_kv_record_fill_and_transition(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);
  int ep = -1;

  kv_set(&ev, 2, 10, -1); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 10, 90); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 10, 90); kv_stamp_fresh(&ev, 4);
  kv_record_reset();
  pfe.pd_decode_ep_idx = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "fill: rc ok");
  ASSERT_EQ(pd_test_last_decode_path, PD_DEC_PATH_SCORE, "fill: best set unchanged -> score");
  ASSERT_EQ(pd_test_last_decode_kv_fill, 1, "fill: one candidate took the fill");
  ASSERT_EQ(atomic_load(&ev.pd_kv_fill_state), 1, "fill: state 0 -> 1 (log edge)");

  kv_set(&ev, 2, 10, 90); kv_stamp_fresh(&ev, 2);
  kv_record_reset();
  pfe.pd_decode_ep_idx = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "recover: rc ok");
  ASSERT_EQ(pd_test_last_decode_kv_fill, 0, "recover: nobody took the fill");
  ASSERT_EQ(atomic_load(&ev.pd_kv_fill_state), 0, "recover: state 1 -> 0 (log edge)");

  kv_set(&ev, 2, 10, -1);
  kv_set(&ev, 3, 11, -1);
  kv_set(&ev, 4, 11, -1);
  kv_record_reset();
  pfe.pd_decode_ep_idx = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "all-unknown: rc ok");
  ASSERT_EQ(ep, 2, "all-unknown: the W=0 pick");
  ASSERT_EQ(pd_test_last_decode_path, PD_DEC_PATH_SCORE, "all-unknown: score");
  ASSERT_EQ(pd_test_last_decode_kv_fill, 1, "all-unknown: every candidate took the (0) fill");
  ASSERT_EQ(atomic_load(&ev.pd_kv_fill_state), 1, "all-unknown: state 0 -> 1 again");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E13 (kv run): the connect-time variant is not a selection event — the
 * recorder is not called, whether the hint is kept or scored around. */
static int test_kv_record_excluding_is_silent(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);

  kv_set(&ev, 2, 10, 92); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 10, 40); kv_stamp_fresh(&ev, 3);
  kv_set(&ev, 4, 10, 40); kv_stamp_fresh(&ev, 4);

  int ep = -1;
  pfe.pd_decode_ep_idx = 2;
  kv_record_reset();
  ASSERT_EQ(pd_select_decode_excluding(&ev, &pfe, &ep, 0), 0, "silent hint: rc ok");
  ASSERT_EQ(ep, 2, "silent hint: pinned EP kept");
  ASSERT_EQ(pd_test_last_decode_path, -1, "silent hint: nothing recorded");
  ASSERT_EQ(pd_select_decode_excluding(&ev, &pfe, &ep, 1u << 2), 0, "silent scored: rc ok");
  ASSERT_TRUE(ep == 3 || ep == 4, "silent scored: picked around the exclusion");
  ASSERT_EQ(pd_test_last_decode_path, -1, "silent scored: nothing recorded");
  ASSERT_EQ(pd_test_last_decode_kv_fill, -1, "silent scored: no fill recorded");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

/* E14 (default run, W=0): every scored pick is `score` with no fill, and the
 * fill state is never written, whatever the KV values. */
static int test_kv_w0_record_score(void) {
  proxy_epval_t ev;
  proxy_fd_ent_t pfe;
  init_cache_aware_epval(&ev, 2, 3);
  init_test_pfe(&pfe);
  ASSERT_EQ(pd_decode_kv_weight(), 0, "W unset reads 0");

  kv_set(&ev, 2, 10, 92); kv_stamp_fresh(&ev, 2);
  kv_set(&ev, 3, 11, -1);
  kv_set(&ev, 4, 11, 40); kv_stamp_stale(&ev, 4);

  kv_record_reset();
  int ep = -1;
  ASSERT_EQ(pd_select_decode(&ev, &pfe, &ep), 0, "W=0: rc ok");
  ASSERT_EQ(ep, 2, "W=0: the shipped pick");
  ASSERT_EQ(pd_test_last_decode_path, PD_DEC_PATH_SCORE, "W=0: score");
  ASSERT_EQ(pd_test_last_decode_kv_fill, 0, "W=0: never a fill");
  ASSERT_EQ(atomic_load(&ev.pd_kv_fill_state), 0, "W=0: fill state never written");
  cleanup_cache_aware_epval(&ev);
  return 1;
}

int main(int argc, char **argv) {
  if (argc > 1 && strcmp(argv[1], "kv") == 0) {
    printf("\n=== P/D Decode KV-Pressure Tests (LLB_PD_DECODE_KV_WEIGHT=8) ===\n\n");
    RUN_TEST(test_kv_pressure_ordering);
    RUN_TEST(test_kv_unknown_neutralised);
    RUN_TEST(test_kv_stale_neutralised);
    RUN_TEST(test_kv_zero_reported_is_zero);
    RUN_TEST(test_kv_hint_precedence);
    RUN_TEST(test_kv_excluded_with_pressure);
    RUN_TEST(test_kv_all_unknown_equals_w0);
    RUN_TEST(test_kv_tie_rotates);
    RUN_TEST(test_kv_record_score_kv);
    RUN_TEST(test_kv_record_score_when_set_unchanged);
    RUN_TEST(test_kv_record_hint);
    RUN_TEST(test_kv_record_fill_and_transition);
    RUN_TEST(test_kv_record_excluding_is_silent);
    printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);
    return tests_passed != tests_run;
  }
  if (argc > 1 && strcmp(argv[1], "cap") == 0) {
    printf("\n===: P/D Admission-Cap Tests (LLB_PD_MAX_INFLIGHT_PER_EP=4) ===\n\n");
    RUN_TEST(test_cap_spill_from_over_cap_owner);
    RUN_TEST(test_cap_all_at_cap_sheds);
    RUN_TEST(test_cap_under_cap_normal);
    printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);
    return tests_passed != tests_run;
  }

  printf("\n=== P/D Cache-Aware Unit Tests ===\n\n");

  printf("Suite A: Radix Trie Tests\n");
  RUN_TEST(test_trie_insert_match);
  RUN_TEST(test_trie_prefix_match);
  RUN_TEST(test_trie_no_match);
  RUN_TEST(test_trie_remove_ep);
  RUN_TEST(test_trie_node_count);
  RUN_TEST(test_trie_evict_lru);
  RUN_TEST(test_trie_match_rate);
  RUN_TEST(test_trie_overwrite_ep);

  printf("\nSuite B: Session Tests\n");
  RUN_TEST(test_session_store_lookup);
  RUN_TEST(test_session_lookup_miss);
  RUN_TEST(test_session_ttl_expiry);
  RUN_TEST(test_session_lru_eviction);
  RUN_TEST(test_session_evict_key);
  RUN_TEST(test_session_upsert);
  RUN_TEST(test_session_batch_evict);
  RUN_TEST(test_session_zero_ttl_lookup);
  RUN_TEST(test_session_zero_ttl_evict);
  RUN_TEST(test_session_positive_ttl_controls);
  RUN_TEST(test_session_sliding_ttl_refresh);
  RUN_TEST(test_session_zero_ttl_capacity_bound);
  RUN_TEST(test_session_ttl_without_trie);

  printf("\nSuite C: Integration Tests\n");
  RUN_TEST(test_select_prefill_tier0_session);
  RUN_TEST(test_select_prefill_tier1_trie);
  RUN_TEST(test_select_prefill_tier2_minload);
  RUN_TEST(test_select_prefill_load_imbalance_guard);
  RUN_TEST(test_select_decode_session_hint);
  RUN_TEST(test_kv_w0_identity);
  RUN_TEST(test_kv_w0_record_score);

  printf("\nSuite D: Concurrent Cleanup Recursive-Lock Test (.1)\n");
  RUN_TEST(test_concurrent_cleanup_recursive_lock);

  printf("\n=== Results: %d/%d tests passed ===\n\n", tests_passed, tests_run);
  return tests_passed != tests_run;
}
