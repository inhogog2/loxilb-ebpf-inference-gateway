/*
 * Copyright (c) 2024 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_CACHE_H__
#define __SOCKPROXY_CACHE_H__

#include "sockproxy.h"

/*
 * sockproxy_cache.h - Xmit cache, backpressure, and logging helpers.
 *
 * This header is included by sockproxy.c and any future module that needs
 * to drain or account xmit data for a proxy_fd_ent_t.
 *
 * See sockproxy_refactoring_plan.md §6.1
 */

/* Per-connection byte accounting (TX / RX stats) */
void pfe_ent_accouting(proxy_fd_ent_t *pfe, uint64_t bc, int txdir);

/*
 * cmp_proxy_ent: temporary home until sockproxy_conn.c is created in.
 * See sockproxy_refactoring_plan.md §6.2 -- will move to sockproxy_conn.h.
 */
bool cmp_proxy_ent(proxy_ent_t *e1, proxy_ent_t *e2);

/* Add a data buffer to the xmit cache */
int  proxy_add_xmitcache(proxy_fd_ent_t *ent, uint8_t *cache, size_t len);

/* Free all cached entries for connection ent */
void proxy_destroy_xmitcache(proxy_fd_ent_t *ent);

/* Drain the xmit cache for connection ent (sends buffered data) */
int  proxy_xmit_cache(proxy_fd_ent_t *ent);

/* Check and release backpressure once cache drains below LOW_WATER */
void proxy_check_release_backpressure(proxy_fd_ent_t *ent);

/*
 * Cache backpressure thresholds and the mark selection live in
 * sockproxy_cache_mark.h (included after proxy_fd_ent_t is complete). The
 * mark is resolved over the entry and its legs -- see that header for why
 * the entry's own flag was never enough on the response path.
 */
#include "sockproxy_cache_mark.h"

#endif /* __SOCKPROXY_CACHE_H__ */
