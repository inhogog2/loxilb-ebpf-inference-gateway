/*
 * Copyright (c) 2026 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * Endpoint Picker (EPP) side table and completion wake — see sockproxy_epp.h.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>

#include "log.h"
#include "uthash.h"
#include "notify.h"
#include "sockproxy.h"
#include "sockproxy_internal.h"
#include "sockproxy_epp.h"

struct epp_pending {
  uint64_t sid;
  int      fd;
  uint64_t gen;
  uint64_t at_ns;
  struct epp_result r;      /* the pointer fields own heap copies */
  UT_hash_handle hh;
};

static pthread_mutex_t epp_lock = PTHREAD_MUTEX_INITIALIZER;
static epp_pending_t *epp_table;
static int epp_n;

uint64_t
epp_now_ns(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static char *
epp_dup(const char *s, int n)
{
  char *d;
  if (!s || n <= 0) return NULL;
  d = malloc((size_t)n + 1);
  if (!d) return NULL;
  memcpy(d, s, (size_t)n);
  d[n] = '\0';
  return d;
}

static void
epp_result_free_bufs(struct epp_result *r)
{
  free((void *)r->imm_body);
  free((void *)r->hdr_set);
  free((void *)r->hdr_del);
  free((void *)r->new_body);
  r->imm_body = r->hdr_set = r->hdr_del = r->new_body = NULL;
}

int
proxy_epp_complete(void *ns, int fd, uint64_t gen, uint64_t sid,
                   const struct epp_result *r)
{
  epp_pending_t *p;
  uint64_t reg_gen = 0;
  int owner;

  if (!ns || fd <= 0 || sid == 0 || !r) return -1;
  /* The fd must still be the registration the submit saw: a recycled slot
   * (gen bumped) or a closed fd has nobody waiting for this decision. */
  if (!notify_priv_of_fd(ns, fd, &reg_gen) || reg_gen != gen) {
    log_debug("[EPP] complete sid=%llu fd=%d gen=%llu: slot gone (reg gen %llu) - dropped",
              (unsigned long long)sid, fd, (unsigned long long)gen,
              (unsigned long long)reg_gen);
    return -2;
  }
  p = calloc(1, sizeof(*p));
  if (!p) return -1;
  p->sid = sid;
  p->fd = fd;
  p->gen = gen;
  p->at_ns = epp_now_ns();
  p->r.status = r->status;
  p->r.ncands = r->ncands < 0 ? 0 : (r->ncands > EPP_MAX_CANDS ? EPP_MAX_CANDS : r->ncands);
  for (int i = 0; i < p->r.ncands; i++) {
    strncpy(p->r.cands[i], r->cands[i], EPP_CAND_LEN - 1);
    p->r.cands[i][EPP_CAND_LEN - 1] = '\0';
  }
  p->r.imm_code = r->imm_code;
  p->r.imm_body = epp_dup(r->imm_body, r->imm_body_len);
  p->r.imm_body_len = p->r.imm_body ? r->imm_body_len : 0;
  p->r.hdr_set = epp_dup(r->hdr_set, r->hdr_set_len);
  p->r.hdr_set_len = p->r.hdr_set ? r->hdr_set_len : 0;
  p->r.hdr_del = epp_dup(r->hdr_del, r->hdr_del_len);
  p->r.hdr_del_len = p->r.hdr_del ? r->hdr_del_len : 0;
  p->r.new_body = epp_dup(r->new_body, r->new_body_len);
  p->r.new_body_len = p->r.new_body ? r->new_body_len : 0;

  pthread_mutex_lock(&epp_lock);
  {
    epp_pending_t *old = NULL;
    HASH_FIND(hh, epp_table, &sid, sizeof(sid), old);
    if (old) {  /* a second completion for one stream: the last one wins */
      HASH_DEL(epp_table, old);
      epp_n--;
      epp_result_free_bufs(&old->r);
      free(old);
    }
    HASH_ADD(hh, epp_table, sid, sizeof(sid), p);
    epp_n++;
  }
  pthread_mutex_unlock(&epp_lock);

  owner = notify_owner_thr(ns, fd);
  if (owner < 0 || notify_wake_worker(ns, owner, fd) != 0) {
    log_warn("[EPP] complete sid=%llu fd=%d: owner worker %d could not be woken; "
             "the reaper collects it", (unsigned long long)sid, fd, owner);
    return -3;
  }
  return 0;
}

epp_pending_t *
epp_pending_take(uint64_t sid, int fd, uint64_t gen)
{
  epp_pending_t *p = NULL;

  if (sid == 0) return NULL;
  pthread_mutex_lock(&epp_lock);
  HASH_FIND(hh, epp_table, &sid, sizeof(sid), p);
  if (p) {
    HASH_DEL(epp_table, p);
    epp_n--;
  }
  pthread_mutex_unlock(&epp_lock);
  if (p && (p->fd != fd || p->gen != gen)) {
    log_warn("[EPP] take sid=%llu: entry is for fd=%d gen=%llu, caller fd=%d gen=%llu - dropped",
             (unsigned long long)sid, p->fd, (unsigned long long)p->gen, fd,
             (unsigned long long)gen);
    epp_pending_free(p);
    return NULL;
  }
  return p;
}

const struct epp_result *
epp_pending_result(const epp_pending_t *p)
{
  return p ? &p->r : NULL;
}

void
epp_pending_free(epp_pending_t *p)
{
  if (!p) return;
  epp_result_free_bufs(&p->r);
  free(p);
}

void
epp_pending_drop(uint64_t sid)
{
  epp_pending_t *p = NULL;

  if (sid == 0) return;
  pthread_mutex_lock(&epp_lock);
  HASH_FIND(hh, epp_table, &sid, sizeof(sid), p);
  if (p) {
    HASH_DEL(epp_table, p);
    epp_n--;
  }
  pthread_mutex_unlock(&epp_lock);
  epp_pending_free(p);
}

int
epp_pending_count(void)
{
  int n;
  pthread_mutex_lock(&epp_lock);
  n = epp_n;
  pthread_mutex_unlock(&epp_lock);
  return n;
}

int
epp_pending_reap(uint64_t max_age_ns)
{
  epp_pending_t *p, *tmp;
  uint64_t now = epp_now_ns();
  int freed = 0;

  pthread_mutex_lock(&epp_lock);
  HASH_ITER(hh, epp_table, p, tmp) {
    if (now - p->at_ns >= max_age_ns) {
      HASH_DEL(epp_table, p);
      epp_n--;
      epp_result_free_bufs(&p->r);
      free(p);
      freed++;
    }
  }
  pthread_mutex_unlock(&epp_lock);
  if (freed)
    log_warn("[EPP] reaped %d orphaned decision(s)", freed);
  return freed;
}

static const char *
epp_reason(int status)
{
  switch (status) {
  case 400: return "Bad Request";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 413: return "Payload Too Large";
  case 429: return "Too Many Requests";
  case 500: return "Internal Server Error";
  case 502: return "Bad Gateway";
  case 503: return "Service Unavailable";
  case 504: return "Gateway Timeout";
  default:  return "Error";
  }
}

void
epp_send_error(proxy_fd_ent_t *pfe, int status, const char *code, const char *detail)
{
  char body[512];
  char resp[1024];
  int blen, n;

  blen = snprintf(body, sizeof(body), "{\"error\":\"%s\",\"detail\":\"%s\"}\r\n",
                  code, detail ? detail : "");
  if (blen < 0 || blen >= (int)sizeof(body)) blen = 0;
  n = snprintf(resp, sizeof(resp),
               "HTTP/1.1 %d %s\r\n"
               "Content-Type: application/json\r\n"
               "Content-Length: %d\r\n"
               "Connection: close\r\n"
               "\r\n%s", status, epp_reason(status), blen, blen ? body : "");
  if (n > 0 && n < (int)sizeof(resp)) {
    if (proxy_send_local_response_and_shutdown(pfe, resp, (size_t)n) != 0)
      log_error("[EPP] fd=%d failed to send %d %s", pfe->fd, status, code);
    pfe->lb_err_body_sent = 1;
  }
  log_info("[EPP] fd=%d answered %d %s: %s", pfe->fd, status, code, detail ? detail : "");
}

void
epp_send_immediate(proxy_fd_ent_t *pfe, const struct epp_result *r)
{
  size_t cap = 256 + (size_t)(r->hdr_set_len > 0 ? r->hdr_set_len : 0) +
               (size_t)(r->imm_body_len > 0 ? r->imm_body_len : 0);
  char *resp = malloc(cap);
  int n;

  if (!resp) return;
  n = snprintf(resp, cap, "HTTP/1.1 %d %s\r\n%.*sContent-Length: %d\r\nConnection: close\r\n\r\n",
               r->imm_code, epp_reason(r->imm_code),
               r->hdr_set_len > 0 ? r->hdr_set_len : 0, r->hdr_set ? r->hdr_set : "",
               r->imm_body_len > 0 ? r->imm_body_len : 0);
  if (n > 0 && (size_t)n < cap) {
    if (r->imm_body_len > 0 && r->imm_body) {
      memcpy(resp + n, r->imm_body, (size_t)r->imm_body_len);
      n += r->imm_body_len;
    }
    if (proxy_send_local_response_and_shutdown(pfe, resp, (size_t)n) != 0)
      log_error("[EPP] fd=%d failed to send the EPP's %d", pfe->fd, r->imm_code);
    pfe->lb_err_body_sent = 1;
  }
  free(resp);
  log_info("[EPP] fd=%d sid=%llu EPP immediate response %d relayed", pfe->fd,
           (unsigned long long)pfe->epp_sid, r->imm_code);
}

void
epp_request_end(proxy_fd_ent_t *pfe)
{
  if (!pfe || pfe->epp_sid == 0) return;
  if (!pfe->epp_reported) {
    pfe->epp_reported = 1;
    llb_epp_resp_event(pfe->epp_sid, EPP_EV_ABORT, 0, NULL, 0, NULL, 0);
    log_debug("[EPP] fd=%d sid=%llu abort reported", pfe->fd, (unsigned long long)pfe->epp_sid);
  }
  epp_pending_drop(pfe->epp_sid);
  pfe->epp_sid = 0;
  pfe->epp_decided = 0;
  pfe->epp_deadline_ns = 0;
}
