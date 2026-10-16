/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * test_parser_once.c — llhttp settings shared by every connection are filled
 * once (sockproxy_parser_once.h), the way the client entry's request and
 * response framers in sockproxy_http.c use them.
 *
 * Two threads meet their first connection together: each takes the shared
 * settings at the same moment (a barrier releases them) and parses one
 * complete response and one complete request with its own parser. Each must
 * see every callback (status, headers complete, message complete). Built
 * with ASan + UBSan, and with TSan, where a lazy fill of the shared
 * settings is a data race even when the timing hides the lost callback.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "llhttp.h"
#include "sockproxy_parser_once.h"

static int failures;
static int checks;

#define CHECK(cond, msg) do {                                   \
    checks++;                                                   \
    if (!(cond)) { failures++; printf("FAIL %d - %s\n", checks, msg); } \
    else printf("ok %d - %s\n", checks, msg);                   \
  } while (0)

struct seen {
  int begin, status, headers, complete;
};

static int on_begin(llhttp_t *p) { ((struct seen *)p->data)->begin++; return 0; }
static int on_status_done(llhttp_t *p) { ((struct seen *)p->data)->status++; return 0; }
static int on_headers(llhttp_t *p) { ((struct seen *)p->data)->headers++; return 0; }
static int on_complete(llhttp_t *p) { ((struct seen *)p->data)->complete++; return 0; }

static void
resp_fill(llhttp_settings_t *s)
{
  s->on_message_begin = on_begin;
  s->on_status_complete = on_status_done;
  s->on_headers_complete = on_headers;
  s->on_message_complete = on_complete;
}

static void
req_fill(llhttp_settings_t *s)
{
  s->on_message_begin = on_begin;
  s->on_headers_complete = on_headers;
  s->on_message_complete = on_complete;
}

SP_PARSER_SETTINGS_ONCE(tresp, resp_fill)
SP_PARSER_SETTINGS_ONCE(treq, req_fill)

static const char RESP[] =
  "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}";
static const char REQ[] =
  "POST /v1/chat/completions HTTP/1.1\r\nHost: gw\r\nContent-Length: 2\r\n\r\n{}";

static pthread_barrier_t start;

struct result {
  struct seen resp, req;
  int resp_err, req_err;
};

static void *
first_connection(void *arg)
{
  struct result *r = arg;
  llhttp_t resp, req;

  pthread_barrier_wait(&start);
  llhttp_init(&resp, HTTP_RESPONSE, tresp_settings_get());
  resp.data = &r->resp;
  llhttp_init(&req, HTTP_REQUEST, treq_settings_get());
  req.data = &r->req;
  r->resp_err = llhttp_execute(&resp, RESP, sizeof(RESP) - 1);
  r->req_err = llhttp_execute(&req, REQ, sizeof(REQ) - 1);
  return NULL;
}

int
main(void)
{
  pthread_t t[2];
  struct result r[2];
  char msg[128];

  memset(r, 0, sizeof(r));
  pthread_barrier_init(&start, NULL, 2);
  for (int i = 0; i < 2; i++)
    pthread_create(&t[i], NULL, first_connection, &r[i]);
  for (int i = 0; i < 2; i++)
    pthread_join(t[i], NULL);

  for (int i = 0; i < 2; i++) {
    snprintf(msg, sizeof(msg), "thread %d: the response parses without error", i);
    CHECK(r[i].resp_err == HPE_OK, msg);
    snprintf(msg, sizeof(msg), "thread %d: the response's status is seen", i);
    CHECK(r[i].resp.status == 1, msg);
    snprintf(msg, sizeof(msg), "thread %d: the response's headers end is seen", i);
    CHECK(r[i].resp.headers == 1, msg);
    snprintf(msg, sizeof(msg), "thread %d: the response's end is seen", i);
    CHECK(r[i].resp.begin == 1 && r[i].resp.complete == 1, msg);
    snprintf(msg, sizeof(msg), "thread %d: the request parses without error", i);
    CHECK(r[i].req_err == HPE_OK, msg);
    snprintf(msg, sizeof(msg), "thread %d: the request's headers end and end are seen", i);
    CHECK(r[i].req.begin == 1 && r[i].req.headers == 1 && r[i].req.complete == 1, msg);
  }
  CHECK(tresp_settings_get() == tresp_settings_get() &&
        tresp_settings_get()->on_message_complete == on_complete,
        "the shared response settings stay filled after first use");
  CHECK(treq_settings_get()->on_headers_complete == on_headers,
        "the shared request settings stay filled after first use");

  pthread_barrier_destroy(&start);
  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
