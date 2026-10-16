/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_end_log.c - an HTTP/2 client connection's end says why.
 *
 * The gateway used to close an HTTP/2 client connection without recording
 * the reason, the backend connection that caused it or the endpoint, so a
 * client that lost its in-flight requests could not be told apart from one
 * that left. Now the site that decides records the cause
 * (proxy_h2_client_end_mark) and the teardown logs one line
 * (proxy_h2_client_end_log). This drives the REAL functions out of
 * sockproxy_h2.c and reads the line they log:
 *   - the first recorded cause wins;
 *   - nothing is recorded for a backend leg or an HTTP/1.1 connection;
 *   - a leg's teardown names the leg, its pool index and its endpoint;
 *   - the client leaving, the idle timeout and a leg that ended with no
 *     request in flight are info; every other end is a warning;
 *   - with no recorded cause the line carries the socket's pending error;
 *   - the last request's X-Forwarded-For decision and its age are in it;
 *   - a header-deadline end names the check that fired, the header block's
 *     age, the deadline and the connection's age.
 * Putting back any part of the old behaviour turns it red (mutation twins).
 *
 * Build: make test_h2end (ASan + UBSan).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_h2.h"
#include "log.h"

static int checks, failures;

#define CHECK(cond, ...) do {                                        \
    checks++;                                                        \
    if (cond) {                                                      \
      printf("ok %d - ", checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      failures++;                                                    \
      printf("FAIL %d - ", checks); printf(__VA_ARGS__);             \
      printf("  (%s:%d)\n", __FILE__, __LINE__);                     \
    }                                                                \
  } while (0)

/* The last line logged, and at which level. */
static char last_line[1024];
static int last_level = -1, lines;

void
log_log(int level, const char *file, int line, const char *fmt, ...)
{
  va_list ap;

  (void)file; (void)line;
  va_start(ap, fmt);
  vsnprintf(last_line, sizeof(last_line), fmt, ap);
  va_end(ap);
  last_level = level;
  lines++;
}

static uint64_t now_ms = 50000;

uint64_t
proxy_mono_ms(void)
{
  return now_ms;
}

static int
has(const char *needle)
{
  return strstr(last_line, needle) != NULL;
}

/* A connected TCP pair on loopback: [0] is the gateway's end of a leg. */
static uint16_t
tcp_pair(int fds[2])
{
  struct sockaddr_in a = { .sin_family = AF_INET };
  socklen_t al = sizeof(a);
  int l = socket(AF_INET, SOCK_STREAM, 0);

  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  assert(l >= 0 && bind(l, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(l, 1) == 0);
  assert(getsockname(l, (struct sockaddr *)&a, &al) == 0);
  fds[0] = socket(AF_INET, SOCK_STREAM, 0);
  assert(connect(fds[0], (struct sockaddr *)&a, sizeof(a)) == 0);
  fds[1] = accept(l, NULL, NULL);
  assert(fds[1] >= 0);
  close(l);
  return ntohs(a.sin_port);
}

/* A socket whose connect was refused: SO_ERROR holds ECONNREFUSED until
 * someone reads it. */
static int
refused_socket(void)
{
  struct sockaddr_in a = { .sin_family = AF_INET };
  socklen_t al = sizeof(a);
  int l = socket(AF_INET, SOCK_STREAM, 0), s;
  struct pollfd p;

  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  assert(l >= 0 && bind(l, (struct sockaddr *)&a, sizeof(a)) == 0);
  assert(getsockname(l, (struct sockaddr *)&a, &al) == 0);
  close(l);                      /* nothing listens on that port now */
  s = socket(AF_INET, SOCK_STREAM, 0);
  assert(s >= 0 && fcntl(s, F_SETFL, O_NONBLOCK) == 0);
  if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0)
    assert(errno == EINPROGRESS || errno == ECONNREFUSED);
  p.fd = s;
  p.events = POLLOUT;
  assert(poll(&p, 1, 2000) == 1);
  return s;
}

static proxy_fd_ent_t *
h2_client(int fd)
{
  proxy_fd_ent_t *c = calloc(1, sizeof(*c));

  assert(c);
  c->h2_session = calloc(1, sizeof(*c->h2_session));
  assert(c->h2_session);
  c->fd = fd;
  c->odir = 0;
  snprintf(c->l7_peer_ip, sizeof(c->l7_peer_ip), "10.0.0.7");
  return c;
}

static void
drop(proxy_fd_ent_t *c)
{
  free(c->h2_session);
  free(c);
}

int
main(void)
{
  int legfds[2], cfds[2];
  uint16_t port;
  char want[96];
  proxy_fd_ent_t *c, leg = { 0 }, h1 = { 0 };

  setvbuf(stdout, NULL, _IONBF, 0);
  port = tcp_pair(legfds);
  tcp_pair(cfds);

  /* A leg's teardown takes the client: the leg, its index and its endpoint. */
  c = h2_client(cfds[0]);
  c->h2_session->active_stream_count = 3;
  c->h2_last_req_ms = now_ms - 120;
  c->l7_xff_verdict = SP_XFF_EXTENDED;
  c->l7_xff_ntrusted = 1;
  leg.fd = legfds[0];
  leg.odir = 1;
  leg.ep_num = 2;
  proxy_h2_client_end_mark(c, SP_H2_END_LEG, 0, &leg);
  proxy_h2_client_end_mark(c, SP_H2_END_CLIENT_EOF, 0, NULL);
  CHECK(c->h2_end_reason == SP_H2_END_LEG, "the first cause wins (reason %u)", c->h2_end_reason);
  proxy_h2_client_end_log(c);
  CHECK(lines == 1 && last_level == LOG_WARN, "one line, a warning (level %d)", last_level);
  CHECK(has("reason=backend_leg_ended"), "it names the cause: %s", last_line);
  snprintf(want, sizeof(want), "leg_fd=%d leg_ep=2 leg_endpoint=127.0.0.1:%u", legfds[0], port);
  CHECK(has(want), "the leg, its pool index and its endpoint (%s)", want);
  snprintf(want, sizeof(want), "ended: reason=backend_leg_ended fd=%d peer=10.0.0.7 open_streams=3", cfds[0]);
  CHECK(has(want), "the client, its peer and the streams it still had (%s)", want);
  CHECK(has("last_request_ms_ago=120"), "the age of the last request");
  CHECK(has("xff=extended trusted_ranges=1"), "the last request's X-Forwarded-For decision");
  drop(c);

  /* Nothing is recorded for a backend leg (even one carrying an HTTP/2
   * session) or an HTTP/1.1 connection. */
  {
    proxy_h2_session_t bs = { 0 };
    leg.h2_session = &bs;
    proxy_h2_client_end_mark(&leg, SP_H2_END_IDLE, 0, NULL);
    leg.h2_session = NULL;
  }
  proxy_h2_client_end_mark(&leg, SP_H2_END_IDLE, 0, NULL);
  h1.fd = cfds[1];
  proxy_h2_client_end_mark(&h1, SP_H2_END_IDLE, 0, NULL);
  CHECK(leg.h2_end_reason == 0 && h1.h2_end_reason == 0,
        "a leg and an HTTP/1.1 client record nothing");
  lines = 0;
  proxy_h2_client_end_log(&h1);
  CHECK(lines == 0, "and an HTTP/1.1 connection logs no HTTP/2 end line");

  /* A read error is an error path: a warning, with its errno. */
  c = h2_client(cfds[0]);
  proxy_h2_client_end_mark(c, SP_H2_END_CLIENT_ERROR, ECONNRESET, NULL);
  proxy_h2_client_end_log(c);
  snprintf(want, sizeof(want), "errno=%d", ECONNRESET);
  CHECK(last_level == LOG_WARN && has("reason=client_error") && has(want),
        "a client reset is a warning, with its errno: %s", last_line);
  CHECK(has("leg_fd=-1 leg_ep=-1 leg_endpoint=-:0"), "and names no leg");
  CHECK(has("last_request_ms_ago=-1") && has("xff=none"), "no request: no age, no decision");
  drop(c);

  /* Ordinary ends are info: the client closing, the idle timeout, a leg
   * that ended with nothing in flight. */
  {
    static const struct { int r; int streams; const char *name; } o[] = {
      { SP_H2_END_CLIENT_EOF, 0, "client_eof" },
      { SP_H2_END_IDLE, 2, "idle_timeout" },
      { SP_H2_END_LEG, 0, "backend_leg_ended" },
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof(o) / sizeof(o[0]); i++) {
      char r[48];
      c = h2_client(cfds[0]);
      c->h2_session->active_stream_count = o[i].streams;
      proxy_h2_client_end_mark(c, o[i].r, 0, NULL);
      proxy_h2_client_end_log(c);
      snprintf(r, sizeof(r), "reason=%s ", o[i].name);
      if (last_level != LOG_INFO || !has(r)) {
        ok = 0;
        printf("# %s: level %d line %s\n", o[i].name, last_level, last_line);
      }
      drop(c);
    }
    CHECK(ok, "each ordinary end is info under its own name");
  }

  /* Every other end the gateway decided is a warning. */
  {
    static const struct { int r; const char *name; } g[] = {
      { SP_H2_END_SESSION_ERROR, "session_error" },
      { SP_H2_END_HDR_DEADLINE, "header_deadline" },
      { SP_H2_END_LISTENER, "listener_deleted" },
      { SP_H2_END_TEARDOWN, "endpoint_teardown" },
      { SP_H2_END_DEFERRED, "deferred_close" },
      { SP_H2_END_REAPER, "reaper" },
    };
    int ok = 1;
    for (size_t i = 0; i < sizeof(g) / sizeof(g[0]); i++) {
      char r[48];
      c = h2_client(cfds[0]);
      proxy_h2_client_end_mark(c, g[i].r, 0, NULL);
      proxy_h2_client_end_log(c);
      snprintf(r, sizeof(r), "reason=%s ", g[i].name);
      if (last_level != LOG_WARN || !has(r)) {
        ok = 0;
        printf("# %s: level %d line %s\n", g[i].name, last_level, last_line);
      }
      drop(c);
    }
    CHECK(ok, "each gateway decision is a warning under its own name");
  }

  /* The header deadline names the check that fired, the block's age, the
   * deadline and the connection's age; other ends name none of it. */
  c = h2_client(cfds[0]);
  c->h2_session->created_ts = time(NULL) - 30;
  c->l7_hdr.stream = 7;
  proxy_h2_client_end_mark_deadline(c, SP_HDR_CHECK_CLOCK, 12, 10000);
  proxy_h2_client_end_mark(c, SP_H2_END_CLIENT_EOF, 0, NULL);
  proxy_h2_client_end_log(c);
  CHECK(last_level == LOG_WARN && has("reason=header_deadline") &&
        has("hdr_check=clock hdr_age_s=12 hdr_deadline_ms=10000 hdr_stream=7 last_stream=-1"),
        "the deadline's check, block age and deadline: %s", last_line);
  CHECK(has("conn_age_s=30 ") || has("conn_age_s=31 "), "and the connection's age");
  drop(c);
  c = h2_client(cfds[0]);
  proxy_h2_client_end_mark(c, SP_H2_END_CLIENT_EOF, 0, NULL);
  proxy_h2_client_end_mark_deadline(c, SP_HDR_CHECK_H2_READ, 12, 10000);
  proxy_h2_client_end_log(c);
  CHECK(has("reason=client_eof") && has("hdr_check=- hdr_age_s=-1 hdr_deadline_ms=0 hdr_stream=-1 last_stream=-1"),
        "a deadline after another cause records nothing: %s", last_line);
  drop(c);

  /* No recorded cause: the line says so and carries the socket's error. */
  {
    int rs = refused_socket();
    c = h2_client(rs);
    proxy_h2_client_end_log(c);
    snprintf(want, sizeof(want), "errno=%d", ECONNREFUSED);
    CHECK(last_level == LOG_WARN && has("reason=unrecorded") && has(want),
          "an unrecorded end is a warning with the socket's pending error: %s", last_line);
    drop(c);
    close(rs);
  }

  close(legfds[0]); close(legfds[1]); close(cfds[0]); close(cfds[1]);
  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
