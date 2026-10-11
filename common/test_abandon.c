/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_abandon.c - unfinished-stream accounting and the stalled-client policy
 * (sockproxy_abandon.h), driven as plain integers, and the end of an
 * abandoned backend leg, driven on loopback sockets.
 *
 * Build (wired into `make test_abandon`):
 *   gcc -Wall -Wextra -Werror -o test_abandon_bin test_abandon.c -I.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "sockproxy_abandon.h"

static int failures = 0, checks = 0;

static void
check(const char *name, int ok, long got, long want)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAIL %-60s got %ld want %ld\n", name, got, want);
  } else {
    printf("ok   %-60s (%ld)\n", name, got);
  }
}

/* One backend leg ended the way the teardown ends it, over loopback: the
 * peer (the engine) writes until the leg's window is shut, then the leg is
 * shut both ways, read out, and closed. Returns the engine socket's pending
 * error 1.5 s later (0 = it was told nothing), or -1 if the shape could not
 * be built. `arm` applies abandon_leg_arm_reset() before the shutdown. */
static int
leg_end_seen_by_engine(int arm, long *stuck_bytes)
{
  struct sockaddr_in a;
  socklen_t alen = sizeof(a);
  char buf[4096];
  int ls, leg, eng, rcv = 4096, idle = 0, err = 0;
  socklen_t elen = sizeof(err);
  struct pollfd pf;
  long sent = 0;

  memset(&a, 0, sizeof(a));
  memset(buf, 'x', sizeof(buf));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ls = socket(AF_INET, SOCK_STREAM, 0);
  leg = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0 || leg < 0 || bind(ls, (struct sockaddr *)&a, sizeof(a)) < 0 ||
      listen(ls, 1) < 0 || getsockname(ls, (struct sockaddr *)&a, &alen) < 0) {
    return -1;
  }
  setsockopt(leg, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
  if (connect(leg, (struct sockaddr *)&a, sizeof(a)) < 0 ||
      (eng = accept(ls, NULL, NULL)) < 0) {
    return -1;
  }
  fcntl(eng, F_SETFL, fcntl(eng, F_GETFL) | O_NONBLOCK);
  /* the engine writes until nothing more has gone out for 300 ms */
  while (idle < 30) {
    ssize_t n = send(eng, buf, sizeof(buf), MSG_NOSIGNAL);
    if (n > 0) {
      sent += n;
      idle = 0;
    } else {
      idle++;
      usleep(10 * 1000);
    }
  }
  *stuck_bytes = sent;

  if (arm) {
    abandon_leg_arm_reset(leg);
  }
  shutdown(leg, SHUT_RDWR);
  while (recv(leg, buf, sizeof(buf), MSG_DONTWAIT) > 0) {
  }
  close(leg);

  pf.fd = eng;
  pf.events = 0;                       /* POLLERR / POLLHUP only */
  poll(&pf, 1, 1500);
  getsockopt(eng, SOL_SOCKET, SO_ERROR, &err, &elen);
  close(eng);
  close(ls);
  return err;
}

int
main(void)
{
  abandon_stats_t st;
  int abort_now;
  long since;

  memset(&st, 0, sizeof(st));

  /* ---- recorder ---- */
  abandon_record(&st, ABANDON_CLIENT_GONE, 7);     /* le 10 is the first bucket it lands in */
  check("client_gone total", st.total[ABANDON_CLIENT_GONE] == 1, st.total[ABANDON_CLIENT_GONE], 1);
  check("age 7 not in le=5", st.age_bucket[ABANDON_CLIENT_GONE][2] == 0, st.age_bucket[ABANDON_CLIENT_GONE][2], 0);
  check("age 7 in le=10", st.age_bucket[ABANDON_CLIENT_GONE][3] == 1, st.age_bucket[ABANDON_CLIENT_GONE][3], 1);
  check("cumulative: in the last bucket too", st.age_bucket[ABANDON_CLIENT_GONE][11] == 1,
        st.age_bucket[ABANDON_CLIENT_GONE][11], 1);
  check("age sum", st.age_sum_s[ABANDON_CLIENT_GONE] == 7, st.age_sum_s[ABANDON_CLIENT_GONE], 7);
  check("other reasons untouched", st.total[ABANDON_BACKEND_DIED] == 0 && st.total[ABANDON_STALL_ABORT] == 0, 0, 0);

  abandon_record(&st, ABANDON_STALL_ABORT, 5000);  /* past the last bound: count only */
  check("stall total", st.total[ABANDON_STALL_ABORT] == 1, st.total[ABANDON_STALL_ABORT], 1);
  check("age past the last bound is in no bucket", st.age_bucket[ABANDON_STALL_ABORT][11] == 0,
        st.age_bucket[ABANDON_STALL_ABORT][11], 0);
  check("... but counted", st.age_count[ABANDON_STALL_ABORT] == 1, st.age_count[ABANDON_STALL_ABORT], 1);

  abandon_record(&st, ABANDON_BACKEND_DIED, -3);    /* clock went backwards: 0 */
  check("negative age records as 0 (le=1 bucket)", st.age_bucket[ABANDON_BACKEND_DIED][0] == 1,
        st.age_bucket[ABANDON_BACKEND_DIED][0], 1);
  check("negative age adds nothing to the sum", st.age_sum_s[ABANDON_BACKEND_DIED] == 0,
        st.age_sum_s[ABANDON_BACKEND_DIED], 0);

  abandon_record(&st, ABANDON_REASONS, 1);          /* out of range: no-op */
  abandon_record(&st, -1, 1);
  check("out-of-range reason is a no-op",
        st.total[0] + st.total[1] + st.total[2] == 3, st.total[0] + st.total[1] + st.total[2], 3);

  /* ---- stall policy ---- */
  since = abandon_stall_tick(0, 0, 100, 30, &abort_now);
  check("no backpressure: disarmed", since == 0 && !abort_now, since, 0);
  since = abandon_stall_tick(1, 0, 100, 30, &abort_now);
  check("first sight arms at now", since == 100 && !abort_now, since, 100);
  since = abandon_stall_tick(1, 100, 129, 30, &abort_now);
  check("29 s in: not yet", since == 100 && !abort_now, abort_now, 0);
  since = abandon_stall_tick(1, 100, 130, 30, &abort_now);
  check("30 s in: abort", since == 100 && abort_now, abort_now, 1);
  since = abandon_stall_tick(0, 100, 131, 30, &abort_now);
  check("draining again: disarmed, no abort", since == 0 && !abort_now, since, 0);
  since = abandon_stall_tick(1, 100, 10000, 0, &abort_now);
  check("knob 0: never aborts, stays armed", since == 100 && !abort_now, abort_now, 0);

  /* which leg is reset when it is let go */
  check("client lets a paused backend leg go: reset", abandon_leg_wants_reset(0, 1, 1) == 1, abandon_leg_wants_reset(0, 1, 1), 1);
  check("client lets a reading backend leg go: orderly", abandon_leg_wants_reset(0, 1, 0) == 0, abandon_leg_wants_reset(0, 1, 0), 0);
  check("backend lets its client go: orderly", abandon_leg_wants_reset(1, 0, 1) == 0, abandon_leg_wants_reset(1, 0, 1), 0);
  check("arming a closed fd is refused", abandon_leg_arm_reset(-1) == -1, abandon_leg_arm_reset(-1), -1);

  /* what the engine is told, on real sockets: the orderly end tells it
   * nothing while its bytes are stuck behind the shut window; the armed end
   * resets it. Both arms must have stuck the engine first. */
  {
    long stuck0 = 0, stuck1 = 0;
    int e0 = leg_end_seen_by_engine(0, &stuck0);
    int e1 = leg_end_seen_by_engine(1, &stuck1);

    check("orderly end: the engine was stuck sending", stuck0 > 0 && e0 >= 0, stuck0 > 0, 1);
    check("orderly end: the engine is told nothing", e0 == 0, e0, 0);
    check("armed end: the engine was stuck sending", stuck1 > 0 && e1 >= 0, stuck1 > 0, 1);
    /* the reset lands after the FIN the shutdown sent, and a reset on a
     * connection whose peer already closed is reported as a broken pipe */
    check("armed end: the engine is reset", e1 == EPIPE, e1, EPIPE);
  }

  printf("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
