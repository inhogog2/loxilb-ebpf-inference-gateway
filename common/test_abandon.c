/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_abandon.c - unfinished-stream accounting and the stalled-client policy
 * (sockproxy_abandon.h), driven as plain integers.
 *
 * Build (wired into `make test_abandon`):
 *   gcc -Wall -Wextra -Werror -o test_abandon_bin test_abandon.c -I.
 */
#include <stdio.h>
#include <string.h>
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

  printf("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
