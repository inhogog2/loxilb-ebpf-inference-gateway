#!/bin/sh
# Mutation tests for check_deadline_init_order.sh: each rule is broken once in
# a scratch copy of the sources, and the check must fail with that rule's
# message. The unmutated copy must pass. Exit 1 when a mutation survives.
#
#   sh check_deadline_init_order_mutations.sh    (from anywhere; needs python3)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

survived=0
n=0

fresh() {
  rm -rf "$work/src"
  mkdir "$work/src"
  cp "$here"/sockproxy*.c "$here"/sockproxy*.h "$here/check_deadline_init_order.sh" "$work/src/"
}

# mut FILE OLD NEW: replace the one occurrence of OLD (it must exist once).
mut() {
  python3 - "$work/src/$1" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
if s.count(old) != 1:
    sys.exit("mutation anchor found %d times in %s: %r" % (s.count(old), p, old))
open(p, "w").write(s.replace(old, new))
PY
}

# expect NAME MESSAGE: the check fails, and says MESSAGE.
expect() {
  n=$((n + 1))
  if out=$(sh "$work/src/check_deadline_init_order.sh" 2>&1); then
    echo "SURVIVED: $1 (the check passed)"
    survived=1
  elif ! printf '%s\n' "$out" | grep -qF "$2"; then
    echo "SURVIVED: $1 (the check failed for another reason):"
    printf '%s\n' "$out" | sed 's/^/  /'
    survived=1
  else
    echo "killed: $1"
  fi
}

fresh
sh "$work/src/check_deadline_init_order.sh" >/dev/null || { echo "the unmutated sources fail the check"; exit 1; }

OPEN='  if (fc_deadline_init(fc_deadline_global()) != 0)
    log_error("[AIGateway] queue deadline timer: timerfd_create failed (%s); "
              "deadlines run on the 1 Hz health pass", strerror(errno));
'
# 1: proxy_main no longer opens the timer.
fresh
mut sockproxy_notifier.c "$OPEN" '  if (0)
    log_error("[AIGateway] queue deadline timer: timerfd_create failed (%s); "
              "deadlines run on the 1 Hz health pass", strerror(errno));
'
expect "1: proxy_main does not open the timer" "proxy_main does not open the deadline timer"

# 1: the open moved after the first thread.
fresh
mut sockproxy_notifier.c "$OPEN" ''
mut sockproxy_notifier.c '  pthread_create(&proxy_struct->pthr, NULL, proxy_run, NULL);
' '  pthread_create(&proxy_struct->pthr, NULL, proxy_run, NULL);
  (void)fc_deadline_init(fc_deadline_global());
'
expect "1: the open after the first pthread_create" "after its first pthread_create"

# 1: opened twice.
fresh
mut sockproxy_notifier.c "$OPEN" "$OPEN  (void)fc_deadline_init(fc_deadline_global());
"
expect "1: proxy_main opens the timer twice" "exactly once; found 2"

# 2: the thread opens the timer itself again (the TSAN-01 shape).
fresh
mut sockproxy_health.c '  if (d->tfd <= 0)
    return NULL;
  log_info("[AIGateway] queue deadline timer on' '  if (fc_deadline_init(d) != 0)
    return NULL;
  log_info("[AIGateway] queue deadline timer on'
expect "2: the thread opens the timer itself" "proxy_fc_deadline_thread opens the timer itself"

# 2: the thread no longer checks for a timer.
fresh
mut sockproxy_health.c '  if (d->tfd <= 0)
    return NULL;
  log_info("[AIGateway] queue deadline timer on' '  if (0)
    return NULL;
  log_info("[AIGateway] queue deadline timer on'
expect "2: the thread does not check for a timer" "must check 'if (d->tfd <= 0)'"

# 3: another product caller (the drain checker opens a missing timer).
fresh
mut sockproxy_health.c '  if (fc_deadline_global()->tfd <= 0)
    (void)fc_deadline_pass(NULL,' '  if (fc_deadline_global()->tfd <= 0 && fc_deadline_init(fc_deadline_global()) == 0)
    (void)fc_deadline_pass(NULL,'
expect "3: a product caller outside proxy_main" "product caller outside proxy_main"

echo "check_deadline_init_order.sh mutations: $((n - survived)) of $n killed"
[ "$survived" = "0" ]
