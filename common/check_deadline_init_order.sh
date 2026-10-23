#!/bin/sh
# Source invariant: the capacity-queue deadline timer is opened by proxy_main
# before any worker thread exists, never by a thread.
#
# fc_deadline_proc.tfd is a plain int: the drain checker reads it on every
# pass (a process without a timer owes the deadline sweep to that pass) and
# the deadline thread waits on it. Opened inside the deadline thread, the
# first drain-checker pass could read the field while the thread wrote it: a
# start-up data race between two threads proxy_main creates a few lines
# apart. Opened in proxy_main before the first pthread_create, every thread's
# reads are ordered after the write (pthread_create synchronizes-with the
# start of the new thread).
#
#   1. proxy_main (sockproxy_notifier.c) calls fc_deadline_init exactly once,
#      before its first pthread_create.
#   2. proxy_fc_deadline_thread (sockproxy_health.c) does not call
#      fc_deadline_init; it checks the descriptor and returns when there is
#      no timer (the 1 Hz pass owes the deadlines then).
#   3. fc_deadline_init has no product caller but proxy_main (units may call
#      it; the definition in sockproxy_fc.c is not a call).
#
#   sh check_deadline_init_order.sh    (from anywhere; exit 1 on a violation)
set -eu
cd "$(dirname "$0")"
fail=0

# 1. In proxy_main, the open precedes the first pthread_create.
body=$(awk '/^proxy_main\(/{f=1} f{print} f&&/^}/{exit}' ./sockproxy_notifier.c)
[ -n "$body" ] || { echo "sockproxy_notifier.c: proxy_main not found"; exit 1; }
init=$(printf '%s\n' "$body" | grep -n 'fc_deadline_init(fc_deadline_global())' | head -1 | cut -d: -f1)
first=$(printf '%s\n' "$body" | grep -n 'pthread_create(' | head -1 | cut -d: -f1)
if [ -z "$init" ]; then
  echo "sockproxy_notifier.c: proxy_main does not open the deadline timer (fc_deadline_init(fc_deadline_global()))"
  fail=1
elif [ -z "$first" ]; then
  echo "sockproxy_notifier.c: proxy_main creates no thread"
  fail=1
elif [ "$init" -ge "$first" ]; then
  echo "sockproxy_notifier.c: proxy_main opens the deadline timer (function line $init) after its first pthread_create (function line $first): the open must precede every thread"
  fail=1
fi
n=$(printf '%s\n' "$body" | grep -c 'fc_deadline_init(' || true)
if [ "$n" != 1 ]; then
  echo "sockproxy_notifier.c: proxy_main must call fc_deadline_init exactly once; found $n"
  fail=1
fi

# 2. The deadline thread does not open the timer; it checks and returns when there is none.
thr=$(awk '/^proxy_fc_deadline_thread\(/{f=1} f{print} f&&/^}/{exit}' ./sockproxy_health.c)
[ -n "$thr" ] || { echo "sockproxy_health.c: proxy_fc_deadline_thread not found"; exit 1; }
if printf '%s\n' "$thr" | grep -q 'fc_deadline_init('; then
  echo "sockproxy_health.c: proxy_fc_deadline_thread opens the timer itself (fc_deadline_init): the open belongs to proxy_main, before the threads"
  fail=1
fi
if ! printf '%s\n' "$thr" | grep -q 'if (d->tfd <= 0)'; then
  echo "sockproxy_health.c: proxy_fc_deadline_thread must check 'if (d->tfd <= 0)' and return when no timer was opened"
  fail=1
fi

# 3. No product caller of fc_deadline_init outside proxy_main.
others=$(grep -n 'fc_deadline_init(' ./sockproxy_*.c | grep -v '^./sockproxy_notifier.c:' | grep -v '^./sockproxy_fc.c:[0-9]*:fc_deadline_init(fc_deadline_t \*d)$' || true)
if [ -n "$others" ]; then
  printf '%s\n' "$others"
  echo "  ^ fc_deadline_init has a product caller outside proxy_main"
  fail=1
fi

[ "$fail" = 0 ] || exit 1
echo "Deadline timer init order: OK (opened once in proxy_main before its first pthread_create; the deadline thread checks, never opens; no other product caller)"
