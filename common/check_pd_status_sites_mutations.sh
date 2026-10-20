#!/bin/sh
# Mutation tests for check_pd_status_sites.sh: each rule added for the P/D
# lifecycle record is broken once in a scratch copy of the sources, and the
# check must fail with that rule's message. The unmutated copy must pass.
# Exit 1 when a mutation survives.
#
#   sh check_pd_status_sites_mutations.sh    (from anywhere; needs python3)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

survived=0
n=0

fresh() {
  rm -rf "$work/src"
  mkdir "$work/src"
  cp "$here"/sockproxy*.c "$here"/sockproxy*.h "$here/check_pd_status_sites.sh" "$work/src/"
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
  if out=$(sh "$work/src/check_pd_status_sites.sh" 2>&1); then
    echo "SURVIVED: $1 (the check passed)"
    survived=1
  elif ! printf '%s\n' "$out" | grep -qF "$2"; then
    echo "SURVIVED: $1 (failed without: $2)"
    printf '%s\n' "$out" | sed 's/^/    /'
    survived=1
  else
    echo "killed: $1"
  fi
}

fresh
sh "$work/src/check_pd_status_sites.sh" >/dev/null ||
  { echo "the unmutated sources fail the check"; exit 1; }

# 5: a non-SSE decode completion records a literal success on a continuation line.
fresh
mut sockproxy_http.c '        llb_ai_pd_record((char *)ns_model, prefill_ms, decode_ms, pd_kv,
                         pd_decode_error_phase(rfd_ent->metric_response_status));' '        llb_ai_pd_record((char *)ns_model, prefill_ms, decode_ms, pd_kv,
                         0);'
expect "5: the body-complete record is a literal success" "a P/D completion records a literal success (0)"

# 5b: the graceful-[DONE] sweep records decode/truncated.
fresh
mut sockproxy_health.c '8 /*decode truncated*/);' '0);'
expect "5b: the sweep records a success again" "a reaper records a literal success (0)"
fresh
mut sockproxy_health.c '8 /*decode truncated*/);' '2 /*decode error*/);'
expect "5b: the sweep records decode/error" "the graceful-[DONE] sweep must record decode/truncated (8) once"
fresh
mut sockproxy_health.c 'llb_ai_pd_record((char *)pd_tmo_model, t_prefill_ms, 0, t_kv, 1);' 'llb_ai_pd_record((char *)pd_tmo_model, t_prefill_ms, 0, t_kv, 0);'
expect "5b: another reaper records a success" "a reaper records a literal success (0)"

echo "check_pd_status_sites.sh mutations: $((n - survived)) of $n killed"
[ "$survived" = "0" ]
