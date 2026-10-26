/* SPDX-License-Identifier: BSD-3-Clause
 * The finish-evidence tracker (sockproxy_pd_terminal.c): a finish event split
 * at every byte, the events that cannot prove a finish, the choice-less events
 * that keep one, and what clears one. */
#include "sockproxy_pd_terminal.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static void feed(sp_pd_finish_t *s, const char *event)
{
  for (size_t i = 0; i < strlen(event); i++)
    sp_pd_finish_feed(s, event + i, 1);
}

int main(void)
{
  sp_pd_finish_t *s = calloc(1, sizeof(*s));
  const char *stop = "data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\r\n\r\n";
  assert(s);
  for (size_t cut = 0; cut <= strlen(stop); cut++) {
    sp_pd_finish_reset(s);
    sp_pd_finish_feed(s, stop, cut);
    if (cut < strlen(stop))
      assert(!s->finished);
    sp_pd_finish_feed(s, stop + cut, strlen(stop) - cut);
    assert(s->finished);
  }
  const char *negative[] = {
      "data\n\n",
      "data: {\"error\":\"failed\",\"choices\":[{\"finish_reason\":\"stop\"}]}\n\n",
      "data: {\"choices\" [{\"finish_reason\":\"stop\"}]}\n\n",
      "data",
      "data: {\"choices\":[{\"finish_reason\":null}]}\n\n",
      "data: {\"choices\":[{\"delta\":{\"content\":\"finish_reason: stop\"}}]}\n\n",
      "data: {\"choices\":[{\"delta\":{\"finish_reason\":\"stop\"}}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"error\"}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"not_finished\"}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"stop\"},{\"finish_reason\":null}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"stop\",\"finish_reason\":null}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"stop\"}]} garbage\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n",
      "data: {\"error\":\"InternalServerError\"}\n\n",
      "data: {\"choices\":[],\"error\":\"InternalServerError\"}\n\n",
      "data: {\"choices\":[{\"delta\":{\"content\":\"more\"}}]}\n\n"};
  for (size_t i = 0; i < sizeof(negative) / sizeof(*negative); i++) {
    sp_pd_finish_reset(s);
    feed(s, stop);
    assert(s->finished);
    feed(s, negative[i]);
    assert(!s->finished);
  }
  /* After the finish, events that carry no choice keep it: the usage event of
   * stream_options.include_usage (vLLM and SGLang send it after the finish
   * event and before [DONE]) and [DONE] itself. */
  const char *neutral[] = {
      "data: {\"choices\":[]}\n\n",
      "data: {\"usage\":{\"completion_tokens\":10}}\n\n",
      "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[],"
      "\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":10,\"total_tokens\":15}}\n\n",
      "data: [DONE]\n\n"};
  for (size_t i = 0; i < sizeof(neutral) / sizeof(*neutral); i++) {
    sp_pd_finish_reset(s);
    feed(s, stop);
    feed(s, neutral[i]);
    assert(s->finished);
    /* ... but prove nothing on their own. */
    sp_pd_finish_reset(s);
    feed(s, neutral[i]);
    assert(!s->finished);
  }
  /* Content after the usage event: the generation went on, nothing is proven. */
  sp_pd_finish_reset(s);
  feed(s, stop);
  feed(s, neutral[2]);
  feed(s, "data: {\"choices\":[{\"delta\":{\"content\":\"late\"}}]}\n\n");
  assert(!s->finished);
  /* A two-line event, a keepalive comment, a partial data line. */
  sp_pd_finish_reset(s);
  feed(s, "data: {\"choices\":\n");
  feed(s, "data: [{\"finish_reason\":\"length\"}]}\n\n");
  assert(s->finished);
  feed(s, ": keepalive\n\n");
  assert(s->finished);
  feed(s, "data:");
  assert(!s->finished);
  /* An oversized event clears the proof; the next finish restores it. */
  sp_pd_finish_reset(s);
  feed(s, stop);
  feed(s, "data: ");
  for (size_t i = 0; i < SP_PD_EVENT_MAX + 100; i++)
    feed(s, "x");
  feed(s, "\n\n");
  assert(!s->finished);
  feed(s, stop);
  assert(s->finished);
  /* A reset forgets the proof. */
  sp_pd_finish_reset(s);
  assert(!s->finished && !s->proof);
  free(s);
  puts("finish evidence: a finish followed only by choice-less events (usage, [DONE]) proves "
       "completion; partial/null/error/overflow/late-data refuse it: PASS");
  return 0;
}
