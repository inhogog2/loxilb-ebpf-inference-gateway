/* Observe SSE after HTTP framing: chunk-size lines are never SSE data. */
#ifndef SOCKPROXY_SSE_OBSERVE_H
#define SOCKPROXY_SSE_OBSERVE_H
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
  char field[32], value[96];
  size_t field_len, value_len;
  uint8_t field_overflow, value_overflow, is_sse, done, first_obj;
  char tail[20];
  size_t tail_len;
} sp_sse_observer_t;

static inline void sp_sse_field(sp_sse_observer_t *s, const char *at, size_t n)
{
  size_t room = sizeof(s->field) - 1 - s->field_len;
  if (n > room) s->field_overflow = 1;
  size_t take = n < room ? n : room;
  memcpy(s->field + s->field_len, at, take);
  s->field_len += take; s->field[s->field_len] = 0;
}
static inline void sp_sse_value(sp_sse_observer_t *s, const char *at, size_t n)
{
  size_t room = sizeof(s->value) - 1 - s->value_len;
  if (n > room) s->value_overflow = 1;
  size_t take = n < room ? n : room;
  memcpy(s->value + s->value_len, at, take);
  s->value_len += take; s->value[s->value_len] = 0;
}
static inline int sp_sse_content_type(const char *value, size_t len)
{
  static const char mime[] = "text/event-stream";
  size_t n = sizeof(mime) - 1;
  return len >= n && !strncasecmp(value, mime, n) &&
      (len == n || value[n] == ';' || value[n] == ' ' || value[n] == '\t');
}
static inline void sp_sse_header_done(sp_sse_observer_t *s)
{
  if (!s->field_overflow && !strcasecmp(s->field, "content-type") &&
      sp_sse_content_type(s->value, s->value_len))
    s->is_sse = 1;
  s->field_len = s->value_len = 0;
  s->field_overflow = s->value_overflow = 0;
  s->field[0] = s->value[0] = 0;
}
static inline int sp_sse_has_done(const char *p, size_t n)
{
  static const char a[] = "data:[DONE]\n\n", b[] = "data: [DONE]\n\n";
  for (size_t i = 0; i < n; i++) {
    if ((n-i >= sizeof(a)-1 && !memcmp(p+i,a,sizeof(a)-1)) ||
        (n-i >= sizeof(b)-1 && !memcmp(p+i,b,sizeof(b)-1))) return 1;
  }
  return 0;
}
/* An SSE data object: "data:{" or "data: {", the first event that carries
 * content (a role-only delta included). */
static inline int sp_sse_has_object(const char *p, size_t n)
{
  static const char a[] = "data:{", b[] = "data: {";
  for (size_t i = 0; i < n; i++) {
    if ((n-i >= sizeof(a)-1 && !memcmp(p+i,a,sizeof(a)-1)) ||
        (n-i >= sizeof(b)-1 && !memcmp(p+i,b,sizeof(b)-1))) return 1;
  }
  return 0;
}
/* Returns 1 for the read in which the stream's first data object completed,
 * once per answer (a "data: {" split across reads is seen in the read that
 * finishes it). */
static inline int sp_sse_body(sp_sse_observer_t *s, const char *at, size_t n)
{
  int first = 0;
  if (!s->is_sse || !n) return 0;
  char window[40];
  size_t head = n < sizeof(s->tail) ? n : sizeof(s->tail);
  memcpy(window, s->tail, s->tail_len);
  memcpy(window+s->tail_len, at, head);
  if (sp_sse_has_done(window,s->tail_len+head) || sp_sse_has_done(at,n)) s->done = 1;
  if (!s->first_obj &&
      (sp_sse_has_object(window,s->tail_len+head) || sp_sse_has_object(at,n))) {
    s->first_obj = 1;
    first = 1;
  }
  if (n >= sizeof(s->tail)) {
    s->tail_len = sizeof(s->tail);
    memcpy(s->tail, at+n-s->tail_len, s->tail_len);
  } else {
    size_t keep = s->tail_len < sizeof(s->tail)-n ? s->tail_len : sizeof(s->tail)-n;
    memmove(s->tail, s->tail+s->tail_len-keep, keep);
    memcpy(s->tail+keep, at, n);
    s->tail_len = keep+n;
  }
  return first;
}
/* The framed end of a streamed answer is its end, whether or not it carried
 * the [DONE] event: a backend may end a stream with its last chunk alone. */
static inline void sp_sse_message_done(sp_sse_observer_t *s)
{
  if (s->is_sse) s->done = 1;
}
#endif
