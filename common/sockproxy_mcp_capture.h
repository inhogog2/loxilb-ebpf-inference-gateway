/* Copyright (c) 2026 LoxiLB Authors; SPDX-License-Identifier: BSD-3-Clause */
#ifndef SOCKPROXY_MCP_CAPTURE_H
#define SOCKPROXY_MCP_CAPTURE_H
#include <stdlib.h>
#include <strings.h>
#include "sockproxy_mcp.h"
/* Keep complete body validation below the existing one-MiB receive buffer.
 * This is an explicit admission bound, never a stream/fail-open fallback. */
#define SP_MCP_PROXY_BODY_MAX (768U * 1024U)
struct sp_mcp_capture {
  struct sp_mcp_request req;
  char *body;
  size_t len, cap;
};
static inline void sp_mcp_capture_reset(struct sp_mcp_capture *c) {
  if (!c) return;
  sp_mcp_reset(&c->req);
  free(c->body); c->body = NULL; c->len = c->cap = 0;
}
static inline void sp_mcp_capture_free(struct sp_mcp_capture *c) {
  if (!c) return;
  free(c->body); free(c);
}
static inline int sp_mcp_capture_body(struct sp_mcp_capture *c, const char *s, size_t n) {
  if (!c || (!s && n)) return 400;
  if (n > SP_MCP_PROXY_BODY_MAX - c->len) return 413;
  if (c->len + n > c->cap) {
    size_t cap = c->cap ? c->cap : 4096;
    while (cap < c->len + n) cap *= 2;
    if (cap > SP_MCP_PROXY_BODY_MAX) cap = SP_MCP_PROXY_BODY_MAX;
    char *p = realloc(c->body, cap);
    if (!p) return 503;
    c->body = p; c->cap = cap;
  }
  if (n) memcpy(c->body + c->len, s, n);
  c->len += n; return 0;
}

struct sp_mcp_media { unsigned ct, accept; int json, sse, error; };
/* Strict RFC 9110 token/quoted-string parsing. In Accept, commas inside
 * quoted parameters are not list separators, and q=0 forbids that range.
 * Wildcards are syntactically accepted in Accept but do not satisfy MCP's
 * requirement to explicitly accept both JSON and the SSE response type. */
static inline int sp_mcp_media_tchar(unsigned char c) {
  return c && ((c>='a' && c<='z') || (c>='A' && c<='Z') ||
      (c>='0' && c<='9') || strchr("!#$%&'*+-.^_`|~",c));
}
static inline void sp_mcp_media_ows(const char *p, size_t n, size_t *at) {
  while (*at<n && (p[*at]==' ' || p[*at]=='\t')) (*at)++;
}
static inline int sp_mcp_media_ident(const char *p, size_t n, size_t *at,
    size_t *start, size_t *len) {
  *start=*at;
  while (*at<n && sp_mcp_media_tchar((unsigned char)p[*at])) (*at)++;
  *len=*at-*start;
  return *len ? 0 : -1;
}
static inline int sp_mcp_media_span(const char *p, size_t start, size_t len,
    const char *want) {
  return len==strlen(want) && !strncasecmp(p+start,want,len);
}
/* HTTP qvalue = 0[.0*3DIGIT] / 1[.0*3("0")]. Quoted qvalues,
 * duplicate q parameters and extensions beyond three digits are rejected. */
static inline int sp_mcp_media_quality(const char *p, size_t n, int *positive) {
  if (!n || (p[0]!='0' && p[0]!='1')) return -1;
  *positive=p[0]=='1';
  if (n==1) return 0;
  if (p[1]!='.' || n>5) return -1;
  for (size_t i=2; i<n; i++) {
    if (p[i]<'0' || p[i]>'9' || (p[0]=='1' && p[i]!='0')) return -1;
    if (p[i]!='0') *positive=1;
  }
  return 0;
}
/* Parse exactly one media range through its last parameter; leaves at at
 * the comma or end of input. matched=1 for JSON, 2 for SSE, 0 otherwise. */
static inline int sp_mcp_media_range(const char *p, size_t n, size_t *at,
    int accept, int *matched, int *positive) {
  size_t type, tl, sub, sl;
  int quality_seen=0;
  *matched=0; *positive=1;
  sp_mcp_media_ows(p,n,at);
  if (sp_mcp_media_ident(p,n,at,&type,&tl) || *at==n || p[(*at)++]!='/') return -1;
  if (sp_mcp_media_ident(p,n,at,&sub,&sl)) return -1;
  int type_star=tl==1 && p[type]=='*', sub_star=sl==1 && p[sub]=='*';
  if ((!accept && (type_star || sub_star)) || (type_star && !sub_star)) return -1;
  if (sp_mcp_media_span(p,type,tl,"application") && sp_mcp_media_span(p,sub,sl,"json")) *matched=1;
  if (sp_mcp_media_span(p,type,tl,"text") && sp_mcp_media_span(p,sub,sl,"event-stream")) *matched=2;
  for (;;) {
    sp_mcp_media_ows(p,n,at);
    if (*at==n || (accept && p[*at]==',')) return 0;
    if (p[(*at)++]!=';') return -1;
    sp_mcp_media_ows(p,n,at);
    size_t key, kl, value, vl;
    if (sp_mcp_media_ident(p,n,at,&key,&kl)) return -1;
    sp_mcp_media_ows(p,n,at);
    if (*at==n || p[(*at)++]!='=') return -1;
    sp_mcp_media_ows(p,n,at);
    if (*at==n) return -1;
    int quoted=p[*at]=='"';
    if (quoted) {
      (*at)++; value=*at;
      while (*at<n && p[*at]!='"') {
        unsigned char c=(unsigned char)p[(*at)++];
        if (c=='\\') {
          if (*at==n) return -1;
          c=(unsigned char)p[(*at)++];
          if (c!=9 && c!=32 && !(c>=33 && c<=126) && c<128) return -1;
        } else if (c!=9 && c!=32 && c!=33 && !(c>=35 && c<=91) &&
                   !(c>=93 && c<=126) && c<128) return -1;
      }
      if (*at==n) return -1;
      vl=*at-value; (*at)++;
    } else if (sp_mcp_media_ident(p,n,at,&value,&vl)) return -1;
    if (accept && sp_mcp_media_span(p,key,kl,"q")) {
      if (quality_seen++ || quoted || sp_mcp_media_quality(p+value,vl,positive)) return -1;
    }
  }
}
static inline int sp_mcp_media_token(const char *p, size_t n, const char *want) {
  if (!p && n) return 0;
  size_t at=0; int matched, positive;
  if (sp_mcp_media_range(p,n,&at,0,&matched,&positive) || at!=n) return 0;
  return (!strcasecmp(want,"application/json") && matched==1) ||
         (!strcasecmp(want,"text/event-stream") && matched==2);
}
static inline void sp_mcp_media_header(struct sp_mcp_media *m,
    const char *name, size_t nl, const char *value, size_t vl) {
  if ((!name && nl) || (!value && vl)) { m->error=400; return; }
  if (nl==12 && !strncasecmp(name,"content-type",nl)) {
    if (++m->ct!=1 || !sp_mcp_media_token(value,vl,"application/json")) m->error=400;
  }
  if (nl==6 && !strncasecmp(name,"accept",nl)) {
    m->accept++;
    if (!vl) { m->error=400; return; }
    size_t at=0;
    for (;;) {
      int matched, positive;
      if (sp_mcp_media_range(value,vl,&at,1,&matched,&positive)) { m->error=400; return; }
      if (positive && matched==1) m->json=1;
      if (positive && matched==2) m->sse=1;
      if (at==vl) return;
      at++; /* range parser stopped at a comma */
      if (at==vl) { m->error=400; return; }
    }
  }
}
static inline int sp_mcp_media_valid(const struct sp_mcp_media *m) {
  return !m->error && m->ct==1 && m->accept && m->json && m->sse;
}
#endif
