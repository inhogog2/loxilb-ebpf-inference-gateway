/* Copyright (c) 2026 LoxiLB Authors; SPDX-License-Identifier: BSD-3-Clause */
#ifndef SOCKPROXY_MCP_H
#define SOCKPROXY_MCP_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "sockproxy_json_unescape.h"

/* These bounds reject requests rather than silently truncating routing keys. */
#define SP_MCP_NAME_MAX 16384U
#define SP_MCP_HEADER_VALUE_MAX (((SP_MCP_NAME_MAX + 2U) / 3U) * 4U + 11U)
#define SP_MCP_BODY_MAX 1048576U
#define SP_MCP_TOKENS_MAX 4096U
#define SP_MCP_DEPTH_MAX 32U
#define SP_MCP_VERSION "2026-07-28"
struct sp_mcp_request {
  char field[128], value[SP_MCP_HEADER_VALUE_MAX + 1];
  char name[SP_MCP_NAME_MAX + 1], method[256], version[32];
  size_t field_len, value_len, name_len;
  unsigned int version_seen, method_seen, name_seen;
  int error, active, value_started;
};
typedef struct sp_mcp_request mcp_request_state_t;
static inline void sp_mcp_reset(struct sp_mcp_request *r) { memset(r, 0, sizeof(*r)); }
static inline void sp_mcp_header_begin(struct sp_mcp_request *r) {
  if (r->active) r->error = 400;
  r->active = 1; r->field_len = r->value_len = 0; r->value_started = 0;
}
static inline void sp_mcp_header_name(struct sp_mcp_request *r, const char *s, size_t n) {
  if (!r->active || r->value_started || (!s && n)) { r->error = 400; return; }
  if (n >= sizeof(r->field) - r->field_len) { r->error = 413; return; }
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (!c || !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9') || strchr("!#$%&'*+-.^_`|~", c))) { r->error = 400; return; }
    r->field[r->field_len++] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
  }
  r->field[r->field_len] = 0;
}
static inline void sp_mcp_header_value(struct sp_mcp_request *r, const char *s, size_t n) {
  if (!r->active || (!s && n)) { r->error = 400; return; }
  r->value_started = 1;
  if (n > SP_MCP_HEADER_VALUE_MAX - r->value_len) { r->error = 413; return; }
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if ((c < 32 && c != '\t') || c == 127) { r->error = 400; return; }
  }
  if (n) memcpy(r->value + r->value_len, s, n);
  r->value_len += n; r->value[r->value_len] = 0;
}
/* Decode one Unicode scalar from UTF-8, rejecting overlongs and surrogates. */
static inline int sp_mcp_utf8(const char *s, size_t n, size_t *at, uint32_t *cp) {
  if (*at >= n) return -1;
  unsigned char c = (unsigned char)s[(*at)++];
  if (c < 128) { *cp = c; return 0; }
  unsigned count; uint32_t v, min;
  if (c >= 0xc2 && c <= 0xdf) { count = 1; v = c & 31; min = 128; }
  else if (c >= 0xe0 && c <= 0xef) { count = 2; v = c & 15; min = 2048; }
  else if (c >= 0xf0 && c <= 0xf4) { count = 3; v = c & 7; min = 65536; }
  else return -1;
  if (count > n - *at) return -1;
  for (unsigned i = 0; i < count; i++) {
    c = (unsigned char)s[(*at)++]; if ((c & 0xc0) != 0x80) return -1;
    v = (v << 6) | (c & 63);
  }
  if (v < min || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) return -1;
  *cp = v; return 0;
}
static inline int sp_mcp_safe_name(const char *s, size_t n) {
  size_t at = 0; uint32_t cp;
  while (at < n) if (sp_mcp_utf8(s, n, &at, &cp) || cp < 32 || cp == 127) return -1;
  return 0;
}
static inline int sp_mcp_b64digit(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
static inline int sp_mcp_name_decode(struct sp_mcp_request *r, const char *s, size_t n) {
  size_t out = 0;
  int encoded = n >= 11 && !memcmp(s, "=?base64?", 9) && !memcmp(s + n - 2, "?=", 2);
  if (encoded) {
    s += 9; n -= 11;
    if (n % 4) return 400;
    for (size_t i = 0; i < n; i += 4) {
      int a = sp_mcp_b64digit((unsigned char)s[i]), b = sp_mcp_b64digit((unsigned char)s[i+1]);
      int c = s[i+2] == '=' ? -2 : sp_mcp_b64digit((unsigned char)s[i+2]);
      int d = s[i+3] == '=' ? -2 : sp_mcp_b64digit((unsigned char)s[i+3]);
      if (a < 0 || b < 0 || c == -1 || d == -1 ||
          (c == -2 && d != -2) || ((c == -2 || d == -2) && i + 4 != n) ||
          (c == -2 && (b & 15)) || (d == -2 && c >= 0 && (c & 3))) return 400;
      size_t need = c == -2 ? 1 : d == -2 ? 2 : 3;
      if (need > SP_MCP_NAME_MAX - out) return 413;
      r->name[out++] = (char)((a << 2) | (b >> 4));
      if (c >= 0) r->name[out++] = (char)((b << 4) | (c >> 2));
      if (d >= 0) r->name[out++] = (char)((c << 6) | d);
    }
  } else {
    if (n > SP_MCP_NAME_MAX) return 413;
    memcpy(r->name, s, n); out = n;
  }
  if (encoded) {
    size_t at = 0; uint32_t cp;
    while (at < out) if (sp_mcp_utf8(r->name, out, &at, &cp)) return 400;
  } else {
    if (sp_mcp_safe_name(r->name, out)) return 400;
    for (size_t i = 0; i < out; i++) if ((unsigned char)r->name[i] >= 127) return 400;
  }
  r->name[out] = 0; r->name_len = out; return 0;
}
static inline void sp_mcp_header_end(struct sp_mcp_request *r) {
  if (!r->active || !r->field_len) { r->error = 400; return; }
  r->active = 0; if (r->error) return;
  const char *s = r->value; size_t n = r->value_len;
  while (n && (*s == ' ' || *s == '\t')) { s++; n--; }
  while (n && (s[n-1] == ' ' || s[n-1] == '\t')) n--;
  if (!strcmp(r->field, "mcp-protocol-version")) {
    if (r->version_seen++ || n >= sizeof(r->version)) { r->error = 400; return; }
    memcpy(r->version, s, n); r->version[n] = 0;
  } else if (!strcmp(r->field, "mcp-method")) {
    if (r->method_seen++ || n >= sizeof(r->method)) { r->error = 400; return; }
    memcpy(r->method, s, n); r->method[n] = 0;
  } else if (!strcmp(r->field, "mcp-name")) {
    if (r->name_seen++) { r->error = 400; return; }
    r->error = sp_mcp_name_decode(r, s, n);
  }
}
static inline void sp_mcp_header(struct sp_mcp_request *r, const char *name, size_t nl,
                                  const char *value, size_t vl) {
  sp_mcp_header_begin(r); sp_mcp_header_name(r, name, nl);
  sp_mcp_header_value(r, value, vl); sp_mcp_header_end(r);
}

/* Strict JSON scanner. Each token's next index skips its complete subtree.
 * Duplicate keys compare decoded Unicode scalars, so escaped aliases collide.
 * Work and storage are bounded by body, token and nesting limits. */
struct sp_mcp_token { size_t start, end; unsigned next; char type; };
struct sp_mcp_json { const char *s; size_t n, at, compare_budget; unsigned used; int error;
  struct sp_mcp_token tokens[SP_MCP_TOKENS_MAX]; };
static inline void sp_mcp_ws(struct sp_mcp_json *j) {
  while (j->at < j->n && strchr(" \t\r\n", j->s[j->at]) && j->s[j->at]) j->at++;
}
static inline int sp_mcp_scalar(const char *s, size_t n, size_t *at, uint32_t *cp) {
  if (*at >= n) return -1;
  if (s[*at] != '\\') return sp_mcp_utf8(s, n, at, cp);
  (*at)++; if (*at >= n) return -1;
  char c = s[(*at)++];
  switch (c) {
  case '"': case '\\': case '/': *cp = (unsigned char)c; return 0;
  case 'b': *cp = 8; return 0; case 'f': *cp = 12; return 0;
  case 'n': *cp = 10; return 0; case 'r': *cp = 13; return 0; case 't': *cp = 9; return 0;
  case 'u': {
    uint32_t v, lo;
    if (n - *at < 4 || kv_json__hex4(s + *at, &v)) return -1;
    *at += 4;
    if (v >= 0xd800 && v <= 0xdbff) {
      if (n - *at < 6 || s[*at] != '\\' || s[*at+1] != 'u' ||
          kv_json__hex4(s + *at + 2, &lo) || lo < 0xdc00 || lo > 0xdfff) return -1;
      *at += 6; v = 0x10000 + ((v - 0xd800) << 10) + lo - 0xdc00;
    } else if (v >= 0xdc00 && v <= 0xdfff) return -1;
    *cp = v; return 0;
  }
  default: return -1;
  }
}
static inline int sp_mcp_string(struct sp_mcp_json *j, unsigned t) {
  j->at++; j->tokens[t].start = j->at;
  while (j->at < j->n && j->s[j->at] != '"') {
    if ((unsigned char)j->s[j->at] < 32) return -1;
    uint32_t cp;
    if (sp_mcp_scalar(j->s, j->n, &j->at, &cp)) return -1;
  }
  if (j->at == j->n) return -1;
  j->tokens[t].end = j->at++; return 0;
}
static inline int sp_mcp_equal(const struct sp_mcp_json *j, unsigned a, unsigned b) {
  size_t x = j->tokens[a].start, y = j->tokens[b].start;
  while (x < j->tokens[a].end && y < j->tokens[b].end) {
    uint32_t u, v;
    if (sp_mcp_scalar(j->s, j->tokens[a].end, &x, &u) ||
        sp_mcp_scalar(j->s, j->tokens[b].end, &y, &v) || u != v) return 0;
  }
  return x == j->tokens[a].end && y == j->tokens[b].end;
}
static inline int sp_mcp_literal(const struct sp_mcp_json *j, unsigned t, const char *s) {
  size_t at = j->tokens[t].start, k = 0;
  if (j->tokens[t].type != 's') return 0;
  while (at < j->tokens[t].end) {
    uint32_t cp;
    if (!s[k] || sp_mcp_scalar(j->s, j->tokens[t].end, &at, &cp) || cp != (unsigned char)s[k++]) return 0;
  }
  return s[k] == 0;
}
static inline int sp_mcp_parse(struct sp_mcp_json *j, unsigned depth) {
  sp_mcp_ws(j);
  if (j->at == j->n) return -1;
  if (depth > SP_MCP_DEPTH_MAX || j->used == SP_MCP_TOKENS_MAX) { j->error = 413; return -1; }
  unsigned t = j->used++; char c = j->s[j->at];
  j->tokens[t].start = j->at;
  if (c == '"') { j->tokens[t].type = 's'; if (sp_mcp_string(j, t)) return -1; }
  else if (c == '{' || c == '[') {
    j->tokens[t].type = c; char close = c == '{' ? '}' : ']'; j->at++; sp_mcp_ws(j);
    if (j->at < j->n && j->s[j->at] == close) j->at++;
    else for (;;) {
      unsigned key = j->used;
      if (c == '{') {
        if (j->at >= j->n || j->s[j->at] != '"' || sp_mcp_parse(j, depth + 1)) return -1;
        for (unsigned prev = t + 1; prev < key; prev = j->tokens[prev + 1].next) {
          size_t cost = j->tokens[prev].end - j->tokens[prev].start +
                        j->tokens[key].end - j->tokens[key].start;
          if (cost > j->compare_budget) { j->error = 413; return -1; }
          j->compare_budget -= cost;
          if (sp_mcp_equal(j, prev, key)) return -1;
        }
        sp_mcp_ws(j); if (j->at == j->n || j->s[j->at++] != ':') return -1;
      }
      if (sp_mcp_parse(j, depth + 1)) return -1;
      sp_mcp_ws(j); if (j->at == j->n) return -1;
      c = j->tokens[t].type;
      if (j->s[j->at] == close) { j->at++; break; }
      if (j->s[j->at++] != ',') return -1;
      sp_mcp_ws(j);
    }
    j->tokens[t].end = j->at;
  } else {
    j->tokens[t].type = 'p';
    if (c == '-' || (c >= '0' && c <= '9')) {
      if (c == '-') j->at++;
      if (j->at == j->n) return -1;
      if (j->s[j->at] == '0') j->at++;
      else { if (j->s[j->at] < '1' || j->s[j->at] > '9') return -1;
        do { j->at++; } while (j->at < j->n && j->s[j->at] >= '0' && j->s[j->at] <= '9'); }
      if (j->at < j->n && j->s[j->at] == '.') {
        j->at++; size_t start = j->at;
        while (j->at < j->n && j->s[j->at] >= '0' && j->s[j->at] <= '9') j->at++;
        if (j->at == start) return -1;
      }
      if (j->at < j->n && (j->s[j->at] == 'e' || j->s[j->at] == 'E')) {
        j->at++; if (j->at < j->n && (j->s[j->at] == '+' || j->s[j->at] == '-')) j->at++;
        size_t start = j->at;
        while (j->at < j->n && j->s[j->at] >= '0' && j->s[j->at] <= '9') j->at++;
        if (j->at == start) return -1;
      }
    } else {
      const char *word = c == 't' ? "true" : c == 'f' ? "false" : c == 'n' ? "null" : "";
      size_t n = strlen(word);
      if (!n || n > j->n - j->at || memcmp(j->s + j->at, word, n)) return -1;
      j->at += n;
    }
    j->tokens[t].end = j->at;
  }
  j->tokens[t].next = j->used; return 0;
}
static inline unsigned sp_mcp_find(const struct sp_mcp_json *j, unsigned obj, const char *key) {
  if (obj >= j->used || j->tokens[obj].type != '{') return SP_MCP_TOKENS_MAX;
  for (unsigned t = obj + 1; t < j->tokens[obj].next; t = j->tokens[t + 1].next)
    if (sp_mcp_literal(j, t, key)) return t + 1;
  return SP_MCP_TOKENS_MAX;
}
static inline int sp_mcp_name_equal(const struct sp_mcp_json *j, unsigned t, const struct sp_mcp_request *r) {
  if (t >= j->used || j->tokens[t].type != 's') return 0;
  size_t a = j->tokens[t].start, b = 0;
  while (a < j->tokens[t].end && b < r->name_len) {
    uint32_t x, y;
    if (sp_mcp_scalar(j->s, j->tokens[t].end, &a, &x) ||
        sp_mcp_utf8(r->name, r->name_len, &b, &y) || x != y) return 0;
  }
  return a == j->tokens[t].end && b == r->name_len;
}
static inline int sp_mcp_validate_core(struct sp_mcp_request *r, const char *http_method,
                                  const char *body, size_t len, struct sp_mcp_json *j) {
  if (!http_method || strcmp(http_method, "POST")) return 405;
  if (r->error) return r->error;
  if (r->active || r->version_seen != 1 || r->method_seen != 1 ||
      strcmp(r->version, SP_MCP_VERSION) || !r->method[0]) return 400;
  if (len > SP_MCP_BODY_MAX) return 413;
  if (!body || !len) return 400;
  j->s = body; j->n = len; j->at = 0; j->used = 0; j->error = 400;
  j->compare_budget = 8U * SP_MCP_BODY_MAX;
  if (sp_mcp_parse(j, 0)) return j->error;
  sp_mcp_ws(j); if (j->at != len || j->tokens[0].type != '{') return 400;
  unsigned rpc = sp_mcp_find(j, 0, "jsonrpc"), method = sp_mcp_find(j, 0, "method");
  if (rpc >= j->used || !sp_mcp_literal(j, rpc, "2.0") || method >= j->used ||
      !sp_mcp_literal(j, method, r->method)) return 400;
  unsigned params = sp_mcp_find(j, 0, "params"), meta = sp_mcp_find(j, params, "_meta");
  unsigned version = sp_mcp_find(j, meta, "io.modelcontextprotocol/protocolVersion");
  unsigned caps = sp_mcp_find(j, meta, "io.modelcontextprotocol/clientCapabilities");
  if (version >= j->used || !sp_mcp_literal(j, version, SP_MCP_VERSION) ||
      caps >= j->used || j->tokens[caps].type != '{') return 400;
  const char *key = !strcmp(r->method, "tools/call") || !strcmp(r->method, "prompts/get") ? "name" :
                    !strcmp(r->method, "resources/read") ? "uri" : NULL;
  if (key) {
    unsigned name = sp_mcp_find(j, params, key);
    if (r->name_seen != 1 || !sp_mcp_name_equal(j, name, r)) return 400;
  } else if (r->name_seen) return 400;
  /* Responses/batches are not client requests. IDs, if present, must be valid. */
  if (sp_mcp_find(j, 0, "result") < j->used || sp_mcp_find(j, 0, "error") < j->used) return 400;
  unsigned id = sp_mcp_find(j, 0, "id");
  if (id < j->used && j->tokens[id].type != 's' &&
      !(j->tokens[id].type == 'p' && (body[j->tokens[id].start] == '-' ||
        (body[j->tokens[id].start] >= '0' && body[j->tokens[id].start] <= '9')))) return 400;
  return 0;
}
/* One fixed allocation avoids a 96KiB parser object on worker thread stacks.
 * It is released on every outcome and never grows with input. Allocation
 * failure is an unavailable service (503), never an accepted request. */
static inline int sp_mcp_validate(struct sp_mcp_request *r, const char *http_method,
                                  const char *body, size_t len) {
  if (!http_method || strcmp(http_method, "POST")) return 405;
  if (r->error) return r->error;
  if (len > SP_MCP_BODY_MAX) return 413;
  struct sp_mcp_json *j = (struct sp_mcp_json *)malloc(sizeof(*j));
  if (!j) return 503;
  int status = sp_mcp_validate_core(r, http_method, body, len, j);
  free(j); return status;
}
#endif
