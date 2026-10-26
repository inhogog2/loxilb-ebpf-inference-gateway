/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __SOCKPROXY_ROUTING_H__
#define __SOCKPROXY_ROUTING_H__

#include "sockproxy.h"

/* Build composite ephash lookup key from hostname, path prefix, and model name.
 *
 * Format examples:
 *   "api.example.com|/v1/users|llama-70b"  (host + path + model)
 *   "api.example.com|/v1/users"            (host + path, no model)
 *   "api.example.com||llama-70b"           (host + model, no path)
 *   "api.example.com"                      (host only – backward compat)
 */
void build_ephash_key(char *key_buf, size_t buf_size,
                      const char *host, const char *path_prefix,
                      const char *model_name);

/* Find endpoint using Longest Prefix Match over the ephash table in ent.
 * Returns the matching proxy_epval_t or NULL if nothing matches.
 */
proxy_epval_t *find_endpoint_lpm(proxy_map_ent_t *ent, const char *host,
                                  const char *request_path,
                                  const char *model_name);

/* The pool of a request with no usable Host (sp_route_hostless). */
enum sp_hostless {
  SP_HOSTLESS_FIRST,   /* no pool names a model: the listener's first pool */
  SP_HOSTLESS_MODEL,   /* the pool that names the request's model */
  SP_HOSTLESS_REFUSE,  /* pools name models, none the request's: refused */
};
int sp_route_hostless(const proxy_map_ent_t *ent, const char *model,
                      proxy_epval_t **pool);

#endif /* __SOCKPROXY_ROUTING_H__ */
