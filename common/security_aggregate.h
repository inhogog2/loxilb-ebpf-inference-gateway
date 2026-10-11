/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#ifndef LLB_SECURITY_AGGREGATE_H
#define LLB_SECURITY_AGGREGATE_H
#include <linux/bpf.h>
#include <linux/types.h>

struct security_aggregate_state {
    struct bpf_spin_lock lock;
    __u32 version;
    __u64 second, syn_count, conn_count, udp_count, udp_bytes;
};
struct security_aggregate_budget {
    __u32 version, syn, conn, udp, bytes;
};

/* Caller holds the shared state lock. No BPF helpers may run in this core.
 * Returns 0=pass, 1=SYN budget, 2=connection-SYN budget, 3=UDP budget.
 * A budget is an aligned one-second window, not a smooth token bucket.
 */
static __inline__ __attribute__((always_inline)) unsigned int
security_aggregate_decide(struct security_aggregate_state *s,
                         const struct security_aggregate_budget *b,
                         __u64 second, int syn, int udp, __u32 bytes)
{
    unsigned int drop = 0;
    if (s->version != b->version || s->second != second) {
        s->version = b->version;
        s->second = second;
        s->syn_count = s->conn_count = s->udp_count = s->udp_bytes = 0;
    }
    if (syn) {
        if (b->syn && s->syn_count <= b->syn) s->syn_count++;
        if (b->conn && s->conn_count <= b->conn) s->conn_count++;
        if (b->syn && s->syn_count > b->syn) drop = 1;
        else if (b->conn && s->conn_count > b->conn) drop = 2;
    }
    if (udp) {
        if (b->udp && s->udp_count <= b->udp) s->udp_count++;
        if (b->bytes && s->udp_bytes <= b->bytes) s->udp_bytes += bytes;
        if ((b->udp && s->udp_count > b->udp) ||
            (b->bytes && s->udp_bytes > b->bytes)) drop = 3;
    }
    return drop;
}
#endif
