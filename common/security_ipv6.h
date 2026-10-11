/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#ifndef LLB_SECURITY_IPV6_H
#define LLB_SECURITY_IPV6_H
#include <linux/types.h>

#define SECURITY_IPV6_MAX_EXTENSIONS 8
#define SECURITY_IPV6_OK 0
#define SECURITY_IPV6_MALFORMED 1
#define SECURITY_IPV6_TOO_DEEP 2
#define SECURITY_IPV6_NONINITIAL_FRAGMENT 3

struct security_ipv6_transport {
    __u32 offset;
    __u8 protocol, fragmented, status;
};

/* Bounded, allocation-free header walk shared by XDP and native fixture tests.
 * The caller decides fragment policy. ESP is opaque, not a parsed TCP/UDP arm.
 * The advertised payload bounds the walk; Ethernet padding is never a header.
 */
static __inline__ __attribute__((always_inline)) struct security_ipv6_transport
security_ipv6_transport(const __u8 *ip, const __u8 *end)
{
    struct security_ipv6_transport r = {0, 0, 0, SECURITY_IPV6_MALFORMED};
    if (ip + 40 > end || (ip[0] >> 4) != 6) return r;
    __u32 payload = ((__u32)ip[4] << 8) | ip[5];
#ifdef __BPF__
    /* Older verifier scalar OR tracking loses the byte-derived bound. Keep
     * the bound explicit in BPF bytecode, without changing native semantics. */
    asm volatile("%0 &= 65535" : "+r"(payload));
#endif
    const __u8 *limit = ip + 40 + payload;
    if (limit > end) return r;
    const __u8 *cursor = ip + 40;
    r.protocol = ip[6];
    r.offset = 40;
#ifdef __BPF__
#pragma unroll
#endif
    for (int i = 0; i < SECURITY_IPV6_MAX_EXTENSIONS; i++) {
        __u32 length;
        if (r.protocol == 44) {
            if (r.fragmented || cursor + 8 > end || cursor + 8 > limit) return r;
            r.fragmented = 1;
            r.protocol = cursor[0];
            __u32 fragment = ((__u32)cursor[2] << 8) | cursor[3];
            cursor += 8;
            r.offset += 8;
            if (fragment & 0xfff8) {
                r.status = SECURITY_IPV6_NONINITIAL_FRAGMENT;
                return r;
            }
            continue;
        }
        if (r.protocol != 0 && r.protocol != 43 && r.protocol != 60 && r.protocol != 51) {
            r.status = SECURITY_IPV6_OK;
            return r;
        }
        if (cursor + 2 > end || cursor + 2 > limit) return r;
        length = r.protocol == 51 ? ((__u32)cursor[1] + 2) * 4 : ((__u32)cursor[1] + 1) * 8;
        if (length < 8 || cursor + length > end || cursor + length > limit) return r;
        r.protocol = cursor[0];
        cursor += length;
        r.offset += length;
    }
    r.status = (r.protocol == 0 || r.protocol == 43 || r.protocol == 60 || r.protocol == 51 || r.protocol == 44)
        ? SECURITY_IPV6_TOO_DEEP : SECURITY_IPV6_OK;
    return r;
}
#endif
