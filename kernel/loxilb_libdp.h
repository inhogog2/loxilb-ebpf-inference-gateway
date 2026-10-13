/* 
 * Copyright (c) 2022-2025 LoxiLB Authors
 *
 * SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) 
 */
#ifndef __LOXILB_DP_H__
#define __LOXILB_DP_H__

#define LOXILB_DP_LOGF           "/var/log/loxilbdp.log"

#ifndef XDP_LL_SEC_DEFAULT
#define XDP_LL_SEC_DEFAULT       "xdp_packet_hook"
#endif

#ifndef TC_LL_SEC_DEFAULT
#define TC_LL_SEC_DEFAULT        "tc_packet_hook0"

enum llb_bpf_mnt_type {
  LL_BPF_MOUNT_NONE = 0,
  LL_BPF_MOUNT_XDP,
  LL_BPF_MOUNT_TC
};

#endif

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/bpf.h>
#include <pthread.h>

#include "../common/common_libbpf.h"
#include "../common/common_pdi.h"
#include "../common/throttler.h"
#include "../common/llb_dpapi.h"
#include "../common/llb_dp_mdi.h"
#include "../common/cgroup.h"
#include "../common/log.h"

unsigned long long get_os_usecs(void);
unsigned long long get_os_nsecs(void);

struct ebpfcfg {
  int have_mtrace;
  int have_ptrace;
  int no_loader;
  int nodenum;
  int loglevel;
  int egr_hooks;
  int have_sockrwr;
  int have_sockmap;
  int have_ktls;
  int have_noebpf;
};

void loxilb_set_loglevel(struct ebpfcfg *cfg);
/* The data-plane log (log.c). After the proxy has started, log calls queue
 * their lines and the log's writer thread writes them. */
/* The writer renames the log and opens it anew when it would pass max_bytes;
 * 0 = never. */
void loxilb_log_rotate(unsigned long long max_bytes);
/* Shutdown: write what is queued, waiting at most two seconds for the log's
 * device; log calls write for themselves after it. */
void loxilb_log_stop(void);
/* Lines dropped on a full ring since start; level is a log.h level. */
unsigned long long loxilb_log_dropped(int level);
int loxilb_main(struct ebpfcfg *cfg);
/* Interfaces to attach XDP in native (driver) mode on: a comma-separated
 * list or "all"; empty/NULL = generic (skb) mode everywhere (the default).
 * Call before the links are attached. */
int llb_dp_xdp_native_set(const char *ifnames);


#endif
