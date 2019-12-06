// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_trace_helpers.h"

#define bpf_debug(fmt, ...)                \
{                                          \
    char __fmt[] = fmt;                    \
    bpf_trace_printk(__fmt, sizeof(__fmt), \
                     ##__VA_ARGS__);       \
}

struct net_device {
    /* Structure does not need to contain all entries,
     * as "preserve_access_index" will use BTF to fix this... */
    int                    ifindex;
} __attribute__((preserve_access_index));

struct xdp_rxq_info {
    /* Structure does not need to contain all entries,
     * as "preserve_access_index" will use BTF to fix this... */
    struct net_device *dev;
    __u32 queue_index;
} __attribute__((preserve_access_index));

struct xdp_buff {
    void *data;
    void *data_end;
    void *data_meta;
    void *data_hard_start;
    unsigned long handle;
    struct xdp_rxq_info *rxq;
} __attribute__((preserve_access_index));


BPF_TRACE_1("fentry/xdp_prog_simple", trace_on_entry,
            struct xdp_buff *, xdp)
{
    bpf_debug("fentry: [ifindex = %u, queue =  %u]\n",
              xdp->rxq->dev->ifindex, xdp->rxq->queue_index);
    return 0;
}


BPF_TRACE_2("fexit/xdp_prog_simple", trace_on_exit,
            struct xdp_buff*, xdp, int, ret)
{
    bpf_debug("fexit: [ifindex = %u, queue =  %u, ret = %d]\n",
              xdp->rxq->dev->ifindex, xdp->rxq->queue_index, ret);

    return 0;
}

char _license[] SEC("license") = "GPL";
