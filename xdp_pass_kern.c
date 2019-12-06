/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include "bpf_helpers.h"

int _version SEC("version") = 1;


#define bpf_debug(fmt, ...)                         \
{                                                   \
    char __fmt[] = fmt;                             \
    bpf_trace_printk(__fmt, sizeof(__fmt),          \
                     ##__VA_ARGS__);                \
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
    bpf_trace_printk("In xdp_prog_simple(ingress_ifindex = %u)\n",
                     ctx->ingress_ifindex);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
