// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_trace_helpers.h"

// eval $(../testenv/testenv.sh alias)
// t setup --name veth-tst
// sudo ./xdp_pass_user --dev veth-tst
// bpftool prog list
//
// 6: xdp  name xdp_prog_simple  tag 3b185187f1855c4c  gpl
//        loaded_at 2019-11-28T13:33:13+0000  uid 0
//        xlated 16B  jited 35B  memlock 4096B
//        btf_id 3

#define bpf_debug(fmt, ...)                         \
{                                                   \
  char __fmt[] = fmt;				    \
  bpf_trace_printk(__fmt, sizeof(__fmt),	    \
		   ##__VA_ARGS__);		    \
}

BPF_TRACE_2("fexit/xdp_prog_simple", trace_on_exit,
	    struct xdp_md *, ctx, int, ret)
{
  return 0;
}

/* struct args { */
/*   struct xdp_md *ctx; */
/*   int ret; */
/* }; */

/* SEC("fexit/xdp_prog_simple") */
/* int test_main(struct args *ctx) */
/* { */
/*   bpf_debug("EELCO Debug: [ifindex = %u, queue =  %u, ret = %d]\n", */
/*   	    ctx->ctx->ingress_ifindex, ctx->ctx->rx_queue_index, ctx->ret); */

/*   return 0; */
/* } */

char _license[] SEC("license") = "GPL";
