/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include "bpf_helpers.h"

int _version SEC("version") = 1;

SEC("xdp_prog_simple_sec")
int  xdp_prog_simple(struct xdp_md *ctx)
{
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
