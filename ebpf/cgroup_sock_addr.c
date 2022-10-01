// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT
// modified from https://github.com/microsoft/ebpf-for-windows/blob/main/tests/sample/cgroup_sock_addr.c

#include "bpf_helpers.h"
#include "socket_headers.h"
#include "bpf_endian.h"

SEC("maps")
struct bpf_map_def egress_connection_policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(connection_tuple_t),
    .value_size = sizeof(connection_tuple_t),
    .max_entries = 100};

__inline int
authorize_v4(bpf_sock_addr_t* ctx, struct bpf_map_def* connection_policy_map)
{
    bpf_printk("starting... ");
    connection_tuple_t tuple_key = {0};
    connection_tuple_t* verdict = NULL; 

    tuple_key.dst_ip = ntohl(ctx->user_ip4);
    // tuple_key.dst_port = ctx->user_port;

    bpf_printk("Connnection to from %u to %u on %ld",ntohl(ctx->msg_src_ip4), ntohl(tuple_key.dst_ip), ctx->interface_luid);


    // bpf_map_update_elem(connection_policy_map, &tuple_key, &tuple_key, 0);
    verdict = bpf_map_lookup_elem(connection_policy_map, &tuple_key);
    
    if (verdict == NULL){
        bpf_printk("No rule for %u, %d", ntohl(tuple_key.dst_ip), tuple_key.dst_port);
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    bpf_printk("Blocking %u blocked on port %u", ntohl(tuple_key.dst_ip), verdict->dst_port);

    return BPF_SOCK_ADDR_VERDICT_REJECT;
}


SEC("cgroup/connect4")
int
redirect(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx, &egress_connection_policy_map);
}