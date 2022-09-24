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

    tuple_key.dst_ip = 1;
    tuple_key.dst_port = 0;
    tuple_key.new_dst_ip = 0;
    tuple_key.new_dst_ip = 0;

    // bpf_map_update_elem(connection_policy_map, &tuple_key, &tuple_key, 0);
    verdict = bpf_map_lookup_elem(connection_policy_map, &tuple_key);
    
    if (verdict == NULL){
        bpf_printk("No redirect for %x", ntohl(tuple_key.dst_ip));
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    bpf_printk("Connnection to %x redirected to %ld", ntohl(tuple_key.dst_ip), verdict->new_dst_ip);


    ctx->user_ip4 = verdict->new_dst_ip;
    ctx->user_port = verdict->new_dst_port;

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}


SEC("cgroup/connect4")
int
redirect(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx, &egress_connection_policy_map);
}