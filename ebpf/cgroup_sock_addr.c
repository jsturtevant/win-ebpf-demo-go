// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

// Whenever this sample program changes, bpf2c_tests will fail unless the
// expected files in tests\bpf2c_tests\expected are updated. The following
// script can be used to regenerate the expected files:
//     generate_expected_bpf2c_output.ps1
//
// Usage:
// .\scripts\generate_expected_bpf2c_output.ps1 <build_output_path>
// Example:
// .\scripts\generate_expected_bpf2c_output.ps1 .\x64\Debug\

#include "bpf_helpers.h"
#include "socket_headers.h"
#include "bpf_endian.h"

SEC("maps")
struct bpf_map_def egress_connection_policy_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(connection_tuple_t),
    .value_size = sizeof(connection_tuple_t),
    .max_entries = 1};

__inline int
authorize_v4(bpf_sock_addr_t* ctx, struct bpf_map_def* connection_policy_map)
{
    connection_tuple_t tuple_key = {0};
    connection_tuple_t* verdict = NULL;

    tuple_key.dst_ip.ipv4 = ctx->user_ip4;
    tuple_key.dst_port = ctx->user_port;

    verdict = bpf_map_lookup_elem(connection_policy_map, &tuple_key);

    if (verdict == NULL){
        bpf_printk("No redirect for %x", ntohl(tuple_key.dst_ip.ipv4));
        return BPF_SOCK_ADDR_VERDICT_PROCEED;
    }

    bpf_printk("Connnection to %x redirected to %ld", ntohl(tuple_key.dst_ip.ipv4), verdict->new_dst_ip.ipv4);


    ctx->user_ip4 = verdict->new_dst_ip.ipv4;
    ctx->user_port = verdict->new_dst_port;

    return BPF_SOCK_ADDR_VERDICT_PROCEED;
}


SEC("cgroup/connect4")
int
authorize_connect4(bpf_sock_addr_t* ctx)
{
    return authorize_v4(ctx, &egress_connection_policy_map);
}